#!/usr/bin/env python3
"""
IRCd Web Health Check (Python, no external deps)

Health is HTTP 200 only if BOTH are true:
  1) Client port accepts a localhost TCP connect (127.0.0.1).
  2) At least one ESTABLISHED S2S socket exists on the configured S2S port(s).

HTTPS:
  - Uses your IRCd's cert/key (e.g., Let's Encrypt).
  - Watches the cert/key files; if they change, gracefully restarts the HTTPS
    listener in-process to pick up the new certs.

Linux:
  - S2S socket check uses /proc/net/tcp and /proc/net/tcp6.
  - Non-Linux platforms will report s2sValid = false.

No external dependencies; uses only Python stdlib.

Example:
  python3 health-check.py \
    --listen 0.0.0.0:8443 \
    --client-port 6668 \
    --s2s-ports 7000,7001 \
    --cert /etc/letsencrypt/live/irc.example.org/fullchain.pem \
    --key  /etc/letsencrypt/live/irc.example.org/privkey.pem \
    --mode cached \
    --poll-interval 15
"""

import argparse
import json
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Optional, Tuple

# ----------------- CLI -----------------

def parse_args():
    p = argparse.ArgumentParser(description="IRCd HTTPS health check (no deps)")
    p.add_argument("--listen", default="0.0.0.0:8080",
                   help="Bind address and port, e.g. 127.0.0.1:8080 or 0.0.0.0:8443")
    p.add_argument("--health-path", default="/health",
                   help="Path for health endpoint (default: /health)")
    p.add_argument("--client-port", type=int, default=6667,
                   help="Local IRC client port to test (TCP connect on 127.0.0.1)")
    p.add_argument("--s2s-ports", default=4497,
                   help="Comma-separated S2S port list (e.g., 4497)")
    p.add_argument("--timeout-ms", type=int, default=500,
                   help="Per-check timeout in milliseconds (client connect)")
    p.add_argument("--mode", choices=["live", "cached"], default="live",
                   help="Compute on every request (live) or poll in background (cached)")
    p.add_argument("--poll-interval", type=int, default=15,
                   help="Seconds between polls in cached mode (>=5s recommended)")
    p.add_argument("--cert", default=None,
                   help="TLS certificate chain file (e.g., Let's Encrypt fullchain.pem)")
    p.add_argument("--key", default=None,
                   help="TLS private key file (e.g., Let's Encrypt privkey.pem)")
    p.add_argument("--reload-check-interval", type=int, default=30,
                   help="Seconds between TLS cert/key change checks")
    p.add_argument("--allow-http", action="store_true",
                   help="Allow plain HTTP if cert/key are not provided (default is HTTPS only)")
    p.add_argument("--foreground", action="store_true",
                   help="Stay in foreground with blocking loop (useful without systemd)")
    p.add_argument("--stable-duration", type=int, default=10,
                   help="Require S2S connection to be stable for N seconds before marking healthy (default: 10)")
    return p.parse_args()

# ----------------- Health logic -----------------

def now_iso() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

def can_connect_local(port: int, timeout_ms: int) -> Tuple[bool, Optional[str]]:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout_ms / 1000.0):
            return True, None
    except Exception as e:
        return False, str(e)

def _hex_to_port(h: str) -> Optional[int]:
    try:
        return int(h, 16)
    except Exception:
        return None

def _hex_to_ipv4(h: str) -> Optional[str]:
    # /proc/net/tcp encodes IPv4 as 8 hex chars, little-endian
    if not h or len(h) != 8:
        return None
    try:
        b = [int(h[i:i+2], 16) for i in range(0, 8, 2)]
        return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"
    except Exception:
        return None

def _hex_to_ipv6(h: str) -> Optional[str]:
    # Best-effort; not normalized. Good enough for display and simple matching.
    if not h or len(h) != 32:
        return None
    try:
        parts = [h[i:i+4] for i in range(0, 32, 4)]
        return ":".join(parts)
    except Exception:
        return None

def _parse_proc_net(lines: str, is6: bool) -> List[dict]:
    """
    Parse /proc/net/tcp or /proc/net/tcp6 content into structured connection data.

    Returns: List of dicts with shape:
    {
        "fam": "tcp" or "tcp6",      # Protocol family
        "laddr": str or None,         # Local IP address
        "lport": int or None,         # Local port
        "raddr": str or None,         # Remote IP address
        "rport": int or None,         # Remote port
        "state": str,                 # Connection state hex (e.g., "01" = ESTABLISHED)
        "inode": str or None          # Socket inode number for unique identification
    }
    """
    out = []
    if not lines:
        return out
    rows = lines.splitlines()
    for i, ln in enumerate(rows):
        if i == 0:
            continue  # header
        ln = ln.strip()
        if not ln:
            continue
        cols = ln.split()
        if len(cols) < 10:
            continue
        laddr_hex, lport_hex = cols[1].split(":")
        raddr_hex, rport_hex = cols[2].split(":")
        state_hex = cols[3]
        # Column indexing: sl=0, local=1, remote=2, st=3, tx_rx=4, tr=5, when=6, retr=7, uid=8, timeout=9, inode=10
        inode = cols[10] if len(cols) > 10 else None
        lport = _hex_to_port(lport_hex)
        rport = _hex_to_port(rport_hex)
        if is6:
            laddr = _hex_to_ipv6(laddr_hex)
            raddr = _hex_to_ipv6(raddr_hex)
        else:
            laddr = _hex_to_ipv4(laddr_hex)
            raddr = _hex_to_ipv4(raddr_hex)
        out.append({
            "fam": "tcp6" if is6 else "tcp",
            "laddr": laddr, "lport": lport,
            "raddr": raddr, "rport": rport,
            "state": state_hex,
            "inode": inode
        })
    return out

def _is_established(state_hex: str) -> bool:
    # 01 = ESTABLISHED in /proc/net/tcp*
    return state_hex == "01"

def count_established_s2s(ports: List[int],
                          stable_duration: int,
                          connection_tracker: dict) -> Tuple[bool, bool, Optional[str]]:
    """
    Check for established S2S connections with stability tracking.

    Connection tracker structure (modified in-place):
    {
        "stable_inode": str or None,         # The proven stable connection we're monitoring
        "candidates": {str: float, ...}      # Connections being evaluated: {inode: first_seen_timestamp}
    }

    Returns: (s2s_stable, s2s_warming, s2s_err)
    - s2s_stable: bool - True if stable_inode still exists OR a candidate has become stable
    - s2s_warming: bool - True if we're evaluating candidates but none are stable yet
    - s2s_err: str or None - Error message if check failed, None otherwise
    """
    if sys.platform != "linux":
        return False, False, "non-linux platform; /proc/net unavailable"

    try:
        tcp = ""
        tcp6 = ""
        try:
            with open("/proc/net/tcp", "r", encoding="utf-8") as f:
                tcp = f.read()
        except Exception:
            pass
        try:
            with open("/proc/net/tcp6", "r", encoding="utf-8") as f:
                tcp6 = f.read()
        except Exception:
            pass

        if not tcp and not tcp6:
            return False, False, "cannot read /proc/net/tcp*"

        # Initialize tracker structure if needed
        if "stable_inode" not in connection_tracker:
            connection_tracker["stable_inode"] = None
            connection_tracker["candidates"] = {}

        rows = _parse_proc_net(tcp, is6=False) + _parse_proc_net(tcp6, is6=True)
        current_time = time.time()
        current_s2s_inodes = set()

        # Collect all current S2S connection inodes
        for r in rows:
            if not _is_established(r["state"]):
                continue
            lport = r["lport"]
            rport = r["rport"]
            if lport is None and rport is None:
                continue
            if (lport in ports) or (rport in ports):
                inode = r.get("inode")
                if inode:
                    current_s2s_inodes.add(inode)

        # If we have a stable connection, just check if it still exists
        if connection_tracker["stable_inode"]:
            if connection_tracker["stable_inode"] in current_s2s_inodes:
                # Stable connection still alive, we're good!
                return True, False, None
            else:
                # Stable connection lost! Reset and start evaluating candidates
                connection_tracker["stable_inode"] = None
                connection_tracker["candidates"] = {}

        # No stable connection - evaluate candidates
        if not current_s2s_inodes:
            # No S2S connections at all
            connection_tracker["candidates"] = {}
            return False, False, None

        # Track new candidates and check if any are stable
        for inode in current_s2s_inodes:
            if inode not in connection_tracker["candidates"]:
                connection_tracker["candidates"][inode] = current_time

        # Clean up candidates that disappeared
        stale_candidates = [i for i in connection_tracker["candidates"].keys() if i not in current_s2s_inodes]
        for i in stale_candidates:
            del connection_tracker["candidates"][i]

        # Check if any candidate has become stable
        for inode, first_seen in connection_tracker["candidates"].items():
            if current_time - first_seen >= stable_duration:
                # This connection is now stable! Promote it and clear candidates
                connection_tracker["stable_inode"] = inode
                connection_tracker["candidates"] = {}
                return True, False, None

        # We have candidates but none are stable yet - warming up
        return False, True, None
    except Exception as e:
        return False, False, str(e)

def compute_health(client_port: int,
                   s2s_ports: List[int],
                   timeout_ms: int,
                   stable_duration: int,
                   connection_tracker: dict) -> dict:
    """
    Compute overall health by checking client port and S2S connections.

    Returns: dict with shape:
    {
        "clientValid": bool,   # True if client port accepts connections on 127.0.0.1
        "s2sValid": bool,      # True if stable S2S connection exists (or warming up with candidates)
        "routable": bool,      # True if BOTH clientValid AND s2sValid are true
        "warm": bool           # False during warmup period, True once connection is proven stable
    }
    """
    client_ok, client_err = can_connect_local(client_port, timeout_ms)
    s2s_stable, s2s_warming, s2s_err = count_established_s2s(s2s_ports, stable_duration, connection_tracker)

    # During warmup, we're optimistic: s2s is "valid" if warming (has any connection)
    # After warmup, s2s must be stable
    s2s_ok = s2s_stable or s2s_warming
    ok = client_ok and s2s_ok

    return {
        "clientValid": client_ok,
        "s2sValid": s2s_ok,
        "routable": ok,
        "warm": not s2s_warming  # warm=true means we're out of warmup period
    }

# ----------------- HTTP(S) server with hot-reload TLS -----------------

class HealthHandler(BaseHTTPRequestHandler):
    server_version = "ircd-health/1.0"

    def do_GET(self):
        if self.path == self.server.health_path:
            self.serve_health()
            return
        if self.path in ("/", "/_info"):
            self.serve_info()
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"not found")

    def log_message(self, fmt, *args):
        # quiet by default (avoid noisy health logs)
        sys.stderr.write("%s - - [%s] %s\n" % (
            self.address_string(),
            now_iso(),
            fmt % args
        ))

    def serve_health(self):
        if self.server.mode == "cached":
            result = self.server.last_result or {"clientValid": False, "s2sValid": False, "routable": False, "warm": False}
        else:
            result = compute_health(
                self.server.client_port,
                self.server.s2s_ports,
                self.server.timeout_ms,
                self.server.stable_duration,
                self.server.connection_tracker
            )
        status = 200 if result.get("routable") else 503
        payload = json.dumps(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def serve_info(self):
        info = {
            "name": "ircd-web-health",
            "healthPath": self.server.health_path,
            "mode": self.server.mode,
            "https": self.server.https_enabled
        }
        payload = json.dumps(info, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

class TLSReloadingServer:
    """
    Supervises a ThreadingHTTPServer wrapped in TLS.
    Watches cert/key mtime and restarts listener when they change.
    """

    def __init__(self,
                 bind_host: str,
                 bind_port: int,
                 handler_cls,
                 health_path: str,
                 client_port: int,
                 s2s_ports: List[int],
                 timeout_ms: int,
                 mode: str,
                 poll_interval: int,
                 certfile: Optional[str],
                 keyfile: Optional[str],
                 allow_http: bool,
                 reload_check_interval: int,
                 stable_duration: int):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.handler_cls = handler_cls
        self.health_path = health_path
        self.client_port = client_port
        self.s2s_ports = s2s_ports
        self.timeout_ms = timeout_ms
        self.mode = mode
        self.poll_interval = poll_interval
        self.certfile = certfile
        self.keyfile = keyfile
        self.allow_http = allow_http
        self.reload_check_interval = max(5, reload_check_interval)
        self.stable_duration = stable_duration

        self._server = None  # ThreadingHTTPServer
        self._thread = None
        self._stop_evt = threading.Event()
        self._watcher_thread = None
        self._poll_thread = None

        self.last_result = None
        self.https_enabled = False
        self._cert_mtime = None
        self._key_mtime = None
        self.connection_tracker = {}  # Track S2S connection stability

    # ---- public ----
    def start(self):
        self._start_httpd()
        if self.mode == "cached":
            self._start_poll()
        self._start_watcher()

    def stop(self):
        self._stop_evt.set()
        self._shutdown_httpd()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=3)
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=3)

    # ---- internals ----

    def _make_httpd(self) -> ThreadingHTTPServer:
        httpd = ThreadingHTTPServer((self.bind_host, self.bind_port), self.handler_cls)
        # attach config to server for handler access
        httpd.health_path = self.health_path
        httpd.client_port = self.client_port
        httpd.s2s_ports = self.s2s_ports
        httpd.timeout_ms = self.timeout_ms
        httpd.mode = self.mode
        httpd.poll_interval = self.poll_interval
        httpd.last_result = lambda: None  # placeholder, replaced below
        httpd.bind_host = self.bind_host
        httpd.bind_port = self.bind_port
        httpd.certfile = self.certfile
        httpd.keyfile = self.keyfile
        httpd.https_enabled = False
        httpd.stable_duration = self.stable_duration
        httpd.connection_tracker = self.connection_tracker

        # Provide handler access to last_result (cached mode)
        def _get_last():
            return self.last_result
        httpd.last_result = _get_last

        # Wrap with TLS if cert+key provided, else honor allow_http
        if self.certfile and self.keyfile:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # Harden a bit, keeping broad compatibility
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            httpd.https_enabled = True
        else:
            if not self.allow_http:
                raise RuntimeError("cert/key not provided and --allow-http not set")
            httpd.https_enabled = False

        return httpd

    def _start_httpd(self):
        self._server = self._make_httpd()

        def _serve():
            try:
                sys.stderr.write(f"[{now_iso()}] Listening on {self.bind_host}:{self.bind_port} "
                                 f"{'HTTPS' if self._server.https_enabled else 'HTTP'} path={self.health_path} mode={self.mode}\n")
                self._server.serve_forever(poll_interval=0.5)
            except Exception as e:
                sys.stderr.write(f"[{now_iso()}] server thread exception: {e}\n")

        self._thread = threading.Thread(target=_serve, daemon=True)
        self._thread.start()

        # capture initial mtimes to detect changes
        self._update_cert_mtimes()

    def _shutdown_httpd(self):
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception as e:
                sys.stderr.write(f"[{now_iso()}] error closing server: {e}\n")
            self._server = None
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3)
            self._thread = None

    def _restart_httpd(self):
        self._shutdown_httpd()
        self._start_httpd()

    def _path_mtime(self, path: Optional[str]) -> Optional[float]:
        if not path:
            return None
        try:
            st = os.stat(path)
            return st.st_mtime
        except Exception:
            return None

    def _update_cert_mtimes(self):
        self._cert_mtime = self._path_mtime(self.certfile)
        self._key_mtime = self._path_mtime(self.keyfile)

    def _certs_changed(self) -> bool:
        return (self._path_mtime(self.certfile) != self._cert_mtime) or \
               (self._path_mtime(self.keyfile) != self._key_mtime)

    def _start_watcher(self):
        if not (self.certfile and self.keyfile):
            # nothing to watch
            return

        def _watch():
            while not self._stop_evt.wait(self.reload_check_interval):
                try:
                    if self._certs_changed():
                        sys.stderr.write(f"[{now_iso()}] Detected cert/key change; reloading TLS listener...\n")
                        self._update_cert_mtimes()
                        self._restart_httpd()
                except Exception as e:
                    sys.stderr.write(f"[{now_iso()}] watcher error: {e}\n")

        self._watcher_thread = threading.Thread(target=_watch, daemon=True)
        self._watcher_thread.start()

    def _start_poll(self):
        def _poll():
            while not self._stop_evt.wait(max(5, self.poll_interval)):
                try:
                    self.last_result = compute_health(
                        self.client_port,
                        self.s2s_ports,
                        self.timeout_ms,
                        self.stable_duration,
                        self.connection_tracker
                    )
                except Exception as e:
                    self.last_result = {
                        "clientValid": False,
                        "s2sValid": False,
                        "routable": False,
                        "warm": False
                    }
        self._poll_thread = threading.Thread(target=_poll, daemon=True)
        self._poll_thread.start()

# ----------------- main -----------------

def main():
    args = parse_args()

    # Parse listen
    if ":" not in args.listen:
        print("Invalid --listen (expected host:port)", file=sys.stderr)
        sys.exit(2)
    bind_host, port_str = args.listen.rsplit(":", 1)
    try:
        bind_port = int(port_str)
    except ValueError:
        print("Invalid port in --listen", file=sys.stderr)
        sys.exit(2)

    # Parse S2S ports
    s2s_ports = []
    if args.s2s_ports.strip():
        for p in args.s2s_ports.split(","):
            p = p.strip()
            if not p:
                continue
            try:
                s2s_ports.append(int(p))
            except ValueError:
                print(f"Ignoring invalid S2S port: {p}", file=sys.stderr)
    s2s_ports = sorted(set(s2s_ports))

    # Create server supervisor
    srv = TLSReloadingServer(
        bind_host=bind_host,
        bind_port=bind_port,
        handler_cls=HealthHandler,
        health_path=args.health_path if args.health_path.startswith("/") else "/" + args.health_path,
        client_port=args.client_port,
        s2s_ports=s2s_ports or [7000],
        timeout_ms=max(50, args.timeout_ms),
        mode=args.mode,
        poll_interval=max(5, args.poll_interval),
        certfile=args.cert,
        keyfile=args.key,
        allow_http=args.allow_http,
        reload_check_interval=args.reload_check_interval,
        stable_duration=max(0, args.stable_duration)
    )

    # Graceful shutdown hooks
    def _stop(_sig=None, _frm=None):
        try:
            srv.stop()
        finally:
            sys.exit(0)

    import signal
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    # Start
    try:
        srv.start()
    except Exception as e:
        print(f"Failed to start server: {e}", file=sys.stderr)
        sys.exit(1)

    # Keep the main thread alive (only if --foreground)
    if args.foreground:
        while True:
            time.sleep(3600)
    # Otherwise, let systemd or process manager keep us alive via daemon threads

if __name__ == "__main__":
    main()
