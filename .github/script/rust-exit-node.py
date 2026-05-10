#!/usr/bin/env python3
"""
rust-exit-node.py — Python re‑implementation of the mhrv-rs exit node
(exit-node.ts).  Deploy on any server or in GitHub Actions behind Cloudflare
Tunnel.  Only web‑standard libraries (http, json, base64, urllib) –
portable across any Python 3.8+.

Protocol: POST JSON { k, u, m, h, b } → outbound fetch → JSON { s, h, b }.
"""

import argparse
import base64
import http.server
import json
import logging
import os
import re
import socketserver
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("rust-exit-node")

# ---------------------------------------------------------------------------
# Constants – keep in sync with exit-node.ts
# ---------------------------------------------------------------------------
# Headers that MUST NOT be forwarded to the destination.
STRIP_REQUEST_HEADERS = frozenset(
    h.lower()
    for h in [
        "host",
        "connection",
        "content-length",
        "transfer-encoding",
        "proxy-connection",
        "proxy-authorization",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-real-ip",
        "forwarded",
        "via",
        # We do not want compressed responses – Python's urllib won't auto‑decompress.
        "accept-encoding",
    ]
)

# Response headers that we strip before sending back to the client because
# they would be incorrect or misleading (like after decompression or chunking).
STRIP_RESPONSE_HEADERS = frozenset(["content-encoding", "content-length"])

MAX_REQUEST_BODY = 32 * 1024 * 1024      # 32 MiB
MAX_RESPONSE_BODY = 64 * 1024 * 1024     # 64 MiB
OUTBOUND_TIMEOUT = 30                    # seconds

PSK = ""  # set on startup

# ---------------------------------------------------------------------------
# SSRF / loop guard helpers
# ---------------------------------------------------------------------------
_SSRF_PRIVATE_RE = re.compile(
    r"^("
    r"localhost"
    r"|127\.\d+\.\d+\.\d+"
    r"|::1"
    r"|0\.0\.0\.0"
    r"|10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|169\.254\.\d+\.\d+"
    r"|fc[0-9a-f]{2}:.*"
    r"|fd[0-9a-f]{2}:.*"
    r")$"
)


def _safe_url(url: str, req_host: str) -> bool:
    """Return True only for http/https URLs, not looping back to us, not private."""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        return False
    parsed = urllib.request.urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False
    # Block private / loopback addresses.
    if _SSRF_PRIVATE_RE.match(host):
        return False
    # Block requests that would point back to this exit node (loop guard).
    if host == req_host:
        return False
    return True


# ---------------------------------------------------------------------------
# Outbound HTTP request (no redirect following)
# ---------------------------------------------------------------------------
_NO_REDIRECT_OPENER = urllib.request.OpenerDirector()
for _h in [
    urllib.request.UnknownHandler(),
    urllib.request.HTTPDefaultErrorHandler(),
    urllib.request.HTTPErrorProcessor(),
    urllib.request.HTTPHandler(),
    urllib.request.HTTPSHandler(),
]:
    _NO_REDIRECT_OPENER.add_handler(_h)
del _h


def _collect_response_headers(raw_headers) -> dict:
    """Collect response headers, preserving duplicate keys as lists."""
    out = {}
    key_map = {}  # lowercase -> first-seen canonical case
    for k, v in raw_headers.items():
        kl = k.lower()
        if kl in STRIP_RESPONSE_HEADERS:
            continue
        if kl not in key_map:
            key_map[kl] = k
            out[k] = v
        else:
            canonical = key_map[kl]
            cur = out[canonical]
            if isinstance(cur, list):
                cur.append(v)
            else:
                out[canonical] = [cur, v]
    return out


def _relay_request(url: str, method: str, headers: dict, body: bytes) -> dict:
    """Perform the outbound request and return a relay‑JSON dict."""
    req = urllib.request.Request(url, method=method, headers=headers, data=body or None)
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=OUTBOUND_TIMEOUT) as resp:
            data = resp.read(MAX_RESPONSE_BODY)
            return {
                "s": resp.status,
                "h": _collect_response_headers(resp.headers),
                "b": base64.b64encode(data).decode("ascii"),
            }
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_RESPONSE_BODY) if exc.fp else b""
        return {
            "s": exc.code,
            "h": _collect_response_headers(exc.headers) if exc.headers else {},
            "b": base64.b64encode(data).decode("ascii"),
        }


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class RustExitNodeHandler(http.server.BaseHTTPRequestHandler):
    """Handles POST relay requests, GET health check."""

    def log_message(self, fmt, *args):
        pass  # we log with our own format

    def _send_json(self, status: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send_json(
            200,
            {
                "ok": True,
                "status": "healthy",
                "message": "mhrv-rs exit node running (Python).",
                "usage": "POST JSON with relay payload.",
            },
        )

    def do_POST(self):
        # Size limits
        content_length = int(self.headers.get("Content-Length") or 0)
        if content_length <= 0:
            self._send_json(400, {"e": "empty_body"})
            return
        if content_length > MAX_REQUEST_BODY:
            self._send_json(413, {"e": "request_too_large"})
            return

        raw = self.rfile.read(content_length)
        try:
            body = json.loads(raw)
        except Exception:
            self._send_json(400, {"e": "bad_json"})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"e": "bad_json"})
            return

        k = str(body.get("k") or "")
        u = str(body.get("u") or "")
        m = str(body.get("m") or "GET").upper()
        h = body.get("h", {})
        b64 = body.get("b")

        # 1. PSK check
        if k != PSK:
            log.warning("Rejected unauthorized request from %s", self.client_address[0])
            self._send_json(401, {"e": "unauthorized"})
            return

        # 2. URL validation + loop guard
        req_host = (self.headers.get("Host") or "").split(":")[0].lower()
        if not _safe_url(u, req_host):
            self._send_json(400, {"e": "bad_url"})
            return

        # 3. Sanitise request headers
        clean_headers = {}
        if isinstance(h, dict):
            for key, value in h.items():
                if not key or not isinstance(key, str):
                    continue
                if key.lower() in STRIP_REQUEST_HEADERS:
                    continue
                clean_headers[key] = str(value) if value is not None else ""

        # 4. Decode base64 body
        payload_bytes = b""
        if isinstance(b64, str) and b64:
            try:
                payload_bytes = base64.b64decode(b64)
            except Exception:
                self._send_json(400, {"e": "bad_base64"})
                return

        log.info("Relaying %s %s", m, u[:100])
        try:
            result = _relay_request(u, m, clean_headers, payload_bytes)
        except Exception as exc:
            log.warning("Relay error for %s: %s", u[:80], exc)
            self._send_json(500, {"e": str(exc) or type(exc).__name__})
            return

        log.info(
            "Relay OK %s → HTTP %d (%d B)",
            u[:80],
            result["s"],
            len(result.get("b", "")),
        )
        self._send_json(200, result)


# ---------------------------------------------------------------------------
# Threaded server
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="mhrv-rs exit node (Python)")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Listen interface (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8181,
        help="Listen port (default: 8181)",
    )
    parser.add_argument(
        "--psk",
        default="",
        help="Pre‑shared key (or set EXIT_NODE_PSK env var)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity",
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    global PSK
    PSK = (args.psk or os.environ.get("EXIT_NODE_PSK", "")).strip()
    if not PSK:
        log.error("No PSK configured. Use --psk or EXIT_NODE_PSK env var.")
        sys.exit(1)
    if PSK == "CHANGE_ME_TO_A_STRONG_SECRET":
        log.error(
            "Placeholder PSK detected. Set a strong secret before running the exit node."
        )
        sys.exit(1)

    server = ThreadedHTTPServer((args.host, args.port), RustExitNodeHandler)
    log.info("rust-exit-node listening on %s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
