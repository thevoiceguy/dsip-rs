#!/usr/bin/env python3
"""A simulated number authority for the discovery demo (Number Attestation Profile N§6, route 2): serves the bindings
it issued at `/.well-known/dsip/tn/<tn>`, one file per number in DIR (`<tn>.jws`, one binding per line).

    tn_authority.py HOST:PORT DIR

Answers 200 `{"bindings": [...]}` for a number it holds, 404 otherwise, and 400 for a path that is not a number.
The log entry route 2 also calls for (T§6) is staged with Alias Transparency stage 2.

Spec: none (infrastructure).
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

HOST, PORT = sys.argv[1].rsplit(":", 1)
DIR = Path(sys.argv[2])
TN = re.compile(r"^\+[1-9][0-9]{1,14}$")


class H(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        prefix = "/.well-known/dsip/tn/"
        if not self.path.startswith(prefix):
            return self._send(404, {"error": "not-found"})
        tn = unquote(self.path[len(prefix):])
        if not TN.fullmatch(tn):
            return self._send(400, {"error": "bad-number"})
        f = DIR / f"{tn}.jws"
        if not f.exists():
            return self._send(404, {"error": "not-found"})
        bindings = [ln.strip() for ln in f.read_text().splitlines() if ln.strip()]
        self._send(200, {"bindings": bindings})

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stdout.write("authority: " + (fmt % args) + "\n")
        sys.stdout.flush()


print(f"http://{HOST}:{PORT}/.well-known/dsip/tn/<tn> from {DIR}   N\u00a76 route 2", flush=True)
ThreadingHTTPServer((HOST, int(PORT)), H).serve_forever()
