#!/usr/bin/env python3
"""A local stand-in for a Pkarr relay, so the demo runs offline: Pkarr's HTTP API (`PUT /<z32>`, `GET /<z32>`, the
body `signature ‖ ts ‖ dns`) over an in-memory store. The real relay also writes the packet to the Mainline DHT;
this one only stores it. The interoperability check against the real `pkarr-relay` is in impl/docs/spec-gaps.md
(gap 105).

    pkarr_relay.py PORT              an honest relay: verifies the BEP 44 signature, keeps the highest ts (409 otherwise)
    pkarr_relay.py PORT --hostile    a hostile relay: stores and serves anything, and serves a forged packet for
                                     KEY_Z32 if given --forge KEY_Z32=PAYLOAD_HEX

Spec: none (infrastructure).
"""
import http.server
import struct
import sys

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "tools"))
from dsipvec.crypto import ed25519_verify  # noqa: E402
from dsipvec.pkarr import bep44_signable, z32_decode  # noqa: E402

PORT = int(sys.argv[1])
HOSTILE = "--hostile" in sys.argv
STORE = {}
for a in sys.argv:
    if "=" in a and not a.startswith("--"):
        k, v = a.split("=", 1)
        STORE[k] = bytes.fromhex(v)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stdout.write("pkarr-relay %s %s\n" % (self.command, self.path))
        sys.stdout.flush()

    def _key(self):
        z = self.path.strip("/")
        try:
            pub = z32_decode(z)
        except Exception:
            return None, None
        return (z, pub) if len(pub) == 32 else (None, None)

    def do_GET(self):
        z, _ = self._key()
        body = STORE.get(z) if z else None
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/pkarr.org/relays#payload")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        z, pub = self._key()
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if z is None or len(body) < 72 or len(body) > 72 + 1000:
            self.send_response(400)
            self.end_headers()
            return
        ts = struct.unpack(">Q", body[64:72])[0]
        if not HOSTILE:
            if not ed25519_verify(pub, bep44_signable(ts, body[72:]), body[:64]):
                self.send_response(400)
                self.end_headers()
                return
            old = STORE.get(z)
            if old is not None and struct.unpack(">Q", old[64:72])[0] >= ts:
                self.send_response(409)
                self.end_headers()
                return
            STORE[z] = body
        elif z not in STORE:
            STORE[z] = body  # the hostile relay keeps serving its forgery
        self.send_response(204)
        self.end_headers()


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
