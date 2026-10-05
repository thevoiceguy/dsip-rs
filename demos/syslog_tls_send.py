#!/usr/bin/env python3
"""Send syslog over TLS (RFC 5425: octet-counted frames `MSG-LEN SP SYSLOG-MSG`) for the demos.

    syslog_tls_send.py HOST:PORT CA_PEM [--cert CERT_PEM --key KEY_PEM] MESSAGE [MESSAGE ...]

The gateway's certificate is verified against CA_PEM. Prints `SENT n` or the TLS error, exiting 1.

Spec: none (infrastructure).
"""
import socket
import ssl
import sys

a = sys.argv[1:]
cert = key = None
if "--cert" in a:
    i = a.index("--cert"); cert = a[i + 1]; del a[i:i + 2]
if "--key" in a:
    i = a.index("--key"); key = a[i + 1]; del a[i:i + 2]
host, port = a[0].rsplit(":", 1)
ctx = ssl.create_default_context(cafile=a[1])
ctx.check_hostname = False
if cert:
    ctx.load_cert_chain(cert, key)
try:
    with socket.create_connection((host, int(port)), timeout=5) as raw, ctx.wrap_socket(raw) as s:
        for m in a[2:]:
            b = m.encode()
            s.sendall(str(len(b)).encode() + b" " + b)
        # TLS 1.3 reports a refused client certificate only on the next read
        s.settimeout(1)
        try:
            if s.recv(1) == b"":
                pass
        except socket.timeout:
            pass
    print(f"SENT {len(a) - 2}")
except (ssl.SSLError, OSError) as e:
    print(f"TLS ERROR {e}")
    sys.exit(1)
