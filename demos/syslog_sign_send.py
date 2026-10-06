#!/usr/bin/env python3
"""A minimal RFC 5848 (syslog-sign) signer for the demos: RFC 5424 messages over UDP, Certificate Blocks carrying
the signer's DSA certificate (key blob type C), and Signature Blocks over the messages sent so far.

    syslog_sign_send.py HOST:PORT STATE --key KEY.pem --cert CERT.pem --hostname H cert [--fragment N]
    syslog_sign_send.py HOST:PORT STATE --hostname H msg APP MSGID TEXT [--sd SD]
    syslog_sign_send.py HOST:PORT STATE --key KEY.pem --hostname H sign

STATE (a JSON file) keeps the reboot session, the next message number and the hashes not yet signed. No packaged
signer exists to use instead (NetBSD's syslogd is the one implementation); the vectors carry RFC 5848's own
examples as the independent check.

Spec: none (infrastructure).
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import socket

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509 import load_pem_x509_certificate

a = argparse.ArgumentParser()
a.add_argument("to")
a.add_argument("state")
a.add_argument("--key")
a.add_argument("--cert")
a.add_argument("--hostname", required=True)
a.add_argument("--app", default="syslogd")
a.add_argument("--procid", default=str(os.getpid() % 10000))
a.add_argument("cmd", choices=["cert", "msg", "sign"])
a.add_argument("rest", nargs="*")
a.add_argument("--fragment", type=int, default=0)
a.add_argument("--sd", default="-")
a.add_argument("--lose", action="store_true", help="msg: record its hash but do not send it (a lost message)")
args = a.parse_args()

host, port = args.to.rsplit(":", 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    st = json.load(open(args.state))
except FileNotFoundError:
    st = {"rsid": 1, "next": 1, "pending": [], "gbc": 0, "procid": args.procid, "started": None}
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
st["started"] = st["started"] or now


def send(b: bytes):
    sock.sendto(b, (host, int(port)))


def mpi(v: int) -> bytes:
    return v.bit_length().to_bytes(2, "big") + v.to_bytes((v.bit_length() + 7) // 8, "big")


def block(kind: str, params: list) -> bytes:
    key = serialization.load_pem_private_key(open(args.key, "rb").read(), None)
    body = " ".join(f'{n}="{v}"' for n, v in [("VER", "0121")] + params)
    unsigned = f"<110>1 {now} {args.hostname} {args.app} {st['procid']} - [{kind} {body}]".encode()
    r, s = decode_dss_signature(key.sign(unsigned, hashes.SHA256()))
    return unsigned[:-1] + f' SIGN="{base64.b64encode(mpi(r) + mpi(s)).decode()}"]'.encode()


if args.cmd == "cert":
    der = load_pem_x509_certificate(open(args.cert, "rb").read()).public_bytes(serialization.Encoding.DER)
    payload = f"{st['started']} C {base64.b64encode(der).decode()}"
    size = args.fragment or len(payload)
    pieces = [(i + 1, payload[i:i + size]) for i in range(0, len(payload), size)]
    for index, frag in pieces:
        send(block("ssign-cert", [("RSID", st["rsid"]), ("SG", 0), ("SPRI", 0), ("TPBL", len(payload)),
                                  ("INDEX", index), ("FLEN", len(frag)), ("FRAG", frag)]))
    print(f"SENT certificate block(s): {len(pieces)} fragment(s) of a {len(payload)}-byte payload")
elif args.cmd == "msg":
    app, msgid, text = args.rest
    m = f"<187>1 {now} {args.hostname} {app} - {msgid} {args.sd} {text}".encode()
    if not args.lose:
        send(m)
    st["pending"].append(base64.b64encode(hashlib.sha256(m).digest()).decode())
    print(f"{'LOST' if args.lose else 'SENT'} message {st['next'] + len(st['pending']) - 1}: {text}")
else:
    hb = st["pending"]
    send(block("ssign", [("RSID", st["rsid"]), ("SG", 0), ("SPRI", 0), ("GBC", st["gbc"]), ("FMN", st["next"]),
                         ("CNT", len(hb)), ("HB", " ".join(hb))]))
    print(f"SENT signature block: messages {st['next']}–{st['next'] + len(hb) - 1}")
    st["next"] += len(hb)
    st["gbc"] += 1
    st["pending"] = []
json.dump(st, open(args.state, "w"))
