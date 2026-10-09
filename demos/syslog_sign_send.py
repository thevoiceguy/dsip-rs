#!/usr/bin/env python3
"""A minimal RFC 5848 (syslog-sign) signer for the demos: RFC 5424 messages over UDP, Certificate Blocks carrying
the signer's key (key blob type C, a DSA certificate; P, an OpenPGP certificate built from the DSA key; or N, no
key, pre-distributed), and Signature Blocks over the messages sent so far.

    syslog_sign_send.py HOST:PORT STATE --key KEY.pem --cert CERT.pem --hostname H cert [--fragment N] [--blob C|P|N]
    syslog_sign_send.py HOST:PORT STATE --key KEY.pem --hostname H blob      # print the P key blob, base64
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
a.add_argument("cmd", choices=["cert", "blob", "msg", "sign"])
a.add_argument("rest", nargs="*")
a.add_argument("--fragment", type=int, default=0)
a.add_argument("--blob", choices=["C", "P", "N"], default="C", help="cert: the key blob type to send")
a.add_argument("--rsid", type=int, help="the reboot session id for a fresh STATE (a rebooted signer)")
a.add_argument("--sd", default="-")
a.add_argument("--lose", action="store_true", help="msg: record its hash but do not send it (a lost message)")
args = a.parse_args()

host, port = args.to.rsplit(":", 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    st = json.load(open(args.state))
except FileNotFoundError:
    st = {"rsid": args.rsid or 1, "next": 1, "pending": [], "gbc": 0, "procid": args.procid, "started": None}
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


def pgp_blob() -> bytes:
    """Key blob type P: the OpenPGP KeyID, then a certificate (a v4 DSA Public-Key packet and a User ID packet)."""
    n = serialization.load_pem_private_key(open(args.key, "rb").read(), None).public_key().public_numbers()
    pn = n.parameter_numbers
    # the creation time is the signer's session start, so `blob` and `cert --blob P` build the same bytes
    created = int(datetime.datetime.strptime(st["started"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc).timestamp())
    body = b"\x04" + created.to_bytes(4, "big") + b"\x11" + mpi(pn.p) + mpi(pn.q) + mpi(pn.g) + mpi(n.y)
    keyid = hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).digest()[-8:]
    uid = f"{args.hostname} <syslog@{args.hostname}>".encode()
    return keyid + b"\x99" + len(body).to_bytes(2, "big") + body + b"\xb4" + bytes([len(uid)]) + uid


if args.cmd == "blob":
    print(base64.b64encode(pgp_blob()).decode())
    json.dump(st, open(args.state, "w"))  # keep `started`: `cert --blob P` must build the same bytes
    raise SystemExit(0)
if args.cmd == "cert":
    if args.blob == "N":
        payload = f"{st['started']} N"
    elif args.blob == "P":
        payload = f"{st['started']} P {base64.b64encode(pgp_blob()).decode()}"
    else:
        der = load_pem_x509_certificate(open(args.cert, "rb").read()).public_bytes(serialization.Encoding.DER)
        payload = f"{st['started']} C {base64.b64encode(der).decode()}"
    size = args.fragment or len(payload)
    pieces = [(i + 1, payload[i:i + size]) for i in range(0, len(payload), size)]
    for index, frag in pieces:
        send(block("ssign-cert", [("RSID", st["rsid"]), ("SG", 0), ("SPRI", 0), ("TPBL", len(payload)),
                                  ("INDEX", index), ("FLEN", len(frag)), ("FRAG", frag)]))
    print(f"SENT certificate block(s): {len(pieces)} fragment(s) of a {len(payload)}-byte payload (key blob type {args.blob}, rsid {st['rsid']})")
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
