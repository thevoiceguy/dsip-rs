#!/usr/bin/env python3
"""A real SNMPv3 sender for the demos, on pysnmp (an independent USM implementation): traps and informs with
authNoPriv or authPriv (AES-128), and a raw resend of a captured trap for replay tests.

    snmpv3_send.py trap   HOST:PORT ENGINE_ID BOOTS USER AUTH AUTH_PW [PRIV_PW|-] TRAP_OID [OID=i:N|s:TEXT ...] [--save F]
    snmpv3_send.py inform HOST:PORT ENGINE_ID BOOTS USER AUTH AUTH_PW [PRIV_PW|-] TRAP_OID [OID=i:N|s:TEXT ...]
    snmpv3_send.py raw    HOST:PORT FILE

AUTH is md5, sha, sha224, sha256, sha384 or sha512; a privacy password selects AES-128 (authPriv). A trap names the
sender's own engine (ENGINE_ID, with BOOTS); an inform discovers the receiver's engine first (RFC 3414 §4) and prints
`RESPONSE` once answered, or `NO RESPONSE` and exits 1. `--save F` writes the trap's exact bytes (hex) to F.

Spec: none (infrastructure).
"""
import asyncio
import os
import socket
import sys

from pysnmp.hlapi.v3arch.asyncio import (ContextData, Integer, NotificationType, ObjectIdentity, SnmpEngine,
                                        UdpTransportTarget, UsmUserData, send_notification, usmAesCfb128Protocol,
                                        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
                                        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
                                        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol)
from pysnmp.proto.rfc1902 import OctetString

AUTH = {"md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol, "sha224": usmHMAC128SHA224AuthProtocol,
        "sha256": usmHMAC192SHA256AuthProtocol, "sha384": usmHMAC256SHA384AuthProtocol,
        "sha512": usmHMAC384SHA512AuthProtocol}


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def varbinds(args):
    out = []
    for a in args:
        oid, val = a.split("=", 1)
        t, v = val.split(":", 1)
        out.append((oid, Integer(int(v)) if t == "i" else OctetString(v)))
    return out


async def notify(kind, target, engine_id, boots, user, auth, auth_pw, priv_pw, trap_oid, vbs):
    eng = SnmpEngine(OctetString(hexValue=engine_id))
    (b,) = eng.get_mib_builder().import_symbols("__SNMP-FRAMEWORK-MIB", "snmpEngineBoots")
    b.syntax = b.syntax.clone(boots)
    u = UsmUserData(user, auth_pw, priv_pw, authProtocol=AUTH[auth],
                    privProtocol=usmAesCfb128Protocol) if priv_pw else UsmUserData(user, auth_pw, authProtocol=AUTH[auth])
    t = await UdpTransportTarget.create(target, timeout=float(os.environ.get("INFORM_TIMEOUT", "2")),
                                        retries=int(os.environ.get("INFORM_RETRIES", "5")))
    err, status, _, _ = await send_notification(eng, u, t, ContextData(), kind,
                                                NotificationType(ObjectIdentity(trap_oid)).add_varbinds(*vbs))
    eng.close_dispatcher()
    return err or (status and status.prettyPrint())


def main():
    a = [x for x in sys.argv[1:] if x != "--save"]
    save = sys.argv[sys.argv.index("--save") + 1] if "--save" in sys.argv else None
    if save:
        a.remove(save)
    mode = a[0]
    if mode == "raw":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(bytes.fromhex(open(a[2]).read().strip()), hostport(a[1]))
        print("sent the captured bytes again")
        return
    target, engine, boots, user, auth, auth_pw, priv_pw, trap_oid = a[1:9]
    priv_pw = None if priv_pw == "-" else priv_pw
    vbs = varbinds(a[9:])
    if mode == "trap" and save:
        # capture the exact bytes on a local socket, then forward them, so a replay can resend them unchanged
        cap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cap.bind(("127.0.0.1", 0))
        cap.settimeout(5)
        asyncio.run(notify("trap", ("127.0.0.1", cap.getsockname()[1]), engine, int(boots), user, auth, auth_pw,
                           priv_pw, trap_oid, vbs))
        d = cap.recv(65535)
        open(save, "w").write(d.hex())
        cap.sendto(d, hostport(target))
        print(f"trap sent ({len(d)} bytes, saved)")
        return
    err = asyncio.run(notify(mode, hostport(target), engine, int(boots), user, auth, auth_pw, priv_pw, trap_oid, vbs))
    if mode == "inform":
        print("RESPONSE" if not err else f"NO RESPONSE ({err})")
        sys.exit(1 if err else 0)
    print("trap sent")


main()
