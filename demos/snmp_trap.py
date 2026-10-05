#!/usr/bin/env python3
"""Send an SNMPv1 or SNMPv2c trap over UDP, BER-encoded (RFC 1157 §4.1.6, RFC 3416 §3) — the demo's stand-in for
`snmptrap`, so the demo needs no net-snmp.

  snmp_trap.py v2c HOST:PORT COMMUNITY UPTIME TRAP_OID [OID=TYPE:VALUE ...]
  snmp_trap.py inform HOST:PORT COMMUNITY UPTIME TRAP_OID [rid=N] [OID=TYPE:VALUE ...]   (retries until answered)
  snmp_trap.py v1  HOST:PORT COMMUNITY UPTIME ENTERPRISE AGENT_ADDR GENERIC SPECIFIC [OID=TYPE:VALUE ...]

TYPE is i (INTEGER), s (OCTET STRING), o (OBJECT IDENTIFIER), a (IpAddress), t (TimeTicks).
"""
import os
import socket
import sys


def tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def integer(v: int, tag: int = 0x02) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(tag, b)


def unsigned(v: int, tag: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return tlv(tag, b)


def oid(s: str) -> bytes:
    arcs = [int(x) for x in s.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def value(spec: str) -> bytes:
    t, v = spec.split(":", 1)
    return {"i": lambda: integer(int(v)), "s": lambda: tlv(0x04, v.encode()), "o": lambda: oid(v),
            "a": lambda: tlv(0x40, bytes(int(x) for x in v.split("."))), "t": lambda: unsigned(int(v), 0x43)}[t]()


def varbinds(items) -> bytes:
    return tlv(0x30, b"".join(tlv(0x30, oid(k) + value(v)) for k, v in (i.split("=", 1) for i in items)))


def main(argv):
    version, target, community, uptime = argv[1], argv[2], argv[3], int(argv[4])
    host, port = target.rsplit(":", 1)
    if version in ("v2c", "inform"):
        trap_oid, rest = argv[5], argv[6:]
        request_id = int(rest.pop(0).split("=", 1)[1]) if rest and rest[0].startswith("rid=") else 1
        vbs = varbinds([f"1.3.6.1.2.1.1.3.0=t:{uptime}", f"1.3.6.1.6.3.1.1.4.1.0=o:{trap_oid}"] + rest)
        pdu = tlv(0xA6 if version == "inform" else 0xA7, integer(request_id) + integer(0) + integer(0) + vbs)
        msg = tlv(0x30, integer(1) + tlv(0x04, community.encode()) + pdu)
    else:
        enterprise, agent, generic, specific, rest = argv[5], argv[6], int(argv[7]), int(argv[8]), argv[9:]
        pdu = tlv(0xA4, oid(enterprise) + tlv(0x40, bytes(int(x) for x in agent.split("."))) + integer(generic)
                  + integer(specific) + unsigned(uptime, 0x43) + varbinds(rest))
        msg = tlv(0x30, integer(0) + tlv(0x04, community.encode()) + pdu)
    if host == "-":
        print(msg.hex())
        return
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if version != "inform":
        sock.sendto(msg, (host, int(port)))
        return
    # An inform is retransmitted, with the same request id, until a Response-PDU answers it (RFC 3416 §4.2.7)
    timeout, retries = float(os.environ.get("INFORM_TIMEOUT", "2")), int(os.environ.get("INFORM_RETRIES", "30"))
    sock.settimeout(timeout)
    for attempt in range(1, retries + 1):
        sock.sendto(msg, (host, int(port)))
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            print(f"inform request-id {request_id}: no response (attempt {attempt})", flush=True)
            continue
        if b"\xa2" in data:
            print(f"inform request-id {request_id}: RESPONSE after {attempt} attempt(s)", flush=True)
            return
    print(f"inform request-id {request_id}: GAVE UP", flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
