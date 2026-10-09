#!/usr/bin/env python3
"""A test number authority for the number-attestation demo (Number Attestation Profile N§3; demo fixture only).

Two carriers under one test STI-CA, with certificates valid around the real clock:
  A  "Carrier Example"  x5u https://cr.carrier-a.example/sti.pem  TNAuthList: one 15551234567, range 15552000000+1000
  B  "Carrier B"        x5u https://cr.carrier-b.example/sti.pem  TNAuthList: one 15551234567 (the number, ported)

  tn_issuer.py policy OUT.json                 the relying party's policy: the STI-CA anchor, both x5u chains and
                                               the gateway's delegate chain
  tn_issuer.py bind A|B TN DID OUT.jws [AGE]   a binding of TN to DID, signed by that carrier, valid for one day,
                                               issued AGE seconds ago (default 60)
  tn_issuer.py gateway-key OUT.pem             the gateway's delegate-certificate key (PKCS#8 PEM), for `assert`
                                               (N§4.1); its chain is served at https://gw.example/sti.pem

The gateway's certificate is an RFC 9060 delegate: Carrier Example's delegation CA (a range of 100 numbers from
15551234500) issues "Enterprise Example" a leaf for 15551234567 only.

Keys are the vector generator's deterministic test keys: never use them for anything real.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from dsipvec.gen import tnbinding as G  # noqa: E402

NOW = int(time.time())
ROOT = G.cert(G.name((G.C, "US"), (G.O, "Example STI-CA"), (G.CN, "Example STI-CA Root")), G.key("root"), None,
              [G.bc(True), G.CA_KU], 1, nb=NOW - 86400 * 365, na=NOW + 86400 * 365)
INTER = G.cert(G.name((G.C, "US"), (G.O, "Example STI-CA"), (G.CN, "Example STI-CA Issuing 1")), G.key("inter"), ROOT,
               [G.bc(True, 1), G.CA_KU], 2, nb=NOW - 86400 * 300, na=NOW + 86400 * 300)
CARRIERS = {
    "A": ("Carrier Example", "https://cr.carrier-a.example/sti.pem", "sp",
          G.tnauth(G.tn_one("15551234567"), G.tn_range("15552000000", 1000))),
    "B": ("Carrier B", "https://cr.carrier-b.example/sti.pem", "sp-b", G.tnauth(G.tn_one("15551234567"))),
}


SPCA = G.cert(G.name((G.O, "Carrier Example"), (G.CN, "Carrier Example Delegation CA")), G.key("sp-ca"), INTER,
              [G.bc(True, 0), G.CA_KU, G.tnauth(G.tn_range("15551234500", 100))], 11, nb=NOW - 86400 * 30, na=NOW + 86400 * 90)
DELEGATE = G.cert(G.name((G.O, "Enterprise Example"), (G.CN, "Delegate")), G.key("delegate"), SPCA,
                  [G.LEAF_KU, G.tnauth(G.tn_one("15551234567"))], 12, nb=NOW - 86400 * 30, na=NOW + 86400 * 90)
GW_X5U = "https://gw.example/sti.pem"


def leaf(c: str) -> G.Cert:
    name, _, k, tn = CARRIERS[c]
    return G.cert(G.name((G.C, "US"), (G.O, name), (G.CN, f"SHAKEN {name}")), G.key(k), INTER, [G.LEAF_KU, tn],
                  10 + ord(c), nb=NOW - 86400 * 30, na=NOW + 86400 * 90)


def main(argv: list[str]) -> int:
    if argv[:1] == ["policy"] and len(argv) == 2:
        certificates = {CARRIERS[c][1]: G.pem(leaf(c), INTER) for c in CARRIERS}
        certificates[GW_X5U] = G.pem(DELEGATE, SPCA, INTER)
        policy = {"trust_anchors": [ROOT.b64()], "certificates": certificates,
                  "spc_numbers": {}, "require_status": False, "status": {}}
        Path(argv[1]).write_text(json.dumps(policy, indent=1))
        return 0
    if argv[:1] == ["gateway-key"] and len(argv) == 2:
        Path(argv[1]).write_text(G.key_pem(DELEGATE.key))
        return 0
    if argv[:1] == ["bind"] and len(argv) in (5, 6):
        c, tn, did, out = argv[1:5]
        age = int(argv[5]) if len(argv) == 6 else 60
        ulid = G.JTI[:-3] + f"{(NOW - age) % 1000:03d}"
        payload = {"tn": tn, "did": did, "iat": NOW - age, "exp": NOW - age + 86400, "jti": ulid}
        binding = G.jws(G.header(x5u=CARRIERS[c][1]), payload, leaf(c).key)
        Path(out).write_text(binding + "\n")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
