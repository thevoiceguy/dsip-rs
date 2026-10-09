#!/usr/bin/env python3
"""A test number authority for the number-attestation demo (Number Attestation Profile N§3; demo fixture only).

Two carriers under one test STI-CA, with certificates valid around the real clock:
  A  "Carrier Example"  x5u https://cr.carrier-a.example/sti.pem  TNAuthList: one 15551234567, range 15552000000+1000
  B  "Carrier B"        x5u https://cr.carrier-b.example/sti.pem  TNAuthList: one 15551234567 (the number, ported)

  tn_issuer.py policy OUT.json                 the relying party's policy: the STI-CA anchor and both x5u chains
  tn_issuer.py bind A|B TN DID OUT.jws         a binding of TN to DID, signed by that carrier, valid for one day

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


def leaf(c: str) -> G.Cert:
    name, _, k, tn = CARRIERS[c]
    return G.cert(G.name((G.C, "US"), (G.O, name), (G.CN, f"SHAKEN {name}")), G.key(k), INTER, [G.LEAF_KU, tn],
                  10 + ord(c), nb=NOW - 86400 * 30, na=NOW + 86400 * 90)


def main(argv: list[str]) -> int:
    if argv[:1] == ["policy"] and len(argv) == 2:
        policy = {"trust_anchors": [ROOT.b64()],
                  "certificates": {CARRIERS[c][1]: G.pem(leaf(c), INTER) for c in CARRIERS},
                  "spc_numbers": {}, "require_status": False, "status": {}}
        Path(argv[1]).write_text(json.dumps(policy, indent=1))
        return 0
    if argv[:1] == ["bind"] and len(argv) == 5:
        c, tn, did, out = argv[1:]
        ulid = G.JTI[:-3] + f"{NOW % 1000:03d}"
        payload = {"tn": tn, "did": did, "iat": NOW - 60, "exp": NOW - 60 + 86400, "jti": ulid}
        binding = G.jws(G.header(x5u=CARRIERS[c][1]), payload, leaf(c).key)
        Path(out).write_text(binding + "\n")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
