#!/usr/bin/env python3
# Expand an ASN manifest into sing-box source rule-sets (.json).
#
# sing-box has no ip_asn rule item, so "send this operator's IP space direct"
# has to be resolved to prefixes at build time. This is the standalone
# counterpart to the IP-ASN handling inside surge2singbox.py, whose
# fetch_asn_cidrs() it reuses: that one expands ASNs a Surge list asks for,
# this one expands ASNs we pick ourselves.
#
# Why not just paste the prefixes into source/*.json: a pasted list is a
# snapshot. It is accurate the day it is written and silently wrong afterwards,
# because the operator adds capacity by announcing new prefixes and nothing in
# the repo notices — and the failure is invisible, since traffic to the new
# prefixes still works, it just leaves through the wrong exit. Regenerating on
# the daily schedule tracks BGP for free.
#
# Manifest format (default: asn.txt), one output set per line:
#   <output-name>: <ASN> [<ASN> ...]
# '#' comments and blank lines are ignored.
#
# Usage:  asn2singbox.py <manifest> <outdir>
# Needs:  `sing-box` on PATH (to decode meta-rules-dat's asn/AS<n>.srs).
# Exit:   nonzero if any ASN fails to expand. Same reasoning as the converter:
#         a missing IP rule flips routing direction without breaking anything,
#         so it must fail the build rather than print a note.

import json
import os
import re
import sys

from surge2singbox import RULESET_VERSION, fetch_asn_cidrs

LINE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)\s*:\s*(?P<asns>[0-9\s]+)$")


def parse_manifest(path):
    sets = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = LINE.match(line)
            if not m:
                raise ValueError("%s:%d: expected '<name>: <ASN> [<ASN> ...]', got %r"
                                 % (path, lineno, raw.rstrip()))
            sets.append((m.group("name"), m.group("asns").split()))
    return sets


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: asn2singbox.py <manifest> <outdir>")
    manifest, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    failures = 0
    for name, asns in parse_manifest(manifest):
        print("== %s  <-  %s" % (name, " ".join("AS" + a for a in asns)))
        cidrs = set()
        ok = True
        for asn in asns:
            try:
                got = fetch_asn_cidrs(asn)
            except Exception as e:
                print("  AS%s FAILED: %s" % (asn, e), file=sys.stderr)
                failures += 1
                ok = False
                continue
            print("  AS%s -> %d prefixes" % (asn, len(got)))
            cidrs.update(got)
        if not ok:
            # Writing a partial set would be worse than writing none: the
            # compile step would happily publish a rule-set that silently
            # covers less than it claims.
            continue
        doc = {"version": RULESET_VERSION, "rules": [{"ip_cidr": sorted(cidrs)}]}
        out = os.path.join(outdir, name + ".json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("  -> %s : %d prefixes" % (out, len(cidrs)))

    if failures:
        sys.exit("done with %d failure(s)" % failures)
    print("all ASN sets expanded")


if __name__ == "__main__":
    main()
