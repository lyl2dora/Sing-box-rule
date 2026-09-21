#!/usr/bin/env python3
# Convert Surge rule-set (.list) files into sing-box source rule-sets (.json).
#
# This is NOT sing-box's internal `rule-set compile` (which only reads sing-box
# JSON) nor `rule-set convert` (which only reads AdGuard). Surge and sing-box
# use different rule syntax; this bridges the Surge line types that have a
# faithful sing-box equivalent, expands the ones that need a build-time lookup,
# and fails on the ones whose loss would change routing.
#
# Semantic notes (verified against sing-box 1.14.0-alpha.43 empirically):
#   - Surge DOMAIN-SUFFIX,x  ==  sing-box domain_suffix ["x"] (no leading dot):
#     matches apex x AND *.x, but NOT "notx" — identical to Surge.
#   - domain / domain_suffix / domain_keyword / ip_cidr placed in ONE rule
#     object are OR-combined (a connection matches if it matches ANY), which is
#     exactly Surge's "match any line" rule-set semantics.
#   - Surge IP-ASN,<n> has no sing-box counterpart: sing-box has no ip_asn rule
#     item, so the ASN must be resolved to prefixes here, at build time. See
#     fetch_asn_cidrs().
#
# Why a dropped IP rule is a hard failure and a dropped domain rule is not:
#   Losing a domain line only narrows coverage — the traffic falls through to
#   the config's `final` outbound, which for a proxy-first config is usually
#   still a working direction. Losing an IP line REVERSES the decision for any
#   client that reaches the service by IP literal: traffic that should have
#   gone direct is proxied instead. Nothing breaks, nothing logs, the
#   connection succeeds — it just leaves through the wrong exit, indefinitely.
#   So IP-shaped types we cannot translate abort the run (see IP_SHAPED).
#
# Input:  a manifest file (default: list.txt), one URL per line, each pointing
#         to a Surge .list. '#'/'//' comment lines and blanks are ignored.
# Output: <outdir>/<name>.json per URL, where <name> is the URL's basename with
#         .list stripped (WeChat.list -> WeChat.json).
#
# Usage:  surge2singbox.py <manifest> <outdir>
# Needs:  `sing-box` on PATH, but only when a list contains IP-ASN.
# Exit:   nonzero if ANY url failed to fetch, produced zero rules, or dropped
#         an IP-shaped rule type (so a silent drop is always visible), after
#         processing every url it can.

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

RULESET_VERSION = 3  # compile downgrades to the minimal version the rules need

# Surge line type -> sing-box source array key. Types absent here are skipped.
DOMAIN_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
}
IP_TYPES = {"IP-CIDR", "IP-CIDR6"}

# Surge line types that carry IP-layer meaning. Dropping any of these silently
# flips routing direction (see the header), so if one ends up in `skipped` the
# run fails instead of logging. IP-ASN is listed here as a backstop: it is
# handled below, and only lands in `skipped` if that handling is ever removed.
IP_SHAPED = {
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "IP-ASN6", "IP-SUFFIX",
    "GEOIP", "SRC-IP-CIDR", "SRC-IP-ASN", "SRC-GEOIP",
}

# MetaCubeX/meta-rules-dat rebuilds one rule-set per ASN daily from BGP data.
ASN_SRS_URL = "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/asn/AS%s.srs"

_asn_cache = {}


def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "surge2singbox"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_asn_cidrs(asn):
    # sing-box cannot match on ASN, so IP-ASN,<n> is expanded to that ASN's
    # announced prefixes at build time. The source is meta-rules-dat's daily
    # asn/AS<n>.srs, decoded with the same pinned sing-box the workflow already
    # installed for `rule-set compile` — no extra toolchain.
    if asn in _asn_cache:
        return _asn_cache[asn]
    if not asn.isdigit():
        raise ValueError("IP-ASN value is not numeric: %r" % asn)
    if not shutil.which("sing-box"):
        raise RuntimeError("IP-ASN,%s needs `sing-box` on PATH to decode AS%s.srs" % (asn, asn))
    tmp = tempfile.mkdtemp(prefix="asn-")
    try:
        srs = os.path.join(tmp, "AS%s.srs" % asn)
        out = os.path.join(tmp, "AS%s.json" % asn)
        with open(srs, "wb") as f:
            f.write(http_get(ASN_SRS_URL % asn))
        subprocess.run(
            ["sing-box", "rule-set", "decompile", srs, "-o", out],
            check=True, stdout=subprocess.DEVNULL,
        )
        with open(out, "r", encoding="utf-8") as f:
            doc = json.load(f)
        cidrs = [c for rule in doc.get("rules", []) for c in rule.get("ip_cidr", [])]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not cidrs:
        raise RuntimeError("AS%s expanded to zero prefixes" % asn)
    _asn_cache[asn] = cidrs
    return cidrs


def normalize_url(url):
    # github.com/U/R/blob/BRANCH/PATH -> raw.githubusercontent.com/U/R/BRANCH/PATH
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/(.+)", url)
    if m:
        return "https://raw.githubusercontent.com/%s/%s/%s" % (m.group(1), m.group(2), m.group(3))
    # /raw/... URLs 302-redirect to raw content; urllib follows redirects.
    return url


def name_from_url(url):
    base = url.rstrip("/").split("/")[-1]
    if base.lower().endswith(".list"):
        base = base[:-5]
    return base


def wildcard_to_regex(pat):
    # Surge DOMAIN-WILDCARD: * = any run, ? = single char.
    out = re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".")
    return "^" + out + "$"


def convert_surge(text):
    buckets = {k: [] for k in ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr")}
    seen = {k: set() for k in buckets}
    skipped = {}
    expanded = []

    def add(key, val):
        if val and val not in seen[key]:
            seen[key].add(val)
            buckets[key].append(val)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        parts = [p.strip() for p in line.split(",")]
        rtype = parts[0].upper()
        val = parts[1] if len(parts) > 1 else ""
        if rtype in DOMAIN_MAP:
            add(DOMAIN_MAP[rtype], val)
        elif rtype == "DOMAIN-WILDCARD":
            add("domain_regex", wildcard_to_regex(val))
        elif rtype in IP_TYPES:
            add("ip_cidr", val)  # drop trailing modifiers like no-resolve
        elif rtype == "IP-ASN":
            cidrs = fetch_asn_cidrs(val)  # raises -> caller counts a failure
            for cidr in cidrs:
                add("ip_cidr", cidr)
            expanded.append((val, len(cidrs)))
        else:
            skipped[rtype] = skipped.get(rtype, 0) + 1

    rule = {k: v for k, v in buckets.items() if v}
    doc = {"version": RULESET_VERSION, "rules": [rule] if rule else []}
    total = sum(len(v) for v in buckets.values())
    return doc, total, skipped, expanded


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: surge2singbox.py <manifest> <outdir>")
    manifest, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    with open(manifest, "r", encoding="utf-8") as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]

    failures = 0
    for url in urls:
        name = name_from_url(url)
        fetch = normalize_url(url)
        print("== %s  <-  %s" % (name, fetch))
        try:
            text = http_get(fetch).decode("utf-8", "replace")
        except Exception as e:
            print("  FETCH FAILED: %s" % e, file=sys.stderr)
            failures += 1
            continue

        try:
            doc, total, skipped, expanded = convert_surge(text)
        except Exception as e:
            print("  CONVERT FAILED: %s" % e, file=sys.stderr)
            failures += 1
            continue

        out = os.path.join(outdir, name + ".json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        print("  -> %s : %d rules" % (out, total))
        for asn, n in expanded:
            print("  expanded IP-ASN,%s -> %d prefixes" % (asn, n))
        if skipped:
            print("  skipped unsupported: " + ", ".join("%s x%d" % (t, n) for t, n in sorted(skipped.items())))
        dropped_ip = sorted(t for t in skipped if t in IP_SHAPED)
        if dropped_ip:
            # See the header: an untranslated IP rule flips routing direction
            # silently, so this is an error rather than a note.
            print("  DROPPED IP-LAYER RULE TYPE(S): %s" % ", ".join(dropped_ip), file=sys.stderr)
            failures += 1
        if total == 0:
            print("  WARNING: zero convertible rules", file=sys.stderr)
            failures += 1

    if failures:
        sys.exit("done with %d failure(s)" % failures)
    print("all rule-sets converted")


if __name__ == "__main__":
    main()
