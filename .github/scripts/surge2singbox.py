#!/usr/bin/env python3
# Convert Surge rule-set (.list) files into sing-box source rule-sets (.json).
#
# This is NOT sing-box's internal `rule-set compile` (which only reads sing-box
# JSON) nor `rule-set convert` (which only reads AdGuard). Surge and sing-box
# use different rule syntax; this bridges them, mapping the Surge line types
# that have a faithful sing-box equivalent and loudly skipping the rest.
#
# Semantic notes (verified against sing-box 1.14.0-alpha.43 empirically):
#   - Surge DOMAIN-SUFFIX,x  ==  sing-box domain_suffix ["x"] (no leading dot):
#     matches apex x AND *.x, but NOT "notx" — identical to Surge.
#   - domain / domain_suffix / domain_keyword / ip_cidr placed in ONE rule
#     object are OR-combined (a connection matches if it matches ANY), which is
#     exactly Surge's "match any line" rule-set semantics.
#
# Input:  a manifest file (default: list.txt), one URL per line, each pointing
#         to a Surge .list. '#'/'//' comment lines and blanks are ignored.
# Output: <outdir>/<name>.json per URL, where <name> is the URL's basename with
#         .list stripped (WeChat.list -> WeChat.json).
#
# Usage:  surge2singbox.py <manifest> <outdir>
# Exit:   nonzero if ANY url failed to fetch or produced zero rules (so a
#         silent drop is always visible), after processing every url it can.

import json
import os
import re
import sys
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
        else:
            skipped[rtype] = skipped.get(rtype, 0) + 1

    rule = {k: v for k, v in buckets.items() if v}
    doc = {"version": RULESET_VERSION, "rules": [rule] if rule else []}
    total = sum(len(v) for v in buckets.values())
    return doc, total, skipped


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
            req = urllib.request.Request(fetch, headers={"User-Agent": "surge2singbox"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", "replace")
        except Exception as e:
            print("  FETCH FAILED: %s" % e, file=sys.stderr)
            failures += 1
            continue

        doc, total, skipped = convert_surge(text)
        out = os.path.join(outdir, name + ".json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        print("  -> %s : %d rules" % (out, total))
        if skipped:
            print("  skipped unsupported: " + ", ".join("%s x%d" % (t, n) for t, n in sorted(skipped.items())))
        if total == 0:
            print("  WARNING: zero convertible rules", file=sys.stderr)
            failures += 1

    if failures:
        sys.exit("done with %d failure(s)" % failures)
    print("all rule-sets converted")


if __name__ == "__main__":
    main()
