#!/usr/bin/env python3
"""
AT&T ASN Checker & Root Domain Extractor
-----------------------------------------
1. Resolves AT&T ASNs via the BGPView public API.
2. Fetches all IPv4/IPv6 prefixes announced by those ASNs.
3. Extracts root domains from two sources:
   - Certificate Transparency logs (crt.sh)
   - Reverse PTR lookups on prefix gateway IPs
4. Writes unique, sorted root domains to stdout and to att_domains.txt.

Usage:
    python3 att_asn_domains.py [--output att_domains.txt]
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Known AT&T ASNs (well-documented, publicly available information)
# ---------------------------------------------------------------------------
ATT_ASNS = {
    2386:  "AT&T Data Communications Services",
    2387:  "AT&T",
    6341:  "AT&T",
    7011:  "AT&T",
    7018:  "AT&T Services, Inc.",
    7046:  "AT&T/MIS",
    7132:  "AT&T Internet Services",
    11722: "AT&T Wireless",
    12271: "AT&T",
    13979: "AT&T",
    20001: "AT&T Broadband",
    21928: "T-Mobile / AT&T Mobility",
    22394: "AT&T Wireless",
    35995: "AT&T Mobility",
    46164: "AT&T",
}

BGPVIEW_BASE = "https://api.bgpview.io"
CRTSH_BASE   = "https://crt.sh"
REQUEST_DELAY = 0.5   # seconds between API calls to be polite

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, timeout: int = 20) -> dict | None:
    """Fetch JSON from *url* and return parsed dict, or None on error."""
    req = Request(url, headers={"User-Agent": "att-asn-domain-extractor/1.0"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, HTTPError, json.JSONDecodeError) as exc:
        print(f"  [warn] GET {url} → {exc}", file=sys.stderr)
        return None


def extract_root_domain(fqdn: str) -> str | None:
    """
    Return the registrable (eTLD+1) root domain from *fqdn*.
    Uses a simple two-label heuristic that works for .com/.net/.org etc.
    For compound TLDs (co.uk, com.au …) we keep three labels.
    """
    fqdn = fqdn.strip().lower().rstrip(".")
    if not fqdn:
        return None
    # Strip leading wildcards
    fqdn = re.sub(r"^\*\.", "", fqdn)
    parts = fqdn.split(".")
    if len(parts) < 2:
        return None
    # Simple compound-TLD detection: second-to-last label is short (≤3 chars)
    # e.g. co.uk, com.au, net.au, org.uk …
    if len(parts) >= 3 and len(parts[-2]) <= 3 and parts[-2].isalpha():
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# BGPView helpers
# ---------------------------------------------------------------------------

def get_asn_prefixes(asn: int) -> list[str]:
    """Return list of CIDR prefixes announced by *asn*."""
    url = f"{BGPVIEW_BASE}/asn/{asn}/prefixes"
    data = _get(url)
    prefixes = []
    if data and data.get("status") == "ok":
        for item in data.get("data", {}).get("ipv4_prefixes", []):
            pfx = item.get("prefix")
            if pfx:
                prefixes.append(pfx)
        for item in data.get("data", {}).get("ipv6_prefixes", []):
            pfx = item.get("prefix")
            if pfx:
                prefixes.append(pfx)
    return prefixes


def verify_asn_org(asn: int) -> str:
    """Return the organisation name for *asn* from BGPView."""
    url = f"{BGPVIEW_BASE}/asn/{asn}"
    data = _get(url)
    if data and data.get("status") == "ok":
        return data.get("data", {}).get("description_short", "")
    return ""


# ---------------------------------------------------------------------------
# Domain extraction: crt.sh
# ---------------------------------------------------------------------------

def domains_from_crtsh_org(org_name: str) -> set[str]:
    """
    Query crt.sh for certificates issued to *org_name* and return root domains.
    Uses the JSON endpoint.
    """
    # URL-encode just the spaces / special chars we need
    safe = org_name.replace(" ", "%20").replace("&", "%26")
    url = f"{CRTSH_BASE}/?o={safe}&output=json"
    data = _get(url, timeout=30)
    roots: set[str] = set()
    if not isinstance(data, list):
        return roots
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            rd = extract_root_domain(name.strip())
            if rd:
                roots.add(rd)
    return roots


def domains_from_crtsh_asn(asn: int) -> set[str]:
    """
    crt.sh also supports ?asn= queries.
    """
    url = f"{CRTSH_BASE}/?asn={asn}&output=json"
    data = _get(url, timeout=30)
    roots: set[str] = set()
    if not isinstance(data, list):
        return roots
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            rd = extract_root_domain(name.strip())
            if rd:
                roots.add(rd)
    return roots


# ---------------------------------------------------------------------------
# Domain extraction: reverse PTR
# ---------------------------------------------------------------------------

def ptr_sample_from_prefix(cidr: str, sample_size: int = 5) -> set[str]:
    """
    Do reverse-PTR lookups on up to *sample_size* host IPs from *cidr*.
    Return any root domains found.
    """
    roots: set[str] = set()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return roots

    hosts = list(net.hosts())
    # Sample first, middle, last hosts to keep it quick
    if len(hosts) <= sample_size:
        sampled = hosts
    else:
        step = len(hosts) // (sample_size - 1)
        sampled = [hosts[i * step] for i in range(sample_size - 1)] + [hosts[-1]]

    for ip in sampled:
        try:
            fqdn = socket.gethostbyaddr(str(ip))[0]
            rd = extract_root_domain(fqdn)
            if rd:
                roots.add(rd)
        except (socket.herror, socket.gaierror, OSError):
            pass
    return roots


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Extract root domains from AT&T ASNs")
    parser.add_argument("--output", default="att_domains.txt",
                        help="Output file for discovered root domains (default: att_domains.txt)")
    parser.add_argument("--no-ptr", action="store_true",
                        help="Skip reverse-PTR lookups (faster)")
    parser.add_argument("--no-crt", action="store_true",
                        help="Skip certificate transparency lookups")
    parser.add_argument("--asn", type=int, nargs="*",
                        help="Override ASN list (space-separated integers)")
    args = parser.parse_args()

    asns = {int(a): f"User-supplied ASN{a}" for a in args.asn} if args.asn else ATT_ASNS

    all_roots: set[str] = set()
    all_prefixes: list[str] = []

    print("=" * 60)
    print("  AT&T ASN Checker & Root Domain Extractor")
    print("=" * 60)

    # ── Step 1: verify ASNs and collect prefixes ──────────────────────────
    print("\n[1/3] Verifying ASNs and fetching IP prefixes …\n")
    for asn, label in asns.items():
        org = verify_asn_org(asn)
        print(f"  AS{asn:<6}  {label}  →  BGPView org: '{org or 'N/A'}'")
        time.sleep(REQUEST_DELAY)
        prefixes = get_asn_prefixes(asn)
        print(f"            {len(prefixes)} prefixes found")
        all_prefixes.extend(prefixes)
        time.sleep(REQUEST_DELAY)

    print(f"\n  Total prefixes: {len(all_prefixes)}")

    # ── Step 2: Certificate Transparency ─────────────────────────────────
    if not args.no_crt:
        print("\n[2/3] Querying certificate transparency logs (crt.sh) …\n")

        # By organisation name
        for org_query in ["AT&T", "AT&T Inc", "AT&T Services", "AT&T Mobility"]:
            print(f"  org: {org_query!r}", end=" … ", flush=True)
            roots = domains_from_crtsh_org(org_query)
            print(f"{len(roots)} root domains")
            all_roots.update(roots)
            time.sleep(REQUEST_DELAY)

        # By ASN
        for asn in list(asns)[:5]:   # limit to avoid rate limits
            print(f"  ASN {asn}:", end=" … ", flush=True)
            roots = domains_from_crtsh_asn(asn)
            print(f"{len(roots)} root domains")
            all_roots.update(roots)
            time.sleep(REQUEST_DELAY)
    else:
        print("\n[2/3] Certificate transparency lookups skipped (--no-crt).\n")

    # ── Step 3: Reverse PTR sampling ─────────────────────────────────────
    if not args.no_ptr:
        print("\n[3/3] Sampling reverse-PTR lookups across prefixes …\n")
        for cidr in all_prefixes:
            roots = ptr_sample_from_prefix(cidr, sample_size=3)
            if roots:
                print(f"  {cidr:<22} → {', '.join(sorted(roots))}")
            all_roots.update(roots)
    else:
        print("\n[3/3] Reverse-PTR lookups skipped (--no-ptr).\n")

    # ── Output ────────────────────────────────────────────────────────────
    sorted_roots = sorted(all_roots)
    print(f"\n{'=' * 60}")
    print(f"  {len(sorted_roots)} unique root domains discovered")
    print(f"{'=' * 60}\n")
    for rd in sorted_roots:
        print(rd)

    with open(args.output, "w") as fh:
        fh.write("\n".join(sorted_roots) + "\n")
    print(f"\n[✓] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
