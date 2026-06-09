#!/usr/bin/env python3
"""
AT&T ASN Checker & Root Domain Extractor
-----------------------------------------
1. Confirms AT&T ASNs via the RIPEstat public API (fallback: BGPView).
2. Fetches all IPv4/IPv6 prefixes announced by those ASNs.
3. Extracts root domains via:
   - Certificate Transparency logs (crt.sh)
   - Reverse PTR lookups (optional)
4. Writes unique, sorted root domains to stdout and to att_domains.txt.

Usage:
    python3 asn.py [--output att_domains.txt] [--no-ptr] [--no-crt]
                   [--asn 7018 7132 ...]
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
# Known AT&T ASNs (publicly documented)
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

RIPESTAT_BASE = "https://stat.ripe.net/data"
BGPVIEW_BASE  = "https://api.bgpview.io"
CRTSH_BASE    = "https://crt.sh"
REQUEST_DELAY = 1.0   # seconds between API calls
MAX_RETRIES   = 3

# ---------------------------------------------------------------------------
# HTTP helper with retry
# ---------------------------------------------------------------------------

def _get(url: str, timeout: int = 30, retries: int = MAX_RETRIES) -> dict | list | None:
    """Fetch JSON from *url* with retry/backoff. Returns parsed JSON or None."""
    req = Request(url, headers={"User-Agent": "att-asn-domain-extractor/1.0",
                                "Accept": "application/json"})
    for attempt in range(1, retries + 1):
        try:
            with urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw)
        except HTTPError as exc:
            if exc.code == 429 or exc.code >= 500:
                wait = attempt * 3
                print(f"  [retry {attempt}/{retries}] HTTP {exc.code} — waiting {wait}s …",
                      file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"  [warn] GET {url} → HTTP {exc.code}", file=sys.stderr)
                return None
        except (URLError, OSError) as exc:
            wait = attempt * 2
            print(f"  [retry {attempt}/{retries}] {exc} — waiting {wait}s …", file=sys.stderr)
            time.sleep(wait)
        except json.JSONDecodeError as exc:
            print(f"  [warn] JSON parse error for {url}: {exc}", file=sys.stderr)
            return None
    print(f"  [error] Failed after {retries} attempts: {url}", file=sys.stderr)
    return None

# ---------------------------------------------------------------------------
# Root domain extractor
# ---------------------------------------------------------------------------

def extract_root_domain(fqdn: str) -> str | None:
    """Return the registrable (eTLD+1) root domain, or None."""
    fqdn = fqdn.strip().lower().rstrip(".")
    if not fqdn:
        return None
    fqdn = re.sub(r"^\*\.", "", fqdn)          # strip wildcard prefix
    parts = fqdn.split(".")
    if len(parts) < 2:
        return None
    # Compound TLD heuristic: e.g. co.uk, com.au, net.nz
    if len(parts) >= 3 and len(parts[-2]) <= 3 and parts[-2].isalpha():
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# ---------------------------------------------------------------------------
# RIPEstat helpers (primary)
# ---------------------------------------------------------------------------

def ripestat_asn_info(asn: int) -> str:
    """Return organisation name for *asn* from RIPEstat."""
    url = f"{RIPESTAT_BASE}/as-overview/data.json?resource=AS{asn}"
    data = _get(url)
    if data and data.get("status") == "ok":
        return data.get("data", {}).get("holder", "")
    return ""


def ripestat_prefixes(asn: int) -> list[str]:
    """Return list of prefixes announced by *asn* via RIPEstat."""
    url = f"{RIPESTAT_BASE}/announced-prefixes/data.json?resource=AS{asn}"
    data = _get(url)
    prefixes = []
    if data and data.get("status") == "ok":
        for item in data.get("data", {}).get("prefixes", []):
            pfx = item.get("prefix")
            if pfx:
                prefixes.append(pfx)
    return prefixes

# ---------------------------------------------------------------------------
# BGPView helpers (fallback)
# ---------------------------------------------------------------------------

def bgpview_asn_info(asn: int) -> str:
    url = f"{BGPVIEW_BASE}/asn/{asn}"
    data = _get(url)
    if data and data.get("status") == "ok":
        return data.get("data", {}).get("description_short", "")
    return ""


def bgpview_prefixes(asn: int) -> list[str]:
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

# ---------------------------------------------------------------------------
# Unified ASN info with fallback
# ---------------------------------------------------------------------------

def get_asn_info(asn: int) -> tuple[str, list[str]]:
    """Return (org_name, [prefixes]) trying RIPEstat first, BGPView as fallback."""
    org = ripestat_asn_info(asn)
    prefixes = ripestat_prefixes(asn)
    if not org and not prefixes:
        org = bgpview_asn_info(asn)
        prefixes = bgpview_prefixes(asn)
    return org, prefixes

# ---------------------------------------------------------------------------
# crt.sh domain extraction
# ---------------------------------------------------------------------------

def _parse_crtsh(data) -> set[str]:
    roots: set[str] = set()
    if not isinstance(data, list):
        return roots
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            rd = extract_root_domain(name.strip())
            if rd:
                roots.add(rd)
    return roots


def domains_from_crtsh_org(org_name: str) -> set[str]:
    safe = org_name.replace(" ", "%20").replace("&", "%26")
    return _parse_crtsh(_get(f"{CRTSH_BASE}/?o={safe}&output=json", timeout=60))


def domains_from_crtsh_asn(asn: int) -> set[str]:
    return _parse_crtsh(_get(f"{CRTSH_BASE}/?asn={asn}&output=json", timeout=60))

# ---------------------------------------------------------------------------
# Reverse PTR sampling
# ---------------------------------------------------------------------------

def ptr_sample_from_prefix(cidr: str, sample_size: int = 3) -> set[str]:
    roots: set[str] = set()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return roots
    hosts = list(net.hosts())
    if not hosts:
        return roots
    if len(hosts) <= sample_size:
        sampled = hosts
    else:
        step = max(1, len(hosts) // (sample_size - 1))
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
    parser = argparse.ArgumentParser(description="Check AT&T ASNs and extract root domains")
    parser.add_argument("--output", default="att_domains.txt",
                        help="Output file (default: att_domains.txt)")
    parser.add_argument("--no-ptr", action="store_true",
                        help="Skip reverse-PTR lookups (faster)")
    parser.add_argument("--no-crt", action="store_true",
                        help="Skip certificate transparency lookups")
    parser.add_argument("--asn", type=int, nargs="*",
                        help="Custom ASN list (overrides built-in AT&T ASNs)")
    args = parser.parse_args()

    asns = {int(a): f"Custom ASN {a}" for a in args.asn} if args.asn else ATT_ASNS

    all_roots: set[str] = set()
    all_prefixes: list[str] = []

    print("=" * 60)
    print("  AT&T ASN Checker & Root Domain Extractor")
    print("=" * 60)

    # ── Step 1: ASN verification + prefix collection ──────────────────────
    print("\n[1/3] Verifying ASNs and collecting IP prefixes …\n")
    for asn, label in asns.items():
        print(f"  AS{asn:<6}  {label}", end=" … ", flush=True)
        org, prefixes = get_asn_info(asn)
        print(f"org='{org or 'N/A'}', {len(prefixes)} prefixes")
        all_prefixes.extend(prefixes)
        time.sleep(REQUEST_DELAY)

    all_prefixes = sorted(set(all_prefixes))
    print(f"\n  Total unique prefixes: {len(all_prefixes)}")

    # ── Step 2: Certificate Transparency ─────────────────────────────────
    if not args.no_crt:
        print("\n[2/3] Querying crt.sh certificate transparency logs …\n")
        for org_query in ["AT&T", "AT&T Inc.", "AT&T Services", "AT&T Mobility",
                          "AT&T Corp", "AT&T Intellectual Property"]:
            print(f"  org={org_query!r}", end=" … ", flush=True)
            roots = domains_from_crtsh_org(org_query)
            print(f"{len(roots)} root domains")
            all_roots.update(roots)
            time.sleep(REQUEST_DELAY)

        for asn in list(asns)[:8]:
            print(f"  AS{asn}", end=" … ", flush=True)
            roots = domains_from_crtsh_asn(asn)
            print(f"{len(roots)} root domains")
            all_roots.update(roots)
            time.sleep(REQUEST_DELAY)
    else:
        print("\n[2/3] Certificate transparency lookups skipped (--no-crt).\n")

    # ── Step 3: Reverse PTR ───────────────────────────────────────────────
    if not args.no_ptr and all_prefixes:
        print("\n[3/3] Sampling reverse-PTR lookups …\n")
        for cidr in all_prefixes:
            roots = ptr_sample_from_prefix(cidr)
            if roots:
                print(f"  {cidr:<22} → {', '.join(sorted(roots))}")
            all_roots.update(roots)
    elif args.no_ptr:
        print("\n[3/3] Reverse-PTR lookups skipped (--no-ptr).\n")
    else:
        print("\n[3/3] No prefixes collected; skipping PTR lookups.\n")

    # ── Output ────────────────────────────────────────────────────────────
    sorted_roots = sorted(all_roots)
    print(f"\n{'=' * 60}")
    print(f"  {len(sorted_roots)} unique root domains discovered")
    print(f"{'=' * 60}\n")
    for rd in sorted_roots:
        print(rd)

    with open(args.output, "w") as fh:
        fh.write("\n".join(sorted_roots) + ("\n" if sorted_roots else ""))
    print(f"\n[✓] Saved to: {args.output}")


if __name__ == "__main__":
    main()
