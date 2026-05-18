#!/usr/bin/env python3
"""Check whether subdomains have CNAMEs pointing at unclaimed services (subdomain takeover).

For each subdomain, resolves the CNAME chain via raw UDP DNS and checks whether the
target service responds with an "unclaimed" fingerprint string.

Examples:
    tools/subdomain_takeover.py example.com
    tools/subdomain_takeover.py example.com --lang pt
    tools/subdomain_takeover.py example.com --subdomains subs.txt
    tools/subdomain_takeover.py example.com --json
    cat subs.txt | tools/subdomain_takeover.py example.com --subdomains -
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import struct
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg

USER_AGENT = make_user_agent("subdomain_takeover.py")
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "domain": "Domain",
        "checked": "Subdomains checked",
        "vulnerable_header": "Vulnerable",
        "status_vulnerable": "VULNERABLE — unclaimed service detected",
        "status_service_unconfirmed": "Service matched (HTTP check inconclusive)",
        "no_issues": "No issues found.",
        "cname_label": "CNAME",
        "service_label": "Service",
        "status_label": "Status",
        "err_domain": "error: invalid domain",
        "err_crt": "warning: crt.sh query failed",
        "warn_http": "warning: HTTP probe failed",
    },
    "pt": {
        "domain": "Domínio",
        "checked": "Subdomínios verificados",
        "vulnerable_header": "Vulneráveis",
        "status_vulnerable": "VULNERÁVEL — serviço não registado detetado",
        "status_service_unconfirmed": "Serviço identificado (verificação HTTP inconclusiva)",
        "no_issues": "Nenhum problema encontrado.",
        "cname_label": "CNAME",
        "service_label": "Serviço",
        "status_label": "Estado",
        "err_domain": "erro: domínio inválido",
        "err_crt": "aviso: consulta a crt.sh falhou",
        "warn_http": "aviso: sondagem HTTP falhou",
    },
}

# (cname_regex, http_fingerprint_string, service_name)
SERVICE_FINGERPRINTS = [
    (r"\.github\.io$",                           "There isn't a GitHub Pages site here",               "GitHub Pages"),
    (r"\.herokudns\.com$|\.herokuapp\.com$",      "No such app",                                        "Heroku"),
    (r"\.netlify\.app$|\.netlify\.com$",          "Not Found - Request ID",                             "Netlify"),
    (r"\.s3\.amazonaws\.com$|\.s3-website",       "NoSuchBucket|does not exist",                        "AWS S3"),
    (r"\.azurewebsites\.net$",                    "404 Web Site not found",                             "Azure"),
    (r"\.cloudapp\.net$",                         "404 - Web server is not found",                      "Azure CloudApp"),
    (r"\.ghost\.io$",                             "The thing you were looking for is no longer here",   "Ghost"),
    (r"\.surge\.sh$",                             "project not found",                                  "Surge"),
    (r"\.readme\.io$|\.readmessl\.com$",          "Project doesnt exist",                               "ReadMe"),
    (r"\.myshopify\.com$",                        "Sorry, this shop is currently unavailable",          "Shopify"),
    (r"\.fastly\.net$",                           "Fastly error: unknown domain",                       "Fastly"),
    (r"\.zendesk\.com$",                          "Help Center Closed",                                 "Zendesk"),
    (r"\.tumblr\.com$",                           "There's nothing here",                               "Tumblr"),
    (r"\.wpengine\.com$",                         "The site you were looking for couldn't be found",    "WP Engine"),
    (r"\.squarespace\.com$",                      "No Such Account",                                    "Squarespace"),
    (r"\.fly\.dev$",                              "404 Not Found",                                      "Fly.io"),
]


@dataclass
class SubdomainResult:
    subdomain: str
    cname: Optional[str]
    service: Optional[str]
    vulnerable: bool
    http_status: Optional[int]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Raw DNS CNAME resolution
# ---------------------------------------------------------------------------

def _build_dns_query(hostname: str) -> bytes:
    """Build a minimal DNS query packet for QTYPE=CNAME (5)."""
    txid = 0x1337
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)

    labels = b""
    for part in hostname.rstrip(".").split("."):
        encoded = part.encode("ascii")
        labels += bytes([len(encoded)]) + encoded
    labels += b"\x00"

    qtype = 5   # CNAME
    qclass = 1  # IN
    question = labels + struct.pack(">HH", qtype, qclass)
    return header + question


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name at `offset`, following compression pointers.

    Returns (name, new_offset) where new_offset is the position after the
    name field in the *original* message (i.e. after the first pointer if
    one was encountered, not after the pointer target).
    """
    parts: list[str] = []
    visited: set[int] = set()
    jumped = False
    end_offset = offset

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break

        # Compression pointer: top two bits are 11
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            jumped = True
            if ptr in visited:
                break
            visited.add(ptr)
            offset = ptr
            continue

        offset += 1
        parts.append(data[offset: offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(parts), end_offset


def dns_cname(hostname: str, timeout: float) -> Optional[str]:
    """Return the CNAME target for `hostname`, or None if none exists.

    Sends a single UDP query to 8.8.8.8:53 and parses the answer section.
    Returns None on NXDOMAIN, no-CNAME answer, or any error.
    """
    try:
        query = _build_dns_query(hostname)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, ("8.8.8.8", 53))
            response, _ = sock.recvfrom(512)
        finally:
            sock.close()
    except (socket.timeout, socket.error, OSError):
        return None

    if len(response) < 12:
        return None

    # Parse the header to find ANCOUNT (answer count)
    _txid, _flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", response[:12])

    if ancount == 0:
        return None

    # Skip the question section to find where answers start
    offset = 12
    for _ in range(qdcount):
        # Skip QNAME
        _name, offset = _decode_dns_name(response, offset)
        offset += 4  # QTYPE + QCLASS

    # Walk answer records looking for a CNAME (type 5)
    for _ in range(ancount):
        if offset >= len(response):
            break
        _name, offset = _decode_dns_name(response, offset)
        if offset + 10 > len(response):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", response[offset: offset + 10])
        offset += 10
        if rtype == 5:  # CNAME
            cname, _ = _decode_dns_name(response, offset)
            return cname.lower().rstrip(".") if cname else None
        offset += rdlength

    return None


# ---------------------------------------------------------------------------
# crt.sh enumeration (same approach as subfinder.py)
# ---------------------------------------------------------------------------

def query_crtsh(domain: str, timeout: float) -> list[str]:
    import urllib.parse
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return []
    seen: set[str] = set()
    for e in entries:
        for field_name in ("name_value", "common_name"):
            value = e.get(field_name) or ""
            for name in value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain) and "@" not in name and name != domain:
                    seen.add(name)
    return sorted(seen)


# ---------------------------------------------------------------------------
# HTTP fingerprint probe
# ---------------------------------------------------------------------------

def http_probe(subdomain: str, fingerprint: str, timeout: float) -> tuple[Optional[int], bool]:
    """GET http(s)://subdomain/ and check whether the fingerprint string appears in the body.

    Returns (http_status, fingerprint_found). Tries HTTPS first, then HTTP.
    Ignores certificate errors intentionally — a dangling CNAME may have an
    expired or mismatched cert, and we still want to read the body.
    """
    ctx = build_ssl_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(32768).decode("utf-8", errors="replace")
                found = bool(re.search(fingerprint, body, re.IGNORECASE))
                return resp.status, found
        except urllib.error.HTTPError as e:
            try:
                body = e.read(32768).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            found = bool(re.search(fingerprint, body, re.IGNORECASE))
            return e.code, found
        except (urllib.error.URLError, socket.timeout, OSError):
            continue

    return None, False


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------

def check_subdomain(subdomain: str, timeout: float, lang: str) -> SubdomainResult:
    cname = dns_cname(subdomain, timeout)
    if cname is None:
        return SubdomainResult(subdomain=subdomain, cname=None, service=None,
                               vulnerable=False, http_status=None, error=None)

    for cname_pattern, http_fp, service_name in SERVICE_FINGERPRINTS:
        if re.search(cname_pattern, cname, re.IGNORECASE):
            http_status, found = http_probe(subdomain, http_fp, timeout)
            return SubdomainResult(
                subdomain=subdomain,
                cname=cname,
                service=service_name,
                vulnerable=found,
                http_status=http_status,
                error=None,
            )

    # Has a CNAME, but no fingerprint matched
    return SubdomainResult(subdomain=subdomain, cname=cname, service=None,
                           vulnerable=False, http_status=None, error=None)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_human(domain: str, results: list[SubdomainResult], lang: str) -> None:
    L = LABELS[lang]
    vulnerable = [r for r in results if r.vulnerable]
    service_matched = [r for r in results if r.service and not r.vulnerable]

    print(f"\n{L['domain']}: {domain}")
    print(f"{L['checked']}: {len(results)}\n")

    if vulnerable:
        print(f"{L['vulnerable_header']} ({len(vulnerable)}):")
        for r in vulnerable:
            print(f"  {r.subdomain}")
            print(f"    {L['cname_label']}  → {r.cname}")
            print(f"    {L['service_label']}: {r.service}")
            print(f"    {L['status_label']}: {L['status_vulnerable']}")
            print()
    elif service_matched:
        for r in service_matched:
            print(f"  {r.subdomain}")
            print(f"    {L['cname_label']}  → {r.cname}")
            print(f"    {L['service_label']}: {r.service}")
            print(f"    {L['status_label']}: {L['status_service_unconfirmed']}")
            print()
    else:
        print(L["no_issues"])
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Check subdomains for CNAMEs pointing at unclaimed services (subdomain takeover).",
    )
    add_version_arg(parser, "subdomain_takeover.py")
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument("domain", help="Base domain, e.g. example.com. Use '-' to read from stdin.")
    parser.add_argument("--subdomains", metavar="FILE",
                        help="File with one subdomain per line ('-' for stdin). "
                             "If omitted, crt.sh is queried automatically.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-operation timeout in seconds (default 5).")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    L = LABELS[args.lang]
    USER_AGENT = args.user_agent

    domain = stdin_or_arg(args.domain).strip().lower()
    if not re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", domain):
        print(f"{L['err_domain']}: {domain}", file=sys.stderr)
        return 2

    subdomains: list[str] = []

    if args.subdomains:
        source = args.subdomains
        if source == "-":
            lines = sys.stdin.read().splitlines()
        else:
            try:
                with open(source) as fh:
                    lines = fh.read().splitlines()
            except OSError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
        subdomains = [ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")]
    else:
        print(f"Querying crt.sh for {domain}...", file=sys.stderr)
        try:
            subdomains = query_crtsh(domain, timeout=max(args.timeout, 30.0))
        except (urllib.error.URLError, socket.timeout) as e:
            print(f"{L['err_crt']}: {e}", file=sys.stderr)
            return 3

    if not subdomains:
        print(f"No subdomains to check.", file=sys.stderr)
        if args.json:
            print(json.dumps({"domain": domain, "lang": args.lang, "results": []}, indent=2, ensure_ascii=False))
        return 0

    results: list[SubdomainResult] = []
    for sub in subdomains:
        results.append(check_subdomain(sub, args.timeout, args.lang))

    vulnerable_count = sum(1 for r in results if r.vulnerable)

    if args.json:
        out = {
            "domain": domain,
            "lang": args.lang,
            "subdomains_checked": len(results),
            "vulnerable_count": vulnerable_count,
            "results": [asdict(r) for r in results],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(domain, results, args.lang)

    return 1 if vulnerable_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
