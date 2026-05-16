#!/usr/bin/env python3
"""Enumerate subdomains of a domain via crt.sh and (optionally) a wordlist.

Examples:
    tools/subfinder.py example.com
    tools/subfinder.py example.com --lang pt
    tools/subfinder.py example.com --wordlist tools/wordlists/subdomains_small.txt
    tools/subfinder.py example.com --json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

USER_AGENT = "subfinder.py/0.1 (+https://ciberacaro.github.io)"
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "domain": "Domain",
        "querying_crt": "Querying crt.sh...",
        "crt_results": "crt.sh results",
        "bruteforce_results": "Wordlist brute-force results",
        "resolved": "Resolved subdomains",
        "skipped": "Skipped",
        "no_resolve": "did not resolve",
        "total": "Total unique resolved",
        "err_crt": "warning: crt.sh query failed",
        "err_domain": "error: invalid domain",
    },
    "pt": {
        "domain": "Domínio",
        "querying_crt": "A consultar crt.sh...",
        "crt_results": "Resultados crt.sh",
        "bruteforce_results": "Resultados de brute-force via wordlist",
        "resolved": "Subdomínios resolvidos",
        "skipped": "Ignorados",
        "no_resolve": "não resolveram",
        "total": "Total único resolvido",
        "err_crt": "aviso: consulta a crt.sh falhou",
        "err_domain": "erro: domínio inválido",
    },
}

# A tiny default wordlist used when --wordlist is omitted.
DEFAULT_WORDLIST = """\
www
mail
ftp
api
admin
dev
test
staging
beta
blog
shop
portal
secure
vpn
git
gitlab
jenkins
ci
cdn
m
mobile
app
status
docs
support
help
forum
community
""".strip().split()


CA_FALLBACK_LOCATIONS = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)


def build_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    for cafile in CA_FALLBACK_LOCATIONS:
        if os.path.exists(cafile):
            ctx.load_verify_locations(cafile=cafile)
            return ctx
    return ctx


@dataclass
class ResolvedHost:
    hostname: str
    ips: list[str]
    source: str


def query_crtsh(domain: str, timeout: float = 30.0) -> list[str]:
    """Query crt.sh for known subdomains via its JSON API."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return []
    seen = set()
    for e in entries:
        for field_name in ("name_value", "common_name"):
            value = e.get(field_name) or ""
            for name in value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain) and "@" not in name:
                    seen.add(name)
    return sorted(seen)


def resolve(host: str) -> list[str]:
    """Return list of A/AAAA addresses for host, empty if it doesn't resolve.

    Note: getaddrinfo() does not honour socket.setdefaulttimeout() — that
    timeout only affects subsequent socket I/O, not the underlying DNS
    resolver. So we don't bother setting it (the previous version did,
    and worse, did so as a global side effect that race'd between threads).
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.timeout, OSError):
        return []
    return sorted({info[4][0] for info in infos})


def resolve_many(hosts: list[str], threads: int = 20) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolve, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                out[host] = fut.result()
            except Exception:
                out[host] = []
    return out


def load_wordlist(path: Optional[str]) -> list[str]:
    if path:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return DEFAULT_WORDLIST


def print_human(domain: str, resolved: list[ResolvedHost], skipped: int, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['domain']}: {domain}\n")
    if not resolved:
        print(f"  ({L['no_resolve']})\n")
        return
    print(f"{L['resolved']} ({len(resolved)}):")
    name_width = max(len(r.hostname) for r in resolved)
    for r in resolved:
        ips = ", ".join(r.ips) if r.ips else "—"
        print(f"  {r.hostname:<{name_width}}  [{r.source}]  {ips}")
    print(f"\n{L['total']}: {len(resolved)}  ({L['skipped']}: {skipped})")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Enumerate subdomains via crt.sh + DNS wordlist brute-force.")
    parser.add_argument("domain", help="Base domain, e.g. example.com")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--wordlist", help="Path to a wordlist (default: built-in 27 entries)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=30.0, help="crt.sh request timeout (default 30s)")
    parser.add_argument("--skip-crtsh", action="store_true", help="Don't query crt.sh, only brute-force")
    parser.add_argument("--skip-bruteforce", action="store_true", help="Skip wordlist brute-force, only crt.sh")
    args = parser.parse_args()
    L = LABELS[args.lang]

    domain = args.domain.strip().lower()
    if not re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", domain):
        print(f"{L['err_domain']}: {domain}", file=sys.stderr)
        return 2

    candidates: dict[str, str] = {}  # host -> source

    if not args.skip_crtsh:
        print(L["querying_crt"], file=sys.stderr)
        try:
            for host in query_crtsh(domain, timeout=args.timeout):
                candidates[host] = "crt.sh"
        except (urllib.error.URLError, socket.timeout) as e:
            print(f"{L['err_crt']}: {e}", file=sys.stderr)

    if not args.skip_bruteforce:
        wordlist = load_wordlist(args.wordlist)
        for word in wordlist:
            host = f"{word}.{domain}"
            if host not in candidates:
                candidates[host] = "wordlist"

    results = resolve_many(list(candidates.keys()), threads=args.threads)
    resolved: list[ResolvedHost] = []
    skipped = 0
    for host, ips in sorted(results.items()):
        if ips:
            resolved.append(ResolvedHost(hostname=host, ips=ips, source=candidates[host]))
        else:
            skipped += 1

    if args.json:
        out = {
            "domain": domain,
            "lang": args.lang,
            "resolved": [asdict(r) for r in resolved],
            "skipped_count": skipped,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(domain, resolved, skipped, args.lang)

    return 0 if resolved else 1


if __name__ == "__main__":
    sys.exit(main())
