#!/usr/bin/env python3
"""Fetch and analyze /robots.txt and /sitemap.xml for a site.

Useful as a recon staple — disallowed paths often point at endpoints the
developer didn't want indexed but didn't actually protect.

Examples:
    tools/robots_check.py https://example.com
    tools/robots_check.py https://example.com --lang pt
    tools/robots_check.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg, build_opener, add_proxy_arg

USER_AGENT = make_user_agent("robots_check.py")
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "target": "Target",
        "robots_url": "robots.txt",
        "sitemap_url": "Sitemaps",
        "status": "Status",
        "user_agents": "Per User-Agent rules",
        "disallow": "Disallow",
        "allow": "Allow",
        "crawl_delay": "Crawl-Delay",
        "host": "Host",
        "interesting": "Potentially interesting paths",
        "interesting_note": "Paths matching admin/api/backup/debug/dev/internal/test/.git etc.",
        "sitemap_entries": "Sitemap entries",
        "no_robots": "No robots.txt found (HTTP {})",
        "no_sitemap": "No sitemap.xml or sitemap declared in robots.txt",
        "no_rules": "No rules — robots.txt exists but is empty",
        "showing_first": "showing first",
        "more": "more",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
        "err_timeout": "error: timeout after",
    },
    "pt": {
        "target": "Alvo",
        "robots_url": "robots.txt",
        "sitemap_url": "Sitemaps",
        "status": "Estado",
        "user_agents": "Regras por User-Agent",
        "disallow": "Disallow",
        "allow": "Allow",
        "crawl_delay": "Crawl-Delay",
        "host": "Host",
        "interesting": "Caminhos potencialmente interessantes",
        "interesting_note": "Paths que correspondem a admin/api/backup/debug/dev/internal/test/.git etc.",
        "sitemap_entries": "Entradas do sitemap",
        "no_robots": "Sem robots.txt (HTTP {})",
        "no_sitemap": "Sem sitemap.xml nem sitemap declarado no robots.txt",
        "no_rules": "Sem regras — robots.txt existe mas está vazio",
        "showing_first": "a mostrar os primeiros",
        "more": "mais",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
        "err_timeout": "erro: timeout após",
    },
}

INTERESTING_PATTERNS = (
    r"admin",
    r"api",
    r"backup",
    r"\bbeta\b",
    r"\bconfig\b",
    r"\bdebug\b",
    r"\bdev\b",
    r"\.env",
    r"\.git",
    r"\binternal\b",
    r"\blogs?\b",
    r"\bprivate\b",
    r"\bsecret",
    r"\bstaging\b",
    r"\btest\b",
    r"\.sql",
    r"\.bak",
    r"phpinfo",
    r"wp-admin",
    r"console",
    r"dashboard",
)
INTERESTING_RE = re.compile("|".join(INTERESTING_PATTERNS), re.IGNORECASE)


@dataclass
class UARules:
    user_agent: str
    disallow: list[str] = field(default_factory=list)
    allow: list[str] = field(default_factory=list)
    crawl_delay: Optional[str] = None
    host: Optional[str] = None


def fetch(url: str, timeout: float = 10.0, opener=None) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        if opener is not None:
            with opener.open(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        else:
            ctx = build_ssl_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def parse_robots(text: str) -> tuple[list[UARules], list[str]]:
    """Return (per-UA rules, sitemap URLs)."""
    sitemaps: list[str] = []
    rules: list[UARules] = []
    current: Optional[UARules] = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "sitemap":
            sitemaps.append(value)
            continue
        if key == "user-agent":
            current = UARules(user_agent=value)
            rules.append(current)
            continue
        if current is None:
            # Rule without a preceding user-agent: treat as wildcard.
            current = UARules(user_agent="*")
            rules.append(current)
        if key == "disallow":
            if value:
                current.disallow.append(value)
        elif key == "allow":
            if value:
                current.allow.append(value)
        elif key == "crawl-delay":
            current.crawl_delay = value
        elif key == "host":
            current.host = value
    return rules, sitemaps


def collect_interesting(rules: list[UARules]) -> list[str]:
    seen = set()
    interesting = []
    for ua in rules:
        for path in ua.disallow + ua.allow:
            if path in seen:
                continue
            if INTERESTING_RE.search(path):
                seen.add(path)
                interesting.append(path)
    return interesting


def fetch_sitemap_entries(sitemap_url: str, timeout: float, limit: int = 50, _depth: int = 0, opener=None) -> list[str]:
    """Fetch URL entries from a sitemap. Follows sitemapindex up to depth 2, max 5 nested."""
    if _depth > 2:
        return []
    status, body = fetch(sitemap_url, timeout=timeout, opener=opener)
    if status != 200 or not body:
        return []
    entries: list[str] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    ns = re.match(r"\{.*\}", root.tag).group(0) if root.tag.startswith("{") else ""
    local_tag = root.tag[len(ns):]

    if local_tag == "sitemapindex":
        # Follow nested sitemaps, cap at 5 per level to avoid runaway fetches.
        nested_count = 0
        for sitemap_elem in root.iter(f"{ns}sitemap"):
            loc = sitemap_elem.find(f"{ns}loc")
            if loc is not None and loc.text:
                entries.extend(
                    fetch_sitemap_entries(loc.text.strip(), timeout, limit - len(entries), _depth + 1, opener=opener)
                )
                nested_count += 1
                if nested_count >= 5 or len(entries) >= limit:
                    break
    else:
        for loc in root.iter(f"{ns}loc"):
            if loc.text:
                entries.append(loc.text.strip())
                if len(entries) >= limit:
                    break
    return entries[:limit]


def print_human(
    target: str,
    robots_url: str,
    robots_status: int,
    rules: list[UARules],
    sitemaps: list[str],
    interesting: list[str],
    sitemap_entries: list[str],
    lang: str,
) -> None:
    L = LABELS[lang]
    print(f"\n{L['target']}: {target}")
    print(f"{L['robots_url']}: {robots_url} ({L['status']}: {robots_status})\n")

    if robots_status != 200:
        print(f"  {L['no_robots'].format(robots_status)}\n")
        return

    if not rules and not sitemaps:
        print(f"  {L['no_rules']}\n")
        return

    if rules:
        print(f"{L['user_agents']}:")
        for ua in rules:
            print(f"\n  User-Agent: {ua.user_agent}")
            if ua.crawl_delay:
                print(f"    {L['crawl_delay']}: {ua.crawl_delay}")
            if ua.host:
                print(f"    {L['host']}: {ua.host}")
            for path in ua.allow:
                print(f"    {L['allow']}: {path}")
            for path in ua.disallow:
                print(f"    {L['disallow']}: {path}")
        print()

    if sitemaps:
        print(f"{L['sitemap_url']}:")
        for s in sitemaps:
            print(f"  - {s}")
        print()
    else:
        print(f"  {L['no_sitemap']}\n")

    if interesting:
        print(f"{L['interesting']} ({L['interesting_note']}):")
        for path in interesting:
            print(f"  ! {path}")
        print()

    if sitemap_entries:
        shown = min(len(sitemap_entries), 20)
        print(f"{L['sitemap_entries']} ({L['showing_first']} {shown}):")
        for url in sitemap_entries[:shown]:
            print(f"  - {url}")
        if len(sitemap_entries) > shown:
            print(f"  ... ({len(sitemap_entries) - shown} {L['more']})")
        print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(description="Analyze /robots.txt and /sitemap.xml for a site.")
    add_version_arg(parser, "robots_check.py")
    add_user_agent_arg(parser, USER_AGENT)
    add_proxy_arg(parser)
    parser.add_argument("url", help="Target site URL (http:// or https://). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]
    USER_AGENT = args.user_agent
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    opener = build_opener(build_ssl_context(), args.proxy) if args.proxy else None

    parsed = urllib.parse.urlparse(args.url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    robots_url = f"{base}/robots.txt"

    try:
        robots_status, robots_body = fetch(robots_url, timeout=args.timeout, opener=opener)
    except urllib.error.URLError as e:
        print(f"{L['err_unreachable']} {robots_url} — {e.reason}", file=sys.stderr)
        return 3
    except socket.timeout:
        print(f"{L['err_timeout']} {args.timeout}s {robots_url}", file=sys.stderr)
        return 3

    rules: list[UARules] = []
    sitemaps: list[str] = []
    interesting: list[str] = []
    sitemap_entries: list[str] = []

    if robots_status == 200 and robots_body:
        rules, sitemaps = parse_robots(robots_body)
        interesting = collect_interesting(rules)

    if not sitemaps:
        # Fall back to /sitemap.xml
        candidate = f"{base}/sitemap.xml"
        sm_status, _ = fetch(candidate, timeout=args.timeout, opener=opener)
        if sm_status == 200:
            sitemaps = [candidate]

    for s in sitemaps[:3]:  # cap sitemap fetches
        sitemap_entries.extend(fetch_sitemap_entries(s, timeout=args.timeout, limit=50, opener=opener))

    if args.json:
        out = {
            "target": base,
            "robots_url": robots_url,
            "robots_status": robots_status,
            "lang": args.lang,
            "rules": [asdict(r) for r in rules],
            "sitemaps": sitemaps,
            "interesting": interesting,
            "sitemap_entries": sitemap_entries,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(
            base, robots_url, robots_status, rules, sitemaps, interesting, sitemap_entries, args.lang
        )

    return 0 if robots_status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
