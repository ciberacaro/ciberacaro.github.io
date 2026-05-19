#!/usr/bin/env python3
"""Look up a URL's history on the Internet Archive's Wayback Machine.

Two flavours of query:

    (default)        Show the closest snapshot info (single API call).
    --timeline       List every snapshot via the CDX API.
    --diff           Fetch the closest snapshot and diff it against the
                     live URL (added/removed lines, capped output).

Useful for OSINT: archived versions often retain endpoints, secrets,
or internal references that have since been removed from the live site.

Examples:
    tools/wayback_check.py https://example.com
    tools/wayback_check.py https://example.com --timeline --limit 20
    tools/wayback_check.py https://example.com --diff --lang pt
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg

USER_AGENT = make_user_agent("wayback_check.py")
LANGS = ("en", "pt")

AVAILABILITY_URL = "https://archive.org/wayback/available"
CDX_URL = "https://web.archive.org/cdx/search/cdx"

LABELS = {
    "en": {
        "url": "URL",
        "closest": "Closest snapshot",
        "not_archived": "Not archived (no snapshot found).",
        "available": "Available",
        "timestamp": "Captured at",
        "snapshot_url": "Snapshot URL",
        "timeline": "Timeline",
        "snapshots_total": "snapshots returned (CDX API)",
        "diff_section": "Diff: live vs snapshot",
        "no_diff": "No textual differences detected (whitespace-insensitive).",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_api": "error: Wayback API request failed",
    },
    "pt": {
        "url": "URL",
        "closest": "Snapshot mais próximo",
        "not_archived": "Não arquivado (nenhum snapshot encontrado).",
        "available": "Disponível",
        "timestamp": "Capturado em",
        "snapshot_url": "URL do snapshot",
        "timeline": "Linha temporal",
        "snapshots_total": "snapshots devolvidos (CDX API)",
        "diff_section": "Diff: live vs snapshot",
        "no_diff": "Sem diferenças textuais detetadas (insensível a espaços).",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_api": "erro: pedido à API Wayback falhou",
    },
}


@dataclass
class Snapshot:
    available: bool
    timestamp: Optional[str] = None
    url: Optional[str] = None
    status: Optional[str] = None


def _fetch(url: str, timeout: float = 15.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def closest_snapshot(target_url: str, timeout: float) -> Snapshot:
    query = urllib.parse.urlencode({"url": target_url})
    data = _fetch(f"{AVAILABILITY_URL}?{query}", timeout=timeout)
    payload = json.loads(data.decode("utf-8", errors="replace"))
    snap = payload.get("archived_snapshots", {}).get("closest")
    if not snap:
        return Snapshot(available=False)
    return Snapshot(
        available=bool(snap.get("available")),
        timestamp=snap.get("timestamp"),
        url=snap.get("url"),
        status=snap.get("status"),
    )


def cdx_timeline(target_url: str, limit: int, timeout: float) -> list[dict]:
    """Return up to `limit` snapshot records via the CDX API.

    CDX fields: urlkey, timestamp, original, mimetype, statuscode,
    digest, length. We request JSON with explicit field order.
    """
    params = {
        "url": target_url,
        "output": "json",
        "fl": "timestamp,original,mimetype,statuscode,digest,length",
        "limit": str(limit),
        "filter": "statuscode:200",
    }
    query = urllib.parse.urlencode(params)
    data = _fetch(f"{CDX_URL}?{query}", timeout=timeout)
    rows = json.loads(data.decode("utf-8", errors="replace"))
    if not rows:
        return []
    header, *body = rows
    return [dict(zip(header, row)) for row in body]


def fetch_text(url: str, timeout: float) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = build_ssl_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(500_000)
    except (urllib.error.URLError, socket.timeout):
        return ""
    return body.decode("utf-8", errors="replace")


# Patterns that vary between snapshot and live without security relevance:
# timestamps, CSRF tokens, nonces, long hex tokens.
_DYNAMIC_RE = re.compile(
    r"(?:csrf|_token|nonce|__requestverificationtoken|viewstate)"
    r'[^"\'>\s]*'
    r"|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"  # ISO 8601 timestamps
    r"|"
    r"\b\d{10,13}\b"                           # Unix timestamps
    r"|"
    r'["\']?[a-f0-9]{32,}["\']?',              # long hex tokens / hashes
    re.IGNORECASE,
)


def normalise_lines(text: str) -> list[str]:
    """Strip whitespace-only differences and dynamic tokens before diffing."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        lines.append(_DYNAMIC_RE.sub("", line))
    return lines


def fmt_ts(ts: str) -> str:
    """Wayback uses YYYYMMDDHHMMSS strings. Render as ISO for readability."""
    if not ts or len(ts) < 14:
        return ts or ""
    try:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"
    except IndexError:
        return ts


def print_human(target: str, snap: Snapshot, timeline: list[dict] | None,
                diff_lines: list[str] | None, lang: str, max_diff: int = 100) -> None:
    L = LABELS[lang]
    print(f"\n{L['url']}: {target}\n")

    if not snap.available:
        print(f"  {L['not_archived']}\n")
        return

    print(f"{L['closest']}:")
    print(f"  {L['timestamp']}: {fmt_ts(snap.timestamp or '')}")
    print(f"  HTTP {snap.status or '?'}")
    print(f"  {L['snapshot_url']}: {snap.url or '?'}")
    print()

    if timeline:
        print(f"{L['timeline']} ({len(timeline)} {L['snapshots_total']}):\n")
        for row in timeline:
            print(f"  - {fmt_ts(row.get('timestamp', ''))}  HTTP {row.get('statuscode', '?')}  "
                  f"{row.get('mimetype', '?')}  {row.get('length', '?')} bytes")
        print()

    if diff_lines is not None:
        print(f"{L['diff_section']}:\n")
        if not diff_lines:
            print(f"  {L['no_diff']}\n")
        else:
            for line in diff_lines[:max_diff]:
                print(f"  {line}")
            if len(diff_lines) > max_diff:
                print(f"  ... ({len(diff_lines) - max_diff} more)")
            print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(description="Look up a URL on the Wayback Machine.")
    add_version_arg(parser, "wayback_check.py")
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument("url", help="Target URL. Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeline", action="store_true", help="Also list snapshots via the CDX API.")
    parser.add_argument("--limit", type=int, default=20, help="Max snapshots to list with --timeline (default 20).")
    parser.add_argument("--diff", action="store_true", help="Fetch the closest snapshot and diff against the live URL.")
    parser.add_argument("--max-diff", type=int, default=100, metavar="N",
                        help="Max diff lines to show with --diff (default 100).")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    L = LABELS[args.lang]
    USER_AGENT = args.user_agent

    args.url = stdin_or_arg(args.url)
    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    try:
        snap = closest_snapshot(args.url, timeout=args.timeout)
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        print(f"{L['err_api']}: {e}", file=sys.stderr)
        return 3

    timeline: list[dict] | None = None
    if args.timeline:
        try:
            timeline = cdx_timeline(args.url, args.limit, timeout=args.timeout)
        except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
            print(f"warning: CDX query failed: {e}", file=sys.stderr)
            timeline = []

    diff_lines: list[str] | None = None
    if args.diff and snap.available and snap.url:
        live = normalise_lines(fetch_text(args.url, timeout=args.timeout))
        archived = normalise_lines(fetch_text(snap.url, timeout=args.timeout))
        diff_lines = [
            l for l in difflib.unified_diff(archived, live, fromfile="snapshot", tofile="live", lineterm="")
            if l and not l.startswith(("---", "+++"))
        ]

    if args.json:
        out = {
            "url": args.url,
            "lang": args.lang,
            "closest": asdict(snap),
            "timeline": timeline,
            "diff": diff_lines,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, snap, timeline, diff_lines, args.lang, max_diff=args.max_diff)

    return 0 if snap.available else 1


if __name__ == "__main__":
    sys.exit(main())
