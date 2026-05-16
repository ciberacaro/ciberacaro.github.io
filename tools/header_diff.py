#!/usr/bin/env python3
"""Snapshot a URL's security headers and diff future snapshots against the past.

Two modes:

    snapshot URL    Fetch the current security-header state and save it as a JSON
                    snapshot under .header_snapshots/<host>/<timestamp>.json

    diff URL        Compare the current state to the most recent snapshot and
                    report what changed.

Examples:
    tools/header_diff.py snapshot https://ciberacaro.github.io
    tools/header_diff.py diff https://ciberacaro.github.io --lang pt
    tools/header_diff.py diff https://ciberacaro.github.io --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "header_diff.py/0.1 (+https://ciberacaro.github.io)"
LANGS = ("en", "pt")

# These are the response headers we track. Add/remove as you like.
TRACKED_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
)

SNAPSHOT_DIR = Path(".header_snapshots")

LABELS = {
    "en": {
        "url": "URL",
        "snapshot_saved": "Saved snapshot",
        "previous": "Previous snapshot",
        "current": "Current state",
        "no_previous": "No previous snapshot to diff against — run 'snapshot' first.",
        "no_changes": "No header changes since the previous snapshot.",
        "added": "Added",
        "removed": "Removed",
        "changed": "Changed",
        "from": "from",
        "to": "to",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
    },
    "pt": {
        "url": "URL",
        "snapshot_saved": "Snapshot guardado",
        "previous": "Snapshot anterior",
        "current": "Estado atual",
        "no_previous": "Sem snapshot anterior — corre 'snapshot' primeiro.",
        "no_changes": "Sem alterações de headers desde o último snapshot.",
        "added": "Adicionado",
        "removed": "Removido",
        "changed": "Alterado",
        "from": "de",
        "to": "para",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
    },
}

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


def fetch(url: str, timeout: float = 10.0) -> tuple[int, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}


def relevant(headers: dict[str, str]) -> dict[str, str]:
    return {h: headers[h] for h in TRACKED_HEADERS if h in headers}


def host_dir(url: str) -> Path:
    parsed = urllib.parse.urlparse(url)
    safe_host = re.sub(r"[^a-zA-Z0-9.\-]", "_", parsed.netloc)
    return SNAPSHOT_DIR / safe_host


def latest_snapshot(url: str) -> tuple[Path, dict] | None:
    d = host_dir(url)
    if not d.exists():
        return None
    snapshots = sorted(d.glob("*.json"))
    if not snapshots:
        return None
    path = snapshots[-1]
    with open(path) as f:
        return path, json.load(f)


def save_snapshot(url: str, status: int, headers: dict[str, str]) -> Path:
    d = host_dir(url)
    d.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = d / f"{now}.json"
    snapshot = {
        "url": url,
        "captured_at": now,
        "status": status,
        "headers": headers,
    }
    with open(path, "w") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
    return path


def diff(prev: dict[str, str], curr: dict[str, str]) -> dict[str, list]:
    prev_keys = set(prev)
    curr_keys = set(curr)
    added = sorted(curr_keys - prev_keys)
    removed = sorted(prev_keys - curr_keys)
    changed = sorted(k for k in (prev_keys & curr_keys) if prev[k] != curr[k])
    return {"added": added, "removed": removed, "changed": changed}


def print_snapshot_result(url: str, path: Path, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['snapshot_saved']}: {path}")
    print(f"{L['url']}: {url}\n")


def print_diff_result(url: str, prev_path: Path, prev: dict, curr: dict, changes: dict, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['url']}: {url}")
    print(f"{L['previous']}: {prev_path}\n")

    if not any(changes.values()):
        print(f"  {L['no_changes']}\n")
        return

    for h in changes["added"]:
        print(f"  + {L['added']}: {h}")
        print(f"      {curr[h]}")
    for h in changes["removed"]:
        print(f"  - {L['removed']}: {h}")
        print(f"      {prev[h]}")
    for h in changes["changed"]:
        print(f"  ~ {L['changed']}: {h}")
        print(f"      {L['from']}: {prev[h]}")
        print(f"      {L['to']}:   {curr[h]}")
    print()


def cmd_snapshot(args, lang: str) -> int:
    L = LABELS[lang]
    try:
        status, all_headers = fetch(args.url, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(f"{L['err_unreachable']} {args.url} — {e.reason}", file=sys.stderr)
        return 3
    headers = relevant(all_headers)
    path = save_snapshot(args.url, status, headers)
    if args.json:
        print(json.dumps({"saved_to": str(path), "url": args.url, "status": status, "headers": headers},
                         indent=2, ensure_ascii=False))
    else:
        print_snapshot_result(args.url, path, lang)
    return 0


def cmd_diff(args, lang: str) -> int:
    L = LABELS[lang]
    prev = latest_snapshot(args.url)
    if prev is None:
        print(L["no_previous"], file=sys.stderr)
        return 4
    prev_path, prev_data = prev
    try:
        status, all_headers = fetch(args.url, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(f"{L['err_unreachable']} {args.url} — {e.reason}", file=sys.stderr)
        return 3
    curr = relevant(all_headers)
    changes = diff(prev_data["headers"], curr)
    if args.json:
        out = {
            "url": args.url,
            "previous_snapshot": str(prev_path),
            "previous_captured_at": prev_data.get("captured_at"),
            "changes": changes,
            "previous_headers": prev_data["headers"],
            "current_headers": curr,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_diff_result(args.url, prev_path, prev_data["headers"], curr, changes, lang)
    return 1 if any(changes.values()) else 0


def main() -> int:
    # Parent parser carries the flags shared by every subcommand so they can
    # appear either before or after the subcommand name on the CLI.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--lang", choices=LANGS, default="en")
    common.add_argument("--json", action="store_true")
    common.add_argument("--timeout", type=float, default=10.0)

    parser = argparse.ArgumentParser(
        description="Snapshot a URL's security headers and diff over time.",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp_snap = sub.add_parser("snapshot", help="Save current header state as a snapshot", parents=[common])
    sp_snap.add_argument("url")
    sp_diff = sub.add_parser("diff", help="Diff current state against last snapshot", parents=[common])
    sp_diff.add_argument("url")
    args = parser.parse_args()

    if not re.match(r"^https?://", args.url):
        print(LABELS[args.lang]["err_scheme"], file=sys.stderr)
        return 2

    if args.cmd == "snapshot":
        return cmd_snapshot(args, args.lang)
    if args.cmd == "diff":
        return cmd_diff(args, args.lang)
    return 2


if __name__ == "__main__":
    sys.exit(main())
