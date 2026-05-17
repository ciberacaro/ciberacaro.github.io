#!/usr/bin/env python3
"""Generate HackTheBox badge markdown and (optionally) fetch profile stats.

The official HTB v4 API requires a bearer token for most endpoints. This
tool works *without* a token by generating standard badge markdown
(image hosted by HTB), and works *with* a token (env var HTB_TOKEN or
--token) to fetch actual stats.

Examples:
    tools/htb_stats.py 12345
    tools/htb_stats.py 12345 --lang pt
    tools/htb_stats.py 12345 --badge-only
    HTB_TOKEN=eyJ... tools/htb_stats.py 12345 --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg

USER_AGENT = make_user_agent("htb_stats.py")
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "user_id": "User ID",
        "profile_url": "Profile URL",
        "badge_url": "Badge image",
        "badge_markdown": "Badge markdown (paste into a README or post)",
        "stats_header": "Profile stats",
        "stats_unavailable": "Profile stats require an HTB API token. Pass --token or set HTB_TOKEN env var.",
        "stats_failed": "Failed to fetch stats",
        "name": "Name",
        "rank": "Rank",
        "points": "Points",
        "own_user": "User owns",
        "own_root": "System owns",
        "respects": "Respects",
        "country": "Country",
        "team": "Team",
        "err_id": "error: user ID must be numeric",
    },
    "pt": {
        "user_id": "ID do utilizador",
        "profile_url": "URL do perfil",
        "badge_url": "Imagem do badge",
        "badge_markdown": "Markdown do badge (cola num README ou post)",
        "stats_header": "Estatísticas do perfil",
        "stats_unavailable": "As estatísticas do perfil requerem um token da API HTB. Passa --token ou define a env var HTB_TOKEN.",
        "stats_failed": "Falha ao obter estatísticas",
        "name": "Nome",
        "rank": "Posição",
        "points": "Pontos",
        "own_user": "User owns",
        "own_root": "System owns",
        "respects": "Respects",
        "country": "País",
        "team": "Equipa",
        "err_id": "erro: ID de utilizador tem de ser numérico",
    },
}

def badge_image_url(user_id: int) -> str:
    return f"https://www.hackthebox.com/badge/image/{user_id}"


def profile_url(user_id: int) -> str:
    return f"https://app.hackthebox.com/profile/{user_id}"


def badge_markdown(user_id: int) -> str:
    img = badge_image_url(user_id)
    profile = profile_url(user_id)
    return f"[![HackTheBox]({img})]({profile})"


def fetch_profile(user_id: int, token: str, timeout: float = 10.0) -> dict:
    """Hit HTB v4 profile endpoint. Requires a bearer token."""
    url = f"https://www.hackthebox.com/api/v4/user/profile/basic/{user_id}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def print_human(user_id: int, stats: dict | None, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['user_id']}: {user_id}")
    print(f"{L['profile_url']}: {profile_url(user_id)}")
    print(f"{L['badge_url']}: {badge_image_url(user_id)}\n")

    print(f"{L['badge_markdown']}:\n")
    print(f"  {badge_markdown(user_id)}\n")

    if stats is None:
        print(f"  {L['stats_unavailable']}\n")
        return

    profile = stats.get("profile") or stats  # API wraps under "profile"
    print(f"{L['stats_header']}:")
    fields = (
        ("name", L["name"]),
        ("rank", L["rank"]),
        ("points", L["points"]),
        ("user_owns", L["own_user"]),
        ("system_owns", L["own_root"]),
        ("respects", L["respects"]),
        ("country_name", L["country"]),
        ("team", L["team"]),
    )
    for key, label in fields:
        if key in profile:
            value = profile[key]
            if isinstance(value, dict):
                value = value.get("name") or value
            print(f"  {label}: {value}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate HackTheBox profile badge markdown; optional stats fetch with API token.",
    )
    add_version_arg(parser, "htb_stats.py")
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument("user_id", help="HTB user ID (numeric, from the profile URL). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--token", help="HTB API bearer token (or set HTB_TOKEN env var)")
    parser.add_argument("--badge-only", action="store_true", help="Only print the badge URL/markdown, skip the API call")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]
    global USER_AGENT
    USER_AGENT = args.user_agent
    args.user_id = stdin_or_arg(args.user_id)

    if not re.fullmatch(r"\d+", args.user_id):
        print(f"{L['err_id']}: {args.user_id!r}", file=sys.stderr)
        return 2
    user_id = int(args.user_id)

    token = args.token or os.environ.get("HTB_TOKEN")
    stats: dict | None = None
    if not args.badge_only and token:
        try:
            stats = fetch_profile(user_id, token, timeout=args.timeout)
        except urllib.error.HTTPError as e:
            print(f"{L['stats_failed']}: HTTP {e.code}", file=sys.stderr)
        except (urllib.error.URLError, socket.timeout) as e:
            print(f"{L['stats_failed']}: {e}", file=sys.stderr)

    if args.json:
        out = {
            "user_id": user_id,
            "lang": args.lang,
            "profile_url": profile_url(user_id),
            "badge_image": badge_image_url(user_id),
            "badge_markdown": badge_markdown(user_id),
            "stats": stats,
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(user_id, stats, args.lang)

    return 0


if __name__ == "__main__":
    sys.exit(main())
