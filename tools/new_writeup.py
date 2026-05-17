#!/usr/bin/env python3
"""Generate a new writeup skeleton in _posts/.

Examples:
    tools/new_writeup.py "Vulnversity" --platform thm --difficulty easy
    tools/new_writeup.py "Soccer" --platform htb --tags web,enumeration
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

from _lib import add_version_arg

REPO_ROOT = Path(__file__).resolve().parent.parent
POSTS_DIR = REPO_ROOT / "_posts"

PLATFORMS = {
    "thm": ("TryHackMe", "https://tryhackme.com/"),
    "htb": ("HackTheBox", "https://app.hackthebox.com/"),
    "portswigger": (
        "PortSwigger Web Security Academy",
        "https://portswigger.net/web-security/",
    ),
    "other": ("Other", ""),
}

DIFFICULTIES = ["info", "easy", "medium", "hard", "insane"]

TEMPLATE = """\
---
title: "{title}"
date: {date}
categories: [Writeups, {platform_category}]
tags: [{tags}]
description: "{description}"
---

## Overview

- **Platform:** {platform_display}
- **Difficulty:** {difficulty}
- **OS:** TBD

One-paragraph summary of the box: what it is, what the path looked like, and what made it interesting (skip the marketing copy).

## Reconnaissance

### Port scan

```bash
nmap -sC -sV -oN nmap.txt <IP>
```

Open ports / services:

| Port | Service | Version |
|------|---------|---------|
|      |         |         |

### Service enumeration

Notes per service.

## Initial Access

How the foothold was obtained. Tools used, vulnerabilities exploited, *and* the dead ends tried before the working path.

## Privilege Escalation

Path to root / Administrator. SUID? Misconfigured cron? Weak service? Kernel exploit? Document the enumeration that found it, not just the final exploit.

## Lessons Learned

- A technique or concept that was new.
- A mistake that cost time.
- A command or tool worth remembering.

## References

- [{platform_display}]({platform_url})
"""


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a new writeup skeleton in _posts/",
    )
    add_version_arg(parser, "new_writeup.py")
    parser.add_argument("name", help="Room/machine name, e.g. 'Vulnversity'")
    parser.add_argument(
        "--platform",
        choices=list(PLATFORMS.keys()),
        default="thm",
        help="Platform (default: thm)",
    )
    parser.add_argument(
        "--difficulty",
        choices=DIFFICULTIES,
        default="easy",
        help="Difficulty level (default: easy)",
    )
    parser.add_argument(
        "--tags",
        default="",
        help="Comma-separated extra tags, e.g. 'web,sqli'",
    )
    parser.add_argument(
        "--date",
        default=datetime.now().strftime("%Y-%m-%d"),
        help="Override date in YYYY-MM-DD format (default: today)",
    )
    args = parser.parse_args()

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        print(f"error: --date must be YYYY-MM-DD, got {args.date!r}", file=sys.stderr)
        return 2

    slug = slugify(args.name)
    if not slug:
        print(f"error: name {args.name!r} produces an empty slug", file=sys.stderr)
        return 2

    path = POSTS_DIR / f"{args.date}-{slug}.md"
    if path.exists():
        print(
            f"error: {path.relative_to(REPO_ROOT)} already exists — not overwriting",
            file=sys.stderr,
        )
        return 1

    platform_display, platform_url = PLATFORMS[args.platform]
    tags = [args.platform, args.difficulty]
    if args.tags:
        tags += [t.strip() for t in args.tags.split(",") if t.strip()]

    content = TEMPLATE.format(
        title=args.name,
        date=f"{args.date} 12:00:00 +0100",
        platform_category=platform_display,
        platform_display=platform_display,
        platform_url=platform_url or "#",
        difficulty=args.difficulty.capitalize(),
        tags=", ".join(tags),
        description=f"Writeup for {args.name} on {platform_display}.",
    )

    POSTS_DIR.mkdir(exist_ok=True)
    path.write_text(content)
    print(f"created: {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
