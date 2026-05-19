#!/usr/bin/env python3
"""Discover hidden paths and directories on a web server (gobuster-equivalent).

Probes a target URL with a built-in wordlist (or a custom one) and reports
which paths exist, along with a risk classification for sensitive findings.

Examples:
    tools/path_scan.py https://example.com
    tools/path_scan.py https://example.com --wordlist /usr/share/wordlists/dirb/common.txt
    tools/path_scan.py https://example.com --extensions php,html,bak
    tools/path_scan.py https://example.com --threads 20 --timeout 8
    tools/path_scan.py https://example.com --codes 200,403 --lang pt
    tools/path_scan.py https://example.com --json
    echo https://example.com | tools/path_scan.py -
"""

from __future__ import annotations

import argparse
import json
import random
import re
import socket
import string
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import List, Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg

USER_AGENT = make_user_agent("path_scan.py")
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "target": "Target",
        "wordlist_builtin": "builtin",
        "wordlist_paths": "paths",
        "wordlist_external": "external",
        "extensions": "extensions",
        "threads": "threads",
        "findings_header": "Findings",
        "no_findings": "No findings.",
        "redirect_arrow": "→",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_wordlist": "error: cannot read wordlist",
        "err_unreachable": "error: could not reach",
        "risk_critical": "CRITICAL",
        "risk_high": "HIGH",
        "risk_medium": "MEDIUM",
        "wildcard_warn": "Wildcard/soft-404 detected — random path returned 200 (body ~{}B).",
        "wildcard_note": "Filtering 200 results within 10% of baseline. Review remaining 200s carefully.",
    },
    "pt": {
        "target": "Alvo",
        "wordlist_builtin": "incorporada",
        "wordlist_paths": "caminhos",
        "wordlist_external": "externa",
        "extensions": "extensões",
        "threads": "threads",
        "findings_header": "Resultados",
        "no_findings": "Sem resultados.",
        "redirect_arrow": "→",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_wordlist": "erro: não foi possível ler a wordlist",
        "err_unreachable": "erro: não foi possível alcançar",
        "risk_critical": "CRÍTICO",
        "risk_high": "ALTO",
        "risk_medium": "MÉDIO",
        "wildcard_warn": "Wildcard/soft-404 detetado — caminho aleatório devolveu 200 (body ~{}B).",
        "wildcard_note": "A filtrar resultados 200 dentro de 10% do tamanho base. Revê os 200 restantes com cuidado.",
    },
}

BUILTIN_WORDLIST = [
    ".env",
    ".env.backup",
    ".env.bak",
    ".env.local",
    ".env.prod",
    ".env.production",
    ".git/config",
    ".git/HEAD",
    ".htaccess",
    ".htpasswd",
    ".DS_Store",
    "admin",
    "admin/login",
    "admin/index.php",
    "administrator",
    "api",
    "api/v1",
    "api/v2",
    "api/swagger",
    "actuator",
    "actuator/env",
    "actuator/health",
    "actuator/mappings",
    "backup",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backup.bak",
    "config",
    "config.php",
    "config.yml",
    "config.yaml",
    "config.json",
    "config.py",
    "dashboard",
    "db",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "id_rsa",
    "id_rsa.pub",
    "info.php",
    "login",
    "logs",
    "myadmin",
    "panel",
    "passwd",
    "phpmyadmin",
    "phpinfo.php",
    "pma",
    "server-status",
    "server-info",
    "setup",
    "shadow",
    "shell.php",
    "test",
    "tmp",
    "upload",
    "uploads",
    "web.config",
    "wp-config.php",
    "wp-admin",
    "wp-login.php",
    "xmlrpc.php",
    ".well-known/security.txt",
    "console",
    "debug",
    "dev",
    "internal",
    "private",
    "secret",
    "secrets",
    "server.key",
    "server.pem",
    "site.key",
]

RISK_PATTERNS = [
    (re.compile(r"\.env(\.|$)", re.I), "env_file", "high"),
    (re.compile(r"\.git", re.I), "git_exposed", "high"),
    (re.compile(r"wp-config|config\.(php|yml|yaml|json|py)$", re.I), "config_file", "high"),
    (re.compile(r"backup|\.zip$|\.tar|\.sql$|\.bak$", re.I), "backup_file", "high"),
    (re.compile(r"phpmyadmin|/pma(/|$)|myadmin", re.I), "db_admin", "high"),
    (re.compile(r"actuator", re.I), "spring_actuator", "high"),
    (re.compile(r"\.htpasswd$|/passwd$|/shadow$", re.I), "cred_file", "critical"),
    (re.compile(r"id_rsa|\.pem$|\.key$", re.I), "private_key", "critical"),
    (re.compile(r"phpinfo|info\.php$", re.I), "phpinfo", "medium"),
    (re.compile(r"admin|administrator|dashboard|panel", re.I), "admin_panel", "medium"),
    (re.compile(r"\.DS_Store$|Dockerfile|docker-compose", re.I), "devops_file", "medium"),
]

DEFAULT_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


@dataclass
class Finding:
    path: str
    status: int
    risk_key: Optional[str]
    risk_level: Optional[str]
    redirect_url: Optional[str]
    error: Optional[str]
    content_length: int = 0


def classify_risk(path: str):
    for pattern, key, level in RISK_PATTERNS:
        if pattern.search(path):
            return key, level
    return None, None


def probe_path(
    base_url: str,
    path: str,
    timeout: int,
    ssl_ctx,
    user_agent: str,
) -> Finding:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        handler = urllib.request.HTTPSHandler(context=ssl_ctx)
        opener = urllib.request.build_opener(handler, NoRedirectHandler())
        resp = opener.open(req, timeout=timeout)
        status = resp.status
        body = resp.read(4096)
        redirect_url = None
    except NoRedirectError as e:
        status = e.code
        body = b""
        redirect_url = e.location
    except urllib.error.HTTPError as e:
        status = e.code
        body = b""
        redirect_url = e.headers.get("Location") if status in (301, 302, 307, 308) else None
    except urllib.error.URLError as e:
        return Finding(path=path, status=0, risk_key=None, risk_level=None, redirect_url=None, error=str(e.reason))
    except socket.timeout:
        return Finding(path=path, status=0, risk_key=None, risk_level=None, redirect_url=None, error="timeout")
    except OSError as e:
        return Finding(path=path, status=0, risk_key=None, risk_level=None, redirect_url=None, error=str(e))

    risk_key, risk_level = classify_risk(path)
    return Finding(path=path, status=status, risk_key=risk_key, risk_level=risk_level,
                   redirect_url=redirect_url, error=None, content_length=len(body))


class NoRedirectError(Exception):
    def __init__(self, code: int, location: Optional[str]):
        self.code = code
        self.location = location


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NoRedirectError(code, headers.get("Location"))

    def http_error_301(self, req, fp, code, msg, headers):
        raise NoRedirectError(code, headers.get("Location"))

    def http_error_302(self, req, fp, code, msg, headers):
        raise NoRedirectError(code, headers.get("Location"))

    def http_error_307(self, req, fp, code, msg, headers):
        raise NoRedirectError(code, headers.get("Location"))

    def http_error_308(self, req, fp, code, msg, headers):
        raise NoRedirectError(code, headers.get("Location"))


def load_wordlist(path: str) -> List[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = []
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped.lstrip("/"))
        return lines


def build_path_list(base_paths: List[str], extensions: List[str]) -> List[str]:
    seen = {}
    result = []
    for p in base_paths:
        if p not in seen:
            seen[p] = True
            result.append(p)
        for ext in extensions:
            candidate = p + "." + ext.lstrip(".")
            if candidate not in seen:
                seen[candidate] = True
                result.append(candidate)
    return result


def format_risk_label(risk_level: Optional[str], lang: str) -> str:
    if not risk_level:
        return ""
    L = LABELS[lang]
    mapping = {
        "critical": L["risk_critical"],
        "high": L["risk_high"],
        "medium": L["risk_medium"],
    }
    label = mapping.get(risk_level, risk_level.upper())
    return f"[{label}]"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="path_scan.py",
        description="Discover hidden paths on a web server.",
    )
    parser.add_argument("url", help="Target base URL (or '-' to read from stdin)")
    parser.add_argument("--wordlist", metavar="FILE", help="External wordlist (one path per line, # = comment)")
    parser.add_argument("--extensions", metavar="LIST", default="", help="Comma-separated extensions to append to each path (e.g. php,html,bak)")
    parser.add_argument("--threads", type=int, default=10, metavar="N", help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, metavar="SECS", help="Per-request timeout in seconds (default: 5)")
    parser.add_argument("--codes", default="", metavar="LIST", help="Comma-separated status codes to report (default: 200,201,204,301,302,307,308,401,403,405)")
    parser.add_argument("--lang", choices=LANGS, default="en", help="Output language (default: en)")
    parser.add_argument("--json", dest="json_out", action="store_true", help="Machine-readable JSON output")
    add_user_agent_arg(parser, USER_AGENT)
    add_version_arg(parser, "path_scan.py")
    args = parser.parse_args()

    L = LABELS[args.lang]
    url = stdin_or_arg(args.url)

    if not url.startswith(("http://", "https://")):
        print(L["err_scheme"], file=sys.stderr)
        sys.exit(2)

    url = url.rstrip("/")

    if args.codes:
        try:
            show_codes = {int(c.strip()) for c in args.codes.split(",") if c.strip()}
        except ValueError:
            print("error: --codes must be comma-separated integers", file=sys.stderr)
            sys.exit(2)
    else:
        show_codes = DEFAULT_CODES

    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()] if args.extensions else []

    wordlist_label = L["wordlist_builtin"]
    if args.wordlist:
        try:
            base_paths = load_wordlist(args.wordlist)
        except OSError as e:
            print(f"{L['err_wordlist']}: {e}", file=sys.stderr)
            sys.exit(2)
        wordlist_label = L["wordlist_external"]
    else:
        base_paths = list(BUILTIN_WORDLIST)

    all_paths = build_path_list(base_paths, extensions)
    ssl_ctx = build_ssl_context()

    # Wildcard / soft-404 detection: probe a random nonexistent path first.
    rand_path = "".join(random.choices(string.ascii_lowercase, k=18))
    wc_probe = probe_path(url, rand_path, args.timeout, ssl_ctx, args.user_agent)
    is_wildcard = wc_probe.status == 200
    wildcard_size = wc_probe.content_length if is_wildcard else None

    if not args.json_out:
        ext_info = f" | {len(extensions)} {L['extensions']}" if extensions else ""
        print(f"{L['target']}: {url}")
        print(f"Wordlist: {wordlist_label} ({len(base_paths)} {L['wordlist_paths']}){ext_info} | {args.threads} {L['threads']}")
        if is_wildcard:
            print(f"\n! {L['wildcard_warn'].format(wildcard_size)}")
            print(f"  {L['wildcard_note']}")
        print()

    results: List[Finding] = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(probe_path, url, p, args.timeout, ssl_ctx, args.user_agent): p
            for p in all_paths
        }
        for fut in as_completed(futures):
            finding = fut.result()
            if finding.error is None and finding.status in show_codes:
                if is_wildcard and finding.status == 200 and wildcard_size is not None:
                    # Filter out responses that match the wildcard baseline size (within 10%)
                    if abs(finding.content_length - wildcard_size) <= max(1, wildcard_size * 0.10):
                        continue
                results.append(finding)

    results.sort(key=lambda f: all_paths.index(f.path) if f.path in all_paths else 0)

    if args.json_out:
        out = {
            "url": url,
            "wordlist_size": len(base_paths),
            "wildcard_detected": is_wildcard,
            "wildcard_baseline_size": wildcard_size,
            "findings": [asdict(f) for f in results],
        }
        print(json.dumps(out, indent=2))
        sys.exit(1 if results else 0)

    if not results:
        print(L["no_findings"])
        sys.exit(0)

    print(f"{L['findings_header']} ({len(results)}):")
    for f in results:
        risk_str = ""
        if f.risk_level and f.risk_key:
            risk_str = f"  {format_risk_label(f.risk_level, args.lang)}   {f.risk_key}"
        redirect_str = ""
        if f.redirect_url:
            redirect_str = f"  {L['redirect_arrow']} {f.redirect_url}"
        print(f"  {f.status:<4} /{f.path.lstrip('/'):<40}{risk_str}{redirect_str}")

    sys.exit(1)


if __name__ == "__main__":
    main()
