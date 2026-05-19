#!/usr/bin/env python3
"""Discover hidden/undocumented query parameters via fuzzing.

Probes a URL with a wordlist of common parameter names, comparing each
response (status, body length, reflection) against a baseline to identify
parameters the application responds to differently.

Exit codes:
  0  No parameters detected beyond baseline
  1  One or more hidden parameters found
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/param_miner.py https://api.example.com/users
    tools/param_miner.py https://api.example.com/users --lang pt
    tools/param_miner.py https://api.example.com/users --json
    tools/param_miner.py https://api.example.com/users --threshold 5
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import List, Optional

from _lib import (
    build_ssl_context,
    make_user_agent,
    add_version_arg,
    add_user_agent_arg,
    stdin_or_arg,
)

TOOL_NAME = "param_miner.py"
USER_AGENT = make_user_agent(TOOL_NAME)
LANGS = ("en", "pt")

# Common parameter names across web frameworks and platforms.
# Deduplicated (insertion order preserved via dict.fromkeys).
_RAW_PARAM_NAMES: List[str] = [
    "debug", "test", "admin", "id", "callback", "next", "return",
    "redirect", "url", "uri", "path", "goto", "continue", "back",
    "ref", "referrer", "referer", "target", "to", "from", "src",
    "dest", "destination", "origin", "host", "domain", "email",
    "user", "username", "login", "password", "pwd", "auth",
    "token", "api_key", "key", "secret", "access_token",
    "refresh_token", "bearer", "session", "sessionid", "sid",
    "jsessionid", "phpsessid", "aspsessionid", "cfid", "cftoken",
    "format", "output", "type", "extension", "lang", "language",
    "locale", "timezone", "region", "country", "charset", "encoding",
    "jsonp", "json", "xml", "csv", "html", "txt",
    "download", "export", "import", "upload", "file", "filename",
    "action", "method", "_method", "verb", "cmd", "command",
    "exec", "execute", "run", "eval", "expression", "code",
    "search", "query", "q", "filter", "sort", "order",
    "page", "pagesize", "limit", "offset", "skip", "take",
    "per_page", "per-page", "count", "max", "min", "range",
    "start", "end", "begin", "finish", "from_date", "to_date",
    "date", "time", "timestamp", "version", "v", "api",
    "verbose", "trace", "log", "level",
    "cache", "nocache", "bypass", "flush", "clear",
    "force", "override", "allow", "deny", "permit", "block",
    "moderator", "role", "permission", "access",
    "public", "private", "draft", "publish", "unpublish",
    "active", "inactive", "enable", "disable", "delete",
    "restore", "undelete", "archive", "unarchive", "backup",
    "restore_from", "restore_to", "migrate", "sync",
    "_callback", "success", "error", "fail",
    "message", "msg", "alert", "notice", "warning",
    "include", "exclude", "omit", "only",
    "fields", "columns", "attributes", "props", "properties",
    "expand", "collapse", "full", "summary", "minimal",
    "width", "height", "size", "scale", "zoom",
    "color", "theme", "style", "template", "layout",
    "sort_by", "sort-by", "orderby", "order-by",
    "filter_by", "filter-by", "search_by", "search-by",
    "group_by", "group-by", "group", "grouping",
    "category", "subcategory", "subtype",
    "tag", "tags", "label", "labels", "keyword", "keywords",
    "index", "indices", "array", "list", "collection",
    "item", "object", "parent", "child", "sibling",
    "first", "last", "prev", "current",
    "default", "fallback", "alternative", "option",
    "param", "parameter", "arg", "argument",
    "flag", "switch", "toggle", "checkbox", "radio",
    "select", "choice", "pick", "choose", "decide",
    "confirmation", "confirm", "verify", "validate",
    "sign", "signature", "mac", "hmac", "hash",
    "nonce", "csrf", "xsrf", "state", "challenge",
    "callback_url", "webhook", "hook", "listener",
    "endpoint", "service", "provider", "handler",
    "config", "configuration", "settings", "preference",
    "setting", "property", "attribute",
    "data", "payload", "body", "content", "value",
    "raw", "encoded", "decoded", "compressed",
    "digest", "checksum",
]
PARAM_NAMES: List[str] = list(dict.fromkeys(_RAW_PARAM_NAMES))

LABELS = {
    "en": {
        "target": "Target",
        "params_tested": "Parameters tested",
        "threshold": "Threshold",
        "findings_header": "Hidden parameters found",
        "no_findings": "No parameters detected beyond baseline.",
        "baseline_status": "Baseline status",
        "baseline_length": "Baseline response length",
        "difference": "Difference",
        "status_change": "Status changed",
        "length_delta": "Length delta",
        "reflected": "Parameter reflected in response",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "params_tested": "Parâmetros testados",
        "threshold": "Limiar",
        "findings_header": "Parâmetros ocultos encontrados",
        "no_findings": "Nenhum parâmetro detetado além da baseline.",
        "baseline_status": "Status da baseline",
        "baseline_length": "Tamanho da resposta baseline",
        "difference": "Diferença",
        "status_change": "Status alterou",
        "length_delta": "Delta de tamanho",
        "reflected": "Parâmetro refletido na resposta",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "label": "Parameter '{}' detected",
        "risk": (
            "Hidden parameters may indicate overlooked functionality, internal flags, "
            "or mass-assignment vulnerabilities. Cache poisoning, feature-flag bypass, "
            "and authentication bypass often leverage undocumented parameters."
        ),
        "fix": (
            "Document all parameters your API accepts. Implement strict parameter "
            "validation and reject unexpected keys. Use an allowlist of known parameters "
            "rather than a blacklist of forbidden ones."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "label": "Parâmetro '{}' detetado",
        "risk": (
            "Parâmetros ocultos podem indicar funcionalidade esquecida, flags internas, "
            "ou vulnerabilidades de mass-assignment. Cache poisoning, bypass de feature "
            "flags, e bypass de autenticação frequentemente exploram parâmetros não documentados."
        ),
        "fix": (
            "Documenta todos os parâmetros que a tua API aceita. Implementa validação "
            "estrita de parâmetros e rejeita chaves inesperadas. Usa uma allowlist de "
            "parâmetros conhecidos em vez de uma blacklist de proibidos."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}


@dataclass
class Finding:
    param: str
    status: int
    length: int
    reflected: bool


@dataclass
class Baseline:
    status: int
    length: int


def _fetch(url: str, timeout: float, user_agent: str) -> tuple[Optional[int], Optional[int], Optional[str]]:
    """Fetch a URL and return (status, body_length, body). Returns (None, None, None) on error."""
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, len(body), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, len(body), body
    except (urllib.error.URLError, socket.timeout, OSError):
        return None, None, None


def _build_test_url(base_url: str, param: str) -> str:
    """Append a test parameter with a canary value."""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [f"canary{hash(param) % 10000}"]
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
    )


def _probe(
    base_url: str,
    param: str,
    baseline: Baseline,
    timeout: float,
    user_agent: str,
    threshold: int,
) -> Optional[Finding]:
    """Probe a parameter and return a Finding if it differs from baseline."""
    test_url = _build_test_url(base_url, param)
    status, length, body = _fetch(test_url, timeout, user_agent)
    if status is None:
        return None

    # Check for differences: status change, or length delta >= threshold
    status_changed = status != baseline.status
    length_delta = abs(length - baseline.length)
    length_different = length_delta >= threshold

    # Check if the parameter name or value appears reflected
    reflected = (param in (body or "")) or (f"canary{hash(param) % 10000}" in (body or ""))

    if status_changed or length_different or reflected:
        return Finding(param=param, status=status, length=length, reflected=reflected)
    return None


def run(
    url: str,
    timeout: float,
    user_agent: str,
    threshold: int,
    threads: int,
) -> tuple[List[Finding], Baseline]:
    # Get baseline
    status, length, _ = _fetch(url, timeout, user_agent)
    if status is None:
        return [], Baseline(0, 0)
    baseline = Baseline(status, length)

    # Fuzz parameters
    findings: List[Finding] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(_probe, url, param, baseline, timeout, user_agent, threshold): param
            for param in PARAM_NAMES
        }
        for future in as_completed(futures):
            f = future.result()
            if f:
                findings.append(f)

    return findings, baseline


def print_human(url: str, findings: List[Finding], baseline: Baseline, all_params: int, lang: str) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]

    print(f"\n{L['target']}: {url}")
    print(f"{L['params_tested']}: {all_params}")
    print(f"{L['baseline_status']}: {baseline.status}  |  {L['baseline_length']}: {baseline.length} bytes")
    print()

    if findings:
        print(f"{L['findings_header']} ({len(findings)}):\n")
        for f in findings:
            extra = " (reflected)" if f.reflected else ""
            print(f"  ✗ {IT['label'].format(f.param)}{extra}")
            print(f"     {L['status_change']}: {baseline.status} → {f.status}")
            print(f"     {L['length_delta']}: {baseline.length} → {f.length} bytes ({f.length - baseline.length:+d})")
            print(f"     {IT['risk_label']} {IT['risk']}")
            print(f"     {IT['fix_label']} {IT['fix']}")
            print()
    else:
        print(L["no_findings"])
    print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Discover hidden query parameters by fuzzing a wordlist.",
    )
    add_version_arg(parser, TOOL_NAME)
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument(
        "url",
        help="Target URL (http:// or https://). Use '-' to read from stdin.",
    )
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Per-request timeout. Default: 10.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="BYTES",
        help="Minimum response size delta to flag. Default: 5 bytes.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent probes. Default: 10.",
    )
    args = parser.parse_args()

    L = LABELS[args.lang]
    USER_AGENT = args.user_agent
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    findings, baseline = run(args.url, args.timeout, USER_AGENT, args.threshold, args.threads)

    if args.as_json:
        print(json.dumps({
            "url": args.url,
            "lang": args.lang,
            "baseline": asdict(baseline),
            "params_tested": len(PARAM_NAMES),
            "threshold_bytes": args.threshold,
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, findings, baseline, len(PARAM_NAMES), args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
