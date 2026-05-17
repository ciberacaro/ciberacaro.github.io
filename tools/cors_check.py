#!/usr/bin/env python3
"""Probe a URL for dangerous CORS configurations.

Sends requests with several different Origin headers and reports how the
server responds. Flags reflected origins, wildcard + credentials,
null acceptance, and pre-suffix tricks.

Examples:
    tools/cors_check.py https://api.example.com/users/me
    tools/cors_check.py https://api.example.com/users/me --lang pt
    tools/cors_check.py https://api.example.com/users/me --json
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
from dataclasses import asdict, dataclass, field
from typing import Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg

USER_AGENT = make_user_agent("cors_check.py")
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "target": "Target",
        "probes": "Probes",
        "probe_origin": "Origin",
        "response": "ACAO",
        "credentials": "ACAC",
        "status": "status",
        "issues_header": "Issues found",
        "no_issues": "No risky CORS behaviour detected with the probes tried.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "probes": "Sondagens",
        "probe_origin": "Origin",
        "response": "ACAO",
        "credentials": "ACAC",
        "status": "estado",
        "issues_header": "Problemas encontrados",
        "no_issues": "Nenhum comportamento CORS perigoso detetado com as sondagens tentadas.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "reflected_origin": {
        "en": ("Server reflects arbitrary Origin ({})",
               "Validate Origin against an allowlist server-side. Never echo the request's Origin back."),
        "pt": ("Servidor reflete Origin arbitrário ({})",
               "Valida Origin contra uma allowlist no servidor. Nunca devolvas o Origin do pedido."),
    },
    "wildcard_with_credentials": {
        "en": ("Wildcard ACAO ('*') with Allow-Credentials: true",
               "Browsers reject this, but the misconfig signals broken intent. Use an explicit origin or remove credentials."),
        "pt": ("ACAO wildcard ('*') com Allow-Credentials: true",
               "Os browsers rejeitam isto, mas a má configuração revela uma intenção partida. Usa um Origin explícito ou remove credentials."),
    },
    "null_accepted": {
        "en": ("Server accepts Origin: null with Allow-Credentials: true",
               "`null` is sent by sandboxed iframes, file:// pages, and some redirects — easy attacker path."),
        "pt": ("Servidor aceita Origin: null com Allow-Credentials: true",
               "`null` é enviado por iframes em sandbox, páginas file:// e alguns redirects — caminho fácil para um atacante."),
    },
    "suffix_trick": {
        "en": ("Server reflects an origin that ends with the target domain ({}) — possible suffix-match bug",
               "Validate Origin with an exact match (with host parsing), not endswith/contains."),
        "pt": ("Servidor reflete um origin que termina com o domínio alvo ({}) — possível bug de suffix-match",
               "Valida Origin com correspondência exata (com host parsing), não endswith/contains."),
    },
    "prefix_trick": {
        "en": ("Server reflects an origin that starts with the target domain ({}) — possible prefix-match bug",
               "Same as above — exact match only."),
        "pt": ("Servidor reflete um origin que começa com o domínio alvo ({}) — possível bug de prefix-match",
               "Mesmo problema do anterior — só correspondência exata."),
    },
}


@dataclass
class Probe:
    origin: str
    method: str  # 'GET' or 'OPTIONS' (preflight)
    acao: Optional[str]
    acac: Optional[str]
    acam: Optional[str]  # Access-Control-Allow-Methods
    acah: Optional[str]  # Access-Control-Allow-Headers
    status: int
    error: Optional[str] = None


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


def _read_cors_headers(resp_headers) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    if resp_headers is None:
        return (None, None, None, None)
    return (
        resp_headers.get("Access-Control-Allow-Origin"),
        resp_headers.get("Access-Control-Allow-Credentials"),
        resp_headers.get("Access-Control-Allow-Methods"),
        resp_headers.get("Access-Control-Allow-Headers"),
    )


def probe(url: str, origin: Optional[str], method: str, timeout: float) -> Probe:
    headers = {"User-Agent": USER_AGENT}
    if origin is not None:
        headers["Origin"] = origin
    if method == "OPTIONS":
        # Preflight needs these two request headers to trigger a real
        # preflight response from the target.
        headers["Access-Control-Request-Method"] = "PUT"
        headers["Access-Control-Request-Headers"] = "X-Probe-Header"
    req = urllib.request.Request(url, headers=headers, method=method)
    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            acao, acac, acam, acah = _read_cors_headers(resp.headers)
            return Probe(origin=origin or "", method=method, acao=acao, acac=acac,
                         acam=acam, acah=acah, status=resp.status)
    except urllib.error.HTTPError as e:
        acao, acac, acam, acah = _read_cors_headers(e.headers)
        return Probe(origin=origin or "", method=method, acao=acao, acac=acac,
                     acam=acam, acah=acah, status=e.code)
    except (urllib.error.URLError, socket.timeout) as e:
        return Probe(origin=origin or "", method=method, acao=None, acac=None,
                     acam=None, acah=None, status=0, error=str(e))


def build_probes(url: str) -> list[str]:
    """Return Origin values to probe."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    return [
        f"https://attacker.example",        # arbitrary attacker origin
        f"null",                            # null origin
        f"https://{host}.attacker.example", # prefix trick
        f"https://attacker.example.{host}", # suffix trick (likely not registered, but the matcher might be loose)
        f"https://{host}",                  # legitimate, sanity check
    ]


def evaluate(probes: list[Probe], target_host: str, lang: str) -> list[Issue]:
    issues = []
    seen_keys = set()
    target_host = target_host.lower()

    for p in probes:
        if p.error or p.acao is None:
            continue
        acao = p.acao.strip()
        acac_true = (p.acac or "").strip().lower() == "true"

        # Wildcard + credentials
        if acao == "*" and acac_true and "wildcard_with_credentials" not in seen_keys:
            t = ISSUE_TEXT["wildcard_with_credentials"][lang]
            issues.append(Issue("wildcard_with_credentials", t[0], t[0], t[1]))
            seen_keys.add("wildcard_with_credentials")

        # null accepted with credentials
        if p.origin == "null" and acao.lower() == "null" and acac_true and "null_accepted" not in seen_keys:
            t = ISSUE_TEXT["null_accepted"][lang]
            issues.append(Issue("null_accepted", t[0], t[0], t[1]))
            seen_keys.add("null_accepted")

        # Reflected origin == sent origin (and the sent origin isn't the legit one)
        if acao.lower() == p.origin.lower() and p.origin and p.origin != f"https://{target_host}":
            key = "reflected_origin"
            if key not in seen_keys:
                t = ISSUE_TEXT[key][lang]
                issues.append(Issue(key, t[0].format(p.origin), t[0].format(p.origin), t[1]))
                seen_keys.add(key)

        # Prefix / suffix tricks
        if "attacker" in p.origin.lower() and acao.lower() == p.origin.lower():
            host_in_origin = urllib.parse.urlparse(p.origin).hostname or ""
            if host_in_origin.endswith(target_host) and host_in_origin != target_host:
                key = "prefix_trick"
                if key not in seen_keys:
                    t = ISSUE_TEXT[key][lang]
                    issues.append(Issue(key, t[0].format(p.origin), t[0].format(p.origin), t[1]))
                    seen_keys.add(key)
            elif host_in_origin.startswith(target_host):
                key = "suffix_trick"
                if key not in seen_keys:
                    t = ISSUE_TEXT[key][lang]
                    issues.append(Issue(key, t[0].format(p.origin), t[0].format(p.origin), t[1]))
                    seen_keys.add(key)

    return issues


def print_human(url: str, probes: list[Probe], issues: list[Issue], lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['target']}: {url}\n")
    print(f"{L['probes']}:")
    name_width = max(len(p.origin or "(none)") for p in probes)
    for p in probes:
        origin_display = p.origin or "(none)"
        if p.error:
            print(f"  - {p.method:<7} {origin_display:<{name_width}}  ERROR: {p.error}")
            continue
        acao = p.acao or "—"
        acac = p.acac or "—"
        extra = ""
        if p.method == "OPTIONS":
            extra = f"  ACAM: {p.acam or '—'}  ACAH: {p.acah or '—'}"
        print(f"  - {p.method:<7} {origin_display:<{name_width}}  [{L['status']}: {p.status}]  {L['response']}: {acao}  {L['credentials']}: {acac}{extra}")

    if issues:
        print(f"\n{L['issues_header']} ({len(issues)}):")
        for iss in issues:
            print(f"\n  ✗ {iss.label}")
            print(f"     {L['risk_label']} {iss.risk}")
            print(f"     {L['fix_label']}{iss.fix}")
    else:
        print(f"\n{L['no_issues']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe a URL for risky CORS configurations.",
    )
    add_version_arg(parser, "cors_check.py")
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument("url", help="Target URL (http:// or https://). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]
    global USER_AGENT
    USER_AGENT = args.user_agent
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or ""
    origins = build_probes(args.url)
    probes = []
    for origin in origins:
        probes.append(probe(args.url, origin, "GET", args.timeout))
        probes.append(probe(args.url, origin, "OPTIONS", args.timeout))
    issues = evaluate(probes, host, args.lang)

    if args.json:
        out = {
            "url": args.url,
            "lang": args.lang,
            "probes": [asdict(p) for p in probes],
            "issues": [asdict(i) for i in issues],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, probes, issues, args.lang)

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
