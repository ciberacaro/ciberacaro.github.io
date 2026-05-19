#!/usr/bin/env python3
"""Test for CRLF injection (HTTP response splitting) vulnerabilities.

Uses http.client directly (bypassing urllib's URL encoding) to inject CRLF
sequences into the URL path and query parameters. If the server reflects the
injected newlines into its response headers, an attacker can insert arbitrary
headers into the HTTP response.

Exit codes:
  0  No CRLF injection detected
  1  One or more injection points found
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/crlf_inject.py https://example.com/page
    tools/crlf_inject.py https://example.com/login?next=/dashboard --lang pt
    tools/crlf_inject.py https://example.com/page --json
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from _lib import (
    build_ssl_context,
    make_user_agent,
    add_version_arg,
    add_user_agent_arg,
    stdin_or_arg,
)

TOOL_NAME = "crlf_inject.py"
USER_AGENT = make_user_agent(TOOL_NAME)
LANGS = ("en", "pt")

# Canary header name — easy to recognise in the response.
CANARY_HEADER = "X-Crlf-Test"
CANARY_VALUE = "injected"

# Payloads: raw strings to append to the path or a param value.
# The http.client layer does NOT re-encode these, so they reach the server as-is.
PAYLOADS: List[Tuple[str, str]] = [
    (f"%0d%0a{CANARY_HEADER}:%20{CANARY_VALUE}", "CR+LF percent-encoded (%0d%0a)"),
    (f"%0a{CANARY_HEADER}:%20{CANARY_VALUE}", "LF-only percent-encoded (%0a)"),
    (f"%0d{CANARY_HEADER}:%20{CANARY_VALUE}", "CR-only percent-encoded (%0d)"),
    (f"%0D%0A{CANARY_HEADER}:%20{CANARY_VALUE}", "CR+LF uppercase (%0D%0A)"),
    (f"%E5%98%8A%E5%98%8D{CANARY_HEADER}:%20{CANARY_VALUE}", "Unicode CRLF (%E5%98%8A%E5%98%8D)"),
    # Double URL-encoded — bypass WAFs that decode only once before forwarding
    (f"%250d%250a{CANARY_HEADER}:%20{CANARY_VALUE}", "Double-encoded CR+LF (%250d%250a)"),
    (f"%250D%250A{CANARY_HEADER}:%20{CANARY_VALUE}", "Double-encoded CR+LF uppercase (%250D%250A)"),
    (f"%250a{CANARY_HEADER}:%20{CANARY_VALUE}", "Double-encoded LF (%250a)"),
]

LABELS = {
    "en": {
        "target": "Target",
        "tests": "Tests run",
        "findings_header": "CRLF injection found",
        "no_findings": "No CRLF injection detected with the payloads tried.",
        "injection_point": "Injection point",
        "payload_used": "Payload",
        "canary_found": "Canary header in response",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "tests": "Testes executados",
        "findings_header": "Injeção CRLF encontrada",
        "no_findings": "Nenhuma injeção CRLF detetada com os payloads tentados.",
        "injection_point": "Ponto de injeção",
        "payload_used": "Payload",
        "canary_found": "Cabeçalho canary na resposta",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "label": "CRLF injection confirmed at {} with payload: {}",
        "risk": (
            "HTTP response splitting allows an attacker to inject arbitrary headers into "
            "the response. Consequences include: session fixation via Set-Cookie injection, "
            "XSS via injecting a crafted body, cache poisoning to serve malicious content "
            "to other users, and redirect via a Location header."
        ),
        "fix": (
            "Strip or reject CR (\\r, %0d) and LF (\\n, %0a) characters from any input that "
            "is reflected in HTTP response headers. Apply this validation server-side before "
            "placing user input in Location, Set-Cookie, or any other header."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "label": "Injeção CRLF confirmada em {} com payload: {}",
        "risk": (
            "HTTP response splitting permite que um atacante injete cabeçalhos arbitrários "
            "na resposta. Consequências incluem: fixação de sessão via injeção de Set-Cookie, "
            "XSS via injeção de body manipulado, cache poisoning para servir conteúdo "
            "malicioso a outros utilizadores, e redirect via header Location."
        ),
        "fix": (
            "Remove ou rejeita caracteres CR (\\r, %0d) e LF (\\n, %0a) de qualquer input "
            "que seja refletido em cabeçalhos de resposta HTTP. Aplica esta validação no "
            "servidor antes de colocar input do utilizador em Location, Set-Cookie, ou "
            "qualquer outro cabeçalho."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}


@dataclass
class Finding:
    injection_point: str
    payload_desc: str
    payload: str
    canary_header_value: str


def _connect(host: str, port: int, use_https: bool, timeout: float) -> Optional[http.client.HTTPConnection]:
    """Open an http.client connection, with SSL context if needed."""
    try:
        if use_https:
            ctx = build_ssl_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        return conn
    except Exception:
        return None


def _probe_path(
    host: str,
    port: int,
    base_path: str,
    query: str,
    use_https: bool,
    payload: str,
    payload_desc: str,
    timeout: float,
    user_agent: str,
) -> Optional[Finding]:
    """Inject CRLF into the URL path and check if canary appears in response headers."""
    # Build the raw request target: path + payload + query
    # http.client does NOT URL-encode the request target, so payload reaches server raw.
    raw_path = base_path + payload
    if query:
        raw_path = raw_path + "?" + query

    conn = _connect(host, port, use_https, timeout)
    if conn is None:
        return None
    try:
        conn.request("GET", raw_path, headers={"User-Agent": user_agent, "Connection": "close"})
        resp = conn.getresponse()
        headers = dict(resp.getheaders())
        # Check if the canary header was injected into the response
        for hname, hval in headers.items():
            if hname.lower() == CANARY_HEADER.lower() and CANARY_VALUE in hval:
                return Finding(
                    injection_point="URL path",
                    payload_desc=payload_desc,
                    payload=payload,
                    canary_header_value=f"{hname}: {hval}",
                )
        return None
    except (http.client.HTTPException, socket.error, OSError):
        return None
    finally:
        conn.close()


def _probe_query(
    host: str,
    port: int,
    base_path: str,
    qs: dict,
    use_https: bool,
    payload: str,
    payload_desc: str,
    timeout: float,
    user_agent: str,
    max_params: int = 3,
) -> Optional[Finding]:
    """Inject CRLF into a query parameter value and check for header injection."""
    # For each existing query param, inject the payload as its value.
    # Also test with a fresh 'url' param if no query string exists.
    test_params = list(qs.keys()) if qs else ["url"]

    for param in test_params[:max_params]:
        injected_qs = dict(qs)
        injected_qs[param] = payload
        # Build raw query string without re-encoding the payload value
        # We manually construct the query to avoid double-encoding.
        parts = []
        for k, v in injected_qs.items():
            if k == param:
                parts.append(f"{urllib.parse.quote(k)}={payload}")
            else:
                vals = v if isinstance(v, list) else [v]
                for val in vals:
                    parts.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(val))}")
        raw_path = base_path + "?" + "&".join(parts)

        conn = _connect(host, port, use_https, timeout)
        if conn is None:
            continue
        try:
            conn.request("GET", raw_path, headers={"User-Agent": user_agent, "Connection": "close"})
            resp = conn.getresponse()
            headers = dict(resp.getheaders())
            for hname, hval in headers.items():
                if hname.lower() == CANARY_HEADER.lower() and CANARY_VALUE in hval:
                    return Finding(
                        injection_point=f"query parameter '{param}'",
                        payload_desc=payload_desc,
                        payload=payload,
                        canary_header_value=f"{hname}: {hval}",
                    )
        except (http.client.HTTPException, socket.error, OSError):
            pass
        finally:
            conn.close()
    return None


def run(url: str, timeout: float, user_agent: str, max_params: int = 3) -> Tuple[List[Finding], int]:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_https = parsed.scheme == "https"
    base_path = parsed.path or "/"
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    findings: List[Finding] = []
    tests_run = 0
    seen_points: set = set()

    for payload, payload_desc in PAYLOADS:
        # Test path injection
        f = _probe_path(host, port, base_path, parsed.query, use_https, payload, payload_desc, timeout, user_agent)
        tests_run += 1
        if f and "path" not in seen_points:
            findings.append(f)
            seen_points.add("path")

        # Test query injection
        f = _probe_query(host, port, base_path, qs, use_https, payload, payload_desc, timeout, user_agent, max_params)
        tests_run += 1
        if f and "query" not in seen_points:
            findings.append(f)
            seen_points.add("query")

    return findings, tests_run


def print_human(url: str, findings: List[Finding], tests_run: int, lang: str) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]

    print(f"\n{L['target']}: {url}")
    print(f"{L['tests']}: {tests_run}  ({len(PAYLOADS)} payloads × path + query params)")
    print()

    if findings:
        print(f"{L['findings_header']} ({len(findings)}):\n")
        for f in findings:
            print(f"  ✗ {IT['label'].format(f.injection_point, f.payload_desc)}")
            print(f"     {L['injection_point']}: {f.injection_point}")
            print(f"     {L['payload_used']}: {f.payload}")
            print(f"     {L['canary_found']}: {f.canary_header_value}")
            print(f"     {IT['risk_label']} {IT['risk']}")
            print(f"     {IT['fix_label']} {IT['fix']}")
            print()
    else:
        print(L["no_findings"])
    print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Test for HTTP response splitting (CRLF injection) vulnerabilities.",
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
        "--max-params",
        type=int,
        default=3,
        metavar="N",
        help="Max query parameters to test per payload. Default: 3.",
    )
    args = parser.parse_args()

    L = LABELS[args.lang]
    USER_AGENT = args.user_agent
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    findings, tests_run = run(args.url, args.timeout, USER_AGENT, max_params=args.max_params)

    if args.as_json:
        print(json.dumps({
            "url": args.url,
            "lang": args.lang,
            "tests_run": tests_run,
            "payloads": [p[0] for p in PAYLOADS],
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, findings, tests_run, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
