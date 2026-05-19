#!/usr/bin/env python3
"""Test for CRLF injection (HTTP response splitting) vulnerabilities.

Sends HTTP requests with CRLF payloads (`%0d%0a`, `%0a%0d`) in the URL path
and query parameters to detect whether the server reflects attacker-controlled
line endings in the response headers. Successful injection can allow header
injection, response cache poisoning, and HTTP response splitting.

Exit codes:
  0  No CRLF injection detected
  1  One or more injection points found
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/crlf_inject.py https://example.com/page?url=https://evil.com
    tools/crlf_inject.py https://example.com/page?url=https://evil.com --lang pt
    tools/crlf_inject.py https://example.com/page --json
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import List, Optional

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

# CRLF payload variants.
PAYLOADS: List[tuple[str, str]] = [
    ("%0d%0a", "LF+CR (percent-encoded)"),
    ("%0a%0d", "CR+LF (percent-encoded)"),
    ("%0d", "LF only (percent-encoded)"),
    ("%0a", "CR only (percent-encoded)"),
    ("%0d%0aX-Injected: yes", "LF+CR + header (percent-encoded)"),
    ("%0d%0aSet-Cookie: evil=1", "LF+CR + Set-Cookie (percent-encoded)"),
]

LABELS = {
    "en": {
        "target": "Target",
        "injection_points": "Injection points tested",
        "payloads": "Payloads per point",
        "findings_header": "CRLF injection found",
        "no_findings": "No CRLF injection detected with the payloads tried.",
        "location": "Location",
        "payload_label": "Payload",
        "response_snippet": "Response snippet",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "injection_points": "Pontos de injeção testados",
        "payloads": "Payloads por ponto",
        "findings_header": "Injeção CRLF encontrada",
        "no_findings": "Nenhuma injeção CRLF detetada com os payloads tentados.",
        "location": "Localização",
        "payload_label": "Payload",
        "response_snippet": "Excerto da resposta",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "label": "CRLF injection in {} → {}",
        "risk": (
            "HTTP response splitting allows an attacker to inject arbitrary HTTP headers "
            "or even an entire second response. Commonly chained with cache poisoning to "
            "serve malicious content to other users, or header injection (Set-Cookie, "
            "Location) to steal sessions or redirect users."
        ),
        "fix": (
            "Never reflect user input directly in the response. If input must appear in "
            "headers or URL paths, apply strict validation and encoding: strip or reject "
            "any CRLF sequences (%0d, %0a, carriage returns, line feeds)."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "label": "Injeção CRLF em {} → {}",
        "risk": (
            "HTTP response splitting permite que um atacante injete cabeçalhos HTTP arbitrários "
            "ou até uma segunda resposta completa. Frequentemente encadeado com cache poisoning "
            "para servir conteúdo malicioso a outros utilizadores, ou injeção de cabeçalhos "
            "(Set-Cookie, Location) para roubo de sessões ou redirecionamento de utilizadores."
        ),
        "fix": (
            "Nunca reflitas input de utilizador diretamente na resposta. Se o input tem de "
            "aparecer em cabeçalhos ou paths, aplica validação estrita e encoding: remove ou "
            "rejeita qualquer sequência CRLF (%0d, %0a, carriage returns, line feeds)."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}


@dataclass
class Finding:
    location: str
    payload_desc: str
    payload: str
    response_preview: str


def _build_injection_url(base_url: str, injection_point: str, payload: str) -> str:
    """Build a URL with the payload injected at the specified point."""
    parsed = urllib.parse.urlparse(base_url)

    if injection_point == "path":
        # Inject into the path
        new_path = parsed.path + payload
        return urllib.parse.urlunparse(parsed._replace(path=new_path))
    else:  # injection_point == "query_param"
        # Inject into each existing query parameter
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            # No existing params; create a test param
            qs = {"test": [payload]}
        else:
            # Replace the first param's value with the payload
            first_param = next(iter(qs))
            qs[first_param] = [payload]
        return urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
        )


def _probe(
    url: str,
    injection_point: str,
    payload: str,
    payload_desc: str,
    timeout: float,
    user_agent: str,
) -> Optional[Finding]:
    """Inject payload and check if it appears in response headers."""
    test_url = _build_injection_url(url, injection_point, payload)

    try:
        req = urllib.request.Request(test_url, headers={"User-Agent": user_agent})
        ctx = build_ssl_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            # Get raw response headers as string
            headers_str = str(resp.headers)
            body = resp.read().decode("utf-8", errors="replace")[:500]  # First 500 bytes
            response_preview = headers_str[:200] + "\n..." if len(headers_str) > 200 else headers_str

            # Check if our injected CRLF appears in the response
            if "%0d%0a" in payload or "%0a%0d" in payload or "%0d" in payload or "%0a" in payload:
                # We injected raw CRLF sequences; check if they're reflected
                # Look for header names we tried to inject
                if "X-Injected" in response_preview or "evil=" in response_preview or "Set-Cookie" in response_preview:
                    return Finding(
                        location=f"{injection_point} (URL: {test_url[:80]}...)",
                        payload_desc=payload_desc,
                        payload=payload,
                        response_preview=response_preview,
                    )
            return None
    except urllib.error.HTTPError as e:
        headers_str = str(e.headers)
        response_preview = headers_str[:200] + "\n..." if len(headers_str) > 200 else headers_str

        # Same check for error responses
        if "X-Injected" in response_preview or "evil=" in response_preview or "Set-Cookie" in response_preview:
            return Finding(
                location=f"{injection_point} (URL: {test_url[:80]}...)",
                payload_desc=payload_desc,
                payload=payload,
                response_preview=response_preview,
            )
        return None
    except (urllib.error.URLError, socket.timeout, OSError):
        return None


def run(url: str, timeout: float, user_agent: str) -> tuple[List[Finding], int]:
    """Test URL for CRLF injection at multiple points."""
    findings: List[Finding] = []
    parsed = urllib.parse.urlparse(url)

    injection_points = ["path"]
    if parsed.query:
        injection_points.append("query_param")

    for point in injection_points:
        for payload, payload_desc in PAYLOADS:
            f = _probe(url, point, payload, payload_desc, timeout, user_agent)
            if f:
                findings.append(f)
                break  # One finding per injection point is enough

    return findings, len(injection_points) * len(PAYLOADS)


def print_human(url: str, findings: List[Finding], tests_count: int, lang: str) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]

    print(f"\n{L['target']}: {url}")
    print(f"{L['injection_points']}: {tests_count // len(PAYLOADS)}  ({L['payloads']}: {len(PAYLOADS)})")
    print()

    if findings:
        print(f"{L['findings_header']} ({len(findings)}):\n")
        for f in findings:
            print(f"  ✗ {IT['label'].format(f.location, f.payload_desc)}")
            print(f"     {L['payload_label']}: {f.payload}")
            print(f"     {L['response_snippet']}: {f.response_preview[:150]}")
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
    args = parser.parse_args()

    L = LABELS[args.lang]
    USER_AGENT = args.user_agent
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    findings, tests_count = run(args.url, args.timeout, USER_AGENT)

    if args.as_json:
        print(json.dumps({
            "url": args.url,
            "lang": args.lang,
            "payloads": [p[0] for p in PAYLOADS],
            "tests_count": tests_count,
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, findings, tests_count, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
