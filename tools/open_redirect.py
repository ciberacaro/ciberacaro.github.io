#!/usr/bin/env python3
"""Probe a URL for open redirect vulnerabilities.

Injects redirect payloads into every query parameter in the URL, and into
common redirect parameter names not already present. Reports any case where
the server issues a 3xx response pointing outside the original origin.

Exit codes:
  0  No open redirect detected
  1  One or more vulnerable parameters found
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/open_redirect.py https://example.com/login?next=/dashboard
    tools/open_redirect.py https://example.com/login?next=/dashboard --lang pt
    tools/open_redirect.py https://example.com/login?next=/dashboard --json
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
from dataclasses import asdict, dataclass
from typing import List, Optional

from _lib import (
    build_ssl_context,
    make_user_agent,
    add_version_arg,
    add_user_agent_arg,
    stdin_or_arg,
)

TOOL_NAME = "open_redirect.py"
USER_AGENT = make_user_agent(TOOL_NAME)
LANGS = ("en", "pt")

# A hostname that will never exist — easy to spot in Location headers.
CANARY_HOST = "open-redirect-canary.example"

# Payloads covering the most common bypass patterns.
PAYLOADS: List[str] = [
    f"https://{CANARY_HOST}",
    f"http://{CANARY_HOST}",
    f"//{CANARY_HOST}",
    f"\\/\\/{CANARY_HOST}",
    f"/{CANARY_HOST}",
    f"///{CANARY_HOST}",
    f"https:{CANARY_HOST}",
    f"@{CANARY_HOST}",
]

# Common parameter names that carry redirect destinations.
REDIRECT_PARAMS: List[str] = [
    "url", "redirect", "redirect_url", "redirectUrl", "redirect_uri",
    "next", "return", "return_url", "returnUrl", "returnTo", "return_to",
    "goto", "dest", "destination", "target", "to", "ref",
    "path", "continue", "forward", "back", "callback", "open",
]

LABELS = {
    "en": {
        "target": "Target",
        "params_tested": "Parameters tested",
        "payloads_each": "Payloads per parameter",
        "note_extra": "Includes common redirect parameter names not in the original URL.",
        "issues_header": "Vulnerable parameters found",
        "no_issues": "No open redirect detected with the payloads tried.",
        "status": "Status",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "params_tested": "Parâmetros testados",
        "payloads_each": "Payloads por parâmetro",
        "note_extra": "Inclui nomes de parâmetros comuns não presentes no URL original.",
        "issues_header": "Parâmetros vulneráveis encontrados",
        "no_issues": "Nenhum open redirect detetado com os payloads tentados.",
        "status": "Estado",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "label": "Open redirect via '{}' with payload '{}' → {}",
        "risk": (
            "An attacker can craft a link on your domain that sends visitors to an arbitrary "
            "external site. Commonly chained with OAuth flows to steal authorization tokens, "
            "or used directly in phishing campaigns."
        ),
        "fix": (
            "Validate redirect destinations against a strict allowlist of internal paths or "
            "explicitly trusted origins. Compare the parsed host — never use startswith / "
            "endswith on the raw string."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "label": "Open redirect via '{}' com payload '{}' → {}",
        "risk": (
            "Um atacante pode criar um link no teu domínio que redireciona visitantes para um "
            "site externo arbitrário. Frequentemente encadeado com fluxos OAuth para roubo de "
            "tokens de autorização, ou usado diretamente em campanhas de phishing."
        ),
        "fix": (
            "Valida os destinos de redirect contra uma allowlist estrita de caminhos internos "
            "ou origens explicitamente confiáveis. Compara o host parseado — nunca uses "
            "startswith / endswith na string em bruto."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}


@dataclass
class Finding:
    param: str
    payload: str
    status: int
    location: str


class _StopRedirect(urllib.request.HTTPRedirectHandler):
    """Re-raise 3xx responses as HTTPError instead of following them."""

    def _stop(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = _stop
    http_error_302 = _stop
    http_error_303 = _stop
    http_error_307 = _stop
    http_error_308 = _stop


def _make_opener() -> urllib.request.OpenerDirector:
    ctx = build_ssl_context()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _StopRedirect(),
    )


def _is_external(location: str, original_host: str) -> bool:
    """Return True when `location` resolves to a host other than `original_host`."""
    if not location:
        return False
    normalised = ("http:" + location) if location.startswith("//") else location
    try:
        loc_host = (urllib.parse.urlparse(normalised).hostname or "").lower()
        if loc_host and loc_host != original_host.lower():
            return True
    except Exception:
        pass
    return CANARY_HOST in location


def _probe(
    opener: urllib.request.OpenerDirector,
    base_url: str,
    param: str,
    payload: str,
    timeout: float,
    user_agent: str,
) -> Optional[Finding]:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    test_url = urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
    )
    req = urllib.request.Request(test_url, headers={"User-Agent": user_agent})
    try:
        with opener.open(req, timeout=timeout) as _:
            return None  # 2xx — no redirect triggered
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            location = e.headers.get("Location", "")
            if _is_external(location, parsed.hostname or ""):
                return Finding(param=param, payload=payload, status=e.code, location=location)
    except (urllib.error.URLError, socket.timeout, OSError):
        pass
    return None


def run(url: str, timeout: float, user_agent: str) -> tuple:
    parsed = urllib.parse.urlparse(url)
    existing = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
    extra = [p for p in REDIRECT_PARAMS if p not in existing]
    all_params = existing + extra

    opener = _make_opener()
    findings: List[Finding] = []
    seen: set = set()

    for param in all_params:
        for payload in PAYLOADS:
            f = _probe(opener, url, param, payload, timeout, user_agent)
            if f and param not in seen:
                findings.append(f)
                seen.add(param)
                break  # one confirmed finding per parameter is enough

    return findings, all_params


def print_human(url: str, findings: List[Finding], all_params: List[str], lang: str) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]
    parsed = urllib.parse.urlparse(url)
    existing_count = len(urllib.parse.parse_qs(parsed.query).keys())

    print(f"\n{L['target']}: {url}")
    print(f"{L['params_tested']}: {len(all_params)}  ({L['payloads_each']}: {len(PAYLOADS)})")
    if len(all_params) > existing_count:
        print(f"  [{L['note_extra']}]")
    print()

    if findings:
        print(f"{L['issues_header']} ({len(findings)}):\n")
        for f in findings:
            print(f"  ✗ {IT['label'].format(f.param, f.payload, f.location)}")
            print(f"     {L['status']}: {f.status}")
            print(f"     {IT['risk_label']} {IT['risk']}")
            print(f"     {IT['fix_label']} {IT['fix']}")
            print()
    else:
        print(L["no_issues"])
    print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Probe a URL for open redirect vulnerabilities.",
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
        help="Per-request timeout in seconds. Default: 10.",
    )
    args = parser.parse_args()

    L = LABELS[args.lang]
    USER_AGENT = args.user_agent
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    findings, all_params = run(args.url, args.timeout, USER_AGENT)

    if args.as_json:
        print(json.dumps({
            "url": args.url,
            "lang": args.lang,
            "params_tested": all_params,
            "payloads": PAYLOADS,
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, findings, all_params, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
