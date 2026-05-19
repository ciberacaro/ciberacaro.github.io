#!/usr/bin/env python3
"""Probe for Server-Side Request Forgery (SSRF) vulnerabilities.

Tests URL parameters and common endpoint names by injecting internal
addresses (127.0.0.1, 169.254.169.254 for AWS metadata, localhost, IPv6
loopback) and checking for timing anomalies, unusual response sizes,
or error messages that indicate the server fetched the URL.

Exit codes:
  0  No SSRF evidence detected
  1  One or more potential SSRF vectors found
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/ssrf_probe.py https://example.com/fetch?url=http://target.com
    tools/ssrf_probe.py https://example.com/fetch?url=http://target.com --lang pt
    tools/ssrf_probe.py https://example.com/fetch --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
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

TOOL_NAME = "ssrf_probe.py"
USER_AGENT = make_user_agent(TOOL_NAME)
LANGS = ("en", "pt")

# Payloads targeting internal services and metadata endpoints.
PAYLOADS: List[tuple[str, str]] = [
    ("http://127.0.0.1", "localhost (IPv4)"),
    ("http://127.0.0.1:80", "localhost port 80"),
    ("http://127.0.0.1:8080", "localhost port 8080"),
    ("http://127.0.0.1:3306", "localhost port 3306 (MySQL)"),
    ("http://127.0.0.1:5432", "localhost port 5432 (PostgreSQL)"),
    ("http://127.0.0.1:6379", "localhost port 6379 (Redis)"),
    ("http://127.0.0.1:9200", "localhost port 9200 (Elasticsearch)"),
    ("http://[::1]", "IPv6 loopback"),
    ("http://localhost", "localhost by hostname"),
    ("http://169.254.169.254", "AWS metadata (IMDSv1)"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata API endpoint"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
    ("http://169.254.169.254/latest/user-data/", "AWS user data"),
    ("http://169.254.169.255", "AWS metadata (alt)"),
    ("http://metadata.google.internal", "GCP metadata"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata API"),
    ("http://169.254.169.254/metadata/v1/", "Digital Ocean metadata"),
    ("http://169.254.170.2", "Azure metadata"),
    ("http://169.254.170.2/metadata/instance", "Azure metadata API"),
    ("http://[fc00::]/metadata/v1/", "Alibaba Cloud metadata"),
    ("http://192.168.1.1", "common router IP"),
    ("http://10.0.0.1", "common internal network"),
]

LABELS = {
    "en": {
        "target": "Target",
        "params_tested": "Parameters tested",
        "payloads": "Payloads per parameter",
        "findings_header": "Potential SSRF vectors found",
        "no_findings": "No SSRF evidence detected.",
        "baseline_time": "Baseline response time",
        "payload_label": "Payload",
        "status": "Status",
        "response_size": "Response size",
        "timing_delta": "Timing delta",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "params_tested": "Parâmetros testados",
        "payloads": "Payloads por parâmetro",
        "findings_header": "Possíveis vetores SSRF encontrados",
        "no_findings": "Nenhuma evidência de SSRF detetada.",
        "baseline_time": "Tempo da resposta baseline",
        "payload_label": "Payload",
        "status": "Estado",
        "response_size": "Tamanho da resposta",
        "timing_delta": "Delta de timing",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "label": "Potential SSRF: parameter '{}' with payload '{}'",
        "risk": (
            "Server-Side Request Forgery allows an attacker to make the server issue "
            "requests to arbitrary internal or external systems. Can lead to data exfiltration "
            "(reading internal files via file:// URLs, cloud metadata endpoints), internal "
            "port scanning, bypassing IP-based access controls, and attacking internal services."
        ),
        "fix": (
            "Validate and allowlist the destinations the server is permitted to fetch from. "
            "Disable dangerous protocols (file://, gopher://, dict://). Use DNS rebinding "
            "protections and time-based request limits. Block access to metadata endpoints "
            "and internal IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, etc.)."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "label": "Possível SSRF: parâmetro '{}' com payload '{}'",
        "risk": (
            "Server-Side Request Forgery permite que um atacante force o servidor a fazer "
            "pedidos para sistemas arbitrários internos ou externos. Pode levar a exfiltração "
            "de dados (leitura de ficheiros internos via URLs file://, endpoints de metadata "
            "em cloud), scanning de portas internas, bypass de controlos baseados em IP, "
            "e ataque a serviços internos."
        ),
        "fix": (
            "Valida e allowlista os destinos que o servidor tem permissão de ir buscar. "
            "Desativa protocolos perigosos (file://, gopher://, dict://). Usa proteções contra "
            "DNS rebinding e limites de tempo por pedido. Bloqueia acesso a endpoints de "
            "metadata e ranges de IP interno (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, etc.)."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}


@dataclass
class Finding:
    param: str
    payload: str
    payload_desc: str
    status: Optional[int]
    response_size: Optional[int]
    timing_delta: float


# Common parameter names for URL input.
URL_PARAMS: List[str] = [
    "url", "uri", "href", "target", "src", "image", "avatar",
    "callback", "redirect", "next", "return", "goto", "path",
    "link", "file", "download", "fetch", "get", "load",
    "proxy", "endpoint", "api", "host", "domain", "remote",
]


def _probe(
    base_url: str,
    param: str,
    payload: str,
    timeout: float,
    user_agent: str,
    baseline_time: float,
) -> Optional[Finding]:
    """Inject payload into parameter and check for SSRF indicators."""
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    test_url = urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
    )

    req = urllib.request.Request(test_url, headers={"User-Agent": user_agent})
    ctx = build_ssl_context()

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            elapsed = time.time() - start
            timing_delta = elapsed - baseline_time
            # Primary signal: timing outlier indicates the server fetched the URL.
            # Threshold is 2× baseline to reduce false positives from network jitter.
            if timing_delta > max(1.0, baseline_time * 2):
                return Finding(
                    param=param, payload=payload, payload_desc="",
                    status=resp.status, response_size=len(body), timing_delta=timing_delta,
                )
            # Secondary signal: unusually large response from an internal address
            # (e.g. metadata endpoint returning credentials JSON).
            # Guard both conditions together to avoid false positives.
            is_internal = any(x in payload for x in ("169.254", "127.0.0", "localhost", "[::1]"))
            if is_internal and len(body) > 500 and resp.status == 200:
                return Finding(
                    param=param, payload=payload, payload_desc="",
                    status=resp.status, response_size=len(body), timing_delta=timing_delta,
                )
            return None
    except urllib.error.HTTPError as e:
        elapsed = time.time() - start
        timing_delta = elapsed - baseline_time
        # A 4xx from an internal address is suspicious (real server responding).
        is_internal = any(x in payload for x in ("169.254", "127.0.0", "localhost", "[::1]"))
        if is_internal and 400 <= e.code < 500:
            body_bytes = e.read()
            return Finding(
                param=param, payload=payload, payload_desc="",
                status=e.code, response_size=len(body_bytes), timing_delta=timing_delta,
            )
        return None
    except (urllib.error.URLError, socket.timeout, OSError):
        return None


def run(base_url: str, timeout: float, user_agent: str) -> tuple[List[Finding], float]:
    """Test URL parameters for SSRF vulnerability."""
    parsed = urllib.parse.urlparse(base_url)
    params = URL_PARAMS.copy()
    if parsed.query:
        existing = urllib.parse.parse_qs(parsed.query).keys()
        params = list(existing) + params

    # Get baseline timing (no SSRF payload)
    start = time.time()
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": user_agent})
        ctx = build_ssl_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as _:
            baseline_time = time.time() - start
    except (urllib.error.URLError, socket.timeout, OSError):
        baseline_time = timeout / 2  # Fallback

    findings: List[Finding] = []
    seen_params: set = set()

    for param in params:
        if param in seen_params:
            continue
        seen_params.add(param)
        for payload, payload_desc in PAYLOADS:
            f = _probe(base_url, param, payload, timeout, user_agent, baseline_time)
            if f:
                f.payload_desc = payload_desc
                findings.append(f)
                break  # One finding per param is enough

    return findings, baseline_time


def print_human(url: str, findings: List[Finding], baseline_time: float, lang: str) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]

    print(f"\n{L['target']}: {url}")
    print(f"{L['baseline_time']}: {baseline_time:.2f}s")
    print()

    if findings:
        print(f"{L['findings_header']} ({len(findings)}):\n")
        for f in findings:
            print(f"  ✗ {IT['label'].format(f.param, f.payload)}")
            print(f"     {L['payload_label']}: {f.payload_desc}")
            if f.status:
                print(f"     {L['status']}: {f.status}")
            if f.response_size:
                print(f"     {L['response_size']}: {f.response_size} bytes")
            print(f"     {L['timing_delta']}: {f.timing_delta:.2f}s (baseline: {baseline_time:.2f}s)")
            print(f"     {IT['risk_label']} {IT['risk']}")
            print(f"     {IT['fix_label']} {IT['fix']}")
            print()
    else:
        print(L["no_findings"])
    print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Probe for SSRF vulnerabilities by injecting internal addresses.",
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

    findings, baseline_time = run(args.url, args.timeout, USER_AGENT)

    if args.as_json:
        print(json.dumps({
            "url": args.url,
            "lang": args.lang,
            "baseline_time_seconds": baseline_time,
            "payloads": [p[0] for p in PAYLOADS],
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, findings, baseline_time, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
