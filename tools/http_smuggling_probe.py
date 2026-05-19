#!/usr/bin/env python3
"""Probe for HTTP request smuggling vulnerabilities (CL.TE / TE.CL).

Tests HTTP/1.1 request smuggling by sending ambiguous Content-Length and
Transfer-Encoding header combinations to detect desynchronization between
the front-end and back-end parsers. Vulnerability allows request injection,
cache poisoning, and WAF bypass.

Exit codes:
  0  No smuggling indicators detected
  1  Potential HTTP request smuggling found
  2  Bad URL / usage error
  3  Network / DNS / TLS error

Examples:
    tools/http_smuggling_probe.py https://example.com
    tools/http_smuggling_probe.py https://example.com --lang pt
    tools/http_smuggling_probe.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
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

TOOL_NAME = "http_smuggling_probe.py"
USER_AGENT = make_user_agent(TOOL_NAME)
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "target": "Target",
        "host": "Host",
        "port": "Port",
        "probes": "Probes sent",
        "findings_header": "Potential HTTP smuggling detected",
        "no_findings": "No HTTP smuggling indicators detected.",
        "technique": "Technique",
        "status": "Status",
        "response": "Response",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_net": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "host": "Host",
        "port": "Porto",
        "probes": "Probes enviadas",
        "findings_header": "Possível HTTP smuggling detetado",
        "no_findings": "Nenhum indicador de HTTP smuggling detetado.",
        "technique": "Técnica",
        "status": "Estado",
        "response": "Resposta",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_net": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "en": {
        "label": "HTTP request smuggling (CL.TE / TE.CL desync)",
        "risk": (
            "HTTP request smuggling exploits differences in how front-end and back-end "
            "servers parse HTTP requests. An attacker can inject a hidden second request "
            "that the front-end forwards to the back-end, bypassing WAF rules, poisoning "
            "caches, stealing user data, or performing privilege escalation."
        ),
        "fix": (
            "Ensure front-end and back-end use identical HTTP parsing. Disable or align "
            "Content-Length and Transfer-Encoding handling. Use HTTP/2 exclusively if possible "
            "(it forbids request smuggling). Implement strict Content-Length validation and "
            "reject requests with both Content-Length and Transfer-Encoding headers."
        ),
        "risk_label": "Risk:",
        "fix_label": "Fix:",
    },
    "pt": {
        "label": "HTTP request smuggling (desincronização CL.TE / TE.CL)",
        "risk": (
            "HTTP request smuggling explora diferenças em como servidores front-end e back-end "
            "fazem parse de pedidos HTTP. Um atacante pode injetar um segundo pedido oculto "
            "que o front-end encaminha para o back-end, evitando regras WAF, envenenando "
            "caches, roubando dados de utilizadores, ou fazendo escalação de privilégio."
        ),
        "fix": (
            "Garante que front-end e back-end usam parsing HTTP idêntico. Desativa ou alinha "
            "o tratamento de Content-Length e Transfer-Encoding. Usa HTTP/2 exclusivamente "
            "se possível (proíbe request smuggling). Implementa validação estrita de "
            "Content-Length e rejeita pedidos com ambos Content-Length e Transfer-Encoding."
        ),
        "risk_label": "Risco:",
        "fix_label": "Correção:",
    },
}


@dataclass
class Finding:
    technique: str
    evidence: str


def _send_raw_request(
    host: str,
    port: int,
    request_bytes: bytes,
    use_https: bool,
    timeout: float = 10.0,
) -> Optional[bytes]:
    """Send raw HTTP request via socket and return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if use_https:
            ctx = build_ssl_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(request_bytes)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response
    except (socket.error, ssl.SSLError, OSError):
        return None


def _timed_request(host: str, port: int, request_bytes: bytes, use_https: bool,
                   timeout: float) -> Tuple[Optional[bytes], float]:
    """Send request and return (response_bytes, elapsed_seconds)."""
    start = time.time()
    data = _send_raw_request(host, port, request_bytes, use_https, timeout)
    return data, time.time() - start


def _probe_cl_te(host: str, port: int, use_https: bool, baseline: float) -> Optional[Finding]:
    """Probe for CL.TE desync using a timing side-channel.

    Strategy (James Kettle / PortSwigger):
      - Send a request whose body is complete under Content-Length but has an
        unterminated chunked body (no `0\\r\\n\\r\\n` terminator).
      - If the back-end uses Transfer-Encoding, it waits for the chunk
        terminator → detectable timeout.
      - If the back-end uses Content-Length, it reads the body and responds
        normally → fast response.
    """
    # Body: CL says 3 bytes (`3\r\n`), TE sees an unterminated chunk.
    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 3\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "3\r\n"  # chunk size — back-end using TE waits for 3-byte chunk + terminator
        "abc"    # 3 bytes of chunk data, no trailing \r\n0\r\n\r\n
    ).encode()

    _, elapsed = _timed_request(host, port, request, use_https, timeout=10.0)
    # If the response took significantly longer than baseline, the back-end stalled
    # waiting for a chunk terminator that never arrived → CL.TE indicator.
    if elapsed > max(5.0, baseline * 3):
        return Finding(
            technique="CL.TE",
            evidence=(
                f"Response delayed {elapsed:.1f}s vs baseline {baseline:.1f}s. "
                "Back-end likely stalled waiting for chunked terminator."
            ),
        )
    return None


def _probe_te_cl(host: str, port: int, use_https: bool, baseline: float) -> Optional[Finding]:
    """Probe for TE.CL desync using a timing side-channel.

    Strategy:
      - Send a request that is complete under Transfer-Encoding (chunked body
        with `0\\r\\n\\r\\n` terminator) but Content-Length declares more bytes
        than the body actually contains.
      - If the back-end uses Content-Length, it waits for the remaining bytes
        → detectable timeout.
      - If the back-end uses Transfer-Encoding, it reads the body and responds
        normally → fast response.
    """
    # Complete chunked body (0-byte chunk + terminator), but CL claims 6 bytes.
    request = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 6\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n"  # valid chunked terminator (empty body)
        "\r\n"   # end of chunked encoding — only 4 bytes, but CL says 6
    ).encode()

    _, elapsed = _timed_request(host, port, request, use_https, timeout=10.0)
    if elapsed > max(5.0, baseline * 3):
        return Finding(
            technique="TE.CL",
            evidence=(
                f"Response delayed {elapsed:.1f}s vs baseline {baseline:.1f}s. "
                "Back-end likely stalled waiting for Content-Length bytes."
            ),
        )
    return None


def run(url: str) -> Tuple[List[Finding], str, int, bool]:
    """Test URL for HTTP request smuggling."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_https = parsed.scheme == "https"

    # Measure baseline response time with a normal GET request.
    baseline_req = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    _, baseline = _timed_request(host, port, baseline_req, use_https, timeout=15.0)

    findings: List[Finding] = []

    f = _probe_cl_te(host, port, use_https, baseline)
    if f:
        findings.append(f)

    f = _probe_te_cl(host, port, use_https, baseline)
    if f:
        findings.append(f)

    return findings, host, port, use_https


def print_human(url: str, findings: List[Finding], host: str, port: int, lang: str) -> None:
    L = LABELS[lang]
    IT = ISSUE_TEXT[lang]

    print(f"\n{L['target']}: {url}")
    print(f"{L['host']}: {host}  {L['port']}: {port}")
    print(f"{L['probes']}: 2 (CL.TE, TE.CL)")
    print()

    if findings:
        print(f"{L['findings_header']} ({len(findings)}):\n")
        for f in findings:
            print(f"  ✗ {IT['label']}")
            print(f"     {L['technique']}: {f.technique}")
            print(f"     {L['status']}: {f.evidence}")
            print(f"     {IT['risk_label']} {IT['risk']}")
            print(f"     {IT['fix_label']} {IT['fix']}")
            print()
    else:
        print(L["no_findings"])
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe for HTTP request smuggling (CL.TE / TE.CL desynchronization).",
    )
    add_version_arg(parser, TOOL_NAME)
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument(
        "url",
        help="Target URL (http:// or https://). Use '-' to read from stdin.",
    )
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    L = LABELS[args.lang]
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    findings, host, port, use_https = run(args.url)

    if args.as_json:
        print(json.dumps({
            "url": args.url,
            "lang": args.lang,
            "host": host,
            "port": port,
            "probes": ["CL.TE", "TE.CL"],
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, findings, host, port, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
