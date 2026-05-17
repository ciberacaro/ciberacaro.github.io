#!/usr/bin/env python3
"""Test which HTTP methods an endpoint allows.

Sends each HTTP method against the URL and reports the status code
returned. Highlights "interesting" responses (allowed dangerous methods,
unexpected 200/204, reflection of TRACE, etc.).

IMPORTANT: This tool sends real PUT/DELETE/PATCH requests with empty
bodies. Against a poorly-built endpoint, those can mutate data. Run
only against targets you are authorised to test.

Examples:
    tools/http_methods.py https://example.com/api/users/me
    tools/http_methods.py https://example.com/ --lang pt
    tools/http_methods.py https://example.com/ --json
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
from typing import Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, stdin_or_arg

USER_AGENT = make_user_agent("http_methods.py")
LANGS = ("en", "pt")

# Methods we send. GET/HEAD first so the user sees the "baseline" status
# the server normally returns for this URL before any odd methods.
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT")

# These methods are "destructive-by-design" against a properly-built API
# (RFC-compliant interpretation). A 2xx response is suspicious.
DESTRUCTIVE = {"PUT", "PATCH", "DELETE"}

# Auxiliary: TRACE is almost always either disabled or a XST risk if open.
RISKY_METHODS = {"TRACE", "CONNECT"}

LABELS = {
    "en": {
        "target": "Target",
        "results": "Methods tested",
        "allow_header": "Allow header (from OPTIONS)",
        "no_allow": "(server did not return an Allow header)",
        "issues_header": "Issues found",
        "no_issues": "Nothing unusual — server seems to refuse non-standard methods.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "warning_destructive": (
            "Warning: this tool sends PUT/DELETE/PATCH against the target. "
            "Run only against endpoints you are authorised to test."
        ),
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "results": "Métodos testados",
        "allow_header": "Header Allow (do OPTIONS)",
        "no_allow": "(servidor não devolveu header Allow)",
        "issues_header": "Problemas encontrados",
        "no_issues": "Nada de invulgar — o servidor parece recusar métodos não-standard.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "warning_destructive": (
            "Aviso: este tool envia PUT/DELETE/PATCH contra o alvo. "
            "Corre apenas contra endpoints que estás autorizado a testar."
        ),
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "trace_open": {
        "en": ("TRACE method enabled (HTTP {})",
               "Disable TRACE — it enables Cross-Site Tracing (XST) attacks against HttpOnly cookies via XHR + TRACE."),
        "pt": ("Método TRACE ativo (HTTP {})",
               "Desativa TRACE — permite ataques Cross-Site Tracing (XST) contra cookies HttpOnly via XHR + TRACE."),
    },
    "connect_open": {
        "en": ("CONNECT method enabled (HTTP {})",
               "CONNECT on a web server usually indicates a misconfigured proxy; can enable open-proxy abuse."),
        "pt": ("Método CONNECT ativo (HTTP {})",
               "CONNECT num servidor web geralmente indica proxy mal configurado; pode permitir abuso de open-proxy."),
    },
    "destructive_allowed": {
        "en": ("{} returned {} — server may accept writes from arbitrary clients",
               "If this URL is not meant to accept writes from anonymous users, restrict the method server-side or require authentication."),
        "pt": ("{} devolveu {} — servidor pode aceitar escritas de clientes arbitrários",
               "Se este URL não deve aceitar escritas anónimas, restringe o método no servidor ou exige autenticação."),
    },
    "options_no_allow": {
        "en": ("OPTIONS responded but did not include an Allow header",
               "Per RFC 7231 §4.3.7, OPTIONS responses should advertise supported methods via Allow. Not security-critical, but signals an under-baked HTTP layer."),
        "pt": ("OPTIONS respondeu mas não incluiu header Allow",
               "Por RFC 7231 §4.3.7, respostas OPTIONS devem anunciar métodos suportados via Allow. Não é crítico, mas indica camada HTTP mal implementada."),
    },
    "trace_reflection": {
        "en": ("TRACE response body echoes the request — classic XST signature",
               "Disable TRACE in your web server config."),
        "pt": ("Corpo da resposta TRACE reflete o pedido — assinatura clássica de XST",
               "Desativa TRACE na configuração do servidor web."),
    },
}


@dataclass
class MethodResult:
    method: str
    status: int
    allow_header: Optional[str]
    server: Optional[str]
    body_size: int
    body_echoes_request: bool
    error: Optional[str] = None


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


def send_method(url: str, method: str, timeout: float) -> MethodResult:
    """Send a single HTTP method to the URL and capture the response shape."""
    # CONNECT against an https URL via urllib is meaningless — urllib will
    # try to interpret it as a proxy tunnel. Use a raw HTTP socket request
    # so we can really send CONNECT (or any method) without urllib mangling.
    return _raw_request(url, method, timeout)


def _raw_request(url: str, method: str, timeout: float) -> MethodResult:
    """Send a raw HTTP request and parse the response by hand.

    urllib refuses some non-standard methods (CONNECT, TRACE on some
    versions). Bypass that with a direct socket + manual request framing.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    # Build the request line + headers
    marker_header = "X-Probe-Marker: 8f3e1c2d4b5a"  # unique-ish, for TRACE reflection check
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"{marker_header}\r\n"
        f"Connection: close\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode("latin-1")

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
        return MethodResult(
            method=method, status=0, allow_header=None, server=None,
            body_size=0, body_echoes_request=False, error=str(e),
        )

    try:
        if scheme == "https":
            ctx = build_ssl_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        sock.settimeout(timeout)
        chunks = []
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) > 200_000:  # cap response read
                break
        raw = b"".join(chunks)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not raw:
        return MethodResult(
            method=method, status=0, allow_header=None, server=None,
            body_size=0, body_echoes_request=False, error="no response",
        )

    # Parse the response line + headers + body
    head_end = raw.find(b"\r\n\r\n")
    if head_end < 0:
        return MethodResult(
            method=method, status=0, allow_header=None, server=None,
            body_size=0, body_echoes_request=False, error="malformed response",
        )
    head = raw[:head_end].decode("latin-1", errors="replace")
    body = raw[head_end + 4:]
    lines = head.split("\r\n")
    status_line = lines[0]
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", status_line)
    status = int(m.group(1)) if m else 0

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    echoes = b"X-Probe-Marker: 8f3e1c2d4b5a" in body  # TRACE check
    return MethodResult(
        method=method,
        status=status,
        allow_header=headers.get("allow"),
        server=headers.get("server"),
        body_size=len(body),
        body_echoes_request=echoes,
    )


def evaluate(results: list[MethodResult], lang: str) -> list[Issue]:
    issues = []
    by_method = {r.method: r for r in results}

    # TRACE
    trace = by_method.get("TRACE")
    if trace and 200 <= trace.status < 300:
        t = ISSUE_TEXT["trace_open"][lang]
        issues.append(Issue("trace_open", t[0].format(trace.status), t[0].format(trace.status), t[1]))
        if trace.body_echoes_request:
            t2 = ISSUE_TEXT["trace_reflection"][lang]
            issues.append(Issue("trace_reflection", t2[0], t2[0], t2[1]))

    # CONNECT
    connect = by_method.get("CONNECT")
    if connect and 200 <= connect.status < 300:
        t = ISSUE_TEXT["connect_open"][lang]
        issues.append(Issue("connect_open", t[0].format(connect.status), t[0].format(connect.status), t[1]))

    # Destructive methods returning 2xx (suspicious)
    for m in ("PUT", "PATCH", "DELETE"):
        r = by_method.get(m)
        if r and 200 <= r.status < 300:
            t = ISSUE_TEXT["destructive_allowed"][lang]
            label = t[0].format(m, r.status)
            issues.append(Issue("destructive_allowed", label, label, t[1]))

    # OPTIONS without Allow header
    options = by_method.get("OPTIONS")
    if options and 200 <= options.status < 300 and not options.allow_header:
        t = ISSUE_TEXT["options_no_allow"][lang]
        issues.append(Issue("options_no_allow", t[0], t[0], t[1]))

    return issues


def print_human(url: str, results: list[MethodResult], issues: list[Issue], lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['target']}: {url}")
    print(f"\033[33m{L['warning_destructive']}\033[0m\n" if sys.stdout.isatty() else f"{L['warning_destructive']}\n")

    print(f"{L['results']}:")
    width = max(len(r.method) for r in results)
    for r in results:
        if r.error:
            print(f"  {r.method:<{width}}  ERROR: {r.error}")
            continue
        flags = []
        if r.allow_header:
            flags.append(f"Allow: {r.allow_header}")
        if r.body_echoes_request:
            flags.append("echoes request")
        extra = ("  [" + ", ".join(flags) + "]") if flags else ""
        print(f"  {r.method:<{width}}  HTTP {r.status:<3}  body {r.body_size:>6} bytes{extra}")

    options = next((r for r in results if r.method == "OPTIONS"), None)
    if options and options.allow_header:
        print(f"\n{L['allow_header']}: {options.allow_header}")
    elif options and not options.error:
        print(f"\n{L['allow_header']}: {L['no_allow']}")

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
    parser = argparse.ArgumentParser(description="Test which HTTP methods an endpoint allows.")
    add_version_arg(parser, "http_methods.py")
    parser.add_argument("url", help="Target URL (http:// or https://). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]

    args.url = stdin_or_arg(args.url)
    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    results = [send_method(args.url, m, args.timeout) for m in METHODS]
    issues = evaluate(results, args.lang)

    if args.json:
        out = {
            "url": args.url,
            "lang": args.lang,
            "results": [asdict(r) for r in results],
            "issues": [asdict(i) for i in issues],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, results, issues, args.lang)

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
