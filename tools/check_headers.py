#!/usr/bin/env python3
"""Check the security-relevant HTTP response headers of a URL.

Examples:
    tools/check_headers.py https://example.com
    tools/check_headers.py https://example.com --no-color
    tools/check_headers.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

USER_AGENT = "check_headers.py/0.1 (+https://ciberacaro.github.io)"

OK = "OK"
WEAK = "WEAK"
MISSING = "MISSING"
INFO = "INFO"

ANSI = {
    OK: "\033[32m",
    WEAK: "\033[33m",
    MISSING: "\033[31m",
    INFO: "\033[36m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

SYMBOL = {OK: "✓", WEAK: "!", MISSING: "✗", INFO: "i"}


@dataclass
class Finding:
    header: str
    status: str
    value: Optional[str]
    note: str


CA_FALLBACK_LOCATIONS = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)


def build_ssl_context() -> ssl.SSLContext:
    """Build an SSL context with sensible CA fallbacks.

    Python.org Python on macOS ships without root CAs unless the user runs
    `Install Certificates.command`. Fall back to common system CA bundles
    so the tool works out of the box.
    """
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    for cafile in CA_FALLBACK_LOCATIONS:
        if os.path.exists(cafile):
            ctx.load_verify_locations(cafile=cafile)
            return ctx
    return ctx


def _normalize(headers_obj) -> dict[str, str]:
    """Return headers as a dict keyed by lowercase name (HTTP headers are case-insensitive)."""
    return {k.lower(): v for k, v in headers_obj.items()} if headers_obj else {}


def fetch_headers(url: str, timeout: float = 10.0):
    """Fetch URL and return (final_url, status_code, headers).

    Headers are keyed by lowercase name (HTTP headers are case-insensitive
    per RFC 7230 §3.2). All check_* functions must look up lowercase keys.
    """
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.geturl(), resp.status, _normalize(resp.headers)
    except urllib.error.HTTPError as e:
        return e.geturl(), e.code, _normalize(e.headers)


def check_hsts(headers: dict) -> Finding:
    display = "Strict-Transport-Security"
    raw = headers.get("strict-transport-security")
    if not raw:
        return Finding(display, MISSING, None, "HTTPS not enforced; supports downgrade attacks")
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", raw, re.I)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    if max_age < 15552000:  # 180 days, the commonly-recommended floor
        return Finding(display, WEAK, raw, f"max-age={max_age} is below 180 days (15552000)")
    return Finding(display, OK, raw, "HSTS enforced")


def check_csp(headers: dict) -> Finding:
    display = "Content-Security-Policy"
    enforced = headers.get("content-security-policy")
    report_only = headers.get("content-security-policy-report-only")
    raw = enforced or report_only
    if not raw:
        return Finding(display, MISSING, None, "No CSP; XSS payloads are not restricted by the browser")
    weak = []
    if "'unsafe-inline'" in raw:
        weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in raw:
        weak.append("'unsafe-eval'")
    if "*" in raw.split():
        weak.append("wildcard '*' source")
    if weak:
        return Finding(display, WEAK, raw, "Permissive directives: " + ", ".join(weak))
    if report_only and not enforced:
        return Finding(display, WEAK, raw, "Report-Only mode — not enforced, only logged")
    return Finding(display, OK, raw, "CSP present and reasonably strict")


def check_x_frame_options(headers: dict) -> Finding:
    display = "X-Frame-Options"
    raw = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        if not raw:
            return Finding(display, OK, None, "Covered by CSP frame-ancestors")
        return Finding(display, OK, raw, "Backed up by CSP frame-ancestors")
    if not raw:
        return Finding(display, MISSING, None, "Clickjacking risk")
    if raw.strip().upper() in ("DENY", "SAMEORIGIN"):
        return Finding(display, OK, raw, "Iframes restricted")
    return Finding(display, WEAK, raw, f"Unusual value: {raw}")


def check_x_content_type_options(headers: dict) -> Finding:
    display = "X-Content-Type-Options"
    raw = headers.get("x-content-type-options")
    if not raw:
        return Finding(display, MISSING, None, "MIME-sniffing not disabled; consider 'nosniff'")
    if raw.strip().lower() == "nosniff":
        return Finding(display, OK, raw, "MIME sniffing disabled")
    return Finding(display, WEAK, raw, "Expected exactly 'nosniff'")


def check_referrer_policy(headers: dict) -> Finding:
    display = "Referrer-Policy"
    raw = headers.get("referrer-policy")
    if not raw:
        return Finding(display, MISSING, None, "Default referrer behavior leaks paths to third parties")
    strong_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if any(v in raw.lower() for v in strong_values):
        return Finding(display, OK, raw, "Privacy-respecting policy")
    if "unsafe-url" in raw.lower() or raw.lower().strip() == "":
        return Finding(display, WEAK, raw, "Unsafe — sends full URL cross-origin")
    return Finding(display, WEAK, raw, "Weak policy")


def check_permissions_policy(headers: dict) -> Finding:
    display = "Permissions-Policy"
    perms = headers.get("permissions-policy")
    feature = headers.get("feature-policy")
    raw = perms or feature
    if not raw:
        return Finding(display, MISSING, None, "No restriction on browser features (camera, geolocation, etc.)")
    if feature and not perms:
        return Finding(display, WEAK, raw, "Using deprecated Feature-Policy — migrate to Permissions-Policy")
    return Finding(display, OK, raw, "Permissions policy set")


def check_info_disclosure(headers: dict) -> list[Finding]:
    findings = []
    candidates = (
        ("server", "Server"),
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
        ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
    )
    for key, display in candidates:
        v = headers.get(key)
        if not v:
            continue
        if display == "Server" and re.search(r"\d", v):
            findings.append(Finding(display, WEAK, v, "Reveals server software/version"))
        elif display == "Server":
            findings.append(Finding(display, INFO, v, "Reveals server software (no version)"))
        else:
            findings.append(Finding(display, WEAK, v, "Reveals stack/version — consider removing"))
    return findings


def colorize(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{ANSI[key]}{text}{ANSI['reset']}"


def print_human_report(url: str, status: int, findings: list[Finding], use_color: bool) -> None:
    bold = lambda s: f"{ANSI['bold']}{s}{ANSI['reset']}" if use_color else s
    dim = lambda s: f"{ANSI['dim']}{s}{ANSI['reset']}" if use_color else s

    print(f"\n{bold('URL:')}    {url}")
    print(f"{bold('Status:')} {status}\n")

    print(bold("Security headers:"))
    name_width = max(len(f.header) for f in findings)
    for f in findings:
        sym = colorize(SYMBOL[f.status], f.status, use_color)
        status_label = colorize(f"{f.status:<8}", f.status, use_color)
        print(f"  {sym}  {f.header:<{name_width}}  {status_label}  {f.note}")
        if f.value and len(f.value) <= 100:
            print(f"     {dim(f.value)}")
        elif f.value:
            print(f"     {dim(f.value[:97] + '...')}")

    ok_count = sum(1 for f in findings if f.status == OK)
    relevant = sum(1 for f in findings if f.status != INFO)
    print(f"\n{bold('Score:')} {ok_count}/{relevant} headers OK")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check security-relevant HTTP response headers of a URL.",
    )
    parser.add_argument("url", help="Target URL (must include scheme: http:// or https://)")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in output"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output as JSON (overrides human format)"
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)"
    )
    args = parser.parse_args()

    if not re.match(r"^https?://", args.url):
        print(
            f"error: URL must start with http:// or https:// (got {args.url!r})",
            file=sys.stderr,
        )
        return 2

    try:
        final_url, status, headers = fetch_headers(args.url, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(f"error: could not reach {args.url} — {e.reason}", file=sys.stderr)
        return 3
    except socket.timeout:
        print(f"error: timeout after {args.timeout}s reaching {args.url}", file=sys.stderr)
        return 3

    findings: list[Finding] = [
        check_hsts(headers),
        check_csp(headers),
        check_x_frame_options(headers),
        check_x_content_type_options(headers),
        check_referrer_policy(headers),
        check_permissions_policy(headers),
    ]
    findings.extend(check_info_disclosure(headers))

    if args.json:
        out = {
            "url": final_url,
            "status": status,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(out, indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print_human_report(final_url, status, findings, use_color)

    has_missing = any(f.status == MISSING for f in findings)
    return 1 if has_missing else 0


if __name__ == "__main__":
    sys.exit(main())
