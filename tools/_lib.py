"""Shared utilities for the portfolio CLI tools.

Stdlib-only. Imported by the sibling scripts in this directory as
`from _lib import ...`. Because Python prepends a script's directory
to `sys.path`, the import works regardless of where the script is
invoked from.

What's here, and why:

- `TOOLS_VERSION` — shared version string for all tools (used by the
  `--version` flag and by `make_user_agent`).
- `PORTFOLIO_URL` — canonical site URL referenced in User-Agent strings,
  so a target site that's curious about the traffic can navigate to a
  page explaining what these tools are.
- `make_user_agent` — keeps every tool's User-Agent in the same format.
- `build_ssl_context` — works around macOS Python.org installs that
  ship without root CAs. Tries `/etc/ssl/cert.pem` and other common
  locations if the default context has no CAs configured.
- `stdin_or_arg` — convenience for treating `-` as "read from stdin".
- `add_common_args` — registers the `--lang`, `--json`, `--no-color`,
  `--version` family on a parser. Optional; tools that already define
  these by hand can keep doing so.
"""

from __future__ import annotations

import argparse
import os
import ssl
import sys
import urllib.request

TOOLS_VERSION = "0.2"
PORTFOLIO_URL = "https://ciberacaro.github.io"

CA_FALLBACK_LOCATIONS = (
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)


def make_user_agent(tool_name: str, version: str = TOOLS_VERSION) -> str:
    """Build a consistent User-Agent string for a tool's outbound requests."""
    return f"{tool_name}/{version} (+{PORTFOLIO_URL})"


def build_ssl_context() -> ssl.SSLContext:
    """Return an SSL context with sensible CA fallbacks for macOS Python.org.

    Python.org Python on macOS ships without root CAs unless the user
    runs `Install Certificates.command`. The default context will then
    fail with `CERTIFICATE_VERIFY_FAILED` on every HTTPS request. We try
    `/etc/ssl/cert.pem` (always present on macOS) and a few Homebrew
    OpenSSL locations as fallbacks.
    """
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    for cafile in CA_FALLBACK_LOCATIONS:
        if os.path.exists(cafile):
            ctx.load_verify_locations(cafile=cafile)
            return ctx
    return ctx


def stdin_or_arg(value: str) -> str:
    """If `value` is exactly '-', read a single line from stdin (stripped).

    Otherwise return `value` unchanged. Designed for tools that accept one
    target (URL, host, domain, JWT) as a positional arg.
    """
    if value == "-":
        line = sys.stdin.readline().strip()
        if not line:
            print("error: stdin is empty", file=sys.stderr)
            sys.exit(2)
        return line
    return value


def add_version_arg(parser: argparse.ArgumentParser, tool_name: str) -> None:
    """Register a uniform `--version` action on `parser`."""
    parser.add_argument(
        "--version",
        action="version",
        version=f"{tool_name} {TOOLS_VERSION}",
    )


def add_user_agent_arg(parser: argparse.ArgumentParser, default: str) -> None:
    """Register a `--user-agent` override.

    Useful for evading WAFs that block scripted clients, or for testing
    how the target responds to different UA strings.
    """
    parser.add_argument(
        "--user-agent",
        default=default,
        metavar="STRING",
        help="Override the User-Agent header (default: the tool's own UA).",
    )


def add_proxy_arg(parser: argparse.ArgumentParser) -> None:
    """Register a --proxy argument for routing requests through a proxy.

    Useful for intercepting traffic with Burp Suite (http://127.0.0.1:8080)
    or routing through Tor/corporate proxies. Works with HTTP and HTTPS targets.
    """
    parser.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="Route all requests through a proxy (e.g. http://127.0.0.1:8080 for Burp Suite).",
    )


def build_opener(
    ssl_ctx: ssl.SSLContext,
    proxy_url: str | None = None,
    extra_handlers: list | None = None,
) -> urllib.request.OpenerDirector:
    """Return an urllib OpenerDirector with optional proxy and custom SSL context.

    Pass extra_handlers to include tool-specific handlers (e.g. redirect trackers).
    """
    handlers: list = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
    if extra_handlers:
        handlers.extend(extra_handlers)
    return urllib.request.build_opener(*handlers)
