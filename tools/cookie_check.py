#!/usr/bin/env python3
"""Analyze the Set-Cookie response headers of a URL for security flags.

For each cookie the server sets, reports:
- HttpOnly, Secure, SameSite, Domain, Path, Expires/Max-Age, Priority

Flags risky configurations: missing HttpOnly on session-like names,
missing Secure on HTTPS URLs, missing/weak SameSite, overly broad
Domain scoping, etc.

Examples:
    tools/cookie_check.py https://example.com
    tools/cookie_check.py https://example.com --lang pt
    tools/cookie_check.py https://example.com --json
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

USER_AGENT = make_user_agent("cookie_check.py")
LANGS = ("en", "pt")

# Cookie name patterns that typically carry sessions / auth tokens.
# Used to decide whether a missing HttpOnly is a serious issue (yes for
# these, low-severity for analytics/preferences cookies).
SESSION_NAME_PATTERN = re.compile(
    r"(sess(ion)?|sid|auth|token|jwt|csrf|xsrf|access|refresh|login|user|account|connect\.sid|"
    r"PHPSESSID|JSESSIONID|ASP\.NET_SessionId|laravel_session)",
    re.IGNORECASE,
)

LABELS = {
    "en": {
        "target": "Target",
        "scheme": "URL scheme",
        "cookies_found": "Cookies set by the server",
        "no_cookies": "Server did not set any cookies.",
        "attributes": "Attributes",
        "issues_header": "Issues found",
        "no_issues": "No issues — every cookie has sensible flags.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
    },
    "pt": {
        "target": "Alvo",
        "scheme": "Esquema do URL",
        "cookies_found": "Cookies definidos pelo servidor",
        "no_cookies": "Servidor não definiu cookies.",
        "attributes": "Atributos",
        "issues_header": "Problemas encontrados",
        "no_issues": "Sem problemas — todos os cookies têm flags sensatas.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
    },
}

ISSUE_TEXT = {
    "missing_httponly_session": {
        "en": ("Cookie '{}' has no HttpOnly flag",
               "Without HttpOnly, JavaScript can read the cookie via document.cookie — XSS payloads can steal session tokens."),
        "pt": ("Cookie '{}' sem flag HttpOnly",
               "Sem HttpOnly, JavaScript consegue ler o cookie via document.cookie — payloads de XSS podem roubar tokens de sessão."),
    },
    "missing_secure_https": {
        "en": ("Cookie '{}' has no Secure flag but URL is HTTPS",
               "Without Secure, the cookie can leak when the user visits an http:// version of the site (e.g. via mixed content or a link)."),
        "pt": ("Cookie '{}' sem flag Secure mas o URL é HTTPS",
               "Sem Secure, o cookie pode vazar quando o utilizador visita a versão http:// do site (ex: via conteúdo misto ou um link)."),
    },
    "missing_samesite": {
        "en": ("Cookie '{}' has no SameSite attribute",
               "Defaults vary by browser. Set SameSite=Lax or Strict to prevent CSRF; Lax is the modern default."),
        "pt": ("Cookie '{}' sem atributo SameSite",
               "Os defaults variam por browser. Define SameSite=Lax ou Strict para prevenir CSRF; Lax é o default moderno."),
    },
    "samesite_none_without_secure": {
        "en": ("Cookie '{}' has SameSite=None but is missing Secure",
               "Browsers reject SameSite=None without Secure — set both, or change SameSite to Lax/Strict."),
        "pt": ("Cookie '{}' tem SameSite=None mas falta Secure",
               "Os browsers rejeitam SameSite=None sem Secure — define ambos, ou muda SameSite para Lax/Strict."),
    },
    "domain_too_broad": {
        "en": ("Cookie '{}' has Domain={} — scope wider than the response host",
               "A broad Domain shares the cookie with every subdomain, including ones you don't own. Set Domain only when you intentionally need cross-subdomain access."),
        "pt": ("Cookie '{}' tem Domain={} — escopo mais largo do que o host da resposta",
               "Um Domain alargado partilha o cookie com todos os subdomínios, incluindo os que não controlas. Define Domain apenas quando precisas mesmo de acesso cross-subdomain."),
    },
    "host_prefix_violation": {
        "en": ("Cookie '{}' uses '__Host-' prefix but violates its rules",
               "Cookies with '__Host-' prefix MUST have Secure, MUST have Path=/, and MUST NOT have Domain set (RFC 6265bis). Otherwise browsers will reject them."),
        "pt": ("Cookie '{}' usa o prefixo '__Host-' mas viola as suas regras",
               "Cookies com prefixo '__Host-' TÊM de ter Secure, TÊM de ter Path=/, e NÃO PODEM ter Domain definido (RFC 6265bis). Caso contrário os browsers rejeitam-nos."),
    },
    "secure_prefix_violation": {
        "en": ("Cookie '{}' uses '__Secure-' prefix but is not Secure",
               "Cookies with '__Secure-' prefix MUST have the Secure flag. Browsers reject the cookie otherwise."),
        "pt": ("Cookie '{}' usa o prefixo '__Secure-' mas não tem flag Secure",
               "Cookies com prefixo '__Secure-' TÊM de ter a flag Secure. Os browsers rejeitam o cookie caso contrário."),
    },
    "long_expiry": {
        "en": ("Cookie '{}' has expiry longer than 1 year",
               "Long-lived cookies are persistent tracking surface. Set Max-Age ≤ 1 year for session-like cookies, ≤ 30 days where possible."),
        "pt": ("Cookie '{}' tem expiração superior a 1 ano",
               "Cookies de longa duração são uma superfície de tracking persistente. Define Max-Age ≤ 1 ano para cookies tipo sessão, ≤ 30 dias quando possível."),
    },
    "partitioned_without_secure": {
        "en": ("Cookie '{}' has Partitioned attribute but is missing Secure",
               "The Partitioned attribute (CHIPS) requires Secure. Browsers ignore Partitioned cookies without Secure."),
        "pt": ("Cookie '{}' tem o atributo Partitioned mas falta Secure",
               "O atributo Partitioned (CHIPS) requer Secure. Browsers ignoram cookies Partitioned sem Secure."),
    },
}


@dataclass
class Cookie:
    name: str
    value_preview: str
    attributes: dict[str, str | bool]
    raw: str


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


def _split_cookie_attrs(raw: str) -> tuple[str, str, dict[str, str | bool]]:
    """Parse a single Set-Cookie value into (name, value, attributes dict)."""
    parts = raw.split(";")
    nv = parts[0].strip()
    if "=" in nv:
        name, _, value = nv.partition("=")
    else:
        name, value = nv, ""
    attrs: dict[str, str | bool] = {}
    for part in parts[1:]:
        p = part.strip()
        if not p:
            continue
        if "=" in p:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[p.lower()] = True
    return name.strip(), value.strip(), attrs


def fetch_set_cookies(url: str, timeout: float = 10.0) -> tuple[int, list[str]]:
    """Return (status, list-of-Set-Cookie-values). Always lowercases the lookup."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        return e.code, (e.headers.get_all("Set-Cookie") if e.headers else []) or []


def evaluate(cookies: list[Cookie], target_host: str, scheme: str, lang: str) -> list[Issue]:
    issues: list[Issue] = []
    target_host = (target_host or "").lower()

    for c in cookies:
        attrs = c.attributes
        has_httponly = bool(attrs.get("httponly"))
        has_secure = bool(attrs.get("secure"))
        samesite = (attrs.get("samesite") or "")
        samesite_str = samesite.lower() if isinstance(samesite, str) else ""
        domain = attrs.get("domain")
        domain_str = domain.lstrip(".").lower() if isinstance(domain, str) else ""

        # HttpOnly missing on session-looking cookies
        if not has_httponly and SESSION_NAME_PATTERN.search(c.name):
            t = ISSUE_TEXT["missing_httponly_session"][lang]
            issues.append(Issue("missing_httponly_session", t[0].format(c.name), t[0].format(c.name), t[1]))

        # Secure missing on HTTPS
        if scheme == "https" and not has_secure:
            t = ISSUE_TEXT["missing_secure_https"][lang]
            issues.append(Issue("missing_secure_https", t[0].format(c.name), t[0].format(c.name), t[1]))

        # SameSite missing
        if not samesite_str:
            t = ISSUE_TEXT["missing_samesite"][lang]
            issues.append(Issue("missing_samesite", t[0].format(c.name), t[0].format(c.name), t[1]))

        # SameSite=None without Secure
        if samesite_str == "none" and not has_secure:
            t = ISSUE_TEXT["samesite_none_without_secure"][lang]
            issues.append(Issue("samesite_none_without_secure", t[0].format(c.name), t[0].format(c.name), t[1]))

        # Domain wider than the response host (e.g. response on app.example.com, cookie Domain=example.com)
        if domain_str and target_host and domain_str != target_host:
            # If target_host ends with .{domain_str}, then domain is broader (parent scope)
            if target_host.endswith("." + domain_str):
                t = ISSUE_TEXT["domain_too_broad"][lang]
                issues.append(Issue("domain_too_broad", t[0].format(c.name, domain_str), t[0].format(c.name, domain_str), t[1]))

        # RFC 6265bis cookie prefixes
        if c.name.startswith("__Host-"):
            path = attrs.get("path") if isinstance(attrs.get("path"), str) else ""
            if not has_secure or path != "/" or domain_str:
                t = ISSUE_TEXT["host_prefix_violation"][lang]
                issues.append(Issue("host_prefix_violation", t[0].format(c.name), t[0].format(c.name), t[1]))
        elif c.name.startswith("__Secure-"):
            if not has_secure:
                t = ISSUE_TEXT["secure_prefix_violation"][lang]
                issues.append(Issue("secure_prefix_violation", t[0].format(c.name), t[0].format(c.name), t[1]))

        # Partitioned (CHIPS) requires Secure
        if attrs.get("partitioned") and not has_secure:
            t = ISSUE_TEXT["partitioned_without_secure"][lang]
            issues.append(Issue("partitioned_without_secure", t[0].format(c.name), t[0].format(c.name), t[1]))

        # Long expiry / Max-Age (> 1 year)
        max_age_raw = attrs.get("max-age")
        if isinstance(max_age_raw, str):
            try:
                if int(max_age_raw) > 365 * 24 * 3600:
                    t = ISSUE_TEXT["long_expiry"][lang]
                    issues.append(Issue("long_expiry", t[0].format(c.name), t[0].format(c.name), t[1]))
                    # Skip the Expires check below since Max-Age already triggered it.
                    continue
            except ValueError:
                pass
        expires_raw = attrs.get("expires")
        if isinstance(expires_raw, str):
            # Try common cookie Expires format
            from datetime import datetime, timezone
            for fmt in ("%a, %d %b %Y %H:%M:%S GMT", "%a, %d-%b-%Y %H:%M:%S GMT"):
                try:
                    dt = datetime.strptime(expires_raw.strip(), fmt).replace(tzinfo=timezone.utc)
                    if (dt - datetime.now(timezone.utc)).days > 365:
                        t = ISSUE_TEXT["long_expiry"][lang]
                        issues.append(Issue("long_expiry", t[0].format(c.name), t[0].format(c.name), t[1]))
                    break
                except ValueError:
                    continue

    return issues


def print_human(target: str, scheme: str, cookies: list[Cookie], issues: list[Issue], lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['target']}: {target}  ({L['scheme']}: {scheme})\n")
    if not cookies:
        print(f"  {L['no_cookies']}\n")
        return

    # Canonical casing per RFC / browser devtools convention
    canonical = {"secure": "Secure", "httponly": "HttpOnly"}

    print(f"{L['cookies_found']} ({len(cookies)}):")
    for c in cookies:
        flags = []
        for key in ("secure", "httponly"):
            if c.attributes.get(key):
                flags.append(canonical[key])
        if "samesite" in c.attributes:
            flags.append(f"SameSite={c.attributes['samesite']}")
        if "domain" in c.attributes:
            flags.append(f"Domain={c.attributes['domain']}")
        if "path" in c.attributes:
            flags.append(f"Path={c.attributes['path']}")
        if "max-age" in c.attributes:
            flags.append(f"Max-Age={c.attributes['max-age']}")
        if "expires" in c.attributes:
            flags.append(f"Expires={c.attributes['expires']}")
        if c.attributes.get("partitioned"):
            flags.append("Partitioned")
        flags_str = " | ".join(flags) if flags else "(no attributes set)"
        preview = c.value_preview if c.value_preview else "(empty)"
        print(f"\n  {c.name}")
        print(f"    value:      {preview}")
        print(f"    {L['attributes']}: {flags_str}")

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
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Analyze the Set-Cookie response headers of a URL.",
    )
    add_version_arg(parser, "cookie_check.py")
    add_user_agent_arg(parser, USER_AGENT)
    parser.add_argument("url", help="Target URL (http:// or https://). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]
    USER_AGENT = args.user_agent

    args.url = stdin_or_arg(args.url)
    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or ""
    scheme = parsed.scheme

    try:
        status, raw_cookies = fetch_set_cookies(args.url, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(f"{L['err_unreachable']} {args.url} — {e.reason}", file=sys.stderr)
        return 3
    except socket.timeout:
        print(f"{L['err_unreachable']} {args.url} — timeout", file=sys.stderr)
        return 3

    cookies: list[Cookie] = []
    for raw in raw_cookies:
        name, value, attrs = _split_cookie_attrs(raw)
        preview = value if len(value) <= 60 else value[:57] + "..."
        cookies.append(Cookie(name=name, value_preview=preview, attributes=attrs, raw=raw))

    issues = evaluate(cookies, host, scheme, args.lang)

    if args.json:
        out = {
            "url": args.url,
            "lang": args.lang,
            "status": status,
            "cookies": [{"name": c.name, "value_preview": c.value_preview, "attributes": c.attributes} for c in cookies],
            "issues": [asdict(i) for i in issues],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, scheme, cookies, issues, args.lang)

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
