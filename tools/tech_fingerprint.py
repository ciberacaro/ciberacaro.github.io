#!/usr/bin/env python3
"""Identify the technology stack behind a website (Wappalyzer-lite).

Fetches the URL and runs a set of signatures over the response headers,
cookies, and HTML body to detect: web servers, languages, frameworks,
CMS, e-commerce platforms, JS frameworks, analytics, and CDNs.

Examples:
    tools/tech_fingerprint.py https://example.com
    tools/tech_fingerprint.py https://example.com --lang pt
    tools/tech_fingerprint.py https://example.com --json
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

# We deliberately use a browser-like UA. Some sites serve different content
# (different framework markers in HTML) to scripted clients vs browsers.
DEFAULT_UA = "Mozilla/5.0 (compatible) tech_fingerprint.py/0.2"
USER_AGENT = DEFAULT_UA
LANGS = ("en", "pt")

LABELS = {
    "en": {
        "url": "URL",
        "detected": "Technologies detected",
        "no_detect": "No technologies matched. Either the site is very minimal, or the signatures here don't cover its stack.",
        "category": "category",
        "matched_via": "matched via",
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
    },
    "pt": {
        "url": "URL",
        "detected": "Tecnologias detetadas",
        "no_detect": "Nenhuma tecnologia identificada. Ou o site é muito minimalista, ou as assinaturas aqui não cobrem a stack.",
        "category": "categoria",
        "matched_via": "detetado via",
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
    },
}

# Signature schema:
#   name            tech name shown in output
#   category        Server / Language / CMS / Framework / JS / Analytics / CDN / Cache / Other
#   header_re       optional regex against any response header (name=value pairs)
#   cookie_re       optional regex against any cookie name
#   html_re         optional regex against the response body (first ~200 KB)
#   header_name     optional: if set, only checks the named header's value
# A signature matches if ANY of its specified probes match.
SIGNATURES = (
    # ---- Web servers
    {"name": "nginx", "category": "Server", "header_name": "server", "header_re": r"(?i)nginx"},
    {"name": "Apache httpd", "category": "Server", "header_name": "server", "header_re": r"(?i)apache"},
    {"name": "IIS", "category": "Server", "header_name": "server", "header_re": r"(?i)IIS|Microsoft-IIS"},
    {"name": "Caddy", "category": "Server", "header_name": "server", "header_re": r"(?i)caddy"},
    {"name": "Cloudflare", "category": "CDN", "header_name": "server", "header_re": r"(?i)cloudflare"},
    {"name": "Fastly", "category": "CDN", "header_re": r"(?i)^x-served-by:.*cache-.*fastly|^via:.*fastly"},
    {"name": "Cloudfront", "category": "CDN", "header_re": r"(?i)^x-amz-cf-id|^via:.*cloudfront"},
    {"name": "Akamai", "category": "CDN", "header_re": r"(?i)^x-akamai|^server:.*akamaiGHost"},
    {"name": "Varnish", "category": "Cache", "header_re": r"(?i)^via:.*varnish|^x-varnish"},
    {"name": "GitHub Pages", "category": "Server", "header_name": "server", "header_re": r"(?i)GitHub\.com"},
    {"name": "Vercel", "category": "Server", "header_re": r"(?i)^server:.*vercel|^x-vercel"},
    {"name": "Netlify", "category": "Server", "header_re": r"(?i)^server:.*netlify|^x-nf-request-id"},
    # ---- Languages / runtimes (via X-Powered-By or cookies)
    {"name": "PHP", "category": "Language", "header_name": "x-powered-by", "header_re": r"(?i)PHP"},
    {"name": "Node.js / Express", "category": "Framework", "header_name": "x-powered-by", "header_re": r"(?i)express"},
    {"name": "ASP.NET", "category": "Framework", "header_name": "x-powered-by", "header_re": r"(?i)ASP\.NET"},
    {"name": "ASP.NET Core", "category": "Framework", "header_name": "server", "header_re": r"(?i)kestrel"},
    {"name": "Python (any of Django/Flask/FastAPI — needs further probe)", "category": "Language", "header_re": r"(?i)^server:.*python|^server:.*werkzeug|^server:.*gunicorn|^server:.*uvicorn"},
    {"name": "Ruby on Rails", "category": "Framework", "cookie_re": r"_rails_session", "header_re": r"(?i)^x-runtime"},
    {"name": "Java EE / Servlet", "category": "Framework", "cookie_re": r"^JSESSIONID$", "header_re": r"(?i)^server:.*tomcat|^server:.*jetty"},
    # ---- CMS
    {"name": "WordPress", "category": "CMS",
     "html_re": r"/wp-(?:content|includes|json)/|<meta[^>]+generator['\"]?\s*=\s*['\"]?WordPress",
     "cookie_re": r"^wordpress_"},
    {"name": "Drupal", "category": "CMS", "header_re": r"(?i)^x-generator:.*drupal", "html_re": r"<meta[^>]+content=['\"]Drupal"},
    {"name": "Joomla", "category": "CMS", "html_re": r"<meta[^>]+content=['\"]Joomla"},
    {"name": "Ghost", "category": "CMS", "html_re": r"<meta[^>]+content=['\"]Ghost", "header_re": r"(?i)^x-ghost-cache"},
    # ---- JS frameworks
    {"name": "React", "category": "JS", "html_re": r"data-reactroot|/static/js/main\.[a-f0-9]+\.js|React\.createElement"},
    {"name": "Vue.js", "category": "JS", "html_re": r"data-v-[a-f0-9]{8}|\bVue\.config\.|new Vue\("},
    {"name": "Svelte / SvelteKit", "category": "JS", "html_re": r"data-sveltekit|svelte-kit/"},
    {"name": "Next.js", "category": "JS", "html_re": r"/_next/static/|<script id=\"__NEXT_DATA__\""},
    {"name": "Nuxt.js", "category": "JS", "html_re": r"window\.__NUXT__|/_nuxt/"},
    {"name": "Angular", "category": "JS", "html_re": r"ng-version=|ng-app=|<app-root"},
    {"name": "jQuery", "category": "JS", "html_re": r"/jquery[.-][\d.]+(?:\.min)?\.js"},
    {"name": "Alpine.js", "category": "JS", "html_re": r"<script[^>]+alpinejs|x-data="},
    # ---- Site builders / SaaS
    {"name": "Squarespace", "category": "CMS", "header_re": r"(?i)^x-served-by:.*squarespace"},
    {"name": "Wix", "category": "CMS", "header_re": r"(?i)^server:.*wix|^x-wix"},
    {"name": "Shopify", "category": "E-commerce", "header_re": r"(?i)^server:.*cloudflare.*shopify|^x-shopify", "cookie_re": r"^_shopify_"},
    {"name": "WooCommerce", "category": "E-commerce", "html_re": r"woocommerce-loop|woocommerce/assets/"},
    {"name": "Magento", "category": "E-commerce", "cookie_re": r"frontend(_cid)?=", "html_re": r"Mage\.Cookies|/skin/frontend/"},
    # ---- Static-site generators (often inferred from HTML hints)
    {"name": "Jekyll", "category": "Generator", "html_re": r"<meta[^>]+generator['\"]?\s*=\s*['\"]?Jekyll"},
    {"name": "Hugo", "category": "Generator", "html_re": r"<meta[^>]+generator['\"]?\s*=\s*['\"]?Hugo"},
    {"name": "Gatsby", "category": "Generator", "html_re": r"<script[^>]+/page-data/|gatsby-link/"},
    # ---- Analytics
    {"name": "Google Analytics", "category": "Analytics", "html_re": r"www\.googletagmanager\.com/gtag/js|google-analytics\.com/(?:analytics|ga)\.js"},
    {"name": "Plausible", "category": "Analytics", "html_re": r"plausible\.io/js/"},
    {"name": "Matomo", "category": "Analytics", "html_re": r"matomo\.js|_paq\.push"},
    # ---- Tag managers
    {"name": "Google Tag Manager", "category": "TagManager", "html_re": r"googletagmanager\.com/gtm\.js"},
    # ---- Frameworks (back end, harder to pin)
    {"name": "Laravel", "category": "Framework", "cookie_re": r"^laravel_session$|^XSRF-TOKEN$"},
    {"name": "Django", "category": "Framework", "cookie_re": r"^csrftoken$|^sessionid$"},
)

CATEGORY_ORDER = ["Server", "CDN", "Cache", "Language", "Framework", "CMS",
                  "E-commerce", "Generator", "JS", "TagManager", "Analytics", "Other"]


@dataclass
class Detection:
    name: str
    category: str
    matched_via: list[str]


def fetch(url: str, timeout: float = 15.0) -> tuple[int, dict, list, str]:
    """Return (status, headers-dict-lowercased, set-cookie-list, body-text)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read(200_000).decode("utf-8", errors="replace")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        set_cookies = resp.headers.get_all("Set-Cookie") or []
        return resp.status, headers, set_cookies, body


def cookie_names(set_cookies: list[str]) -> list[str]:
    out = []
    for raw in set_cookies:
        nv = raw.split(";", 1)[0].strip()
        if "=" in nv:
            out.append(nv.split("=", 1)[0].strip())
    return out


def fingerprint(headers: dict, set_cookies: list[str], body: str) -> list[Detection]:
    matches: list[Detection] = []
    cookies = cookie_names(set_cookies)
    # Reconstruct a "key: value" blob of headers (lowercase keys) so signatures
    # can match against the raw text.
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())

    for sig in SIGNATURES:
        reasons: list[str] = []
        if "header_name" in sig and "header_re" in sig:
            v = headers.get(sig["header_name"], "")
            if v and re.search(sig["header_re"], v):
                reasons.append(f"{sig['header_name']}: {v}")
        elif "header_re" in sig:
            if re.search(sig["header_re"], header_blob, re.MULTILINE):
                reasons.append("response header")
        if "cookie_re" in sig:
            for name in cookies:
                if re.search(sig["cookie_re"], name):
                    reasons.append(f"cookie {name}")
                    break
        if "html_re" in sig:
            if re.search(sig["html_re"], body):
                reasons.append("HTML body")
        if reasons:
            matches.append(Detection(name=sig["name"], category=sig["category"], matched_via=reasons))
    return matches


def print_human(url: str, detections: list[Detection], lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['url']}: {url}\n")
    if not detections:
        print(f"  {L['no_detect']}\n")
        return

    by_cat: dict[str, list[Detection]] = {}
    for d in detections:
        by_cat.setdefault(d.category, []).append(d)

    print(f"{L['detected']} ({len(detections)}):\n")
    for cat in CATEGORY_ORDER + sorted(set(by_cat) - set(CATEGORY_ORDER)):
        if cat not in by_cat:
            continue
        print(f"  [{cat}]")
        for d in by_cat[cat]:
            print(f"    - {d.name}")
            for reason in d.matched_via:
                print(f"        {L['matched_via']}: {reason}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Identify the technology stack behind a website.")
    add_version_arg(parser, "tech_fingerprint.py")
    parser.add_argument("url", help="Target URL (http:// or https://). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    L = LABELS[args.lang]

    args.url = stdin_or_arg(args.url)
    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({args.url!r})", file=sys.stderr)
        return 2

    try:
        status, headers, set_cookies, body = fetch(args.url, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(f"{L['err_unreachable']} {args.url} — {e.reason}", file=sys.stderr)
        return 3
    except socket.timeout:
        print(f"{L['err_unreachable']} {args.url} — timeout", file=sys.stderr)
        return 3

    detections = fingerprint(headers, set_cookies, body)

    if args.json:
        out = {
            "url": args.url,
            "lang": args.lang,
            "status": status,
            "detections": [asdict(d) for d in detections],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(args.url, detections, args.lang)

    return 0 if detections else 1


if __name__ == "__main__":
    sys.exit(main())
