#!/usr/bin/env python3
"""Check the security-relevant HTTP response headers of a URL.

Examples:
    tools/check_headers.py https://example.com
    tools/check_headers.py https://example.com --lang pt
    tools/check_headers.py https://example.com --no-color
    tools/check_headers.py https://example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import textwrap
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Optional

from _lib import build_ssl_context, make_user_agent, add_version_arg, add_user_agent_arg, stdin_or_arg, add_proxy_arg

USER_AGENT = make_user_agent("check_headers.py")

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

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "url": "URL",
        "final_url": "Final URL",
        "redirect_chain": "Redirect chain",
        "status": "Status",
        "security_headers": "Security headers",
        "score": "Score",
        "score_suffix": "headers OK",
        "issues_found": "Issues found",
        "no_issues": "No issues — every checked header is in good shape.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "redirect_note": (
            "Note: the URL above redirected — the headers below describe the FINAL response, "
            "not the original URL. The original may have weaker headers (or none)."
        ),
        "err_scheme": "error: URL must start with http:// or https://",
        "err_unreachable": "error: could not reach",
        "err_timeout": "error: timeout after",
        "got": "got",
        "seconds": "s",
    },
    "pt": {
        "url": "URL",
        "final_url": "URL final",
        "redirect_chain": "Cadeia de redirects",
        "status": "Estado",
        "security_headers": "Headers de segurança",
        "score": "Pontuação",
        "score_suffix": "headers OK",
        "issues_found": "Problemas encontrados",
        "no_issues": "Sem problemas — todos os headers verificados estão em ordem.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "redirect_note": (
            "Nota: o URL acima foi redirecionado — os headers abaixo descrevem a resposta FINAL, "
            "não o URL original. O URL original pode ter headers mais fracos (ou nenhuns)."
        ),
        "err_scheme": "erro: URL tem de começar por http:// ou https://",
        "err_unreachable": "erro: não foi possível alcançar",
        "err_timeout": "erro: timeout após",
        "got": "recebido",
        "seconds": "s",
    },
}

NOTES = {
    "en": {
        "hsts_missing": "HTTPS not enforced; supports downgrade attacks",
        "hsts_weak": "max-age={} is below 180 days (15552000)",
        "hsts_ok": "HSTS enforced",
        "csp_missing": "No CSP; XSS payloads are not restricted by the browser",
        "csp_weak_directives": "Permissive directives: {}",
        "csp_weak_report_only": "Report-Only mode — not enforced, only logged",
        "csp_ok": "CSP present and reasonably strict",
        "xfo_ok_covered": "Covered by CSP frame-ancestors",
        "xfo_ok_backup": "Backed up by CSP frame-ancestors",
        "xfo_missing": "Clickjacking risk",
        "xfo_ok_restricted": "Iframes restricted",
        "xfo_weak_unusual": "Unusual value: {}",
        "xcto_missing": "MIME-sniffing not disabled; consider 'nosniff'",
        "xcto_ok": "MIME sniffing disabled",
        "xcto_weak": "Expected exactly 'nosniff'",
        "ref_missing": "Default referrer behavior leaks paths to third parties",
        "ref_ok": "Privacy-respecting policy",
        "ref_weak_unsafe": "Unsafe — sends full URL cross-origin",
        "ref_weak": "Weak policy",
        "perm_missing": "No restriction on browser features (camera, geolocation, etc.)",
        "perm_weak_feature": "Using deprecated Feature-Policy — migrate to Permissions-Policy",
        "perm_ok": "Permissions policy set",
        "server_weak_version": "Reveals server software/version",
        "server_info_no_version": "Reveals server software (no version)",
        "info_disclosure": "Reveals stack/version — consider removing",
        "wildcard_source": "wildcard '*' source",
        "csp_data_uri_script": "'data:' in script/default-src (XSS via data URI)",
        "csp_http_scheme": "'http:' in script/default-src (plaintext load)",
        "csp_no_object_src": "no object-src (plugin bypass possible)",
        "coop_missing": "No COOP; cross-origin windows share browsing context (Spectre / cross-window attacks)",
        "coop_ok": "Browsing context isolated from cross-origin windows",
        "coop_weak": "COOP set but with permissive value",
        "coep_missing": "No COEP; embedding cross-origin resources without explicit consent",
        "coep_ok": "Embedder requires cross-origin resources to opt-in",
        "coep_weak": "COEP set but with unusual value",
        "corp_missing": "No CORP; resources can be embedded by any origin",
        "corp_ok": "Resource embedding restricted to same-origin or same-site",
        "corp_weak": "CORP set but allows cross-origin embedding",
        "xss_prot_deprecated": "Deprecated — set to 0 or remove it; '1' can create vulnerabilities in old browsers",
        "xss_prot_disabled": "Explicitly disabled (correct for modern sites)",
    },
    "pt": {
        "hsts_missing": "HTTPS não imposto; permite downgrade attacks",
        "hsts_weak": "max-age={} é inferior a 180 dias (15552000)",
        "hsts_ok": "HSTS imposto",
        "csp_missing": "Sem CSP; payloads de XSS não são restringidos pelo browser",
        "csp_weak_directives": "Diretivas permissivas: {}",
        "csp_weak_report_only": "Modo Report-Only — não imposto, apenas registado",
        "csp_ok": "CSP presente e razoavelmente estrito",
        "xfo_ok_covered": "Coberto pelo CSP frame-ancestors",
        "xfo_ok_backup": "Reforçado pelo CSP frame-ancestors",
        "xfo_missing": "Risco de clickjacking",
        "xfo_ok_restricted": "Iframes restritos",
        "xfo_weak_unusual": "Valor invulgar: {}",
        "xcto_missing": "MIME-sniffing não desativado; considera 'nosniff'",
        "xcto_ok": "MIME sniffing desativado",
        "xcto_weak": "Esperado exatamente 'nosniff'",
        "ref_missing": "Comportamento por defeito do referrer expõe paths a terceiros",
        "ref_ok": "Política respeitadora da privacidade",
        "ref_weak_unsafe": "Inseguro — envia URL completo cross-origin",
        "ref_weak": "Política fraca",
        "perm_missing": "Sem restrição de funcionalidades do browser (câmara, geolocalização, etc.)",
        "perm_weak_feature": "Uso de Feature-Policy (descontinuado) — migra para Permissions-Policy",
        "perm_ok": "Política de permissões definida",
        "server_weak_version": "Revela software/versão do servidor",
        "server_info_no_version": "Revela software do servidor (sem versão)",
        "info_disclosure": "Revela stack/versão — considera remover",
        "wildcard_source": "origem com wildcard '*'",
        "csp_data_uri_script": "'data:' em script/default-src (XSS via data URI)",
        "csp_http_scheme": "'http:' em script/default-src (carga em texto claro)",
        "csp_no_object_src": "object-src em falta (bypass via plugin possível)",
        "coop_missing": "Sem COOP; janelas cross-origin partilham contexto de browsing (Spectre / ataques cross-window)",
        "coop_ok": "Contexto de browsing isolado de janelas cross-origin",
        "coop_weak": "COOP definido mas com valor permissivo",
        "coep_missing": "Sem COEP; recursos cross-origin podem ser embebidos sem consentimento explícito",
        "coep_ok": "Embedder exige opt-in dos recursos cross-origin",
        "coep_weak": "COEP definido mas com valor invulgar",
        "corp_missing": "Sem CORP; recursos podem ser embebidos por qualquer origem",
        "corp_ok": "Embedding de recursos restrito a same-origin ou same-site",
        "corp_weak": "CORP definido mas permite embedding cross-origin",
        "xss_prot_deprecated": "Descontinuado — define como 0 ou remove; '1' pode criar vulnerabilidades em browsers antigos",
        "xss_prot_disabled": "Explicitamente desativado (correto para sites modernos)",
    },
}

HEADER_RISK_INFO = {
    "en": {
        "Strict-Transport-Security": {
            "risk": (
                "Without HSTS, browsers may connect over plain HTTP at least once. "
                "An attacker on the network can intercept that request (SSL stripping) "
                "and serve a malicious unencrypted version of the page."
            ),
            "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
        "Content-Security-Policy": {
            "risk": (
                "XSS (Cross-Site Scripting) impact is unconstrained. Any injected "
                "<script> tag or inline JS executes with full page permissions — "
                "session theft, account takeover, defacement."
            ),
            "fix": "Start with: default-src 'self'; then refine per resource type.",
        },
        "X-Frame-Options": {
            "risk": (
                "Clickjacking. The page can be embedded in an invisible iframe on a "
                "malicious site and users tricked into clicking authenticated actions."
            ),
            "fix": "X-Frame-Options: DENY  (or use CSP: frame-ancestors 'none')",
        },
        "X-Content-Type-Options": {
            "risk": (
                "MIME-sniffing. Browsers may interpret uploaded or served files as a "
                "different content type than declared, enabling XSS via file uploads "
                "(e.g. a .txt file being executed as JavaScript)."
            ),
            "fix": "X-Content-Type-Options: nosniff",
        },
        "Referrer-Policy": {
            "risk": (
                "Full URLs (paths, query strings) are sent in the Referer header to "
                "every cross-origin resource. Can leak session tokens in URLs, "
                "internal page structure, or sensitive identifiers."
            ),
            "fix": "Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "risk": (
                "Embedded iframes and compromised scripts can request access to "
                "camera, microphone, geolocation, USB, etc. without your origin "
                "restricting which features may be used."
            ),
            "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        },
        "Server": {
            "risk": (
                "Reveals server software (and sometimes version) — helps attackers "
                "narrow down which exploits to try first."
            ),
            "fix": "Remove the header, or strip the version (e.g. Server: nginx).",
        },
        "X-Powered-By": {
            "risk": "Reveals application stack and/or framework version — unnecessary disclosure.",
            "fix": "Remove the header from your server / framework config.",
        },
        "X-AspNet-Version": {
            "risk": "Reveals exact .NET framework version — helps target known CVEs.",
            "fix": "In web.config: <httpRuntime enableVersionHeader=\"false\" />",
        },
        "X-AspNetMvc-Version": {
            "risk": "Reveals exact ASP.NET MVC version — same as above.",
            "fix": "Remove via MvcHandler.DisableMvcResponseHeader = true.",
        },
        "Cross-Origin-Opener-Policy": {
            "risk": (
                "Without COOP, a window opened by an attacker (or one that opens you) "
                "shares a browsing context group. This enables Spectre-class side-channel "
                "attacks and cross-window reference probing."
            ),
            "fix": "Cross-Origin-Opener-Policy: same-origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "risk": (
                "Without COEP, the page can embed cross-origin resources that haven't "
                "opted in (no CORP). Combined with COOP, COEP enables crossOriginIsolated "
                "mode (required for SharedArrayBuffer and high-precision timers)."
            ),
            "fix": "Cross-Origin-Embedder-Policy: require-corp",
        },
        "Cross-Origin-Resource-Policy": {
            "risk": (
                "Without CORP, any origin can embed this resource via <img>, <script>, "
                "<iframe>, etc. — useful for tracking, side-channels, or hotlinking attacks."
            ),
            "fix": "Cross-Origin-Resource-Policy: same-origin  (or same-site)",
        },
        "X-XSS-Protection": {
            "risk": (
                "X-XSS-Protection is deprecated and ignored by modern browsers. "
                "Setting it to '1' can in some edge cases introduce XSS vulnerabilities "
                "in legacy browsers. Modern protection is provided by CSP instead."
            ),
            "fix": "Remove the header, or set X-XSS-Protection: 0 to explicitly disable it.",
        },
    },
    "pt": {
        "Strict-Transport-Security": {
            "risk": (
                "Sem HSTS, os browsers podem ligar-se via HTTP simples pelo menos uma "
                "vez. Um atacante na rede pode intercetar esse pedido (SSL stripping) "
                "e servir uma versão maliciosa não cifrada da página."
            ),
            "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
        "Content-Security-Policy": {
            "risk": (
                "O impacto de XSS (Cross-Site Scripting) fica ilimitado. Qualquer tag "
                "<script> injetada ou JavaScript inline executa com todas as "
                "permissões da página — roubo de sessão, account takeover, defacement."
            ),
            "fix": "Começa com: default-src 'self'; depois refina por tipo de recurso.",
        },
        "X-Frame-Options": {
            "risk": (
                "Clickjacking. A página pode ser embebida num iframe invisível num "
                "site malicioso e os utilizadores enganados a clicar em ações "
                "autenticadas."
            ),
            "fix": "X-Frame-Options: DENY  (ou usa CSP: frame-ancestors 'none')",
        },
        "X-Content-Type-Options": {
            "risk": (
                "MIME-sniffing. Os browsers podem interpretar ficheiros servidos ou "
                "enviados com um content-type diferente do declarado, abrindo "
                "caminho a XSS via uploads (ex: um ficheiro .txt executado como "
                "JavaScript)."
            ),
            "fix": "X-Content-Type-Options: nosniff",
        },
        "Referrer-Policy": {
            "risk": (
                "URLs completos (paths, query strings) são enviados no header Referer "
                "para todos os recursos cross-origin. Pode expor tokens de sessão em "
                "URLs, estrutura interna da aplicação ou identificadores sensíveis."
            ),
            "fix": "Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "risk": (
                "Iframes embebidos e scripts comprometidos podem pedir acesso à "
                "câmara, microfone, geolocalização, USB, etc. sem que a tua origem "
                "restrinja que funcionalidades podem ser usadas."
            ),
            "fix": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        },
        "Server": {
            "risk": (
                "Revela o software do servidor (e por vezes a versão) — ajuda os "
                "atacantes a saber por que exploits começar."
            ),
            "fix": "Remove o header, ou retira a versão (ex: Server: nginx).",
        },
        "X-Powered-By": {
            "risk": "Revela a stack/framework da aplicação — disclosure desnecessário.",
            "fix": "Remove o header da configuração do servidor / framework.",
        },
        "X-AspNet-Version": {
            "risk": "Revela a versão exata do .NET framework — ajuda a apontar CVEs conhecidas.",
            "fix": "Em web.config: <httpRuntime enableVersionHeader=\"false\" />",
        },
        "X-AspNetMvc-Version": {
            "risk": "Revela a versão exata do ASP.NET MVC — o mesmo problema do anterior.",
            "fix": "Remove com MvcHandler.DisableMvcResponseHeader = true.",
        },
        "Cross-Origin-Opener-Policy": {
            "risk": (
                "Sem COOP, uma janela aberta por um atacante (ou uma que te abre) partilha "
                "browsing context group. Permite ataques side-channel da família Spectre e "
                "sondagem por referência cross-window."
            ),
            "fix": "Cross-Origin-Opener-Policy: same-origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "risk": (
                "Sem COEP, a página pode embeber recursos cross-origin que não fizeram opt-in "
                "(sem CORP). Combinado com COOP, COEP permite o modo crossOriginIsolated "
                "(necessário para SharedArrayBuffer e timers de alta precisão)."
            ),
            "fix": "Cross-Origin-Embedder-Policy: require-corp",
        },
        "Cross-Origin-Resource-Policy": {
            "risk": (
                "Sem CORP, qualquer origem pode embeber este recurso via <img>, <script>, "
                "<iframe>, etc. — útil para tracking, side-channels ou ataques de hotlinking."
            ),
            "fix": "Cross-Origin-Resource-Policy: same-origin  (ou same-site)",
        },
        "X-XSS-Protection": {
            "risk": (
                "X-XSS-Protection é descontinuado e ignorado por browsers modernos. "
                "Definido como '1', pode em alguns casos introduzir vulnerabilidades XSS "
                "em browsers antigos. A proteção moderna é fornecida pelo CSP."
            ),
            "fix": "Remove o header, ou define X-XSS-Protection: 0 para o desativar explicitamente.",
        },
    },
}


@dataclass
class Finding:
    header: str
    status: str
    value: Optional[str]
    note: str


def _normalize(headers_obj) -> dict[str, str]:
    """Return headers as a dict keyed by lowercase name (HTTP headers are case-insensitive)."""
    return {k.lower(): v for k, v in headers_obj.items()} if headers_obj else {}


class _RedirectTracker(urllib.request.HTTPRedirectHandler):
    """HTTP redirect handler that records the chain of intermediate URLs.

    Default urllib follows redirects silently. We need visibility because
    the *original* URL might have a weak header configuration that gets
    hidden behind a strong-headers final destination.
    """
    def __init__(self) -> None:
        super().__init__()
        self.chain: list[tuple[int, str, str]] = []  # (status, from_url, to_url)

    def http_error_301(self, req, fp, code, msg, headers):
        new_url = headers.get("Location") or headers.get("URI") or ""
        self.chain.append((code, req.full_url, new_url))
        return super().http_error_301(req, fp, code, msg, headers)

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


def fetch_headers(url: str, timeout: float = 10.0, proxy_url: str | None = None):
    """Fetch URL and return (final_url, status_code, headers, redirect_chain).

    Headers are keyed by lowercase name (HTTP headers are case-insensitive
    per RFC 7230 §3.2). All check_* functions must look up lowercase keys.

    redirect_chain is a list of (status, from_url, to_url) tuples, empty
    if the response came directly from the requested URL.
    """
    tracker = _RedirectTracker()
    handlers: list = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    handlers += [urllib.request.HTTPSHandler(context=build_ssl_context()), tracker]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.geturl(), resp.status, _normalize(resp.headers), tracker.chain
    except urllib.error.HTTPError as e:
        return e.geturl(), e.code, _normalize(e.headers), tracker.chain


def check_hsts(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Strict-Transport-Security"
    raw = headers.get("strict-transport-security")
    if not raw:
        return Finding(display, MISSING, None, N["hsts_missing"])
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", raw, re.I)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    if max_age < 15552000:
        return Finding(display, WEAK, raw, N["hsts_weak"].format(max_age))
    return Finding(display, OK, raw, N["hsts_ok"])


def check_csp(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Content-Security-Policy"
    enforced = headers.get("content-security-policy")
    report_only = headers.get("content-security-policy-report-only")
    raw = enforced or report_only
    if not raw:
        return Finding(display, MISSING, None, N["csp_missing"])
    weak = []
    raw_lower = raw.lower()
    if "'unsafe-inline'" in raw_lower:
        weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in raw_lower:
        weak.append("'unsafe-eval'")
    if "*" in raw.split():
        weak.append(N["wildcard_source"])
    # data: URI in script-src / default-src allows inline script via data: URLs
    if re.search(r"(?:script-src|default-src)\s[^;]*\bdata:", raw_lower):
        weak.append(N["csp_data_uri_script"])
    # http: scheme in script-src / default-src loads scripts over plaintext
    if re.search(r"(?:script-src|default-src)\s[^;]*\bhttp:", raw_lower):
        weak.append(N["csp_http_scheme"])
    # No object-src and no default-src → plugin elements (object/embed) unrestricted
    if "object-src" not in raw_lower and "default-src" not in raw_lower:
        weak.append(N["csp_no_object_src"])
    if weak:
        return Finding(display, WEAK, raw, N["csp_weak_directives"].format(", ".join(weak)))
    if report_only and not enforced:
        return Finding(display, WEAK, raw, N["csp_weak_report_only"])
    return Finding(display, OK, raw, N["csp_ok"])


def check_x_frame_options(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "X-Frame-Options"
    raw = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if "frame-ancestors" in csp.lower():
        if not raw:
            return Finding(display, OK, None, N["xfo_ok_covered"])
        return Finding(display, OK, raw, N["xfo_ok_backup"])
    if not raw:
        return Finding(display, MISSING, None, N["xfo_missing"])
    if raw.strip().upper() in ("DENY", "SAMEORIGIN"):
        return Finding(display, OK, raw, N["xfo_ok_restricted"])
    return Finding(display, WEAK, raw, N["xfo_weak_unusual"].format(raw))


def check_x_content_type_options(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "X-Content-Type-Options"
    raw = headers.get("x-content-type-options")
    if not raw:
        return Finding(display, MISSING, None, N["xcto_missing"])
    if raw.strip().lower() == "nosniff":
        return Finding(display, OK, raw, N["xcto_ok"])
    return Finding(display, WEAK, raw, N["xcto_weak"])


def check_referrer_policy(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Referrer-Policy"
    raw = headers.get("referrer-policy")
    if not raw:
        return Finding(display, MISSING, None, N["ref_missing"])
    strong_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if any(v in raw.lower() for v in strong_values):
        return Finding(display, OK, raw, N["ref_ok"])
    if "unsafe-url" in raw.lower() or raw.lower().strip() == "":
        return Finding(display, WEAK, raw, N["ref_weak_unsafe"])
    return Finding(display, WEAK, raw, N["ref_weak"])


def check_permissions_policy(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Permissions-Policy"
    perms = headers.get("permissions-policy")
    feature = headers.get("feature-policy")
    raw = perms or feature
    if not raw:
        return Finding(display, MISSING, None, N["perm_missing"])
    if feature and not perms:
        return Finding(display, WEAK, raw, N["perm_weak_feature"])
    return Finding(display, OK, raw, N["perm_ok"])


def check_coop(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Cross-Origin-Opener-Policy"
    raw = headers.get("cross-origin-opener-policy")
    if not raw:
        return Finding(display, MISSING, None, N["coop_missing"])
    if raw.strip().lower() in ("same-origin", "same-origin-allow-popups"):
        return Finding(display, OK, raw, N["coop_ok"])
    return Finding(display, WEAK, raw, N["coop_weak"])


def check_coep(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Cross-Origin-Embedder-Policy"
    raw = headers.get("cross-origin-embedder-policy")
    if not raw:
        return Finding(display, MISSING, None, N["coep_missing"])
    if raw.strip().lower() in ("require-corp", "credentialless"):
        return Finding(display, OK, raw, N["coep_ok"])
    return Finding(display, WEAK, raw, N["coep_weak"])


def check_corp(headers: dict, lang: str) -> Finding:
    N = NOTES[lang]
    display = "Cross-Origin-Resource-Policy"
    raw = headers.get("cross-origin-resource-policy")
    if not raw:
        return Finding(display, MISSING, None, N["corp_missing"])
    if raw.strip().lower() in ("same-origin", "same-site"):
        return Finding(display, OK, raw, N["corp_ok"])
    return Finding(display, WEAK, raw, N["corp_weak"])


def check_x_xss_protection(headers: dict, lang: str) -> list[Finding]:
    N = NOTES[lang]
    raw = headers.get("x-xss-protection")
    if not raw:
        return []
    if raw.strip() == "0":
        return [Finding("X-XSS-Protection", INFO, raw, N["xss_prot_disabled"])]
    return [Finding("X-XSS-Protection", WEAK, raw, N["xss_prot_deprecated"])]


def check_info_disclosure(headers: dict, lang: str) -> list[Finding]:
    N = NOTES[lang]
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
            findings.append(Finding(display, WEAK, v, N["server_weak_version"]))
        elif display == "Server":
            findings.append(Finding(display, INFO, v, N["server_info_no_version"]))
        else:
            findings.append(Finding(display, WEAK, v, N["info_disclosure"]))
    return findings


def colorize(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{ANSI[key]}{text}{ANSI['reset']}"


def print_human_report(
    url: str, status: int, findings: list[Finding], use_color: bool, lang: str,
    requested_url: str = "", redirect_chain: list[tuple[int, str, str]] | None = None,
) -> None:
    L = LABELS[lang]
    bold = lambda s: f"{ANSI['bold']}{s}{ANSI['reset']}" if use_color else s
    dim = lambda s: f"{ANSI['dim']}{s}{ANSI['reset']}" if use_color else s

    if requested_url and requested_url != url:
        print(f"\n{bold(L['url'] + ':')}        {requested_url}")
        print(f"{bold(L['final_url'] + ':')}  {url}")
        if redirect_chain:
            print(f"\n{bold(L['redirect_chain'] + ':')}")
            for code, src, dst in redirect_chain:
                print(f"  {code}  {src}  →  {dst}")
        print(f"\n{colorize(L['redirect_note'], WEAK, use_color)}")
    else:
        print(f"\n{bold(L['url'] + ':')}    {url}")
    print(f"{bold(L['status'] + ':')} {status}\n")

    print(bold(L["security_headers"] + ":"))
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
    print(f"\n{bold(L['score'] + ':')} {ok_count}/{relevant} {L['score_suffix']}")

    print_issue_report(findings, use_color, lang)


def print_issue_report(findings: list[Finding], use_color: bool, lang: str) -> None:
    """Print a per-issue summary with concrete risk and recommended fix."""
    L = LABELS[lang]
    risk_info = HEADER_RISK_INFO[lang]
    bold = lambda s: f"{ANSI['bold']}{s}{ANSI['reset']}" if use_color else s
    dim = lambda s: f"{ANSI['dim']}{s}{ANSI['reset']}" if use_color else s

    issues = [f for f in findings if f.status in (MISSING, WEAK)]
    if not issues:
        print(f"\n{colorize(L['no_issues'], OK, use_color)}")
        return

    print(f"\n{bold(L['issues_found'] + f' ({len(issues)}):')}")
    for f in issues:
        info = risk_info.get(f.header, {})
        sym = colorize(SYMBOL[f.status], f.status, use_color)
        status_label = colorize(f.status, f.status, use_color)
        print(f"\n  {sym}  {bold(f.header)} [{status_label}]")
        risk = info.get("risk")
        if risk:
            wrapped = textwrap.wrap(risk, width=72)
            if wrapped:
                print(f"     {dim(L['risk_label'])} {wrapped[0]}")
                for line in wrapped[1:]:
                    print(f"           {line}")
        fix = info.get("fix")
        if fix:
            print(f"     {dim(L['fix_label'])}{fix}")


def main() -> int:
    global USER_AGENT
    parser = argparse.ArgumentParser(
        description="Check security-relevant HTTP response headers of a URL.",
    )
    add_version_arg(parser, "check_headers.py")
    add_user_agent_arg(parser, USER_AGENT)
    add_proxy_arg(parser)
    parser.add_argument("url", help="Target URL (must include scheme: http:// or https://). Use '-' to read from stdin.")
    parser.add_argument(
        "--lang",
        choices=LANGS,
        default="en",
        help="Output language (default: en). 'pt' uses European Portuguese.",
    )
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
    USER_AGENT = args.user_agent
    L = LABELS[args.lang]
    args.url = stdin_or_arg(args.url)

    if not re.match(r"^https?://", args.url):
        print(f"{L['err_scheme']} ({L['got']} {args.url!r})", file=sys.stderr)
        return 2

    requested_url = args.url
    try:
        final_url, status, headers, redirect_chain = fetch_headers(args.url, timeout=args.timeout, proxy_url=args.proxy)
    except urllib.error.URLError as e:
        print(f"{L['err_unreachable']} {args.url} — {e.reason}", file=sys.stderr)
        return 3
    except socket.timeout:
        print(f"{L['err_timeout']} {args.timeout}{L['seconds']} {args.url}", file=sys.stderr)
        return 3

    findings: list[Finding] = [
        check_hsts(headers, args.lang),
        check_csp(headers, args.lang),
        check_x_frame_options(headers, args.lang),
        check_x_content_type_options(headers, args.lang),
        check_referrer_policy(headers, args.lang),
        check_permissions_policy(headers, args.lang),
        check_coop(headers, args.lang),
        check_coep(headers, args.lang),
        check_corp(headers, args.lang),
    ]
    findings.extend(check_x_xss_protection(headers, args.lang))
    findings.extend(check_info_disclosure(headers, args.lang))

    if args.json:
        risk_info = HEADER_RISK_INFO[args.lang]
        findings_out = []
        for f in findings:
            entry = asdict(f)
            if f.status in (MISSING, WEAK):
                info = risk_info.get(f.header, {})
                entry["risk"] = info.get("risk")
                entry["fix"] = info.get("fix")
            findings_out.append(entry)
        out = {
            "requested_url": requested_url,
            "url": final_url,
            "status": status,
            "lang": args.lang,
            "redirect_chain": [{"status": c, "from": s, "to": d} for c, s, d in redirect_chain],
            "findings": findings_out,
            "issues_count": sum(1 for f in findings if f.status in (MISSING, WEAK)),
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        print_human_report(final_url, status, findings, use_color, args.lang,
                           requested_url=requested_url, redirect_chain=redirect_chain)

    has_missing = any(f.status == MISSING for f in findings)
    return 1 if has_missing else 0


if __name__ == "__main__":
    sys.exit(main())
