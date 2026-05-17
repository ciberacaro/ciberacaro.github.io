#!/usr/bin/env python3
"""Inspect the TLS certificate of a host and flag common issues.

Examples:
    tools/tls_inspect.py example.com
    tools/tls_inspect.py example.com:8443 --lang pt
    tools/tls_inspect.py https://github.com --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from _lib import add_version_arg, stdin_or_arg

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "target": "Target",
        "subject": "Subject",
        "issuer": "Issuer",
        "validity": "Validity",
        "valid_from": "Valid from",
        "valid_to": "Valid to",
        "days_left": "days left",
        "sig_algo": "Signature algorithm",
        "key": "Public key",
        "version": "Version",
        "serial": "Serial",
        "sans": "Subject Alternative Names",
        "tls_version": "TLS version (negotiated)",
        "cipher": "Cipher",
        "supported_versions": "TLS versions accepted by server",
        "supported": "accepted",
        "not_supported": "rejected",
        "not_tested": "not tested (build-time disabled)",
        "issues_header": "Issues found",
        "no_issues": "No issues — certificate looks healthy.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "err_resolve": "error: could not resolve host",
        "err_connect": "error: could not connect",
        "err_tls": "error: TLS handshake failed",
        "err_timeout": "error: timeout after",
    },
    "pt": {
        "target": "Alvo",
        "subject": "Subject",
        "issuer": "Emissor",
        "validity": "Validade",
        "valid_from": "Válido desde",
        "valid_to": "Válido até",
        "days_left": "dias restantes",
        "sig_algo": "Algoritmo de assinatura",
        "key": "Chave pública",
        "version": "Versão",
        "serial": "Série",
        "sans": "Subject Alternative Names",
        "tls_version": "Versão TLS (negociada)",
        "cipher": "Cifra",
        "supported_versions": "Versões TLS aceites pelo servidor",
        "supported": "aceite",
        "not_supported": "rejeitada",
        "not_tested": "não testado (desativado em build-time)",
        "issues_header": "Problemas encontrados",
        "no_issues": "Sem problemas — o certificado parece saudável.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "err_resolve": "erro: não foi possível resolver o host",
        "err_connect": "erro: não foi possível ligar",
        "err_tls": "erro: handshake TLS falhou",
        "err_timeout": "erro: timeout após",
    },
}

# Issues with bilingual risk/fix text
ISSUE_TEXT = {
    "weak_tls_versions": {
        "en": ("Server accepts deprecated TLS version(s): {}",
               "Disable SSLv3 / TLS 1.0 / TLS 1.1 in your server config. They are vulnerable to BEAST, POODLE, and others; modern browsers refuse them anyway."),
        "pt": ("Servidor aceita versão(ões) TLS descontinuada(s): {}",
               "Desativa SSLv3 / TLS 1.0 / TLS 1.1 na configuração do servidor. São vulneráveis a BEAST, POODLE e outros; browsers modernos já as recusam."),
    },
    "expired": {
        "en": ("Certificate has expired", "Renew the certificate immediately. Browsers will refuse the connection."),
        "pt": ("O certificado expirou", "Renova o certificado imediatamente. Os browsers vão recusar a ligação."),
    },
    "expiring_soon": {
        "en": ("Certificate expires within 30 days", "Schedule renewal now — production outages happen when certs lapse silently."),
        "pt": ("O certificado expira em menos de 30 dias", "Agenda a renovação já — outages em produção acontecem quando os certificados expiram silenciosamente."),
    },
    "self_signed": {
        "en": ("Self-signed certificate (issuer == subject)", "Browsers will warn the user. Use a proper CA (Let's Encrypt is free)."),
        "pt": ("Certificado auto-assinado (issuer == subject)", "Os browsers vão alertar o utilizador. Usa uma CA reconhecida (Let's Encrypt é gratuito)."),
    },
    "weak_sig": {
        "en": ("Weak signature algorithm ({})", "Modern CAs no longer issue MD5/SHA-1 certs. Reissue with SHA-256 or better."),
        "pt": ("Algoritmo de assinatura fraco ({})", "CAs modernos já não emitem certificados MD5/SHA-1. Reemite com SHA-256 ou melhor."),
    },
    "wildcard_too_broad": {
        "en": ("Wildcard SAN covers too broad a domain ({})", "A *.example.com wildcard means one compromised host compromises all. Limit scope where possible."),
        "pt": ("Wildcard SAN cobre um domínio demasiado abrangente ({})", "Um wildcard *.example.com significa que um host comprometido compromete todos. Limita o escopo quando possível."),
    },
    "host_mismatch": {
        "en": ("Connected host '{}' is not covered by the certificate's CN/SANs", "Either the cert was issued for a different name, or DNS routes you incorrectly."),
        "pt": ("O host '{}' não está coberto pelo CN/SANs do certificado", "Ou o certificado foi emitido para outro nome, ou o DNS está a encaminhar mal."),
    },
}


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


@dataclass
class CertInfo:
    target: str
    subject: dict
    issuer: dict
    valid_from: str
    valid_to: str
    days_left: int
    sig_algorithm: str
    version: int
    serial: str
    sans: list[str]
    tls_version: str
    cipher: str
    accepted_versions: dict[str, str] = field(default_factory=dict)  # version -> "accepted"|"rejected"|"unavailable"
    issues: list[Issue] = field(default_factory=list)


# Versions we probe, ordered oldest -> newest. ssl.TLSVersion uses these names.
# Some are likely to be unavailable depending on the Python build (e.g. SSLv3
# is compiled out in modern Pythons).
TLS_VERSIONS_TO_PROBE = (
    ("SSLv3", "SSLv3"),
    ("TLSv1", "TLSv1.0"),
    ("TLSv1_1", "TLSv1.1"),
    ("TLSv1_2", "TLSv1.2"),
    ("TLSv1_3", "TLSv1.3"),
)
# Versions that are considered weak/deprecated for security reporting purposes.
DEPRECATED_VERSIONS = {"SSLv3", "TLSv1.0", "TLSv1.1"}


def parse_host_port(value: str) -> tuple[str, int]:
    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 443)
        return host, port
    if ":" in value:
        host, _, p = value.partition(":")
        return host, int(p)
    return value, 443


def probe_tls_version(host: str, port: int, version_attr: str, timeout: float) -> str:
    """Try to handshake with `host:port` constrained to a single TLS version.

    Returns "accepted", "rejected", or "unavailable" (this build of Python /
    OpenSSL has no support for that version at all).
    """
    try:
        version_enum = getattr(ssl.TLSVersion, version_attr)
    except AttributeError:
        return "unavailable"

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Force min == max so the handshake is pinned to exactly this version.
        ctx.minimum_version = version_enum
        ctx.maximum_version = version_enum
        # SSLv3 / TLS 1.0 / TLS 1.1 ciphers may have been removed from the
        # default cipher list. Re-enable a permissive list for the probe.
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    except (ValueError, ssl.SSLError):
        return "unavailable"

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "accepted"
    except (ssl.SSLError, ssl.SSLEOFError, ConnectionResetError):
        return "rejected"
    except (socket.timeout, TimeoutError, OSError):
        # Treat network-level errors as rejected — distinguishing them from
        # protocol errors isn't possible without parsing the alert.
        return "rejected"


def fetch_cert(host: str, port: int, timeout: float = 10.0) -> tuple[dict, str, str, bytes]:
    """Return (cert_dict, tls_version, cipher_name, der_bytes).

    Permissive by design: CERT_NONE so even invalid/self-signed/expired certs
    are inspectable, and SECLEVEL=0 so legacy-only servers (TLS 1.0/1.1) can
    still hand us their certificate. Without that, modern OpenSSL excludes
    legacy ciphers by default and the handshake refuses to start.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
            cipher_name = ssock.cipher()[0] if ssock.cipher() else ""
    if not cert_der:
        return {}, tls_version, cipher_name, b""
    cert = _parse_der(cert_der)
    return cert, tls_version, cipher_name, cert_der


def _parse_der(der: bytes) -> dict:
    """Convert DER to PEM and parse with ssl's internal cert decoder.

    Caveat: ssl._ssl._test_decode_cert is an internal/private API
    (leading underscore on the module). It's the only way to get a
    parsed cert dict in pure stdlib without `cryptography`. If a future
    Python release removes it, this function will need to fall back to
    parsing DER manually or shelling out to `openssl x509`.
    """
    import tempfile

    pem = ssl.DER_cert_to_PEM_cert(der)
    fd_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            fd_path = f.name
        try:
            return ssl._ssl._test_decode_cert(fd_path)
        except AttributeError as e:
            raise RuntimeError(
                "ssl._ssl._test_decode_cert is unavailable in this Python build — "
                "cert parsing requires either upgrading to a stdlib version that "
                "exposes it, or adding 'cryptography' as a dependency."
            ) from e
    finally:
        if fd_path and os.path.exists(fd_path):
            os.unlink(fd_path)


def _flatten_name(name_tuples) -> dict:
    flat = {}
    for rdn in name_tuples:
        for key, value in rdn:
            flat[key] = value
    return flat


def _parse_cert_date(s: str) -> datetime:
    # OpenSSL format: 'Mar 17 12:00:00 2026 GMT'
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _extract_signature_algorithm(der: bytes) -> str:
    """Lightweight inspection of the cert's signature algorithm via OID lookup.

    Avoids pulling in heavy parsing libraries. Maps the few signature OIDs we
    care about; returns 'unknown' otherwise.
    """
    sig_oid_map = {
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04": "md5WithRSAEncryption",  # 1.2.840.113549.1.1.4
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": "sha1WithRSAEncryption",  # 1.2.840.113549.1.1.5
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": "sha256WithRSAEncryption",  # 1.2.840.113549.1.1.11
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": "sha384WithRSAEncryption",  # 1.2.840.113549.1.1.12
        b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": "sha512WithRSAEncryption",  # 1.2.840.113549.1.1.13
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02": "ecdsa-with-SHA256",  # 1.2.840.10045.4.3.2
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03": "ecdsa-with-SHA384",  # 1.2.840.10045.4.3.3
        b"\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04": "ecdsa-with-SHA512",  # 1.2.840.10045.4.3.4
    }
    for oid_bytes, name in sig_oid_map.items():
        if oid_bytes in der:
            return name
    return "unknown"


def host_matches_cert(host: str, common_name: str, sans: list[str]) -> bool:
    candidates = [common_name] + sans
    host_lower = host.lower()
    for c in candidates:
        if not c:
            continue
        c = c.lower()
        if c.startswith("*."):
            domain = c[2:]
            if host_lower == domain:
                continue
            if host_lower.endswith("." + domain) and host_lower.count(".") == domain.count(".") + 1:
                return True
        elif c == host_lower:
            return True
    return False


def evaluate(info: CertInfo, host: str, lang: str) -> list[Issue]:
    issues = []

    # Weak TLS versions enabled by the server
    weak_enabled = [v for v, status in info.accepted_versions.items()
                    if status == "accepted" and v in DEPRECATED_VERSIONS]
    if weak_enabled:
        t = ISSUE_TEXT["weak_tls_versions"][lang]
        label = t[0].format(", ".join(weak_enabled))
        issues.append(Issue(key="weak_tls_versions", label=label, risk=label, fix=t[1]))

    now = datetime.now(timezone.utc)
    valid_to = _parse_cert_date(info.valid_to)
    if valid_to < now:
        t = ISSUE_TEXT["expired"][lang]
        issues.append(Issue(key="expired", label=t[0], risk=t[0], fix=t[1]))
    elif (valid_to - now).days <= 30:
        t = ISSUE_TEXT["expiring_soon"][lang]
        issues.append(Issue(key="expiring_soon", label=t[0], risk=t[0], fix=t[1]))

    if info.subject == info.issuer and info.subject:
        t = ISSUE_TEXT["self_signed"][lang]
        issues.append(Issue(key="self_signed", label=t[0], risk=t[0], fix=t[1]))

    algo_lower = info.sig_algorithm.lower()
    if "md5" in algo_lower or "sha1" in algo_lower:
        t = ISSUE_TEXT["weak_sig"][lang]
        issues.append(Issue(key="weak_sig", label=t[0].format(info.sig_algorithm),
                             risk=t[0].format(info.sig_algorithm), fix=t[1]))

    for san in info.sans:
        if san.startswith("*.") and san.count(".") <= 1:
            t = ISSUE_TEXT["wildcard_too_broad"][lang]
            issues.append(Issue(key="wildcard_too_broad", label=t[0].format(san),
                                 risk=t[0].format(san), fix=t[1]))

    cn = info.subject.get("commonName", "")
    if not host_matches_cert(host, cn, info.sans):
        t = ISSUE_TEXT["host_mismatch"][lang]
        issues.append(Issue(key="host_mismatch", label=t[0].format(host),
                             risk=t[0].format(host), fix=t[1]))

    return issues


def collect(host: str, port: int, timeout: float, lang: str) -> CertInfo:
    cert, tls_version, cipher, der = fetch_cert(host, port, timeout=timeout)
    subject = _flatten_name(cert.get("subject", ()))
    issuer = _flatten_name(cert.get("issuer", ()))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    valid_from = cert.get("notBefore", "")
    valid_to = cert.get("notAfter", "")
    days_left = (_parse_cert_date(valid_to) - datetime.now(timezone.utc)).days if valid_to else 0
    sig_algo = _extract_signature_algorithm(der)

    info = CertInfo(
        target=f"{host}:{port}",
        subject=subject,
        issuer=issuer,
        valid_from=valid_from,
        valid_to=valid_to,
        days_left=days_left,
        sig_algorithm=sig_algo,
        version=cert.get("version", 0),
        serial=cert.get("serialNumber", ""),
        sans=sans,
        tls_version=tls_version,
        cipher=cipher,
    )
    # Probe each TLS version with a short timeout. Sequential is fine —
    # we're only doing 5 quick handshakes per target.
    for attr, name in TLS_VERSIONS_TO_PROBE:
        info.accepted_versions[name] = probe_tls_version(host, port, attr, timeout=min(timeout, 5.0))
    info.issues = evaluate(info, host, lang)
    return info


def print_human(info: CertInfo, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['target']}: {info.target}")
    print(f"{L['tls_version']}: {info.tls_version}    {L['cipher']}: {info.cipher}\n")

    print(f"{L['subject']}:")
    for k, v in info.subject.items():
        print(f"  {k}: {v}")
    print(f"\n{L['issuer']}:")
    for k, v in info.issuer.items():
        print(f"  {k}: {v}")

    print(f"\n{L['validity']}:")
    print(f"  {L['valid_from']}: {info.valid_from}")
    print(f"  {L['valid_to']}:   {info.valid_to}  ({info.days_left} {L['days_left']})")

    print(f"\n{L['sig_algo']}: {info.sig_algorithm}")
    print(f"{L['version']}: {info.version}    {L['serial']}: {info.serial}")

    if info.sans:
        print(f"\n{L['sans']} ({len(info.sans)}):")
        for san in info.sans[:20]:
            print(f"  - {san}")
        if len(info.sans) > 20:
            print(f"  ... ({len(info.sans) - 20} more)")

    if info.accepted_versions:
        print(f"\n{L['supported_versions']}:")
        for v, status in info.accepted_versions.items():
            if status == "accepted":
                marker = "✓" if v not in DEPRECATED_VERSIONS else "✗"
                tag = L["supported"]
            elif status == "unavailable":
                marker = "i"
                tag = L["not_tested"]
            else:
                marker = "·"
                tag = L["not_supported"]
            print(f"  {marker} {v:<8}  {tag}")

    if info.issues:
        print(f"\n{L['issues_header']} ({len(info.issues)}):")
        for iss in info.issues:
            print(f"\n  ✗ {iss.label}")
            print(f"     {L['risk_label']} {iss.risk}")
            print(f"     {L['fix_label']}{iss.fix}")
    else:
        print(f"\n{L['no_issues']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect the TLS certificate of a host.")
    add_version_arg(parser, "tls_inspect.py")
    parser.add_argument("target", help="Hostname, host:port, or full URL (default port: 443). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]
    args.target = stdin_or_arg(args.target)

    host, port = parse_host_port(args.target)
    if not host:
        print(f"error: invalid target {args.target!r}", file=sys.stderr)
        return 2

    try:
        info = collect(host, port, timeout=args.timeout, lang=args.lang)
    except socket.gaierror:
        print(f"{L['err_resolve']}: {host}", file=sys.stderr)
        return 3
    except (socket.timeout, TimeoutError):
        print(f"{L['err_timeout']} {args.timeout}s", file=sys.stderr)
        return 3
    except ConnectionRefusedError:
        print(f"{L['err_connect']}: {host}:{port}", file=sys.stderr)
        return 3
    except ssl.SSLError as e:
        print(f"{L['err_tls']}: {e}", file=sys.stderr)
        return 3
    except OSError as e:
        print(f"{L['err_connect']}: {host}:{port} — {e}", file=sys.stderr)
        return 3

    if args.json:
        out = asdict(info)
        out["lang"] = args.lang
        print(json.dumps(out, indent=2, ensure_ascii=False, default=str))
    else:
        print_human(info, args.lang)

    return 1 if info.issues else 0


if __name__ == "__main__":
    sys.exit(main())
