#!/usr/bin/env python3
"""Query WHOIS for a domain and extract key fields.

WHOIS runs over plain TCP on port 43. There's no standard format for
the response — every registrar/TLD does it differently — so the parser
is conservative: grabs common keys via flexible regex and presents them
as best-effort. Warns when the domain expires soon.

Examples:
    tools/whois_check.py example.com
    tools/whois_check.py example.com --lang pt
    tools/whois_check.py example.com --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from _lib import add_version_arg, stdin_or_arg

LANGS = ("en", "pt")
WHOIS_IANA = "whois.iana.org"
PORT = 43

LABELS = {
    "en": {
        "domain": "Domain",
        "tld_server": "TLD WHOIS server",
        "registrar": "Registrar",
        "created": "Created",
        "updated": "Updated",
        "expires": "Expires",
        "name_servers": "Name servers",
        "status": "Domain status",
        "dnssec": "DNSSEC",
        "days_until_expiry": "days until expiry",
        "issues_header": "Issues found",
        "no_issues": "No issues — registration looks healthy.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "err_domain": "error: invalid domain",
        "err_query": "error: WHOIS query failed",
    },
    "pt": {
        "domain": "Domínio",
        "tld_server": "Servidor WHOIS do TLD",
        "registrar": "Registrar",
        "created": "Criado",
        "updated": "Atualizado",
        "expires": "Expira",
        "name_servers": "Name servers",
        "status": "Estado do domínio",
        "dnssec": "DNSSEC",
        "days_until_expiry": "dias até expirar",
        "issues_header": "Problemas encontrados",
        "no_issues": "Sem problemas — o registo parece saudável.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "err_domain": "erro: domínio inválido",
        "err_query": "erro: consulta WHOIS falhou",
    },
}

ISSUE_TEXT = {
    "expired": {
        "en": ("Domain has expired ({} days ago)",
               "Renew immediately. An expired domain can be picked up by a squatter or attacker."),
        "pt": ("Domínio expirou (há {} dias)",
               "Renova imediatamente. Um domínio expirado pode ser apanhado por um squatter ou atacante."),
    },
    "expiring_soon": {
        "en": ("Domain expires in {} days",
               "Schedule renewal. Drops are routinely scraped by domain-hijack actors."),
        "pt": ("Domínio expira em {} dias",
               "Agenda a renovação. Drops são rotineiramente vigiados por agentes de domain-hijack."),
    },
    "no_dnssec": {
        "en": ("DNSSEC is unsigned",
               "Sign the zone — DNSSEC prevents cache poisoning attacks (KSK + ZSK at the registrar/registry)."),
        "pt": ("DNSSEC não está assinado",
               "Assina a zona — DNSSEC previne ataques de cache poisoning (KSK + ZSK no registrar/registry)."),
    },
}


@dataclass
class WhoisInfo:
    domain: str
    tld_server: str
    registrar: Optional[str] = None
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    days_until_expiry: Optional[int] = None
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    raw_size: int = 0


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


def whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    """Open TCP/43 to `server`, send `query\\r\\n`, read until close."""
    sock = socket.create_connection((server, PORT), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall((query + "\r\n").encode("ascii", errors="replace"))
        chunks = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) > 200_000:
                break
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        sock.close()


def find_tld_server(domain: str, timeout: float) -> str:
    """Ask whois.iana.org which WHOIS server is responsible for the TLD."""
    response = whois_query(WHOIS_IANA, domain, timeout=timeout)
    m = re.search(r"^\s*whois:\s*(\S+)", response, re.IGNORECASE | re.MULTILINE)
    if m:
        return m.group(1)
    # Fallback: try whois.verisign-grs.com for .com/.net
    tld = domain.rsplit(".", 1)[-1].lower()
    fallback = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.publicinterestregistry.org",
        "io": "whois.nic.io",
        "pt": "whois.dns.pt",
    }
    return fallback.get(tld, WHOIS_IANA)


def parse_whois(text: str, domain: str, tld_server: str) -> WhoisInfo:
    info = WhoisInfo(domain=domain, tld_server=tld_server, raw_size=len(text))

    # Each TLD uses different field names. We try a few synonyms.
    patterns = {
        "registrar": (r"^\s*Registrar:\s*(.+)$", r"^\s*Sponsoring Registrar:\s*(.+)$",
                      r"^\s*Registrar Name:\s*(.+)$"),
        "created": (r"^\s*Creation Date:\s*(.+)$", r"^\s*Created:\s*(.+)$",
                    r"^\s*Created On:\s*(.+)$", r"^\s*Registered on:\s*(.+)$",
                    r"^\s*Registration Date:\s*(.+)$"),
        "updated": (r"^\s*Updated Date:\s*(.+)$", r"^\s*Last Updated:\s*(.+)$",
                    r"^\s*Updated:\s*(.+)$"),
        "expires": (r"^\s*Registry Expiry Date:\s*(.+)$", r"^\s*Registrar Registration Expiration Date:\s*(.+)$",
                    r"^\s*Expiration Date:\s*(.+)$", r"^\s*Expiry Date:\s*(.+)$",
                    r"^\s*Expires:\s*(.+)$", r"^\s*Expires On:\s*(.+)$"),
        "dnssec": (r"^\s*DNSSEC:\s*(.+)$",),
    }
    for field_name, regexes in patterns.items():
        for rx in regexes:
            m = re.search(rx, text, re.IGNORECASE | re.MULTILINE)
            if m:
                setattr(info, field_name, m.group(1).strip())
                break

    # Name servers — there can be many
    info.name_servers = sorted({
        m.group(1).strip().lower()
        for m in re.finditer(r"^\s*Name Server:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
    } | {
        m.group(1).strip().lower()
        for m in re.finditer(r"^\s*nserver:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
    })

    # Domain status
    info.status = [
        m.group(1).strip()
        for m in re.finditer(r"^\s*(?:Domain )?Status:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    ]

    # Days until expiry
    if info.expires:
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
            "%d-%b-%Y", "%d.%m.%Y",
        ):
            try:
                dt = datetime.strptime(info.expires.split(" #")[0].strip(), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                info.days_until_expiry = (dt - datetime.now(timezone.utc)).days
                break
            except ValueError:
                continue
    return info


def evaluate(info: WhoisInfo, lang: str) -> list[Issue]:
    issues = []
    if info.days_until_expiry is not None:
        if info.days_until_expiry < 0:
            t = ISSUE_TEXT["expired"][lang]
            label = t[0].format(-info.days_until_expiry)
            issues.append(Issue("expired", label, label, t[1]))
        elif info.days_until_expiry <= 30:
            t = ISSUE_TEXT["expiring_soon"][lang]
            label = t[0].format(info.days_until_expiry)
            issues.append(Issue("expiring_soon", label, label, t[1]))
    if info.dnssec and re.search(r"unsigned|no", info.dnssec, re.IGNORECASE):
        t = ISSUE_TEXT["no_dnssec"][lang]
        issues.append(Issue("no_dnssec", t[0], t[0], t[1]))
    return issues


def print_human(info: WhoisInfo, issues: list[Issue], lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['domain']}: {info.domain}")
    print(f"{L['tld_server']}: {info.tld_server}\n")
    if info.registrar:
        print(f"  {L['registrar']}:    {info.registrar}")
    if info.created:
        print(f"  {L['created']}:      {info.created}")
    if info.updated:
        print(f"  {L['updated']}:      {info.updated}")
    if info.expires:
        days = f"  ({info.days_until_expiry} {L['days_until_expiry']})" if info.days_until_expiry is not None else ""
        print(f"  {L['expires']}:      {info.expires}{days}")
    if info.dnssec:
        print(f"  {L['dnssec']}:       {info.dnssec}")
    if info.name_servers:
        print(f"\n  {L['name_servers']}:")
        for ns in info.name_servers:
            print(f"    - {ns}")
    if info.status:
        print(f"\n  {L['status']}:")
        for s in info.status[:10]:
            print(f"    - {s}")
        if len(info.status) > 10:
            print(f"    ... ({len(info.status) - 10} more)")

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
    parser = argparse.ArgumentParser(description="WHOIS lookup with parsed output.")
    add_version_arg(parser, "whois_check.py")
    parser.add_argument("domain", help="Domain to query. Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]

    domain = stdin_or_arg(args.domain).strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", domain):
        print(f"{L['err_domain']}: {domain!r}", file=sys.stderr)
        return 2

    try:
        tld_server = find_tld_server(domain, timeout=args.timeout)
        response = whois_query(tld_server, domain, timeout=args.timeout)
        # Some registries redirect to a registrar-specific server.
        m = re.search(r"^\s*(?:Registrar WHOIS Server|whois):\s*(\S+)",
                      response, re.IGNORECASE | re.MULTILINE)
        if m and m.group(1).lower() != tld_server.lower():
            try:
                response = whois_query(m.group(1), domain, timeout=args.timeout)
                tld_server = m.group(1)
            except (socket.timeout, OSError):
                pass  # fall back to the TLD server's response
    except (socket.timeout, OSError, ConnectionRefusedError) as e:
        print(f"{L['err_query']}: {e}", file=sys.stderr)
        return 3

    info = parse_whois(response, domain, tld_server)
    issues = evaluate(info, args.lang)

    if args.json:
        out = asdict(info)
        out["lang"] = args.lang
        out["issues"] = [asdict(i) for i in issues]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(info, issues, args.lang)

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
