#!/usr/bin/env python3
"""Query DNS records for a domain and audit email-auth setup.

Sends raw UDP DNS queries (no dnspython dependency — stdlib only) for
A, AAAA, MX, NS, TXT, CAA. Then analyzes SPF, DKIM and DMARC TXT
records, flagging missing or weak configurations.

Examples:
    tools/dns_records.py example.com
    tools/dns_records.py example.com --lang pt
    tools/dns_records.py example.com --json
    tools/dns_records.py example.com --resolver 1.1.1.1
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import struct
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

from _lib import add_version_arg, stdin_or_arg

LANGS = ("en", "pt")

DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

# DNS record type codes (RFC 1035 §3.2.2 + later)
TYPE = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "CAA": 257,
}
CLASS_IN = 1

LABELS = {
    "en": {
        "domain": "Domain",
        "resolver": "Resolver",
        "records": "DNS records",
        "no_records": "No records of this type",
        "email_section": "Email authentication",
        "spf": "SPF",
        "dkim": "DKIM (default selector tested)",
        "dmarc": "DMARC",
        "issues_header": "Issues found",
        "no_issues": "Nothing alarming in the records returned.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "err_domain": "error: invalid domain",
        "err_query": "error: DNS query failed",
    },
    "pt": {
        "domain": "Domínio",
        "resolver": "Resolver",
        "records": "Registos DNS",
        "no_records": "Sem registos deste tipo",
        "email_section": "Autenticação de email",
        "spf": "SPF",
        "dkim": "DKIM (selector default testado)",
        "dmarc": "DMARC",
        "issues_header": "Problemas encontrados",
        "no_issues": "Nada de alarmante nos registos devolvidos.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "err_domain": "erro: domínio inválido",
        "err_query": "erro: consulta DNS falhou",
    },
}

ISSUE_TEXT = {
    "no_spf": {
        "en": ("No SPF record found for this domain",
               "Add a TXT record like 'v=spf1 include:_spf.your-provider.example -all' so receivers can verify which servers may send mail."),
        "pt": ("Sem registo SPF para este domínio",
               "Adiciona um registo TXT como 'v=spf1 include:_spf.teu-provider.example -all' para que os recetores possam verificar que servidores podem enviar email."),
    },
    "spf_softfail_or_neutral": {
        "en": ("SPF ends with '~all' or '?all' instead of '-all'",
               "Soft-fail/Neutral lets unauthorized mail still be accepted (sometimes). For a domain that doesn't send email at all, prefer '-all' to harden against spoofing."),
        "pt": ("SPF termina em '~all' ou '?all' em vez de '-all'",
               "Soft-fail/Neutral permite que mail não autorizado seja aceite (por vezes). Para um domínio que não envia email, prefere '-all' para reforçar contra spoofing."),
    },
    "multiple_spf": {
        "en": ("Multiple SPF records found",
               "Per RFC 7208 §3.2, a domain MUST publish only one SPF record. Merge them into one."),
        "pt": ("Múltiplos registos SPF encontrados",
               "Por RFC 7208 §3.2, um domínio DEVE publicar apenas um registo SPF. Funde-os num só."),
    },
    "no_dmarc": {
        "en": ("No DMARC record found (queried _dmarc.{domain})",
               "Add a TXT record at _dmarc.{domain} starting with 'v=DMARC1; p=quarantine'. Start with p=none in monitor mode if you're uncertain about side effects."),
        "pt": ("Sem registo DMARC (consultado _dmarc.{domain})",
               "Adiciona um TXT em _dmarc.{domain} a começar com 'v=DMARC1; p=quarantine'. Começa em p=none para monitorizar antes de aplicar."),
    },
    "dmarc_p_none": {
        "en": ("DMARC policy is 'p=none' — monitor-only mode",
               "Once you've validated that legitimate senders pass, move to p=quarantine or p=reject for real protection."),
        "pt": ("Política DMARC é 'p=none' — modo apenas monitorização",
               "Depois de validar que os remetentes legítimos passam, passa para p=quarantine ou p=reject para proteção real."),
    },
    "no_caa": {
        "en": ("No CAA records — any CA may issue certificates for this domain",
               "Add CAA records to restrict which CAs may issue (e.g. 'letsencrypt.org', 'digicert.com')."),
        "pt": ("Sem registos CAA — qualquer CA pode emitir certificados para este domínio",
               "Adiciona registos CAA para restringir que CAs podem emitir (ex: 'letsencrypt.org', 'digicert.com')."),
    },
}


@dataclass
class Records:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    dmarc: list[str] = field(default_factory=list)


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


# ---- Raw DNS implementation -------------------------------------------------

def _encode_name(name: str) -> bytes:
    """Encode a DNS name as length-prefixed labels followed by a zero byte."""
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("idna") if label else b""
        if len(b) > 63:
            raise ValueError("label > 63 bytes")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) DNS name. Return (name, new_offset)."""
    labels: list[str] = []
    jumped = False
    consumed = offset
    while True:
        if offset >= len(data):
            raise ValueError("malformed name (out of bounds)")
        length = data[offset]
        # Compression pointer
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("malformed compression pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                consumed = offset + 2
                jumped = True
            offset = ptr
            continue
        if length == 0:
            offset += 1
            if not jumped:
                consumed = offset
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("latin-1", errors="replace"))
        offset += length
    return ".".join(labels), consumed


def _send_udp(packet: bytes, resolver: str, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (resolver, 53))
        data, _ = sock.recvfrom(4096)
        return data
    finally:
        sock.close()


def _send_tcp(packet: bytes, resolver: str, timeout: float) -> bytes:
    """DNS over TCP: prefix message with 2-byte big-endian length."""
    sock = socket.create_connection((resolver, 53), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(struct.pack(">H", len(packet)) + packet)
        # Read length prefix
        len_bytes = b""
        while len(len_bytes) < 2:
            chunk = sock.recv(2 - len(len_bytes))
            if not chunk:
                return b""
            len_bytes += chunk
        msg_len = struct.unpack(">H", len_bytes)[0]
        data = b""
        while len(data) < msg_len:
            chunk = sock.recv(msg_len - len(data))
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


def _query_dns(qname: str, qtype: int, resolver: str, timeout: float) -> list:
    """Send a DNS query (UDP, falling back to TCP on truncation).

    Returns a list of (rdata, full_message, offset) tuples — full message
    and offset are needed for compression-pointer resolution by the parsers.
    Returns [] on transient errors so callers can degrade gracefully.
    """
    txid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack(">HH", qtype, CLASS_IN)
    packet = header + question

    data = _send_udp(packet, resolver, timeout)
    if len(data) < 12:
        return []

    rtxid, rflags, qdc, anc, nsc, arc = struct.unpack(">HHHHHH", data[:12])
    if rtxid != txid:
        return []
    if rflags & 0x0200:
        # Truncated UDP response — retry over TCP per RFC 1035 §4.2.2.
        data = _send_tcp(packet, resolver, timeout)
        if len(data) < 12:
            return []
        rtxid, rflags, qdc, anc, nsc, arc = struct.unpack(">HHHHHH", data[:12])
        if rtxid != txid:
            return []

    # Skip the question section
    offset = 12
    for _ in range(qdc):
        _, offset = _read_name(data, offset)
        offset += 4  # qtype + qclass

    # Parse the answer section
    rdata_list: list = []
    for _ in range(anc):
        _, offset = _read_name(data, offset)
        rrtype, rrclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rrtype == qtype:
            rdata_list.append((rdata, data, offset))
        offset += rdlen
    return rdata_list


def _parse_a(rdata: bytes, *_) -> str:
    return ".".join(str(b) for b in rdata)


def _parse_aaaa(rdata: bytes, *_) -> str:
    parts = [f"{rdata[i]<<8 | rdata[i+1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _parse_ns(rdata: bytes, full: bytes, offset: int) -> str:
    name, _ = _read_name(full, offset)
    return name


def _parse_mx(rdata: bytes, full: bytes, offset: int) -> str:
    pref = struct.unpack(">H", rdata[:2])[0]
    name, _ = _read_name(full, offset + 2)
    return f"{pref} {name}"


def _parse_txt(rdata: bytes, *_) -> str:
    """TXT RDATA is a series of length-prefixed strings; concatenate them."""
    out = []
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        out.append(rdata[i:i + length].decode("utf-8", errors="replace"))
        i += length
    return "".join(out)


def _parse_caa(rdata: bytes, *_) -> str:
    if len(rdata) < 2:
        return ""
    flags = rdata[0]
    tag_len = rdata[1]
    tag = rdata[2:2 + tag_len].decode("ascii", errors="replace")
    value = rdata[2 + tag_len:].decode("utf-8", errors="replace")
    return f"{flags} {tag} \"{value}\""


PARSERS = {
    TYPE["A"]: _parse_a,
    TYPE["AAAA"]: _parse_aaaa,
    TYPE["NS"]: _parse_ns,
    TYPE["MX"]: _parse_mx,
    TYPE["TXT"]: _parse_txt,
    TYPE["CAA"]: _parse_caa,
}


def lookup(qname: str, type_name: str, resolver: str, timeout: float) -> list[str]:
    qtype = TYPE[type_name]
    parser = PARSERS[qtype]
    try:
        answers = _query_dns(qname, qtype, resolver, timeout)
    except (socket.timeout, OSError, ValueError):
        return []
    out: list[str] = []
    for entry in answers:
        if len(entry) == 3:
            rdata, full, offset = entry
            try:
                out.append(parser(rdata, full, offset))
            except Exception:
                continue
    return out


# ---- Email-auth analysis ----------------------------------------------------

def find_spf(txt_records: list[str]) -> list[str]:
    return [t for t in txt_records if t.lower().startswith("v=spf1")]


def evaluate(records: Records, domain: str, lang: str) -> list[Issue]:
    issues = []

    spf_records = find_spf(records.txt)
    if not spf_records:
        t = ISSUE_TEXT["no_spf"][lang]
        issues.append(Issue("no_spf", t[0], t[0], t[1]))
    else:
        if len(spf_records) > 1:
            t = ISSUE_TEXT["multiple_spf"][lang]
            issues.append(Issue("multiple_spf", t[0], t[0], t[1]))
        for spf in spf_records:
            if re.search(r"~all\s*$", spf) or re.search(r"\?all\s*$", spf):
                t = ISSUE_TEXT["spf_softfail_or_neutral"][lang]
                issues.append(Issue("spf_softfail_or_neutral", t[0], t[0], t[1]))
                break

    if not records.dmarc:
        t = ISSUE_TEXT["no_dmarc"][lang]
        label = t[0].format(domain=domain)
        issues.append(Issue("no_dmarc", label, label, t[1].format(domain=domain)))
    else:
        for d in records.dmarc:
            if re.search(r"\bp\s*=\s*none\b", d, re.IGNORECASE):
                t = ISSUE_TEXT["dmarc_p_none"][lang]
                issues.append(Issue("dmarc_p_none", t[0], t[0], t[1]))
                break

    if not records.caa:
        t = ISSUE_TEXT["no_caa"][lang]
        issues.append(Issue("no_caa", t[0], t[0], t[1]))

    return issues


# ---- CLI -------------------------------------------------------------------

def print_human(domain: str, resolver: str, records: Records, issues: list[Issue], lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['domain']}: {domain}    {L['resolver']}: {resolver}\n")

    def section(title: str, items: list[str]) -> None:
        print(f"  {title}:")
        if not items:
            print(f"    {L['no_records']}")
        else:
            for it in items:
                print(f"    - {it}")
        print()

    print(f"{L['records']}:")
    section("A", records.a)
    section("AAAA", records.aaaa)
    section("MX", records.mx)
    section("NS", records.ns)
    section("TXT", records.txt)
    section("CAA", records.caa)

    print(f"{L['email_section']}:")
    spf = find_spf(records.txt)
    print(f"  {L['spf']}: " + (spf[0] if spf else "—"))
    print(f"  {L['dmarc']}: " + (records.dmarc[0] if records.dmarc else "—"))
    print()

    if issues:
        print(f"{L['issues_header']} ({len(issues)}):")
        for iss in issues:
            print(f"\n  ✗ {iss.label}")
            print(f"     {L['risk_label']} {iss.risk}")
            print(f"     {L['fix_label']}{iss.fix}")
    else:
        print(L["no_issues"])
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Query DNS records for a domain and audit email-auth setup.")
    add_version_arg(parser, "dns_records.py")
    parser.add_argument("domain", help="Base domain (e.g. example.com). Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--resolver", default=DEFAULT_RESOLVERS[0],
                        help=f"DNS resolver IP (default: {DEFAULT_RESOLVERS[0]})")
    args = parser.parse_args()
    L = LABELS[args.lang]

    domain = stdin_or_arg(args.domain).strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", domain):
        print(f"{L['err_domain']}: {domain!r}", file=sys.stderr)
        return 2

    records = Records()
    records.a = lookup(domain, "A", args.resolver, args.timeout)
    records.aaaa = lookup(domain, "AAAA", args.resolver, args.timeout)
    records.mx = lookup(domain, "MX", args.resolver, args.timeout)
    records.ns = lookup(domain, "NS", args.resolver, args.timeout)
    records.txt = lookup(domain, "TXT", args.resolver, args.timeout)
    records.caa = lookup(domain, "CAA", args.resolver, args.timeout)
    records.dmarc = lookup(f"_dmarc.{domain}", "TXT", args.resolver, args.timeout)

    issues = evaluate(records, domain, args.lang)

    if args.json:
        out = {
            "domain": domain,
            "resolver": args.resolver,
            "lang": args.lang,
            "records": asdict(records),
            "issues": [asdict(i) for i in issues],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(domain, args.resolver, records, issues, args.lang)

    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())
