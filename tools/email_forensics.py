#!/usr/bin/env python3
"""Analyze email headers for forensic investigation and phishing detection.

Parses an .eml file, extracts basic headers, the Received chain, and
Authentication-Results, then flags common phishing / impersonation signals
(SPF/DKIM/DMARC failures, From/Return-Path/Reply-To mismatches, display
name impersonation, anomalous time skew in the hop chain).

Examples:
    tools/email_forensics.py phishing.eml
    tools/email_forensics.py phishing.eml --lang pt
    tools/email_forensics.py phishing.eml --json
    cat phishing.eml | tools/email_forensics.py -
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Optional

from _lib import make_user_agent, add_version_arg, stdin_or_arg

USER_AGENT = make_user_agent("email_forensics.py")

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "email_file": "Email file",
        "stdin_label": "<stdin>",
        "from": "From",
        "to": "To",
        "subject": "Subject",
        "date": "Date",
        "return_path": "Return-Path",
        "reply_to": "Reply-To",
        "message_id": "Message-ID",
        "list_unsubscribe": "List-Unsubscribe",
        "received_chain": "Received chain ({n} hops, oldest first)",
        "no_received": "(no Received headers)",
        "authentication": "Authentication",
        "spf_label": "SPF:  ",
        "dkim_label": "DKIM: ",
        "dmarc_label": "DMARC:",
        "auth_pass": "pass",
        "auth_fail": "fail",
        "auth_softfail": "softfail",
        "auth_neutral": "neutral",
        "auth_none": "none",
        "auth_missing": "(not present)",
        "issues_found": "Issues found",
        "no_issues": "No issues found.",
        "risk_high": "HIGH",
        "risk_medium": "MEDIUM",
        "risk_low": "LOW",
        "not_set": "(not set)",
        "err_file_missing": "error: file does not exist:",
        "err_read": "error: could not read email file:",
        "err_parse": "error: could not parse email:",
        "err_empty": "error: input is empty",
        "issue_spf_fail": "SPF check failed",
        "issue_dkim_fail": "DKIM signature failed",
        "issue_dmarc_fail": "DMARC verification failed",
        "issue_spf_missing": "No SPF result in Authentication-Results",
        "issue_dmarc_missing": "No DMARC result in Authentication-Results",
        "issue_from_returnpath": "From domain ({a}) differs from Return-Path domain ({b})",
        "issue_from_replyto": "From domain ({a}) differs from Reply-To domain ({b})",
        "issue_display_impersonation": "Display name impersonates {brand} but sender domain is {domain}",
        "issue_time_skew": "Anomalous timestamp in Received chain (hop {n} is older than the next hop)",
        "issue_no_received": "Email has no Received headers (suspicious)",
    },
    "pt": {
        "email_file": "Ficheiro do email",
        "stdin_label": "<stdin>",
        "from": "From",
        "to": "To",
        "subject": "Assunto",
        "date": "Data",
        "return_path": "Return-Path",
        "reply_to": "Reply-To",
        "message_id": "Message-ID",
        "list_unsubscribe": "List-Unsubscribe",
        "received_chain": "Cadeia Received ({n} saltos, do mais antigo)",
        "no_received": "(sem headers Received)",
        "authentication": "Autenticação",
        "spf_label": "SPF:  ",
        "dkim_label": "DKIM: ",
        "dmarc_label": "DMARC:",
        "auth_pass": "pass",
        "auth_fail": "fail",
        "auth_softfail": "softfail",
        "auth_neutral": "neutral",
        "auth_none": "none",
        "auth_missing": "(ausente)",
        "issues_found": "Problemas encontrados",
        "no_issues": "Nenhum problema encontrado.",
        "risk_high": "HIGH",
        "risk_medium": "MEDIUM",
        "risk_low": "LOW",
        "not_set": "(não definido)",
        "err_file_missing": "erro: o ficheiro não existe:",
        "err_read": "erro: não foi possível ler o ficheiro de email:",
        "err_parse": "erro: não foi possível fazer parse do email:",
        "err_empty": "erro: entrada vazia",
        "issue_spf_fail": "Verificação SPF falhou",
        "issue_dkim_fail": "Assinatura DKIM falhou",
        "issue_dmarc_fail": "Verificação DMARC falhou",
        "issue_spf_missing": "Sem resultado SPF nos Authentication-Results",
        "issue_dmarc_missing": "Sem resultado DMARC nos Authentication-Results",
        "issue_from_returnpath": "Domínio do From ({a}) difere do domínio do Return-Path ({b})",
        "issue_from_replyto": "Domínio do From ({a}) difere do domínio do Reply-To ({b})",
        "issue_display_impersonation": "Display name passa-se por {brand} mas o domínio do remetente é {domain}",
        "issue_time_skew": "Timestamp anómalo na cadeia Received (salto {n} é anterior ao seguinte)",
        "issue_no_received": "Email sem headers Received (suspeito)",
    },
}

RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"

SYMBOL = {RISK_HIGH: "✗", RISK_MEDIUM: "!", RISK_LOW: "i"}

COMMON_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.pt"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com"],
    "spotify": ["spotify.com"],
}


@dataclass
class ReceivedHop:
    from_server: Optional[str]
    by_server: Optional[str]
    timestamp: Optional[str]
    ip: Optional[str]


@dataclass
class Issue:
    key: str
    risk: str
    message: str


@dataclass
class AuthResults:
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    raw: list[str] = field(default_factory=list)


@dataclass
class EmailReport:
    headers: dict
    received_chain: list[ReceivedHop]
    auth_results: AuthResults
    issues: list[Issue] = field(default_factory=list)


def _extract_domain(addr_value: Optional[str]) -> Optional[str]:
    if not addr_value:
        return None
    _, addr = parseaddr(addr_value)
    if "@" not in addr:
        return None
    return addr.rsplit("@", 1)[1].strip().lower().strip(">").strip()


def _extract_display_name(addr_value: Optional[str]) -> Optional[str]:
    if not addr_value:
        return None
    name, _ = parseaddr(addr_value)
    return name.strip() if name else None


def parse_received(raw: str) -> ReceivedHop:
    """Parse a single Received: header.

    Received headers are notoriously irregular. We extract the easy bits
    (from, by, IP literal, trailing date) with permissive regex and leave
    the rest as None — good enough for a forensic overview.
    """
    text = " ".join(raw.split())

    from_match = re.search(r"\bfrom\s+([^\s\(\);]+)", text, re.I)
    from_server = from_match.group(1) if from_match else None

    by_match = re.search(r"\bby\s+([^\s\(\);]+)", text, re.I)
    by_server = by_match.group(1) if by_match else None

    ip_match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", text)
    ip = ip_match.group(1) if ip_match else None

    timestamp = None
    if ";" in text:
        date_part = text.rsplit(";", 1)[1].strip()
        try:
            dt = parsedate_to_datetime(date_part)
            if dt is not None:
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
        except (TypeError, ValueError):
            timestamp = date_part if date_part else None

    return ReceivedHop(from_server=from_server, by_server=by_server, timestamp=timestamp, ip=ip)


def parse_auth_results(msg) -> AuthResults:
    """Pick the first (closest to recipient) Authentication-Results header.

    Some providers emit multiple Authentication-Results headers as the
    message traverses internal infrastructure. The first one returned by
    `get_all` is the one nearest the recipient (top of the file), which
    is what we want for verdict purposes.
    """
    all_ar = msg.get_all("Authentication-Results") or []
    ar = AuthResults(raw=[str(x) for x in all_ar])
    if not all_ar:
        return ar
    primary = str(all_ar[0]).lower()
    spf_m = re.search(r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", primary)
    if spf_m:
        ar.spf = spf_m.group(1)
    dkim_m = re.search(r"\bdkim\s*=\s*(pass|fail|none|permerror|temperror|neutral|policy)\b", primary)
    if dkim_m:
        ar.dkim = dkim_m.group(1)
    dmarc_m = re.search(r"\bdmarc\s*=\s*(pass|fail|none|permerror|temperror)\b", primary)
    if dmarc_m:
        ar.dmarc = dmarc_m.group(1)
    return ar


def _parse_hop_dt(hop: ReceivedHop):
    if not hop.timestamp:
        return None
    try:
        return datetime.strptime(hop.timestamp.strip(), "%Y-%m-%d %H:%M:%S %Z")
    except ValueError:
        try:
            return datetime.strptime(hop.timestamp.strip().rstrip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None


def evaluate(report: EmailReport, lang: str) -> list[Issue]:
    L = LABELS[lang]
    issues: list[Issue] = []
    h = report.headers
    ar = report.auth_results

    if ar.spf == "fail":
        issues.append(Issue("spf_fail", RISK_HIGH, L["issue_spf_fail"]))
    if ar.dkim == "fail":
        issues.append(Issue("dkim_fail", RISK_HIGH, L["issue_dkim_fail"]))
    if ar.dmarc == "fail":
        issues.append(Issue("dmarc_fail", RISK_HIGH, L["issue_dmarc_fail"]))
    if ar.spf is None:
        issues.append(Issue("spf_missing", RISK_MEDIUM, L["issue_spf_missing"]))
    if ar.dmarc is None:
        issues.append(Issue("dmarc_missing", RISK_MEDIUM, L["issue_dmarc_missing"]))

    from_domain = _extract_domain(h.get("From"))
    return_path_domain = _extract_domain(h.get("Return-Path"))
    reply_to_domain = _extract_domain(h.get("Reply-To"))

    if from_domain and return_path_domain and from_domain != return_path_domain:
        issues.append(Issue(
            "from_returnpath_mismatch", RISK_MEDIUM,
            L["issue_from_returnpath"].format(a=from_domain, b=return_path_domain),
        ))
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        issues.append(Issue(
            "from_replyto_mismatch", RISK_MEDIUM,
            L["issue_from_replyto"].format(a=from_domain, b=reply_to_domain),
        ))

    display_name = _extract_display_name(h.get("From"))
    if display_name and from_domain:
        dn_lower = display_name.lower()
        embedded_addrs = [a for _, a in getaddresses([display_name]) if "@" in a]
        embedded_domains = {a.rsplit("@", 1)[1].lower() for a in embedded_addrs}

        for brand, brand_domains in COMMON_BRANDS.items():
            if brand in dn_lower:
                if not any(from_domain == bd or from_domain.endswith("." + bd) for bd in brand_domains):
                    issues.append(Issue(
                        "display_name_impersonation", RISK_HIGH,
                        L["issue_display_impersonation"].format(brand=brand.capitalize(), domain=from_domain),
                    ))
                    break
        else:
            for emb in embedded_domains:
                if emb != from_domain and not from_domain.endswith("." + emb) and not emb.endswith("." + from_domain):
                    issues.append(Issue(
                        "display_name_impersonation", RISK_HIGH,
                        L["issue_display_impersonation"].format(brand=emb, domain=from_domain),
                    ))
                    break

    if not report.received_chain:
        issues.append(Issue("no_received_headers", RISK_MEDIUM, L["issue_no_received"]))
    else:
        for i in range(len(report.received_chain) - 1):
            current = _parse_hop_dt(report.received_chain[i])
            nxt = _parse_hop_dt(report.received_chain[i + 1])
            if current and nxt and current > nxt:
                issues.append(Issue(
                    "time_skew", RISK_LOW,
                    L["issue_time_skew"].format(n=i + 1),
                ))
                break

    return issues


def build_report(msg) -> EmailReport:
    header_keys = (
        "From", "To", "Subject", "Date", "Message-ID",
        "Return-Path", "Reply-To", "List-Unsubscribe",
    )
    headers = {}
    for k in header_keys:
        v = msg.get(k)
        headers[k] = str(v) if v is not None else None

    received_raw = msg.get_all("Received") or []
    # Received headers are prepended at each hop, so the first one is the
    # most recent. Reverse to get oldest-first chronology for display.
    hops = [parse_received(str(r)) for r in received_raw]
    hops.reverse()

    auth = parse_auth_results(msg)

    return EmailReport(headers=headers, received_chain=hops, auth_results=auth)


def _auth_glyph(state: Optional[str]) -> str:
    if state is None:
        return " "
    if state == "pass":
        return "✓"
    if state in ("fail", "softfail"):
        return "✗"
    return "!"


def print_human(report: EmailReport, source_label: str, lang: str) -> None:
    L = LABELS[lang]
    h = report.headers

    print()
    print(f"{L['email_file']}: {source_label}")
    print(f"{L['from']+':':<13} {h.get('From') or L['not_set']}")
    print(f"{L['to']+':':<13} {h.get('To') or L['not_set']}")
    print(f"{L['subject']+':':<13} {h.get('Subject') or L['not_set']}")
    print(f"{L['date']+':':<13} {h.get('Date') or L['not_set']}")
    print(f"{L['return_path']+':':<13} {h.get('Return-Path') or L['not_set']}")
    print(f"{L['reply_to']+':':<13} {h.get('Reply-To') or L['not_set']}")
    print(f"{L['message_id']+':':<13} {h.get('Message-ID') or L['not_set']}")
    if h.get("List-Unsubscribe"):
        print(f"{L['list_unsubscribe']+':':<13} {h['List-Unsubscribe']}")

    print()
    if report.received_chain:
        print(L["received_chain"].format(n=len(report.received_chain)) + ":")
        for i, hop in enumerate(report.received_chain, start=1):
            src = hop.from_server or "?"
            if hop.ip:
                src = f"{src} [{hop.ip}]"
            dst = hop.by_server or "?"
            print(f"  {i}. {src}")
            print(f"     → {dst}")
            if hop.timestamp:
                print(f"     {hop.timestamp}")
    else:
        print(L["no_received"])

    print()
    print(L["authentication"] + ":")
    ar = report.auth_results
    for label, value in (
        (L["spf_label"], ar.spf),
        (L["dkim_label"], ar.dkim),
        (L["dmarc_label"], ar.dmarc),
    ):
        glyph = _auth_glyph(value)
        shown = value if value is not None else L["auth_missing"]
        print(f"  {glyph} {label} {shown}")

    print()
    if report.issues:
        print(f"{L['issues_found']} ({len(report.issues)}):")
        risk_word = {
            RISK_HIGH: L["risk_high"],
            RISK_MEDIUM: L["risk_medium"],
            RISK_LOW: L["risk_low"],
        }
        for iss in report.issues:
            sym = SYMBOL[iss.risk]
            print(f"  {sym} [{risk_word[iss.risk]:<6}] {iss.message}")
    else:
        print(L["no_issues"])
    print()


def read_email_bytes(path: str, lang: str) -> bytes:
    L = LABELS[lang]
    if path == "-":
        try:
            data = sys.stdin.buffer.read()
        except OSError as e:
            print(f"{L['err_read']} {e}", file=sys.stderr)
            raise SystemExit(2)
        if not data:
            print(L["err_empty"], file=sys.stderr)
            raise SystemExit(2)
        return data
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"{L['err_file_missing']} {path}", file=sys.stderr)
        raise SystemExit(2)
    except OSError as e:
        print(f"{L['err_read']} {e}", file=sys.stderr)
        raise SystemExit(2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze email headers for forensic investigation and phishing detection.",
    )
    add_version_arg(parser, "email_forensics.py")
    parser.add_argument("email_file", help="Path to an .eml file; use '-' for stdin")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    L = LABELS[args.lang]

    args.email_file = stdin_or_arg(args.email_file) if args.email_file != "-" else "-"

    raw = read_email_bytes(args.email_file, args.lang)

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as e:
        print(f"{L['err_parse']} {e}", file=sys.stderr)
        return 2

    report = build_report(msg)
    report.issues = evaluate(report, args.lang)

    source_label = L["stdin_label"] if args.email_file == "-" else args.email_file

    if args.json:
        out = {
            "source": source_label,
            "lang": args.lang,
            "headers": report.headers,
            "received_chain": [asdict(h) for h in report.received_chain],
            "auth_results": {
                "spf": report.auth_results.spf,
                "dkim": report.auth_results.dkim,
                "dmarc": report.auth_results.dmarc,
                "raw": report.auth_results.raw,
            },
            "issues": [asdict(i) for i in report.issues],
            "issues_count": len(report.issues),
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(report, source_label, args.lang)

    return 1 if report.issues else 0


if __name__ == "__main__":
    sys.exit(main())
