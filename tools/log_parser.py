#!/usr/bin/env python3
"""Parse log files and extract / normalize indicators (IPs, emails, URLs, timestamps).

Detects suspicious patterns: brute-force attempts (many 4xx from same IP),
scanners (one IP hitting many distinct paths), and hits on sensitive paths
(.env, .git, admin panels, etc.). Reads Apache/Nginx access logs, syslog,
JSON logs (CloudWatch, GCP, Docker, ECS), or any free-form text.

Examples:
    tools/log_parser.py access.log
    tools/log_parser.py access.log --top 20 --bruteforce 25
    tools/log_parser.py - < /var/log/nginx/access.log
    tools/log_parser.py cloudwatch.json --lang pt --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from _lib import add_version_arg, stdin_or_arg

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "log": "Log",
        "lines_parsed": "Lines parsed",
        "lines_with_ts": "Lines with timestamps",
        "date_range": "date range",
        "ips_top": "IPs (top {n})",
        "emails_top": "Emails extracted (top {n})",
        "urls_top": "URLs / paths (top {n})",
        "domains_top": "Domains (top {n})",
        "status_codes": "Status codes",
        "suspicious_patterns": "Suspicious patterns",
        "no_suspicious": "No suspicious patterns detected.",
        "private": "private",
        "public": "public",
        "loopback": "loopback",
        "linklocal": "link-local",
        "sensitive": "SENSITIVE",
        "bruteforce": "Brute-force suspect",
        "scanner": "Scanner",
        "unique_paths": "unique paths",
        "likely_scanner": "likely scanner",
        "sensitive_hits": "Sensitive path hits",
        "responses_4xx": "4xx responses",
        "err_not_found": "error: file not found",
        "err_stdin_empty": "error: stdin is empty",
    },
    "pt": {
        "log": "Log",
        "lines_parsed": "Linhas analisadas",
        "lines_with_ts": "Linhas com timestamps",
        "date_range": "intervalo de datas",
        "ips_top": "IPs (top {n})",
        "emails_top": "Emails extraídos (top {n})",
        "urls_top": "URLs / caminhos (top {n})",
        "domains_top": "Domínios (top {n})",
        "status_codes": "Códigos de estado",
        "suspicious_patterns": "Padrões suspeitos",
        "no_suspicious": "Nenhum padrão suspeito detetado.",
        "private": "privado",
        "public": "público",
        "loopback": "loopback",
        "linklocal": "link-local",
        "sensitive": "SENSÍVEL",
        "bruteforce": "Suspeita de brute-force",
        "scanner": "Scanner",
        "unique_paths": "caminhos únicos",
        "likely_scanner": "provável scanner",
        "sensitive_hits": "Acessos a caminhos sensíveis",
        "responses_4xx": "respostas 4xx",
        "err_not_found": "erro: ficheiro não encontrado",
        "err_stdin_empty": "erro: stdin vazio",
    },
}

RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_IPV6 = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}\b"
    r"|\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}\b"
)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
RE_URL_FULL = re.compile(r"https?://\S+")
RE_HTTP_METHOD_PATH = re.compile(
    r"(?:GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|CONNECT|TRACE)\s+(\S+)"
)
RE_STATUS_AFTER_QUOTE = re.compile(r'"\s+(\d{3})\s+\d+')

RE_TS_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
RE_TS_APACHE = re.compile(r"\[\d{2}/[A-Za-z]+/\d{4}:\d{2}:\d{2}:\d{2}")
RE_TS_SYSLOG = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")

# Single-pass Apache combined/common log line. Captures IP, timestamp, method, path, status.
RE_APACHE_LINE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d{3})\s+\S+'
)

RE_SENSITIVE = re.compile(
    r"(?:\.env|\.git|admin|backup|\.bak|\.sql|wp-admin|phpmyadmin|passwd|shadow)",
    re.IGNORECASE,
)


@dataclass
class IPStat:
    ip: str
    count: int
    kind: str


@dataclass
class EmailStat:
    email: str
    count: int


@dataclass
class URLStat:
    url: str
    count: int
    sensitive: bool


@dataclass
class DomainStat:
    domain: str
    count: int


@dataclass
class SuspiciousFinding:
    kind: str
    detail: dict = field(default_factory=dict)


def valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def classify_ipv4(ip: str) -> str:
    parts = [int(p) for p in ip.split(".")]
    a, b = parts[0], parts[1]
    if a == 127:
        return "loopback"
    if a == 169 and b == 254:
        return "linklocal"
    if a == 10:
        return "private"
    if a == 192 and b == 168:
        return "private"
    if a == 172 and 16 <= b <= 31:
        return "private"
    return "public"


def classify_ip(ip: str) -> str:
    if ":" in ip:
        # IPv6: treat ::1 as loopback, fe80::/10 as link-local, else public.
        low = ip.lower()
        if low == "::1":
            return "loopback"
        if low.startswith("fe80:") or low.startswith("fe80::"):
            return "linklocal"
        if low.startswith(("fc", "fd")):
            return "private"
        return "public"
    return classify_ipv4(ip)


def parse_log(stream, bruteforce_threshold: int) -> dict:
    ip_counter: Counter = Counter()
    email_counter: Counter = Counter()
    url_counter: Counter = Counter()
    domain_counter: Counter = Counter()
    status_counter: Counter = Counter()
    ip_4xx: Counter = Counter()
    ip_paths: Dict[str, set] = defaultdict(set)
    sensitive_hits: Counter = Counter()

    lines_parsed = 0
    lines_with_ts = 0
    ts_first: Optional[str] = None
    ts_last: Optional[str] = None

    for raw in stream:
        line = raw.rstrip("\n")
        lines_parsed += 1
        if not line:
            continue

        # JSON log format (CloudWatch, GCP, Docker, ECS, etc.)
        if line.lstrip().startswith("{"):
            try:
                obj = json.loads(line)
                ip = (obj.get("client_ip") or obj.get("clientip") or obj.get("remote_addr")
                      or obj.get("ip") or obj.get("src_ip") or obj.get("source_ip") or "")
                path = (obj.get("request") or obj.get("path") or obj.get("uri")
                        or obj.get("url_path") or obj.get("http.url") or "")
                status = str(obj.get("status") or obj.get("status_code") or obj.get("http_status")
                             or obj.get("response") or obj.get("http.response.status_code") or "")
                ts = str(obj.get("time") or obj.get("timestamp") or obj.get("@timestamp")
                         or obj.get("time_local") or obj.get("datetime") or "")[:30]
                email = str(obj.get("email") or obj.get("user_email") or "")
                if ip and (valid_ipv4(ip) or ":" in ip):
                    ip_counter[ip] += 1
                    if path:
                        ip_paths[ip].add(path)
                    if status.startswith("4"):
                        ip_4xx[ip] += 1
                if path:
                    url_counter[path] += 1
                    if RE_SENSITIVE.search(path):
                        sensitive_hits[path] += 1
                if status:
                    status_counter[status] += 1
                if ts:
                    lines_with_ts += 1
                    if ts_first is None:
                        ts_first = ts
                    ts_last = ts
                if email and "@" in email:
                    email_counter[email.lower()] += 1
                continue
            except (json.JSONDecodeError, AttributeError):
                pass

        apache_match = RE_APACHE_LINE.match(line)
        if apache_match:
            ip, ts, _method, path, status = apache_match.groups()
            if valid_ipv4(ip) or ":" in ip:
                ip_counter[ip] += 1
                ip_paths[ip].add(path)
                if status.startswith("4"):
                    ip_4xx[ip] += 1
            url_counter[path] += 1
            status_counter[status] += 1
            if RE_SENSITIVE.search(path):
                sensitive_hits[path] += 1
            lines_with_ts += 1
            if ts_first is None:
                ts_first = ts
            ts_last = ts
            continue

        for m in RE_IPV4.findall(line):
            if valid_ipv4(m):
                ip_counter[m] += 1
        for m in RE_IPV6.findall(line):
            ip_counter[m] += 1

        for m in RE_EMAIL.findall(line):
            email_counter[m.lower()] += 1

        method_paths = RE_HTTP_METHOD_PATH.findall(line)
        for path in method_paths:
            url_counter[path] += 1
            if RE_SENSITIVE.search(path):
                sensitive_hits[path] += 1
        for url in RE_URL_FULL.findall(line):
            url = url.rstrip(",.;)\"'")
            url_counter[url] += 1
            if RE_SENSITIVE.search(url):
                sensitive_hits[url] += 1

        for status in RE_STATUS_AFTER_QUOTE.findall(line):
            status_counter[status] += 1

        for d in RE_DOMAIN.findall(line):
            d_low = d.lower()
            # Skip strings that already looked like full IPv4 — RE_DOMAIN can match them.
            if not valid_ipv4(d_low):
                domain_counter[d_low] += 1

        ts = None
        m = RE_TS_ISO.search(line)
        if m:
            ts = m.group(0)
        if ts is None:
            m = RE_TS_APACHE.search(line)
            if m:
                ts = m.group(0).lstrip("[")
        if ts is None:
            m = RE_TS_SYSLOG.search(line)
            if m:
                ts = m.group(0)
        if ts is not None:
            lines_with_ts += 1
            if ts_first is None:
                ts_first = ts
            ts_last = ts

    suspicious: List[SuspiciousFinding] = []
    for ip, n in ip_4xx.items():
        if n >= bruteforce_threshold:
            suspicious.append(SuspiciousFinding("bruteforce", {"ip": ip, "count": n}))
    for ip, paths in ip_paths.items():
        if len(paths) > 50:
            suspicious.append(
                SuspiciousFinding("scanner", {"ip": ip, "unique_paths": len(paths)})
            )
    for path, n in sensitive_hits.most_common():
        suspicious.append(
            SuspiciousFinding("sensitive_path", {"path": path, "count": n})
        )

    return {
        "lines_parsed": lines_parsed,
        "lines_with_ts": lines_with_ts,
        "ts_first": ts_first,
        "ts_last": ts_last,
        "ip_counter": ip_counter,
        "email_counter": email_counter,
        "url_counter": url_counter,
        "domain_counter": domain_counter,
        "status_counter": status_counter,
        "sensitive_hits": sensitive_hits,
        "suspicious": suspicious,
    }


def fmt_int(n: int) -> str:
    return f"{n:,}"


def render_human(result: dict, logfile: str, top: int, lang: str) -> str:
    L = LABELS[lang]
    out: List[str] = []
    out.append(f"{L['log']}: {logfile}")
    out.append(f"{L['lines_parsed']}: {fmt_int(result['lines_parsed'])}")
    if result["lines_with_ts"]:
        rng = ""
        if result["ts_first"] and result["ts_last"]:
            rng = f"  ({L['date_range']}: {result['ts_first']} to {result['ts_last']})"
        out.append(
            f"{L['lines_with_ts']}: {fmt_int(result['lines_with_ts'])}{rng}"
        )

    ip_counter: Counter = result["ip_counter"]
    if ip_counter:
        out.append("")
        out.append(L["ips_top"].format(n=top) + ":")
        for ip, n in ip_counter.most_common(top):
            kind = classify_ip(ip)
            kind_label = L.get(kind, kind)
            out.append(f"  {ip:<20} {fmt_int(n):>6}  ({kind_label})")

    email_counter: Counter = result["email_counter"]
    if email_counter:
        out.append("")
        out.append(L["emails_top"].format(n=top) + ":")
        for email, n in email_counter.most_common(top):
            out.append(f"  {email:<30} {fmt_int(n):>6}")

    url_counter: Counter = result["url_counter"]
    if url_counter:
        out.append("")
        out.append(L["urls_top"].format(n=top) + ":")
        for url, n in url_counter.most_common(top):
            tag = f"  [{L['sensitive']}]" if RE_SENSITIVE.search(url) else ""
            out.append(f"  {url:<30} {fmt_int(n):>6}{tag}")

    domain_counter: Counter = result["domain_counter"]
    if domain_counter:
        out.append("")
        out.append(L["domains_top"].format(n=top) + ":")
        for d, n in domain_counter.most_common(top):
            out.append(f"  {d:<30} {fmt_int(n):>6}")

    status_counter: Counter = result["status_counter"]
    if status_counter:
        out.append("")
        out.append(L["status_codes"] + ":")
        for code, n in sorted(status_counter.items()):
            out.append(f"  {code}  {fmt_int(n):>6}")

    suspicious: List[SuspiciousFinding] = result["suspicious"]
    out.append("")
    if not suspicious:
        out.append(L["no_suspicious"])
    else:
        out.append(f"{L['suspicious_patterns']} ({len(suspicious)}):")
        for f in suspicious:
            if f.kind == "bruteforce":
                out.append(
                    f"  x {L['bruteforce']}: {f.detail['ip']} -> "
                    f"{f.detail['count']} {L['responses_4xx']}"
                )
            elif f.kind == "scanner":
                out.append(
                    f"  x {L['scanner']}: {f.detail['ip']} -> "
                    f"{f.detail['unique_paths']} {L['unique_paths']} ({L['likely_scanner']})"
                )
            elif f.kind == "sensitive_path":
                out.append(
                    f"  x {L['sensitive_hits']}: {f.detail['path']} "
                    f"({f.detail['count']}x)"
                )

    return "\n".join(out)


def render_json(result: dict, logfile: str, top: int, lang: str) -> str:
    ip_counter: Counter = result["ip_counter"]
    email_counter: Counter = result["email_counter"]
    url_counter: Counter = result["url_counter"]
    domain_counter: Counter = result["domain_counter"]
    status_counter: Counter = result["status_counter"]

    ip_top = [
        asdict(IPStat(ip=ip, count=n, kind=classify_ip(ip)))
        for ip, n in ip_counter.most_common(top)
    ]
    email_top = [
        asdict(EmailStat(email=e, count=n))
        for e, n in email_counter.most_common(top)
    ]
    url_top = [
        asdict(URLStat(url=u, count=n, sensitive=bool(RE_SENSITIVE.search(u))))
        for u, n in url_counter.most_common(top)
    ]
    domain_top = [
        asdict(DomainStat(domain=d, count=n))
        for d, n in domain_counter.most_common(top)
    ]

    suspicious_json = []
    for f in result["suspicious"]:
        entry = {"kind": f.kind}
        entry.update(f.detail)
        suspicious_json.append(entry)

    payload = {
        "logfile": logfile,
        "lang": lang,
        "lines_parsed": result["lines_parsed"],
        "lines_with_timestamps": result["lines_with_ts"],
        "date_range": {"first": result["ts_first"], "last": result["ts_last"]},
        "ip_stats": {"top": ip_top, "distinct": len(ip_counter)},
        "email_stats": {"top": email_top, "distinct": len(email_counter)},
        "url_stats": {"top": url_top, "distinct": len(url_counter)},
        "domain_stats": {"top": domain_top, "distinct": len(domain_counter)},
        "status_codes": dict(sorted(status_counter.items())),
        "suspicious": suspicious_json,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def open_stream(path: str, lang: str):
    if path == "-":
        if sys.stdin.isatty():
            print(LABELS[lang]["err_stdin_empty"], file=sys.stderr)
            sys.exit(2)
        return sys.stdin
    try:
        return open(path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        print(f"{LABELS[lang]['err_not_found']}: {path}", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse a log file and extract IPs, emails, URLs, status codes, "
        "and flag suspicious patterns (brute-force, scanners, sensitive paths).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "logfile",
        help="Path to the log file, or '-' to read from stdin.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="Top N items per category (default: 10).",
    )
    parser.add_argument(
        "--bruteforce",
        type=int,
        default=10,
        metavar="N",
        help="4xx-response threshold per IP to flag brute-force (default: 10).",
    )
    parser.add_argument(
        "--lang",
        choices=LANGS,
        default="en",
        help="Output language (default: en).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of human-readable output.",
    )
    add_version_arg(parser, "log_parser.py")

    args = parser.parse_args()

    # stdin_or_arg handles the '-' case for one-shot single-line input.
    # For a log file we still want streaming, so we open the stream ourselves —
    # call stdin_or_arg only to keep the consistent UX for "missing input".
    if args.logfile == "-" and sys.stdin.isatty():
        print(LABELS[args.lang]["err_stdin_empty"], file=sys.stderr)
        return 2

    stream = open_stream(args.logfile, args.lang)
    try:
        result = parse_log(stream, args.bruteforce)
    finally:
        if stream is not sys.stdin:
            stream.close()

    if args.json:
        print(render_json(result, args.logfile, args.top, args.lang))
    else:
        print(render_human(result, args.logfile, args.top, args.lang))

    return 1 if result["suspicious"] else 0


if __name__ == "__main__":
    sys.exit(main())
