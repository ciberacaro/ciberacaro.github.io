#!/usr/bin/env python3
"""Orchestrate reconnaissance against a domain by composing other tools.

Workflow:
  1. subfinder.py     — enumerate subdomains (crt.sh + DNS).
  2. For each resolved subdomain, run in parallel:
       - check_headers.py  (security headers + COOP/COEP/CORP)
       - tls_inspect.py    (cert info + issues)
       - cookie_check.py   (Set-Cookie flags)
  3. Once, on the base domain:
       - dns_records.py    (email auth + CAA)
  4. Aggregate everything into a single Markdown report.

This is a wrapper around the tools that already exist — it doesn't
re-implement their logic. Each tool is invoked as a subprocess and
its --json output parsed.

Examples:
    tools/recon.py example.com
    tools/recon.py example.com --lang pt --output report.md
    tools/recon.py example.com --top 5     # only scan top 5 subdomains
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from _lib import add_version_arg, stdin_or_arg

LANGS = ("en", "pt")
TOOLS_DIR = Path(__file__).resolve().parent

LABELS = {
    "en": {
        "report_title": "Reconnaissance report",
        "target_domain": "Target domain",
        "generated_at": "Generated at",
        "subdomains_found": "Subdomains found",
        "scanned": "Scanned",
        "base_dns": "Base-domain DNS / email auth",
        "per_host": "Per-host findings",
        "headers": "Security headers",
        "tls": "TLS certificate",
        "cookies": "Cookies",
        "issues": "Issues",
        "no_issues": "No issues.",
        "error": "Error",
        "skipped": "skipped (did not resolve)",
        "running": "Running",
        "summary": "Summary",
        "total_issues": "Total issues found across all hosts",
    },
    "pt": {
        "report_title": "Relatório de reconhecimento",
        "target_domain": "Domínio alvo",
        "generated_at": "Gerado em",
        "subdomains_found": "Subdomínios encontrados",
        "scanned": "Analisados",
        "base_dns": "DNS / autenticação de email do domínio base",
        "per_host": "Achados por host",
        "headers": "Headers de segurança",
        "tls": "Certificado TLS",
        "cookies": "Cookies",
        "issues": "Problemas",
        "no_issues": "Sem problemas.",
        "error": "Erro",
        "skipped": "saltado (não resolveu)",
        "running": "A executar",
        "summary": "Resumo",
        "total_issues": "Total de problemas encontrados em todos os hosts",
    },
}


@dataclass
class HostReport:
    hostname: str
    ips: list[str]
    headers: dict | None = None
    tls: dict | None = None
    cookies: dict | None = None
    issues_count: int = 0


def run_tool(args: list[str], timeout: float = 60.0) -> dict | None:
    """Run a sibling tool with --json, parse the output.

    Tools return non-zero exit codes when issues are found, which is
    fine — we still get JSON on stdout. Only treat 'no JSON' or signal
    death as failure.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    if not proc.stdout.strip():
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def subfinder(domain: str, lang: str, timeout: float = 90.0) -> list[dict]:
    """Returns the list of {hostname, ips, source} from subfinder.py --json."""
    out = run_tool([str(TOOLS_DIR / "subfinder.py"), domain, "--json", "--lang", lang], timeout=timeout)
    return out["resolved"] if out else []


def dns_records(domain: str, lang: str, timeout: float = 30.0) -> dict | None:
    return run_tool([str(TOOLS_DIR / "dns_records.py"), domain, "--json", "--lang", lang], timeout=timeout)


def headers_for(host: str, lang: str, timeout: float = 20.0) -> dict | None:
    return run_tool(
        [str(TOOLS_DIR / "check_headers.py"), f"https://{host}", "--json", "--lang", lang, "--timeout", "10"],
        timeout=timeout,
    )


def tls_for(host: str, lang: str, timeout: float = 20.0) -> dict | None:
    return run_tool(
        [str(TOOLS_DIR / "tls_inspect.py"), host, "--json", "--lang", lang, "--timeout", "10"],
        timeout=timeout,
    )


def cookies_for(host: str, lang: str, timeout: float = 20.0) -> dict | None:
    return run_tool(
        [str(TOOLS_DIR / "cookie_check.py"), f"https://{host}", "--json", "--lang", lang, "--timeout", "10"],
        timeout=timeout,
    )


def count_issues(host_report: HostReport) -> int:
    count = 0
    if host_report.headers:
        count += host_report.headers.get("issues_count", 0)
    if host_report.tls and host_report.tls.get("issues"):
        count += len(host_report.tls["issues"])
    if host_report.cookies and host_report.cookies.get("issues"):
        count += len(host_report.cookies["issues"])
    return count


def render_report(domain: str, dns: dict | None, hosts: list[HostReport],
                  total_subdomains: int, lang: str) -> str:
    from datetime import datetime, timezone
    L = LABELS[lang]
    out: list[str] = []
    out.append(f"# {L['report_title']}: `{domain}`")
    out.append("")
    out.append(f"- **{L['target_domain']}:** `{domain}`")
    out.append(f"- **{L['generated_at']}:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    out.append(f"- **{L['subdomains_found']}:** {total_subdomains} — **{L['scanned']}:** {len(hosts)}")
    out.append("")

    # ---- Base-domain DNS / email auth
    out.append(f"## {L['base_dns']}")
    out.append("")
    if dns:
        records = dns.get("records", {})
        for key in ("a", "aaaa", "mx", "ns"):
            vals = records.get(key, [])
            if vals:
                out.append(f"- **{key.upper()}:** " + ", ".join(f"`{v}`" for v in vals[:10]))
        txt = records.get("txt", [])
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        out.append(f"- **SPF:** " + (f"`{spf[0]}`" if spf else "—"))
        dmarc = records.get("dmarc", [])
        out.append(f"- **DMARC:** " + (f"`{dmarc[0]}`" if dmarc else "—"))
        caa = records.get("caa", [])
        out.append(f"- **CAA:** " + (", ".join(f"`{c}`" for c in caa) if caa else "—"))
        issues = dns.get("issues", [])
        if issues:
            out.append("")
            out.append(f"### {L['issues']}")
            out.append("")
            for iss in issues:
                out.append(f"- ✗ {iss.get('label', iss.get('risk', ''))}")
                if iss.get("fix"):
                    out.append(f"  - **Fix:** {iss['fix']}")
    else:
        out.append(f"_{L['error']}: dns_records.py returned no data._")
    out.append("")

    # ---- Per-host findings
    out.append(f"## {L['per_host']}")
    out.append("")
    if not hosts:
        out.append(f"_{L['skipped']}_")
        out.append("")
    for host in hosts:
        out.append(f"### `{host.hostname}`  ({', '.join(host.ips[:3])})")
        out.append("")
        out.append(f"- **{L['headers']}:** {_headers_summary(host.headers, L)}")
        out.append(f"- **{L['tls']}:** {_tls_summary(host.tls, L)}")
        out.append(f"- **{L['cookies']}:** {_cookies_summary(host.cookies, L)}")
        # Issue details
        all_issues = _collect_host_issues(host)
        if all_issues:
            out.append("")
            out.append(f"#### {L['issues']}  ({len(all_issues)})")
            out.append("")
            for source, iss in all_issues:
                label = _issue_label(source, iss)
                out.append(f"- ✗ [{source}] {label}")
        out.append("")

    # ---- Summary
    total = sum(count_issues(h) for h in hosts)
    if dns:
        total += len(dns.get("issues", []))
    out.append(f"## {L['summary']}")
    out.append("")
    out.append(f"- **{L['total_issues']}:** {total}")
    out.append("")
    return "\n".join(out)


def _headers_summary(h: dict | None, L: dict) -> str:
    if h is None:
        return f"_{L['error']}_"
    findings = h.get("findings", [])
    ok = sum(1 for f in findings if f.get("status") == "OK")
    return f"score {ok} OK, {h.get('issues_count', 0)} {L['issues'].lower()}"


def _tls_summary(t: dict | None, L: dict) -> str:
    if t is None:
        return f"_{L['error']}_"
    issuer = t.get("issuer", {}).get("commonName", "?")
    days = t.get("days_left", "?")
    issues = len(t.get("issues", []))
    return f"issuer `{issuer}`, {days} days left, {issues} {L['issues'].lower()}"


def _cookies_summary(c: dict | None, L: dict) -> str:
    if c is None:
        return f"_{L['error']}_"
    n_cookies = len(c.get("cookies", []))
    issues = len(c.get("issues", []))
    return f"{n_cookies} cookies, {issues} {L['issues'].lower()}"


def _issue_label(source: str, iss: dict) -> str:
    """Produce a short, scannable label for the issue regardless of source tool.

    check_headers findings have {header, status, note} — render as
    'Strict-Transport-Security [MISSING] — short note'. Issue objects from
    other tools already carry a 'label' field.
    """
    if source == "headers" and iss.get("header"):
        return f"{iss['header']} [{iss.get('status', '?')}] — {iss.get('note', '')}"
    return iss.get("label") or iss.get("risk") or iss.get("note") or "(no description)"


def _collect_host_issues(host: HostReport):
    out = []
    if host.headers:
        for f in host.headers.get("findings", []):
            if f.get("status") in ("MISSING", "WEAK"):
                out.append(("headers", f))
    if host.tls:
        for iss in host.tls.get("issues", []):
            out.append(("tls", iss))
    if host.cookies:
        for iss in host.cookies.get("issues", []):
            out.append(("cookies", iss))
    return out


def scan_host(host_info: dict, lang: str) -> HostReport:
    host = host_info["hostname"]
    ips = host_info.get("ips", [])
    h = HostReport(hostname=host, ips=ips)
    # Run the three checks. Each handles its own timeout.
    h.headers = headers_for(host, lang)
    h.tls = tls_for(host, lang)
    h.cookies = cookies_for(host, lang)
    h.issues_count = count_issues(h)
    return h


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconnaissance orchestrator: composes subfinder, check_headers, tls_inspect, cookie_check, dns_records.",
    )
    add_version_arg(parser, "recon.py")
    parser.add_argument("domain", help="Base domain. Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--top", type=int, default=10,
                        help="Maximum number of subdomains to scan per-host (default: 10)")
    parser.add_argument("--threads", type=int, default=6, help="Parallel per-host scans (default: 6)")
    parser.add_argument("--output", "-o", help="Write the markdown report to a file instead of stdout")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of markdown")
    args = parser.parse_args()
    L = LABELS[args.lang]

    domain = stdin_or_arg(args.domain).strip().lower()
    if not re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", domain):
        print(f"error: invalid domain {domain!r}", file=sys.stderr)
        return 2

    print(f"{L['running']}: subfinder.py …", file=sys.stderr)
    resolved = subfinder(domain, args.lang)
    total_subdomains = len(resolved)
    targets = resolved[: args.top]

    print(f"{L['running']}: dns_records.py on {domain} …", file=sys.stderr)
    dns = dns_records(domain, args.lang)

    print(f"{L['running']}: {len(targets)} host scan(s) in parallel …", file=sys.stderr)
    hosts: list[HostReport] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h, args.lang): h["hostname"] for h in targets}
        for fut in concurrent.futures.as_completed(futures):
            try:
                hosts.append(fut.result())
            except Exception as e:
                print(f"  warn: {futures[fut]}: {e}", file=sys.stderr)
    hosts.sort(key=lambda h: h.hostname)

    if args.json:
        out = {
            "domain": domain,
            "lang": args.lang,
            "total_subdomains_resolved": total_subdomains,
            "scanned": len(hosts),
            "dns": dns,
            "hosts": [
                {
                    "hostname": h.hostname, "ips": h.ips,
                    "headers": h.headers, "tls": h.tls, "cookies": h.cookies,
                    "issues_count": h.issues_count,
                }
                for h in hosts
            ],
        }
        rendered = json.dumps(out, indent=2, ensure_ascii=False)
    else:
        rendered = render_report(domain, dns, hosts, total_subdomains, args.lang)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"report written to: {args.output}", file=sys.stderr)
    else:
        print(rendered)

    total_issues = sum(h.issues_count for h in hosts) + (len(dns.get("issues", [])) if dns else 0)
    return 1 if total_issues else 0


if __name__ == "__main__":
    sys.exit(main())
