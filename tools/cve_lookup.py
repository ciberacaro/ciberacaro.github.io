#!/usr/bin/env python3
"""Look up CVE details from the NVD (National Vulnerability Database).

Queries the NVD CVE v2 API. No auth required for low-volume usage
(rate-limited to a few requests / 30 seconds without an API key).

Examples:
    tools/cve_lookup.py CVE-2021-44228
    tools/cve_lookup.py CVE-2021-44228 --lang pt
    tools/cve_lookup.py CVE-2021-44228 --json
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

from _lib import build_ssl_context, make_user_agent, add_version_arg, stdin_or_arg

USER_AGENT = make_user_agent("cve_lookup.py")
LANGS = ("en", "pt")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

LABELS = {
    "en": {
        "id": "CVE",
        "published": "Published",
        "last_modified": "Last modified",
        "status": "Status",
        "description": "Description",
        "cvss_v3": "CVSS v3",
        "cvss_v2": "CVSS v2",
        "score": "score",
        "vector": "vector",
        "severity": "severity",
        "weaknesses": "Weaknesses (CWE)",
        "affected": "Affected products",
        "references": "References",
        "not_found": "CVE not found in NVD.",
        "err_format": "error: CVE id must look like CVE-YYYY-NNNN",
        "err_api": "error: NVD API request failed",
    },
    "pt": {
        "id": "CVE",
        "published": "Publicado",
        "last_modified": "Última alteração",
        "status": "Estado",
        "description": "Descrição",
        "cvss_v3": "CVSS v3",
        "cvss_v2": "CVSS v2",
        "score": "score",
        "vector": "vetor",
        "severity": "severidade",
        "weaknesses": "Fraquezas (CWE)",
        "affected": "Produtos afetados",
        "references": "Referências",
        "not_found": "CVE não encontrado no NVD.",
        "err_format": "erro: CVE tem de ter o formato CVE-YYYY-NNNN",
        "err_api": "erro: pedido à API NVD falhou",
    },
}


@dataclass
class CveInfo:
    cve_id: str
    published: str = ""
    last_modified: str = ""
    status: str = ""
    description: str = ""
    cvss_v3_score: str = ""
    cvss_v3_severity: str = ""
    cvss_v3_vector: str = ""
    cvss_v2_score: str = ""
    cvss_v2_severity: str = ""
    cvss_v2_vector: str = ""
    weaknesses: list[str] = field(default_factory=list)
    affected_cpes: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)


def fetch_cve(cve_id: str, timeout: float = 30.0) -> dict | None:
    url = f"{NVD_URL}?cveId={cve_id}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    return vulns[0].get("cve")


def parse(raw: dict, cve_id: str) -> CveInfo:
    info = CveInfo(cve_id=cve_id)
    info.published = raw.get("published", "")
    info.last_modified = raw.get("lastModified", "")
    info.status = raw.get("vulnStatus", "")

    # Description: prefer English ('en' lang code) if available.
    descs = raw.get("descriptions") or []
    en = [d.get("value", "") for d in descs if d.get("lang") == "en"]
    if en:
        info.description = en[0]
    elif descs:
        info.description = descs[0].get("value", "")

    # CVSS metrics — NVD nests under metrics.cvssMetricV31 / V30 / V2
    metrics = raw.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            data = m.get("cvssData", {})
            info.cvss_v3_score = str(data.get("baseScore", ""))
            info.cvss_v3_severity = data.get("baseSeverity", "") or m.get("baseSeverity", "")
            info.cvss_v3_vector = data.get("vectorString", "")
            break
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        m = metrics["cvssMetricV2"][0]
        data = m.get("cvssData", {})
        info.cvss_v2_score = str(data.get("baseScore", ""))
        info.cvss_v2_severity = m.get("baseSeverity", "") or data.get("baseSeverity", "")
        info.cvss_v2_vector = data.get("vectorString", "")

    # Weaknesses (CWE)
    weaknesses = raw.get("weaknesses") or []
    seen_cwes: set[str] = set()
    for w in weaknesses:
        for desc in w.get("description", []):
            value = desc.get("value", "")
            if value and value not in seen_cwes:
                seen_cwes.add(value)
                info.weaknesses.append(value)

    # Affected products (CPE)
    configs = raw.get("configurations") or []
    seen_cpes: set[str] = set()
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria", "")
                if criteria and criteria not in seen_cpes:
                    seen_cpes.add(criteria)
                    info.affected_cpes.append(criteria)

    # References
    for ref in raw.get("references") or []:
        info.references.append({
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", []),
        })

    return info


def print_human(info: CveInfo, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['id']}: {info.cve_id}")
    print(f"  {L['published']}:     {info.published}")
    print(f"  {L['last_modified']}: {info.last_modified}")
    print(f"  {L['status']}:        {info.status}\n")

    print(f"{L['description']}:")
    print(f"  {info.description}\n")

    if info.cvss_v3_score:
        print(f"{L['cvss_v3']}: {L['score']} {info.cvss_v3_score}  ({L['severity']}: {info.cvss_v3_severity})")
        print(f"  {L['vector']}: {info.cvss_v3_vector}")
    if info.cvss_v2_score:
        print(f"{L['cvss_v2']}: {L['score']} {info.cvss_v2_score}  ({L['severity']}: {info.cvss_v2_severity})")
        print(f"  {L['vector']}: {info.cvss_v2_vector}")

    if info.weaknesses:
        print(f"\n{L['weaknesses']}:")
        for w in info.weaknesses:
            print(f"  - {w}")

    if info.affected_cpes:
        print(f"\n{L['affected']} ({len(info.affected_cpes)}):")
        for cpe in info.affected_cpes[:15]:
            print(f"  - {cpe}")
        if len(info.affected_cpes) > 15:
            print(f"  ... ({len(info.affected_cpes) - 15} more)")

    if info.references:
        print(f"\n{L['references']} ({len(info.references)}):")
        for ref in info.references[:15]:
            tags = (" [" + ", ".join(ref.get("tags", [])) + "]") if ref.get("tags") else ""
            print(f"  - {ref.get('url')}{tags}")
        if len(info.references) > 15:
            print(f"  ... ({len(info.references) - 15} more)")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch CVE details from the NVD database.")
    add_version_arg(parser, "cve_lookup.py")
    parser.add_argument("cve_id", help="CVE identifier like CVE-2021-44228. Use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    L = LABELS[args.lang]

    cve_id = stdin_or_arg(args.cve_id).strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        print(f"{L['err_format']} ({cve_id!r})", file=sys.stderr)
        return 2

    try:
        raw = fetch_cve(cve_id, timeout=args.timeout)
    except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
        print(f"{L['err_api']}: {e}", file=sys.stderr)
        return 3

    if raw is None:
        print(f"\n{L['not_found']}\n", file=sys.stderr)
        return 1

    info = parse(raw, cve_id)

    if args.json:
        out = asdict(info)
        out["lang"] = args.lang
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(info, args.lang)

    return 0


if __name__ == "__main__":
    sys.exit(main())
