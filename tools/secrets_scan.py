#!/usr/bin/env python3
"""Scan a directory or a git repo's history for committed secrets.

Two modes:

    --path DIR     Scan the working tree under DIR (default: current dir).
                   Walks files, skips binaries and the common noise (node_modules,
                   .git, __pycache__, dist, build, etc.).

    --git-history  Scan every commit in the current git repo via `git log -p`.
                   Catches secrets that were committed and later removed —
                   removal does not delete history.

Patterns include AWS keys, Stripe / Slack / GitHub / Google / Twilio /
SendGrid / OpenAI / Anthropic / HuggingFace tokens, generic API keys,
private keys, JWT-looking strings, .env-style assignments, and common
database connection URLs.

Examples:
    tools/secrets_scan.py
    tools/secrets_scan.py --path ~/Projects/some-repo
    tools/secrets_scan.py --git-history
    tools/secrets_scan.py --lang pt --json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from _lib import add_version_arg

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "scanning": "Scanning",
        "mode_path": "filesystem mode",
        "mode_git": "git history mode",
        "findings": "Findings",
        "no_findings": "No secret-like patterns found.",
        "summary": "Summary",
        "total": "total findings",
        "files_scanned": "files scanned",
        "files_skipped_binary": "files skipped (binary)",
        "files_skipped_size": "files skipped (too large)",
        "err_path": "error: path does not exist",
        "err_not_git": "error: --git-history must run inside a git repository",
        "warning_false_positives": (
            "Note: regex scans produce false positives. Review each finding before acting; "
            "high-entropy IDs and example values are commonly flagged."
        ),
        "sev_critical": "CRITICAL",
        "sev_high": "HIGH",
        "sev_medium": "MEDIUM",
        "sev_low": "LOW",
        "sev_info": "INFO",
    },
    "pt": {
        "scanning": "A varrer",
        "mode_path": "modo filesystem",
        "mode_git": "modo histórico git",
        "findings": "Achados",
        "no_findings": "Não foram encontrados padrões compatíveis com secrets.",
        "summary": "Resumo",
        "total": "achados no total",
        "files_scanned": "ficheiros varridos",
        "files_skipped_binary": "ficheiros saltados (binários)",
        "files_skipped_size": "ficheiros saltados (demasiado grandes)",
        "err_path": "erro: caminho não existe",
        "err_not_git": "erro: --git-history requer um repositório git",
        "warning_false_positives": (
            "Nota: scans por regex produzem falsos positivos. Revê cada achado antes de "
            "agir; IDs com alta entropia e valores de exemplo são frequentemente marcados."
        ),
        "sev_critical": "CRÍTICO",
        "sev_high": "ALTO",
        "sev_medium": "MÉDIO",
        "sev_low": "BAIXO",
        "sev_info": "INFO",
    },
}

# Regex patterns and friendly names. Be conservative — false positives erode trust.
# Each entry: (name, regex, description)
PATTERNS = (
    ("aws_access_key", r"\b(AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b",
     "AWS access key ID"),
    ("aws_secret_key", r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key[\"'\s:=]{1,5}\"?([A-Za-z0-9/+=]{40})\"?",
     "AWS secret access key (assignment)"),
    ("github_pat_classic", r"\bghp_[A-Za-z0-9]{36,}\b",
     "GitHub personal access token (classic)"),
    ("github_pat_fine", r"\bgithub_pat_[A-Za-z0-9_]{59,}\b",
     "GitHub fine-grained PAT"),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36,}\b",
     "GitHub OAuth token"),
    ("github_app", r"\b(ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}\b",
     "GitHub app/refresh/server token"),
    ("slack_bot_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
     "Slack bot/user/app token"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
     "Slack incoming webhook"),
    ("stripe_live_key", r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b",
     "Stripe live secret/restricted key"),
    ("stripe_test_key", r"\b(sk|rk)_test_[A-Za-z0-9]{20,}\b",
     "Stripe test secret/restricted key"),
    ("twilio_sid", r"\bAC[a-f0-9]{32}\b",
     "Twilio Account SID"),
    ("twilio_auth", r"\bSK[a-f0-9]{32}\b",
     "Twilio API key SID"),
    ("sendgrid", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
     "SendGrid API key"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b",
     "Google API key"),
    ("google_oauth_id", r"\b[0-9]{10,}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b",
     "Google OAuth client ID"),
    ("private_key_block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
     "Private key PEM block"),
    ("jwt_token", r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
     "JWT (possibly fine, but worth reviewing)"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b",
     "npm access token"),
    ("heroku_api", r"(?i)heroku[\"'\s:=]{1,5}\"?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\"?",
     "Heroku API key (assignment)"),
    ("openai_key", r"\bsk-[A-Za-z0-9]{48}\b",
     "OpenAI API key (legacy format)"),
    ("openai_proj_key", r"\bsk-proj-[A-Za-z0-9_\-]{80,}\b",
     "OpenAI project API key"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{90,}\b",
     "Anthropic API key"),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{34}\b",
     "HuggingFace API token"),
    ("bare_credential_assign",
     r"(?i)(?:^|[\s;,{\[])(?:api[_\-]?key|secret[_\-]?key|auth[_\-]?(?:key|token)|access[_\-]?(?:key|token))\s*[=:]\s*([A-Za-z0-9+/=_\-]{20,})(?=\s|$|[,;\"'\]}])",
     "Bare credential assignment (no quotes, entropy-gated)"),
    ("postgres_url", r"postgres(?:ql)?://[^\s\"']*:[^@\s\"']+@[^\s\"']+",
     "Postgres connection string with password"),
    ("mysql_url", r"mysql://[^\s\"']*:[^@\s\"']+@[^\s\"']+",
     "MySQL connection string with password"),
    ("mongo_url", r"mongodb(?:\+srv)?://[^\s\"']*:[^@\s\"']+@[^\s\"']+",
     "MongoDB connection string with password"),
    ("generic_secret_assign",
     r"(?i)\b(?:api[_\-]?key|secret|password|passwd|token)\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{16,})[\"']",
     "Generic credential assignment (low confidence)"),
)

# Severity tier per pattern name. Used for output grouping and actionability.
PATTERN_SEVERITY: dict[str, str] = {
    "aws_access_key":      "critical",
    "aws_secret_key":      "critical",
    "private_key_block":   "critical",
    "stripe_live_key":     "critical",
    "github_pat_classic":  "high",
    "github_pat_fine":     "high",
    "github_oauth":        "high",
    "github_app":          "high",
    "slack_bot_token":     "high",
    "slack_webhook":       "high",
    "openai_key":          "high",
    "openai_proj_key":     "high",
    "anthropic_key":       "high",
    "huggingface_token":   "high",
    "sendgrid":            "high",
    "postgres_url":        "high",
    "mysql_url":           "high",
    "mongo_url":           "high",
    "twilio_sid":          "medium",
    "twilio_auth":         "medium",
    "stripe_test_key":     "medium",
    "google_api_key":      "medium",
    "google_oauth_id":     "medium",
    "npm_token":           "medium",
    "heroku_api":          "medium",
    "bare_credential_assign": "medium",
    "generic_secret_assign":  "low",
    "jwt_token":           "low",
    "env_file_name":       "info",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Matches .env, .env.local, .env.production, .env.bak, etc.
_ENV_FILE_RE = re.compile(r"^\.env(\.|$)", re.I)

# Files / directories to skip entirely.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".pytest_cache", ".mypy_cache", ".tox", "vendor",
             ".next", ".nuxt", "target", "Pods", ".gradle", ".idea", ".vscode"}
SKIP_EXTS = {".pyc", ".pyo", ".class", ".jar", ".dll", ".so", ".dylib",
             ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".ico",
             ".mp3", ".mp4", ".mov", ".wav", ".zip", ".tar", ".gz", ".tgz",
             ".7z", ".bz2", ".db", ".sqlite", ".woff", ".woff2", ".ttf", ".eot"}

MAX_FILE_BYTES = 1_000_000  # 1 MB — anything larger almost certainly isn't source code

# Patterns where we apply a Shannon-entropy gate to the captured value before
# reporting a hit. Reduces false positives on patterns that match anything
# that *looks* like a token (e.g. generic api_key='...' assignments).
ENTROPY_GATED_PATTERNS = {"generic_secret_assign", "bare_credential_assign"}
ENTROPY_MIN_BITS_PER_CHAR = 3.5  # ~empirical floor between "real secret" and "example string"


def shannon_entropy(text: str) -> float:
    """Bits per character. Random hex ≈ 4.0, base64 ≈ 6.0, English prose ≈ 2.0."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass
class Finding:
    pattern_name: str
    description: str
    location: str           # file path or "<commit-sha>:<file>"
    line_number: Optional[int]
    preview: str            # masked preview of the match
    severity: str = "medium"


def is_binary_file(path: Path) -> bool:
    """Quick heuristic: read first chunk, look for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    # Many text files have no nulls but plenty of high-bit bytes. We only
    # skip if the file is *clearly* binary.
    return False


def mask_preview(value: str, max_len: int = 80) -> str:
    """Mask the middle of the match so we don't paste real secrets into reports."""
    if len(value) <= 10:
        return value[:3] + "***" + value[-2:] if len(value) > 5 else "***"
    half = max(4, (max_len - 8) // 2)
    if len(value) > max_len:
        return value[:half] + " ...[masked]... " + value[-half:]
    visible = max(4, len(value) // 4)
    return value[:visible] + "***" + value[-visible:]


def scan_text(text: str, location: str) -> list[Finding]:
    out: list[Finding] = []
    for name, pattern, desc in PATTERNS:
        for m in re.finditer(pattern, text):
            full = m.group(0)
            # For gated patterns, apply Shannon-entropy gate to the captured
            # *value* (first capture group if present, otherwise the whole match).
            # Filters out e.g. api_key='example' or api_key='changeme1234'.
            if name in ENTROPY_GATED_PATTERNS:
                captured = m.group(1) if m.groups() else full
                if shannon_entropy(captured) < ENTROPY_MIN_BITS_PER_CHAR:
                    continue
            line_no = text[:m.start()].count("\n") + 1
            out.append(Finding(
                pattern_name=name,
                description=desc,
                location=location,
                line_number=line_no,
                preview=mask_preview(full),
                severity=PATTERN_SEVERITY.get(name, "medium"),
            ))
    return out


def _env_file_finding(path: Path, location: str) -> Optional[Finding]:
    """Return a finding if the filename looks like a committed .env file."""
    if _ENV_FILE_RE.match(path.name):
        return Finding(
            pattern_name="env_file_name",
            description=".env file committed to repository (may contain secrets)",
            location=location,
            line_number=None,
            preview=str(path.name),
            severity="info",
        )
    return None


def walk_path(root: Path):
    """Yield (file_path, content) pairs, skipping the obvious noise."""
    skipped_binary = 0
    skipped_size = 0
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Mutate dirnames in-place to skip
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXTS:
                continue
            path = Path(dirpath) / fn
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                skipped_size += 1
                continue
            if is_binary_file(path):
                skipped_binary += 1
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            scanned += 1
            yield path, text
    yield {"scanned": scanned, "skipped_binary": skipped_binary, "skipped_size": skipped_size}, None


def scan_filesystem(root: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    stats: dict = {}
    for item, text in walk_path(root):
        if text is None:
            stats = item  # type: ignore[assignment]
            continue
        path = item  # type: ignore[assignment]
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        env_f = _env_file_finding(path, str(rel))
        if env_f:
            findings.append(env_f)
        for f in scan_text(text, str(rel)):
            findings.append(f)
    return findings, stats


def scan_git_history(root: Path) -> tuple[list[Finding], dict]:
    """Run `git log -p` and scan each commit's diff for secrets."""
    findings: list[Finding] = []
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "log", "--all", "-p", "--full-history"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("git not found in PATH")
    if result.returncode != 0:
        raise RuntimeError(f"git failed: {result.stderr.strip()}")
    current_commit = "unknown"
    current_file = "unknown"
    for raw_line in result.stdout.splitlines():
        if raw_line.startswith("commit "):
            current_commit = raw_line.split(maxsplit=1)[1][:10]
            continue
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            continue
        # Only scan added lines (start with '+', not '+++').
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            content = raw_line[1:]
            for f in scan_text(content, f"{current_commit}:{current_file}"):
                # The line_number from scan_text is bogus here (single-line context);
                # set to None.
                f.line_number = None
                findings.append(f)
    return findings, {}


_SEV_COLOR = {
    "critical": "\033[91m",
    "high":     "\033[31m",
    "medium":   "\033[33m",
    "low":      "\033[36m",
    "info":     "\033[37m",
}
_RESET = "\033[0m"


def _sev_label(sev: str, lang: str, tty: bool) -> str:
    L = LABELS[lang]
    key = f"sev_{sev}"
    text = L.get(key, sev.upper())
    if tty:
        return f"{_SEV_COLOR.get(sev, '')}{text}{_RESET}"
    return text


def print_human(findings: list[Finding], stats: dict, mode_label: str, lang: str) -> None:
    L = LABELS[lang]
    tty = sys.stdout.isatty()
    print(f"\n{L['scanning']}: {mode_label}\n")
    warn = f"\033[33m{L['warning_false_positives']}{_RESET}" if tty else L["warning_false_positives"]
    print(f"{warn}\n")

    if not findings:
        print(f"  {L['no_findings']}\n")
    else:
        # Group by severity first, then by pattern_name within each tier.
        by_sev: dict[str, dict[str, list[Finding]]] = {s: {} for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_sev else "medium"
            by_sev[sev].setdefault(f.pattern_name, []).append(f)

        print(f"{L['findings']} ({len(findings)}):\n")
        for sev in SEVERITY_ORDER:
            patterns = by_sev[sev]
            if not patterns:
                continue
            sev_count = sum(len(g) for g in patterns.values())
            print(f"  [{_sev_label(sev, lang, tty)}]  ({sev_count})")
            for name, group in patterns.items():
                desc = group[0].description
                print(f"    [{name}]  {desc}  ({len(group)})")
                for f in group[:15]:
                    loc = f"{f.location}:{f.line_number}" if f.line_number else f.location
                    print(f"      {loc}")
                    print(f"        {f.preview}")
                if len(group) > 15:
                    print(f"      ... ({len(group) - 15} more)")
            print()

    if stats:
        print(f"{L['summary']}: {stats.get('scanned', 0)} {L['files_scanned']}, "
              f"{stats.get('skipped_binary', 0)} {L['files_skipped_binary']}, "
              f"{stats.get('skipped_size', 0)} {L['files_skipped_size']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan filesystem or git history for committed secrets.")
    add_version_arg(parser, "secrets_scan.py")
    parser.add_argument("--path", default=".", help="Directory to scan (default: current dir)")
    parser.add_argument("--git-history", action="store_true",
                        help="Scan git log -p (all commits) instead of the working tree")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    L = LABELS[args.lang]

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"{L['err_path']}: {args.path!r}", file=sys.stderr)
        return 2

    if args.git_history:
        if not (root / ".git").exists():
            print(f"{L['err_not_git']}: {root}", file=sys.stderr)
            return 2
        try:
            findings, stats = scan_git_history(root)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
        mode_label = f"{L['mode_git']} ({root})"
    else:
        findings, stats = scan_filesystem(root)
        mode_label = f"{L['mode_path']} ({root})"

    if args.json:
        out = {
            "mode": "git-history" if args.git_history else "filesystem",
            "root": str(root),
            "lang": args.lang,
            "stats": stats,
            "findings": [asdict(f) for f in findings],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(findings, stats, mode_label, args.lang)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
