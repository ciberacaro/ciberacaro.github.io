#!/usr/bin/env python3
"""Analyze password strength and check it against breach databases.

Computes character-set entropy (Shannon-style estimate based on the
classes present), assigns a 0-10 score, and optionally checks the
password against Have I Been Pwned's "pwned passwords" range API using
k-anonymity — only the first 5 SHA-1 hex chars are sent over the wire,
NEVER the full password or its full hash.

Read passwords from stdin (no echo if your terminal supports it) so
they don't end up in shell history.

Examples:
    tools/password_strength.py                  # prompts for password without echo
    tools/password_strength.py --no-breach       # skip the HIBP check
    echo "hunter2" | tools/password_strength.py --stdin
    tools/password_strength.py --stdin --lang pt --json
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import math
import re
import socket
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from _lib import build_ssl_context, make_user_agent, add_version_arg

USER_AGENT = make_user_agent("password_strength.py")
LANGS = ("en", "pt")
HIBP_URL = "https://api.pwnedpasswords.com/range/"

LABELS = {
    "en": {
        "input_prompt": "Password (won't be echoed): ",
        "length": "Length",
        "char_classes": "Character classes",
        "lower": "lowercase",
        "upper": "uppercase",
        "digit": "digit",
        "symbol": "symbol",
        "entropy": "Estimated entropy",
        "bits": "bits",
        "score": "Score",
        "score_label": ("very weak", "weak", "fair", "good", "strong", "excellent"),
        "breach_section": "Have I Been Pwned (k-anonymity check)",
        "breach_hit": "Password appears in known breaches",
        "breach_clean": "Password not found in known breaches",
        "times_seen": "times seen across known breaches",
        "recommendations": "Recommendations",
        "rec_short": "Length < 12 — make it longer; length matters more than class diversity.",
        "rec_classes": "Add more character classes (mix lower, upper, digit, symbol).",
        "rec_breach": "Stop using this password everywhere. If reused on important accounts, rotate them now.",
        "rec_common": "Looks like a common password pattern. Use a passphrase or a generated password.",
        "rec_ok": "Looks solid. Use a password manager + unique passwords per site.",
        "err_empty": "error: empty password",
        "err_breach": "warning: breach check failed",
    },
    "pt": {
        "input_prompt": "Password (não será mostrada): ",
        "length": "Comprimento",
        "char_classes": "Classes de caracteres",
        "lower": "minúsculas",
        "upper": "maiúsculas",
        "digit": "dígitos",
        "symbol": "símbolos",
        "entropy": "Entropia estimada",
        "bits": "bits",
        "score": "Pontuação",
        "score_label": ("muito fraca", "fraca", "razoável", "boa", "forte", "excelente"),
        "breach_section": "Have I Been Pwned (verificação por k-anonymity)",
        "breach_hit": "Password aparece em fugas conhecidas",
        "breach_clean": "Password não foi encontrada em fugas conhecidas",
        "times_seen": "vezes vista em fugas conhecidas",
        "recommendations": "Recomendações",
        "rec_short": "Comprimento < 12 — aumenta-o; comprimento conta mais que diversidade de classes.",
        "rec_classes": "Adiciona mais classes de caracteres (mistura minúsculas, maiúsculas, dígitos, símbolos).",
        "rec_breach": "Deixa de usar esta password em todo o lado. Se a reutilizas em contas importantes, troca-as já.",
        "rec_common": "Parece um padrão comum. Usa uma passphrase ou uma password gerada.",
        "rec_ok": "Parece sólida. Usa um gestor de passwords + passwords únicas por site.",
        "err_empty": "erro: password vazia",
        "err_breach": "aviso: verificação de fugas falhou",
    },
}

# A tiny list of *very* common patterns. Trips a warning regardless of length.
# (Real breach scoring should rely on HIBP, not this list — this is just a heuristic.)
COMMON_PATTERNS = re.compile(
    r"^(?:password|passw0rd|123456|12345678|qwerty|asdfgh|letmein|admin|welcome|"
    r"iloveyou|monkey|dragon|football|baseball|abc123|sunshine|princess|hunter2)\d{0,4}$",
    re.IGNORECASE,
)


@dataclass
class Analysis:
    length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    pool_size: int
    entropy_bits: float
    score: int                    # 0-10
    common_pattern: bool
    breach_count: int = -1        # -1 means "not checked"; 0 means clean
    breach_error: bool = False


def analyze(password: str) -> Analysis:
    if not password:
        return Analysis(0, False, False, False, False, 0, 0.0, 0, False)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^\w]", password))

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += 33  # rough printable-symbol estimate

    entropy = len(password) * math.log2(pool) if pool > 0 else 0.0

    # 0-10 score: composed from entropy bins, with a penalty for common patterns
    if entropy < 28:
        score = 1
    elif entropy < 40:
        score = 3
    elif entropy < 60:
        score = 5
    elif entropy < 80:
        score = 7
    elif entropy < 100:
        score = 9
    else:
        score = 10

    common = bool(COMMON_PATTERNS.fullmatch(password))
    if common:
        score = min(score, 2)
    if len(password) < 8:
        score = min(score, 2)

    return Analysis(
        length=len(password),
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        pool_size=pool,
        entropy_bits=entropy,
        score=score,
        common_pattern=common,
    )


def hibp_check(password: str, timeout: float = 10.0) -> int:
    """Query HIBP's pwned-passwords range API via k-anonymity.

    Only the first 5 hex chars of SHA-1(password) are sent. The API
    returns every known hash that starts with that prefix; we check
    locally whether ours is among them. The full password never leaves
    this process.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        HIBP_URL + prefix,
        headers={
            "User-Agent": USER_AGENT,
            "Add-Padding": "true",  # API recommendation to defeat traffic-size analysis
        },
    )
    ctx = build_ssl_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    for line in body.splitlines():
        if ":" not in line:
            continue
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return 1
    return 0


def score_label(score: int, labels: tuple[str, ...]) -> str:
    """Map 0-10 score onto the L['score_label'] tuple (6 buckets)."""
    if score <= 2:
        return labels[0]
    if score <= 4:
        return labels[1]
    if score <= 6:
        return labels[2]
    if score <= 7:
        return labels[3]
    if score <= 9:
        return labels[4]
    return labels[5]


def recommendations(a: Analysis, lang: str) -> list[str]:
    L = LABELS[lang]
    out = []
    if a.length < 12:
        out.append(L["rec_short"])
    classes = sum([a.has_lower, a.has_upper, a.has_digit, a.has_symbol])
    if classes < 3:
        out.append(L["rec_classes"])
    if a.common_pattern:
        out.append(L["rec_common"])
    if a.breach_count > 0:
        out.append(L["rec_breach"])
    if not out:
        out.append(L["rec_ok"])
    return out


def print_human(a: Analysis, lang: str) -> None:
    L = LABELS[lang]
    print()
    print(f"  {L['length']}:      {a.length}")
    classes = []
    if a.has_lower:
        classes.append(L["lower"])
    if a.has_upper:
        classes.append(L["upper"])
    if a.has_digit:
        classes.append(L["digit"])
    if a.has_symbol:
        classes.append(L["symbol"])
    print(f"  {L['char_classes']}: " + (", ".join(classes) if classes else "—"))
    print(f"  {L['entropy']}:    {a.entropy_bits:.1f} {L['bits']}  (pool={a.pool_size})")
    label = score_label(a.score, L["score_label"])
    print(f"  {L['score']}:       {a.score}/10  ({label})")

    if a.breach_count >= 0:
        print()
        print(f"  {L['breach_section']}:")
        if a.breach_count == 0:
            print(f"    ✓ {L['breach_clean']}")
        else:
            print(f"    ✗ {L['breach_hit']}: {a.breach_count} {L['times_seen']}")
    elif a.breach_error:
        print()
        print(f"  {L['err_breach']}")

    print()
    print(f"  {L['recommendations']}:")
    for rec in recommendations(a, lang):
        print(f"    - {rec}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Password strength + Have I Been Pwned check (k-anonymity).",
    )
    add_version_arg(parser, "password_strength.py")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--stdin", action="store_true",
                        help="Read password from stdin instead of prompting (no echo).")
    parser.add_argument("--no-breach", action="store_true", help="Skip the HIBP check.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    L = LABELS[args.lang]

    if args.stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass(L["input_prompt"])

    if not password:
        print(L["err_empty"], file=sys.stderr)
        return 2

    analysis = analyze(password)
    if not args.no_breach:
        try:
            analysis.breach_count = hibp_check(password, timeout=args.timeout)
        except (urllib.error.URLError, socket.timeout, ValueError) as e:
            analysis.breach_error = True
            print(f"{L['err_breach']}: {e}", file=sys.stderr)

    if args.json:
        out = asdict(analysis)
        out["lang"] = args.lang
        # Do NOT echo the password back in JSON output.
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(analysis, args.lang)

    return 1 if (analysis.score < 5 or analysis.breach_count > 0) else 0


if __name__ == "__main__":
    sys.exit(main())
