#!/usr/bin/env python3
"""Identify the likely type(s) of a hash string by structure.

Examples:
    tools/hashid.py 5f4dcc3b5aa765d61d8327deb882cf99
    tools/hashid.py '$2b$12$KIXp...DfwdU' --lang pt
    echo "098f6bcd4621d373cade4e832627b4f6" | tools/hashid.py -
    tools/hashid.py 5f4dcc3b5aa765d61d8327deb882cf99 --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass

from _lib import add_version_arg

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "input": "Input",
        "length": "length",
        "candidates": "Possible hash types",
        "no_match": "No known hash type matched the input structure.",
        "confidence_high": "high",
        "confidence_medium": "medium",
        "confidence_low": "low",
        "tip": "Tip: same length doesn't mean same type. Treat results as candidates, not certainties.",
        "err_empty": "error: input is empty",
        "err_stdin": "error: could not read from stdin",
    },
    "pt": {
        "input": "Entrada",
        "length": "tamanho",
        "candidates": "Tipos de hash possíveis",
        "no_match": "Nenhum tipo de hash conhecido corresponde à estrutura da entrada.",
        "confidence_high": "alta",
        "confidence_medium": "média",
        "confidence_low": "baixa",
        "tip": "Dica: mesmo tamanho não significa mesmo tipo. Trata os resultados como candidatos, não certezas.",
        "err_empty": "erro: entrada vazia",
        "err_stdin": "erro: falha a ler do stdin",
    },
}

# Confidence levels
HIGH = "high"
MEDIUM = "medium"
LOW = "low"


@dataclass
class HashCandidate:
    name: str
    confidence: str
    hashcat_mode: str = ""
    note_en: str = ""
    note_pt: str = ""


# Each entry: (regex, name, confidence, hashcat_mode, note_en, note_pt)
# Order matters — more specific patterns first so they're tried first.
SIGNATURES = [
    # Modern algorithms with distinctive prefixes
    (r"^\$argon2(?:i|d|id)\$.+\$.+\$.+$", "Argon2", HIGH, "—",
     "Modern memory-hard KDF, widely considered the gold standard.",
     "KDF moderno, memory-hard — atualmente considerado o estado da arte."),
    (r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", HIGH, "3200",
     "Classic password-hashing function. Cost factor in the second segment.",
     "Função clássica de hashing de palavras-passe. Cost factor no segundo segmento."),
    (r"^\$scrypt\$.+$", "scrypt", HIGH, "8900",
     "Memory-hard KDF; common in cryptocurrency wallets.",
     "KDF memory-hard; comum em carteiras de criptomoedas."),
    (r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "MD5 crypt ($1$)", HIGH, "500",
     "Old Unix MD5-based password hash. Considered weak today.",
     "Hash MD5-based clássico do Unix. Considerado fraco hoje."),
    (r"^\$5\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$", "SHA-256 crypt ($5$)", HIGH, "7400",
     "Unix SHA-256 password hash.", "Hash SHA-256 do Unix."),
    (r"^\$6\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$", "SHA-512 crypt ($6$)", HIGH, "1800",
     "Unix SHA-512 password hash (default on modern Linux).",
     "Hash SHA-512 do Unix (predefinido no Linux moderno)."),
    (r"^\$y\$.+\$.+\$.+$", "yescrypt", HIGH, "—",
     "Modern Unix password hash, default on some recent distros.",
     "Hash de palavra-passe Unix moderno, predefinido em algumas distros recentes."),
    (r"^\$P\$[./A-Za-z0-9]{31}$", "phpass (WordPress)", HIGH, "400",
     "Used by WordPress, phpBB.", "Usado por WordPress, phpBB."),
    (r"^\$H\$[./A-Za-z0-9]{31}$", "phpass (vBulletin/older WP)", HIGH, "400", "", ""),
    (r"^\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$", "MD5 (Apache APR1)", HIGH, "1600",
     "Used in htpasswd files.", "Usado em ficheiros htpasswd."),

    # JWT — has a distinctive 3-part dot-separated base64url structure
    (r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$", "JSON Web Token (JWT)", HIGH, "—",
     "Not a hash — but commonly mistaken for one. Use tools/jwt_inspect.py.",
     "Não é um hash — mas é frequentemente confundido. Usa tools/jwt_inspect.py."),

    # MySQL
    (r"^\*[A-F0-9]{40}$", "MySQL 4.1+ SHA1", HIGH, "300",
     "MySQL password hash, starts with '*'.",
     "Hash de palavra-passe do MySQL, começa por '*'."),
    (r"^[a-fA-F0-9]{16}$", "MySQL <4.1 / DES-based / LM half / CRC-64", MEDIUM, "200",
     "16 hex chars — many candidates; context matters.",
     "16 chars hex — vários candidatos; o contexto interessa."),

    # NTLM / NetNTLM family
    (r"^[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}$", "LM:NTLM (PWDump format)", HIGH, "1000",
     "Format from pwdump and similar.", "Formato do pwdump e similares."),

    # Length-based generics — lower confidence, listed late
    (r"^[a-fA-F0-9]{32}$", "MD5 / NTLM / MD4 / LM", MEDIUM, "0 / 1000",
     "32 hex chars — MD5 is the classic guess but NTLM and MD4 share the length.",
     "32 chars hex — MD5 é o palpite clássico, mas NTLM e MD4 têm o mesmo tamanho."),
    (r"^[a-fA-F0-9]{40}$", "SHA-1 / RIPEMD-160", MEDIUM, "100",
     "40 hex chars.", "40 chars hex."),
    (r"^[a-fA-F0-9]{56}$", "SHA-224 / Keccak-224", LOW, "1300",
     "56 hex chars.", "56 chars hex."),
    (r"^[a-fA-F0-9]{64}$", "SHA-256 / SHA3-256 / BLAKE2s / Keccak-256", MEDIUM, "1400",
     "64 hex chars — SHA-256 is the most common.",
     "64 chars hex — SHA-256 é o mais comum."),
    (r"^[a-fA-F0-9]{96}$", "SHA-384 / Keccak-384", LOW, "10800",
     "96 hex chars.", "96 chars hex."),
    (r"^[a-fA-F0-9]{128}$", "SHA-512 / SHA3-512 / BLAKE2b / Whirlpool", MEDIUM, "1700",
     "128 hex chars.", "128 chars hex."),

    # Base64-encoded
    (r"^[A-Za-z0-9+/]{27}=$", "Base64-encoded SHA-1 (e.g. LDAP {SHA})", LOW, "111",
     "Common as LDAP {SHA} prefix value.",
     "Frequente como valor do prefixo LDAP {SHA}."),
    (r"^[A-Za-z0-9+/]{43}=$", "Base64-encoded SHA-256", LOW, "—", "", ""),
    (r"^[A-Za-z0-9+/]{86}==$", "Base64-encoded SHA-512", LOW, "—", "", ""),

    # CRC and other shorts
    (r"^[a-fA-F0-9]{8}$", "CRC32 / FCS-32 / Adler-32", LOW, "11500",
     "8 hex chars — likely a checksum, not a cryptographic hash.",
     "8 chars hex — provavelmente um checksum, não um hash criptográfico."),
]


def identify(text: str) -> list[HashCandidate]:
    candidates: list[HashCandidate] = []
    for pattern, name, confidence, hashcat, note_en, note_pt in SIGNATURES:
        if re.fullmatch(pattern, text):
            candidates.append(HashCandidate(
                name=name, confidence=confidence, hashcat_mode=hashcat,
                note_en=note_en, note_pt=note_pt,
            ))
    # Sort: higher confidence first
    rank = {HIGH: 0, MEDIUM: 1, LOW: 2}
    candidates.sort(key=lambda c: rank[c.confidence])
    return candidates


def print_human(text: str, candidates: list[HashCandidate], lang: str) -> None:
    L = LABELS[lang]
    conf_map = {HIGH: L["confidence_high"], MEDIUM: L["confidence_medium"], LOW: L["confidence_low"]}
    print(f"\n{L['input']}: {text}")
    print(f"  ({L['length']}: {len(text)})\n")

    if not candidates:
        print(f"  {L['no_match']}\n")
        return

    print(f"{L['candidates']}:")
    name_width = max(len(c.name) for c in candidates)
    for c in candidates:
        confidence_label = conf_map[c.confidence]
        hashcat = f"hashcat: {c.hashcat_mode}" if c.hashcat_mode else ""
        print(f"  • {c.name:<{name_width}}  [{confidence_label}]  {hashcat}")
        note = c.note_pt if lang == "pt" else c.note_en
        if note:
            print(f"      {note}")
    print(f"\n  {L['tip']}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Identify the likely type(s) of a hash string.")
    add_version_arg(parser, "hashid.py")
    parser.add_argument("text", help="Hash string; use '-' for stdin")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    L = LABELS[args.lang]

    if args.text == "-":
        try:
            text = sys.stdin.read().strip()
        except OSError:
            print(L["err_stdin"], file=sys.stderr)
            return 3
    else:
        text = args.text.strip()

    if not text:
        print(L["err_empty"], file=sys.stderr)
        return 2

    candidates = identify(text)

    if args.json:
        out = {
            "input": text,
            "length": len(text),
            "lang": args.lang,
            "candidates": [asdict(c) for c in candidates],
        }
        # Drop the irrelevant-language note from each candidate for cleanliness
        for entry in out["candidates"]:
            other = "note_en" if args.lang == "pt" else "note_pt"
            entry.pop(other, None)
            entry["note"] = entry.pop("note_pt" if args.lang == "pt" else "note_en", "")
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(text, candidates, args.lang)

    return 0 if candidates else 1


if __name__ == "__main__":
    sys.exit(main())
