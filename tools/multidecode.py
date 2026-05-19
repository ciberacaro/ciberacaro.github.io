#!/usr/bin/env python3
"""Try multiple decodings on a string and report which ones produce readable output.

Examples:
    tools/multidecode.py "SGVsbG8gd29ybGQh"
    tools/multidecode.py "%2Fetc%2Fpasswd" --lang pt
    echo -n "deadbeef" | tools/multidecode.py -
    tools/multidecode.py "VGhlIGJyb3duIGZveA==" --cascade
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import html
import json
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Optional

from _lib import add_version_arg

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "input": "Input",
        "length": "length",
        "results": "Decodings that produced readable output",
        "no_results": "None of the attempted decodings produced readable text.",
        "cascade_header": "Cascade (recursive decoding)",
        "encoding": "Encoding",
        "decoded": "Decoded",
        "depth": "depth",
        "err_empty": "error: input is empty",
        "err_stdin": "error: could not read from stdin",
    },
    "pt": {
        "input": "Entrada",
        "length": "tamanho",
        "results": "Descodificações que produziram texto legível",
        "no_results": "Nenhuma das descodificações tentadas produziu texto legível.",
        "cascade_header": "Cascata (descodificação recursiva)",
        "encoding": "Codificação",
        "decoded": "Descodificado",
        "depth": "profundidade",
        "err_empty": "erro: entrada vazia",
        "err_stdin": "erro: falha a ler do stdin",
    },
}

# A printable result must have at least this proportion of "readable" chars.
# We deliberately count only ASCII printable + common whitespace, NOT extended
# latin-1, so that random-looking decoded bytes don't pass the heuristic.
READABLE_THRESHOLD = 0.9
_READABLE = set(range(32, 127)) | {9, 10, 13}  # printable ASCII + tab/lf/cr


@dataclass
class DecodeResult:
    encoding: str
    decoded: str
    raw: Optional[str] = None  # Raw decoded bytes as repr, if useful


def is_readable(text: str) -> bool:
    """Heuristic: is this text mostly printable ASCII?"""
    if not text:
        return False
    readable = sum(1 for c in text if ord(c) in _READABLE)
    return readable / len(text) >= READABLE_THRESHOLD


def try_base64(s: str) -> Optional[str]:
    s_clean = s.strip()
    # Base64 typically uses A-Z, a-z, 0-9, +, /, = (or -, _ for URL-safe).
    if not re.fullmatch(r"[A-Za-z0-9+/=\-_]+", s_clean):
        return None
    # Try both standard and URL-safe variants. Pad if necessary.
    candidates = [s_clean, s_clean.replace("-", "+").replace("_", "/")]
    for variant in candidates:
        padded = variant + "=" * ((4 - len(variant) % 4) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = decoded.decode("latin-1")
            except UnicodeDecodeError:
                continue
        if is_readable(text):
            return text
    return None


def try_base32(s: str) -> Optional[str]:
    s_clean = s.strip().upper()
    if not re.fullmatch(r"[A-Z2-7=]+", s_clean):
        return None
    padded = s_clean + "=" * ((8 - len(s_clean) % 8) % 8)
    try:
        decoded = base64.b32decode(padded)
    except (binascii.Error, ValueError):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = decoded.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if is_readable(text):
        return text
    return None


def try_hex(s: str) -> Optional[str]:
    s_clean = re.sub(r"\s+", "", s.strip())
    # Strip an optional 0x prefix.
    s_clean = s_clean[2:] if s_clean.lower().startswith("0x") else s_clean
    if not re.fullmatch(r"[0-9a-fA-F]+", s_clean) or len(s_clean) % 2:
        return None
    try:
        decoded = bytes.fromhex(s_clean)
    except ValueError:
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        text = decoded.decode("latin-1", errors="replace")
    if is_readable(text):
        return text
    return None


def try_url(s: str) -> Optional[str]:
    if "%" not in s and "+" not in s:
        return None
    decoded = urllib.parse.unquote_plus(s)
    if decoded == s:
        return None
    if is_readable(decoded):
        return decoded
    return None


def try_rot13(s: str) -> Optional[str]:
    if not any(c.isalpha() for c in s):
        return None
    decoded = codecs.decode(s, "rot_13")
    if decoded == s:
        return None
    # ROT13 always yields readable output for readable input — only useful if it
    # produces dictionary-ish English (we don't have a dict, so we just report it).
    return decoded


def try_html_entities(s: str) -> Optional[str]:
    if "&" not in s:
        return None
    decoded = html.unescape(s)
    if decoded == s:
        return None
    if is_readable(decoded):
        return decoded
    return None


def try_binary_string(s: str) -> Optional[str]:
    """Decode strings like '01001000 01101001' as ASCII."""
    s_clean = re.sub(r"\s+", "", s.strip())
    if not re.fullmatch(r"[01]+", s_clean) or len(s_clean) < 8 or len(s_clean) % 8:
        return None
    try:
        chars = [chr(int(s_clean[i : i + 8], 2)) for i in range(0, len(s_clean), 8)]
        text = "".join(chars)
    except ValueError:
        return None
    if is_readable(text):
        return text
    return None


def try_base85(s: str) -> Optional[str]:
    """Decode RFC 1924 Base85 (Python base64.b85decode alphabet)."""
    s_clean = s.strip()
    if len(s_clean) < 5:
        return None
    try:
        decoded = base64.b85decode(s_clean)
    except (ValueError, binascii.Error):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = decoded.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if is_readable(text):
        return text
    return None


def try_unicode_escapes(s: str) -> Optional[str]:
    r"""Decode \uXXXX, \u{XXXX} (JS-style), and \xXX escape sequences."""
    if not re.search(r"\\[uxU]", s):
        return None
    try:
        result = re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), s)
        result = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), result)
        result = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), result)
    except (ValueError, OverflowError):
        return None
    if result == s:
        return None
    if is_readable(result):
        return result
    return None


DECODERS = (
    ("Base64", try_base64),
    ("Base32", try_base32),
    ("Base85", try_base85),
    ("Hex", try_hex),
    ("URL", try_url),
    ("HTML Entities", try_html_entities),
    ("Unicode Escapes", try_unicode_escapes),
    ("Binary (8-bit)", try_binary_string),
    ("ROT13", try_rot13),
)

# Pre-filtered list used by cascade() — excludes ROT13 (its own inverse, would loop).
CASCADE_DECODERS = [(name, fn) for name, fn in DECODERS if name != "ROT13"]


def attempt_all(s: str) -> list[DecodeResult]:
    results: list[DecodeResult] = []
    for name, fn in DECODERS:
        decoded = fn(s)
        if decoded is not None and decoded != s:
            results.append(DecodeResult(encoding=name, decoded=decoded))
    return results


def cascade(s: str, max_depth: int = 5) -> list[tuple[str, str]]:
    """Repeatedly try to decode until nothing new happens or we hit max_depth."""
    chain: list[tuple[str, str]] = []
    seen = {s}
    current = s
    for _ in range(max_depth):
        next_value = None
        next_name = None
        for name, fn in CASCADE_DECODERS:
            decoded = fn(current)
            if decoded and decoded != current and decoded not in seen:
                next_value = decoded
                next_name = name
                break
        if next_value is None:
            break
        chain.append((next_name, next_value))
        seen.add(next_value)
        current = next_value
    return chain


def print_human(input_str: str, results: list[DecodeResult], cascade_chain, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['input']}: {input_str!r} ({L['length']}: {len(input_str)})\n")

    if results:
        print(f"{L['results']}:\n")
        for r in results:
            preview = r.decoded if len(r.decoded) <= 200 else r.decoded[:197] + "..."
            print(f"  [{r.encoding}]")
            print(f"    {preview!r}")
            print()
    else:
        print(f"  {L['no_results']}\n")

    if cascade_chain:
        print(f"{L['cascade_header']}:\n")
        for i, (enc, decoded) in enumerate(cascade_chain, start=1):
            preview = decoded if len(decoded) <= 200 else decoded[:197] + "..."
            print(f"  [{L['depth']} {i}] {enc} -> {preview!r}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Try multiple decodings (Base64, hex, URL, ROT13, etc.) on a string."
    )
    add_version_arg(parser, "multidecode.py")
    parser.add_argument("text", help="Text to decode; use '-' to read from stdin.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true", help="Output as JSON.")
    parser.add_argument(
        "--cascade",
        action="store_true",
        help="Also try recursive decoding (e.g. Base64-of-Base64).",
    )
    args = parser.parse_args()
    L = LABELS[args.lang]

    if args.text == "-":
        try:
            text = sys.stdin.read().strip()
        except OSError:
            print(L["err_stdin"], file=sys.stderr)
            return 3
    else:
        text = args.text

    if not text:
        print(L["err_empty"], file=sys.stderr)
        return 2

    results = attempt_all(text)
    cascade_chain = cascade(text) if args.cascade else []

    if args.json:
        out = {
            "input": text,
            "lang": args.lang,
            "results": [asdict(r) for r in results],
            "cascade": [{"encoding": e, "decoded": d} for e, d in cascade_chain],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(text, results, cascade_chain, args.lang)

    return 0 if results or cascade_chain else 1


if __name__ == "__main__":
    sys.exit(main())
