#!/usr/bin/env python3
"""Crack XOR-encrypted ciphertext using frequency analysis.

Supports single-byte XOR (brute-force all 256 keys) and multi-byte XOR
(key-length detection via Index of Coincidence, then per-byte brute-force).
Input is hex-encoded by default; use --raw for binary stdin.

Examples:
    tools/xor_crack.py 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
    echo "1b37..." | tools/xor_crack.py -
    tools/xor_crack.py <hex> --key-len 3
    tools/xor_crack.py <hex> --key 6b6579
    cat cipher.bin | tools/xor_crack.py - --raw
    tools/xor_crack.py <hex> --lang pt
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from _lib import add_version_arg

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "single_header": "Single-byte XOR — top candidates",
        "multi_header": "Multi-byte XOR",
        "keylen_header": "Key length detection (Index of Coincidence)",
        "key_label": "Key",
        "plaintext_label": "Plaintext",
        "score_label": "score",
        "ic_label": "avg IC",
        "best_label": "best",
        "known_key_header": "Decrypt with key",
        "err_hex": "error: input is not valid hex",
        "err_empty": "error: empty input",
        "err_keylen": "error: --key-len must be >= 1",
        "err_key": "error: --key is not valid hex",
        "err_stdin": "error: stdin is empty",
        "note_multibyte": "Solving each byte independently assuming English plaintext.",
        "note_low_ic": "IC values are low — ciphertext may not be English or key length is > {}.",
    },
    "pt": {
        "single_header": "XOR de byte único — melhores candidatos",
        "multi_header": "XOR multi-byte",
        "keylen_header": "Deteção de tamanho de chave (Índice de Coincidência)",
        "key_label": "Chave",
        "plaintext_label": "Texto claro",
        "score_label": "pontuação",
        "ic_label": "IC médio",
        "best_label": "melhor",
        "known_key_header": "Desencriptar com chave",
        "err_hex": "erro: a entrada não é hex válido",
        "err_empty": "erro: entrada vazia",
        "err_keylen": "erro: --key-len tem de ser >= 1",
        "err_key": "erro: --key não é hex válido",
        "err_stdin": "erro: stdin está vazio",
        "note_multibyte": "A resolver cada byte independentemente assumindo texto em inglês.",
        "note_low_ic": "Valores de IC baixos — o texto cifrado pode não ser inglês ou a chave tem comprimento > {}.",
    },
}

# Letter + space frequencies for English scoring
_FREQ: dict[int, float] = {
    ord(c): v for c, v in zip(
        " etaoinshrdlcumwfgypbvkjxqz",
        [13.0, 12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3,
         4.0, 2.8, 2.8, 2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.5,
         1.0, 0.8, 0.2, 0.2, 0.1, 0.1],
    )
}


def score_english(data: bytes) -> float:
    """Score bytes by English letter frequency. Higher = more English-like."""
    if not data:
        return 0.0
    total = 0.0
    for b in data:
        lower = b | 0x20  # lowercase letters and space map to themselves
        total += _FREQ.get(lower, -1.0 if b < 32 or b > 126 else -0.2)
    return total / len(data)


def index_of_coincidence(data: bytes) -> float:
    """IC ≈ 0.065 for English, ≈ 0.038 for random."""
    n = len(data)
    if n < 2:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def guess_key_lengths(data: bytes, max_len: int) -> list:
    """Return [(key_len, avg_ic), ...] sorted by descending avg IC."""
    results = []
    for klen in range(1, min(max_len + 1, len(data) // 2 + 1)):
        groups = [data[i::klen] for i in range(klen)]
        avg_ic = sum(index_of_coincidence(g) for g in groups) / klen
        results.append((klen, avg_ic))
    return sorted(results, key=lambda x: -x[1])


def crack_single_byte(data: bytes) -> list:
    """Return [(key_byte, score, plaintext), ...] sorted by descending score."""
    candidates = []
    for k in range(256):
        plaintext = bytes(b ^ k for b in data)
        s = score_english(plaintext)
        candidates.append((k, s, plaintext))
    return sorted(candidates, key=lambda x: -x[1])


def crack_multibyte(data: bytes, key_len: int) -> tuple:
    """Return (key_bytes, plaintext)."""
    key = bytearray()
    for i in range(key_len):
        group = data[i::key_len]
        best_k = max(range(256), key=lambda k: score_english(bytes(b ^ k for b in group)))
        key.append(best_k)
    plaintext = bytes(data[i] ^ key[i % key_len] for i in range(len(data)))
    return bytes(key), plaintext


def xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def _safe_str(data: bytes, max_len: int = 80) -> str:
    """Best-effort UTF-8 decode, replacing non-printable bytes with dots."""
    out = []
    for b in data[:max_len]:
        if 32 <= b <= 126:
            out.append(chr(b))
        else:
            out.append("·")
    suffix = "..." if len(data) > max_len else ""
    return "".join(out) + suffix


def print_human(args, data: bytes, lang: str) -> None:
    L = LABELS[lang]

    if args.key:
        key = bytes.fromhex(args.key)
        plaintext = xor_with_key(data, key)
        key_ascii = _safe_str(key, 32)
        print(f"\n{L['known_key_header']}: {args.key} ('{key_ascii}')")
        print(f"{L['plaintext_label']}: {_safe_str(plaintext)}")
        print(f"(hex: {plaintext.hex()})\n")
        return

    if args.key_len is not None:
        klen = args.key_len
        ic_ranked = guess_key_lengths(data, klen)
        key, plaintext = crack_multibyte(data, klen)
        print(f"\n{L['multi_header']}  (key length: {klen})")
        print(f"{L['note_multibyte']}")
        print(f"\n{L['key_label']}: {key.hex()} ('{_safe_str(key, 32)}')")
        print(f"{L['plaintext_label']}: {_safe_str(plaintext)}")
        print(f"(hex: {plaintext[:64].hex()}{'...' if len(plaintext) > 64 else ''})\n")
        return

    # Auto-detect: try single-byte first
    if len(data) <= 60:
        # Short data — just brute-force single-byte
        candidates = crack_single_byte(data)
        top = candidates[:args.top]
        print(f"\n{L['single_header']} ({len(data)} bytes):\n")
        for k, s, pt in top:
            char = chr(k) if 32 <= k <= 126 else "·"
            print(f"  0x{k:02x} ('{char}')  {L['score_label']} {s:+.2f}  :  {_safe_str(pt)}")
        print()
        return

    # Longer data — run IC to detect key length, then solve
    ic_ranked = guess_key_lengths(data, args.max_len)
    print(f"\n{L['keylen_header']}:\n")
    english_ic = 0.065
    low_ic = True
    for klen, ic in ic_ranked[:8]:
        marker = f"  ← {L['best_label']}" if klen == ic_ranked[0][0] else ""
        print(f"  length {klen:>2}:  {L['ic_label']} {ic:.4f}{marker}")
        if ic > 0.050:
            low_ic = False

    if low_ic:
        print(f"\n  ! {L['note_low_ic'].format(args.max_len)}")

    best_klen = ic_ranked[0][0]
    if best_klen == 1:
        candidates = crack_single_byte(data)
        top = candidates[:args.top]
        print(f"\n{L['single_header']} ({len(data)} bytes):\n")
        for k, s, pt in top:
            char = chr(k) if 32 <= k <= 126 else "·"
            print(f"  0x{k:02x} ('{char}')  {L['score_label']} {s:+.2f}  :  {_safe_str(pt)}")
    else:
        key, plaintext = crack_multibyte(data, best_klen)
        print(f"\n{L['multi_header']}  (key length: {best_klen})")
        print(f"{L['note_multibyte']}")
        print(f"\n{L['key_label']}: {key.hex()} ('{_safe_str(key, 32)}')")
        print(f"{L['plaintext_label']}: {_safe_str(plaintext)}")
        print(f"(hex: {plaintext[:64].hex()}{'...' if len(plaintext) > 64 else ''})")

        # Also show top single-byte candidates as fallback
        print(f"\n{L['single_header']} (fallback):\n")
        for k, s, pt in crack_single_byte(data)[:3]:
            char = chr(k) if 32 <= k <= 126 else "·"
            print(f"  0x{k:02x} ('{char}')  {L['score_label']} {s:+.2f}  :  {_safe_str(pt)}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crack XOR-encrypted ciphertext via frequency analysis.",
    )
    add_version_arg(parser, "xor_crack.py")
    parser.add_argument("data", help="Hex-encoded ciphertext. Use '-' to read from stdin.")
    parser.add_argument("--raw", action="store_true",
                        help="Read raw bytes from stdin (use with '-').")
    parser.add_argument("--key-len", type=int, metavar="N",
                        help="Force key length N (skip auto-detection).")
    parser.add_argument("--max-len", type=int, default=16, metavar="N",
                        help="Max key length to consider for auto-detection (default: 16).")
    parser.add_argument("--top", type=int, default=5,
                        help="Number of top candidates to show for single-byte (default: 5).")
    parser.add_argument("--key", metavar="HEX",
                        help="Decrypt with a known key (hex) — skip cracking.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    L = LABELS[args.lang]

    # Validate options
    if args.key_len is not None and args.key_len < 1:
        print(L["err_keylen"], file=sys.stderr)
        return 2
    if args.key is not None:
        try:
            bytes.fromhex(args.key)
        except ValueError:
            print(L["err_key"], file=sys.stderr)
            return 2

    # Read input
    if args.data == "-":
        raw_input = sys.stdin.buffer.read() if args.raw else sys.stdin.readline().strip().encode()
        if not raw_input:
            print(L["err_stdin"], file=sys.stderr)
            return 2
        if args.raw:
            data = raw_input
        else:
            try:
                data = bytes.fromhex(raw_input.decode().strip())
            except ValueError:
                print(L["err_hex"], file=sys.stderr)
                return 2
    else:
        try:
            data = bytes.fromhex(args.data.strip())
        except ValueError:
            print(L["err_hex"], file=sys.stderr)
            return 2

    if not data:
        print(L["err_empty"], file=sys.stderr)
        return 2

    if args.json:
        out: dict = {"lang": args.lang, "input_len": len(data)}
        if args.key:
            key = bytes.fromhex(args.key)
            pt = xor_with_key(data, key)
            out["mode"] = "known_key"
            out["key"] = args.key
            out["plaintext_hex"] = pt.hex()
            out["plaintext_ascii"] = _safe_str(pt, 200)
        elif args.key_len is not None:
            key, pt = crack_multibyte(data, args.key_len)
            out["mode"] = "multibyte"
            out["key_len"] = args.key_len
            out["key"] = key.hex()
            out["plaintext_hex"] = pt.hex()
            out["plaintext_ascii"] = _safe_str(pt, 200)
        else:
            candidates = crack_single_byte(data)
            out["mode"] = "single_byte"
            out["candidates"] = [
                {"key": f"{k:02x}", "score": round(s, 4), "plaintext": _safe_str(pt, 200)}
                for k, s, pt in candidates[:args.top]
            ]
            if len(data) > 60:
                ic_ranked = guess_key_lengths(data, args.max_len)
                out["ic_ranking"] = [
                    {"key_len": kl, "avg_ic": round(ic, 4)} for kl, ic in ic_ranked[:8]
                ]
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(args, data, args.lang)

    return 0


if __name__ == "__main__":
    sys.exit(main())
