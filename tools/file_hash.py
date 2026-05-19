#!/usr/bin/env python3
"""Compute forensic file hashes (chain-of-custody) with streaming I/O.

Examples:
    tools/file_hash.py evidence.bin
    tools/file_hash.py evidence.bin --algos sha256,sha512 --lang pt
    tools/file_hash.py evidence.bin --verify 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    tools/file_hash.py *.bin --save manifest.txt
    tools/file_hash.py --check manifest.txt
    cat evidence.bin | tools/file_hash.py - --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from _lib import add_version_arg, stdin_or_arg

LANGS = ("en", "pt")
CHUNK_SIZE = 65536
DEFAULT_ALGOS = ["md5", "sha1", "sha256", "sha512"]
STDIN_LABEL = "<stdin>"

LABELS = {
    "en": {
        "file": "File",
        "size": "Size",
        "bytes": "bytes",
        "algorithm": "Algorithm",
        "expected": "Expected",
        "computed": "Computed",
        "result": "Result",
        "match": "✓ MATCH",
        "mismatch": "✗ MISMATCH",
        "manifest_saved": "Manifest saved",
        "files": "files",
        "summary": "Summary",
        "ok": "OK",
        "mismatch_word": "mismatch",
        "missing": "missing",
        "not_found": "FILE NOT FOUND",
        "mismatch_detail": "MISMATCH",
        "manifest": "Manifest",
        "err_no_file": "error: file not found",
        "err_invalid_algo": "error: invalid algorithm",
        "err_available_algos": "available algorithms",
        "err_io": "error: could not read file",
        "err_verify_one_file": "error: --verify only accepts one file",
        "err_check_no_files": "error: --check does not accept positional file arguments",
        "err_manifest_empty": "error: manifest file is empty or has no valid entries",
        "err_manifest_read": "error: could not read manifest",
        "err_unknown_algo_len": "could not infer algorithm from hash length",
        "expected_got": "expected {exp}, got {got}",
    },
    "pt": {
        "file": "Ficheiro",
        "size": "Tamanho",
        "bytes": "bytes",
        "algorithm": "Algoritmo",
        "expected": "Esperado",
        "computed": "Calculado",
        "result": "Resultado",
        "match": "✓ CORRESPONDE",
        "mismatch": "✗ NÃO CORRESPONDE",
        "manifest_saved": "Manifesto guardado",
        "files": "ficheiros",
        "summary": "Sumário",
        "ok": "OK",
        "mismatch_word": "incorreto",
        "missing": "em falta",
        "not_found": "FICHEIRO NÃO ENCONTRADO",
        "mismatch_detail": "INCORRETO",
        "manifest": "Manifesto",
        "err_no_file": "erro: ficheiro não encontrado",
        "err_invalid_algo": "erro: algoritmo inválido",
        "err_available_algos": "algoritmos disponíveis",
        "err_io": "erro: falha a ler o ficheiro",
        "err_verify_one_file": "erro: --verify só aceita um ficheiro",
        "err_check_no_files": "erro: --check não aceita argumentos posicionais",
        "err_manifest_empty": "erro: manifesto vazio ou sem entradas válidas",
        "err_manifest_read": "erro: falha a ler o manifesto",
        "err_unknown_algo_len": "não foi possível inferir o algoritmo pelo tamanho do hash",
        "expected_got": "esperado {exp}, obtido {got}",
    },
}

PRETTY_NAMES = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "sha224": "SHA-224",
    "sha384": "SHA-384",
}

SUPPORTED_ALGOS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                   "sha3_256", "sha3_512", "blake2b", "blake2s")

LENGTH_TO_ALGO = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}


@dataclass
class FileHashResult:
    path: str
    size: int
    hashes: dict = field(default_factory=dict)


def format_size(bytes_value: int) -> str:
    if bytes_value < 1024:
        return f"{bytes_value} bytes"
    units = ("KiB", "MiB", "GiB", "TiB", "PiB")
    value = float(bytes_value)
    for unit in units:
        value /= 1024.0
        if value < 1024.0:
            return f"{value:.2f} {unit}"
    return f"{value:.2f} EiB"


def pretty_algo(algo: str) -> str:
    return PRETTY_NAMES.get(algo, algo.upper())


def parse_algos(spec: str, lang: str) -> list[str]:
    L = LABELS[lang]
    algos = [a.strip().lower() for a in spec.split(",") if a.strip()]
    if not algos:
        print(f"{L['err_invalid_algo']}: empty", file=sys.stderr)
        sys.exit(2)
    for a in algos:
        try:
            hashlib.new(a)
        except (ValueError, TypeError):
            available = ", ".join(SUPPORTED_ALGOS)
            print(f"{L['err_invalid_algo']}: {a!r} ({L['err_available_algos']}: {available})",
                  file=sys.stderr)
            sys.exit(2)
    return algos


def hash_stream(stream, algos: list[str]) -> tuple[dict, int]:
    hashers = {a: hashlib.new(a) for a in algos}
    total = 0
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        for h in hashers.values():
            h.update(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}, total


def hash_file(path: str, algos: list[str], lang: str) -> FileHashResult:
    L = LABELS[lang]
    if path == "-":
        hashes, size = hash_stream(sys.stdin.buffer, algos)
        return FileHashResult(path=STDIN_LABEL, size=size, hashes=hashes)
    if not os.path.exists(path):
        print(f"{L['err_no_file']}: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        with open(path, "rb") as f:
            hashes, size = hash_stream(f, algos)
    except OSError as e:
        print(f"{L['err_io']}: {path} ({e})", file=sys.stderr)
        sys.exit(2)
    return FileHashResult(path=path, size=size, hashes=hashes)


def print_file_human(result: FileHashResult, algos: list[str], lang: str) -> None:
    L = LABELS[lang]
    print(f"{L['file']}: {result.path}")
    if result.size >= 1024:
        print(f"{L['size']}: {result.size:,} {L['bytes']} ({format_size(result.size)})")
    else:
        print(f"{L['size']}: {result.size:,} {L['bytes']}")
    print()
    name_width = max(len(pretty_algo(a)) for a in algos) + 1
    for a in algos:
        label = pretty_algo(a) + ":"
        print(f"  {label:<{name_width + 1}} {result.hashes[a]}")


def cmd_default(results: list[FileHashResult], algos: list[str], lang: str, as_json: bool) -> int:
    if as_json:
        out = {
            "lang": lang,
            "algorithms": algos,
            "files": [
                {"path": r.path, "size": r.size, "hashes": r.hashes}
                for r in results
            ],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    for i, r in enumerate(results):
        if i > 0:
            print()
        print_file_human(r, algos, lang)
    return 0


def cmd_verify(result: FileHashResult, expected: str, algo: str,
               lang: str, as_json: bool) -> int:
    L = LABELS[lang]
    computed = result.hashes[algo]
    expected_norm = expected.strip().lower()
    match = computed.lower() == expected_norm
    if as_json:
        out = {
            "lang": lang,
            "verification": {
                "path": result.path,
                "size": result.size,
                "algorithm": algo,
                "expected": expected_norm,
                "computed": computed,
                "match": match,
            },
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{L['file']}: {result.path}")
        print(f"{L['algorithm']}: {algo}")
        print(f"{L['expected']}: {expected_norm}")
        print(f"{L['computed']}: {computed}")
        print(f"{L['result']}: {L['match'] if match else L['mismatch']}")
    return 0 if match else 1


def cmd_save(results: list[FileHashResult], algo: str, save_path: str,
             lang: str, as_json: bool) -> int:
    L = LABELS[lang]
    lines = []
    entries = []
    for r in results:
        name = r.path if r.path != STDIN_LABEL else "-"
        lines.append(f"{r.hashes[algo]}  {name}\n")
        entries.append({"path": name, "hash": r.hashes[algo], "size": r.size})
    try:
        with open(save_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except OSError as e:
        print(f"{L['err_io']}: {save_path} ({e})", file=sys.stderr)
        return 2
    if as_json:
        out = {
            "lang": lang,
            "manifest": {
                "path": save_path,
                "algorithm": algo,
                "entries": entries,
            },
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{L['manifest_saved']}: {save_path} ({len(results)} {L['files']}, {algo})")
    return 0


def parse_manifest(path: str, lang: str) -> tuple[str, list[tuple[str, str]]]:
    L = LABELS[lang]
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.readlines()
    except OSError as e:
        print(f"{L['err_manifest_read']}: {path} ({e})", file=sys.stderr)
        sys.exit(2)
    entries: list[tuple[str, str]] = []
    algo: Optional[str] = None
    for line in raw:
        line = line.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        hash_val, filename = parts[0], parts[1].lstrip()
        # GNU coreutils prefixes filenames with '*' for binary mode and '\' for
        # filenames containing backslashes/newlines. Strip those markers.
        if filename.startswith("*"):
            filename = filename[1:]
        hash_val = hash_val.lower()
        if not all(c in "0123456789abcdef" for c in hash_val):
            continue
        if algo is None:
            algo = LENGTH_TO_ALGO.get(len(hash_val))
            if algo is None:
                print(f"{L['err_manifest_read']}: {L['err_unknown_algo_len']} "
                      f"({len(hash_val)})", file=sys.stderr)
                sys.exit(2)
        entries.append((hash_val, filename))
    if not entries:
        print(f"{L['err_manifest_empty']}: {path}", file=sys.stderr)
        sys.exit(2)
    return algo, entries


def cmd_check(manifest_path: str, lang: str, as_json: bool) -> int:
    L = LABELS[lang]
    algo, entries = parse_manifest(manifest_path, lang)
    base_dir = os.path.dirname(os.path.abspath(manifest_path))
    ok_count = 0
    mismatch_count = 0
    missing_count = 0
    rows = []
    for expected_hash, filename in entries:
        resolved = filename if os.path.isabs(filename) else os.path.join(base_dir, filename)
        if not os.path.exists(resolved) and os.path.exists(filename):
            resolved = filename
        if not os.path.exists(resolved):
            missing_count += 1
            rows.append({"path": filename, "status": "missing",
                         "expected": expected_hash, "computed": None})
            continue
        try:
            with open(resolved, "rb") as f:
                hashes, _ = hash_stream(f, [algo])
        except OSError as e:
            missing_count += 1
            rows.append({"path": filename, "status": "missing",
                         "expected": expected_hash, "computed": None, "error": str(e)})
            continue
        computed = hashes[algo]
        if computed == expected_hash:
            ok_count += 1
            rows.append({"path": filename, "status": "ok",
                         "expected": expected_hash, "computed": computed})
        else:
            mismatch_count += 1
            rows.append({"path": filename, "status": "mismatch",
                         "expected": expected_hash, "computed": computed})

    if as_json:
        out = {
            "lang": lang,
            "check": {
                "manifest": manifest_path,
                "algorithm": algo,
                "results": rows,
                "summary": {
                    "ok": ok_count,
                    "mismatch": mismatch_count,
                    "missing": missing_count,
                },
            },
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"{L['manifest']}: {manifest_path} ({L['algorithm'].lower()}: {algo})")
        for row in rows:
            if row["status"] == "ok":
                print(f"  ✓ {row['path']}")
            elif row["status"] == "mismatch":
                exp_short = row["expected"][:6] + "..."
                got_short = row["computed"][:6] + "..."
                detail = L["expected_got"].format(exp=exp_short, got=got_short)
                print(f"  ✗ {row['path']}    [{L['mismatch_detail']} — {detail}]")
            else:
                print(f"  ! {row['path']}    [{L['not_found']}]")
        print()
        print(f"{L['summary']}: {ok_count} {L['ok']}, "
              f"{mismatch_count} {L['mismatch_word']}, "
              f"{missing_count} {L['missing']}")
    return 0 if mismatch_count == 0 and missing_count == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute forensic file hashes (chain-of-custody) with streaming I/O."
    )
    add_version_arg(parser, "file_hash.py")
    parser.add_argument("files", nargs="*",
                        help="File paths; use '-' to read binary data from stdin.")
    parser.add_argument("--algos", default=",".join(DEFAULT_ALGOS),
                        help="Comma-separated list of algorithms "
                             f"(default: {','.join(DEFAULT_ALGOS)}).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", metavar="HASH",
                      help="Compare against this hash (uses the first algo of --algos).")
    mode.add_argument("--save", metavar="FILE",
                      help="Write a sha256sum-style manifest to FILE.")
    mode.add_argument("--check", metavar="FILE",
                      help="Read a manifest and verify each listed file.")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true", help="Output as JSON.")
    args = parser.parse_args()
    L = LABELS[args.lang]

    algos = parse_algos(args.algos, args.lang)

    if args.check:
        if args.files:
            print(L["err_check_no_files"], file=sys.stderr)
            return 2
        return cmd_check(args.check, args.lang, args.json)

    if not args.files:
        parser.print_usage(sys.stderr)
        return 2

    if args.verify and len(args.files) != 1:
        print(L["err_verify_one_file"], file=sys.stderr)
        return 2

    results = [hash_file(p, algos, args.lang) for p in args.files]

    if args.verify:
        return cmd_verify(results[0], args.verify, algos[0], args.lang, args.json)
    if args.save:
        return cmd_save(results, algos[0], args.save, args.lang, args.json)
    return cmd_default(results, algos, args.lang, args.json)


if __name__ == "__main__":
    sys.exit(main())
