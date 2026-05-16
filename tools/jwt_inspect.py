#!/usr/bin/env python3
"""Decode a JSON Web Token and flag common security issues.

Examples:
    tools/jwt_inspect.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.sig
    tools/jwt_inspect.py "$JWT" --lang pt
    echo "$JWT" | tools/jwt_inspect.py -
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

LANGS = ("en", "pt")

LABELS = {
    "en": {
        "input": "Token",
        "header": "Header",
        "payload": "Payload",
        "signature": "Signature",
        "claims": "Notable claims",
        "issues_header": "Issues found",
        "no_issues": "No issues detected.",
        "risk_label": "Risk:",
        "fix_label": "Fix: ",
        "exp_in": "expires in",
        "exp_ago": "expired",
        "iat_at": "issued at",
        "not_set": "not set",
        "err_format": "error: not a valid JWT — expected three base64url segments separated by dots",
        "err_decode": "error: could not decode segment as base64url JSON",
        "err_empty": "error: input is empty",
        "err_stdin": "error: could not read from stdin",
    },
    "pt": {
        "input": "Token",
        "header": "Cabeçalho",
        "payload": "Payload",
        "signature": "Assinatura",
        "claims": "Claims relevantes",
        "issues_header": "Problemas encontrados",
        "no_issues": "Nenhum problema detetado.",
        "risk_label": "Risco:",
        "fix_label": "Correção: ",
        "exp_in": "expira em",
        "exp_ago": "expirou há",
        "iat_at": "emitido em",
        "not_set": "não definido",
        "err_format": "erro: não é um JWT válido — esperados três segmentos base64url separados por pontos",
        "err_decode": "erro: não foi possível descodificar segmento como JSON base64url",
        "err_empty": "erro: entrada vazia",
        "err_stdin": "erro: falha a ler do stdin",
    },
}

ISSUE_TEXT = {
    "alg_none": {
        "en": ("alg: 'none' — signature not verified",
               "Many JWT libraries accept this by default. Reject any token with alg=none server-side."),
        "pt": ("alg: 'none' — assinatura não verificada",
               "Muitas bibliotecas JWT aceitam isto por defeito. Rejeita qualquer token com alg=none no servidor."),
    },
    "alg_weak": {
        "en": ("alg: '{}' — weak / deprecated",
               "Use HS256 with a strong secret, or move to RS256/ES256."),
        "pt": ("alg: '{}' — fraco / descontinuado",
               "Usa HS256 com um secret forte, ou migra para RS256/ES256."),
    },
    "no_exp": {
        "en": ("Token has no expiry (`exp`) claim",
               "Tokens without expiry stay valid forever. Always include an `exp` claim."),
        "pt": ("O token não tem claim de expiração (`exp`)",
               "Tokens sem expiração ficam válidos para sempre. Inclui sempre um claim `exp`."),
    },
    "expired": {
        "en": ("Token has expired ({} ago)",
               "Server-side validation should reject this. If accepted, validation is broken."),
        "pt": ("O token expirou (há {})",
               "A validação no servidor deve rejeitar isto. Se for aceite, a validação está partida."),
    },
    "no_iss": {
        "en": ("No `iss` (issuer) claim",
               "Without `iss`, you can't verify *who* issued the token. Add it and verify server-side."),
        "pt": ("Sem claim `iss` (issuer)",
               "Sem `iss` não consegues verificar *quem* emitiu o token. Adiciona-o e valida no servidor."),
    },
    "no_aud": {
        "en": ("No `aud` (audience) claim",
               "Without `aud`, a token issued for service A could be replayed against service B."),
        "pt": ("Sem claim `aud` (audience)",
               "Sem `aud`, um token emitido para o serviço A pode ser reusado contra o serviço B."),
    },
    "long_validity": {
        "en": ("Validity longer than 24 hours ({})",
               "Long-lived tokens increase blast radius if stolen. Use short tokens + refresh."),
        "pt": ("Validade superior a 24h ({})",
               "Tokens longos aumentam o impacto se forem roubados. Usa tokens curtos + refresh."),
    },
    "weak_kid": {
        "en": ("`kid` looks like a path ({}) — possible LFI / path traversal",
               "Server-side, validate kid is one of a known list, not a path."),
        "pt": ("`kid` parece um path ({}) — possível LFI / path traversal",
               "No servidor, valida que kid é um de uma lista conhecida, não um path."),
    },
}

WEAK_ALGS = {"HS1", "HS128", "SHA1", "MD5"}


@dataclass
class Issue:
    key: str
    label: str
    risk: str
    fix: str


@dataclass
class JWTInfo:
    header: dict
    payload: dict
    signature_b64: str
    issues: list[Issue] = field(default_factory=list)


def b64url_decode(s: str) -> bytes:
    s = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s.encode())


def parse_jwt(token: str, lang: str) -> JWTInfo:
    L = LABELS[lang]
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(L["err_format"])
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"{L['err_decode']}: {e}")
    return JWTInfo(header=header, payload=payload, signature_b64=parts[2])


def fmt_timedelta(seconds: int, lang: str) -> str:
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    return sign + ("".join(parts) if parts else "<1m")


def evaluate(info: JWTInfo, lang: str) -> list[Issue]:
    issues = []
    h = info.header
    p = info.payload

    alg = (h.get("alg") or "").upper()
    if alg in ("NONE", ""):
        t = ISSUE_TEXT["alg_none"][lang]
        issues.append(Issue("alg_none", t[0], t[0], t[1]))
    elif alg in WEAK_ALGS:
        t = ISSUE_TEXT["alg_weak"][lang]
        issues.append(Issue("alg_weak", t[0].format(alg), t[0].format(alg), t[1]))

    kid = h.get("kid")
    if isinstance(kid, str) and ("/" in kid or ".." in kid):
        t = ISSUE_TEXT["weak_kid"][lang]
        issues.append(Issue("weak_kid", t[0].format(kid), t[0].format(kid), t[1]))

    now = int(datetime.now(tz=timezone.utc).timestamp())
    exp = p.get("exp")
    iat = p.get("iat")
    if exp is None:
        t = ISSUE_TEXT["no_exp"][lang]
        issues.append(Issue("no_exp", t[0], t[0], t[1]))
    elif isinstance(exp, (int, float)) and exp < now:
        delta = fmt_timedelta(now - int(exp), lang)
        t = ISSUE_TEXT["expired"][lang]
        issues.append(Issue("expired", t[0].format(delta), t[0].format(delta), t[1]))
    elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        validity_seconds = int(exp - iat)
        if validity_seconds > 86400:
            delta = fmt_timedelta(validity_seconds, lang)
            t = ISSUE_TEXT["long_validity"][lang]
            issues.append(Issue("long_validity", t[0].format(delta), t[0].format(delta), t[1]))

    if "iss" not in p:
        t = ISSUE_TEXT["no_iss"][lang]
        issues.append(Issue("no_iss", t[0], t[0], t[1]))
    if "aud" not in p:
        t = ISSUE_TEXT["no_aud"][lang]
        issues.append(Issue("no_aud", t[0], t[0], t[1]))

    return issues


def print_human(info: JWTInfo, lang: str) -> None:
    L = LABELS[lang]
    print(f"\n{L['header']}:")
    print(json.dumps(info.header, indent=2, ensure_ascii=False))

    print(f"\n{L['payload']}:")
    print(json.dumps(info.payload, indent=2, ensure_ascii=False))

    print(f"\n{L['signature']}: {info.signature_b64[:60]}{'...' if len(info.signature_b64) > 60 else ''}")

    # Notable claims
    notable = []
    now = int(datetime.now(tz=timezone.utc).timestamp())
    for claim in ("iss", "sub", "aud", "iat", "nbf", "exp", "jti"):
        if claim in info.payload:
            value = info.payload[claim]
            extra = ""
            if claim in ("iat", "nbf", "exp") and isinstance(value, (int, float)):
                ts = datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
                if claim == "exp":
                    delta = int(value) - now
                    label = L["exp_in"] if delta >= 0 else L["exp_ago"]
                    extra = f"  ({ts}, {label} {fmt_timedelta(abs(delta), lang)})"
                elif claim == "iat":
                    extra = f"  ({ts}, {L['iat_at']})"
                else:
                    extra = f"  ({ts})"
            notable.append(f"  {claim:<5}: {value}{extra}")
    if notable:
        print(f"\n{L['claims']}:")
        for line in notable:
            print(line)

    if info.issues:
        print(f"\n{L['issues_header']} ({len(info.issues)}):")
        for iss in info.issues:
            print(f"\n  ✗ {iss.label}")
            print(f"     {L['risk_label']} {iss.risk}")
            print(f"     {L['fix_label']}{iss.fix}")
    else:
        print(f"\n{L['no_issues']}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode a JSON Web Token and flag common security issues.")
    parser.add_argument("token", help="JWT string; use '-' for stdin")
    parser.add_argument("--lang", choices=LANGS, default="en")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    L = LABELS[args.lang]

    if args.token == "-":
        try:
            token = sys.stdin.read().strip()
        except OSError:
            print(L["err_stdin"], file=sys.stderr)
            return 3
    else:
        token = args.token.strip()

    if not token:
        print(L["err_empty"], file=sys.stderr)
        return 2

    try:
        info = parse_jwt(token, args.lang)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    info.issues = evaluate(info, args.lang)

    if args.json:
        out = {
            "header": info.header,
            "payload": info.payload,
            "signature_b64": info.signature_b64,
            "lang": args.lang,
            "issues": [asdict(i) for i in info.issues],
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print_human(info, args.lang)

    return 1 if info.issues else 0


if __name__ == "__main__":
    sys.exit(main())
