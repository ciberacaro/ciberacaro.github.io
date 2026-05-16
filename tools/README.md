# Tools

Small utilities used while building this portfolio. This directory is excluded from the Jekyll build (see `exclude:` in `_config.yml`), so nothing here is published as part of the site.

## `new_writeup.py`

Generate a writeup skeleton in `_posts/` with Chirpy frontmatter and the standard pentest-writeup sections (Overview, Reconnaissance, Initial Access, Privilege Escalation, Lessons Learned, References).

### Usage

```bash
tools/new_writeup.py "Vulnversity" --platform thm --difficulty easy
tools/new_writeup.py "Soccer"      --platform htb --tags web,enumeration
tools/new_writeup.py "Lab name"    --platform portswigger --difficulty medium
```

### Options

| Flag | Choices / format | Default | Notes |
|------|------------------|---------|-------|
| `name` (positional) | string | — | Room/box name. Slugified for the filename. |
| `--platform` | `thm`, `htb`, `portswigger`, `other` | `thm` | |
| `--difficulty` | `info`, `easy`, `medium`, `hard`, `insane` | `easy` | |
| `--tags` | comma-separated string | empty | Extra tags appended to `[platform, difficulty]`. |
| `--date` | `YYYY-MM-DD` | today | Overrides today's date (useful for back-dating). |

The script refuses to overwrite an existing file.

### Requirements

Python 3.8+. Standard library only — no `pip install` needed.

## `check_headers.py`

Inspect the security-relevant HTTP response headers of any URL and produce a quick report. Useful both as a portfolio piece and as a real day-to-day tool when looking at a target site.

### Checks performed

| Header | Why it matters |
|--------|----------------|
| `Strict-Transport-Security` | Forces HTTPS; defends against downgrade attacks |
| `Content-Security-Policy` | Reduces XSS impact; warns on `'unsafe-inline'` / `'unsafe-eval'` / `*` |
| `X-Frame-Options` *(or CSP `frame-ancestors`)* | Clickjacking defense |
| `X-Content-Type-Options` | Disables MIME-sniffing (`nosniff`) |
| `Referrer-Policy` | Limits referrer info leakage |
| `Permissions-Policy` | Restricts browser features (camera, geolocation, etc.) |
| `Cross-Origin-Opener-Policy` | Isolates browsing context from cross-origin windows |
| `Cross-Origin-Embedder-Policy` | Requires cross-origin resources to opt-in |
| `Cross-Origin-Resource-Policy` | Controls who may embed this resource |
| `Server`, `X-Powered-By`, `X-AspNet-*` | Information disclosure |

### Usage

```bash
tools/check_headers.py https://example.com
tools/check_headers.py https://example.com --lang pt        # European Portuguese
tools/check_headers.py https://example.com --no-color
tools/check_headers.py https://example.com --json
tools/check_headers.py https://slow-host.example --timeout 30
```

### Output

The human-readable output has three sections:

1. **Header table** — status (✓ OK / ! WEAK / ✗ MISSING / i INFO) for each checked header, with the value the server returned.
2. **Score** — `N/9 headers OK` (info-disclosure headers don't count toward the score).
3. **Issues found** — for every MISSING and WEAK header: the concrete attack/risk it enables and a one-line fix recommendation.

JSON output (`--json`) includes `risk` and `fix` fields per finding, plus `issues_count` at the top level. The `--lang` flag affects both human and JSON output.

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | All security headers present |
| `1` | At least one header MISSING |
| `2` | Bad arguments (e.g. URL missing scheme) |
| `3` | Network / DNS / TLS error |

### Requirements

Python 3.8+, standard library only. On macOS Python.org installs, the script falls back to `/etc/ssl/cert.pem` automatically if the default SSL context has no CAs configured.

## `multidecode.py`

Auto-detect and decode common encodings: Base64, Base32, hex, URL, binary, ROT13. Useful when you grab a suspicious string from a CTF or HTTP traffic.

```bash
tools/multidecode.py "SGVsbG8gd29ybGQh"
tools/multidecode.py "%2Fetc%2Fpasswd" --lang pt
echo -n "deadbeef" | tools/multidecode.py -
tools/multidecode.py "VGhlIGJyb3duIGZveA==" --cascade
```

`--cascade` recursively decodes (e.g. Base64-of-Base64) until nothing new appears.

## `robots_check.py`

Fetch `/robots.txt` and `/sitemap.xml`. Lists rules per User-Agent, highlights paths matching interesting patterns (admin, api, backup, debug, .git, etc.), and prints the first 50 sitemap URLs as a recon starting point.

```bash
tools/robots_check.py https://example.com
tools/robots_check.py https://example.com --lang pt --json
```

## `hashid.py`

Identify the likely type(s) of a hash string. Knows ~25 formats: MD5/SHA-family, bcrypt, scrypt, Argon2, phpass (WordPress), Apache APR1, Unix crypt variants ($1$/$5$/$6$/$y$), MySQL old/new, NTLM/LM pwdump format, base64-encoded LDAP forms, and JWT (commonly mistaken for a hash). Ranks candidates by confidence and includes hashcat mode hints.

```bash
tools/hashid.py 5f4dcc3b5aa765d61d8327deb882cf99
tools/hashid.py '$2b$12$...' --lang pt
echo "098f6bcd..." | tools/hashid.py -
```

## `tls_inspect.py`

Connect to a host:port, fetch the TLS certificate (with `CERT_NONE` so even bad certs can be inspected), and report issuer/subject/validity/SANs/signature algorithm/TLS version/cipher. Flags expired, expiring-soon (<30 days), self-signed, weak signature algorithms (MD5/SHA-1), overly broad wildcards, and host-name mismatches.

```bash
tools/tls_inspect.py example.com
tools/tls_inspect.py example.com:8443 --lang pt
tools/tls_inspect.py https://github.com --json
```

## `jwt_inspect.py`

Decode a JSON Web Token (header / payload / signature), pretty-print claims with human-readable timestamps and validity windows, and flag common issues: `alg: none`, weak algorithms, missing `exp`, expired tokens, validity windows >24h, missing `iss`/`aud`, and path-traversal patterns in the `kid` header.

```bash
tools/jwt_inspect.py "eyJhbGciOi..."
tools/jwt_inspect.py "$JWT" --lang pt
echo "$JWT" | tools/jwt_inspect.py -
```

## `cors_check.py`

Probe a URL with several different `Origin` header values (arbitrary attacker, `null`, prefix/suffix tricks, legitimate). For each origin, sends both **GET** and **OPTIONS preflight** (with `Access-Control-Request-Method`/`Access-Control-Request-Headers`), then inspects the `Access-Control-Allow-Origin/Credentials/Methods/Headers` responses. Flags reflected arbitrary origins, wildcard + credentials, `null` + credentials, and prefix/suffix-match bugs.

```bash
tools/cors_check.py https://api.example.com/users/me
tools/cors_check.py https://api.example.com/users/me --lang pt --json
```

## `subfinder.py`

Enumerate subdomains for a base domain. Queries crt.sh transparency-logs JSON API, then optionally brute-forces a small built-in wordlist (or one you provide). All candidates are DNS-resolved in parallel (default 20 threads). Output lists each resolved host with source (crt.sh / wordlist) and IPs.

```bash
tools/subfinder.py example.com
tools/subfinder.py example.com --lang pt
tools/subfinder.py example.com --wordlist /usr/share/wordlists/subdomains-top1million.txt
tools/subfinder.py example.com --skip-crtsh        # only wordlist brute-force
tools/subfinder.py example.com --skip-bruteforce   # only crt.sh
```

## `htb_stats.py`

Generate HackTheBox profile-badge markdown ready to paste into a README or post (no API token needed). Optionally fetch profile stats (rank, points, owns, respects) via the HTB v4 API when you set `HTB_TOKEN` or pass `--token`.

```bash
tools/htb_stats.py 12345                          # numeric HTB user ID
tools/htb_stats.py 12345 --badge-only --lang pt
HTB_TOKEN=eyJ... tools/htb_stats.py 12345 --json
```

## `header_diff.py`

Builds on `check_headers.py`. Snapshot a URL's security headers to `.header_snapshots/<host>/<timestamp>.json`, then diff the current state against the latest snapshot. Catches regressions when site config, CDN, or framework changes silently strip a header.

```bash
tools/header_diff.py snapshot https://ciberacaro.github.io
tools/header_diff.py diff     https://ciberacaro.github.io
tools/header_diff.py diff     https://ciberacaro.github.io --lang pt --json
```

`.header_snapshots/` is gitignored — it's local state, not artifact.

## `run.sh` / `test.sh`

Local Jekyll preview and build-test scripts shipped with the Chirpy starter. Useful for previewing changes locally before pushing.

```bash
bash tools/run.sh      # serve at http://127.0.0.1:4000
bash tools/test.sh     # build and run html-proofer
```

Requires a local Ruby + bundler + Jekyll setup.
