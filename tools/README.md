# Tools

Small utilities used while building this portfolio. This directory is excluded from the Jekyll build (see `exclude:` in `_config.yml`), so nothing here is published as part of the site.

## Conventions across the toolchain

These rules hold for every Python tool in this directory unless its own section says otherwise:

- **Language:** Python 3.8+ standard library only. No `pip install` required.
- **Bilingual:** every tool with non-trivial output supports `--lang {en,pt}`. Default is `en`; `pt` is European Portuguese.
- **Version:** every tool exposes `--version`. The version string is centralised in `_lib.TOOLS_VERSION`.
- **Stdin:** every tool that takes a single positional argument (URL, host, domain, token, hash, text, user ID) accepts `-` to read it from stdin. Useful for `... | xargs` pipelines and `... | tool -` chains.
- **User-Agent override:** every tool that makes HTTP requests accepts `--user-agent STRING`. Useful for evading WAFs that block scripted clients, or for testing how a target serves different UAs. Default is the tool's own UA string.
- **Exit codes** (uniform across tools):

  | Code | Meaning |
  |------|---------|
  | `0` | Success — no issues or nothing notable found |
  | `1` | Issues found (missing/weak security headers, expired cert, alg:none in JWT, etc.) — or in `header_diff`, snapshot differences detected |
  | `2` | Usage / argument error (bad URL, missing stdin, empty input, invalid hash format) |
  | `3` | Network, DNS, or TLS error |

- **macOS Python.org SSL fallback:** every networked tool falls back to `/etc/ssl/cert.pem` (or other common CA locations) when the default SSL context has no CAs configured. This avoids the `CERTIFICATE_VERIFY_FAILED` paper cut without requiring the user to run `Install Certificates.command`.
- **User-Agent:** uniform format `<tool>/<version> (+https://ciberacaro.github.io)` produced by `_lib.make_user_agent`. Operators on the receiving end can land on the portfolio and read what this traffic is.

## `_lib.py`

Shared utilities (not a runnable tool) used by every other script here. Stdlib-only. Exposes:

| Function / constant | Purpose |
|----|----|
| `TOOLS_VERSION` | Single source of truth for the version string |
| `PORTFOLIO_URL` | Portfolio URL referenced in User-Agent strings |
| `make_user_agent(tool, version=TOOLS_VERSION)` | Build the standard UA string |
| `build_ssl_context()` | SSL context with macOS Python.org CA fallback |
| `stdin_or_arg(value)` | Return `value`, or read from stdin if `value == "-"` |
| `add_version_arg(parser, tool_name)` | Register a uniform `--version` action on an argparse parser |
| `add_user_agent_arg(parser, default)` | Register a uniform `--user-agent STRING` override |

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

When the URL redirects (301/302/303/307/308), the report shows both the requested URL and the final URL, plus the full redirect chain, with a warning that the headers describe the destination not the origin (a common source of misleading "looks fine" results).

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

Also enumerates which TLS versions the server actually accepts by attempting handshakes with SSLv3 / TLS 1.0 / 1.1 / 1.2 / 1.3 pinned. A `deprecated` version reported as `accepted` becomes an issue (BEAST / POODLE territory). Versions disabled at Python build-time show as `not tested`.

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

Enumerate subdomains for a base domain. Queries crt.sh transparency-logs JSON API, then optionally brute-forces a small built-in wordlist (or one you provide). All candidates are DNS-resolved in parallel (default 10 threads) with a small per-worker jitter to spread the load across resolvers instead of bursting them.

```bash
tools/subfinder.py example.com
tools/subfinder.py example.com --lang pt
tools/subfinder.py example.com --wordlist /usr/share/wordlists/subdomains-top1million.txt
tools/subfinder.py example.com --skip-crtsh        # only wordlist brute-force
tools/subfinder.py example.com --skip-bruteforce   # only crt.sh
tools/subfinder.py example.com --threads 20 --jitter 0.3   # tune for your resolver
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

## `http_methods.py`

Test which HTTP methods an endpoint accepts. Sends each of GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE/TRACE/CONNECT via a raw socket (urllib refuses non-standard methods on some setups). Flags TRACE/CONNECT enabled, destructive methods returning 2xx, OPTIONS without `Allow` header, and TRACE reflection (XST signature).

```bash
tools/http_methods.py https://example.com/api/users/me
tools/http_methods.py https://example.com/ --lang pt --json
```

⚠️ Sends real PUT/DELETE/PATCH with empty bodies. Run only against endpoints you are authorised to test.

## `cookie_check.py`

Analyse `Set-Cookie` response headers. Flags missing HttpOnly on session-looking names, missing Secure over HTTPS, missing SameSite, SameSite=None without Secure, and Domain scoped wider than the response host.

```bash
tools/cookie_check.py https://example.com
tools/cookie_check.py https://example.com --lang pt --json
```

## `dns_records.py`

Pure-stdlib DNS client (raw UDP/53 with TCP fallback per RFC 1035 §4.2.2). Queries A/AAAA/MX/NS/TXT/CAA and analyses email auth: SPF (missing, multiple, `~all`/`?all`), DMARC (missing, `p=none`), CAA (missing).

```bash
tools/dns_records.py example.com
tools/dns_records.py example.com --resolver 1.1.1.1 --lang pt
```

## `secrets_scan.py`

Scan filesystem or git history for committed credentials. Patterns for AWS keys, Stripe/Slack/GitHub/Twilio/SendGrid tokens, Google API keys, JWT-like strings, private-key PEM blocks, DB connection URLs with passwords, and generic `api_key='...'` assignments. All matches masked in the output.

Generic credential assignments are entropy-gated (Shannon entropy ≥ 3.5 bits/char on the captured value) to suppress false positives on documentation placeholders and low-randomness strings (`"exampletoken"`, `"changeme1234"`, repeated chars).

```bash
tools/secrets_scan.py --path .                     # current directory
tools/secrets_scan.py --path ~/Projects/some-repo
tools/secrets_scan.py --git-history                # scan all commits
```

## `recon.py`

Orchestrator: runs `subfinder.py` → for each resolved subdomain, in parallel runs `check_headers.py` + `tls_inspect.py` + `cookie_check.py`. Adds one `dns_records.py` on the base domain. Aggregates the result into a single Markdown report.

```bash
tools/recon.py example.com --top 10
tools/recon.py example.com --output report.md --lang pt
```

## `whois_check.py`

WHOIS lookup via TCP/43. Two-step: queries IANA for the TLD-authoritative server, then queries it (and follows up to a registrar-specific server when advertised). Parses common fields across multiple TLDs. Flags expired, expiring-soon (<30 days), and unsigned DNSSEC.

```bash
tools/whois_check.py example.com
tools/whois_check.py sapo.pt --lang pt
```

## `wayback_check.py`

Wayback Machine snapshot lookup via the `archive.org` availability and CDX APIs. `--timeline` lists historical snapshots; `--diff` fetches the closest snapshot and unified-diffs it against the live URL.

```bash
tools/wayback_check.py https://example.com
tools/wayback_check.py https://example.com --timeline --limit 20
tools/wayback_check.py https://example.com --diff
```

## `tech_fingerprint.py`

Identify the technology stack behind a website from response headers, cookies, and HTML (Wappalyzer-lite). Signature database covers nginx, Apache, IIS, Caddy; Cloudflare, Fastly, Cloudfront, Akamai; PHP, ASP.NET, Python, Ruby, Java EE; React, Vue, Svelte, Next, Nuxt, Angular, jQuery, Alpine; WordPress, Drupal, Joomla, Ghost; Shopify, Magento, WooCommerce; Jekyll, Hugo, Gatsby; Google Analytics, Plausible, Matomo; Rails, Django, Laravel cookies.

```bash
tools/tech_fingerprint.py https://example.com
tools/tech_fingerprint.py https://example.com --lang pt --json
```

## `password_strength.py`

Entropy-based scoring (0-10) + Have I Been Pwned check via k-anonymity (only the first 5 hex chars of SHA-1(password) are sent — the full password never leaves the machine). Reads via `getpass` by default (no echo); accepts `--stdin` for piping.

```bash
tools/password_strength.py                  # prompts, no echo
echo "hunter2" | tools/password_strength.py --stdin
tools/password_strength.py --stdin --no-breach --lang pt
```

## `cve_lookup.py`

Fetch CVE details from the NVD v2 API. Reports description, CVSS v3 / v2 scores and vectors, CWE weaknesses, affected CPEs, and references with their NVD tags.

```bash
tools/cve_lookup.py CVE-2021-44228
tools/cve_lookup.py CVE-2021-44228 --lang pt --json
```

## `project_sync.sh`

Helper for keeping the claude.ai Project knowledge in sync with this repo. Run it after editing `CLAUDE.md` or `SESSION_LOG.md`. It:

- Prints current sizes and last-modified times for both files.
- Shows the raw GitHub URLs to copy or re-upload.
- Warns when there are unpushed commits touching either file (so you don't upload a stale version).
- On first run per clone, enables the `.githooks/` directory so the `post-commit` hook fires automatically next time these files change.

```bash
tools/project_sync.sh
```

The post-commit hook also prints the reminder automatically — running this script manually is just for when you forgot, or to see the URLs without making a commit.

## `run.sh` / `test.sh`

Local Jekyll preview and build-test scripts shipped with the Chirpy starter. Useful for previewing changes locally before pushing.

```bash
bash tools/run.sh      # serve at http://127.0.0.1:4000
bash tools/test.sh     # build and run html-proofer
```

Requires a local Ruby + bundler + Jekyll setup.
