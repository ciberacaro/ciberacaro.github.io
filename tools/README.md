# Tools

Small utilities used while building this portfolio. This directory is excluded from the Jekyll build (see `exclude:` in `_config.yml`), so nothing here is published as part of the site.

> Looking for a long-form tutorial with scenarios, expected output and tips for every tool? See [`HOWTO.txt`](HOWTO.txt) (bilingual EN + PT-PT, ~2500 lines). This README is the quick reference.

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

## `path_scan.py`

Discover hidden paths and directories on a web server. Stdlib equivalent of gobuster/dirb-style scanners — concurrent HTTP probes (default 10 threads) over a built-in 75-path wordlist (admin panels, backups, `.env`, `.git/config`, `wp-config.php`, `phpmyadmin`, Spring Actuator endpoints, etc.). Flags dangerous findings (env files, exposed `.git`, backups, admin panels, private-key files) with a risk level.

Supports external wordlists (`--wordlist`), extension expansion (`--extensions php,html,bak`), custom status-code filtering (`--codes`), and tunable concurrency. A 403 on a sensitive path still reports — the directory exists even if not directly readable.

```bash
tools/path_scan.py https://example.com
tools/path_scan.py https://example.com --extensions php,bak --threads 20
tools/path_scan.py https://example.com --wordlist /usr/share/wordlists/dirb/common.txt --lang pt
tools/path_scan.py https://example.com --codes 200,301,302 --json
```

## `open_redirect.py`

Probe a URL for open redirect vulnerabilities. Injects 8 payloads (protocol-relative `//`, backslash bypass `\/\/`, `@`-trick, etc.) into every query parameter in the URL **and** into 24 common redirect parameter names (`url`, `next`, `redirect`, `returnTo`, `goto`, `dest`, `callback`, …) not already present. Reports any parameter where the server issues a 3xx response with a `Location` header pointing outside the original host.

```bash
tools/open_redirect.py https://example.com/login?next=/dashboard
tools/open_redirect.py https://example.com/login?next=/dashboard --lang pt
tools/open_redirect.py https://example.com/login?next=/dashboard --json
echo "https://example.com/login?next=/dashboard" | tools/open_redirect.py -
```

## `param_miner.py`

Discover hidden or undocumented query parameters by fuzzing a 278-name wordlist against a target URL. Establishes a response baseline (status + body length), then probes each parameter name with a canary value and flags any parameter that causes a measurable difference (status change, body length delta ≥ threshold, or value reflection). Useful for surfacing cache-poisoning vectors, mass-assignment bugs, internal feature flags, and forgotten debug parameters.

```bash
tools/param_miner.py https://api.example.com/users
tools/param_miner.py https://api.example.com/users --threshold 20 --threads 20
tools/param_miner.py https://api.example.com/users --lang pt --json
echo "https://api.example.com/users" | tools/param_miner.py -
```

## `crlf_inject.py`

Test for HTTP response splitting (CRLF injection). Uses `http.client` directly — bypassing `urllib`'s URL encoding — to inject CRLF sequences (`%0d%0a`, `%0a`, `%0D%0A`, Unicode CRLF `%E5%98%8A%E5%98%8D`) into the URL path and query parameters. Confirms injection only if the canary header (`X-Crlf-Test: injected`) appears in the server's actual response headers — no false positives from sites that already set cookies.

```bash
tools/crlf_inject.py https://example.com/page
tools/crlf_inject.py https://example.com/login?next=/dashboard --lang pt
tools/crlf_inject.py https://example.com/page --json
```

## `ssrf_probe.py`

Probe URL parameters for Server-Side Request Forgery. Tests 22 internal payloads (127.0.0.1, AWS IMDSv1 at 169.254.169.254, GCP metadata, Azure, Digital Ocean, common internal IPs/ports) against URL-accepting parameters (`url`, `src`, `redirect`, `fetch`, `proxy`, …). Flags responses where the server took significantly longer than baseline (timing side-channel) or returned an unexpected 200/4xx from an internal address.

```bash
tools/ssrf_probe.py https://example.com/fetch?url=https://target.com
tools/ssrf_probe.py https://example.com/api/image --lang pt
tools/ssrf_probe.py https://example.com/proxy --json
```

## `http_smuggling_probe.py`

Detect HTTP/1.1 request smuggling susceptibility (CL.TE and TE.CL desync) via timing side-channel. Sends requests with deliberately contradictory `Content-Length` / `Transfer-Encoding` headers using raw sockets (no normalization). A vulnerable back-end stalls waiting for bytes that never arrive, producing a measurable delay against a baseline GET. Reports both technique variants independently.

```bash
tools/http_smuggling_probe.py https://example.com
tools/http_smuggling_probe.py https://example.com --lang pt
tools/http_smuggling_probe.py https://example.com --json
```

## `subdomain_takeover.py`

Detect subdomains vulnerable to takeover — where a CNAME points to a third-party service that's no longer registered (forgotten GitHub Pages site, dead Heroku app, abandoned S3 bucket). An attacker can register that orphaned service and serve content under the original domain.

Workflow: enumerate subdomains (crt.sh automatically, or supply your own list via `--subdomains FILE`/`-`), resolve CNAMEs via raw UDP/53 (full pointer decompression, no `dnspython` needed), match against 16 service patterns (GitHub Pages, Heroku, Netlify, AWS S3, Azure, Fastly, Ghost, Surge, ReadMe, Shopify, Zendesk, Tumblr, WP Engine, Squarespace, Fly.io, Azure CloudApp), then HTTP-probe for the service's "unclaimed" fingerprint string before flagging.

```bash
tools/subdomain_takeover.py example.com
tools/subdomain_takeover.py example.com --lang pt
tools/subfinder.py example.com --json | jq -r '.resolved[].host' | \
  tools/subdomain_takeover.py example.com --subdomains -
tools/subdomain_takeover.py example.com --json
```

⚠️ When a real vulnerable subdomain is found: do NOT register the service yourself unless authorised. Report via the organisation's responsible-disclosure / VDP channel.

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

Analyse `Set-Cookie` response headers. Flags missing HttpOnly on session-looking names, missing Secure over HTTPS, missing SameSite, SameSite=None without Secure, Domain scoped wider than the response host, RFC 6265bis `__Host-` / `__Secure-` prefix violations, and long-lived cookies (Max-Age or Expires > 1 year).

```bash
tools/cookie_check.py https://example.com
tools/cookie_check.py https://example.com --lang pt --json
```

## `dns_records.py`

Pure-stdlib DNS client (raw UDP/53 with TCP fallback per RFC 1035 §4.2.2). Queries A/AAAA/MX/NS/CNAME/SOA/TXT/CAA and analyses email auth: SPF (missing, multiple, `~all`/`?all`), DMARC (missing, `p=none`), CAA (missing).

Also probes AXFR (zone transfer) against every authoritative NS over TCP/53 — almost every server refuses, which is correct. An `allowed` result is a high-severity finding: full DNS zone publicly retrievable.

```bash
tools/dns_records.py example.com
tools/dns_records.py example.com --resolver 1.1.1.1 --lang pt
tools/dns_records.py example.com --no-axfr           # skip zone-transfer probe
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

Identify the technology stack behind a website from response headers, cookies, and HTML (Wappalyzer-lite). Signature database covers nginx, Apache, IIS, Caddy; Cloudflare, Fastly, Cloudfront, Akamai; WAFs (Cloudflare WAF, AWS WAF, Sucuri, Imperva/Incapsula, ModSecurity, Akamai Kona, F5 BIG-IP ASM); PHP, ASP.NET, Python, Ruby, Java EE; React, Vue, Svelte, Next, Nuxt, Angular, jQuery, Alpine; WordPress, Drupal, Joomla, Ghost; Shopify, Magento, WooCommerce; Jekyll, Hugo, Gatsby; Google Analytics, Plausible, Matomo; Rails, Django, Laravel cookies.

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

## `xor_crack.py`

Recover plaintext from XOR-encrypted ciphertext. Single-byte XOR is brute-forced over all 256 keys using English letter-frequency scoring. Multi-byte XOR uses Index-of-Coincidence to guess the key length, then brute-forces each byte position independently.

```bash
tools/xor_crack.py 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
tools/xor_crack.py <hex> --key-len 3                # known key length
tools/xor_crack.py <hex> --key 6b6579               # decrypt with given key
cat cipher.bin | tools/xor_crack.py - --raw         # binary input via stdin
tools/xor_crack.py <hex> --lang pt --json
```

## `cve_lookup.py`

Fetch CVE details from the NVD v2 API. Reports description, CVSS v3 / v2 scores and vectors, CWE weaknesses, affected CPEs, and references with their NVD tags.

```bash
tools/cve_lookup.py CVE-2021-44228
tools/cve_lookup.py CVE-2021-44228 --lang pt --json
```

## `log_parser.py`

Parse a log file (Apache/nginx access logs, syslog, or generic text) and extract & normalise IPs, emails, domains, URLs, and timestamps with precompiled regex. Aggregates top-N counts per category, classifies IPs (private / public / loopback / link-local for both IPv4 and IPv6), flags sensitive-path hits (`.env`, `.git`, `wp-admin`, etc.), and detects suspicious patterns: brute-force (same IP with ≥N 4xx responses), scanner activity (single IP touching >50 unique paths), and BOTNET-style hits on sensitive paths. Streams line-by-line so it handles multi-GB log files without loading them into memory.

Inspired by curriculum unit UC01481 / UC01482 of the Portuguese CET in Cybersecurity (log normalisation and filtering).

```bash
tools/log_parser.py access.log
tools/log_parser.py access.log --top 20 --bruteforce 25 --lang pt
cat /var/log/auth.log | tools/log_parser.py -
tools/log_parser.py access.log --json | jq '.suspicious[]'
```

## `email_forensics.py`

Phishing-investigation tool for `.eml` files. Uses the stdlib `email` module (BytesParser + `policy.default`) to parse the headers and runs targeted checks: SPF/DKIM/DMARC verdicts from `Authentication-Results`, From/Return-Path/Reply-To domain consistency, display-name impersonation against 13 known brands (PayPal, Microsoft, Apple, Google, Amazon, etc.), Received-chain timestamp anomalies, and missing-headers flags. Reconstructs the Received chain in chronological order with originating IP per hop.

Inspired by curriculum unit UC01485 (forensic analysis of cyber-incidents).

```bash
tools/email_forensics.py phishing.eml
tools/email_forensics.py phishing.eml --lang pt
cat suspicious.eml | tools/email_forensics.py -
tools/email_forensics.py phishing.eml --json | jq '.issues[]'
```

## `file_hash.py`

Forensic file hashing (chain-of-custody). Computes MD5/SHA-1/SHA-256/SHA-512 (and SHA-3, BLAKE2) in a single pass with 64 KB streaming chunks — handles arbitrarily large files without memory pressure. Four modes:

- **Default** — print hashes for one or more files.
- **`--verify HASH`** — compare computed hash against an expected value (exit 0 = match, 1 = mismatch).
- **`--save FILE`** — write a GNU-coreutils-style manifest (`<hash>  <filename>`) for later verification.
- **`--check FILE`** — verify all files listed in a manifest, reporting OK / MISMATCH / MISSING per entry.

Inspired by curriculum unit UC01489 (digital forensic collection and analysis — preserving evidence integrity).

```bash
tools/file_hash.py evidence.bin
tools/file_hash.py evidence.bin --algos sha256,sha3_256
tools/file_hash.py evidence.bin --verify 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
tools/file_hash.py *.bin --save manifest.sha256
tools/file_hash.py --check manifest.sha256 --lang pt
cat document.pdf | tools/file_hash.py -
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
