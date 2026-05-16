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
2. **Score** — `N/6 headers OK` (info-disclosure headers don't count toward the score).
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

## `run.sh` / `test.sh`

Local Jekyll preview and build-test scripts shipped with the Chirpy starter. Useful for previewing changes locally before pushing.

```bash
bash tools/run.sh      # serve at http://127.0.0.1:4000
bash tools/test.sh     # build and run html-proofer
```

Requires a local Ruby + bundler + Jekyll setup.
