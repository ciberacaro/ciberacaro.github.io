---
title: "Web reconnaissance from scratch, with nothing but the Python standard library"
date: 2026-05-18 12:00:00 +0100
categories: [Notes, Tools]
tags: [recon, web, python, dns, tls, http-headers]
pin: false
permalink: /posts/web-recon-stdlib-python/
---

> Versão em português: [Reconhecimento web do zero, só com a stdlib do Python](/posts/recon-web-stdlib-python/).
{: .prompt-info }

When you first poke at a target's web surface, you usually need the same five things: a list of its subdomains, an audit of its security headers, the TLS certificate, the cookie flags, and the DNS records. There is a pile of mature tools for each of these — `subfinder`, `nmap`, `testssl.sh`, `dig`, and so on — but stitching them into a single report takes time and a working install for each.

I wanted something I could run on any machine that has Python 3.8+, with no `pip install`, no Homebrew, no fiddling. The result is `recon.py`, an orchestrator that runs five smaller tools in sequence and produces a single Markdown report.

This post walks through what it does, what the output tells you, and where to push next.

## The pipeline

`recon.py` is intentionally not clever — it composes five existing tools from the same toolchain:

```
subfinder.py          → find subdomains via crt.sh + a small wordlist
check_headers.py      → audit security headers (HSTS, CSP, X-Frame, etc.)
tls_inspect.py        → fetch the cert, enumerate accepted TLS versions
cookie_check.py       → check Set-Cookie flags (HttpOnly, Secure, SameSite)
dns_records.py        → A/AAAA/MX/NS/TXT/CAA + SPF/DMARC audit + AXFR probe
```

Each one is stdlib-only. The orchestrator runs them, captures their JSON output, and renders a single Markdown report.

## Running it

The smallest invocation:

```bash
$ tools/recon.py example.com
```

For a target with several subdomains, ask it to evaluate the top N (default 10):

```bash
$ tools/recon.py example.com --top 5 --output report.md --lang pt
```

The `--lang pt` flag affects every sub-tool's output — useful when the audience for the report is Portuguese-speaking.

## What the output looks like

Truncated example from a real run:

```
## Reconnaissance: example.com

### Subdomains (12 found, top 5 resolved)
- www.example.com           → 93.184.216.34
- api.example.com           → 93.184.216.50
- mail.example.com          → 93.184.216.60
- dev.example.com           → 10.0.0.1   ← internal IP exposed publicly
- old.example.com           → CNAME old-example.herokudns.com

### Security headers (per subdomain)
| Host | Score | Notes |
|------|-------|-------|
| www.example.com | 5/9 | Missing CSP, Permissions-Policy |
| api.example.com | 3/9 | Missing HSTS, CSP, X-Frame, COOP |

### TLS certificates
- www: Let's Encrypt, expires 2024-09-01 (143 days), TLS 1.0 ✗ accepted
- api: Let's Encrypt, expires 2024-09-01, TLS 1.2/1.3 only ✓

### Cookies
- www.example.com  → `session=...` missing SameSite, Secure OK
- api.example.com  → no Set-Cookie

### DNS records
- A:    93.184.216.34
- MX:   mail.example.com
- SPF:  ✓ present (`v=spf1 ~all`)
- DMARC: ✗ missing — anyone can spoof email From this domain
- AXFR: refused by all NS (good)
```

That report alone is enough to write the first paragraph of a finding list.

## Reading the report critically

A few things worth flagging the first time you look at one of these:

**Internal IPs in DNS.** A subdomain resolving to `10.x.x.x` or `192.168.x.x` is either a configuration mistake or a deliberate split-horizon setup. Either way it's noise to a recruiter and signal to an attacker. The `dev.example.com → 10.0.0.1` line in the example above is a real pattern; I have seen it in the wild.

**CNAME pointing at a third-party service.** `old-example.herokudns.com` is a possible *subdomain takeover* if the Heroku app was deleted but the CNAME was forgotten. That deserves a separate check with `subdomain_takeover.py` — see the [next post](/posts/subdomain-takeover-dangling-cnames/) on this.

**TLS 1.0 accepted.** Browsers stopped negotiating it in 2020, but a server still offering it is exposed to legacy clients and to anyone using a vulnerable BEAST-style downgrade. Worth a finding even if no current user is affected.

**Missing DMARC.** SPF on its own doesn't stop the message arriving — it just lets the receiver decide. Without DMARC the receiver has no enforcement policy to apply, and the From header can be anything the attacker wants.

## What this is not

This tool **does not** replace a real recon suite. It will not:

- Crawl the application for routes the way Burp / ZAP do
- Run authenticated checks
- Detect WAF behaviour beyond what's already in the HTTP response
- Brute-force directories — see [`path_scan.py`](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/path_scan.py) for that

What it is good for: a fast, repeatable first sweep that turns an empty page into a structured starting point. Pair it with `path_scan.py`, `subdomain_takeover.py`, and the rest of the toolchain depending on what the report surfaces.

## Where to find it

All 27 tools live in the [`tools/`](https://github.com/ciberacaro/ciberacaro.github.io/tree/main/tools) directory of this repository, with a [bilingual long-form tutorial](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/HOWTO.txt) for each.

```bash
git clone https://github.com/ciberacaro/ciberacaro.github.io.git
cd ciberacaro.github.io
python3 tools/recon.py your-target.example
```

No installation step. Python 3.8 or newer is the only prerequisite.

---

*If you find a real issue with one of the tools, or want to compare notes on the recon flow, the easiest way to reach me is via the [GitHub repo](https://github.com/ciberacaro/ciberacaro.github.io).*
