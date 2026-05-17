# CLAUDE.md

Context for any Claude (Code, web, or otherwise) working on this repository.

## About this project

This repo is the personal cybersecurity portfolio of **Luís Soares** (GitHub handle: `ciberacaro`), published at <https://ciberacaro.github.io>. It is a Jekyll site using the **Chirpy** theme, deployed automatically via GitHub Actions to GitHub Pages.

The portfolio's purpose is to support Luís's career transition into cybersecurity — specifically **penetration testing / red team / ethical hacking** — and to land a first security job. Broader identity goal: be an *ethical hacker* (encompasses pentesting, bug bounty, security research, CTFs, community involvement).

## About the user (Luís)

- **Career stage:** Entry-level, transitioning into cybersecurity from scratch (no prior security job).
- **Background skills:** Basic programming, Linux/CLI, networking — self-describes as "just starting, knowledge isn't deep."
- **Practice platforms:** Has a TryHackMe account with some rooms done. Will move to HackTheBox later in the roadmap.
- **Time available:** 10-20 hours/week.
- **Spoken language:** European Portuguese — chat with Luís in Portuguese. All portfolio content / commits / repo files are in **English** (for international reach).
- **Location:** Portugal.
- **Identity model:** Handle (`ciberacaro`) in usernames; real name (Luís Soares) in GitHub profile "Name" field, footers, bios, LinkedIn — so recruiters can bridge the two.

## Site / repo conventions

- **Stack:** Jekyll + Chirpy theme. Source: <https://github.com/cotes2020/chirpy-starter>
- **Deploy:** GitHub Actions builds and deploys on push to `main`. See `.github/workflows/`.
- **Branding (locked):**
  - Title: `Luís Soares · ciberacaro`
  - Tagline: `Notes from an aspiring penetration tester`
  - URL: `https://ciberacaro.github.io`
  - Timezone: `Europe/Lisbon`
  - Language: Bilingual (see below)
- **Language policy:**
  - Posts / writeups / categories / tags / archives: **English only** (international reach).
  - Static "identity" pages (About, etc.): **bilingual EN + PT-PT**, as separate `_tabs/` files. Convention: English uses the standard English name (`about.md` → `/about/`), Portuguese uses the Portuguese equivalent (`sobre.md` → `/sobre/`) and links back to the English version at the top via a `prompt-info` callout.
  - Repo files (README, CLAUDE.md, commit messages): English.
  - **CLI tools in `tools/`** with non-trivial user-facing output (reports, multi-line text): support a `--lang {en,pt}` flag, EN default. Reference implementation: `tools/check_headers.py` — labels/notes/risk-fix strings live in `LABELS` / `NOTES` / `HEADER_RISK_INFO` dicts keyed by language; `--lang` affects both human and JSON output. Skip the bilingual treatment for tools whose output is trivial (e.g. `tools/new_writeup.py` just prints `created: <path>`).
  - In Portuguese strings, keep security jargon (XSS, CSP, HSTS, clickjacking, payload, port scan, etc.) in English — universal in the community. Use PT-PT, not BR-PT: "ficheiro" not "arquivo", "câmara" not "câmera", "descontinuado" not "obsoleto".
- **Avatar:** Placeholder for now; deferred decision.
- **Visual theme variant:** Not yet chosen — to be picked from Chirpy variants when content is in place.
- **Posts location:** `_posts/` — Jekyll convention `YYYY-MM-DD-title.md`.
- **Custom tabs:** `_tabs/` (e.g., About + Sobre).
- **Categories planned:** Web, Active Directory, Linux, Windows, Crypto, Forensics, Notes/Cheatsheets, Tools.

## 6-month roadmap

| Month | Learning focus | Portfolio output |
|-------|----------------|------------------|
| 1 | Linux, networking, TryHackMe Pre-Security / Jr Pentester paths | Site live, 3-5 first writeups |
| 2 | Web hacking — PortSwigger Web Security Academy + THM web rooms | 5+ web writeups, first cheat-sheet repo |
| 3 | Active Directory + Windows | AD writeups, first published Python tool |
| 4 | HackTheBox Starting Point + Tier 1 | 5-10 HTB box writeups |
| 5 | eJPT certification (INE/eLearnSecurity) | eJPT cert on profile, more technical writeups |
| 6 | HTB Easy boxes + start applying | Polished portfolio, active HTB profile, applications begin |

**6-month target:** eJPT + 25-30 well-written writeups + 1-2 own tools + active HackTheBox profile.

**Longer horizon:**
- Bug bounty on HackerOne / Bugcrowd — real-world impact, beats CTF writeups.
- Portuguese community presence: Confraria de Segurança da Informação, BSides Lisbon.
- Responsible disclosure mindset if real vulnerabilities found in the wild.

## Writeup quality principles

1. **Well-written writeups > many bad writeups.** Quality of reasoning matters more than quantity.
2. **Show the path, not just the destination.** "I tried X, it failed because Y, so I tried Z" > "I ran this command and got root."
3. **Consistency > intensity.** Weekly commits beat 50 writeups in a month then 6 months of silence.

## Inspirations / reference portfolios

- <https://0xdf.gitlab.io> — gold standard for HTB writeups
- <https://ippsec.rocks> — HTB legend
- <https://tib3rius.com> — clean, professional
- <https://www.johnhammond.org> — personal-brand style
- <https://xct.github.io> — beginner-to-pro trajectory
- <https://m0chan.github.io> — GitHub Pages + Jekyll, good structure

## Current build state (last updated 2026-05-16)

- ✅ Repo forked from `cotes2020/chirpy-starter`
- ✅ GitHub Pages enabled (source: GitHub Actions)
- ✅ Site live at <https://ciberacaro.github.io>
- ✅ `_config.yml` cleaned: no remaining template placeholders
- ✅ Local dev: clone at `~/Projects/ciberacaro.github.io` on Luís's Mac; `gh` CLI installed at `~/.local/bin/gh`; git configured with name `Luís Soares` and GitHub noreply email
- ✅ Preliminary About pages published — `/about/` (EN) and `/sobre/` (PT-PT). **Luís asked to defer iteration on both** — do not rewrite unless he reopens.
- ✅ `.claude/settings.json` configured:
  - `defaultMode: "bypassPermissions"` — Claude auto-accepts Bash/edits in this project (Luís opted in). **Be extra careful with destructive operations** — there is no prompt to catch a mistake. Confirm explicitly in chat before any `rm -rf`, `git push --force`, branch deletion, or anything irreversible.
  - `allow: ["Bash(gh run watch *)"]` — read-only allowlist (mostly redundant given bypassPermissions, kept for clarity).
- ✅ Toolchain at `tools/` (Python 3.8+ stdlib). Shared utilities in `tools/_lib.py`. All tools support `--lang {en,pt}`, `--version`, and stdin via `-`. Uniform exit codes (0 ok / 1 issues / 2 usage / 3 network). 21 tools total — see `tools/README.md` for the canonical reference. Key additions in 2026-05-17 wave: `http_methods`, `cookie_check`, `dns_records` (raw UDP/TCP DNS), `secrets_scan` (filesystem + git history), `recon` (orchestrator), `whois_check`, `wayback_check`, `tech_fingerprint`, `password_strength` (HIBP k-anonymity), `cve_lookup` (NVD v2).
  - `new_writeup.py` — generate Chirpy-compatible writeup skeletons.
  - `check_headers.py` — analyze security headers + per-issue risk/fix report.
  - `multidecode.py` — auto-decode Base64/Base32/hex/URL/binary/ROT13, with `--cascade`.
  - `robots_check.py` — parse /robots.txt + /sitemap.xml, highlight interesting paths.
  - `hashid.py` — identify hash types (~25 signatures, confidence-ranked, hashcat modes).
  - `tls_inspect.py` — fetch TLS cert (even bad ones), flag expired/weak-sig/self-signed/host-mismatch.
  - `jwt_inspect.py` — decode JWTs, flag alg:none, expired, missing iss/aud, kid traversal.
  - `cors_check.py` — probe with attacker/null/prefix/suffix Origins, flag reflection / wildcard+creds / null acceptance.
  - `subfinder.py` — crt.sh + DNS wordlist subdomain enumeration.
  - `htb_stats.py` — HackTheBox badge markdown generator (no token); profile stats with HTB_TOKEN.
  - `header_diff.py` — snapshot + diff security headers over time (builds on check_headers.py).
  - See `tools/README.md` for the full usage reference per tool.
  - macOS Python.org SSL fallback (`/etc/ssl/cert.pem`) is implemented in every networked tool, so they all work out of the box.
- ⏳ **Open work items:**
  - First actual writeup (use the generator + fill it in after Luís has CTF content)
  - Avatar image
  - LinkedIn URL once Luís creates a profile
  - Audit existing public repos on `ciberacaro` account before promoting site publicly
  - Polish GitHub profile (Name field still shows "ciberacaro" instead of "Luís Soares"; bio empty)
  - Consider reciprocal link from EN About → /sobre/ when iteration is reopened

## How to help Luís

- **Chat language:** Portuguese (European). All portfolio content stays in English.
- **Tone:** Direct, concrete. Beginner-friendly — don't assume security background. Explain trade-offs, not just answers.
- **Be honest about market reality.** Pentesting junior roles are competitive in Portugal — SOC analyst is the more common entry point. Don't pretend otherwise.
- **Working preference:** Luís prefers continuing portfolio development with Claude's help rather than being told to step away and "go learn first." Suggest concrete dev tasks (tools, infra, content scaffolding, polish) at decision points. Don't nudge him toward stepping away unless he asks for a learning recommendation.
- **claude.ai Project sync:** Luís uses a claude.ai Project named "Cybersecurity Portfolio" for mobile/multi-device access. Its knowledge files are `CLAUDE.md` and `SESSION_LOG.md`. The Project does not auto-sync from GitHub — re-upload is manual. A `post-commit` git hook in `.githooks/` reminds him when these files change. Whenever you (Claude) modify `CLAUDE.md` or `SESSION_LOG.md`, the hook will print a reminder after the commit; if for any reason it doesn't, mention the sync step yourself.
- **Reversibility:** Confirm before destructive actions (force pushes, deleting repos, large refactors).
- **Verify before claiming success.** Don't assume the live site reflects changes — fetch and check. Note: GitHub CDN caching can lag the build by 1-2 min.

## Useful commands

```bash
# Make sure gh CLI is on PATH (Luís's Mac uses ~/.local/bin/gh)
export PATH="$HOME/.local/bin:$PATH"

# From repo root
gh run list --limit 5            # check recent Actions builds
gh run watch                     # watch the latest run live

# Local validation before push
ruby -ryaml -e 'YAML.load_file("_config.yml"); puts "Valid YAML"'

# Site is at:
# https://ciberacaro.github.io
```
