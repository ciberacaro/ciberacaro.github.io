---
title: "Log analysis from scratch: spotting brute force and scanners in five minutes"
date: 2026-05-18 12:30:00 +0100
categories: [Notes, Tools]
tags: [logs, forensics, brute-force, detection, python]
pin: false
permalink: /posts/log-analysis-brute-force/
---

> Versão em português: [Análise de logs do zero: detetar *brute force* em cinco minutos](/posts/analise-de-logs-brute-force/).
{: .prompt-info }

The first time you stare at a server access log of any reasonable size — a few hundred thousand lines is normal — it can feel like the signal is invisible. There is no easy way to look at a flat text file and see where the trouble is. You can grep, but you don't yet know what you're looking for.

This post walks through a small Python tool, `log_parser.py`, and the three patterns it looks for. The patterns matter more than the tool: once you know what to look for, you can do this with grep, with `awk`, with Splunk, or with whatever the SIEM stack of your day looks like.

## What the tool extracts

For every line of the log, the parser pulls out the things that tend to matter:

- IPv4 and IPv6 addresses (with octet validation)
- Email addresses
- Domain names
- URLs and HTTP paths
- HTTP status codes
- Timestamps in three common formats (ISO 8601, Apache, syslog)

For Apache and nginx access logs there is a fast-path regex that pulls IP + timestamp + method + path + status in a single match, which matters when you're processing a multi-gigabyte file.

The output ranks each category — top 10 IPs by request count, top 10 paths, top 5 emails — and classifies each IP as private, public, loopback, or link-local. That last bit alone is often enough to surface a misconfiguration: a public-facing service should not be logging requests from `10.x.x.x` unless you have a real reason for it.

## Pattern 1: brute force

Brute force has a very recognisable shape in a log. The same IP makes many requests, most of which receive a 4xx response (401 Unauthorized or 403 Forbidden), and almost all of which target a small number of URLs (a login form, an admin panel, a `/wp-login.php`).

The tool's threshold is configurable — by default it flags any IP that gets ten or more 4xx responses. On a moderately busy server you usually want to raise this to 25 or 50, otherwise normal users with bad bookmarks will trip it. On a quiet internal application the default is fine.

```bash
$ tools/log_parser.py access.log --bruteforce 25
```

In a real run, the finding looks like this:

```
Suspicious patterns (3):
  ✗ Brute-force suspect: 185.220.101.5 → 187 4xx responses
  ✗ Brute-force suspect: 91.234.56.78  → 54 4xx responses
  ...
```

187 failed responses from a single IP is not a typo on someone's part. The follow-up is to check what they were hitting (almost always a login page), what user agent they used (almost always something obviously scripted), and whether any of their 5xx or rare 2xx responses suggest the attempt succeeded.

## Pattern 2: scanner activity

A scanner has a different shape: one IP touching many different paths, most of which return 404. Whoever it is, is enumerating — running a wordlist against your server to find admin panels, backup files, exposed `.env` files, and the rest of the usual list.

The tool flags any IP that hits more than 50 unique paths. In practice this catches automated scanners — `nikto`, `gobuster`, the recon stage of an opportunistic worm — long before they get anywhere interesting.

```
✗ Scanner: 91.234.56.78 → 124 unique paths (likely scanner)
```

You can usually see this pattern coming because the request rate is too fast for a human. Five hundred requests in two minutes is not someone browsing.

## Pattern 3: sensitive paths

This one is about absolute, not relative, signal. Some paths should almost never appear in a healthy log:

- `/.env`
- `/.git/config`
- `/wp-admin/`
- `/backup.zip` or `*.bak` files
- `/admin/`
- `/phpmyadmin/`

The tool keeps a regex pattern for these and counts how often any line in the log hits one. If `/.env` shows up 45 times, that is not because 45 different legitimate users happened to type `.env` into their browser. It is one or more scanners attempting to lift your environment variables.

```
✗ Sensitive path hits: /.env (45×), /.git/config (12×), /wp-admin/ (8×)
```

Two follow-ups worth doing: confirm the paths don't actually exist (a `200` response on `/.env` is a serious problem, not a curiosity), and consider whether the IPs hitting them overlap with the brute-force and scanner findings — usually they do.

## A worked example

A small access log fragment:

```
185.220.101.5 - - [15/Jan/2026:14:32:18 +0000] "GET /wp-login.php HTTP/1.1" 401 4571
185.220.101.5 - - [15/Jan/2026:14:32:19 +0000] "POST /wp-login.php HTTP/1.1" 401 4571
185.220.101.5 - - [15/Jan/2026:14:32:20 +0000] "POST /wp-login.php HTTP/1.1" 401 4571
91.234.56.78 - - [15/Jan/2026:14:33:01 +0000] "GET /.env HTTP/1.1" 404 134
91.234.56.78 - - [15/Jan/2026:14:33:01 +0000] "GET /.git/config HTTP/1.1" 404 134
91.234.56.78 - - [15/Jan/2026:14:33:02 +0000] "GET /backup.zip HTTP/1.1" 404 134
```

Even with six lines, the two patterns are visible: one IP brute-forcing WordPress, another scanning sensitive paths. On a real log you will not see them this cleanly — they're hidden under thousands of normal requests — but the structure underneath is the same.

## What to do with the findings

Three immediate next steps, in order:

1. **Block the source.** If your firewall, CDN, or WAF accepts IP rules, that is the cheapest action. Fail2ban automates this for SSH and a few other services.
2. **Investigate the gaps.** Did any of the 4xx responses ever become a 2xx? Did the scanner find anything? `grep` the sensitive paths against the full log for status `200`.
3. **Push the data to a SIEM if you have one.** The JSON output (`--json`) is designed to be piped into another tool. The structure is stable: `ip_stats`, `url_stats`, `email_stats`, `date_range`, `suspicious`.

```bash
$ tools/log_parser.py access.log --json | \
    jq '.suspicious[] | select(.kind == "bruteforce")'
```

## Where to find it

[`tools/log_parser.py`](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/log_parser.py) is Python 3.8+ stdlib only — no external dependencies, streams line-by-line so it handles multi-gigabyte logs comfortably.

```bash
git clone https://github.com/ciberacaro/ciberacaro.github.io.git
cd ciberacaro.github.io
python3 tools/log_parser.py /path/to/access.log
```

---

*This tool maps directly to the Portuguese CET in Cybersecurity curriculum, units UC01481 (cybersecurity scripting) and UC01482 (log normalisation and filtering). If you're following that programme, it's a useful reference implementation of the techniques both units describe.*
