---
title: "Subdomain takeover: finding the dangling CNAMEs everyone forgets"
date: 2026-05-18 12:15:00 +0100
categories: [Notes, Tools]
tags: [subdomain-takeover, dns, cname, recon, bug-bounty]
pin: false
permalink: /posts/subdomain-takeover-dangling-cnames/
---

> Versão em português: [Subdomain takeover: encontrar os CNAMEs órfãos](/posts/subdomain-takeover-cnames-orfaos/).
{: .prompt-info }

A subdomain takeover is the kind of bug that sounds almost too simple to be real. An organisation creates a subdomain — say `marketing-campaign.example.com` — and points it at a third-party service like GitHub Pages, Heroku, or an S3 bucket. The campaign ends. Someone deletes the GitHub Pages site, or the Heroku app, or the S3 bucket. The DNS record stays.

Now anyone who can register a new GitHub Pages site (or Heroku app, or S3 bucket) with the matching name can serve content under `marketing-campaign.example.com`, with all the trust that the parent domain carries — including, in many cases, cookies and CORS access.

It's an easy bug to introduce, very easy to miss, and a recurring entry on HackerOne, Bugcrowd, and similar platforms.

## How it actually happens

The pattern is always the same:

1. A marketing or engineering team creates `subdomain.example.com` pointing at `myproject.github.io` (or any other service).
2. Months later, the team deletes the project from the service.
3. Nobody removes the DNS record.

The CNAME now points at a name that resolves but is "unclaimed" — the service still serves something, but it serves an error page that effectively says *"this site is not configured"*. An attacker who registers `myproject` on the same platform now controls `subdomain.example.com`.

## What you can do with one

The impact depends on the trust the parent domain carries:

- **Cookie theft** if the cookie scope is set to `.example.com`.
- **CORS bypass** if the application trusts `*.example.com` origins.
- **Phishing** with a perfectly legitimate URL.
- **Brand damage** — content under your domain that you didn't write.
- **Bypass of HSTS preload pinning** in some configurations.

Some of these need other conditions to line up, but the *position* — serving content under a trusted domain — is the foothold.

## Finding them

You need three things:

1. **A list of subdomains.** Either you enumerate them (crt.sh certificate logs, brute force, passive DNS) or you have one already.
2. **Each subdomain's CNAME.** A DNS query, nothing fancy.
3. **A way to tell whether the CNAME target is "unclaimed".** Each service has a recognisable error page; matching the response body against a known fingerprint is enough.

`subdomain_takeover.py` does all three:

```bash
$ tools/subdomain_takeover.py example.com
```

It auto-enumerates via crt.sh, resolves CNAMEs over raw UDP/53, and checks each against 16 service fingerprints — GitHub Pages, Heroku, Netlify, AWS S3, Azure, Fastly, Shopify, Tumblr, WP Engine, and others.

For a domain you already have a subdomain list for:

```bash
$ tools/subfinder.py example.com --json | jq -r '.resolved[].host' | \
    tools/subdomain_takeover.py example.com --subdomains -
```

## What a vulnerable result looks like

Real-shaped output (sensitive bits redacted):

```
Domain: example.com
Subdomains checked: 14

Vulnerable (2):
  marketing-campaign.example.com
    CNAME  → marketing-campaign-2022.github.io
    Service: GitHub Pages
    Status: VULNERABLE — unclaimed service detected

  old.example.com
    CNAME  → old-example-app.herokudns.com
    Service: Heroku
    Status: VULNERABLE — unclaimed service detected
```

The combination that flags a finding is *(matching CNAME pattern) AND (matching "unclaimed" body fingerprint)*. A CNAME pointing at `*.github.io` is not by itself a vulnerability — it's only a vulnerability when the GitHub Pages site no longer exists.

## What NOT to do

Once you've found a real vulnerable subdomain:

- **Do not register the service yourself.** Even with good intentions, that constitutes unauthorised use. In Portugal the Cybercrime Law (Lei n.º 109/2009) treats unauthorised access to information systems as a criminal offence, and "I was going to give it back" is not a defence.
- **Report through the right channel.** If the organisation publishes a `security.txt` (at `/.well-known/security.txt`) it tells you where to send vulnerability reports. Otherwise look for a VDP or bug bounty programme.
- **Document the finding before you report it.** Take a screenshot, save the DNS response, save the HTTP fingerprint. You want the report to be reproducible without further action on the vulnerable subdomain.

## Limitations of this approach

Three things this tool does not do:

- **Brand-new services.** Service fingerprints go stale. New PaaS providers come out, old error pages change. The current list of 16 covers the common cases but is not exhaustive — `can-i-take-over-xyz` is the community-maintained list to compare against if you're hunting seriously.
- **Wildcard CNAMEs.** If `*.example.com` points at a service, the resolution behaviour can be unpredictable.
- **Authenticated services.** Some takeovers (Azure DNS, some Fastly setups) require additional steps the tool cannot automate.

But for an organisation's perimeter audit, or for a starting point in a bug bounty, this catches the easy cases reliably.

## Where to find it

[`tools/subdomain_takeover.py`](https://github.com/ciberacaro/ciberacaro.github.io/blob/main/tools/subdomain_takeover.py) is Python 3.8+ stdlib only — no `pip install`, no external DNS library.

```bash
git clone https://github.com/ciberacaro/ciberacaro.github.io.git
cd ciberacaro.github.io
python3 tools/subdomain_takeover.py your-target.example
```

Pair it with [`recon.py`](/posts/web-recon-stdlib-python/) for the wider picture.

---

*Further reading: the [HackerOne Hacktivity feed](https://hackerone.com/hacktivity?type=public) has hundreds of disclosed reports tagged "Subdomain takeover" — the writeups are some of the best free training material for spotting the pattern.*
