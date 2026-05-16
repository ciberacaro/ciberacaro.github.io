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

## `run.sh` / `test.sh`

Local Jekyll preview and build-test scripts shipped with the Chirpy starter. Useful for previewing changes locally before pushing.

```bash
bash tools/run.sh      # serve at http://127.0.0.1:4000
bash tools/test.sh     # build and run html-proofer
```

Requires a local Ruby + bundler + Jekyll setup.
