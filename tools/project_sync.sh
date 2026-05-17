#!/usr/bin/env bash
# Show what needs to be re-uploaded to the claude.ai Project to keep its
# knowledge in sync with this repo. Also activates the post-commit hook
# the first time it's run.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TRACKED_FILES=("CLAUDE.md" "SESSION_LOG.md")
PROJECT_URL="https://claude.ai/projects"

# Activate the hook once per clone (idempotent).
CURRENT_HOOKS_PATH="$(git config --get core.hooksPath || true)"
if [ "$CURRENT_HOOKS_PATH" != ".githooks" ]; then
  echo "→ enabling git hooks (one-time setup for this clone)"
  git config core.hooksPath .githooks
fi

echo
echo "Project to keep in sync: Cybersecurity Portfolio at $PROJECT_URL"
echo

printf "%-18s  %10s  %s\n" "FILE" "SIZE" "LAST CHANGED (this repo)"
printf "%-18s  %10s  %s\n" "----" "----" "------------------------"
for f in "${TRACKED_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    printf "%-18s  %10s  %s\n" "$f" "missing" "—"
    continue
  fi
  size=$(wc -c < "$f" | tr -d ' ')
  last=$(git log -1 --format=%cd --date=iso -- "$f" 2>/dev/null || echo "uncommitted")
  printf "%-18s  %10s  %s\n" "$f" "$size" "$last"
done

echo
echo "Raw URLs to upload (or copy-paste content from):"
for f in "${TRACKED_FILES[@]}"; do
  echo "  https://raw.githubusercontent.com/ciberacaro/ciberacaro.github.io/main/$f"
done

# Check if there are unpushed commits touching these files.
UNPUSHED=$(git log @{u}..HEAD --name-only --pretty=format: 2>/dev/null | grep -E "^(CLAUDE\.md|SESSION_LOG\.md)$" | sort -u || true)
if [ -n "$UNPUSHED" ]; then
  echo
  echo "WARNING: unpushed commit(s) modify these files — push first or upload"
  echo "         a version that will be out of date in seconds."
  echo "$UNPUSHED" | sed 's/^/         - /'
fi

echo
