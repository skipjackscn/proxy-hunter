#!/usr/bin/env bash
set -euo pipefail
REMOTE="${1:-https://github.com/skipjackscn/proxy-hunter.git}"
if ! command -v git >/dev/null 2>&1; then
  echo "Git is required. Install Git and retry." >&2
  exit 1
fi
if [[ ! -f README.md || ! -d .github/workflows ]]; then
  echo "Run this script from the extracted proxy-hunter project directory." >&2
  exit 1
fi
if [[ ! -d .git ]]; then
  git init
  git branch -M main
fi
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE"
else
  git remote add origin "$REMOTE"
fi
git add .
if ! git diff --cached --quiet; then
  git -c user.name="Proxy Hunter Setup" -c user.email="proxy-hunter-setup@users.noreply.github.com" commit -m "Initial Proxy Hunter project"
fi
git push -u origin main
