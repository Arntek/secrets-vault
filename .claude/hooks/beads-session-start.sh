#!/usr/bin/env sh
# Beads sync setup for Claude Code sessions (local, worktree or cloud).
# Runs on SessionStart: installs bd if missing, links the beads database to
# this repo's GitHub origin (hidden ref refs/dolt/data - not a branch, no deploy),
# pulls the latest issues, then prints bd prime for the agent.
export GIT_TERMINAL_PROMPT=0 BD_NON_INTERACTIVE=1
cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0
# macOS has no `timeout` by default
t() { if command -v timeout >/dev/null 2>&1; then timeout 120 "$@"; else "$@"; fi; }

if ! command -v bd >/dev/null 2>&1; then
  npm install -g @beads/bd@1.3.4 >/dev/null 2>&1 || { echo "beads: could not install bd"; exit 0; }
fi

# Fresh clone (e.g. cloud session): build the database from GitHub
if ! bd dolt remote list >/dev/null 2>&1; then
  t bd bootstrap --yes >/dev/null 2>&1
fi

# Link the Dolt remote to git origin if not already set
if ! bd dolt remote list 2>/dev/null | grep -q '^origin'; then
  url=$(git remote get-url origin 2>/dev/null)
  case "$url" in
    https://*|http://*|file://*) durl="git+$url" ;;
    git@*:*) durl="git+ssh://$(echo "$url" | sed 's#:#/#')" ;;
    ssh://*) durl="git+$url" ;;
    *) durl="" ;;
  esac
  [ -n "$durl" ] && GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null bd dolt remote add origin "$durl" >/dev/null 2>&1
fi

t bd dolt pull >/dev/null 2>&1 || echo "beads: bd dolt pull failed - run it manually before claiming work"
bd prime
exit 0
