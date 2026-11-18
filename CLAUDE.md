# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Build & Test

_Add your build and test commands here_

```bash
# Example:
# npm install
# npm test
```

## Architecture Overview

_Add a brief overview of your project architecture_

## Conventions & Patterns

_Add your project-specific conventions here_

## Beads sync (all agents, local and cloud)

The beads database syncs through this repo's GitHub origin on a hidden ref (`refs/dolt/data`) - not a branch, so it never triggers a deploy. The SessionStart hook (`.claude/hooks/beads-session-start.sh`) installs bd if missing, links the Dolt remote, and runs `bd dolt pull`. Run `bd dolt pull` before claiming work and `bd dolt push` straight after any issue change (create, claim, update, close). If a push is rejected, `bd dolt pull` then `bd dolt push` again.

## Dev standards

Read `docs/standards/` before writing code: default stack (`stack.md`), design preview before building (`design-first.md`), layers (`architecture-layers.md`), Neon compute, branches and keeping it asleep (`neon.md`), dev login + one hostname per agent (`dev-login.md`), the agent team (`agent-team.md`) and multi-agent workflow (`agent-workflow.md`). Those files are copied from arnoldsmyth/dev-setup - don't edit them here.

### Layer map (this repo)

<!-- Fill in: where each layer lives in this repo, e.g. Domain = src/domain, Repositories = src/repositories, Adapters = src/adapters/<name>/ -->

### Who uses this site

<!-- Fill in: the users and editors (e.g. "older, non-technical staff edit content"). Design and QA follow this. -->

## Agent team

Rule: run the agent team as separate Claude Code sessions (`start_session`), never as background subagents. Follow `docs/standards/agent-team.md`.

The main Claude session is the **coordinator**: it talks to Arnold, plans work as beads issues, and starts the UI/UX, Developer, QA and Security (white-hat) specialists as **separate sessions** that Arnold can open and talk to, plus a long-lived **Ask the Human** session that is his single inbox. Each session follows its role brief in `.claude/agents/<role>.md` and gets its issue, worktree, `*.localhost` hostname and port, and what "done" means. Sessions report back to the coordinator and can message each other. QA closes issues, not the developer. Questions for Arnold go to Ask the Human as numbered items (Q1, Q2…), not the coordinator's chat, unless he is already asking there.

## This project: secrets-vault (Go CLI)

A command-line secrets manager installed by Homebrew (Phase 1) and npm (Phase 2). Commands: `secrets-vault`, with short names `vault` and `sv`.

- **Stack overrides `docs/standards/stack.md`:** Go (1.27+) for the CLI, plus a small Swift helper or Swift library for macOS Touch ID (CryptoKit Secure Enclave). No web framework, database, Neon, hosting or dev login. "UI" means the terminal UI (`vault ui`); there is no browser UI by design.
- **Design doc:** `/Users/asmyth/Documents/Development/the-secrets-vault/docs/private/vault-cli-design.html` (local only, git-ignored because it contains personal paths and vault names). Read it before working. Its Decisions section (D1-D10) is settled.
- **Never commit vault data, real keys, personal paths or real key names.** Tests use generated keys and canary values. This repo is public.
- **Phase 0 (done):** `spikes/phase0-touchid` proves Touch ID via the Secure Enclave from an unsigned ad-hoc build. This Mac's Command Line Tools need the vfsoverlay in that README to compile Swift.
- **Security testing is required from the first commit:** leak tests (canary values must never appear in output/logs/errors), tamper tests, Go fuzzing of every parser, gosec, govulncheck, CodeQL, gitleaks. See the design doc's Security testing section.
