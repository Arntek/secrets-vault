<!-- dev-standards v4 (2026-11-16) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Agent workflow (several agents at once)

## Issues: beads
- Issues live in beads (`bd`). Start with `bd ready`; claim before working (`bd update <id> --claim`); close with a note.
- Run `bd dolt pull` before claiming work and `bd dolt push` straight after any issue change. If a push is rejected: `bd dolt pull`, then `bd dolt push`.
- The database syncs through GitHub on a hidden ref (`refs/dolt/data`), so it never triggers a deploy. The session-start hook sets this up automatically.
- **Never** run `bd migrate` or `bd dolt push --force`. If bd reports "pending schema migrations" or "no common ancestor", stop and tell Arnold.
- bd version is pinned (see `.claude/hooks/beads-session-start.sh`). Don't install a different version.

## Sessions
- Each agent (UI/UX, Developer, QA, Security, Ask the Human) is its own Claude Code session started by the coordinator with `start_session`, not a background subagent, so Arnold can open, watch and talk to it. See `agent-team.md`.
- Background subagents are only for quick read-only lookups.

## Worktrees and dev servers
- One worktree per session writing code at the same time: the coordinator starts each such session with `use_worktree: true`. Read-only sessions (e.g. QA reviewing a merged branch) may share the checkout. Worktrees share the repo's beads database.
- Each worktree runs its own dev server on the port given in its session brief.

## Browsers and sign-in
- Each agent uses its own `*.localhost` hostname for the whole session. See `dev-login.md`.
- The coordinator gives each session its hostname and port in the session brief.

## Messaging
- Sessions report back to the coordinator when they finish a turn: what they did, what they verified, what they couldn't verify.
- A session can message the coordinator or another session with `SendMessage` to that session's id. Use it for blocking questions and hand-offs; beads holds the issue state.
- Questions only Arnold can answer go to the coordinator, which sends them to the **Ask the Human** session (his single inbox) as numbered questions, not to its own chat. Ask the Human sends his answers back to the coordinator. The coordinator reviews results, merges or commits, and reports to Arnold.

## Local services
- Every external service has a local provider (see `architecture-layers.md`), so agents never need production accounts. Email goes to Mailpit or the console, not to real people.
