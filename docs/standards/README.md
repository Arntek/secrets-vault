<!-- dev-standards v8 (2026-11-16) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Dev standards

Shared rules for every project. Read them all before writing code.

| File | Covers |
|---|---|
| `stack.md` | Default stack: Next.js, Tailwind + Tailwind UI Plus, Lucide icons, Neon, DigitalOcean, which GitHub org |
| `design-first.md` | Template preview approved by Arnold before any UI is built |
| `architecture-layers.md` | Website vs app size, the layers, reads vs writes, permissions, adapters, and the database rule |
| `neon.md` | Neon compute, branches and keeping it asleep: never "never suspend", every temporary branch expires in 24 hours, rehearsals prove their target, timers call the app (never the database), skip the database until something is due, one web instance, no database reads for read-only pages |
| `dev-login.md` | Localhost-only dev sign-in, its safety gates, and one hostname per agent |
| `agent-team.md` | Coordinator + UI/UX, Developer, QA, Security (white-hat) and Ask the Human (Arnold's inbox), each run as its own session: who does what, the session brief, and how work moves between them |
| `agent-workflow.md` | Beads, sessions, worktrees, browsers, dev servers and messaging when several agents work at once |

These files describe the rules. **Where each layer lives in this repo** and **who uses the site** belong in the repo's own `CLAUDE.md`.
