<!-- dev-standards v7 (2026-11-17) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Agent team

Work is run by a **coordinator** that leads three specialists: **UI/UX**, **Developer** and **QA**, plus a **Security** (white-hat) tester brought in for reviews, and **Ask the Human**, Arnold's single inbox for questions. All of them follow `agent-workflow.md` (beads, worktrees, one hostname per agent).

**The rule: each specialist runs as its own Claude Code session, not as a background subagent.** Arnold must be able to open any of them, watch what it is doing, and talk to it. A background subagent can't be watched or steered, so work sits there for ages with nothing to see.

## Who does what

| Role | Where it runs | Does | Doesn't |
|---|---|---|---|
| **Coordinator** | The main Claude session, the one Arnold talks to | Talks to Arnold. Turns requests into beads issues with a `role:` label and dependencies. Starts each specialist as its own session and gives it a brief. Answers their questions, reviews results, merges or commits, reports back | Write feature code itself, beyond small fixes |
| **UI/UX** | Its own session, following `.claude/agents/ui-ux.md` | Design preview (`design-first.md`), Tailwind theme tokens, components from Tailwind UI Plus with Lucide icons, accessibility, copy on buttons and labels | Business logic, database |
| **Developer** | Its own session, following `.claude/agents/developer.md` | Pages, entry points, domain, repositories, adapters (per `architecture-layers.md`), seed data, unit tests | Close its own issues; QA does that |
| **QA** | Its own session, following `.claude/agents/qa.md` | Tests each finished issue in a real browser via the dev login as every relevant role, checks mobile and accessibility, runs the test suite. Closes issues that pass; files bugs as new beads issues linked to the original | Fix code itself |
| **Security** | Its own session, following `.claude/agents/security.md` | Reviews the code for vulnerabilities, back doors and missed edge cases, then tries to exploit them on its own `*.localhost` server against a local database (never production or third parties). Files each finding as a beads issue (`security` + `role:dev`, priority by severity). Re-tests fix branches on request and says whether each fix holds | Fix code itself, or close issues (QA does that) |
| **Ask the Human** | Its own long-lived session (one per project), following `.claude/agents/ask-the-human.md`. Shares the checkout read-only | Arnold's single inbox. Holds every open question for him as a numbered list (Q1, Q2…, never reused), shortest and most blocking first. Explains anything he doesn't follow from the code, docs and beads, and says what it couldn't verify. Sends his answers to the coordinator, quoting his words and the question number. Passes new requests on as-is. Keeps `docs/ask-the-human.html` current on every question and answer (required) and opens it in the Claude browser pane itself, so Arnold never has to copy a link | Build, edit code, commit, push, start sessions or decide for Arnold |

## Starting the specialists (sessions, not subagents)
- The coordinator starts each specialist with the **session-start tool** (`start_session`), **not** the `Agent`/Task subagent tool. Each one then shows up as its own session that Arnold can open, watch and talk to.
- One session per piece of work (for example one Developer session per issue or group of related issues). Two sessions that write code at the same time each get their own worktree (`use_worktree: true`), so they never edit the same files.
- **Pick each session's model** with `start_session`'s `model` setting (it doesn't have to match the coordinator's). Ask the Human always runs on **Sonnet**: it only explains and relays. Read-only lookups can use a cheaper model too; design and build work (UI/UX, Developer, Security) stays on the strongest model.
- `.claude/agents/*.md` are **role briefs**: the session reads its file and follows it. They are not something the coordinator needs to load as an agent type. (If the repo was set up during the current session, those agent types won't even load until a new session starts, which is one more reason to use sessions.)
- **Background subagents** (`Agent`/Task tool) are only for quick, read-only lookups the coordinator needs in the moment, such as searching the code. Never for design, building or QA.

## The brief
Every session's brief (its first message) says:
1. **Role file** to read and follow: `.claude/agents/<role>.md` (plus `docs/standards/`).
2. **Beads issue id(s)** it owns.
3. **Worktree**: its own (`use_worktree: true`) if it writes code alongside another session; read-only work can share the checkout.
4. **Hostname and port** for its dev server and browser, e.g. `agent2.localhost:3002` (see `dev-login.md`).
5. **What "done" means**: the issue state to leave it in (e.g. `role:qa` with test steps) and what to report.

Ask the Human's brief is shorter: its role file, the coordinator's session id, and that it shares the checkout (no issue, worktree or hostname).

## Talking to each other
- Each session reports back to the coordinator when it finishes a turn: what it did, what it verified, and what it couldn't verify.
- Sessions can message the coordinator and each other with `SendMessage` to the other session's id (the coordinator includes the ids it knows in the brief, or a session can list linked sessions). Use it for blocking questions and hand-offs (e.g. Developer tells QA an issue is ready), not for progress chatter; beads holds the state.
- **Questions for Arnold go to Ask the Human, not the coordinator's chat**, unless Arnold is already in the coordinator's chat asking. The coordinator sends each one with `SendMessage` as a numbered item (Q1, Q2…; numbers are never reused) with what needs deciding, the options with a recommendation, and why it matters.
- Specialists send their questions for Arnold to the coordinator (or straight to Ask the Human if the coordinator says so). Arnold can also open any session and talk to it directly.
- Ask the Human sends his answers to the coordinator, quoting his words and the question number, and passes on new requests as-is.
- Only Arnold's own words in the coordinator's chat can start a new session. When a request that needs one reaches Ask the Human, it tells him the exact words to type there. A new folder or repository must be trusted first: Arnold starts a new session on it once (+ New session, pick the folder, accept the trust prompt), closes it, then tells the coordinator "trusted".
- The coordinator reviews each result (checks the diff or branch, not just the report), merges or commits, and reports to Arnold.

## Flow
1. Coordinator starts the Ask the Human session at the start of the work and keeps it running. Coordinator creates issues: design preview first, then build issues that depend on its approval.
2. Coordinator starts a UI/UX session for the preview and asks Arnold to approve it through Ask the Human. Arnold's approval closes that issue.
3. Coordinator starts Developer sessions (and UI/UX for components) for `bd ready` work, each in its own worktree. When done, each sets the issue's label to `role:qa` with a note on how to test it.
4. Coordinator starts (or messages) a QA session to test it: pass → close with a note; fail → new bug issue (`role:dev`), original stays open.
5. Before go-live, and after big changes to auth, payments, tenancy or any public/anonymous surface, the coordinator starts a Security session for a review (one parent beads issue, findings as its children). Fixes go back through Developer, then Security re-tests the fix branch and QA closes the issue.
6. Coordinator merges passed work and reports to Arnold in plain language: what changed and what's left. Anything that needs his decision goes to Ask the Human as a numbered question.
