<!-- dev-standards v2 (2026-11-14) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Neon: compute, branches and keeping it asleep

Why this exists: in October 2026 six rehearsal branches in one project each ran a compute non-stop for two weeks (about 480 compute-hours) because the project default was "never suspend", every branch inherited it, and nobody deleted them. In November 2026 an hourly reminder call in bible-reading-plan queried Neon every time and kept it awake about 2 hours a day, although reminders are due at most twice a week per reader. These rules are not optional.

## 1. Never "never suspend"
- **Never set `suspend_timeout_seconds` to `-1`** (shown in the console as scale to zero disabled / "never suspend") on any compute, branch or project default. Not for production, not "just for now".
- **Project default:** when a Neon project is created, set its default compute to suspend after **300 seconds** idle (`default_endpoint_settings.suspend_timeout_seconds: 300`). Check it before creating any branch: a branch inherits the project default.
- An existing compute that is set to never suspend is a defect: report it to Arnold and file an issue. Only Arnold can approve an always-on compute, and that approval is recorded in the repo's docs with the reason.

## 2. Every temporary branch expires in 24 hours
A temporary branch is anything that is not the long-lived production (or staging) branch: dev and test branches, migration rehearsals, previews, CI branches, experiments. Never leave a test branch or its compute running.
- Create it with **an expiry 24 hours out** and **a suspend timeout of 300 seconds or less**. Both, every time.
  - Neon MCP: `create_branch` with `compute.suspend_timeout_seconds: 300`, then straight away `update_branch` with `expires_at` set to now + 24 h (RFC 3339, UTC, e.g. `2026-11-15T06:00:00Z`).
  - CLI: `neon branches create --project-id <id> --name <name> --expires-at "$(date -u -v+24H +%Y-%m-%dT%H:%M:%SZ)"` (macOS; on Linux `date -u -d '+24 hours' ...`). Existing branch: `neon branches set-expiration <branch-id> --expires-at <timestamp> --project-id <id>`.
  - API: `"expires_at"` on `POST` or `PATCH /projects/{id}/branches`.
- Need it longer than 24 hours? Ask Arnold, then extend the expiry; never remove it. Neon's maximum is 30 days.
- **Delete the branch yourself as soon as its result is recorded.** The expiry is the backstop, not the plan. "Leave the branch in place" is never an instruction to give another agent without an expiry on it.
- Name it for its purpose and date (`phase3-rehearsal-2026-10-30`) so a leftover is obvious.
- Neon will not put an expiry on a protected branch, the default branch, or a branch that has children. Do not create children from a temporary branch.

## 3. A rehearsal proves its target before it writes
- Get the connection string **from the branch id**: MCP `get_connection_string` with `branch_id`, or `neon connection-string <branch-id>` with the branch as the positional argument. `--branch-id` is silently ignored by the CLI and returns the default branch, which is production.
- Print the host and compare it with the branch's own endpoint. If it is production's endpoint, stop.
- A Laravel `DB_URL` without a port takes the port from `DB_PORT`, so set `DB_PORT=5432` beside it.

## 4. Before you end a session
List the project's branches (`list_branches`). Anything you created is deleted or has an expiry. If you find a branch you did not create with no expiry, tell Arnold and file an issue; do not delete someone else's branch without asking.

## 5. Never wake the database on a timer
A suspended compute wakes on any query and then stays up for the suspend timeout. A job that queries every hour keeps it awake for hours a day doing nothing.
- **Scheduled triggers only call the web app, over the internal network.** The default is a DigitalOcean App Platform scheduled job that runs `curl` against the web service by its component name and internal port, never its public domain (for example `curl -fsS -H "Authorization: Bearer $CRON_SECRET" http://web:8080/api/jobs/<name>`). Nothing else.
- **The job endpoint is not public.** Anything under `/api/jobs/*` answers 404 to any request that arrives on a public host (check the `Host` header against the internal component name). It also still checks the bearer secret; both checks, every time.
- **A scheduled job never runs a script that queries the database itself.** Each job run is a fresh container, so it knows nothing from the last run and has to ask the database every time.
- **The endpoint skips the database until something is due:**
  - It keeps the earliest upcoming due time in the web process's memory.
  - Before that time it answers "skipped" without touching the database.
  - It still does a real check at least every 24 hours, as a safety net.
  - After a deploy or restart the time is unknown, so the first call does a real check.
  - Every write that changes a due time (a user changes their schedule, a new record is added) brings the stored time forward if the new one is sooner. No extra database read for that.
  - After a real run, one small query (`min(next_due_at)`) fetches the next due time while the database is awake anyway.
- Reference implementation: `arnoldsmyth/bible-reading-plan`, `src/domain/next-due.ts` and `runReminderJobIfDue` in `src/domain/reminder-job.ts` (branch `claude/reminder-next-due-ae660a` until it is merged).

## 6. The in-memory due time needs exactly one web instance
- It only works with **one** web instance (`instance_count: 1` in `.do/app.json`). With two, a write on one instance does not move the time on the other, and reminders are missed or late.
- Say so in the app's `CLAUDE.md` next to `instance_count`, so nobody scales it up without thinking.
- Need more than one instance? Move the due time to a shared store first (not the database you are trying to keep asleep).

## 7. Read-only pages do not read the database
- No database read per request for pages that only show content. Serve them from data bundled with the app, plus a snapshot the browser caches.
- Only these touch the database: writes, sign-in, admin pages and the due-time check in section 5.
