<!-- dev-standards v2 (2026-11-16) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Dev login

Agents need to sign in and out as any user and role while developing. Every app with sign-in provides a **dev login**: a localhost-only page listing seeded users with their roles, one click to sign in as any of them. It is an `auth` adapter provider (`dev`), selected by env var, next to the real one (e.g. `google`).

Reference implementation: ebcfo-os (`web/src/services/auth/dev-gate.ts`, `dev.ts`, `dev.disabled.ts`, `src/proxy.ts`, `scripts/check-prod-safety.mjs`).

## Layout (copy this)
Reference screenshots: `images/sign-in.png` and `images/dev-login.png` (from ebcfo-os).

**Sign-in page** - centred white card on the app's dark background: logo, "Sign in", one line of help text, the real provider button (e.g. "Continue with Google"), a divider, then a "Developer login (localhost only)" link. The link only renders when dev login is allowed (same gate as below).

**Developer login page** - same card style:
- A "Localhost only" pill (amber) above the title "Developer login".
- One line of help text explaining the password pattern.
- A scrollable list of seeded users, one row each: radio button, **name** · job title, and a small role tag on the right (e.g. admin, leadership, client team). The selected row is highlighted.
- A password field, pre-filled for the selected user (pattern `pwd.<firstname>123!`), so the flow matches a real password sign-in.
- One full-width button: "Sign in as <first name>".
- After sign-in, show the current user and a sign-out control somewhere persistent (e.g. the account menu), so agents can switch users quickly.

## Three safety gates (all required)
1. **Runtime gate.** Dev login works only when `NODE_ENV !== "production"` AND `AUTH_DEV=enabled` AND the request host is local. Any other host gets a 404 for the dev login route (middleware / proxy).
2. **Build gate.** Production builds swap the dev auth module for a stub (bundler alias), so the code is never shipped.
3. **Pre-build check.** A script runs before every build; when `DEPLOY_TARGET=production` it fails the build if dev auth, a non-production auth provider, or a local/seed database is configured.

Dev login is only as local as the machine. **Never forward the dev port to another machine or the network** (`ssh -R`, a tunnel, a port forwarder): the forwarded request still looks local, so the app can't tell it apart and anyone who reaches it can sign in as any user.

"Local host" means `localhost`, `127.0.0.1`, `[::1]` **and any `*.localhost` name** (they always resolve to this machine). Allow `*.localhost` in the framework's dev-origin settings too (Next.js: `allowedDevOrigins: ["127.0.0.1", "::1", "*.localhost"]`).

## One hostname per agent
Browsers keep cookies per **hostname**, not per port. Agents that share one browser (a coordinator and its sub-agents working in tabs of the same browser) share one session cookie on plain `localhost`, so they keep signing each other in and out.

Rule: **every agent uses its own hostname** and never switches.
- The coordinator assigns names when it spawns agents: `agent1.localhost`, `agent2.localhost`, ... (or the worktree name: `<worktree>.localhost`).
- Any agent can sign in as any user/role on its own hostname. Role is chosen on the dev login page, not by hostname.
- Separate worktrees run separate dev servers on separate ports: `agent1.localhost:3001`, `agent2.localhost:3002`. The hostname separates the cookies; the port separates the servers.
- Never use plain `localhost` when more than one agent is active.

## API testing without a browser
For curl / script / MCP testing, the dev auth provider also accepts a header **`X-Dev-User: <user id or email>`**, behind the same three gates (local host, `AUTH_DEV=enabled`, not a production build). No cookie is involved, so parallel agents cannot collide.

## Seeded users
Seed at least one user per role, with obvious names (e.g. "Admin Ada", "Viewer Vic"). The dev login page lists name, email and role. Keep the seed in the repo so every machine and cloud session gets the same users.
