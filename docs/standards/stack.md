<!-- dev-standards v4 (2026-11-14) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Default stack

Use these for every new website or app unless the repo's `CLAUDE.md` says otherwise. Existing repos keep what they have.

| Area | Default | Notes |
|---|---|---|
| Framework | **Next.js** (App Router, TypeScript) with **React** | Server components by default; client components only where interaction needs them |
| Styling | **Tailwind CSS** | Design tokens (colours, fonts, radius) live in the Tailwind theme, not scattered through components |
| UI components | **Tailwind UI Plus** (Arnold has a licence) | Start from UI Plus blocks and the Catalyst kit (admin screens) rather than designing from scratch. Copy only the components used; don't commit the whole library. Agents can't download UI Plus themselves: match its patterns and ask Arnold to paste the exact component when it matters |
| Icons | **Lucide** (`lucide-react`, lucide.dev) | One icon set only. UI Plus examples use Heroicons, so swap them for the Lucide equivalent when copying |
| Database | **Neon** Postgres (production) | Local and tests use a real local Postgres; see `architecture-layers.md` section 4. Compute never set to "never suspend" and every temporary branch expires in 24 hours; scheduled jobs only `curl` the app and the app skips the database until something is due; see `neon.md` |
| Hosting | **DigitalOcean** (`doctl`) | Unless the project says otherwise. Timed work uses App Platform scheduled jobs that `curl` the web service over the internal network (job endpoints answer 404 on public hosts); see `neon.md` section 5 |
| Source control | GitHub | **Client and EBCFO work goes in the `ebcfo` org**, not `arntek` or `arnoldsmyth`. If it's unclear which org, ask Arnold before creating the repo |

Sign-in method is decided per project. Every app with sign-in still has the localhost-only dev login (`dev-login.md`).

## Before building
Get a design preview approved first. See `design-first.md`.
