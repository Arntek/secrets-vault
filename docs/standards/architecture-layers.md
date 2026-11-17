<!-- dev-standards v1 (2026-11-10) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Architecture layers

Each layer has one job and only calls the layer(s) beneath it. The goals: agents always know where code goes, and a vendor (email, database, auth, AI, storage) can be swapped by changing one adapter and one env var, never business logic.

## 1. Pick the size first

| Project type | Layers used |
|---|---|
| **Website** - mostly content, forms, maybe a CMS (e.g. westside-website, pro-d-website) | UI, entry points (form handlers), adapters (mail, storage, CMS). No domain or repository layers unless real business rules appear. |
| **App** - users, roles, data and business rules (e.g. ebcfo-os, assessify-platform) | All layers below. |

Don't build empty layers. If a website grows real rules, add the domain and repository layers then.

## 2. The layers (apps)

| Layer | Job | May call | Must never |
|---|---|---|---|
| **UI** | Screens and components | Entry points for writes; repositories for reads (server-rendered only - see rule A) | Hold business rules; call adapters; run client-side database access |
| **Entry points** - server actions, API routes, MCP tools, background jobs | Turn a request into a domain call: authenticate, validate input, map errors to the caller's format | Domain | Contain business rules; write to the database or call adapters directly |
| **Domain** (business logic) | What the system does: rules, workflows, transactions, and the permission rules (see rule B) | Repositories, adapters (through their interfaces) | Know about HTTP, cookies, sessions, frameworks or which vendor is used |
| **Repositories** | The only code that reads or writes the database; maps rows to domain objects; applies permission rules to reads | Database connection; permission functions from the domain | Contain business workflows; make up their own permission logic |
| **Adapters** (external providers) | One interface per outside service; one thin implementation per vendor | The vendor SDK / API | Decide *when* or *whether* something happens - the domain decides |
| **Config** | Reads env vars and picks which adapter implementation to use | - | Be read anywhere except where adapters are wired up |

Dependency direction is one-way. Nothing calls upward.

### Rule A - reads may skip the domain, writes never do
- **Reads:** server-rendered pages and components may call repository read functions directly. Don't write a domain function that only passes a read through.
- **Writes:** every create / update / delete goes entry point → domain → repository, so business rules always run.
- If a read needs business logic (calculated totals, filtered by rules beyond permissions), put that in the domain and read through it.

### Rule B - permissions live in one place
- Permission rules are plain functions in the domain (e.g. `domain/permissions.ts`: `canViewClient(user, client)`, `visibleClientsFilter(user)`).
- The domain calls them before writes. Repositories call them to scope reads (e.g. add the filter to the query).
- Nobody else invents permission checks. Entry points only establish *who* the caller is.

## 3. Adapters - only where they earn it

Create an adapter when at least one is true:
- it sends something outside (email, SMS, payments, webhooks out), or
- switching vendors is plausible, or
- agents need a local fake to work without real accounts.

Otherwise call the library directly in the layer that needs it. Keep adapters thin: an interface with the few methods the app uses, not a general wrapper around the vendor's whole SDK.

| Adapter | Typical providers |
|---|---|
| `auth` | google / dev (localhost only) / preview |
| `mail` | console / mailpit (local) / resend / sendgrid |
| `storage` | local folder / DO Spaces / S3 / Box |
| `ai` | canned (tests) / anthropic |
| `payments`, `sms`, `realtime`, integrations | as needed, same pattern |

Rules:
- Interface in one file, providers beside it (e.g. `adapters/mail/types.ts`, `adapters/mail/providers/resend.ts`).
- The domain receives adapters through one factory or injection; it never imports a provider file.
- Inbound webhooks: API route → adapter (verify + parse) → domain (handle).

## 4. Database - one real database everywhere
- Repositories have **one** implementation, against the real database engine (Postgres / Neon). No second "fixtures" version of repository code.
- Local development and tests use a real local Postgres - in-process (PGlite) or Docker - loaded from a seed script kept in the repo. Production uses Neon.
- Only the connection string changes between environments.
- Seed data includes at least one user per role (used by the dev login - see `dev-login.md`).

## 5. Other rules
- Validation schemas (e.g. Zod) are defined once and shared by entry points and domain.
- The domain returns typed results or typed errors for expected failures; it does not throw across layers.
- Secrets only via env vars. Never commit credentials.
- Enforce the boundaries with a lint rule (e.g. dependency-cruiser) where the stack makes it cheap, and fail CI on violations.

## 6. Quick test

| If the code... | It belongs in |
|---|---|
| enforces a business rule or changes data | Domain |
| decides who may see or do something | Domain permission functions |
| reads or writes the database | Repository |
| talks to an outside service that sends things or might be swapped | Adapter |
| handles a form, button, API request, tool call or job | Entry point |
| only displays data | UI, reading from repositories |

## 7. Naming note
Older repos use different names for the same layers. Map them in the repo's `CLAUDE.md` "Layer map" rather than renaming code:
- assessify-platform, taskbox-zero: "services" = **Domain**; "adapters" = **Adapters**
- ebcfo-os: `src/domain` = **Domain**; `src/services/*` = **Adapters**

New projects use the names in this file: `domain`, `repositories`, `adapters`.

**When Arnold says "services"** he usually means the outside providers - email, auth, database connection, storage - which this standard calls **adapters**. If it's unclear whether he means adapters or business logic, ask him.
