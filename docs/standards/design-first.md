<!-- dev-standards v2 (2026-11-11) - copied from arnoldsmyth/dev-setup. Do not edit here; change it in dev-setup and re-run setup-beads-repo.sh. -->
# Design first

Arnold approves a **template preview** before any real UI is built. Building first and redesigning later wastes the most time.

## The preview
- **Static HTML** using Tailwind (CDN build) and Lucide icons, matching Tailwind UI Plus patterns, so the approved design maps straight onto real components.
- **Real content**, never lorem ipsum: from the old site, the client, or the brief.
- **Covers:**
  - the home page
  - one typical inner page
  - the mobile layout
  - any screen the client's own staff will use (sign-in, editing, dashboard)
- Shows the **design tokens**: colour palette, fonts, type scale, button and form styles.
- Kept in `design/preview/` in the repo. It can also be shared as a private Claude artifact for Arnold to show the client.

## Approval
- The UI/UX agent makes the preview; the coordinator shows it to Arnold.
- Track it as a beads issue ("Design preview approved"). Only Arnold's go-ahead closes it.
- Build issues for UI depend on that issue, so `bd ready` doesn't offer them until the design is approved.
- After approval, the tokens move into the Tailwind theme first. Components then use the tokens, never hard-coded colours.

## Audience
Write down who uses the site in the repo's `CLAUDE.md`, and design for them. For example, older or non-technical users need:
- body text 18px or larger
- high contrast
- large tap targets
- plain words on buttons
- one main action per screen
