# Claude Code instructions

@AGENTS.md

- Start each session from `docs/dev/PRODUCT_PLAN.md` (current ordered work queue).
- Use `.venv/bin/python` (private Python 3.12); run `.venv/bin/ruff check .` and
  `.venv/bin/python -m pytest -q` before committing.
- Private experiments follow the `lab-experiment` project skill; receipts stay in
  `~/Work/threatfusion-lab/`, never in Git.
- `.claude/hooks/publish_guard.sh` blocks commits/pushes carrying private data
  and pushes that fail lint, tests or the release privacy audit. No hosting is
  connected; never add one without an explicit user request (AGENTS.md).

## Design rules (React workspace, `web/`; DEC-102)

- Direction A "Konsol": dense, serious SOC table. Tokens live only in
  `web/src/index.css` (`:root` light, `.dark` dark); components use token
  classes (`bg-card`, `text-threat`, …), never raw hex.
- **Dark is the default theme**, even when the system is light. Light applies
  only after the analyst presses the theme button; the choice is stored in
  `localStorage` (`tf-theme`). `public/theme-init.js` sets the class in
  `<head>` before the first paint (CSP allows only same-origin scripts, so no
  inline script). Never derive the theme from `prefers-color-scheme`.
- One meaning per colour: threat list = red (`threat`), needs a look = amber
  (`review`), marked suspicious = blue (`suspect`), live = green. No
  gradients, glass, glow, decorative shadows or emoji icons; 4 px corners.
- Type: IBM Plex Sans (UI, tabular numbers) and IBM Plex Mono only for data
  (addresses, ports, times). Self-hosted via `@fontsource`; no font CDNs.
- Density: single-line table rows on ≥1024 px with a fixed column template
  shared by the header and rows (What to check: target, reason, device →
  target, network owner or "—", time, mark); rows stack below that and show
  the owner under the address only when known. Addresses never break inside. Mark buttons show text
  on ≥1024 px and become icon buttons with tooltip and `aria-label` below it,
  with ≥44 px touch targets.
- **Turkish is the default language**; English applies only after the analyst
  presses EN and is remembered (`tf-lang`). Wording comes from the shared
  Python i18n dictionary (`/api/i18n`); only page chrome lives in
  `web/src/lib/preferences.tsx`.
- Every screen: Vitest + Playwright e2e (desktop and 375 px, clean open is
  dark and Turkish, no console errors, no horizontal scroll) and review
  screenshots **in Turkish** (dark, then light) with
  `SCREENSHOTS=1 npm run test:e2e` (written to ignored `.playwright-mcp/`).
- Times are shown short and local (`dd.mm HH:MM`, year only when it differs);
  UTC only where the label says UTC. No raw ISO strings in the UI. Turkish
  pages must contain no English UI words (`tests/test_api_language.py`,
  `web/e2e/language.spec.ts`); missing wording goes into `i18n.py`.
- Wide tables scroll inside themselves with the first column pinned; charts
  are the default view and their bucket tables start collapsed.
- Switching language keeps the page's data on screen until the new wording
  arrives (`keepPreviousData`), so open rows and selections survive.
