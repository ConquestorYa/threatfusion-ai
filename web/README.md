# ThreatFusion web workspace (React)

React + TypeScript + Tailwind + shadcn/ui front end for the local FastAPI
backend in `src/threatfusion/api/`. It replaces the Streamlit workspace screen
by screen ([DEC-101](../docs/dev/DECISIONS.md)); **every screen has moved**:
What to check, Details (with timelines and the DNS ML column), Experimental
ML (DEC-105), Quick lookup, Analyze telemetry (samples in
`data/samples/demo/`), Analysis history (only in history mode, DEC-107),
Model evaluation (same visibility as Streamlit, DEC-106) and Setup & CTI
updates (keys are always saved, DEC-103; Stop local application). Streamlit
stays supported: `threatfusion-ai --streamlit` (DEC-108). The header links to
Streamlit only when `THREATFUSION_STREAMLIT_URL` names one running beside it
(DEC-109).
Design rules (dark by default, tokens, density) are in
[CLAUDE.md](../CLAUDE.md#design-rules-react-workspace-web-dec-102).

Every server here listens on `127.0.0.1` only. None has a host option.

## How installations get the page

`threatfusion-ai` (and the desktop entry) starts this API on a free
127.0.0.1 port and it serves the **committed** pre-built page in `web/dist`
from the same origin, so installing or running needs no Node (DEC-108). After
changing anything under `web/src`, run `npm run build` and commit `web/dist`
with the source; CI rebuilds and fails when they differ. A source without
`web/dist` falls back to Streamlit with a message.

## Run both applications together

Quickest, with synthetic data: `scripts/demo_web.sh` (see the
[demo checklist](../docs/dev/DEMO_CHECKLIST_TR.md)); it also adds a synthetic,
untrained behavior model so Experimental ML and Model evaluation appear.

Two terminals, from the repository root. The project's `.venv` (with
`requirements.txt`) is needed; Node 22 (`nvm install 22`) only to rebuild.

```bash
# Terminal 1 — Streamlit workspace (unchanged), 127.0.0.1:8501
.venv/bin/streamlit run streamlit_app.py --server.address=127.0.0.1 --server.port=8501

# Terminal 2 — React page + API, 127.0.0.1:8600
THREATFUSION_COLLECTOR_STATE_DIR=/path/to/private/collector \
THREATFUSION_STREAMLIT_URL=http://127.0.0.1:8501 \
  .venv/bin/python -m threatfusion.api
```

Open http://127.0.0.1:8600 for the new page and http://127.0.0.1:8501 for
Streamlit. Both read the same collector snapshot and share the same marks
(`review-labels.json`).

- **With a managed installation**: `threatfusion-ai` opens the React
  workspace; `threatfusion-ai --streamlit` opens Streamlit. To run this
  checkout's API against the installation instead:
  `THREATFUSION_LOCAL_INSTALL_DIR=~/.local/share/threatfusion-ai
  THREATFUSION_LOCAL_LOOPBACK=1 .venv/bin/python -m threatfusion.api`.
- **Without collected data**, create a synthetic state (documentation
  addresses only): `.venv/bin/python scripts/demo_review_snapshot.py
  /tmp/tf-demo` and use `/tmp/tf-demo/collector` as the state directory.
  `--managed --behavior-model` adds a synthetic behavior model;
  `--history-model` (developer layout) adds the synthetic demo domain artifact
  for Analysis history (`THREATFUSION_CTI_ONLY=0`,
  `THREATFUSION_MODEL_DIR=/tmp/tf-demo/models/demo-synthetic`,
  `THREATFUSION_DB_PATH=/tmp/tf-demo/cti.sqlite`). Neither is a measured model.
- `THREATFUSION_STREAMLIT_URL` accepts only a loopback `http://` address; any
  other value, or none, means no Streamlit link.

## Development with live reload

```bash
.venv/bin/python -m threatfusion.api           # API, 127.0.0.1:8600
cd web && npm run dev                           # page, 127.0.0.1:5173 (/api forwarded)
```

## Checks

```bash
npm run typecheck && npm run lint && npm test && npm run build
npm run test:e2e                         # Playwright: desktop + 375 px, real API on 127.0.0.1:8611
SCREENSHOTS=1 npm run test:e2e           # also writes review screenshots to ../.playwright-mcp/screens/
npm audit
```

The browser tests start two APIs with fresh synthetic states: `e2e/serve.sh`
(managed CTI-only installation with a synthetic behavior model, port 8611)
and `e2e/serve-history.sh` (developer configuration with the synthetic demo
domain artifact and history enabled, port 8612, for `history.spec.ts`). They
need the Playwright Chromium (`npx playwright install chromium`).

## Rules the page relies on

- The list, wording and marks come from the same Python code as the Streamlit
  tab (`build_review_items`, the shared i18n dictionary and
  `review-labels.json`), so both interfaces agree.
- Real IPs of the user's own network are shown on screen exactly as Streamlit
  does (the local identity view); nothing leaves the computer unless the
  analyst clicks an outside lookup link.
- The API refuses foreign `Host` headers (DNS rebinding) and refuses writes
  without a loopback `Origin`, a same-origin fetch and a JSON body. There is no
  CORS and no OpenAPI page. The CSP allows only same-origin scripts.
- Dependencies are pinned to exact versions; `node_modules` is not
  committed, `web/dist` is (DEC-108). Add shadcn components with `npx shadcn@4.23.0 add <name>`.
  The CLI is not a project dependency (its stylesheet is vendored in
  `src/styles/`).
