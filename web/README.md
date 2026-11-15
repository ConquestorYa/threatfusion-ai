# ThreatFusion web workspace (React)

React + TypeScript + Tailwind + shadcn/ui front end for the local FastAPI
backend in `src/threatfusion/api/`. It replaces the Streamlit workspace screen
by screen ([DEC-101](../docs/dev/DECISIONS.md)). Moved so far: **What to
check**, **Details** (with connection and DNS timelines), **Quick lookup** and **Setup & CTI
updates** (keys entered here are always saved; stopping the app stays in Streamlit). Telemetry analysis, Experimental ML, Model evaluation and Analysis
history stay in Streamlit; the header link **Open in Streamlit** goes there.
Design rules (dark by default, tokens, density) are in
[CLAUDE.md](../CLAUDE.md#design-rules-react-workspace-web-dec-102).

Every server here listens on `127.0.0.1` only. None has a host option.

## Run both applications together

Two terminals, from the repository root. Node 22 (`nvm install 22`) and the
project's `.venv` (with `requirements.txt`) are needed.

```bash
# Terminal 1 — Streamlit workspace (unchanged), 127.0.0.1:8501
.venv/bin/streamlit run streamlit_app.py --server.address=127.0.0.1 --server.port=8501

# Terminal 2 — React page + API, 127.0.0.1:8600
(cd web && npm ci && npm run build)
THREATFUSION_COLLECTOR_STATE_DIR=/path/to/private/collector \
THREATFUSION_STREAMLIT_URL=http://127.0.0.1:8501 \
  .venv/bin/python -m threatfusion.api
```

Open http://127.0.0.1:8600 for the new page and http://127.0.0.1:8501 for
Streamlit. Both read the same collector snapshot and share the same marks
(`review-labels.json`).

- **With a managed installation** (`threatfusion-ai start` already runs
  Streamlit; the address is printed at start, usually 127.0.0.1:8501): point
  the API at the installation instead of a state directory:
  `THREATFUSION_LOCAL_INSTALL_DIR=~/.local/share/threatfusion-ai
  THREATFUSION_LOCAL_LOOPBACK=1 .venv/bin/python -m threatfusion.api`.
  The installer does not ship the React page yet.
- **Without collected data**, create a synthetic state (documentation
  addresses only): `.venv/bin/python scripts/demo_review_snapshot.py
  /tmp/tf-demo` and use `/tmp/tf-demo/collector` as the state directory.
- `THREATFUSION_STREAMLIT_URL` accepts only a loopback `http://` address; any
  other value falls back to `http://127.0.0.1:8501`.

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

The browser tests start their own API with a fresh synthetic state
(`e2e/serve.sh`) and need the Playwright Chromium (`npx playwright install
chromium`).

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
- Dependencies are pinned to exact versions; `web/dist` and `node_modules` are
  not committed. Add shadcn components with `npx shadcn@4.23.0 add <name>`.
  The CLI is not a project dependency (its stylesheet is vendored in
  `src/styles/`).
