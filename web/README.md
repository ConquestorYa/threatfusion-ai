# ThreatFusion web workspace (React)

React + TypeScript + Tailwind + shadcn/ui front end for the local FastAPI
backend in `src/threatfusion/api/`. It is the application's only interface:
What to check, Details, Experimental ML (DEC-105), Quick lookup, Analyze
telemetry (samples in `data/samples/demo/`), Analysis history (history mode
only, DEC-107), Model evaluation (DEC-106) and Setup & CTI updates (DEC-103).
It replaced the Streamlit workspace screen by screen (DEC-101); Streamlit was
removed on 2026-11-22 (DEC-111). The shared view logic still lives in the
Python `ui_*` modules, without any Streamlit code.
Design rules (dark by default, tokens, density) are in
[CLAUDE.md](../CLAUDE.md#design-rules-react-workspace-web-dec-102).

Every server here listens on `127.0.0.1` only. None has a host option.

## How installations get the page

`threatfusion-ai` (and the desktop entry) starts this API on a free
127.0.0.1 port and it serves the **committed** pre-built page in `web/dist`
from the same origin, so installing or running needs no Node (DEC-108). After
changing anything under `web/src`, run `npm run build` and commit `web/dist`
with the source; CI rebuilds and fails when they differ. A source without
`web/dist` refuses to start.

## Run it from a source checkout

Quickest, with synthetic data: `scripts/demo_web.sh` (see the
[demo checklist](../docs/dev/DEMO_CHECKLIST_TR.md)); it also adds a synthetic,
untrained behavior model so Experimental ML and Model evaluation appear.

With your own collector state, from the repository root (the project's
`.venv` with `requirements.txt`; Node 22 only to rebuild the page):

```bash
THREATFUSION_COLLECTOR_STATE_DIR=/path/to/private/collector .venv/bin/python -m threatfusion.api
```

Open http://127.0.0.1:8600.

- **With a managed installation**: `threatfusion-ai` opens it. To run this
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
- **Docker**: `docker build -t threatfusion . && docker run --rm --network host
  threatfusion` serves it on the host's 127.0.0.1:8600 (public demo mode; the
  API binds loopback only, so host networking is how the host reaches it).

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
`E2E_PYTHON=/path/to/python` runs them with another Python environment.

## Rules the page relies on

- The list, wording and marks come from the shared Python view code
  (`build_review_items`, the shared i18n dictionary and `review-labels.json`).
- Real IPs of the user's own network are shown on screen (the local identity
  view); nothing leaves the computer unless the analyst clicks an outside
  lookup link.
- The API refuses foreign `Host` headers (DNS rebinding) and refuses writes
  without a loopback `Origin`, a same-origin fetch and a JSON body. There is no
  CORS and no OpenAPI page. The CSP allows only same-origin scripts.
- Dependencies are pinned to exact versions; `node_modules` is not
  committed, `web/dist` is (DEC-108). Add shadcn components with `npx shadcn@4.23.0 add <name>`.
  The CLI is not a project dependency (its stylesheet is vendored in
  `src/styles/`).
