# ThreatFusion web workspace (React)

React + TypeScript + Tailwind + shadcn/ui front end for the local FastAPI
backend in `src/threatfusion/api/`. It is replacing the Streamlit workspace one
screen at a time ([DEC-101](../docs/dev/DECISIONS.md)); Streamlit stays the
supported interface until every screen has moved. The first screen is
**What to check**.

Both servers listen on `127.0.0.1` only. Neither has a host option.

## Development

Requires Node 22 (`nvm install 22`) and the project's `.venv`.

```bash
# 1. API on 127.0.0.1:8600. Point it at a collector state directory, or run it
#    inside a managed installation (THREATFUSION_LOCAL_INSTALL_DIR).
THREATFUSION_COLLECTOR_STATE_DIR=/path/to/private/collector \
  .venv/bin/python -m threatfusion.api

# 2. Page on 127.0.0.1:5173; /api is forwarded to the API above.
cd web && npm ci && npm run dev
```

`npm run build` writes `web/dist/`, which `python -m threatfusion.api` serves
from the same origin when it exists (open http://127.0.0.1:8600).

Checks: `npm run typecheck`, `npm run lint`, `npm test`, `npm audit`.

## Rules the page relies on

- The list, wording and marks come from the same Python code as the Streamlit
  tab (`build_review_items`, the shared i18n dictionary and
  `review-labels.json`), so both interfaces agree.
- Real IPs of the user's own network are shown on screen exactly as Streamlit
  does (the local identity view); nothing leaves the computer unless the
  analyst clicks an outside lookup link.
- The API refuses foreign `Host` headers (DNS rebinding) and refuses writes
  without a loopback `Origin`, a same-origin fetch and a JSON body. There is no
  CORS and no OpenAPI page.
- Dependencies are pinned to exact versions; `web/dist` and `node_modules` are
  not committed. Add shadcn components with `npx shadcn@4.23.0 add <name>`.
  The CLI is not a project dependency (its stylesheet is vendored in
  `src/styles/`).
