# Claude Code instructions

@AGENTS.md

- Start each session from `docs/PRODUCT_PLAN.md` (current ordered work queue).
- Use `.venv/bin/python` (private Python 3.12); run `.venv/bin/ruff check .` and
  `.venv/bin/python -m pytest -q` before committing.
- Private experiments follow the `lab-experiment` project skill; receipts stay in
  `/home/yahya/Work/threatfusion-lab/`, never in Git.
- `.claude/hooks/publish_guard.sh` blocks commits/pushes carrying private data
  and pushes that fail lint, tests or the release privacy audit. It does not
  verify Render hosting; that check in AGENTS.md is still required.
