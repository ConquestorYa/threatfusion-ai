#!/usr/bin/env bash
# Claude Code PreToolUse guard: blocks commits/pushes that carry private data,
# and pushes whose source fails lint, tests or the release privacy audit.
# Exit 2 blocks the tool call and shows stderr to Claude.
set -uo pipefail
command=$(jq -r '.tool_input.command // ""')
case "$command" in
  *"git commit"*|*"git push"*) ;;
  *) exit 0 ;;
esac
cd "$(dirname "$0")/../.." || exit 0
private='(^|/)\.env($|\.)|\.(sqlite|sqlite3|db|joblib|pcap|pcapng|cap)$|^data/.+'
check() {
  local found
  found=$(grep -E "$private" | grep -v -E '^data/samples/\.gitkeep$' || true)
  if [[ -n "$found" ]]; then
    echo "Blocked: private/local data would be published ($1):" >&2
    echo "$found" | head -20 >&2
    exit 2
  fi
}
check "staged files" < <(git diff --cached --name-only)
if [[ "$command" == *"git push"* ]]; then
  check "tracked files" < <(git ls-files)
  py=.venv/bin/python
  "$py" -m ruff check . >/dev/null 2>&1 || { echo "Blocked: ruff check failed." >&2; exit 2; }
  out=$("$py" -m pytest -q -p no:cacheprovider 2>&1) || { echo "Blocked: pytest failed:" >&2; echo "$out" | tail -15 >&2; exit 2; }
  audit=$("$py" scripts/audit_public_release.py --history 2>&1) || { echo "Blocked: release privacy audit failed:" >&2; echo "$audit" | tail -15 >&2; exit 2; }
fi
exit 0
