from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.release_audit import audit_git_history, audit_tracked_tree


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit tracked files and optional Git history before public release"
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Scan every unique text blob reachable from local Git refs",
    )
    return parser


def _print_findings(label: str, findings) -> None:
    print(f"{label}: {len(findings)} finding(s)")
    for finding in findings[:50]:
        suffix = (
            f" object={finding.object_id[:12]}"
            if finding.object_id is not None
            else ""
        )
        print(f"  {finding.rule}: {finding.path}{suffix}")
    if len(findings) > 50:
        print(f"  ... {len(findings) - 50} additional finding(s) omitted")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        tree_findings, tree_scanned = audit_tracked_tree(_PROJECT_ROOT)
        print(f"Current tracked tree: scanned {tree_scanned} text file(s)")
        _print_findings("Current tracked tree", tree_findings)

        history_findings = ()
        if args.history:
            history_findings, history_scanned = audit_git_history(_PROJECT_ROOT)
            print(f"Git history: scanned {history_scanned} unique text blob(s)")
            _print_findings("Git history", history_findings)
    except (OSError, RuntimeError, UnicodeError) as error:
        raise SystemExit(
            f"Public release audit failed: {type(error).__name__}: {error}"
        ) from None

    if tree_findings or history_findings:
        print(
            "Audit failed. Review the reported rule/path metadata without "
            "copying any secret value into issues, logs, or documentation."
        )
        return 1

    print("Public release audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
