from __future__ import annotations

import importlib
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

main = importlib.import_module("threatfusion.cli").main


if __name__ == "__main__":
    raise SystemExit(main())
