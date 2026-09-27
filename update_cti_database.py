from __future__ import annotations

import os
from pathlib import Path

from scripts.refresh_cti_cache import main as refresh_main

DEFAULT_DB_PATH = Path("data/threatfusion.sqlite")


def main() -> int:
    """Refresh the local CTI database without starting the web application."""
    db_path = os.environ.get("THREATFUSION_DB_PATH")
    target = Path(db_path) if db_path and db_path.strip() else DEFAULT_DB_PATH
    return refresh_main(
        [
            "--db",
            str(target),
            "--force",
            "--allow-missing-keys",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
