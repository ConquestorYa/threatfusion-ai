"""Small installed command interface; never accepts API keys as CLI arguments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from threatfusion.local_setup import request_local_control
from threatfusion.local_workspace import load_settings, refresh_workspace, validate_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, required=True)
    parser.add_argument("action", choices=("stop", "status", "refresh", "collect"))
    args, extra = parser.parse_known_args()
    if extra and args.action != "collect":
        parser.error("Unexpected command options")
    try:
        root = validate_root(args.install_dir)
        if args.action == "collect":
            if load_settings(root)["mode"] != "cti-only":
                print("Toplama için yerel arayüzde gerçek CTI modunu seçin.")
                return 1
            from threatfusion.telemetry_collector import main as collect
            return collect(["--state-dir", str(root / "collector"),
                            "--db", str(root / "runtime/cti/threatfusion.sqlite"), *extra])
        if args.action in {"stop", "status"}:
            result = request_local_control(root, args.action)
            print(json.dumps(result))
            return 0
        if load_settings(root)["mode"] != "cti-only":
            print("Gerçek CTI güncellemesi için web arayüzünde cti-only modunu seçin.")
            return 1
        result = refresh_workspace(root)
        print(json.dumps(result))
        return (
            1
            if result.get("busy")
            or result.get("failed")
            or any(item["status"] == "failed" for item in result.get("outcomes", []))
            else 0
        )
    except (OSError, ValueError, TypeError):
        print(
            "Local işlem tamamlanamadı. Kurulum ve özel dosya izinlerini kontrol edin."
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
