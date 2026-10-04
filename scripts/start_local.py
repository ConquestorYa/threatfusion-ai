from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.local_setup import (
    prepare_local_environment,
    run_local_server,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare and start ThreatFusion on loopback only"
    )
    parser.add_argument("--install-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("demo", "cti-only"), default="cti-only")
    parser.add_argument("--refresh-cti", action="store_true")
    parser.add_argument("--port", type=int)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if args.refresh_cti and args.mode != "cti-only":
        parser.error("--refresh-cti requires --mode cti-only")
    try:
        environment = prepare_local_environment(
            args.install_dir.resolve(), args.mode, os.environ
        )
        if args.mode == "demo":
            print(
                "Sentetik DEMO: gerçek CTI veya ölçülmüş ML modeli değildir. Örnek sorgu: known-threat.example",
                flush=True,
            )
        else:
            print(
                "Gerçek CTI-only: ML kapalı. Veri yoksa --refresh-cti ile kaynakları yenileyin; eşleşme olmaması zararsızlık kanıtı değildir.",
                flush=True,
            )
        if args.refresh_cti:
            from threatfusion.local_workspace import refresh_workspace

            refresh_workspace(args.install_dir.resolve())
        if args.prepare_only:
            print(
                f"Kurulum hazır. Daha sonra başlatmak için: {shlex.quote(str(args.install_dir.resolve() / 'start'))}",
                flush=True,
            )
            return 0
        return run_local_server(
            _PROJECT_ROOT,
            environment,
            port=args.port,
            open_browser=not args.no_browser,
            install_dir=args.install_dir.resolve(),
        )
    except (OSError, TypeError, ValueError, RuntimeError) as error:
        print(
            f"Local başlatma tamamlanamadı ({type(error).__name__}): {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
