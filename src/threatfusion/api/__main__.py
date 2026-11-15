"""Run the API on 127.0.0.1 only: ``python -m threatfusion.api [--port 8600]``.

There is deliberately no host option. The built React app (``web/dist``) is
served from the same origin when it exists; during development Vite serves
the page and forwards ``/api`` here.
"""
from __future__ import annotations

import argparse
from pathlib import Path

LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 8600
SOURCE_STATIC_DIR = Path(__file__).resolve().parents[3] / "web" / "dist"


def _port(value: str) -> int:
    port = int(value)
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m threatfusion.api",
                                     description="ThreatFusion local API (127.0.0.1 only).")
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT)
    parser.add_argument("--static-dir", type=Path, default=SOURCE_STATIC_DIR,
                        help="built React app to serve (default: web/dist of this checkout)")
    args = parser.parse_args(argv)

    import uvicorn

    from .app import create_app

    app = create_app(static_dir=args.static_dir)
    uvicorn.run(app, host=LOOPBACK, port=args.port, proxy_headers=False, server_header=False,
                forwarded_allow_ips="", log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
