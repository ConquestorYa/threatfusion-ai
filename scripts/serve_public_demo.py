from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.public_demo_hosting import (
    public_demo_environment,
    render_public_demo_proxy,
)


def main() -> int:
    runtime = _PROJECT_ROOT / "runtime"
    try:
        environment = public_demo_environment(
            runtime,
            _PROJECT_ROOT / "public-demo.sha256",
            os.environ,
        )
        proxy = render_public_demo_proxy(
            (_PROJECT_ROOT / "deploy/public-demo/nginx.conf.template").read_text(),
            environment.get("PORT", "10000"),
            environment.get("THREATFUSION_TRUSTED_PROXY_CIDRS", ""),
        )
    except (OSError, TypeError, ValueError) as error:
        print(
            f"Public demo configuration refused: {type(error).__name__}",
            file=sys.stderr,
        )
        return 1

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    processes: list[subprocess.Popen] = []
    with tempfile.TemporaryDirectory(prefix="threatfusion-proxy-") as temporary:
        config_path = Path(temporary) / "nginx.conf"
        config_path.write_text(proxy)
        try:
            subprocess.run(
                ["nginx", "-t", "-c", str(config_path)], check=True, env=environment
            )
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "streamlit",
                        "run",
                        "streamlit_app.py",
                        "--server.address=127.0.0.1",
                        "--server.port=8501",
                        "--server.headless=true",
                        "--browser.gatherUsageStats=false",
                        "--server.maxUploadSize=20",
                        "--server.maxMessageSize=25",
                    ],
                    cwd=_PROJECT_ROOT,
                    env=environment,
                )
            )
            processes.append(
                subprocess.Popen(
                    [
                        "nginx",
                        "-c",
                        str(config_path),
                        "-g",
                        "daemon off;",
                    ],
                    env=environment,
                )
            )
            print(
                "Synthetic public demo started with request and connection limits",
                flush=True,
            )
            while not stop.wait(0.5):
                if any(process.poll() is not None for process in processes):
                    return 1
            return 0
        except (OSError, subprocess.SubprocessError):
            print("Public demo process could not start", file=sys.stderr)
            return 1
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
