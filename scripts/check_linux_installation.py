"""Black-box checks against a disposable Linux installation, never user data."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_running(root: Path, mode: str, port: int, *, auto_port: bool = False) -> None:
    source = Path(json.loads((root / "installation.json").read_text())["source"])
    command = [str(root / "start"), "--mode", mode, "--no-browser"]
    if not auto_port:
        command += ["--port", str(port)]
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen(
            command, stdout=log, stderr=log, start_new_session=True
        )
        url = f"http://127.0.0.1:{port}"
        http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            deadline = time.monotonic() + 60
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read())
                try:
                    with http.open(url + "/_stcore/health", timeout=1) as response:
                        if response.read() == b"ok":
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError("local health endpoint timed out")
                time.sleep(0.2)
            # Health alone does not execute the application. Render its real UI.
            spec = importlib.util.spec_from_file_location(
                "session_check", source / "scripts/check_public_demo_session.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            asyncio.run(module.check_session(url))
            listeners = [
                line.split()[1]
                for line in Path("/proc/net/tcp").read_text().splitlines()[1:]
                if line.split()[3] == "0A" and line.split()[1].endswith(f":{port:04X}")
            ]
            assert listeners == [f"0100007F:{port:04X}"], listeners
            duplicate = subprocess.run(
                [str(root / "start"), "--prepare-only"], capture_output=True, text=True
            )
            assert duplicate.returncode == 1 and "zaten çalışıyor" in duplicate.stdout
            process.send_signal(signal.SIGINT if mode == "demo" else signal.SIGTERM)
            assert process.wait(timeout=25) == 0
            time.sleep(0.3)
            with socket.socket() as client:
                assert client.connect_ex(("127.0.0.1", port)) != 0, "orphan server"
            log.seek(0)
            output = log.read()
            assert "[4/4] Uygulama hazır" in output
            assert "Traceback" not in output
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=30)
    print(f"{mode}: real UI, loopback binding, duplicate lock and shutdown passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.install_dir.resolve()
    assert root != Path.home() and (root / ".threatfusion-install").is_file()
    assert sys.version_info[:3] == (3, 12, 14)
    source = Path(json.loads((root / "installation.json").read_text())["source"])
    model = root / "runtime/demo/bundle/models/development-001/model.joblib"
    demo_db = root / "runtime/demo/bundle/threatfusion.sqlite"
    identity = (digest(model), digest(demo_db))
    for _ in range(2):
        subprocess.run([str(root / "start"), "--prepare-only"], check=True)
        assert (digest(model), digest(demo_db)) == identity
    # Occupied default port must select the next free loopback port.
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 8501))
        refusal = subprocess.run(
            [str(root / "start"), "--port", "8501", "--no-browser"],
            capture_output=True,
            text=True,
        )
        assert refusal.returncode == 1 and "busy" in refusal.stderr
        check_running(root, "demo", 8502, auto_port=True)
    subprocess.run(
        [str(root / "start"), "--mode", "cti-only", "--prepare-only"], check=True
    )
    sys.path.insert(0, str(source / "src"))
    from threatfusion.cti_cache import load_ioc_records, replace_source_records
    from threatfusion.models import IOCRecord, IOCType

    db = root / "runtime/cti/threatfusion.sqlite"
    replace_source_records(
        db,
        "Installer Test",
        [IOCRecord("fixture.example", IOCType.DOMAIN, "Installer Test")],
    )
    check_running(root, "cti-only", 18511)
    subprocess.run(
        [str(root / "start"), "--mode", "demo", "--prepare-only"], check=True
    )
    assert [item.value for item in load_ioc_records(db)] == ["fixture.example"]
    assert (digest(model), digest(demo_db)) == identity
    print(
        "Linux installation verified: Python, hashed packages, repeat runs, both modes, private data preserved"
    )


if __name__ == "__main__":
    main()
