"""Private first-run assets and loopback-only Streamlit lifecycle."""

from __future__ import annotations

import os
import json
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Mapping
from pathlib import Path

from .cti_cache import initialize_cti_cache
from .cti_refresh import refresh_configured_sources
from .demo_runtime import create_public_demo_runtime
from .ml_artifact import load_trusted_ml_artifact


def prepare_local_environment(
    install_dir: Path, mode: str, environment: Mapping[str, str]
) -> dict[str, str]:
    """Use dedicated data only; never discover/promote a developer model."""
    if mode not in {"demo", "cti-only"}:
        raise ValueError("unsupported setup mode")
    runtime = install_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    if mode == "demo":
        demo = runtime / "demo"
        if not demo.exists():
            with tempfile.TemporaryDirectory(dir=runtime, prefix=".demo-") as temporary:
                stage = Path(temporary) / "ready"
                stage.mkdir()
                _, model_dir = create_public_demo_runtime(stage / "bundle")
                (stage / "trusted-model.sha256").write_text(
                    (model_dir / "artifact.sha256").read_text()
                )
                stage.rename(demo)
        model = demo / "bundle/models/development-001"
        pin = (demo / "trusted-model.sha256").read_text().strip()
        artifact = load_trusted_ml_artifact(model, expected_checksum=pin)
        if artifact.metadata.evaluation_status != "demo_only_synthetic":
            raise ValueError("local demo requires a synthetic-only model")
        db = demo / "bundle/threatfusion.sqlite"
        if not db.is_file():
            raise ValueError("demo CTI database is missing; existing files preserved")
    else:
        cti = runtime / "cti"
        cti.mkdir(exist_ok=True)
        db = cti / "threatfusion.sqlite"
        initialize_cti_cache(db, writer=True)
        model = cti / "no-ml-artifact"
        pin = ""
    values = dict(environment)
    # A desktop launcher must not inherit unrelated developer/public runtime paths.
    for key in tuple(values):
        if key.startswith("THREATFUSION_") or key.startswith("STREAMLIT_"):
            values.pop(key)
    for key in ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY"):
        values.pop(key, None)
    values.update(
        {
            "THREATFUSION_PUBLIC_MODE": "1" if mode == "demo" else "0",
            "THREATFUSION_HISTORY_ENABLED": "0",
            "THREATFUSION_CTI_ONLY": "1" if mode == "cti-only" else "0",
            "THREATFUSION_DB_PATH": str(db),
            "THREATFUSION_MODEL_DIR": str(model),
            "THREATFUSION_EVALUATION_REPORT": str(runtime / "no-final-report.json"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    if sys.platform == "linux" and (install_dir / ".threatfusion-install").is_file():
        values["THREATFUSION_LOCAL_INSTALL_DIR"] = str(install_dir)
        values["THREATFUSION_LOCAL_LOOPBACK"] = "1"
    if pin:
        values["THREATFUSION_MODEL_SHA256"] = pin
    return values


def refresh_local_cti(install_dir: Path, environment: Mapping[str, str]) -> None:
    """Explicit opt-in collection; never print upstream URLs or key-bearing errors."""
    print(
        "Gerçek CTI verileri kaynaklardan indiriliyor; bu işlem birkaç dakika sürebilir.",
        flush=True,
    )
    for source, name in (
        ("ThreatFox", "THREATFOX_AUTH_KEY"),
        ("URLhaus", "URLHAUS_AUTH_KEY"),
    ):
        if not environment.get(name, "").strip():
            print(f"  {source}: API anahtarı yok, bu kaynak atlandı.", flush=True)
    outcomes = refresh_configured_sources(
        install_dir / "runtime/cti/threatfusion.sqlite",
        threatfox_key=environment.get("THREATFOX_AUTH_KEY"),
        urlhaus_key=environment.get("URLHAUS_AUTH_KEY"),
        phishtank_key=environment.get("PHISHTANK_APP_KEY"),
        progress=lambda source, stage, detail: print(
            f"  {source}: {stage}", flush=True
        ),
    )
    for outcome in outcomes:
        if outcome.status == "refreshed":
            print(f"  {outcome.source}: {outcome.record_count:,} kayıt güncellendi.")
        elif outcome.status == "fresh":
            print(f"  {outcome.source}: mevcut cache güncel.")
        else:
            print(
                f"  {outcome.source}: yenilenemedi ({outcome.error_type}); eski cache korundu."
            )


def choose_local_port(requested: int | None = None) -> int:
    if requested is not None and not 1024 <= requested <= 65535:
        raise ValueError("port must be between 1024 and 65535")
    candidates = [requested] if requested is not None else range(8501, 8601)
    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise ValueError(
        "local port is busy; stop the existing app or select another --port"
    )


def streamlit_command(source_dir: Path, port: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(source_dir / "streamlit_app.py"),
        "--server.address=127.0.0.1",
        f"--server.port={port}",
        "--server.headless=true",
        "--browser.gatherUsageStats=false",
        "--server.enableCORS=true",
        "--server.enableXsrfProtection=true",
    ]


def run_local_server(
    source_dir: Path,
    environment: Mapping[str, str],
    *,
    port: int | None = None,
    open_browser: bool = True,
    readiness_timeout: float = 60,
    install_dir: Path | None = None,
) -> int:
    selected = choose_local_port(port)
    url = f"http://127.0.0.1:{selected}"
    stop = threading.Event()
    previous = {}
    for signum in (
        signal.SIGINT,
        signal.SIGTERM,
        *([signal.SIGHUP] if hasattr(signal, "SIGHUP") else []),
    ):
        previous[signum] = signal.signal(signum, lambda *_: stop.set())
    process = None
    control = None
    try:
        if install_dir is not None:
            from .local_workspace import automatic_refresh_loop, validate_root

            validate_root(install_dir)
            control = create_local_control(install_dir, stop, url)
            threading.Thread(
                target=automatic_refresh_loop, args=(install_dir, stop), daemon=True
            ).start()
        process = subprocess.Popen(
            streamlit_command(source_dir, selected),
            cwd=source_dir,
            env=dict(environment),
            start_new_session=True,
        )
        deadline = time.monotonic() + readiness_timeout
        # Local health requests must not go through a corporate HTTP proxy.
        local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        ready = False
        while not stop.wait(0.2):
            if process.poll() is not None:
                raise RuntimeError("Streamlit exited before it became ready")
            try:
                with local_http.open(url + "/_stcore/health", timeout=1) as response:
                    ready = response.status == 200 and response.read() == b"ok"
            except (OSError, urllib.error.URLError):
                pass
            if ready:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("local application did not become ready in time")
        if stop.is_set():
            return 0
        print(
            f"[4/4] Uygulama hazır: {url}\nYalnızca bu bilgisayarda çalışır. Durdurmak için Ctrl+C.",
            flush=True,
        )
        if open_browser:
            try:
                if not webbrowser.open(url):
                    print(
                        "Tarayıcı otomatik açılamadı; yukarıdaki local adresi açın.",
                        flush=True,
                    )
            except (webbrowser.Error, OSError):
                print(
                    "Tarayıcı otomatik açılamadı; yukarıdaki local adresi açın.",
                    flush=True,
                )
        while not stop.wait(0.3):
            if process.poll() is not None:
                return 1
        return 0
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        stop.set()
        if control is not None:
            control.close()
            (install_dir / "control.sock").unlink(missing_ok=True)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def create_local_control(root: Path, stop: threading.Event, url: str):
    """Owner-only Unix socket avoids killing PIDs from stale/reused PID files."""
    path = root / "control.sock"
    if path.exists() or path.is_symlink():
        # Bootstrap holds the exclusive installation session lock here.
        if path.is_symlink() or not path.is_socket():
            raise ValueError("unexpected local control file; existing file preserved")
        path.unlink()
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        control.bind(str(path))
        path.chmod(0o600)
        control.listen(4)
        control.settimeout(0.5)
    except Exception:
        control.close()
        raise

    def serve():
        while not stop.is_set():
            try:
                client, _ = control.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with client:
                client.settimeout(1)
                try:
                    command = client.recv(16).decode("ascii")
                    if command == "stop":
                        client.sendall(b"stopping")
                        stop.set()
                    elif command == "status":
                        client.sendall(json.dumps({"url": url}).encode())
                except (OSError, UnicodeError):
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return control


def request_local_control(root: Path, command: str) -> dict:
    from .local_workspace import validate_root

    validate_root(root)
    if command not in {"status", "stop"}:
        raise ValueError("invalid local control command")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        try:
            client.connect(str(root / "control.sock"))
            client.sendall(command.encode())
            response = client.recv(4096)
        except (OSError, socket.timeout):
            return {"running": False}
    if command == "stop":
        return {"running": True, "stopping": response == b"stopping"}
    values = json.loads(response)
    return {"running": True, "url": values["url"]}
