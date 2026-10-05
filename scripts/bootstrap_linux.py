"""Standard-library bootstrap: immutable source, hashed wheels, private environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

PYTHON_VERSION = (3, 12, 14)
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXTRACTED_BYTES = 64 * 1024 * 1024


def extract_source(archive: Path, target: Path) -> None:
    """Validate the entire archive before extracting any application file."""
    with tarfile.open(archive, "r:gz") as handle:
        members = []
        roots: set[str] = set()
        total = 0
        for member in handle:
            members.append(member)
            if len(members) > 10_000:
                raise ValueError("invalid source archive entry count")
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or "\\" in member.name
                or not path.parts
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("unsafe source archive entry")
            roots.add(path.parts[0])
            total += member.size
            if member.size > 8 * 1024 * 1024 or total > MAX_EXTRACTED_BYTES:
                raise ValueError("source archive exceeds extraction size limit")
        if not members or len(roots) != 1:
            raise ValueError("source archive must have exactly one root")
        for member in members:
            parts = PurePosixPath(member.name).parts[1:]
            if not parts:
                continue
            destination = target.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = handle.extractfile(member)
                if source is None:
                    raise ValueError("missing archive file content")
                with source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output)


def obtain_source(root: Path, sha: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("source SHA must be a full commit identity")
    releases = root / "releases"
    releases.mkdir(exist_ok=True)
    destination = releases / sha
    if destination.exists():
        if (destination / ".source-sha").read_text().strip() != sha:
            raise ValueError("existing source checkout has no matching identity")
        return destination
    with tempfile.TemporaryDirectory(dir=releases, prefix=".download-") as temporary:
        temporary_path = Path(temporary)
        archive = temporary_path / "source.tar.gz"
        url = f"https://codeload.github.com/ConquestorYa/threatfusion-ai/tar.gz/{sha}"
        with (
            urllib.request.urlopen(url, timeout=60) as response,
            archive.open("wb") as output,
        ):
            count = 0
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_ARCHIVE_BYTES:
                    raise ValueError("source download exceeds size limit")
                output.write(chunk)
        checkout = temporary_path / "source"
        checkout.mkdir()
        extract_source(archive, checkout)
        (checkout / ".source-sha").write_text(sha)
        checkout.rename(destination)
    return destination


def prepare_environment(root: Path, source: Path, uv: Path) -> Path:
    lock = source / "requirements-linux.lock"
    identity = hashlib.sha256(lock.read_bytes()).hexdigest()
    environment = root / "environments" / identity
    python = environment / "bin/python"
    marker = environment / ".threatfusion-venv"
    if environment.exists() and not marker.is_file():
        raise ValueError("existing environment is not managed by this installer")
    if not environment.exists():
        environment.parent.mkdir(exist_ok=True)
        subprocess.run(
            [
                str(uv),
                "--no-config",
                "venv",
                "--python",
                sys.executable,
                str(environment),
            ],
            check=True,
        )
        marker.write_text(identity)
    if marker.read_text().strip() != identity:
        raise ValueError("environment lock identity mismatch")
    subprocess.run(
        [
            str(uv),
            "--no-config",
            "pip",
            "sync",
            "--python",
            str(python),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "--default-index",
            "https://pypi.org/simple",
            str(lock),
        ],
        check=True,
    )
    subprocess.run(
        [str(uv), "--no-config", "pip", "check", "--python", str(python)], check=True
    )
    subprocess.run(
        [
            str(python),
            "-c",
            "import sys; assert sys.version_info[:3]==(3,12,14); "
            "import streamlit,sklearn,pandas,pyarrow,openpyxl,xlrd,dpkt,plotly",
        ],
        check=True,
    )
    return python


def run_application(command: list[str]) -> int:
    process = subprocess.Popen(command, start_new_session=True)
    previous = {}
    try:
        for signum in (
            signal.SIGINT,
            signal.SIGTERM,
            *([signal.SIGHUP] if hasattr(signal, "SIGHUP") else []),
        ):
            previous[signum] = signal.signal(
                signum,
                lambda received, frame: (
                    process.send_signal(received) if process.poll() is None else None
                ),
            )
        return process.wait()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", type=Path, required=True)
    parser.add_argument("--uv", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--source-dir", type=Path)
    group.add_argument("--source-sha")
    parser.add_argument("--mode", choices=("demo", "cti-only"))
    parser.add_argument("--port", type=int)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--refresh-cti", action="store_true")
    parser.add_argument("--launch-only", action="store_true")
    parser.add_argument(
        "--no-integrations",
        action="store_true",
        help="Do not register desktop or shell shortcuts",
    )
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or sys.version_info[:3] != PYTHON_VERSION:
            raise ValueError("use the Linux installer with its private Python 3.12.14")
        root = args.install_dir.resolve()
        if not (root / ".threatfusion-install").is_file():
            raise ValueError("missing installer ownership marker")
        import fcntl

        with (root / ".session.lock").open("a") as session_lock:
            try:
                fcntl.flock(session_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(
                    "Bu kurulum zaten çalışıyor. Mevcut terminalde Ctrl+C ile durdurun."
                )
                return 1
            configuration = root / "installation.json"
            existing = (
                json.loads(configuration.read_text()) if configuration.exists() else {}
            )
            if args.launch_only:
                source = Path(existing["source"])
                python = Path(existing["python"])
            else:
                print(
                    "[2/4] Kaynak kod ve hash doğrulamalı kütüphaneler hazırlanıyor…",
                    flush=True,
                )
                if args.uv is None:
                    raise ValueError("uv is required for installation")
                source = (
                    args.source_dir.resolve()
                    if args.source_dir
                    else obtain_source(root, args.source_sha or "")
                )
                if not (source / "streamlit_app.py").is_file():
                    raise ValueError("application source is missing")
                python = prepare_environment(root, source, args.uv)
            sys.path.insert(0, str(source / "src"))
            from threatfusion.local_workspace import load_settings, save_settings
            from threatfusion.local_integration import install_user_integration

            settings = load_settings(root)
            mode = args.mode or (
                settings["mode"]
                if (root / "workspace.json").exists()
                else existing.get("mode", "cti-only")
            )
            save_settings(
                root,
                mode=mode,
                interval_hours=settings["interval_hours"],
                automatic=settings["automatic"],
            )
            if args.refresh_cti and mode != "cti-only":
                raise ValueError("feed refresh requires explicit cti-only mode")
            values = {
                "schema_version": 1,
                "source": str(source),
                "python": str(python),
                "mode": mode,
            }
            temporary = configuration.with_suffix(".tmp")
            temporary.write_text(json.dumps(values, indent=2) + "\n")
            temporary.replace(configuration)
            launcher = root / "start"
            command = [
                str(python),
                str(source / "scripts/bootstrap_linux.py"),
                "--install-dir",
                str(root),
                "--launch-only",
            ]
            launcher.write_text(
                "#!/usr/bin/env bash\nset -e\nunset PYTHONHOME PYTHONPATH VIRTUAL_ENV CONDA_PREFIX\n"
                + 'case "${1:-}" in\n  stop|status|refresh|collect) exec '
                + shlex.join(
                    [
                        str(python),
                        str(source / "scripts/manage_local.py"),
                        "--install-dir",
                        str(root),
                    ]
                )
                + ' "$@" ;;\nesac\nexec '
                + shlex.join(command)
                + ' "$@"\n'
            )
            launcher.chmod(0o700)
            if not args.launch_only and not args.no_integrations:
                registered = install_user_integration(root)
                print(
                    "Yeniden aç: uygulamalar menüsünden ThreatFusion AI veya yeni terminalde threatfusion-ai.",
                    flush=True,
                )
                if not all(registered.values()):
                    print(
                        "Var olan başka bir kısayol korundu; alternatif başlatıcı: "
                        + str(launcher),
                        flush=True,
                    )
            command = [
                str(python),
                str(source / "scripts/start_local.py"),
                "--install-dir",
                str(root),
                "--mode",
                mode,
            ]
            if args.port is not None:
                command.extend(["--port", str(args.port)])
            for enabled, flag in (
                (args.prepare_only, "--prepare-only"),
                (args.no_browser, "--no-browser"),
                (args.refresh_cti, "--refresh-cti"),
            ):
                if enabled:
                    command.append(flag)
            print("[3/4] Local çalışma verileri kontrol ediliyor…", flush=True)
            return run_application(command)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(
            f"Kurulum tamamlanamadı ({type(error).__name__}). Ağ/disk erişimini kontrol edip aynı komutu tekrar çalıştırın.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
