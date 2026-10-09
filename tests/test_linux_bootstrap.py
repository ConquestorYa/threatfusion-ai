from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "bootstrap_linux", SOURCE / "scripts/bootstrap_linux.py"
)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def archive_at(tmp_path, entries):
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = 4
                handle.addfile(info, io.BytesIO(b"safe"))
            else:
                info.linkname = "/tmp/outside"
                handle.addfile(info)
    return archive


@pytest.mark.parametrize(
    "name,kind",
    [
        ("root/../../escape", tarfile.REGTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("root/back\\slash", tarfile.REGTYPE),
        ("root/link", tarfile.SYMTYPE),
        ("root/link", tarfile.LNKTYPE),
        ("root/device", tarfile.CHRTYPE),
        ("other/file", tarfile.REGTYPE),
    ],
)
def test_unsafe_archive_is_rejected_before_any_extraction(tmp_path, name, kind):
    archive = archive_at(tmp_path, [("root/valid", tarfile.REGTYPE), (name, kind)])
    target = tmp_path / "target"
    target.mkdir()
    with pytest.raises(ValueError):
        bootstrap.extract_source(archive, target)
    assert not list(target.iterdir())


def test_source_archive_extracts_only_under_one_root(tmp_path):
    archive = archive_at(tmp_path, [("root/nested/app.py", tarfile.REGTYPE)])
    target = tmp_path / "target"
    target.mkdir()
    bootstrap.extract_source(archive, target)
    assert (target / "nested/app.py").read_bytes() == b"safe"


def test_archive_size_limit_is_checked_before_writes(tmp_path, monkeypatch):
    archive = archive_at(
        tmp_path, [("root/a", tarfile.REGTYPE), ("root/b", tarfile.REGTYPE)]
    )
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(bootstrap, "MAX_EXTRACTED_BYTES", 7)
    with pytest.raises(ValueError, match="size limit"):
        bootstrap.extract_source(archive, target)
    assert not list(target.iterdir())


def test_existing_source_identity_is_required_and_preserved(tmp_path):
    sha = "a" * 40
    checkout = tmp_path / "releases" / sha
    checkout.mkdir(parents=True)
    (checkout / ".source-sha").write_text("wrong")
    (checkout / "private.txt").write_text("keep")
    with pytest.raises(ValueError, match="identity"):
        bootstrap.obtain_source(tmp_path, sha)
    assert (checkout / "private.txt").read_text() == "keep"
    (checkout / ".source-sha").write_text(sha)
    assert bootstrap.obtain_source(tmp_path, sha) == checkout


@pytest.mark.parametrize("sha", ["main", "", "a" * 39, "../escape"])
def test_invalid_source_identity_is_refused(tmp_path, sha):
    with pytest.raises(ValueError):
        bootstrap.obtain_source(tmp_path, sha)
    assert not list(tmp_path.iterdir())


def test_environment_install_enforces_hashes_and_preserves_unknown_env(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "requirements-linux.lock").write_text("locked")
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if "venv" in command:
            Path(command[-1]).mkdir(parents=True)

    monkeypatch.setattr(subprocess, "run", run)
    python = bootstrap.prepare_environment(tmp_path, source, Path("uv"))
    assert python.is_relative_to(tmp_path / "environments")
    sync = next(command for command in calls if "sync" in command)
    assert "--require-hashes" in sync and "--only-binary" in sync
    assert "https://pypi.org/simple" in sync
    assert sys.executable in calls[0]
    calls.clear()
    bootstrap.prepare_environment(tmp_path, source, Path("uv"))
    assert not any("venv" in command for command in calls)
    (python.parent.parent / ".threatfusion-venv").unlink()
    with pytest.raises(ValueError, match="not managed"):
        bootstrap.prepare_environment(tmp_path, source, Path("uv"))


@pytest.mark.skipif(sys.platform != "linux", reason="Linux shell installer")
@pytest.mark.parametrize(
    "flags",
    [
        ["--mode", "invalid"],
        ["--port", "80"],
        ["--port", "0000008501"],
        ["--refresh-cti"],
        ["--install-dir"],
        ["--unknown"],
    ],
)
def test_shell_invalid_options_fail_before_installing(tmp_path, flags):
    result = subprocess.run(
        [
            "bash",
            str(SOURCE / "scripts/install_linux.sh"),
            "--install-dir",
            str(tmp_path / "install"),
            *flags,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert not (tmp_path / "install").exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux shell installer")
def test_shell_help_requires_no_python_or_network():
    result = subprocess.run(
        ["bash", str(SOURCE / "scripts/install_linux.sh"), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "no sudo" in result.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="Linux shell installer")
@pytest.mark.parametrize("download", ["exit 22", 'printf "wrong archive" > "${@: -1}"'])
def test_failed_download_or_checksum_preserves_existing_files(tmp_path, download):
    if os.geteuid() == 0:
        pytest.skip("installer deliberately refuses root")
    tools = tmp_path / "tools"
    tools.mkdir()
    curl = tools / "curl"
    curl.write_text("#!/usr/bin/env bash\n" + download + "\n")
    curl.chmod(0o700)
    root = tmp_path / "installation"
    root.mkdir()
    (root / ".threatfusion-install").write_text("1\n")
    preserved = root / "keep.txt"
    preserved.write_text("existing user data")
    result = subprocess.run(
        [
            "bash",
            str(SOURCE / "scripts/install_linux.sh"),
            "--install-dir",
            str(root),
            "--prepare-only",
        ],
        env={
            **os.environ,
            "PATH": str(tools) + os.pathsep + os.environ["PATH"],
            "UV_VERSION": "untrusted-override",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "[1/4] uv 0.12.23" in result.stdout
    assert preserved.read_text() == "existing user data"
    assert not (root / "installation.json").exists()
    assert not list(root.glob(".bootstrap-*"))


def test_settings_import_requires_only_standard_library():
    result = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            "import sys; sys.path.insert(0, 'src'); import threatfusion.local_workspace; "
            "import threatfusion.local_integration; assert 'requests' not in sys.modules",
        ],
        cwd=SOURCE,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_committed_source_archive_passes_the_installer_checks(tmp_path):
    """The installer downloads GitHub's archive of a commit; it must extract."""
    git = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True, text=True)
    if git.returncode:
        pytest.skip("not a git checkout")
    archive = tmp_path / "source.tar.gz"
    subprocess.run(["git", "-C", str(SOURCE), "archive", "--format=tar.gz", "--prefix=source/",
                    "-o", str(archive), "HEAD"], check=True)
    target = tmp_path / "out"
    target.mkdir()
    bootstrap.extract_source(archive, target)  # Rejects symlinks, e.g. a committed .venv link.
    assert (target / "scripts/bootstrap_linux.py").is_file()
    tracked = subprocess.run(["git", "-C", str(SOURCE), "ls-files", "-s"], capture_output=True, text=True, check=True)
    assert not [line for line in tracked.stdout.splitlines() if line.startswith("120000 ")]
