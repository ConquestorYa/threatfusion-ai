from __future__ import annotations

import subprocess

import pytest

from threatfusion.release_audit import (
    audit_git_history,
    audit_tracked_tree,
    scan_release_path,
    scan_release_text,
)


def test_release_audit_detects_common_secret_formats_without_returning_values() -> None:
    secret = "ghp_" + ("A" * 24)

    findings = scan_release_text(
        f"TOKEN={secret}",
        path="config.txt",
        object_id="abc123",
    )

    assert len(findings) == 1
    assert findings[0].rule == "github-token"
    assert findings[0].path == "config.txt"
    assert findings[0].object_id == "abc123"
    assert secret not in repr(findings[0])


def test_release_audit_detects_private_key_marker() -> None:
    findings = scan_release_text(
        "-----BEGIN " + "PRIVATE KEY-----\nredacted\n",
        path="key.pem",
    )

    assert [finding.rule for finding in findings] == ["private-key"]


def test_release_audit_detects_local_user_paths() -> None:
    windows = scan_release_text(
        "saved at C:"
        + "\\"
        + "Users"
        + "\\"
        + "alice"
        + "\\"
        + "project"
        + "\\"
        + "file.txt",
        path="notes.txt",
    )
    macos = scan_release_text(
        "saved at /" + "Users/alice/project/file.txt",
        path="notes.txt",
    )

    assert [finding.rule for finding in windows] == ["local-windows-user-path"]
    assert [finding.rule for finding in macos] == ["local-macos-user-path"]


def test_release_audit_allows_documented_placeholders() -> None:
    text = """
$env:THREATFOX_AUTH_KEY="..."
$env:URLHAUS_AUTH_KEY="..."
$env:PHISHTANK_APP_KEY="YOUR_PHISHTANK_APP_KEY"
OPENAI_API_KEY="<set-in-secret-manager>"
"""

    assert scan_release_text(text, path="README.md") == ()


@pytest.mark.parametrize(
    "path",
    [
        "data/models/model.bin",
        "data/snapshots/dataset.csv",
        "data/evaluation/holdout.json",
        "data/collector/connections.json",
        "data/analyst/context.json",
        "data/deployment/runtime/cache.bin",
        "data/demo/public_demo_cti.sqlite",
        "cache.sqlite-wal",
        "cache.sqlite3-shm",
        "cache.db-journal",
        "model.joblib",
        "model.pkl",
    ],
)
def test_release_audit_rejects_local_data_artifact_paths(path):
    findings = scan_release_path(path, object_id="abc123")
    assert len(findings) == 1
    assert findings[0].rule == "local-data-artifact"
    assert findings[0].path == path
    assert findings[0].object_id == "abc123"


def test_release_audit_allows_code_docs_and_inert_fixtures():
    for path in (
        "src/threatfusion/ml_artifact.py",
        "docs/evidence/ML_DATASET.md",
        "tests/fixtures/dns.csv",
    ):
        assert scan_release_path(path) == ()


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        "config/.env.production",
        ".streamlit/secrets.toml",
        "nested/secrets.toml",
        "credential.key",
        "credential.pem",
        "credential.p12",
        "credential.pfx",
    ],
)
def test_release_audit_rejects_secret_files_even_without_recognizable_key(path):
    findings = scan_release_path(path, object_id="abc123")
    assert len(findings) == 1
    assert findings[0].rule == "secret-file-path"
    assert findings[0].object_id == "abc123"


def test_release_audit_allows_only_env_example():
    assert scan_release_path(".env.example") == ()
    assert scan_release_path("config/.env.example") == ()


def test_secret_file_is_rejected_in_both_tree_and_history(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    (tmp_path / ".env").write_text("TINY_TOKEN=fixture\n")
    subprocess.run(["git", "add", "--force", ".env"], cwd=tmp_path, check=True)
    findings, _ = audit_tracked_tree(tmp_path)
    assert [finding.rule for finding in findings] == ["secret-file-path"]
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "inert fixture",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "rm", ".env"], cwd=tmp_path, check=True, capture_output=True)
    findings, _ = audit_git_history(tmp_path)
    assert any(finding.rule == "secret-file-path" for finding in findings)


def test_release_audit_checks_binary_artifacts_in_tree_and_history(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    artifact = tmp_path / "cache.sqlite"
    artifact.write_bytes(b"SQLite\x00private fixture")
    subprocess.run(["git", "add", "cache.sqlite"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Audit test",
            "-c",
            "user.email=audit@example.com",
            "commit",
            "-m",
            "Synthetic audit fixture",
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    tree, scanned = audit_tracked_tree(tmp_path)
    assert scanned == 0
    assert [finding.rule for finding in tree] == ["local-data-artifact"]
    history, scanned = audit_git_history(tmp_path)
    assert scanned == 0
    assert [finding.rule for finding in history] == ["local-data-artifact"]


def test_history_audit_checks_removed_artifact_blob_alias(tmp_path):
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    payload = b"inert\x00binary fixture"
    (tmp_path / "fixture.bin").write_bytes(payload)
    (tmp_path / "cache.sqlite").write_bytes(payload)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    def commit(message):
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Audit test",
                "-c",
                "user.email=audit@example.com",
                "commit",
                "-m",
                message,
            ],
            cwd=tmp_path,
            check=True,
            capture_output=True,
        )

    commit("Synthetic binary aliases")
    subprocess.run(
        ["git", "rm", "cache.sqlite"], cwd=tmp_path, check=True, capture_output=True
    )
    commit("Remove synthetic cache")
    assert audit_tracked_tree(tmp_path)[0] == ()
    findings, _ = audit_git_history(tmp_path)
    assert [finding.path for finding in findings] == ["cache.sqlite"]


def test_release_audit_detects_threatfusion_service_secret_assignments() -> None:
    secret = "abcdefghijkl" + "mnopqrstuvwx"
    findings = scan_release_text(
        'THREATFOX_AUTH_KEY="' + secret + '"',
        path=".env.example.bad",
    )

    assert [finding.rule for finding in findings] == ["threatfusion-service-secret"]


def test_release_audit_allows_service_secret_placeholders() -> None:
    text = """
THREATFOX_AUTH_KEY="..."
URLHAUS_AUTH_KEY="<set-in-secret-manager>"
PHISHTANK_APP_KEY="YOUR_PHISHTANK_APP_KEY"
RENDER_API_KEY="..."
"""

    assert scan_release_text(text, path="README.md") == ()


def test_saved_installer_credentials_are_rejected_even_with_short_keys():
    from threatfusion.release_audit import scan_release_path

    findings = scan_release_path("local/credentials.json")
    assert findings[0].rule == "secret-file-path"
