from __future__ import annotations

from threatfusion.release_audit import scan_release_text


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

    assert [finding.rule for finding in windows] == [
        "local-windows-user-path"
    ]
    assert [finding.rule for finding in macos] == [
        "local-macos-user-path"
    ]


def test_release_audit_allows_documented_placeholders() -> None:
    text = '''
$env:THREATFOX_AUTH_KEY="..."
$env:URLHAUS_AUTH_KEY="..."
OPENAI_API_KEY="<set-in-secret-manager>"
'''

    assert scan_release_text(text, path="README.md") == ()


def test_release_audit_detects_threatfusion_service_secret_assignments() -> None:
    secret = "abcdefghijkl" + "mnopqrstuvwx"
    findings = scan_release_text(
        'THREATFOX_AUTH_KEY="' + secret + '"',
        path=".env.example.bad",
    )

    assert [finding.rule for finding in findings] == [
        "threatfusion-service-secret"
    ]


def test_release_audit_allows_service_secret_placeholders() -> None:
    text = '''
THREATFOX_AUTH_KEY="..."
URLHAUS_AUTH_KEY="<set-in-secret-manager>"
RENDER_API_KEY="..."
'''

    assert scan_release_text(text, path="README.md") == ()
