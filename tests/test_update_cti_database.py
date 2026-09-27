from __future__ import annotations

import update_cti_database


def test_update_database_uses_default_database(monkeypatch) -> None:
    calls: list[list[str]] = []

    monkeypatch.delenv("THREATFUSION_DB_PATH", raising=False)
    monkeypatch.setattr(
        update_cti_database,
        "refresh_main",
        lambda argv: calls.append(argv) or 0,
    )

    assert update_cti_database.main() == 0
    assert calls == [
        [
            "--db",
            "data/threatfusion.sqlite",
            "--force",
            "--allow-missing-keys",
        ]
    ]


def test_update_database_respects_configured_database(monkeypatch, tmp_path) -> None:
    calls: list[list[str]] = []
    db_path = tmp_path / "custom.sqlite"

    monkeypatch.setenv("THREATFUSION_DB_PATH", str(db_path))
    monkeypatch.setattr(
        update_cti_database,
        "refresh_main",
        lambda argv: calls.append(argv) or 0,
    )

    assert update_cti_database.main() == 0
    assert calls == [
        [
            "--db",
            str(db_path),
            "--force",
            "--allow-missing-keys",
        ]
    ]
