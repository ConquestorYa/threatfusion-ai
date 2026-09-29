"""The CTI refresh CLI reports partial coverage without treating it as failure."""

from scripts import refresh_cti_cache
from threatfusion.cti_refresh import CTIRefreshOutcome


def test_degraded_urlhaus_summary_preserves_success_exit(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        refresh_cti_cache,
        "refresh_configured_sources",
        lambda *args, **kwargs: (
            CTIRefreshOutcome(
                source="URLhaus",
                status="degraded",
                detail="recent fallback has partial coverage",
            ),
        ),
    )

    exit_code = refresh_cti_cache.main(
        ["--db", str(tmp_path / "cti.sqlite"), "--allow-missing-keys"]
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert (
        "URLhaus: degraded (recent fallback has partial coverage); "
        "previous full cache preserved"
    ) in output
    assert "failed (unknown error)" not in output


def test_real_failure_still_sets_failure_exit_with_degraded_source(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        refresh_cti_cache,
        "refresh_configured_sources",
        lambda *args, **kwargs: (
            CTIRefreshOutcome(source="URLhaus", status="degraded"),
            CTIRefreshOutcome(
                source="ThreatFox",
                status="failed",
                error_type="RuntimeError",
                detail="upstream unavailable",
            ),
        ),
    )

    exit_code = refresh_cti_cache.main(
        ["--db", str(tmp_path / "cti.sqlite"), "--allow-missing-keys"]
    )
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "URLhaus: degraded; previous full cache preserved" in output
    assert "ThreatFox: failed (RuntimeError: upstream unavailable)" in output
