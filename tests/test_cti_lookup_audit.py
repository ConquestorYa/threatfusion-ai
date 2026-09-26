import sqlite3
from threatfusion.cti_cache import replace_source_records
from threatfusion.cti_lookup_audit import audit_exact_url_lookup_coverage
from threatfusion.models import IOCRecord, IOCType


def test_exact_url_lookup_coverage_audits_domain_and_ip_hosted_urls(tmp_path):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "https://bad.example/payload",
                IOCType.URL,
                "URLhaus",
            ),
            IOCRecord(
                "http://143.20.185.213/armv7",
                IOCType.URL,
                "URLhaus",
            ),
        ],
    )

    report = audit_exact_url_lookup_coverage(db_path)

    assert report.total_url_records == 2
    assert report.audited_url_records == 2
    assert report.exact_url_hits == 2
    assert report.exact_url_misses == 0
    assert report.exact_url_coverage == 1.0
    assert report.hostname_hits == 2
    assert report.hostname_misses == 0
    assert report.hostname_coverage == 1.0
    assert report.ip_hosted_records == 1
    assert report.ip_hosted_exact_hits == 1


def test_exact_url_lookup_coverage_limit_is_deterministic(tmp_path):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord("https://one.example/a", IOCType.URL, "URLhaus"),
            IOCRecord("https://two.example/b", IOCType.URL, "URLhaus"),
        ],
    )

    report = audit_exact_url_lookup_coverage(db_path, limit=1)

    assert report.total_url_records == 2
    assert report.audited_url_records == 1
    assert report.exact_url_hits == 1


def test_exact_url_lookup_coverage_rejects_invalid_limit(tmp_path):
    db_path = tmp_path / "cti.sqlite"

    try:
        audit_exact_url_lookup_coverage(db_path, limit=0)
    except ValueError as error:
        assert "at least 1" in str(error)
    else:
        raise AssertionError("invalid limit must be rejected")


def test_exact_url_lookup_coverage_detects_corrupt_index_fields(tmp_path):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "http://143.20.185.213/armv7",
                IOCType.URL,
                "URLhaus",
            )
        ],
    )

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            UPDATE cti_records
            SET normalized_value = 'http://wrong.example/'
            WHERE source = 'URLhaus'
            """
        )

    report = audit_exact_url_lookup_coverage(db_path)

    assert report.audited_url_records == 1
    assert report.exact_url_hits == 0
    assert report.exact_url_misses == 1
    assert report.ip_hosted_records == 1
    assert report.ip_hosted_exact_hits == 0


def test_phishtank_hostname_lookup_coverage_is_audited(tmp_path):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "PhishTank",
        [
            IOCRecord(
                "https://phish.example/login",
                IOCType.URL,
                "PhishTank",
            ),
            IOCRecord(
                "http://another-phish.example/",
                IOCType.URL,
                "PhishTank",
            ),
        ],
    )

    report = audit_exact_url_lookup_coverage(
        db_path,
        source="PhishTank",
    )

    assert report.source == "PhishTank"
    assert report.total_url_records == 2
    assert report.exact_url_coverage == 1.0
    assert report.hostname_coverage == 1.0
    assert report.hostname_misses == 0
