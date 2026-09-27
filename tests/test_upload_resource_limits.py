"""Regression coverage for resource limits on untrusted telemetry uploads."""

import io
import sqlite3
import zipfile

import pytest

from threatfusion import dns_ingest, dns_pihole


@pytest.mark.parametrize("reference", ["ZZZZZZ1", "XFE1", "A0", "A1junk"])
def test_xlsx_rejects_invalid_or_oversized_columns(reference) -> None:
    with pytest.raises(ValueError, match="XLSX"):
        dns_ingest._xlsx_column_index(reference)


def test_xlsx_accepts_last_standard_column() -> None:
    assert dns_ingest._xlsx_column_index("XFD1") == 16_383


def _worksheet_archive(rows: str) -> io.BytesIO:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            '<worksheet xmlns="'
            'http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f"<sheetData>{rows}</sheetData></worksheet>",
        )
    payload.seek(0)
    return payload


def test_xlsx_bounds_expanded_sparse_rows(monkeypatch) -> None:
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_CELLS", 12)
    rows = "".join(
        f'<row><c r="D{index}" t="inlineStr"><is><t>x</t></is></c></row>'
        for index in range(1, 5)
    )
    with zipfile.ZipFile(_worksheet_archive(rows)) as archive:
        with pytest.raises(ValueError, match="safe cell import limit"):
            dns_ingest._xlsx_sheet_csv(archive, "xl/worksheets/sheet1.xml", [])


def test_xlsx_accepts_sparse_rows_within_budget(monkeypatch) -> None:
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_CELLS", 12)
    rows = '<row><c r="D1" t="inlineStr"><is><t>x</t></is></c></row>'
    with zipfile.ZipFile(_worksheet_archive(rows)) as archive:
        result = dns_ingest._xlsx_sheet_csv(
            archive, "xl/worksheets/sheet1.xml", []
        )
    assert result == ",,,x\r\n"


def test_pihole_stops_expensive_uploaded_view(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(dns_pihole, "_MAX_PIHOLE_QUERY_STEPS", 1_000)
    path = tmp_path / "expensive.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE numbers (value INTEGER)")
        connection.executemany(
            "INSERT INTO numbers VALUES (?)", [(index,) for index in range(10)]
        )
        connection.execute(
            """
            CREATE VIEW queries AS
            SELECT 1 AS id, 0 AS timestamp, 1 AS type,
                   CAST(count(*) AS TEXT) AS domain, 'client' AS client
            FROM numbers AS a, numbers AS b, numbers AS c, numbers AS d
            """
        )

    with pytest.raises(ValueError, match="could not be read"):
        dns_pihole.parse_pihole_query_db_with_diagnostics(path.read_bytes())


def test_pihole_rejects_large_computed_values(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(dns_pihole, "_MAX_PIHOLE_VALUE_BYTES", 1_024)
    path = tmp_path / "large-value.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE VIEW queries AS
            SELECT 1 AS id, 0 AS timestamp, 1 AS type,
                   zeroblob(2048) AS domain, 'client' AS client
            """
        )

    with pytest.raises(ValueError, match="could not be read"):
        dns_pihole.parse_pihole_query_db_with_diagnostics(path.read_bytes())


def test_pihole_preserves_normal_uploaded_views(tmp_path) -> None:
    path = tmp_path / "normal.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE entries (id, timestamp, type, domain, client)"
        )
        connection.execute(
            "INSERT INTO entries VALUES (?, ?, ?, ?, ?)",
            (1, 1700000000, 1, "example.com", "10.0.0.5"),
        )
        connection.execute("CREATE VIEW queries AS SELECT * FROM entries")

    result = dns_pihole.parse_pihole_query_db_with_diagnostics(path.read_bytes())
    assert len(result.events) == 1
    assert result.events[0].query_name == "example.com"
    assert result.events[0].client_ip == "10.0.0.5"
