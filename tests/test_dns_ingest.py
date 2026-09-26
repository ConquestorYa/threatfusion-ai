from __future__ import annotations

import io
import sqlite3

import pandas as pd

from threatfusion import dns_ingest
from threatfusion.dns_ingest import parse_dns_upload_with_diagnostics


def test_auto_detects_flexible_csv_headers_and_semantic_query_type() -> None:
    content = (
        "Timestamp,Server,Service,Client IP,Port,Query Domain,"
        "Record Type,Record Class\n"
        "Jun 4 02:14:20,ns1,named[4096]:,client,,ntp.ubuntu.com,IN,AAAA\n"
        "Jun 4 02:14:21,ns1,named[4096]:,client,,example.com,IN,A\n"
    ).encode("utf-8")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "dns_logs.csv",
    )

    assert detection.format_name == "Delimited DNS table"
    assert [event.query_name for event in parsed.events] == [
        "ntp.ubuntu.com",
        "example.com",
    ]
    assert [event.query_type for event in parsed.events] == ["AAAA", "A"]
    assert parsed.events[0].timestamp is not None
    assert parsed.events[0].timestamp.year == 2000
    assert parsed.diagnostics.invalid_timestamps == 0
    assert parsed.diagnostics.accepted_rows == 2


def test_auto_detects_semicolon_delimiter_and_cp1254_text() -> None:
    content = (
        "zaman;istemci;domain;tip\n"
        "2026-09-26 10:00:00;10.0.0.5;örnek.example;A\n"
    ).encode("cp1254")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "dns.csv",
    )

    assert detection.encoding == "cp1254"
    assert parsed.events[0].query_name == "örnek.example"


def test_auto_detects_utf16_tsv() -> None:
    content = (
        "timestamp\tclient_ip\tquery_name\tquery_type\n"
        "2026-09-26T10:00:00Z\t10.0.0.5\texample.com\tAAAA\n"
    ).encode("utf-16")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "dns.tsv",
    )

    assert detection.encoding == "utf-16"
    assert parsed.events[0].query_name == "example.com"
    assert parsed.events[0].query_type == "AAAA"


def test_auto_detects_xlsx_and_selects_dns_worksheet() -> None:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        pd.DataFrame({"notes": ["not dns"]}).to_excel(
            writer,
            sheet_name="README",
            index=False,
        )
        pd.DataFrame(
            {
                "Query Domain": ["example.com", "api.example.com"],
                "Client IP": ["10.0.0.5", "10.0.0.6"],
                "Record Type": ["IN", "IN"],
                "Record Class": ["A", "AAAA"],
            }
        ).to_excel(writer, sheet_name="DNS", index=False)

    parsed, detection = parse_dns_upload_with_diagnostics(
        buffer.getvalue(),
        "dns_logs.xlsx",
    )

    assert detection.format_name == "Excel DNS table"
    assert detection.detail == "worksheet: DNS"
    assert [event.query_name for event in parsed.events] == [
        "example.com",
        "api.example.com",
    ]
    assert [event.query_type for event in parsed.events] == ["A", "AAAA"]


def test_xlsx_uses_builtin_reader_when_excel_engine_is_unavailable(
    monkeypatch,
) -> None:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        pd.DataFrame(
            {
                "Query Domain": ["fallback.example", "api.fallback.example"],
                "Client IP": ["10.0.0.5", "10.0.0.6"],
                "Record Class": ["A", "AAAA"],
            }
        ).to_excel(writer, sheet_name="DNS", index=False)

    def fail_excel_engine(*args, **kwargs):
        raise ImportError("openpyxl is unavailable")

    monkeypatch.setattr(dns_ingest.pd, "ExcelFile", fail_excel_engine)

    parsed, detection = parse_dns_upload_with_diagnostics(
        buffer.getvalue(),
        "dns_logs.xlsx",
    )

    assert detection.format_name == "Excel DNS table"
    assert detection.detail == "worksheet: DNS"
    assert [event.query_name for event in parsed.events] == [
        "fallback.example",
        "api.fallback.example",
    ]
    assert [event.query_type for event in parsed.events] == ["A", "AAAA"]


def test_auto_detects_zeek_content_without_manual_format_selection() -> None:
    content = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tquery\tqtype_name\tanswers\n"
        "1700000000.0\t10.0.0.5\texample.com\tA\t203.0.113.7\n"
    ).encode("utf-8")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "anything.log",
    )

    assert detection.format_name == "Zeek dns.log"
    assert parsed.events[0].response_ip == "203.0.113.7"


def test_auto_detects_adguard_json() -> None:
    content = (
        '{"IP":"10.0.0.5","T":"2026-09-25T18:00:00Z",'
        '"QH":"example.com","QT":"A"}'
    ).encode("utf-8")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "querylog.json",
    )

    assert detection.format_name == "AdGuard Home query log"
    assert parsed.events[0].query_name == "example.com"


def test_auto_detects_pihole_sqlite_signature(tmp_path) -> None:
    path = tmp_path / "pihole-FTL.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE queries (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER,
                type INTEGER,
                domain TEXT,
                client TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO queries VALUES (?, ?, ?, ?, ?)",
            (1, 1700000000, 1, "example.com", "10.0.0.5"),
        )

    parsed, detection = parse_dns_upload_with_diagnostics(
        path.read_bytes(),
        "renamed.bin",
    )

    assert detection.format_name == "Pi-hole FTL database"
    assert parsed.events[0].query_name == "example.com"
