"""Regression coverage for resource limits on untrusted telemetry uploads."""

import io
import sqlite3
import zipfile

import dpkt
import pytest

from threatfusion import (
    dns,
    dns_adguard,
    dns_ingest,
    dns_pihole,
    dns_zeek,
    network_telemetry,
)


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


def _excel_zip_members(members, *, compression=zipfile.ZIP_STORED) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return payload.getvalue()


def _forbid_excel_readers(monkeypatch) -> None:
    def unexpected_reader(*args, **kwargs):
        pytest.fail("unsafe archive reached an Excel reader")

    monkeypatch.setattr(
        dns_ingest, "_parse_excel_with_pandas", unexpected_reader
    )
    monkeypatch.setattr(
        dns_ingest, "_parse_xlsx_without_engine", unexpected_reader
    )


@pytest.mark.parametrize("filename", ["upload.xlsx", "renamed.xls"])
def test_excel_rejects_large_zip_member_before_readers(
    monkeypatch, filename
) -> None:
    _forbid_excel_readers(monkeypatch)
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_XML_BYTES", 1_024)
    content = _excel_zip_members({"xl/sharedStrings.xml": b"x" * 1_025})
    with pytest.raises(ValueError, match="member exceeds"):
        dns_ingest.parse_dns_upload_with_diagnostics(content, filename)


def test_excel_bounds_total_expansion_before_readers(monkeypatch) -> None:
    _forbid_excel_readers(monkeypatch)
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_XML_BYTES", 1_024)
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_ARCHIVE_BYTES", 1_024)
    content = _excel_zip_members(
        {"xl/sharedStrings.xml": b"x" * 600, "xl/styles.xml": b"y" * 600}
    )
    with pytest.raises(ValueError, match="archive exceeds"):
        dns_ingest.parse_dns_upload_with_diagnostics(content, "upload.xlsx")


def test_excel_rejects_extreme_compression_before_readers(monkeypatch) -> None:
    _forbid_excel_readers(monkeypatch)
    content = _excel_zip_members(
        {"xl/sharedStrings.xml": b"x" * 100_000},
        compression=zipfile.ZIP_DEFLATED,
    )
    with pytest.raises(ValueError, match="compression ratio"):
        dns_ingest.parse_dns_upload_with_diagnostics(content, "upload.xlsx")


def test_excel_validates_prefixed_zip_before_readers(monkeypatch) -> None:
    _forbid_excel_readers(monkeypatch)
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_XML_BYTES", 1_024)
    content = b"prefix" + _excel_zip_members(
        {"xl/sharedStrings.xml": b"x" * 1_025}
    )
    with pytest.raises(ValueError, match="member exceeds"):
        dns_ingest.parse_dns_upload_with_diagnostics(content, "upload.xlsx")


def test_excel_accepts_archive_at_byte_limits(monkeypatch) -> None:
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_XML_BYTES", 512)
    monkeypatch.setattr(dns_ingest, "_MAX_XLSX_ARCHIVE_BYTES", 1_024)
    content = _excel_zip_members(
        {"xl/sharedStrings.xml": b"x" * 512, "xl/styles.xml": b"y" * 512}
    )
    dns_ingest._validate_xlsx_archive(content)


def test_excel_keeps_non_zip_legacy_reader_path(monkeypatch) -> None:
    expected = object()
    monkeypatch.setattr(
        dns_ingest, "_parse_excel_with_pandas", lambda content: expected
    )
    assert dns_ingest._parse_excel(b"legacy binary data", "upload.xls") is expected


def test_delimited_dns_rejects_excessive_columns(monkeypatch) -> None:
    monkeypatch.setattr(dns, "_MAX_TABLE_COLUMNS", 3)
    content = "query_name,a,b,c\nexample.com,1,2,3\n"
    with pytest.raises(ValueError, match="column import limit"):
        dns.parse_dns_csv_with_diagnostics(content)


def test_delimited_dns_rejects_excessive_rows(monkeypatch) -> None:
    monkeypatch.setattr(dns, "_MAX_TABLE_ROWS", 2)
    content = (
        "query_name\n"
        "one.example\n"
        "two.example\n"
        "three.example\n"
    )
    with pytest.raises(ValueError, match="row import limit"):
        dns.parse_dns_csv_with_diagnostics(content)


def test_delimited_dns_rejects_total_cell_expansion(monkeypatch) -> None:
    monkeypatch.setattr(dns, "_MAX_TABLE_CELLS", 4)
    content = (
        "query_name,client_ip\n"
        "one.example,10.0.0.1\n"
        "two.example,10.0.0.2\n"
        "three.example,10.0.0.3\n"
    )
    with pytest.raises(ValueError, match="cell import limit"):
        dns.parse_dns_csv_with_diagnostics(content)


def test_zeek_dns_rejects_excessive_fields(monkeypatch) -> None:
    monkeypatch.setattr(dns_zeek, "_MAX_ZEEK_FIELDS", 3)
    content = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tquery\tqtype_name\n"
        "1700000000\t10.0.0.5\texample.com\tA\n"
    )
    with pytest.raises(ValueError, match="field import limit"):
        dns_zeek.parse_zeek_dns_log_with_diagnostics(content)


def test_zeek_dns_rejects_total_cell_expansion(monkeypatch) -> None:
    monkeypatch.setattr(dns_zeek, "_MAX_ZEEK_CELLS", 5)
    content = (
        "#separator \\x09\n"
        "#fields\tts\tquery\tqtype_name\n"
        "1700000000\tone.example\tA\n"
        "1700000001\ttwo.example\tA\n"
    )
    with pytest.raises(ValueError, match="cell import limit"):
        dns_zeek.parse_zeek_dns_log_with_diagnostics(content)


def test_zeek_conn_rejects_excessive_rows(monkeypatch) -> None:
    monkeypatch.setattr(network_telemetry, "_MAX_ZEEK_ROWS", 1)
    content = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\n"
        "1700000000\t10.0.0.5\t203.0.113.10\n"
        "1700000001\t10.0.0.6\t203.0.113.11\n"
    )
    with pytest.raises(ValueError, match="row import limit"):
        network_telemetry.parse_zeek_conn_log_with_diagnostics(content)


def test_zeek_conn_rejects_excessive_fields(monkeypatch) -> None:
    monkeypatch.setattr(network_telemetry, "_MAX_ZEEK_FIELDS", 3)
    content = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.resp_h\tproto\n"
        "1700000000\t10.0.0.5\t203.0.113.10\ttcp\n"
    )
    with pytest.raises(ValueError, match="field import limit"):
        network_telemetry.parse_zeek_conn_log_with_diagnostics(content)


def test_adguard_rejects_excessive_jsonl_entries(monkeypatch) -> None:
    monkeypatch.setattr(dns_adguard, "_MAX_ADGUARD_ENTRIES", 1)
    content = (
        '{"QH":"one.example","QT":"A"}\n'
        '{"QH":"two.example","QT":"A"}\n'
    )
    with pytest.raises(ValueError, match="entry import limit"):
        dns_adguard.parse_adguard_query_log_with_diagnostics(content)


def test_adguard_rejects_excessive_answer_expansion(monkeypatch) -> None:
    monkeypatch.setattr(dns_adguard, "_MAX_ADGUARD_ANSWERS", 1)
    content = (
        '{"question":{"host":"one.example","type":"A"},'
        '"answer":[{"value":"alias.example"},{"value":"203.0.113.5"}]}'
    )
    with pytest.raises(ValueError, match="answer list"):
        dns_adguard.parse_adguard_query_log_with_diagnostics(content)


def test_adguard_detection_uses_bounded_probe_for_generic_json() -> None:
    content = '{"QH":"one.example"' + ("x" * 200_000)
    assert dns_ingest._looks_like_adguard(content, "upload.txt")


def test_suricata_rejects_excessive_jsonl_records(monkeypatch) -> None:
    monkeypatch.setattr(network_telemetry, "_MAX_SURICATA_RECORDS", 1)
    content = (
        '{"event_type":"dns","dns":{"rrname":"one.example"}}\n'
        '{"event_type":"dns","dns":{"rrname":"two.example"}}\n'
    )
    with pytest.raises(ValueError, match="record import limit"):
        network_telemetry.parse_suricata_eve_with_diagnostics(content)


def test_dnstop_rejects_excessive_rows(monkeypatch) -> None:
    monkeypatch.setattr(network_telemetry, "_MAX_DNSTOP_ROWS", 1)
    content = "one.example 1\ntwo.example 1\n"
    with pytest.raises(ValueError, match="row import limit"):
        network_telemetry.parse_dnstop_with_diagnostics(content)


def _pcap_with_packets(packets: list[bytes]) -> bytes:
    payload = io.BytesIO()
    writer = dpkt.pcap.Writer(payload)
    for index, packet in enumerate(packets):
        writer.writepkt(packet, ts=1700000000.0 + index)
    result = payload.getvalue()
    writer.close()
    return result


def test_pcap_rejects_excessive_packet_count(monkeypatch) -> None:
    monkeypatch.setattr(network_telemetry, "_MAX_PCAP_PACKETS", 1)
    content = _pcap_with_packets([b"\x00" * 60, b"\x00" * 60])
    with pytest.raises(ValueError, match="packet import limit"):
        network_telemetry.parse_pcap_dns_with_diagnostics(content)


def test_pcap_rejects_excessive_dns_events(monkeypatch) -> None:
    monkeypatch.setattr(network_telemetry, "_MAX_PCAP_DNS_EVENTS", 1)

    dns_packet = dpkt.dns.DNS(
        id=1,
        qd=[
            dpkt.dns.DNS.Q(name="one.example", type=dpkt.dns.DNS_A),
            dpkt.dns.DNS.Q(name="two.example", type=dpkt.dns.DNS_A),
        ],
    )
    udp = dpkt.udp.UDP(sport=53000, dport=53, data=bytes(dns_packet))
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=b"\x0a\x00\x00\x05",
        dst=b"\x08\x08\x08\x08",
        p=dpkt.ip.IP_PROTO_UDP,
        data=udp,
    )
    ip.len = len(ip)
    ethernet = dpkt.ethernet.Ethernet(
        src=b"\x00\x01\x02\x03\x04\x05",
        dst=b"\x06\x07\x08\x09\x0a\x0b",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )

    with pytest.raises(ValueError, match="DNS event import limit"):
        network_telemetry.parse_pcap_dns_with_diagnostics(
            _pcap_with_packets([bytes(ethernet)])
        )
