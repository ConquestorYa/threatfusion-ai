from __future__ import annotations

import io
import sqlite3

import dpkt
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
        "2026-09-26 10:00:00;10.0.0.5;�rnek.example;A\n"
    ).encode("cp1254")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "dns.csv",
    )

    assert detection.encoding == "cp1254"
    assert parsed.events[0].query_name == "�rnek.example"


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


def test_xlsx_response_ip_header_is_not_consumed_by_missing_client_ip() -> None:
    buffer = io.BytesIO()
    pd.DataFrame(
        {"Query Domain": ["example.com"], "Answer IP": ["203.0.113.9"]}
    ).to_excel(buffer, index=False)

    parsed, _ = parse_dns_upload_with_diagnostics(buffer.getvalue(), "dns.xlsx")

    assert parsed.events[0].client_ip is None
    assert parsed.events[0].response_ip == "203.0.113.9"


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


def test_auto_detects_zeek_conn_log_as_destination_ip_telemetry() -> None:
    content = (
        "#separator \\x09\n"
        "#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p"
        "\tproto\tservice\tlabel\tdet_label\n"
        "1545404132.353979\tC1\t192.168.1.195\t48986\t185.244.25.235"
        "\t6667\ttcp\t-\tMalicious\tC&C\n"
    ).encode("utf-8")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "conn.log.labeled.txt",
    )

    assert detection.format_name == "Zeek conn.log"
    assert parsed.diagnostics.accepted_rows == 1
    assert parsed.events[0].query_name == "185.244.25.235"
    assert parsed.events[0].response_ip == "185.244.25.235"
    assert parsed.events[0].client_ip == "192.168.1.195"


def test_auto_detects_suricata_eve_dns_jsonl() -> None:
    content = (
        '{"timestamp":"2026-09-26T12:00:00Z","event_type":"dns",'
        '"src_ip":"10.0.0.5","dns":{"type":"query","rrname":"evil.example",'
        '"rrtype":"A"}}\n'
    ).encode("utf-8")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "eve.json",
    )

    assert detection.format_name == "Suricata EVE JSON"
    assert parsed.events[0].query_name == "evil.example"
    assert parsed.events[0].query_type == "A"


def test_auto_detects_dnstop_domain_rows() -> None:
    content = (
        "Domain Count Percent\n"
        "example.com 12 60.0\n"
        "api.example.net 8 40.0\n"
    ).encode("utf-8")

    parsed, detection = parse_dns_upload_with_diagnostics(
        content,
        "capture.dnstop",
    )

    assert detection.format_name == "dnstop text"
    assert [event.query_name for event in parsed.events] == [
        "example.com",
        "api.example.net",
    ]


def test_capinfos_metadata_is_rejected_with_actionable_message() -> None:
    try:
        parse_dns_upload_with_diagnostics(
            b"File name: capture.pcap\nNumber of packets: 10\n",
            "capture.capinfos",
        )
    except ValueError as error:
        assert "upload the original .pcap" in str(error)
    else:
        raise AssertionError("capinfos metadata must not be analyzed as telemetry")


def test_auto_detects_pcap_and_extracts_udp_dns_query() -> None:
    dns = dpkt.dns.DNS(
        id=1,
        qd=[dpkt.dns.DNS.Q(name="pcap.example", type=dpkt.dns.DNS_A)],
    )
    udp = dpkt.udp.UDP(sport=53000, dport=53, data=bytes(dns))
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
    buffer = io.BytesIO()
    writer = dpkt.pcap.Writer(buffer)
    writer.writepkt(bytes(ethernet), ts=1700000000.0)
    pcap_bytes = buffer.getvalue()
    writer.close()

    parsed, detection = parse_dns_upload_with_diagnostics(
        pcap_bytes,
        "capture.pcap",
    )

    assert detection.format_name == "PCAP/PCAPNG DNS capture"
    assert parsed.events[0].query_name == "pcap.example"
    assert parsed.events[0].client_ip == "10.0.0.5"
