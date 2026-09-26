from __future__ import annotations

import ipaddress
import io
import json
import re
import socket
from datetime import datetime, timezone

import dpkt

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult
from .normalization import normalize_domain_name


def _empty_result() -> DNSParseResult:
    return DNSParseResult(
        events=(),
        diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
    )


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text in {"-", "(empty)", "null", "None"}:
        return None
    return text


def _epoch(value: object) -> datetime | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _iso_timestamp(value: object) -> datetime | None:
    text = _optional_text(value)
    if text is None:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _zeek_separator(line: str) -> str:
    value = line[len("#separator") :].strip()
    if value == r"\x09":
        return "\t"
    if len(value) == 1:
        return value
    raise ValueError("unsupported Zeek field separator")


def parse_zeek_conn_log_with_diagnostics(content: str) -> DNSParseResult:
    """Map Zeek conn.log destination IP observations into passive CTI events."""
    if content is None or not content.strip():
        return _empty_result()

    separator = "\t"
    fields: list[str] | None = None
    events: list[DNSEvent] = []
    total_rows = 0
    skipped = 0
    invalid_timestamps = 0
    invalid_ips = 0

    for raw_line in content.splitlines():
        if not raw_line:
            continue
        if raw_line.startswith("#separator"):
            separator = _zeek_separator(raw_line)
            continue
        if raw_line.startswith("#fields"):
            remainder = raw_line[len("#fields") :]
            remainder = (
                remainder[len(separator) :]
                if remainder.startswith(separator)
                else remainder.lstrip()
            )
            fields = remainder.split(separator)
            continue
        if raw_line.startswith("#"):
            continue

        if fields is None:
            raise ValueError("Zeek conn.log is missing a #fields header")

        values = raw_line.split(separator)
        if len(values) < len(fields):
            values.extend([""] * (len(fields) - len(values)))
        row = dict(zip(fields, values, strict=False))
        total_rows += 1

        destination = _optional_text(row.get("id.resp_h"))
        if destination is None:
            skipped += 1
            continue
        try:
            destination = str(ipaddress.ip_address(destination))
        except ValueError:
            invalid_ips += 1
            skipped += 1
            continue

        timestamp_text = _optional_text(row.get("ts"))
        timestamp = _epoch(timestamp_text)
        if timestamp_text is not None and timestamp is None:
            invalid_timestamps += 1

        events.append(
            DNSEvent(
                query_name=destination,
                timestamp=timestamp,
                client_ip=_optional_text(row.get("id.orig_h")),
                response_ip=destination,
            )
        )

    if fields is None:
        raise ValueError("Zeek conn.log is missing a #fields header")
    required = {"id.orig_h", "id.resp_h"}
    if not required.issubset(fields):
        raise ValueError(
            "Zeek conn.log must include id.orig_h and id.resp_h fields"
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total_rows,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=invalid_ips,
        ),
    )


def _suricata_dns_event(record: dict[str, object]) -> DNSEvent | None:
    dns = record.get("dns")
    if not isinstance(dns, dict):
        return None

    rrname = _optional_text(dns.get("rrname"))
    if rrname is None:
        query = dns.get("query")
        if isinstance(query, list) and query and isinstance(query[0], dict):
            rrname = _optional_text(query[0].get("rrname"))
    if rrname is None:
        return None

    rrtype = _optional_text(dns.get("rrtype") or dns.get("type"))
    rcode = _optional_text(dns.get("rcode"))

    response_ip = None
    answers = dns.get("answers")
    if isinstance(answers, list):
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            rdata = _optional_text(answer.get("rdata"))
            if rdata is None:
                continue
            try:
                response_ip = str(ipaddress.ip_address(rdata))
                break
            except ValueError:
                continue

    return DNSEvent(
        query_name=rrname,
        timestamp=_iso_timestamp(record.get("timestamp")),
        client_ip=_optional_text(record.get("src_ip")),
        query_type=rrtype.upper() if rrtype else None,
        response_ip=response_ip,
        response_code=rcode.upper() if rcode else None,
    )


def _suricata_ip_event(record: dict[str, object]) -> DNSEvent | None:
    destination = _optional_text(record.get("dest_ip"))
    if destination is None:
        return None
    try:
        destination = str(ipaddress.ip_address(destination))
    except ValueError:
        return None
    return DNSEvent(
        query_name=destination,
        timestamp=_iso_timestamp(record.get("timestamp")),
        client_ip=_optional_text(record.get("src_ip")),
        response_ip=destination,
    )


def parse_suricata_eve_with_diagnostics(content: str) -> DNSParseResult:
    """Parse Suricata EVE JSON/JSONL, preferring DNS records when present."""
    if content is None or not content.strip():
        return _empty_result()

    stripped = content.lstrip()
    records: list[dict[str, object]] = []
    if stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise ValueError("Suricata EVE JSON is malformed") from error
        if not isinstance(parsed, list):
            raise ValueError("Suricata EVE JSON array is invalid")
        records = [item for item in parsed if isinstance(item, dict)]
    else:
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError("Suricata EVE JSONL contains a malformed line") from error
            if isinstance(item, dict):
                records.append(item)

    dns_events = [
        event
        for record in records
        if (event := _suricata_dns_event(record)) is not None
    ]
    events = dns_events
    if not events:
        events = [
            event
            for record in records
            if (event := _suricata_ip_event(record)) is not None
        ]

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=len(records),
            accepted_rows=len(events),
            skipped_missing_query_name=max(0, len(records) - len(events)),
            invalid_timestamps=0,
            invalid_response_ips=0,
        ),
    )


def _ip_text(address_bytes: bytes) -> str | None:
    try:
        if len(address_bytes) == 4:
            return socket.inet_ntop(socket.AF_INET, address_bytes)
        if len(address_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, address_bytes)
    except OSError:
        return None
    return None


def _dns_events_from_packet(timestamp: float, packet: bytes) -> list[DNSEvent]:
    try:
        ethernet = dpkt.ethernet.Ethernet(packet)
        ip_packet = ethernet.data
        if not isinstance(ip_packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return []
        transport = ip_packet.data
        if not isinstance(transport, dpkt.udp.UDP):
            return []
        if transport.sport != 53 and transport.dport != 53:
            return []
        dns = dpkt.dns.DNS(bytes(transport.data))
    except (dpkt.UnpackError, ValueError):
        return []

    client_ip = _ip_text(ip_packet.src)
    timestamp_value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    events: list[DNSEvent] = []

    questions = list(getattr(dns, "qd", ()) or ())
    answers = list(getattr(dns, "an", ()) or ())
    response_ip = None
    for answer in answers:
        answer_type = getattr(answer, "type", None)
        rdata = getattr(answer, "rdata", b"")
        if answer_type in {dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA}:
            response_ip = _ip_text(rdata)
            if response_ip:
                break

    for question in questions:
        name = _optional_text(getattr(question, "name", None))
        if name is None:
            continue
        qtype = getattr(question, "type", None)
        qtype_name = {
            dpkt.dns.DNS_A: "A",
            dpkt.dns.DNS_AAAA: "AAAA",
            dpkt.dns.DNS_CNAME: "CNAME",
            dpkt.dns.DNS_MX: "MX",
            dpkt.dns.DNS_NS: "NS",
            dpkt.dns.DNS_PTR: "PTR",
            dpkt.dns.DNS_SOA: "SOA",
            dpkt.dns.DNS_TXT: "TXT",
        }.get(qtype, str(qtype) if qtype is not None else None)
        events.append(
            DNSEvent(
                query_name=name,
                timestamp=timestamp_value,
                client_ip=client_ip,
                query_type=qtype_name,
                response_ip=response_ip,
                response_code=str(getattr(dns, "rcode", "")) or None,
            )
        )
    return events


def parse_pcap_dns_with_diagnostics(content: bytes) -> DNSParseResult:
    """Extract classic UDP DNS observations from PCAP or PCAPNG bytes."""
    if not content:
        return _empty_result()

    stream = io.BytesIO(content)
    try:
        if content.startswith(b"\x0a\x0d\x0d\x0a"):
            reader = dpkt.pcapng.Reader(stream)
        else:
            reader = dpkt.pcap.Reader(stream)
    except (ValueError, dpkt.UnpackError) as error:
        raise ValueError("packet capture is not a readable PCAP/PCAPNG file") from error

    events: list[DNSEvent] = []
    packet_count = 0
    try:
        for timestamp, packet in reader:
            packet_count += 1
            events.extend(_dns_events_from_packet(float(timestamp), packet))
    except (ValueError, dpkt.UnpackError) as error:
        raise ValueError("packet capture contains malformed packet data") from error

    if not events:
        raise ValueError(
            "PCAP/PCAPNG contains no readable classic UDP DNS traffic; "
            "encrypted DNS and non-DNS packets cannot be converted to DNS telemetry"
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=packet_count,
            accepted_rows=len(events),
            skipped_missing_query_name=max(0, packet_count - len(events)),
            invalid_timestamps=0,
            invalid_response_ips=0,
        ),
    )


def parse_dnstop_with_diagnostics(content: str) -> DNSParseResult:
    """Parse a conservative dnstop-style domain/count text export."""
    if content is None or not content.strip():
        return _empty_result()

    events: list[DNSEvent] = []
    total = 0
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        total += 1
        parts = re.split(r"\s+", line)
        candidates = parts[:2]
        domain = None
        for candidate in candidates:
            candidate = candidate.rstrip(".")
            if "." not in candidate:
                continue
            try:
                ipaddress.ip_address(candidate)
                continue
            except ValueError:
                pass
            normalized = normalize_domain_name(candidate, strict=True)
            if normalized:
                domain = normalized
                break
        if domain is not None:
            events.append(DNSEvent(query_name=domain))

    if not events:
        raise ValueError(
            "dnstop text does not contain recognizable domain rows"
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total,
            accepted_rows=len(events),
            skipped_missing_query_name=max(0, total - len(events)),
            invalid_timestamps=0,
            invalid_response_ips=0,
        ),
    )
