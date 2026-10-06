from __future__ import annotations

import ipaddress
import io
import json
import math
import re
import socket
from datetime import datetime, timezone

import dpkt

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult, parse_response_ips
from .connections import ConnectionRecord
from .normalization import normalize_domain_name


_MAX_ZEEK_FIELDS = 512
_MAX_ZEEK_ROWS = 100_000
_MAX_ZEEK_CELLS = 5_000_000
_MAX_SURICATA_RECORDS = 100_000
_MAX_PCAP_PACKETS = 500_000
_MAX_PCAP_DNS_EVENTS = 100_000
_MAX_PCAP_PAIR_CHECKS = 1_000_000
_MAX_DNSTOP_ROWS = 100_000


class _TelemetryResourceLimitError(ValueError):
    """Raised when untrusted telemetry exceeds a parser work budget."""


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
    invalid_connection_fields = 0
    connections = []
    cell_count = 0

    for raw_line in io.StringIO(content):
        raw_line = raw_line.rstrip("\r\n")
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
            fields = remainder.split(separator, _MAX_ZEEK_FIELDS)
            if len(fields) > _MAX_ZEEK_FIELDS:
                raise ValueError("Zeek conn.log exceeds the safe field import limit")
            continue
        if raw_line.startswith("#"):
            continue

        if fields is None:
            raise ValueError("Zeek conn.log is missing a #fields header")

        values = raw_line.split(separator, _MAX_ZEEK_FIELDS)
        if len(values) > _MAX_ZEEK_FIELDS:
            raise ValueError("Zeek conn.log exceeds the safe field import limit")
        if total_rows >= _MAX_ZEEK_ROWS:
            raise ValueError("Zeek conn.log exceeds the safe row import limit")

        cell_count += max(len(fields), len(values))
        if cell_count > _MAX_ZEEK_CELLS:
            raise ValueError("Zeek conn.log exceeds the safe cell import limit")

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
        invalid = []
        def number(name, *, maximum, integer=False):
            text = _optional_text(row.get(name))
            if text is None:
                return None
            try:
                if len(text) > 32:
                    raise ValueError
                value = int(text) if integer else float(text)
                if not math.isfinite(value) or not 0 <= value <= maximum:
                    raise ValueError
                return value
            except (ValueError, OverflowError):
                invalid.append(name)
                return None
        def bounded_text(name, maximum, *, allowed=()):
            text = _optional_text(row.get(name))
            if text is not None and text not in allowed and len(text) > maximum:
                invalid.append(name)
                return None
            return text
        source = _optional_text(row.get("id.orig_h"))
        try:
            source = str(ipaddress.ip_address(source)) if source else None
        except ValueError:
            source = None
            invalid.append("id.orig_h")
        connections.append(ConnectionRecord(
            uid=bounded_text("uid", 128), timestamp=timestamp,
            originator_ip=source, responder_ip=destination,
            originator_port=number("id.orig_p", maximum=65535, integer=True),
            responder_port=number("id.resp_p", maximum=65535, integer=True),
            # Zeek's official enum is 17 characters. Keep the exact value;
            # unknown transport must never be inferred as TCP or UDP.
            protocol=bounded_text("proto", 16, allowed=("unknown_transport",)),
            duration_seconds=number("duration", maximum=365 * 86400),
            originator_bytes=number("orig_bytes", maximum=2**63 - 1, integer=True),
            responder_bytes=number("resp_bytes", maximum=2**63 - 1, integer=True),
            state=bounded_text("conn_state", 16),
            missed_bytes=number("missed_bytes", maximum=2**63 - 1, integer=True),
        ))
        invalid_connection_fields += len(invalid)

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
            invalid_connection_fields=invalid_connection_fields,
        ),
        connections=tuple(connections),
    )


def _suricata_dns_event(record: dict[str, object]) -> DNSEvent | None:
    dns = record.get("dns")
    if not isinstance(dns, dict):
        return None

    rrname = _optional_text(dns.get("rrname"))
    queries = dns.get("queries", dns.get("query"))
    if isinstance(queries, list) and len(queries) > 1:
        raise ValueError("Suricata multi-question DNS records are not supported; use a single-question export")
    question = queries[0] if isinstance(queries, list) and queries and isinstance(queries[0], dict) else {}
    if rrname is None:
        rrname = _optional_text(question.get("rrname"))
    if rrname is None:
        return None

    rrtype = _optional_text(dns.get("rrtype") or question.get("rrtype"))
    rcode = _optional_text(dns.get("rcode"))

    raw_addresses = []
    answers = dns.get("answers")
    if isinstance(answers, list):
        if len(answers) > 1024:
            raise ValueError("Suricata DNS answers exceed the safe answer limit")
        raw_addresses.extend(_optional_text(answer.get("rdata"))
                             if isinstance(answer, dict) else None for answer in answers)
    grouped = dns.get("grouped")
    if isinstance(grouped, dict):
        for kind in ("A", "AAAA"):
            values = grouped.get(kind, [])
            if not isinstance(values, list) or len(values) > 1024:
                raise ValueError("Suricata grouped DNS answers exceed the safe answer limit")
            raw_addresses.extend(values)
    if dns.get("rdata") is not None:
        raw_addresses.append(_optional_text(dns.get("rdata")))
    addresses = parse_response_ips(raw_addresses)
    kind = str(dns.get("type", "")).lower()
    if record.get("src_port") == 53 and record.get("dest_port") != 53:
        client = _optional_text(record.get("dest_ip"))
    elif record.get("dest_port") == 53 and record.get("src_port") != 53:
        client = _optional_text(record.get("src_ip"))
    else:
        # Some exporters keep flow direction on answers. Without ports, do
        # not guess whether src_ip is a resolver or an actual client.
        client = _optional_text(record.get("src_ip")) if kind in ("query", "request") else None

    return DNSEvent(
        query_name=rrname,
        timestamp=_iso_timestamp(record.get("timestamp")),
        client_ip=client,
        query_type=rrtype.upper() if rrtype else None,
        response_ip=addresses[0] if addresses else None,
        response_ips=addresses[1:],
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
        except (json.JSONDecodeError, RecursionError) as error:
            raise ValueError("Suricata EVE JSON is malformed") from error
        if not isinstance(parsed, list):
            raise ValueError("Suricata EVE JSON array is invalid")
        if len(parsed) > _MAX_SURICATA_RECORDS:
            raise ValueError("Suricata EVE exceeds the safe record import limit")
        if any(not isinstance(item, dict) for item in parsed):
            raise ValueError("Suricata EVE array must contain event objects")
        records = parsed
    else:
        for line in io.StringIO(content):
            if not line.strip():
                continue
            if len(records) >= _MAX_SURICATA_RECORDS:
                raise ValueError("Suricata EVE exceeds the safe record import limit")
            try:
                item = json.loads(line)
            except (json.JSONDecodeError, RecursionError) as error:
                raise ValueError("Suricata EVE JSONL contains a malformed line") from error
            if not isinstance(item, dict):
                raise ValueError("Suricata EVE JSONL must contain event objects")
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


def _dns_events_from_packet(timestamp: float, packet: bytes, *, identity=None) -> list[DNSEvent]:
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

    reply = bool(dns.qr)
    client_ip = _ip_text(ip_packet.dst if reply else ip_packet.src)
    resolver_ip = _ip_text(ip_packet.src if reply else ip_packet.dst)
    if identity is not None:
        identity.extend((reply, client_ip, transport.dport if reply else transport.sport,
                         resolver_ip, transport.sport if reply else transport.dport, dns.id))
    timestamp_value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    events: list[DNSEvent] = []

    questions = list(getattr(dns, "qd", ()) or ())
    answers = list(getattr(dns, "an", ()) or ())
    if len(questions) > 1024 or len(answers) > 1024:
        raise _TelemetryResourceLimitError("DNS packet exceeds the safe question/answer limit")
    addresses = []
    for answer in answers:
        answer_type = getattr(answer, "type", None)
        rdata = getattr(answer, "rdata", b"")
        if answer_type in {dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA}:
            address = _ip_text(rdata)
            if address:
                addresses.append(address)
    addresses = parse_response_ips(addresses)

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
                response_ip=addresses[0] if reply and addresses else None,
                response_ips=addresses[1:] if reply else (),
                response_code=str(dns.rcode) if reply else None,
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

    if reader.datalink() != dpkt.pcap.DLT_EN10MB:
        raise ValueError("Only Ethernet packet captures are supported for DNS import")

    events: list[DNSEvent] = []
    pending = {}
    queries = paired = response_only = 0
    packet_count = 0
    pair_checks = 0
    try:
        for timestamp, packet in reader:
            packet_count += 1
            if packet_count > _MAX_PCAP_PACKETS:
                raise _TelemetryResourceLimitError(
                    "packet capture exceeds the safe packet import limit"
                )
            identity = []
            observed = _dns_events_from_packet(float(timestamp), packet, identity=identity)
            for event in observed:
                reply = identity[0]
                key = (*identity[1:], normalize_domain_name(event.query_name), event.query_type)
                if reply:
                    candidates = pending.get(key, [])
                    # Most recent preceding query, same endpoints/ports/ID/name,
                    # within two minutes. Never join different clients or reuse
                    # an old transaction ID without a bounded timing match.
                    index = None
                    position = None
                    for position in range(len(candidates) - 1, -1, -1):
                        pair_checks += 1
                        if pair_checks > _MAX_PCAP_PAIR_CHECKS:
                            raise _TelemetryResourceLimitError("DNS transaction pairing exceeds the safe work limit")
                        candidate = candidates[position]
                        if 0 <= (event.timestamp - events[candidate].timestamp).total_seconds() <= 120:
                            index = candidate
                            break
                    if index is not None:
                        query = events[index]
                        query.response_ip = event.response_ip
                        query.response_ips = event.response_ips
                        query.response_code = event.response_code
                        candidates.pop(position)
                        paired += 1
                        continue
                    response_only += 1
                else:
                    queries += 1
                    pending.setdefault(key, []).append(len(events))
                events.append(event)
            if len(events) > _MAX_PCAP_DNS_EVENTS:
                raise _TelemetryResourceLimitError(
                    "packet capture exceeds the safe DNS event import limit"
                )
    except _TelemetryResourceLimitError:
        raise
    except (ValueError, OverflowError, OSError, dpkt.UnpackError) as error:
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
            packet_dns_queries=queries,
            packet_paired_queries=paired,
            packet_response_only=response_only,
        ),
    )


def parse_dnstop_with_diagnostics(content: str) -> DNSParseResult:
    """Parse a conservative dnstop-style domain/count text export."""
    if content is None or not content.strip():
        return _empty_result()

    events: list[DNSEvent] = []
    total = 0
    for raw_line in io.StringIO(content):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if total >= _MAX_DNSTOP_ROWS:
            raise ValueError("dnstop text exceeds the safe row import limit")
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
            try:
                normalized = normalize_domain_name(candidate, strict=True)
            except ValueError:
                continue
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
