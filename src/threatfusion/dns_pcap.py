from __future__ import annotations

import io
import ipaddress
import socket
from datetime import datetime, timezone

import dpkt

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult

_MAX_CAPTURE_PACKETS = 2_000_000
_MAX_CAPTURE_DNS_EVENTS = 100_000

_QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _reader(content: bytes):
    stream = io.BytesIO(content)
    if content.startswith(b"\x0a\x0d\x0d\x0a"):
        try:
            return dpkt.pcapng.Reader(stream)
        except (ValueError, dpkt.dpkt.NeedData) as error:
            raise ValueError("PCAPNG capture could not be opened") from error

    try:
        return dpkt.pcap.Reader(stream)
    except (ValueError, dpkt.dpkt.NeedData) as pcap_error:
        stream.seek(0)
        try:
            return dpkt.pcapng.Reader(stream)
        except (ValueError, dpkt.dpkt.NeedData) as error:
            raise ValueError("packet capture could not be opened") from error


def _network_packet(buf: bytes, linktype: int):
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            return dpkt.ethernet.Ethernet(buf).data
        if linktype == dpkt.pcap.DLT_LINUX_SLL:
            return dpkt.sll.SLL(buf).data
        if linktype in {dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP}:
            return dpkt.loopback.Loopback(buf).data
        if linktype in {
            dpkt.pcap.DLT_RAW,
            getattr(dpkt.pcap, "DLT_IPV4", 228),
            getattr(dpkt.pcap, "DLT_IPV6", 229),
        }:
            if not buf:
                return None
            version = buf[0] >> 4
            if version == 4:
                return dpkt.ip.IP(buf)
            if version == 6:
                return dpkt.ip6.IP6(buf)
            return None
    except (ValueError, dpkt.dpkt.Error):
        return None
    return None


def _ip_text(value: bytes) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _dns_payload(ip):
    transport = getattr(ip, "data", None)
    if isinstance(transport, dpkt.udp.UDP):
        if transport.sport != 53 and transport.dport != 53:
            return None
        return transport, bytes(transport.data), "udp"
    if isinstance(transport, dpkt.tcp.TCP):
        if transport.sport != 53 and transport.dport != 53:
            return None
        raw = bytes(transport.data)
        if len(raw) < 2:
            return None
        declared = int.from_bytes(raw[:2], "big")
        if declared <= 0 or len(raw) < declared + 2:
            return None
        return transport, raw[2 : declared + 2], "tcp"
    return None


def _first_answer_ip(dns: dpkt.dns.DNS) -> str | None:
    for answer in getattr(dns, "an", ()) or ():
        try:
            if answer.type == dpkt.dns.DNS_A:
                return socket.inet_ntop(socket.AF_INET, answer.rdata)
            if answer.type == dpkt.dns.DNS_AAAA:
                return socket.inet_ntop(socket.AF_INET6, answer.rdata)
        except (OSError, ValueError):
            continue
    return None


def _question_name(question) -> str | None:
    value = getattr(question, "name", None)
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _question_type(question) -> str | None:
    value = getattr(question, "type", None)
    if not isinstance(value, int):
        return None
    return _QTYPE_NAMES.get(value, str(value))


def parse_pcap_dns_with_diagnostics(content: bytes) -> DNSParseResult:
    """Extract DNS query/response evidence from a PCAP or PCAPNG capture."""
    if not isinstance(content, bytes) or not content:
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    capture = _reader(content)
    linktype = capture.datalink()
    events: list[DNSEvent] = []
    pending: dict[tuple[object, ...], list[int]] = {}
    dns_messages = 0
    skipped_missing_query_name = 0
    invalid_timestamps = 0
    invalid_response_ips = 0
    packet_count = 0

    for timestamp, buf in capture:
        packet_count += 1
        if packet_count > _MAX_CAPTURE_PACKETS:
            raise ValueError(
                "packet capture exceeds the 2,000,000 packet analysis limit"
            )

        ip = _network_packet(buf, linktype)
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            continue
        payload_info = _dns_payload(ip)
        if payload_info is None:
            continue

        transport, payload, protocol = payload_info
        try:
            dns = dpkt.dns.DNS(payload)
        except (ValueError, dpkt.dpkt.Error):
            continue

        dns_messages += 1
        src_ip = _ip_text(ip.src)
        dst_ip = _ip_text(ip.dst)
        if src_ip is None or dst_ip is None:
            invalid_response_ips += 1
            continue

        try:
            observed_at = datetime.fromtimestamp(
                float(timestamp),
                tz=timezone.utc,
            )
        except (OverflowError, OSError, ValueError, TypeError):
            observed_at = None
            invalid_timestamps += 1

        questions = list(getattr(dns, "qd", ()) or ())
        if not questions:
            skipped_missing_query_name += 1
            continue

        is_response = bool(getattr(dns, "qr", 0))
        if not is_response:
            indices: list[int] = []
            for question in questions:
                query_name = _question_name(question)
                if query_name is None:
                    skipped_missing_query_name += 1
                    continue
                if len(events) >= _MAX_CAPTURE_DNS_EVENTS:
                    raise ValueError(
                        "packet capture exceeds the 100,000 DNS event analysis limit"
                    )
                events.append(
                    DNSEvent(
                        query_name=query_name,
                        timestamp=observed_at,
                        client_ip=src_ip,
                        query_type=_question_type(question),
                    )
                )
                indices.append(len(events) - 1)
            if indices:
                key = (
                    protocol,
                    int(getattr(dns, "id", 0)),
                    src_ip,
                    dst_ip,
                    int(transport.sport),
                    int(transport.dport),
                )
                pending[key] = indices
            continue

        response_ip = _first_answer_ip(dns)
        response_code = _RCODE_NAMES.get(
            int(getattr(dns, "rcode", 0)),
            str(int(getattr(dns, "rcode", 0))),
        )
        key = (
            protocol,
            int(getattr(dns, "id", 0)),
            dst_ip,
            src_ip,
            int(transport.dport),
            int(transport.sport),
        )
        pending_indices = pending.pop(key, [])
        if pending_indices:
            for index in pending_indices:
                events[index].response_ip = response_ip
                events[index].response_code = response_code
            continue

        for question in questions:
            query_name = _question_name(question)
            if query_name is None:
                skipped_missing_query_name += 1
                continue
            if len(events) >= _MAX_CAPTURE_DNS_EVENTS:
                raise ValueError(
                    "packet capture exceeds the 100,000 DNS event analysis limit"
                )
            events.append(
                DNSEvent(
                    query_name=query_name,
                    timestamp=observed_at,
                    client_ip=dst_ip,
                    query_type=_question_type(question),
                    response_ip=response_ip,
                    response_code=response_code,
                )
            )

    if dns_messages == 0:
        raise ValueError(
            "packet capture contains no readable DNS traffic on TCP/UDP port 53"
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=dns_messages,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_query_name,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=invalid_response_ips,
        ),
    )
