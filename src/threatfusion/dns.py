import csv
import io
import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class DNSEvent:
    query_name: str
    timestamp: datetime | None = None
    client_ip: str | None = None
    query_type: str | None = None
    response_ip: str | None = None
    response_code: str | None = None


@dataclass(frozen=True)
class DNSParseDiagnostics:
    total_rows: int
    accepted_rows: int
    skipped_missing_query_name: int
    invalid_timestamps: int
    invalid_response_ips: int


@dataclass(frozen=True)
class DNSParseResult:
    events: tuple[DNSEvent, ...]
    diagnostics: DNSParseDiagnostics


_DNS_QUERY_TYPES = {
    "A",
    "AAAA",
    "AFSDB",
    "ANY",
    "CAA",
    "CNAME",
    "DNAME",
    "DNSKEY",
    "DS",
    "HTTPS",
    "LOC",
    "MX",
    "NAPTR",
    "NS",
    "NSEC",
    "NSEC3",
    "PTR",
    "RRSIG",
    "SOA",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
}

_RESPONSE_CODES = {
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
}

_FIELD_ALIASES = {
    "query_name": {
        "queryname",
        "query",
        "querydomain",
        "domain",
        "domainname",
        "dnsquery",
        "dnsname",
        "qname",
        "hostname",
        "host",
        "requestedomain",
        "questionname",
        "name",
    },
    "timestamp": {
        "timestamp",
        "time",
        "ts",
        "datetime",
        "date",
        "querytime",
        "eventtime",
        "eventtimestamp",
    },
    "client_ip": {
        "clientip",
        "client",
        "srcip",
        "sourceip",
        "source",
        "idorigh",
        "requesterip",
        "remoteaddr",
        "hostip",
    },
    "query_type": {
        "querytype",
        "qtype",
        "qtypename",
        "recordtype",
        "recordclass",
        "type",
        "rrtype",
        "dnsrecordtype",
    },
    "response_ip": {
        "responseip",
        "answerip",
        "resolvedip",
        "destinationip",
        "dstip",
        "replyip",
        "rdata",
        "answer",
        "answers",
    },
    "response_code": {
        "responsecode",
        "rcode",
        "rcodename",
        "status",
        "result",
        "replycode",
    },
}


def _as_optional_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None

    text = str(value).strip()
    return text or None


def _parse_timestamp(value: object) -> datetime | None:
    text = _as_optional_text(value)
    if text is None:
        return None

    candidate = text
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"

    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        pass

    if re.fullmatch(r"\d{9,}(?:\.\d+)?", candidate):
        try:
            return datetime.fromtimestamp(float(candidate), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass

    for date_format in (
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y/%m/%d",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
    ):
        try:
            return datetime.strptime(candidate, date_format)
        except ValueError:
            continue
    return None


def _parse_response_ip(value: object) -> str | None:
    text = _as_optional_text(value)
    if text is None:
        return None

    for candidate in re.split(r"[\s,;|]+", text):
        candidate = candidate.strip("[](){}'\"")
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return str(address)
    return None


def _parse_response_code(value: object) -> str | None:
    text = _as_optional_text(value)
    if text is None:
        return None
    return text.upper()


def _normalize_header(value: object) -> str:
    text = _as_optional_text(value) or ""
    return re.sub(r"[^a-z0-9]+", "", text.casefold())


def _looks_like_dns_name(value: object) -> bool:
    text = _as_optional_text(value)
    if text is None or len(text) > 253 or " " in text:
        return False

    candidate = text.rstrip(".")
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        return False
    if candidate.casefold() == "localhost":
        return True
    if "." not in candidate:
        return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,63}", candidate))
    return bool(
        re.fullmatch(
            r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+"
            r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?",
            candidate,
        )
    )


def _looks_like_query_column_value(value: object) -> bool:
    text = _as_optional_text(value)
    if text is None:
        return False
    candidate = text.rstrip(".")
    return _looks_like_dns_name(candidate) and (
        "." in candidate or candidate.casefold() == "localhost"
    )


def _is_ip(value: object) -> bool:
    text = _as_optional_text(value)
    if text is None:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _sample_ratio(values: list[object], predicate) -> float:
    present = [value for value in values if _as_optional_text(value) is not None]
    if not present:
        return 0.0
    return sum(bool(predicate(value)) for value in present) / len(present)


def _header_score(field: str, canonical: str) -> float:
    normalized = _normalize_header(field)
    canonical_normalized = canonical.replace("_", "")
    if normalized == canonical_normalized:
        return 60.0
    if normalized in _FIELD_ALIASES[canonical]:
        return 35.0
    return 0.0


def _content_score(canonical: str, values: list[object]) -> float:
    if canonical == "query_name":
        return 35.0 * _sample_ratio(values, _looks_like_query_column_value)
    if canonical == "timestamp":
        return 30.0 * _sample_ratio(
            values,
            lambda value: _parse_timestamp(value) is not None,
        )
    if canonical == "client_ip":
        return 45.0 * _sample_ratio(values, _is_ip)
    if canonical == "query_type":
        return 60.0 * _sample_ratio(
            values,
            lambda value: (_as_optional_text(value) or "").upper()
            in _DNS_QUERY_TYPES,
        )
    if canonical == "response_ip":
        return 55.0 * _sample_ratio(
            values,
            lambda value: _parse_response_ip(value) is not None,
        )
    if canonical == "response_code":
        return 45.0 * _sample_ratio(
            values,
            lambda value: (_as_optional_text(value) or "").upper()
            in _RESPONSE_CODES,
        )
    return 0.0


def _infer_field_mapping(
    fieldnames: list[str],
    rows: list[dict[str, object]],
) -> dict[str, str]:
    sample = rows[:200]
    values_by_field = {
        field: [row.get(field) for row in sample]
        for field in fieldnames
    }

    mapping: dict[str, str] = {}
    used: set[str] = set()
    for canonical in (
        "query_name",
        "timestamp",
        "client_ip",
        "query_type",
        "response_ip",
        "response_code",
    ):
        ranked: list[tuple[float, str]] = []
        for field in fieldnames:
            if field in used:
                continue
            score = _header_score(field, canonical)
            score += _content_score(canonical, values_by_field[field])
            if score > 0:
                ranked.append((score, field))

        if not ranked:
            continue
        ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
        score, field = ranked[0]
        minimum = 20.0 if canonical == "query_name" else 25.0
        if score >= minimum:
            mapping[canonical] = field
            used.add(field)

    return mapping


def _detect_delimiter(content: str) -> str:
    sample = "\n".join(content.splitlines()[:50])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return ","
    return dialect.delimiter


def _read_dns_table(
    content: str,
) -> tuple[list[str], list[dict[str, object]], dict[str, str]]:
    delimiter = _detect_delimiter(content)
    reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)
    fieldnames = [field for field in (reader.fieldnames or []) if field is not None]
    rows = [dict(row) for row in reader if row is not None]

    if not fieldnames:
        return [], [], {}

    mapping = _infer_field_mapping(fieldnames, rows)
    if "query_name" in mapping:
        return fieldnames, rows, mapping

    if len(fieldnames) == 1 and _looks_like_dns_name(fieldnames[0]):
        raw_reader = csv.reader(io.StringIO(content), delimiter=delimiter)
        values = [
            row[0]
            for row in raw_reader
            if row and _as_optional_text(row[0]) is not None
        ]
        rows = [{"query_name": value} for value in values]
        return ["query_name"], rows, {"query_name": "query_name"}

    return fieldnames, rows, mapping


def parse_dns_csv_with_diagnostics(content: str) -> DNSParseResult:
    if content is None or not content.strip():
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    fieldnames, rows, mapping = _read_dns_table(content)
    if not fieldnames:
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )
    if "query_name" not in mapping:
        raise ValueError(
            "DNS table does not contain a recognizable query/domain "
            "(query_name) column"
        )

    events: list[DNSEvent] = []
    total_rows = 0
    skipped_missing_query_name = 0
    invalid_timestamps = 0
    invalid_response_ips = 0

    query_name_key = mapping["query_name"]
    timestamp_key = mapping.get("timestamp")
    client_ip_key = mapping.get("client_ip")
    query_type_key = mapping.get("query_type")
    response_ip_key = mapping.get("response_ip")
    response_code_key = mapping.get("response_code")

    for row in rows:
        total_rows += 1
        query_name = _as_optional_text(row.get(query_name_key))
        if query_name is None:
            skipped_missing_query_name += 1
            continue

        timestamp_text = (
            _as_optional_text(row.get(timestamp_key))
            if timestamp_key
            else None
        )
        timestamp = _parse_timestamp(timestamp_text)
        if timestamp_text is not None and timestamp is None:
            invalid_timestamps += 1

        response_ip_text = (
            _as_optional_text(row.get(response_ip_key))
            if response_ip_key
            else None
        )
        response_ip = _parse_response_ip(response_ip_text)
        if response_ip_text is not None and response_ip is None:
            invalid_response_ips += 1

        event = DNSEvent(
            query_name=query_name,
            timestamp=timestamp,
            client_ip=(
                _as_optional_text(row.get(client_ip_key))
                if client_ip_key
                else None
            ),
            query_type=None,
            response_ip=response_ip,
            response_code=(
                _parse_response_code(row.get(response_code_key))
                if response_code_key
                else None
            ),
        )

        if query_type_key:
            query_type = _as_optional_text(row.get(query_type_key))
            if query_type is not None:
                event.query_type = query_type.upper()

        events.append(event)

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total_rows,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_query_name,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=invalid_response_ips,
        ),
    )


def parse_dns_csv(content: str) -> list[DNSEvent]:
    """Parse a delimited DNS table and return accepted DNS events only."""
    return list(parse_dns_csv_with_diagnostics(content).events)
