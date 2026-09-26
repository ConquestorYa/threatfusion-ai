from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .dns import DNSParseResult, parse_dns_csv_with_diagnostics
from .dns_adguard import parse_adguard_query_log_with_diagnostics
from .dns_pihole import parse_pihole_query_db_with_diagnostics
from .dns_zeek import parse_zeek_dns_log_with_diagnostics


@dataclass(frozen=True)
class DNSInputDetection:
    format_name: str
    detail: str
    encoding: str | None = None


def _decode_text(content: bytes) -> tuple[str, str]:
    if not isinstance(content, bytes) or not content:
        raise ValueError("DNS telemetry upload is empty")

    candidates: list[str] = []
    if content.startswith(b"\xef\xbb\xbf"):
        candidates.append("utf-8-sig")
    elif content.startswith(
        (
            b"\xff\xfe\x00\x00",
            b"\x00\x00\xfe\xff",
        )
    ):
        candidates.append("utf-32")
    elif content.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append("utf-16")

    if not candidates:
        sample = content[:4096]
        even_nulls = sample[0::2].count(0)
        odd_nulls = sample[1::2].count(0)
        pairs = max(1, len(sample) // 2)
        if odd_nulls / pairs > 0.25 and even_nulls / pairs < 0.05:
            candidates.append("utf-16-le")
        elif even_nulls / pairs > 0.25 and odd_nulls / pairs < 0.05:
            candidates.append("utf-16-be")

    for encoding in (
        "utf-8-sig",
        "utf-8",
        "cp1254",
        "cp1252",
        "latin-1",
    ):
        if encoding not in candidates:
            candidates.append(encoding)

    for encoding in candidates:
        try:
            text = content.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
        if "\x00" in text[:2000] and encoding not in {
            "utf-16",
            "utf-16-le",
            "utf-16-be",
            "utf-32",
        }:
            continue
        return text, encoding

    raise ValueError("text encoding could not be detected")


def _looks_like_excel(content: bytes, filename: str | None) -> bool:
    suffix = Path(filename or "").suffix.casefold()
    if suffix in {".xlsx", ".xlsm", ".xltx", ".xltm", ".xls"}:
        return True

    if content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return True

    if not content.startswith(b"PK"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return False
    return "[Content_Types].xml" in names and any(
        name.startswith("xl/") for name in names
    )


def _parse_excel(content: bytes) -> tuple[DNSParseResult, DNSInputDetection]:
    try:
        workbook = pd.ExcelFile(io.BytesIO(content))
    except (ImportError, OSError, ValueError) as error:
        raise ValueError("Excel DNS telemetry could not be opened") from error

    best: tuple[int, DNSParseResult, str] | None = None
    errors: list[str] = []

    for sheet_name in workbook.sheet_names:
        try:
            frame = pd.read_excel(
                workbook,
                sheet_name=sheet_name,
                dtype=object,
            )
        except (ImportError, OSError, ValueError) as error:
            errors.append(f"{sheet_name}: {type(error).__name__}")
            continue

        if frame.empty and not len(frame.columns):
            continue

        frame = frame.where(pd.notna(frame), None)
        text = frame.to_csv(index=False)
        try:
            parsed = parse_dns_csv_with_diagnostics(text)
        except ValueError as error:
            errors.append(f"{sheet_name}: {error}")
            continue

        score = parsed.diagnostics.accepted_rows
        if best is None or score > best[0]:
            best = (score, parsed, sheet_name)

    if best is None:
        detail = "; ".join(errors[:3])
        if detail:
            raise ValueError(
                "Excel workbook has no worksheet with a recognizable DNS "
                f"query/domain column ({detail})"
            )
        raise ValueError(
            "Excel workbook has no worksheet with a recognizable DNS "
            "query/domain column"
        )

    _, parsed, sheet_name = best
    return parsed, DNSInputDetection(
        format_name="Excel DNS table",
        detail=f"worksheet: {sheet_name}",
    )


def _looks_like_zeek(text: str) -> bool:
    header = "\n".join(text.splitlines()[:40])
    return (
        "#fields" in header
        and "query" in header
        and (
            "#separator" in header
            or "\t" in header
            or " id.orig_h " in header
        )
    )


def _looks_like_adguard(text: str, filename: str | None) -> bool:
    suffix = Path(filename or "").suffix.casefold()
    stripped = text.lstrip()
    if suffix == ".json" and stripped.startswith(("{", "[")):
        return True
    if not stripped.startswith(("{", "[")):
        return False

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        first_line = next(
            (line for line in text.splitlines() if line.strip()),
            "",
        )
        try:
            parsed = json.loads(first_line)
        except json.JSONDecodeError:
            return False

    if isinstance(parsed, dict):
        keys = {str(key) for key in parsed}
        return bool({"QH", "question", "data", "T", "IP"} & keys)
    if isinstance(parsed, list) and parsed:
        first = parsed[0]
        return isinstance(first, dict) and bool(
            {"QH", "question", "T", "IP"} & {str(key) for key in first}
        )
    return False


def parse_dns_upload_with_diagnostics(
    content: bytes,
    filename: str | None = None,
) -> tuple[DNSParseResult, DNSInputDetection]:
    """Auto-detect and parse supported DNS telemetry without networking."""
    if not isinstance(content, bytes) or not content:
        raise ValueError("DNS telemetry upload is empty")

    if content.startswith(b"SQLite format 3\x00"):
        parsed = parse_pihole_query_db_with_diagnostics(content)
        return parsed, DNSInputDetection(
            format_name="Pi-hole FTL database",
            detail="SQLite signature detected",
        )

    if _looks_like_excel(content, filename):
        return _parse_excel(content)

    text, encoding = _decode_text(content)

    if _looks_like_zeek(text):
        parsed = parse_zeek_dns_log_with_diagnostics(text)
        return parsed, DNSInputDetection(
            format_name="Zeek dns.log",
            detail="Zeek #fields header detected",
            encoding=encoding,
        )

    if _looks_like_adguard(text, filename):
        parsed = parse_adguard_query_log_with_diagnostics(text)
        return parsed, DNSInputDetection(
            format_name="AdGuard Home query log",
            detail="JSON query-log structure detected",
            encoding=encoding,
        )

    parsed = parse_dns_csv_with_diagnostics(text)
    return parsed, DNSInputDetection(
        format_name="Delimited DNS table",
        detail="delimiter and DNS columns detected automatically",
        encoding=encoding,
    )
