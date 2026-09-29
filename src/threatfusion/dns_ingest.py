from __future__ import annotations

import csv
import io
import posixpath
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

import pandas as pd

from .dns import DNSParseResult, parse_dns_csv_with_diagnostics
from .dns_adguard import parse_adguard_query_log_with_diagnostics
from .dns_pihole import parse_pihole_query_db_with_diagnostics
from .dns_zeek import parse_zeek_dns_log_with_diagnostics
from .network_telemetry import (
    parse_dnstop_with_diagnostics,
    parse_pcap_dns_with_diagnostics,
    parse_suricata_eve_with_diagnostics,
    parse_zeek_conn_log_with_diagnostics,
)

_XLSX_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_XLSX_DOC_REL_NS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)
_XLSX_PACKAGE_REL_NS = (
    "http://schemas.openxmlformats.org/package/2006/relationships"
)
_MAX_XLSX_ROWS = 100_001
_MAX_XLSX_CELLS = 1_000_000
_MAX_XLSX_COLUMNS = 16_384
_MAX_XLSX_XML_BYTES = 128 * 1024 * 1024
_MAX_XLSX_ARCHIVE_BYTES = 128 * 1024 * 1024
_MAX_XLSX_COMPRESSION_RATIO = 200
_DETECTION_PROBE_CHARS = 64 * 1024


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


def _is_xlsx_package(content: bytes) -> bool:
    if not content.startswith(b"PK"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return False
    return (
        "[Content_Types].xml" in names
        and "xl/workbook.xml" in names
        and "xl/_rels/workbook.xml.rels" in names
        and any(name.startswith("xl/worksheets/") for name in names)
    )


def _looks_like_excel(content: bytes, filename: str | None) -> bool:
    suffix = Path(filename or "").suffix.casefold()
    if suffix in {".xlsx", ".xlsm", ".xltx", ".xltm", ".xls"}:
        return True

    if content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return True

    return _is_xlsx_package(content)


def _sheet_to_dns_result(
    text: str,
    sheet_name: str,
) -> tuple[int, DNSParseResult, str] | None:
    try:
        parsed = parse_dns_csv_with_diagnostics(text)
    except ValueError:
        return None
    return parsed.diagnostics.accepted_rows, parsed, sheet_name


def _parse_excel_with_pandas(
    content: bytes,
) -> tuple[DNSParseResult, DNSInputDetection]:
    workbook = pd.ExcelFile(io.BytesIO(content))

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
        candidate = _sheet_to_dns_result(frame.to_csv(index=False), sheet_name)
        if candidate is None:
            errors.append(
                f"{sheet_name}: no recognizable DNS query/domain column"
            )
            continue
        if best is None or candidate[0] > best[0]:
            best = candidate

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


def _xlsx_xml_bytes(
    archive: zipfile.ZipFile,
    name: str,
) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise ValueError(f"XLSX package is missing {name}") from error
    if info.file_size > _MAX_XLSX_XML_BYTES:
        raise ValueError("XLSX worksheet XML exceeds the safe import limit")
    return archive.read(info)


def _xlsx_sheet_paths(
    archive: zipfile.ZipFile,
) -> list[tuple[str, str]]:
    workbook_root = ElementTree.fromstring(
        _xlsx_xml_bytes(archive, "xl/workbook.xml")
    )
    rels_root = ElementTree.fromstring(
        _xlsx_xml_bytes(archive, "xl/_rels/workbook.xml.rels")
    )

    relationships = {
        relation.attrib.get("Id", ""): relation.attrib.get("Target", "")
        for relation in rels_root.findall(
            f"{{{_XLSX_PACKAGE_REL_NS}}}Relationship"
        )
    }

    sheets: list[tuple[str, str]] = []
    for sheet in workbook_root.findall(
        f".//{{{_XLSX_MAIN_NS}}}sheet"
    ):
        name = sheet.attrib.get("name", "").strip() or "Sheet"
        relationship_id = sheet.attrib.get(
            f"{{{_XLSX_DOC_REL_NS}}}id",
            "",
        )
        target = relationships.get(relationship_id, "")
        if not target:
            continue

        if target.startswith("/"):
            sheet_path = target.lstrip("/")
        else:
            sheet_path = posixpath.normpath(
                posixpath.join("xl", target)
            )
        if not sheet_path.startswith("xl/worksheets/"):
            continue
        sheets.append((name, sheet_path))

    if not sheets:
        raise ValueError("XLSX workbook contains no readable worksheets")
    return sheets


def _xlsx_shared_strings(
    archive: zipfile.ZipFile,
) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []

    root = ElementTree.fromstring(
        _xlsx_xml_bytes(archive, "xl/sharedStrings.xml")
    )
    values: list[str] = []
    for item in root.findall(f"{{{_XLSX_MAIN_NS}}}si"):
        values.append(
            "".join(
                node.text or ""
                for node in item.iter(f"{{{_XLSX_MAIN_NS}}}t")
            )
        )
    return values


def _xlsx_column_index(cell_reference: str) -> int:
    match = re.fullmatch(r"([A-Za-z]{1,3})[1-9][0-9]*", cell_reference)
    if match is None:
        raise ValueError("XLSX cell reference is invalid")

    index = 0
    for character in match.group(1).upper():
        index = index * 26 + (ord(character) - ord("A") + 1)
    if index > _MAX_XLSX_COLUMNS:
        raise ValueError("XLSX column exceeds the safe import limit")
    return index - 1


def _xlsx_cell_text(
    cell: ElementTree.Element,
    shared_strings: list[str],
) -> str:
    cell_type = cell.attrib.get("t", "")

    if cell_type == "inlineStr":
        return "".join(
            node.text or ""
            for node in cell.iter(f"{{{_XLSX_MAIN_NS}}}t")
        )

    value = cell.find(f"{{{_XLSX_MAIN_NS}}}v")
    raw = value.text if value is not None and value.text is not None else ""

    if cell_type == "s":
        try:
            return shared_strings[int(raw)]
        except (IndexError, ValueError) as error:
            raise ValueError("XLSX shared-string reference is invalid") from error
    if cell_type == "b":
        return "TRUE" if raw == "1" else "FALSE"
    return raw


def _xlsx_sheet_csv(
    archive: zipfile.ZipFile,
    sheet_path: str,
    shared_strings: list[str],
) -> str:
    try:
        info = archive.getinfo(sheet_path)
    except KeyError as error:
        raise ValueError("XLSX worksheet relationship is invalid") from error
    if info.file_size > _MAX_XLSX_XML_BYTES:
        raise ValueError("XLSX worksheet XML exceeds the safe import limit")

    rows: list[list[str]] = []
    cell_count = 0
    expanded_cells = 0

    with archive.open(info) as stream:
        try:
            iterator = ElementTree.iterparse(stream, events=("end",))
            for _, element in iterator:
                if element.tag != f"{{{_XLSX_MAIN_NS}}}row":
                    continue

                row_values: dict[int, str] = {}
                max_column = -1
                for cell in element.findall(f"{{{_XLSX_MAIN_NS}}}c"):
                    reference = cell.attrib.get("r", "")
                    column_index = _xlsx_column_index(reference)
                    row_values[column_index] = _xlsx_cell_text(
                        cell,
                        shared_strings,
                    )
                    max_column = max(max_column, column_index)
                    cell_count += 1
                    if cell_count > _MAX_XLSX_CELLS:
                        raise ValueError(
                            "XLSX input exceeds the safe cell import limit"
                        )

                if max_column >= 0:
                    expanded_cells += max_column + 1
                    if expanded_cells > _MAX_XLSX_CELLS:
                        raise ValueError(
                            "XLSX input exceeds the safe cell import limit"
                        )
                    row = [""] * (max_column + 1)
                    for column_index, value in row_values.items():
                        row[column_index] = value
                    if any(value.strip() for value in row):
                        rows.append(row)
                        if len(rows) > _MAX_XLSX_ROWS:
                            raise ValueError(
                                "XLSX input exceeds the safe row import limit"
                            )
                element.clear()
        except ElementTree.ParseError as error:
            raise ValueError("XLSX worksheet XML is malformed") from error

    if not rows:
        return ""

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerows(rows)
    return output.getvalue()


def _parse_xlsx_without_engine(
    content: bytes,
) -> tuple[DNSParseResult, DNSInputDetection]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as error:
        raise ValueError("uploaded file is not a readable XLSX workbook") from error

    with archive:
        sheets = _xlsx_sheet_paths(archive)
        shared_strings = _xlsx_shared_strings(archive)
        best: tuple[int, DNSParseResult, str] | None = None
        errors: list[str] = []

        for sheet_name, sheet_path in sheets:
            try:
                text = _xlsx_sheet_csv(
                    archive,
                    sheet_path,
                    shared_strings,
                )
                if not text.strip():
                    continue
                candidate = _sheet_to_dns_result(text, sheet_name)
            except ValueError as error:
                errors.append(f"{sheet_name}: {error}")
                continue

            if candidate is None:
                errors.append(
                    f"{sheet_name}: no recognizable DNS query/domain column"
                )
                continue
            if best is None or candidate[0] > best[0]:
                best = candidate

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


def _validate_xlsx_archive(content: bytes) -> None:
    """Bound ZIP expansion before either Excel reader touches XML content."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        total_bytes = 0
        for info in archive.infolist():
            if info.file_size > _MAX_XLSX_XML_BYTES:
                raise ValueError("XLSX member exceeds the safe import limit")
            total_bytes += info.file_size
            if total_bytes > _MAX_XLSX_ARCHIVE_BYTES:
                raise ValueError("XLSX archive exceeds the safe import limit")
            if (
                info.file_size
                > max(info.compress_size, 1) * _MAX_XLSX_COMPRESSION_RATIO
            ):
                raise ValueError("XLSX archive compression ratio is unsafe")


def _validate_excel_dimensions(
    rows: int,
    columns: int,
    *,
    workbook_cells: int,
    format_name: str,
) -> int:
    if rows > _MAX_XLSX_ROWS:
        raise ValueError(f"{format_name} input exceeds the safe row import limit")
    if columns > _MAX_XLSX_COLUMNS:
        raise ValueError(f"{format_name} input exceeds the safe column import limit")
    cells = rows * columns
    if cells > _MAX_XLSX_CELLS:
        raise ValueError(f"{format_name} input exceeds the safe cell import limit")
    workbook_cells += cells
    if workbook_cells > _MAX_XLSX_CELLS:
        raise ValueError(
            f"{format_name} input exceeds the safe workbook cell import limit"
        )
    return workbook_cells


def _preflight_xlsx_dimensions(content: bytes) -> None:
    """Check each sheet's expanded rectangle before pandas allocates it."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        workbook_cells = 0
        for _, sheet_path in _xlsx_sheet_paths(archive):
            max_row = 0
            max_column = 0
            last_row = 0
            with archive.open(sheet_path) as stream:
                try:
                    for event, element in ElementTree.iterparse(
                        stream, events=("start", "end")
                    ):
                        if (
                            event == "start"
                            and element.tag == f"{{{_XLSX_MAIN_NS}}}dimension"
                        ):
                            reference = element.attrib.get("ref", "")
                            match = re.fullmatch(
                                r"(?:[A-Za-z]{1,3}[1-9][0-9]*:)?"
                                r"([A-Za-z]{1,3})([1-9][0-9]*)",
                                reference,
                            )
                            if match is None:
                                raise ValueError("XLSX sheet dimension is invalid")
                            declared_column = _xlsx_column_index(
                                match.group(1) + match.group(2)
                            ) + 1
                            declared_row = int(match.group(2))
                            _validate_excel_dimensions(
                                declared_row,
                                declared_column,
                                workbook_cells=0,
                                format_name="XLSX",
                            )
                            max_row = max(max_row, declared_row)
                            max_column = max(max_column, declared_column)
                            continue
                        if event != "end":
                            continue
                        if element.tag != f"{{{_XLSX_MAIN_NS}}}row":
                            continue
                        raw_row = element.attrib.get("r", "")
                        if raw_row:
                            try:
                                row_number = int(raw_row)
                            except ValueError as error:
                                raise ValueError(
                                    "XLSX row reference is invalid"
                                ) from error
                        else:
                            row_number = last_row + 1
                        if row_number < 1:
                            raise ValueError("XLSX row reference is invalid")
                        last_row = row_number
                        max_row = max(max_row, row_number)
                        if max_row > _MAX_XLSX_ROWS:
                            raise ValueError(
                                "XLSX input exceeds the safe row import limit"
                            )
                        column_number = 0
                        for cell in element.findall(f"{{{_XLSX_MAIN_NS}}}c"):
                            reference = cell.attrib.get("r")
                            column_number = (
                                _xlsx_column_index(reference) + 1
                                if reference
                                else column_number + 1
                            )
                            max_column = max(max_column, column_number)
                        if max_column > _MAX_XLSX_COLUMNS:
                            raise ValueError(
                                "XLSX input exceeds the safe column import limit"
                            )
                        if max_row * max_column > _MAX_XLSX_CELLS:
                            raise ValueError(
                                "XLSX input exceeds the safe cell import limit"
                            )
                        element.clear()
                except ElementTree.ParseError as error:
                    raise ValueError("XLSX worksheet XML is malformed") from error
            workbook_cells = _validate_excel_dimensions(
                max_row,
                max_column,
                workbook_cells=workbook_cells,
                format_name="XLSX",
            )


def _preflight_xls_dimensions(content: bytes) -> None:
    """Read legacy sheet dimensions without materializing pandas frames."""
    try:
        import xlrd
    except ImportError:
        return  # The existing pandas path reports the missing Excel engine.

    try:
        workbook = xlrd.open_workbook(file_contents=content, on_demand=True)
    except xlrd.XLRDError as error:
        raise ValueError("XLS workbook could not be opened") from error
    try:
        workbook_cells = 0
        for index in range(workbook.nsheets):
            sheet = workbook.sheet_by_index(index)
            workbook_cells = _validate_excel_dimensions(
                sheet.nrows,
                sheet.ncols,
                workbook_cells=workbook_cells,
                format_name="XLS",
            )
            workbook.unload_sheet(index)
    finally:
        workbook.release_resources()


def _parse_excel(
    content: bytes,
    filename: str | None = None,
) -> tuple[DNSParseResult, DNSInputDetection]:
    # Check all ZIP containers, including renamed files and prefixed ZIPs.
    # Keep this outside the fallback try: safety failures must be terminal.
    if zipfile.is_zipfile(io.BytesIO(content)):
        _validate_xlsx_archive(content)
        if _is_xlsx_package(content):
            _preflight_xlsx_dimensions(content)
    elif content.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        _preflight_xls_dimensions(content)

    pandas_error: Exception | None = None
    try:
        return _parse_excel_with_pandas(content)
    except (ImportError, OSError, ValueError) as error:
        pandas_error = error

    if _is_xlsx_package(content):
        try:
            return _parse_xlsx_without_engine(content)
        except ValueError as fallback_error:
            raise ValueError(
                "Excel DNS telemetry could not be opened: "
                f"{fallback_error}"
            ) from fallback_error

    suffix = Path(filename or "").suffix.casefold()
    if suffix in {".xlsx", ".xlsm", ".xltx", ".xltm"}:
        raise ValueError(
            "Excel DNS telemetry could not be opened because the uploaded "
            "file is not a readable XLSX package"
        ) from pandas_error

    error_name = type(pandas_error).__name__ if pandas_error is not None else "Error"
    raise ValueError(
        "Legacy Excel DNS telemetry could not be opened "
        f"({error_name}). Reinstall the project requirements to enable .xls support."
    ) from pandas_error


def _detection_probe(text: str, *, max_lines: int = 40) -> str:
    """Return a bounded prefix for format detection without copying the file."""
    prefix = text[:_DETECTION_PROBE_CHARS]
    return "\n".join(prefix.splitlines()[:max_lines])


def _looks_like_zeek_conn(text: str) -> bool:
    header = _detection_probe(text)
    return (
        "#fields" in header
        and "id.orig_h" in header
        and "id.resp_h" in header
        and "#path" in header
        and "conn" in header
    )


def _looks_like_suricata_eve(text: str, filename: str | None) -> bool:
    name = Path(filename or "").name.casefold()
    if name in {"eve.json", "eve.jsonl"} or "suricata" in name:
        return True
    sample = next(
        (line.strip() for line in _detection_probe(text).splitlines() if line.strip()),
        "",
    )
    if not sample.startswith(("{", "[")):
        return False
    return '"event_type"' in sample and (
        '"dns"' in sample
        or '"src_ip"' in sample
        or '"dest_ip"' in sample
    )


def _looks_like_zeek(text: str) -> bool:
    header = _detection_probe(text)
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
    probe = _detection_probe(text).lstrip()
    if suffix == ".json" and probe.startswith(("{", "[")):
        return True
    if not probe.startswith(("{", "[")):
        return False

    # Detection must stay bounded: parsing an entire attacker-controlled JSON
    # document here would duplicate the work and memory of the real parser.
    markers = ('"QH"', '"question"', '"data"', '"T"', '"IP"')
    return any(marker in probe for marker in markers)


def parse_dns_upload_with_diagnostics(
    content: bytes,
    filename: str | None = None,
) -> tuple[DNSParseResult, DNSInputDetection]:
    """Auto-detect and parse supported DNS telemetry without networking."""
    if not isinstance(content, bytes) or not content:
        raise ValueError("DNS telemetry upload is empty")

    suffix = Path(filename or "").suffix.casefold()
    lowered_name = Path(filename or "").name.casefold()

    if suffix == ".capinfos" or lowered_name.endswith(".capinfos"):
        raise ValueError(
            "capinfos is capture metadata only; upload the original .pcap or "
            ".pcapng file for traffic analysis"
        )

    if suffix in {".pcap", ".pcapng", ".cap"}:
        parsed = parse_pcap_dns_with_diagnostics(content)
        return parsed, DNSInputDetection(
            format_name="PCAP/PCAPNG DNS capture",
            detail="classic UDP DNS packets extracted locally",
        )

    if content.startswith(b"SQLite format 3\x00"):
        parsed = parse_pihole_query_db_with_diagnostics(content)
        return parsed, DNSInputDetection(
            format_name="Pi-hole FTL database",
            detail="SQLite signature detected",
        )

    if _looks_like_excel(content, filename):
        return _parse_excel(content, filename)

    text, encoding = _decode_text(content)

    if _looks_like_zeek_conn(text):
        parsed = parse_zeek_conn_log_with_diagnostics(text)
        return parsed, DNSInputDetection(
            format_name="Zeek conn.log",
            detail="destination-IP telemetry; domain ML is skipped for IP targets",
            encoding=encoding,
        )

    if _looks_like_zeek(text):
        parsed = parse_zeek_dns_log_with_diagnostics(text)
        return parsed, DNSInputDetection(
            format_name="Zeek dns.log",
            detail="Zeek #fields header detected",
            encoding=encoding,
        )

    if _looks_like_suricata_eve(text, filename):
        parsed = parse_suricata_eve_with_diagnostics(text)
        return parsed, DNSInputDetection(
            format_name="Suricata EVE JSON",
            detail="DNS records preferred; destination-IP telemetry used as fallback",
            encoding=encoding,
        )

    if suffix == ".dnstop" or lowered_name.endswith(".dnstop"):
        parsed = parse_dnstop_with_diagnostics(text)
        return parsed, DNSInputDetection(
            format_name="dnstop text",
            detail="recognizable domain rows extracted from dnstop output",
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
