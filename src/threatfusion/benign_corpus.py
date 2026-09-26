from __future__ import annotations

import codecs
import csv
import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from .ml_dataset import normalize_domain_candidate

CESNET_DATASET_DOI = "10.5281/zenodo.14332167"
CESNET_DATASET_RECORD_URL = "https://zenodo.org/records/14332167"
CESNET_BENIGN_DOWNLOAD_URL = (
    "https://zenodo.org/records/14332167/files/benign_cesnet.json?download=1"
)
CESNET_BENIGN_SOURCE_MD5 = "cea8cbe33ec308f76c5ecf3ef6a6219e"
CESNET_DATASET_LICENSE = "CC BY 4.0"


@dataclass(frozen=True)
class BenignCorpusSampleMetadata:
    source_name: str
    source_doi: str
    source_record_url: str
    source_file: str
    source_file_md5: str
    source_license: str
    requested_unique_domains: int
    retained_unique_domains: int
    invalid_or_missing_domains: int
    duplicate_domains: int
    downloaded_bytes: int
    output_sha256: str


def iter_json_array_objects(chunks: Iterable[bytes]) -> Iterator[dict[str, object]]:
    """Incrementally decode a top-level JSON array without loading it in memory."""
    utf8_decoder = codecs.getincrementaldecoder("utf-8")()
    json_decoder = json.JSONDecoder()
    buffer = ""
    position = 0
    started = False
    finished = False

    chunk_list = iter(chunks)
    while True:
        try:
            chunk = next(chunk_list)
            final = False
        except StopIteration:
            chunk = b""
            final = True

        if not isinstance(chunk, bytes):
            raise TypeError("JSON stream chunks must be bytes")
        buffer += utf8_decoder.decode(chunk, final=final)

        while True:
            while position < len(buffer) and buffer[position].isspace():
                position += 1

            if not started:
                if position >= len(buffer):
                    break
                if buffer[position] != "[":
                    raise ValueError("CESNET source must be a top-level JSON array")
                started = True
                position += 1
                continue

            while position < len(buffer) and buffer[position].isspace():
                position += 1

            if position >= len(buffer):
                break
            if buffer[position] == "]":
                finished = True
                position += 1
                break
            if buffer[position] == ",":
                position += 1
                continue

            try:
                value, end = json_decoder.raw_decode(buffer, position)
            except json.JSONDecodeError:
                if final:
                    raise ValueError("CESNET JSON stream is incomplete or invalid") from None
                break

            if not isinstance(value, dict):
                raise ValueError("CESNET JSON array entries must be objects")
            yield value
            position = end

            if position > 1_000_000:
                buffer = buffer[position:]
                position = 0

        if finished:
            return
        if final:
            break

    raise ValueError("CESNET JSON stream ended before the array was closed")


def sample_cesnet_domain_names(
    records: Iterable[dict[str, object]],
    *,
    limit: int,
) -> tuple[tuple[str, ...], int, int]:
    """Return normalized unique CESNET domains plus skip counters."""
    if limit < 1:
        raise ValueError("sample limit must be positive")

    retained: list[str] = []
    seen: set[str] = set()
    invalid_or_missing = 0
    duplicates = 0

    for record in records:
        raw_domain = record.get("domain_name")
        normalized = (
            normalize_domain_candidate(raw_domain)
            if isinstance(raw_domain, str)
            else None
        )
        if normalized is None:
            invalid_or_missing += 1
            continue
        if normalized in seen:
            duplicates += 1
            continue

        seen.add(normalized)
        retained.append(normalized)
        if len(retained) >= limit:
            break

    if not retained:
        raise ValueError("CESNET source produced no valid domains")
    return tuple(retained), invalid_or_missing, duplicates


def write_dns_csv(domains: Iterable[str], path: Path) -> tuple[Path, str]:
    """Write a local one-column DNS CSV and return its SHA-256."""
    output = Path(path)
    if output.exists():
        raise FileExistsError("CESNET benign sample output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256()
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["query_name"])
        for domain in domains:
            writer.writerow([domain])

    with output.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return output, digest.hexdigest()


def write_sample_metadata(
    metadata: BenignCorpusSampleMetadata,
    path: Path,
) -> Path:
    output = Path(path)
    if output.exists():
        raise FileExistsError("CESNET sample metadata already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(asdict(metadata), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output
