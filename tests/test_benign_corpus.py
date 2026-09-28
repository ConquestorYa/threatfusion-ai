from __future__ import annotations

import json

import pytest

from threatfusion.benign_corpus import (
    BenignCorpusSampleMetadata,
    iter_json_array_objects,
    sample_cesnet_domain_names,
    write_dns_csv,
    write_sample_metadata,
)


def chunk_bytes(payload: bytes, sizes: list[int]) -> list[bytes]:
    chunks: list[bytes] = []
    offset = 0
    for size in sizes:
        chunks.append(payload[offset : offset + size])
        offset += size
    if offset < len(payload):
        chunks.append(payload[offset:])
    return chunks


def test_iter_json_array_objects_handles_arbitrary_chunk_boundaries() -> None:
    payload = json.dumps(
        [
            {"domain_name": "one.example", "nested": {"value": [1, 2]}},
            {"domain_name": "two.example", "text": "hello"},
        ]
    ).encode()

    records = list(
        iter_json_array_objects(
            chunk_bytes(payload, [1, 2, 5, 3, 11, 7, 4, 9])
        )
    )

    assert [record["domain_name"] for record in records] == [
        "one.example",
        "two.example",
    ]


def test_iter_json_array_objects_rejects_non_array_and_incomplete_json() -> None:
    with pytest.raises(ValueError, match="top-level JSON array"):
        list(iter_json_array_objects([b'{"domain_name":"one.example"}']))

    with pytest.raises(ValueError, match="incomplete or invalid"):
        list(iter_json_array_objects([b'[{"domain_name":"one.example"']))


def test_sample_cesnet_domain_names_normalizes_deduplicates_and_limits() -> None:
    records = [
        {"domain_name": "One.Example."},
        {"domain_name": "one.example"},
        {"domain_name": ""},
        {"not_domain_name": "missing.example"},
        {"domain_name": "two.example"},
        {"domain_name": "three.example"},
    ]

    domains, invalid, duplicates = sample_cesnet_domain_names(records, limit=2)

    assert domains == ("one.example", "two.example")
    assert invalid == 2
    assert duplicates == 1


def test_sample_cesnet_domain_names_supports_disjoint_unique_offset() -> None:
    records = [
        {"domain_name": "one.example"},
        {"domain_name": "ONE.example."},
        {"domain_name": "two.example"},
        {"domain_name": "three.example"},
        {"domain_name": "four.example"},
    ]

    domains, invalid, duplicates = sample_cesnet_domain_names(
        records,
        limit=2,
        skip_unique=2,
    )

    assert domains == ("three.example", "four.example")
    assert invalid == 0
    assert duplicates == 1


def test_sample_cesnet_domain_names_rejects_negative_offset() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        sample_cesnet_domain_names([], limit=1, skip_unique=-1)


def test_sample_cesnet_domain_names_requires_positive_limit() -> None:
    with pytest.raises(ValueError, match="positive"):
        sample_cesnet_domain_names([], limit=0)


def test_write_dns_csv_and_metadata_are_deterministic_and_private(tmp_path) -> None:
    csv_path, sha256 = write_dns_csv(
        ["one.example", "two.example"],
        tmp_path / "cesnet.csv",
    )
    assert csv_path.read_text(encoding="utf-8") == (
        "query_name\none.example\ntwo.example\n"
    )
    assert len(sha256) == 64

    metadata = BenignCorpusSampleMetadata(
        source_name="CESNET real-traffic benign domains",
        source_doi="10.5281/zenodo.14332167",
        source_record_url="https://zenodo.org/records/14332167",
        source_file="benign_cesnet.json",
        source_file_md5="c" * 32,
        source_license="CC BY 4.0",
        requested_unique_domains=2,
        retained_unique_domains=2,
        invalid_or_missing_domains=0,
        duplicate_domains=0,
        downloaded_bytes=12345,
        output_sha256=sha256,
    )
    metadata_path = write_sample_metadata(
        metadata,
        tmp_path / "cesnet.metadata.json",
    )
    serialized = metadata_path.read_text(encoding="utf-8")

    assert "one.example" not in serialized
    assert "two.example" not in serialized
    assert json.loads(serialized)["retained_unique_domains"] == 2


def test_writers_refuse_to_overwrite_existing_corpus(tmp_path) -> None:
    csv_path = tmp_path / "cesnet.csv"
    write_dns_csv(["one.example"], csv_path)

    with pytest.raises(FileExistsError, match="already exists"):
        write_dns_csv(["two.example"], csv_path)

    metadata = BenignCorpusSampleMetadata(
        source_name="source",
        source_doi="doi",
        source_record_url="record",
        source_file="file",
        source_file_md5="d" * 32,
        source_license="CC BY 4.0",
        requested_unique_domains=1,
        retained_unique_domains=1,
        invalid_or_missing_domains=0,
        duplicate_domains=0,
        downloaded_bytes=1,
        output_sha256="e" * 64,
    )
    metadata_path = tmp_path / "metadata.json"
    write_sample_metadata(metadata, metadata_path)

    with pytest.raises(FileExistsError, match="already exists"):
        write_sample_metadata(metadata, metadata_path)
