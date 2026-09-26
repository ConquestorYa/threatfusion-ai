from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

import requests

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.benign_corpus import (
    CESNET_BENIGN_DOWNLOAD_URL,
    CESNET_BENIGN_SOURCE_MD5,
    CESNET_DATASET_DOI,
    CESNET_DATASET_LICENSE,
    CESNET_DATASET_RECORD_URL,
    BenignCorpusSampleMetadata,
    iter_json_array_objects,
    sample_cesnet_domain_names,
    write_dns_csv,
    write_sample_metadata,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Stream a bounded sample of verified-benign CESNET real-traffic "
            "domains without saving the full 6.4 GB source file"
        )
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20_000,
        help="Number of unique valid domains to retain (default: 20000)",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=Path("data/evaluation/cesnet-benign-20k.csv"),
    )
    parser.add_argument(
        "--metadata-output",
        type=Path,
        default=Path("data/evaluation/cesnet-benign-20k.metadata.json"),
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=1024 * 1024,
        help="Streaming HTTP chunk size in bytes",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 1:
        raise SystemExit("--limit must be positive")
    if args.chunk_size < 4096:
        raise SystemExit("--chunk-size must be at least 4096 bytes")
    if args.output_csv.exists() or args.metadata_output.exists():
        raise SystemExit(
            "CESNET sample output already exists; choose new output paths "
            "instead of overwriting an evaluation corpus"
        )

    downloaded_bytes = 0

    def byte_chunks(response: requests.Response):
        nonlocal downloaded_bytes
        for chunk in response.iter_content(chunk_size=args.chunk_size):
            if not chunk:
                continue
            downloaded_bytes += len(chunk)
            yield chunk

    try:
        with requests.get(
            CESNET_BENIGN_DOWNLOAD_URL,
            stream=True,
            timeout=(15, 60),
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": "ThreatFusion-AI-benign-evaluation/1.0",
            },
        ) as response:
            response.raise_for_status()
            records = iter_json_array_objects(byte_chunks(response))
            domains, invalid_or_missing, duplicates = sample_cesnet_domain_names(
                records,
                limit=args.limit,
            )

        output_path, output_sha256 = write_dns_csv(domains, args.output_csv)
        metadata = BenignCorpusSampleMetadata(
            source_name="CESNET real-traffic benign domains",
            source_doi=CESNET_DATASET_DOI,
            source_record_url=CESNET_DATASET_RECORD_URL,
            source_file="benign_cesnet.json",
            source_file_md5=CESNET_BENIGN_SOURCE_MD5,
            source_license=CESNET_DATASET_LICENSE,
            requested_unique_domains=args.limit,
            retained_unique_domains=len(domains),
            invalid_or_missing_domains=invalid_or_missing,
            duplicate_domains=duplicates,
            downloaded_bytes=downloaded_bytes,
            output_sha256=output_sha256,
        )
        metadata_path = write_sample_metadata(metadata, args.metadata_output)
    except requests.RequestException as error:
        raise SystemExit(
            f"CESNET download failed: {type(error).__name__}: {error}"
        ) from None
    except (OSError, TypeError, ValueError) as error:
        raise SystemExit(
            f"CESNET sample preparation failed: {type(error).__name__}: {error}"
        ) from None

    print("ThreatFusion AI CESNET benign-corpus sample")
    print(f"  Source DOI: {CESNET_DATASET_DOI}")
    print(f"  Source license: {CESNET_DATASET_LICENSE}")
    print(f"  Requested unique domains: {args.limit}")
    print(f"  Retained unique domains: {len(domains)}")
    print(f"  Invalid/missing domains skipped: {invalid_or_missing}")
    print(f"  Duplicate domains skipped: {duplicates}")
    print(f"  Streamed bytes before stop: {downloaded_bytes}")
    print(f"  Local CSV SHA-256: {output_sha256}")
    print(f"  CSV: {output_path}")
    print(f"  Metadata: {metadata_path}")
    print(
        "Source limitation: CESNET domains originate from real network TLS SNI "
        "observations, not from a DNS query-frequency sample."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
