from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
from typing import Any

import requests

from ..models import IOCRecord, IOCType

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/{}/online-valid.csv"
REQUEST_TIMEOUT_SECONDS = 30


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_phishtank_csv(content: str) -> list[IOCRecord]:
    reader = csv.DictReader(StringIO(content))
    records: list[IOCRecord] = []
    for row in reader:
        url = row.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        if str(row.get("verified", "")).casefold() != "yes":
            continue
        if str(row.get("online", "")).casefold() != "yes":
            continue

        tags = ["verified", "online"]
        target = row.get("target")
        if isinstance(target, str) and target.strip():
            tags.append(f"target:{target.strip()}")

        records.append(
            IOCRecord(
                value=url.strip(),
                ioc_type=IOCType.URL,
                source="PhishTank",
                first_seen=_parse_timestamp(
                    row.get("verification_time") or row.get("submission_time")
                ),
                last_seen=None,
                threat_type="phishing",
                confidence=1.0,
                tags=tags,
            )
        )
    return records


class PhishTankCollector:
    def __init__(
        self,
        app_key: str,
        session: requests.Session | None = None,
    ) -> None:
        if not app_key.strip():
            raise ValueError("PhishTank app key is required")
        self.app_key = app_key.strip()
        self.session = session if session is not None else requests.Session()

    def fetch_verified_online_urls(self) -> list[IOCRecord]:
        feed_url = PHISHTANK_FEED_URL.format(self.app_key)
        try:
            response = self.session.get(
                feed_url,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise requests.HTTPError(
                "PhishTank feed request failed (request error)"
            ) from None

        try:
            response.raise_for_status()
        except requests.RequestException:
            status_code = getattr(response, "status_code", "unknown")
            raise requests.HTTPError(
                f"PhishTank feed request failed (HTTP status {status_code})"
            ) from None

        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise requests.HTTPError(
                f"PhishTank feed request failed (HTTP status {status_code})"
            )

        records = parse_phishtank_csv(response.text)
        if not records:
            raise ValueError("PhishTank feed contained no usable verified URLs")
        return records
