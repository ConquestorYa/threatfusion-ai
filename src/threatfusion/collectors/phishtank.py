from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
from typing import Any
from urllib.parse import quote

import requests

from ..http_safety import decode_utf8_response
from ..models import IOCRecord, IOCType

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"
PHISHTANK_AUTHENTICATED_FEED_TEMPLATE = (
    "https://data.phishtank.com/data/{app_key}/online-valid.csv"
)
PHISHTANK_USER_AGENT = "phishtank/ThreatFusionAI"
REQUEST_TIMEOUT_SECONDS = 30
MAX_PHISHTANK_FEED_BYTES = 64 * 1024 * 1024


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
    """Download the verified-online feed at a deliberately low cadence."""

    def __init__(
        self,
        session: requests.Session | None = None,
        *,
        app_key: str | None = None,
    ) -> None:
        self.session = session if session is not None else requests.Session()
        self.app_key = app_key.strip() if app_key and app_key.strip() else None

    def _feed_url(self) -> str:
        if self.app_key is None:
            return PHISHTANK_FEED_URL
        return PHISHTANK_AUTHENTICATED_FEED_TEMPLATE.format(
            app_key=quote(self.app_key, safe="")
        )

    def fetch_verified_online_urls(self) -> list[IOCRecord]:
        feed_url = self._feed_url()
        try:
            response = self.session.get(
                feed_url,
                headers={"User-Agent": PHISHTANK_USER_AGENT},
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException:
            raise requests.HTTPError(
                "PhishTank feed request failed (request error)"
            ) from None

        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and 300 <= status_code < 400:
            if self.app_key is None:
                raise requests.HTTPError(
                    "PhishTank public feed redirected to an access/security "
                    "check; set PHISHTANK_APP_KEY for automated downloads "
                    f"(HTTP status {status_code})"
                )
            raise requests.HTTPError(
                "PhishTank authenticated feed redirected unexpectedly; "
                "verify PHISHTANK_APP_KEY "
                f"(HTTP status {status_code})"
            )

        try:
            response.raise_for_status()
        except requests.RequestException:
            status_code = getattr(response, "status_code", "unknown")
            raise requests.HTTPError(
                "PhishTank feed request failed "
                f"(HTTP status {status_code})"
            ) from None

        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise requests.HTTPError(
                "PhishTank feed request failed "
                f"(HTTP status {status_code})"
            )

        content = decode_utf8_response(
            response,
            max_bytes=MAX_PHISHTANK_FEED_BYTES,
            label="PhishTank feed",
        )
        records = parse_phishtank_csv(content)
        if not records:
            raise ValueError(
                "PhishTank feed contained no usable verified URLs"
            )
        return records
