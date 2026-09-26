from __future__ import annotations

import bz2
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import requests

from ..models import IOCRecord, IOCType

PHISHTANK_EXPORT_URL = (
    "https://data.phishtank.com/data/{}/online-valid.json.bz2"
)
REQUEST_TIMEOUT_SECONDS = 45
USER_AGENT = "ThreatFusionAI/0.1 threat-intelligence-refresh"


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _valid_url(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def parse_phishtank_json(content: bytes) -> list[IOCRecord]:
    try:
        decoded = bz2.decompress(content)
    except OSError as error:
        raise ValueError("PhishTank feed is not valid bzip2 data") from error

    try:
        payload = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("PhishTank feed is not valid JSON") from error

    if not isinstance(payload, list):
        raise TypeError("PhishTank feed must be a JSON list")

    records: list[IOCRecord] = []
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("verified", "")).casefold() != "yes":
            continue
        if str(item.get("online", "")).casefold() != "yes":
            continue

        value = item.get("url")
        if not _valid_url(value):
            continue

        target = item.get("target")
        tags = ["verified", "online"]
        if isinstance(target, str) and target.strip():
            tags.append(f"target:{target.strip()}")

        records.append(
            IOCRecord(
                value=str(value).strip(),
                ioc_type=IOCType.URL,
                source="PhishTank",
                first_seen=(
                    _parse_time(item.get("verification_time"))
                    or _parse_time(item.get("submission_time"))
                ),
                last_seen=None,
                threat_type="phishing",
                confidence=None,
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
            raise ValueError("PhishTank app key must not be empty")
        self.app_key = app_key.strip()
        self.session = session if session is not None else requests.Session()

    def fetch_online_verified_urls(self) -> list[IOCRecord]:
        feed_url = PHISHTANK_EXPORT_URL.format(self.app_key)
        try:
            response = self.session.get(
                feed_url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise requests.HTTPError(
                "PhishTank feed request failed (request error)"
            ) from None

        status_code = getattr(response, "status_code", 200)
        try:
            response.raise_for_status()
        except requests.RequestException:
            raise requests.HTTPError(
                f"PhishTank feed request failed (HTTP status {status_code})"
            ) from None
        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise requests.HTTPError(
                f"PhishTank feed request failed (HTTP status {status_code})"
            )

        payload = getattr(response, "content", b"")
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("PhishTank response content must be bytes")
        return parse_phishtank_json(bytes(payload))
