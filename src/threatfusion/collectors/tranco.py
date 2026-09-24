import re

import requests

TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/download/{}/1000000"
REQUEST_TIMEOUT_SECONDS = 30
_LIST_ID_PATTERN = re.compile(r"^[A-Za-z0-9]{4,32}$")


def _sanitized_http_error(status_code: object) -> requests.HTTPError:
    return requests.HTTPError(
        f"Tranco download request failed (HTTP status {status_code})"
    )


def _validate_list_id(list_id: str) -> str:
    if not isinstance(list_id, str):
        raise TypeError("list_id must be a text identifier")

    normalized = list_id.strip()
    if not _LIST_ID_PATTERN.fullmatch(normalized):
        raise ValueError("list_id must be a non-empty text identifier")

    return normalized


class TrancoCollector:
    def __init__(
        self,
        list_id: str,
        session: requests.Session | None = None,
    ) -> None:
        self.list_id = _validate_list_id(list_id)
        self.session = session if session is not None else requests.Session()

    def fetch_csv(self) -> str:
        download_url = TRANCO_DOWNLOAD_URL.format(self.list_id)
        response = self.session.get(
            download_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        response.raise_for_status()
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise _sanitized_http_error(status_code)
        return response.text
