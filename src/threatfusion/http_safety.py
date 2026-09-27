from __future__ import annotations

from typing import Any

_CHUNK_SIZE = 1024 * 1024


def _content_length(response: Any) -> int | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        raw = headers.get("Content-Length")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def read_bounded_response_bytes(
    response: Any,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read one HTTP response while enforcing a hard byte ceiling.

    The helper prefers streaming responses so oversized feeds can be rejected
    before they are buffered in full. Test doubles and older callers without
    iter_content are supported through a bounded content/text fallback.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")

    declared = _content_length(response)
    if declared is not None and declared > max_bytes:
        raise ValueError(f"{label} exceeds the safe download limit")

    iterator = getattr(response, "iter_content", None)
    if callable(iterator):
        chunks: list[bytes] = []
        total = 0
        for chunk in iterator(chunk_size=_CHUNK_SIZE):
            if not chunk:
                continue
            if not isinstance(chunk, (bytes, bytearray)):
                raise ValueError(f"{label} returned invalid response bytes")
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds the safe download limit")
            chunks.append(bytes(chunk))
        return b"".join(chunks)

    raw = getattr(response, "content", None)
    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise ValueError(f"{label} exceeds the safe download limit")
        return raw

    text = getattr(response, "text", None)
    if isinstance(text, str):
        encoded = text.encode("utf-8")
        if len(encoded) > max_bytes:
            raise ValueError(f"{label} exceeds the safe download limit")
        return encoded

    raise ValueError(f"{label} response body is unavailable")


def decode_utf8_response(
    response: Any,
    *,
    max_bytes: int,
    label: str,
) -> str:
    payload = read_bounded_response_bytes(
        response,
        max_bytes=max_bytes,
        label=label,
    )
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not valid UTF-8 text") from error
