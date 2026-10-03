"""Check a deliberately supplied demo service URL, never an IOC destination."""

from __future__ import annotations

import argparse
import http.client
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


def check_public_demo_proxy(base_url: str) -> None:
    base = base_url.rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path:
        raise ValueError("base URL must be an HTTP(S) service origin without a path")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base URL must not include credentials, query or fragment")
    for attempt in range(30):
        try:
            with urllib.request.urlopen(
                base + "/_stcore/health", timeout=2
            ) as response:
                if response.status == 200 and response.read() == b"ok":
                    break
        except (OSError, urllib.error.URLError):
            pass
        if attempt == 29:
            raise RuntimeError("public demo health did not become ready")
        time.sleep(1)

    with urllib.request.urlopen(base, timeout=10) as response:
        if response.status != 200 or any(
            response.headers.get(key) != expected
            for key, expected in {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            }.items()
        ):
            raise RuntimeError("demo root or security headers are incorrect")

    connection_type = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_type(parsed.hostname, parsed.port, timeout=10)
    try:
        connection.putrequest("POST", "/_stcore/upload_file")
        connection.putheader("Content-Length", str(21 * 1024 * 1024 + 1))
        connection.endheaders()
        if connection.getresponse().status != 413:
            raise RuntimeError("proxy did not reject an oversized request")
    finally:
        connection.close()

    def probe(_: int) -> int:
        try:
            with urllib.request.urlopen(
                base + "/_stcore/host-config", timeout=10
            ) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=16) as pool:
        counts = Counter(pool.map(probe, range(120)))
    if not counts[429] or not counts[200] or set(counts) - {200, 429}:
        raise RuntimeError(f"unexpected aggregate burst statuses: {dict(counts)}")
    with urllib.request.urlopen(base + "/_stcore/health", timeout=10) as response:
        if response.status != 200:
            raise RuntimeError("health endpoint was affected by visitor limits")
    print(
        "Public demo health, security headers, 413 body limit and 429 burst limit passed"
    )
    print(f"Aggregate burst response counts: {dict(counts)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:18501")
    args = parser.parse_args()
    check_public_demo_proxy(args.base_url)
