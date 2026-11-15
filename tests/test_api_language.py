"""No screen mixes Turkish and English, and no raw ISO time reaches the page."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import resolve_settings

ORIGIN = "http://127.0.0.1:8600"
HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}

# English UI words that must not survive in Turkish output. Loanwords that the
# Turkish dictionary deliberately keeps (domain, hostname, port, DNS, IP, URL,
# CTI, IOC, Zeek, TCP) and data (names, sources, tags) are not listed.
ENGLISH = frozenset("""
the and with for from after before into than this that these those are was were has have
interval periodic periodicity pattern churn label labels codes depth subdomain entropy numeric types inspect software activity score ratio timing sustained stale
observe investigate review query queries connection connections session sessions record records
match matches seen first last unknown fresh state reason needs insufficient exact response confidence
refreshed active events verdict same addresses unanswered rejected observed duration payload endings
closes duplicate conflicting originator responder count update updates download show table loading
group device target threat evidence coverage limits check lookup details setup mark suspicious
why open light dark theme language screens bucket bytes window distinct failed attempts known
""".split())

# Internal fields: codes, keys and data, not text for people.
SKIP_KEYS = frozenset({"key", "kind", "tone", "url", "icon", "file", "revision", "updated_at", "generated_at", "verdict", "verdicts", "domains",
                       "finished_at", "domain", "name", "device", "host", "t", "state", "mark", "value_code"})
DATA_COLUMNS = frozenset({"Kaynak", "Gösterge", "Tehdit türü", "Etiketler", "Hedef"})
DOMAIN_OR_ADDRESS = re.compile(r"\b[\w-]+(?:\.[\w-]+)+(?::\d+)?\b|https?://\S+")
ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


@pytest.fixture(scope="module")
def turkish_output(tmp_path_factory):
    from scripts.demo_review_snapshot import main

    root = tmp_path_factory.mktemp("language") / "install"
    assert main(["--managed", str(root)]) == 0
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(root), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    client = TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)
    pages = {
        "i18n": client.get("/api/i18n", params={"lang": "tr"}).json(),
        "review": client.get("/api/review", params={"lang": "tr"}).json(),
        "details": client.get("/api/details", params={"lang": "tr", "reviews_only": False, "dns_observations": True}).json(),
        "dns-timeline": client.get("/api/details/dns-timeline", params={"lang": "tr", "group": 1}).json(),
        "lookup-status": client.get("/api/lookup/status", params={"lang": "tr"}).json(),
        "setup": client.get("/api/setup", params={"lang": "tr"}).json(),
    }
    for group in pages["details"]["connections"]["groups"][:4]:
        pages[f"timeline-{group['group']}"] = client.get(
            "/api/details/connection-timeline", params={"lang": "tr", "group": group["group"]}).json()
    samples = Path(__file__).resolve().parents[1] / "data/samples/demo"
    upload = {**HEADERS, "Content-Type": "application/octet-stream"}
    for name in ("dns.log", "conn.log", "dns_queries.csv"):
        body = client.post("/api/analyze", params={"format": "Auto-detect", "name": name, "lang": "tr"},
                           content=(samples / name).read_bytes(), headers=upload).json()
        pages[f"analyze {name}"] = body
        for kind, params in (("devices", {"include_observe": True}), ("connections", {"reviews_only": False})):
            part = client.get(f"/api/analyze/{body['id']}/{kind}", params={"lang": "tr", **params}).json()
            pages[f"analyze {name} {kind}"] = part
        for domain in body["investigation"]["domains"][:3]:
            pages[f"analyze {name} {domain}"] = client.get(f"/api/analyze/{body['id']}/domain",
                                                           params={"lang": "tr", "name": domain}).json()
    pages["analyze-status"] = client.get("/api/analyze/status", params={"lang": "tr"}).json()
    for value in ("https://malicious.example.test/login", "http://203.0.113.7/x", "quiet.example.test"):
        pages[f"lookup {value}"] = client.post("/api/lookup", params={"lang": "tr"}, json={"value": value},
                                              headers=HEADERS).json()
    return pages


def _texts(value, key=None):
    """Every user-facing string with the field it came from."""
    if isinstance(value, dict):
        if "label" in value and isinstance(value.get("value"), str):  # a choice: value is a code
            value = {k: v for k, v in value.items() if k != "value"}
        if "columns" in value and "rows" in value:  # a table: skip data columns
            for column in value["columns"]:
                yield "columns", column
            keep = [index for index, column in enumerate(value["columns"]) if column not in DATA_COLUMNS]
            for row in value["rows"]:
                for index in keep:
                    if isinstance(row[index], str):
                        yield "cell", row[index]
            value = {k: v for k, v in value.items() if k not in {"columns", "rows"}}
        for child_key, child in value.items():
            if child_key not in SKIP_KEYS:
                yield from _texts(child, child_key)
    elif isinstance(value, list):
        for child in value:
            yield from _texts(child, key)
    elif isinstance(value, str):
        yield key, value


def test_turkish_output_has_no_english_words(turkish_output):
    leftovers = []
    for page, body in turkish_output.items():
        for field, text in _texts(body):
            if field == "links" or text.startswith("connection:"):
                continue
            # Format help names the file's own fields (query, query_name, timestamp): not UI wording.
            if page == "analyze-status" and field in {"help", "required"}:
                continue
            cleaned = re.sub(r"\{\w+\}", " ", DOMAIN_OR_ADDRESS.sub(" ", text))  # placeholders
            # Whole words including Turkish letters, so "olağandışı" is not read as "and".
            words = re.findall(r"[A-Za-zÇĞİÖŞÜçğıöşü]+", cleaned)
            english = sorted({word for word in words if word.lower() in ENGLISH})
            if english:
                leftovers.append(f"{page}/{field}: {english} in {text[:90]!r}")
    assert not leftovers, "\n".join(leftovers)


def test_no_raw_iso_times_in_page_text(turkish_output):
    """Tables carry ISO values for the browser to format; text must not."""
    raw = [f"{page}/{field}: {text[:80]!r}" for page, body in turkish_output.items()
           for field, text in _texts(body) if field != "cell" and ISO_TIME.search(text)]
    assert not raw, "\n".join(raw)
