from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
import requests

from threatfusion import domain_age
from tests.test_streamlit_feedback import feedback_app  # noqa: F401,F811

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
BOOTSTRAP = {"services": [[["test"], ["http://insecure.example/", "https://rdap.registry.test/rdap"]],
                          [["plain"], ["http://only-http.example/"]]]}
RULES = frozenset({"test", "dyn-host.test"})


class _Response:
    def __init__(self, url, status=200, payload=None, history=()):
        self.url, self.status_code, self.history = url, status, list(history)
        self._body = json.dumps(payload).encode() if payload is not None else b""
        self.headers = {}

    def iter_content(self, chunk_size):
        yield self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def close(self):
        pass


class _Session:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, **kwargs):
        self.calls.append(url)
        route = self.routes.get(url)
        if route is None:
            raise requests.ConnectionError("no route")
        return route(url) if callable(route) else _Response(url, *route)


def _domain(registered, registrar="Example Registrar"):
    return {"events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": registered}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", registrar]]]}]}


def _session(domain_route):
    return _Session({domain_age.BOOTSTRAP_URL: (200, BOOTSTRAP),
                     "https://rdap.registry.test/rdap/domain/example.test": domain_route})


@pytest.mark.parametrize("name, sent", [
    ("deep.sub.example.test", "example.test"), ("EXAMPLE.test.", "example.test"),
    ("a.user1.dyn-host.test", "user1.dyn-host.test"), ("192.0.2.1", None), ("localhost", None), ("test", None),
])
def test_only_the_registrable_domain_is_sent(name, sent):
    assert domain_age.rdap_domain(name, RULES) == sent


def test_age_from_the_registration_event_only_the_domain_is_sent():
    session = _session((200, _domain("2026-10-08T12:00:00Z")))
    age = domain_age.lookup_domain_age("login.deep.example.test", suffix_rules=RULES, session=session, now=NOW)
    assert (age.status, age.domain, age.age_days, age.tier, age.registrar) == (
        "found", "example.test", 2, "very_new", "Example Registrar")
    assert session.calls == [domain_age.BOOTSTRAP_URL, "https://rdap.registry.test/rdap/domain/example.test"]
    old = domain_age.lookup_domain_age("example.test", suffix_rules=RULES,
                                       session=_session((200, _domain("2001-01-01T00:00:00+00:00"))), now=NOW)
    assert old.tier == "established" and old.age_days > 9000


def test_missing_unsupported_and_failed_lookups_are_plain_states():
    assert domain_age.lookup_domain_age("example.test", suffix_rules=RULES, session=_session((404,)),
                                        now=NOW).status == "not_found"
    no_date = domain_age.lookup_domain_age("example.test", suffix_rules=RULES, session=_session((200, {})), now=NOW)
    assert no_date.status == "found" and no_date.age_days is None and no_date.tier is None
    assert domain_age.lookup_domain_age("example.plain", session=_session((200, {})), now=NOW).status == "unsupported"
    assert domain_age.lookup_domain_age("example.test", suffix_rules=RULES, session=_session((500,)),
                                        now=NOW).status == "error"
    assert domain_age.lookup_domain_age("192.0.2.1", session=_Session({})).status == "unsupported"


def test_a_redirect_away_from_https_is_refused():
    def downgrade(url):
        return _Response("http://rdap.registry.test/rdap/domain/example.test", 200, _domain("2026-10-08T00:00:00Z"),
                         history=[_Response(url, 302)])
    assert domain_age.lookup_domain_age("example.test", suffix_rules=RULES, session=_session(downgrade),
                                        now=NOW).status == "error"


def test_oversized_answer_is_refused(monkeypatch):
    monkeypatch.setattr(domain_age, "MAX_RESPONSE_BYTES", 10)
    assert domain_age.lookup_domain_age("example.test", suffix_rules=RULES,
                                        session=_session((200, _domain("2026-10-08T00:00:00Z"))),
                                        now=NOW).status == "error"


def test_quick_lookup_button_sends_nothing_until_pressed(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    calls = []
    script = (
        "from pathlib import Path\n"
        "from threatfusion import domain_age, ui_quick_lookup\n"
        "from threatfusion.quick_lookup import analyze_quick_lookup\n"
        "from tests.test_domain_age import record\n"
        "ui_quick_lookup.lookup_domain_age = record\n"
        "result = analyze_quick_lookup('https://login.example.test/x', [], None)\n"
        f"ui_quick_lookup.render_quick_lookup_result(result, registry_db_path=Path({str(tmp_path / 'none.sqlite')!r}))\n"
    )
    monkeypatch.setattr("tests.test_domain_age.CALLS", calls)
    app = AppTest.from_string(script).run(timeout=15)
    assert not app.exception and calls == []
    assert any("example.test" in c.value for c in app.caption)
    next(b for b in app.button if b.label == "Check site age").click().run(timeout=15)
    assert not app.exception and calls == ["example.test"]
    assert not [b for b in app.button if b.label == "Check site age"]  # the result replaces the button
    assert any("Very new site" in md.value for md in app.markdown)


CALLS: list[str] = []


def record(domain, **kwargs):
    CALLS.append(domain)
    return domain_age.DomainAge(domain, "found", NOW, 3, None, "rdap.registry.test")


def test_tests_cannot_reach_a_registry():
    with pytest.raises(RuntimeError, match="network access is disabled"):
        domain_age.lookup_domain_age("example.test", suffix_rules=RULES)


def test_site_age_stays_turkish_through_the_whole_app_flow(feedback_app, monkeypatch, tmp_path):  # noqa: F811
    from streamlit.testing.v1 import AppTest

    from threatfusion import ui_quick_lookup
    from threatfusion.quick_lookup import analyze_quick_lookup

    app_module = feedback_app[0]
    monkeypatch.setattr(app_module, "analyze_quick_lookup_from_cache", lambda value, db, artifact: analyze_quick_lookup(value, [], None))
    monkeypatch.setattr(ui_quick_lookup, "lookup_domain_age",
                        lambda domain, **kw: domain_age.DomainAge(domain, "found", NOW, 340, "Example Registrar"))
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    app.text_input(key="quick_lookup_input").input("fujei.example.com").run(timeout=15)
    app.button(key="quick_lookup_analyze").click().run(timeout=15)
    next(b for b in app.button if b.label == "Site yaşını öğren").click().run(timeout=15)
    assert not app.exception
    cards = " ".join(m.value for m in app.markdown if "Site" in m.value)
    assert "Eski site · 11 aylık" in cards and "Established" not in cards


def test_a_name_on_a_shared_platform_reports_the_platform():
    rules = RULES | {"pages.test"}
    session = _Session({domain_age.BOOTSTRAP_URL: (200, BOOTSTRAP),
                        "https://rdap.registry.test/rdap/domain/shop.pages.test": (400,),
                        "https://rdap.registry.test/rdap/domain/pages.test": (200, _domain("2015-01-01T00:00:00Z"))})
    age = domain_age.lookup_domain_age("login.shop.pages.test", suffix_rules=rules, session=session, now=NOW)
    assert (age.status, age.domain, age.platform, age.tier) == ("shared_platform", "shop.pages.test", "pages.test", None)
    gone = _Session({domain_age.BOOTSTRAP_URL: (200, BOOTSTRAP)} | {
        f"https://rdap.registry.test/rdap/domain/{d}": (404,) for d in ("shop.pages.test", "pages.test")})
    assert domain_age.lookup_domain_age("shop.pages.test", suffix_rules=rules, session=gone, now=NOW).status == "not_found"
