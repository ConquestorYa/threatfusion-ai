from __future__ import annotations

from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_adguard import (
    parse_adguard_query_log,
    parse_adguard_query_log_with_diagnostics,
)


def test_parse_adguard_json_lines_maps_query_fields() -> None:
    content = (
        '{"IP":"10.0.0.5","T":"2026-09-25T18:00:00Z",'
        '"QH":"Example.COM","QT":"A"}\n'
        '{"IP":"10.0.0.6","T":"bad-time","QH":"second.example","QT":"AAAA"}\n'
    )

    parsed = parse_adguard_query_log_with_diagnostics(content)

    assert parsed.events == (
        DNSEvent(
            query_name="Example.COM",
            timestamp=datetime(2026, 9, 25, 18, 0, tzinfo=timezone.utc),
            client_ip="10.0.0.5",
            query_type="A",
            response_ip=None,
        ),
        DNSEvent(
            query_name="second.example",
            timestamp=None,
            client_ip="10.0.0.6",
            query_type="AAAA",
            response_ip=None,
        ),
    )
    assert parsed.diagnostics.total_rows == 2
    assert parsed.diagnostics.accepted_rows == 2
    assert parsed.diagnostics.invalid_timestamps == 1


def test_parse_adguard_api_export_maps_answer_ip() -> None:
    content = """{
      "oldest": "2026-09-25T17:59:00Z",
      "data": [
        {
          "client": "10.0.0.7",
          "time": "2026-09-25T18:01:00Z",
          "question": {
            "host": "api.example",
            "type": "A"
          },
          "answer": [
            {"ttl": 60, "type": "CNAME", "value": "alias.example"},
            {"ttl": 60, "type": "A", "value": "203.0.113.9"}
          ]
        }
      ]
    }"""

    events = parse_adguard_query_log(content)

    assert events == [
        DNSEvent(
            query_name="api.example",
            timestamp=datetime(2026, 9, 25, 18, 1, tzinfo=timezone.utc),
            client_ip="10.0.0.7",
            query_type="A",
            response_ip="203.0.113.9",
        )
    ]


def test_adguard_diagnostics_skip_missing_query_name() -> None:
    content = '[{"IP":"10.0.0.1","T":"2026-09-25T18:00:00Z","QT":"A"}]'

    parsed = parse_adguard_query_log_with_diagnostics(content)

    assert parsed.events == ()
    assert parsed.diagnostics.total_rows == 1
    assert parsed.diagnostics.accepted_rows == 0
    assert parsed.diagnostics.skipped_missing_query_name == 1


def test_invalid_adguard_json_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid JSON"):
        parse_adguard_query_log('{"QH":"one.example"}\nnot-json\n')


def test_empty_adguard_log_is_safe() -> None:
    assert parse_adguard_query_log("") == []
