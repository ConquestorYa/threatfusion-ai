from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_zeek import (
    parse_zeek_dns_log,
    parse_zeek_dns_log_with_diagnostics,
)

ZEEK_LOG = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected
1700000000.5\tC1\t10.0.0.5\t53000\t10.0.0.53\t53\tudp\t1\t0.01\tExample.COM\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t203.0.113.7,alias.example\t60.0\tF
bad-ts\tC2\t10.0.0.6\t53001\t10.0.0.53\t53\tudp\t2\t0.01\tsecond.example\t1\tC_INTERNET\t28\tAAAA\t0\tNOERROR\tF\tF\tT\tT\t0\t2001:db8::7\t60.0\tF
1700000002.0\tC3\t10.0.0.7\t53002\t10.0.0.53\t53\tudp\t3\t0.01\t-\t1\tC_INTERNET\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t-\t-\tF
#close\t2026-09-25-18-00-00
"""


def test_parse_zeek_dns_log_maps_standard_dns_fields() -> None:
    events = parse_zeek_dns_log(ZEEK_LOG)

    assert events[0] == DNSEvent(
        query_name="Example.COM",
        timestamp=datetime.fromtimestamp(1700000000.5, tz=timezone.utc),
        client_ip="10.0.0.5",
        query_type="A",
        response_ip="203.0.113.7",
    )
    assert events[1].query_name == "second.example"
    assert events[1].timestamp is None
    assert events[1].query_type == "AAAA"
    assert events[1].response_ip == "2001:db8::7"


def test_parse_zeek_dns_log_reports_input_quality() -> None:
    parsed = parse_zeek_dns_log_with_diagnostics(ZEEK_LOG)

    assert parsed.diagnostics.total_rows == 3
    assert parsed.diagnostics.accepted_rows == 2
    assert parsed.diagnostics.skipped_missing_query_name == 1
    assert parsed.diagnostics.invalid_timestamps == 1
    assert parsed.diagnostics.invalid_response_ips == 0


def test_zeek_log_requires_fields_header() -> None:
    with pytest.raises(ValueError, match="#fields"):
        parse_zeek_dns_log("1700000000\tmissing.example")


def test_zeek_log_requires_query_field() -> None:
    content = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\n"
        "1700000000\t10.0.0.5\n"
    )

    with pytest.raises(ValueError, match="query"):
        parse_zeek_dns_log(content)


def test_empty_zeek_log_is_safe() -> None:
    assert parse_zeek_dns_log("") == []
