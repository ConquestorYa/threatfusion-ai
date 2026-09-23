from threatfusion.correlation import IOCGroup, correlate_iocs
from threatfusion.models import IOCRecord, IOCType


def test_same_domain_from_three_sources_becomes_one_group() -> None:
    records = [
        IOCRecord(" Example.COM. ", IOCType.DOMAIN, "USOM"),
        IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox"),
        IOCRecord("EXAMPLE.COM", IOCType.DOMAIN, "URLhaus"),
    ]

    groups = correlate_iocs(records)

    assert len(groups) == 1
    assert groups[0].value == "example.com"
    assert groups[0].ioc_type is IOCType.DOMAIN
    assert groups[0].sources == {"USOM", "ThreatFox", "URLhaus"}
    assert groups[0].source_count == 3


def test_domain_normalization_is_applied_before_correlation() -> None:
    groups = correlate_iocs(
        [
            IOCRecord("  EXAMPLE.COM.  ", IOCType.DOMAIN, "one"),
            IOCRecord("example.com", IOCType.DOMAIN, "two"),
        ]
    )

    assert len(groups) == 1
    assert groups[0].value == "example.com"


def test_different_ioc_values_remain_separate_groups() -> None:
    groups = correlate_iocs(
        [
            IOCRecord("first.example", IOCType.DOMAIN, "source"),
            IOCRecord("second.example", IOCType.DOMAIN, "source"),
        ]
    )

    assert [group.value for group in groups] == ["first.example", "second.example"]


def test_same_text_with_different_ioc_types_is_not_merged() -> None:
    groups = correlate_iocs(
        [
            IOCRecord("example.com", IOCType.DOMAIN, "domain-source"),
            IOCRecord("example.com", IOCType.UNKNOWN, "unknown-source"),
        ]
    )

    assert len(groups) == 2
    assert {group.ioc_type for group in groups} == {IOCType.DOMAIN, IOCType.UNKNOWN}


def test_original_record_values_are_not_modified() -> None:
    records = [IOCRecord("  EXAMPLE.COM.  ", IOCType.DOMAIN, "source")]

    correlate_iocs(records)

    assert records[0].value == "  EXAMPLE.COM.  "


def test_multiple_records_from_same_source_are_preserved() -> None:
    records = [
        IOCRecord("example.com", IOCType.DOMAIN, "same-source"),
        IOCRecord("EXAMPLE.COM", IOCType.DOMAIN, "same-source"),
    ]

    groups = correlate_iocs(records)

    assert groups[0].records[0] is records[0]
    assert groups[0].records[1] is records[1]
    assert groups[0].source_count == 1


def test_sources_returns_unique_source_names() -> None:
    group = IOCGroup(
        value="example.com",
        ioc_type=IOCType.DOMAIN,
        records=[
            IOCRecord("example.com", IOCType.DOMAIN, "source"),
            IOCRecord("example.com", IOCType.DOMAIN, "source"),
        ],
    )

    assert group.sources == {"source"}
    assert group.source_count == 1


def test_empty_input_returns_empty_list() -> None:
    assert correlate_iocs([]) == []