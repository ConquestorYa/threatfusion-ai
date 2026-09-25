from threatfusion.models import IOCRecord, IOCType
from threatfusion.normalization import normalize_ioc_value


def test_domain_normalization() -> None:
    assert normalize_ioc_value("  Example.COM.  ", IOCType.DOMAIN) == "example.com"




def test_unicode_domain_normalizes_to_idna_ascii() -> None:
    assert (
        normalize_ioc_value("BÜCHER.Example.", IOCType.DOMAIN)
        == "xn--bcher-kva.example"
    )


def test_ipv6_network_normalization() -> None:
    assert (
        normalize_ioc_value(
            " 2001:0DB8:0000::/32 ",
            IOCType.IPV6_NETWORK,
        )
        == "2001:db8::/32"
    )

def test_uppercase_hash_normalization() -> None:
    value = "  AABBCCDDEEFF00112233445566778899  "

    assert normalize_ioc_value(value, IOCType.MD5) == "aabbccddeeff00112233445566778899"


def test_ipv4_normalization() -> None:
    assert normalize_ioc_value(" 192.168.1.1 ", IOCType.IPV4) == "192.168.1.1"


def test_ipv6_normalization() -> None:
    value = " 2001:0DB8:0000:0000:0000:0000:0000:0001 "

    assert normalize_ioc_value(value, IOCType.IPV6) == "2001:db8::1"


def test_url_whitespace_removal() -> None:
    value = "  HTTPS://Example.COM/path?q=1  "

    assert normalize_ioc_value(value, IOCType.URL) == "HTTPS://Example.COM/path?q=1"


def test_unknown_ioc_handling() -> None:
    assert normalize_ioc_value("  Mixed Value  ", IOCType.UNKNOWN) == "Mixed Value"


def test_ioc_record_default_values() -> None:
    record = IOCRecord(value="example.com", ioc_type=IOCType.DOMAIN, source="test")

    assert record.first_seen is None
    assert record.last_seen is None
    assert record.threat_type is None
    assert record.confidence is None
    assert record.tags == []


def test_ioc_record_tags_are_independent() -> None:
    first = IOCRecord(value="one", ioc_type=IOCType.UNKNOWN, source="test")
    second = IOCRecord(value="two", ioc_type=IOCType.UNKNOWN, source="test")

    first.tags.append("review")

    assert second.tags == []