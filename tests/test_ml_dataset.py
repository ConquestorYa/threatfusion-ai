import socket

import pytest

from threatfusion.ml_dataset import (
    DomainSample,
    build_benign_samples,
    build_domain_dataset,
    extract_malicious_domains,
)
from threatfusion.models import IOCRecord, IOCType


def test_domain_ioc_becomes_malicious_sample() -> None:
    indicator = IOCRecord("Example.COM.", IOCType.DOMAIN, "ThreatFox")

    samples = extract_malicious_domains([indicator])

    assert samples == [DomainSample(domain="example.com", label=1, source="ThreatFox")]


def test_url_ioc_hostname_becomes_malicious_sample() -> None:
    indicator = IOCRecord("https://Evil.Example/path/file.exe", IOCType.URL, "URLhaus")

    samples = extract_malicious_domains([indicator])

    assert samples == [DomainSample(domain="evil.example", label=1, source="URLhaus")]


def test_url_ioc_ip_literal_hostname_is_excluded() -> None:
    indicators = [
        IOCRecord("http://203.0.113.7/payload", IOCType.URL, "URLhaus"),
        IOCRecord("http://[2001:db8::7]/payload", IOCType.URL, "URLhaus"),
    ]

    assert extract_malicious_domains(indicators) == []


def test_malformed_url_ioc_is_ignored_safely() -> None:
    indicator = IOCRecord("http://[::1", IOCType.URL, "ThreatFox")

    assert extract_malicious_domains([indicator]) == []


def test_ip_hash_and_unknown_ioc_types_are_ignored() -> None:
    indicators = [
        IOCRecord("203.0.113.7", IOCType.IPV4, "ThreatFox"),
        IOCRecord("2001:db8::1", IOCType.IPV6, "SGB"),
        IOCRecord("abcdef0123456789", IOCType.SHA256, "ThreatFox"),
        IOCRecord("example.com", IOCType.UNKNOWN, "URLhaus"),
    ]

    assert extract_malicious_domains(indicators) == []


def test_domain_normalization_is_applied() -> None:
    indicator = IOCRecord("  BAD.EXAMPLE.  ", IOCType.DOMAIN, "SGB")

    samples = extract_malicious_domains([indicator])

    assert samples == [DomainSample(domain="bad.example", label=1, source="SGB")]


def test_case_variants_and_trailing_dots_deduplicate() -> None:
    malicious = [
        DomainSample("Example.COM", 1, "ThreatFox"),
        DomainSample("example.com.", 1, "SGB"),
        DomainSample("example.com", 1, "URLhaus"),
    ]

    dataset = build_domain_dataset(malicious, [])

    assert dataset == [DomainSample("example.com", 1, "ThreatFox")]


def test_same_malicious_source_duplicates_are_removed() -> None:
    malicious = [
        DomainSample("example.com", 1, "ThreatFox"),
        DomainSample("example.com", 1, "ThreatFox"),
        DomainSample("example.com", 1, "ThreatFox"),
    ]

    assert build_domain_dataset(malicious, []) == [
        DomainSample("example.com", 1, "ThreatFox")
    ]


def test_duplicates_across_sources_are_deduplicated_for_dataset() -> None:
    malicious = [
        DomainSample("example.com", 1, "ThreatFox"),
        DomainSample("EXAMPLE.COM.", 1, "SGB"),
        DomainSample("example.com", 1, "URLhaus"),
    ]

    assert build_domain_dataset(malicious, []) == [
        DomainSample("example.com", 1, "ThreatFox")
    ]


def test_benign_domains_get_label_zero() -> None:
    samples = build_benign_samples(["Example.COM.", "safe.example", "  ", "bad.example"])

    assert samples == [
        DomainSample("example.com", 0, "Tranco"),
        DomainSample("safe.example", 0, "Tranco"),
        DomainSample("bad.example", 0, "Tranco"),
    ]


def test_benign_ip_literals_are_rejected() -> None:
    assert build_benign_samples(["203.0.113.7", "2001:db8::7", "safe.example"]) == [
        DomainSample("safe.example", 0, "Tranco")
    ]


def test_malicious_domains_get_label_one() -> None:
    sample = extract_malicious_domains([IOCRecord("mal.example", IOCType.DOMAIN, "ThreatFox")])[0]

    assert sample.label == 1


def test_malicious_benign_overlap_keeps_only_malicious() -> None:
    malicious = [DomainSample("example.com", 1, "ThreatFox")]
    benign = [
        DomainSample("example.com", 0, "Tranco"),
        DomainSample("safe.example", 0, "Tranco"),
    ]

    dataset = build_domain_dataset(malicious, benign)

    assert dataset == [
        DomainSample("example.com", 1, "ThreatFox"),
        DomainSample("safe.example", 0, "Tranco"),
    ]


def test_dataset_enforces_labels_from_input_roles() -> None:
    malicious = [DomainSample("evil.example", 0, "ThreatFox")]
    benign = [DomainSample("safe.example", 1, "Tranco")]

    assert build_domain_dataset(malicious, benign) == [
        DomainSample("evil.example", 1, "ThreatFox"),
        DomainSample("safe.example", 0, "Tranco"),
    ]


def test_dataset_consumes_generators_once_and_preserves_order() -> None:
    malicious = (
        sample
        for sample in [
            DomainSample("first.example", 0, "ThreatFox"),
            DomainSample("overlap.example", 1, "SGB"),
        ]
    )
    benign = (
        sample
        for sample in [
            DomainSample("overlap.example", 0, "Tranco"),
            DomainSample("safe.example", 1, "Tranco"),
        ]
    )

    assert build_domain_dataset(malicious, benign) == [
        DomainSample("first.example", 1, "ThreatFox"),
        DomainSample("overlap.example", 1, "SGB"),
        DomainSample("safe.example", 0, "Tranco"),
    ]


def test_empty_benign_values_are_skipped() -> None:
    samples = build_benign_samples(["", "  ", "example.com", "example.com", "bad.example"])

    assert samples == [
        DomainSample("example.com", 0, "Tranco"),
        DomainSample("bad.example", 0, "Tranco"),
    ]


def test_deterministic_ordering_is_preserved() -> None:
    malicious = [
        DomainSample("beta.example", 1, "ThreatFox"),
        DomainSample("alpha.example", 1, "SGB"),
    ]
    benign = [
        DomainSample("gamma.example", 0, "Tranco"),
        DomainSample("alpha.example", 0, "Tranco"),
    ]

    dataset = build_domain_dataset(malicious, benign)

    assert [sample.domain for sample in dataset] == [
        "beta.example",
        "alpha.example",
        "gamma.example",
    ]


def test_original_ioc_values_are_not_mutated() -> None:
    indicator = IOCRecord("  Example.COM.  ", IOCType.DOMAIN, "ThreatFox")

    extract_malicious_domains([indicator])

    assert indicator.value == "  Example.COM.  "


def test_no_networking_is_performed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access should not occur in dataset preparation")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    indicator = IOCRecord("https://evil.example/path", IOCType.URL, "ThreatFox")

    samples = extract_malicious_domains([indicator])

    assert samples == [DomainSample("evil.example", 1, "ThreatFox")]


def test_empty_inputs_are_safe() -> None:
    assert extract_malicious_domains([]) == []
    assert build_benign_samples([]) == []
    assert build_domain_dataset([], []) == []
