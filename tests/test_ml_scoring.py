from threatfusion.ml_scoring import evaluate_ml_scoring_eligibility


def test_public_domains_are_eligible_for_ml_scoring() -> None:
    result = evaluate_ml_scoring_eligibility("Example.COM.")

    assert result.eligible is True
    assert result.normalized_domain == "example.com"
    assert result.reason is None


def test_single_label_and_local_names_are_not_scored() -> None:
    single = evaluate_ml_scoring_eligibility("printer")
    local = evaluate_ml_scoring_eligibility("printer.local")
    internal = evaluate_ml_scoring_eligibility("api.corp.internal")

    assert single.reason == "single_label"
    assert local.reason == "non_public_suffix"
    assert internal.reason == "non_public_suffix"


def test_reverse_dns_and_service_discovery_names_are_not_scored() -> None:
    reverse = evaluate_ml_scoring_eligibility(
        "7.113.0.203.in-addr.arpa"
    )
    service = evaluate_ml_scoring_eligibility(
        "_ldap._tcp.example.com"
    )

    assert reverse.eligible is False
    assert reverse.reason == "non_public_suffix"
    assert service.eligible is False
    assert service.reason == "service_discovery"


def test_invalid_public_domain_syntax_is_not_scored() -> None:
    result = evaluate_ml_scoring_eligibility("-invalid.example")

    assert result.eligible is False
    assert result.reason == "invalid_public_domain"
