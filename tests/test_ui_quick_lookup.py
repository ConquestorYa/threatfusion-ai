from threatfusion.ui_quick_lookup import _presentation_for


def test_low_lookup_uses_clear_green_safe_state():
    view = _presentation_for("low")

    assert view.css_class == "safe"
    assert view.icon == "✓"
    assert view.kicker == "Low risk"
    assert view.title == "No threat signal found"


def test_review_lookup_uses_warning_state():
    view = _presentation_for("review")

    assert view.css_class == "review"
    assert view.icon == "!"
    assert view.kicker == "Review recommended"


def test_high_risk_lookup_uses_danger_state():
    view = _presentation_for("high_risk")

    assert view.css_class == "danger"
    assert view.icon == "!"
    assert view.kicker == "High risk"


def test_known_threat_lookup_uses_critical_state():
    view = _presentation_for("known_threat")

    assert view.css_class == "critical"
    assert view.icon == "×"
    assert view.kicker == "Known threat"
    assert "Threat intelligence match" in view.title


def test_unknown_lookup_falls_back_to_review_state():
    view = _presentation_for("unexpected_state")

    assert view.css_class == "review"
    assert view.kicker == "Unknown"
