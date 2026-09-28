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


def test_ml_signal_presentation_converts_model_score_to_clear_zero_to_100_scale():
    from types import SimpleNamespace

    from threatfusion.ui_quick_lookup import _ml_signal_presentation

    result = SimpleNamespace(
        ml_score=0.42,
        ml_tier=None,
    )

    tone, level, subtitle, score, explanation = _ml_signal_presentation(result)

    assert tone == "safe"
    assert level == "Minimal"
    assert subtitle == "Below review threshold"
    assert score == 42
    assert "did not raise" in explanation


def test_known_threat_neutralizes_ml_risk_presentation():
    from types import SimpleNamespace

    from threatfusion.ui_quick_lookup import _ml_signal_presentation

    result = SimpleNamespace(
        verdict=SimpleNamespace(value="known_threat"),
        ml_score=0.50,
        ml_tier=None,
    )

    tone, level, subtitle, score, explanation = _ml_signal_presentation(result)

    assert tone == "neutral"
    assert level == "Context only"
    assert subtitle == "Final decision comes from CTI"
    assert score == 50
    assert "does not override the CTI verdict" in explanation


def test_ml_signal_presentation_keeps_existing_high_tier_semantics():
    from types import SimpleNamespace

    from threatfusion.ui_quick_lookup import _ml_signal_presentation

    result = SimpleNamespace(
        ml_score=0.87,
        ml_tier="high",
    )

    tone, level, subtitle, score, explanation = _ml_signal_presentation(result)

    assert tone == "danger"
    assert level == "High"
    assert subtitle == "Strong model signal"
    assert score == 87
    assert "high review threshold" in explanation
