from copy import deepcopy

import pytest

from threatfusion.ui_components import filter_findings, source_status_html
from threatfusion.ui_theme import (
    THEME_OPTIONS,
    apply_plotly_theme,
    canonical_theme_name,
    palette,
    verdict_colors,
)


def test_filters_use_literal_search_and_preserve_data_and_order():
    rows = [
        {
            "Domain": "a[1].example",
            "Verdict": "Known Threat",
            "Known CTI sources": "ThreatFox, SGB",
        },
        {"Domain": "b.example", "Verdict": "High Risk", "Known CTI sources": "URLhaus"},
        {"Domain": "c.example", "Verdict": "Review", "Known CTI sources": ""},
    ]
    before = deepcopy(rows)
    assert filter_findings(rows, query="[1]") == [rows[0]]
    assert filter_findings(rows, query=" A[1].EXAMPLE ", source="SGB") == [rows[0]]
    assert filter_findings(rows, source="Threat") == []
    assert filter_findings(rows, verdict="Low") == []
    assert rows == before


@pytest.mark.parametrize("status", ["Fresh", "Stale", "Unknown", "Not cached"])
def test_source_status_keeps_backend_state_and_escapes_metadata(status):
    row = {
        "Source": '<script>alert("source")</script>',
        "Status": status,
        "Records": 8590,
        "Age": "3.0 h",
    }
    rendered = source_status_html(row)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "8,590 active indicators" in rendered
    assert "Updated 3h ago" in rendered
    assert status in rendered
    assert "<table" not in rendered


@pytest.mark.parametrize("theme", THEME_OPTIONS)
def test_text_and_verdict_tokens_meet_normal_text_contrast(theme):
    def luminance(hex_color):
        values = [int(hex_color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [
            v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values
        ]
        return sum(a * b for a, b in zip(linear, (0.2126, 0.7152, 0.0722)))

    colors = palette(theme)
    for foreground in [
        colors["text"],
        colors["muted"],
        *verdict_colors(theme).values(),
    ]:
        for background in [
            colors["bg"],
            colors["bg_alt"],
            colors["panel"],
            colors["panel_alt"],
            colors["surface"],
            colors["input_bg"],
        ]:
            a, b = sorted((luminance(foreground), luminance(background)))
            assert (b + 0.05) / (a + 0.05) >= 4.5




def test_visual_theme_choices_match_product_ui():
    assert THEME_OPTIONS == ("Midnight", "Crimson", "Violet Noir")
    assert canonical_theme_name("Dark") == "Midnight"
    assert canonical_theme_name("White") == "Midnight"
    assert canonical_theme_name("Arctic") == "Midnight"
    assert canonical_theme_name("Blue Dark") == "Midnight"
    assert canonical_theme_name("Red") == "Crimson"
    assert palette("Light") == palette("Midnight")


def test_each_theme_has_a_distinct_logo_tint_and_input_surface():
    logo_colors = {palette(theme)["logo"] for theme in THEME_OPTIONS}
    assert len(logo_colors) == len(THEME_OPTIONS)
    for theme in THEME_OPTIONS:
        colors = palette(theme)
        assert colors["input_bg"] != colors["surface"]


def test_violet_noir_theme_is_distinctly_purple_black():
    colors = palette("Violet Noir")
    assert colors["bg"] == "#09070F"
    assert colors["panel"] == "#171022"
    assert colors["cyan"] == "#A97BFF"
    assert colors["logo"] == "#B98CFF"


def test_distribution_keeps_semantic_colors_with_native_theme_text():
    from types import SimpleNamespace

    from threatfusion.ui_charts import _verdict_distribution_figure
    from threatfusion.ui_theme import VERDICT_COLORS

    figure = _verdict_distribution_figure(
        SimpleNamespace(
            known_threat_count=1,
            high_risk_count=2,
            review_count=3,
            low_count=4,
            domain_count=10,
        )
    )
    pie = figure.data[0]
    assert list(pie.values) == [1, 2, 3, 4]
    assert dict(zip(pie.labels, pie.marker.colors)) == VERDICT_COLORS
    assert figure.layout.font.color is not None


def test_plotly_theme_uses_selected_product_palette():
    import plotly.graph_objects as go

    figure = apply_plotly_theme(go.Figure(), theme="Violet Noir")

    assert figure.layout.font.color == palette("Violet Noir")["text"]
    assert figure.layout.hoverlabel.bgcolor == palette("Violet Noir")["panel"]
    assert figure.layout.xaxis.gridcolor == palette("Violet Noir")["grid"]


def test_loaded_evaluation_preserves_operating_points_and_source_diagnostics(tmp_path):
    import json
    import runpy
    from dataclasses import asdict
    from pathlib import Path

    from streamlit.testing.v1 import AppTest

    fixture = runpy.run_path(
        str(Path(__file__).with_name("test_evaluation_dashboard.py"))
    )
    report = fixture["report"]()
    report_path = tmp_path / "synthetic-holdout.json"
    report_path.write_text(json.dumps(asdict(report)), encoding="utf-8")
    app = AppTest.from_string(
        "from pathlib import Path\n"
        "from threatfusion.ui_evaluation import _show_model_evaluation\n"
        f"_show_model_evaluation(Path({str(report_path)!r}))"
    ).run(timeout=15)
    assert not app.exception
    assert len(app.dataframe) == 2
    assert list(app.dataframe[0].value["Threshold"]) == [
        "0.800000",
        "0.600000",
        "0.500000",
    ]
    assert "n/a" in app.dataframe[1].value.to_numpy()
    assert any("Source-aware" in item.label for item in app.expander)
    assert any("operational positive predictive" in item.value for item in app.info)
