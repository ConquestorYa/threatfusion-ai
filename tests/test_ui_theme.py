from __future__ import annotations

from threatfusion.ui_theme import (
    THEME_PALETTES,
    VERDICT_COLORS,
    palette,
    safe_text,
)


def test_theme_palettes_define_product_modes() -> None:
    assert {"Dark", "White", "Blue Dark", "Red", "Light"} <= set(THEME_PALETTES)
    assert THEME_PALETTES["Light"] == THEME_PALETTES["White"]
    assert palette("Dark")["bg"] != palette("Light")["bg"]
    assert palette("Dark")["text"] != palette("Light")["text"]


def test_verdict_palette_covers_all_runtime_verdicts() -> None:
    assert set(VERDICT_COLORS) == {
        "Known Threat",
        "High Risk",
        "Review",
        "Low",
    }


def test_safe_text_escapes_dynamic_html() -> None:
    assert safe_text("<script>alert(1)</script>") == (
        "&lt;script&gt;alert(1)&lt;/script&gt;"
    )
