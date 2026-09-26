from __future__ import annotations

from threatfusion.ui_theme import (
    THEME_PALETTES,
    VERDICT_COLORS,
    palette,
    safe_text,
)


def test_theme_palettes_define_product_modes() -> None:
    assert {"Obsidian", "Arctic", "Midnight", "Crimson"} == set(THEME_PALETTES)
    assert palette("Light") == palette("Arctic")
    assert palette("White") == palette("Arctic")
    assert palette("Dark") == palette("Obsidian")
    assert palette("Blue Dark") == palette("Midnight")
    assert palette("Red") == palette("Crimson")
    assert palette("Obsidian")["bg"] != palette("Arctic")["bg"]
    assert palette("Obsidian")["text"] != palette("Arctic")["text"]


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
