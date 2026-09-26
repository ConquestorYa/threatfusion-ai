from __future__ import annotations

from threatfusion.brand_assets import THREATFUSION_LOGO_DATA_URI
from threatfusion.ui_theme import (
    THEME_PALETTES,
    VERDICT_COLORS,
    palette,
    safe_text,
)


def test_theme_palettes_define_product_modes() -> None:
    assert {"Midnight", "Crimson", "Violet Noir"} == set(THEME_PALETTES)
    assert palette("Light") == palette("Midnight")
    assert palette("White") == palette("Midnight")
    assert palette("Dark") == palette("Midnight")
    assert palette("Obsidian") == palette("Midnight")
    assert palette("Arctic") == palette("Midnight")
    assert palette("Blue Dark") == palette("Midnight")
    assert palette("Red") == palette("Crimson")
    assert palette("Midnight")["bg"] != palette("Crimson")["bg"]
    assert palette("Midnight")["logo"] != palette("Violet Noir")["logo"]


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


def test_brand_logo_is_vector_and_theme_tinted() -> None:
    assert THREATFUSION_LOGO_DATA_URI.startswith("data:image/svg+xml")
    assert "base64" not in THREATFUSION_LOGO_DATA_URI
    assert len({palette(theme)["logo"] for theme in THEME_PALETTES}) == 3
