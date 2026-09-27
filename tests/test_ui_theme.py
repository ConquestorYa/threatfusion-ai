from __future__ import annotations

from streamlit.testing.v1 import AppTest

from threatfusion.brand_assets import THREATFUSION_LOGO_DATA_URI
from threatfusion.ui_theme import (
    THEME_OPTIONS,
    THEME_PALETTES,
    VERDICT_COLORS,
    palette,
    safe_text,
)


def test_theme_palettes_define_product_modes() -> None:
    assert {"Midnight", "Crimson", "Violet Noir", "Monochrome"} == set(THEME_PALETTES)
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
    assert len({palette(theme)["logo"] for theme in THEME_PALETTES}) == 4


def test_language_segmented_control_is_required() -> None:
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from threatfusion.ui_theme import render_main_brand\n"
        "render_main_brand()\n"
    ).run(timeout=15)

    assert not app.exception
    language = next(
        item for item in app.segmented_control if item.key == "language_selector"
    )
    language.set_value("🇹🇷 Türkçe").run(timeout=15)
    assert app.session_state["language_selector"] == "🇹🇷 Türkçe"

    language = next(
        item for item in app.segmented_control if item.key == "language_selector"
    )
    language.set_value("🇹🇷 Türkçe").run(timeout=15)
    assert app.session_state["language_selector"] == "🇹🇷 Türkçe"


def test_theme_picker_is_non_editable_prominent_and_updates_state() -> None:
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from threatfusion.ui_theme import render_main_brand\n"
        "st.session_state.setdefault('visual_theme', 'Midnight')\n"
        "render_main_brand()\n"
    ).run(timeout=15)

    assert not app.exception
    assert not any(item.key == "visual_theme" for item in app.selectbox)
    assert not any(item.key == "visual_theme" for item in app.radio)
    assert not any(button.label == "Apply" for button in app.button)

    theme = next(
        item for item in app.segmented_control if item.key == "visual_theme"
    )
    assert theme.value == "Midnight"
    assert list(theme.options) == list(THEME_OPTIONS)
    theme.set_value("Monochrome").run(timeout=15)

    assert not app.exception
    assert app.session_state["visual_theme"] == "Monochrome"


def test_monochrome_theme_is_black_white_and_grayscale() -> None:
    colors = palette("Monochrome")

    assert colors["bg"] == "#000000"
    assert colors["text"] == "#F8F8F8"
    assert colors["logo"] == "#FFFFFF"
    assert colors["cyan"] == "#FFFFFF"
    assert colors["panel"] == "#0A0A0A"
    assert colors["border"] == "#343434"


def test_monochrome_verdict_palette_is_grayscale() -> None:
    from threatfusion.ui_theme import verdict_colors

    colors = verdict_colors("Monochrome")
    assert colors == {
        "Known Threat": "#FFFFFF",
        "High Risk": "#E2E2E2",
        "Review": "#CFCFCF",
        "Low": "#B8B8B8",
    }
