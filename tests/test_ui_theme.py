from __future__ import annotations

import re
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
import streamlit
from streamlit.testing.v1 import AppTest

from threatfusion import ui_theme
from threatfusion.brand_assets import _THREATFUSION_LOGO_SVG, THREATFUSION_LOGO_DATA_URI
from threatfusion.ui_theme import (
    STREAMLIT_THEME_STORAGE_KEY,
    THEME_OPTION_LABELS,
    THEME_OPTIONS,
    THEME_PALETTES,
    VERDICT_COLORS,
    palette,
    safe_text,
    theme_switch_script,
)

ROOT = Path(__file__).resolve().parents[1]


def _ratio(a: str, b: str) -> float:
    def lum(color):
        values = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        lin = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]

    high, low = sorted((lum(a), lum(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_exactly_two_product_themes_with_readable_accent_text() -> None:
    assert set(THEME_PALETTES) == {"Dark", "Light"} == set(THEME_OPTIONS)
    for theme in THEME_OPTIONS:
        colors = palette(theme)
        assert _ratio(colors["on_accent"], colors["cyan"]) >= 4.5
        assert _ratio(colors["logo"], colors["bg"]) >= 4.5


def test_streamlit_native_theme_matches_product_palette() -> None:
    # Dataframes and inputs use Streamlit's theme; it must equal the palette.
    config = tomllib.loads((ROOT / ".streamlit/config.toml").read_text())["theme"]
    assert "base" not in config
    for theme in THEME_OPTIONS:
        native, colors = config[theme.lower()], palette(theme)
        assert native["backgroundColor"] == colors["bg"]
        assert native["textColor"] == colors["text"]
        assert native["primaryColor"] == colors["cyan"]
        assert native["borderColor"] == colors["border"]
        assert native["sidebar"]["backgroundColor"] == colors["bg_alt"]
        for token in ("red", "orange", "yellow", "green", "blue"):
            assert native[f"{token}Color"] == colors[token]


def test_bundled_streamlit_stores_the_theme_under_the_expected_key() -> None:
    static = Path(streamlit.__file__).parent / "static/static/js"
    source = "".join(path.read_text(errors="ignore") for path in static.glob("*.js"))
    match = re.search(r"(\w+)=(\d+),(\w+)=`stActiveTheme-\$\{window\.location\.pathname\}`,"
                      r"\w+=\{CACHED_THEME_VERSION:\1,CACHED_THEME_BASE_KEY:\3,ACTIVE_THEME:`\$\{\3\}-v\$\{\1\}`", source)
    assert match, "Streamlit changed its theme storage; update STREAMLIT_THEME_STORAGE_KEY"
    assert STREAMLIT_THEME_STORAGE_KEY == f"stActiveTheme-{{path}}-v{match.group(2)}"


def test_theme_switch_script_writes_streamlit_choice_and_reloads() -> None:
    script = theme_switch_script("Light")
    assert '"stActiveTheme-" + window.parent.location.pathname + "-v2"' in script
    assert '"\\"Light\\""' in script and "location.reload()" in script
    with pytest.raises(ValueError):
        theme_switch_script("Midnight\"); alert(1); (\"")


def test_active_theme_follows_streamlit(monkeypatch) -> None:
    for kind, expected in (("light", "Light"), ("dark", "Dark"), (None, "Dark")):
        monkeypatch.setattr(ui_theme.st, "context", SimpleNamespace(theme=SimpleNamespace(type=kind)), raising=False)
        assert ui_theme.active_theme() == expected


def test_verdict_palette_covers_all_runtime_verdicts() -> None:
    assert set(VERDICT_COLORS) == {"Known Threat", "High Risk", "Review", "Low"}


def test_safe_text_escapes_dynamic_html() -> None:
    assert safe_text("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_brand_logo_is_simple_vector_without_text_and_theme_tinted() -> None:
    assert THREATFUSION_LOGO_DATA_URI.startswith("data:image/svg+xml")
    assert "base64" not in THREATFUSION_LOGO_DATA_URI
    assert "<text" not in _THREATFUSION_LOGO_SVG and _THREATFUSION_LOGO_SVG.count("<circle") == 4
    assert palette("Dark")["logo"] != palette("Light")["logo"]


def test_controls_have_no_emoji_and_switch_theme_once() -> None:
    assert all(label.isascii() for label in THEME_OPTION_LABELS.values())
    app = AppTest.from_string(
        "from threatfusion.ui_theme import render_main_brand\nrender_main_brand()\n"
    ).run(timeout=15)
    assert not app.exception
    language = next(item for item in app.segmented_control if item.key == "language_selector")
    assert language.options == ["Türkçe", "English"]  # visible labels, no flags
    theme = next(item for item in app.segmented_control if item.key == "visual_theme")
    assert theme.value == "Dark"
    theme.set_value("Light").run(timeout=15)
    assert not app.exception
    assert any("Tema uygulanıyor" in item.value or "Applying theme" in item.value for item in app.caption)
    app.run(timeout=15)
    assert not any("Applying theme" in item.value or "Tema uygulanıyor" in item.value for item in app.caption)
    other = AppTest.from_string(
        "from threatfusion.ui_theme import render_main_brand\nrender_main_brand()\n"
    ).run(timeout=15)
    next(i for i in other.segmented_control if i.key == "language_selector").set_value("🇹🇷 Türkçe").run(timeout=15)
    assert other.session_state["language_selector"] == "🇹🇷 Türkçe" and not other.exception


def test_css_has_no_decorative_effects(monkeypatch) -> None:
    rendered: list[str] = []
    monkeypatch.setattr(ui_theme.st, "markdown", lambda body, **kwargs: rendered.append(body))
    ui_theme.inject_theme_css("Light")
    css = "\n".join(rendered)
    for forbidden in ("text-transform:uppercase", "letter-spacing", "box-shadow", "drop-shadow", "Aptos"):
        assert forbidden not in css
    assert "border-radius:999px" not in css
    assert '"IBM Plex Sans"' in css and '"IBM Plex Mono"' in css
    assert '[data-testid="stBaseButton-primary"]' in css and "var(--tf-on-accent)" in css
    assert palette("Light")["bg"] in css


def test_bundled_fonts_are_served_locally_with_license() -> None:
    config = tomllib.loads((ROOT / ".streamlit/config.toml").read_text())
    assert config["server"]["enableStaticServing"] is True
    faces = config["theme"]["fontFaces"]
    assert {face["family"] for face in faces} == {"IBM Plex Sans", "IBM Plex Mono"}
    for face in faces:
        assert face["url"].startswith("app/static/fonts/")
        assert (ROOT / "static/fonts" / face["url"].rsplit("/", 1)[1]).is_file()
    # Turkish letters (ğ ş İ ı) need the Latin Extended subset.
    assert any("U+0100-02BA" in face["unicodeRange"] for face in faces if face["family"] == "IBM Plex Sans")
    assert config["theme"]["font"].startswith("IBM Plex Sans")
    assert sorted(p.name for p in (ROOT / "static/fonts").glob("OFL-*.txt")) == [
        "OFL-IBM-Plex-Mono.txt", "OFL-IBM-Plex-Sans.txt"]


def test_static_folder_holds_only_public_font_assets() -> None:
    # Streamlit serves ./static without the app's Host guard; keep it to fonts.
    files = [p for p in (ROOT / "static").rglob("*") if p.is_file()]
    assert files and all(p.parent == ROOT / "static/fonts" for p in files)
    assert {p.suffix for p in files} <= {".woff2", ".txt", ".md"}


def test_file_uploader_texts_follow_the_language(monkeypatch) -> None:
    rendered: list[str] = []
    monkeypatch.setattr(ui_theme.st, "markdown", lambda body, **kwargs: rendered.append(body))
    monkeypatch.setattr(ui_theme, "tr", lambda text, **values: {
        "Choose file": 'Dosya "seç"',
    }.get(text, text).format(**values))
    ui_theme.inject_theme_css("Dark")
    css = "\n".join(rendered)
    assert '--tf-upload-button:"Dosya \\"seç\\"";' in css
    assert "up to 100 MB" in css  # From server.maxUploadSize, not hard-coded.
    assert "content:var(--tf-upload-button)" in css and "content:var(--tf-upload-hint)" in css


def test_collector_and_evaluation_pages_explain_themselves_in_turkish(tmp_path) -> None:
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_string(
        "from pathlib import Path\nimport streamlit as st\n"
        "st.session_state['language_selector'] = '🇹🇷 Türkçe'\n"
        "from threatfusion.ui_collector import render_collector\n"
        "from threatfusion.ui_evaluation import _show_model_evaluation\n"
        "render_collector(None, public_mode=False)\n"
        f"_show_model_evaluation(Path({str(tmp_path / 'missing.json')!r}))\n"
    ).run(timeout=15)
    assert not app.exception
    assert [e.label for e in app.expander][:2] == ["Bu sayfa ne işe yarar?"] * 2
    text = "\n".join(m.value for m in app.markdown)
    assert "Veri nereden geliyor" in text and "Neden boş olabilir" in text
    assert "What it is for" not in text
