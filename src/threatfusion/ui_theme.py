"""Shared presentation tokens and small, escaped Streamlit components."""

from __future__ import annotations

import html

import plotly.graph_objects as go
import streamlit as st

from .brand_assets import THREATFUSION_LOGO_DATA_URI

THEME_OPTIONS = ("Obsidian", "Arctic", "Midnight", "Crimson")

_LEGACY_THEME_NAMES = {
    "Dark": "Obsidian",
    "White": "Arctic",
    "Light": "Arctic",
    "Blue Dark": "Midnight",
    "Red": "Crimson",
}

THEME_PALETTES = {
    "Obsidian": {
        "bg": "#0C121C",
        "bg_alt": "#101923",
        "panel": "#141F2C",
        "panel_alt": "#182534",
        "surface": "#213143",
        "input_bg": "#111C28",
        "border": "#2C3C4E",
        "text": "#E5ECF4",
        "muted": "#A0AFC1",
        "cyan": "#53C9BE",
        "cyan_soft": "rgba(83, 201, 190, 0.09)",
        "logo": "#62D5CA",
        "on_accent": "#0C121C",
        "green": "#81CAA3",
        "yellow": "#E8C76A",
        "orange": "#F4A26D",
        "red": "#FA8991",
        "blue": "#97B6D5",
        "grid": "rgba(160, 175, 193, 0.12)",
        "plot_template": "plotly_dark",
        "scheme": "dark",
    },
    "Arctic": {
        "bg": "#EEF4F8",
        "bg_alt": "#E3EDF4",
        "panel": "#F8FBFD",
        "panel_alt": "#EDF4F8",
        "surface": "#D8E6EF",
        "input_bg": "#F7FBFE",
        "border": "#AFC2D0",
        "text": "#183246",
        "muted": "#4B6578",
        "cyan": "#096A77",
        "cyan_soft": "rgba(9, 106, 119, 0.09)",
        "logo": "#0A7282",
        "on_accent": "#FFFFFF",
        "green": "#1F6B4B",
        "yellow": "#795A00",
        "orange": "#9A4618",
        "red": "#A72D3A",
        "blue": "#305F86",
        "grid": "rgba(72, 97, 116, 0.14)",
        "plot_template": "plotly_white",
        "scheme": "light",
    },
    "Midnight": {
        "bg": "#071525",
        "bg_alt": "#0B1D31",
        "panel": "#10243A",
        "panel_alt": "#15304A",
        "surface": "#1C3B58",
        "input_bg": "#0C2136",
        "border": "#2E4C68",
        "text": "#E8F2FF",
        "muted": "#9EB4CA",
        "cyan": "#62B8FF",
        "cyan_soft": "rgba(98, 184, 255, 0.11)",
        "logo": "#69C1FF",
        "on_accent": "#06121F",
        "green": "#83D8AE",
        "yellow": "#F0D074",
        "orange": "#FFA36C",
        "red": "#FF8791",
        "blue": "#91C6F4",
        "grid": "rgba(158, 180, 202, 0.14)",
        "plot_template": "plotly_dark",
        "scheme": "dark",
    },
    "Crimson": {
        "bg": "#170B10",
        "bg_alt": "#211017",
        "panel": "#2A141D",
        "panel_alt": "#341925",
        "surface": "#44202E",
        "input_bg": "#26121B",
        "border": "#5A3040",
        "text": "#F7EAF0",
        "muted": "#C7A6B4",
        "cyan": "#E9687B",
        "cyan_soft": "rgba(233, 104, 123, 0.12)",
        "logo": "#F06D80",
        "on_accent": "#18090E",
        "green": "#8FD2A4",
        "yellow": "#F0C972",
        "orange": "#F09A6C",
        "red": "#FF8791",
        "blue": "#D8A0B5",
        "grid": "rgba(199, 166, 180, 0.13)",
        "plot_template": "plotly_dark",
        "scheme": "dark",
    },
}

_VERDICT_TOKENS = {
    "Known Threat": "red",
    "High Risk": "orange",
    "Review": "yellow",
    "Low": "green",
}
_VERDICT_CLASSES = {
    "Known Threat": "critical",
    "High Risk": "high",
    "Review": "review",
    "Low": "low",
}
# Chart fills retain semantic colors during native theme transitions.
VERDICT_COLORS = {
    "Known Threat": "#D95264",
    "High Risk": "#C87535",
    "Review": "#A78A2E",
    "Low": "#388563",
}


def canonical_theme_name(theme: str) -> str:
    """Map legacy theme labels to the current product-facing names."""
    return _LEGACY_THEME_NAMES.get(theme, theme)


def active_theme() -> str:
    """Return the explicit ThreatFusion theme, falling back to native mode."""
    selected = st.session_state.get("visual_theme")
    if isinstance(selected, str):
        canonical = canonical_theme_name(selected)
        if canonical in THEME_OPTIONS:
            return canonical
    try:
        theme_type = st.context.theme.type
    except (AttributeError, TypeError):
        theme_type = "dark"
    return "Arctic" if theme_type == "light" else "Obsidian"


def palette(theme: str | None = None) -> dict[str, str]:
    selected = canonical_theme_name(theme) if theme is not None else active_theme()
    return THEME_PALETTES[selected]


def verdict_colors(theme: str | None = None) -> dict[str, str]:
    colors = palette(theme)
    return {label: colors[token] for label, token in _VERDICT_TOKENS.items()}


def safe_text(value: object) -> str:
    return html.escape(str(value))


def inject_theme_css(theme: str | None = None) -> None:
    selected = theme or active_theme()
    colors = palette(selected)
    variables = ";".join(
        f"--tf-{key.replace('_', '-')}:{value}"
        for key, value in colors.items()
        if key not in {"plot_template", "scheme"}
    )
    st.markdown(
        "<style>:root{"
        + variables
        + f";color-scheme:{colors['scheme']};"
        + "}"
        + _CSS
        + "</style>",
        unsafe_allow_html=True,
    )


_CSS = """
:root {
    --tf-font-ui:"Aptos","Segoe UI Variable","Segoe UI",system-ui,-apple-system,sans-serif;
    --tf-font-display:"Aptos Display","Aptos","Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;
}
[data-testid="stAppViewContainer"] {
    background:var(--tf-bg);
    color:var(--tf-text);
    font-family:var(--tf-font-ui);
}
[data-testid="stAppViewContainer"] button,
[data-testid="stAppViewContainer"] input,
[data-testid="stAppViewContainer"] textarea,
[data-testid="stAppViewContainer"] label,
[data-testid="stSidebar"] {
    font-family:var(--tf-font-ui)!important;
}
[data-testid="stHeader"] { background:var(--tf-bg); }
[data-testid="stSidebar"] {
    background:var(--tf-bg-alt); border-right:1px solid var(--tf-border);
}
.block-container { max-width:1440px; padding-top:4.5rem; padding-bottom:3rem; }
h1,h2,h3,.tf-page-head,.tf-sidebar-brand,.tf-product-brand { font-family:var(--tf-font-display); }
h1 { font-size:1.8rem!important; line-height:1.25!important; letter-spacing:-.03em; }
h2 { font-size:1.3rem!important; line-height:1.35!important; }
h3 { font-size:1.06rem!important; line-height:1.4!important; }
.tf-page-head { padding:0 0 1.2rem; border-bottom:1px solid var(--tf-border); margin-bottom:1.1rem; }
.tf-page-head h1 { margin:0; padding:.15rem 0; color:var(--tf-text); }
.tf-page-head p { margin:.35rem 0 0; color:var(--tf-muted); font-size:.95rem; line-height:1.6; }
.tf-eyebrow,.tf-section-label {
    color:var(--tf-muted); font-size:.75rem; font-weight:600;
    text-transform:uppercase; letter-spacing:.09em;
}
.tf-section-label { margin:1.15rem 0 .65rem; }
.tf-sidebar-brand { display:flex; align-items:center; gap:.7rem; margin:0 0 1.15rem; }
.tf-sidebar-brand-logo {
    width:2.65rem;
    height:2.3rem;
    flex:0 0 auto;
    background:var(--tf-logo);
    -webkit-mask:var(--tf-brand-logo) center / contain no-repeat;
    mask:var(--tf-brand-logo) center / contain no-repeat;
    filter:drop-shadow(0 5px 12px rgba(0,0,0,.16));
}
.tf-sidebar-brand-title { font-size:1rem; font-weight:650; color:var(--tf-text); }
.tf-sidebar-brand-sub { color:var(--tf-muted); font-size:.75rem; margin-top:.1rem; }

.st-key-product_topbar {
    margin:-.45rem 0 1.15rem;
    padding:.2rem 0 1rem;
    border-bottom:1px solid var(--tf-border);
}
.tf-product-brand {
    display:flex;
    align-items:center;
    gap:1rem;
    min-height:4rem;
}
.tf-product-brand-main {
    display:flex;
    align-items:center;
    gap:.9rem;
    min-width:0;
}
.tf-product-brand-logo {
    flex:0 0 auto;
    width:4rem;
    height:3.4rem;
    background:var(--tf-logo);
    -webkit-mask:var(--tf-brand-logo) center / contain no-repeat;
    mask:var(--tf-brand-logo) center / contain no-repeat;
    filter:drop-shadow(0 8px 20px rgba(0,0,0,.18));
    transition:background-color .18s ease;
}
.st-key-theme_picker [data-testid="stHorizontalBlock"] {
    align-items:center;
}
.tf-theme-picker-label {
    color:var(--tf-muted);
    font-size:.72rem;
    font-weight:750;
    letter-spacing:.08em;
    text-transform:uppercase;
    text-align:right;
    margin:0;
    line-height:1;
    white-space:nowrap;
}
.st-key-visual_theme {
    display:flex;
    justify-content:flex-end;
    align-items:center;
    margin:0;
}
.st-key-visual_theme [role="radiogroup"] {
    justify-content:flex-end;
}
.st-key-visual_theme button {
    background:var(--tf-panel)!important;
    color:var(--tf-text)!important;
    border-color:var(--tf-border)!important;
    min-height:38px!important;
}
.st-key-visual_theme button[aria-pressed="true"],
.st-key-visual_theme button[data-selected="true"] {
    background:var(--tf-cyan-soft)!important;
    color:var(--tf-cyan)!important;
    border-color:color-mix(in srgb, var(--tf-cyan) 56%, var(--tf-border))!important;
}
.tf-product-brand-title {
    color:var(--tf-text);
    font-size:1.55rem;
    font-weight:780;
    line-height:1.1;
    letter-spacing:-.03em;
}
.tf-product-brand-sub {
    color:var(--tf-muted);
    font-family:var(--tf-font-ui);
    font-size:.82rem;
    line-height:1.4;
    margin-top:.28rem;
}
.tf-product-brand-badge {
    flex:0 0 auto;
    padding:.38rem .62rem;
    border:1px solid var(--tf-border);
    border-radius:999px;
    color:var(--tf-muted);
    font-family:var(--tf-font-ui);
    font-size:.7rem;
    font-weight:650;
    letter-spacing:.06em;
    text-transform:uppercase;
}

.tf-primary-workspace {
    margin:0 0 1.5rem;
    padding:1.15rem 1.2rem 1.25rem;
    border:1px solid var(--tf-border);
    border-radius:14px;
    background:color-mix(in srgb, var(--tf-panel) 94%, var(--tf-cyan-soft));
}
.tf-primary-workspace-head {
    display:flex;
    align-items:flex-end;
    justify-content:space-between;
    gap:1rem;
    margin-bottom:.9rem;
}
.tf-primary-workspace-kicker {
    color:var(--tf-cyan);
    font-size:.72rem;
    font-weight:700;
    letter-spacing:.09em;
    text-transform:uppercase;
}
.tf-primary-workspace-title {
    color:var(--tf-text);
    font-size:1.15rem;
    font-weight:700;
    letter-spacing:-.015em;
    margin-top:.2rem;
}
.tf-primary-workspace-hint {
    color:var(--tf-muted);
    font-size:.78rem;
    text-align:right;
    max-width:26rem;
}
.tf-primary-card {
    min-height:132px;
    padding:1rem 1.05rem;
    border:1px solid var(--tf-border);
    border-radius:11px;
    background:var(--tf-bg-alt);
    transition:border-color .15s ease, background .15s ease, transform .15s ease;
}
.tf-primary-card--active {
    border-color:color-mix(in srgb, var(--tf-cyan) 62%, var(--tf-border));
    background:color-mix(in srgb, var(--tf-cyan-soft) 72%, var(--tf-bg-alt));
    box-shadow:inset 0 0 0 1px color-mix(in srgb, var(--tf-cyan) 14%, transparent);
}
.tf-primary-card-top {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:.75rem;
}
.tf-primary-card-number {
    color:var(--tf-cyan);
    font-size:.72rem;
    font-weight:700;
    letter-spacing:.08em;
}
.tf-primary-card-state {
    color:var(--tf-muted);
    font-size:.7rem;
    font-weight:600;
    text-transform:uppercase;
    letter-spacing:.07em;
}
.tf-primary-card--active .tf-primary-card-state { color:var(--tf-cyan); }
.tf-primary-card-title {
    color:var(--tf-text);
    font-size:1.08rem;
    font-weight:700;
    margin-top:.65rem;
}
.tf-primary-card-copy {
    color:var(--tf-muted);
    font-size:.8rem;
    line-height:1.5;
    margin-top:.3rem;
}
.tf-primary-card-tags {
    display:flex;
    flex-wrap:wrap;
    gap:.35rem;
    margin-top:.7rem;
}
.tf-primary-card-tag {
    padding:.16rem .42rem;
    border:1px solid var(--tf-border);
    border-radius:999px;
    color:var(--tf-muted);
    font-size:.68rem;
}
.st-key-open_telemetry_workspace button,
.st-key-open_quick_lookup_workspace button {
    min-height:48px!important;
    border-radius:9px!important;
    font-weight:700!important;
    margin-top:.2rem;
}

.st-key-workspace_nav [data-testid="stRadio"] label {
    padding:.5rem .65rem; border-radius:6px; margin:0; min-height:42px;
}
.st-key-workspace_nav [data-testid="stRadio"] label:has(input:checked) {
    background:var(--tf-cyan-soft); color:var(--tf-cyan);
}
.tf-status-card {
    display:grid; grid-template-columns:.6rem 1fr auto; gap:.45rem;
    align-items:center; padding:.5rem 0; font-size:.78rem;
}
.tf-status-label { color:var(--tf-muted); }
.tf-status-value { font-weight:600; text-align:right; }
.tf-status-dot { font-size:.65rem; }
.tf-tone-good { color:var(--tf-green); }
.tf-tone-warn { color:var(--tf-yellow); }
.tf-tone-info { color:var(--tf-muted); }
.tf-tone-bad { color:var(--tf-red); }
.tf-source { padding:.65rem 0 .35rem; border-top:1px solid var(--tf-border); }
.tf-source-heading { display:flex; justify-content:space-between; gap:.65rem; font-size:.85rem; }
.tf-source-name { color:var(--tf-text); font-weight:600; overflow-wrap:anywhere; }
.tf-source-count { color:var(--tf-text); font-size:.8rem; margin-top:.35rem; }
.tf-source-age { color:var(--tf-muted); font-size:.75rem; margin-top:.1rem; }
.tf-metric-card { padding:.5rem .65rem .65rem 0; border-bottom:2px solid var(--tf-accent,var(--tf-border)); }
.tf-metric-label { color:var(--tf-muted); font-size:.78rem; line-height:1.5; }
.tf-metric-value { color:var(--tf-text); font-size:1.5rem; line-height:1.5; font-weight:600; overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
.tf-metric-text { font-size:.95rem; font-weight:500; line-height:1.6; padding:.3rem 0; }
.tf-metric-sub { color:var(--tf-muted); font-size:.75rem; margin-top:.2rem; }
.tf-finding-row {
    display:grid; grid-template-columns:minmax(0,1.2fr) auto minmax(0,1fr);
    gap:1rem; align-items:center; border-bottom:1px solid var(--tf-border);
    border-left:3px solid var(--tf-row-accent); padding:.85rem 1rem;
    background:var(--tf-panel);
}
.tf-finding-domain,.tf-domain-name {
    font-family:ui-monospace,"Cascadia Code",Consolas,monospace;
    color:var(--tf-text); overflow-wrap:anywhere;
}
.tf-finding-domain { font-size:.88rem; font-weight:600; }
.tf-finding-meta { font-size:.75rem; color:var(--tf-muted); margin-top:.3rem; line-height:1.5; }
.tf-finding-evidence { color:var(--tf-muted); font-size:.8rem; line-height:1.5; overflow-wrap:anywhere; }
.tf-badge {
    display:inline-block; padding:.15rem .45rem; border-radius:4px;
    font-size:.75rem; font-weight:600; line-height:1.5; white-space:nowrap;
    background:var(--tf-bg-alt);
}
.tf-badge-critical { color:var(--tf-red); }
.tf-badge-high { color:var(--tf-orange); }
.tf-badge-review { color:var(--tf-yellow); }
.tf-badge-low { color:var(--tf-green); }
.tf-badge-neutral { color:var(--tf-muted); }
.tf-investigation-head {
    display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;
    padding:.4rem 0 1rem; border-bottom:1px solid var(--tf-border); margin-bottom:1rem;
}
.tf-domain-name { font-size:1.05rem; font-weight:600; margin-top:.35rem; }
.tf-steps {
    display:grid;
    grid-template-columns:repeat(3,minmax(0,1fr));
    gap:.8rem;
    margin:.65rem 0 1.35rem;
}
.tf-step {
    display:flex;
    gap:.8rem;
    align-items:flex-start;
    min-height:92px;
    padding:.9rem 1rem;
    border:1px solid var(--tf-border);
    border-radius:10px;
    background:var(--tf-bg-alt);
}
.tf-step--active {
    border-color:color-mix(in srgb, var(--tf-cyan) 52%, var(--tf-border));
    background:color-mix(in srgb, var(--tf-cyan-soft) 72%, var(--tf-bg-alt));
    box-shadow:inset 0 0 0 1px color-mix(in srgb, var(--tf-cyan) 10%, transparent);
}
.tf-step-number {
    flex:0 0 auto;
    display:grid;
    place-items:center;
    width:2.25rem;
    height:2.25rem;
    border-radius:999px;
    border:1px solid color-mix(in srgb, var(--tf-cyan) 42%, var(--tf-border));
    background:color-mix(in srgb, var(--tf-cyan) 14%, transparent);
    color:var(--tf-cyan);
    font-size:.8rem;
    font-weight:800;
}
.tf-step-title {
    color:var(--tf-text);
    font-size:.92rem;
    font-weight:700;
    line-height:1.35;
}
.tf-step-sub {
    color:var(--tf-muted);
    font-size:.75rem;
    line-height:1.45;
    margin-top:.22rem;
}
.tf-empty { padding:1.25rem 0; color:var(--tf-muted); border-top:1px solid var(--tf-border); }
.tf-empty strong { display:block; color:var(--tf-text); font-size:.95rem; margin-bottom:.35rem; }
.tf-empty p { font-size:.85rem; margin:0; line-height:1.6; }
.tf-privacy { color:var(--tf-muted); font-size:.78rem; line-height:1.6; margin:.45rem 0; }

/* Quick lookup: one clear outcome first, then evidence. Inspired by the
   simplicity of breach-check tools without copying their branding or layout. */
.tf-lookup-result {
    --tf-lookup-accent:var(--tf-blue);
    --tf-lookup-soft:color-mix(in srgb, var(--tf-lookup-accent) 10%, transparent);
    --tf-lookup-border:color-mix(in srgb, var(--tf-lookup-accent) 32%, var(--tf-border));
    margin:1.05rem 0 1.25rem;
    padding:1.35rem 1.45rem;
    border:1px solid var(--tf-lookup-border);
    border-left:5px solid var(--tf-lookup-accent);
    border-radius:12px;
    background:linear-gradient(
        90deg,
        var(--tf-lookup-soft) 0%,
        color-mix(in srgb, var(--tf-panel) 96%, transparent) 48%,
        var(--tf-panel) 100%
    );
}
.tf-lookup-result--safe { --tf-lookup-accent:var(--tf-green); }
.tf-lookup-result--review { --tf-lookup-accent:var(--tf-yellow); }
.tf-lookup-result--danger { --tf-lookup-accent:var(--tf-orange); }
.tf-lookup-result--critical { --tf-lookup-accent:var(--tf-red); }

.tf-lookup-result-top {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:1.25rem;
}
.tf-lookup-result-copy {
    display:flex;
    align-items:center;
    gap:1rem;
    min-width:0;
}
.tf-lookup-icon {
    flex:0 0 auto;
    display:grid;
    place-items:center;
    width:3.3rem;
    height:3.3rem;
    border-radius:999px;
    border:1px solid color-mix(in srgb, var(--tf-lookup-accent) 48%, transparent);
    background:color-mix(in srgb, var(--tf-lookup-accent) 14%, transparent);
    color:var(--tf-lookup-accent);
    font-family:"Segoe UI Symbol","Segoe UI",Arial,sans-serif;
    font-size:1.7rem;
    font-weight:700;
    line-height:1;
}
.tf-lookup-kicker {
    color:var(--tf-lookup-accent);
    font-size:.72rem;
    font-weight:700;
    letter-spacing:.09em;
    text-transform:uppercase;
}
.tf-lookup-title {
    color:var(--tf-text);
    font-size:1.55rem;
    font-weight:700;
    letter-spacing:-.025em;
    line-height:1.22;
    margin:.18rem 0 .2rem;
}
.tf-lookup-summary {
    color:var(--tf-muted);
    font-size:.9rem;
    line-height:1.55;
}
.tf-lookup-target {
    flex:0 1 42%;
    max-width:42rem;
    min-width:15rem;
    font-family:ui-monospace,"Cascadia Code",Consolas,monospace;
    color:var(--tf-text);
    background:color-mix(in srgb, var(--tf-bg) 72%, transparent);
    border:1px solid var(--tf-border);
    border-radius:8px;
    padding:.72rem .85rem;
    overflow-wrap:anywhere;
    font-size:.83rem;
}
.tf-lookup-meta {
    display:flex;
    flex-wrap:wrap;
    gap:.45rem 1rem;
    margin-top:1rem;
    padding-top:.9rem;
    border-top:1px solid color-mix(in srgb, var(--tf-lookup-accent) 20%, var(--tf-border));
    color:var(--tf-muted);
    font-size:.78rem;
}
.tf-lookup-meta strong { color:var(--tf-text); font-weight:600; }

.tf-signal-grid {
    display:grid;
    grid-template-columns:repeat(3,minmax(0,1fr));
    gap:.7rem;
    margin:.2rem 0 1rem;
}
.tf-signal {
    min-height:76px;
    padding:.78rem .85rem;
    border:1px solid var(--tf-border);
    border-radius:8px;
    background:var(--tf-panel);
}
.tf-signal-label {
    color:var(--tf-muted);
    font-size:.72rem;
    text-transform:uppercase;
    letter-spacing:.07em;
    font-weight:600;
}
.tf-signal-value {
    color:var(--tf-text);
    font-size:1rem;
    font-weight:650;
    margin-top:.32rem;
}
.tf-signal-sub {
    color:var(--tf-muted);
    font-size:.74rem;
    line-height:1.45;
    margin-top:.18rem;
}
.tf-signal--safe .tf-signal-value { color:var(--tf-green); }
.tf-signal--review .tf-signal-value { color:var(--tf-yellow); }
.tf-signal--danger .tf-signal-value { color:var(--tf-red); }

.tf-reason-list {
    margin:.25rem 0 1rem;
    border-top:1px solid var(--tf-border);
}
.tf-reason-row {
    display:grid;
    grid-template-columns:1.35rem minmax(0,1fr);
    gap:.55rem;
    align-items:start;
    padding:.72rem 0;
    border-bottom:1px solid var(--tf-border);
    color:var(--tf-text);
    font-size:.86rem;
    line-height:1.5;
}
.tf-reason-icon {
    color:var(--tf-cyan);
    font-weight:700;
    text-align:center;
}
.tf-evidence-state {
    display:flex;
    gap:.7rem;
    align-items:flex-start;
    padding:.85rem 1rem;
    border:1px solid var(--tf-border);
    border-radius:8px;
    background:var(--tf-panel);
    font-size:.84rem;
    line-height:1.55;
    margin:.15rem 0 .85rem;
}
.tf-evidence-state strong { display:block; color:var(--tf-text); margin-bottom:.12rem; }
.tf-evidence-state span { color:var(--tf-muted); }
.tf-evidence-state--safe { border-left:4px solid var(--tf-green); }
.tf-evidence-state--review { border-left:4px solid var(--tf-yellow); }
.tf-evidence-state--danger { border-left:4px solid var(--tf-red); }
.tf-evidence-state-icon {
    flex:0 0 auto;
    width:1.6rem;
    color:var(--tf-text);
    font-size:1.05rem;
    font-weight:700;
    line-height:1.4;
    text-align:center;
}

/* Make the single-item lookup feel like the primary action, not a form field. */
.st-key-quick_lookup_input [data-baseweb="input"] {
    min-height:68px;
    border-radius:12px;
    border:1px solid color-mix(in srgb, var(--tf-cyan) 42%, var(--tf-border));
    background:var(--tf-input-bg)!important;
    box-shadow:0 0 0 1px color-mix(in srgb, var(--tf-cyan) 8%, transparent);
}
.st-key-quick_lookup_input [data-baseweb="input"] > div {
    background:transparent!important;
}
.st-key-quick_lookup_input input {
    min-height:66px;
    padding:0 1.05rem!important;
    font-size:1.08rem!important;
    font-family:ui-monospace,"Cascadia Code",Consolas,monospace!important;
    color:var(--tf-text)!important;
}
.st-key-quick_lookup_input label p {
    color:var(--tf-text)!important;
    font-size:.9rem!important;
    font-weight:650!important;
}
.st-key-quick_lookup_input [data-baseweb="input"]:focus-within {
    border-color:var(--tf-cyan);
    box-shadow:0 0 0 3px color-mix(in srgb, var(--tf-cyan) 16%, transparent);
}
.st-key-quick_lookup_analyze button {
    min-height:68px!important;
    border-radius:12px!important;
    font-size:1rem!important;
    font-weight:700!important;
}

.tf-signal-console {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:.65rem;
    min-height:250px;
    padding:.85rem;
    border:1px solid var(--tf-border);
    border-radius:12px;
    background:var(--tf-panel);
}
.tf-signal-node {
    position:relative;
    display:flex;
    flex-direction:column;
    justify-content:center;
    min-height:104px;
    padding:.9rem 1rem;
    border:1px solid var(--tf-border);
    border-radius:9px;
    background:var(--tf-bg-alt);
}
.tf-signal-node--wide { grid-column:1 / -1; }
.tf-signal-node--safe { border-left:4px solid var(--tf-green); }
.tf-signal-node--review { border-left:4px solid var(--tf-yellow); }
.tf-signal-node--danger { border-left:4px solid var(--tf-red); }
.tf-signal-node--info { border-left:4px solid var(--tf-cyan); }
.tf-signal-node-label {
    color:var(--tf-muted);
    font-size:.7rem;
    font-weight:650;
    text-transform:uppercase;
    letter-spacing:.08em;
}
.tf-signal-node-value {
    color:var(--tf-text);
    font-size:1.12rem;
    font-weight:700;
    margin-top:.3rem;
}
.tf-signal-node-sub {
    color:var(--tf-muted);
    font-size:.75rem;
    line-height:1.45;
    margin-top:.2rem;
}
.tf-signal-node-arrow {
    position:absolute;
    right:.65rem;
    top:.55rem;
    color:var(--tf-muted);
    font-size:.95rem;
}
.tf-console-caption {
    color:var(--tf-muted);
    font-size:.74rem;
    line-height:1.45;
    margin-top:.55rem;
}
.tf-lookup-empty-visual {
    display:grid;
    grid-template-columns:minmax(0,1fr) auto minmax(0,1fr) auto minmax(0,1fr);
    gap:.75rem;
    align-items:center;
    margin:1.4rem 0 .55rem;
    padding:1rem;
    border:1px solid var(--tf-border);
    border-radius:12px;
    background:color-mix(in srgb, var(--tf-panel) 92%, var(--tf-cyan-soft));
}
.tf-lookup-empty-step {
    min-height:108px;
    display:flex;
    flex-direction:column;
    justify-content:center;
    padding:.9rem 1rem;
    border:1px solid var(--tf-border);
    border-radius:9px;
    background:var(--tf-bg-alt);
}
.tf-lookup-empty-step-num {
    color:var(--tf-cyan);
    font-size:.7rem;
    font-weight:700;
    letter-spacing:.08em;
    text-transform:uppercase;
}
.tf-lookup-empty-step-title {
    color:var(--tf-text);
    font-size:1rem;
    font-weight:700;
    margin-top:.3rem;
}
.tf-lookup-empty-step-copy {
    color:var(--tf-muted);
    font-size:.76rem;
    line-height:1.45;
    margin-top:.22rem;
}
.tf-lookup-empty-arrow {
    color:var(--tf-cyan);
    font-size:1.4rem;
    font-weight:700;
    text-align:center;
}
.tf-lookup-empty-note {
    color:var(--tf-muted);
    font-size:.78rem;
    line-height:1.5;
    text-align:center;
    margin-bottom:1rem;
}

[data-baseweb="input"],
[data-baseweb="select"] > div,
[data-testid="stFileUploaderDropzone"] {
    background:var(--tf-input-bg)!important;
    color:var(--tf-text)!important;
    border-color:var(--tf-border)!important;
}
[data-baseweb="input"] input,
[data-baseweb="textarea"] textarea,
[data-baseweb="select"] input {
    background:transparent!important;
    color:var(--tf-text)!important;
    -webkit-text-fill-color:var(--tf-text)!important;
    caret-color:var(--tf-cyan)!important;
}
[data-baseweb="input"] input::placeholder,
[data-baseweb="textarea"] textarea::placeholder {
    color:var(--tf-muted)!important;
    -webkit-text-fill-color:var(--tf-muted)!important;
    opacity:.82!important;
}
[data-testid="stWidgetLabel"] p,
[data-testid="stCaptionContainer"],
[data-testid="stMarkdownContainer"] {
    color:var(--tf-text);
}
[data-testid="stCaptionContainer"] {
    color:var(--tf-muted)!important;
}
[data-baseweb="select"] span,
[data-baseweb="select"] svg {
    color:var(--tf-text)!important;
}
[data-baseweb="popover"] [role="listbox"],
[data-baseweb="menu"] {
    background:var(--tf-panel)!important;
    color:var(--tf-text)!important;
    border-color:var(--tf-border)!important;
}
[data-baseweb="popover"] [role="option"] {
    color:var(--tf-text)!important;
}
.stButton > button,
.stDownloadButton > button {
    background:var(--tf-panel);
    color:var(--tf-text);
    border-color:var(--tf-border);
}
[data-testid="stBaseButton-primary"] {
    background:var(--tf-cyan)!important;
    border-color:var(--tf-cyan)!important;
    color:var(--tf-on-accent)!important;
}
[data-testid="stDataFrame"] { border:1px solid var(--tf-border); border-radius:6px; }
[data-testid="stExpander"] { border-color:var(--tf-border); border-radius:6px; }
[data-testid="stMetric"] { padding:.4rem 0; }
[data-testid="stTabs"] [data-baseweb="tab-list"] { gap:1.2rem; flex-wrap:wrap; }
[data-testid="stTabs"] button { color:var(--tf-muted); font-weight:500; }
[data-testid="stTabs"] button[aria-selected="true"] { color:var(--tf-cyan); }
[data-testid="stTabs"] [data-baseweb="tab-highlight"] { background:var(--tf-cyan); }
.stButton > button,.stDownloadButton > button { border-radius:6px; min-height:40px; }
[data-testid="stBaseButton-primary"] { color:var(--tf-on-accent); }
button:focus-visible,a:focus-visible,input:focus-visible {
    outline:2px solid var(--tf-cyan)!important; outline-offset:3px;
}
@media(max-width:900px) {
    .tf-finding-row { grid-template-columns:minmax(0,1fr) auto; gap:.5rem; padding:.7rem; }
    .tf-finding-evidence { grid-column:1 / -1; }
    .block-container { padding-left:1rem; padding-right:1rem; }
    .tf-steps { grid-template-columns:1fr; gap:.65rem; }
    .tf-step { min-height:auto; }
    .tf-lookup-result { padding:1rem; }
    .tf-lookup-result-top { align-items:flex-start; flex-direction:column; }
    .tf-lookup-target { flex-basis:auto; min-width:0; width:100%; max-width:none; }
    .tf-signal-grid { grid-template-columns:1fr; }
    .tf-signal-console { grid-template-columns:1fr; }
    .tf-signal-node--wide { grid-column:auto; }
    .tf-lookup-empty-visual { grid-template-columns:1fr; }
    .tf-lookup-empty-arrow { transform:rotate(90deg); }
    .tf-primary-workspace { padding:.9rem; }
    .tf-primary-workspace-head { align-items:flex-start; flex-direction:column; }
    .tf-primary-workspace-hint { text-align:left; }
    .tf-primary-card { min-height:118px; }
    .tf-product-brand { align-items:flex-start; }
    .tf-product-brand-badge { display:none; }
    .tf-product-brand-title { font-size:1.35rem; }
    .tf-theme-picker-label { text-align:left; }
    .st-key-visual_theme,
    .st-key-visual_theme [role="radiogroup"] { justify-content:flex-start; }
    .st-key-quick_lookup_input [data-baseweb="input"],
    .st-key-quick_lookup_analyze button { min-height:60px!important; }
    .st-key-quick_lookup_input input { min-height:58px; font-size:1rem!important; }
}
@media(prefers-reduced-motion:reduce) { .tf-finding-row { transition:none; } }
"""


def render_app_header(
    title: str = "Analyze telemetry",
    description: str = "Turn DNS activity into a prioritized investigation queue.",
) -> None:
    st.markdown(
        '<header class="tf-page-head"><div class="tf-eyebrow">Analyst workspace</div>'
        f"<h1>{safe_text(title)}</h1><p>{safe_text(description)}</p></header>",
        unsafe_allow_html=True,
    )


def _logo_markup(css_class: str) -> str:
    return (
        f'<span class="{safe_text(css_class)}" role="img" '
        'aria-label="ThreatFusion AI logo" '
        f'style="--tf-brand-logo:url(&quot;{THREATFUSION_LOGO_DATA_URI}&quot;)"></span>'
    )


def render_main_brand() -> None:
    with st.container(key="product_topbar"):
        brand_col, theme_col = st.columns([1.55, 1.15], vertical_alignment="center")
        with brand_col:
            st.markdown(
                '<div class="tf-product-brand">'
                + _logo_markup("tf-product-brand-logo")
                + '<div><div class="tf-product-brand-title">ThreatFusion AI</div>'
                '<div class="tf-product-brand-sub">'
                'Threat intelligence, DNS analysis and AI-assisted triage in one analyst workspace.'
                '</div></div></div>',
                unsafe_allow_html=True,
            )
        with theme_col:
            with st.container(key="theme_picker"):
                label_col, options_col = st.columns(
                    [0.22, 0.78],
                    vertical_alignment="center",
                    gap="small",
                )
                with label_col:
                    st.markdown(
                        '<div class="tf-theme-picker-label">Theme</div>',
                        unsafe_allow_html=True,
                    )
                with options_col:
                    st.segmented_control(
                        "Theme",
                        list(THEME_OPTIONS),
                        key="visual_theme",
                        label_visibility="collapsed",
                        width="stretch",
                    )


def render_sidebar_brand() -> None:
    st.sidebar.markdown(
        '<div class="tf-sidebar-brand">'
        + _logo_markup("tf-sidebar-brand-logo")
        + '<div><div class="tf-sidebar-brand-title">ThreatFusion AI</div>'
        '<div class="tf-sidebar-brand-sub">DNS intelligence workspace</div></div></div>',
        unsafe_allow_html=True,
    )


def status_card(label: str, value: str, tone: str) -> None:
    tone_class = (
        f"tf-tone-{tone}" if tone in {"good", "warn", "info", "bad"} else "tf-tone-info"
    )
    st.sidebar.markdown(
        f'<div class="tf-status-card"><span class="tf-status-dot {tone_class}" aria-hidden="true">●</span>'
        f'<span class="tf-status-label">{safe_text(label)}</span>'
        f'<span class="tf-status-value {tone_class}">{safe_text(value)}</span></div>',
        unsafe_allow_html=True,
    )


def metric_card(
    container,
    label: str,
    value: object,
    *,
    accent: str = "neutral",
    subtitle: str | None = None,
) -> None:
    colors = palette()
    # Descriptive metrics remain neutral; only verdicts use severity color.
    accent_color = f"var(--tf-{accent})" if accent in colors else "var(--tf-border)"
    sub = f'<div class="tf-metric-sub">{safe_text(subtitle)}</div>' if subtitle else ""
    value_class = (
        "tf-metric-value"
        if isinstance(value, (int, float)) or str(value).replace(".", "", 1).isdigit()
        else "tf-metric-value tf-metric-text"
    )
    container.markdown(
        f'<div class="tf-metric-card" style="--tf-accent:{accent_color}">'
        f'<div class="tf-metric-label">{safe_text(label)}</div>'
        f'<div class="{value_class}">{safe_text(value)}</div>{sub}</div>',
        unsafe_allow_html=True,
    )


def section_label(text: str) -> None:
    st.markdown(
        f'<div class="tf-section-label">{safe_text(text)}</div>', unsafe_allow_html=True
    )


def verdict_badge(verdict: str) -> str:
    badge_class = _VERDICT_CLASSES.get(verdict, "neutral")
    return f'<span class="tf-badge tf-badge-{badge_class}">{safe_text(verdict)}</span>'


def render_priority_finding(row: dict[str, object]) -> None:
    verdict = str(row["Verdict"])
    accent = f"var(--tf-{_VERDICT_TOKENS.get(verdict, 'muted')})"
    sources = str(row.get("Known CTI sources") or "No cached CTI match")
    evidence = str(row.get("Evidence") or "No strong signal summary")
    st.markdown(
        f'<div class="tf-finding-row" style="--tf-row-accent:{accent}"><div>'
        f'<div class="tf-finding-domain">{safe_text(row["Domain"])}</div>'
        f'<div class="tf-finding-meta">{safe_text(row.get("DNS events", 0))} events'
        f" · {safe_text(sources)}</div></div>{verdict_badge(verdict)}"
        f'<div class="tf-finding-evidence">{safe_text(evidence)}</div></div>',
        unsafe_allow_html=True,
    )


def apply_plotly_theme(
    figure: go.Figure, *, theme: str | None = None, height: int | None = None
) -> go.Figure:
    """Apply the selected product theme independently of Streamlit's native theme."""
    colors = palette(theme)
    figure.update_layout(
        template=colors["plot_template"],
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={
            "family": "Aptos, Segoe UI Variable, Segoe UI, Arial, sans-serif",
            "size": 13,
            "color": colors["text"],
        },
        legend={"font": {"color": colors["text"]}},
        hoverlabel={
            "bgcolor": colors["panel"],
            "bordercolor": colors["border"],
            "font": {"color": colors["text"]},
        },
        margin={"l": 20, "r": 20, "t": 35, "b": 20},
        height=height,
    )
    figure.update_xaxes(
        gridcolor=colors["grid"],
        zerolinecolor=colors["border"],
        tickfont={"color": colors["muted"]},
        title_font={"color": colors["text"]},
    )
    figure.update_yaxes(
        gridcolor=colors["grid"],
        zerolinecolor=colors["border"],
        tickfont={"color": colors["muted"]},
        title_font={"color": colors["text"]},
    )
    return figure
