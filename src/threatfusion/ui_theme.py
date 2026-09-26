"""Shared presentation tokens and small, escaped Streamlit components."""

from __future__ import annotations

import html

import plotly.graph_objects as go
import streamlit as st

THEME_PALETTES = {
    "Dark": {
        "bg": "#0C121C",
        "bg_alt": "#101923",
        "panel": "#141F2C",
        "panel_alt": "#182534",
        "surface": "#213143",
        "border": "#2C3C4E",
        "text": "#E5ECF4",
        "muted": "#A0AFC1",
        "cyan": "#53C9BE",
        "cyan_soft": "rgba(83, 201, 190, 0.09)",
        "on_accent": "#0C121C",
        "green": "#81CAA3",
        "yellow": "#E8C76A",
        "orange": "#F4A26D",
        "red": "#FA8991",
        "blue": "#97B6D5",
        "grid": "rgba(160, 175, 193, 0.12)",
        "plot_template": "plotly_dark",
    },
    "Light": {
        "bg": "#F6F8FB",
        "bg_alt": "#EDF1F6",
        "panel": "#FFFFFF",
        "panel_alt": "#F1F5F9",
        "surface": "#E5ECF3",
        "border": "#CAD4E0",
        "text": "#1D2B3D",
        "muted": "#526278",
        "cyan": "#0E706D",
        "cyan_soft": "rgba(14, 112, 109, 0.07)",
        "on_accent": "#FFFFFF",
        "green": "#246843",
        "yellow": "#785A0D",
        "orange": "#A04413",
        "red": "#AE2B3B",
        "blue": "#3A628A",
        "grid": "rgba(82, 98, 120, 0.12)",
        "plot_template": "plotly_white",
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


def active_theme() -> str:
    """Follow the viewer's native Streamlit setting."""
    try:
        theme_type = st.context.theme.type
    except (AttributeError, TypeError):
        theme_type = "dark"
    return "Light" if theme_type == "light" else "Dark"


def palette(theme: str | None = None) -> dict[str, str]:
    return THEME_PALETTES[theme or active_theme()]


def verdict_colors(theme: str | None = None) -> dict[str, str]:
    colors = palette(theme)
    return {label: colors[token] for label, token in _VERDICT_TOKENS.items()}


def safe_text(value: object) -> str:
    return html.escape(str(value))


def inject_theme_css(theme: str | None = None) -> None:
    # Native Streamlit sets color-scheme on .stApp. CSS light-dark() follows it
    # immediately, while st.context.theme can lag behind a theme-menu change.
    colors = palette(theme)
    variables = ";".join(
        f"--tf-{key.replace('_', '-')}:"
        + (
            value
            if theme
            else f"light-dark({THEME_PALETTES['Light'][key]}, {THEME_PALETTES['Dark'][key]})"
        )
        for key, value in colors.items()
        if key != "plot_template"
    )
    st.markdown(
        "<style>:root{" + variables + "}" + _CSS + "</style>", unsafe_allow_html=True
    )


_CSS = """
[data-testid="stAppViewContainer"] { background:var(--tf-bg); color:var(--tf-text); }
[data-testid="stHeader"] { background:var(--tf-bg); }
[data-testid="stSidebar"] {
    background:var(--tf-bg-alt); border-right:1px solid var(--tf-border);
}
.block-container { max-width:1440px; padding-top:4.5rem; padding-bottom:3rem; }
h1,h2,h3,.tf-page-head,.tf-sidebar-brand { font-family:"Segoe UI",Arial,sans-serif; }
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
.tf-brand-mark {
    display:grid; place-items:center; width:2.1rem; height:2.3rem;
    border:1px solid var(--tf-border); border-radius:6px; color:var(--tf-cyan);
    font-size:.9rem; font-weight:700;
}
.tf-sidebar-brand-title { font-size:1rem; font-weight:650; color:var(--tf-text); }
.tf-sidebar-brand-sub { color:var(--tf-muted); font-size:.75rem; margin-top:.1rem; }
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
.tf-steps { display:flex; gap:1.5rem; flex-wrap:wrap; margin:.25rem 0 1.1rem; color:var(--tf-muted); font-size:.8rem; }
.tf-steps strong { color:var(--tf-text); font-weight:600; margin-right:.4rem; }
.tf-empty { padding:1.25rem 0; color:var(--tf-muted); border-top:1px solid var(--tf-border); }
.tf-empty strong { display:block; color:var(--tf-text); font-size:.95rem; margin-bottom:.35rem; }
.tf-empty p { font-size:.85rem; margin:0; line-height:1.6; }
.tf-privacy { color:var(--tf-muted); font-size:.78rem; line-height:1.6; margin:.45rem 0; }
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
    .tf-steps { gap:.55rem 1rem; }
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


def render_sidebar_brand() -> None:
    st.sidebar.markdown(
        '<div class="tf-sidebar-brand"><span class="tf-brand-mark" aria-hidden="true">TF</span>'
        '<div><div class="tf-sidebar-brand-title">ThreatFusion AI</div>'
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
    # Let Streamlit update chart typography and hover surfaces on theme changes.
    figure.update_layout(
        template="streamlit",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Segoe UI, Arial, sans-serif", "size": 13},
        margin={"l": 20, "r": 20, "t": 35, "b": 20},
        height=height,
    )
    return figure
