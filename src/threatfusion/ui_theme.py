from __future__ import annotations

import html

import plotly.graph_objects as go
import streamlit as st


THEME_PALETTES = {
    "Dark": {
        "bg": "#07111F",
        "bg_alt": "#091728",
        "panel": "#0D1B2A",
        "panel_alt": "#112338",
        "surface": "#13283E",
        "border": "#203A55",
        "text": "#E8F1F8",
        "muted": "#91A4B7",
        "cyan": "#22D3EE",
        "cyan_soft": "rgba(34, 211, 238, 0.13)",
        "green": "#35D07F",
        "yellow": "#F6C85F",
        "orange": "#F59E0B",
        "red": "#FF5C6C",
        "blue": "#60A5FA",
        "shadow": "0 18px 48px rgba(0, 0, 0, 0.28)",
        "grid": "rgba(145, 164, 183, 0.16)",
        "plot_template": "plotly_dark",
    },
    "Light": {
        "bg": "#F4F7FB",
        "bg_alt": "#EDF2F7",
        "panel": "#FFFFFF",
        "panel_alt": "#F8FAFC",
        "surface": "#EEF5F8",
        "border": "#D7E1EA",
        "text": "#102033",
        "muted": "#60758A",
        "cyan": "#0891B2",
        "cyan_soft": "rgba(8, 145, 178, 0.10)",
        "green": "#15803D",
        "yellow": "#A16207",
        "orange": "#C2410C",
        "red": "#C6283D",
        "blue": "#2563EB",
        "shadow": "0 14px 36px rgba(15, 31, 46, 0.10)",
        "grid": "rgba(96, 117, 138, 0.16)",
        "plot_template": "plotly_white",
    },
}

VERDICT_COLORS = {
    "Known Threat": "#FF5C6C",
    "High Risk": "#F59E0B",
    "Review": "#F6C85F",
    "Low": "#35D07F",
}

_VERDICT_CLASSES = {
    "Known Threat": "critical",
    "High Risk": "high",
    "Review": "review",
    "Low": "low",
}


def active_theme() -> str:
    """Return the viewer's native Streamlit light/dark theme."""
    try:
        theme_type = st.context.theme.type
    except (AttributeError, TypeError):
        theme_type = "dark"

    return "Dark" if theme_type == "dark" else "Light"


def palette(theme: str | None = None) -> dict[str, str]:
    return THEME_PALETTES[theme or active_theme()]


def safe_text(value: object) -> str:
    return html.escape(str(value))


def inject_theme_css(theme: str | None = None) -> None:
    current = theme or active_theme()
    colors = palette(current)
    st.markdown(
        f"""
        <style>
        :root {{
            --tf-bg: {colors["bg"]};
            --tf-bg-alt: {colors["bg_alt"]};
            --tf-panel: {colors["panel"]};
            --tf-panel-alt: {colors["panel_alt"]};
            --tf-surface: {colors["surface"]};
            --tf-border: {colors["border"]};
            --tf-text: {colors["text"]};
            --tf-muted: {colors["muted"]};
            --tf-cyan: {colors["cyan"]};
            --tf-cyan-soft: {colors["cyan_soft"]};
            --tf-green: {colors["green"]};
            --tf-yellow: {colors["yellow"]};
            --tf-orange: {colors["orange"]};
            --tf-red: {colors["red"]};
            --tf-blue: {colors["blue"]};
            --tf-shadow: {colors["shadow"]};
        }}

        [data-testid="stAppViewContainer"] {{
            background:
                radial-gradient(
                    circle at 84% 0%,
                    var(--tf-cyan-soft),
                    transparent 30rem
                ),
                linear-gradient(
                    180deg,
                    var(--tf-bg) 0%,
                    var(--tf-bg-alt) 100%
                );
        }}

        [data-testid="stHeader"] {{
            background: rgba(0, 0, 0, 0);
        }}

        [data-testid="stSidebar"] {{
            border-right: 1px solid var(--tf-border);
        }}

        [data-testid="stSidebar"] > div:first-child {{
            padding-top: 1.05rem;
        }}

        .block-container {{
            max-width: 1540px;
            padding-top: 1.55rem;
            padding-bottom: 4rem;
        }}

        .tf-hero {{
            position: relative;
            overflow: hidden;
            border: 1px solid var(--tf-border);
            background:
                linear-gradient(
                    120deg,
                    var(--tf-panel) 0%,
                    var(--tf-panel-alt) 68%,
                    var(--tf-cyan-soft) 100%
                );
            border-radius: 22px;
            padding: 1.35rem 1.55rem 1.25rem;
            margin-bottom: 1.15rem;
            box-shadow: var(--tf-shadow);
        }}

        .tf-hero::after {{
            content: "";
            position: absolute;
            width: 15rem;
            height: 15rem;
            border-radius: 50%;
            right: -6rem;
            top: -8rem;
            background: var(--tf-cyan-soft);
        }}

        .tf-eyebrow {{
            color: var(--tf-cyan);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            margin-bottom: 0.35rem;
        }}

        .tf-hero-title {{
            font-size: clamp(1.8rem, 3.1vw, 2.65rem);
            line-height: 1.04;
            font-weight: 800;
            letter-spacing: -0.035em;
            margin: 0;
            color: var(--tf-text);
        }}

        .tf-hero-subtitle {{
            max-width: 58rem;
            margin-top: 0.55rem;
            color: var(--tf-muted);
            font-size: 0.98rem;
        }}

        .tf-chip-row {{
            display: flex;
            gap: 0.45rem;
            flex-wrap: wrap;
            margin-top: 0.8rem;
        }}

        .tf-chip {{
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            border-radius: 999px;
            border: 1px solid var(--tf-border);
            background: var(--tf-panel-alt);
            padding: 0.28rem 0.58rem;
            color: var(--tf-muted);
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.02em;
        }}

        .tf-chip-accent {{
            color: var(--tf-cyan);
            border-color: var(--tf-cyan);
            background: var(--tf-cyan-soft);
        }}

        .tf-sidebar-brand {{
            border: 1px solid var(--tf-border);
            border-radius: 15px;
            background: var(--tf-panel-alt);
            padding: 0.75rem 0.8rem;
            margin: 0 0 0.7rem 0;
        }}

        .tf-sidebar-brand-title {{
            font-weight: 800;
            font-size: 0.96rem;
            letter-spacing: -0.01em;
            color: var(--tf-text);
        }}

        .tf-sidebar-brand-sub {{
            color: var(--tf-muted);
            font-size: 0.72rem;
            margin-top: 0.12rem;
        }}

        .tf-status-card {{
            display: grid;
            grid-template-columns: 0.6rem 1fr auto;
            gap: 0.55rem;
            align-items: center;
            padding: 0.62rem 0.72rem;
            border: 1px solid var(--tf-border);
            background: var(--tf-panel-alt);
            border-radius: 12px;
            margin-bottom: 0.45rem;
        }}

        .tf-status-dot {{
            width: 0.54rem;
            height: 0.54rem;
            border-radius: 50%;
        }}

        .tf-status-label {{
            font-size: 0.78rem;
            color: var(--tf-muted);
        }}

        .tf-status-value {{
            font-size: 0.74rem;
            font-weight: 800;
            text-align: right;
        }}

        .tf-tone-good {{ color: var(--tf-green); }}
        .tf-tone-warn {{ color: var(--tf-orange); }}
        .tf-tone-info {{ color: var(--tf-blue); }}
        .tf-tone-bad {{ color: var(--tf-red); }}

        .tf-metric-card {{
            min-height: 104px;
            border-radius: 16px;
            border: 1px solid var(--tf-border);
            border-top: 3px solid var(--tf-accent, var(--tf-cyan));
            background:
                linear-gradient(
                    180deg,
                    var(--tf-panel) 0%,
                    var(--tf-panel-alt) 100%
                );
            padding: 0.8rem 0.86rem;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.05);
        }}

        .tf-metric-label {{
            color: var(--tf-muted);
            font-size: 0.74rem;
            font-weight: 700;
            letter-spacing: 0.035em;
            text-transform: uppercase;
        }}

        .tf-metric-value {{
            color: var(--tf-text);
            font-size: 1.58rem;
            line-height: 1.1;
            font-weight: 800;
            margin-top: 0.38rem;
            letter-spacing: -0.03em;
            overflow-wrap: anywhere;
        }}

        .tf-metric-sub {{
            color: var(--tf-muted);
            font-size: 0.69rem;
            margin-top: 0.34rem;
        }}

        .tf-section-label {{
            display: flex;
            align-items: center;
            gap: 0.55rem;
            font-size: 0.77rem;
            color: var(--tf-muted);
            text-transform: uppercase;
            letter-spacing: 0.11em;
            font-weight: 800;
            margin: 0.8rem 0 0.55rem;
        }}

        .tf-section-label::before {{
            content: "";
            width: 1.7rem;
            height: 2px;
            border-radius: 999px;
            background: var(--tf-cyan);
        }}

        .tf-finding-row {{
            display: grid;
            grid-template-columns: minmax(0, 1.65fr) auto minmax(0, 1fr);
            gap: 0.8rem;
            align-items: center;
            padding: 0.68rem 0.78rem;
            margin-bottom: 0.48rem;
            border: 1px solid var(--tf-border);
            border-left: 4px solid var(--tf-row-accent, var(--tf-cyan));
            background: var(--tf-panel);
            border-radius: 12px;
        }}

        .tf-finding-domain {{
            font-family:
                ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.83rem;
            font-weight: 750;
            overflow-wrap: anywhere;
            color: var(--tf-text);
        }}

        .tf-finding-meta {{
            color: var(--tf-muted);
            font-size: 0.69rem;
            margin-top: 0.12rem;
        }}

        .tf-finding-evidence {{
            color: var(--tf-muted);
            font-size: 0.74rem;
            text-align: right;
            overflow-wrap: anywhere;
        }}

        .tf-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            padding: 0.27rem 0.58rem;
            font-size: 0.70rem;
            font-weight: 850;
            white-space: nowrap;
            border: 1px solid currentColor;
        }}

        .tf-badge-critical {{
            color: var(--tf-red);
            background: rgba(255, 92, 108, 0.10);
        }}
        .tf-badge-high {{
            color: var(--tf-orange);
            background: rgba(245, 158, 11, 0.10);
        }}
        .tf-badge-review {{
            color: var(--tf-yellow);
            background: rgba(246, 200, 95, 0.11);
        }}
        .tf-badge-low {{
            color: var(--tf-green);
            background: rgba(53, 208, 127, 0.10);
        }}
        .tf-badge-neutral {{
            color: var(--tf-cyan);
            background: var(--tf-cyan-soft);
        }}

        .tf-investigation-head {{
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            align-items: flex-start;
            border-bottom: 1px solid var(--tf-border);
            padding-bottom: 0.85rem;
            margin-bottom: 0.85rem;
        }}

        .tf-domain-name {{
            font-family:
                ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-weight: 800;
            font-size: 1.05rem;
            overflow-wrap: anywhere;
            color: var(--tf-text);
        }}

        div[data-testid="stMetric"] {{
            border: 1px solid var(--tf-border);
            border-radius: 14px;
            padding: 0.65rem 0.75rem;
        }}

        div[data-testid="stVerticalBlockBorderWrapper"] {{
            border-color: var(--tf-border) !important;
            border-radius: 17px !important;
        }}

        [data-testid="stDataFrame"] {{
            border: 1px solid var(--tf-border);
            border-radius: 14px;
            overflow: hidden;
        }}

        [data-testid="stFileUploader"] {{
            border: 1px dashed var(--tf-border);
            border-radius: 16px;
            padding: 0.25rem;
        }}

        [data-testid="stExpander"] {{
            border-color: var(--tf-border);
            border-radius: 13px;
        }}

        div[data-testid="stTabs"] button {{
            border-radius: 10px 10px 0 0;
            color: var(--tf-muted);
            font-weight: 760;
        }}

        div[data-testid="stTabs"] button[aria-selected="true"] {{
            color: var(--tf-cyan);
        }}

        div[data-testid="stTabs"] [data-baseweb="tab-highlight"] {{
            background-color: var(--tf-cyan);
        }}

        .stButton > button,
        .stDownloadButton > button {{
            border-radius: 11px;
            border-color: var(--tf-border);
            font-weight: 760;
            transition: transform 120ms ease, border-color 120ms ease;
        }}

        .stButton > button:hover,
        .stDownloadButton > button:hover {{
            transform: translateY(-1px);
            border-color: var(--tf-cyan);
        }}

        div[data-testid="stAlert"] {{
            border-radius: 13px;
        }}

        @media (max-width: 900px) {{
            .tf-finding-row {{
                grid-template-columns: 1fr;
            }}

            .tf-finding-evidence {{
                text-align: left;
            }}

            .block-container {{
                padding-left: 1rem;
                padding-right: 1rem;
            }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_app_header() -> None:
    st.markdown(
        """
        <div class="tf-hero">
            <div class="tf-eyebrow">Threat operations workspace</div>
            <div class="tf-hero-title">ThreatFusion AI</div>
            <div class="tf-hero-subtitle">
                Local-first DNS threat triage that fuses deterministic CTI
                evidence, malicious-domain ML, DNS behavior, and analyst
                context without hiding the reasoning chain.
            </div>
            <div class="tf-chip-row">
                <span class="tf-chip tf-chip-accent">
                    Explainable verdicts
                </span>
                <span class="tf-chip">Multi-source CTI</span>
                <span class="tf-chip">Privacy-first</span>
                <span class="tf-chip">Local analyst workflow</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar_brand() -> None:
    st.sidebar.markdown(
        """
        <div class="tf-sidebar-brand">
            <div class="tf-sidebar-brand-title">ThreatFusion Console</div>
            <div class="tf-sidebar-brand-sub">
                DNS threat analysis · local workspace
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def status_card(label: str, value: str, tone: str) -> None:
    tone_class = {
        "good": "tf-tone-good",
        "warn": "tf-tone-warn",
        "info": "tf-tone-info",
        "bad": "tf-tone-bad",
    }.get(tone, "tf-tone-info")
    st.sidebar.markdown(
        f"""
        <div class="tf-status-card">
            <span class="tf-status-dot {tone_class}">●</span>
            <span class="tf-status-label">{safe_text(label)}</span>
            <span class="tf-status-value {tone_class}">
                {safe_text(value)}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(
    container,
    label: str,
    value: object,
    *,
    accent: str = "cyan",
    subtitle: str | None = None,
) -> None:
    colors = palette()
    accent_color = {
        "cyan": colors["cyan"],
        "green": colors["green"],
        "yellow": colors["yellow"],
        "orange": colors["orange"],
        "red": colors["red"],
        "blue": colors["blue"],
    }.get(accent, colors["cyan"])
    subtitle_html = (
        f'<div class="tf-metric-sub">{safe_text(subtitle)}</div>'
        if subtitle
        else ""
    )
    container.markdown(
        f"""
        <div class="tf-metric-card" style="--tf-accent:{accent_color}">
            <div class="tf-metric-label">{safe_text(label)}</div>
            <div class="tf-metric-value">{safe_text(value)}</div>
            {subtitle_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def section_label(text: str) -> None:
    st.markdown(
        f'<div class="tf-section-label">{safe_text(text)}</div>',
        unsafe_allow_html=True,
    )


def verdict_badge(verdict: str) -> str:
    badge_class = _VERDICT_CLASSES.get(verdict, "neutral")
    return (
        f'<span class="tf-badge tf-badge-{badge_class}">'
        f"{safe_text(verdict)}</span>"
    )


def render_priority_finding(row: dict[str, object]) -> None:
    verdict = str(row["Verdict"])
    colors = palette()
    accent = {
        "Known Threat": colors["red"],
        "High Risk": colors["orange"],
        "Review": colors["yellow"],
        "Low": colors["green"],
    }.get(verdict, colors["cyan"])
    sources = str(row.get("Known CTI sources") or "No cached CTI source")
    ml_tier = str(row.get("ML tier") or "Not scored")
    events = row.get("DNS events", 0)
    evidence = str(row.get("Evidence") or "No strong signal summary")
    st.markdown(
        f"""
        <div class="tf-finding-row" style="--tf-row-accent:{accent}">
            <div>
                <div class="tf-finding-domain">
                    {safe_text(row["Domain"])}
                </div>
                <div class="tf-finding-meta">
                    ML {safe_text(ml_tier)} · {safe_text(events)} DNS event(s)
                    · {safe_text(sources)}
                </div>
            </div>
            <div>{verdict_badge(verdict)}</div>
            <div class="tf-finding-evidence">{safe_text(evidence)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def apply_plotly_theme(
    figure: go.Figure,
    *,
    theme: str | None = None,
    height: int | None = None,
) -> go.Figure:
    colors = palette(theme)
    figure.update_layout(
        template=colors["plot_template"],
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={
            "color": colors["text"],
            "family": "Inter, Segoe UI, sans-serif",
        },
        hoverlabel={
            "bgcolor": colors["panel_alt"],
            "bordercolor": colors["border"],
            "font": {"color": colors["text"]},
        },
        margin={"l": 20, "r": 20, "t": 35, "b": 20},
        height=height,
    )
    figure.update_xaxes(
        gridcolor=colors["grid"],
        zerolinecolor=colors["grid"],
        linecolor=colors["border"],
    )
    figure.update_yaxes(
        gridcolor=colors["grid"],
        zerolinecolor=colors["grid"],
        linecolor=colors["border"],
    )
    return figure
