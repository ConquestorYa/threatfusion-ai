from __future__ import annotations

import html

import plotly.graph_objects as go
import streamlit as st

THEME_PALETTES = {
    "Dark": {
        "bg": "#08111F",
        "bg_alt": "#0A1423",
        "panel": "#0E1929",
        "panel_alt": "#111E30",
        "surface": "#162437",
        "border": "#24344B",
        "border_soft": "#1B2A3E",
        "text": "#F1F5F9",
        "muted": "#94A3B8",
        "muted_strong": "#B7C2D0",
        "cyan": "#2DD4BF",
        "cyan_soft": "rgba(45, 212, 191, 0.10)",
        "green": "#34D399",
        "yellow": "#FBBF24",
        "orange": "#FB923C",
        "red": "#F87171",
        "blue": "#60A5FA",
        "shadow": "0 18px 50px rgba(2, 8, 23, 0.24)",
        "grid": "rgba(148, 163, 184, 0.12)",
        "plot_template": "plotly_dark",
    },
    "Light": {
        "bg": "#F7F9FC",
        "bg_alt": "#F1F5F9",
        "panel": "#FFFFFF",
        "panel_alt": "#F8FAFC",
        "surface": "#EEF3F8",
        "border": "#DCE4EE",
        "border_soft": "#E8EDF3",
        "text": "#0F172A",
        "muted": "#64748B",
        "muted_strong": "#475569",
        "cyan": "#0F766E",
        "cyan_soft": "rgba(15, 118, 110, 0.08)",
        "green": "#15803D",
        "yellow": "#A16207",
        "orange": "#C2410C",
        "red": "#DC2626",
        "blue": "#2563EB",
        "shadow": "0 16px 42px rgba(15, 23, 42, 0.08)",
        "grid": "rgba(100, 116, 139, 0.12)",
        "plot_template": "plotly_white",
    },
}

VERDICT_COLORS = {
    "Known Threat": "#F87171",
    "High Risk": "#FB923C",
    "Review": "#FBBF24",
    "Low": "#34D399",
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
            --tf-border-soft: {colors["border_soft"]};
            --tf-text: {colors["text"]};
            --tf-muted: {colors["muted"]};
            --tf-muted-strong: {colors["muted_strong"]};
            --tf-accent: {colors["cyan"]};
            --tf-accent-soft: {colors["cyan_soft"]};
            --tf-green: {colors["green"]};
            --tf-yellow: {colors["yellow"]};
            --tf-orange: {colors["orange"]};
            --tf-red: {colors["red"]};
            --tf-blue: {colors["blue"]};
            --tf-shadow: {colors["shadow"]};
        }}

        html,
        body,
        [class*="css"] {{
            font-family:
                Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont,
                "Segoe UI", sans-serif;
        }}

        [data-testid="stAppViewContainer"] {{
            background: var(--tf-bg);
            color: var(--tf-text);
        }}

        [data-testid="stHeader"] {{
            background: var(--tf-bg);
        }}

        [data-testid="stAppDeployButton"] {{
            display: none;
        }}

        [data-testid="stSidebar"] {{
            background: var(--tf-bg-alt);
            border-right: 1px solid var(--tf-border-soft);
        }}

        [data-testid="stSidebar"] > div:first-child {{
            padding-top: 1.15rem;
        }}

        .block-container {{
            max-width: 1390px;
            padding-top: 1.35rem;
            padding-bottom: 4.5rem;
        }}

        h1, h2, h3 {{
            letter-spacing: -0.025em;
        }}

        .tf-hero {{
            display: flex;
            justify-content: space-between;
            gap: 2rem;
            align-items: flex-end;
            border-bottom: 1px solid var(--tf-border);
            padding: 0.4rem 0 1.35rem;
            margin-bottom: 1.1rem;
        }}

        .tf-hero-main {{
            min-width: 0;
        }}

        .tf-eyebrow {{
            color: var(--tf-accent);
            font-size: 0.69rem;
            font-weight: 800;
            letter-spacing: 0.16em;
            text-transform: uppercase;
            margin-bottom: 0.42rem;
        }}

        .tf-hero-title {{
            font-size: clamp(2rem, 3.8vw, 3rem);
            line-height: 0.98;
            font-weight: 760;
            letter-spacing: -0.052em;
            margin: 0;
            color: var(--tf-text);
        }}

        .tf-hero-title span {{
            color: var(--tf-accent);
        }}

        .tf-hero-subtitle {{
            max-width: 50rem;
            margin-top: 0.7rem;
            color: var(--tf-muted);
            font-size: 0.98rem;
            line-height: 1.65;
        }}

        .tf-hero-meta {{
            display: flex;
            flex-wrap: wrap;
            justify-content: flex-end;
            gap: 0.45rem;
            padding-bottom: 0.2rem;
        }}

        .tf-chip {{
            display: inline-flex;
            align-items: center;
            gap: 0.34rem;
            border-radius: 999px;
            border: 1px solid var(--tf-border);
            background: var(--tf-panel);
            padding: 0.34rem 0.64rem;
            color: var(--tf-muted-strong);
            font-size: 0.71rem;
            font-weight: 700;
        }}

        .tf-chip-accent {{
            color: var(--tf-accent);
            border-color: color-mix(
                in srgb,
                var(--tf-accent) 48%,
                var(--tf-border)
            );
            background: var(--tf-accent-soft);
        }}

        .tf-sidebar-brand {{
            display: flex;
            align-items: center;
            gap: 0.72rem;
            padding: 0.15rem 0 0.95rem;
            margin-bottom: 0.35rem;
            border-bottom: 1px solid var(--tf-border-soft);
        }}

        .tf-brand-mark {{
            display: grid;
            place-items: center;
            width: 2.15rem;
            height: 2.15rem;
            border-radius: 10px;
            background: var(--tf-accent-soft);
            border: 1px solid var(--tf-border);
            color: var(--tf-accent);
            font-size: 0.72rem;
            font-weight: 850;
            letter-spacing: 0.04em;
        }}

        .tf-sidebar-brand-title {{
            font-weight: 760;
            font-size: 0.9rem;
            letter-spacing: -0.015em;
            color: var(--tf-text);
        }}

        .tf-sidebar-brand-sub {{
            color: var(--tf-muted);
            font-size: 0.69rem;
            margin-top: 0.08rem;
        }}

        .tf-sidebar-label {{
            color: var(--tf-muted);
            font-size: 0.66rem;
            font-weight: 800;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            margin: 1rem 0 0.55rem;
        }}

        .tf-status-card {{
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 0.75rem;
            align-items: center;
            padding: 0.62rem 0.04rem;
            border-bottom: 1px solid var(--tf-border-soft);
        }}

        .tf-status-label {{
            font-size: 0.76rem;
            color: var(--tf-muted-strong);
        }}

        .tf-status-value {{
            display: inline-flex;
            align-items: center;
            border-radius: 999px;
            border: 1px solid currentColor;
            padding: 0.18rem 0.42rem;
            font-size: 0.64rem;
            font-weight: 800;
            line-height: 1.2;
        }}

        .tf-tone-good {{ color: var(--tf-green); }}
        .tf-tone-warn {{ color: var(--tf-orange); }}
        .tf-tone-info {{ color: var(--tf-blue); }}
        .tf-tone-bad {{ color: var(--tf-red); }}

        .tf-source-card {{
            padding: 0.72rem 0;
            border-bottom: 1px solid var(--tf-border-soft);
        }}

        .tf-source-card:last-child {{
            border-bottom: 0;
        }}

        .tf-source-head {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.7rem;
        }}

        .tf-source-name {{
            color: var(--tf-text);
            font-size: 0.77rem;
            font-weight: 760;
        }}

        .tf-source-state {{
            font-size: 0.62rem;
            font-weight: 800;
            letter-spacing: 0.02em;
            text-transform: uppercase;
        }}

        .tf-source-meta {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.55rem;
            margin-top: 0.48rem;
        }}

        .tf-source-stat {{
            color: var(--tf-muted);
            font-size: 0.67rem;
            line-height: 1.35;
        }}

        .tf-source-stat strong {{
            display: block;
            color: var(--tf-muted-strong);
            font-size: 0.72rem;
            font-weight: 700;
            margin-bottom: 0.06rem;
        }}

        .tf-page-intro {{
            margin: 1.3rem 0 1.05rem;
        }}

        .tf-page-title {{
            color: var(--tf-text);
            font-size: clamp(1.55rem, 2.2vw, 2.05rem);
            font-weight: 740;
            letter-spacing: -0.035em;
            margin: 0;
        }}

        .tf-page-copy {{
            color: var(--tf-muted);
            max-width: 52rem;
            margin-top: 0.38rem;
            line-height: 1.6;
            font-size: 0.9rem;
        }}

        .tf-panel {{
            border: 1px solid var(--tf-border);
            background: var(--tf-panel);
            border-radius: 16px;
            padding: 1rem 1.05rem;
        }}

        .tf-panel-title {{
            color: var(--tf-text);
            font-size: 0.78rem;
            font-weight: 760;
            margin-bottom: 0.18rem;
        }}

        .tf-panel-copy {{
            color: var(--tf-muted);
            font-size: 0.73rem;
            line-height: 1.5;
        }}

        .tf-pipeline {{
            border: 1px solid var(--tf-border);
            background: var(--tf-panel);
            border-radius: 16px;
            padding: 0.95rem 1rem;
        }}

        .tf-pipeline-title {{
            color: var(--tf-text);
            font-size: 0.78rem;
            font-weight: 760;
            margin-bottom: 0.75rem;
        }}

        .tf-pipeline-step {{
            display: grid;
            grid-template-columns: 1.55rem 1fr;
            gap: 0.55rem;
            align-items: start;
            padding: 0.42rem 0;
        }}

        .tf-pipeline-index {{
            display: grid;
            place-items: center;
            width: 1.45rem;
            height: 1.45rem;
            border-radius: 8px;
            color: var(--tf-accent);
            background: var(--tf-accent-soft);
            border: 1px solid var(--tf-border);
            font-size: 0.63rem;
            font-weight: 850;
        }}

        .tf-pipeline-name {{
            color: var(--tf-muted-strong);
            font-size: 0.72rem;
            font-weight: 720;
        }}

        .tf-pipeline-copy {{
            color: var(--tf-muted);
            font-size: 0.66rem;
            line-height: 1.45;
            margin-top: 0.08rem;
        }}

        .tf-note {{
            display: flex;
            gap: 0.55rem;
            align-items: flex-start;
            border: 1px solid var(--tf-border);
            background: var(--tf-panel-alt);
            border-radius: 12px;
            padding: 0.7rem 0.78rem;
            color: var(--tf-muted);
            font-size: 0.72rem;
            line-height: 1.5;
        }}

        .tf-note-dot {{
            color: var(--tf-accent);
            font-size: 0.9rem;
            line-height: 1;
            margin-top: 0.09rem;
        }}

        .tf-metric-card {{
            min-height: 96px;
            border-radius: 14px;
            border: 1px solid var(--tf-border);
            background: var(--tf-panel);
            padding: 0.78rem 0.82rem;
            position: relative;
            overflow: hidden;
        }}

        .tf-metric-card::before {{
            content: "";
            position: absolute;
            inset: 0 auto 0 0;
            width: 3px;
            background: var(--tf-card-accent, var(--tf-accent));
        }}

        .tf-metric-label {{
            color: var(--tf-muted);
            font-size: 0.67rem;
            font-weight: 720;
            letter-spacing: 0.055em;
            text-transform: uppercase;
        }}

        .tf-metric-value {{
            color: var(--tf-text);
            font-size: 1.42rem;
            line-height: 1.12;
            font-weight: 760;
            margin-top: 0.34rem;
            letter-spacing: -0.035em;
            overflow-wrap: anywhere;
        }}

        .tf-metric-sub {{
            color: var(--tf-muted);
            font-size: 0.65rem;
            margin-top: 0.3rem;
        }}

        .tf-section-label {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.67rem;
            color: var(--tf-muted);
            text-transform: uppercase;
            letter-spacing: 0.11em;
            font-weight: 800;
            margin: 1rem 0 0.55rem;
        }}

        .tf-section-label::after {{
            content: "";
            height: 1px;
            flex: 1;
            margin-left: 0.65rem;
            background: var(--tf-border-soft);
        }}

        .tf-finding-row {{
            display: grid;
            grid-template-columns: minmax(0, 1.65fr) auto minmax(0, 1fr);
            gap: 0.8rem;
            align-items: center;
            padding: 0.72rem 0.8rem;
            margin-bottom: 0.42rem;
            border: 1px solid var(--tf-border);
            background: var(--tf-panel);
            border-radius: 12px;
            position: relative;
            overflow: hidden;
        }}

        .tf-finding-row::before {{
            content: "";
            position: absolute;
            inset: 0 auto 0 0;
            width: 3px;
            background: var(--tf-row-accent, var(--tf-accent));
        }}

        .tf-finding-domain {{
            font-family:
                "SFMono-Regular", Consolas, "Liberation Mono", monospace;
            font-size: 0.79rem;
            font-weight: 720;
            overflow-wrap: anywhere;
            color: var(--tf-text);
        }}

        .tf-finding-meta {{
            color: var(--tf-muted);
            font-size: 0.66rem;
            margin-top: 0.14rem;
        }}

        .tf-finding-evidence {{
            color: var(--tf-muted);
            font-size: 0.7rem;
            text-align: right;
            overflow-wrap: anywhere;
            line-height: 1.45;
        }}

        .tf-badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 999px;
            padding: 0.24rem 0.5rem;
            font-size: 0.65rem;
            font-weight: 820;
            white-space: nowrap;
            border: 1px solid currentColor;
        }}

        .tf-badge-critical {{
            color: var(--tf-red);
            background: rgba(248, 113, 113, 0.08);
        }}
        .tf-badge-high {{
            color: var(--tf-orange);
            background: rgba(251, 146, 60, 0.08);
        }}
        .tf-badge-review {{
            color: var(--tf-yellow);
            background: rgba(251, 191, 36, 0.08);
        }}
        .tf-badge-low {{
            color: var(--tf-green);
            background: rgba(52, 211, 153, 0.08);
        }}
        .tf-badge-neutral {{
            color: var(--tf-accent);
            background: var(--tf-accent-soft);
        }}

        .tf-investigation-head {{
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            align-items: flex-start;
            border-bottom: 1px solid var(--tf-border-soft);
            padding-bottom: 0.8rem;
            margin-bottom: 0.8rem;
        }}

        .tf-domain-name {{
            font-family:
                "SFMono-Regular", Consolas, "Liberation Mono", monospace;
            font-weight: 760;
            font-size: 1rem;
            overflow-wrap: anywhere;
            color: var(--tf-text);
        }}

        div[data-testid="stVerticalBlockBorderWrapper"] {{
            border-color: var(--tf-border) !important;
            border-radius: 16px !important;
            background: var(--tf-panel);
        }}

        [data-testid="stDataFrame"] {{
            border: 1px solid var(--tf-border);
            border-radius: 12px;
            overflow: hidden;
        }}

        [data-testid="stFileUploader"] {{
            border: 1px dashed var(--tf-border);
            border-radius: 14px;
            padding: 0.18rem;
            background: var(--tf-panel-alt);
        }}

        [data-testid="stFileUploader"] section {{
            padding: 1rem !important;
        }}

        [data-testid="stExpander"] {{
            border: 1px solid var(--tf-border-soft);
            border-radius: 12px;
            background: transparent;
        }}

        div[data-testid="stTabs"] {{
            margin-top: 0.05rem;
        }}

        div[data-testid="stTabs"] [role="tablist"] {{
            gap: 0.35rem;
            border-bottom: 1px solid var(--tf-border-soft);
        }}

        div[data-testid="stTabs"] button {{
            border-radius: 9px 9px 0 0;
            color: var(--tf-muted);
            font-size: 0.76rem;
            font-weight: 700;
            padding-left: 0.72rem;
            padding-right: 0.72rem;
        }}

        div[data-testid="stTabs"] button[aria-selected="true"] {{
            color: var(--tf-text);
        }}

        div[data-testid="stTabs"] [data-baseweb="tab-highlight"] {{
            background-color: var(--tf-accent);
            height: 2px;
        }}

        div[data-baseweb="select"] > div {{
            border-color: var(--tf-border);
            background: var(--tf-panel);
            border-radius: 10px;
        }}

        .stButton > button,
        .stDownloadButton > button {{
            border-radius: 10px;
            border-color: var(--tf-border);
            font-weight: 720;
            transition:
                transform 120ms ease,
                border-color 120ms ease,
                background 120ms ease;
        }}

        .stButton > button:hover,
        .stDownloadButton > button:hover {{
            transform: translateY(-1px);
            border-color: var(--tf-accent);
        }}

        .stButton > button[kind="primary"] {{
            background: var(--tf-accent);
            border-color: var(--tf-accent);
            color: #05201C;
        }}

        div[data-testid="stAlert"] {{
            border-radius: 12px;
            border-width: 1px;
        }}

        div[data-testid="stMetric"] {{
            border: 1px solid var(--tf-border);
            border-radius: 12px;
            padding: 0.62rem 0.7rem;
            background: var(--tf-panel);
        }}

        @media (max-width: 900px) {{
            .tf-hero {{
                display: block;
            }}

            .tf-hero-meta {{
                justify-content: flex-start;
                margin-top: 0.85rem;
            }}

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
            <div class="tf-hero-main">
                <div class="tf-eyebrow">DNS threat analysis workspace</div>
                <div class="tf-hero-title">ThreatFusion <span>AI</span></div>
                <div class="tf-hero-subtitle">
                    Triage DNS telemetry with known threat intelligence,
                    machine-learning signals, DNS behavior, and explainable
                    evidence in one local-first workflow.
                </div>
            </div>
            <div class="tf-hero-meta">
                <span class="tf-chip tf-chip-accent">Explainable</span>
                <span class="tf-chip">Local-first</span>
                <span class="tf-chip">Privacy-aware</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar_brand() -> None:
    st.sidebar.markdown(
        """
        <div class="tf-sidebar-brand">
            <div class="tf-brand-mark">TF</div>
            <div>
                <div class="tf-sidebar-brand-title">ThreatFusion AI</div>
                <div class="tf-sidebar-brand-sub">
                    Threat analysis workspace
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def sidebar_label(text: str) -> None:
    st.sidebar.markdown(
        f'<div class="tf-sidebar-label">{safe_text(text)}</div>',
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
            <span class="tf-status-label">{safe_text(label)}</span>
            <span class="tf-status-value {tone_class}">
                {safe_text(value)}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def source_status_card(row: dict[str, object]) -> None:
    status = str(row.get("Status") or "Unknown")
    tone_class = {
        "Fresh": "tf-tone-good",
        "Stale": "tf-tone-warn",
        "Unknown": "tf-tone-info",
    }.get(status, "tf-tone-info")
    records = row.get("Records", 0)
    inactive = row.get("Inactive history", 0)
    st.sidebar.markdown(
        f"""
        <div class="tf-source-card">
            <div class="tf-source-head">
                <span class="tf-source-name">
                    {safe_text(row.get("Source", "Unknown"))}
                </span>
                <span class="tf-source-state {tone_class}">
                    {safe_text(status)}
                </span>
            </div>
            <div class="tf-source-meta">
                <div class="tf-source-stat">
                    <strong>{safe_text(f"{records:,}")}</strong>
                    active indicators
                </div>
                <div class="tf-source-stat">
                    <strong>{safe_text(row.get("Age", "Unknown"))}</strong>
                    cache age
                </div>
                <div class="tf-source-stat">
                    <strong>{safe_text(row.get("Stale after", "Unknown"))}</strong>
                    freshness limit
                </div>
                <div class="tf-source-stat">
                    <strong>{safe_text(f"{inactive:,}")}</strong>
                    inactive history
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_page_intro(
    title: str,
    description: str,
    *,
    eyebrow: str | None = None,
) -> None:
    eyebrow_html = (
        f'<div class="tf-eyebrow">{safe_text(eyebrow)}</div>'
        if eyebrow
        else ""
    )
    st.markdown(
        f"""
        <div class="tf-page-intro">
            {eyebrow_html}
            <div class="tf-page-title">{safe_text(title)}</div>
            <div class="tf-page-copy">{safe_text(description)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pipeline_overview() -> None:
    steps = (
        (
            "Normalize",
            "Parse the selected DNS format and validate usable fields.",
        ),
        (
            "Correlate",
            "Match domains and infrastructure against the local CTI cache.",
        ),
        (
            "Score",
            "Combine ML and DNS-behavior signals with deterministic evidence.",
        ),
        (
            "Explain",
            "Prioritize findings and expose the reasoning behind each verdict.",
        ),
    )
    step_html = "".join(
        f"""
        <div class="tf-pipeline-step">
            <div class="tf-pipeline-index">{index}</div>
            <div>
                <div class="tf-pipeline-name">{safe_text(name)}</div>
                <div class="tf-pipeline-copy">{safe_text(copy)}</div>
            </div>
        </div>
        """
        for index, (name, copy) in enumerate(steps, start=1)
    )
    st.markdown(
        f"""
        <div class="tf-pipeline">
            <div class="tf-pipeline-title">Analysis pipeline</div>
            {step_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_privacy_note() -> None:
    st.markdown(
        """
        <div class="tf-note">
            <span class="tf-note-dot">●</span>
            <span>
                Raw DNS rows and client IP values stay in memory during
                analysis. They are not written to saved analysis history.
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
        <div class="tf-metric-card" style="--tf-card-accent:{accent_color}">
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
