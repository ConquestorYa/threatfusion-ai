"""Theme-aware, aggregate-only analysis figures."""

from __future__ import annotations
import pandas as pd
import plotly.graph_objects as go
from .dashboard import build_relationship_graph
from .i18n import tr
from .ui_theme import VERDICT_COLORS, apply_plotly_theme, palette


def _verdict_chart(summary) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "verdict": [
                "Known Threat",
                "High Risk",
                "Review",
                "Low",
            ],
            "count": [
                summary.known_threat_count,
                summary.high_risk_count,
                summary.review_count,
                summary.low_count,
            ],
        }
    )


def _verdict_distribution_figure(summary) -> go.Figure:
    frame = _verdict_chart(summary)
    display_labels = [tr(label) for label in frame["verdict"]]
    figure = go.Figure(
        data=[
            go.Pie(
                labels=display_labels,
                values=frame["count"],
                hole=0.70,
                sort=False,
                marker={
                    "colors": [VERDICT_COLORS[label] for label in frame["verdict"]]
                },
                textinfo="none",
                hovertemplate=(f"<b>%{{label}}</b><br>{tr('Domains')}: %{{value}}<extra></extra>"),
            )
        ]
    )
    figure.add_annotation(
        text=(f"<b>{summary.domain_count}</b><br><span>{tr('domains')}</span>"),
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 17},
        align="center",
    )
    figure.update_layout(
        showlegend=True, legend={"orientation": "h", "y": -0.08, "x": 0}
    )
    return apply_plotly_theme(figure, height=265)


def _relationship_figure(report, result) -> go.Figure:
    graph = build_relationship_graph(report, result)
    colors = palette()
    figure = go.Figure()

    for edge in graph.edges:
        figure.add_trace(
            go.Scatter(
                x=[edge.x0, edge.x1],
                y=[edge.y0, edge.y1],
                mode="lines",
                line={
                    "width": 1.0 + (edge.strength * 3.0),
                    "color": colors["muted"],
                },
                opacity=0.42,
                hoverinfo="text",
                text=[edge.hover_text, edge.hover_text],
                showlegend=False,
            )
        )

    if graph.nodes:
        node_colors = [
            VERDICT_COLORS.get(node.verdict, colors["cyan"]) for node in graph.nodes
        ]
        figure.add_trace(
            go.Scatter(
                x=[node.x for node in graph.nodes],
                y=[node.y for node in graph.nodes],
                mode="markers+text",
                marker={
                    "size": 21,
                    "color": node_colors,
                    "line": {
                        "width": 2,
                        "color": colors["panel"],
                    },
                },
                text=[node.domain for node in graph.nodes],
                textposition="top center",
                textfont={"size": 11},
                hoverinfo="text",
                hovertext=[
                    (
                        f"{node.domain}<br>"
                        f"{tr('Group')}: {node.cluster_id}<br>"
                        f"{tr('Verdict')}: {tr(node.verdict)}<br>"
                        f"{tr('ML tier')}: {tr(node.ml_tier)}<br>"
                        f"{tr('Known CTI sources')}: "
                        f"{', '.join(node.known_sources) or tr('None')}"
                    )
                    for node in graph.nodes
                ],
                showlegend=False,
            )
        )

    figure.update_layout(
        title={
            "text": tr("Possible related-activity graph"),
            "font": {"size": 15},
        },
        xaxis={"visible": False},
        yaxis={"visible": False},
        hovermode="closest",
    )
    return apply_plotly_theme(figure, height=440)
