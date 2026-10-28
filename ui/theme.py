"""Restrained light theme and shared chart styling for SecureTrack."""

from __future__ import annotations

import re
from typing import Any

import plotly.graph_objects as go
import streamlit as st

APP_CSS = """
:root {
    --st-border: #dbe4ec;
    --st-muted: #5b6776;
    --st-text: #1f2933;
    --st-surface: #f7f9fb;
}

.block-container {
    max-width: 1280px;
    padding-top: 2.1rem;
    padding-bottom: 3rem;
}

h1, h2, h3 {
    color: var(--st-text);
    letter-spacing: -0.02em;
}

h1 {
    font-size: 2.1rem;
    margin-bottom: 0.1rem;
}

h2 {
    font-size: 1.35rem;
    margin-top: 1.2rem;
}

h3 {
    font-size: 1.05rem;
}

p, li, label {
    color: var(--st-text);
}

[data-testid="stCaptionContainer"] {
    color: var(--st-muted);
}

[data-testid="stSidebar"] {
    background: var(--st-surface);
    border-right: 1px solid var(--st-border);
}

[data-testid="stSidebar"] .block-container {
    padding-top: 1.4rem;
}

[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    margin-top: 0.5rem;
}

[data-testid="stMetric"] {
    background: #ffffff;
    border: 1px solid var(--st-border);
    border-radius: 8px;
    padding: 0.75rem 0.9rem;
}

[data-testid="stMetricLabel"] {
    color: var(--st-muted);
    font-size: 0.75rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}

[data-testid="stMetricValue"] {
    color: var(--st-text);
    font-size: 1.5rem;
}

[data-testid="stTabs"] [data-baseweb="tab-list"] {
    gap: 1.25rem;
    border-bottom: 1px solid var(--st-border);
}

[data-testid="stTabs"] button[data-baseweb="tab"] {
    font-weight: 600;
    padding-left: 0;
    padding-right: 0;
}

.stButton > button,
.stDownloadButton > button {
    border-radius: 6px;
}

[data-testid="stExpander"] details {
    border: 1px solid var(--st-border);
    border-radius: 8px;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--st-border);
    border-radius: 8px;
}

hr {
    border-color: var(--st-border);
}

[data-testid="stAlert"] {
    border-radius: 8px;
}

[data-testid="stToolbar"] {
    visibility: hidden;
}

/* Two metric cards per row keep every label readable at tablet widths. */
@media (max-width: 1000px) {
    div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"]:has(
        [data-testid="stMetric"]
    ) {
        flex: 1 1 45% !important;
        min-width: 45% !important;
        max-width: 45% !important;
    }
}

@media (max-width: 760px) {
    .block-container {
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }

    div[data-testid="stHorizontalBlock"] {
        flex-wrap: wrap !important;
        gap: 0.75rem !important;
    }

    /* Fallback for browsers without :has(): stack every column. */
    div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"] {
        flex: 1 1 100% !important;
        min-width: 100% !important;
    }

    div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"]:has(
        [data-testid="stMetric"]
    ) {
        flex: 1 1 45% !important;
        min-width: 45% !important;
    }
}

@media (max-width: 480px) {
    div[data-testid="stHorizontalBlock"] > div[data-testid="stColumn"]:has(
        [data-testid="stMetric"]
    ) {
        flex: 1 1 100% !important;
        min-width: 100% !important;
        max-width: 100% !important;
    }

    /* Keep all four tab labels reachable on narrow phones. */
    [data-testid="stTabs"] [data-baseweb="tab-list"] {
        gap: 0.55rem;
        overflow-x: auto;
    }

    [data-testid="stTabs"] button[data-baseweb="tab"] {
        font-size: 0.78rem;
        padding-left: 0;
        padding-right: 0;
    }
}
"""

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|>])")


def apply_theme() -> None:
    """Inject the static application stylesheet."""
    st.markdown(f"<style>{APP_CSS}</style>", unsafe_allow_html=True)


def escape_markdown(value: Any) -> str:
    """Escape untrusted display text before placing it in Markdown.

    Most user-controlled values are shown in plain widgets (tables, badges,
    captions), but file names are occasionally included in a small Markdown
    line. Escaping keeps that path predictable.
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", str(value))


def style_figure(fig: go.Figure, *, height: int = 320) -> go.Figure:
    """Apply a consistent, readable chart treatment."""
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=14, b=8),
        font=dict(
            family="Segoe UI, Arial, sans-serif",
            size=12,
            color="#243447",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#ffffff",
        hoverlabel=dict(
            bgcolor="#ffffff",
            bordercolor="#dbe4ec",
            font=dict(color="#1f2933", size=12),
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="left",
            x=0,
            title=None,
        ),
    )
    fig.update_xaxes(
        showgrid=False,
        linecolor="#cbd5e1",
        tickcolor="#cbd5e1",
        zeroline=False,
    )
    fig.update_yaxes(
        gridcolor="#e7edf3",
        linecolor="#cbd5e1",
        tickcolor="#cbd5e1",
        zeroline=False,
    )
    return fig
