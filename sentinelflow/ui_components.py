"""Reusable UI Components and SOC Visual Design System for SentinelFlow AI.

Implements the futuristic SOC dashboard styling: near-black navy background,
cyan/electric blue borders, restrained glow, high-contrast metric cards, and responsive layouts.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
import streamlit as st

from sentinelflow.config import (
    COLOR_BG_DARK,
    COLOR_PANEL_BG,
    COLOR_PANEL_BORDER,
    COLOR_ACCENT_CYAN,
    COLOR_ACCENT_BLUE,
    COLOR_CRITICAL,
    COLOR_HIGH,
    COLOR_MEDIUM,
    COLOR_LOW,
    COLOR_INFO,
    COLOR_SUCCESS,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
    SIMULATION_DISCLAIMER,
)


def inject_custom_css():
    """Inject global CSS rules to transform Streamlit into a futuristic SOC dashboard."""
    css = f"""
    <style>
    /* Global Application Styles */
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Outfit', sans-serif;
        background-color: {COLOR_BG_DARK} !important;
        color: {COLOR_TEXT_PRIMARY};
    }}

    code, pre, .mono-font {{
        font-family: 'JetBrains Mono', monospace !important;
    }}

    /* Top Padding Adjustment */
    .block-container {{
        padding-top: 1.5rem !important;
        padding-bottom: 2rem !important;
        max-width: 98% !important;
    }}

    /* Cyber Glass Cards */
    .soc-card {{
        background: linear-gradient(135deg, rgba(17, 24, 39, 0.95) 0%, rgba(15, 23, 42, 0.90) 100%);
        border: 1px solid {COLOR_PANEL_BORDER};
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.85rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        position: relative;
        overflow: hidden;
    }}

    .soc-card-accent {{
        border-left: 3px solid {COLOR_ACCENT_CYAN} !important;
    }}

    .soc-card-critical {{
        border-left: 3px solid {COLOR_CRITICAL} !important;
    }}

    .soc-card-high {{
        border-left: 3px solid {COLOR_HIGH} !important;
    }}

    .soc-card-success {{
        border-left: 3px solid {COLOR_SUCCESS} !important;
    }}

    /* Top Navigation Bar */
    .soc-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: linear-gradient(90deg, #070b12 0%, #0f172a 100%);
        border-bottom: 1px solid rgba(0, 240, 255, 0.25);
        padding: 0.75rem 1.5rem;
        margin-bottom: 1.25rem;
        border-radius: 8px;
    }}

    .soc-brand {{
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }}

    .soc-brand-icon {{
        font-size: 1.8rem;
        color: {COLOR_ACCENT_CYAN};
        text-shadow: 0 0 10px rgba(0, 240, 255, 0.6);
    }}

    .soc-brand-title {{
        font-size: 1.35rem;
        font-weight: 700;
        letter-spacing: 0.08em;
        color: #ffffff;
        margin: 0;
        line-height: 1.2;
    }}

    .soc-brand-sub {{
        font-size: 0.72rem;
        letter-spacing: 0.14em;
        color: {COLOR_ACCENT_CYAN};
        text-transform: uppercase;
        margin: 0;
    }}

    /* Badges */
    .badge {{
        display: inline-block;
        padding: 0.2rem 0.55rem;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        border-radius: 4px;
        text-transform: uppercase;
        font-family: 'JetBrains Mono', monospace;
    }}

    .badge-critical {{
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }}

    .badge-high {{
        background: rgba(249, 115, 22, 0.15);
        color: #fb923c;
        border: 1px solid rgba(249, 115, 22, 0.4);
    }}

    .badge-medium {{
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }}

    .badge-low {{
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid rgba(56, 189, 248, 0.4);
    }}

    .badge-info {{
        background: rgba(100, 116, 139, 0.15);
        color: #94a3b8;
        border: 1px solid rgba(100, 116, 139, 0.4);
    }}

    .badge-success {{
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
    }}

    .badge-demo {{
        background: rgba(0, 240, 255, 0.12);
        color: #00f0ff;
        border: 1px solid rgba(0, 240, 255, 0.5);
        box-shadow: 0 0 8px rgba(0, 240, 255, 0.3);
    }}

    /* KPI Metric Tiles */
    .kpi-tile {{
        background: linear-gradient(180deg, #111827 0%, #0f172a 100%);
        border: 1px solid #1e293b;
        border-radius: 6px;
        padding: 0.85rem 1rem;
        text-align: left;
    }}

    .kpi-title {{
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: {COLOR_TEXT_SECONDARY};
        margin-bottom: 0.25rem;
    }}

    .kpi-value {{
        font-size: 1.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1;
        margin-bottom: 0.2rem;
    }}

    .kpi-subtitle {{
        font-size: 0.72rem;
        color: #64748b;
    }}

    /* Simulation Notice Banner */
    .sim-banner {{
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(0, 240, 255, 0.2);
        border-radius: 6px;
        padding: 0.45rem 0.85rem;
        font-size: 0.75rem;
        color: {COLOR_TEXT_SECONDARY};
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.75rem;
    }}

    /* Buttons customization */
    .stButton>button {{
        border-radius: 4px !important;
        font-family: 'Outfit', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: 0.04em !important;
        transition: all 0.2s ease-in-out !important;
    }}

    .stButton>button:hover {{
        box-shadow: 0 0 12px rgba(0, 240, 255, 0.3) !important;
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def render_header(
    pending_approvals: int = 0,
    active_mode: str = "AUTO",
    gemini_ready: bool = False,
):
    """Render the top SOC navigation brand header."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    mode_text = (
        "GEMINI AI ACTIVE"
        if (gemini_ready and active_mode in ("auto", "gemini_ai", "gemini_only"))
        else "DETERMINISTIC DEMO MODE"
    )
    mode_class = "badge-success" if (gemini_ready and active_mode != "deterministic") else "badge-demo"

    pending_html = ""
    if pending_approvals > 0:
        pending_html = f"""
        <span class="badge badge-high" title="Simulated containment actions awaiting analyst approval">
            ⚠️ {pending_approvals} PENDING APPROVAL
        </span>
        """

    header_html = f"""
    <div class="soc-header">
        <div class="soc-brand">
            <span class="soc-brand-icon">🛡️</span>
            <div>
                <h1 class="soc-brand-title">SENTINELFLOW AI</h1>
                <p class="soc-brand-sub">Autonomous Incident Investigation & Response Simulation</p>
            </div>
        </div>
        <div style="display: flex; align-items: center; gap: 0.85rem; flex-wrap: wrap;">
            <span class="badge badge-demo">🔴 SYNTHETIC DEMO ENVIRONMENT</span>
            <span class="badge {mode_class}">⚡ {mode_text}</span>
            {pending_html}
            <span class="badge badge-info" style="font-family:'JetBrains Mono',monospace;">🕒 {now_str}</span>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_simulation_banner():
    """Render the explicit simulation safety disclaimer."""
    st.markdown(
        f"""
        <div class="sim-banner">
            <span style="color:#00f0ff;">ℹ️</span>
            <span><b>Controlled Simulation:</b> {SIMULATION_DISCLAIMER}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpi_card(
    title: str,
    value: Any,
    subtitle: str = "",
    color: str = COLOR_ACCENT_CYAN,
    icon: str = "",
):
    """Render a single high-contrast KPI metric tile."""
    st.markdown(
        f"""
        <div class="kpi-tile">
            <div class="kpi-title">{icon} {title}</div>
            <div class="kpi-value" style="color:{color};">{value}</div>
            <div class="kpi-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_severity_badge(severity: str) -> str:
    """Return HTML string for a styled severity badge."""
    sev = severity.upper()
    cls_map = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
        "INFORMATIONAL": "badge-info",
    }
    cls = cls_map.get(sev, "badge-info")
    return f'<span class="badge {cls}">{sev}</span>'


def render_status_badge(status: str) -> str:
    """Return HTML string for an incident or response status badge."""
    st_upper = status.upper()
    if st_upper in ("RESOLVED", "VERIFIED", "APPROVED"):
        cls = "badge-success"
    elif st_upper in ("CRITICAL", "FAILED_VERIFICATION", "FAILED_EXECUTION", "REJECTED"):
        cls = "badge-critical"
    elif st_upper in ("AWAITING_APPROVAL", "CONTAINMENT_PROPOSED", "INVESTIGATING", "ESCALATED"):
        cls = "badge-high"
    elif st_upper in ("MONITORING", "OPEN"):
        cls = "badge-low"
    else:
        cls = "badge-info"
    return f'<span class="badge {cls}">{status}</span>'
