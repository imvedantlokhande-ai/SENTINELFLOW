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

    /* Buttons customization & Touch Targets (WCAG 2.2 AA) */
    .stButton>button {{
        border-radius: 4px !important;
        font-family: 'Outfit', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: 0.04em !important;
        transition: all 0.2s ease-in-out !important;
        min-height: 44px !important;
        min-width: 44px !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
    }}

    .stButton>button:hover {{
        box-shadow: 0 0 12px rgba(0, 240, 255, 0.3) !important;
    }}

    /* Accessibility Focus Indicators */
    *:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible {{
        outline: 2px solid {COLOR_ACCENT_CYAN} !important;
        outline-offset: 2px !important;
    }}

    /* Text inputs touch targets */
    .stTextInput input, .stSelectbox select {{
        min-height: 44px !important;
    }}

    /* Mobile Responsiveness & Breakpoints */
    @media (max-width: 768px) {{
        .block-container {{
            padding-left: 0.75rem !important;
            padding-right: 0.75rem !important;
            padding-top: 1rem !important;
        }}

        .soc-header {{
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 0.75rem !important;
            padding: 0.75rem 1rem !important;
        }}

        .soc-brand {{
            width: 100% !important;
        }}

        .kpi-tile {{
            margin-bottom: 0.5rem !important;
        }}

        .soc-card {{
            padding: 0.85rem 1rem !important;
        }}
    }}

    @media (max-width: 480px) {{
        .soc-brand-title {{
            font-size: 1.15rem !important;
        }}
        .soc-brand-sub {{
            font-size: 0.65rem !important;
        }}
        .kpi-value {{
            font-size: 1.4rem !important;
        }}
    }}

    /* Reduced Motion Preference Support */
    @media (prefers-reduced-motion: reduce) {{
        *, ::before, ::after {{
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.01ms !important;
            scroll-behavior: auto !important;
        }}
    }}

    /* Footer styling */
    .soc-footer {{
        margin-top: 2.5rem;
        padding: 1.75rem 1.25rem 1.25rem 1.25rem;
        border-top: 1px solid rgba(0, 240, 255, 0.2);
        background: linear-gradient(180deg, rgba(7, 11, 18, 0.95) 0%, #05070c 100%);
        border-radius: 8px;
        text-align: center;
    }}

    .soc-footer-links {{
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 1.25rem;
        margin-bottom: 1rem;
        font-size: 0.82rem;
    }}

    .soc-footer-link {{
        color: {COLOR_ACCENT_CYAN};
        text-decoration: none;
        transition: color 0.15s ease;
    }}

    .soc-footer-link:hover {{
        color: #ffffff;
        text-decoration: underline;
    }}

    /* Cookie Banner Card */
    .soc-cookie-card {{
        background: #0f172a;
        border: 1px solid {COLOR_ACCENT_CYAN};
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 20px rgba(0, 240, 255, 0.15);
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


def render_seo_meta(
    title: str = "SentinelFlow AI - Autonomous Cybersecurity Investigation & Response Simulation",
    description: str = "AI-powered cybersecurity incident investigation and response simulation platform with human-in-the-loop oversight.",
    path: str = "/",
    og_image: str = "https://sentinelflow.ai/static/og_preview.svg",
):
    """Inject semantic SEO metadata, canonical URL, Open Graph, and Twitter card tags."""
    canonical_url = f"https://sentinelflow.ai{path}"
    meta_html = f"""
    <!-- SEO & Social Sharing Meta Tags -->
    <meta name="description" content="{description}">
    <link rel="canonical" href="{canonical_url}">
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{description}">
    <meta property="og:type" content="website">
    <meta property="og:url" content="{canonical_url}">
    <meta property="og:image" content="{og_image}">
    <meta property="og:site_name" content="SentinelFlow AI">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{title}">
    <meta name="twitter:description" content="{description}">
    <meta name="twitter:image" content="{og_image}">
    <script>
      if (document.title !== "{title}") {{
        document.title = "{title}";
      }}
    </script>
    """
    st.markdown(meta_html, unsafe_allow_html=True)


def render_cookie_consent():
    """Render a professional, non-intrusive cookie consent banner with category preferences."""
    if "cookie_consent" not in st.session_state:
        st.session_state.cookie_consent = None
    if "show_cookie_settings" not in st.session_state:
        st.session_state.show_cookie_settings = False

    # If consent has not been decided yet or user opened settings
    if st.session_state.cookie_consent is None or st.session_state.show_cookie_settings:
        with st.container():
            st.markdown(
                f"""
                <div class="soc-cookie-card">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div style="display:flex; align-items:center; gap:0.5rem;">
                            <span style="font-size:1.2rem;">🍪</span>
                            <span style="font-size:0.9rem; font-weight:700; color:#ffffff;">COOKIE & PRIVACY PREFERENCES</span>
                        </div>
                        <span class="badge badge-demo">PRIVACY-FIRST</span>
                    </div>
                    <p style="font-size:0.8rem; color:{COLOR_TEXT_SECONDARY}; margin:0.4rem 0 0.75rem 0; line-height:1.5;">
                        SentinelFlow AI uses <b>strictly necessary cookies</b> for session security and CSRF protection.
                        With your permission, we also collect <b>anonymous operational telemetry</b> (e.g. simulation latency and scenario engagement)
                        to benchmark correlation engines. No personal data or credentials are ever collected.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            col_btn1, col_btn2, col_btn3 = st.columns([2, 2, 3])
            with col_btn1:
                if st.button("✅ Accept All", key="cookie_accept_all", type="primary", use_container_width=True):
                    st.session_state.cookie_consent = {
                        "necessary": True,
                        "analytics": True,
                        "decided": True,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    st.session_state.show_cookie_settings = False
                    st.rerun()

            with col_btn2:
                if st.button("🛡️ Reject Optional", key="cookie_reject_optional", use_container_width=True):
                    st.session_state.cookie_consent = {
                        "necessary": True,
                        "analytics": False,
                        "decided": True,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                    st.session_state.show_cookie_settings = False
                    st.rerun()

            with col_btn3:
                with st.expander("⚙️ Customize Preferences", expanded=st.session_state.show_cookie_settings):
                    st.write("**Strictly Necessary Cookies:** Always active (required for session state & security).")
                    analytics_toggle = st.checkbox(
                        "Performance & Operational Telemetry",
                        value=True if (st.session_state.cookie_consent and st.session_state.cookie_consent.get("analytics")) else False,
                        help="Anonymous benchmark metrics (e.g., event correlation throughput).",
                    )
                    if st.button("Save Custom Preferences", key="cookie_save_custom", type="secondary"):
                        st.session_state.cookie_consent = {
                            "necessary": True,
                            "analytics": analytics_toggle,
                            "decided": True,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                        st.session_state.show_cookie_settings = False
                        st.success("Preferences saved.")
                        st.rerun()


def render_footer():
    """Render standard footer with links, copyright, and Cookie Settings trigger."""
    st.markdown(
        f"""
        <div class="soc-footer">
            <div class="soc-footer-links">
                <a href="/" class="soc-footer-link">Dashboard</a>
                <a href="/Incidents" class="soc-footer-link">Incidents</a>
                <a href="/Threat_Intelligence" class="soc-footer-link">Threat Intel</a>
                <a href="/Response_Center" class="soc-footer-link">Response Center</a>
                <a href="/Audit_Timeline" class="soc-footer-link">Audit Trail</a>
                <a href="/Analytics" class="soc-footer-link">Analytics</a>
                <a href="/Settings" class="soc-footer-link">Settings</a>
                <a href="/Privacy_Policy" class="soc-footer-link">Privacy Policy</a>
                <a href="/Terms" class="soc-footer-link">Terms & Conditions</a>
            </div>
            <p style="font-size:0.75rem; color:#64748b; margin:0.3rem 0;">
                <b>SentinelFlow AI</b> v1.2.0-prod &bull; Autonomous Cybersecurity Incident Investigation & Safe Response Simulation.
            </p>
            <p style="font-size:0.7rem; color:#475569; margin:0.2rem 0;">
                All scenarios, alerts, indicators of compromise, and telemetry are synthetic. No production credentials or live endpoints are accessed.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_c, _ = st.columns([3, 9])
    with col_c:
        if st.button("🍪 Manage Cookie Preferences", key=f"footer_cookie_btn_{st.session_state.get('footer_count', 0)}", type="secondary"):
            st.session_state.show_cookie_settings = True
            st.rerun()

