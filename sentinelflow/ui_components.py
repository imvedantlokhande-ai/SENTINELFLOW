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

    /* Smooth Flutter-grade Touch Interactions & Micro-animations */
    * {{
        -webkit-tap-highlight-color: rgba(0, 240, 255, 0.15) !important;
        box-sizing: border-box;
    }}

    /* Custom Cyber Sleek Scrollbar */
    ::-webkit-scrollbar {{
        width: 6px;
        height: 6px;
    }}
    ::-webkit-scrollbar-track {{
        background: #070b12;
    }}
    ::-webkit-scrollbar-thumb {{
        background: #1e293b;
        border-radius: 3px;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: {COLOR_ACCENT_CYAN};
        box-shadow: 0 0 6px rgba(0, 240, 255, 0.5);
    }}

    /* Buttons customization & Touch Targets (WCAG 2.2 AA & Material/Flutter) */
    .stButton>button {{
        border-radius: 6px !important;
        font-family: 'Outfit', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: 0.04em !important;
        transition: transform 0.12s ease-out, box-shadow 0.2s ease-in-out !important;
        min-height: 46px !important;
        min-width: 44px !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
    }}

    .stButton>button:hover {{
        box-shadow: 0 0 14px rgba(0, 240, 255, 0.35) !important;
    }}

    .stButton>button:active {{
        transform: scale(0.97) !important;
    }}

    /* Interactive Card Micro-elevation */
    .soc-card {{
        transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.2s ease !important;
    }}
    .soc-card:hover {{
        transform: translateY(-1px);
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.5) !important;
    }}

    /* Accessibility Focus Indicators */
    *:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible {{
        outline: 2px solid {COLOR_ACCENT_CYAN} !important;
        outline-offset: 2px !important;
    }}

    /* Inputs touch target sizing */
    .stTextInput input, .stSelectbox select {{
        min-height: 46px !important;
        border-radius: 6px !important;
    }}

    /* =========================================================================
       DEVICE BREAKPOINT OPTIMIZATION (PC, LAPTOP, TABLET, MOBILE)
       ========================================================================= */

    /* Desktop & Large Laptops (1200px+) */
    @media (min-width: 1200px) {{
        .block-container {{
            max-width: 1560px !important;
            margin: 0 auto !important;
        }}
    }}

    /* Tablet Screen Optimization (768px - 1024px: iPad, Android Tablets, Foldables) */
    @media (min-width: 768px) and (max-width: 1024px) {{
        .block-container {{
            max-width: 96% !important;
            padding: 1.25rem 1rem !important;
        }}
        /* Top Control Bar: adapt 4 columns into 2x2 grid */
        div[data-testid="column"] {{
            min-width: 48% !important;
            flex: 1 1 48% !important;
            margin-bottom: 0.75rem !important;
        }}
        .kpi-tile {{
            padding: 0.75rem 0.85rem !important;
        }}
        .kpi-value {{
            font-size: 1.5rem !important;
        }}
        .soc-brand-title {{
            font-size: 1.25rem !important;
        }}
    }}

    /* Mobile Phones (320px - 767px: iPhone SE, 13/14/15, Pixel, Galaxy) */
    @media (max-width: 767px) {{
        /* Full width stacking for columns */
        div[data-testid="column"] {{
            min-width: 100% !important;
            flex: 1 1 100% !important;
            margin-bottom: 0.85rem !important;
        }}

        .block-container {{
            padding-left: 0.65rem !important;
            padding-right: 0.65rem !important;
            padding-top: 0.75rem !important;
            padding-bottom: calc(2rem + env(safe-area-inset-bottom, 16px)) !important;
        }}

        /* Touch Swipeable Horizontal Tabs */
        .stTabs [data-baseweb="tab-list"] {{
            display: flex !important;
            overflow-x: auto !important;
            -webkit-overflow-scrolling: touch !important;
            flex-wrap: nowrap !important;
            scrollbar-width: none !important;
            gap: 0.35rem !important;
            padding-bottom: 0.3rem !important;
        }}
        .stTabs [data-baseweb="tab-list"]::-webkit-scrollbar {{
            display: none !important;
        }}
        .stTabs [data-baseweb="tab"] {{
            flex: 0 0 auto !important;
            white-space: nowrap !important;
            font-size: 0.82rem !important;
            padding: 0.5rem 0.75rem !important;
        }}

        .soc-header {{
            flex-direction: column !important;
            align-items: flex-start !important;
            padding: 0.75rem 0.85rem !important;
            gap: 0.65rem !important;
        }}

        .soc-brand {{
            width: 100% !important;
        }}

        .soc-brand-title {{
            font-size: 1.12rem !important;
        }}

        .soc-brand-sub {{
            font-size: 0.65rem !important;
        }}

        .kpi-tile {{
            margin-bottom: 0.5rem !important;
            padding: 0.75rem !important;
        }}

        .kpi-value {{
            font-size: 1.4rem !important;
        }}

        .soc-card {{
            padding: 0.85rem 1rem !important;
        }}

        /* 48px touch targets for mobile thumb navigation */
        .stButton>button, .stTextInput input, .stSelectbox select {{
            min-height: 48px !important;
            font-size: 0.9rem !important;
        }}
    }}

    /* Smallest Mobile Displays (320px - 375px) */
    @media (max-width: 375px) {{
        .soc-brand-title {{
            font-size: 1rem !important;
        }}
        .soc-brand-icon {{
            font-size: 1.4rem !important;
        }}
        .badge {{
            font-size: 0.62rem !important;
            padding: 0.15rem 0.35rem !important;
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

    /* PWA Install Banner Card */
    .soc-pwa-card {{
        background: linear-gradient(90deg, rgba(15, 23, 42, 0.95) 0%, rgba(7, 11, 18, 0.95) 100%);
        border: 1px solid rgba(0, 240, 255, 0.4);
        border-radius: 8px;
        padding: 0.75rem 1.25rem;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        flex-wrap: wrap;
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def render_header(
    pending_approvals: int = 0,
    active_mode: str = "AUTO",
    gemini_ready: bool = False,
    user_session: Optional[Any] = None,
):
    """Render the top SOC navigation brand header with role and authentication badges."""
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

    # Active User & Role badge
    user = user_session or st.session_state.get("current_user")
    if user:
        role_upper = getattr(user, "role", "viewer").upper()
        role_icon = "👑" if role_upper == "ADMINISTRATOR" else ("🛡️" if role_upper == "ANALYST" else "👁️")
        role_badge_class = "badge-critical" if role_upper == "ADMINISTRATOR" else ("badge-demo" if role_upper == "ANALYST" else "badge-info")
        auth_html = f"""
        <span class="badge {role_badge_class}" title="Authenticated Session: {getattr(user, 'email', '')}">
            {role_icon} {role_upper}: {getattr(user, 'email', '').split('@')[0]}
        </span>
        """
    else:
        auth_html = """<span class="badge badge-info">👤 GUEST</span>"""

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
            {auth_html}
            {pending_html}
            <span class="badge badge-info" style="font-family:'JetBrains Mono',monospace;">🕒 {now_str}</span>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def render_auth_modal():
    """Render the Firebase & Role-Based Authentication panel."""
    current_user = st.session_state.get("current_user")
    if not current_user:
        return

    role_str = getattr(current_user, "role", "viewer").upper()
    email_str = getattr(current_user, "email", "user@sentinelflow.ai")
    remaining_sec = current_user.get_remaining_seconds() if hasattr(current_user, "get_remaining_seconds") else 3600

    with st.expander(f"🔐 Identity, Firebase Auth & RBAC Settings [{role_str} &bull; {email_str}]", expanded=st.session_state.get("show_auth_modal", False)):
        st.markdown(
            f"""
            <div style="font-size:0.8rem; color:#94a3b8; margin-bottom:0.75rem;">
                <b>Authenticated Session:</b> <code>{getattr(current_user, 'uid', '')}</code> &bull; 
                <b>Provider:</b> {getattr(current_user, 'auth_provider', 'demo_auth')} &bull; 
                <b>Session Expiry:</b> {remaining_sec}s remaining
            </div>
            """,
            unsafe_allow_html=True,
        )

        tab1, tab2, tab3 = st.tabs(["⚡ Fast Role Switcher (Demo)", "🔥 Firebase ID Token Verification", "🔑 Email & Password Login"])

        with tab1:
            st.markdown("<p style='font-size:0.85rem; color:#f8fafc;'>Switch active persona to test server-side Role-Based Access Control (RBAC):</p>", unsafe_allow_html=True)
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("👑 Switch to Administrator", key="auth_switch_admin", use_container_width=True):
                    from sentinelflow.auth import get_default_demo_session
                    st.session_state.current_user = get_default_demo_session("administrator")
                    st.session_state.audit_trail.log(
                        event_type="AUTH_ROLE_SWITCHED",
                        status="SUCCESS",
                        actor="admin@sentinelflow.ai",
                        details="Switched active session to Administrator role.",
                    )
                    st.success("Active Session: Administrator (Full Privileges)")
                    st.rerun()
            with col2:
                if st.button("🛡️ Switch to Analyst", key="auth_switch_analyst", use_container_width=True):
                    from sentinelflow.auth import get_default_demo_session
                    st.session_state.current_user = get_default_demo_session("analyst")
                    st.session_state.audit_trail.log(
                        event_type="AUTH_ROLE_SWITCHED",
                        status="SUCCESS",
                        actor="analyst@sentinelflow.ai",
                        details="Switched active session to Analyst role.",
                    )
                    st.success("Active Session: Senior Analyst (Triage & Tier-1 Containment)")
                    st.rerun()
            with col3:
                if st.button("👁️ Switch to Viewer (Read-Only)", key="auth_switch_viewer", use_container_width=True):
                    from sentinelflow.auth import get_default_demo_session
                    st.session_state.current_user = get_default_demo_session("viewer")
                    st.session_state.audit_trail.log(
                        event_type="AUTH_ROLE_SWITCHED",
                        status="SUCCESS",
                        actor="viewer@sentinelflow.ai",
                        details="Switched active session to Viewer role.",
                    )
                    st.success("Active Session: Viewer (Read-Only Mode)")
                    st.rerun()

        with tab2:
            st.markdown("<p style='font-size:0.85rem; color:#f8fafc;'>Verify an authentic Firebase ID Token on the trusted server side:</p>", unsafe_allow_html=True)
            token_input = st.text_area("Paste Firebase JWT ID Token", key="auth_jwt_input", height=80, help="Signed JWT issued by Firebase Authentication.")
            if st.button("Verify Token with Google Auth Infrastructure", key="auth_verify_jwt_btn"):
                if not token_input.strip():
                    st.error("Please enter a token.")
                else:
                    try:
                        from sentinelflow.auth import authenticate_user
                        session = authenticate_user(email="firebase_user@sentinelflow.ai", id_token=token_input.strip())
                        st.session_state.current_user = session
                        st.session_state.audit_trail.log(
                            event_type="AUTH_FIREBASE_SUCCESS",
                            status="SUCCESS",
                            actor=session.email,
                            details=f"Firebase ID token verified for UID {session.uid}",
                        )
                        st.success(f"Firebase Token Verified! Logged in as {session.email} [{session.role}]")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Token Verification Rejected: {e}")
                        st.session_state.audit_trail.log(
                            event_type="AUTH_FIREBASE_FAILED",
                            status="FAILURE",
                            actor="unauthenticated",
                            details="Firebase ID token verification failed.",
                        )

        with tab3:
            st.markdown("<p style='font-size:0.85rem; color:#f8fafc;'>Sign in with Email and Password:</p>", unsafe_allow_html=True)
            col_e1, col_e2 = st.columns(2)
            with col_e1:
                login_email = st.text_input("Email Address", value="analyst@sentinelflow.ai", key="auth_email_input")
            with col_e2:
                login_pwd = st.text_input("Password", type="password", value="AnalystPass@2026!", key="auth_pwd_input")

            if st.button("Sign In Securely", key="auth_submit_login_btn", type="primary"):
                try:
                    from sentinelflow.auth import authenticate_user
                    from sentinelflow.rate_limiter import evaluate_rate_limit
                    allowed, remaining, retry_after = evaluate_rate_limit("login", client_ip="127.0.0.1")
                    if not allowed:
                        st.error(f"Rate limit exceeded: Too many login attempts. Cooldown active for {retry_after}s.")
                    else:
                        session = authenticate_user(email=login_email, password=login_pwd)
                        st.session_state.current_user = session
                        st.session_state.audit_trail.log(
                            event_type="AUTH_LOGIN_SUCCESS",
                            status="SUCCESS",
                            actor=session.email,
                            details=f"User {session.email} authenticated successfully.",
                        )
                        st.success(f"Authenticated as {session.email} [{session.role.upper()}]")
                        st.rerun()
                except Exception as e:
                    st.error(f"Authentication Failed: {e}")
                    st.session_state.audit_trail.log(
                        event_type="AUTH_LOGIN_FAILED",
                        status="FAILURE",
                        actor=login_email,
                        details="Authentication failed with invalid credentials.",
                    )



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
    """Inject semantic SEO metadata, canonical URL, Open Graph, Twitter card, and PWA manifest/service worker tags."""
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

    <!-- Progressive Web App (PWA) Metadata -->
    <link rel="manifest" href="/app/static/manifest.json">
    <meta name="theme-color" content="#00f0ff">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="SentinelFlow">
    <link rel="apple-touch-icon" href="/app/static/icon-192.svg">
    <link rel="icon" type="image/svg+xml" href="/app/static/favicon.svg">

    <!-- Service Worker Registration for Offline & PWA Execution -->
    <script>
      if (document.title !== "{title}") {{
        document.title = "{title}";
      }}
      if ('serviceWorker' in navigator) {{
        window.addEventListener('load', function() {{
          navigator.serviceWorker.register('/app/static/service-worker.js', {{ scope: '/' }})
            .then(function(reg) {{
              console.log('[PWA] ServiceWorker registered successfully with scope:', reg.scope);
            }})
            .catch(function(err) {{
              console.log('[PWA] ServiceWorker info:', err);
            }});
        }});
      }}
    </script>
    """
    st.markdown(meta_html, unsafe_allow_html=True)


def render_pwa_install_banner():
    """Render a responsive, native-app install suggestion banner for PC, Laptop, Tablet & Mobile."""
    if st.session_state.get("dismiss_pwa_banner", False):
        return

    st.markdown(
        """
        <div class="soc-pwa-card">
            <div style="display:flex; align-items:center; gap:0.75rem;">
                <span style="font-size:1.4rem;">📲</span>
                <div>
                    <div style="font-size:0.85rem; font-weight:700; color:#00f0ff;">
                        INSTALL SENTINELFLOW PWA
                    </div>
                    <div style="font-size:0.75rem; color:#94a3b8;">
                        Install as a standalone app on PC, Mac, Tablet, or Mobile for offline caching and zero-latency windowed SOC monitoring.
                    </div>
                </div>
            </div>
            <div style="font-size:0.75rem; color:#64748b; font-family:'JetBrains Mono',monospace;">
                Chrome / Edge: Click (⊕ Install) in URL bar &bull; Safari / iOS: Tap Share → 'Add to Home Screen'
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


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


def render_footer(key_suffix: str = ""):
    """Render standard footer with links, copyright, PWA status, and Cookie Settings trigger."""
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
                <b>SentinelFlow AI</b> v1.2.0-pwa &bull; Autonomous Cybersecurity Incident Investigation & Safe Response Simulation.
            </p>
            <p style="font-size:0.7rem; color:#475569; margin:0.2rem 0;">
                PWA Enabled &bull; Optimised for Mobile, Tablet, Laptop, and PC &bull; Air-Gapped Synthetic SOC Telemetry
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_c, col_pwa = st.columns([3, 9])
    with col_c:
        btn_key = f"footer_cookie_btn_{key_suffix}" if key_suffix else "footer_cookie_btn"
        if st.button("🍪 Manage Cookie Preferences", key=btn_key, type="secondary"):
            st.session_state.show_cookie_settings = True
            st.rerun()


