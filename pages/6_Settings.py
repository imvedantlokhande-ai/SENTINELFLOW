"""SentinelFlow AI - Settings & Configuration Page."""

import streamlit as st
import re
from sentinelflow.config import (
    COLOR_ACCENT_CYAN,
    DEFAULT_GEMINI_MODEL,
    AVAILABLE_GEMINI_MODELS,
)
from sentinelflow.state import init_session_state, reset_demo_data
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_seo_meta,
    render_cookie_consent,
    render_footer,
)

st.set_page_config(page_title="Settings | SentinelFlow AI", page_icon="⚙️", layout="wide")
init_session_state(st)
inject_custom_css()
render_seo_meta(
    title="System Settings & Security Safeguards | SentinelFlow AI",
    description="Configure Gemini API credentials, select reasoning models, and manage synthetic scenario registries.",
    path="/Settings",
)

pending_count = sum(1 for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval"))
render_header(pending_approvals=pending_count, active_mode=st.session_state.analysis_mode_override)
render_simulation_banner()
render_cookie_consent()

st.markdown("<h2 style='color:#ffffff; margin-bottom:0.25rem;'>⚙️ Platform Settings & AI Configuration</h2>", unsafe_allow_html=True)

with st.form("settings_form_page"):
    st.write("### Google Gemini AI Engine Configuration")
    api_val = st.text_input(
        "Gemini API Key",
        value="" if not st.session_state.gemini_api_key else "••••••••••••••••••••••••••••••••",
        type="password",
        help="Stored in server-side session memory only. Never logged or written to persistent storage.",
    )
    model_choice = st.selectbox(
        "Gemini Model",
        options=["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.1-pro-preview"],
        index=0,
    )
    mode_choice = st.selectbox(
        "Operational Mode",
        options=["auto", "deterministic", "gemini_ai"],
        format_func=lambda m: "Auto (Gemini AI with Deterministic Fallback)" if m == "auto" else ("Deterministic Demo Only" if m == "deterministic" else "Gemini AI Live Only"),
        index=0,
    )
    clear_key = st.checkbox("Clear current API Key (switch to deterministic mode)", value=False)
    
    save_btn = st.form_submit_button("💾 Save Settings", type="primary")
    if save_btn:
        has_error = False
        if clear_key:
            st.session_state.gemini_api_key = ""
            st.info("API Key cleared. Application running in deterministic rule mode.")
        elif api_val and not api_val.startswith("•••"):
            clean_key = api_val.strip()
            # Form Validation (Item 13)
            if len(clean_key) < 20:
                st.error("Validation Error: API key is too short. Google Gemini keys are typically at least 30 characters.")
                has_error = True
            elif not re.match(r"^[A-Za-z0-9_\-]+$", clean_key):
                st.error("Validation Error: API key contains invalid characters. Must contain alphanumeric, underscore, or hyphen characters.")
                has_error = True
            else:
                st.session_state.gemini_api_key = clean_key
        
        if not has_error:
            if model_choice in ["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.1-pro-preview"]:
                st.session_state.gemini_model = model_choice.strip()
            if mode_choice in ["auto", "deterministic", "gemini_ai"]:
                st.session_state.analysis_mode_override = mode_choice.strip()
            st.success("Platform settings validated and updated successfully.")
            st.rerun()

st.markdown("<hr style='border-color:#1e293b; margin:1.5rem 0;'>", unsafe_allow_html=True)

st.write("### Demo Telemetry Controls")
st.write("Purge all in-memory scenario registries and restore factory baseline.")
if st.button("🔄 Reset All Demo State to Factory Baseline", type="secondary"):
    reset_demo_data(st)
    st.success("All synthetic scenarios, response registries, and audit logs have been reset.")
    st.rerun()

render_footer()
