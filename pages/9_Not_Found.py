"""SentinelFlow AI - Custom 404 Not Found Page.

Responsive SOC-themed error route providing clear navigation recovery paths.
"""

import streamlit as st
from sentinelflow.state import init_session_state
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_seo_meta,
    render_footer,
    render_cookie_consent,
)

st.set_page_config(
    page_title="404 - Route Not Found | SentinelFlow AI",
    page_icon="🛡️",
    layout="wide",
)

init_session_state(st)
inject_custom_css()
render_seo_meta(
    title="404 - Security Route Not Found | SentinelFlow AI",
    description="The requested investigation route or endpoint could not be found in SentinelFlow AI.",
    path="/404",
)

render_header()
render_cookie_consent()

st.markdown(
    """
    <div style="text-align:center; padding: 3rem 1rem 2rem 1rem;">
        <div style="font-size: 4.5rem; text-shadow: 0 0 25px rgba(0, 240, 255, 0.4); margin-bottom: 0.5rem;">
            🛰️
        </div>
        <div style="font-family:'JetBrains Mono', monospace; font-size: 1.1rem; color: #00f0ff; letter-spacing: 0.15em; text-transform: uppercase;">
            ERROR CODE: ERR_SOC_404_ROUTE_NOT_FOUND
        </div>
        <h1 style="color: #ffffff; font-size: 2.4rem; font-weight: 700; margin: 0.5rem 0 1rem 0;">
            Target Route Telemetry Unreachable
        </h1>
        <p style="color: #94a3b8; font-size: 1.05rem; max-width: 620px; margin: 0 auto 2rem auto; line-height: 1.6;">
            The security investigation endpoint or view you requested does not exist, has been decommissioned,
            or requires authenticated SOC privileges. Return to active radar or select a verified destination below.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

col_c1, col_c2, col_c3 = st.columns([1, 2, 1])
with col_c2:
    st.markdown(
        """
        <div class="soc-card soc-card-accent" style="padding:1.5rem; text-align:left;">
            <div style="font-size:0.85rem; font-weight:700; color:#00f0ff; margin-bottom:0.75rem;">
                RECOMMENDED RECOVERY PATHS
            </div>
            <ul style="color:#f8fafc; font-size:0.9rem; line-height:1.8; margin-bottom:1.25rem;">
                <li><b>Primary SOC Dashboard:</b> Live 3-column incident radar and interactive telemetry.</li>
                <li><b>Incident Workspace:</b> All 6 synthetic scenarios and detailed findings.</li>
                <li><b>Global Threat Map:</b> Geographic adversary coordinates and attack vectors.</li>
                <li><b>Response Center:</b> Analyst authorization gate and containment registries.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        if st.button("⬅️ Return to SOC Dashboard", type="primary", use_container_width=True):
            st.switch_page("app.py")
    with btn_col2:
        if st.button("📋 View Incident Workspace", type="secondary", use_container_width=True):
            st.switch_page("pages/1_Incidents.py")

render_footer()
