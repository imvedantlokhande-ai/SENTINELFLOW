"""SentinelFlow AI - Global Threat Intelligence Page."""

import streamlit as st
from sentinelflow.config import COLOR_ACCENT_CYAN, COLOR_PANEL_BG
from sentinelflow.state import init_session_state
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_severity_badge,
)
from sentinelflow.analytics import build_global_threat_map, build_attack_vectors_bar_chart

st.set_page_config(page_title="Threat Intel - SentinelFlow AI", page_icon="🎯", layout="wide")
init_session_state(st)
inject_custom_css()

pending_count = sum(1 for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval"))
render_header(pending_approvals=pending_count, active_mode=st.session_state.analysis_mode_override)
render_simulation_banner()

st.markdown("<h2 style='color:#ffffff; margin-bottom:0.25rem;'>🌍 Global Threat Intelligence & Adversary Tracking</h2>", unsafe_allow_html=True)
st.markdown("<p style='font-size:0.8rem; color:#94a3b8;'>Simulated adversary campaigns, geographic vectors, and telemetry indicators.</p>", unsafe_allow_html=True)

# Category filter
filter_col1, _ = st.columns([2, 5])
with filter_col1:
    v_filter = st.selectbox("Adversary Vector Filter", ["ALL", "AUTHENTICATION", "NETWORK", "PRIVILEGE_ESCALATION", "DATA_ACCESS"])

st.plotly_chart(
    build_global_threat_map(st.session_state.geo_points, category_filter=v_filter),
    use_container_width=True,
    config={"displayModeBar": False},
)

t_c1, t_c2 = st.columns([1, 1])
with t_c1:
    st.markdown(f"<h3 style='color:#ffffff; font-size:1.05rem;'>Observed Attack Vector Frequency</h3>", unsafe_allow_html=True)
    st.plotly_chart(build_attack_vectors_bar_chart(st.session_state.attack_vectors), use_container_width=True)

with t_c2:
    st.markdown(f"<h3 style='color:#ffffff; font-size:1.05rem;'>Simulated Threat Campaigns</h3>", unsafe_allow_html=True)
    for p in st.session_state.geo_points:
        st.markdown(
            f"""
            <div class="soc-card soc-card-accent">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:0.85rem; font-weight:700; color:#ffffff;">{p['origin_name']}</span>
                    {render_severity_badge(p['severity'])}
                </div>
                <div style="font-size:0.75rem; color:#00f0ff; margin:0.2rem 0;">{p['attack_vector']}</div>
                <div style="font-size:0.7rem; color:#94a3b8;">
                    Source IP: <code>{p['source_ip']}</code> | Target: <code>{p['target_name']}</code> | Intensity: <b>{p['intensity']}%</b>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
