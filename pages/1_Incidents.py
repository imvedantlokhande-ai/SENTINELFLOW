"""SentinelFlow AI - Incident Investigation Workspace Page."""

import streamlit as st
from sentinelflow.config import (
    COLOR_ACCENT_CYAN,
    COLOR_PANEL_BG,
    COLOR_CRITICAL,
    COLOR_HIGH,
    COLOR_MEDIUM,
    COLOR_LOW,
    COLOR_TEXT_PRIMARY,
    COLOR_TEXT_SECONDARY,
)
from sentinelflow.state import (
    init_session_state,
    get_incident_by_id,
    get_events_for_incident,
    get_raw_state_dict,
)
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_severity_badge,
    render_status_badge,
)
from sentinelflow.event_correlation import EventCorrelationEngine
from sentinelflow.investigation import InvestigationEngine
from sentinelflow.response_engine import ResponseEngine
from sentinelflow.verification import VerificationEngine
from sentinelflow.analytics import build_entity_relationship_graph

st.set_page_config(page_title="Incidents - SentinelFlow AI", page_icon="📋", layout="wide")
init_session_state(st)
inject_custom_css()

correlation_engine = EventCorrelationEngine()
investigation_engine = InvestigationEngine(
    api_key=st.session_state.gemini_api_key,
    model=st.session_state.gemini_model,
)
response_engine = ResponseEngine()
verification_engine = VerificationEngine()

pending_count = sum(1 for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval"))
render_header(pending_approvals=pending_count, active_mode=st.session_state.analysis_mode_override, gemini_ready=investigation_engine.gemini_client.is_configured())
render_simulation_banner()

st.markdown("<h2 style='color:#ffffff; margin-bottom:0.5rem;'>📋 Security Incidents & Correlation Center</h2>", unsafe_allow_html=True)

# Filters
fc1, fc2, fc3 = st.columns([2, 2, 3])
with fc1:
    filter_sev = st.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"], index=0)
with fc2:
    filter_st = st.selectbox("Status", ["ALL", "OPEN", "INVESTIGATING", "RESOLVED", "MONITORING", "ESCALATED"], index=0)
with fc3:
    search_q = st.text_input("Search (ID, Title, Account)", "")

incidents = st.session_state.incidents
if filter_sev != "ALL":
    incidents = [i for i in incidents if i.severity == filter_sev]
if filter_st != "ALL":
    incidents = [i for i in incidents if i.status == filter_st]
if search_q.strip():
    q = search_q.strip().lower()
    incidents = [i for i in incidents if q in i.incident_id.lower() or q in i.title.lower() or q in i.primary_account.lower()]

for inc in incidents:
    events = get_events_for_incident(st, inc.incident_id)
    with st.expander(f"{inc.incident_id} — {inc.title} [{inc.severity}] — {inc.status}", expanded=(inc.incident_id == st.session_state.selected_incident_id)):
        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="display:flex; justify-content:space-between;">
                        <span style="font-size:0.8rem; font-weight:700; color:#00f0ff;">{inc.incident_id}</span>
                        <div>{render_severity_badge(inc.severity)} {render_status_badge(inc.status)}</div>
                    </div>
                    <div style="font-size:0.95rem; font-weight:700; color:#ffffff; margin:0.3rem 0;">{inc.title}</div>
                    <div style="font-size:0.8rem; color:#94a3b8;">{inc.description}</div>
                    <div style="font-size:0.75rem; color:#64748b; margin-top:0.4rem;">
                        Target Account: <code>{inc.primary_account}</code> | Created: <code>{inc.created_at}</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Correlated events summary
            st.markdown(f"<div style='font-size:0.8rem; font-weight:700; color:#00f0ff;'>CORRELATED EVENTS ({len(events)})</div>", unsafe_allow_html=True)
            for ev in events:
                st.markdown(
                    f"""
                    <div style="background:#0f172a; border-left:2px solid #00f0ff; padding:0.35rem 0.6rem; margin-bottom:0.25rem; font-size:0.75rem;">
                        <span style="color:#ffffff; font-weight:600;">{ev.event_id}</span> • {render_severity_badge(ev.severity)} • <span style="color:#94a3b8;">{ev.description[:60]}...</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        with col2:
            st.plotly_chart(build_entity_relationship_graph(inc, events), use_container_width=True, config={"displayModeBar": False})

            if inc.finding:
                f = inc.finding
                st.markdown(
                    f"""
                    <div class="soc-card">
                        <div style="display:flex; justify-content:space-between;">
                            <span style="font-size:0.8rem; font-weight:700; color:#00f0ff;">INVESTIGATION FINDING</span>
                            <span class="badge badge-demo">{f.analysis_mode}</span>
                        </div>
                        <div style="font-size:1.15rem; font-weight:700; color:#ef4444; margin:0.2rem 0;">Risk Score: {f.risk_score}/100</div>
                        <div style="font-size:0.75rem; color:#ffffff;">{f.incident_summary}</div>
                        <div style="font-size:0.72rem; color:#94a3b8; margin-top:0.3rem;"><b>Likely Cause:</b> {f.likely_explanation}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        if st.button(f"🎯 Set Active on SOC Dashboard", key=f"set_act_{inc.incident_id}"):
            st.session_state.selected_incident_id = inc.incident_id
            st.success(f"Incident {inc.incident_id} selected as active.")
            st.rerun()
