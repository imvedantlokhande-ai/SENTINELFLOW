"""SentinelFlow AI - Audit Timeline Page."""

import streamlit as st
import json
from sentinelflow.config import COLOR_ACCENT_CYAN, COLOR_PANEL_BG
from sentinelflow.state import init_session_state
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_status_badge,
    render_seo_meta,
    render_cookie_consent,
    render_footer,
)

st.set_page_config(page_title="Audit Timeline | SentinelFlow AI", page_icon="📜", layout="wide")
init_session_state(st)
inject_custom_css()
render_seo_meta(
    title="Audit Timeline | SentinelFlow AI",
    description="Inspect the immutable append-only application audit trail tracking every security analysis, containment approval, and verification event.",
    path="/Audit_Timeline",
)

pending_count = sum(1 for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval"))
render_header(pending_approvals=pending_count, active_mode=st.session_state.analysis_mode_override)
render_simulation_banner()
render_cookie_consent()

st.markdown("<h2 style='color:#ffffff; margin-bottom:0.25rem;'>📜 Append-Only Application Audit Trail</h2>", unsafe_allow_html=True)
st.markdown("<p style='font-size:0.8rem; color:#94a3b8;'>Chronological ledger of security lifecycle events, AI investigations, analyst decisions, and simulated executions.</p>", unsafe_allow_html=True)

# Filters
fc1, fc2 = st.columns([2, 2])
with fc1:
    evt_types = ["ALL", "DEMO_INITIALIZED", "DEMO_RESET", "FINDING_GENERATED", "ACTION_APPROVED", "ACTION_REJECTED", "SIMULATION_EXECUTED", "VERIFICATION_PASSED", "VERIFICATION_FAILED"]
    sel_type = st.selectbox("Event Type Filter", evt_types, index=0)
with fc2:
    inc_filter = st.selectbox("Incident Filter", ["ALL"] + [i.incident_id for i in st.session_state.incidents], index=0)

entries = st.session_state.audit_trail.get_entries(
    incident_id=inc_filter if inc_filter != "ALL" else None,
    event_type=sel_type if sel_type != "ALL" else None,
)

st.markdown(f"<div style='font-size:0.8rem; color:#64748b; margin-bottom:0.5rem;'>Displaying {len(entries)} audit record(s)</div>", unsafe_allow_html=True)

for entry in entries:
    st.markdown(
        f"""
        <div class="soc-card soc-card-accent" style="margin-bottom:0.4rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:0.8rem; font-weight:700; color:{COLOR_ACCENT_CYAN}; font-family:'JetBrains Mono',monospace;">
                    {entry.entry_id} • {entry.event_type}
                </span>
                <span style="font-size:0.72rem; color:#64748b; font-family:'JetBrains Mono',monospace;">{entry.timestamp}</span>
            </div>
            <div style="font-size:0.82rem; color:#ffffff; margin:0.3rem 0;">{entry.details}</div>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.72rem; color:#94a3b8;">
                <span>Actor: <code>{entry.actor}</code> {f'| Incident: <code>{entry.incident_id}</code>' if entry.incident_id else ''}</span>
                {render_status_badge(entry.status)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Export Audit Trail as JSON
audit_json = json.dumps([e.model_dump() for e in entries], indent=2)
st.download_button(
    label="📥 Export Filtered Audit Trail (JSON)",
    data=audit_json,
    file_name="sentinelflow_audit_trail.json",
    mime="application/json",
    type="secondary",
)

render_footer()

