"""SentinelFlow AI - Human-in-the-Loop Response Center Page."""

import streamlit as st
from sentinelflow.config import (
    COLOR_ACCENT_CYAN,
    COLOR_SUCCESS,
    COLOR_CRITICAL,
    ACTION_LABELS,
)
from sentinelflow.state import (
    init_session_state,
    get_raw_state_dict,
)
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_status_badge,
    render_severity_badge,
    render_seo_meta,
    render_cookie_consent,
    render_footer,
)
from sentinelflow.response_engine import ResponseEngine
from sentinelflow.verification import VerificationEngine

st.set_page_config(page_title="Response Center | SentinelFlow AI", page_icon="⚡", layout="wide")
init_session_state(st)
inject_custom_css()
render_seo_meta(
    title="Human-in-the-Loop Response Center | SentinelFlow AI",
    description="Review, authorize, and verify simulated containment actions with strict human oversight and automated independent verification.",
    path="/Response_Center",
)

response_engine = ResponseEngine()
verification_engine = VerificationEngine()

pending_count = sum(1 for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval"))
render_header(pending_approvals=pending_count, active_mode=st.session_state.analysis_mode_override)
render_simulation_banner()
render_cookie_consent()

st.markdown("<h2 style='color:#ffffff; margin-bottom:0.25rem;'>⚡ Human-in-the-Loop Response Center</h2>", unsafe_allow_html=True)
st.markdown("<p style='font-size:0.8rem; color:#94a3b8;'>Strictly allowlisted simulated containment actions requiring analyst authorization.</p>", unsafe_allow_html=True)

# Registries overview
st.markdown(
    f"""
    <div class="soc-card" style="margin-bottom:1rem;">
        <div style="font-size:0.85rem; font-weight:700; color:{COLOR_ACCENT_CYAN}; margin-bottom:0.4rem;">ACTIVE SIMULATION REGISTRIES</div>
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:0.75rem; font-size:0.75rem;">
            <div><b>Revoked Sessions:</b> <code>{list(st.session_state.synthetic_revoked_sessions) or 'None'}</code></div>
            <div><b>Locked Accounts:</b> <code>{list(st.session_state.synthetic_locked_accounts) or 'None'}</code></div>
            <div><b>Escalated Incidents:</b> <code>{list(st.session_state.synthetic_escalated_incidents) or 'None'}</code></div>
            <div><b>Monitored Incidents:</b> <code>{list(st.session_state.synthetic_monitored_incidents) or 'None'}</code></div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_pending, tab_history = st.tabs(["⏳ Pending Approvals", "✅ Completed & Verified Actions"])

with tab_pending:
    pending_incidents = [i for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval")]
    if not pending_incidents:
        st.success("No containment actions currently awaiting analyst review. All incidents are either resolved or monitored.")
    else:
        for inc in pending_incidents:
            prop = inc.proposed_action
            st.markdown(
                f"""
                <div class="soc-card soc-card-high">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.9rem; font-weight:700; color:#ffffff;">{inc.incident_id} — {inc.title}</span>
                        <div>{render_severity_badge(inc.severity)} <span class="badge badge-high">AWAITING REVIEW</span></div>
                    </div>
                    <div style="font-size:0.85rem; color:#00f0ff; margin:0.3rem 0;">
                        Action: <b>{ACTION_LABELS.get(prop.action_name, prop.action_name.upper())}</b>
                    </div>
                    <div style="font-size:0.75rem; color:#94a3b8;">
                        <b>Target:</b> <code>{prop.target_id}</code> ({prop.target_type})<br>
                        <b>Rationale:</b> {prop.reasoning}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            b_col1, b_col2, _ = st.columns([2, 2, 4])
            with b_col1:
                if st.button(f"✅ Authorize & Simulate", key=f"rc_app_{inc.incident_id}", type="primary"):
                    approved_req = response_engine.approve_action(prop, analyst_id="soc_analyst_01")
                    executed_req, raw_state = response_engine.execute_simulated_action(approved_req, get_raw_state_dict(st))
                    verif = verification_engine.verify_action_state(executed_req, raw_state)
                    executed_req.status = "verified" if verif.passed else "failed_verification"
                    inc.proposed_action = executed_req
                    inc.verification_result = verif

                    st.session_state.audit_trail.log(
                        event_type="ACTION_APPROVED",
                        status="SUCCESS",
                        incident_id=inc.incident_id,
                        action_id=prop.action_id,
                        details=f"Analyst authorized {prop.action_name} on {prop.target_id}.",
                    )
                    st.session_state.audit_trail.log(
                        event_type="VERIFICATION_PASSED" if verif.passed else "VERIFICATION_FAILED",
                        status="PASSED" if verif.passed else "FAILED",
                        incident_id=inc.incident_id,
                        action_id=prop.action_id,
                        details=verif.details,
                    )
                    st.rerun()

            with b_col2:
                if st.button(f"❌ Reject Action", key=f"rc_rej_{inc.incident_id}"):
                    rejected_req = response_engine.reject_action(prop, analyst_id="soc_analyst_01")
                    inc.proposed_action = rejected_req
                    st.session_state.audit_trail.log(
                        event_type="ACTION_REJECTED",
                        status="REJECTED",
                        incident_id=inc.incident_id,
                        action_id=prop.action_id,
                        details=f"Analyst rejected {prop.action_name}.",
                    )
                    st.rerun()

with tab_history:
    completed = [i for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status not in ("proposed", "awaiting_approval")]
    if not completed:
        st.info("No containment actions have been executed yet.")
    else:
        for inc in completed:
            act = inc.proposed_action
            verif = inc.verification_result
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="display:flex; justify-content:space-between;">
                        <span style="font-weight:700; color:#ffffff;">{inc.incident_id} — {inc.title}</span>
                        {render_status_badge(act.status)}
                    </div>
                    <div style="font-size:0.8rem; color:#00f0ff; margin:0.25rem 0;">
                        Action: <b>{act.action_name.upper()}</b> on <code>{act.target_id}</code>
                    </div>
                    <div style="font-size:0.75rem; color:#94a3b8;">
                        Approved at: <code>{act.approved_at or 'N/A'}</code> | Executed: <code>{act.executed_at or 'N/A'}</code>
                    </div>
                    {f'<div style="font-size:0.75rem; color:#10b981; margin-top:0.3rem;"><b>Verification:</b> {verif.details}</div>' if verif else ''}
                </div>
                """,
                unsafe_allow_html=True,
            )

render_footer()

