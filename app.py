"""SentinelFlow AI - Autonomous Cybersecurity Incident Investigation & Response Simulation.

Main entrypoint for the SOC web application.
Run with: python -m streamlit run app.py
"""

import streamlit as st
from datetime import datetime, timezone

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
)
from sentinelflow.state import (
    init_session_state,
    reset_demo_data,
    get_incident_by_id,
    get_events_for_incident,
    get_raw_state_dict,
)
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_kpi_card,
    render_severity_badge,
    render_status_badge,
)
from sentinelflow.event_correlation import EventCorrelationEngine
from sentinelflow.investigation import InvestigationEngine
from sentinelflow.response_engine import ResponseEngine, ResponseExecutionError
from sentinelflow.verification import VerificationEngine
from sentinelflow.analytics import (
    calculate_soc_metrics,
    build_severity_donut_chart,
    build_attack_vectors_bar_chart,
    build_global_threat_map,
    build_entity_relationship_graph,
)

# Page configuration
st.set_page_config(
    page_title="SentinelFlow AI - SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Initialize application state & inject theme
init_session_state(st)
inject_custom_css()

# Instantiate core engines
correlation_engine = EventCorrelationEngine()
investigation_engine = InvestigationEngine(
    api_key=st.session_state.gemini_api_key,
    model=st.session_state.gemini_model,
)
response_engine = ResponseEngine()
verification_engine = VerificationEngine()

# Calculate active metrics
metrics = calculate_soc_metrics(
    incidents=st.session_state.incidents,
    audit_entries=st.session_state.audit_trail.get_entries(),
    attack_vectors=st.session_state.attack_vectors,
)

# Count pending approvals
pending_approvals = sum(
    1
    for inc in st.session_state.incidents
    if inc.proposed_action and inc.proposed_action.status in ("proposed", "awaiting_approval")
)

# Render Global Header
render_header(
    pending_approvals=pending_approvals,
    active_mode=st.session_state.analysis_mode_override,
    gemini_ready=investigation_engine.gemini_client.is_configured(),
)
render_simulation_banner()

# Quick Navigation Bar (Horizontal Tab Controls)
nav_tabs = st.tabs([
    "📊 SOC Dashboard",
    "🎯 Threat Map & Intel",
    "🛡️ Incident Workspace",
    "⚡ Response Center",
    "📜 Audit Timeline",
    "📈 Analytics",
    "⚙️ Settings",
])

# =========================================================================
# TAB 1: SOC DASHBOARD (Main 3-Column Dashboard)
# =========================================================================
with nav_tabs[0]:
    # Top Control Bar (Scenario selection, filters, reset)
    with st.container():
        ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([3, 2, 2, 2])
        with ctrl_col1:
            scenario_options = {
                "INC-2026-001": "Scenario 1: Unusual Admin Login (Eastern Europe IP)",
                "INC-2026-002": "Scenario 2: Credential Stuffing & Session Hijack",
                "INC-2026-003": "Scenario 3: Service Account Compromise (Tor Exit / S3)",
                "INC-2026-004": "Scenario 4: Benign Context: Scheduled DR Backup Sync",
                "INC-2026-005": "Scenario 5: Benign Context: Routine Corporate SSO Login",
                "INC-2026-006": "Scenario 6: Critical C2 Beaconing & Bulk Exfiltration",
            }
            selected_scenario = st.selectbox(
                "Active Synthetic Scenario",
                options=list(scenario_options.keys()),
                format_func=lambda k: scenario_options[k],
                index=list(scenario_options.keys()).index(st.session_state.selected_incident_id)
                if st.session_state.selected_incident_id in scenario_options
                else 0,
                key="dashboard_scenario_select",
            )
            st.session_state.selected_incident_id = selected_scenario

        with ctrl_col2:
            st.session_state.filter_severity = st.selectbox(
                "Severity Filter",
                options=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                index=0,
                key="dashboard_sev_filter",
            )

        with ctrl_col3:
            st.session_state.analysis_mode_override = st.selectbox(
                "Investigation Mode",
                options=["auto", "deterministic", "gemini_ai"],
                format_func=lambda m: "Auto (Gemini AI + Fallback)" if m == "auto" else ("Deterministic Demo" if m == "deterministic" else "Gemini AI Live Only"),
                index=0,
                key="dashboard_mode_select",
            )

        with ctrl_col4:
            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            if st.button("🔄 Reset Demo State", use_container_width=True, type="secondary"):
                reset_demo_data(st)
                st.rerun()

    st.markdown("<hr style='border-color:#1e293b; margin:0.75rem 0;'>", unsafe_allow_html=True)

    # 3-Column SOC Dashboard
    col_left, col_center, col_right = st.columns([1, 2, 1])

    # -------------------------------------------------------------------------
    # LEFT COLUMN: Threat Overview
    # -------------------------------------------------------------------------
    with col_left:
        st.markdown(
            f"""
            <div class="soc-card soc-card-accent">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0; font-size:1.05rem; color:{COLOR_ACCENT_CYAN};">🚨 THREAT OVERVIEW</h3>
                    <span class="badge badge-demo">ACTIVE</span>
                </div>
                <p style="margin:0.25rem 0 0.75rem 0; font-size:0.75rem; color:{COLOR_TEXT_SECONDARY};">Synthetic telemetry summary</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        kpi_r1_c1, kpi_r1_c2 = st.columns(2)
        with kpi_r1_c1:
            render_kpi_card("Total Incidents", metrics["total_incidents"], "Seeded scenarios", COLOR_ACCENT_CYAN, "📁")
        with kpi_r1_c2:
            render_kpi_card("Critical Threats", metrics["critical_count"], "Immediate review", COLOR_CRITICAL, "🔥")

        kpi_r2_c1, kpi_r2_c2 = st.columns(2)
        with kpi_r2_c1:
            render_kpi_card("High Risk", metrics["high_count"], "Elevated alerts", COLOR_HIGH, "⚠️")
        with kpi_r2_c2:
            render_kpi_card("Medium / Low", metrics["medium_count"] + metrics["low_count"], "Routine / Monitored", COLOR_LOW, "ℹ️")

        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)
        st.markdown(f"<div style='font-size:0.85rem; font-weight:600; color:{COLOR_TEXT_SECONDARY};'>SEVERITY DISTRIBUTION</div>", unsafe_allow_html=True)
        st.plotly_chart(build_severity_donut_chart(metrics), use_container_width=True, config={"displayModeBar": False})
        st.caption("ℹ️ Accessible Summary: Distribution shows 2 Critical, 2 High, 1 Medium, and 1 Low/Informational incident.")

        # Recent Activity Feed
        st.markdown(f"<div style='font-size:0.85rem; font-weight:600; color:{COLOR_TEXT_SECONDARY}; margin-bottom:0.4rem;'>RECENT SYNTHETIC ALERTS</div>", unsafe_allow_html=True)
        for inc in st.session_state.incidents[:4]:
            is_sel = inc.incident_id == st.session_state.selected_incident_id
            bg_style = "border:1px solid #00f0ff; background:rgba(0,240,255,0.06);" if is_sel else "border:1px solid #1e293b;"
            st.markdown(
                f"""
                <div style="background:#111827; {bg_style} border-radius:6px; padding:0.5rem 0.75rem; margin-bottom:0.45rem;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.75rem; font-weight:700; color:#ffffff;">{inc.incident_id}</span>
                        {render_severity_badge(inc.severity)}
                    </div>
                    <div style="font-size:0.75rem; color:#94a3b8; margin:0.2rem 0;">{inc.title[:45]}...</div>
                    <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.68rem; color:#64748b;">
                        <span>Target: {inc.primary_account}</span>
                        <span>{inc.status}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # -------------------------------------------------------------------------
    # CENTER COLUMN: Global Threat Visualization & Infrastructure Cards
    # -------------------------------------------------------------------------
    with col_center:
        map_header_c1, map_header_c2 = st.columns([2, 1])
        with map_header_c1:
            st.markdown(
                f"""
                <div style="display:flex; align-items:center; gap:0.5rem;">
                    <span style="font-size:1.15rem; color:{COLOR_ACCENT_CYAN};">🌐</span>
                    <h3 style="margin:0; font-size:1.05rem; color:#ffffff;">GLOBAL THREAT VISUALIZATION</h3>
                    <span class="badge badge-demo">SIMULATION ONLY</span>
                </div>
                <p style="margin:0.15rem 0 0.5rem 0; font-size:0.75rem; color:{COLOR_TEXT_SECONDARY};">
                    Visualization of synthetic demo events. Fictional attack origins and destinations.
                </p>
                """,
                unsafe_allow_html=True,
            )
        with map_header_c2:
            map_cat_filter = st.selectbox(
                "Vector Filter",
                options=["ALL", "AUTHENTICATION", "NETWORK", "PRIVILEGE_ESCALATION", "DATA_ACCESS"],
                index=0,
                key="map_vector_filter",
            )

        # Plotly Threat Map
        st.plotly_chart(
            build_global_threat_map(st.session_state.geo_points, category_filter=map_cat_filter),
            use_container_width=True,
            config={"displayModeBar": False},
        )
        st.caption("ℹ️ Accessible Summary: Threat map visualizes 6 synthetic attack trajectories targeting primary SOC endpoints.")

        # Central Shield Element & Simulation Status Banner
        st.markdown(
            f"""
            <div style="display:flex; justify-content:space-between; align-items:center; background:#0f172a; border:1px solid #1e293b; border-radius:6px; padding:0.55rem 1rem; margin-top:0.4rem; margin-bottom:0.75rem;">
                <div style="display:flex; align-items:center; gap:0.6rem;">
                    <span style="font-size:1.3rem;">🛡️</span>
                    <div>
                        <div style="font-size:0.8rem; font-weight:700; color:#00f0ff; letter-spacing:0.06em;">SIMULATION MONITORING ACTIVE</div>
                        <div style="font-size:0.7rem; color:#64748b;">Telemetry feed connected to synthetic deterministic event generator</div>
                    </div>
                </div>
                <span class="badge badge-success">● SECURE RUNTIME</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Infrastructure Status Cards (Endpoints, Cloud, Network)
        infra = st.session_state.infrastructure
        inf_col1, inf_col2, inf_col3 = st.columns(3)
        with inf_col1:
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="font-size:0.72rem; font-weight:700; color:{COLOR_TEXT_SECONDARY}; text-transform:uppercase;">💻 ENDPOINTS (DEMO)</div>
                    <div style="font-size:1.15rem; font-weight:700; color:#ffffff; margin:0.25rem 0;">{infra['endpoints']['healthy_count']}/{infra['endpoints']['total']} Healthy</div>
                    <div style="font-size:0.7rem; color:#ef4444;">⚠️ {infra['endpoints']['at_risk_count']} At Risk | Isolated: {infra['endpoints']['isolated_count']}</div>
                    <div style="font-size:0.68rem; color:#64748b; margin-top:0.3rem;">Agent: {infra['endpoints']['agent_version']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with inf_col2:
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="font-size:0.72rem; font-weight:700; color:{COLOR_TEXT_SECONDARY}; text-transform:uppercase;">☁️ CLOUD SYSTEMS (DEMO)</div>
                    <div style="font-size:1.15rem; font-weight:700; color:#ffffff; margin:0.25rem 0;">{infra['cloud_systems']['active_tenants']} Tenants Monitored</div>
                    <div style="font-size:0.7rem; color:#f59e0b;">Anomalous IAM Roles: {infra['cloud_systems']['anomalous_roles']}</div>
                    <div style="font-size:0.68rem; color:#64748b; margin-top:0.3rem;">S3 Guardrails: Active</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with inf_col3:
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="font-size:0.72rem; font-weight:700; color:{COLOR_TEXT_SECONDARY}; text-transform:uppercase;">🌐 NETWORK (DEMO)</div>
                    <div style="font-size:1.15rem; font-weight:700; color:#ffffff; margin:0.25rem 0;">{infra['network']['inbound_pps']}</div>
                    <div style="font-size:0.7rem; color:#ef4444;">Suspicious Flows: {infra['network']['suspicious_flows']}</div>
                    <div style="font-size:0.68rem; color:#64748b; margin-top:0.3rem;">Egress Filter: Strict</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # -------------------------------------------------------------------------
    # RIGHT COLUMN: AI & Threat Intelligence
    # -------------------------------------------------------------------------
    with col_right:
        st.markdown(
            f"""
            <div class="soc-card soc-card-accent">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0; font-size:1.05rem; color:{COLOR_ACCENT_CYAN};">🧠 AI & THREAT INTEL</h3>
                    <span class="badge badge-success">ONLINE</span>
                </div>
                <p style="margin:0.25rem 0 0.75rem 0; font-size:0.75rem; color:{COLOR_TEXT_SECONDARY};">Autonomous correlation status</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
            <div style="background:#111827; border:1px solid #1e293b; border-radius:6px; padding:0.6rem 0.8rem; margin-bottom:0.75rem;">
                <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem; font-size:0.75rem;">
                    <span style="color:{COLOR_TEXT_SECONDARY};">AI Investigation Engine:</span>
                    <span style="font-weight:700; color:{COLOR_ACCENT_CYAN};">{'Gemini Ready' if investigation_engine.gemini_client.is_configured() else 'Rule-Based Demo'}</span>
                </div>
                <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem; font-size:0.75rem;">
                    <span style="color:{COLOR_TEXT_SECONDARY};">Behavior Analysis:</span>
                    <span style="font-weight:700; color:#34d399;">Active Baseline</span>
                </div>
                <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem; font-size:0.75rem;">
                    <span style="color:{COLOR_TEXT_SECONDARY};">Anomaly Detection:</span>
                    <span style="font-weight:700; color:#00f0ff;">99.4% Precision</span>
                </div>
                <div style="display:flex; justify-content:space-between; font-size:0.75rem;">
                    <span style="color:{COLOR_TEXT_SECONDARY};">Event Correlation:</span>
                    <span style="font-weight:700; color:#34d399;">6 Active Rules</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(f"<div style='font-size:0.85rem; font-weight:600; color:{COLOR_TEXT_SECONDARY}; margin-bottom:0.3rem;'>TOP ATTACK VECTORS</div>", unsafe_allow_html=True)
        st.plotly_chart(build_attack_vectors_bar_chart(st.session_state.attack_vectors), use_container_width=True, config={"displayModeBar": False})
        st.caption("ℹ️ Accessible Summary: Top vectors are Credential Stuffing (42), Anomalous Admin (28), Exfiltration (19), Service Misuse (15), and Bulk Exports (11).")

        # Illustrative Compliance Framework
        st.markdown(
            f"""
            <div style="font-size:0.85rem; font-weight:600; color:{COLOR_TEXT_SECONDARY}; margin-bottom:0.3rem;">
                DEMO COMPLIANCE TELEMETRY
            </div>
            <div style="font-size:0.68rem; color:#64748b; margin-bottom:0.4rem;">
                *Illustrative demo indicators. Does not constitute certification.
            </div>
            """,
            unsafe_allow_html=True,
        )
        for comp in st.session_state.compliance_indicators:
            st.markdown(
                f"""
                <div style="background:#111827; border:1px solid #1e293b; border-radius:6px; padding:0.45rem 0.65rem; margin-bottom:0.35rem;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.72rem; font-weight:700; color:#ffffff;">{comp['framework']}</span>
                        <span style="font-size:0.75rem; font-weight:700; color:#00f0ff;">{comp['score_percent']}%</span>
                    </div>
                    <div style="font-size:0.66rem; color:#94a3b8; margin-top:0.15rem;">{comp['description'][:52]}...</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # =========================================================================
    # INCIDENT INVESTIGATION WORKSPACE (Directly beneath main dashboard)
    # =========================================================================
    st.markdown("<hr style='border-color:#1e293b; margin:1.25rem 0;'>", unsafe_allow_html=True)
    st.markdown(
        f"""
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
            <div style="display:flex; align-items:center; gap:0.6rem;">
                <span style="font-size:1.3rem; color:{COLOR_ACCENT_CYAN};">🔍</span>
                <h2 style="margin:0; font-size:1.25rem; color:#ffffff;">INCIDENT INVESTIGATION WORKSPACE</h2>
            </div>
            <span class="badge badge-demo">HUMAN-IN-THE-LOOP SUPERVISION</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    current_inc = get_incident_by_id(st, st.session_state.selected_incident_id)
    if current_inc:
        current_events = get_events_for_incident(st, current_inc.incident_id)
        current_corr = correlation_engine.correlate_incident_events(current_events, current_inc.incident_id)

        # Trigger investigation if not yet run
        if current_inc.finding is None:
            finding, warning_msg = investigation_engine.investigate(
                current_inc,
                current_events,
                current_corr,
                force_mode=st.session_state.analysis_mode_override,
            )
            current_inc.finding = finding
            # Propose action if applicable
            if finding.proposed_action and not current_inc.proposed_action:
                target_type = "session" if "sess-" in " ".join(current_inc.correlated_entities) else "account"
                target_id = (
                    next((e for e in current_inc.correlated_entities if e.startswith("sess-")), None)
                    or current_inc.primary_account
                )
                current_inc.proposed_action = response_engine.propose_action(
                    incident=current_inc,
                    action_name=finding.proposed_action,
                    target_type=target_type,
                    target_id=target_id,
                    reasoning=finding.human_review_rationale,
                    supporting_evidence_ids=finding.supporting_evidence_ids,
                )
            # Log audit
            st.session_state.audit_trail.log(
                event_type="FINDING_GENERATED",
                status="SUCCESS",
                incident_id=current_inc.incident_id,
                actor="gemini_engine" if finding.analysis_mode == "gemini_ai" else "rule_engine",
                details=f"Generated {finding.severity} finding (Risk: {finding.risk_score}) via {finding.analysis_mode}.",
            )

        ws_col1, ws_col2 = st.columns([1, 1])

        with ws_col1:
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-size:0.85rem; font-weight:700; color:{COLOR_ACCENT_CYAN};">{current_inc.incident_id}</span>
                        <div>
                            {render_severity_badge(current_inc.severity)}
                            {render_status_badge(current_inc.status)}
                        </div>
                    </div>
                    <h3 style="margin:0.4rem 0 0.2rem 0; font-size:1.1rem; color:#ffffff;">{current_inc.title}</h3>
                    <p style="margin:0; font-size:0.8rem; color:{COLOR_TEXT_SECONDARY};">{current_inc.description}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Risk Score Card
            finding = current_inc.finding
            score_color = COLOR_CRITICAL if finding.risk_score >= 80 else (COLOR_HIGH if finding.risk_score >= 60 else (COLOR_MEDIUM if finding.risk_score >= 35 else COLOR_LOW))
            st.markdown(
                f"""
                <div class="soc-card">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <div style="font-size:0.75rem; color:{COLOR_TEXT_SECONDARY};">CALCULATED RISK SCORE</div>
                            <div style="font-size:2rem; font-weight:700; color:{score_color}; font-family:'JetBrains Mono',monospace;">
                                {finding.risk_score}<span style="font-size:1rem; color:#64748b;"> / 100</span>
                            </div>
                        </div>
                        <div style="text-align:right;">
                            <div style="font-size:0.75rem; color:{COLOR_TEXT_SECONDARY};">CONFIDENCE LEVEL</div>
                            <div style="font-size:1.4rem; font-weight:700; color:#ffffff; font-family:'JetBrains Mono',monospace;">
                                {int(finding.confidence_score * 100)}%
                            </div>
                        </div>
                    </div>
                    <div style="margin-top:0.5rem; font-size:0.75rem; color:#94a3b8;">
                        <b>Mode:</b> <span class="badge {'badge-success' if finding.analysis_mode == 'gemini_ai' else 'badge-demo'}">{finding.analysis_mode}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Correlated Event Timeline
            st.markdown(f"<div style='font-size:0.85rem; font-weight:600; color:{COLOR_TEXT_SECONDARY}; margin-bottom:0.4rem;'>CORRELATED EVENT TIMELINE</div>", unsafe_allow_html=True)
            for ev in current_events:
                st.markdown(
                    f"""
                    <div style="background:#0f172a; border-left:3px solid {COLOR_ACCENT_CYAN}; padding:0.45rem 0.75rem; margin-bottom:0.35rem; border-radius:0 4px 4px 0;">
                        <div style="display:flex; justify-content:space-between; font-size:0.7rem; color:#64748b; font-family:'JetBrains Mono',monospace;">
                            <span>{ev.event_id} • {ev.timestamp}</span>
                            <span>{render_severity_badge(ev.severity)}</span>
                        </div>
                        <div style="font-size:0.76rem; color:#ffffff; margin-top:0.15rem;">{ev.description}</div>
                        <div style="font-size:0.68rem; color:#94a3b8; margin-top:0.15rem;">Source IP: {ev.synthetic_source_ip} ({ev.fictional_location})</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        with ws_col2:
            # Entity Relationship Graph
            st.markdown(f"<div style='font-size:0.85rem; font-weight:600; color:{COLOR_TEXT_SECONDARY}; margin-bottom:0.4rem;'>ENTITY RELATIONSHIP NETWORK</div>", unsafe_allow_html=True)
            st.plotly_chart(
                build_entity_relationship_graph(current_inc, current_events),
                use_container_width=True,
                config={"displayModeBar": False},
            )
            st.caption(f"ℹ️ Accessible Summary: Relationship network connects {current_inc.primary_account} to {len(current_events)} correlated events and {len(current_inc.correlated_entities)} entities.")

            # Findings & Explanations Panel
            st.markdown(
                f"""
                <div class="soc-card">
                    <div style="font-size:0.75rem; font-weight:700; color:{COLOR_ACCENT_CYAN}; text-transform:uppercase;">AI FINDINGS & TIMELINE INTERPRETATION</div>
                    <div style="font-size:0.8rem; color:#ffffff; margin:0.35rem 0;">{finding.incident_summary}</div>
                    <div style="font-size:0.75rem; color:#94a3b8; background:#070b12; padding:0.4rem 0.6rem; border-radius:4px; font-family:'JetBrains Mono',monospace; white-space:pre-wrap; margin-bottom:0.4rem;">{finding.timeline_interpretation}</div>
                    <div style="font-size:0.75rem; color:#f87171;"><b>Likely Cause:</b> {finding.likely_explanation}</div>
                    <div style="font-size:0.75rem; color:#38bdf8; margin-top:0.25rem;"><b>Alternative Hypotheses:</b> {'; '.join(finding.alternative_explanations)}</div>
                    <div style="font-size:0.72rem; color:#64748b; margin-top:0.25rem;"><b>Telemetry Limitations:</b> {finding.uncertainties_and_limitations}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Human-in-the-Loop Response Controls
            if current_inc.proposed_action:
                prop = current_inc.proposed_action
                st.markdown(
                    f"""
                    <div class="soc-card soc-card-accent">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:0.8rem; font-weight:700; color:{COLOR_ACCENT_CYAN};">PROPOSED SIMULATED CONTAINMENT</span>
                            {render_status_badge(prop.status)}
                        </div>
                        <div style="font-size:0.95rem; font-weight:700; color:#ffffff; margin:0.25rem 0;">
                            Action: <span style="color:#00f0ff;">{prop.action_name.upper()}</span>
                        </div>
                        <div style="font-size:0.75rem; color:#94a3b8;">
                            <b>Target:</b> {prop.target_id} ({prop.target_type})<br>
                            <b>Rationale:</b> {prop.reasoning}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                if prop.status in ("proposed", "awaiting_approval"):
                    resp_col1, resp_col2 = st.columns(2)
                    with resp_col1:
                        if st.button("✅ Approve & Simulate Action", key=f"btn_approve_{current_inc.incident_id}", type="primary", use_container_width=True):
                            # 1. Approve
                            approved_req = response_engine.approve_action(prop, analyst_id="soc_analyst_01")
                            # 2. Execute simulated containment against demo state
                            executed_req, raw_state = response_engine.execute_simulated_action(
                                approved_req,
                                get_raw_state_dict(st),
                            )
                            # 3. Independent Verification
                            verif = verification_engine.verify_action_state(executed_req, raw_state)
                            executed_req.status = "verified" if verif.passed else "failed_verification"

                            current_inc.proposed_action = executed_req
                            current_inc.verification_result = verif

                            # 4. Log Audit Trail
                            st.session_state.audit_trail.log(
                                event_type="ACTION_APPROVED",
                                status="SUCCESS",
                                incident_id=current_inc.incident_id,
                                action_id=prop.action_id,
                                details=f"Analyst approved action {prop.action_name} on {prop.target_id}.",
                            )
                            st.session_state.audit_trail.log(
                                event_type="SIMULATION_EXECUTED",
                                status="SUCCESS",
                                incident_id=current_inc.incident_id,
                                action_id=prop.action_id,
                                details=f"Simulated containment applied to demo state: {prop.action_name}.",
                            )
                            st.session_state.audit_trail.log(
                                event_type="VERIFICATION_PASSED" if verif.passed else "VERIFICATION_FAILED",
                                status="PASSED" if verif.passed else "FAILED",
                                incident_id=current_inc.incident_id,
                                action_id=prop.action_id,
                                actor="verification_engine",
                                details=verif.details,
                            )
                            st.rerun()

                    with resp_col2:
                        if st.button("❌ Reject Proposed Action", key=f"btn_reject_{current_inc.incident_id}", use_container_width=True):
                            rejected_req = response_engine.reject_action(prop, analyst_id="soc_analyst_01")
                            current_inc.proposed_action = rejected_req
                            st.session_state.audit_trail.log(
                                event_type="ACTION_REJECTED",
                                status="REJECTED",
                                incident_id=current_inc.incident_id,
                                action_id=prop.action_id,
                                details=f"Analyst rejected proposed action {prop.action_name}.",
                            )
                            st.rerun()

                # Display Verification Results if executed
                if current_inc.verification_result:
                    v = current_inc.verification_result
                    v_color = COLOR_SUCCESS if v.passed else COLOR_CRITICAL
                    st.markdown(
                        f"""
                        <div style="background:#0f172a; border:1px solid {v_color}; border-radius:6px; padding:0.6rem 0.8rem; margin-top:0.4rem;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <span style="font-size:0.75rem; font-weight:700; color:{v_color};">INDEPENDENT VERIFICATION RESULT</span>
                                <span class="badge {'badge-success' if v.passed else 'badge-critical'}">{'PASSED' if v.passed else 'FAILED'}</span>
                            </div>
                            <div style="font-size:0.76rem; color:#ffffff; margin:0.25rem 0;">{v.details}</div>
                            <div style="font-size:0.68rem; color:#64748b; font-family:'JetBrains Mono',monospace;">Checked at: {v.checked_at}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

# =========================================================================
# TAB 2: THREAT MAP & INTEL
# =========================================================================
with nav_tabs[1]:
    st.markdown(f"<h2 style='color:#ffffff; font-size:1.25rem;'>🌍 Global Threat Map & Adversary Intelligence</h2>", unsafe_allow_html=True)
    st.plotly_chart(
        build_global_threat_map(st.session_state.geo_points, category_filter="ALL"),
        use_container_width=True,
        config={"displayModeBar": False},
    )

    t_col1, t_col2 = st.columns(2)
    with t_col1:
        st.markdown(f"<h3 style='color:#ffffff; font-size:1.05rem;'>Observed Attack Vectors</h3>", unsafe_allow_html=True)
        st.plotly_chart(build_attack_vectors_bar_chart(st.session_state.attack_vectors), use_container_width=True)
    with t_col2:
        st.markdown(f"<h3 style='color:#ffffff; font-size:1.05rem;'>Synthetic Adversary Telemetry Feed</h3>", unsafe_allow_html=True)
        for p in st.session_state.geo_points:
            st.markdown(
                f"""
                <div class="soc-card soc-card-accent">
                    <div style="display:flex; justify-content:space-between;">
                        <span style="font-weight:700; color:#ffffff; font-size:0.85rem;">{p['origin_name']}</span>
                        {render_severity_badge(p['severity'])}
                    </div>
                    <div style="font-size:0.75rem; color:#94a3b8; margin:0.2rem 0;">Vector: {p['attack_vector']} | Source IP: {p['source_ip']}</div>
                    <div style="font-size:0.72rem; color:#00f0ff;">Target: {p['target_name']} (Simulated Intensity: {p['intensity']}%)</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

# =========================================================================
# TAB 3: INCIDENT WORKSPACE (Full Table & Inspection)
# =========================================================================
with nav_tabs[2]:
    st.markdown(f"<h2 style='color:#ffffff; font-size:1.25rem;'>📋 All Synthetic Security Incidents</h2>", unsafe_allow_html=True)
    for inc in st.session_state.incidents:
        with st.expander(f"{inc.incident_id} - {inc.title} [{inc.severity}] - {inc.status}", expanded=(inc.incident_id == st.session_state.selected_incident_id)):
            st.write(f"**Target Account:** `{inc.primary_account}` | **Created:** `{inc.created_at}`")
            st.write(f"**Description:** {inc.description}")
            st.write(f"**Associated Event IDs:** `{inc.event_ids}`")
            if inc.finding:
                st.info(f"**AI Risk Score:** {inc.finding.risk_score}/100 | **Confidence:** {int(inc.finding.confidence_score*100)}% | **Mode:** {inc.finding.analysis_mode}")
                st.write(f"**Executive Summary:** {inc.finding.incident_summary}")
                st.write(f"**Likely Cause:** {inc.finding.likely_explanation}")
            if st.button(f"Investigate {inc.incident_id} on Dashboard", key=f"sel_{inc.incident_id}"):
                st.session_state.selected_incident_id = inc.incident_id
                st.rerun()

# =========================================================================
# TAB 4: RESPONSE CENTER
# =========================================================================
with nav_tabs[3]:
    st.markdown(f"<h2 style='color:#ffffff; font-size:1.25rem;'>⚡ Human-in-the-Loop Response Center</h2>", unsafe_allow_html=True)
    st.markdown(
        "<p style='font-size:0.8rem; color:#94a3b8;'>Strict allowlist actions: Revoke Session, Lock Account, Escalate Review, Mark Monitoring.</p>",
        unsafe_allow_html=True,
    )

    r_col1, r_col2 = st.columns(2)
    with r_col1:
        st.markdown(f"<h3 style='color:#ffffff; font-size:1rem;'>Active Synthetic Registries</h3>", unsafe_allow_html=True)
        st.markdown(
            f"""
            <div class="soc-card">
                <div style="font-size:0.8rem; color:#ffffff;"><b>Revoked Synthetic Sessions:</b> {list(st.session_state.synthetic_revoked_sessions) or 'None'}</div>
                <div style="font-size:0.8rem; color:#ffffff; margin-top:0.4rem;"><b>Locked Synthetic Accounts:</b> {list(st.session_state.synthetic_locked_accounts) or 'None'}</div>
                <div style="font-size:0.8rem; color:#ffffff; margin-top:0.4rem;"><b>Escalated Incidents:</b> {list(st.session_state.synthetic_escalated_incidents) or 'None'}</div>
                <div style="font-size:0.8rem; color:#ffffff; margin-top:0.4rem;"><b>Monitored Incidents:</b> {list(st.session_state.synthetic_monitored_incidents) or 'None'}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with r_col2:
        st.markdown(f"<h3 style='color:#ffffff; font-size:1rem;'>Pending Response Approvals</h3>", unsafe_allow_html=True)
        pending_items = [i for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval")]
        if not pending_items:
            st.success("No containment actions currently awaiting analyst review.")
        else:
            for item in pending_items:
                act = item.proposed_action
                st.markdown(
                    f"""
                    <div class="soc-card soc-card-high">
                        <div style="display:flex; justify-content:space-between;">
                            <span style="font-weight:700; color:#ffffff;">{item.incident_id}</span>
                            <span class="badge badge-high">AWAITING REVIEW</span>
                        </div>
                        <div style="font-size:0.8rem; color:#ffffff; margin:0.25rem 0;">Action: <b>{act.action_name.upper()}</b> on target <code>{act.target_id}</code></div>
                        <div style="font-size:0.72rem; color:#94a3b8;">{act.reasoning}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

# =========================================================================
# TAB 5: AUDIT TIMELINE
# =========================================================================
with nav_tabs[4]:
    st.markdown(f"<h2 style='color:#ffffff; font-size:1.25rem;'>📜 Append-Only Application Audit Trail</h2>", unsafe_allow_html=True)
    st.markdown(
        "<p style='font-size:0.75rem; color:#64748b;'>Chronological immutable log of investigation lifecycle events and analyst containment approvals.</p>",
        unsafe_allow_html=True,
    )

    audit_entries = st.session_state.audit_trail.get_entries()
    for entry in audit_entries:
        st.markdown(
            f"""
            <div style="background:#111827; border:1px solid #1e293b; border-left:3px solid {COLOR_ACCENT_CYAN}; padding:0.5rem 0.8rem; margin-bottom:0.4rem; border-radius:4px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:0.75rem; font-weight:700; color:#00f0ff; font-family:'JetBrains Mono',monospace;">{entry.entry_id} • {entry.event_type}</span>
                    <span style="font-size:0.7rem; color:#64748b; font-family:'JetBrains Mono',monospace;">{entry.timestamp}</span>
                </div>
                <div style="font-size:0.78rem; color:#ffffff; margin:0.2rem 0;">{entry.details}</div>
                <div style="font-size:0.68rem; color:#94a3b8;">
                    Actor: <code>{entry.actor}</code> | Status: <code>{entry.status}</code> {f'| Incident: <code>{entry.incident_id}</code>' if entry.incident_id else ''}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# =========================================================================
# TAB 6: ANALYTICS & METRICS
# =========================================================================
with nav_tabs[5]:
    st.markdown(f"<h2 style='color:#ffffff; font-size:1.25rem;'>📈 SOC Performance & Analytics</h2>", unsafe_allow_html=True)
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        render_kpi_card("Investigated", f"{metrics['investigated_count']}/{metrics['total_incidents']}", "Scenarios analyzed", COLOR_ACCENT_CYAN)
    with m_col2:
        render_kpi_card("Approvals", metrics["approvals_count"], "Analyst approved", COLOR_SUCCESS)
    with m_col3:
        render_kpi_card("Verification Rate", f"{metrics['verification_success_rate']}%", f"{metrics['verifications_passed']} passed", COLOR_ACCENT_BLUE)
    with m_col4:
        render_kpi_card("Gemini AI Calls", metrics["gemini_calls"], f"{metrics['deterministic_fallbacks']} fallbacks", COLOR_HIGH)

    st.markdown("<hr style='border-color:#1e293b; margin:1rem 0;'>", unsafe_allow_html=True)
    g_col1, g_col2 = st.columns(2)
    with g_col1:
        st.markdown(f"<h3 style='color:#ffffff; font-size:1rem;'>Incident Severity Breakdown</h3>", unsafe_allow_html=True)
        st.plotly_chart(build_severity_donut_chart(metrics), use_container_width=True)
    with g_col2:
        st.markdown(f"<h3 style='color:#ffffff; font-size:1rem;'>Adversary Attack Distribution</h3>", unsafe_allow_html=True)
        st.plotly_chart(build_attack_vectors_bar_chart(st.session_state.attack_vectors), use_container_width=True)

# =========================================================================
# TAB 7: SETTINGS & SECRETS
# =========================================================================
with nav_tabs[6]:
    st.markdown(f"<h2 style='color:#ffffff; font-size:1.25rem;'>⚙️ System Settings & Security Safeguards</h2>", unsafe_allow_html=True)

    with st.form("settings_form"):
        st.write("### Gemini AI Configuration")
        api_input = st.text_input(
            "Gemini API Key",
            value="" if not st.session_state.gemini_api_key else "••••••••••••••••••••••••••••••••",
            type="password",
            help="Your key is never logged or written to disk. Stored in server-side session memory only.",
        )
        model_input = st.selectbox(
            "Gemini Model Selection",
            options=["gemini-3.8-flash", "gemini-3.5-flash-lite", "gemini-3.1-pro-preview"],
            index=0,
            help="Configurable Gemini model identifier.",
        )
        saved = st.form_submit_button("💾 Save Settings", type="primary")
        if saved:
            if api_input and not api_input.startswith("•••"):
                st.session_state.gemini_api_key = api_input.strip()
            st.session_state.gemini_model = model_input.strip()
            st.success("Settings updated successfully.")
            st.rerun()

    st.markdown(
        f"""
        <div class="soc-card" style="margin-top:1.5rem;">
            <div style="font-size:0.85rem; font-weight:700; color:{COLOR_ACCENT_CYAN};">SECURITY & ARCHITECTURE DISCLOSURE</div>
            <ul style="font-size:0.78rem; color:#94a3b8; margin-top:0.4rem; padding-left:1.2rem;">
                <li><b>Air-Gapped Simulation:</b> No production credentials, live corporate networks, or active endpoints are reachable.</li>
                <li><b>Strict Action Allowlist:</b> Only 4 pre-authorized actions are possible (revoke_session, lock_account, escalate_incident, mark_monitoring).</li>
                <li><b>Human-in-the-Loop:</b> AI cannot execute or authorize containment autonomously. Explicit analyst approval is mandatory.</li>
                <li><b>Independent Verification:</b> State transitions are independently queried and confirmed by a distinct verification module.</li>
                <li><b>Secret Protection:</b> API keys are kept strictly in server-side memory and never written to audit trails or client responses.</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )
