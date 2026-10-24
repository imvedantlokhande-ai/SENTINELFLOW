"""SentinelFlow AI - Performance & Analytics Page."""

import streamlit as st
from sentinelflow.config import (
    COLOR_ACCENT_CYAN,
    COLOR_SUCCESS,
    COLOR_HIGH,
    COLOR_ACCENT_BLUE,
)
from sentinelflow.state import init_session_state
from sentinelflow.ui_components import (
    inject_custom_css,
    render_header,
    render_simulation_banner,
    render_kpi_card,
    render_seo_meta,
    render_cookie_consent,
    render_footer,
)
from sentinelflow.analytics import (
    calculate_soc_metrics,
    build_severity_donut_chart,
    build_attack_vectors_bar_chart,
)

st.set_page_config(page_title="Performance & Analytics | SentinelFlow AI", page_icon="📈", layout="wide")
init_session_state(st)
inject_custom_css()
render_seo_meta(
    title="SOC Performance & Analytics | SentinelFlow AI",
    description="Operational performance benchmarks, verification accuracy, and adversary frequency distributions in SentinelFlow AI.",
    path="/Analytics",
)

metrics = calculate_soc_metrics(
    incidents=st.session_state.incidents,
    audit_entries=st.session_state.audit_trail.get_entries(),
    attack_vectors=st.session_state.attack_vectors,
)

pending_count = sum(1 for i in st.session_state.incidents if i.proposed_action and i.proposed_action.status in ("proposed", "awaiting_approval"))
render_header(pending_approvals=pending_count, active_mode=st.session_state.analysis_mode_override)
render_simulation_banner()
render_cookie_consent()

st.markdown("<h2 style='color:#ffffff; margin-bottom:0.25rem;'>📈 SOC Operational Analytics & Efficiency</h2>", unsafe_allow_html=True)
st.markdown("<p style='font-size:0.8rem; color:#94a3b8;'>Measured operational metrics calculated directly from session telemetry and analyst actions.</p>", unsafe_allow_html=True)

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
with kpi1:
    render_kpi_card("Total Scenarios", metrics["total_incidents"], f"{metrics['investigated_count']} investigated", COLOR_ACCENT_CYAN, "📁")
with kpi2:
    render_kpi_card("Analyst Approvals", metrics["approvals_count"], f"{metrics['rejections_count']} rejected", COLOR_SUCCESS, "✅")
with kpi3:
    render_kpi_card("Verification Accuracy", f"{metrics['verification_success_rate']}%", f"{metrics['verifications_passed']} verified", COLOR_ACCENT_BLUE, "🛡️")
with kpi4:
    render_kpi_card("Gemini AI Invocations", metrics["gemini_calls"], f"{metrics['deterministic_fallbacks']} deterministic", COLOR_HIGH, "⚡")

st.markdown("<hr style='border-color:#1e293b; margin:1rem 0;'>", unsafe_allow_html=True)

ch1, ch2 = st.columns(2)
with ch1:
    st.markdown("<h3 style='color:#ffffff; font-size:1.05rem;'>Incident Severity Distribution</h3>", unsafe_allow_html=True)
    st.plotly_chart(build_severity_donut_chart(metrics), use_container_width=True)

with ch2:
    st.markdown("<h3 style='color:#ffffff; font-size:1.05rem;'>Attack Vector Frequency</h3>", unsafe_allow_html=True)
    st.plotly_chart(build_attack_vectors_bar_chart(metrics["attack_vectors"]), use_container_width=True)

st.markdown(
    """
    <div class="soc-card" style="margin-top:1rem;">
        <div style="font-size:0.85rem; font-weight:700; color:#00f0ff;">INVESTIGATION EFFICIENCY BENCHMARKS</div>
        <p style="font-size:0.75rem; color:#94a3b8; margin:0.3rem 0;">
            <b>Illustrative SOC Baseline:</b> Traditional tier-1 manual investigation across disparate SIEM logs averages 
            <b>18 to 25 minutes</b> per incident. SentinelFlow AI correlates multi-source synthetic telemetry and generates 
            structured evidence-backed containment proposals in <b>under 3 seconds</b> under human supervision.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Consent-Aware Operational Telemetry Status
consent = st.session_state.get("cookie_consent")
has_analytics_consent = consent and consent.get("analytics") is True

with st.expander("📊 Privacy-Respecting Operational Telemetry Log", expanded=False):
    if not has_analytics_consent:
        st.info("ℹ️ Analytics telemetry is currently **OFF** (cookie consent not granted). No usage data is being recorded.")
    else:
        events = st.session_state.get("analytics_events", [])
        st.success(f"✅ Operational telemetry is **ACTIVE** with user consent. {len(events)} anonymous performance event(s) recorded.")
        if events:
            for ev in events[-5:]:
                st.write(f"- `{ev['event']}` at timestamp `{ev['timestamp']}` | {ev['meta']}")

render_footer()

