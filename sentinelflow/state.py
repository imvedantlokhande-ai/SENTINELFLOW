"""Session State Management and Data Reset for SentinelFlow AI.

Manages in-memory state across Streamlit rerenders, page transitions, and demo resets.
Provides consistent references to active incidents, synthetic events, and response registries.
"""

from typing import Dict, Any, List, Optional
from sentinelflow.config import GEMINI_API_KEY, DEFAULT_GEMINI_MODEL, APP_MODE
from sentinelflow.models import Incident, SecurityEvent
from sentinelflow.sample_data import (
    get_fresh_sample_data,
    SYNTHETIC_ATTACK_VECTORS,
    SYNTHETIC_COMPLIANCE_INDICATORS,
)
from sentinelflow.audit import AuditTrail


def init_session_state(st_module) -> None:
    """Initialize all Streamlit session state keys if not already initialized."""
    st = st_module

    if "initialized" not in st.session_state:
        fresh = get_fresh_sample_data()
        st.session_state.incidents = fresh["incidents"]
        st.session_state.events = fresh["events"]
        st.session_state.infrastructure = fresh["infrastructure"]
        st.session_state.geo_points = fresh["geo_points"]
        st.session_state.attack_vectors = [dict(v) for v in SYNTHETIC_ATTACK_VECTORS]
        st.session_state.compliance_indicators = [dict(c) for c in SYNTHETIC_COMPLIANCE_INDICATORS]

        # Audit trail instance
        audit = AuditTrail()
        audit.log(
            event_type="DEMO_INITIALIZED",
            status="SUCCESS",
            actor="system",
            details="SentinelFlow AI operational simulation initialized with 6 synthetic scenarios.",
        )
        st.session_state.audit_trail = audit

        # Response state registries
        st.session_state.synthetic_revoked_sessions = set()
        st.session_state.synthetic_locked_accounts = set()
        st.session_state.synthetic_escalated_incidents = set()
        st.session_state.synthetic_monitored_incidents = set()

        # UI selection & filter state
        st.session_state.selected_incident_id = "INC-2026-001"
        st.session_state.filter_severity = "ALL"
        st.session_state.filter_status = "ALL"
        st.session_state.filter_event_category = "ALL"
        st.session_state.threat_category_filter = "ALL"
        st.session_state.analysis_mode_override = APP_MODE

        # Config state
        st.session_state.gemini_api_key = GEMINI_API_KEY
        st.session_state.gemini_model = DEFAULT_GEMINI_MODEL

        st.session_state.initialized = True


def reset_demo_data(st_module) -> None:
    """Reset all synthetic telemetry, investigations, response registries, and logs to factory demo state."""
    st = st_module
    fresh = get_fresh_sample_data()

    st.session_state.incidents = fresh["incidents"]
    st.session_state.events = fresh["events"]
    st.session_state.infrastructure = fresh["infrastructure"]
    st.session_state.geo_points = fresh["geo_points"]
    st.session_state.attack_vectors = [dict(v) for v in SYNTHETIC_ATTACK_VECTORS]
    st.session_state.compliance_indicators = [dict(c) for c in SYNTHETIC_COMPLIANCE_INDICATORS]

    st.session_state.synthetic_revoked_sessions = set()
    st.session_state.synthetic_locked_accounts = set()
    st.session_state.synthetic_escalated_incidents = set()
    st.session_state.synthetic_monitored_incidents = set()

    # Re-initialize audit trail with reset notice
    audit = AuditTrail()
    audit.log(
        event_type="DEMO_RESET",
        status="SUCCESS",
        actor="analyst",
        details="Analyst triggered demo state reset. All synthetic scenario registries restored to baseline.",
    )
    st.session_state.audit_trail = audit
    st.session_state.selected_incident_id = "INC-2026-001"


def get_incident_by_id(st_module, incident_id: str) -> Optional[Incident]:
    """Retrieve an incident object from session state by its ID."""
    for inc in st_module.session_state.incidents:
        if inc.incident_id == incident_id:
            return inc
    return None


def get_events_for_incident(st_module, incident_id: str) -> List[SecurityEvent]:
    """Retrieve all synthetic events matching the incident's event_ids or incident_id."""
    inc = get_incident_by_id(st_module, incident_id)
    if not inc:
        return []
    target_ids = set(inc.event_ids)
    return [e for e in st_module.session_state.events if e.event_id in target_ids or e.incident_id == incident_id]


def get_raw_state_dict(st_module) -> Dict[str, Any]:
    """Provide a dictionary view of state compatible with response and verification engines."""
    return {
        "incidents": st_module.session_state.incidents,
        "events": st_module.session_state.events,
        "synthetic_revoked_sessions": st_module.session_state.synthetic_revoked_sessions,
        "synthetic_locked_accounts": st_module.session_state.synthetic_locked_accounts,
        "synthetic_escalated_incidents": st_module.session_state.synthetic_escalated_incidents,
        "synthetic_monitored_incidents": st_module.session_state.synthetic_monitored_incidents,
    }
