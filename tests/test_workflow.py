"""End-to-End workflow integration test for SentinelFlow AI.

Validates the complete lifecycle:
Synthetic Events → Event Correlation → AI/Rule Investigation → Evidence Validation
→ Risk Assessment → Human Approval → Simulated Response → Independent Verification → Audit Trail
"""

from sentinelflow.sample_data import get_fresh_sample_data, SCENARIO_1_EVENTS
from sentinelflow.event_correlation import EventCorrelationEngine
from sentinelflow.investigation import InvestigationEngine
from sentinelflow.response_engine import ResponseEngine
from sentinelflow.verification import VerificationEngine
from sentinelflow.audit import AuditTrail


def test_complete_end_to_end_investigation_and_response_lifecycle():
    """Execute complete end-to-end incident lifecycle test."""
    # 1. Load fresh synthetic scenario data
    data = get_fresh_sample_data()
    incidents = data["incidents"]
    events = data["events"]
    target_inc = incidents[0]  # INC-2026-001 (Admin unusual login)

    audit = AuditTrail()
    audit.log("DEMO_INITIALIZED", "SUCCESS", "Workflow test started.", actor="test_runner")

    # 2. Event Correlation
    corr_engine = EventCorrelationEngine()
    inc_events = [e for e in events if e.incident_id == target_inc.incident_id]
    correlation = corr_engine.correlate_incident_events(inc_events, target_inc.incident_id)

    assert correlation.primary_account == "admin-ops-root"
    assert len(correlation.event_ids) >= 3
    audit.log("EVENTS_CORRELATED", "SUCCESS", "Correlated 3 events.", incident_id=target_inc.incident_id)

    # 3. Investigation & Evidence Validation
    inv_engine = InvestigationEngine()
    finding, warning = inv_engine.investigate(target_inc, inc_events, correlation, force_mode="deterministic")

    assert finding is not None
    assert finding.risk_score >= 60
    # Strict evidence validation: all evidence IDs must belong to the incident
    valid_ids = set(e.event_id for e in inc_events)
    for eid in finding.supporting_evidence_ids:
        assert eid in valid_ids

    target_inc.finding = finding
    audit.log("FINDING_GENERATED", "SUCCESS", f"Risk score: {finding.risk_score}", incident_id=target_inc.incident_id)

    # 4. Propose Allowlisted Response Action
    resp_engine = ResponseEngine()
    prop_action = resp_engine.propose_action(
        incident=target_inc,
        action_name=finding.proposed_action,  # "revoke_session"
        target_type="session",
        target_id="sess-9011",
        reasoning=finding.human_review_rationale,
        supporting_evidence_ids=finding.supporting_evidence_ids,
    )
    assert prop_action.status == "awaiting_approval"
    target_inc.proposed_action = prop_action
    audit.log("RESPONSE_PROPOSED", "PENDING", f"Proposed {prop_action.action_name}", incident_id=target_inc.incident_id)

    # 5. Human Analyst Approval Gate
    approved_action = resp_engine.approve_action(prop_action, analyst_id="analyst_verifier")
    assert approved_action.status == "approved"
    assert approved_action.approved_at is not None
    audit.log("ACTION_APPROVED", "SUCCESS", f"Approved by {approved_action.analyst_id}", incident_id=target_inc.incident_id)

    # 6. Execute Simulated Containment against Synthetic State
    demo_state = {
        "synthetic_revoked_sessions": set(),
        "synthetic_locked_accounts": set(),
        "synthetic_escalated_incidents": set(),
        "synthetic_monitored_incidents": set(),
        "incidents": incidents,
    }
    executed_action, demo_state = resp_engine.execute_simulated_action(approved_action, demo_state)
    assert executed_action.status == "executed_simulation"
    assert "sess-9011" in demo_state["synthetic_revoked_sessions"]
    audit.log("SIMULATION_EXECUTED", "SUCCESS", "Executed in simulation", incident_id=target_inc.incident_id)

    # 7. Independent State Verification
    verif_engine = VerificationEngine()
    verif_result = verif_engine.verify_action_state(executed_action, demo_state)
    assert verif_result.passed is True
    assert "PASSED" in verif_result.details
    target_inc.verification_result = verif_result
    audit.log("VERIFICATION_PASSED", "PASSED", verif_result.details, incident_id=target_inc.incident_id)

    # 8. Inspect Audit Trail Integrity
    entries = audit.get_entries(incident_id=target_inc.incident_id)
    assert len(entries) >= 5
    types = [e.event_type for e in entries]
    assert "EVENTS_CORRELATED" in types
    assert "FINDING_GENERATED" in types
    assert "RESPONSE_PROPOSED" in types
    assert "ACTION_APPROVED" in types
    assert "SIMULATION_EXECUTED" in types
    assert "VERIFICATION_PASSED" in types
