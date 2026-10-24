"""Unit tests for the Human-in-the-Loop Response Engine."""

import pytest
from sentinelflow.response_engine import ResponseEngine, ResponseExecutionError
from sentinelflow.sample_data import SEEDED_INCIDENTS


def test_propose_allowlisted_action():
    """Test proposing an action from the strict allowlist."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    req = engine.propose_action(
        incident=inc,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-9011",
        reasoning="Suspicious geo-location",
        supporting_evidence_ids=["EVT-101"],
    )

    assert req.action_name == "revoke_session"
    assert req.target_id == "sess-9011"
    assert req.status == "awaiting_approval"


def test_propose_unsupported_action_raises_error():
    """Test proposing an action outside allowlist raises ResponseExecutionError."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    with pytest.raises(ResponseExecutionError, match="not permitted"):
        engine.propose_action(
            incident=inc,
            action_name="execute_raw_bash_script",
            target_type="system",
            target_id="root",
            reasoning="illegal",
            supporting_evidence_ids=["EVT-101"],
        )


def test_execution_without_approval_blocked():
    """Test that executing an action before approval is rejected."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    req = engine.propose_action(
        incident=inc,
        action_name="lock_account",
        target_type="account",
        target_id=inc.primary_account,
        reasoning="test",
        supporting_evidence_ids=["EVT-101"],
    )
    demo_state = {}

    with pytest.raises(ResponseExecutionError, match="must be in 'approved' status"):
        engine.execute_simulated_action(req, demo_state)


def test_rejection_prevents_execution():
    """Test that rejecting an action prevents execution."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    req = engine.propose_action(
        incident=inc,
        action_name="lock_account",
        target_type="account",
        target_id=inc.primary_account,
        reasoning="test",
        supporting_evidence_ids=["EVT-101"],
    )

    rejected_req = engine.reject_action(req, analyst_id="analyst_bob", rejection_reason="False positive")
    assert rejected_req.status == "rejected"

    demo_state = {}
    with pytest.raises(ResponseExecutionError, match="must be in 'approved' status"):
        engine.execute_simulated_action(rejected_req, demo_state)


def test_duplicate_execution_blocked():
    """Test that duplicate execution of an action is blocked."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    req = engine.propose_action(
        incident=inc,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-9011",
        reasoning="test",
        supporting_evidence_ids=["EVT-101"],
    )

    approved = engine.approve_action(req, analyst_id="analyst_alice")
    demo_state = {}
    executed, demo_state = engine.execute_simulated_action(approved, demo_state)

    assert executed.status == "executed_simulation"
    assert "sess-9011" in demo_state["synthetic_revoked_sessions"]

    # Attempting to execute the already executed action again
    with pytest.raises(ResponseExecutionError, match="(Duplicate execution blocked|must be in 'approved' status)"):
        engine.execute_simulated_action(executed, demo_state)


def test_simulated_account_lock():
    """Test simulated account locking updates demo state."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[2]

    req = engine.propose_action(
        incident=inc,
        action_name="lock_account",
        target_type="account",
        target_id="svc-billing-exporter",
        reasoning="Compromised service account",
        supporting_evidence_ids=["EVT-301"],
    )

    approved = engine.approve_action(req)
    demo_state = {}
    executed, demo_state = engine.execute_simulated_action(approved, demo_state)

    assert "svc-billing-exporter" in demo_state["synthetic_locked_accounts"]


def test_simulated_escalation_and_monitoring():
    """Test escalation and monitoring actions update demo state."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[3]

    # Test monitoring
    req_mon = engine.propose_action(
        incident=inc,
        action_name="mark_monitoring",
        target_type="incident",
        target_id=inc.incident_id,
        reasoning="Benign backup context",
        supporting_evidence_ids=["EVT-401"],
    )
    approved_mon = engine.approve_action(req_mon)
    demo_state = {}
    executed_mon, demo_state = engine.execute_simulated_action(approved_mon, demo_state)
    assert inc.incident_id in demo_state["synthetic_monitored_incidents"]

    # Test escalation
    req_esc = engine.propose_action(
        incident=inc,
        action_name="escalate_incident",
        target_type="incident",
        target_id=inc.incident_id,
        reasoning="Escalate for senior SOC review",
        supporting_evidence_ids=["EVT-401"],
    )
    approved_esc = engine.approve_action(req_esc)
    executed_esc, demo_state = engine.execute_simulated_action(approved_esc, demo_state)
    assert inc.incident_id in demo_state["synthetic_escalated_incidents"]
