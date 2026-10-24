"""Unit tests for the Independent Verification Engine."""

from sentinelflow.verification import VerificationEngine
from sentinelflow.models import ResponseActionRequest


def test_verification_success_session_revocation():
    """Test verification passes when revoked session is present in state."""
    engine = VerificationEngine()
    req = ResponseActionRequest(
        action_id="ACT-001",
        incident_id="INC-001",
        action_name="revoke_session",
        target_type="session",
        target_id="sess-9999",
        reasoning="test",
        supporting_evidence_ids=["EVT-1"],
        status="executed_simulation",
    )
    demo_state = {"synthetic_revoked_sessions": {"sess-9999"}}

    result = engine.verify_action_state(req, demo_state)
    assert result.passed is True
    assert "PASSED" in result.details
    assert result.actual_state["session_revoked"] is True


def test_verification_failure_when_state_not_mutated():
    """Test verification FAILS when expected session revocation is missing from state."""
    engine = VerificationEngine()
    req = ResponseActionRequest(
        action_id="ACT-002",
        incident_id="INC-001",
        action_name="revoke_session",
        target_type="session",
        target_id="sess-missing",
        reasoning="test",
        supporting_evidence_ids=["EVT-1"],
        status="executed_simulation",
    )
    # Empty demo state - session was never added!
    demo_state = {"synthetic_revoked_sessions": set()}

    result = engine.verify_action_state(req, demo_state)
    assert result.passed is False
    assert "FAILED" in result.details
    assert result.actual_state["session_revoked"] is False


def test_verification_account_lock_success_and_failure():
    """Test account lock verification passes when present, fails when absent."""
    engine = VerificationEngine()
    req = ResponseActionRequest(
        action_id="ACT-003",
        incident_id="INC-003",
        action_name="lock_account",
        target_type="account",
        target_id="svc-compromised",
        reasoning="test",
        supporting_evidence_ids=["EVT-3"],
        status="executed_simulation",
    )

    # Success case
    state_ok = {"synthetic_locked_accounts": {"svc-compromised"}}
    res_ok = engine.verify_action_state(req, state_ok)
    assert res_ok.passed is True

    # Failure case
    state_fail = {"synthetic_locked_accounts": {"other-account"}}
    res_fail = engine.verify_action_state(req, state_fail)
    assert res_fail.passed is False
    assert "FAILED" in res_fail.details


def test_verification_escalation_and_monitoring():
    """Test escalation and monitoring verification."""
    engine = VerificationEngine()

    req_esc = ResponseActionRequest(
        action_id="ACT-004",
        incident_id="INC-2026-004",
        action_name="escalate_incident",
        target_type="incident",
        target_id="INC-2026-004",
        reasoning="test",
        supporting_evidence_ids=["EVT-4"],
        status="executed_simulation",
    )
    state_esc = {"synthetic_escalated_incidents": {"INC-2026-004"}}
    assert engine.verify_action_state(req_esc, state_esc).passed is True

    state_no_esc = {"synthetic_escalated_incidents": set()}
    assert engine.verify_action_state(req_esc, state_no_esc).passed is False
