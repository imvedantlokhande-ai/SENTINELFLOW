"""Tests for Safe Human-in-the-Loop Simulated Response Engine.

Verifies:
- Strict allowlist enforcement (rejects arbitrary system commands)
- Mandatory human analyst authorization gate
- Prevention of duplicate containment action execution
- Independent state verification and failure detection
- Inability of rejected or unauthorized actions to mutate state
- Target ID and incident scope validation
"""

import pytest
from sentinelflow.response_engine import ResponseEngine, ResponseExecutionError
from sentinelflow.verification import VerificationEngine
from sentinelflow.models import Incident, ResponseActionRequest
from sentinelflow.auth import get_default_demo_session
from sentinelflow.authorization import AuthorizationError


@pytest.fixture
def mock_incident():
    return Incident(
        incident_id="INC-SIM-001",
        title="Simulated Credential Abuse",
        description="Synthetic testing scenario",
        scenario_id="SCENARIO_2",
        created_at="2026-10-24T12:00:00Z",
        severity="HIGH",
        primary_account="j.doe",
        event_ids=["EVT-201"],
        correlated_entities=["sess-4412", "host-ws-04"],
    )


@pytest.fixture
def response_env():
    engine = ResponseEngine()
    verif_engine = VerificationEngine()
    demo_state = {
        "synthetic_revoked_sessions": set(),
        "synthetic_locked_accounts": set(),
        "synthetic_escalated_incidents": set(),
        "synthetic_monitored_incidents": set(),
        "incidents": [],
    }
    return engine, verif_engine, demo_state


def test_propose_action_rejects_unallowlisted_or_empty_actions(response_env, mock_incident):
    """Verify that arbitrary or unallowlisted actions are rejected upon proposal."""
    engine, _, _ = response_env

    # Disallowed action (e.g. system commands, code execution)
    with pytest.raises(ResponseExecutionError, match="not permitted"):
        engine.propose_action(
            incident=mock_incident,
            action_name="execute_system_script",
            target_type="account",
            target_id="j.doe",
            reasoning="Disallowed action",
            supporting_evidence_ids=["EVT-201"],
        )

    # Empty target
    with pytest.raises(ResponseExecutionError, match="cannot be empty"):
        engine.propose_action(
            incident=mock_incident,
            action_name="revoke_session",
            target_type="session",
            target_id="",
            reasoning="Empty target",
            supporting_evidence_ids=["EVT-201"],
        )


def test_action_execution_without_prior_approval_is_blocked(response_env, mock_incident):
    """Verify that an action in 'proposed' status cannot be executed directly."""
    engine, _, demo_state = response_env

    proposed = engine.propose_action(
        incident=mock_incident,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-4412",
        reasoning="Revoke session",
        supporting_evidence_ids=["EVT-201"],
    )

    # Execution attempt while status is 'awaiting_approval'
    with pytest.raises(ResponseExecutionError, match="Action must be in 'approved' status"):
        engine.execute_simulated_action(proposed, demo_state)

    # Verify synthetic demo state was NOT mutated
    assert len(demo_state["synthetic_revoked_sessions"]) == 0


def test_rejected_action_cannot_mutate_state(response_env, mock_incident):
    """Verify that a rejected action cannot be approved or executed."""
    engine, _, demo_state = response_env
    analyst = get_default_demo_session("analyst")

    proposed = engine.propose_action(
        incident=mock_incident,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-4412",
        reasoning="Revoke session",
        supporting_evidence_ids=["EVT-201"],
    )

    rejected = engine.reject_action(proposed, session=analyst)
    assert rejected.status == "rejected"

    # Attempting to execute rejected action is blocked
    with pytest.raises(ResponseExecutionError, match="Action must be in 'approved' status"):
        engine.execute_simulated_action(rejected, demo_state, session=analyst)

    assert len(demo_state["synthetic_revoked_sessions"]) == 0


def test_duplicate_action_execution_is_prevented(response_env, mock_incident):
    """Verify that executing the same approved action twice is blocked."""
    engine, _, demo_state = response_env
    analyst = get_default_demo_session("analyst")

    proposed = engine.propose_action(
        incident=mock_incident,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-4412",
        reasoning="Revoke session",
        supporting_evidence_ids=["EVT-201"],
    )

    approved = engine.approve_action(proposed, session=analyst, incident=mock_incident)

    # First execution succeeds
    executed, state_after_1 = engine.execute_simulated_action(
        approved, demo_state, session=analyst, incident=mock_incident
    )
    assert executed.status == "executed_simulation"
    assert "sess-4412" in state_after_1["synthetic_revoked_sessions"]

    # Duplicate execution attempt raises error
    with pytest.raises(ResponseExecutionError, match="Duplicate execution blocked"):
        engine.execute_simulated_action(executed, state_after_1, session=analyst, incident=mock_incident)


def test_verification_engine_detects_state_transition_and_failures(response_env, mock_incident):
    """Verify that VerificationEngine independently checks resulting synthetic state."""
    engine, verif_engine, demo_state = response_env
    analyst = get_default_demo_session("analyst")

    proposed = engine.propose_action(
        incident=mock_incident,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-4412",
        reasoning="Revoke session",
        supporting_evidence_ids=["EVT-201"],
    )

    approved = engine.approve_action(proposed, session=analyst, incident=mock_incident)
    executed, state_after = engine.execute_simulated_action(approved, demo_state, session=analyst, incident=mock_incident)

    # 1. Verification succeeds when state matches
    verif_pass = verif_engine.verify_action_state(executed, state_after)
    assert verif_pass.passed is True
    assert "passed" in verif_pass.details.lower()

    # 2. Verification fails if state was somehow tampered/missing target
    corrupted_state = {"synthetic_revoked_sessions": set()}
    verif_fail = verif_engine.verify_action_state(executed, corrupted_state)
    assert verif_fail.passed is False
    assert "failed" in verif_fail.details.lower()
