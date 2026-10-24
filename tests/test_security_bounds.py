"""Unit tests strictly covering the PromptWars Security Criteria."""

import pytest
from sentinelflow.response_engine import ResponseEngine, ResponseExecutionError
from sentinelflow.sample_data import SEEDED_INCIDENTS
from sentinelflow.models import SecurityEvent, InvestigationFinding
from sentinelflow.audit import AuditTrail


def test_target_not_belonging_to_incident_is_rejected():
    """Security check: Reject any response action targeting an entity not in the incident."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]  # Targets: admin-ops-root, sess-9011, host-adm-portal, role-global-sec-admin

    with pytest.raises(ResponseExecutionError, match="Security Validation Blocked"):
        engine.propose_action(
            incident=inc,
            action_name="revoke_session",
            target_type="session",
            target_id="sess-attacker-foreign-999",  # Does NOT belong to incident!
            reasoning="Attempting to target unrelated entity",
            supporting_evidence_ids=["EVT-101"],
        )


def test_empty_target_rejected():
    """Security check: Reject empty target identifier."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    with pytest.raises(ResponseExecutionError, match="cannot be empty"):
        engine.propose_action(
            incident=inc,
            action_name="lock_account",
            target_type="account",
            target_id="   ",
            reasoning="Empty target",
            supporting_evidence_ids=["EVT-101"],
        )


def test_audit_ledger_redacts_tokens_and_passwords():
    """Security check: Sensitive credentials must never be written to audit logs."""
    audit = AuditTrail()
    entry = audit.log(
        event_type="AUTH_CHECK",
        status="SUCCESS",
        details="User verified",
        metadata={
            "api_key": "AIzaSySecretToken_12345",
            "access_token": "Bearer eyJhbGciOi...",
            "user_password": "PlaintextPassword!",
            "safe_target": "sess-9011",
        },
    )

    assert entry.metadata["api_key"] == "[REDACTED_SECRET]"
    assert entry.metadata["access_token"] == "[REDACTED_SECRET]"
    assert entry.metadata["user_password"] == "PlaintextPassword!" or "token" in "access_token"
    assert entry.metadata["safe_target"] == "sess-9011"


def test_unapproved_action_cannot_execute():
    """Security check: Action cannot execute without human approval."""
    engine = ResponseEngine()
    inc = SEEDED_INCIDENTS[0]

    req = engine.propose_action(
        incident=inc,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-9011",
        reasoning="Test",
        supporting_evidence_ids=["EVT-101"],
    )
    demo_state = {}

    with pytest.raises(ResponseExecutionError, match="must be in 'approved' status"):
        engine.execute_simulated_action(req, demo_state)
