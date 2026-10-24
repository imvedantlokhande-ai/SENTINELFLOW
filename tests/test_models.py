"""Unit tests for Pydantic data models in SentinelFlow AI."""

import pytest
from pydantic import ValidationError
from sentinelflow.models import (
    SecurityEvent,
    Incident,
    InvestigationFinding,
    ResponseActionRequest,
    VerificationResult,
    AuditEntry,
)


def test_valid_security_event():
    """Test creating a valid security event."""
    event = SecurityEvent(
        event_id="EVT-100",
        timestamp="2026-10-24T12:00:00Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="admin-test",
        synthetic_source_ip="192.0.2.1",
        fictional_location="Synthetic-US",
        severity="HIGH",
        description="Test authentication event",
        incident_id="INC-001",
        related_entity_ids=["sess-123"],
        evidence_metadata={"mfa": True},
    )
    assert event.event_id == "EVT-100"
    assert event.severity == "HIGH"
    assert event.is_synthetic is True


def test_invalid_event_severity():
    """Test that invalid severity values are rejected."""
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="EVT-101",
            timestamp="2026-10-24T12:00:00Z",
            event_category="AUTHENTICATION",
            synthetic_account_id="admin-test",
            synthetic_source_ip="192.0.2.1",
            severity="SUPER_CRITICAL_INVALID",
            description="Test invalid severity",
        )


def test_missing_required_fields_in_event():
    """Test that missing required fields raise ValidationError."""
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="EVT-102",
            # Missing timestamp, event_category, synthetic_account_id, etc.
            severity="LOW",
            description="Missing fields",
        )


def test_empty_event_id():
    """Test that empty event_id is rejected."""
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="   ",
            timestamp="2026-10-24T12:00:00Z",
            event_category="NETWORK",
            synthetic_account_id="test",
            synthetic_source_ip="192.0.2.1",
            severity="LOW",
            description="Empty ID",
        )


def test_valid_investigation_finding():
    """Test valid structured investigation finding."""
    finding = InvestigationFinding(
        incident_summary="Test summary",
        risk_score=85,
        severity="CRITICAL",
        confidence_score=0.92,
        supporting_evidence_ids=["EVT-101", "EVT-102"],
        timeline_interpretation="Step 1 then step 2",
        likely_explanation="Credential compromise",
        alternative_explanations=["Penetration test"],
        uncertainties_and_limitations="Synthetic data bounds",
        recommended_next_steps=["Revoke session"],
        proposed_action="revoke_session",
        human_review_rationale="Requires confirmation",
    )
    assert finding.risk_score == 85
    assert finding.proposed_action == "revoke_session"


def test_invalid_risk_scores_in_finding():
    """Test that risk scores < 0 or > 100 are rejected."""
    with pytest.raises(ValidationError):
        InvestigationFinding(
            incident_summary="Test",
            risk_score=-5,
            severity="LOW",
            confidence_score=0.5,
            supporting_evidence_ids=["EVT-1"],
            timeline_interpretation="t",
            likely_explanation="e",
            recommended_next_steps=["s"],
            human_review_rationale="r",
            uncertainties_and_limitations="u",
        )

    with pytest.raises(ValidationError):
        InvestigationFinding(
            incident_summary="Test",
            risk_score=105,
            severity="HIGH",
            confidence_score=0.5,
            supporting_evidence_ids=["EVT-1"],
            timeline_interpretation="t",
            likely_explanation="e",
            recommended_next_steps=["s"],
            human_review_rationale="r",
            uncertainties_and_limitations="u",
        )


def test_invalid_confidence_scores_in_finding():
    """Test confidence scores < 0.0 or > 1.0 are rejected."""
    with pytest.raises(ValidationError):
        InvestigationFinding(
            incident_summary="Test",
            risk_score=50,
            severity="MEDIUM",
            confidence_score=1.5,
            supporting_evidence_ids=["EVT-1"],
            timeline_interpretation="t",
            likely_explanation="e",
            recommended_next_steps=["s"],
            human_review_rationale="r",
            uncertainties_and_limitations="u",
        )


def test_empty_supporting_evidence_ids_rejected():
    """Test that empty supporting evidence list is rejected."""
    with pytest.raises(ValidationError):
        InvestigationFinding(
            incident_summary="Test",
            risk_score=50,
            severity="MEDIUM",
            confidence_score=0.8,
            supporting_evidence_ids=[],  # min_length=1
            timeline_interpretation="t",
            likely_explanation="e",
            recommended_next_steps=["s"],
            human_review_rationale="r",
            uncertainties_and_limitations="u",
        )


def test_unsupported_proposed_action_rejected():
    """Test that an arbitrary action name outside the allowlist is rejected."""
    with pytest.raises(ValidationError):
        InvestigationFinding(
            incident_summary="Test",
            risk_score=90,
            severity="CRITICAL",
            confidence_score=0.9,
            supporting_evidence_ids=["EVT-1"],
            timeline_interpretation="t",
            likely_explanation="e",
            recommended_next_steps=["s"],
            proposed_action="format_c_drive_rm_rf",  # Illegal action
            human_review_rationale="r",
            uncertainties_and_limitations="u",
        )


def test_invalid_response_action_request():
    """Test that invalid action name in ResponseActionRequest raises ValidationError."""
    with pytest.raises(ValidationError):
        ResponseActionRequest(
            action_id="ACT-001",
            incident_id="INC-001",
            action_name="unauthorized_reboot_host",
            target_type="host",
            target_id="host-1",
            reasoning="test",
            supporting_evidence_ids=["EVT-1"],
        )


def test_invalid_incident_status():
    """Test that invalid incident status raises ValidationError."""
    with pytest.raises(ValidationError):
        Incident(
            incident_id="INC-001",
            title="Test",
            description="Test",
            scenario_id="S1",
            created_at="2026-10-24T00:00:00Z",
            severity="HIGH",
            status="INVALID_STATUS_ABC",
            primary_account="user-1",
        )
