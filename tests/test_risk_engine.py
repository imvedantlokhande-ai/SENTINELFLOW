"""Unit tests for the Deterministic Risk Engine."""

from sentinelflow.risk_engine import RiskEngine
from sentinelflow.event_correlation import EventCorrelationEngine
from sentinelflow.sample_data import (
    SCENARIO_1_EVENTS,
    SCENARIO_3_EVENTS,
    SCENARIO_4_EVENTS,
    SCENARIO_5_EVENTS,
    SCENARIO_6_EVENTS,
)


def test_benign_sso_risk_evaluation():
    """Test that benign routine SSO results in low risk and monitoring recommendation."""
    corr_engine = EventCorrelationEngine()
    risk_engine = RiskEngine()

    corr = corr_engine.correlate_incident_events(SCENARIO_5_EVENTS, incident_id="INC-2026-005")
    breakdown = risk_engine.evaluate_incident(SCENARIO_5_EVENTS, corr)

    assert breakdown.risk_score <= 25
    assert breakdown.severity in ("INFORMATIONAL", "LOW")
    assert breakdown.recommended_action == "mark_monitoring"
    assert len(breakdown.reducing_factors) > 0


def test_benign_dr_sync_with_ticket_mitigation():
    """Test that sanctioned ticket mitigates risk score for bulk export."""
    corr_engine = EventCorrelationEngine()
    risk_engine = RiskEngine()

    corr = corr_engine.correlate_incident_events(SCENARIO_4_EVENTS, incident_id="INC-2026-004")
    breakdown = risk_engine.evaluate_incident(SCENARIO_4_EVENTS, corr)

    assert breakdown.risk_score < 60
    assert any("SEC-DATA-SYNC-98" in f for f in breakdown.reducing_factors)
    assert breakdown.recommended_action in ("mark_monitoring", "escalate_incident")


def test_critical_c2_exfiltration_risk_evaluation():
    """Test that C2 exfiltration produces high/critical risk and account locking."""
    corr_engine = EventCorrelationEngine()
    risk_engine = RiskEngine()

    corr = corr_engine.correlate_incident_events(SCENARIO_6_EVENTS, incident_id="INC-2026-006")
    breakdown = risk_engine.evaluate_incident(SCENARIO_6_EVENTS, corr)

    assert breakdown.risk_score >= 80
    assert breakdown.severity == "CRITICAL"
    assert breakdown.recommended_action == "lock_account"
    assert len(breakdown.increasing_factors) >= 3


def test_service_account_compromise_risk_evaluation():
    """Test service account compromise evaluation."""
    corr_engine = EventCorrelationEngine()
    risk_engine = RiskEngine()

    corr = corr_engine.correlate_incident_events(SCENARIO_3_EVENTS, incident_id="INC-2026-003")
    breakdown = risk_engine.evaluate_incident(SCENARIO_3_EVENTS, corr)

    assert breakdown.risk_score >= 75
    assert breakdown.severity in ("HIGH", "CRITICAL")
    assert any("SUPERUSER" in f or "Privilege escalation" in f for f in breakdown.increasing_factors)
