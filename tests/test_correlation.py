"""Unit tests for the Deterministic Event Correlation Engine."""

import pytest
from sentinelflow.event_correlation import EventCorrelationEngine
from sentinelflow.sample_data import (
    SCENARIO_1_EVENTS,
    SCENARIO_2_EVENTS,
    SCENARIO_3_EVENTS,
    SCENARIO_4_EVENTS,
    SCENARIO_5_EVENTS,
    SCENARIO_6_EVENTS,
)


def test_correlate_empty_events_raises_error():
    """Test that correlating an empty event list raises ValueError."""
    engine = EventCorrelationEngine()
    with pytest.raises(ValueError, match="Cannot correlate empty event list"):
        engine.correlate_incident_events([])


def test_correlate_credential_stuffing_scenario():
    """Test correlation of failed logins followed by success (Scenario 2)."""
    engine = EventCorrelationEngine()
    corr = engine.correlate_incident_events(SCENARIO_2_EVENTS, incident_id="INC-2026-002")

    assert corr.incident_id == "INC-2026-002"
    assert corr.primary_account == "j.doe@sentinelflow.internal"
    assert len(corr.event_ids) == 5
    assert any("RULE-CORR-01" in r for r in corr.correlation_rules_triggered)
    assert corr.confidence_score >= 0.80
    assert "sess-4412" in corr.related_entities


def test_correlate_anomalous_geo_admin_scenario():
    """Test correlation of anomalous admin login with IAM escalation (Scenario 1)."""
    engine = EventCorrelationEngine()
    corr = engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id="INC-2026-001")

    assert corr.primary_account == "admin-ops-root"
    assert any("RULE-CORR-02" in r for r in corr.correlation_rules_triggered)
    assert corr.confidence_score >= 0.80


def test_correlate_service_account_compromise():
    """Test correlation of service account compromise and S3 exfiltration (Scenario 3)."""
    engine = EventCorrelationEngine()
    corr = engine.correlate_incident_events(SCENARIO_3_EVENTS, incident_id="INC-2026-003")

    assert corr.primary_account == "svc-billing-exporter"
    assert any("RULE-CORR-03" in r for r in corr.correlation_rules_triggered)
    assert "role-superadmin" in corr.related_entities


def test_correlate_endpoint_c2_exfiltration():
    """Test correlation of PowerShell execution and C2 exfiltration (Scenario 6)."""
    engine = EventCorrelationEngine()
    corr = engine.correlate_incident_events(SCENARIO_6_EVENTS, incident_id="INC-2026-006")

    assert corr.primary_account == "eng-k.chen"
    assert any("RULE-CORR-04" in r for r in corr.correlation_rules_triggered)
    assert corr.confidence_score >= 0.85


def test_correlate_benign_routine_sso():
    """Test correlation of compliant benign SSO routine activity (Scenario 5)."""
    engine = EventCorrelationEngine()
    corr = engine.correlate_incident_events(SCENARIO_5_EVENTS, incident_id="INC-2026-005")

    assert corr.primary_account == "hr-m.garcia"
    assert any("RULE-CORR-06" in r for r in corr.correlation_rules_triggered)


def test_group_events_by_account_or_incident():
    """Test grouping a mixed list of events."""
    engine = EventCorrelationEngine()
    all_events = SCENARIO_1_EVENTS + SCENARIO_2_EVENTS
    grouped = engine.group_events_by_account_or_incident(all_events)

    assert "INC-2026-001" in grouped
    assert "INC-2026-002" in grouped
    assert len(grouped["INC-2026-001"]) == len(SCENARIO_1_EVENTS)
