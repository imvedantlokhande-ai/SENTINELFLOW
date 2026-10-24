"""Unit tests for the Append-Only Audit Trail."""

from sentinelflow.audit import AuditTrail


def test_audit_log_entry_creation():
    """Test creating an audit entry and incrementing IDs."""
    audit = AuditTrail()
    e1 = audit.log(
        event_type="INVESTIGATION_STARTED",
        status="RUNNING",
        incident_id="INC-001",
        actor="analyst",
        details="Started manual investigation.",
    )
    assert e1.entry_id == "AUD-00001"
    assert e1.event_type == "INVESTIGATION_STARTED"

    e2 = audit.log(
        event_type="RESPONSE_PROPOSED",
        status="PENDING",
        incident_id="INC-001",
        actor="system",
        details="Proposed session revocation.",
    )
    assert e2.entry_id == "AUD-00002"
    assert len(audit.get_entries()) == 2


def test_audit_secret_redaction():
    """Test that secrets or API keys are automatically redacted in audit metadata."""
    audit = AuditTrail()
    e = audit.log(
        event_type="CONFIG_SAVED",
        status="SUCCESS",
        actor="admin",
        details="Saved provider settings",
        metadata={"gemini_api_key": "AIzaSySecretRealKey12345", "safe_param": "gemini-3.8-flash"},
    )
    assert e.metadata["gemini_api_key"] == "[REDACTED_SECRET]"
    assert e.metadata["safe_param"] == "gemini-3.8-flash"


def test_audit_filtering():
    """Test filtering audit entries by incident_id and event_type."""
    audit = AuditTrail()
    audit.log("FINDING_GENERATED", "SUCCESS", "details", incident_id="INC-001")
    audit.log("ACTION_APPROVED", "SUCCESS", "details", incident_id="INC-001")
    audit.log("FINDING_GENERATED", "SUCCESS", "details", incident_id="INC-002")

    inc1_entries = audit.get_entries(incident_id="INC-001")
    assert len(inc1_entries) == 2

    finding_entries = audit.get_entries(event_type="FINDING_GENERATED")
    assert len(finding_entries) == 2
