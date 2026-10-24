"""Tests for Server-Side Role-Based Access Control (RBAC) and IDOR Protection.

Verifies:
- Explicit permission matrix for 'viewer', 'analyst', and 'administrator'
- Denial of sensitive state operations to unauthorized roles
- Two-tier containment approval (critical account locking requires admin)
- Insecure Direct Object Reference (IDOR) target isolation
"""

import time
import pytest
from sentinelflow.auth import UserSession, get_default_demo_session
from sentinelflow.models import Incident, ResponseActionRequest
from sentinelflow.authorization import (
    check_permission,
    enforce_permission,
    validate_idor_target_ownership,
    AuthorizationError,
    PERM_VIEW_INCIDENTS,
    PERM_APPROVE_RESPONSE_TIER1,
    PERM_APPROVE_RESPONSE_TIER2,
    PERM_EXECUTE_SIMULATION,
    PERM_MODIFY_CONFIG,
    PERM_RESET_DEMO_DATA,
)


@pytest.fixture
def sample_incident():
    return Incident(
        incident_id="INC-TEST-001",
        title="Test Compromise Scenario",
        description="Synthetic unauthorized access simulation",
        scenario_id="SCENARIO_1",
        created_at="2026-10-24T12:00:00Z",
        severity="CRITICAL",
        primary_account="admin-root-01",
        event_ids=["EVT-101", "EVT-102"],
        correlated_entities=["sess-8899", "host-srv-01"],
    )


def test_viewer_role_has_read_only_access(sample_incident):
    """Verify viewer role has read access but is blocked from mutative operations."""
    viewer = get_default_demo_session("viewer")

    # Read access allowed
    allowed, _ = check_permission(viewer, PERM_VIEW_INCIDENTS)
    assert allowed is True

    # Mutative containment operations blocked
    allowed, reason = check_permission(viewer, PERM_APPROVE_RESPONSE_TIER1)
    assert allowed is False
    assert "lacks required permission" in reason

    with pytest.raises(AuthorizationError, match="lacks required permission"):
        enforce_permission(viewer, PERM_EXECUTE_SIMULATION)

    with pytest.raises(AuthorizationError, match="lacks required permission"):
        enforce_permission(viewer, PERM_MODIFY_CONFIG)


def test_analyst_can_approve_tier1_but_blocked_on_tier2_critical_lock(sample_incident):
    """Verify analyst can approve standard containment but requires admin for critical account locking."""
    analyst = get_default_demo_session("analyst")

    # 1. Tier-1 Session Revocation action is permitted
    action_revoke = ResponseActionRequest(
        action_id="ACT-001",
        incident_id=sample_incident.incident_id,
        action_name="revoke_session",
        target_type="session",
        target_id="sess-8899",
        reasoning="Terminate compromised session",
        supporting_evidence_ids=["EVT-101"],
        status="proposed",
    )
    allowed, reason = check_permission(
        session=analyst,
        permission=PERM_APPROVE_RESPONSE_TIER1,
        incident=sample_incident,
        target_id="sess-8899",
        action_request=action_revoke,
    )
    assert allowed is True

    # 2. Tier-2 Critical Account Lock on a CRITICAL incident is blocked for analyst
    action_lock = ResponseActionRequest(
        action_id="ACT-002",
        incident_id=sample_incident.incident_id,
        action_name="lock_account",
        target_type="account",
        target_id="admin-root-01",
        reasoning="Lock root account",
        supporting_evidence_ids=["EVT-101"],
        status="proposed",
    )
    allowed_lock, reason_lock = check_permission(
        session=analyst,
        permission=PERM_APPROVE_RESPONSE_TIER1,
        incident=sample_incident,
        target_id="admin-root-01",
        action_request=action_lock,
    )
    assert allowed_lock is False
    assert "Tier-2 Authorization Required" in reason_lock


def test_administrator_has_full_operational_authority(sample_incident):
    """Verify administrator can approve all tiers, modify config, and reset demo data."""
    admin = get_default_demo_session("administrator")

    # Critical account lock allowed for admin
    action_lock = ResponseActionRequest(
        action_id="ACT-002",
        incident_id=sample_incident.incident_id,
        action_name="lock_account",
        target_type="account",
        target_id="admin-root-01",
        reasoning="Lock root account",
        supporting_evidence_ids=["EVT-101"],
        status="proposed",
    )
    allowed, _ = check_permission(
        session=admin,
        permission=PERM_APPROVE_RESPONSE_TIER2,
        incident=sample_incident,
        target_id="admin-root-01",
        action_request=action_lock,
    )
    assert allowed is True

    # Config modification and reset allowed
    assert check_permission(admin, PERM_MODIFY_CONFIG)[0] is True
    assert check_permission(admin, PERM_RESET_DEMO_DATA)[0] is True


def test_idor_target_ownership_enforcement(sample_incident):
    """Verify IDOR protection blocks actions targeting entities outside incident scope."""
    analyst = get_default_demo_session("analyst")

    # Target belonging to incident is valid
    assert validate_idor_target_ownership(sample_incident, "sess-8899") is True
    assert validate_idor_target_ownership(sample_incident, "admin-root-01") is True

    # Target belonging to an external, unrelated account/session is strictly blocked
    assert validate_idor_target_ownership(sample_incident, "unrelated-user-account") is False
    assert validate_idor_target_ownership(sample_incident, "sess-foreign-9999") is False

    # Attempting to check permission on foreign target raises IDOR block
    allowed, reason = check_permission(
        session=analyst,
        permission=PERM_APPROVE_RESPONSE_TIER1,
        incident=sample_incident,
        target_id="sess-foreign-9999",
    )
    assert allowed is False
    assert "IDOR Violation" in reason


def test_expired_or_unauthenticated_session_denied(sample_incident):
    """Verify unauthenticated requests or expired sessions are denied all permissions."""
    # None session
    allowed, reason = check_permission(None, PERM_VIEW_INCIDENTS)
    assert allowed is False
    assert "Authentication required" in reason

    # Expired session
    expired_user = UserSession(
        uid="usr-expired",
        email="analyst@sentinelflow.ai",
        role="administrator",
        expires_at=time.time() - 50.0,
    )
    allowed_exp, reason_exp = check_permission(expired_user, PERM_MODIFY_CONFIG)
    assert allowed_exp is False
    assert "Session expired" in reason_exp
