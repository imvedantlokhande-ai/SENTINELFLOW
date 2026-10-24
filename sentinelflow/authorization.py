"""Server-Side Role-Based Access Control (RBAC) and IDOR Protection for SentinelFlow AI.

Enforces:
- Explicit permission matrix across 'viewer', 'analyst', and 'administrator' roles
- Insecure Direct Object Reference (IDOR) validation
- Sensitive state operation guarding (approval, execution, config changes, resets)
- Centralized server-side authorization enforcement without relying on client UI hiding
"""

from typing import Optional, Dict, Set, Tuple
from sentinelflow.auth import UserSession
from sentinelflow.models import Incident, ResponseActionRequest


class AuthorizationError(Exception):
    """Exception raised when an authenticated or unauthenticated user lacks required permission."""
    pass


# Permissions Registry
PERM_VIEW_DASHBOARD = "VIEW_DASHBOARD"
PERM_VIEW_INCIDENTS = "VIEW_INCIDENTS"
PERM_VIEW_INTEL = "VIEW_INTEL"
PERM_VIEW_AUDIT = "VIEW_AUDIT"
PERM_ANALYZE_INCIDENT = "ANALYZE_INCIDENT"
PERM_PROPOSE_RESPONSE = "PROPOSE_RESPONSE"
PERM_APPROVE_RESPONSE_TIER1 = "APPROVE_RESPONSE_TIER1"
PERM_APPROVE_RESPONSE_TIER2 = "APPROVE_RESPONSE_TIER2"
PERM_EXECUTE_SIMULATION = "EXECUTE_SIMULATION"
PERM_MODIFY_CONFIG = "MODIFY_CONFIG"
PERM_RESET_DEMO_DATA = "RESET_DEMO_DATA"
PERM_EXPORT_AUDIT_LOG = "EXPORT_AUDIT_LOG"


# Strict Role-to-Permissions Mapping
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "viewer": {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_VIEW_INTEL,
        PERM_VIEW_AUDIT,
    },
    "analyst": {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_VIEW_INTEL,
        PERM_VIEW_AUDIT,
        PERM_ANALYZE_INCIDENT,
        PERM_PROPOSE_RESPONSE,
        PERM_APPROVE_RESPONSE_TIER1,
        PERM_EXECUTE_SIMULATION,
        PERM_EXPORT_AUDIT_LOG,
    },
    "administrator": {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INCIDENTS,
        PERM_VIEW_INTEL,
        PERM_VIEW_AUDIT,
        PERM_ANALYZE_INCIDENT,
        PERM_PROPOSE_RESPONSE,
        PERM_APPROVE_RESPONSE_TIER1,
        PERM_APPROVE_RESPONSE_TIER2,
        PERM_EXECUTE_SIMULATION,
        PERM_MODIFY_CONFIG,
        PERM_RESET_DEMO_DATA,
        PERM_EXPORT_AUDIT_LOG,
    },
}


def validate_idor_target_ownership(
    incident: Incident,
    target_id: str,
) -> bool:
    """Validate that target_id strictly belongs to the scope of the given incident.

    Prevents Insecure Direct Object References (IDOR) where an attacker attempts
    to manipulate or quarantine targets belonging to an unrelated incident or user.

    Returns:
        True if target is validly associated with the incident; False otherwise.
    """
    if not target_id or not target_id.strip():
        return False

    clean_target = target_id.strip()
    permitted_targets = set(incident.correlated_entities) | {
        incident.primary_account,
        incident.incident_id,
    }
    return clean_target in permitted_targets


def check_permission(
    session: Optional[UserSession],
    permission: str,
    incident: Optional[Incident] = None,
    target_id: Optional[str] = None,
    action_request: Optional[ResponseActionRequest] = None,
) -> Tuple[bool, Optional[str]]:
    """Evaluate whether the given user session holds the requested permission.

    Returns:
        (allowed: bool, reason_if_denied: Optional[str])
    """
    # 1. Validate session integrity (authenticated, not expired, not revoked, account active)
    if session is None:
        return False, "Authentication required. Please log in to perform this operation."

    is_valid, invalid_reason = session.is_valid()
    if not is_valid:
        return False, invalid_reason or "Session is not valid. Please re-authenticate."

    # 3. Check role authorization matrix
    user_role = session.role.lower()
    allowed_perms = ROLE_PERMISSIONS.get(user_role, set())

    if permission not in allowed_perms:
        return False, f"Access Denied: Role '{user_role}' lacks required permission '{permission}'."

    # 4. Contextual Tier-2 check: Critical account locking requires Tier-2 approval
    if permission in (PERM_APPROVE_RESPONSE_TIER1, PERM_APPROVE_RESPONSE_TIER2):
        if action_request is not None:
            # High-impact containment (account locking) requires administrator (Tier-2)
            is_tier2_action = action_request.action_name == "lock_account"
            if is_tier2_action and user_role != "administrator":
                return (
                    False,
                    f"Tier-2 Authorization Required: Action '{action_request.action_name}' requires Administrator approval (current role: '{user_role}').",
                )

    # 5. IDOR validation if incident and target are specified
    if incident is not None and target_id is not None:
        if not validate_idor_target_ownership(incident, target_id):
            return (
                False,
                f"Security Validation Blocked (IDOR Violation): Target '{target_id}' is not an authorized entity of Incident '{incident.incident_id}'.",
            )

    return True, None


def enforce_permission(
    session: Optional[UserSession],
    permission: str,
    incident: Optional[Incident] = None,
    target_id: Optional[str] = None,
    action_request: Optional[ResponseActionRequest] = None,
) -> None:
    """Enforce authorization, raising AuthorizationError if denied.

    Server-side gatekeeper function for all sensitive mutative actions.
    """
    allowed, reason = check_permission(
        session=session,
        permission=permission,
        incident=incident,
        target_id=target_id,
        action_request=action_request,
    )
    if not allowed:
        raise AuthorizationError(reason or "Unauthorized operation.")
