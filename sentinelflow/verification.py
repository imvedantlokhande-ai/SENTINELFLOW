"""Independent State Verification Engine for SentinelFlow AI.

Verifies that simulated containment actions actually produced the expected synthetic
state transitions rather than blindly trusting the response engine's return value.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from sentinelflow.models import ResponseActionRequest, VerificationResult


class VerificationEngine:
    """Independent verifier for simulated incident response state transitions."""

    def verify_action_state(
        self,
        action_request: ResponseActionRequest,
        demo_state: Dict[str, Any],
    ) -> VerificationResult:
        """Inspect synthetic state independently and verify the requested transition occurred."""
        action = action_request.action_name
        target_id = action_request.target_id
        incident_id = action_request.incident_id
        verification_id = f"VERIF-{action_request.action_id}"

        expected_state: Dict[str, Any] = {}
        actual_state: Dict[str, Any] = {}
        passed = False
        details = ""

        if action == "revoke_session":
            revoked_sessions = demo_state.get("synthetic_revoked_sessions", set())
            expected_state = {"session_revoked": True, "target_session": target_id}
            is_revoked = target_id in revoked_sessions
            actual_state = {"session_revoked": is_revoked, "active_revocations": list(revoked_sessions)}

            if is_revoked:
                passed = True
                details = f"Independent verification PASSED: Synthetic session '{target_id}' is recorded in the active revocation registry."
            else:
                passed = False
                details = f"Independent verification FAILED: Synthetic session '{target_id}' was NOT found in the revocation registry."

        elif action == "lock_account":
            locked_accounts = demo_state.get("synthetic_locked_accounts", set())
            expected_state = {"account_locked": True, "target_account": target_id}
            is_locked = target_id in locked_accounts
            actual_state = {"account_locked": is_locked, "active_locked_accounts": list(locked_accounts)}

            if is_locked:
                passed = True
                details = f"Independent verification PASSED: Synthetic account '{target_id}' is recorded in the active account lock registry."
            else:
                passed = False
                details = f"Independent verification FAILED: Synthetic account '{target_id}' was NOT found in the account lock registry."

        elif action == "escalate_incident":
            escalated_incidents = demo_state.get("synthetic_escalated_incidents", set())
            expected_state = {"incident_escalated": True, "target_incident": incident_id}
            is_escalated = incident_id in escalated_incidents
            actual_state = {"incident_escalated": is_escalated, "escalated_set": list(escalated_incidents)}

            if is_escalated:
                passed = True
                details = f"Independent verification PASSED: Incident '{incident_id}' successfully transitioned to ESCALATED status."
            else:
                passed = False
                details = f"Independent verification FAILED: Incident '{incident_id}' missing from escalation registry."

        elif action == "mark_monitoring":
            monitored_incidents = demo_state.get("synthetic_monitored_incidents", set())
            expected_state = {"monitoring_active": True, "target_incident": incident_id}
            is_monitored = incident_id in monitored_incidents
            actual_state = {"monitoring_active": is_monitored, "monitored_set": list(monitored_incidents)}

            if is_monitored:
                passed = True
                details = f"Independent verification PASSED: Incident '{incident_id}' successfully marked for MONITORING without disruptive containment."
            else:
                passed = False
                details = f"Independent verification FAILED: Incident '{incident_id}' missing from monitoring registry."

        else:
            expected_state = {"action": action}
            actual_state = {"error": "unsupported_action"}
            passed = False
            details = f"Independent verification FAILED: Unsupported action '{action}' cannot be verified."

        return VerificationResult(
            verification_id=verification_id,
            action_id=action_request.action_id,
            incident_id=incident_id,
            target_id=target_id,
            passed=passed,
            checked_at=datetime.now(timezone.utc).isoformat(),
            expected_state=expected_state,
            actual_state=actual_state,
            details=details,
        )
