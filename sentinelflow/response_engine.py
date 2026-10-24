"""Safe Human-in-the-Loop Simulated Response Engine for SentinelFlow AI.

Enforces strict action allowlists, human authorization gates, target validation,
duplicate execution prevention, and simulation boundary enforcement.
NEVER touches real systems or runs arbitrary system commands.
"""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sentinelflow.config import ALLOWED_ACTIONS, ACTION_LABELS
from sentinelflow.models import ResponseActionRequest, Incident
from sentinelflow.auth import UserSession
from sentinelflow.authorization import (
    enforce_permission,
    PERM_APPROVE_RESPONSE_TIER1,
    PERM_APPROVE_RESPONSE_TIER2,
    PERM_EXECUTE_SIMULATION,
    PERM_PROPOSE_RESPONSE,
    AuthorizationError,
)


class ResponseExecutionError(Exception):
    """Exception raised when simulated action execution fails or is rejected."""
    pass


class ResponseEngine:
    """Safely manages and executes simulated incident containment actions."""

    def __init__(self):
        self.allowed_actions = ALLOWED_ACTIONS

    def propose_action(
        self,
        incident: Incident,
        action_name: str,
        target_type: str,
        target_id: str,
        reasoning: str,
        supporting_evidence_ids: List[str],
    ) -> ResponseActionRequest:
        """Create a formal proposed response action awaiting analyst review."""
        action_clean = action_name.strip().lower()
        if action_clean not in self.allowed_actions:
            raise ResponseExecutionError(
                f"Action '{action_name}' is not permitted. Strictly allowed: {sorted(self.allowed_actions)}"
            )

        if not target_id or not target_id.strip():
            raise ResponseExecutionError("Target identifier cannot be empty.")

        target_clean = target_id.strip()
        valid_targets = set(incident.correlated_entities) | {incident.primary_account, incident.incident_id}
        if target_clean not in valid_targets:
            raise ResponseExecutionError(
                f"Security Validation Blocked: Target '{target_clean}' does not belong to incident '{incident.incident_id}'. Allowed targets: {sorted(list(valid_targets))}"
            )

        action_id = f"ACT-{incident.incident_id}-{action_clean}"
        return ResponseActionRequest(
            action_id=action_id,
            incident_id=incident.incident_id,
            action_name=action_clean,
            target_type=target_type,
            target_id=target_clean,
            reasoning=reasoning,
            supporting_evidence_ids=supporting_evidence_ids,
            status="awaiting_approval",
            simulation_mode=True,
        )

    def approve_action(
        self,
        action_request: ResponseActionRequest,
        analyst_id: str = "soc_analyst_01",
        session: Optional[UserSession] = None,
        incident: Optional[Incident] = None,
    ) -> ResponseActionRequest:
        """Mark an action as explicitly approved by an authorized human analyst."""
        if session is not None:
            enforce_permission(
                session=session,
                permission=PERM_APPROVE_RESPONSE_TIER1,
                incident=incident,
                target_id=action_request.target_id,
                action_request=action_request,
            )
            analyst_id = session.email

        if action_request.status not in ("proposed", "awaiting_approval"):
            raise ResponseExecutionError(
                f"Cannot approve action in status '{action_request.status}'."
            )

        updated = action_request.model_copy()
        updated.status = "approved"
        updated.analyst_id = analyst_id
        updated.approved_at = datetime.now(timezone.utc).isoformat()
        return updated

    def reject_action(
        self,
        action_request: ResponseActionRequest,
        analyst_id: str = "soc_analyst_01",
        rejection_reason: str = "Analyst rejected proposed containment.",
        session: Optional[UserSession] = None,
    ) -> ResponseActionRequest:
        """Mark an action as rejected by the analyst, preventing execution."""
        if session is not None:
            enforce_permission(
                session=session,
                permission=PERM_PROPOSE_RESPONSE,
                action_request=action_request,
            )
            analyst_id = session.email

        if action_request.status not in ("proposed", "awaiting_approval"):
            raise ResponseExecutionError(
                f"Cannot reject action in status '{action_request.status}'."
            )

        updated = action_request.model_copy()
        updated.status = "rejected"
        updated.analyst_id = analyst_id
        updated.reasoning = f"{updated.reasoning} | REJECTED: {rejection_reason}"
        return updated

    def execute_simulated_action(
        self,
        action_request: ResponseActionRequest,
        demo_state: Dict[str, Any],
        session: Optional[UserSession] = None,
        incident: Optional[Incident] = None,
    ) -> Tuple[ResponseActionRequest, Dict[str, Any]]:
        """Execute approved simulated containment against synthetic demo state only.

        Raises ResponseExecutionError or AuthorizationError if:
        - User lacks execution permission
        - Action is not approved
        - Action is already executed (duplicate execution prevention)
        - Action is not in allowlist
        - Target is invalid
        """
        # 0. Check server-side authorization if session provided
        if session is not None:
            enforce_permission(
                session=session,
                permission=PERM_EXECUTE_SIMULATION,
                incident=incident,
                target_id=action_request.target_id,
                action_request=action_request,
            )

        # 1. Reject duplicate execution
        if action_request.executed_at is not None or action_request.status in ("executed_simulation", "verified"):
            raise ResponseExecutionError(
                f"Duplicate execution blocked: Action {action_request.action_id} was already executed at {action_request.executed_at}."
            )

        # 2. Require approval
        if action_request.status != "approved":
            raise ResponseExecutionError(
                f"Action execution blocked: Action must be in 'approved' status, but is '{action_request.status}'."
            )

        # 3. Validate action name in allowlist
        if action_request.action_name not in self.allowed_actions:
            raise ResponseExecutionError(
                f"Unsupported action '{action_request.action_name}'."
            )

        action = action_request.action_name
        target_id = action_request.target_id
        incident_id = action_request.incident_id

        # Update synthetic state dictionary based on action
        # Initialize synthetic registries if not present
        if "synthetic_revoked_sessions" not in demo_state:
            demo_state["synthetic_revoked_sessions"] = set()
        if "synthetic_locked_accounts" not in demo_state:
            demo_state["synthetic_locked_accounts"] = set()
        if "synthetic_escalated_incidents" not in demo_state:
            demo_state["synthetic_escalated_incidents"] = set()
        if "synthetic_monitored_incidents" not in demo_state:
            demo_state["synthetic_monitored_incidents"] = set()

        if action == "revoke_session":
            demo_state["synthetic_revoked_sessions"].add(target_id)

        elif action == "lock_account":
            demo_state["synthetic_locked_accounts"].add(target_id)

        elif action == "escalate_incident":
            demo_state["synthetic_escalated_incidents"].add(incident_id)

        elif action == "mark_monitoring":
            demo_state["synthetic_monitored_incidents"].add(incident_id)

        # Update incident status in demo state incidents list if present
        if "incidents" in demo_state:
            for inc in demo_state["incidents"]:
                if inc.incident_id == incident_id:
                    if action in ("revoke_session", "lock_account"):
                        inc.status = "RESOLVED"
                    elif action == "escalate_incident":
                        inc.status = "ESCALATED"
                    elif action == "mark_monitoring":
                        inc.status = "MONITORING"
                    break

        updated_request = action_request.model_copy()
        updated_request.status = "executed_simulation"
        updated_request.executed_at = datetime.now(timezone.utc).isoformat()

        return updated_request, demo_state
