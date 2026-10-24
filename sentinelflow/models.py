"""Pydantic data models for SentinelFlow AI with strict validation."""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator, model_validator

from sentinelflow.config import ALLOWED_ACTIONS, VALID_SEVERITIES, VALID_INCIDENT_STATUSES


class SecurityEvent(BaseModel):
    """Synthetic security event record."""
    event_id: str = Field(..., description="Unique event identifier (e.g. EVT-1001)")
    timestamp: str = Field(..., description="ISO 8601 formatted timestamp")
    event_category: str = Field(..., description="Category: AUTHENTICATION, NETWORK, DATA_ACCESS, PRIVILEGE_ESCALATION, ENDPOINT")
    synthetic_account_id: str = Field(..., description="Fictional account identifier")
    synthetic_source_ip: str = Field(..., description="Synthetic or reserved documentation IP address")
    fictional_location: Optional[str] = Field(default="Synthetic-Region-US", description="Fictional origin location")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    description: str = Field(..., description="Human-readable event description")
    incident_id: Optional[str] = Field(default=None, description="Associated synthetic incident identifier")
    related_entity_ids: List[str] = Field(default_factory=list, description="IDs of related entities, hosts, sessions, or resources")
    evidence_metadata: Dict[str, Any] = Field(default_factory=dict, description="Technical metadata (user_agent, bytes_transferred, etc.)")
    is_synthetic: bool = Field(default=True, description="Strictly synthetic demo flag")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {sorted(VALID_SEVERITIES)}")
        return v_upper

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("event_id cannot be empty")
        return v.strip()


class CorrelatedGroup(BaseModel):
    """Deterministic grouping of correlated synthetic events."""
    group_id: str
    incident_id: Optional[str] = None
    primary_account: str
    event_ids: List[str]
    correlation_rules_triggered: List[str]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    earliest_timestamp: str
    latest_timestamp: str
    related_entities: List[str] = Field(default_factory=list)
    summary_reason: str


class InvestigationFinding(BaseModel):
    """Structured AI or rule-based investigation outcome."""
    incident_summary: str = Field(..., description="Executive summary of the incident")
    risk_score: int = Field(..., ge=0, le=100, description="Calculated risk score from 0 to 100")
    severity: str = Field(..., description="Severity classification")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence level between 0.0 and 1.0")
    supporting_evidence_ids: List[str] = Field(..., min_length=1, description="List of validated event IDs supporting the finding")
    timeline_interpretation: str = Field(..., description="Chronological interpretation of the attack chain")
    likely_explanation: str = Field(..., description="Most probable explanation of the observed behavior")
    alternative_explanations: List[str] = Field(default_factory=list, description="Plausible benign or alternate explanations")
    uncertainties_and_limitations: str = Field(..., description="Caveats, data gaps, or ambiguities in the telemetry")
    recommended_next_steps: List[str] = Field(..., min_length=1, description="Analyst action checklist")
    proposed_action: Optional[str] = Field(default=None, description="Allowlisted simulated response action name")
    human_review_rationale: str = Field(..., description="Justification for why human confirmation is required")
    analysis_mode: str = Field(default="deterministic_rule_based", description="'gemini_ai' or 'deterministic_rule_based'")
    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {sorted(VALID_SEVERITIES)}")
        return v_upper

    @field_validator("proposed_action")
    @classmethod
    def validate_proposed_action(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "" or v.lower() == "none":
            return None
        v_clean = v.strip().lower()
        if v_clean not in ALLOWED_ACTIONS:
            raise ValueError(f"Action '{v}' is not in the strict allowlist: {sorted(ALLOWED_ACTIONS)}")
        return v_clean


class ResponseActionRequest(BaseModel):
    """Safe, human-in-the-loop simulated containment action."""
    action_id: str
    incident_id: str
    action_name: str
    target_type: str = Field(..., description="Target category: account, session, incident")
    target_id: str = Field(..., description="Target identifier (e.g. demo-admin-01, sess-9021)")
    reasoning: str
    supporting_evidence_ids: List[str]
    status: str = Field(default="proposed", description="proposed, awaiting_approval, approved, rejected, executed_simulation, verified, failed_verification, failed_execution")
    analyst_id: Optional[str] = None
    approved_at: Optional[str] = None
    executed_at: Optional[str] = None
    simulation_mode: bool = True

    @field_validator("action_name")
    @classmethod
    def validate_action_name(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if v_clean not in ALLOWED_ACTIONS:
            raise ValueError(f"Action '{v}' is not in the strict allowlist: {sorted(ALLOWED_ACTIONS)}")
        return v_clean


class VerificationResult(BaseModel):
    """Independent verification result confirming simulated state transition."""
    verification_id: str
    action_id: str
    incident_id: str
    target_id: str
    passed: bool
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expected_state: Dict[str, Any]
    actual_state: Dict[str, Any]
    details: str


class AuditEntry(BaseModel):
    """Append-only audit record for application lifecycle and analyst actions."""
    entry_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = Field(..., description="INVESTIGATION_STARTED, EVENTS_CORRELATED, FINDING_GENERATED, RESPONSE_PROPOSED, ACTION_APPROVED, ACTION_REJECTED, SIMULATION_EXECUTED, VERIFICATION_PASSED, VERIFICATION_FAILED, DEMO_RESET")
    incident_id: Optional[str] = None
    action_id: Optional[str] = None
    status: str
    actor: str = Field(default="analyst", description="analyst, system, gemini_engine, response_engine, verification_engine")
    details: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Incident entity representing an operational security investigation."""
    incident_id: str
    title: str
    description: str
    scenario_id: str
    created_at: str
    severity: str
    status: str = Field(default="OPEN")
    primary_account: str
    event_ids: List[str] = Field(default_factory=list)
    correlated_entities: List[str] = Field(default_factory=list)
    finding: Optional[InvestigationFinding] = None
    proposed_action: Optional[ResponseActionRequest] = None
    verification_result: Optional[VerificationResult] = None
    is_synthetic: bool = True

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'. Must be one of: {sorted(VALID_SEVERITIES)}")
        return v_upper

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        v_upper = v.upper()
        if v_upper not in VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid status '{v}'. Must be one of: {sorted(VALID_INCIDENT_STATUSES)}")
        return v_upper
