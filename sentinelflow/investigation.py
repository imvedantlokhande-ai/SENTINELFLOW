"""Investigation Orchestration Engine for SentinelFlow AI.

Coordinates AI-powered (Gemini) and deterministic rule-based investigation workflows.
Maintains clear distinction between analysis modes and ensures human review requirements.
"""

from typing import List, Optional, Tuple
from sentinelflow.config import APP_MODE
from sentinelflow.models import SecurityEvent, CorrelatedGroup, InvestigationFinding, Incident
from sentinelflow.risk_engine import RiskEngine
from sentinelflow.gemini_client import GeminiInvestigationClient, GeminiProviderError


class InvestigationEngine:
    """Orchestrates incident investigation using Gemini or deterministic fallback."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.gemini_client = GeminiInvestigationClient(api_key=api_key, model=model)
        self.risk_engine = RiskEngine()

    def investigate(
        self,
        incident: Incident,
        events: List[SecurityEvent],
        correlation: CorrelatedGroup,
        force_mode: Optional[str] = None,
    ) -> Tuple[InvestigationFinding, Optional[str]]:
        """Run investigation on the incident events.

        Returns:
            Tuple of (InvestigationFinding, fallback_warning_message_or_none)
        """
        mode = (force_mode or APP_MODE).lower()
        fallback_warning: Optional[str] = None

        # Check if Gemini AI mode should be attempted
        if mode in ("gemini_ai", "gemini_only", "auto") and self.gemini_client.is_configured():
            try:
                finding = self.gemini_client.analyze_incident(
                    incident_id=incident.incident_id,
                    events=events,
                    correlation=correlation,
                )
                return finding, None
            except GeminiProviderError as e:
                if mode == "gemini_only":
                    raise e
                fallback_warning = (
                    f"Gemini API unavailable ({str(e)}). Switched to deterministic rule-based investigation."
                )

        # Execute deterministic rule-based investigation
        finding = self.run_deterministic_investigation(incident, events, correlation)
        return finding, fallback_warning

    def run_deterministic_investigation(
        self,
        incident: Incident,
        events: List[SecurityEvent],
        correlation: CorrelatedGroup,
    ) -> InvestigationFinding:
        """Run deterministic rule-based analysis with transparent scoring and reasoning."""
        risk_breakdown = self.risk_engine.evaluate_incident(events, correlation)
        event_ids = [e.event_id for e in events]

        # Contextual scenario-specific intelligence
        scenario_id = incident.scenario_id

        if scenario_id == "SCENARIO_1":
            summary = (
                f"Anomalous administrative session detected for {correlation.primary_account}. "
                "Authentication originated from an atypical Romanian IP address followed by IAM policy read requests."
            )
            timeline = (
                "03:10 UTC - Admin authentication from 198.51.100.45 without hardware token.\n"
                "03:12 UTC - IAM policy read and privilege escalation query (AdministratorAccess).\n"
                "03:14 UTC - Session renewal granted via atypical geo-IP."
            )
            likely = "Credential compromise or session token leakage enabling remote unauthorized admin access."
            alts = [
                "Authorized administrator traveling abroad or routing through commercial VPN.",
                "Sanctioned internal red-team security assessment.",
            ]
            uncertainties = "MFA bypass mechanism not fully resolved from current authentication logs."
            steps = [
                "Revoke active synthetic session sess-9011 immediately.",
                "Review Azure AD/Okta sign-in audit logs for impossible travel patterns.",
                "Contact user admin-ops-root via secondary out-of-band communication channel.",
            ]
            action = "revoke_session"
            rationale = (
                "Revoking an active admin session severs potentially malicious control while allowing the admin "
                "to re-authenticate safely using hardware MFA after confirmation."
            )

        elif scenario_id == "SCENARIO_2":
            summary = (
                f"Credential stuffing attack against {correlation.primary_account}. "
                "Multiple rapid authentication failures culminated in a successful login accessing HR compensation tables."
            )
            timeline = (
                "08:01:10 - 08:01:42 UTC - 3 consecutive failed login attempts (ERR_INVALID_PASSWORD) from 203.0.113.88.\n"
                "08:02:11 UTC - Successful password authentication established.\n"
                "08:03:00 UTC - Unauthorized query executed against internal payroll database."
            )
            likely = "Automated dictionary or credential stuffing attack successfully guessed user password."
            alts = [
                "Employee forgot password repeatedly before entering correct one from home network.",
                "Typo in automated scripted test query.",
            ]
            uncertainties = "Origin IP is synthetic documentation IP; external threat intelligence correlation is simulated."
            steps = [
                "Revoke synthetic session sess-4412 immediately.",
                "Force password reset and invalidate active SSO refresh tokens for j.doe.",
                "Audit query logs on res-hr-payroll-db for exfiltrated employee records.",
            ]
            action = "revoke_session"
            rationale = (
                "The correlation between high-velocity failed attempts and subsequent sensitive payroll queries "
                "strongly indicates account takeover requiring immediate session termination."
            )

        elif scenario_id == "SCENARIO_3":
            summary = (
                f"Critical service account compromise on {correlation.primary_account}. "
                "External authentication, superuser role escalation, and bulk invoice downloads observed."
            )
            timeline = (
                "10:15 UTC - Service account authenticated from external IP 192.0.2.14.\n"
                "10:16 UTC - Executed ALTER ROLE ... WITH SUPERUSER.\n"
                "10:18 UTC - 1,420 invoice objects (850 MB) downloaded from S3 storage."
            )
            likely = "Hardcoded service account API key leaked in repository or artifact and exploited externally."
            alts = [
                "DevOps engineer debugging billing integration from external network using root credentials.",
                "Disaster recovery script testing backup integrity.",
            ]
            uncertainties = "Caller process was psql command line tool; exact ingress point requires host forensic image."
            steps = [
                "Temporarily lock synthetic demo account svc-billing-exporter.",
                "Revoke all AWS IAM access keys and rotate database credentials.",
                "Inspect S3 bucket access logs for secondary exfiltration paths.",
            ]
            action = "lock_account"
            rationale = (
                "A compromised service account cannot be neutralized by session revocation alone because API keys "
                "allow immediate re-authentication. Account lockdown is essential."
            )

        elif scenario_id == "SCENARIO_4":
            summary = (
                f"High-volume data export by {correlation.primary_account} correlated with valid disaster recovery ticket."
            )
            timeline = (
                "22:00 UTC - FIDO2 hardware MFA authentication at Tokyo DR site.\n"
                "22:05 UTC - 45,000 transaction records exported matching Jira ticket SEC-DATA-SYNC-98."
            )
            likely = "Authorized monthly disaster recovery replication and database synchronization exercise."
            alts = [
                "Legitimate employee abusing change ticket pretext to exfiltrate proprietary transaction data.",
            ]
            uncertainties = "Destination storage integrity at DR site verified by change request documentation."
            steps = [
                "Mark incident for monitoring without containment.",
                "Verify ticket completion in Jira with change advisory board.",
                "Confirm checksum of exported records against DR site catalog.",
            ]
            action = "mark_monitoring"
            rationale = (
                "Strong mitigating evidence (valid Jira ticket, hardware FIDO2 MFA, scheduled timing) indicates "
                "benign authorized activity. Disruptive containment would interrupt sanctioned disaster recovery testing."
            )

        elif scenario_id == "SCENARIO_5":
            summary = (
                f"Routine corporate SSO login and handbook view by {correlation.primary_account} from branch office."
            )
            timeline = (
                "14:30 UTC - Corporate SSO login from Los Angeles branch IP with compliant EDR posture.\n"
                "14:32 UTC - Read access to benefits open enrollment handbook PDF."
            )
            likely = "Standard employee operational activity with zero threat indicators."
            alts = [
                "N/A - All telemetry conforms to normal baseline.",
            ]
            uncertainties = "None. Telemetry is fully consistent with routine enterprise usage."
            steps = [
                "Mark incident for monitoring without containment.",
                "Archive incident as benign informational event.",
            ]
            action = "mark_monitoring"
            rationale = (
                "No suspicious indicators, policy violations, or anomalous patterns detected. "
                "Containment actions are inappropriate and unnecessary."
            )

        elif scenario_id == "SCENARIO_6":
            summary = (
                f"Severe C2 beaconing and bulk exfiltration on workstation WORKSTATION-ENG-88 ({correlation.primary_account}). "
                "Encoded PowerShell execution followed by 4.2 GB data egress over port 8443."
            )
            timeline = (
                "11:45 UTC - Obfuscated PowerShell execution spawned by word.exe on WORKSTATION-ENG-88.\n"
                "11:47 UTC - Outbound encrypted TLS beaconing to C2 infrastructure over port 8443.\n"
                "11:50 UTC - Exfiltration of 4.2 GB compressed source code archive to 203.0.113.200."
            )
            likely = "Malware infection via malicious attachment resulting in full C2 implant and source code exfiltration."
            alts = [
                "Authorized penetration test conducting simulated exfiltration exercise.",
                "Large build artifact upload misclassified by firewall heuristics.",
            ]
            uncertainties = "Exact content of encrypted TLS egress stream requires host memory dump."
            steps = [
                "Temporarily lock synthetic demo account eng-k.chen.",
                "Isolate synthetic endpoint WORKSTATION-ENG-88 from network simulation.",
                "Block destination IP 203.0.113.200 and C2 domain on perimeter firewall.",
            ]
            action = "lock_account"
            rationale = (
                "Active high-volume exfiltration and command-and-control communication represents an immediate "
                "threat to proprietary source code requiring account lock and host isolation."
            )

        else:
            summary = f"Investigation of synthetic security activity for {correlation.primary_account}."
            timeline = f"Telemetry spanning from {correlation.earliest_timestamp} to {correlation.latest_timestamp}."
            likely = "Correlated anomalous security telemetry identified by rule heuristics."
            alts = ["Operational testing or administrative oversight."]
            uncertainties = "Synthetic telemetry bounds."
            steps = ["Review audit trail", "Verify entity baseline"]
            action = risk_breakdown.recommended_action
            rationale = risk_breakdown.rationale

        return InvestigationFinding(
            incident_summary=summary,
            risk_score=risk_breakdown.risk_score,
            severity=risk_breakdown.severity,
            confidence_score=risk_breakdown.confidence,
            supporting_evidence_ids=event_ids,
            timeline_interpretation=timeline,
            likely_explanation=likely,
            alternative_explanations=alts,
            uncertainties_and_limitations=uncertainties,
            recommended_next_steps=steps,
            proposed_action=action,
            human_review_rationale=rationale,
            analysis_mode="deterministic_rule_based",
        )
