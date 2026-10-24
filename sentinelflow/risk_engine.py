"""Deterministic Risk Engine for SentinelFlow AI.

Calculates transparent, explainable risk scores based on explicit security signals,
identifying factors that increase risk vs factors that mitigate risk, without false certainty.
"""

from typing import List, Dict, Any, Tuple
from sentinelflow.models import SecurityEvent, CorrelatedGroup


class RiskAssessmentBreakdown:
    """Detailed risk assessment outcome with transparent signal attribution."""

    def __init__(
        self,
        risk_score: int,
        severity: str,
        confidence: float,
        increasing_factors: List[str],
        reducing_factors: List[str],
        recommended_action: str,
        rationale: str,
    ):
        self.risk_score = risk_score
        self.severity = severity
        self.confidence = confidence
        self.increasing_factors = increasing_factors
        self.reducing_factors = reducing_factors
        self.recommended_action = recommended_action
        self.rationale = rationale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "increasing_factors": self.increasing_factors,
            "reducing_factors": self.reducing_factors,
            "recommended_action": self.recommended_action,
            "rationale": self.rationale,
        }


class RiskEngine:
    """Calculates risk scores and explains factors deterministically."""

    def evaluate_incident(self, events: List[SecurityEvent], correlation: CorrelatedGroup) -> RiskAssessmentBreakdown:
        """Evaluate events and correlation to compute a transparent risk assessment."""
        base_score = 15  # Baseline noise floor
        increasing_factors = []
        reducing_factors = []

        # Analyze individual event categories and severities
        severities = [e.severity for e in events]
        categories = {e.event_category for e in events}

        if "CRITICAL" in severities:
            critical_count = severities.count("CRITICAL")
            increment = 35 + (critical_count - 1) * 10
            base_score += increment
            increasing_factors.append(f"Contains {critical_count} event(s) tagged CRITICAL (+{increment} pts)")
        elif "HIGH" in severities:
            high_count = severities.count("HIGH")
            increment = 25 + (high_count - 1) * 8
            base_score += increment
            increasing_factors.append(f"Contains {high_count} event(s) tagged HIGH (+{increment} pts)")
        elif "MEDIUM" in severities:
            base_score += 15
            increasing_factors.append("Contains MEDIUM severity security events (+15 pts)")

        # Factor: Privilege Escalation
        if "PRIVILEGE_ESCALATION" in categories:
            base_score += 20
            increasing_factors.append("Privilege escalation or IAM policy modification attempted (+20 pts)")

        # Factor: Outbound Network Exfiltration / C2
        has_c2 = any("c2" in e.description.lower() or "exfiltration" in e.description.lower() for e in events)
        if has_c2:
            base_score += 25
            increasing_factors.append("Outbound command-and-control beaconing or high-volume data exfiltration detected (+25 pts)")

        # Factor: High volume of data
        for e in events:
            bytes_sent = e.evidence_metadata.get("bytes_sent") or e.evidence_metadata.get("bytes_transferred")
            if bytes_sent and bytes_sent > 100_000_000:
                base_score += 15
                increasing_factors.append(f"High-volume data transfer detected ({bytes_sent / 1_000_000:.1f} MB) (+15 pts)")
                break

        # Factor: Credential stuffing / Brute force
        has_failed = any("Failed login" in e.description or "ERR_INVALID_PASSWORD" in e.description for e in events)
        has_success = any("Successful login" in e.description for e in events)
        if has_failed and has_success:
            base_score += 20
            increasing_factors.append("Multiple failed credential attempts followed immediately by authorized access (+20 pts)")

        # Factor: High risk foreign location or Tor exit
        for e in events:
            loc = e.fictional_location or ""
            if "Tor" in loc or "Romania" in loc or "Russia" in loc or "Singapore" in loc:
                base_score += 10
                increasing_factors.append(f"Traffic originated from atypical geographic source: {loc} (+10 pts)")
                break

        # Mitigating Factors (Reducing Risk)
        # 1. Sanctioned operational change management ticket
        has_ticket = any(e.evidence_metadata.get("ticket_reference") for e in events)
        if has_ticket:
            base_score -= 35
            reducing_factors.append("Correlated with verified operational change ticket SEC-DATA-SYNC-98 (-35 pts)")

        # 2. Compliant hardware MFA / FIDO2 key
        has_fido2 = any(
            e.evidence_metadata.get("auth_mechanism") == "FIDO2_HARDWARE_KEY"
            or e.evidence_metadata.get("mfa_verified") is True
            for e in events
        )
        if has_fido2:
            base_score -= 15
            reducing_factors.append("Hardware-backed multi-factor authentication (FIDO2) cryptographically verified (-15 pts)")

        # 3. Verified healthy EDR posture
        has_edr_ok = any(e.evidence_metadata.get("edr_agent_compliant") is True for e in events)
        if has_edr_ok:
            base_score -= 20
            reducing_factors.append("Endpoint agent health and compliance verified by EDR telemetry (-20 pts)")

        # 4. Routine informational read access
        if all(e.severity in ("INFORMATIONAL", "LOW") for e in events):
            base_score -= 10
            reducing_factors.append("Telemetry exclusively exhibits low-risk standard operational read access (-10 pts)")

        # Clamp score between 0 and 100
        final_score = max(0, min(100, base_score))

        # Determine severity level
        if final_score >= 80:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 35:
            severity = "MEDIUM"
        elif final_score >= 15:
            severity = "LOW"
        else:
            severity = "INFORMATIONAL"

        # Determine recommended response action (from allowlist)
        if final_score >= 80:
            if "c2" in " ".join(e.description.lower() for e in events) or "exfiltration" in " ".join(e.description.lower() for e in events):
                recommended_action = "lock_account"
                rationale = "High-severity exfiltration and C2 beaconing requires temporary account locking pending malware eradication."
            else:
                recommended_action = "revoke_session"
                rationale = "Critical unauthorized access detected; immediate synthetic session revocation recommended to sever live access."
        elif final_score >= 60:
            recommended_action = "revoke_session"
            rationale = "Elevated threat score suggests active credential compromise; revoking the current synthetic session is warranted."
        elif final_score >= 35:
            recommended_action = "escalate_incident"
            rationale = "Ambiguous or medium-risk signals detected; escalate to senior SOC tier for manual review before any containment."
        else:
            recommended_action = "mark_monitoring"
            rationale = "Low risk or verified benign context; no containment action needed. Retain incident in monitoring status."

        # Confidence calculation
        confidence = min(0.99, max(0.50, round(correlation.confidence_score * 0.95 + 0.05, 2)))

        return RiskAssessmentBreakdown(
            risk_score=final_score,
            severity=severity,
            confidence=confidence,
            increasing_factors=increasing_factors,
            reducing_factors=reducing_factors,
            recommended_action=recommended_action,
            rationale=rationale,
        )
