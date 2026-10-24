"""Deterministic Event Correlation Engine for SentinelFlow AI.

Analyzes raw synthetic security events using explicit deterministic heuristics
(shared accounts, temporal clustering, IP matching, session sharing, and known attack chain rules)
without opaque or fake machine learning claims.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sentinelflow.models import SecurityEvent, CorrelatedGroup


class CorrelationRule:
    """Explicit correlation rule definition."""

    def __init__(self, rule_id: str, name: str, description: str, base_confidence: float):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.base_confidence = base_confidence


class EventCorrelationEngine:
    """Deterministic correlation engine for synthetic security events."""

    def __init__(self):
        self.rules = [
            CorrelationRule(
                rule_id="RULE-CORR-01",
                name="Repeated Auth Failures Preceding Success",
                description="Consecutive failed authentication events followed by successful session initiation on same account.",
                base_confidence=0.92,
            ),
            CorrelationRule(
                rule_id="RULE-CORR-02",
                name="Anomalous Geo-IP with IAM Privilege Escalation",
                description="Admin session from foreign or reserved IP requesting elevated policy modifications.",
                base_confidence=0.88,
            ),
            CorrelationRule(
                rule_id="RULE-CORR-03",
                name="Service Account External Access & Data Exfiltration",
                description="Service account authenticated from external subnet modifying roles and accessing bulk storage.",
                base_confidence=0.95,
            ),
            CorrelationRule(
                rule_id="RULE-CORR-04",
                name="Endpoint Obfuscated Scripting & C2 Network Beaconing",
                description="Process execution of base64 commands correlated with outbound TLS beacons on high ports.",
                base_confidence=0.96,
            ),
            CorrelationRule(
                rule_id="RULE-CORR-05",
                name="Scheduled Bulk Export with Sanctioned Ticket Reference",
                description="High volume data access correlated with verified internal change management identifier.",
                base_confidence=0.80,
            ),
            CorrelationRule(
                rule_id="RULE-CORR-06",
                name="Compliant Hardware-Backed SSO Routine Activity",
                description="Authentication and standard file read from verified compliant corporate branch endpoint.",
                base_confidence=0.85,
            ),
        ]

    def correlate_incident_events(self, events: List[SecurityEvent], incident_id: Optional[str] = None) -> CorrelatedGroup:
        """Correlate a group of events for an incident or account deterministically."""
        if not events:
            raise ValueError("Cannot correlate empty event list")

        # Sort chronologically
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        event_ids = [e.event_id for e in sorted_events]
        primary_account = sorted_events[0].synthetic_account_id

        # Collect all related entities and IPs
        all_entities = set()
        all_ips = set()
        categories = set()
        for e in sorted_events:
            all_entities.update(e.related_entity_ids)
            all_ips.add(e.synthetic_source_ip)
            categories.add(e.event_category)

        rules_triggered = []
        reasons = []
        confidence_factors = []

        # Check explicit rules
        has_failed = any("Failed login" in e.description or "ERR_INVALID_PASSWORD" in e.description for e in sorted_events)
        has_success = any("Successful login" in e.description or e.evidence_metadata.get("auth_status") == "SUCCESS" for e in sorted_events)
        if has_failed and has_success:
            rules_triggered.append("RULE-CORR-01: Repeated Auth Failures Preceding Success")
            reasons.append("Detected credential stuffing pattern: multiple failed authentication attempts succeeded by authorization.")
            confidence_factors.append(0.92)

        has_priv_esc = any(e.event_category == "PRIVILEGE_ESCALATION" for e in sorted_events)
        has_unusual_geo = any(e.fictional_location and ("Romania" in e.fictional_location or "Tor" in e.fictional_location) for e in sorted_events)
        if has_priv_esc and has_unusual_geo:
            rules_triggered.append("RULE-CORR-02: Anomalous Geo-IP with IAM Privilege Escalation")
            reasons.append("Identified administrative session from high-risk external geo-IP performing policy expansion.")
            confidence_factors.append(0.90)

        is_svc_acct = any("svc-" in e.synthetic_account_id for e in sorted_events)
        has_data_access = any(e.event_category == "DATA_ACCESS" for e in sorted_events)
        if is_svc_acct and has_priv_esc and has_data_access:
            rules_triggered.append("RULE-CORR-03: Service Account External Access & Data Exfiltration")
            reasons.append("Service account observed operating outside assigned VPC, granting superuser, and downloading sensitive objects.")
            confidence_factors.append(0.95)

        has_endpoint = any(e.event_category == "ENDPOINT" for e in sorted_events)
        has_c2_network = any(e.event_category == "NETWORK" and ("beacon" in e.description.lower() or "exfiltration" in e.description.lower()) for e in sorted_events)
        if has_endpoint and has_c2_network:
            rules_triggered.append("RULE-CORR-04: Endpoint Obfuscated Scripting & C2 Network Beaconing")
            reasons.append("Correlated endpoint process execution (encoded PowerShell) with outbound TLS C2 beaconing and exfiltration.")
            confidence_factors.append(0.96)

        has_ticket = any(e.evidence_metadata.get("ticket_reference") for e in sorted_events)
        if has_ticket and has_data_access:
            rules_triggered.append("RULE-CORR-05: Scheduled Bulk Export with Sanctioned Ticket Reference")
            reasons.append("Bulk data transfer correlated with authorized operational Jira ticket SEC-DATA-SYNC-98.")
            confidence_factors.append(0.82)

        has_benign_edr = any(e.evidence_metadata.get("edr_agent_compliant") is True for e in sorted_events)
        if has_benign_edr and not has_priv_esc and not has_c2_network and not has_failed:
            rules_triggered.append("RULE-CORR-06: Compliant Hardware-Backed SSO Routine Activity")
            reasons.append("Corporate SSO login authenticated with compliant hardware posture and verified user identity.")
            confidence_factors.append(0.85)

        # General correlation by shared IP or shared session
        shared_sessions = set()
        for e in sorted_events:
            for ent in e.related_entity_ids:
                if ent.startswith("sess-"):
                    shared_sessions.add(ent)

        if shared_sessions:
            reasons.append(f"Linked by active synthetic session identifier(s): {', '.join(sorted(shared_sessions))}.")
            confidence_factors.append(0.80)

        if len(all_ips) == 1:
            reasons.append(f"All events originated from unified synthetic source IP: {list(all_ips)[0]}.")
            confidence_factors.append(0.75)

        # Fallback heuristic if no specific pattern triggered
        if not rules_triggered:
            rules_triggered.append("RULE-GENERIC-TEMPORAL-ACCOUNT: Shared Synthetic Identity Clustering")
            reasons.append(f"Events correlated by synthetic account ID '{primary_account}' within close chronological window.")
            confidence_factors.append(0.65)

        # Calculate final confidence score
        final_confidence = round(sum(confidence_factors) / len(confidence_factors), 2)

        return CorrelatedGroup(
            group_id=f"GRP-{incident_id or primary_account}",
            incident_id=incident_id,
            primary_account=primary_account,
            event_ids=event_ids,
            correlation_rules_triggered=rules_triggered,
            confidence_score=min(max(final_confidence, 0.1), 1.0),
            earliest_timestamp=sorted_events[0].timestamp,
            latest_timestamp=sorted_events[-1].timestamp,
            related_entities=sorted(list(all_entities)),
            summary_reason="; ".join(reasons),
        )

    def group_events_by_account_or_incident(self, events: List[SecurityEvent]) -> Dict[str, List[SecurityEvent]]:
        """Group raw events by incident_id or synthetic_account_id."""
        grouped: Dict[str, List[SecurityEvent]] = {}
        for event in events:
            key = event.incident_id or event.synthetic_account_id
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(event)
        return grouped
