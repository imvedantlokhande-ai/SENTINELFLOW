"""Seeded synthetic security scenarios and telemetry for SentinelFlow AI.

ALL DATA IS EXPLICITLY SYNTHETIC AND FICTIONAL FOR DEMONSTRATION PURPOSES.
Uses RFC 5737 documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""

from typing import List, Dict, Any
from sentinelflow.models import SecurityEvent, Incident, ResponseActionRequest

# Fictional Attack Geographic Markers for the Global Threat Visualization Map
SYNTHETIC_GEO_POINTS = [
    {
        "id": "GEO-01",
        "origin_name": "Synthetic-Origin-Eastern-Europe",
        "lat": 44.4268,
        "lon": 26.1025,
        "target_name": "SOC-Primary-US-East",
        "target_lat": 38.9072,
        "target_lon": -77.0369,
        "attack_vector": "Brute Force / Credential Stuffing",
        "category": "AUTHENTICATION",
        "severity": "HIGH",
        "source_ip": "198.51.100.45",
        "intensity": 78,
    },
    {
        "id": "GEO-02",
        "origin_name": "Synthetic-Origin-North-Asia",
        "lat": 59.9343,
        "lon": 30.3351,
        "target_name": "SOC-Primary-US-East",
        "target_lat": 38.9072,
        "target_lon": -77.0369,
        "attack_vector": "Distributed Password Spraying",
        "category": "AUTHENTICATION",
        "severity": "HIGH",
        "source_ip": "203.0.113.88",
        "intensity": 85,
    },
    {
        "id": "GEO-03",
        "origin_name": "Synthetic-Origin-Tor-Exit-Node",
        "lat": 52.5200,
        "lon": 13.4050,
        "target_name": "SOC-Billing-Cluster",
        "target_lat": 37.7749,
        "target_lon": -122.4194,
        "attack_vector": "Privilege Escalation / API Abuse",
        "category": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "source_ip": "192.0.2.14",
        "intensity": 92,
    },
    {
        "id": "GEO-04",
        "origin_name": "Synthetic-Origin-Data-Center-Offsite",
        "lat": 35.6762,
        "lon": 139.6503,
        "target_name": "Cloud-Data-Warehouse",
        "target_lat": 47.6062,
        "target_lon": -122.3321,
        "attack_vector": "High-Volume Bulk Data Retrieval",
        "category": "DATA_ACCESS",
        "severity": "MEDIUM",
        "source_ip": "192.0.2.55",
        "intensity": 45,
    },
    {
        "id": "GEO-05",
        "origin_name": "Synthetic-Origin-Regional-Branch",
        "lat": 34.0522,
        "lon": -118.2437,
        "target_name": "Corporate-VPN-Gateway",
        "target_lat": 38.9072,
        "target_lon": -77.0369,
        "attack_vector": "Sanctioned Corporate VPN Session",
        "category": "AUTHENTICATION",
        "severity": "LOW",
        "source_ip": "198.51.100.12",
        "intensity": 15,
    },
    {
        "id": "GEO-06",
        "origin_name": "Synthetic-Origin-Command-Control",
        "lat": 1.3521,
        "lon": 103.8198,
        "target_name": "Workstation-Eng-88",
        "target_lat": 40.7128,
        "target_lon": -74.0060,
        "attack_vector": "Encrypted C2 Channel & Data Exfiltration",
        "category": "NETWORK",
        "severity": "CRITICAL",
        "source_ip": "203.0.113.200",
        "intensity": 96,
    },
]

# Synthetic Infrastructure Status Cards Data
SYNTHETIC_INFRASTRUCTURE = {
    "endpoints": {
        "status": "Monitored (Simulation)",
        "healthy_count": 142,
        "at_risk_count": 2,
        "isolated_count": 0,
        "agent_version": "v4.12-sim",
        "total": 144,
        "last_heartbeat": "Just now",
    },
    "cloud_systems": {
        "status": "Healthy (Simulation)",
        "active_tenants": 4,
        "anomalous_roles": 1,
        "s3_guardrails_active": True,
        "api_monitoring": "Active",
        "last_sync": "12s ago",
    },
    "network": {
        "status": "Active (Simulation)",
        "inbound_pps": "24,800 pkt/s",
        "suspicious_flows": 3,
        "dns_tunneling_alerts": 1,
        "egress_monitoring": "Strict",
        "last_sync": "5s ago",
    },
}

# Scenario 1: Suspicious administrator login from unusual location
SCENARIO_1_EVENTS = [
    SecurityEvent(
        event_id="EVT-101",
        timestamp="2026-10-24T03:10:15Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="admin-ops-root",
        synthetic_source_ip="198.51.100.45",
        fictional_location="Bucharest, Romania",
        severity="HIGH",
        description="Admin authentication attempt initiated from atypical geo-IP without registered hardware token.",
        incident_id="INC-2026-001",
        related_entity_ids=["sess-9011", "host-adm-portal"],
        evidence_metadata={"user_agent": "Python-urllib/3.11", "mfa_type": "SMS_FALLBACK", "port": 443},
    ),
    SecurityEvent(
        event_id="EVT-102",
        timestamp="2026-10-24T03:12:04Z",
        event_category="PRIVILEGE_ESCALATION",
        synthetic_account_id="admin-ops-root",
        synthetic_source_ip="198.51.100.45",
        fictional_location="Bucharest, Romania",
        severity="CRITICAL",
        description="Session requested IAM policy read and elevated permissions outside normal maintenance window.",
        incident_id="INC-2026-001",
        related_entity_ids=["sess-9011", "role-global-sec-admin"],
        evidence_metadata={"api_call": "iam:GetPolicyVersion", "auth_status": "GRANTED", "policy": "AdministratorAccess"},
    ),
    SecurityEvent(
        event_id="EVT-103",
        timestamp="2026-10-24T03:14:50Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="admin-ops-root",
        synthetic_source_ip="198.51.100.45",
        fictional_location="Bucharest, Romania",
        severity="HIGH",
        description="Session renewal granted for admin console via anomalous IP address.",
        incident_id="INC-2026-001",
        related_entity_ids=["sess-9011"],
        evidence_metadata={"session_duration": 3600, "token_age_sec": 180},
    ),
]

# Scenario 2: Repeated failed logins followed by successful login (Brute Force)
SCENARIO_2_EVENTS = [
    SecurityEvent(
        event_id="EVT-201",
        timestamp="2026-10-24T08:01:10Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="j.doe@sentinelflow.internal",
        synthetic_source_ip="203.0.113.88",
        fictional_location="St. Petersburg, Russia",
        severity="MEDIUM",
        description="Failed login attempt: ERR_INVALID_PASSWORD for user j.doe.",
        incident_id="INC-2026-002",
        related_entity_ids=["auth-gateway-01"],
        evidence_metadata={"attempt_num": 1, "client": "curl/8.1.2"},
    ),
    SecurityEvent(
        event_id="EVT-202",
        timestamp="2026-10-24T08:01:25Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="j.doe@sentinelflow.internal",
        synthetic_source_ip="203.0.113.88",
        fictional_location="St. Petersburg, Russia",
        severity="MEDIUM",
        description="Failed login attempt: ERR_INVALID_PASSWORD for user j.doe.",
        incident_id="INC-2026-002",
        related_entity_ids=["auth-gateway-01"],
        evidence_metadata={"attempt_num": 2, "client": "curl/8.1.2"},
    ),
    SecurityEvent(
        event_id="EVT-203",
        timestamp="2026-10-24T08:01:42Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="j.doe@sentinelflow.internal",
        synthetic_source_ip="203.0.113.88",
        fictional_location="St. Petersburg, Russia",
        severity="MEDIUM",
        description="Failed login attempt: ERR_INVALID_PASSWORD for user j.doe.",
        incident_id="INC-2026-002",
        related_entity_ids=["auth-gateway-01"],
        evidence_metadata={"attempt_num": 3, "client": "curl/8.1.2"},
    ),
    SecurityEvent(
        event_id="EVT-204",
        timestamp="2026-10-24T08:02:11Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="j.doe@sentinelflow.internal",
        synthetic_source_ip="203.0.113.88",
        fictional_location="St. Petersburg, Russia",
        severity="HIGH",
        description="Successful login authenticated immediately following repeated failed credential attempts.",
        incident_id="INC-2026-002",
        related_entity_ids=["sess-4412", "auth-gateway-01"],
        evidence_metadata={"attempt_num": 4, "auth_status": "SUCCESS", "mfa_bypassed": False},
    ),
    SecurityEvent(
        event_id="EVT-205",
        timestamp="2026-10-24T08:03:00Z",
        event_category="DATA_ACCESS",
        synthetic_account_id="j.doe@sentinelflow.internal",
        synthetic_source_ip="203.0.113.88",
        fictional_location="St. Petersburg, Russia",
        severity="HIGH",
        description="Newly authenticated session initiated query on internal HR payroll directory.",
        incident_id="INC-2026-002",
        related_entity_ids=["sess-4412", "res-hr-payroll-db"],
        evidence_metadata={"query": "SELECT * FROM employees_comp LIMIT 500", "rows_returned": 500},
    ),
]

# Scenario 3: Multiple related events suggesting potential account compromise
SCENARIO_3_EVENTS = [
    SecurityEvent(
        event_id="EVT-301",
        timestamp="2026-10-24T10:15:00Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="svc-billing-exporter",
        synthetic_source_ip="192.0.2.14",
        fictional_location="Berlin, Germany (Tor Exit)",
        severity="HIGH",
        description="Service account authenticated from an external non-datacenter IP address.",
        incident_id="INC-2026-003",
        related_entity_ids=["sess-srv-771"],
        evidence_metadata={"expected_subnet": "10.100.0.0/16", "actual_ip": "192.0.2.14"},
    ),
    SecurityEvent(
        event_id="EVT-302",
        timestamp="2026-10-24T10:16:30Z",
        event_category="PRIVILEGE_ESCALATION",
        synthetic_account_id="svc-billing-exporter",
        synthetic_source_ip="192.0.2.14",
        fictional_location="Berlin, Germany (Tor Exit)",
        severity="CRITICAL",
        description="Service account executed unauthorized role modification query: GRANT admin_role.",
        incident_id="INC-2026-003",
        related_entity_ids=["sess-srv-771", "role-superadmin"],
        evidence_metadata={"command": "ALTER ROLE svc-billing-exporter WITH SUPERUSER", "caller": "psql"},
    ),
    SecurityEvent(
        event_id="EVT-303",
        timestamp="2026-10-24T10:18:10Z",
        event_category="DATA_ACCESS",
        synthetic_account_id="svc-billing-exporter",
        synthetic_source_ip="192.0.2.14",
        fictional_location="Berlin, Germany (Tor Exit)",
        severity="CRITICAL",
        description="Bulk download of customer financial invoices from encrypted S3 storage archive.",
        incident_id="INC-2026-003",
        related_entity_ids=["sess-srv-771", "s3-finance-invoices-2026"],
        evidence_metadata={"files_downloaded": 1420, "bytes_transferred": 850000000},
    ),
]

# Scenario 4: Suspicious data access with plausible benign explanation
SCENARIO_4_EVENTS = [
    SecurityEvent(
        event_id="EVT-401",
        timestamp="2026-10-24T22:00:15Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="analyst-t.smith",
        synthetic_source_ip="192.0.2.55",
        fictional_location="Tokyo, Japan (Disaster Recovery Site)",
        severity="LOW",
        description="Data analyst authenticated to offsite backup replication cluster.",
        incident_id="INC-2026-004",
        related_entity_ids=["sess-dr-201"],
        evidence_metadata={"mfa_verified": True, "auth_mechanism": "FIDO2_HARDWARE_KEY"},
    ),
    SecurityEvent(
        event_id="EVT-402",
        timestamp="2026-10-24T22:05:00Z",
        event_category="DATA_ACCESS",
        synthetic_account_id="analyst-t.smith",
        synthetic_source_ip="192.0.2.55",
        fictional_location="Tokyo, Japan (Disaster Recovery Site)",
        severity="MEDIUM",
        description="High volume export of 45,000 transaction records triggered threshold alert.",
        incident_id="INC-2026-004",
        related_entity_ids=["sess-dr-201", "table-tx-archive", "jira-ticket-SEC-DATA-SYNC-98"],
        evidence_metadata={
            "ticket_reference": "SEC-DATA-SYNC-98",
            "justification": "Sanctioned monthly disaster recovery backup test",
            "records_exported": 45000,
        },
    ),
]

# Scenario 5: Benign event that should not trigger containment
SCENARIO_5_EVENTS = [
    SecurityEvent(
        event_id="EVT-501",
        timestamp="2026-10-24T14:30:00Z",
        event_category="AUTHENTICATION",
        synthetic_account_id="hr-m.garcia",
        synthetic_source_ip="198.51.100.12",
        fictional_location="Los Angeles, USA (Corporate Branch)",
        severity="INFORMATIONAL",
        description="Routine corporate SSO login via authorized branch office IP with compliant endpoint health posture.",
        incident_id="INC-2026-005",
        related_entity_ids=["sess-hr-990", "host-laptop-garcia"],
        evidence_metadata={"edr_agent_compliant": True, "os_version": "Win11-Enterprise-Secured", "mfa": "OK"},
    ),
    SecurityEvent(
        event_id="EVT-502",
        timestamp="2026-10-24T14:32:10Z",
        event_category="DATA_ACCESS",
        synthetic_account_id="hr-m.garcia",
        synthetic_source_ip="198.51.100.12",
        fictional_location="Los Angeles, USA (Corporate Branch)",
        severity="INFORMATIONAL",
        description="Standard view query on quarterly benefits open enrollment handbook.",
        incident_id="INC-2026-005",
        related_entity_ids=["sess-hr-990", "res-handbook-pdf"],
        evidence_metadata={"document": "benefits-2026.pdf", "action": "READ"},
    ),
]

# Scenario 6: High-risk incident requiring analyst review (Exfiltration & C2)
SCENARIO_6_EVENTS = [
    SecurityEvent(
        event_id="EVT-601",
        timestamp="2026-10-24T11:45:12Z",
        event_category="ENDPOINT",
        synthetic_account_id="eng-k.chen",
        synthetic_source_ip="203.0.113.200",
        fictional_location="Singapore",
        severity="HIGH",
        description="Encoded base64 PowerShell invocation spawned by untrusted parent process on workstation WORKSTATION-ENG-88.",
        incident_id="INC-2026-006",
        related_entity_ids=["host-workstation-88", "proc-powershell-812"],
        evidence_metadata={"command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAag...", "parent": "word.exe"},
    ),
    SecurityEvent(
        event_id="EVT-602",
        timestamp="2026-10-24T11:47:30Z",
        event_category="NETWORK",
        synthetic_account_id="eng-k.chen",
        synthetic_source_ip="203.0.113.200",
        fictional_location="Singapore",
        severity="CRITICAL",
        description="Outbound encrypted TLS beaconing detected to known malicious synthetic domain over port 8443.",
        incident_id="INC-2026-006",
        related_entity_ids=["host-workstation-88", "c2-domain-darksim.internal"],
        evidence_metadata={"destination_port": 8443, "tls_sni": "darksim-relay.internal", "beacon_interval_sec": 30},
    ),
    SecurityEvent(
        event_id="EVT-603",
        timestamp="2026-10-24T11:50:00Z",
        event_category="NETWORK",
        synthetic_account_id="eng-k.chen",
        synthetic_source_ip="203.0.113.200",
        fictional_location="Singapore",
        severity="CRITICAL",
        description="High-volume outbound data exfiltration of 4.2 GB compressed telemetry archive.",
        incident_id="INC-2026-006",
        related_entity_ids=["host-workstation-88", "archive-source-code.tar.gz"],
        evidence_metadata={"bytes_sent": 4509715660, "protocol": "HTTPS", "destination_ip": "203.0.113.200"},
    ),
]

# All seeded synthetic events
ALL_SEEDED_EVENTS: List[SecurityEvent] = (
    SCENARIO_1_EVENTS
    + SCENARIO_2_EVENTS
    + SCENARIO_3_EVENTS
    + SCENARIO_4_EVENTS
    + SCENARIO_5_EVENTS
    + SCENARIO_6_EVENTS
)

# Seeded Incidents corresponding to scenarios
SEEDED_INCIDENTS: List[Incident] = [
    Incident(
        incident_id="INC-2026-001",
        title="Anomalous Admin Session from Unusual Geo-Location",
        description="Administrative account admin-ops-root logged in from unexpected Eastern Europe IP at 03:10 UTC and queried root IAM policies.",
        scenario_id="SCENARIO_1",
        created_at="2026-10-24T03:15:00Z",
        severity="HIGH",
        status="OPEN",
        primary_account="admin-ops-root",
        event_ids=["EVT-101", "EVT-102", "EVT-103"],
        correlated_entities=["sess-9011", "host-adm-portal", "role-global-sec-admin"],
        is_synthetic=True,
    ),
    Incident(
        incident_id="INC-2026-002",
        title="Credential Stuffing Attack Leading to Session Hijack",
        description="Rapid sequence of failed password attempts followed by successful authentication for j.doe from Russian IP range, accessing payroll database.",
        scenario_id="SCENARIO_2",
        created_at="2026-10-24T08:05:00Z",
        severity="HIGH",
        status="OPEN",
        primary_account="j.doe@sentinelflow.internal",
        event_ids=["EVT-201", "EVT-202", "EVT-203", "EVT-204", "EVT-205"],
        correlated_entities=["sess-4412", "auth-gateway-01", "res-hr-payroll-db"],
        is_synthetic=True,
    ),
    Incident(
        incident_id="INC-2026-003",
        title="Service Account Compromise & Bulk Invoice Extraction",
        description="Internal billing exporter service account accessed via Tor exit node, escalated privileges to superuser, and extracted invoice archives.",
        scenario_id="SCENARIO_3",
        created_at="2026-10-24T10:20:00Z",
        severity="CRITICAL",
        status="OPEN",
        primary_account="svc-billing-exporter",
        event_ids=["EVT-301", "EVT-302", "EVT-303"],
        correlated_entities=["sess-srv-771", "role-superadmin", "s3-finance-invoices-2026"],
        is_synthetic=True,
    ),
    Incident(
        incident_id="INC-2026-004",
        title="Sanctioned Disaster Recovery Replication (Benign Context)",
        description="Data analyst executed large-scale data export from Tokyo DR site, matching authorized Jira ticket SEC-DATA-SYNC-98.",
        scenario_id="SCENARIO_4",
        created_at="2026-10-24T22:10:00Z",
        severity="MEDIUM",
        status="OPEN",
        primary_account="analyst-t.smith",
        event_ids=["EVT-401", "EVT-402"],
        correlated_entities=["sess-dr-201", "table-tx-archive", "jira-ticket-SEC-DATA-SYNC-98"],
        is_synthetic=True,
    ),
    Incident(
        incident_id="INC-2026-005",
        title="Standard Corporate SSO Login (Routine Low-Risk)",
        description="Routine HR authentication and handbook access from corporate branch office with verified compliant device posture.",
        scenario_id="SCENARIO_5",
        created_at="2026-10-24T14:35:00Z",
        severity="INFORMATIONAL",
        status="OPEN",
        primary_account="hr-m.garcia",
        event_ids=["EVT-501", "EVT-502"],
        correlated_entities=["sess-hr-990", "host-laptop-garcia", "res-handbook-pdf"],
        is_synthetic=True,
    ),
    Incident(
        incident_id="INC-2026-006",
        title="Critical C2 Beaconing & Bulk Data Exfiltration",
        description="Workstation executed obfuscated PowerShell beaconing to offshore C2 node, initiating 4.2 GB exfiltration over port 8443.",
        scenario_id="SCENARIO_6",
        created_at="2026-10-24T11:52:00Z",
        severity="CRITICAL",
        status="OPEN",
        primary_account="eng-k.chen",
        event_ids=["EVT-601", "EVT-602", "EVT-603"],
        correlated_entities=["host-workstation-88", "proc-powershell-812", "c2-domain-darksim.internal", "archive-source-code.tar.gz"],
        is_synthetic=True,
    ),
]

# Attack vector summary distribution for threat intelligence charts
SYNTHETIC_ATTACK_VECTORS = [
    {"vector": "Credential Stuffing & Spraying", "count": 42, "risk_category": "Identity"},
    {"vector": "Anomalous Administrative Access", "count": 28, "risk_category": "Privilege"},
    {"vector": "Data Exfiltration / C2 Beaconing", "count": 19, "risk_category": "Network"},
    {"vector": "Service Account Misuse", "count": 15, "risk_category": "Cloud / IAM"},
    {"vector": "Suspicious Bulk Data Exports", "count": 11, "risk_category": "Data Access"},
]

# Synthetic illustrative compliance baseline (strictly labeled as illustrative demo)
SYNTHETIC_COMPLIANCE_INDICATORS = [
    {
        "framework": "NIST CSF 2.0 (Demo Baseline)",
        "score_percent": 94,
        "status": "Healthy Simulation",
        "description": "Illustrative telemetry covering Identify, Protect, Detect, Respond, Recover.",
    },
    {
        "framework": "CIS Controls v8 (Demo Baseline)",
        "score_percent": 91,
        "status": "Healthy Simulation",
        "description": "Synthetic auditing for Inventory, Access Control, and Continuous Vulnerability.",
    },
    {
        "framework": "MITRE ATT&CK Matrix (Demo Coverage)",
        "score_percent": 88,
        "status": "Active Correlation",
        "description": "Simulated detections for T1078, T1110, T1059, T1048, and T1098.",
    },
]


def get_fresh_sample_data():
    """Return a deep copy of initial synthetic events, incidents, and infrastructure state."""
    return {
        "events": [e.model_copy() for e in ALL_SEEDED_EVENTS],
        "incidents": [i.model_copy() for i in SEEDED_INCIDENTS],
        "infrastructure": {k: dict(v) for k, v in SYNTHETIC_INFRASTRUCTURE.items()},
        "geo_points": list(SYNTHETIC_GEO_POINTS),
    }
