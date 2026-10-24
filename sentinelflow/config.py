"""Configuration module for SentinelFlow AI."""

import os
from typing import Set
from dotenv import load_dotenv

# Load local .env if present
load_dotenv()

# Gemini API Configuration
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip()
DEFAULT_GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
APP_MODE: str = os.getenv("SENTINELFLOW_MODE", "auto").strip().lower()

# Strict Action Allowlist for Simulated Responses
ALLOWED_ACTIONS: Set[str] = {
    "revoke_session",
    "lock_account",
    "escalate_incident",
    "mark_monitoring",
}

# Human readable action names
ACTION_LABELS = {
    "revoke_session": "Revoke Synthetic Session",
    "lock_account": "Temporarily Lock Synthetic Demo Account",
    "escalate_incident": "Escalate Incident for Senior Review",
    "mark_monitoring": "Mark Incident for Monitoring Without Containment",
}

# Severity Levels
VALID_SEVERITIES: Set[str] = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
}

# Valid Incident Statuses
VALID_INCIDENT_STATUSES: Set[str] = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINMENT_PROPOSED",
    "AWAITING_APPROVAL",
    "RESOLVED",
    "MONITORING",
    "ESCALATED",
    "CLOSED",
}

# Color Palette Constants (Futuristic SOC Theme)
COLOR_BG_DARK = "#0a0e17"
COLOR_PANEL_BG = "#111827"
COLOR_PANEL_BORDER = "#1e293b"
COLOR_ACCENT_CYAN = "#00f0ff"
COLOR_ACCENT_BLUE = "#3b82f6"
COLOR_CRITICAL = "#ef4444"
COLOR_HIGH = "#f97316"
COLOR_MEDIUM = "#f59e0b"
COLOR_LOW = "#38bdf8"
COLOR_INFO = "#64748b"
COLOR_SUCCESS = "#10b981"
COLOR_TEXT_PRIMARY = "#f8fafc"
COLOR_TEXT_SECONDARY = "#94a3b8"

# Safety notice disclaimer
SIMULATION_DISCLAIMER = (
    "DEMO / SIMULATION ENVIRONMENT: All events, entities, accounts, IP addresses, "
    "and containment actions are strictly synthetic simulations. No live corporate endpoints, "
    "production credentials, or security systems are connected."
)
