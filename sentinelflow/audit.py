"""Append-only audit trail logger for SentinelFlow AI.

Maintains an in-memory chronological record of all analyst actions, AI investigations,
response approvals, simulations, and verification results.
"""

import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sentinelflow.models import AuditEntry


def sanitize_text(text: str) -> str:
    """Sanitize technical text to redact any API keys, tokens, or credential patterns."""
    if not text:
        return ""
    # Redact Google API key patterns like AIzaSy...
    text = re.sub(r"AIza[0-9A-Za-z\-_]{30,45}", "[REDACTED_API_KEY]", text)
    # Redact generic bearer tokens or secret assignments
    text = re.sub(r"(api_key|token|password|secret)\s*[:=]\s*[^\s]+", r"\1: [REDACTED]", text, flags=re.IGNORECASE)
    return text


class AuditTrail:
    """In-memory append-only audit trail."""

    def __init__(self, initial_entries: Optional[List[AuditEntry]] = None):
        self._entries: List[AuditEntry] = initial_entries or []
        self._counter: int = len(self._entries)

    def log(
        self,
        event_type: str,
        status: str,
        details: str,
        incident_id: Optional[str] = None,
        action_id: Optional[str] = None,
        actor: str = "analyst",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Append a new audit entry to the log. Sanitizes any sensitive fields."""
        self._counter += 1
        entry_id = f"AUD-{self._counter:05d}"
        clean_metadata = dict(metadata or {})
        # Safety guarantee: Never log API keys or secrets
        for k in list(clean_metadata.keys()):
            if "key" in k.lower() or "secret" in k.lower() or "token" in k.lower():
                clean_metadata[k] = "[REDACTED_SECRET]"
            elif isinstance(clean_metadata[k], str):
                clean_metadata[k] = sanitize_text(clean_metadata[k])

        clean_details = sanitize_text(details)

        entry = AuditEntry(
            entry_id=entry_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            incident_id=incident_id,
            action_id=action_id,
            status=status,
            actor=actor,
            details=clean_details,
            metadata=clean_metadata,
        )
        self._entries.append(entry)
        return entry

    def get_entries(
        self,
        incident_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Query entries chronologically with optional filtering."""
        results = list(self._entries)
        if incident_id:
            results = [e for e in results if e.incident_id == incident_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        return sorted(results, key=lambda e: e.timestamp, reverse=True)

    def clear(self):
        """Reset the audit trail (used strictly during demo reset)."""
        self._entries = []
        self._counter = 0
