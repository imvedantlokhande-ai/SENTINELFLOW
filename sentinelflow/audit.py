"""Append-only audit trail logger for SentinelFlow AI.

Maintains an in-memory chronological record of all analyst actions, AI investigations,
response approvals, simulations, and verification results.
"""

from __future__ import annotations

import hashlib
import re
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from sentinelflow.models import AuditEntry


def sanitize_text(text: str) -> str:
    """Sanitize technical text to redact any API keys, tokens, or credential patterns."""
    if not text:
        return ""
    # Redact Google API key patterns like AIza...
    text = re.sub(r"AIza[0-9A-Za-z\-_]{30,45}", "[REDACTED_API_KEY]", text)
    # Redact generic bearer tokens or secret assignments
    text = re.sub(r"(api_key|token|password|secret)\s*[:=]\s*[^\s]+", r"\1: [REDACTED]", text, flags=re.IGNORECASE)
    return text


class AuditTrail:
    """In-memory append-only audit trail with tamper-evident cryptographic chaining."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, initial_entries: Optional[List[AuditEntry]] = None):
        self._lock = threading.RLock()
        self._entries: List[AuditEntry] = []
        self._counter: int = 0
        if initial_entries:
            for e in initial_entries:
                self._append_entry(e)

    def _compute_hash(
        self,
        entry_id: str,
        timestamp: str,
        event_type: str,
        status: str,
        actor: str,
        details: str,
        prev_hash: str,
    ) -> str:
        payload = f"{entry_id}|{timestamp}|{event_type}|{status}|{actor}|{details}|{prev_hash}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _append_entry(self, entry: AuditEntry) -> None:
        with self._lock:
            self._counter += 1
            prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
            entry.prev_hash = prev_hash
            entry.entry_hash = self._compute_hash(
                entry.entry_id,
                entry.timestamp,
                entry.event_type,
                entry.status,
                entry.actor,
                entry.details,
                prev_hash,
            )
            self._entries.append(entry)

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
        with self._lock:
            next_count = self._counter + 1
            entry_id = f"AUD-{next_count:05d}"
            clean_metadata = dict(metadata or {})
            # Safety guarantee: Never log API keys or secrets
            for k in list(clean_metadata.keys()):
                if "key" in k.lower() or "secret" in k.lower() or "token" in k.lower():
                    clean_metadata[k] = "[REDACTED_SECRET]"
                elif isinstance(clean_metadata[k], str):
                    clean_metadata[k] = sanitize_text(clean_metadata[k])

            clean_details = sanitize_text(details)
            timestamp = datetime.now(timezone.utc).isoformat()
            prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
            entry_hash = self._compute_hash(
                entry_id, timestamp, event_type, status, actor, clean_details, prev_hash
            )

            entry = AuditEntry(
                entry_id=entry_id,
                timestamp=timestamp,
                event_type=event_type,
                incident_id=incident_id,
                action_id=action_id,
                status=status,
                actor=actor,
                details=clean_details,
                metadata=clean_metadata,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self._counter += 1
            self._entries.append(entry)
            return entry

    def record(
        self,
        event_type: str,
        details: str,
        status: str = "SUCCESS",
        incident_id: Optional[str] = None,
        action_id: Optional[str] = None,
        actor: str = "analyst",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Convenience method for logging security and lifecycle events."""
        return self.log(
            event_type=event_type,
            status=status,
            details=details,
            incident_id=incident_id,
            action_id=action_id,
            actor=actor,
            metadata=metadata,
        )

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """Cryptographically verify the entire audit log chain for tampering.

        Returns:
            (is_valid: bool, error_message: Optional[str])
        """
        with self._lock:
            prev_hash = self.GENESIS_HASH
            for idx, entry in enumerate(self._entries):
                # 1. Check parent hash linkage
                if entry.prev_hash != prev_hash:
                    return (
                        False,
                        f"Audit chain broken at index {idx} ({entry.entry_id}): parent hash '{entry.prev_hash}' does not match expected '{prev_hash}'.",
                    )
                # 2. Recompute current hash
                expected_hash = self._compute_hash(
                    entry.entry_id,
                    entry.timestamp,
                    entry.event_type,
                    entry.status,
                    entry.actor,
                    entry.details,
                    prev_hash,
                )
                if entry.entry_hash != expected_hash:
                    return (
                        False,
                        f"Audit tampering detected at index {idx} ({entry.entry_id}): entry hash '{entry.entry_hash}' mismatch against computed '{expected_hash}'.",
                    )
                prev_hash = entry.entry_hash

            return True, None

    def get_entries(
        self,
        incident_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Query entries chronologically with optional filtering."""
        with self._lock:
            results = list(self._entries)
            if incident_id:
                results = [e for e in results if e.incident_id == incident_id]
            if event_type:
                results = [e for e in results if e.event_type == event_type]
            return sorted(results, key=lambda e: e.timestamp, reverse=True)

    def clear(self):
        """Reset the audit trail (used strictly during demo reset)."""
        with self._lock:
            self._entries = []
            self._counter = 0
