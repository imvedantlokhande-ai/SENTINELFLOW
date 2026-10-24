"""Google Gemini API integration client using official google-genai SDK.

Implements strict Pydantic validation, evidence ID verification, timeout protection,
and safe error handling. Never logs or exposes API keys.
"""

import json
import logging
from typing import List, Optional, Dict, Any

from sentinelflow.config import GEMINI_API_KEY, DEFAULT_GEMINI_MODEL, ALLOWED_ACTIONS, VALID_SEVERITIES
from sentinelflow.models import SecurityEvent, CorrelatedGroup, InvestigationFinding
from sentinelflow.prompt_defense import (
    build_hardened_system_instruction,
    sanitize_untrusted_telemetry,
    detect_prompt_injection,
    validate_and_bound_ai_finding,
)

logger = logging.getLogger("sentinelflow.gemini_client")


class GeminiProviderError(Exception):
    """Custom exception raised when Gemini API call fails or times out."""
    pass


class GeminiInvestigationClient:
    """Encapsulates Gemini API calls with strict validation and safe fallback."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = (api_key or GEMINI_API_KEY or "").strip()
        self.model = (model or DEFAULT_GEMINI_MODEL).strip()

    def is_configured(self) -> bool:
        """Return True if an API key is present."""
        return bool(self.api_key and len(self.api_key) > 5)

    def analyze_incident(
        self,
        incident_id: str,
        events: List[SecurityEvent],
        correlation: CorrelatedGroup,
    ) -> InvestigationFinding:
        """Call Gemini to investigate an incident with strictly validated structured output."""
        if not self.is_configured():
            raise GeminiProviderError(
                "Gemini API key is not configured. Set GEMINI_API_KEY in environment or .env file."
            )

        try:
            from google import genai
        except ImportError as e:
            raise GeminiProviderError(
                f"The official 'google-genai' SDK is not installed in the environment: {e}"
            )

        # Context compilation - sanitize untrusted telemetry and bound input size
        valid_event_ids = set(e.event_id for e in events)
        injections_detected = []
        telemetry_summary = []
        for e in events:
            is_injected, matched_patterns = detect_prompt_injection(e.description)
            if is_injected:
                injections_detected.extend(matched_patterns)
            
            clean_desc = sanitize_untrusted_telemetry(e.description)
            telemetry_summary.append({
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "category": e.event_category,
                "account": e.synthetic_account_id,
                "source_ip": e.synthetic_source_ip,
                "location": e.fictional_location,
                "severity": e.severity,
                "description": clean_desc,
                "evidence_metadata": e.evidence_metadata,
            })

        system_instruction = build_hardened_system_instruction()

        prompt = f"""
Analyze the following synthetic security incident telemetry:
Incident ID: {incident_id}
Primary Account: {correlation.primary_account}
Correlated Group: {correlation.group_id}
Rules Triggered: {correlation.correlation_rules_triggered}
Correlated Events:
{json.dumps(telemetry_summary, indent=2)}

Valid Event IDs present in evidence: {sorted(list(valid_event_ids))}
Allowed simulated response actions (or null if none): {sorted(list(ALLOWED_ACTIONS))}
Allowed severities: {sorted(list(VALID_SEVERITIES))}

Produce a structured JSON investigation report with these EXACT fields:
- incident_summary: Concise executive overview (string)
- risk_score: Integer from 0 to 100 (integer)
- severity: One of {sorted(list(VALID_SEVERITIES))} (string)
- confidence_score: Float between 0.0 and 1.0 (float)
- supporting_evidence_ids: List of event IDs supporting this conclusion. MUST ONLY contain IDs from {sorted(list(valid_event_ids))} (list of strings)
- timeline_interpretation: Detailed chronological reconstruction of the attack chain (string)
- likely_explanation: Most probable cause of the incident (string)
- alternative_explanations: List of 1-3 alternate or benign possibilities (list of strings)
- uncertainties_and_limitations: Gaps or limitations in the synthetic telemetry (string)
- recommended_next_steps: Concrete list of steps for the analyst (list of strings)
- proposed_action: Exactly ONE of {sorted(list(ALLOWED_ACTIONS))} or null (string or null)
- human_review_rationale: Explanation of why human approval is required before execution (string)
"""

        try:
            client = genai.Client(api_key=self.api_key)
            # Use client.models.generate_content or interactions.create
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config={
                    "system_instruction": system_instruction,
                    "response_mime_type": "application/json",
                    "temperature": 0.2,
                },
            )

            raw_text = response.text or ""
            # Clean up potential markdown formatting if returned
            clean_text = raw_text.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.startswith("```"):
                clean_text = clean_text[3:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            clean_text = clean_text.strip()

            parsed_data = json.loads(clean_text)

        except Exception as e:
            logger.error("Gemini API call failed: %s", str(e))
            raise GeminiProviderError(f"Gemini API request failed: {str(e)}")

        # Validate that returned supporting_evidence_ids only contain valid IDs
        returned_evidence = parsed_data.get("supporting_evidence_ids", [])
        if not isinstance(returned_evidence, list) or not returned_evidence:
            parsed_data["supporting_evidence_ids"] = list(valid_event_ids)
        else:
            # Filter unknown evidence IDs
            filtered_evidence = [eid for eid in returned_evidence if eid in valid_event_ids]
            if not filtered_evidence:
                raise GeminiProviderError(
                    f"Gemini output contained hallucinated/unknown evidence IDs: {returned_evidence}"
                )
            parsed_data["supporting_evidence_ids"] = filtered_evidence

        # Set analysis mode
        parsed_data["analysis_mode"] = "gemini_ai"

        # Validate strictly with Pydantic
        try:
            raw_finding = InvestigationFinding(**parsed_data)
            return validate_and_bound_ai_finding(raw_finding, valid_event_ids)
        except Exception as pydantic_err:
            raise GeminiProviderError(f"Gemini output failed Pydantic schema validation: {pydantic_err}")

