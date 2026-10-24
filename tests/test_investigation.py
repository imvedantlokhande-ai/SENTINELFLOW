"""Unit tests for the Investigation Engine and Gemini client integration."""

import json
from unittest.mock import MagicMock, patch
import pytest

from sentinelflow.investigation import InvestigationEngine
from sentinelflow.gemini_client import GeminiInvestigationClient, GeminiProviderError
from sentinelflow.sample_data import SEEDED_INCIDENTS, SCENARIO_1_EVENTS
from sentinelflow.event_correlation import EventCorrelationEngine


def test_deterministic_investigation_mode():
    """Test investigation engine runs in deterministic mode without Gemini API key."""
    corr_engine = EventCorrelationEngine()
    inv_engine = InvestigationEngine(api_key=None)

    inc = SEEDED_INCIDENTS[0]
    corr = corr_engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id=inc.incident_id)

    finding, warning = inv_engine.investigate(inc, SCENARIO_1_EVENTS, corr, force_mode="deterministic")

    assert finding is not None
    assert finding.analysis_mode == "deterministic_rule_based"
    assert finding.risk_score >= 60
    assert finding.proposed_action == "revoke_session"
    assert set(finding.supporting_evidence_ids).issubset(set(inc.event_ids))
    assert warning is None


def test_gemini_client_unconfigured_raises_error():
    """Test that calling unconfigured Gemini client raises GeminiProviderError."""
    client = GeminiInvestigationClient(api_key="")
    assert not client.is_configured()

    corr_engine = EventCorrelationEngine()
    corr = corr_engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id="INC-2026-001")

    with pytest.raises(GeminiProviderError, match="not configured"):
        client.analyze_incident("INC-2026-001", SCENARIO_1_EVENTS, corr)


def test_gemini_investigation_mocked_success():
    """Test successful mock response from Gemini API."""
    mock_payload = {
        "incident_summary": "Mocked admin compromise detected.",
        "risk_score": 85,
        "severity": "CRITICAL",
        "confidence_score": 0.95,
        "supporting_evidence_ids": ["EVT-101", "EVT-102"],
        "timeline_interpretation": "Attacker logged in at 03:10 then elevated IAM.",
        "likely_explanation": "Credential stuffing or session hijack.",
        "alternative_explanations": ["Authorized admin travel."],
        "uncertainties_and_limitations": "Synthetic geo IP context.",
        "recommended_next_steps": ["Revoke session immediately."],
        "proposed_action": "revoke_session",
        "human_review_rationale": "Session revocation severs access safely.",
    }

    mock_response = MagicMock()
    mock_response.text = json.dumps(mock_payload)

    with patch("google.genai.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_instance

        client = GeminiInvestigationClient(api_key="mock_secret_key_12345")
        corr_engine = EventCorrelationEngine()
        corr = corr_engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id="INC-2026-001")

        finding = client.analyze_incident("INC-2026-001", SCENARIO_1_EVENTS, corr)

        assert finding.analysis_mode == "gemini_ai"
        assert finding.risk_score == 85
        assert finding.severity == "CRITICAL"
        assert finding.proposed_action == "revoke_session"
        assert finding.supporting_evidence_ids == ["EVT-101", "EVT-102"]


def test_gemini_investigation_hallucinated_evidence_filtered():
    """Test that unknown evidence IDs returned by Gemini are rejected or filtered."""
    mock_payload = {
        "incident_summary": "Mocked summary",
        "risk_score": 75,
        "severity": "HIGH",
        "confidence_score": 0.85,
        "supporting_evidence_ids": ["EVT-UNKNOWN-9999", "EVT-101"],  # One unknown ID
        "timeline_interpretation": "Timeline",
        "likely_explanation": "Cause",
        "alternative_explanations": ["Alt"],
        "uncertainties_and_limitations": "Limitations",
        "recommended_next_steps": ["Step"],
        "proposed_action": "revoke_session",
        "human_review_rationale": "Rationale",
    }

    mock_response = MagicMock()
    mock_response.text = json.dumps(mock_payload)

    with patch("google.genai.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_instance

        client = GeminiInvestigationClient(api_key="mock_key_test")
        corr_engine = EventCorrelationEngine()
        corr = corr_engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id="INC-2026-001")

        finding = client.analyze_incident("INC-2026-001", SCENARIO_1_EVENTS, corr)
        # Should filter out EVT-UNKNOWN-9999 and keep only EVT-101
        assert "EVT-UNKNOWN-9999" not in finding.supporting_evidence_ids
        assert finding.supporting_evidence_ids == ["EVT-101"]


def test_gemini_fallback_on_provider_error():
    """Test that when Gemini fails in auto mode, it falls back to deterministic analysis with warning."""
    with patch("google.genai.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.models.generate_content.side_effect = Exception("503 Service Unavailable / Rate Limit")
        mock_client_cls.return_value = mock_instance

        inv_engine = InvestigationEngine(api_key="mock_key_fails")
        corr_engine = EventCorrelationEngine()
        inc = SEEDED_INCIDENTS[0]
        corr = corr_engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id=inc.incident_id)

        finding, warning = inv_engine.investigate(inc, SCENARIO_1_EVENTS, corr, force_mode="auto")

        assert finding is not None
        assert finding.analysis_mode == "deterministic_rule_based"
        assert warning is not None
        assert "Switched to deterministic" in warning
