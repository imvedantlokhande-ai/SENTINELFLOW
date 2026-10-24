"""Unit tests for the Interchangeable AI Provider Interface."""

from unittest.mock import MagicMock, patch
import json
from sentinelflow.ai_provider import GeminiProvider, DeterministicRuleProvider, AIProviderRegistry
from sentinelflow.sample_data import SEEDED_INCIDENTS, SCENARIO_1_EVENTS
from sentinelflow.event_correlation import EventCorrelationEngine


def test_deterministic_provider_availability_and_execution():
    """Test deterministic rule provider is always available and produces valid findings."""
    provider = DeterministicRuleProvider()
    assert provider.is_available() is True
    assert "Deterministic" in provider.name()

    corr_engine = EventCorrelationEngine()
    inc = SEEDED_INCIDENTS[0]
    corr = corr_engine.correlate_incident_events(SCENARIO_1_EVENTS, incident_id=inc.incident_id)

    finding = provider.investigate(inc, SCENARIO_1_EVENTS, corr)
    assert finding.analysis_mode == "deterministic_rule_based"
    assert finding.risk_score >= 60


def test_gemini_provider_availability():
    """Test Gemini provider availability check based on API key configuration."""
    unconfigured = GeminiProvider(api_key="")
    assert unconfigured.is_available() is False

    configured = GeminiProvider(api_key="valid_test_api_key_12345")
    assert configured.is_available() is True
    assert "Gemini" in configured.name()


def test_provider_registry():
    """Test AIProviderRegistry registers and returns active providers."""
    det_provider = DeterministicRuleProvider()
    gem_provider = GeminiProvider(api_key="")

    registry = AIProviderRegistry(default_provider=det_provider)
    registry.register("gemini", gem_provider)

    assert registry.get("default") == det_provider
    assert registry.get("gemini") == gem_provider
    assert "default" in registry.list_available()
