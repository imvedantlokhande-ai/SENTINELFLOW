"""Interchangeable AI Provider Interface for SentinelFlow AI.

Defines a provider abstraction allowing seamless switching between Google Gemini,
deterministic rule-based analysis, or future security AI backends.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any

from sentinelflow.models import SecurityEvent, CorrelatedGroup, InvestigationFinding, Incident
from sentinelflow.gemini_client import GeminiInvestigationClient, GeminiProviderError


class BaseAIProvider(ABC):
    """Abstract Base Class for Incident Investigation AI Providers."""

    @abstractmethod
    def name(self) -> str:
        """Return human-readable provider name."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider credentials and network dependencies are ready."""
        pass

    @abstractmethod
    def investigate(
        self,
        incident: Incident,
        events: List[SecurityEvent],
        correlation: CorrelatedGroup,
    ) -> InvestigationFinding:
        """Analyze security incident telemetry and produce validated findings."""
        pass


class GeminiProvider(BaseAIProvider):
    """Google Gemini AI implementation using official google-genai SDK."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.client = GeminiInvestigationClient(api_key=api_key, model=model)

    def name(self) -> str:
        return f"Google Gemini ({self.client.model})"

    def is_available(self) -> bool:
        return self.client.is_configured()

    def investigate(
        self,
        incident: Incident,
        events: List[SecurityEvent],
        correlation: CorrelatedGroup,
    ) -> InvestigationFinding:
        return self.client.analyze_incident(
            incident_id=incident.incident_id,
            events=events,
            correlation=correlation,
        )


class DeterministicRuleProvider(BaseAIProvider):
    """Transparent rule-based fallback provider requiring zero external API keys."""

    def __init__(self, investigation_engine=None):
        self._investigation_engine = investigation_engine

    def name(self) -> str:
        return "Deterministic Heuristic Engine"

    def is_available(self) -> bool:
        return True

    def investigate(
        self,
        incident: Incident,
        events: List[SecurityEvent],
        correlation: CorrelatedGroup,
    ) -> InvestigationFinding:
        if self._investigation_engine is None:
            from sentinelflow.investigation import InvestigationEngine
            self._investigation_engine = InvestigationEngine()
        return self._investigation_engine.run_deterministic_investigation(incident, events, correlation)


class AIProviderRegistry:
    """Registry managing interchangeable AI investigation providers."""

    def __init__(self, default_provider: Optional[BaseAIProvider] = None):
        self._providers: Dict[str, BaseAIProvider] = {}
        if default_provider:
            self.register("default", default_provider)

    def register(self, key: str, provider: BaseAIProvider) -> None:
        self._providers[key.lower()] = provider

    def get(self, key: str) -> Optional[BaseAIProvider]:
        return self._providers.get(key.lower())

    def list_available(self) -> List[str]:
        return [k for k, p in self._providers.items() if p.is_available()]
