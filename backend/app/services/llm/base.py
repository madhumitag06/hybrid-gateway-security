"""
Security Analyst AI Provider Base Interface
===========================================
Defines the contract for optional LLM copilot incident briefing synthesis.
The LLM is strictly an explanatory advisor and CANNOT override RandomForest,
SHAP, PolicyEngine, or execute enforcement actions.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class LLMProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g., 'none', 'groq', 'openai')."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Model identifier being used."""
        pass

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """True if the provider has necessary API keys configured."""
        pass

    @abstractmethod
    def generate_incident_briefing(
        self,
        event_id: str,
        attack_type: str,
        risk_score: int,
        confidence: float,
        source_ip: str,
        destination_ip: str,
        policy_action: str,
        policy_rule: str,
        top_shap_features: List[Dict[str, Any]],
        flow_features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Synthesizes human-readable SecOps incident briefing and actionable remediation advice
        grounded in the deterministic ML model and SHAP feature attributions.
        """
        pass
