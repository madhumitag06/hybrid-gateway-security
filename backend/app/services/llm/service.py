"""
Security Analyst AI Copilot Service Factory
===========================================
Instantiates the configured LLM provider and orchestrates incident briefing synthesis.
"""

from typing import Any, Dict, List
from backend.app.config import settings
from backend.app.services.llm.base import LLMProvider
from backend.app.services.llm.providers import (
    GroqLLMProvider,
    NoneLLMProvider,
    OpenAILLMProvider,
)


class LLMService:
    _instance: "LLMService" = None
    _provider: LLMProvider = None

    def __init__(self):
        self._provider = self._build_provider()

    @classmethod
    def get_instance(cls) -> "LLMService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _build_provider(self) -> LLMProvider:
        prov = (getattr(settings, "ai_provider", None) or getattr(settings, "llm_provider", "none") or "none").lower().strip()
        if prov == "groq" and settings.groq_api_key:
            model = getattr(settings, "groq_model", "") or getattr(settings, "llm_model", "")
            return GroqLLMProvider(api_key=settings.groq_api_key, model=model)
        elif prov == "openai" and settings.openai_api_key:
            model = getattr(settings, "openai_model", "") or getattr(settings, "llm_model", "")
            return OpenAILLMProvider(api_key=settings.openai_api_key, model=model)
        else:
            return NoneLLMProvider()

    def get_status(self) -> Dict[str, Any]:
        conf = getattr(settings, "ai_provider", None) or getattr(settings, "llm_provider", "none") or "none"
        return {
            "configured_provider": conf,
            "active_provider": self._provider.provider_name,
            "model": self._provider.model_name,
            "is_configured": self._provider.is_configured,
            "role": "Advisory SecOps Copilot (Zero Enforcement Permissions)",
        }

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
        return self._provider.generate_incident_briefing(
            event_id=event_id,
            attack_type=attack_type,
            risk_score=risk_score,
            confidence=confidence,
            source_ip=source_ip,
            destination_ip=destination_ip,
            policy_action=policy_action,
            policy_rule=policy_rule,
            top_shap_features=top_shap_features,
            flow_features=flow_features,
        )
