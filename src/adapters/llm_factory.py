from __future__ import annotations

from typing import Any

from adapters.opencode_adapter import OpencodeAdapter
from adapters.openai_adapter import OpenAIAdapter
from modules.classification.classifier import AnomalyClassifier


def build_llm_adapter(config: dict[str, Any]) -> AnomalyClassifier:
    """Build the configured LLM adapter."""
    provider = config.get("llm", {}).get("provider", "opencode")
    if not isinstance(provider, str):
        raise ValueError("llm.provider must be a string")

    provider = provider.strip().lower()
    if provider == "opencode":
        opencode_config = config.get("opencode", {})
        return OpencodeAdapter(
            model=opencode_config.get("model", "big-pickle"),
            base_url=opencode_config.get("base_url", "https://opencode.ai/zen/v1"),
        )
    if provider == "openai":
        openai_config = config.get("openai", {})
        return OpenAIAdapter(
            model=openai_config.get("model", "gpt-4.1-mini"),
            base_url=openai_config.get("base_url"),
        )

    raise ValueError(f"Unsupported LLM provider: {provider}")
