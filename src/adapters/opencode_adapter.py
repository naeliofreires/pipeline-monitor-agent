from __future__ import annotations

import json
import os
from typing import Any


class OpencodeAdapter:
    """Adapter for opencode.ai Zen anomaly classification calls."""

    def __init__(
        self,
        model: str = "big-pickle",
        api_key: str | None = None,
        base_url: str = "https://opencode.ai/zen/v1",
        client: Any | None = None,
    ) -> None:
        self.model = model
        if client is not None:
            self.client = client
            return

        from openai import OpenAI

        self.client = OpenAI(api_key=api_key or os.getenv("OPENCODE_API_KEY"), base_url=base_url)

    def classify_anomaly(self, payload: dict[str, Any]) -> dict[str, Any]:
        prompt = (
            "Classify this Nexla anomaly using the supplied Evidence. Cite specific error logs, run status, "
            "health status, and record/error counts in explanation when present, and base recommended_action on them. "
            "If Evidence is partial, say what is missing. Return only JSON with keys "
            "risk_classification (low, high, or uncertain), explanation, and recommended_action.\n"
            f"Anomaly: {json.dumps(payload, default=str)}"
        )
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
        )
        text = response.choices[0].message.content
        if not text:
            raise ValueError("opencode.ai Zen response had empty content")
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("opencode.ai Zen response JSON was not an object")
        return parsed
