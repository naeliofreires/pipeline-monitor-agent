from __future__ import annotations

import json
import os
from typing import Any

from adapters.opencode_adapter import (
    NEXLA_ANOMALY_ANALYSIS_PROMPT,
    NEXLA_COMMAND_ROUTER_PROMPT,
    _route_response_to_dict,
)


class OpenAIAdapter:
    """Adapter for OpenAI anomaly classification calls."""

    def __init__(
        self,
        model: str = "gpt-4.1-mini",
        api_key: str | None = None,
        base_url: str | None = None,
        client: Any | None = None,
    ) -> None:
        self.model = model
        if client is not None:
            self.client = client
            return

        from openai import OpenAI

        kwargs: dict[str, Any] = {"api_key": api_key or os.getenv("OPENAI_API_KEY")}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)

    def classify_anomaly(self, payload: dict[str, Any]) -> dict[str, Any]:
        prompt = f"{NEXLA_ANOMALY_ANALYSIS_PROMPT}\nAnomaly: {json.dumps(payload, default=str)}"
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            response_format={"type": "json_object"},
        )
        text = response.choices[0].message.content
        if not text:
            raise ValueError("OpenAI response had empty content")
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("OpenAI response JSON was not an object")
        return parsed

    def route_command(self, message: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": NEXLA_COMMAND_ROUTER_PROMPT},
                {"role": "user", "content": message},
            ],
            tools=tools,
            tool_choice="auto",
            max_tokens=300,
        )
        return _route_response_to_dict(response.choices[0].message)
