from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from adapters.llm_factory import build_llm_adapter
from adapters.openai_adapter import OpenAIAdapter


class FakeMessage:
    content = '{"risk_classification":"high","explanation":"failed","recommended_action":"inspect"}'


class FakeChoice:
    message = FakeMessage()


class FakeResponse:
    choices = [FakeChoice()]


class RecordingCompletions:
    def __init__(self, response: Any = FakeResponse()):
        self.calls = []
        self.response = response

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class RecordingChat:
    def __init__(self, response: Any = FakeResponse()):
        self.completions = RecordingCompletions(response)


class RecordingClient:
    def __init__(self, response: Any = FakeResponse()):
        self.chat = RecordingChat(response)


class OpenAIAdapterTests(unittest.TestCase):
    def test_classify_uses_chat_completions_and_prompt_contract(self):
        client = RecordingClient()

        result = OpenAIAdapter(model="gpt-test", client=client).classify_anomaly({"flow_name": "Orders Flow"})

        self.assertEqual(result["risk_classification"], "high")
        call = client.chat.completions.calls[0]
        self.assertEqual(call["model"], "gpt-test")
        self.assertEqual(call["max_tokens"], 500)
        self.assertEqual(call["response_format"], {"type": "json_object"})
        self.assertIn("Nexla moves data through Flows", call["messages"][0]["content"])
        self.assertIn('"flow_name": "Orders Flow"', call["messages"][0]["content"])

    def test_classify_errors_on_empty_or_non_object_response(self):
        class EmptyMessage:
            content = ""

        class EmptyChoice:
            message = EmptyMessage()

        class EmptyResponse:
            choices = [EmptyChoice()]

        with self.assertRaisesRegex(ValueError, "empty content"):
            OpenAIAdapter(client=RecordingClient(EmptyResponse())).classify_anomaly({})

        class ListMessage:
            content = "[]"

        class ListChoice:
            message = ListMessage()

        class ListResponse:
            choices = [ListChoice()]

        with self.assertRaisesRegex(ValueError, "not an object"):
            OpenAIAdapter(client=RecordingClient(ListResponse())).classify_anomaly({})


class LLMFactoryTests(unittest.TestCase):
    def test_defaults_to_opencode_and_preserves_defaults(self):
        with patch("adapters.llm_factory.OpencodeAdapter") as adapter_cls:
            adapter = build_llm_adapter({})

        self.assertEqual(adapter, adapter_cls.return_value)
        adapter_cls.assert_called_once_with(model="big-pickle", base_url="https://opencode.ai/zen/v1")

    def test_builds_openai_from_config(self):
        with patch("adapters.llm_factory.OpenAIAdapter") as adapter_cls:
            adapter = build_llm_adapter(
                {"llm": {"provider": "openai"}, "openai": {"model": "gpt-x", "base_url": "https://openai.test/v1"}}
            )

        self.assertEqual(adapter, adapter_cls.return_value)
        adapter_cls.assert_called_once_with(model="gpt-x", base_url="https://openai.test/v1")

    def test_rejects_unknown_provider(self):
        with self.assertRaisesRegex(ValueError, "Unsupported LLM provider"):
            build_llm_adapter({"llm": {"provider": "other"}})


if __name__ == "__main__":
    unittest.main()
