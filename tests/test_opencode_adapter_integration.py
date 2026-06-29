from __future__ import annotations

import os
import unittest

from adapters.opencode_adapter import NEXLA_ANOMALY_ANALYSIS_PROMPT, OpencodeAdapter


class FakeMessage:
    content = '{"risk_classification":"high","explanation":"failed","recommended_action":"inspect"}'


class FakeChoice:
    message = FakeMessage()


class FakeResponse:
    choices = [FakeChoice()]


class RecordingCompletions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponse()


class RecordingChat:
    def __init__(self):
        self.completions = RecordingCompletions()


class RecordingClient:
    def __init__(self):
        self.chat = RecordingChat()


class OpencodeAdapterPromptTests(unittest.TestCase):
    def test_prompt_includes_nexla_product_context_and_json_contract(self):
        client = RecordingClient()
        payload = {
            "type": "silent_failure",
            "flow_id": 42,
            "flow_name": "Orders Flow",
            "resource_type": "data_sink",
            "evidence": {"partial": True, "health_status": "RED", "records_this_run": 0, "errors_this_run": 3},
        }

        result = OpencodeAdapter(client=client).classify_anomaly(payload)

        self.assertEqual(result["risk_classification"], "high")
        prompt = client.chat.completions.calls[0]["messages"][0]["content"]
        self.assertIn("Nexla moves data through Flows", prompt)
        self.assertIn("Explicit Failure", prompt)
        self.assertIn("Silent Failure", prompt)
        self.assertIn("Capsule-like Flows", prompt)
        self.assertIn("Return only JSON", prompt)
        self.assertIn('"flow_name": "Orders Flow"', prompt)
        self.assertIn("risk_classification (`low`, `high`, or `uncertain`)", NEXLA_ANOMALY_ANALYSIS_PROMPT)


@unittest.skipUnless(os.getenv("OPENCODE_API_KEY"), "OPENCODE_API_KEY is required for real LLM integration test")
class OpencodeAdapterIntegrationTests(unittest.TestCase):
    def test_classifies_fake_explicit_failure_payload_with_real_llm(self):
        payload = {
            "type": "explicit_failure",
            "notification_id": 999001,
            "flow_id": 4242,
            "flow_name": "Integration Test Orders Flow",
            "level": "ERROR",
            "resource_type": "flow",
            "message": "Destination rejected records because authentication failed with HTTP 401.",
            "detected_at": "2026-06-26T12:00:00Z",
        }

        result = OpencodeAdapter().classify_anomaly(payload)

        self.assertIn(result["risk_classification"], {"low", "high", "uncertain"})
        self.assertIsInstance(result["explanation"], str)
        self.assertTrue(result["explanation"].strip())
        self.assertIsInstance(result["recommended_action"], str)
        self.assertTrue(result["recommended_action"].strip())


if __name__ == "__main__":
    unittest.main()
