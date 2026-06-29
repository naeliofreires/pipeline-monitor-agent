from __future__ import annotations

import os
import unittest

from adapters.opencode_adapter import OpencodeAdapter


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
