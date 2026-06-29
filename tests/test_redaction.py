from __future__ import annotations

import unittest

from modules.alerting.alert import build_anomaly_alert_text
from modules.classification.classifier import ClassificationResult, _payload
from modules.detection.anomaly import Anomaly
from modules.enrichment.enricher import Evidence
from modules.redaction import redact


class RedactTests(unittest.TestCase):
    def test_masks_credentials_in_url(self):
        self.assertEqual(
            redact("connect failed at postgres://admin:s3cret@db.internal:5432/orders"),
            "connect failed at postgres://***:***@db.internal:5432/orders",
        )

    def test_masks_jdbc_connection_string(self):
        self.assertEqual(
            redact("jdbc:mysql://host:3306/db?user=root&password=hunter2 timed out"),
            "jdbc:*** timed out",
        )

    def test_masks_key_value_secrets(self):
        self.assertEqual(redact("auth error: password=hunter2"), "auth error: password=***")
        self.assertEqual(redact("token=abc123 expired"), "token=*** expired")
        self.assertEqual(redact("api_key=XYZ rejected"), "api_key=*** rejected")

    def test_keeps_non_sensitive_text(self):
        msg = "Destination table orders_2026 rejected 12 records (constraint violation)"
        self.assertEqual(redact(msg), msg)

    def test_none_and_empty_pass_through(self):
        self.assertIsNone(redact(None))
        self.assertEqual(redact(""), "")


class RedactionBoundaryTests(unittest.TestCase):
    """Credentials must not survive into the printed Alert or the LLM payload."""

    def _anomaly(self):
        return Anomaly(
            7, "explicit_failure", 42, "Orders", "ERROR", 99, "data_sink",
            "Auth failed for postgres://admin:s3cret@db.internal/orders", "now",
        )

    def test_alert_text_redacts_message_and_evidence(self):
        evidence = Evidence(
            health_status="RED",
            error_summary="login as user=admin password=hunter2 failed",
            top_error_logs=("ERROR jdbc:mysql://h:3306/db?pwd=secret",),
        )
        text = build_anomaly_alert_text(
            self._anomaly(), evidence, ClassificationResult("high", "bad", "fix it")
        )
        self.assertNotIn("s3cret", text)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("pwd=secret", text)
        self.assertIn("***", text)

    def test_llm_payload_redacts_message(self):
        payload = _payload(self._anomaly(), Evidence())
        self.assertNotIn("s3cret", payload["message"])
        self.assertIn("postgres://***:***@db.internal/orders", payload["message"])


if __name__ == "__main__":
    unittest.main()
