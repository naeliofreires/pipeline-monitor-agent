from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

from adapters.nexla_adapter import NexlaAdapter, _plain, _resource_type_for_metrics
from modules.detection.anomaly import Anomaly
from modules.detection.explicit_failure import detect_explicit_failures
from modules.detection.health_sweep import detect_unhealthy_flows
from modules.enrichment.enricher import Evidence, enrich_anomaly
from modules.classification.classifier import classify_anomaly
from modules.alerting.alert import build_anomaly_alert_text
from modules.alerting.sender import ConsoleAlertSender, SlackBotAlertSender, build_alert_sender
from monitor import monitor_once
from main import ConfigError, load_config, run_slack_smoke


class RecordingLLM:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.payloads = []

    def classify_anomaly(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.payloads.append(payload)
        if self.exc:
            raise self.exc
        return self.response or {}


class ClassificationTests(unittest.TestCase):
    def test_uncertain_is_normalized_to_high(self):
        anomaly = Anomaly(1, "explicit_failure", 42, "Orders", "ERROR", 99, "data_sink", "failed", "now")
        evidence = Evidence(health_status="RED", run_status="FAILED", latest_run_id="r1", records_this_run=1, errors_this_run=2, top_error_logs=("boom",))
        result = classify_anomaly(
            anomaly,
            evidence,
            RecordingLLM({"risk_classification": "uncertain", "explanation": "maybe", "recommended_action": "inspect"}),
        )

        self.assertEqual(result.risk_classification, "high")
        self.assertEqual(result.explanation, "maybe")
        self.assertEqual(result.recommended_action, "inspect")

    def test_invalid_or_exception_falls_back_to_unknown_and_raw_message(self):
        anomaly = Anomaly(1, "explicit_failure", 42, "Orders", "ERROR", 99, "flow", "raw failure", "now")

        invalid = classify_anomaly(anomaly, Evidence(), RecordingLLM({"risk_classification": "bogus"}))
        raised = classify_anomaly(anomaly, Evidence(), RecordingLLM(exc=RuntimeError("llm down")))

        for result in (invalid, raised):
            self.assertEqual(result.risk_classification, "unknown")
            self.assertEqual(result.explanation, "raw failure")
            self.assertIn("Review the Nexla notification", result.recommended_action)

    def test_payload_includes_evidence(self):
        llm = RecordingLLM({"risk_classification": "low", "explanation": "ok", "recommended_action": "watch"})
        classify_anomaly(Anomaly(1, "explicit_failure", None, None, None, 7, "data_set", "msg", "now"), Evidence(partial=True), llm)
        self.assertTrue(llm.payloads[0]["evidence"]["partial"])
        self.assertEqual(llm.payloads[0]["resource_id"], 7)


class DetectionAndEnrichmentTests(unittest.TestCase):
    def test_notification_resolves_resource_to_flow_and_unresolved_remains(self):
        class Adapter:
            def resolve_flow(self, resource_type, resource_id):
                return 42 if resource_type == "data_sink" else None
        anomalies = detect_explicit_failures([
            {"id": 1, "resource_id": 99, "resource_type": "data_sink", "message": "failed"},
            {"id": 2, "resource_id": 88, "resource_type": "data_set", "message": "failed"},
        ], Adapter())
        self.assertEqual(anomalies[0].flow_id, 42)
        self.assertEqual(anomalies[0].resource_id, 99)
        self.assertIsNone(anomalies[1].flow_id)

    def test_enricher_happy_and_partial_paths(self):
        class Adapter:
            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1", "latestRecordCount": 10, "latestErrorCount": 2, "errorSummary": "bad"}
            def get_run_status(self, flow_id, run_id):
                return {"status": "FAILED"}
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                self.metrics_request = (flow_id, resource_type, resource_id, run_id)
                return {"records": 10, "errors": 2}
            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return [{"level": "ERROR", "message": "boom", "timestamp": "t"}]
        anomaly = Anomaly(1, "explicit_failure", 42, None, None, 99, "data_sink", "failed", None)
        evidence = enrich_anomaly(anomaly, Adapter())
        self.assertFalse(evidence.partial)
        self.assertEqual(evidence.health_status, "RED")
        self.assertIn("boom", evidence.top_error_logs[0])
        self.assertTrue(enrich_anomaly(Anomaly(1, "explicit_failure", None, None, None, 99, "data_sink", "failed", None), Adapter()).partial)

    def test_health_sweep_dedupes_existing_and_duplicate_flows(self):
        anomalies = detect_unhealthy_flows([{"id": 1}, {"id": 2}, {"id": 2}], {1})
        self.assertEqual([a.flow_id for a in anomalies], [2])

    def test_plain_normalizes_objects(self):
        class Model:
            def __init__(self):
                self.id = 1
        self.assertEqual(_plain(Model()), {"id": 1})

    def test_resource_type_normalizes_for_sdk_metrics(self):
        self.assertEqual(_resource_type_for_metrics("data_sink"), "data_sinks")
        self.assertEqual(_resource_type_for_metrics("DATA_SET"), "data_sets")
        self.assertIsNone(_resource_type_for_metrics("flow"))

    def test_adapter_read_methods_degrade_gracefully(self):
        class Broken:
            def __getattr__(self, name):
                raise RuntimeError("sdk down")
        adapter = NexlaAdapter.__new__(NexlaAdapter)
        setattr(adapter, "_client", type("Client", (), {"flows": Broken(), "metrics": Broken()})())
        self.assertIsNone(adapter.resolve_flow("data_sink", 1))
        self.assertIsNone(adapter.get_flow_health(1))
        self.assertIsNone(adapter.get_run_status(1, "r1"))
        self.assertIsNone(adapter.get_flow_error_logs(1, "r1"))
        self.assertIsNone(adapter.get_run_metrics(1))
        self.assertEqual(adapter.list_unhealthy_flows(), [])

    def test_adapter_extracts_sdk_shaped_read_responses(self):
        calls = []

        class Flows:
            def get_by_resource(self, resource_type, resource_id, flows_only=False):
                calls.append(("get_by_resource", resource_type, resource_id, flows_only))
                return {"flows": [{"id": 1, "origin_node_id": 42}]}

            def get_org_health_flows(self, health_status="RED"):
                calls.append(("get_org_health_flows", health_status))
                return {"data": [{"origin_node_id": 42, "healthStatus": "RED"}]}

            def search_flow_logs(self, flow_id, run_ids=None, severity=None, size=None):
                calls.append(("search_flow_logs", flow_id, run_ids, severity, size))
                return {"logs": [{"level": "ERROR", "message": "boom"}]}

            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": 123}

            def get_run_status(self, flow_id, run_id):
                calls.append(("get_run_status", flow_id, run_id))
                return {"status": "FAILED"}

        class Metrics:
            def get_resource_metrics_by_run(self, resource_type, resource_id, size=None):
                calls.append(("get_resource_metrics_by_run", resource_type, resource_id, size))
                return {"status": 200, "metrics": {"data": [{"runId": 122, "records": 9, "errors": 9}, {"runId": 123, "records": 0, "errors": 2}]}}

        adapter = NexlaAdapter.__new__(NexlaAdapter)
        setattr(adapter, "_client", type("Client", (), {"flows": Flows(), "metrics": Metrics()})())

        self.assertEqual(adapter.resolve_flow("data_sink", 99), 42)
        self.assertEqual(adapter.resolve_flow("flow", 42), 42)
        self.assertEqual(adapter.list_unhealthy_flows(), [{"origin_node_id": 42, "healthStatus": "RED"}])
        self.assertEqual(adapter.get_flow_error_logs(42, 123), [{"level": "ERROR", "message": "boom"}])
        self.assertEqual(adapter.get_run_status(42, "123"), {"status": "FAILED"})
        self.assertEqual(adapter.get_run_metrics(42, "data_sink", 99, 123), {"runId": 123, "records": 0, "errors": 2})
        self.assertIn(("get_by_resource", "data_sinks", 99, False), calls)
        self.assertIn(("get_resource_metrics_by_run", "data_sinks", 99, 25), calls)


class AlertTests(unittest.TestCase):
    def test_alert_includes_classification_explanation_and_action(self):
        anomaly = Anomaly(7, "explicit_failure", 42, "Orders", "ERROR", 99, "flow", "Flow failed", datetime(2026, 1, 1, tzinfo=timezone.utc))
        evidence = Evidence(health_status="RED", run_status="FAILED", latest_run_id="r1", records_this_run=10, errors_this_run=2, top_error_logs=("ERROR boom",))
        classification = classify_anomaly(
            anomaly,
            evidence,
            RecordingLLM({"risk_classification": "high", "explanation": "Destination rejected records", "recommended_action": "Fix credentials"}),
        )

        text = build_anomaly_alert_text(anomaly, evidence, classification)

        self.assertIn('🔴 [HIGH] Flow "Orders" — Explicit Failure', text)
        self.assertIn("Explanation: Destination rejected records", text)
        self.assertIn("Recommended Action: Fix credentials", text)
        self.assertIn("Flow ID: 42", text)
        self.assertIn("Detected: 2026-01-01T00:00:00+00:00", text)
        self.assertIn("Health: RED | Run r1: FAILED | Records/Errors: 10/2", text)
        self.assertIn("Top Error: ERROR boom", text)

    def test_console_alert_sender_prints_text(self):
        output = io.StringIO()
        with redirect_stdout(output):
            ConsoleAlertSender().send("hello alert")

        self.assertEqual(output.getvalue(), "hello alert\n")

    def test_build_alert_sender_defaults_to_console(self):
        self.assertIsInstance(build_alert_sender({}), ConsoleAlertSender)
        self.assertIsInstance(build_alert_sender({"slack": {"enabled": False}}), ConsoleAlertSender)
        self.assertIsInstance(build_alert_sender({"slack": {"enabled": True}}), ConsoleAlertSender)

    def test_build_alert_sender_returns_slack_when_enabled_and_configured(self):
        sender = build_alert_sender(
            {"slack": {"enabled": True, "bot_token": "xoxb-token", "channel_id": "C123", "api_url": "https://slack.test/post"}}
        )

        self.assertIsInstance(sender, SlackBotAlertSender)
        self.assertEqual(sender.bot_token, "xoxb-token")
        self.assertEqual(sender.channel_id, "C123")
        self.assertEqual(sender.api_url, "https://slack.test/post")

    def test_slack_sender_posts_expected_request(self):
        requests = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": true}'

        def fake_urlopen(request):
            requests.append(request)
            return FakeResponse()

        with patch("modules.alerting.sender.urllib.request.urlopen", fake_urlopen):
            SlackBotAlertSender("xoxb-token", "C123", "https://slack.test/post").send("hello slack")

        request = requests[0]
        self.assertEqual(request.full_url, "https://slack.test/post")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.headers["Authorization"], "Bearer xoxb-token")
        self.assertEqual(request.headers["Content-type"], "application/json")
        self.assertEqual(json.loads(request.data.decode("utf-8")), {"channel": "C123", "text": "hello slack"})

    def test_slack_sender_styles_alert_message_for_channel(self):
        requests = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": true}'

        alert_text = "\n".join(
            [
                '🔴 [HIGH] Flow "Orders" — Explicit Failure',
                "━" * 60,
                "Health: RED | Run r1: FAILED | Records/Errors: 10/2",
                "",
                "Explanation: Destination rejected records",
                "Recommended Action: Fix credentials",
                "",
                "Flow ID: 42 | Detected: 2026-01-01T00:00:00+00:00",
            ]
        )

        with patch("modules.alerting.sender.urllib.request.urlopen", lambda request: requests.append(request) or FakeResponse()):
            SlackBotAlertSender("xoxb-token", "C123", "https://slack.test/post").send(alert_text)

        posted_text = json.loads(requests[0].data.decode("utf-8"))["text"]
        self.assertIn('*🔴 [HIGH] Flow "Orders" — Explicit Failure*', posted_text)
        self.assertNotIn("━", posted_text)
        self.assertIn("*Explanation:* Destination rejected records", posted_text)
        self.assertIn("*Recommended Action:* Fix credentials", posted_text)
        self.assertIn("_Flow ID: 42 | Detected: 2026-01-01T00:00:00+00:00_", posted_text)

    def test_slack_sender_raises_when_slack_ok_false(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": false, "error": "channel_not_found"}'

        with patch("modules.alerting.sender.urllib.request.urlopen", lambda request: FakeResponse()):
            with self.assertRaisesRegex(RuntimeError, "channel_not_found"):
                SlackBotAlertSender("xoxb-token", "C123").send("hello slack")


class MonitorTests(unittest.TestCase):
    def test_monitor_classifies_prints_then_marks_read_without_flow_actions(self):
        events = []
        sent_alerts = []

        class RecordingAlertSender:
            def send(self, text):
                sent_alerts.append(text)

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                self.flows = self.ForbiddenFlows()
                events.append(("init_nexla", service_key, api_url))

            class ForbiddenFlows:
                def __getattr__(self, name):
                    raise AssertionError(f"flow action must not be called: {name}")

            def list_unread_notifications(self, from_timestamp=None):
                events.append(("list", from_timestamp))
                return [{"id": 10, "resource_id": 99, "resource_name": "Pipe", "level": "ERROR", "resource_type": "flow", "message": "Failed hard", "created_at": "2026-01-01T00:00:00Z"}]

            def resolve_flow(self, resource_type, resource_id):
                events.append(("resolve", resource_type, resource_id))
                return 42

            def list_unhealthy_flows(self):
                events.append(("health_sweep",))
                return [{"id": 42}, {"id": 77, "name": "No notification", "errorSummary": "red"}]

            def list_flow_volumes(self, day):
                events.append(("volumes", day))
                return []

            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1"}

            def get_run_status(self, flow_id, run_id):
                return {"status": "FAILED"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 0, "errors": 1}

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return [{"level": "ERROR", "message": f"boom {flow_id}"}]

            def mark_notifications_read(self, ids):
                events.append(("mark_read", ids))

        class FakeOpencodeAdapter:
            def __init__(self, model, base_url):
                events.append(("init_llm", model, base_url))

            def classify_anomaly(self, payload):
                events.append(("classify", payload["notification_id"], payload["flow_id"], payload["evidence"]["health_status"]))
                return {"risk_classification": "high", "explanation": "Known failure notification", "recommended_action": "Restart flow"}

        config = {"nexla": {"service_key": "sk", "api_url": "https://api"}, "opencode": {"model": "big-pickle-test", "base_url": "https://opencode.test/v1"}, "monitoring": {"notification_lookback_hours": None, "state_db_path": ":memory:"}}

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch("monitor.OpencodeAdapter", FakeOpencodeAdapter):
            monitor_once(config, alert_sender=RecordingAlertSender())

        self.assertLess(next(i for i, event in enumerate(events) if event[0] == "classify"), next(i for i, event in enumerate(events) if event[0] == "mark_read"))
        self.assertTrue(any("[HIGH]" in alert for alert in sent_alerts))
        self.assertTrue(any("Explanation: Known failure notification" in alert for alert in sent_alerts))
        self.assertTrue(any("Recommended Action: Restart flow" in alert for alert in sent_alerts))
        self.assertEqual(events[-1], ("mark_read", [10]))
        self.assertIn(("classify", 0, 77, "RED"), events)


class ConfigTests(unittest.TestCase):
    def test_load_config_reads_env_file_next_to_config(self):
        old_value = os.environ.pop("PIPELINE_MONITOR_TEST_SECRET", None)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                config_path = os.path.join(tmpdir, "config.yaml")
                with open(os.path.join(tmpdir, ".env"), "w", encoding="utf-8") as env_file:
                    env_file.write("PIPELINE_MONITOR_TEST_SECRET=from-dotenv\n")
                with open(config_path, "w", encoding="utf-8") as config_file:
                    config_file.write('nexla:\n  service_key: "${PIPELINE_MONITOR_TEST_SECRET}"\n')

                self.assertEqual(load_config(config_path)["nexla"]["service_key"], "from-dotenv")
        finally:
            if old_value is not None:
                os.environ["PIPELINE_MONITOR_TEST_SECRET"] = old_value

    def test_slack_smoke_requires_enabled_and_configured_slack(self):
        with self.assertRaisesRegex(ConfigError, "slack.enabled"):
            run_slack_smoke({"slack": {"enabled": False, "bot_token": "xoxb", "channel_id": "C123"}})

        with self.assertRaisesRegex(ConfigError, "Slack smoke test bot token"):
            run_slack_smoke({"slack": {"enabled": True, "bot_token": "", "channel_id": "C123"}})

        with self.assertRaisesRegex(ConfigError, "Slack smoke test channel ID"):
            run_slack_smoke({"slack": {"enabled": True, "bot_token": "xoxb", "channel_id": ""}})

    def test_slack_smoke_sends_one_safe_message(self):
        sent = []

        class RecordingSender:
            def send(self, text):
                sent.append(text)

        with patch("main.build_alert_sender", return_value=RecordingSender()):
            output = io.StringIO()
            with redirect_stdout(output):
                run_slack_smoke({"slack": {"enabled": True, "bot_token": "xoxb", "channel_id": "C123"}})

        self.assertEqual(sent, ["Pipeline monitor Slack smoke test passed."])
        self.assertIn("Slack smoke test passed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
