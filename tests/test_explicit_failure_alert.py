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
from modules.enrichment.enricher import Evidence, enrich_anomaly, _short_log
from modules.classification.classifier import classify_anomaly
from modules.alerting.alert import build_anomaly_alert_text, _logs_status
from modules.alerting.sender import ConsoleAlertSender, SlackBotAlertSender, build_alert_sender
from modules.controls.policy import ControlMetadata
from monitor import monitor_once, scan_flow
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

    def test_invalid_or_exception_falls_back_to_high_for_real_anomalies(self):
        anomaly = Anomaly(1, "explicit_failure", 42, "Orders", "ERROR", 99, "flow", "raw failure", "now")

        invalid = classify_anomaly(anomaly, Evidence(), RecordingLLM({"risk_classification": "bogus"}))
        raised = classify_anomaly(anomaly, Evidence(), RecordingLLM(exc=RuntimeError("llm down")))

        # A real detected Anomaly fails safe to high so a transient LLM outage escalates it.
        for result in (invalid, raised):
            self.assertEqual(result.risk_classification, "high")
            self.assertEqual(result.explanation, "raw failure")
            self.assertIn("Review the Nexla notification", result.recommended_action)

    def test_fallback_stays_unknown_for_clean_targeted_scan(self):
        # A targeted scan that found no Anomaly has nothing to escalate on LLM failure.
        anomaly = Anomaly(0, "flow_scan", 42, "Orders", "INFO", None, "flow", "no anomaly", "now")
        result = classify_anomaly(anomaly, Evidence(), RecordingLLM(exc=RuntimeError("llm down")))
        self.assertEqual(result.risk_classification, "unknown")

    def test_payload_includes_evidence(self):
        llm = RecordingLLM({"risk_classification": "low", "explanation": "ok", "recommended_action": "watch"})
        classify_anomaly(
            Anomaly(
                1,
                "explicit_failure",
                None,
                None,
                None,
                7,
                "data_set",
                "msg",
                "now",
                owner_name="Naelio Freires",
                owner_email="naelio.freires@nexla.com",
                org_name="Nexla Eng: GCP",
                access_roles=("owner",),
            ),
            Evidence(partial=True, recent_run_count=3, avg_records_previous_runs=100.0, latest_records_from_summary=25, record_drop_pct=75.0, latest_errors_from_summary=2, consecutive_failed_runs=1, recent_run_log_check="anomalies_found: Nexla ERROR logs were found for the latest/recent runs"),
            llm,
        )
        self.assertTrue(llm.payloads[0]["evidence"]["partial"])
        self.assertEqual(llm.payloads[0]["evidence"]["recent_run_count"], 3)
        self.assertEqual(llm.payloads[0]["evidence"]["record_drop_pct"], 75.0)
        self.assertEqual(llm.payloads[0]["evidence"]["consecutive_failed_runs"], 1)
        self.assertEqual(llm.payloads[0]["evidence"]["recent_run_log_check"], "anomalies_found: Nexla ERROR logs were found for the latest/recent runs")
        self.assertEqual(llm.payloads[0]["resource_id"], 7)
        self.assertEqual(llm.payloads[0]["owner_name"], "Naelio Freires")
        self.assertEqual(llm.payloads[0]["owner_email"], "naelio.freires@nexla.com")
        self.assertEqual(llm.payloads[0]["org_name"], "Nexla Eng: GCP")
        self.assertEqual(llm.payloads[0]["access_roles"], ["owner"])


class DetectionAndEnrichmentTests(unittest.TestCase):
    def test_targeted_scan_uses_flows_get_fallback_shape(self):
        class FakeLLM:
            def classify_anomaly(self, payload):
                self.payload = payload
                return {"risk_classification": "low", "explanation": "Flow appears healthy.", "recommended_action": "No action needed."}

        class FakeNexlaAdapter:
            instances = []
            def __init__(self, service_key, api_url=None):
                self.calls = []
                FakeNexlaAdapter.instances.append(self)
            def get_flow(self, flow_id):
                return {
                    "flows": [{"id": 627808, "origin_node_id": 627808, "data_source_id": 124463, "status": "ACTIVE", "runtime_status": "IDLE", "name": "Orders Flow", "last_run_id": 1782495141188}],
                    "data_sources": [{"id": 124463, "flow_node_id": 627808, "origin_node_id": 627808, "status": "ACTIVE", "runtime_status": "IDLE", "last_run_id": 1782495141188}],
                    "data_sets": [],
                    "metrics": None,
                }
            def get_flow_health(self, flow_id):
                return {"status": 200}
            def list_flow_volumes(self):
                return []
            def get_run_status(self, flow_id, run_id):
                self.calls.append(("status", flow_id, run_id))
                return {"status": "IDLE"}
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                self.calls.append(("metrics", flow_id, resource_type, resource_id, run_id))
                return {"records": 12, "errors": 0}
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                self.calls.append(("summary", flow_id, resource_type, resource_id, run_id))
                return []
            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                self.calls.append(("logs", flow_id, tuple(run_id) if isinstance(run_id, list) else run_id, limit))
                return []

        llm = FakeLLM()
        config = {"nexla": {"service_key": "secret"}, "monitoring": {"state_db_path": ":memory:"}}
        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch("monitor.build_llm_adapter", return_value=llm):
            text = scan_flow(config, 627808)

        adapter = FakeNexlaAdapter.instances[0]
        self.assertIn("Orders Flow", text)
        self.assertIn("Status     : ACTIVE", text)
        self.assertNotIn("Health     : ACTIVE", text)
        self.assertIn("Health     : unknown", text)
        self.assertIn("1782495141188", text)
        self.assertIn(("status", 627808, 1782495141188), adapter.calls)
        self.assertIn(("metrics", 627808, "data_source", 124463, 1782495141188), adapter.calls)
        self.assertIn(("summary", 627808, "data_source", 124463, 1782495141188), adapter.calls)
        self.assertIn(("logs", 627808, (1782495141188,), 5), adapter.calls)
        self.assertEqual(llm.payload["resource_type"], "data_source")
        self.assertEqual(llm.payload["resource_id"], 124463)
        self.assertIsNone(llm.payload["evidence"]["health_status"])
        self.assertEqual(llm.payload["evidence"]["flow_status"], "ACTIVE")
        self.assertNotEqual(llm.payload["evidence"]["flow_status"], "200")

    def test_targeted_scan_uses_latest_available_metrics_when_last_run_absent(self):
        class FakeLLM:
            def classify_anomaly(self, payload):
                self.payload = payload
                return {"risk_classification": "low", "explanation": "Using latest available metrics.", "recommended_action": "Review if needed."}

        class FakeNexlaAdapter:
            instances = []
            def __init__(self, service_key, api_url=None):
                FakeNexlaAdapter.instances.append(self)
            def get_flow(self, flow_id):
                return {"flows": [{"id": flow_id, "origin_node_id": flow_id, "data_source_id": 122875, "status": "ACTIVE", "name": "Orders Flow", "last_run_id": 1782738276439}]}
            def get_flow_health(self, flow_id): return None
            def list_flow_volumes(self): return []
            def get_run_status(self, flow_id, run_id): return None
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None): return None
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return [
                    {"runId": "1782737400000", "records": 44, "errors": 2, "status": "SUCCEEDED"},
                    {"runId": "1782736500000", "records": 20, "errors": 0, "status": "SUCCEEDED"},
                ]
            def get_flow_error_logs(self, flow_id, run_id, limit=5): return []

        llm = FakeLLM()
        config = {"nexla": {"service_key": "secret"}, "monitoring": {"state_db_path": ":memory:"}}
        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch("monitor.build_llm_adapter", return_value=llm):
            text = scan_flow(config, 627808)

        self.assertIn("Metrics Run: 1782737400000 (latest available; Flow last_run_id is 1782738276439)", text)
        self.assertIn("Latest Run : 1782737400000 (SUCCEEDED)", text)
        self.assertIn("Records    : 44", text)
        self.assertIn("Errors     : 2", text)
        self.assertEqual(llm.payload["evidence"]["latest_run_id"], "1782737400000")
        self.assertEqual(llm.payload["evidence"]["records_this_run"], 44)

    def test_notification_resolves_resource_to_flow_and_unresolved_remains(self):
        class Adapter:
            def resolve_flow(self, resource_type, resource_id):
                return 42 if resource_type == "data_sink" else None
        anomalies = detect_explicit_failures([
            {
                "id": 1,
                "level": "ERROR",
                "resource_id": 99,
                "resource_type": "data_sink",
                "message": "failed",
                "owner": {"full_name": "Naelio Freires", "email": "naelio.freires@nexla.com"},
                "org": {"name": "Nexla Eng: GCP"},
                "access_roles": ["owner"],
                "created_at": "2026-06-30T00:55:09.000Z",
                "read_at": "2026-06-30T00:58:11.000Z",
                "updated_at": "2026-06-30T00:55:09.000Z",
            },
            {"id": 2, "level": "ERROR", "resource_id": 88, "resource_type": "data_set", "message": "failed"},
        ], Adapter())
        self.assertEqual(anomalies[0].flow_id, 42)
        self.assertEqual(anomalies[0].resource_id, 99)
        self.assertEqual(anomalies[0].owner_name, "Naelio Freires")
        self.assertEqual(anomalies[0].owner_email, "naelio.freires@nexla.com")
        self.assertEqual(anomalies[0].org_name, "Nexla Eng: GCP")
        self.assertEqual(anomalies[0].access_roles, ("owner",))
        self.assertEqual(anomalies[0].created_at, "2026-06-30T00:55:09.000Z")
        self.assertEqual(anomalies[0].read_at, "2026-06-30T00:58:11.000Z")
        self.assertIsNone(anomalies[1].flow_id)

    def test_info_notification_is_not_an_explicit_failure(self):
        anomalies = detect_explicit_failures([
            {
                "id": 29190013,
                "level": "INFO",
                "resource_id": 124611,
                "resource_type": "SOURCE",
                "message": 'A new Nexset <a href="https://dataops.nexla.io/datasets/432028">432028</a> was detected while scanning source <a href="https://dataops.nexla.io/sources/124611">CSV_records</a>',
                "owner": {"full_name": "Naelio Freires", "email": "naelio.freires@nexla.com"},
                "org": {"name": "Nexla Eng: GCP"},
                "access_roles": ["owner"],
                "created_at": "2026-06-30T02:30:26.000Z",
            }
        ])

        self.assertEqual(anomalies, [])

    def test_enricher_happy_and_partial_paths(self):
        class Adapter:
            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1", "latestRecordCount": 10, "latestErrorCount": 2, "errorSummary": "bad"}
            def get_run_status(self, flow_id, run_id):
                return {"status": "FAILED"}
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                self.metrics_request = (flow_id, resource_type, resource_id, run_id)
                return {"records": 10, "errors": 2}
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return [
                    {"runId": "r1", "records": 10, "errors": 2, "status": "FAILED"},
                    {"runId": "r0", "records": 100, "errors": 0, "status": "SUCCEEDED"},
                    {"runId": "r-1", "records": 80, "errors": 0, "status": "SUCCEEDED"},
                ]
            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return [{"level": "ERROR", "message": "boom", "timestamp": "t"}]
        anomaly = Anomaly(1, "explicit_failure", 42, None, None, 99, "data_sink", "failed", None)
        evidence = enrich_anomaly(anomaly, Adapter())
        self.assertFalse(evidence.partial)
        self.assertEqual(evidence.health_status, "RED")
        self.assertIn("boom", evidence.top_error_logs[0])
        self.assertEqual(evidence.recent_run_count, 3)
        self.assertEqual(evidence.avg_records_previous_runs, 90.0)
        self.assertEqual(evidence.latest_records_from_summary, 10)
        self.assertEqual(evidence.record_drop_pct, 88.89)
        self.assertEqual(evidence.latest_errors_from_summary, 2)
        self.assertEqual(evidence.consecutive_failed_runs, 1)
        self.assertEqual(evidence.recent_run_log_check, "anomalies_found: Nexla ERROR logs were found for the latest/recent runs")
        self.assertTrue(enrich_anomaly(Anomaly(1, "explicit_failure", None, None, None, 99, "data_sink", "failed", None), Adapter()).partial)

    def test_enricher_ignores_optional_run_summary_failure(self):
        class Adapter:
            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1"}
            def get_run_status(self, flow_id, run_id):
                return {"status": "FAILED"}
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 10, "errors": 2}
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                raise RuntimeError("optional endpoint down")
            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return []
        evidence = enrich_anomaly(Anomaly(1, "explicit_failure", 42, None, None, 99, "data_sink", "failed", None), Adapter())
        self.assertFalse(evidence.partial)
        self.assertIsNone(evidence.recent_run_count)
        self.assertEqual(evidence.recent_run_log_check, "none_found: no Nexla ERROR log anomalies were found for the latest/recent runs")

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
        self.assertIsNone(adapter.get_run_summary(1, "data_sink", 1))
        self.assertEqual(adapter.list_unhealthy_flows(), [])

    def test_adapter_extracts_sdk_shaped_read_responses(self):
        calls = []

        class Flows:
            def get_by_resource(self, resource_type, resource_id, flows_only=False):
                calls.append(("get_by_resource", resource_type, resource_id, flows_only))
                return {"flows": [{"id": 1, "origin_node_id": 42}]}

            def get_org_health_flows(self):
                # Real prod shape: rows nested under metrics.data, camelCase fields, no
                # health_status param (the API rejects it). Adapter filters RED client-side.
                calls.append(("get_org_health_flows",))
                return {"status": 200, "metrics": {"data": [
                    {"originNodeId": 42, "healthStatus": "RED", "latestRecordCount": 0},
                    {"originNodeId": 7, "healthStatus": "GREEN", "latestRecordCount": 10},
                ]}}

            def search_flow_logs(self, flow_id, run_ids=None, severity=None, size=None):
                calls.append(("search_flow_logs", flow_id, run_ids, severity, size))
                return {"logs": [{"level": "ERROR", "message": "boom"}]}

            def get_flow_health(self, flow_id):
                # Real shape: health nested under metrics, run fields under affectedResources.
                return {"status": 200, "metrics": {"originNodeId": 42, "healthStatus": "RED", "affectedResources": [
                    {"resourceType": "SOURCE", "resourceId": 99, "status": "ERROR", "latestRunId": 123, "latestRecordCount": 0, "latestErrorCount": 2, "errorSummary": None},
                ]}}

            def get_run_status(self, flow_id, run_id):
                calls.append(("get_run_status", flow_id, run_id))
                return {"status": "FAILED"}

        class Metrics:
            def get_resource_metrics_by_run(self, resource_type, resource_id, groupby=None, orderby=None, size=None):
                calls.append(("get_resource_metrics_by_run", resource_type, resource_id, groupby, orderby, size))
                return {"status": 200, "metrics": {"data": [{"runId": 122, "records": 9, "errors": 9}, {"runId": 123, "records": 0, "errors": 2}]}}

            def get_resource_run_summary(self, resource_type, resource_id, size=None):
                calls.append(("get_resource_run_summary", resource_type, resource_id, size))
                return {"status": 200, "run_summary": {"data": [{"runId": 123, "records": 0, "errors": 2, "status": "FAILED"}, {"runId": 122, "records": 9, "errors": 9, "status": "SUCCEEDED"}]}}

        adapter = NexlaAdapter.__new__(NexlaAdapter)
        setattr(adapter, "_client", type("Client", (), {"flows": Flows(), "metrics": Metrics()})())

        self.assertEqual(adapter.resolve_flow("data_sink", 99), 42)
        self.assertEqual(adapter.resolve_flow("flow", 42), 42)
        self.assertEqual(adapter.list_unhealthy_flows(), [{"originNodeId": 42, "healthStatus": "RED", "latestRecordCount": 0}])
        health = adapter.get_flow_health(42)
        self.assertEqual(health["healthStatus"], "RED")
        self.assertEqual(health["latestRunId"], 123)        # lifted from the SOURCE affectedResource
        self.assertEqual(health["latestRecordCount"], 0)
        self.assertEqual(health["latestErrorCount"], 2)
        self.assertEqual(adapter.get_flow_error_logs(42, 123), [{"level": "ERROR", "message": "boom"}])
        self.assertEqual(adapter.get_run_status(42, "123"), {"status": "FAILED"})
        self.assertEqual(adapter.get_run_metrics(42, "data_sink", 99, 123), {"runId": 123, "records": 0, "errors": 2})
        self.assertEqual(adapter.get_run_summary(42, "data_sink", 99, 123), [{"runId": 123, "records": 0, "errors": 2, "status": "FAILED"}, {"runId": 122, "records": 9, "errors": 9, "status": "SUCCEEDED"}])
        self.assertIn(("get_by_resource", "data_sinks", 99, False), calls)
        self.assertIn(("get_resource_metrics_by_run", "data_sinks", 99, "runId", "runId", 25), calls)
        self.assertIn(("get_resource_run_summary", "data_sinks", 99, 25), calls)


class AlertTests(unittest.TestCase):
    def test_alert_includes_classification_explanation_and_action(self):
        anomaly = Anomaly(
            7,
            "explicit_failure",
            42,
            "Orders",
            "ERROR",
            99,
            "SOURCE",
            "Flow failed",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            owner_name="Naelio Freires",
            owner_email="naelio.freires@nexla.com",
            org_name="Nexla Eng: GCP",
            access_roles=("owner",),
            read_at="2026-01-01T00:05:00+00:00",
            updated_at="2026-01-01T00:01:00+00:00",
        )
        evidence = Evidence(health_status="RED", run_status="FAILED", latest_run_id="r1", records_this_run=10, errors_this_run=2, top_error_logs=("ERROR boom",))
        classification = classify_anomaly(
            anomaly,
            evidence,
            RecordingLLM({"risk_classification": "high", "explanation": "Destination rejected records", "recommended_action": "Fix credentials"}),
        )

        text = build_anomaly_alert_text(anomaly, evidence, classification)

        self.assertIn("🚦 Flow Health Status | ID: 42", text)
        self.assertIn("*Flow:* Orders", text)
        self.assertIn("*Risk Level:* 🔴 HIGH (Explicit Failure)", text)
        self.assertIn("*Explanation:* Destination rejected records", text)
        self.assertIn("*Next Steps:*\n🔹 Fix credentials", text)
        self.assertIn("Flow ID: 42", text)
        self.assertIn("Detected: 2026-01-01T00:00:00+00:00", text)
        self.assertIn("Notification Evidence:\n```", text)
        self.assertIn("Notification: 7 | Level: ERROR | Created: 2026-01-01T00:00:00+00:00", text)
        self.assertIn("Resource: SOURCE 99 | Owner: Naelio Freires <naelio.freires@nexla.com>", text)
        self.assertIn("Org: Nexla Eng: GCP | Access Roles: owner", text)
        self.assertIn("Read: 2026-01-01T00:05:00+00:00 | Updated: 2026-01-01T00:01:00+00:00", text)
        self.assertIn("*Scan Result:*\n```", text)
        self.assertIn("Health     : RED", text)
        self.assertIn("Status     : unknown", text)
        self.assertIn("Latest Run : r1 (FAILED)", text)
        self.assertIn("Records    : 10", text)
        self.assertIn("Errors     : 2", text)
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
            {"slack": {"enabled": True, "bot_token": "xoxb-token", "channel_id": "C123", "api_url": "https://slack.test/post", "flow_url_template": "https://dataops.nexla.io/flows/{flow_id}"}}
        )

        self.assertIsInstance(sender, SlackBotAlertSender)
        self.assertEqual(sender.bot_token, "xoxb-token")
        self.assertEqual(sender.channel_id, "C123")
        self.assertEqual(sender.api_url, "https://slack.test/post")
        self.assertEqual(sender.flow_url_template, "https://dataops.nexla.io/flows/{flow_id}")

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
                "Notification: 29194317 | Level: ERROR | Created: 2026-06-30T10:55:38+00:00",
                "Resource: SOURCE 124542 | Owner: Naelio Freires <naelio.freires@nexla.com>",
                "Org: Nexla Eng: GCP | Access Roles: owner",
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

        payload = json.loads(requests[0].data.decode("utf-8"))
        posted_text = payload["text"]
        block_text = payload["blocks"][0]["text"]
        self.assertIn('*🔴 [HIGH] Flow "Orders" — Explicit Failure*', posted_text)
        self.assertNotIn("━", posted_text)
        self.assertIn("*Enrichment Log*", posted_text)
        self.assertIn("```\nNotification: 29194317 | Level: ERROR | Created: 2026-06-30T10:55:38+00:00", posted_text)
        self.assertIn("Resource: SOURCE 124542 | Owner: Naelio Freires <naelio.freires@nexla.com>", posted_text)
        self.assertIn("Org: Nexla Eng: GCP | Access Roles: owner\n```", posted_text)
        self.assertIn("*Explanation:* Destination rejected records", posted_text)
        self.assertIn("*Recommended Action:* Fix credentials", posted_text)
        self.assertIn("_Flow ID: 42 | Detected: 2026-01-01T00:00:00+00:00_", posted_text)
        self.assertEqual(block_text["type"], "mrkdwn")
        self.assertEqual(block_text["text"], posted_text)

    def test_slack_sender_converts_html_anchor_links_to_mrkdwn_links(self):
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
                '⚪ [UNKNOWN] Flow "628329" — Explicit Failure',
                "━" * 60,
                'Message: Errors were observed for Source <a href=\\"https://dataops.nexla.io/sources/124542\\">web-hook-test</a> (Source ID: <a href=\\"https://dataops.nexla.io/sources/124542\\">124542</a>).',
                "",
                "Explanation: Review source details",
                "Recommended Action: Review the Nexla notification and flow run details before taking action.",
                "",
                "Flow ID: unknown | Detected: unknown time",
            ]
        )

        with patch("modules.alerting.sender.urllib.request.urlopen", lambda request: requests.append(request) or FakeResponse()):
            SlackBotAlertSender("xoxb-token", "C123", "https://slack.test/post").send(alert_text)

        payload = json.loads(requests[0].data.decode("utf-8"))
        posted_text = payload["text"]
        visible_text = payload["blocks"][0]["text"]
        self.assertEqual(visible_text["type"], "mrkdwn")
        self.assertIn("<https://dataops.nexla.io/sources/124542|web-hook-test>", visible_text["text"])
        self.assertIn("<https://dataops.nexla.io/sources/124542|124542>", visible_text["text"])
        self.assertIn("<https://dataops.nexla.io/sources/124542|web-hook-test>", posted_text)
        self.assertIn("<https://dataops.nexla.io/sources/124542|124542>", posted_text)
        self.assertNotIn("<a href=", posted_text)

    def test_slack_sender_adds_open_flow_button_with_configured_url(self):
        requests = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": true}'

        with patch("modules.alerting.sender.urllib.request.urlopen", lambda request: requests.append(request) or FakeResponse()):
            SlackBotAlertSender(
                "xoxb-token",
                "C123",
                "https://slack.test/post",
                controls_config={"enabled": False},
                flow_url_template="https://dataops.nexla.io/flows/{flow_id}",
            ).send("Flow Alert", ControlMetadata(flow_id=42, flow_name="Orders"))

        payload = json.loads(requests[0].data.decode("utf-8"))
        actions = payload["blocks"][1]
        self.assertEqual(actions["type"], "actions")
        self.assertEqual(actions["elements"][0]["type"], "button")
        self.assertEqual(actions["elements"][0]["text"], {"type": "plain_text", "text": "Open Flow"})
        self.assertEqual(actions["elements"][0]["url"], "https://dataops.nexla.io/flows/42")

    def test_slack_sender_omits_open_flow_button_without_template_or_flow_id(self):
        requests = []

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": true}'

        with patch("modules.alerting.sender.urllib.request.urlopen", lambda request: requests.append(request) or FakeResponse()):
            SlackBotAlertSender("xoxb-token", "C123", "https://slack.test/post", flow_url_template="").send(
                "Flow Alert", ControlMetadata(flow_id=42)
            )
            SlackBotAlertSender("xoxb-token", "C123", "https://slack.test/post", flow_url_template="https://dataops.nexla.io/flows/{flow_id}").send(
                "Flow Alert", ControlMetadata(flow_id=None)
            )

        for request in requests:
            payload = json.loads(request.data.decode("utf-8"))
            elements = [element for block in payload.get("blocks", []) if block.get("type") == "actions" for element in block.get("elements", [])]
            self.assertFalse(any(element.get("text", {}).get("text") == "Open Flow" for element in elements))

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

            def list_flow_volumes(self):
                events.append(("volumes",))
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
            def classify_anomaly(self, payload):
                events.append(("classify", payload["notification_id"], payload["flow_id"], payload["evidence"]["health_status"]))
                return {"risk_classification": "high", "explanation": "Known failure notification", "recommended_action": "Restart flow"}

        config = {"nexla": {"service_key": "sk", "api_url": "https://api"}, "opencode": {"model": "big-pickle-test", "base_url": "https://opencode.test/v1"}, "monitoring": {"notification_lookback_hours": None, "state_db_path": ":memory:"}}

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch("monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()):
            monitor_once(config, alert_sender=RecordingAlertSender())

        self.assertLess(next(i for i, event in enumerate(events) if event[0] == "classify"), next(i for i, event in enumerate(events) if event[0] == "mark_read"))
        self.assertTrue(any("*Risk Level:* 🔴 HIGH" in alert for alert in sent_alerts))
        self.assertTrue(any("*Explanation:* Known failure notification" in alert for alert in sent_alerts))
        self.assertTrue(any("*Next Steps:*\n🔹 Restart flow" in alert for alert in sent_alerts))
        self.assertEqual(events[-1], ("mark_read", [10]))
        self.assertIn(("classify", 0, 77, "RED"), events)

    def test_monitor_does_not_mark_notification_read_when_sender_fails(self):
        events = []

        class FailingAlertSender:
            def send(self, *args):
                events.append(("send",))
                raise RuntimeError("sender down")

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return [{"id": 10, "resource_id": 42, "resource_name": "Pipe", "level": "ERROR", "resource_type": "flow", "message": "Failed hard"}]

            def resolve_flow(self, resource_type, resource_id):
                return 42

            def list_unhealthy_flows(self):
                return []

            def list_flow_volumes(self):
                return []

            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1"}

            def get_run_status(self, flow_id, run_id):
                return {"status": "FAILED"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 0, "errors": 1}

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return [{"level": "ERROR", "message": "boom"}]

            def mark_notifications_read(self, ids):
                events.append(("mark_read", ids))

        class FakeOpencodeAdapter:
            def classify_anomaly(self, payload):
                return {"risk_classification": "high", "explanation": "Known failure", "recommended_action": "Inspect flow"}

        config = {"nexla": {"service_key": "sk"}, "monitoring": {"notification_lookback_hours": None, "state_db_path": ":memory:"}}

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch("monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()):
            monitor_once(config, alert_sender=FailingAlertSender())

        self.assertIn(("send",), events)
        self.assertEqual(events[-1], ("mark_read", []))

    def test_monitor_ignores_info_notification_but_still_runs_health_sweep(self):
        events = []

        class RecordingAlertSender:
            def send(self, text, *args):
                events.append(("send", text))

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return [
                    {
                        "id": 29190013,
                        "level": "INFO",
                        "resource_id": 124611,
                        "resource_type": "SOURCE",
                        "resource_name": "CSV_records",
                        "message": "A new Nexset was detected while scanning source CSV_records",
                    }
                ]

            def resolve_flow(self, resource_type, resource_id):
                raise AssertionError("INFO notifications should not be resolved as Explicit Failures")

            def list_unhealthy_flows(self):
                events.append(("health_sweep",))
                return [{"id": 42, "name": "CSV_records Flow", "errorSummary": "red"}]

            def list_flow_volumes(self):
                events.append(("volumes",))
                return []

            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1"}

            def get_run_status(self, flow_id, run_id):
                return {"status": "FAILED"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 0, "errors": 1}

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return [{"level": "ERROR", "message": "boom"}]

            def mark_notifications_read(self, ids):
                events.append(("mark_read", ids))

        class FakeOpencodeAdapter:
            def classify_anomaly(self, payload):
                events.append(("classify", payload["notification_id"], payload["type"], payload["flow_id"]))
                return {"risk_classification": "high", "explanation": "Flow is RED", "recommended_action": "Inspect flow"}

        config = {"nexla": {"service_key": "sk"}, "monitoring": {"notification_lookback_hours": None, "state_db_path": ":memory:"}}

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch("monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()):
            monitor_once(config, alert_sender=RecordingAlertSender())

        self.assertIn(("health_sweep",), events)
        self.assertIn(("classify", 0, "health_sweep", 42), events)
        self.assertEqual(events[-1], ("mark_read", [29190013]))
        self.assertTrue(any(event[0] == "send" and "Health Sweep" in event[1] for event in events))


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


class LogsStatusTests(unittest.TestCase):
    def test_logs_line_reflects_log_check_not_partial(self):
        # Log read succeeded (no ERROR logs) while other Evidence is partial: must NOT say
        # "read failed" — that conflated a missing run status with a failed log read.
        none_found = Evidence(partial=True, recent_run_log_check="none_found: no Nexla ERROR log anomalies were found for the latest/recent runs")
        self.assertEqual(_logs_status(none_found), "No error log lines found; errors=?")

        inconclusive = Evidence(partial=True, recent_run_log_check="inconclusive: unable to check Nexla ERROR logs for the latest/recent runs")
        self.assertEqual(_logs_status(inconclusive), "Inconclusive (log read failed)")

        found = Evidence(top_error_logs=("ERROR boom",), partial=True, recent_run_log_check="anomalies_found: ...")
        self.assertEqual(_logs_status(found), "Available")

        # No log-check signal at all falls back to the overall partial flag.
        self.assertEqual(_logs_status(Evidence(partial=True)), "Inconclusive (read failed)")

    def test_evidence_not_partial_when_run_status_unavailable_but_core_data_read(self):
        # Nexla's API returns no run lifecycle status (get_run_status -> []), so run_status is
        # None on most flows. With health, run id, counts, and logs all read, Evidence must NOT
        # be flagged partial just because run_status is missing — that warning would cry wolf.
        class Adapter:
            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1", "latestRecordCount": 3, "latestErrorCount": 4}
            def get_run_status(self, flow_id, run_id):
                return None  # API returned [] -> adapter None
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return None  # flow-level anomaly: no single resource
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return None
            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return [{"severity": "ERROR", "log": "boom", "timestamp": 1}]
        evidence = enrich_anomaly(Anomaly(0, "health_sweep", 42, None, "ERROR", None, "flow", "x", None), Adapter())
        self.assertFalse(evidence.partial)
        self.assertEqual(evidence.records_this_run, 3)
        self.assertEqual(evidence.errors_this_run, 4)

    def test_evidence_partial_when_no_run_volume_at_all(self):
        class Adapter:
            def get_flow_health(self, flow_id):
                return {"healthStatus": "RED", "latestRunId": "r1"}  # no counts anywhere
            def get_run_status(self, flow_id, run_id):
                return None
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return None
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return None
            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return []
        evidence = enrich_anomaly(Anomaly(0, "health_sweep", 42, None, "ERROR", None, "flow", "x", None), Adapter())
        self.assertTrue(evidence.partial)

    def test_short_log_reads_nexla_log_and_severity_fields(self):
        entry = {"timestamp": 1782495562877, "severity": "ERROR", "log": "4 records failed. Too many entries", "resource_id": 124462}
        rendered = _short_log(entry)
        self.assertIn("ERROR", rendered)
        self.assertIn("4 records failed. Too many entries", rendered)


class AdapterResilienceTests(unittest.TestCase):
    def test_get_flow_falls_back_to_raw_request_on_sdk_validation_error(self):
        # The SDK's strict FlowResponse model rejects e.g. a null data-credential name and
        # raises a pydantic ValidationError; get_flow must fall back to the raw API payload
        # instead of failing the whole scan.
        calls = []

        class Flows:
            def get(self, flow_id, flows_only=False, include_run_metrics=False):
                raise ValueError("2 validation errors for FlowResponse: data_credentials.0.name")

        class Client:
            flows = Flows()

            def request(self, method, path, params=None):
                calls.append((method, path, params))
                return {"flows": [{"id": 588132, "name": "Random User API", "status": "ACTIVE", "data_source_id": 118379}]}

        adapter = NexlaAdapter.__new__(NexlaAdapter)
        setattr(adapter, "_client", Client())
        flow = adapter.get_flow(588132)
        self.assertEqual(flow["flows"][0]["name"], "Random User API")
        self.assertEqual(flow["flows"][0]["id"], 588132)
        self.assertEqual(calls, [("GET", "/flows/588132", {"flows_only": 0})])

    def test_get_flow_returns_none_when_raw_request_also_fails(self):
        class Flows:
            def get(self, flow_id, flows_only=False, include_run_metrics=False):
                raise ValueError("validation error")

        class Client:
            flows = Flows()

            def request(self, method, path, params=None):
                raise RuntimeError("network down")

        adapter = NexlaAdapter.__new__(NexlaAdapter)
        setattr(adapter, "_client", Client())
        self.assertIsNone(adapter.get_flow(588132))


if __name__ == "__main__":
    unittest.main()
