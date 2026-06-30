from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from modules.detection.anomaly import Anomaly
from modules.suppression.suppression import is_blocked, note_alerted, should_alert
from repositories.suppression_repository import SuppressionRepository
from monitor import monitor_once


def _health_anomaly(flow_id: int) -> Anomaly:
    return Anomaly(0, "health_sweep", flow_id, "Flow", "ERROR", None, "flow", "Flow health is RED", None)


class SuppressionRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repo = SuppressionRepository(":memory:")
        self.addCleanup(self.repo.close)
        self.now = datetime(2026, 6, 27, 12, 0, tzinfo=timezone.utc)

    def test_record_then_suppressed_within_window_and_clear_after(self):
        self.assertFalse(self.repo.is_suppressed(42, "health_sweep", self.now))
        self.repo.record_alert(42, "health_sweep", self.now, self.now + timedelta(hours=2))

        self.assertTrue(self.repo.is_suppressed(42, "health_sweep", self.now + timedelta(hours=1)))
        self.assertFalse(self.repo.is_suppressed(42, "health_sweep", self.now + timedelta(hours=3)))

    def test_suppression_is_scoped_per_flow_and_type(self):
        self.repo.record_alert(42, "health_sweep", self.now, self.now + timedelta(hours=2))
        self.assertFalse(self.repo.is_suppressed(99, "health_sweep", self.now))
        self.assertFalse(self.repo.is_suppressed(42, "explicit_failure", self.now))

    def test_purge_expired_removes_only_elapsed_rows(self):
        self.repo.record_alert(1, "health_sweep", self.now, self.now + timedelta(hours=2))
        self.repo.record_alert(2, "health_sweep", self.now, self.now - timedelta(hours=1))
        removed = self.repo.purge_expired(self.now)
        self.assertEqual(removed, 1)
        self.assertTrue(self.repo.is_suppressed(1, "health_sweep", self.now))


class SuppressionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.repo = SuppressionRepository(":memory:")
        self.addCleanup(self.repo.close)
        self.now = datetime(2026, 6, 27, 12, 0, tzinfo=timezone.utc)

    def test_blocklisted_flow_is_not_alerted(self):
        blocklist = [{"flow_id": 42, "reason": "noisy"}]
        self.assertTrue(is_blocked(_health_anomaly(42), blocklist))
        self.assertFalse(should_alert(_health_anomaly(42), self.repo, self.now, blocklist))
        self.assertTrue(should_alert(_health_anomaly(7), self.repo, self.now, blocklist))

    def test_should_alert_then_suppresses_repeat_after_note(self):
        anomaly = _health_anomaly(42)
        self.assertTrue(should_alert(anomaly, self.repo, self.now, []))
        note_alerted(anomaly, self.repo, self.now, window_hours=2)
        self.assertFalse(should_alert(anomaly, self.repo, self.now + timedelta(hours=1), []))
        self.assertTrue(should_alert(anomaly, self.repo, self.now + timedelta(hours=3), []))

    def test_unresolved_flow_id_is_never_suppressed(self):
        anomaly = Anomaly(5, "explicit_failure", None, None, None, 99, "data_sink", "failed", None)
        note_alerted(anomaly, self.repo, self.now, window_hours=2)  # no-op, must not raise
        self.assertTrue(should_alert(anomaly, self.repo, self.now, []))


class SuppressionMonitorTests(unittest.TestCase):
    """A RED flow returned by the health sweep on two consecutive ticks alerts only once."""

    def _run_two_ticks(self, blocklist):
        classify_calls = []

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return []

            def list_unhealthy_flows(self):
                return [{"id": 77, "name": "Persistently red", "errorSummary": "still red"}]

            def list_flow_volumes(self, day):
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
                pass

        class FakeOpencodeAdapter:
            def classify_anomaly(self, payload):
                classify_calls.append(payload["flow_id"])
                return {"risk_classification": "high", "explanation": "red", "recommended_action": "look"}

        # A single shared on-disk DB so the second tick sees the first tick's record.
        db = SuppressionRepository(":memory:")
        config = {
            "nexla": {"service_key": "sk"},
            "opencode": {"model": "m", "base_url": "u"},
            "monitoring": {
                "notification_lookback_hours": None,
                "suppression_window_hours": 2,
                "state_db_path": ":memory:",
            },
            "blocklist": blocklist,
        }

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch(
            "monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()
        ), patch("monitor.build_suppression_repository", return_value=db):
            db.close = lambda: None  # keep the shared connection open across both ticks
            output = io.StringIO()
            with redirect_stdout(output):
                monitor_once(config)
                monitor_once(config)
        return classify_calls, output.getvalue()

    def test_persistently_red_flow_alerts_once_across_ticks(self):
        classify_calls, output = self._run_two_ticks(blocklist=[])
        self.assertEqual(classify_calls, [77])
        self.assertEqual(output.count("[HIGH]"), 1)

    def test_blocklisted_red_flow_never_alerts(self):
        classify_calls, output = self._run_two_ticks(blocklist=[{"flow_id": 77, "reason": "noisy"}])
        self.assertEqual(classify_calls, [])
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
