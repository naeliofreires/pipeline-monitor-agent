from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from modules.detection.silent_failure import (
    VolumeObservation,
    detect_silent_failures,
    extract_flow_volumes,
)
from repositories.snapshot_repository import SnapshotRepository
from monitor import monitor_once


class SnapshotRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repo = SnapshotRepository(":memory:")
        self.addCleanup(self.repo.close)
        self.now = datetime(2026, 6, 27, 12, 0, tzinfo=timezone.utc)

    def test_save_then_read_and_missing_returns_none(self):
        self.assertIsNone(self.repo.get_record_count(42, "2026-06-26"))
        self.repo.save_snapshot(42, "2026-06-26", 950, self.now)
        self.assertEqual(self.repo.get_record_count(42, "2026-06-26"), 950)

    def test_save_upserts_same_flow_and_window(self):
        self.repo.save_snapshot(42, "2026-06-26", 950, self.now)
        self.repo.save_snapshot(42, "2026-06-26", 12, self.now + timedelta(hours=1))
        self.assertEqual(self.repo.get_record_count(42, "2026-06-26"), 12)

    def test_purge_older_than_removes_only_earlier_windows(self):
        self.repo.save_snapshot(1, "2026-06-25", 10, self.now)
        self.repo.save_snapshot(1, "2026-06-26", 20, self.now)
        removed = self.repo.purge_older_than("2026-06-26")
        self.assertEqual(removed, 1)
        self.assertIsNone(self.repo.get_record_count(1, "2026-06-25"))
        self.assertEqual(self.repo.get_record_count(1, "2026-06-26"), 20)

    def test_purge_with_nothing_to_remove_returns_zero(self):
        self.repo.save_snapshot(1, "2026-06-26", 10, self.now)
        self.assertEqual(self.repo.purge_older_than("2020-01-01"), 0)
        self.assertEqual(self.repo.get_record_count(1, "2026-06-26"), 10)


class ExtractVolumesTests(unittest.TestCase):
    def test_parses_org_health_rows_and_defaults_null_count_to_zero(self):
        rows = [
            {"origin_node_id": 55, "name": "Orders", "latestRecordCount": 950},
            {"origin_node_id": 56, "name": "Empty", "latestRecordCount": None},
            {"name": "no flow id"},
        ]
        volumes = extract_flow_volumes(rows)
        self.assertEqual(volumes[55], ("Orders", 950))
        self.assertEqual(volumes[56], ("Empty", 0))
        self.assertNotIn(None, volumes)
        self.assertEqual(len(volumes), 2)


class DetectSilentFailureTests(unittest.TestCase):
    def test_flags_drop_at_or_above_threshold(self):
        anomalies = detect_silent_failures(
            [VolumeObservation(55, "Orders", 50, 1000)], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].type, "silent_failure")
        self.assertEqual(anomalies[0].flow_id, 55)
        self.assertIn("95%", anomalies[0].message)

    def test_ignores_drop_below_threshold(self):
        anomalies = detect_silent_failures(
            [VolumeObservation(55, "Orders", 800, 1000)], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(anomalies, [])

    def test_ignores_missing_or_small_baseline(self):
        no_baseline = detect_silent_failures([VolumeObservation(55, "X", 0, None)], min_baseline=100)
        tiny_baseline = detect_silent_failures([VolumeObservation(55, "X", 0, 10)], min_baseline=100)
        self.assertEqual(no_baseline, [])
        self.assertEqual(tiny_baseline, [])

    def test_per_flow_threshold_overrides_global(self):
        obs = [VolumeObservation(789, "Spiky", 500, 1000)]  # 50% drop
        self.assertEqual(detect_silent_failures(obs, threshold_pct=40, min_baseline=100)[0].flow_id, 789)
        self.assertEqual(
            detect_silent_failures(obs, threshold_pct=40, min_baseline=100, per_flow_threshold={789: 60}),
            [],
        )

    def test_excludes_already_reported_flows(self):
        anomalies = detect_silent_failures(
            [VolumeObservation(55, "Orders", 0, 1000)],
            threshold_pct=40,
            min_baseline=100,
            exclude_flow_ids={55},
        )
        self.assertEqual(anomalies, [])

    def test_threshold_boundary_is_inclusive(self):
        fires = detect_silent_failures(
            [VolumeObservation(55, "X", 600, 1000)], threshold_pct=40, min_baseline=100
        )  # exactly 40% drop
        just_under = detect_silent_failures(
            [VolumeObservation(55, "X", 601, 1000)], threshold_pct=40, min_baseline=100
        )  # 39.9%
        self.assertEqual(len(fires), 1)
        self.assertEqual(just_under, [])

    def test_min_baseline_boundary_is_inclusive(self):
        at = detect_silent_failures(
            [VolumeObservation(55, "X", 0, 100)], threshold_pct=40, min_baseline=100
        )
        below = detect_silent_failures(
            [VolumeObservation(55, "X", 0, 99)], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(len(at), 1)
        self.assertEqual(below, [])

    def test_per_flow_threshold_can_tighten_to_create_alert(self):
        obs = [VolumeObservation(789, "Spiky", 700, 1000)]  # 30% drop, below the global 40%
        self.assertEqual(detect_silent_failures(obs, threshold_pct=40, min_baseline=100), [])
        tightened = detect_silent_failures(
            obs, threshold_pct=40, min_baseline=100, per_flow_threshold={789: 25}
        )
        self.assertEqual(tightened[0].flow_id, 789)

    def test_volume_increase_is_not_flagged(self):
        anomalies = detect_silent_failures(
            [VolumeObservation(55, "Growing", 2000, 1000)], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(anomalies, [])

    def test_mixed_flows_returns_only_qualifying(self):
        obs = [
            VolumeObservation(1, "collapsed", 10, 1000),  # 99% -> fires
            VolumeObservation(2, "steady", 950, 1000),    # 5% -> no
            VolumeObservation(3, "tiny", 0, 10),          # baseline below min -> no
            VolumeObservation(4, "already-reported", 0, 1000),  # excluded
        ]
        out = detect_silent_failures(obs, threshold_pct=40, min_baseline=100, exclude_flow_ids={4})
        self.assertEqual([a.flow_id for a in out], [1])

    def test_min_baseline_zero_does_not_divide_by_zero(self):
        # An operator setting min_baseline 0 must not crash on a baseline of 0.
        anomalies = detect_silent_failures(
            [VolumeObservation(55, "X", 0, 0)], threshold_pct=40, min_baseline=0
        )
        self.assertEqual(anomalies, [])


class SilentFailureMonitorTests(unittest.TestCase):
    """A flow whose volume collapsed day-over-day alerts once, then is suppressed."""

    def _run_two_ticks(self):
        classify_calls = []
        today = datetime.now(timezone.utc).date().isoformat()

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return []

            def list_unhealthy_flows(self):
                return []

            def list_flow_volumes(self, day):
                count = 50 if day == today else 1000
                return [{"origin_node_id": 55, "name": "Orders Export", "latestRecordCount": count}]

            def get_flow_health(self, flow_id):
                return {"healthStatus": "GREEN", "latestRunId": "r1", "latestRecordCount": 50}

            def get_run_status(self, flow_id, run_id):
                return {"status": "SUCCESS"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 50, "errors": 0}

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return []

            def mark_notifications_read(self, ids):
                pass

        class FakeOpencodeAdapter:
            def __init__(self, model, base_url):
                pass

            def classify_anomaly(self, payload):
                classify_calls.append((payload["flow_id"], payload["type"]))
                return {
                    "risk_classification": "high",
                    "explanation": "Volume collapsed",
                    "recommended_action": "Check the source",
                }

        from repositories.suppression_repository import SuppressionRepository

        suppression = SuppressionRepository(":memory:")
        snapshots = SnapshotRepository(":memory:")
        suppression.close = lambda: None
        snapshots.close = lambda: None
        config = {
            "nexla": {"service_key": "sk"},
            "opencode": {"model": "m", "base_url": "u"},
            "monitoring": {"notification_lookback_hours": None, "suppression_window_hours": 2},
            "detection": {"volume_threshold_pct": 40, "min_baseline_records": 100},
        }

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch(
            "monitor.OpencodeAdapter", FakeOpencodeAdapter
        ), patch("monitor.build_suppression_repository", return_value=suppression), patch(
            "monitor.build_snapshot_repository", return_value=snapshots
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                monitor_once(config)
                monitor_once(config)
        return classify_calls, output.getvalue(), snapshots, today

    def test_volume_drop_alerts_once_and_records_snapshot(self):
        classify_calls, output, snapshots, today = self._run_two_ticks()
        self.assertEqual(classify_calls, [(55, "silent_failure")])
        self.assertEqual(output.count("[HIGH]"), 1)
        self.assertIn("Silent Failure", output)
        self.assertEqual(snapshots.get_record_count(55, today), 50)


class SilentFailureResilienceTests(unittest.TestCase):
    def _config(self):
        return {
            "nexla": {"service_key": "sk"},
            "opencode": {"model": "m", "base_url": "u"},
            "monitoring": {"notification_lookback_hours": None, "suppression_window_hours": 2},
            "detection": {"volume_threshold_pct": 40, "min_baseline_records": 100},
        }

    def _run(self, fake_nexla_cls, classify_calls, snapshots):
        from repositories.suppression_repository import SuppressionRepository

        suppression = SuppressionRepository(":memory:")
        suppression.close = lambda: None
        snapshots.close = lambda: None

        class FakeOpencodeAdapter:
            def __init__(self, model, base_url):
                pass

            def classify_anomaly(self, payload):
                classify_calls.append((payload["flow_id"], payload["type"]))
                return {"risk_classification": "high", "explanation": "x", "recommended_action": "y"}

        with patch("monitor.NexlaAdapter", fake_nexla_cls), patch(
            "monitor.OpencodeAdapter", FakeOpencodeAdapter
        ), patch("monitor.build_suppression_repository", return_value=suppression), patch(
            "monitor.build_snapshot_repository", return_value=snapshots
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                monitor_once(self._config())
        return output.getvalue()

    def test_baseline_falls_back_to_snapshot_when_yesterday_window_empty(self):
        classify_calls = []
        today = datetime.now(timezone.utc).date().isoformat()
        yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return []

            def list_unhealthy_flows(self):
                return []

            def list_flow_volumes(self, day):
                if day == today:
                    return [{"origin_node_id": 55, "name": "Orders", "latestRecordCount": 50}]
                return []  # yesterday's window unavailable from the API

            def get_flow_health(self, flow_id):
                return {"healthStatus": "GREEN", "latestRunId": "r1"}

            def get_run_status(self, flow_id, run_id):
                return {"status": "SUCCESS"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 50, "errors": 0}

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return []

            def mark_notifications_read(self, ids):
                pass

        snapshots = SnapshotRepository(":memory:")
        snapshots.save_snapshot(55, yesterday, 1000, datetime.now(timezone.utc))
        output = self._run(FakeNexlaAdapter, classify_calls, snapshots)
        self.assertEqual(classify_calls, [(55, "silent_failure")])
        self.assertIn("Silent Failure", output)

    def test_volume_read_failure_does_not_block_other_alerts(self):
        classify_calls = []

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return []

            def list_unhealthy_flows(self):
                return [{"id": 77, "name": "Red flow", "errorSummary": "boom"}]

            def list_flow_volumes(self, day):
                raise RuntimeError("volume api down")

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

        # Must not raise despite list_flow_volumes blowing up.
        output = self._run(FakeNexlaAdapter, classify_calls, SnapshotRepository(":memory:"))
        self.assertEqual(classify_calls, [(77, "health_sweep")])
        self.assertIn("[HIGH]", output)


if __name__ == "__main__":
    unittest.main()
