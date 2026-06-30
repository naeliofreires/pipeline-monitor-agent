from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from modules.detection.silent_failure import (
    RunVolumeObservation,
    detect_run_drop_failures,
    extract_flow_volumes,
)
from repositories.snapshot_repository import SnapshotRepository
from repositories.monitored_flow_repository import MonitoredFlowRepository
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
            {"origin_node_id": 55, "name": "Orders", "latestRecordCount": 950, "healthStatus": "GREEN"},
            {"origin_node_id": 56, "name": "Empty", "latestRecordCount": None, "status": "RUNNING"},
            {"name": "no flow id"},
        ]
        volumes = extract_flow_volumes(rows)
        self.assertEqual(volumes[55], ("Orders", 950, "GREEN"))
        self.assertEqual(volumes[56], ("Empty", 0, "RUNNING"))
        self.assertNotIn(None, volumes)
        self.assertEqual(len(volumes), 2)


class DetectSilentFailureTests(unittest.TestCase):
    def test_flags_drop_at_or_above_threshold(self):
        anomalies = detect_run_drop_failures(
            [RunVolumeObservation(55, "Orders", 50, 1000, "GREEN")], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].type, "silent_failure")
        self.assertEqual(anomalies[0].flow_id, 55)
        self.assertIn("95%", anomalies[0].message)

    def test_ignores_drop_below_threshold(self):
        anomalies = detect_run_drop_failures(
            [RunVolumeObservation(55, "Orders", 800, 1000, "GREEN")], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(anomalies, [])

    def test_ignores_missing_or_small_baseline(self):
        no_baseline = detect_run_drop_failures([RunVolumeObservation(55, "X", 0, None, "GREEN")], min_baseline=100)
        tiny_baseline = detect_run_drop_failures([RunVolumeObservation(55, "X", 0, 10, "GREEN")], min_baseline=100)
        self.assertEqual(no_baseline, [])
        self.assertEqual(tiny_baseline, [])

    def test_per_flow_threshold_overrides_global(self):
        obs = [RunVolumeObservation(789, "Spiky", 500, 1000, "GREEN")]  # 50% drop
        self.assertEqual(detect_run_drop_failures(obs, threshold_pct=40, min_baseline=100)[0].flow_id, 789)
        self.assertEqual(
            detect_run_drop_failures(obs, threshold_pct=40, min_baseline=100, per_flow_threshold={789: 60}),
            [],
        )

    def test_excludes_already_reported_flows(self):
        anomalies = detect_run_drop_failures(
            [RunVolumeObservation(55, "Orders", 0, 1000, "GREEN")],
            threshold_pct=40,
            min_baseline=100,
            exclude_flow_ids={55},
        )
        self.assertEqual(anomalies, [])

    def test_threshold_boundary_is_inclusive(self):
        fires = detect_run_drop_failures(
            [RunVolumeObservation(55, "X", 600, 1000, "GREEN")], threshold_pct=40, min_baseline=100
        )  # exactly 40% drop
        just_under = detect_run_drop_failures(
            [RunVolumeObservation(55, "X", 601, 1000, "GREEN")], threshold_pct=40, min_baseline=100
        )  # 39.9%
        self.assertEqual(len(fires), 1)
        self.assertEqual(just_under, [])

    def test_min_baseline_boundary_is_inclusive(self):
        at = detect_run_drop_failures(
            [RunVolumeObservation(55, "X", 0, 100, "GREEN")], threshold_pct=40, min_baseline=100
        )
        below = detect_run_drop_failures(
            [RunVolumeObservation(55, "X", 0, 99, "GREEN")], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(len(at), 1)
        self.assertEqual(below, [])

    def test_per_flow_threshold_can_tighten_to_create_alert(self):
        obs = [RunVolumeObservation(789, "Spiky", 700, 1000, "GREEN")]  # 30% drop, below the global 40%
        self.assertEqual(detect_run_drop_failures(obs, threshold_pct=40, min_baseline=100), [])
        tightened = detect_run_drop_failures(
            obs, threshold_pct=40, min_baseline=100, per_flow_threshold={789: 25}
        )
        self.assertEqual(tightened[0].flow_id, 789)

    def test_volume_increase_is_not_flagged(self):
        anomalies = detect_run_drop_failures(
            [RunVolumeObservation(55, "Growing", 2000, 1000, "GREEN")], threshold_pct=40, min_baseline=100
        )
        self.assertEqual(anomalies, [])

    def test_mixed_flows_returns_only_qualifying(self):
        obs = [
            RunVolumeObservation(1, "collapsed", 10, 1000, "GREEN"),  # 99% -> fires
            RunVolumeObservation(2, "steady", 950, 1000, "GREEN"),    # 5% -> no
            RunVolumeObservation(3, "tiny", 0, 10, "GREEN"),          # baseline below min -> no
            RunVolumeObservation(4, "already-reported", 0, 1000, "GREEN"),  # excluded
        ]
        out = detect_run_drop_failures(obs, threshold_pct=40, min_baseline=100, exclude_flow_ids={4})
        self.assertEqual([a.flow_id for a in out], [1])

    def test_min_baseline_zero_does_not_divide_by_zero(self):
        # An operator setting min_baseline 0 must not crash on a baseline of 0.
        anomalies = detect_run_drop_failures(
            [RunVolumeObservation(55, "X", 0, 0, "GREEN")], threshold_pct=40, min_baseline=0
        )
        self.assertEqual(anomalies, [])

    def test_requires_explicit_running_or_healthy_status(self):
        obs = [
            RunVolumeObservation(1, "healthy", 0, 1000, "GREEN"),
            RunVolumeObservation(2, "running", 0, 1000, "RUNNING"),
            RunVolumeObservation(3, "missing-status", 0, 1000, None),
        ]
        anomalies = detect_run_drop_failures(obs, threshold_pct=40, min_baseline=100)
        self.assertEqual([a.flow_id for a in anomalies], [1, 2])

    def test_skips_clearly_unhealthy_or_not_running_statuses(self):
        obs = [
            RunVolumeObservation(1, "red", 0, 1000, "RED"),
            RunVolumeObservation(2, "error", 0, 1000, "ERROR"),
            RunVolumeObservation(3, "failed", 0, 1000, "FAILED"),
            RunVolumeObservation(4, "paused", 0, 1000, "PAUSED"),
            RunVolumeObservation(5, "stopped", 0, 1000, "STOPPED"),
            RunVolumeObservation(6, "inactive", 0, 1000, "INACTIVE"),
        ]
        self.assertEqual(detect_run_drop_failures(obs, threshold_pct=40, min_baseline=100), [])

    def test_run_drop_flags_exceptional_previous_run_drop(self):
        anomalies = detect_run_drop_failures(
            [RunVolumeObservation(55, "Orders", 100, 1000, "GREEN")],
            threshold_pct=80,
            min_baseline=100,
        )
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0].type, "silent_failure")
        self.assertEqual(anomalies[0].flow_id, 55)
        self.assertIn("previous run/observation", anomalies[0].message)
        self.assertIn("90%", anomalies[0].message)

    def test_run_drop_skips_below_threshold_small_baseline_and_excluded_flows(self):
        below_threshold = detect_run_drop_failures(
            [RunVolumeObservation(55, "Orders", 300, 1000, "GREEN")], threshold_pct=80, min_baseline=100
        )
        small_previous = detect_run_drop_failures(
            [RunVolumeObservation(56, "Tiny", 0, 10, "GREEN")], threshold_pct=80, min_baseline=100
        )
        excluded = detect_run_drop_failures(
            [RunVolumeObservation(57, "Excluded", 0, 1000, "GREEN")],
            threshold_pct=80,
            min_baseline=100,
            exclude_flow_ids={57},
        )
        self.assertEqual(below_threshold, [])
        self.assertEqual(small_previous, [])
        self.assertEqual(excluded, [])

    def test_run_drop_requires_running_or_healthy_status(self):
        anomalies = detect_run_drop_failures(
            [
                RunVolumeObservation(1, "healthy", 0, 1000, "GREEN"),
                RunVolumeObservation(2, "failed", 0, 1000, "FAILED"),
                RunVolumeObservation(3, "unknown", 0, 1000, None),
            ],
            threshold_pct=80,
            min_baseline=100,
        )
        self.assertEqual([a.flow_id for a in anomalies], [1])


class SilentFailureMonitorTests(unittest.TestCase):
    """A flow whose latest run collapsed run-over-run alerts once, then is suppressed."""

    def _run_two_ticks(self):
        classify_calls = []
        today = datetime.now(timezone.utc).date().isoformat()

        class FakeNexlaAdapter:
            vol_n = 0

            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return []

            def list_unhealthy_flows(self):
                return []

            def list_flow_volumes(self):
                # Tick 1 establishes the run-over-run baseline (cold start, no alert);
                # tick 2's latest run collapses to 50.
                FakeNexlaAdapter.vol_n += 1
                count = 1000 if FakeNexlaAdapter.vol_n == 1 else 50
                return [{"originNodeId": 55, "name": "Orders Export", "latestRecordCount": count, "healthStatus": "GREEN"}]

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
            "monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()
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

    def test_run_over_run_drop_alerts_when_yesterday_rule_does_not_fire(self):
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

            def list_flow_volumes(self):
                return [{"originNodeId": 55, "name": "Orders Export", "latestRecordCount": 100, "healthStatus": "GREEN"}]

            def get_flow_health(self, flow_id):
                return {"healthStatus": "GREEN", "latestRunId": "r2", "latestRecordCount": 100}

            def get_run_status(self, flow_id, run_id):
                return {"status": "SUCCESS"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 100, "errors": 0}

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return []

            def mark_notifications_read(self, ids):
                pass

        class FakeOpencodeAdapter:
            def classify_anomaly(self, payload):
                classify_calls.append((payload["flow_id"], payload["type"], payload["message"]))
                return {
                    "risk_classification": "high",
                    "explanation": "Run volume collapsed",
                    "recommended_action": "Check the latest run",
                }

        from repositories.suppression_repository import SuppressionRepository

        suppression = SuppressionRepository(":memory:")
        snapshots = SnapshotRepository(":memory:")
        snapshots.save_snapshot(55, today, 1000, datetime.now(timezone.utc))
        snapshots.save_snapshot(55, yesterday, 120, datetime.now(timezone.utc))
        suppression.close = lambda: None
        snapshots.close = lambda: None
        config = {
            "nexla": {"service_key": "sk"},
            "monitoring": {"notification_lookback_hours": None, "suppression_window_hours": 2},
            "detection": {
                "volume_threshold_pct": 40,
                "min_baseline_records": 100,
            },
        }

        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch(
            "monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()
        ), patch("monitor.build_suppression_repository", return_value=suppression), patch(
            "monitor.build_snapshot_repository", return_value=snapshots
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                monitor_once(config)

        self.assertEqual(len(classify_calls), 1)
        self.assertEqual(classify_calls[0][0:2], (55, "silent_failure"))
        self.assertIn("previous run/observation", classify_calls[0][2])
        self.assertIn("Silent Failure", output.getvalue())
        self.assertEqual(snapshots.get_record_count(55, today), 100)


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
            def classify_anomaly(self, payload):
                classify_calls.append((payload["flow_id"], payload["type"]))
                return {"risk_classification": "high", "explanation": "x", "recommended_action": "y"}

        with patch("monitor.NexlaAdapter", fake_nexla_cls), patch(
            "monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()
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

            def list_flow_volumes(self):
                return [{"originNodeId": 55, "name": "Orders", "latestRecordCount": 50, "healthStatus": "GREEN"}]

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

            def list_flow_volumes(self):
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


class RegisteredFlowMonitoringTests(unittest.TestCase):
    def test_registered_flow_new_run_reports_against_previous_five_runs(self):
        from repositories.suppression_repository import SuppressionRepository

        sent = []
        classify_calls = []
        now = datetime.now(timezone.utc)

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None):
                return []

            def list_unhealthy_flows(self):
                return []

            def list_flow_volumes(self):
                return []

            def mark_notifications_read(self, ids):
                pass

            def get_flow(self, flow_id):
                return {"id": flow_id, "name": "Orders", "latestRunId": "r6", "status": "ACTIVE"}

            def get_flow_health(self, flow_id):
                return {"healthStatus": "GREEN", "latestRunId": "r6", "name": "Orders"}

            def get_run_status(self, flow_id, run_id):
                return {"status": "SUCCESS"}

            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return {"records": 600, "errors": 0}

            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
                return []

            def get_flow_error_logs(self, flow_id, run_id, limit=5):
                return []

        class FakeOpencodeAdapter:
            def classify_anomaly(self, payload):
                classify_calls.append(payload)
                return {"risk_classification": "low", "explanation": "normal", "recommended_action": "Keep watching"}

        class CaptureSender:
            def send(self, text, metadata=None):
                sent.append((text, metadata))

        suppression = SuppressionRepository(":memory:")
        snapshots = SnapshotRepository(":memory:")
        monitored = MonitoredFlowRepository(":memory:")
        monitored.register_flow(42, "C1", "U1", now)
        for i, records in enumerate([100, 200, 300, 400, 500], start=1):
            monitored.save_run_snapshot(42, f"r{i}", records, 0, "SUCCESS", now + timedelta(minutes=i))
        suppression.close = lambda: None
        snapshots.close = lambda: None
        monitored.close = lambda: None

        config = {"nexla": {"service_key": "sk"}, "monitoring": {"notification_lookback_hours": None}}
        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch(
            "monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()
        ), patch("monitor.build_suppression_repository", return_value=suppression), patch(
            "monitor.build_snapshot_repository", return_value=snapshots
        ), patch("monitor.build_monitored_flow_repository", return_value=monitored), patch(
            "monitor._channel_sender", return_value=CaptureSender()
        ):
            monitor_once(config)

        self.assertEqual(classify_calls, [])
        self.assertEqual(len(sent), 1)
        text = sent[0][0]
        self.assertIn("New run processed", text)
        self.assertIn("*Previous run:* r5", text)
        self.assertIn("*Previous records:* 500", text)
        self.assertIn("*Change from previous run:* +100 records (+20.0%)", text)
        self.assertIn("previous 5 runs (5 available and used)", text)
        self.assertIn("*Average records:* 300.0", text)
        self.assertIn("*Difference:* +100.0%", text)
        self.assertEqual(monitored.list_flows("C1")[0].last_seen_run_id, "r6")

    def test_registered_flow_high_risk_run_includes_classification(self):
        from repositories.suppression_repository import SuppressionRepository

        sent = []
        classify_calls = []
        now = datetime.now(timezone.utc)

        class FakeNexlaAdapter:
            def __init__(self, service_key, api_url=None):
                pass

            def list_unread_notifications(self, from_timestamp=None): return []
            def list_unhealthy_flows(self): return []
            def list_flow_volumes(self): return []
            def mark_notifications_read(self, ids): pass
            def get_flow(self, flow_id): return {"id": flow_id, "name": "Orders", "latestRunId": "r6", "status": "ACTIVE"}
            def get_flow_health(self, flow_id): return {"healthStatus": "GREEN", "latestRunId": "r6", "name": "Orders"}
            def get_run_status(self, flow_id, run_id): return {"status": "SUCCESS"}
            def get_run_metrics(self, flow_id, resource_type=None, resource_id=None, run_id=None): return {"records": 10, "errors": 0}
            def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None): return []
            def get_flow_error_logs(self, flow_id, run_id, limit=5): return []

        class FakeOpencodeAdapter:
            def classify_anomaly(self, payload):
                classify_calls.append((payload["flow_id"], payload["type"], payload["message"]))
                return {"risk_classification": "high", "explanation": "Run collapsed", "recommended_action": "Check the source"}

        class CaptureSender:
            def send(self, text, metadata=None): sent.append(text)

        suppression = SuppressionRepository(":memory:")
        snapshots = SnapshotRepository(":memory:")
        monitored = MonitoredFlowRepository(":memory:")
        monitored.register_flow(42, "C1", "U1", now)
        for i in range(1, 6):
            monitored.save_run_snapshot(42, f"r{i}", 1000, 0, "SUCCESS", now + timedelta(minutes=i))
        suppression.close = lambda: None
        snapshots.close = lambda: None
        monitored.close = lambda: None

        config = {"nexla": {"service_key": "sk"}, "monitoring": {"notification_lookback_hours": None}}
        with patch("monitor.NexlaAdapter", FakeNexlaAdapter), patch(
            "monitor.build_llm_adapter", return_value=FakeOpencodeAdapter()
        ), patch("monitor.build_suppression_repository", return_value=suppression), patch(
            "monitor.build_snapshot_repository", return_value=snapshots
        ), patch("monitor.build_monitored_flow_repository", return_value=monitored), patch(
            "monitor._channel_sender", return_value=CaptureSender()
        ):
            monitor_once(config)

        self.assertEqual(classify_calls[0][0:2], (42, "silent_failure"))
        self.assertIn("previous 5-run average", classify_calls[0][2])
        self.assertIn("*Change from previous run:* -990 records (-99.0%)", sent[0])
        self.assertIn("*Risk Classification:* HIGH", sent[0])
        flow = monitored.list_flows("C1")[0]
        self.assertEqual((flow.last_seen_run_id, flow.last_alerted_run_id), ("r6", "r6"))


if __name__ == "__main__":
    unittest.main()
