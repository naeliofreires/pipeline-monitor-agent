import unittest

import monitor
from adapters.nexla_adapter import NexlaAdapter
from modules.controls.router import route_message
from modules.controls.router_tools import RouterCallbacks, RouterContext, TOOL_SCHEMAS, build_catalog


class _RunsAdapter(NexlaAdapter):
    """Bypass the SDK-backed __init__; only get_run_summary is exercised by get_flow_runs."""

    def __init__(self, rows):
        self._rows = rows

    def get_run_summary(self, flow_id, resource_type=None, resource_id=None, run_id=None):
        return self._rows


class GetFlowRunsTests(unittest.TestCase):
    def test_orders_latest_first_caps_and_normalizes(self):
        rows = [
            {"runId": 100, "records": 50, "errors": 1, "lastWritten": 1000, "status": "succeeded"},
            {"runId": 101, "records": 0, "errors": 5, "lastWritten": 2000, "status": "failed"},
            {"runId": 99, "records": 10, "errors": 0, "lastWritten": 500},
        ]
        runs = _RunsAdapter(rows).get_flow_runs(1, "data_sink", 2, limit=2)
        self.assertEqual([r["run_id"] for r in runs], [101, 100])
        self.assertEqual(runs[0], {"run_id": 101, "records": 0, "errors": 5, "size": None, "last_written": 2000, "status": "FAILED"})
        self.assertEqual(runs[1]["run_id"], 100)
        self.assertEqual(runs[1]["status"], "SUCCEEDED")  # normalized to upper-case

    def test_none_when_no_rows(self):
        self.assertIsNone(_RunsAdapter(None).get_flow_runs(1, "data_sink", 2))
        self.assertIsNone(_RunsAdapter([]).get_flow_runs(1, "data_sink", 2))


class LatestRunsTests(unittest.TestCase):
    def _patch_adapter(self, fake):
        self._orig = monitor.build_nexla_adapter
        monitor.build_nexla_adapter = lambda config, key: fake

    def tearDown(self):
        if hasattr(self, "_orig"):
            monitor.build_nexla_adapter = self._orig

    def test_formats_run_table(self):
        class Fake:
            def get_flow(self, fid):
                return {"flows": [{"id": 42, "name": "My Flow", "data_sink_id": 99}]}

            def get_flow_health(self, fid):
                return {}

            def get_flow_runs(self, fid, rt, rid, limit):
                return [{"run_id": 101, "records": 0, "errors": 5, "size": 0, "last_written": 2000, "status": "FAILED"}]

        self._patch_adapter(Fake())
        text = monitor.latest_runs({"nexla": {"service_key": "k"}}, 42)
        self.assertIn("My Flow", text)
        self.assertIn("101", text)
        self.assertIn("FAILED", text)

    def test_no_runs_message(self):
        class Fake:
            def get_flow(self, fid):
                return {"flows": [{"id": 42, "name": "My Flow", "data_sink_id": 99}]}

            def get_flow_health(self, fid):
                return {}

            def get_flow_runs(self, fid, rt, rid, limit):
                return None

        self._patch_adapter(Fake())
        self.assertIn("No runs found", monitor.latest_runs({"nexla": {"service_key": "k"}}, 42))


class _Recorder:
    def __init__(self):
        self.calls = []


class FakeRouter:
    def __init__(self, result=None, raises=False):
        self.result = result
        self.raises = raises

    def route_command(self, message, tools):
        if self.raises:
            raise RuntimeError("llm down")
        return self.result


def _callbacks(rec):
    return RouterCallbacks(
        scan_flow=lambda config, fid: rec.calls.append(("scan_flow", config, fid)) or f"scanned {fid}",
        scan_org=lambda config: rec.calls.append(("scan_org", config)),
        latest_runs=lambda config, fid, limit: rec.calls.append(("latest_runs", config, fid, limit)) or f"runs {fid}",
        monitoring=lambda config, action, fid, meta: rec.calls.append(("monitoring", action, fid, meta)) or f"monitoring {action}",
    )


class RouteMessageTests(unittest.TestCase):
    def setUp(self):
        self.rec = _Recorder()
        self.ctx = RouterContext(config={"k": 1}, channel_id="cli", user_id=None)
        self.cbs = _callbacks(self.rec)
        self.fallback = lambda text: f"FALLBACK:{text}"

    def _run(self, router):
        return route_message("the message", self.ctx, self.cbs, router, self.fallback)

    def test_dispatches_scan_flow_tool(self):
        out = self._run(FakeRouter({"tool": "scan_flow", "arguments": {"flow_id": 42}}))
        self.assertEqual(out, "scanned 42")
        self.assertEqual(self.rec.calls, [("scan_flow", {"k": 1}, 42)])

    def test_scan_org_returns_canned_message(self):
        out = self._run(FakeRouter({"tool": "scan_org", "arguments": {}}))
        self.assertIn("Scan finished", out)
        self.assertEqual(self.rec.calls, [("scan_org", {"k": 1})])

    def test_list_flow_runs_default_limit(self):
        out = self._run(FakeRouter({"tool": "list_flow_runs", "arguments": {"flow_id": 7}}))
        self.assertEqual(out, "runs 7")
        self.assertEqual(self.rec.calls, [("latest_runs", {"k": 1}, 7, 10)])

    def test_manage_monitoring_passes_metadata(self):
        out = self._run(FakeRouter({"tool": "manage_monitoring", "arguments": {"action": "list"}}))
        self.assertEqual(out, "monitoring list")
        self.assertEqual(self.rec.calls, [("monitoring", "list", None, {"channel_id": "cli", "user_id": None})])

    def test_plain_text_passthrough(self):
        self.assertEqual(self._run(FakeRouter({"text": "hello there"})), "hello there")

    def test_llm_exception_falls_back(self):
        self.assertEqual(self._run(FakeRouter(raises=True)), "FALLBACK:the message")
        self.assertEqual(self.rec.calls, [])

    def test_unknown_tool_falls_back(self):
        self.assertEqual(self._run(FakeRouter({"tool": "pause_flow", "arguments": {"flow_id": 1}})), "FALLBACK:the message")

    def test_bad_arguments_fall_back(self):
        self.assertEqual(self._run(FakeRouter({"tool": "scan_flow", "arguments": {}})), "FALLBACK:the message")

    def test_empty_text_falls_back(self):
        self.assertEqual(self._run(FakeRouter({"text": "   "})), "FALLBACK:the message")


class CatalogSafetyTests(unittest.TestCase):
    def test_catalog_excludes_write_controls(self):
        names = {schema["function"]["name"] for schema in TOOL_SCHEMAS}
        self.assertEqual(names, {"scan_flow", "scan_org", "list_flow_runs", "manage_monitoring"})
        for forbidden in ("pause", "activate", "pause_flow", "activate_flow"):
            self.assertNotIn(forbidden, names)

    def test_build_catalog_handlers_match_schemas(self):
        ctx = RouterContext(config={}, channel_id="cli")
        schemas, handlers = build_catalog(ctx, _callbacks(_Recorder()))
        self.assertEqual({s["function"]["name"] for s in schemas}, set(handlers))


if __name__ == "__main__":
    unittest.main()
