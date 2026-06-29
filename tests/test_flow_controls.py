from __future__ import annotations

import hmac, json, time, unittest, urllib.error, urllib.parse, urllib.request
from hashlib import sha256
from unittest.mock import patch

from adapters.nexla_adapter import NexlaAdapter
from modules.alerting.sender import SlackBotAlertSender, build_alert_sender
from modules.controls.config import ControlConfigError, validate_control_config
from modules.controls.executor import ControlExecutor
from modules.controls.policy import ControlMetadata, ParsedAction, authorize, build_action_value, parse_action_value
from modules.controls.server import start_interaction_server
from modules.controls.signature import verify_slack_signature
from repositories.control_audit_repository import ControlAuditRepository


class FlowControlTests(unittest.TestCase):
    def test_control_config_fails_closed_when_enabled(self):
        with self.assertRaises(ControlConfigError):
            validate_control_config({"controls": {"enabled": True}})
        validate_control_config({"controls": {"enabled": True, "allowed_actions": ["pause"]}, "slack": {"signing_secret": "s", "allowed_user_ids": ["U1"]}, "nexla": {"service_key": "mk"}})
        validate_control_config({"controls": {"enabled": True, "allowed_actions": ["pause"]}, "slack": {"signing_secret": "s", "allowed_user_ids": ["U1"]}, "nexla": {"service_key": "mk", "control_service_key": "ck"}})

    def test_slack_signature_hmac_and_replay(self):
        raw = b"payload=x"
        ts = str(int(time.time()))
        sig = "v0=" + hmac.new(b"secret", b"v0:" + ts.encode() + b":" + raw, sha256).hexdigest()
        self.assertTrue(verify_slack_signature(raw, ts, sig, "secret"))
        self.assertFalse(verify_slack_signature(raw, str(int(time.time()) - 999), sig, "secret"))
        self.assertFalse(verify_slack_signature(raw, ts, sig, ""))

    def test_action_value_policy(self):
        value = build_action_value(42, "pause", now=100, nonce="n", signing_secret="secret")
        parsed = parse_action_value(value, ttl_seconds=10, now=105, signing_secret="secret")
        self.assertEqual((parsed.flow_id, parsed.action, parsed.correlation_id), (42, "pause", "n"))
        with self.assertRaises(ValueError):
            parse_action_value(value, ttl_seconds=1, now=200, signing_secret="secret")
        with self.assertRaises(ValueError):
            parse_action_value(value, ttl_seconds=10, now=-300, signing_secret="secret")
        with self.assertRaises(ValueError):
            parse_action_value(value, ttl_seconds=10, now=105, signing_secret="wrong")
        with self.assertRaises(ValueError):
            build_action_value(42, "pause")
        config = {"controls": {"enabled": True, "allowed_actions": ["pause"], "protected_flows": []}, "slack": {"allowed_user_ids": ["U1"]}}
        self.assertIsNone(authorize(parsed, {"user": {"id": "U1"}}, config))
        self.assertEqual(authorize(parsed, {"user": {"id": "U2"}}, config), "user not allowed")

    def test_adapter_control_methods_call_sdk(self):
        calls = []
        class Flows:
            def get(self, flow_id, flows_only=False): calls.append(("get", flow_id, flows_only)); return {"status": "ACTIVE"}
            def pause(self, flow_id, all=False): calls.append(("pause", flow_id, all)); return {"ok": True}
            def activate(self, flow_id, all=False): calls.append(("activate", flow_id, all)); return {"ok": True}
        adapter = NexlaAdapter.__new__(NexlaAdapter)
        setattr(adapter, "_client", type("Client", (), {"flows": Flows()})())
        self.assertEqual(adapter.get_flow(7), {"status": "ACTIVE"})
        adapter.pause_flow(7); adapter.activate_flow(7)
        self.assertEqual(calls, [("get", 7, False), ("pause", 7, False), ("activate", 7, False)])

    def test_audit_repository_records_without_payload(self):
        repo = ControlAuditRepository(":memory:")
        repo.record(result="denied", actor_user_id="U1", action="pause", flow_id=42, reason="no", correlation_id="c")
        row = repo.list_all()[0]
        self.assertEqual(row["result"], "denied")
        self.assertNotIn("response_url", row)
        repo.close()

    def test_slack_sender_adds_buttons_from_metadata(self):
        requests = []
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"ok": true}'
        with patch("modules.alerting.sender.urllib.request.urlopen", lambda req: requests.append(req) or Resp()):
            SlackBotAlertSender("t", "C", "https://slack.test", {"enabled": True, "allowed_actions": ["pause", "activate"], "protected_flows": [], "action_signing_secret": "secret"}).send("alert", ControlMetadata(42))
        payload = json.loads(requests[0].data.decode())
        self.assertEqual(len(payload["blocks"][1]["elements"]), 1)
        self.assertEqual(payload["blocks"][1]["elements"][0]["text"]["text"], "Pause")
        value = payload["blocks"][1]["elements"][0]["value"]
        self.assertEqual(parse_action_value(value, 900, signing_secret="secret").flow_id, 42)

    def test_build_alert_sender_injects_action_signing_secret(self):
        requests = []
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"ok": true}'
        config = {"slack": {"enabled": True, "bot_token": "t", "channel_id": "C", "signing_secret": "secret", "api_url": "https://slack.test"}, "controls": {"enabled": True, "allowed_actions": ["pause"]}}
        with patch("modules.alerting.sender.urllib.request.urlopen", lambda req: requests.append(req) or Resp()):
            build_alert_sender(config).send("alert", ControlMetadata(42))
        value = json.loads(requests[0].data.decode())["blocks"][1]["elements"][0]["value"]
        self.assertEqual(parse_action_value(value, 900, signing_secret="secret").action, "pause")

    def test_sender_no_buttons_for_protected_flow(self):
        requests = []
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"ok": true}'
        with patch("modules.alerting.sender.urllib.request.urlopen", lambda req: requests.append(req) or Resp()):
            SlackBotAlertSender("t", "C", "https://slack.test", {"enabled": True, "allowed_actions": ["pause"], "protected_flows": [42], "action_signing_secret": "secret"}).send("alert", ControlMetadata(42))
        self.assertNotIn("blocks", json.loads(requests[0].data.decode()))

    def test_slack_sender_without_action_secret_fails_closed(self):
        requests = []
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"ok": true}'
        with patch("modules.alerting.sender.urllib.request.urlopen", lambda req: requests.append(req) or Resp()):
            SlackBotAlertSender("t", "C", "https://slack.test", {"enabled": True, "allowed_actions": ["pause"], "protected_flows": []}).send("alert", ControlMetadata(42))
        self.assertNotIn("blocks", json.loads(requests[0].data.decode()))

    def test_interaction_server_rejects_bad_signature_without_enqueue(self):
        audit = ControlAuditRepository(":memory:")
        class Executor:
            calls = []
            def enqueue(self, *args): self.calls.append(args)
        server = start_interaction_server({"controls": {"interactions_port": 0}, "slack": {"signing_secret": "secret"}}, audit, Executor())
        try:
            url = f"http://{server.server_address[0]}:{server.server_address[1]}/slack/interactions"
            request = urllib.request.Request(url, data=b"payload=x", headers={"X-Slack-Request-Timestamp": str(int(time.time())), "X-Slack-Signature": "v0=bad"}, method="POST")
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            error.exception.close()
            self.assertEqual(audit.list_all()[0]["reason"], "invalid Slack signature")
            self.assertEqual(Executor.calls, [])
        finally:
            server.shutdown(); server.server_close(); audit.close()

    def test_interaction_server_refuses_empty_signing_secret(self):
        audit = ControlAuditRepository(":memory:")
        try:
            with self.assertRaises(ValueError):
                start_interaction_server({"controls": {"interactions_port": 0}, "slack": {"signing_secret": ""}}, audit, object())
        finally:
            audit.close()

    def test_interaction_server_audits_invalid_path(self):
        audit = ControlAuditRepository(":memory:")
        class Executor:
            def enqueue(self, *args): raise AssertionError("should not enqueue")
        server = start_interaction_server({"controls": {"interactions_port": 0}, "slack": {"signing_secret": "secret"}}, audit, Executor())
        try:
            body = b"payload=x"
            ts = str(int(time.time()))
            sig = "v0=" + hmac.new(b"secret", b"v0:" + ts.encode() + b":" + body, sha256).hexdigest()
            url = f"http://{server.server_address[0]}:{server.server_address[1]}/wrong"
            request = urllib.request.Request(url, data=body, headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}, method="POST")
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            error.exception.close()
            self.assertEqual(audit.list_all()[0]["reason"], "invalid interaction path")
        finally:
            server.shutdown(); server.server_close(); audit.close()

    def test_interaction_server_denies_protected_flow_and_does_not_enqueue(self):
        audit = ControlAuditRepository(":memory:")
        class Executor:
            calls = []
            def enqueue(self, *args): self.calls.append(args)
        config = {"controls": {"enabled": True, "allowed_actions": ["pause"], "protected_flows": [42], "interactions_port": 0}, "slack": {"signing_secret": "secret", "allowed_user_ids": ["U1"]}}
        server = start_interaction_server(config, audit, Executor())
        try:
            value = build_action_value(42, "pause", signing_secret="secret")
            payload = {"type": "block_actions", "actions": [{"value": value}], "user": {"id": "U1"}, "team": {"id": "T1"}, "channel": {"id": "C1"}}
            body = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode()
            ts = str(int(time.time()))
            sig = "v0=" + hmac.new(b"secret", b"v0:" + ts.encode() + b":" + body, sha256).hexdigest()
            url = f"http://{server.server_address[0]}:{server.server_address[1]}/slack/interactions"
            urllib.request.urlopen(urllib.request.Request(url, data=body, headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}, method="POST")).read()
            self.assertEqual(audit.list_all()[0]["reason"], "protected flow")
            self.assertEqual(Executor.calls, [])
        finally:
            server.shutdown(); server.server_close(); audit.close()

    def test_interaction_server_audits_accepted_before_enqueue(self):
        audit = ControlAuditRepository(":memory:")
        class Executor:
            def enqueue(self, *args):
                rows = audit.list_all()
                self.seen = rows[-1]["result"]
        executor = Executor()
        config = {"controls": {"enabled": True, "allowed_actions": ["pause"], "protected_flows": [], "interactions_port": 0}, "slack": {"signing_secret": "secret", "allowed_user_ids": ["U1"]}}
        server = start_interaction_server(config, audit, executor)
        try:
            self._post_signed_action(server, 42, "pause", "secret")
            self.assertEqual(executor.seen, "accepted")
        finally:
            server.shutdown(); server.server_close(); audit.close()

    def test_interaction_server_rejects_tampered_action_without_enqueue(self):
        audit = ControlAuditRepository(":memory:")
        class Executor:
            calls = []
            def enqueue(self, *args): self.calls.append(args)
        config = {"controls": {"enabled": True, "allowed_actions": ["pause"], "protected_flows": [], "interactions_port": 0}, "slack": {"signing_secret": "secret", "allowed_user_ids": ["U1"]}}
        server = start_interaction_server(config, audit, Executor())
        try:
            self._post_signed_payload(server, {"type": "block_actions", "actions": [{"value": build_action_value(42, "pause", signing_secret="secret")[:-2] + "xx"}], "user": {"id": "U1"}})
            self.assertEqual(audit.list_all()[0]["result"], "denied")
            self.assertEqual(Executor.calls, [])
        finally:
            server.shutdown(); server.server_close(); audit.close()

    def test_executor_records_terminal_outcomes_with_actor_context(self):
        payload = {"user": {"id": "U1"}, "team": {"id": "T1"}, "channel": {"id": "C1"}}
        audit = ControlAuditRepository(":memory:")
        class Adapter:
            def __init__(self, status="ACTIVE", fail=False): self.status = status; self.fail = fail
            def get_flow(self, flow_id): return {"status": self.status}
            def pause_flow(self, flow_id):
                if self.fail: raise RuntimeError("boom")
            def activate_flow(self, flow_id): pass
        try:
            ControlExecutor(Adapter()).__dict__  # keep type import exercised
        except TypeError:
            pass
        executor = ControlExecutor.__new__(ControlExecutor)
        executor.adapter = Adapter("PAUSED"); executor.audit = audit
        executor.execute_once(ParsedAction(42, "pause", 1, "noop"), payload, None)
        executor.adapter = Adapter("ACTIVE"); executor.execute_once(ParsedAction(42, "pause", 1, "done"), payload, None)
        executor.adapter = Adapter("ACTIVE", fail=True); executor.execute_once(ParsedAction(42, "pause", 1, "fail"), payload, None)
        rows = audit.list_all()
        self.assertEqual([row["result"] for row in rows], ["no-op", "completed", "failed"])
        self.assertTrue(all(row["actor_user_id"] == "U1" and row["team_id"] == "T1" and row["channel_id"] == "C1" for row in rows))
        audit.close()

    def _post_signed_action(self, server, flow_id, action, secret):
        self._post_signed_payload(server, {"type": "block_actions", "actions": [{"value": build_action_value(flow_id, action, signing_secret=secret)}], "user": {"id": "U1"}, "team": {"id": "T1"}, "channel": {"id": "C1"}})

    def _post_signed_payload(self, server, payload):
        body = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode()
        ts = str(int(time.time()))
        sig = "v0=" + hmac.new(b"secret", b"v0:" + ts.encode() + b":" + body, sha256).hexdigest()
        url = f"http://{server.server_address[0]}:{server.server_address[1]}/slack/interactions"
        urllib.request.urlopen(urllib.request.Request(url, data=body, headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig}, method="POST")).read()


if __name__ == "__main__":
    unittest.main()
