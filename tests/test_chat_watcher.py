import io
import threading
import unittest
from contextlib import redirect_stdout


class ChatWatchSenderTests(unittest.TestCase):
    def test_prints_header_and_redraws_prompt(self):
        from main import _ChatWatchSender

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            _ChatWatchSender().send("flow 42 is unhealthy")
        output = buffer.getvalue()
        self.assertIn("Background monitor", output)
        self.assertIn("flow 42 is unhealthy", output)
        self.assertTrue(output.endswith("> "))  # prompt is redrawn so the session stays usable


class StartChatWatcherTests(unittest.TestCase):
    def test_disabled_returns_none_and_never_scans(self):
        import main

        calls = []
        original = main.monitor_once
        main.monitor_once = lambda config, sender=None: calls.append(config)
        try:
            thread = main._start_chat_watcher(
                {"monitoring": {"chat_watch_enabled": False}}, threading.Event()
            )
        finally:
            main.monitor_once = original
        self.assertIsNone(thread)
        self.assertEqual(calls, [])

    def test_enabled_polls_monitor_once_with_a_sender_then_stops(self):
        import main

        called = threading.Event()
        captured = {}
        stop_event = threading.Event()

        def fake_monitor_once(config, sender=None):
            captured["config"] = config
            captured["sender"] = sender
            called.set()
            stop_event.set()  # stop the watcher after the first tick

        original = main.monitor_once
        main.monitor_once = fake_monitor_once
        try:
            thread = main._start_chat_watcher(
                {"monitoring": {"chat_watch_enabled": True, "poll_interval_seconds": 0}},
                stop_event,
            )
            self.assertIsNotNone(thread)
            self.assertTrue(called.wait(timeout=5), "watcher never ran a monitoring tick")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        finally:
            main.monitor_once = original
            stop_event.set()

        self.assertEqual(captured["config"], {"monitoring": {"chat_watch_enabled": True, "poll_interval_seconds": 0}})
        self.assertIsInstance(captured["sender"], main._ChatWatchSender)


if __name__ == "__main__":
    unittest.main()
