import unittest

from modules.controls.intent import Intent, parse_intent


class ParseIntentTests(unittest.TestCase):
    def test_targeted_scan_from_natural_phrase(self):
        self.assertEqual(parse_intent("please scan the flow 1234"), Intent("scan", 1234))
        self.assertEqual(parse_intent("can you check 42?"), Intent("scan", 42))
        self.assertEqual(parse_intent("look at flow 7"), Intent("scan", 7))

    def test_full_scan_when_no_flow_id(self):
        self.assertEqual(parse_intent("scan everything"), Intent("scan", None))
        self.assertEqual(parse_intent("run a scan"), Intent("scan", None))

    def test_non_positive_flow_id_falls_back_to_full_scan(self):
        self.assertEqual(parse_intent("scan flow 0"), Intent("scan", None))

    def test_help_and_quit_and_unknown(self):
        self.assertEqual(parse_intent("help"), Intent("help"))
        self.assertEqual(parse_intent("quit"), Intent("quit"))
        self.assertEqual(parse_intent("exit"), Intent("quit"))
        self.assertEqual(parse_intent(""), Intent("unknown"))
        self.assertEqual(parse_intent("good morning"), Intent("unknown"))

    def test_first_number_wins(self):
        self.assertEqual(parse_intent("scan flow 99 not 100"), Intent("scan", 99))

    def test_more_english_verbs(self):
        self.assertEqual(parse_intent("inspect flow 1234"), Intent("scan", 1234))
        self.assertEqual(parse_intent("can you analyze 42?"), Intent("scan", 42))
        self.assertEqual(parse_intent("review the flow 7"), Intent("scan", 7))
        self.assertEqual(parse_intent("audit everything"), Intent("scan", None))

    def test_no_false_positive_inside_unrelated_words(self):
        # "block" contains no scan stem as a word prefix; stems match word prefixes only.
        self.assertEqual(parse_intent("the build is blocked"), Intent("unknown"))
        self.assertEqual(parse_intent("good morning team"), Intent("unknown"))


class ReplyForIntentTests(unittest.TestCase):
    def test_targeted_scan_calls_scan_flow(self):
        from main import reply_for_intent
        import main

        calls = []
        original = main.scan_flow
        main.scan_flow = lambda config, flow_id: calls.append((config, flow_id)) or "analysis text"
        try:
            reply = reply_for_intent({"k": 1}, Intent("scan", 1234))
        finally:
            main.scan_flow = original
        self.assertEqual(calls, [({"k": 1}, 1234)])
        self.assertEqual(reply, "analysis text")

    def test_full_scan_calls_monitor_once(self):
        from main import reply_for_intent
        import main

        calls = []
        original = main.monitor_once
        main.monitor_once = lambda config: calls.append(config)
        try:
            reply = reply_for_intent({"k": 2}, Intent("scan", None))
        finally:
            main.monitor_once = original
        self.assertEqual(calls, [{"k": 2}])
        self.assertIn("Scan finished", reply)

    def test_help_and_unknown_do_not_scan(self):
        from main import reply_for_intent, INTENT_HELP

        self.assertEqual(reply_for_intent({}, Intent("help")), INTENT_HELP)
        self.assertIn("didn't catch", reply_for_intent({}, Intent("unknown")))


if __name__ == "__main__":
    unittest.main()
