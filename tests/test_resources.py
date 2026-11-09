import json
import tempfile
import unittest
from pathlib import Path

import harp
import harp_resources


class ResourceDiscoveryTests(unittest.TestCase):
    def test_seclists_discovery_is_logged_once_and_kept_in_session(self):
        class Terminal:
            event_dir = None
            calls = 0

            def run(self, command, timeout, **kwargs):
                self.calls += 1
                self.command = command
                self.timeout = timeout
                self.options = kwargs
                return {"command": command, "exit_code": 0, "truncated": False,
                        "output": json.dumps({"available": True, "roots": ["/usr/share/seclists"],
                                              "categories": ["Discovery", "Passwords"]})}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            run_dir = Path(temp)
            session = {"status": "active", "observations": []}
            terminal = Terminal()
            harp.ensure_seclists(run_dir, session, terminal)
            harp.ensure_seclists(run_dir, session, terminal)
            self.assertEqual(terminal.calls, 1)
            self.assertEqual(terminal.command, harp_resources.CHECK_COMMAND)
            self.assertEqual(terminal.timeout, 10)
            self.assertEqual(terminal.options, {"live": False})
            self.assertEqual(session["seclists"]["roots"], ["/usr/share/seclists"])
            self.assertEqual(harp.load_session(run_dir)["seclists"], session["seclists"])
            event = json.loads((run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(event["type"], "seclists_availability")

    def test_invalid_discovery_does_not_block_session(self):
        class Terminal:
            event_dir = None

            def run(self, command, timeout, **kwargs):
                return {"command": command, "exit_code": 0, "truncated": False, "output": "invalid"}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            session = {"status": "active", "observations": []}
            harp.ensure_seclists(Path(temp), session, Terminal())
            self.assertFalse(session["seclists"]["available"])
            self.assertIn("error", session["seclists"])


if __name__ == "__main__":
    unittest.main()
