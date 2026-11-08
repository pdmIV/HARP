import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_artifacts
import harp_web


class SuccessViewedTests(unittest.TestCase):
    def test_viewed_marker_survives_new_web_state_and_does_not_change_session(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        state = {"status": "finished", "success": "yes", "started_epoch": 1,
                 "config": cfg, "observations": []}
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            harp.save_session(root, state)
            before = (root / "session.json").read_bytes()
            with patch.object(harp_web, "session_path", return_value=root), \
                 patch.object(harp_web, "draft_config", return_value=cfg), \
                 patch.object(harp, "summarize", return_value={}), \
                 patch.object(harp_web.harp_costs, "cost_summary", return_value={}), \
                 patch.object(harp_web, "latest_activity", return_value={}), \
                 patch.object(harp_web, "pending_approval", return_value=None), \
                 patch.object(harp_artifacts, "flag_status", return_value={"user.txt": {"found": True}, "root.txt": {"found": True}}), \
                 patch.object(harp_artifacts, "list_artifacts", return_value=[]):
                first = object.__new__(harp_web.HARPWebState)
                self.assertFalse(first.session_view("test", 0)["success_viewed"])
                harp_web.mark_success_viewed(root)
                timestamp = (root / "success-viewed.json").read_bytes()
                second = object.__new__(harp_web.HARPWebState)
                self.assertTrue(second.session_view("test", 0)["success_viewed"])
                with patch.object(harp_web, "read_events", side_effect=AssertionError("Prefetch must not read the event history")):
                    preview = second.session_view("test", 0, include_events=False)
                    self.assertEqual(preview["events"], [])
                    self.assertEqual(preview["event_cursor"], 0)
                harp_web.mark_success_viewed(root)
                self.assertEqual(timestamp, (root / "success-viewed.json").read_bytes())
            self.assertEqual(before, (root / "session.json").read_bytes())
            self.assertFalse((root / "events.jsonl").exists())

    def test_unverified_or_active_sessions_cannot_be_acknowledged(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            for state in ({"status": "active", "success": "yes"},
                          {"status": "finished", "success": "unknown"},
                          {"status": "finished", "success": "yes"}):
                harp.save_session(root, state)
                with patch.object(harp_artifacts, "flag_status", return_value={}), self.assertRaises(ValueError):
                    harp_web.mark_success_viewed(root)
                self.assertFalse((root / "success-viewed.json").exists())


if __name__ == "__main__":
    unittest.main()
