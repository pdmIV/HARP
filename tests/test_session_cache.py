import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_web


class SessionCacheTests(unittest.TestCase):
    def test_unchanged_session_reuses_parse_and_changed_session_invalidates(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            harp.save_session(root, {"status": "finished", "version": 1})
            with patch.object(harp, "load_session", wraps=harp.load_session) as read:
                self.assertEqual(harp_web.web_session(root)["version"], 1)
                self.assertEqual(harp_web.web_session(root)["version"], 1)
                self.assertEqual(read.call_count, 1)
                harp.save_session(root, {"status": "finished", "version": 222})
                self.assertEqual(harp_web.web_session(root)["version"], 222)
                self.assertEqual(read.call_count, 2)

    def test_activity_cache_detects_appended_events_and_does_not_share_mutable_result(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            harp.append_event(root, {"type": "oracle_plan", "plan": "First plan"})
            first = harp_web.latest_activity(root)
            first["oracle_plan"] = "caller changed this"
            self.assertEqual(harp_web.latest_activity(root)["oracle_plan"], "First plan")
            harp.append_event(root, {"type": "oracle_plan", "plan": "Updated plan"})
            harp.append_event(root, {"type": "oracle_nim_stopped", "reason": "budget"})
            latest = harp_web.latest_activity(root)
            self.assertEqual(latest["oracle_plan"], "Updated plan")
            self.assertEqual(latest["oracle_stopped"], "budget")

    def test_large_raw_session_does_not_fill_parse_cache(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            harp.save_session(root, {"raw": "x" * 2_000_001})
            with patch.object(harp_web, "_cached_web_session") as cached:
                self.assertEqual(len(harp_web.web_session(root)["raw"]), 2_000_001)
                cached.assert_not_called()

    def test_sidebar_includes_125_sessions_and_reuses_unchanged_metadata(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            for index in range(125):
                directory = root / ("20261108-120000-" + format(index, "06x"))
                directory.mkdir()
                harp.save_session(directory, {"status": "finished", "mode": "hybrid",
                    "target": "synthetic-" + str(index), "started_at": "2026-11-08T12:00:00+00:00"})
            web = object.__new__(harp_web.HARPWebState)
            with patch.object(harp_web, "RUNS", root), patch.object(harp, "load_session", wraps=harp.load_session) as read:
                rows = web.session_list()
                self.assertEqual(len(rows), 125)
                self.assertEqual(read.call_count, 125)
                self.assertEqual(len(web.session_list()), 125)
                self.assertEqual(read.call_count, 125, "Warm sidebar must not reparse all session JSON")
                newest = root / rows[0]["id"]
                (newest / "artifacts.jsonl").write_text(json.dumps({"id": "synthetic-user-flag", "kind": "flag",
                    "title": "user.txt", "value": "0" * 32, "at": "now", "evidence_backed": True}) + "\n")
                self.assertEqual(web.session_list()[0]["flags_found"], 1)


if __name__ == "__main__":
    unittest.main()
