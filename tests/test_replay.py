import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import harp
import harp_artifacts
import harp_replay
import harp_web
import test_harp as fixtures


class ReplayTests(unittest.TestCase):
    def make_run(self, path):
        fixtures.HarpTests.make_session(self, path)
        state = harp.load_session(path)
        state.update(status="finished", duration_seconds=40, success="yes")
        harp.save_session(path, state)
        events = [
            {"type": "recon_finished", "at": "1970-01-01T00:00:05+00:00"},
            {"type": "oracle_plan", "plan": "Read the user flag", "at": "1970-01-01T00:00:10+00:00"},
            {"type": "local_terminal", "at": "1970-01-01T00:00:20+00:00", "result": {
                "command": "cat user.txt", "output": "a" * 32, "exit_code": 0}},
            {"type": "local_terminal", "at": "1970-01-01T00:00:30+00:00", "result": {
                "command": "nxc winrm target -X 'type root.txt'", "exit_code": 0,
                "output": "WINRM 10.10.10.5 5985 DC " + "b" * 32}},
            {"type": "finish", "success": "unknown", "at": "1970-01-01T00:00:41+00:00"},
            {"type": "success_reconciled", "at": "2026-11-08T00:00:00+00:00"},
        ]
        (path / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events))

    def test_replay_is_read_only_and_does_not_reveal_future_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_run(path)
            def fingerprints():
                return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir()}
            before = fingerprints()
            with patch.object(harp, "terminal_for", side_effect=AssertionError("No runtime access")), \
                 patch.object(harp, "api_chat", side_effect=AssertionError("No model calls")), \
                 patch.object(harp_artifacts, "register_artifact", side_effect=AssertionError("No registry writes")):
                replay = harp_replay.build_replay(path, {"id": "saved", "events": [], "pending_approval": {"id": "old"}})
            self.assertEqual(before, fingerprints())
            self.assertEqual(replay["duration_seconds"], 40)
            first, user, root, last = (replay["frames"][i] for i in (0, 3, 4, -1))
            self.assertFalse(first["artifacts"])
            self.assertFalse(first["activity"]["oracle_plan"])
            self.assertEqual(first["summary"]["terminal_tool_calls"], 0)
            self.assertTrue(user["flags"]["user.txt"]["found"])
            self.assertFalse(user["flags"]["root.txt"]["found"])
            self.assertEqual(len(user["artifacts"]), 1)
            self.assertEqual(root["summary"]["time_to_success_seconds"], 29)
            self.assertTrue(all(f["found"] for f in last["flags"].values()))
            self.assertEqual(last["summary"]["status"], "finished")
            self.assertEqual(last["summary"]["success"], "yes")
            self.assertIsNone(replay["session"]["pending_approval"])
            self.assertTrue(replay["session"]["replay"])

    def test_rejects_active_sessions(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            with self.assertRaisesRegex(ValueError, "finished"):
                harp_replay.build_replay(path, {})

    def test_research_status_is_reconstructed_without_revealing_future_requests(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_run(path)
            state = harp.load_session(path)
            state["config"]["oracle"]["web_search_enabled"] = True
            harp.save_session(path, state)
            events = [
                {"type": "recon_finished", "at": "1970-01-01T00:00:05+00:00"},
                {"type": "research_started", "id": "one", "operation": "search", "at": "1970-01-01T00:00:10+00:00"},
                {"type": "research_completed", "id": "one", "operation": "search", "status": "failed", "at": "1970-01-01T00:00:15+00:00"},
                {"type": "finish", "at": "1970-01-01T00:00:20+00:00"}]
            (path / "events.jsonl").write_text("\n".join(json.dumps(event) for event in events))
            replay = harp_replay.build_replay(path, {})
            self.assertEqual([frame["summary"]["research_status"] for frame in replay["frames"]],
                             ["enabled_unused", "enabled_unused", "requested", "failed", "failed"])

    def test_authenticated_replay_endpoint(self):
        handler = harp_web.HARPRequestHandler.__new__(harp_web.HARPRequestHandler)
        handler.path = "/api/sessions/20261107-183134-ba6eec/replay"
        handler._authorized = lambda: True
        handler.server = SimpleNamespace(state=SimpleNamespace(session_view=lambda *_args: {"id": "saved"}))
        responses = []
        handler._json = lambda status, data: responses.append((status, data))
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_run(path)
            with patch.object(harp_web, "session_path", return_value=path):
                handler.do_GET()
        self.assertEqual(responses[0][0], 200)
        self.assertTrue(responses[0][1]["session"]["replay"])
        handler._authorized = lambda: False
        with patch.object(harp_replay, "build_replay") as build:
            handler.do_GET()
            build.assert_not_called()
