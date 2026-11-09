"""Crash recovery uses synthetic sessions and never starts a Kali runtime."""
import json
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_mcp
import harp_web


class RecoveryTests(unittest.TestCase):
    def test_mcp_headless_start_records_owner(self):
        with patch.object(harp_mcp, "_session_owner", return_value="a" * 32), \
             patch.object(harp, "load_config", return_value={}), \
             patch.object(harp, "start_session", return_value=Path("synthetic")) as start:
            harp_mcp.start_session()
        self.assertEqual(start.call_args.kwargs["owner_id"], "a" * 32)

    def test_mcp_startup_recovery_keeps_protocol_output_clean(self):
        request = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        output = io.StringIO()
        with patch.object(harp_mcp.sys, "stdin", io.StringIO(request)), \
             patch.object(harp_mcp.sys, "stdout", output), \
             patch.object(harp_web, "recover_interrupted_sessions", return_value=0) as recover:
            harp_mcp.main()
        recover.assert_called_once()
        self.assertEqual(json.loads(output.getvalue())["result"]["serverInfo"]["name"], "harp")

    def test_stale_owner_recovers_but_live_owner_is_left_alone(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            run = root / "runs" / "session-one"
            run.mkdir(parents=True)
            owner = "a" * 32
            harp.save_session(run, {"status": "active", "owner_id": owner,
                                    "started_epoch": 100, "runtime": "wsl"})
            heartbeat = root / (".session-owner-" + owner + ".heartbeat")
            heartbeat.write_text('{"pid":99999}', encoding="utf-8")
            os.utime(heartbeat, (120, 120))
            with patch.object(harp_web.os, "kill", return_value=None), \
                 patch.object(harp, "recover_interrupted_session") as recover:
                self.assertEqual(harp_web.recover_interrupted_sessions(root / "runs", root,
                                                                        now_epoch=200), 0)
                recover.assert_not_called()
            with patch.object(harp_web.os, "kill", side_effect=ProcessLookupError), \
                 patch.object(harp, "recover_interrupted_session") as recover:
                self.assertEqual(harp_web.recover_interrupted_sessions(root / "runs", root,
                                                                        now_epoch=200), 1)
                recover.assert_called_once_with(run, 120)

    def test_recovery_preserves_evidence_and_excludes_offline_time(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            run = Path(temp)
            harp.save_session(run, {"status": "active", "runtime": "wsl", "started_epoch": 100,
                                    "success_epoch": None, "success": "unknown", "recon_stage": "Complete",
                                    "observations": [{"command": "read evidence", "output": "saved"}]})
            with patch.object(harp, "terminal_for") as terminal, patch.object(harp, "docker") as docker:
                harp.recover_interrupted_session(run, 125)
            terminal.assert_not_called()
            docker.assert_not_called()
            state = harp.load_session(run)
            self.assertEqual(state["status"], "finished")
            self.assertEqual(state["termination_reason"], "host_interrupted")
            self.assertEqual(state["duration_seconds"], 25)
            self.assertEqual(state["observations"][0]["output"], "saved")
            events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
            self.assertIn("session_recovered_after_host_interrupt", [event["type"] for event in events])
            self.assertTrue(all(event["at"] == state["finished_at"] for event in events))
            harp.recover_interrupted_session(run, 200)
            self.assertEqual(len((run / "events.jsonl").read_text().splitlines()), len(events))

    def test_recovery_records_docker_cleanup_failure(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            run = Path(temp)
            harp.save_session(run, {"status": "recon", "runtime": "docker", "started_epoch": 100,
                                    "success_epoch": None, "success": "unknown",
                                    "container": "harp-run-" + "a" * 12})
            with patch.object(harp, "docker", side_effect=RuntimeError("daemon unavailable")):
                harp.recover_interrupted_session(run, 120)
            state = harp.load_session(run)
            self.assertEqual(state["status"], "finished")
            self.assertEqual(state["recon_stage"], "Interrupted")
            self.assertIn("Docker cleanup", state["cleanup_error"])


if __name__ == "__main__":
    unittest.main()
