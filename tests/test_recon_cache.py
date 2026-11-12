import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp


OPEN_SCAN = ('<nmaprun><scaninfo protocol="tcp" numservices="65535" services="1-65535"/>'
             '<host><ports><port protocol="tcp" portid="22"><state state="open"/>'
             '<service name="ssh"/></port></ports></host>'
             '<runstats><finished exit="success"/></runstats></nmaprun>')


class ReconCacheTests(unittest.TestCase):
    def config(self):
        cfg = json.loads(Path("harp.example.json").read_text(encoding="utf-8"))
        return {**cfg, "target": "192.0.2.1"}

    def snapshot(self, cfg):
        # Shape of the legacy cache used by the failing session: no coverage,
        # zero services, a successful-looking capture timestamp and source ID.
        return {"schema": 1, "profile": harp.recon_profile(cfg),
                "source_session": "20261111-000000-abcdef", "captured_at": 1,
                "hostnames": ["example.htb"], "recon": [],
                "http_probes": [], "smb_probes": []}

    def test_empty_and_malformed_cache_cannot_be_reused(self):
        cfg = self.config()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            snapshot = self.snapshot(cfg)
            for findings in ([], [None], [{}], [{"port": True}], [{"port": 0}],
                             [{"port": 65536}], [{"port": "22"}],
                             [{"port": 22, "protocol": "invalid"}]):
                with self.subTest(findings=findings):
                    snapshot["recon"] = findings
                    harp.save_recon_snapshot(root, cfg, snapshot)
                    self.assertIsNone(harp.find_recon_snapshot(root, cfg))
                    self.assertEqual(harp.hostname_recon_candidates(
                        root, {**cfg, "target": "192.0.2.2"}), [])
            snapshot["recon"] = [{"port": 22, "protocol": "tcp"}]
            harp.save_recon_snapshot(root, cfg, snapshot)
            # Valid captures stay reusable even when their old run was deleted.
            self.assertEqual(harp.find_recon_snapshot(root, cfg), snapshot)

    def test_empty_historical_run_cannot_seed_cache(self):
        cfg = self.config()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            old = root / "20261111-000000-abcdef"
            old.mkdir()
            harp.save_session(old, {"config": cfg, "target": cfg["target"],
                                   "recon_stage": "Complete", "recon_finished_epoch": 1,
                                   "recon_hostnames": ["example.htb"], "recon": []})
            self.assertIsNone(harp.find_recon_snapshot(root, cfg))
            self.assertEqual(harp.hostname_recon_candidates(
                root, {**cfg, "target": "192.0.2.2"}), [])
            self.assertFalse(harp.recon_cache_path(root, cfg).exists())

    def test_startup_rescans_empty_cache_and_preserves_coverage(self):
        self.run_startup_case(OPEN_SCAN)

    def test_empty_fresh_scan_stops_before_model_handoff(self):
        self.run_startup_case('<nmaprun><host/><runstats><finished exit="success"/>'
                              '</runstats></nmaprun>')

    def run_startup_case(self, output):
        cfg = self.config()
        commands = []

        class FakeTerminal:
            name = "fake-kali"
            event_dir = None
            recon_mode = False
            recon_stage = ""
            def __init__(self, _cfg): pass
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def run(self, command, _timeout, **_kwargs):
                commands.append(command)
                return {"command": command, "exit_code": 0, "seconds": 0.1,
                        "output": output, "truncated": False, "as_root": False}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp, "KaliTerminal", FakeTerminal), \
             patch.object(harp, "docker", return_value="image-id"), \
             patch.object(harp, "ensure_seclists"), \
             patch.object(harp, "ensure_whippet"), \
             patch.object(harp, "deterministic_http_probes", return_value=[]), \
             patch.object(harp, "deterministic_smb_probes", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            harp.save_recon_snapshot(root, cfg, self.snapshot(cfg))
            if output == OPEN_SCAN:
                run = harp.start_session(cfg, root)
                session = harp.load_session(run)
                self.assertEqual(session["recon_stage"], "Complete")
                self.assertTrue(session["recon_coverage"]["full_tcp_completed"])
                count = len(commands)
                self.assertGreater(count, 0)
                reused = harp.load_session(harp.start_session(cfg, root))
                self.assertEqual(reused["recon_stage"], "Reused")
                self.assertEqual(len(commands), count)
                self.assertEqual(reused["recon_coverage"], session["recon_coverage"])
            else:
                with self.assertRaisesRegex(RuntimeError, "no open services"):
                    harp.start_session(cfg, root)
                run = next(root.glob("*/session.json")).parent
                session = harp.load_session(run)
                self.assertEqual(session["status"], "finished")
                self.assertEqual(session["recon_stage"], "Failed")
                self.assertEqual(session["local_steps"], 0)
                self.assertIn("VPN/route", session["startup_error"])
                self.assertIsNone(harp.find_recon_snapshot(root, cfg))
                events = [json.loads(line) for line in
                          (run / "events.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertIn("recon_failed", [event["type"] for event in events])
                self.assertNotIn("recon_finished", [event["type"] for event in events])
                self.assertTrue(commands)
