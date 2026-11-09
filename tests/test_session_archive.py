import json
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import harp_replay
import harp_session_archive
import harp_version
import harp_web


class SessionArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source-run"
        self.source.mkdir()
        self.runs = self.root / "runs"
        self.archive = self.root / "saved.zip"
        self.session = {
            "status": "finished", "mode": "hybrid", "target": "10.0.0.1",
            "started_at": "2026-11-08T00:00:00+00:00", "started_epoch": 1794096000.0,
            "duration_seconds": 4, "success": "unknown", "recon": [],
            "config": {"max_steps": 5, "local": {"provider": "zai"}, "oracle": {"provider": "zai"}},
            "observations": [], "local_calls": [], "local_steps": 0,
            "oracle_actions": 0, "oracle_usage": None, "human_intervention_at": None,
        }
        (self.source / "session.json").write_text(json.dumps(self.session), encoding="utf-8")
        (self.source / "events.jsonl").write_text(
            '{"at":"2026-11-08T00:00:04+00:00","type":"finish","success":"unknown"}\n',
            encoding="utf-8")
        evidence = self.source / "artifact_files" / "sample"
        evidence.parent.mkdir()
        evidence.write_bytes(b"private example evidence")

    def test_round_trip_preserves_session_files_and_replay(self):
        harp_session_archive.export_session(self.source, self.archive)
        with zipfile.ZipFile(self.archive) as saved:
            self.assertEqual(json.loads(saved.read("harp-session.json"))["harp_version"], harp_version.VERSION)
        imported = harp_session_archive.import_session(self.archive, self.runs)
        self.assertNotEqual(imported.name, self.source.name)
        self.assertEqual((imported / "artifact_files" / "sample").read_bytes(), b"private example evidence")
        self.assertEqual((imported / "events.jsonl").read_bytes(), (self.source / "events.jsonl").read_bytes())
        self.assertEqual(json.loads((imported / "session.json").read_text())["imported_from"]["session"], self.source.name)
        sidebar = harp_web._cached_sidebar_row(str(imported), (None, None, None))
        self.assertTrue(sidebar["imported"])
        replay = harp_replay.build_replay(imported, {"id": imported.name})
        self.assertTrue(replay["frames"])
        self.assertEqual(replay["frames"][-1]["summary"]["status"], "finished")

    def test_authenticated_web_export_and_import(self):
        self.runs.mkdir()
        run = self.runs / "20261108-000000-abcdef"
        self.source.replace(run)
        export = object.__new__(harp_web.HARPRequestHandler)
        export.path = f"/api/sessions/{run.name}/archive"
        export._authorized = Mock(return_value=True)
        export.send_response = Mock()
        export.send_header = Mock()
        export.end_headers = Mock()
        export.wfile = io.BytesIO()
        with patch.object(harp_web, "RUNS", self.runs):
            export.do_GET()
            self.assertEqual(export.send_response.call_args.args[0], 200)
            payload = export.wfile.getvalue()
            with zipfile.ZipFile(io.BytesIO(payload)) as saved:
                self.assertIn("session/events.jsonl", saved.namelist())

            upload = object.__new__(harp_web.HARPRequestHandler)
            upload.path = "/api/sessions/import"
            upload._authorized = Mock(return_value=True)
            upload.headers = {"Content-Type": "application/zip", "Content-Length": str(len(payload))}
            upload.rfile = io.BytesIO(payload)
            upload._json = Mock()
            upload.do_POST()
            status, response = upload._json.call_args.args
            self.assertEqual(status, 200)
            self.assertTrue((self.runs / response["session"] / "session.json").exists())

    def test_finished_session_required(self):
        self.session["status"] = "active"
        (self.source / "session.json").write_text(json.dumps(self.session), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Finish the session"):
            harp_session_archive.export_session(self.source, self.archive)

    def test_rejects_traversal_and_duplicate_paths(self):
        for extra in ("session/../escape", "session/SESSION.json"):
            with self.subTest(extra=extra):
                with zipfile.ZipFile(self.archive, "w") as saved:
                    saved.writestr("harp-session.json", json.dumps({"format": "harp-session", "format_version": 1}))
                    saved.writestr("session/session.json", json.dumps(self.session))
                    saved.writestr(extra, "bad")
                with self.assertRaises(ValueError):
                    harp_session_archive.import_session(self.archive, self.runs)
                self.assertEqual(list(self.runs.glob("*/session.json")), [])

    def test_rejects_unknown_format(self):
        with zipfile.ZipFile(self.archive, "w") as saved:
            saved.writestr("harp-session.json", json.dumps({"format": "harp-session", "format_version": 99}))
            saved.writestr("session/session.json", json.dumps(self.session))
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            harp_session_archive.import_session(self.archive, self.runs)


if __name__ == "__main__":
    unittest.main()
