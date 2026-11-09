import base64
import io
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import harp
import harp_artifacts
import harp_mcp
import harp_web
import harp_zai


PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=")


class ImageTests(unittest.TestCase):
    def session(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["local"].update(provider="zai", model="glm-5.3-flash", max_input_tokens=6000)
        return {"status": "active", "mode": "hybrid", "container": "test", "config": cfg,
                "target": "target", "workspace": "/workspace", "recon": [], "local_steps": 0,
                "local_calls": [], "observations": [], "memory_notes": [], "oracle_actions": 0,
                "started_epoch": 1, "success": "unknown", "oracle_usage": None,
                "human_intervention_at": None}

    def capture(self, path, data=PNG, source="/workspace/evidence/clue.png"):
        terminal = harp.KaliTerminal(self.session()["config"])
        with patch.object(harp, "terminal_for", return_value=terminal), patch.object(
                harp_artifacts.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=data)):
            return harp_artifacts.capture_document_file(path, self.session(), source, "Image clue")

    def test_capture_classifies_bytes_not_extension_and_preserves_exact_file(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            artifact = self.capture(path, source="/workspace/clue.bin")
            self.assertEqual(artifact["kind"], "image")
            self.assertEqual(artifact["attachment"]["media_type"], "image/png")
            self.assertEqual((path / "artifact_files" / artifact["id"]).read_bytes(), PNG)
            self.assertEqual(self.capture(path, source="/workspace/clue.bin")["id"], artifact["id"])
            part, reserve = harp_artifacts.image_input(path, artifact)
            self.assertEqual(base64.b64decode(part["image_url"]["url"].split(",")[1]), PNG)
            self.assertGreater(reserve, 1024)
            self.assertEqual(len(list((path / "artifact_files").iterdir())), 1)

    def test_raster_limits_and_unsupported_files(self):
        self.assertIsNone(harp_artifacts.image_metadata(b'<svg onload="evil()"/>'))
        self.assertIsNone(harp_artifacts.image_metadata(b"not a png"))
        self.assertIsNone(harp_artifacts.image_metadata(PNG[:20]))
        self.assertIsNone(harp_artifacts.image_metadata(PNG[:16] + struct.pack(">II", 99999, 1) + PNG[24:]))
        jpeg = b"\xff\xd8\xff\xc0\x00\x0b\x08\x00\x10\x00\x20\x01\x01\x11\x00\xff\xd9"
        self.assertEqual(harp_artifacts.image_metadata(jpeg), {"media_type": "image/jpeg", "width": 32, "height": 16})
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            artifact = self.capture(path, b"fake PNG", "/workspace/fake.png")
            self.assertEqual(artifact["kind"], "document")
            with self.assertRaisesRegex(ValueError, "PNG/JPEG"):
                harp_artifacts.image_input(path, artifact)
            artifact = self.capture(path)
            stored = path / "artifact_files" / artifact["id"]
            stored.write_bytes(PNG + b"tampered")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                harp_artifacts.image_input(path, artifact)
            stored.write_bytes(PNG + b"x" * 5_000_000)
            with self.assertRaisesRegex(ValueError, "5 MB"):
                harp_artifacts.image_input(path, artifact)

    def test_workspace_and_active_session_checks(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(harp, "terminal_for") as terminal:
            for source in ("/workspace/../etc/passwd", "/mnt/c/clue.png", "/workspace2/clue.png"):
                with self.assertRaises(ValueError):
                    harp_artifacts.capture_document_file(Path(temp), self.session(), source, "Clue")
            with self.assertRaises(ValueError):
                harp_artifacts.capture_document_file(Path(temp), {**self.session(), "status": "finished"}, "/workspace/clue.png", "Clue")
            terminal.assert_not_called()

    def run_delegate(self, path, replies, model=None, budget=1):
        state = self.session()
        if model:
            state["config"]["local"]["model"] = model
        harp.save_session(path, state)
        terminal = harp.KaliTerminal(state["config"])
        responses = [io.StringIO(json.dumps({"choices": [{"message": {"content": json.dumps(reply)},
                          "finish_reason": "stop"}], "usage": {"prompt_tokens": 123, "completion_tokens": 12}})) for reply in replies]
        with patch.object(harp, "terminal_for", return_value=terminal), \
             patch.object(terminal, "run") as commands, \
             patch.object(harp, "ensure_whippet"), \
             patch.object(harp, "count_chat_tokens", return_value=250), \
             patch.object(harp_zai, "key", return_value="test-key"), \
             patch.object(harp_zai.urllib.request, "urlopen", side_effect=responses) as send, \
             patch.object(harp_artifacts.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=PNG)):
            harp.delegate(path, "Read the visible password candidate from /workspace/clue.png", budget, quiet=True)
        commands.assert_not_called()
        return [json.loads(call.args[0].data) for call in send.call_args_list]

    def test_end_to_end_capture_pixels_transcription_and_no_false_credential(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            requests = self.run_delegate(path, [
                {"read_image": {"path": "/workspace/clue.png", "title": "Relevant clue"}, "done": False},
                {"done": True, "finding": "Visible password candidate: synthetic-example; unverified",
                 "artifact": {"kind": "credential", "title": "Candidate", "value": "synthetic-example"}}])
            self.assertIsInstance(requests[0]["messages"][1]["content"], str)
            parts = requests[1]["messages"][1]["content"]
            self.assertEqual(base64.b64decode(parts[1]["image_url"]["url"].split(",")[1]), PNG)
            self.assertEqual(json.loads(parts[0]["text"])["image_input"]["source"], "/workspace/clue.png")
            artifacts = harp_artifacts.list_artifacts(path)
            self.assertEqual([a["kind"] for a in artifacts], ["image"])
            state = harp.load_session(path)
            self.assertEqual(state["last_delegate_stop"], "local_done")
            self.assertIn("synthetic-example", state["local_conclusion"])
            self.assertEqual(state["observations"], [])
            self.assertEqual(len(state["local_calls"]), 2)
            self.assertNotIn("base64", (path / "events.jsonl").read_text())
            with patch.object(harp_mcp, "run_path", return_value=path):
                inspection = json.loads(harp_mcp.inspect_session(str(path)))
            self.assertTrue(inspection["proxy_image_input_available"])
            self.assertIn("synthetic-example", inspection["unverified_local_conclusion"])

    def test_unsupported_model_stops_without_commands(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.run_delegate(path, [{"read_image": {"path": "/workspace/clue.png", "title": "Clue"}, "done": False}], "glm-5.3")
            self.assertEqual(harp.load_session(path)["last_delegate_stop"], "image_action_error")
            self.assertEqual(harp_artifacts.list_artifacts(path), [])

    def test_mixed_capture_action_is_repaired_before_any_command_or_capture(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.run_delegate(path, [
                {"capture_file": {"path": "/workspace/clue.png", "title": "Clue"}, "command": "true", "done": True},
                {"capture_file": {"path": "/workspace/clue.png", "title": "Clue"}, "command": "", "done": False},
                {"done": True, "finding": "Preserved"}])
            self.assertEqual(harp.load_session(path)["last_delegate_stop"], "local_done")
            self.assertEqual(len(harp_artifacts.list_artifacts(path)), 1)
            events = [json.loads(x) for x in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["type"] == "invalid_local_reply" for e in events), 1)
            self.assertEqual(sum(e["type"] == "local_file_capture" for e in events), 1)

    def test_conflicting_actions_exhaust_format_retries_without_commands(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            action = {"read_image": {"path": "/workspace/clue.png", "title": "Clue"}, "command": "id", "done": False}
            self.run_delegate(path, [action] * 3)
            self.assertEqual(harp.load_session(path)["last_delegate_stop"], "invalid_replies")
            self.assertEqual(harp_artifacts.list_artifacts(path), [])

    def test_capture_only_reports_success_without_sending_pixels(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            requests = self.run_delegate(path, [
                {"capture_file": {"path": "/workspace/clue.png", "title": "Clue"}, "done": False},
                {"done": True, "finding": "Preserved relevant image evidence"}], model="glm-5.3")
            context = json.loads(requests[1]["messages"][1]["content"])
            self.assertIn("Capture completed", context["last_command_feedback"])
            self.assertIsNone(context["image_input"])
            self.assertEqual(harp_artifacts.list_artifacts(path)[0]["kind"], "image")

    def test_pixels_are_released_after_structured_response(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            requests = self.run_delegate(Path(temp), [
                {"read_image": {"path": "/workspace/clue.png", "title": "Clue"}, "done": False},
                {"memory_query": "prior evidence", "done": False, "memory_note": "Unverified image transcription"},
                {"done": True, "finding": "Read the clue"}])
            self.assertIsInstance(requests[1]["messages"][1]["content"], list)
            self.assertIsInstance(requests[2]["messages"][1]["content"], str)
            context = json.loads(requests[2]["messages"][1]["content"])
            self.assertIn("Unverified image transcription", context["unverified_memory_notes"])

    def test_preview_endpoint_authentication_headers_and_download(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            artifact = self.capture(path)
            for query, expected in [("?preview=1", "image/png"), ("", "application/octet-stream")]:
                handler = object.__new__(harp_web.HARPRequestHandler)
                handler.path = f"/api/sessions/test/attachments/{artifact['id']}" + query
                handler._authorized = Mock(return_value=True)
                handler.send_response = Mock()
                handler.send_header = Mock()
                handler.end_headers = Mock()
                handler.wfile = io.BytesIO()
                with patch.object(harp_web, "session_path", return_value=path):
                    handler.do_GET()
                handler._authorized.assert_called_once()
                handler.send_response.assert_called_once_with(200)
                self.assertIn(("Content-Type", expected), [call.args for call in handler.send_header.call_args_list])
                self.assertEqual(handler.wfile.getvalue(), PNG)


if __name__ == "__main__":
    unittest.main()
