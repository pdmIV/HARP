import io
import json
import os
import tempfile
import threading
import time
import unittest
from collections import deque
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import harp
import harp_mcp
import harp_secret
import harp_web
import harp_artifacts


class DummyTerminal:
    def run(self, command, timeout, **kwargs):
        return {"command": command, "exit_code": 0, "seconds": 0.1,
                "output": "one result", "truncated": False, "as_root": kwargs.get("as_root", False)}

    def stats(self):
        return {"MemUsage": "1MiB / 512MiB"}


class HarpTests(unittest.TestCase):
    def test_nmap_preprocessing_keeps_only_open_ports(self):
        xml = '<nmaprun><host><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>'
        self.assertEqual(harp.parse_nmap_xml(xml), [
            {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "", "version": ""}
        ])

    def make_session(self, directory):
        cfg = json.loads(Path("harp.example.json").read_text())
        session = {"status": "active", "mode": "hybrid", "container": "test", "config": cfg,
                   "target": "target", "started_at": harp.now(), "started_epoch": 1,
                   "recon": [], "local_steps": 0, "local_calls": [], "observations": [],
                   "memory_notes": [], "oracle_actions": 0, "root_approvals": 0,
                   "oracle_usage": None, "human_intervention_at": None,
                   "success": "unknown", "time_to_success_seconds": None,
                   "success_at": None, "success_epoch": None}
        harp.save_session(directory, session)

    def test_repeated_command_stops_delegation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            reply = '{"thought":"test","command":"echo result","done":false}'
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "inspect target", 3)
            state = harp.load_session(path)
            self.assertEqual(state["local_steps"], 1)
            self.assertEqual(state["last_delegate_stop"], "repeated_command")
            self.assertIsNone(state["human_intervention_at"])

    def test_root_request_does_not_execute_or_count_as_human_help(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            reply = '{"thought":"needs raw socket","needs_root":true,"command":"nmap -sS target","done":false}'
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "inspect target", 3)
            state = harp.load_session(path)
            self.assertEqual(state["last_delegate_stop"], "root_requested")
            self.assertEqual(state["pending_root_command"], "nmap -sS target")
            self.assertEqual(state["local_steps"], 0)
            self.assertEqual(state["root_approvals"], 0)
            self.assertIsNone(state["human_intervention_at"])

    def test_http_probe_extracts_status_and_body(self):
        self.assertEqual(harp.parse_http_response("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nWelcome"),
                         {"status": 200, "body_excerpt": "Welcome"})

    def test_context_compaction_keeps_prompt_below_budget(self):
        model = {"model": "test"}
        context = {"recent_terminal_results": [{"output": "x" * 8000}],
                   "unverified_memory_notes": ["note" * 300] * 12,
                   "prior_commands": ["echo test"] * 30}
        with patch.object(harp, "count_chat_tokens", side_effect=lambda m, s, u: len(u) // 4):
            user, tokens, compacted = harp.fit_context(model, context, 1000)
        self.assertTrue(compacted)
        self.assertLessEqual(tokens, 1000)
        self.assertEqual(len(context["recent_terminal_results"][0]["output"]), 8000)

    def test_mcp_lists_root_tool(self):
        answer = harp_mcp.response({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {tool["name"] for tool in answer["result"]["tools"]}
        self.assertIn("terminal_root", names)

    def test_vpn_mode_requires_exact_target_ip(self):
        config = json.loads(Path("harp.htb.example.json").read_text())
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config))
            with self.assertRaises(ValueError):
                harp.load_config(path)
            config["target"] = "10.10.11.123"
            path.write_text(json.dumps(config))
            self.assertEqual(harp.load_config(path)["target"], "10.10.11.123")

    def test_local_request_disables_unsloth_host_tools(self):
        model = json.loads(Path("harp.example.json").read_text())["local"]
        model["model"] = "test-model"
        captured = []

        def fake_open(request, timeout):
            captured.append(json.loads(request.data))
            reply = {"choices": [{"message": {"content": "{}"}}],
                     "usage": {"prompt_tokens": 12, "completion_tokens": 3}}
            return io.BytesIO(json.dumps(reply).encode())

        ledger = []
        with patch.dict(os.environ, {"UNSLOTH_API_KEY": "test-secret"}), \
             patch.object(harp.urllib.request, "urlopen", side_effect=fake_open):
            harp.api_chat(model, "system", "user", ledger)
        self.assertIs(captured[0]["enable_tools"], False)
        self.assertEqual(captured[0]["enabled_tools"], [])
        self.assertEqual(ledger[0]["prompt_tokens"], 12)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI test")
    def test_encrypted_key_round_trip(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            secret_dir = Path(temp) / ".secrets"
            secret_dir.mkdir()
            key_file = secret_dir / "unsloth.key"
            harp_secret.save_key(key_file, "test-value")
            model = {"api_key_env": "UNSLOTH_API_KEY"}
            with patch.object(harp, "__file__", str(Path(temp) / "harp.py")), \
                 patch.dict(os.environ, {"UNSLOTH_API_KEY": ""}):
                self.assertEqual(harp.local_api_key(model), "test-value")

    def test_approved_root_command_is_not_tactical_intervention(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()):
                harp.root_exec(path, "id")
            state = harp.load_session(path)
            self.assertEqual(state["root_approvals"], 1)
            self.assertTrue(state["observations"][-1]["as_root"])
            self.assertIsNone(state["human_intervention_at"])

    def test_web_launch_arguments_and_log_redaction(self):
        args = harp_web.build_launch_args({"model": "example/model:Q4_K_P", "port": 8888,
                                           "context": 32768, "parallel": 1,
                                           "cache_k": "bf16", "cache_v": "q8_0"})
        self.assertIn("--disable-tools", args)
        self.assertEqual(args[args.index("--max-seq-length") + 1], "32768")
        self.assertNotIn("sk-unsloth-test123", harp_web.redact_model_log("API Key: sk-unsloth-test123"))

    def test_web_captures_generated_key_without_logging_it(self):
        state = object.__new__(harp_web.HARPWebState)
        state.lock = threading.RLock()
        state.model_logs = deque(maxlen=500)
        state.model_log_id = 0
        process = type("FakeProcess", (), {"stdout": io.StringIO("API Key: sk-unsloth-test123\n"),
                                            "returncode": 0,
                                            "wait": lambda self: 0})()
        with patch.object(harp_web.harp_secret, "save_key") as save_key:
            state._read_model_output(process)
        save_key.assert_called_once()
        logs = list(state.model_logs)
        self.assertTrue(any("stored encrypted" in item["line"] for item in logs))
        self.assertNotIn("sk-unsloth-test123", str(logs))

    def test_evidence_backed_flag_capture_and_unseen_status(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            result = {"command": "cat /home/htb/user.txt", "exit_code": 0,
                      "output": "0123456789abcdef0123456789abcdef\n"}
            self.assertEqual(harp_artifacts.capture_flags_from_result(path, result)[0]["title"], "user.txt")
            self.assertTrue(harp_artifacts.flag_status(path)["user.txt"]["unseen"])
            self.assertFalse(harp_artifacts.flag_status(path)["root.txt"]["found"])
            harp_artifacts.mark_flags_seen(path)
            self.assertFalse(harp_artifacts.flag_status(path)["user.txt"]["unseen"])
            self.assertEqual(harp_artifacts.capture_flags_from_result(path, result)[0]["id"],
                             harp_artifacts.list_artifacts(path)[0]["id"])
            self.assertEqual(harp_artifacts.capture_flags_from_result(path,
                {"command": "md5sum /home/htb/root.txt", "exit_code": 0,
                 "output": "f" * 32 + "  root.txt"}), [])

    def test_two_captured_flags_mark_success(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            for name, value in (("user.txt", "a" * 32), ("root.txt", "b" * 32)):
                harp_artifacts.capture_flags_from_result(path,
                    {"command": f"cat /path/{name}", "exit_code": 0, "output": value})
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()):
                harp_artifacts.maybe_mark_flag_success(path)
            state = harp.load_session(path)
            self.assertEqual(state["success"], "yes")
            self.assertTrue(state["success_before_human_intervention"])

    def test_flag_acknowledgment_does_not_hide_later_flag(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            user = harp_artifacts.capture_flags_from_result(path,
                {"command": "cat user.txt", "exit_code": 0, "output": "a" * 32})[0]
            harp_artifacts.capture_flags_from_result(path,
                {"command": "cat root.txt", "exit_code": 0, "output": "b" * 32})
            harp_artifacts.mark_flags_seen(path, [user["id"]])
            flags = harp_artifacts.flag_status(path)
            self.assertFalse(flags["user.txt"]["unseen"])
            self.assertTrue(flags["root.txt"]["unseen"])

    def test_model_artifact_requires_exact_terminal_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            session = {"observations": [{"command": "cat notes.txt", "output": "account=demo-pass-123\n"}]}
            proposal = {"kind": "credential", "title": "Service password", "value": "demo-pass-123"}
            item = harp_artifacts.capture_model_artifact(path, session, proposal)
            self.assertEqual(item["value"], "demo-pass-123")
            self.assertIsNone(harp_artifacts.capture_model_artifact(path, session,
                {"kind": "credential", "title": "Hallucinated", "value": "not-in-output"}))
            self.assertEqual(len(harp_artifacts.list_artifacts(path)), 1)

    def test_document_capture_is_bounded_and_preserved(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            with patch.object(harp, "terminal_for", return_value=SimpleNamespace(name="demo-container")), \
                 patch.object(harp_artifacts.subprocess, "run",
                              return_value=SimpleNamespace(returncode=0, stdout=b"Lab document\n")) as run:
                item = harp_artifacts.capture_document_file(path, {"status": "active"},
                                                           "/workspace/evidence/notes.txt", "Notes")
            self.assertEqual(item["attachment"]["filename"], "notes.txt")
            self.assertEqual((path / "artifact_files" / item["id"]).read_bytes(), b"Lab document\n")
            self.assertIn("docker", run.call_args.args[0])
            with self.assertRaises(ValueError):
                harp_artifacts.capture_document_file(path, {"status": "active"},
                                                     "/workspace/../etc/passwd", "Invalid")

    def test_oracle_root_waits_for_exact_gui_approval(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            root = Path(temp)
            runs = root / "runs"
            path = runs / "test-session"
            path.mkdir(parents=True)
            (path / "session.json").write_text("{}", encoding="utf-8")
            heartbeat = root / ".gui_heartbeat"
            heartbeat.touch()
            executed = []
            result = []
            with patch.object(harp_mcp, "RUNS", runs), \
                 patch.object(harp_mcp, "GUI_HEARTBEAT", heartbeat), \
                 patch.object(harp, "root_exec", side_effect=lambda p, c: executed.append((p, c))):
                thread = threading.Thread(target=lambda: result.append(harp_mcp.terminal_root(str(path), "id")))
                thread.start()
                requests = []
                for _ in range(100):
                    requests = list((path / "approvals").glob("*.request.json"))
                    if requests:
                        break
                    time.sleep(0.01)
                self.assertEqual(len(requests), 1)
                request = json.loads(requests[0].read_text(encoding="utf-8"))
                decision = requests[0].with_name(requests[0].name.replace(".request.json", ".decision.json"))
                decision.write_text(json.dumps({"id": request["id"], "command": "id", "approved": True}), encoding="utf-8")
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(executed, [(path, "id")])
            self.assertEqual(len(result), 1)

    def test_oracle_plan_is_published_to_event_log(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            runs = Path(temp) / "runs"
            path = runs / "session"
            path.mkdir(parents=True)
            (path / "session.json").write_text("{}", encoding="utf-8")
            with patch.object(harp_mcp, "RUNS", runs):
                harp_mcp.record_oracle_plan(str(path), "Inspect HTTP evidence, then delegate service review.")
            event = json.loads((path / "events.jsonl").read_text(encoding="utf-8"))
            self.assertEqual(event["type"], "oracle_plan")
            self.assertIn("delegate", event["plan"])

    def test_web_root_denial_clears_pending_without_tactical_help(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            runs = Path(temp) / "runs"
            path = runs / "20261103-000000-abcdef"
            path.mkdir(parents=True)
            self.make_session(path)
            state = harp.load_session(path)
            state["pending_root_command"] = "id"
            harp.save_session(path, state)
            web_state = object.__new__(harp_web.HARPWebState)
            with patch.object(harp_web, "RUNS", runs):
                self.assertIsNone(web_state.decide_approval(path.name, "local", False))
            updated = harp.load_session(path)
            self.assertIsNone(updated["pending_root_command"])
            self.assertIsNone(updated["human_intervention_at"])
            self.assertEqual(updated["root_approvals"], 0)


if __name__ == "__main__":
    unittest.main()
