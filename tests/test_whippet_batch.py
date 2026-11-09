import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_mcp
import harp_whippet
import harp_whippet_batch as batch


class LocalTransport:
    """Runs only a synthetic test peer, never a WSL/Docker or target command."""
    def __init__(self, workspace):
        self.workspace = str(workspace)
        self.cfg = {"runtime": "synthetic"}
        self.name = "synthetic-runtime"

    def batch_argv(self, script, args):
        if script == batch.LAUNCH:
            return [sys.executable, str(Path(__file__).parent / "fixtures" / "whippet_batch_server.py"), *args[:3]]
        if script == batch.CLEANUP:
            code = '''import os,pathlib,signal,sys
p=pathlib.Path(sys.argv[1])/(".fake-"+sys.argv[2]+".pid")
if p.exists():
 try:os.kill(int(p.read_text()),signal.SIGTERM)
 except (ProcessLookupError,PermissionError):pass
 p.unlink(missing_ok=True)
print("synthetic-runtime-exited")
'''
            return [sys.executable, "-c", code, *args]
        # Windows' managed filesystem rejects strict realpath on test directories;
        # the production script executes in Linux. File existence is still checked.
        return [sys.executable, "-c", script.replace(".resolve(strict=True)", ".resolve()"), *args]


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.temp.name)
        self.terminal = LocalTransport(self.root)
        self.events = []
        (self.root / "capture.zip").write_text("snapshot-one")

    def tearDown(self):
        batch.close_all()
        batch.cleanup(self.root, self.terminal, self.events.append)
        self.temp.cleanup()

    def client(self, behavior="normal", **kwargs):
        client = batch.Batch(self.root, self.terminal, [], behavior, self.events.append, **kwargs)
        self.addCleanup(client.close)
        return client.start()

    def test_reuses_process_and_recovers_from_query_errors(self):
        client = self.client()
        pid = client.process.pid
        one = client.request({"mode": "triage", "node": "USER"})
        error = client.request({"mode": "node", "node": "MISSING"})
        three = client.request({"mode": "ping"})
        self.assertIn("error", error)
        self.assertEqual(client.process.pid, pid)
        self.assertEqual(one["batch"]["session_id"], three["batch"]["session_id"])
        self.assertEqual(three["batch"]["request_index"], 3)
        self.assertEqual(len({x["request"]["id"] for x in self.events if x["type"] == "whippet_batch_request"}), 3)
        self.assertTrue(any(x["type"] == "whippet_batch_response" for x in self.events))

    def test_handoff_mode_preserves_one_lead_and_rejects_model_verification(self):
        client = self.client()
        reply = client.request({"mode": "handoff", "node": "USER", "query": "acl-control", "lead_index": 0})
        self.assertEqual(reply["result"]["lead"]["proof"], [{"edge": "GenericAll"}])
        self.assertEqual(reply["result"]["assessment"]["live_access"]["status"], "unverified")
        batch.validate(["capture.zip"], {"mode": "handoff", "node": "USER", "lead_index": 0})
        for invalid in ({"mode": "handoff", "node": "USER", "lead_index": -1},
                        {"mode": "handoff", "node": "USER", "lead_index": True},
                        {"mode": "handoff", "node": "USER", "verified_access": True}):
            with self.assertRaises(ValueError):
                batch.validate(["capture.zip"], invalid)

    def test_transport_errors_invalidate_and_cleanup(self):
        for behavior in ("bad-id", "bad-index", "malformed", "eof", "oversize", "timeout"):
            with self.subTest(behavior=behavior):
                client = self.client(behavior, request_timeout=.15, response_cap=2000)
                with self.assertRaises((ValueError, EOFError, TimeoutError)):
                    client.request({"mode": "ping"})
                self.assertTrue(client.closed.is_set())
                self.assertIsNotNone(client.process.poll())
                self.assertFalse((self.root / "whippet_batch.json").exists())

    def test_incompatible_ready_is_closed(self):
        with self.assertRaises(ValueError):
            self.client("bad-ready")
        self.assertFalse((self.root / "whippet_batch.json").exists())

    def test_operator_cancellation_invalidates(self):
        client = self.client()
        (self.root / ".stop_session").touch()
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            client.request({"mode": "ping"})
        self.assertIsNotNone(client.process.poll())

    def test_capture_changes_get_new_graph_and_failure_needs_explicit_refresh(self):
        def query(**kwargs):
            return batch.query(self.root, self.terminal, ["capture.zip"], {"mode": "ping"},
                               "normal", self.events.append, **kwargs)
        first, second = query(), query()
        self.assertEqual(first["batch"]["session_id"], second["batch"]["session_id"])
        (self.root / "capture.zip").write_text("snapshot-two")
        third = query()
        self.assertNotEqual(first["batch"]["session_id"], third["batch"]["session_id"])
        (self.root / "whippet_batch_failed.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "failed earlier"):
            query()
        fourth = query(refresh=True)
        self.assertNotEqual(third["batch"]["session_id"], fourth["batch"]["session_id"])

    def test_identical_queries_reuse_evidence_until_capture_changes(self):
        def query(**kwargs):
            return batch.query(self.root, self.terminal, ["capture.zip"], {"mode": "triage", "node": "USER"},
                               "normal", self.events.append, **kwargs)
        first = query()
        cached = query()
        self.assertTrue(cached["harp_cache"]["reused"])
        self.assertEqual(first["id"], cached["id"])
        self.assertEqual(sum(e["type"] == "whippet_batch_request" for e in self.events), 1)
        cached["result"]["items"].clear()
        self.assertTrue(query()["result"]["items"])
        (self.root / "capture.zip").write_text("changed capture")
        fresh = query()
        self.assertNotIn("harp_cache", fresh)
        self.assertNotEqual(first["batch"]["session_id"], fresh["batch"]["session_id"])
        refreshed = query(refresh=True)
        self.assertNotIn("harp_cache", refreshed)

    def test_wrapped_transport_failure_is_fatal_and_needs_refresh(self):
        with self.assertRaisesRegex(RuntimeError, "transport failed"):
            batch.query(self.root, self.terminal, ["capture.zip"], {"mode": "triage", "node": "USER"},
                        "malformed", self.events.append)
        with self.assertRaisesRegex(RuntimeError, "failed earlier"):
            batch.query(self.root, self.terminal, ["capture.zip"], {"mode": "triage", "node": "USER"},
                        "normal", self.events.append)

    def test_startup_protocol_failure_is_not_a_correctable_query_rejection(self):
        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            batch.query(self.root, self.terminal, ["capture.zip"], {"mode": "triage", "node": "USER"},
                        "bad-ready", self.events.append)
        self.assertTrue((self.root / "whippet_batch_failed.json").exists())
        self.assertFalse((self.root / "whippet_batch.json").exists())

    def test_capture_cannot_escape_workspace_or_be_absent(self):
        for inputs in (["../README.md"], ["missing.zip"]):
            with self.subTest(inputs=inputs), self.assertRaises(ValueError):
                batch.query(self.root, self.terminal, inputs, {"mode": "ping"}, "normal", self.events.append)
        self.assertFalse(any(x["type"] == "whippet_batch_start" for x in self.events))

    def test_exact_runtime_argv_and_linux_script_syntax(self):
        cfg = {"runtime": "wsl", "wsl_distro": "chosen-kali", "wsl_user": "labuser"}
        terminal = harp.WslTerminal(cfg)
        argv = terminal.batch_argv("SCRIPT", ["path with spaces", "literal;$value"])
        self.assertEqual(argv[:7], ["wsl.exe", "--distribution", "chosen-kali", "--user", "labuser", "--exec", "python3"])
        self.assertEqual(argv[-2:], ["path with spaces", "literal;$value"])
        self.assertNotIn("/bin/sh", argv)
        docker = harp.KaliTerminal({}).batch_argv("SCRIPT", [])
        self.assertIn("-i", docker)
        self.assertIn("10001:10001", docker)
        for code in (batch.LAUNCH, batch.SNAPSHOT, batch.CLEANUP):
            compile(code, "runtime-script", "exec")

    def test_api_no_start_for_non_ad_and_missing_capabilities(self):
        state = {"status": "active", "recon": [], "mode": "hybrid"}
        with self.assertRaises(ValueError), patch.object(harp, "terminal_for") as terminal:
            harp.whippet_query(self.root, ["capture.zip"], {"mode": "ping"}, session=state)
        terminal.assert_not_called()
        state.update(recon=[{"port": 88}, {"port": 389}], whippet={"batch_compatible": False})
        with patch.object(harp, "terminal_for", return_value=self.terminal), patch.object(harp, "ensure_whippet"), \
             patch.object(batch, "query") as query, self.assertRaisesRegex(RuntimeError, "unavailable"):
            harp.whippet_query(self.root, ["capture.zip"], {"mode": "ping"}, session=state)
        query.assert_not_called()

    def test_disabled_session_rejects_query_before_runtime_access(self):
        state = {"status": "active", "recon": [{"port": 88}, {"port": 389}],
                 "config": {"whippet_enabled": False}, "mode": "hybrid"}
        with patch.object(harp, "terminal_for") as terminal, \
             self.assertRaisesRegex(ValueError, "disabled"):
            harp.whippet_query(self.root, ["capture.zip"], {"mode": "triage"}, session=state)
        terminal.assert_not_called()

    def test_api_records_structured_evidence_and_mcp_contract(self):
        state = {"status": "active", "recon": [{"port": 88}, {"port": 389}], "mode": "hybrid",
                 "whippet": {"batch_compatible": True, "executable": "normal"},
                 "config": {"command_timeout_seconds": 30}, "oracle_actions": 0, "observations": []}
        with patch.object(harp, "terminal_for", return_value=self.terminal), patch.object(harp, "ensure_whippet"):
            result = harp.whippet_query(self.root, ["capture.zip"], {"mode": "triage", "node": "USER"}, session=state)
        self.assertEqual(state["oracle_actions"], 1)
        self.assertTrue((self.root / result["whippet_report"]).is_file())
        self.assertIn("harp_context", json.loads(harp_whippet.observation(result)["output"]))
        self.assertIn("whippet_query", harp_mcp.TOOLS)

    def test_cleanup_cannot_kill_a_new_owners_connection(self):
        manifest = self.root / "whippet_batch.json"
        manifest.write_text(json.dumps({"token": "new-owner", "workspace": str(self.root)}))
        with patch.object(batch.subprocess, "run") as run:
            batch.cleanup(self.root, self.terminal, self.events.append, expected_token="old-owner")
            run.assert_not_called()
        self.assertEqual(json.loads(manifest.read_text())["token"], "new-owner")
        manifest.unlink()

    def test_proxy_action_uses_budget_and_returns_terminal_evidence(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        state = {"status": "active", "mode": "hybrid", "container": "test", "config": cfg,
                 "target": "target", "recon": [{"port": 88}, {"port": 389}],
                 "local_steps": 0, "local_calls": [], "observations": [], "memory_notes": [],
                 "oracle_actions": 0, "whippet": {"batch_compatible": True}, "success": "unknown"}
        harp.save_session(self.root, state)
        action = {"thought": "Inspect one collected lead", "whippet_query": {
            "inputs": ["capture.zip"], "request": {"mode": "triage", "node": "USER"}}, "done": False}
        result = {"command": "whippet-query triage id=test", "output": json.dumps({
            "schema_version": 1, "mode": "triage", "result": {"items": []}}),
            "exit_code": 0, "truncated": False}
        terminal = type("Terminal", (), {"stats": lambda self: None})()
        with patch.object(harp, "terminal_for", return_value=terminal), \
             patch.object(harp, "ensure_whippet"), patch.object(harp, "model_context_tokens", return_value=8192), \
             patch.object(harp, "count_chat_tokens", return_value=300), \
             patch.object(harp, "api_chat", return_value=json.dumps(action)), \
             patch.object(harp, "whippet_query", return_value=result) as query:
            harp.delegate(self.root, "Inspect one AD lead", 1, quiet=True)
        saved = harp.load_session(self.root)
        self.assertEqual(saved["local_steps"], 1)
        self.assertEqual(saved["last_delegate_stop"], "step_budget")
        self.assertEqual(saved["observations"][0]["output"], result["output"])
        self.assertEqual(query.call_args.kwargs["origin"], "local")

    def test_disabled_proxy_gets_no_whippet_card_or_query_execution(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["whippet_enabled"] = False
        state = {"status": "active", "mode": "hybrid", "container": "test", "config": cfg,
                 "target": "target", "recon": [{"port": 88}, {"port": 389}],
                 "local_steps": 0, "local_calls": [], "observations": [], "memory_notes": [],
                 "oracle_actions": 0, "success": "unknown"}
        harp.save_session(self.root, state)
        prompts, contexts = [], []
        def chat(_model, system, user, ledger):
            prompts.append(system)
            contexts.append(json.loads(user))
            ledger.append({"finish_reason": "stop"})
            return json.dumps({"whippet_query": {"inputs": ["capture.zip"],
                               "request": {"mode": "triage", "node": "USER"}}, "done": False})
        terminal = type("Terminal", (), {"stats": lambda self: None})()
        with patch.object(harp, "terminal_for", return_value=terminal), \
             patch.object(harp_whippet, "check") as check, \
             patch.object(harp, "model_context_tokens", return_value=8192), \
             patch.object(harp, "count_chat_tokens", return_value=300), \
             patch.object(harp, "api_chat", side_effect=chat), \
             patch.object(harp, "whippet_query", wraps=harp.whippet_query) as query:
            harp.delegate(self.root, "Analyze AD access", 1, quiet=True)
        check.assert_not_called()
        self.assertEqual(query.call_count, 2)
        self.assertEqual(harp.load_session(self.root)["local_steps"], 0)
        self.assertEqual(harp.load_session(self.root)["last_delegate_stop"], "whippet_query_rejected")
        self.assertTrue(all("Whippet is disabled" in prompt for prompt in prompts))
        self.assertTrue(all("Whippet tool card" not in prompt for prompt in prompts))
        self.assertTrue(all(context["whippet_enabled"] is False and context["whippet"] is None
                            for context in contexts))

    def test_proxy_can_correct_capture_path_without_resume_or_cli_fallback(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        state = {"status": "active", "mode": "hybrid", "container": "test", "config": cfg,
                 "target": "target", "workspace": "/workspace", "recon": [{"port": 88}, {"port": 389}],
                 "local_steps": 0, "local_calls": [], "observations": [], "memory_notes": [],
                 "oracle_actions": 0, "whippet": {"batch_compatible": True}, "success": "unknown"}
        harp.save_session(self.root, state)
        contexts = []
        def chat(_model, _system, user, ledger):
            contexts.append(json.loads(user))
            ledger.append({"finish_reason": "stop"})
            return json.dumps({"whippet_query": {"inputs": ["/home/kali/capture.zip" if len(contexts) == 1 else "/workspace/capture.zip"],
                               "request": {"mode": "triage", "node": "USER"}}, "done": False})
        result = {"command": "whippet-query triage id=test", "output": json.dumps({
            "schema_version": 1, "mode": "triage", "result": {"items": []}}),
            "exit_code": 0, "truncated": False}
        terminal = type("Terminal", (), {"stats": lambda self: None})()
        with patch.object(harp, "terminal_for", return_value=terminal), \
             patch.object(harp, "ensure_whippet"), patch.object(harp, "model_context_tokens", return_value=8192), \
             patch.object(harp, "count_chat_tokens", return_value=300), \
             patch.object(harp, "api_chat", side_effect=chat), \
             patch.object(harp, "whippet_query", side_effect=[ValueError("Capture outside session workspace"), result]) as query:
            harp.delegate(self.root, "Inspect one AD lead", 1, quiet=True)
        self.assertIn("rejected before execution", contexts[1]["last_command_feedback"])
        self.assertEqual(contexts[1]["workspace"], "/workspace")
        self.assertEqual(query.call_args.args[1], ["/workspace/capture.zip"])
        saved = harp.load_session(self.root)
        self.assertEqual(saved["local_steps"], 1)
        self.assertEqual(saved["last_delegate_stop"], "step_budget")
        self.assertNotIn("oracle_help_request", saved)


if __name__ == "__main__":
    unittest.main()
