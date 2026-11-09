import copy
import json
import shlex
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import harp
import harp_mcp
import harp_nim
import harp_whippet as whippet


def report():
    return {"schema_version": 1, "mode": "triage", "warnings": ["incomplete ACLs"],
            "unresolved_nodes": 2, "result": {"findings": {"items": [
                {"source": "S-1", "target": "S-2", "conditional": True,
                 "prerequisites": ["verify application"],
                 "proof": [{"edge": "MemberOf", "details": "x" * 600}]} for _ in range(8)],
                "total": 12, "offset": 0, "next_offset": 8, "truncated": True}}}


def observation(data=None, **kwargs):
    return {"command": "whippet capture.zip --triage 'USER@LAB' --limit 8",
            "output": json.dumps(data if data is not None else report()),
            "exit_code": 0, "truncated": False, **kwargs}


class WhippetTests(unittest.TestCase):
    def test_handoff_keeps_atomic_lead_and_unverified_assessment(self):
        report = {"schema_version": 1, "mode": "handoff", "warnings": ["partial capture"],
                  "result": {"lead": {"proof": [{"edge": "MemberOf", "details": "x" * 3500}],
                                      "membership_path": ["USER", "GROUP"]},
                             "assessment": {"live_access": {"status": "unverified"},
                                            "unverified_prerequisites": ["Reauthenticate"]},
                             "coverage": {"profile": "supported"}, "total_leads": 2,
                             "next_lead_index": 1}}
        result = {"command": "whippet-query handoff id=1", "output": json.dumps(report),
                  "exit_code": 0, "truncated": False}
        self.assertTrue(whippet.is_handoff(result["command"]))
        self.assertTrue(whippet.is_handoff("whippet capture.zip --handoff USER"))
        full = json.loads(whippet.observation(result, 8000)["output"])
        self.assertEqual(full["result"], report["result"])
        reduced = json.loads(whippet.observation(result, 1200)["output"])
        self.assertNotIn("result", reduced)
        self.assertIn("result", reduced["harp_context"]["context_omissions"])

    def test_ad_gating_and_reset_guidance(self):
        self.assertFalse(whippet.guidance({"recon": [{"port": 80}]}))
        session = {"recon": [{"port": 88}, {"port": 389}]}
        self.assertIn("tool card v1", harp.system_prompt(session))
        self.assertEqual(harp.system_prompt(session), harp.system_prompt(copy.deepcopy(session)))
        self.assertTrue(whippet.guidance({"observations": [observation()]}))

    def test_whole_items_preserve_proof_and_original_paging(self):
        original = report()
        reduced = whippet.compact(original, 1800, "whippet_reports/a.json")
        rows = reduced["result"]["findings"]
        self.assertGreater(len(rows["items"]), 0)
        self.assertLess(len(rows["items"]), 8)
        self.assertEqual(rows["items"][0], original["result"]["findings"]["items"][0])
        for key in ("total", "offset", "next_offset", "truncated"):
            self.assertEqual(rows[key], original["result"]["findings"][key])
        self.assertEqual(reduced["warnings"], original["warnings"])
        self.assertTrue(reduced["harp_context"]["context_omissions"])
        self.assertEqual(len(original["result"]["findings"]["items"]), 8)

    def test_path_never_loses_an_individual_step(self):
        data = {"schema_version": 1, "mode": "path", "result": {
            "path": [["A", ""], ["B", "GenericAll"]], "proof": "x" * 6000}}
        reduced = whippet.compact(data, 500)
        self.assertNotIn("result", reduced)
        self.assertIn("result", reduced["harp_context"]["context_omissions"])

    def test_bad_reports_are_not_empty_successes(self):
        cases = [observation(exit_code=1), observation(truncated=True),
                 observation({"schema_version": 9, "result": {}}),
                 observation(output="not json"),
                 observation({"schema_version": 1, "error": "bad capture"}),
                 observation({"schema_version": 1}),
                 observation(output=json.dumps(report()) + "\n" + json.dumps(report()))]
        for case in cases:
            with self.subTest(case=case):
                output = json.loads(whippet.observation(case, 800)["output"])
                self.assertIn("whippet_error", output)

    def test_mixed_stderr_and_saved_report(self):
        result = observation(output="warning: collector gap\n" + json.dumps(report()) + "\n")
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            whippet.capture(result, Path(temp))
            self.assertEqual(json.loads((Path(temp) / result["whippet_report"]).read_text()), report())
            reduced = json.loads(whippet.observation(result, 2000)["output"])
            self.assertIn("harp_diagnostics", reduced)
            self.assertEqual(reduced["harp_context"]["report_ref"], result["whippet_report"])

    def test_discovery_is_logged_once_without_affecting_non_ad(self):
        class Terminal:
            def run(self, command, timeout):
                return {"command": command, "exit_code": 0, "output": json.dumps({
                    "available": True, "compatible": True, "executable": "/home/kali/.local/bin/whippet"})}
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            session = {"recon": [{"port": 88}, {"port": 389}]}
            terminal = Terminal()
            with patch.object(terminal, "run", wraps=terminal.run) as run:
                harp.ensure_whippet(Path(temp), session, terminal)
                harp.ensure_whippet(Path(temp), session, terminal)
                self.assertEqual(run.call_count, 1)
            self.assertTrue(session["whippet"]["compatible"])
            event = json.loads((Path(temp) / "events.jsonl").read_text())
            self.assertEqual(event["type"], "whippet_availability")
            with patch.object(terminal, "run") as run:
                harp.ensure_whippet(Path(temp), {"recon": []}, terminal)
                run.assert_not_called()

    def test_discovery_failure_is_optional(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(whippet, "check", side_effect=RuntimeError("timeout")):
            session = {"recon": [{"port": 88}, {"port": 389}]}
            harp.ensure_whippet(Path(temp), session, SimpleNamespace())
            self.assertFalse(session["whippet"]["available"])

    def test_runtime_probe_is_bounded_valid_python(self):
        words = shlex.split(whippet.CHECK_COMMAND)
        self.assertEqual(words[:2], ["python3", "-c"])
        self.assertLess(len(whippet.CHECK_COMMAND), 1000)
        compile(words[2], "probe", "exec")

    def test_oracle_and_proxy_compaction_keep_valid_json(self):
        state = {"observations": [observation()]}
        recent, _ = harp_nim.oracle_observations(state, {})
        self.assertIn("harp_context", json.loads(recent[0]["output"]))
        older = harp_nim.compact_past_observations(state["observations"] + [observation()] * 4)
        self.assertIn("harp_context", json.loads(older[0]["output"]))
        context = {"recent_terminal_results": state["observations"],
                   "unverified_memory_notes": [], "prior_commands": []}
        with patch.object(harp, "count_chat_tokens", side_effect=lambda m, s, u: len(u) // 4):
            user, tokens, _ = harp.fit_context({}, context, 450)
        self.assertLessEqual(tokens, 450)
        self.assertIn("harp_context", json.loads(json.loads(user)["recent_terminal_results"][0]["output"]))

    def test_direct_invocations_only(self):
        self.assertFalse(whippet.is_query("echo whippet --triage"))
        self.assertFalse(whippet.is_query("whippet --help"))
        self.assertTrue(whippet.is_query("/home/kali/.local/bin/whippet capture.zip --summary"))
        self.assertFalse(whippet.is_query("echo '&&' whippet capture.zip --triage USER"))

    def test_shell_setup_does_not_hide_structured_whippet_results(self):
        for command in ("cd /workspace && /home/kali/.local/bin/whippet capture.zip --triage USER --limit 3; echo EXIT:$?",
                        "whippet capture.zip --triage USER > triage.json; cat triage.json"):
            with self.subTest(command=command), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                result = observation(command=command, output="loaded capture\n" + json.dumps(report()) + "\nEXIT:0")
                self.assertTrue(whippet.is_query(command))
                whippet.capture(result, Path(temp))
                self.assertTrue((Path(temp) / result["whippet_report"]).is_file())
                compact = json.loads(whippet.observation(result, 1800)["output"])
                self.assertIn("harp_context", compact)
                self.assertIn("warnings", compact)

    def test_codex_inspection_and_direct_query_use_structured_results(self):
        state = {"recon": [{"port": 88}, {"port": 389}], "observations": [observation()],
                 "memory_notes": [], "whippet": {"available": True, "compatible": True}}
        with patch.object(harp_mcp, "run_path", return_value=Path.cwd()), \
             patch.object(harp, "load_session", return_value=state), \
             patch.object(harp, "summarize", return_value={"last_delegate_stop": "step_budget"}), \
             patch.object(harp_mcp.harp_artifacts, "flag_status", return_value={}), \
             patch.object(harp_mcp.harp_artifacts, "list_artifacts", return_value=[]), \
             patch.object(harp, "direct_exec") as run:
            context = json.loads(harp_mcp.inspect_session("session"))
            self.assertIn("tool card v1", context["whippet_guidance"])
            self.assertIn("harp_context", json.loads(context["recent_observations"][0]["output"]))
            reply = json.loads(harp_mcp.terminal("session", state["observations"][0]["command"]))
            self.assertIn("harp_context", json.loads(reply["output"]))
            self.assertTrue(run.call_args.kwargs["quiet"])

    def test_ad_delegation_returns_compact_inspection_without_stream_replay(self):
        state = {"recon": [{"port": 88}, {"port": 389}]}
        with patch.object(harp_mcp, "run_path", return_value=Path.cwd()), \
             patch.object(harp, "load_session", return_value=state), \
             patch.object(harp, "delegate") as delegate, \
             patch.object(harp_mcp, "inspect_session", return_value="compact"):
            self.assertEqual(harp_mcp.delegate_local("session", "inspect one lead", 2), "compact")
            self.assertTrue(delegate.call_args.kwargs["quiet"])


if __name__ == "__main__":
    unittest.main()
