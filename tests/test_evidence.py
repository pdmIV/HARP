"""Capability-based planning and mixed-result regressions, independent of any box."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_evidence as evidence
import harp_nim
import harp_replay
import harp_research
import harp_strategy
import harp_zai
import test_harp as fixtures
from scripts import evaluate_planning


def check(action="validate_hypothesis", fact="feature.behavior"):
    return {"action": action, "hypothesis": "The reachable operation may expose a configuration-dependent path",
            "fact": fact, "resource": "service", "principal": "anonymous",
            "evidence": [{"observation": 1, "quote": "putting file sample.txt as sample.txt"}],
            "expected_positive": "The specific prerequisite is observed", "expected_negative": "This prerequisite remains unconfirmed"}


def state():
    return {"target": "192.0.2.10", "planning_protocol": 2, "status": "active", "recon": [],
            "config": {"oracle": {"web_search_enabled": True}}, "observations": [
                {"command": "smbclient //192.0.2.10/QUEUE -N -c 'print sample.txt'", "exit_code": 0,
                 "output": "putting file sample.txt as sample.txt"}]}


class EvidenceTests(unittest.TestCase):
    def test_modestly_long_check_fields_preserve_the_proposed_action(self):
        session = state()
        item = check()
        item["fact"] = "f" * 547
        item["research_decision"] = "r" * 578
        proposed = {"check": item}
        self.assertIsNone(evidence.check_issue(proposed, session))
        self.assertIsNone(harp_research.review_issue(proposed, session))
        self.assertEqual(len(item["fact"]), 547)
        self.assertEqual(len(item["research_decision"]), 578)
        item["fact"] = "f" * 4097
        self.assertIn("check.fact is 4097 characters; limit 4096", evidence.check_issue(proposed, session))
        item["research_decision"] = "r" * 4097
        self.assertIn("check.research_decision is 4097", harp_research.review_issue(proposed, session))

    def test_no_timing_signal_stays_inconclusive_and_keeps_observation_limits(self):
        session = state()
        proposed = check()
        evidence.record_check(session, proposed)
        session["observations"].append({"command": "measure submission round trip", "exit_code": 0,
                                        "output": "baseline_ms=200 test_ms=150; no callback observed"})
        evidence.finish_check(session, proposed)
        outcome = session["assessment_history"][-1]["observed_outcome"]
        self.assertEqual(outcome["status"], "inconclusive")
        self.assertIn("backend timing", outcome["limitations"])
        self.assertIn("unverified", outcome["limitations"])

    def test_compound_print_script_confirms_submission_on_target(self):
        command = '''TARGET=192.0.2.10
echo "===== print job =====" | tee -a out
smbclient "//$TARGET/QUEUE" -N -c "lcd /tmp; print sample.txt; queue" 2>&1 | tee -a out
'''
        result = {"command": command, "exit_code": 0,
                  "output": "===== print job =====\nputting file sample.txt as sample.txt (0.1 kB/s)\n"}
        rows = evidence.outcomes(result, "192.0.2.10", 1)
        self.assertTrue(any(row["host"] == "192.0.2.10" and row["resource"] == "QUEUE" and
                            row["operation"] == "printer.submit" and row["status"] == "confirmed"
                            for row in rows))
        unresolved = evidence.outcomes({"command": "smbclient //$OTHER/QUEUE -N -c 'print sample.txt'",
            "exit_code": 0, "output": "putting file sample.txt as sample.txt"}, "192.0.2.10", 2)
        self.assertEqual(unresolved[0]["host"], "unspecified")

    def test_checkpoint_prompts_research_then_revisits_after_inconclusive_check(self):
        session = state()
        checkpoint = harp_research.decision_checkpoint(session)
        self.assertEqual(checkpoint["preference"], "research_before_payload")
        self.assertEqual(checkpoint["evidence"]["operation"], "printer.submit")
        choice = harp_research.record_checkpoint_choice(session, checkpoint,
            {"check": {"research_decision": "Verify one local prerequisite first"}})
        self.assertEqual(choice["choice"], "local_check")
        self.assertIsNone(harp_research.decision_checkpoint(session))
        item = check()
        evidence.record_check(session, item)
        session["observations"].append({"command": "rpcclient -N 192.0.2.10 -c enumprinters",
            "exit_code": 1, "output": "Bad SMB2 signature for message"})
        evidence.finish_check(session, item)
        self.assertEqual(session["assessment_history"][-1]["observed_outcome"]["status"], "transport_error")
        revisit = harp_research.decision_checkpoint(session)
        self.assertEqual(revisit["preference"], "research_after_inconclusive_check")
        harp_research.record_checkpoint_choice(session, revisit, {"research": {"query": "public fact"}})
        self.assertIsNone(harp_research.decision_checkpoint(session))

    def test_confirmed_submission_supersedes_exposed_printer_checkpoint(self):
        session = state()
        session["observations"].insert(0, {"command": "smbclient -L //192.0.2.10 -N",
            "exit_code": 0, "output": "QUEUE Printer Reception printer"})
        checkpoint = harp_research.decision_checkpoint(session)
        self.assertEqual(checkpoint["preference"], "research_before_payload")
        harp_research.record_checkpoint_choice(session, checkpoint,
            {"research": {"query": "public print mechanism"}})
        self.assertIsNone(harp_research.decision_checkpoint(session))

    def test_search_results_require_source_read_then_a_source_to_test_handoff(self):
        session = state()
        task = {"id": "task1", "results": [{"source_id": "source1", "title": "Advisory"}],
                "source_ids": ["source1"], "reads": []}
        research_state = {"tasks": [task], "active_task_id": "task1"}
        checkpoint = harp_research.decision_checkpoint(session, research_state)
        self.assertEqual(checkpoint["phase"], "read_source")
        harp_research.record_checkpoint_choice(session, checkpoint,
            {"research": {"source_id": "source1"}})
        task["reads"].append({"source_id": "source1", "excerpt": "Relevant public source text"})
        checkpoint = harp_research.decision_checkpoint(session, research_state)
        self.assertEqual(checkpoint["phase"], "apply_source")
        self.assertEqual(harp_research.source_application({}, research_state)["status"], "missing")
        basis = {"source_ids": ["source1"], "controlled_input": "client metadata",
                 "execution_sink": "configured helper", "configuration_prerequisites": ["helper enabled"],
                 "observable_test": "one benign callback"}
        self.assertEqual(harp_research.source_application({"check": {"research_basis": basis}},
            research_state)["status"], "documented")
        basis["source_ids"] = ["invented"]
        self.assertEqual(harp_research.source_application({"check": {"research_basis": basis}},
            research_state)["status"], "incomplete")
        session["config"]["oracle"]["web_search_enabled"] = False
        self.assertIsNone(harp_research.decision_checkpoint(session, research_state))

    def test_check_outcomes_distinguish_target_denial_from_local_error(self):
        session = state()
        item = check("validate_hypothesis", "share.map")
        item["resource"] = "DOCS"
        evidence.record_check(session, item)
        session["observations"].append({"command": "smbclient //192.0.2.10/DOCS -N -c 'ls'",
            "exit_code": 1, "output": "tree connect failed: NT_STATUS_ACCESS_DENIED"})
        evidence.finish_check(session, item)
        outcome = session["assessment_history"][-1]["observed_outcome"]
        self.assertEqual(outcome["status"], "negative")
        self.assertEqual(outcome["evidence"][0]["operation"], "share.map")
        evidence.record_check(session, item)
        session["observations"].append({"command": "smbclient //192.0.2.10/DOCS -N -c 'ls'",
            "exit_code": 127, "output": "smbclient: command not found"})
        evidence.finish_check(session, item)
        self.assertEqual(session["assessment_history"][-1]["observed_outcome"]["status"], "tool_error")

    def test_mixed_script_keeps_auth_permissions_print_and_protocol_errors_separate(self):
        command = """echo '=== session ==='
enum4linux-ng -A -u '' -p '' 192.0.2.10
echo '=== disk ==='
smbclient //192.0.2.10/DOCS -N -c 'ls'
echo '=== print ==='
smbclient //192.0.2.10/QUEUE -N -c 'print sample.txt'
echo '=== rpc ==='
rpcclient -N 192.0.2.10 -c 'enumprinters'
"""
        output = """=== session ===
Server allows authentication via username '' and password ''
=== disk ===
tree connect failed: NT_STATUS_ACCESS_DENIED
=== print ===
putting file sample.txt as sample.txt
=== rpc ===
Bad SMB2 (sign_algo_id=2) signature for message
Cannot connect: NT_STATUS_ACCESS_DENIED
/proc/self/fd/3: Bad substitution
"""
        rows = evidence.outcomes({"command": command, "output": output, "exit_code": 2}, "192.0.2.10", 1)
        statuses = {(row["resource"], row["operation"], row["status"]) for row in rows}
        self.assertIn(("session", "session.authenticate", "confirmed"), statuses)
        self.assertIn(("DOCS", "share.map", "denied"), statuses)
        self.assertIn(("QUEUE", "printer.submit", "confirmed"), statuses)
        self.assertIn(("unspecified", "rpc.query", "inconclusive"), statuses)
        self.assertFalse(any(row["operation"] == "session.authenticate" and row["status"] == "denied" for row in rows))

    def test_repeated_print_success_and_wrapper_noise_are_not_new_progress(self):
        session = state()
        first = session["observations"][0]
        self.assertEqual(evidence.progress(session, first), 1)
        for number in (2, 3):
            result = {"command": "smbclient //192.0.2.10/QUEUE -N -c 'print other.txt'",
                      "exit_code": 0, "output": f"=== run {number} ===\nputting file other.txt as other.txt ({number}.0 kB/s)"}
            session["observations"].append(result)
            self.assertEqual(evidence.progress(session, result), 0)
        result = {"command": "cat printer_probe.txt", "exit_code": 0,
                  "output": "putting file sample.txt as sample.txt\n=== new wrapper ==="}
        self.assertEqual(evidence.outcomes(result, session["target"], 4), [])
        self.assertIsNone(harp_strategy.evidence_fingerprint(result))

    def test_negated_credential_prose_and_empty_metadata_do_not_block_other_checks(self):
        decision = {"objective": "Do not spray passwords; probe the exposed feature",
                    "plan": "Avoid credential guessing", "check": check(),
                    "credential_test": {"candidates": [], "max_attempts": 0, "rationale": "No credential test"}}
        self.assertIsNone(harp_strategy.credential_test_issue(decision, []))
        self.assertNotIn("credential_test", decision)
        decision["implementation"] = 'hydra -l person -P "$WL" ssh://192.0.2.10'
        self.assertIsNotNone(harp_strategy.credential_test_issue(decision, []))

    def test_two_unproductive_fingerprint_checks_preserve_unknown_then_not_observable(self):
        session = state()
        for number in (1, 2):
            item = check("fingerprint", "server.version")
            if number == 2:
                item["retry_reason"] = "A signing failure prevented the previous client's query"
            self.assertIsNone(evidence.check_issue({"check": item}, session))
            evidence.record_check(session, item)
            session["observations"].append({"command": "smbclient -L //192.0.2.10 -N -d 4", "exit_code": 0,
                                            "output": "Client started (version 8.9.10)"})
            evidence.finish_check(session, item)
            self.assertEqual(session["prerequisite_ledger"][-1]["state"], "unknown" if number == 1 else "not_observable")
        self.assertIn("Fingerprint budget", evidence.check_issue({"check": item}, session))
        candidate = check()
        self.assertIsNone(evidence.check_issue({"check": candidate}, session))
        self.assertTrue(harp_research.opportunity(session))
        self.assertFalse(any(row["operation"] == "server.version" and row["status"] == "confirmed"
                             for row in evidence.context(session)["facts"]))

    def test_research_review_is_modular_and_can_prefer_a_local_discriminating_check(self):
        session = state()
        decision = {"check": check()}
        self.assertIsNone(harp_research.review_issue(decision, session))
        decision["check"]["research_decision"] = "Validate a source prerequisite with one local check"
        self.assertIsNone(harp_research.review_issue(decision, session))
        decision["check"]["research_decision"] = ""
        self.assertIsNotNone(harp_research.review_issue(decision, session))
        session["config"]["oracle"]["web_search_enabled"] = False
        self.assertIsNone(harp_research.opportunity(session))
        self.assertIsNone(harp_research.review_issue({"check": check()}, session))

    def test_evidence_quote_matches_terminal_text_after_ansi_color_removal(self):
        session = state()
        session["observations"][0]["output"] = ("\x1b[94m[*] Testing share QUEUE\x1b[0m\n"
                                                "\x1b[92m[+] Mapping: OK\x1b[0m")
        item = check()
        item["evidence"] = [{"observation": 1, "quote": "[*] Testing share QUEUE\n[+] Mapping: OK"}]
        self.assertIsNone(evidence.check_issue({"check": item}, session))
        item["evidence"][0]["quote"] = "[*] Testing share QUEUE\n[+] Mapping: DENIED"
        self.assertIn("exact retained terminal", evidence.check_issue({"check": item}, session))

    def test_shell_selection_preserves_scope_and_checks_the_selected_interpreter(self):
        script = 'printf sample | cat\nrc=${PIPESTATUS[0]}\nexit "$rc"'
        self.assertIsNotNone(harp_strategy.shell_issue(script))
        wrapped = harp_strategy.prepare_command(script, "bash")
        self.assertIsNone(harp_strategy.shell_issue(wrapped))
        self.assertTrue(harp_strategy.syntax_probe(wrapped).startswith("bash -n"))
        self.assertIn(script, wrapped)
        self.assertIn("outside", harp.local_command_issue(
            harp_strategy.prepare_command("curl http://203.0.113.55", "bash"), "192.0.2.10", "Inspect primary target"))
        with self.assertRaises(ValueError):
            harp_strategy.prepare_command("id", "powershell")
        self.assertIsNone(harp_strategy.shell_issue("printf '%s' '${PIPESTATUS[0]}'"))
        self.assertIsNotNone(harp_strategy.shell_issue("set -o pipefail\nprintf sample"))
        self.assertIn(wrapped, harp.KaliTerminal({}).command_argv(wrapped, 5, False))
        self.assertIn(wrapped, harp.WslTerminal({}).command_argv(wrapped, 5, False)[-1])

    def test_hidden_version_planning_can_search_without_repeating_a_banner_probe(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            session = harp.load_session(path)
            synthetic = state()
            session.update({key: synthetic[key] for key in ("observations", "planning_protocol", "target")})
            session["config"]["oracle"] = {"provider": "zai", "model": "glm-5.3", "web_search_enabled": True,
                                            "max_cycles": 2, "steps_per_cycle": 1}
            harp.save_session(path, session)
            requests = []
            def chat(cfg, body, **kwargs):
                context = json.loads(body["messages"][1]["content"])
                requests.append(context)
                if len(requests) == 1:
                    self.assertEqual(context["research_opportunity"]["capabilities"][0]["operation"], "printer.submit")
                    self.assertEqual(context["decision_checkpoint"]["preference"], "research_before_payload")
                    record = check("research", "feature.advisory_prerequisites")
                    decision = {"plan": "Investigate reachable functionality", "objective": "", "stop": False,
                                "check": record, "research": {"query": "Example service guest printing advisories prerequisites",
                                                              "reason": "Find configuration prerequisites for the observed reachable operation"}}
                else:
                    decision = {"plan": "Evaluation complete", "objective": "", "stop": True}
                return {"choices": [{"message": {"content": json.dumps(decision)}}]}
            with patch.object(harp_zai, "chat", side_effect=chat), patch.object(harp_research, "search_api", return_value={"search_result": []}) as api, \
                 patch.object(harp, "delegate") as delegate:
                harp_nim.run(path)
            api.assert_called_once()
            delegate.assert_not_called()
            self.assertEqual(len(requests), 2)

    def test_http_negative_control_preserves_resource_and_does_not_imply_an_auth_failure(self):
        row = {"command": "curl -I http://192.0.2.10/private", "output": "HTTP/1.1 403 Forbidden", "exit_code": 0}
        findings = evidence.outcomes(row, "192.0.2.10", 1)
        self.assertEqual(findings[0]["operation"], "http.request")
        self.assertEqual(findings[0]["status"], "denied")
        self.assertFalse(any(finding["operation"] == "session.authenticate" for finding in findings))
        row["exit_code"] = 1
        row["outcomes"] = findings
        self.assertEqual(harp_strategy.result_state(row), "finding")

    def test_mixed_delegation_does_not_stop_on_expected_share_denial(self):
        script = """echo '=== disk ==='
smbclient //192.0.2.10/DOCS -N -c 'ls'
echo '=== print ==='
smbclient //192.0.2.10/QUEUE -N -c 'print sample.txt'
"""
        output = "=== disk ===\ntree connect failed: NT_STATUS_ACCESS_DENIED\n=== print ===\nputting file sample.txt as sample.txt"
        class Terminal:
            def run(self, command, timeout, **kwargs):
                syntax = command.startswith("sh -n")
                return {"command": command, "exit_code": 0 if syntax else 1, "output": "" if syntax else output,
                        "seconds": .1, "truncated": False, "as_root": False}
            def stats(self): return None
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            session = harp.load_session(path)
            session["target"] = "192.0.2.10"
            harp.save_session(path, session)
            replies = [json.dumps({"thought": "Check independent capabilities", "command": script, "done": False}),
                       '{"thought":"Record separate results","done":true,"finding":"Disk denied; operation accepted"}']
            with patch.object(harp, "terminal_for", return_value=Terminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=replies):
                harp.delegate(path, "Use null sessions to check independent disk and print operations", 3, quiet=True)
            session = harp.load_session(path)
            self.assertEqual(session["last_delegate_stop"], "local_done")
            rows = evidence.context(session)["facts"]
            self.assertTrue(any(row["operation"] == "printer.submit" and row["status"] == "confirmed" for row in rows))

    def test_planning_evaluation_cases_score_decisions_and_negative_controls(self):
        cases = json.loads(Path("tests/fixtures/planning_cases.json").read_text())
        for case in cases:
            with self.subTest(case=case["id"]):
                record = check(case["acceptable_actions"][0])
                record["evidence"][0]["quote"] = case["session"]["observations"][0]["output"].splitlines()[0]
                record["research_decision"] = "One discriminating local prerequisite check is useful before further external work"
                decision = {"check": record, "objective": "Inspect the reachable feature; do not spray passwords"}
                if record["action"] == "research":
                    decision.update(objective="", research={"query": "Example service exposed feature advisories", "reason": "Resolve one unknown prerequisite"})
                self.assertTrue(evaluate_planning.score(case, decision)["passed"])
        exhausted = next(case for case in cases if case["id"] == "fingerprint_budget_exhausted")
        bad = check("fingerprint", "server.version")
        bad["retry_reason"] = "Try another client"
        self.assertFalse(evaluate_planning.score(exhausted, {"check": bad})["passed"])
        disabled = next(case for case in cases if case["id"] == "research_disabled")
        self.assertFalse(evaluate_planning.score(disabled, {"check": check("research"), "research": {}})["passed"])

    def test_replay_does_not_leak_future_capability_facts(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            session = harp.load_session(path)
            session.update(status="finished", duration_seconds=10, observations=state()["observations"])
            evidence.sync(session)
            harp.save_session(path, session)
            events = [{"type": "local_terminal", "at": "1970-01-01T00:00:05+00:00", "result": session["observations"][0]},
                      {"type": "finish", "at": "1970-01-01T00:00:11+00:00"}]
            (path / "events.jsonl").write_text("\n".join(json.dumps(row) for row in events))
            before = (path / "session.json").read_bytes()
            replay = harp_replay.build_replay(path, {})
            self.assertEqual(replay["frames"][0]["summary"]["capability_evidence"]["facts"], [])
            self.assertEqual(replay["frames"][1]["summary"]["capability_evidence"]["facts"][0]["operation"], "printer.submit")
            self.assertEqual(before, (path / "session.json").read_bytes())

    def test_rejected_decision_is_auditable_without_recording_private_reasoning(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            session = harp.load_session(path)
            session.update(planning_protocol=2, observations=state()["observations"])
            session["config"]["oracle"] = {"provider": "zai", "model": "glm-5.3", "max_cycles": 2, "steps_per_cycle": 1}
            harp.save_session(path, session)
            decisions = iter(({"plan": "Inspect feature", "objective": "Probe feature", "stop": False},
                              {"plan": "Stop evaluation", "objective": "", "stop": True}))
            with patch.object(harp_zai, "chat", side_effect=lambda *args, **kwargs: {
                    "choices": [{"message": {"content": json.dumps(next(decisions)), "reasoning_content": "not public"}}]}):
                harp_nim.run(path)
            events = [json.loads(row) for row in (path / "events.jsonl").read_text().splitlines()]
            rejection = next(row for row in events if row["type"] == "oracle_strategy_rejected")
            self.assertEqual(rejection["decision"]["objective"], "Probe feature")
            self.assertNotIn("not public", json.dumps(rejection))


if __name__ == "__main__":
    unittest.main()
