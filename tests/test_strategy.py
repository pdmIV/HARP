"""Synthetic regression tests. No model, runtime, network or box-specific solution."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_nim
import harp_research
import harp_strategy as strategy
import harp_zai
import test_harp as fixtures


class StrategyTests(unittest.TestCase):
    def test_syntax_probes_follow_real_shell_support_without_running_the_body(self):
        shell = shutil.which("sh")
        if not shell and os.name == "nt" and shutil.which("git"):
            candidate = Path(shutil.which("git")).parent.parent / "usr/bin/sh.exe"
            shell = str(candidate) if candidate.is_file() else None
        if not shell:
            self.skipTest("A local sh is unavailable for synthetic parser tests")
        env = {**os.environ, "PATH": str(Path(shell).parent) + os.pathsep + os.environ.get("PATH", "")}
        def execute(script):
            return subprocess.run([shell], input=script, text=True, encoding="utf-8", capture_output=True, env=env, timeout=5)
        if os.name == "nt" and execute(":").returncode in (0xC0000142, 0xC0000135):
            self.skipTest("The local sh cannot initialize its Windows runtime")
        self.assertEqual(execute(strategy.syntax_probe('printf "%s" "[[ literal ]]"')).returncode, 0)
        self.assertNotEqual(execute(strategy.syntax_probe("if then")).returncode, 0)
        supported = execute('unset HARP_ARRAY_CHECK; : "${HARP_ARRAY_CHECK[0]-}"').returncode == 0
        result = execute(strategy.syntax_probe('printf HARP_BODY_MUST_NOT_RUN; echo "${ARR[0]}"'))
        self.assertEqual(result.returncode == 0, supported)
        self.assertNotIn("HARP_BODY_MUST_NOT_RUN", result.stdout)

    def test_preflight_checks_active_expansions_without_vetoing_literal_text(self):
        for command in ('echo "${PIPESTATUS[0]}"', 'echo ${ARR[@]}',
                        'cat <<TEXT\n${ARR[0]}\nTEXT', 'echo "$(echo ${ARR[0]})"'):
            with self.subTest(command=command):
                self.assertIsNotNone(strategy.shell_preflight(command)["array_expansion"])
                self.assertTrue(strategy.syntax_probe(command).startswith("sh -c"))
                self.assertTrue(strategy.syntax_probe(strategy.prepare_command(command, "bash")).startswith("bash -n"))
        for command in ("printf '%s' '${ARR[0]}'", '# ${ARR[0]}\necho ready',
                        r'echo "\${ARR[0]}"', "cat <<'TEXT'\n${ARR[0]}\nTEXT",
                        'echo "$(printf \'%s\' \'${ARR[0]}\')"',
                        'printf "%s" "[[ ready ]]"', 'PIPESTATUS=ready; echo "$PIPESTATUS"'):
            with self.subTest(command=command):
                self.assertIsNone(strategy.shell_preflight(command)["array_expansion"])
                self.assertTrue(strategy.syntax_probe(command).startswith("sh -n"))

    def test_generated_helpers_need_distinct_nested_heredoc_delimiters(self):
        bad = "cat >helper.sh <<'EOF'\n#!/bin/bash\ncat <<EOF\ntext\nEOF\necho tail\nEOF\nbash helper.sh"
        self.assertIn("heredoc", strategy.shell_preflight(bad)["issue"])
        self.assertIn("heredoc", strategy.shell_preflight(strategy.prepare_command(bad, "bash"))["issue"])
        good = "cat >helper.sh <<'OUTER'\n#!/bin/bash\ncat <<INNER\ntext\nINNER\necho tail\nOUTER\nbash helper.sh"
        self.assertIsNone(strategy.shell_preflight(good)["issue"])
        self.assertIsNone(strategy.shell_preflight("cat <<'TEXT'\ncat <<TEXT\nTEXT")["issue"])

    def test_local_setup_errors_with_zero_final_status_do_not_count_as_progress(self):
        for output in ('Error opening local file /tmp/input',
                       '/bin/sh: 32: cannot create /tmp/input/part: Directory nonexistent',
                       '/tmp/helper.sh: line 30: /tmp/input/part: No such file or directory',
                       '/proc/self/fd/3: 4: Bad substitution'):
            result = {"command": "cat /tmp/probe.log", "exit_code": 0, "output": output}
            with self.subTest(output=output):
                self.assertIsNotNone(strategy.execution_feedback(result))
                self.assertEqual(strategy.result_state(result), "error")

    def test_array_patterns_provide_bash_repair_hints(self):
        for command in ('AUTH=(-N)', 'AUTH+=(-N)', 'AUTH[0]=(-N)',
                        'printf "%s\\n" "${AUTH[@]}"', 'echo ${AUTH[*]}',
                        'echo "${AUTH[0]}"'):
            with self.subTest(command=command):
                self.assertIn('shell:"bash"', strategy.shell_issue(command))
                wrapped = strategy.prepare_command(command, "bash")
                self.assertIsNone(strategy.shell_issue(wrapped))
                self.assertTrue(strategy.syntax_probe(wrapped).startswith("bash -n"))
                # Terminal.run validates the probe's outer shell, not its data.
                self.assertIsNone(strategy.shell_issue(strategy.syntax_probe(command)))
                self.assertIsNone(strategy.shell_issue(strategy.syntax_probe(wrapped)))

    def test_array_text_in_literals_and_quoted_heredocs_is_data(self):
        for command in ("printf '%s' 'AUTH=(-N) ${AUTH[@]}'",
                        'printf "%s" "AUTH=(-N)"',
                        r'printf "%s" "\${AUTH[@]}"',
                        "cat <<'SCRIPT' >helper.sh\nAUTH=(-N)\nSCRIPT\n/bin/bash helper.sh",
                        "cat <<-'SCRIPT'\n\tAUTH=(-N)\n\tSCRIPT",
                        'AUTH=-N\nprintf "%s" "$AUTH"'):
            with self.subTest(command=command):
                self.assertIsNone(strategy.shell_issue(command))
        self.assertIsNotNone(strategy.shell_issue("cat <<'TEXT'\nAUTH=(-N)\nTEXT\nAUTH=(-U)"))

    def test_strategy_rejections_offer_one_bounded_research_recovery(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.session(path, search=True)
            decisions = iter([
                {"plan": "Check a capability", "objective": "Run one local check", "stop": False}
                for _ in range(3)
            ] + [
                {"plan": "Research missing prerequisite", "objective": "", "stop": False,
                 "research": {"query": "Example service printing advisory prerequisites",
                              "reason": "The local check needs a public configuration fact"}},
                {"plan": "Review complete", "objective": "", "stop": True},
            ])
            contexts = []
            def chat(config, body, **kwargs):
                contexts.append(json.loads(body["messages"][1]["content"]))
                return {"choices": [{"message": {"content": json.dumps(next(decisions))}}]}
            with patch.object(harp_zai, "chat", side_effect=chat), \
                 patch.object(harp_nim.harp_evidence, "check_issue", side_effect=["Invalid evidence"] * 3 + [None]), \
                 patch.object(harp_research, "opportunity", return_value={"capabilities": [{"operation": "printer.submit"}]}), \
                 patch.object(harp_research, "search_api", return_value={"search_result": []}) as search, \
                 patch.object(harp, "delegate") as delegate:
                harp_nim.run(path)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(x["type"] == "oracle_strategy_recovery" for x in events), 1)
            self.assertIn("Step back", contexts[3]["strategy_feedback"]["next"])
            search.assert_called_once()
            delegate.assert_not_called()

    def session(self, path, search=False):
        fixtures.HarpTests.make_session(self, path)
        state = harp.load_session(path)
        state["config"]["oracle"] = {"provider": "zai", "model": "glm-5.3", "max_cycles": 4,
                                      "steps_per_cycle": 3, "web_search_enabled": search}
        harp.save_session(path, state)
        return state

    def test_script_and_dev_null_are_not_authentication_constraints(self):
        for task in ("Validate account credentials. command -v tool >/dev/null 2>&1",
                     "Inspect service" + strategy.IMPLEMENTATION_MARKER + "# anonymous example\ncat /dev/null"):
            self.assertFalse(harp.null_auth_objective(task))
        self.assertTrue(harp.null_auth_objective("Enumerate guest shares only"))
        self.assertTrue(harp.null_auth_objective("Use null-session authentication"))
        self.assertIsNone(harp.local_command_issue("nxc smb target -u staff -p observed --shares",
            "target", "Validate known credentials" + strategy.IMPLEMENTATION_MARKER + "cat /dev/null",
            [{"output": "password=observed"}]))

    def test_generic_online_lists_need_evidence_but_offline_and_discovery_do_not(self):
        for objective in ("Spray SMB passwords", "Validate SSH credentials with a wordlist",
                          "Test 1000 password candidates"):
            self.assertIsNotNone(strategy.credential_test_issue({"objective": objective}, []))
        for objective in ("Enumerate directories using a wordlist", "Enumerate SMB share names using a wordlist",
                          "Crack collected password hashes offline"):
            self.assertIsNone(strategy.credential_test_issue({"objective": objective}, []))
        self.assertIsNotNone(strategy.credential_test_issue({"objective": "Validate access",
            "implementation": 'nxc smb "$HOST" -u staff -p "$WL"'}, []))
        self.assertIsNone(strategy.credential_test_issue({"objective": "Inspect installed tool help",
            "implementation": 'command -v hydra >/dev/null; hydra -h'}, []))
        self.assertIsNotNone(strategy.credential_test_issue({"objective": "Validate access",
            "implementation": 'hydra -l staff -P "$WL" smb://target'}, []))

    def test_candidates_require_exact_provenance_and_total_cap(self):
        observations = [{"output": "Recovered password: sample-secret"}]
        decision = {"credential_test": {"rationale": "Recovered from a target document", "max_attempts": 2,
                    "candidates": [{"observation": 1, "value": "sample-secret", "quote": "password: sample-secret"}]}}
        self.assertIsNone(strategy.credential_test_issue(decision, observations))
        decision["credential_test"]["candidates"][0]["quote"] = "invented password: sample-secret"
        self.assertIsNotNone(strategy.credential_test_issue(decision, observations))
        decision["credential_test"]["max_attempts"] = 1000
        self.assertIsNotNone(strategy.credential_test_issue(decision, observations))

    def test_monitoring_error_and_positive_evidence_classification(self):
        poll = {"command": "ps -p 101 -o etime; tail -3 job.log", "exit_code": 0, "output": "00:41\n933 attempts"}
        self.assertEqual(strategy.result_state(poll), "monitoring")
        self.assertTrue(strategy.poll_command("pgrep -af 'python worker'; tail -3 job.log"))
        self.assertFalse(strategy.poll_command("timeout 60 python worker.py; tail -3 job.log"))
        self.assertIsNone(strategy.evidence_fingerprint(poll))
        poll["output"] = "\n".join("Broken Pipe Error while logging in " + str(i) for i in range(9))
        self.assertEqual(strategy.result_state(poll), "error")
        poll["output"] += "\n[+] LAB\\staff:observed"
        self.assertEqual(strategy.result_state(poll), "evidence")
        self.assertEqual(strategy.result_state({"command": "query service", "exit_code": 0,
                                                "output": "Product Example 2.1"}), "evidence")

    def test_changing_poll_counters_hand_back_after_three_commands(self):
        class Terminal:
            def run(self, command, timeout, **kwargs):
                return {"command": command, "exit_code": 0, "seconds": .1, "truncated": False,
                        "output": "" if command.startswith("sh -n") else command + "\n1000 attempts", "as_root": False}
            def stats(self): return None
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.session(path)
            replies = iter(json.dumps({"thought": "Check existing job", "command": f"ps -p {100+i} -o etime; tail -3 job.log", "done": False}) for i in range(5))
            with patch.object(harp, "terminal_for", return_value=Terminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=lambda *args: next(replies)):
                harp.delegate(path, "Monitor current job", 5, quiet=True, unlimited_budget=True)
            state = harp.load_session(path)
            self.assertEqual(state["local_steps"], 3)
            self.assertEqual(state["last_delegate_stop"], "monitoring_stalled")
            self.assertIn("background job", state["oracle_help_request"])
            event = json.loads((path / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(event["new_evidence"], 0)
            self.assertEqual(harp_nim.oracle_history(path)["stall_cycles"], 1)

    def test_unlimited_session_preserves_model_call_cap_inside_delegation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            state = self.session(path)
            state["config"]["max_model_calls"] = 1
            harp.save_session(path, state)
            def reply(config, system, user, ledger):
                ledger.append({"seconds": 0})
                return '{"thought":"Inspect","command":"echo service","done":false}'
            with patch.object(harp, "terminal_for", return_value=fixtures.DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=reply):
                harp.delegate(path, "Inspect service", 4, quiet=True, unlimited_budget=True)
            state = harp.load_session(path)
            self.assertEqual(state["local_steps"], 1)
            self.assertEqual(state["last_delegate_stop"], "model_call_budget")

    def test_research_prompt_and_context_are_toggle_scoped(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                path = Path(temp)
                state = self.session(path, enabled)
                body_seen = []
                def chat(config, body, **kwargs):
                    body_seen.append(body)
                    return {"choices": [{"message": {"content": '{"plan":"Review complete","objective":"","stop":true}'}}]}
                with patch.object(harp_zai, "chat", side_effect=chat), patch.object(harp_research, "search_api") as api:
                    harp_nim.run(path)
                prompt = body_seen[0]["messages"][0]["content"]
                context = json.loads(body_seen[0]["messages"][1]["content"])
                self.assertEqual(harp_research.INSTRUCTION in prompt, enabled)
                self.assertEqual("unverified_research" in context, enabled)
                self.assertEqual("Public search belongs to the oracle" in harp.system_prompt(state), enabled)
                self.assertNotIn("CVE-", prompt)
                api.assert_not_called()

    def test_rejected_guessing_replans_without_executing_or_searching_when_disabled(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.session(path)
            replies = iter((
                {"plan": "No lockout", "objective": "Spray SMB passwords with a wordlist", "stop": False},
                {"plan": "Inspect another exposed capability", "objective": "Enumerate service configuration", "stop": False},
                {"plan": "Review complete", "objective": "", "stop": True}))
            contexts = []
            def chat(config, body, **kwargs):
                contexts.append(json.loads(body["messages"][1]["content"]))
                return {"choices": [{"message": {"content": json.dumps(next(replies))}}]}
            with patch.object(harp_zai, "chat", side_effect=chat), patch.object(harp, "delegate") as delegate, \
                 patch.object(harp_research, "search_api") as api:
                harp_nim.run(path)
            delegate.assert_called_once()
            self.assertEqual(delegate.call_args.args[1], "Enumerate service configuration")
            self.assertIn("error", contexts[1]["strategy_feedback"])
            self.assertNotIn("unverified_research", contexts[1])
            api.assert_not_called()

    def test_research_status_tracks_toggle_unused_in_progress_and_failed(self):
        state = {"status": "active", "config": {"oracle": {"web_search_enabled": True}}}
        self.assertEqual(harp_research.activity_status(state, []), "enabled_unused")
        self.assertEqual(harp_research.activity_status(state, [{"status": "started"}]), "requested")
        self.assertEqual(harp_research.activity_status(state, [{"status": "failed"}]), "failed")
        self.assertEqual(harp_research.activity_status(state, [{"status": "completed"}]), "completed")
        state["status"] = "finished"
        self.assertEqual(harp_research.activity_status(state, [{"status": "started"}]), "interrupted")
        state["config"]["oracle"]["web_search_enabled"] = False
        self.assertEqual(harp_research.activity_status(state, [{"status": "completed"}]), "disabled")

    def test_three_counter_only_delegations_do_not_reset_oracle_stall_counter(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            state = self.session(path)
            state["config"]["oracle"]["unlimited_budget"] = True
            harp.save_session(path, state)
            count = 0
            def chat(config, body, **kwargs):
                nonlocal count
                count += 1
                return {"choices": [{"message": {"content": json.dumps({"plan": "Review existing job",
                    "objective": f"Read job status {count}", "stop": False})}}]}
            def delegate(run_dir, *args, **kwargs):
                current = harp.load_session(run_dir)
                current["local_steps"] += 1
                current["observations"].append({"command": "tail -3 job.log", "exit_code": 0,
                                                "output": f"Attempts: {count * 100}"})
                current["last_delegate_stop"] = "step_budget"
                harp.save_session(run_dir, current)
            with patch.object(harp_zai, "chat", side_effect=chat), patch.object(harp, "delegate", side_effect=delegate):
                harp_nim.run(path)
            self.assertEqual(count, 3)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(events[-1]["reason"], "no_progress")

    def test_disabled_hosted_research_decision_cannot_call_provider(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.session(path, False)
            decision = {"plan": "Look up a prerequisite", "objective": "", "stop": False,
                        "research": {"query": "Example product requirements", "reason": "Check applicability"}}
            reply = {"choices": [{"message": {"content": json.dumps(decision)}}]}
            with patch.object(harp_zai, "chat", return_value=reply), patch.object(harp_research, "search_api") as api:
                harp_nim.run(path)
            api.assert_not_called()
            self.assertFalse((path / "research.json").exists())

    def test_cited_candidate_cap_reaches_worker_without_modifying_implementation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            state = self.session(path)
            state["observations"] = [{"command": "read target document", "exit_code": 0,
                                       "output": "Temporary password: sample-secret"}]
            harp.save_session(path, state)
            decision = {"plan": "Validate recovered password", "objective": "Validate one credential on the service",
                        "implementation": "printf 'bounded implementation'", "stop": False,
                        "credential_test": {"rationale": "Recovered from the target document", "max_attempts": 1,
                            "candidates": [{"value": "sample-secret", "observation": 1,
                                            "quote": "Temporary password: sample-secret"}]}}
            replies = iter((decision, {"plan": "Review complete", "objective": "", "stop": True}))
            with patch.object(harp_zai, "chat", side_effect=lambda *args, **kwargs: {
                    "choices": [{"message": {"content": json.dumps(next(replies))}}]}), \
                 patch.object(harp, "delegate") as delegate:
                harp_nim.run(path)
            task = delegate.call_args.args[1]
            self.assertIn("at most 1 total authentication attempts", task)
            self.assertTrue(task.endswith(strategy.IMPLEMENTATION_MARKER + decision["implementation"]))
            self.assertEqual(harp_nim.oracle_observations(state, {})[0][0]["observation"], 1)


if __name__ == "__main__":
    unittest.main()
