import io
import json
import os
import sys
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
import harp_nim


class DummyTerminal:
    def run(self, command, timeout, **kwargs):
        return {"command": command, "exit_code": 0, "seconds": 0.1,
                "output": "one result", "truncated": False, "as_root": kwargs.get("as_root", False)}

    def stats(self):
        return {"MemUsage": "1MiB / 512MiB"}


class HarpTests(unittest.TestCase):
    def test_new_session_is_visible_during_recon(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["target"] = "10.10.10.5"
        seen = []

        class FakeTerminal:
            name = "fake-kali"
            event_dir = None
            recon_mode = False
            recon_stage = ""
            def __init__(self, _cfg): pass
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def run(self, command, _timeout, **_kwargs):
                state = harp.load_session(self.event_dir)
                seen.append((state["status"], state["recon_started_epoch"], command))
                return {"command": command, "exit_code": 0, "seconds": 0.1,
                        "output": "<nmaprun></nmaprun>", "truncated": False, "as_root": False}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp, "KaliTerminal", FakeTerminal), \
             patch.object(harp, "docker", return_value="image-id"), \
             patch.object(harp, "deterministic_http_probes", return_value=[]), \
             patch.object(harp, "deterministic_smb_probes", return_value=[]):
            run_dir = harp.start_session(cfg, Path(temp))
            state = harp.load_session(run_dir)
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
            self.assertEqual(seen[0][0], "recon")
            self.assertEqual(state["status"], "active")
            self.assertTrue(any(event["type"] == "recon_started" for event in events))
            self.assertTrue(any(event["type"] == "recon_finished" for event in events))

    def test_recon_command_events_appear_before_and_after_local_execution(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            harp.save_session(path, {"status": "recon", "recon_tool_calls": 0})
            terminal = harp.KaliTerminal({})
            terminal.event_dir = path
            terminal.recon_mode = True
            terminal.recon_stage = "Port sweep"
            with patch.object(terminal, "command_argv", return_value=[sys.executable, "-c", "print('check')"]):
                result = terminal.run("nmap -p 80 10.10.10.5", 5, live=False)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual([event["type"] for event in events],
                             ["recon_command_started", "recon_command_finished"])
            self.assertEqual(harp.load_session(path)["recon_tool_calls"], 1)
            self.assertEqual(result["exit_code"], 0)

    def test_recon_stop_preserves_a_finished_session_record(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["target"] = "10.10.10.5"
        created = []

        class StoppingTerminal:
            name = "fake-kali"
            event_dir = None
            recon_mode = False
            recon_stage = ""
            def __init__(self, _cfg): pass
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def run(self, command, _timeout, **_kwargs):
                created.append(self.event_dir)
                (self.event_dir / ".stop_session").touch()
                return {"command": command, "exit_code": 0, "seconds": 0.1,
                        "output": "<nmaprun></nmaprun>", "truncated": False, "as_root": False}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp, "KaliTerminal", StoppingTerminal), \
             patch.object(harp, "deterministic_http_probes", return_value=[]), \
             patch.object(harp, "deterministic_smb_probes", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "stopped by operator"):
                harp.start_session(cfg, Path(temp))
            state = harp.load_session(created[0])
            events = [json.loads(line) for line in (created[0] / "events.jsonl").read_text().splitlines()]
            self.assertEqual(state["status"], "finished")
            self.assertTrue(any(event["type"] == "recon_cancelled" for event in events))

    def test_nmap_preprocessing_keeps_only_open_ports(self):
        xml = '<nmaprun><host><ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>'
        self.assertEqual(harp.parse_nmap_xml(xml), [
            {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "product": "", "version": ""}
        ])

    def test_ad_port_check_requires_smb_and_domain_hint(self):
        findings = [{"port": port, "protocol": "tcp"} for port in (53, 135, 139, 445)]
        self.assertTrue(harp.active_directory_hint(findings))
        self.assertIn(88, harp.AD_TCP_PORTS)
        self.assertIn(5985, harp.AD_TCP_PORTS)
        self.assertFalse(harp.active_directory_hint([{"port": 445, "protocol": "tcp"}]))
        self.assertTrue(harp.needs_deeper_vpn_scan(findings))
        self.assertFalse(harp.needs_deeper_vpn_scan(findings + [
            {"port": port, "protocol": "tcp"} for port in (88, 389, 464, 593)]))

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

    def test_windows_smb_recon_runs_dot_user_probes(self):
        findings = [{"port": 445, "protocol": "tcp", "service": "microsoft-ds",
                     "product": "Microsoft Windows", "version": ""}]
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            probes = harp.deterministic_smb_probes(DummyTerminal(), "10.10.10.5", findings, path)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
        self.assertEqual([probe["option"] for probe in probes],
                         ["--shares", "--users", "--rid-brute"])
        self.assertEqual([event["result"]["command"] for event in events], [
            f"nxc smb 10.10.10.5 -u '.' -p '' {option}"
            for option in ("--shares", "--users", "--rid-brute")])

    def test_smb_recon_skips_non_windows_and_samba(self):
        linux = [{"port": 445, "protocol": "tcp", "service": "microsoft-ds",
                  "product": "Samba smbd", "version": ""}]
        no_smb = [{"port": 135, "protocol": "tcp", "service": "msrpc",
                   "product": "Microsoft Windows RPC", "version": ""}]
        self.assertFalse(harp.windows_smb_detected(linux))
        self.assertFalse(harp.windows_smb_detected(no_smb))

    def test_nim_context_keeps_useful_smb_evidence_compact(self):
        probes = [{"option": "--shares", "exit_code": 0,
                   "output_excerpt": "[*] Initializing database\nShare Permissions\nHR READ\n"},
                  {"option": "--rid-brute", "exit_code": 0,
                   "output_excerpt": "512: Domain Admins (SidTypeGroup)\n1104: sample.user (SidTypeUser)\n"}]
        compact = harp_nim.compact_smb_probes(probes)
        self.assertIn("HR READ", compact[0]["summary"])
        self.assertNotIn("Initializing database", compact[0]["summary"])
        self.assertIn("sample.user", compact[1]["summary"])
        self.assertNotIn("Domain Admins", compact[1]["summary"])

    def test_nim_speed_test_requires_usable_plan(self):
        reply = {"choices": [{"message": {"content":
                 '{"plan":"Review SMB","objective":"List shares","stop":false}'}}]}
        with patch.object(harp_nim, "request", return_value=reply) as request:
            result = harp_nim.benchmark_one("example/fast-model")
        self.assertTrue(result["usable"])
        self.assertEqual(request.call_args.kwargs["timeout_seconds"], 90)
        self.assertNotIn("10.129.", str(request.call_args))

    def test_nim_ultra_requests_visible_reply_without_reasoning(self):
        self.assertEqual(harp_nim.oracle_model_options("nvidia/nemotron-3-ultra-550b-a55b"),
                         {"reasoning_effort": "none"})
        self.assertEqual(harp_nim.oracle_model_options("example/fast-model"), {})

    def test_nim_plan_carries_null_auth_boundary_to_worker(self):
        objective = harp_nim.bound_objective(
            "Enumerate the HR share using a null SMB session.", "List files in the HR share.")
        self.assertIn("null or guest authentication only", objective)
        self.assertEqual(harp_nim.bound_objective("Inspect HTTP", "Read the page"), "Read the page")

    def test_oracle_probe_is_read_only_and_target_scoped(self):
        session = {"target": "10.10.10.5", "observations": []}
        self.assertIsNone(harp_nim.oracle_probe_issue(
            "nxc smb 10.10.10.5 -u . -p '' --shares", session, "Null SMB session only"))
        self.assertIsNotNone(harp_nim.oracle_probe_issue(
            "nxc smb 10.10.10.5 -u . -p '' --shares; curl other", session, "Null SMB session only"))
        self.assertIsNotNone(harp_nim.oracle_probe_issue(
            "nxc smb 10.10.10.6 -u . -p '' --shares", session, "Null SMB session only"))
        self.assertIsNone(harp_nim.oracle_probe_issue(
            "ldapsearch -x -H ldap://10.10.10.5 -b dc=lab,dc=local '(objectClass=user)'",
            session, "Enumerate LDAP users anonymously"))
        self.assertIsNotNone(harp_nim.oracle_probe_issue(
            "nxc smb 10.10.10.5 -u . -p '' --shares -x id", session, "Null SMB session only"))

    def test_nim_replans_after_unproductive_worker(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["config"]["oracle"] = {"provider": "nvidia_nim", "model": "example/model",
                                          "max_cycles": 3, "steps_per_cycle": 2}
            harp.save_session(path, state)
            first = {"plan": "List services", "objective": "List services once", "stop": False}
            second = {"plan": "Stop after review", "objective": "", "stop": True}
            replies = [{"choices": [{"message": {"content": json.dumps(item)}}]}
                       for item in (first, second)]

            def failed_delegate(run_dir, _objective, _steps, *, quiet):
                current = harp.load_session(run_dir)
                current["last_delegate_stop"] = "three_unproductive_commands"
                current["observations"].append({"command": "nmap target", "exit_code": 1,
                                                "output": "No useful result"})
                harp.save_session(run_dir, current)

            with patch.object(harp_nim, "request", side_effect=replies) as request, \
                 patch.object(harp, "delegate", side_effect=failed_delegate):
                harp_nim.run(path)
            self.assertEqual(request.call_count, 2)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertTrue(any(item.get("type") == "oracle_nim_recovery" for item in events))

    def test_nim_can_run_one_scoped_probe_during_recovery(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["last_delegate_stop"] = "three_unproductive_commands"
            state["config"]["oracle"] = {"provider": "nvidia_nim", "model": "example/model",
                                          "max_cycles": 2, "steps_per_cycle": 2}
            harp.save_session(path, state)
            probe = "nxc smb target -u . -p '' --shares"
            decisions = [
                {"plan": "Check null SMB access", "objective": "", "oracle_command": probe,
                 "stop": False},
                {"plan": "Evidence reviewed", "objective": "", "stop": True},
            ]
            replies = [{"choices": [{"message": {"content": json.dumps(item)}}]}
                       for item in decisions]
            with patch.object(harp_nim, "request", side_effect=replies), \
                 patch.object(harp, "direct_exec") as terminal:
                harp_nim.run(path)
            terminal.assert_called_once_with(path, probe, quiet=True)

    def test_nim_corrects_rejected_probe_without_stopping(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["last_delegate_stop"] = "null_auth_denied"
            state["config"]["oracle"] = {"provider": "nvidia_nim", "model": "example/model",
                                          "max_cycles": 3, "steps_per_cycle": 2}
            harp.save_session(path, state)
            invalid = "nxc smb target -u . -p '' --shares -x id"
            valid = "ldapsearch -x -H ldap://target -b dc=lab,dc=local '(objectClass=user)'"
            decisions = [
                {"plan": "Check LDAP", "objective": "", "oracle_command": invalid, "stop": False},
                {"plan": "Check LDAP", "objective": "", "oracle_command": valid, "stop": False},
                {"plan": "Evidence reviewed", "objective": "", "stop": True},
            ]
            replies = [{"choices": [{"message": {"content": json.dumps(item)}}]}
                       for item in decisions]
            with patch.object(harp_nim, "request", side_effect=replies) as request, \
                 patch.object(harp, "direct_exec") as terminal:
                harp_nim.run(path)
            terminal.assert_called_once_with(path, valid, quiet=True)
            self.assertEqual(request.call_count, 3)
            second_context = json.loads(request.call_args_list[1].args[1]["messages"][1]["content"])
            self.assertIn("probe_feedback", second_context)

    def test_nim_resume_keeps_cycle_budget_and_probe_feedback(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["last_delegate_stop"] = "null_auth_denied"
            state["config"]["oracle"] = {"provider": "nvidia_nim", "model": "example/model",
                                          "max_cycles": 3, "steps_per_cycle": 2}
            harp.save_session(path, state)
            harp.append_event(path, {"type": "oracle_nim_request", "cycle": 1})
            harp.append_event(path, {"type": "oracle_nim_recovery", "reason": "null_auth_denied", "attempt": 1})
            harp.append_event(path, {"type": "oracle_nim_request", "cycle": 2})
            harp.append_event(path, {"type": "oracle_nim_stopped", "reason": "probe_rejected",
                                     "detail": "Probe option was too broad"})
            reply = {"choices": [{"message": {"content": json.dumps(
                {"plan": "Review", "objective": "", "stop": True})}}]}
            with patch.object(harp_nim, "request", return_value=reply) as request:
                harp_nim.run(path)
            self.assertEqual(request.call_count, 1)
            context = json.loads(request.call_args.args[1]["messages"][1]["content"])
            self.assertEqual(context["cycle"], 3)
            self.assertEqual(context["probe_feedback"]["reason"], "Probe option was too broad")

    def test_local_reply_accepts_identical_duplicate_json_only(self):
        action = '{"thought":"list share","command":"smbclient -N //target/HR -c ls","done":false}'
        self.assertEqual(harp.json_object(action + "\n" + action)["thought"], "list share")
        with self.assertRaises(ValueError):
            harp.json_object(action + '\n{"command":"different"}')

    def test_local_command_check_catches_smbclient_prompt_and_quoting(self):
        objective = "Download files from //10.10.10.5/HR"
        self.assertIn("prompt", harp.local_command_issue(
            'smbclient -N //10.10.10.5/HR -c "recurse; mget *"', "10.10.10.5", objective))
        self.assertIn("double quotes", harp.local_command_issue(
            'smbclient -N //10.10.10.5/HR -c "get \'Notice from HR.txt\'"', "10.10.10.5", objective))
        self.assertIsNone(harp.local_command_issue(
            "smbclient -N //10.10.10.5/HR -c 'get \"Notice from HR.txt\"'", "10.10.10.5", objective))
        self.assertIn("outside", harp.local_command_issue(
            "nxc smb 10.10.10.6 --shares", "10.10.10.5", objective))

    def test_null_smb_task_rejects_named_account_and_guessed_password(self):
        target = "10.10.10.5"
        objective = "List the HR share using null authentication only"
        self.assertIn("named accounts", harp.local_command_issue(
            'smbclient //10.10.10.5/HR -U "sample.user%guess" -c ls',
            target, objective, []))
        self.assertIn("empty SMB password", harp.local_command_issue(
            "nxc smb 10.10.10.5 -u . -p guess --shares", target, objective, []))
        self.assertIsNone(harp.local_command_issue(
            "nxc smb 10.10.10.5 -u . -p '' --shares", target, objective, []))
        self.assertIn("no terminal evidence", harp.local_command_issue(
            'smbclient //10.10.10.5/HR -U "sample.user%guess" -c ls',
            target, "Use the known account", []))

    def test_null_smb_access_denied_returns_control_after_one_step(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            reply = json.dumps({"thought": "List share", "command": "smbclient -N //target/HR -c ls",
                                "done": False})

            def run(command, _timeout, **_kwargs):
                denied = not command.startswith("sh -n")
                return {"command": command, "exit_code": 1 if denied else 0,
                        "seconds": 0.1, "output": "NT_STATUS_ACCESS_DENIED" if denied else "",
                        "truncated": False, "as_root": False}

            terminal = SimpleNamespace(run=run, stats=lambda: None)
            with patch.object(harp, "terminal_for", return_value=terminal), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "List //target/HR using null authentication", 3, quiet=True)
            state = harp.load_session(path)
            self.assertEqual(state["local_steps"], 1)
            self.assertEqual(state["last_delegate_stop"], "null_auth_denied")

    def test_rejected_local_command_is_not_executed(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            bad = '{"thought":"download","command":"smbclient -N //target/HR -c \\"mget *\\"","done":false}'
            good = '{"thought":"list","command":"smbclient -N //target/HR -c \\"ls\\"","done":false}'
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=[bad, good]):
                harp.delegate(path, "List //target/HR", 2, quiet=True)
            state = harp.load_session(path)
            commands = [item["command"] for item in state["observations"]]
            self.assertEqual(commands, ['smbclient -N //target/HR -c "ls"'])

    def test_session_stop_marker_prevents_new_delegation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            (path / ".stop_session").touch()
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192):
                with self.assertRaisesRegex(RuntimeError, "Session stop was requested"):
                    harp.delegate(path, "inspect target", 1, quiet=True)

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
        self.assertIn("launch_control_center", names)
        self.assertIn("wait_for_session", names)

    def test_control_center_reopens_without_exposing_its_token(self):
        with patch.object(harp_mcp, "_control_record", return_value={"port": 8765, "token": "private-token"}), \
             patch.object(harp_mcp.webbrowser, "open", return_value=True) as browser:
            result = json.loads(harp_mcp.launch_control_center())
        self.assertEqual(result["url"], "http://127.0.0.1:8765/")
        self.assertNotIn("private-token", json.dumps(result))
        browser.assert_called_once_with("http://127.0.0.1:8765/#token=private-token")

    def test_web_config_can_save_model_before_target(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            config_path = Path(temp) / "harp.json"
            state = object.__new__(harp_web.HARPWebState)
            state.lock = threading.RLock()
            payload = {"studio": {"model": "example/model:Q4_K_P", "port": 8888,
                                  "context": 32768, "cache_k": "q8_0", "cache_v": "q8_0", "parallel": 1}}
            with patch.object(harp_web, "CONFIG", config_path):
                saved = state.save_config(payload)
                self.assertEqual(saved["target"], "")
                self.assertEqual(saved["local"]["model"], "example/model")
                with self.assertRaises(ValueError):
                    harp.load_config(config_path)
                saved = state.save_config({"target": "10.10.11.123"})
                self.assertEqual(harp.load_config(config_path)["target"], "10.10.11.123")

    def test_codex_picks_up_gui_started_hybrid_session(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            runs = Path(temp) / "runs"
            path = runs / "20261103-120000-abcdef"
            path.mkdir(parents=True)
            self.make_session(path)
            with patch.object(harp_mcp, "RUNS", runs):
                result = harp_mcp.wait_for_session("2020-01-01T00:00:00+00:00", 1)
            self.assertIn(str(path.resolve()), result)
            self.assertIn("Hybrid session ready", result)

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

    def test_artifact_value_deduplicates_across_titles_and_old_records(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            args = dict(kind="credential", value="demo-pass-123", source="cat note",
                        evidence="terminal", evidence_backed=True)
            first = harp_artifacts.register_artifact(path, title="First label", **args)
            second = harp_artifacts.register_artifact(path, title="Another label", **args)
            self.assertEqual(first["id"], second["id"])
            with (path / "artifacts.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({**first, "id": "old-duplicate", "title": "Old label"}) + "\n")
            self.assertEqual(len(harp_artifacts.list_artifacts(path)), 1)

    def test_wsl_terminal_uses_selected_distro_and_user(self):
        cfg = json.loads(Path("harp.htb.example.json").read_text())
        cfg.update(runtime="wsl", wsl_distro="kali-linux", wsl_user="kali", target="10.10.10.10")
        terminal = harp.WslTerminal(cfg)
        argv = terminal.command_argv("nmap -sT 10.10.10.10", 10, False)
        self.assertEqual(argv[:6], ["wsl.exe", "--distribution", "kali-linux", "--user", "kali", "--exec"])
        self.assertIn(terminal.workspace, argv[-1])
        self.assertEqual(terminal.command_argv("id", 10, True)[4], "root")
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            self.assertEqual(harp.load_config(path)["runtime"], "wsl")

    def test_document_capture_is_bounded_and_preserved(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            terminal = harp.KaliTerminal(json.loads(Path("harp.example.json").read_text()))
            with patch.object(harp, "terminal_for", return_value=terminal), \
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
