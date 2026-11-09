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
    def test_session_save_retries_transient_windows_replace_denial(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            run_dir = Path(temp)
            original_replace = Path.replace
            attempts = []

            def flaky_replace(source, target):
                attempts.append(source)
                if len(attempts) <= 2:
                    raise PermissionError("destination briefly in use")
                return original_replace(source, target)

            with patch.object(Path, "replace", flaky_replace), patch.object(harp.time, "sleep") as sleep:
                harp.save_session(run_dir, {"status": "active"})
            self.assertEqual(len(attempts), 3)
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual(harp.load_session(run_dir)["status"], "active")
            self.assertEqual(list(run_dir.glob("session.json.*.tmp")), [])

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

    def test_completed_recon_is_reused_and_can_be_refreshed(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["target"] = "10.10.10.5"
        commands = []
        xml = ('<nmaprun><host><ports><port protocol="tcp" portid="445">'
               '<state state="open"/><service name="microsoft-ds"/>'
               '</port></ports></host></nmaprun>')

        class FakeTerminal:
            name = "fake-kali"
            workspace = "/workspace"
            event_dir = None
            recon_mode = False
            recon_stage = ""
            def __init__(self, _cfg): pass
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def run(self, command, _timeout, **_kwargs):
                commands.append(command)
                return {"command": command, "exit_code": 0, "seconds": 0.1,
                        "output": xml, "truncated": False, "as_root": False}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp, "KaliTerminal", FakeTerminal), \
             patch.object(harp, "docker", return_value="image-id"), \
             patch.object(harp, "deterministic_http_probes", return_value=[]), \
             patch.object(harp, "deterministic_smb_probes", return_value=[]):
            runs = Path(temp)
            first = harp.start_session(cfg, runs)
            first_count = len(commands)
            self.assertGreater(first_count, 0)
            cache = harp.recon_cache_path(runs, cfg)
            self.assertTrue(cache.is_file())
            second = harp.start_session(cfg, runs)
            self.assertEqual(len(commands), first_count)
            reused = harp.load_session(second)
            self.assertEqual(reused["recon_stage"], "Reused")
            self.assertEqual(reused["recon_source_session"], first.name)
            self.assertEqual(reused["recon_tool_calls"], 0)
            self.assertEqual(reused["recon"], harp.load_session(first)["recon"])
            self.assertTrue(any(json.loads(line)["type"] == "recon_reused"
                                for line in (second / "events.jsonl").read_text().splitlines()))
            harp.start_session(cfg, runs, fresh_recon=True)
            self.assertGreater(len(commands), first_count)
            refreshed_count = len(commands)
            different = {**cfg, "scan_ports": "1-1024"}
            harp.start_session(different, runs)
            self.assertGreater(len(commands), refreshed_count)

    def test_existing_completed_session_seeds_recon_cache(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["target"] = "10.10.10.5"
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            runs = Path(temp)
            old = runs / "20261101-000000-abcdef"
            old.mkdir()
            self.make_session(old)
            session = harp.load_session(old)
            session.update(config=cfg, recon_stage="Complete", recon_finished_epoch=time.time(),
                           recon=[{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}])
            harp.save_session(old, session)
            (old / "events.jsonl").write_text(json.dumps({"type": "deterministic_recon", "result": {
                "output": '<nmaprun><host><hostnames><hostname name="legacy.htb"/>'
                          '</hostnames></host></nmaprun>'}}) + "\n", encoding="utf-8")
            snapshot = harp.find_recon_snapshot(runs, cfg)
            self.assertEqual(snapshot["source_session"], old.name)
            self.assertEqual(snapshot["recon"][0]["port"], 445)
            self.assertEqual(snapshot["hostnames"], ["legacy.htb"])
            self.assertTrue(harp.recon_cache_path(runs, cfg).is_file())
            self.assertEqual(harp.hostname_recon_candidates(runs, {**cfg, "target": "10.10.10.6"})[0]["hostnames"],
                             ["legacy.htb"])

    def test_hostname_match_reuses_recon_across_new_ip(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["target"] = "10.10.10.5"
        commands = []

        class FakeTerminal:
            name = "fake-kali"
            workspace = "/workspace"
            event_dir = None
            recon_mode = False
            recon_stage = ""
            def __init__(self, config): self.target = config["target"]
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def run(self, command, _timeout, **_kwargs):
                commands.append((self.target, command))
                hostname = "box.htb" if self.target != "10.10.10.7" else "other.htb"
                xml = (f'<nmaprun><host><hostnames><hostname name="{hostname}"/>'
                       '</hostnames><ports><port protocol="tcp" portid="80">'
                       f'<state state="open"/><service name="http" hostname="{hostname}"/>'
                       '</port></ports></host></nmaprun>')
                return {"command": command, "exit_code": 0, "seconds": 0.1,
                        "output": xml, "truncated": False, "as_root": False}

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp, "KaliTerminal", FakeTerminal), \
             patch.object(harp, "docker", return_value="image-id"), \
             patch.object(harp, "deterministic_http_probes", return_value=[]), \
             patch.object(harp, "deterministic_smb_probes", return_value=[]):
            runs = Path(temp)
            first = harp.start_session(cfg, runs)
            self.assertEqual(harp.load_session(first)["recon_hostnames"], ["box.htb"])
            initial_count = len(commands)
            moved = {**cfg, "target": "10.10.10.6"}
            second = harp.start_session(moved, runs)
            self.assertEqual(len(commands), initial_count + 1)
            self.assertIn("-p 80", commands[-1][1])
            state = harp.load_session(second)
            self.assertEqual(state["recon_match_hostname"], "box.htb")
            self.assertEqual(state["recon_source_target"], cfg["target"])
            self.assertEqual(state["recon"], harp.load_session(first)["recon"])
            self.assertTrue(harp.recon_cache_path(runs, moved).is_file())
            third = harp.start_session({**cfg, "target": "10.10.10.7"}, runs)
            self.assertEqual(harp.load_session(third)["recon_stage"], "Complete")
            self.assertGreater(len(commands), initial_count + 2)

    def test_htb_hostname_parser_ignores_unrelated_names(self):
        xml = ('<nmaprun><host><hostnames><hostname name="BOX.HTB"/>'
               '</hostnames><ports><port portid="80"><service extrainfo="redirect to admin.box.htb"/>'
               '</port></ports></host></nmaprun>')
        self.assertEqual(harp.htb_hostnames(xml), ["admin.box.htb", "box.htb"])
        self.assertEqual(harp.htb_hostnames('<nmaprun><hostnames><hostname name="example.com"/>'
                                             '</hostnames></nmaprun>'), [])

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

    def test_repeated_command_can_run_after_human_review(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            reply = '{"thought":"test","command":"echo result","done":false}'
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "review_proxy_command", return_value=(True, 1.0)) as review, \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "inspect target", 2)
            state = harp.load_session(path)
            self.assertEqual(state["local_steps"], 2)
            self.assertEqual(state["last_delegate_stop"], "step_budget")
            review.assert_called_once()
            self.assertIsNone(state["human_intervention_at"])

    def test_unexecutable_proxy_format_is_repaired_without_approval_or_resume(self):
        for bad in ("echo first\necho second", "echo " + "x" * 1000):
            with self.subTest(length=len(bad)), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                path = Path(temp)
                self.make_session(path)
                replies = iter([{"command": bad}, {"command": "echo repaired"}, {"done": True}])
                contexts = []
                def reply(model, system, user, ledger):
                    contexts.append(json.loads(user))
                    ledger.append({"finish_reason": "stop"})
                    return json.dumps(next(replies))
                terminal = DummyTerminal()
                with patch.object(harp, "terminal_for", return_value=terminal), \
                     patch.object(terminal, "run", wraps=terminal.run) as execute, \
                     patch.object(harp, "model_context_tokens", return_value=8192), \
                     patch.object(harp, "count_chat_tokens", return_value=300), \
                     patch.object(harp, "review_proxy_command") as review, \
                     patch.object(harp, "api_chat", side_effect=reply):
                    harp.delegate(path, "Inspect target", 2, quiet=True)
                review.assert_not_called()
                self.assertEqual(harp.load_session(path)["last_delegate_stop"], "local_done")
                self.assertEqual(harp.load_session(path)["local_steps"], 1)
                self.assertIn("single line", contexts[1]["last_command_feedback"])
                self.assertFalse(any(c.args[0] == bad for c in execute.call_args_list))

    def test_repeated_unexecutable_formats_return_bounded_oracle_recovery(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "review_proxy_command") as review, \
                 patch.object(harp, "api_chat", return_value=json.dumps({"command": "echo a\necho b"})) as chat:
                harp.delegate(path, "Inspect target", 2, quiet=True)
            review.assert_not_called()
            self.assertEqual(chat.call_count, 3)
            state = harp.load_session(path)
            self.assertEqual(state["last_delegate_stop"], "command_validation_failed")
            self.assertEqual(state["local_steps"], 0)
            self.assertIn(state["last_delegate_stop"], harp_nim.RECOVERABLE_STOPS)

    def test_proxy_requests_oracle_help_without_running_a_command(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            reply = json.dumps({"thought": "Need exact protocol framing", "needs_oracle": True,
                                "done": False})
            terminal = DummyTerminal()
            with patch.object(terminal, "run") as run, \
                 patch.object(harp, "terminal_for", return_value=terminal), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "Inspect the service", 2, quiet=True)
            state = harp.load_session(path)
            self.assertEqual(state["last_delegate_stop"], "oracle_requested")
            self.assertEqual(state["oracle_help_request"], "Need exact protocol framing")
            self.assertEqual(state["local_steps"], 0)
            run.assert_not_called()

    def test_unlimited_budget_skips_step_and_model_call_caps_but_still_stops(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["config"]["max_model_calls"] = 1
            harp.save_session(path, state)
            replies = iter([
                '{"thought":"first","command":"echo first","done":false}',
                '{"thought":"second","command":"echo second","done":false}',
                '{"thought":"finished","done":true,"finding":"Reviewed results"}',
            ])

            def model_reply(_model, _system, _user, ledger):
                ledger.append({"model": "test", "seconds": 0, "prompt_tokens": 0,
                               "completion_tokens": 0, "estimated_usd": 0})
                return next(replies)

            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=model_reply):
                harp.delegate(path, "Inspect target", 1, quiet=True, unlimited_budget=True)
            saved = harp.load_session(path)
            self.assertEqual(saved["local_steps"], 2)
            self.assertEqual(len(saved["local_calls"]), 3)
            self.assertEqual(saved["last_delegate_stop"], "local_done")

    def test_proxy_api_failure_is_not_reported_as_step_budget(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=RuntimeError("API failed")):
                with self.assertRaisesRegex(RuntimeError, "API failed"):
                    harp.delegate(path, "Inspect target", 1, quiet=True)
            saved = harp.load_session(path)
            self.assertEqual(saved["last_delegate_stop"], "proxy_api_error")
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(events[-1]["reason"], "proxy_api_error")

    def test_proxy_command_trims_trailing_newline_before_terminal(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            reply = json.dumps({"thought": "Check one service", "command": "echo result\n", "done": False})
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "Inspect target", 1, quiet=True)
            saved = harp.load_session(path)
            self.assertEqual(saved["local_steps"], 1)
            self.assertEqual(saved["observations"][0]["command"], "echo result")
            self.assertEqual(saved["last_delegate_stop"], "step_budget")
            self.assertIn("control character", harp.local_command_issue(
                "echo first\necho second", "target", "Inspect target"))

    def test_unlimited_oracle_can_resume_past_cycle_cap_and_uses_verified_artifacts(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["config"]["oracle"] = {"provider": "nvidia_nim", "model": "example/model",
                                           "max_cycles": 1, "steps_per_cycle": 1,
                                           "unlimited_budget": True}
            harp.save_session(path, state)
            harp.append_event(path, {"type": "oracle_nim_request", "cycle": 1})
            harp_artifacts.register_artifact(path, kind="credential", title="Discovered password",
                                             value="example-secret", source="read evidence",
                                             evidence="Observed in terminal", evidence_backed=True)
            reply = {"choices": [{"message": {"content":
                     '{"plan":"Review evidence","objective":"","stop":true}'}}]}
            with patch.object(harp_nim, "request", return_value=reply) as request:
                harp_nim.run(path)
            self.assertEqual(request.call_count, 1)
            body = request.call_args.args[1]
            context = json.loads(body["messages"][1]["content"])
            self.assertEqual(context["cycle"], 2)
            self.assertEqual(context["verified_artifacts"][0]["value"], "example-secret")
            self.assertIn("not proof that it belongs to any named user", body["messages"][0]["content"])

    def test_unlimited_budget_config_accepts_steps_beyond_normal_limit(self):
        config = json.loads(Path("harp.example.json").read_text())
        config["oracle"]["steps_per_cycle"] = config["max_steps"] + 1
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "proxy step limit"):
                harp.load_config(path)
            config["oracle"]["unlimited_budget"] = True
            path.write_text(json.dumps(config), encoding="utf-8")
            self.assertTrue(harp.load_config(path)["oracle"]["unlimited_budget"])

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

    def test_nim_history_preserves_distinct_older_results_with_a_bound(self):
        observations = [
            {"command": "list share", "exit_code": 0, "output": "HR READ\n"},
            {"command": "repeat share", "exit_code": 0, "output": "HR READ\n"},
            {"command": "failed login", "exit_code": 1, "output": "Access denied"},
        ] + [{"command": f"check {n}", "exit_code": 0, "output": f"finding {n}"}
             for n in range(12)]
        older = harp_nim.compact_past_observations(observations)
        self.assertEqual(len(older), 8)
        self.assertEqual(len({item["output_excerpt"] for item in older}), 8)
        self.assertNotIn("Access denied", str(older))
        self.assertTrue(all(len(item["output_excerpt"]) <= 523 for item in older))

    def test_nim_attempt_history_restores_plan_terminal_and_rejection(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            harp.append_event(path, {"type": "oracle_nim_request", "cycle": 1})
            harp.append_event(path, {"type": "oracle_plan", "plan": "Check the readable share"})
            harp.append_event(path, {"type": "delegation", "objective": "List share files"})
            harp.append_event(path, {"type": "local_terminal", "result": {
                "command": "smbclient -c ls", "exit_code": 1, "output": "Access denied"}})
            harp.append_event(path, {"type": "local_command_rejected", "command": "bad syntax",
                                     "reason": "Shell syntax check failed"})
            harp.append_event(path, {"type": "delegation_stopped", "reason": "command_validation_failed",
                                     "local_steps": 1})
            attempt = harp_nim.oracle_history(path)["attempts"][0]
            self.assertEqual(attempt["plan"], "Check the readable share")
            self.assertEqual(attempt["last_command"], "smbclient -c ls")
            self.assertEqual(attempt["last_output"], "Access denied")
            self.assertEqual(attempt["last_rejection"]["reason"], "Shell syntax check failed")

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
        self.assertEqual(harp_nim.oracle_model_options("nvidia/nemotron-3-nano-omni-30b-a3b-reasoning"),
                         {"chat_template_kwargs": {"enable_thinking": False}})
        self.assertEqual(harp_nim.oracle_model_options("example/fast-model"), {})

    def test_nim_plan_carries_null_auth_boundary_to_worker(self):
        objective = harp_nim.bound_objective(
            "Enumerate the HR share using a null SMB session only.", "List files in the HR share.")
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
            state["recon"] = [{"port": 445, "service": "microsoft-ds"}]
            state["http_probes"] = [{"port": 80, "status": 200}]
            state["smb_probes"] = [{"option": "--shares", "exit_code": 0,
                                     "output_excerpt": "Share HR READ"}]
            harp.save_session(path, state)
            first = {"plan": "List services", "objective": "List services once", "stop": False}
            second = {"plan": "Stop after review", "objective": "", "stop": True}
            replies = [{"choices": [{"message": {"content": json.dumps(item)}}]}
                       for item in (first, second)]

            def failed_delegate(run_dir, _objective, _steps, *, quiet, unlimited_budget=False):
                current = harp.load_session(run_dir)
                current["last_delegate_stop"] = "three_unproductive_commands"
                current["local_steps"] += 1
                current["observations"].append({"command": "nmap target", "exit_code": 1,
                                                "output": "No useful result"})
                harp.save_session(run_dir, current)

            with patch.object(harp_nim, "request", side_effect=replies) as request, \
                 patch.object(harp, "delegate", side_effect=failed_delegate):
                harp_nim.run(path)
            self.assertEqual(request.call_count, 2)
            first_context = json.loads(request.call_args_list[0].args[1]["messages"][1]["content"])
            self.assertEqual(first_context["recon"], state["recon"])
            self.assertEqual(first_context["http_probes"], state["http_probes"])
            self.assertIn("HR READ", first_context["smb_probes"][0]["summary"])
            second_context = json.loads(request.call_args_list[1].args[1]["messages"][1]["content"])
            self.assertEqual(second_context["prior_attempts"][0]["plan"], "List services")
            self.assertEqual(second_context["prior_attempts"][0]["last_output"], "No useful result")
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertTrue(any(item.get("type") == "oracle_nim_recovery" for item in events))

    def test_nim_oracle_stops_after_three_delegations_without_terminal_progress(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["config"]["oracle"] = {"provider": "nvidia_nim", "model": "example/model",
                                           "max_cycles": 1, "steps_per_cycle": 1,
                                           "unlimited_budget": True}
            harp.save_session(path, state)
            replies = [{"choices": [{"message": {"content": json.dumps(
                {"plan": f"Try another route {n}", "objective": f"Inspect route {n}", "stop": False})}}]}
                for n in range(1, 4)]

            def no_progress(run_dir, _objective, _steps, *, quiet, unlimited_budget):
                current = harp.load_session(run_dir)
                current["last_delegate_stop"] = "repeated_command"
                harp.save_session(run_dir, current)

            with patch.object(harp_nim, "request", side_effect=replies) as request, \
                 patch.object(harp, "delegate", side_effect=no_progress):
                harp_nim.run(path)
            self.assertEqual(request.call_count, 3)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(events[-1]["reason"], "no_progress")

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
        self.assertEqual(harp.json_object("<think>private reasoning</think>\n" + action)["command"],
                         "smbclient -N //target/HR -c ls")
        with self.assertRaisesRegex(ValueError, "no final answer"):
            harp.json_object("<think>unfinished reasoning")
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
        self.assertIn("recurse on", harp.local_command_issue(
            "smbclient -N //10.10.10.5/HR -c 'prompt off; ls -R'", "10.10.10.5", objective))
        self.assertIn("outside", harp.local_command_issue(
            "nxc smb 10.10.10.6 --shares", "10.10.10.5", objective))
        self.assertIn("root approval", harp.local_command_issue(
            "sudo apt install example", "10.10.10.5", objective))

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

    def test_smb_checks_apply_to_smb_command_not_local_setup(self):
        target = "10.10.10.5"
        objective = "Use null authentication to list //10.10.10.5/HR"
        for auth in ("-N", "-U '%'"):
            command = ("mkdir -p hr_share && cd hr_share && smbclient " + auth
                       + " //10.10.10.5/HR -c 'ls'")
            with self.subTest(auth=auth):
                self.assertIsNone(harp.local_command_issue(command, target, objective, []))
        self.assertIsNone(harp.local_command_issue(
            "smbclient -N -p 445 //10.10.10.5/HR -c 'ls'", target, objective, []))
        self.assertIn("empty SMB password", harp.local_command_issue(
            "mkdir -p hr_share && nxc smb 10.10.10.5 -u . -p guess --shares",
            target, objective, []))

    def test_glm_proxy_runs_compound_null_smb_command(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            session = harp.load_session(path)
            session["target"] = "10.10.10.5"
            session["config"]["local"].update({"provider": "zai", "model": "glm-5.3-flash"})
            harp.save_session(path, session)
            command = "mkdir -p hr_share && cd hr_share && smbclient -N //10.10.10.5/HR -c 'ls'"
            replies = [json.dumps({"thought": "List share", "command": command, "done": False}),
                       json.dumps({"thought": "Listing recorded", "done": True})]
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=replies):
                harp.delegate(path, "Use null authentication to list //10.10.10.5/HR", 3, quiet=True)
            saved = harp.load_session(path)
            self.assertEqual(saved["last_delegate_stop"], "local_done")
            self.assertEqual(saved["observations"][0]["command"], command)

    def test_glm_essential_checks_allow_command_guidance_but_keep_scope(self):
        target = "10.10.10.5"
        objective = "Use null authentication to inspect //10.10.10.5/HR"
        command = "smbclient -N //10.10.10.5/HR -c 'ls -R'"
        self.assertIn("recurse on", harp.local_command_issue(command, target, objective, [], checks="strict"))
        self.assertIsNone(harp.local_command_issue(command, target, objective, [], checks="essential"))
        self.assertIn("outside", harp.local_command_issue(
            "smbclient -N //10.10.10.6/HR -c 'ls'", target, objective, [], checks="essential"))
        self.assertIsNone(harp.local_command_issue(
            "smbclient -U named //10.10.10.5/HR -c 'ls'", target, objective, [], checks="essential"))

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
            done = '{"thought":"listing complete","done":true}'
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "review_proxy_command", return_value=(False, 7.5)) as review, \
                 patch.object(harp, "api_chat", side_effect=[bad, good, done]):
                harp.delegate(path, "List //target/HR", 2, quiet=True)
            state = harp.load_session(path)
            commands = [item["command"] for item in state["observations"]]
            self.assertEqual(commands, ['smbclient -N //target/HR -c "ls"'])
            review.assert_called_once()
            self.assertEqual(state["local_steps"], 1)
            self.assertEqual(state["review_wait_seconds"], 7.5)

    def test_approved_flagged_command_runs_without_using_extra_step(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            command = 'smbclient -N //target/HR -c "mget *"'
            reply = json.dumps({"thought": "download", "command": command, "done": False})
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "review_proxy_command", return_value=(True, 12.0)) as review, \
                 patch.object(harp, "api_chat", return_value=reply):
                harp.delegate(path, "Download files from //target/HR", 1, quiet=True)
            state = harp.load_session(path)
            self.assertEqual([item["command"] for item in state["observations"]], [command])
            self.assertEqual(state["local_steps"], 1)
            self.assertEqual(state["review_wait_seconds"], 12.0)
            review.assert_called_once()

    def test_command_review_web_decision_matches_exact_command(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            runs = Path(temp) / "runs"
            path = runs / "20261103-000000-abcdef"
            path.mkdir(parents=True)
            self.make_session(path)
            review_dir = path / "command_reviews"
            review_dir.mkdir()
            request = {"id": "review123", "command": "id", "reason": "Check flagged command"}
            (review_dir / "review123.request.json").write_text(json.dumps(request), encoding="utf-8")
            web_state = object.__new__(harp_web.HARPWebState)
            with patch.object(harp_web, "RUNS", runs):
                self.assertEqual(harp_web.pending_approval(path, harp.load_session(path))["reason"], request["reason"])
                self.assertIsNone(web_state.decide_approval(path.name, "review123", True))
            decision = json.loads((review_dir / "review123.decision.json").read_text(encoding="utf-8"))
            self.assertEqual(decision["command"], request["command"])
            self.assertTrue(decision["approved"])
            self.assertIsNone(harp_web.pending_approval(path, harp.load_session(path)))

    def test_command_review_waits_for_exact_decision_and_cleans_up(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            outcome = []
            worker = threading.Thread(target=lambda: outcome.append(harp.review_proxy_command(
                path, "id", "Check flagged command", 1, path / ".stop_delegate", path / ".stop_session")))
            worker.start()
            review_dir = path / "command_reviews"
            request_path = None
            for _ in range(100):
                requests = list(review_dir.glob("*.request.json")) if review_dir.exists() else []
                if requests:
                    request_path = requests[0]
                    break
                time.sleep(0.01)
            self.assertIsNotNone(request_path)
            request = json.loads(request_path.read_text(encoding="utf-8"))
            decision_path = review_dir / f"{request['id']}.decision.json"
            decision_path.write_text(json.dumps({"id": request["id"], "command": "id", "approved": True}),
                                     encoding="utf-8")
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertTrue(outcome[0][0])
            self.assertFalse(request_path.exists())
            self.assertFalse(decision_path.exists())

    def test_private_pivot_requires_terminal_evidence_and_current_objective(self):
        command = "nmap -Pn 172.16.12.8"
        evidence = [{"exit_code": 0, "output": "Found 172.16.12.8 in host routes"}]
        self.assertIsNotNone(harp.command_scope_issue(command, "10.10.10.5", [], "Probe 172.16.12.8", []))
        self.assertIsNotNone(harp.command_scope_issue(command, "10.10.10.5", [], "Probe the pivot", evidence))
        self.assertIsNone(harp.command_scope_issue(command, "10.10.10.5", [], "Probe 172.16.12.8", evidence))
        self.assertIsNotNone(harp.command_scope_issue("nmap -Pn 8.8.8.8", "10.10.10.5", [],
                                                        "Probe 8.8.8.8", [{"exit_code": 0, "output": "8.8.8.8"}]))

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

    def test_nim_proxy_uses_separate_model_and_supported_request(self):
        config = json.loads(Path("harp.example.json").read_text())
        config["local"].update(provider="nvidia_nim", model="example/proxy-model")
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            loaded = harp.load_config(path)
        self.assertEqual(loaded["oracle"]["model"], "meta/llama-3.1-8b-instruct")
        self.assertEqual(loaded["local"]["model"], "example/proxy-model")
        captured = []

        def fake_open(request, timeout):
            captured.append(request)
            reply = {"choices": [{"message": {"content": '{"done":true,"finding":"test"}'}}],
                     "usage": {"prompt_tokens": 12, "completion_tokens": 3}}
            return io.BytesIO(json.dumps(reply).encode())

        with patch.dict(os.environ, {"NVIDIA_API_KEY": "test-secret"}), \
             patch.object(harp.urllib.request, "urlopen", side_effect=fake_open):
            answer = harp.api_chat(loaded["local"], "system", "user", [])
        body = json.loads(captured[0].data)
        self.assertEqual(body["model"], "example/proxy-model")
        self.assertNotIn("enable_tools", body)
        self.assertNotIn("enabled_tools", body)
        self.assertEqual(captured[0].full_url, "https://integrate.api.nvidia.com/v1/chat/completions")
        self.assertIn('"done":true', answer)
        self.assertGreater(harp.model_context_tokens(loaded["local"]), loaded["local"]["max_input_tokens"])
        self.assertGreater(harp.count_chat_tokens(loaded["local"], "system", "user"), 0)

    def test_nim_proxy_empty_content_records_reason_and_stops_after_retry(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["config"]["local"].update(provider="nvidia_nim",
                                             model="nvidia/nemotron-3-nano-omni-30b-a3b-reasoning")
            harp.save_session(path, state)

            def fake_open(request, timeout):
                body = json.loads(request.data)
                self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
                reply = {"choices": [{"finish_reason": "length",
                                      "message": {"content": None, "reasoning_content": "unusable reasoning"}}],
                         "usage": {"prompt_tokens": 200, "completion_tokens": 1024}}
                return io.BytesIO(json.dumps(reply).encode())

            with patch.dict(os.environ, {"NVIDIA_API_KEY": "test-secret"}), \
                 patch.object(harp.urllib.request, "urlopen", side_effect=fake_open) as request, \
                 patch.object(harp, "terminal_for", return_value=DummyTerminal()):
                harp.delegate(path, "Review one service", 3, quiet=True)
            saved = harp.load_session(path)
            self.assertEqual(request.call_count, 2)
            self.assertEqual(saved["last_delegate_stop"], "invalid_replies")
            self.assertEqual(saved["local_steps"], 0)
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            invalid = [event for event in events if event["type"] == "invalid_local_reply"]
            self.assertEqual(len(invalid), 2)
            self.assertEqual(invalid[0]["finish_reason"], "length")
            self.assertEqual(invalid[0]["reasoning_chars"], len("unusable reasoning"))

    def test_nim_proxy_can_enable_reasoning_with_sufficient_reply_budget(self):
        config = json.loads(Path("harp.example.json").read_text())
        config["local"].update(provider="nvidia_nim",
                               model="nvidia/nemotron-3-nano-omni-30b-a3b-reasoning",
                               enable_thinking=True, max_tokens=8192)
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            model = harp.load_config(path)["local"]
            self.assertEqual(harp.chat_body(model, "system", "user")["chat_template_kwargs"],
                             {"enable_thinking": True})
            config["local"]["max_tokens"] = 1024
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "at least 4096"):
                harp.load_config(path)

    def test_web_config_can_select_nim_proxy_without_unsloth_server(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            config_path = Path(temp) / "harp.json"
            state = object.__new__(harp_web.HARPWebState)
            state.lock = threading.RLock()
            with patch.object(harp_web, "CONFIG", config_path):
                saved = state.save_config({"local": {"provider": "nvidia_nim", "model": "example/proxy"}})
                self.assertEqual(saved["local"]["provider"], "nvidia_nim")
                self.assertEqual(saved["local"]["model"], "example/proxy")

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
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), patch.object(harp, "docker"):
                harp_artifacts.maybe_mark_flag_success(path)
            state = harp.load_session(path)
            self.assertEqual(state["success"], "yes")
            self.assertTrue(state["success_before_human_intervention"])
            self.assertEqual(state["status"], "finished")
            self.assertIsNotNone(state["duration_seconds"])
            harp_artifacts.maybe_mark_flag_success(path)
            harp.finish_session(path, "yes")
            self.assertEqual(harp.load_session(path)["finished_at"], state["finished_at"])

    def test_winrm_control_sequences_and_two_flag_reads_are_correlated(self):
        command = "printf '%s\\n' 'type C:\\Users\\Admin\\Desktop\\root.txt' 'type C:\\Users\\Lab\\Desktop\\user.txt' exit | evil-winrm -i target -u lab"
        prompt = "\x01\x1b[0;31m\x02*Evil-WinRM*\x01\x1b[0m\x02 PS C:\\Users\\Lab> "
        output = (prompt + "\x1b[?25l\x1b[1G\x1b[K" + prompt + "type C:\\Users\\Admin\\Desktop\\root.txt\r\r\n"
                  + "\x1b[1G" + "b" * 32 + "\n" + prompt + "type C:\\Users\\Lab\\Desktop\\user.txt\r\r\n"
                  + "\x1b[1G" + "a" * 32 + "\n" + prompt + "exit\nInfo: Exiting with code 0")
        result = {"command": command, "output": output, "exit_code": 0}
        self.assertEqual(harp_artifacts.flag_values_from_result(result), [("root.txt", "b" * 32), ("user.txt", "a" * 32)])
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            terminal = DummyTerminal()
            terminal.run = lambda c, *_a, **_k: {**result, "command": c, "seconds": 0.1}
            with patch.object(harp, "terminal_for", return_value=terminal), patch.object(harp, "docker"), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=json.dumps({"command": command, "done": False})) as chat:
                harp.delegate(path, "Read both flag files", 5, quiet=True)
            self.assertEqual(chat.call_count, 1)
            self.assertEqual(harp.load_session(path)["status"], "finished")
            self.assertEqual(harp.load_session(path)["last_delegate_stop"], "flags_captured")
            self.assertTrue(all(f["found"] for f in harp_artifacts.flag_status(path).values()))

    def test_winrm_does_not_guess_ambiguous_or_failed_flag_reads(self):
        command = "printf '%s\\n' 'type user.txt' 'type root.txt' | evil-winrm -i target -u lab"
        prompt = "*Evil-WinRM* PS C:\\Users\\Lab> "
        for output in ("a" * 32 + "\n" + "b" * 32,
                       prompt + "type user.txt; type root.txt\n" + "a" * 32,
                       prompt + "echo user.txt\n" + "a" * 32,
                       prompt + "type user.txt\nAccess denied\n" + "a" * 32,
                       prompt + "type user.txt\n" + "a" * 32 + "\n" + "b" * 32):
            with self.subTest(output=output):
                self.assertEqual(harp_artifacts.flag_values_from_result({"command": command, "output": output, "exit_code": 0}), [])
        result = {"command": command, "output": prompt + "type user.txt\n" + "a" * 32, "exit_code": 0}
        self.assertEqual(harp_artifacts.flag_values_from_result({**result, "exit_code": 1}), [])
        self.assertEqual(harp_artifacts.flag_values_from_result({**result, "truncated": True}), [])

    def test_netexec_flags_require_unambiguous_file_read_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            result = {"command": 'nxc winrm target -X "type C:\\loot\\root.txt"',
                      "exit_code": 0, "output": '\x1b[32mWINRM  10.10.10.5  5985  DC  ' + 'b' * 32 + '\x1b[0m\n'}
            self.assertEqual(harp_artifacts.capture_flags_from_result(path, result)[0]["title"], "root.txt")
            for overrides in ({"exit_code": 1}, {"command": "nxc winrm target --sam"},
                              {"command": "nxc winrm target -X 'type user.txt; type root.txt'"},
                              {"output": "Found root flag: " + "b" * 32},
                              {"output": result["output"] + "\n" + "a" * 32}):
                self.assertEqual(harp_artifacts.capture_flags_from_result(path, {**result, **overrides}), [])

    def test_delegation_stops_on_second_flag_without_another_model_call(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            harp_artifacts.capture_flags_from_result(path,
                {"command": "cat user.txt", "exit_code": 0, "output": "a" * 32})
            terminal = DummyTerminal()
            terminal.run = lambda command, *_args, **_kwargs: {
                "command": command, "exit_code": 0, "seconds": 0.1, "output": "b" * 32}
            with patch.object(harp, "terminal_for", return_value=terminal), \
                 patch.object(harp, "docker"), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", return_value=json.dumps({"command": "cat root.txt"})) as chat:
                harp.delegate(path, "Read root.txt", 5, quiet=True)
            state = harp.load_session(path)
            self.assertEqual(chat.call_count, 1)
            self.assertEqual(state["last_delegate_stop"], "flags_captured")
            self.assertEqual(state["status"], "finished")

    def test_artifact_registered_before_next_model_request(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            calls = []
            def reply(*_args):
                calls.append(1)
                if len(calls) == 1:
                    return json.dumps({"command": "cat notes.txt", "artifact": {
                        "kind": "document", "title": "Notes", "value": "one result"}})
                self.assertEqual(harp_artifacts.list_artifacts(path)[0]["value"], "one result")
                return '{"done":true}'
            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=reply):
                harp.delegate(path, "Read notes", 3, quiet=True)
            self.assertEqual(len(calls), 2)

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

    def test_mislabeled_ntlm_hash_is_saved_as_credential(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            lm, nt = "a" * 32, "b" * 32
            session = {"observations": [{"command": "secretsdump example", "exit_code": 0,
                        "output": f"domain\\Administrator:500:{lm}:{nt}:::\n"}]}
            proposal = {"kind": "flag", "title": "Administrator NTLM hash", "value": f"{lm}:{nt}"}
            item = harp_artifacts.capture_model_artifact(path, session, proposal)
            self.assertEqual(item["kind"], "credential")
            self.assertTrue(item["evidence_backed"])
            self.assertEqual(len(harp_artifacts.list_artifacts(path)), 1)

    def test_zai_format_retry_accepts_third_valid_reply(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.make_session(path)
            state = harp.load_session(path)
            state["config"]["local"].update(provider="zai", model="glm-5.3-flash")
            harp.save_session(path, state)
            replies = iter(["A narrative instead of JSON.", "Another narrative.",
                            '{"thought":"No further work","done":true,"finding":"Done"}'])
            prompts = []

            def fake_chat(_model, prompt, _user, calls):
                prompts.append(prompt)
                calls.append({"prompt_tokens": 10, "completion_tokens": 10,
                              "finish_reason": "stop", "reasoning_chars": 0})
                return next(replies)

            with patch.object(harp, "terminal_for", return_value=DummyTerminal()), \
                 patch.object(harp, "model_context_tokens", return_value=8192), \
                 patch.object(harp, "count_chat_tokens", return_value=300), \
                 patch.object(harp, "api_chat", side_effect=fake_chat):
                harp.delegate(path, "Inspect the service", 1, quiet=True)
            saved = harp.load_session(path)
            self.assertEqual(len(prompts), 3)
            self.assertTrue(all(harp.ENGLISH_ONLY in prompt for prompt in prompts))
            self.assertIn("FORMAT RETRY", prompts[1])
            self.assertEqual(saved["last_delegate_stop"], "local_done")
            self.assertEqual(saved["local_steps"], 0)

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
