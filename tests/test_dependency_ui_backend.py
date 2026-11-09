import io
import contextlib
import json
from pathlib import Path
import subprocess
import time
import tempfile
import unittest
from unittest.mock import patch

import harp_dependencies as dependencies


class DependencyBackendTests(unittest.TestCase):
    def setUp(self):
        self.manager = dependencies.DependencyManager(Path.cwd())
        self.cfg = {"runtime": "wsl", "wsl_distro": "chosen-kali", "wsl_user": "labuser"}
        self.base = self.manager.base(self.cfg)

    def test_offline_check_uses_exact_runtime_and_caches_missing_tools(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({"issues": ["Missing tools: whippet"], "missing": ["whippet"]}), "")
        with patch.object(dependencies.subprocess, "run", return_value=result) as run:
            self.manager._check(self.cfg, self.base)
        self.assertEqual(run.call_args.args[0][:6], ["wsl.exe", "--distribution", "chosen-kali", "--user", "labuser", "--exec"])
        self.assertIn("timeout 20s", run.call_args.args[0][-1])
        with patch.object(dependencies.threading, "Thread") as thread:
            state = self.manager.status(self.cfg)
            self.assertEqual(state["status"], "warning")
            self.assertIn("whippet", state["issues"][0])
            thread.assert_not_called()

    def test_missing_runtime_is_warning_not_ready(self):
        with patch.object(dependencies.subprocess, "run", side_effect=FileNotFoundError("wsl.exe")):
            self.manager._check(self.cfg, self.base)
        self.assertEqual(self.manager.status(self.cfg)["status"], "warning")

    def test_docker_check_is_non_networked_and_cannot_pull_images(self):
        cfg = {"runtime": "docker"}
        with patch.object(dependencies.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, '{"issues":[]}', "")) as run:
            self.manager._check(cfg, self.manager.base(cfg))
        argv = run.call_args.args[0]
        self.assertIn("--pull=never", argv)
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(self.manager.status(cfg)["status"], "ready")

    def test_install_rejects_changed_runtime_and_duplicate_install(self):
        with self.assertRaisesRegex(ValueError, "changed"):
            self.manager.install(self.cfg, "another-runtime")
        with patch.object(dependencies.threading, "Thread") as thread:
            self.manager.install(self.cfg, self.base["key"])
            self.assertTrue(self.manager.installing)
            self.assertEqual(self.manager.status(self.cfg)["status"], "installing")
            with self.assertRaisesRegex(ValueError, "Wait"):
                self.manager.install(self.cfg, self.base["key"])
            self.assertEqual(thread.call_count, 1)

    def test_install_success_is_green_ready_only_after_checks_exit_successfully(self):
        with patch.object(dependencies.threading, "Thread"):
            self.manager.install(self.cfg, self.base["key"])
        process = type("Process", (), {"stdout": io.StringIO("Installing Whippet\nChecks passed\n"), "wait": lambda self: 0})()
        with patch.object(dependencies.subprocess, "Popen", return_value=process) as popen:
            self.manager._install(self.cfg, self.base)
        args = popen.call_args.args[0]
        self.assertEqual(args[-6:], ["--runtime", "wsl", "--distro", "chosen-kali", "--user", "labuser"])
        state = self.manager.status(self.cfg)
        self.assertEqual(state["status"], "ready")
        self.assertIn("installed and verified", state["installation"]["message"])
        self.assertEqual(state["installation"]["logs"][-1], "Checks passed")

    def test_native_dashboard_requests_polkit_auth_and_shows_terminal_fallback(self):
        cfg = {"runtime": "native"}
        base = self.manager.base(cfg)
        self.assertIn("sudo -v && python3", base["command"])
        with patch.object(dependencies.threading, "Thread"):
            self.manager.install(cfg, base["key"])
        process = type("Process", (), {"stdout": io.StringIO("Checks passed\n"), "wait": lambda self: 0})()
        with patch.object(dependencies.subprocess, "Popen", return_value=process) as popen:
            self.manager._install(cfg, base)
        self.assertEqual(popen.call_args.args[0][-2:], ["--native-auth", "polkit"])

    def test_failed_install_keeps_warning_with_output(self):
        with patch.object(dependencies.threading, "Thread"):
            self.manager.install(self.cfg, self.base["key"])
        process = type("Process", (), {"stdout": io.StringIO("Repository unavailable\n"), "wait": lambda self: 1})()
        with patch.object(dependencies.subprocess, "Popen", return_value=process):
            self.manager._install(self.cfg, self.base)
        state = self.manager.status(self.cfg)
        self.assertEqual(state["status"], "warning")
        self.assertIn("Repository unavailable", state["installation"]["logs"])

    def test_checks_are_deduplicated_and_invalid_user_cannot_install(self):
        with patch.object(dependencies.threading, "Thread") as thread:
            self.manager.status(self.cfg)
            self.manager.status(self.cfg)
            self.assertEqual(thread.call_count, 1)
        with self.assertRaises(ValueError):
            self.manager.install({**self.cfg, "wsl_user": "root"}, "")

    def probe_with_kali_names(self, enum_ng=True):
        absent = {"bloodhound-ce-python", "certipy"}
        if not enum_ng:
            absent.add("enum4linux-ng")

        def run(argv, **kwargs):
            if "--batch-ready" in argv:
                text = json.dumps({"event": "ready", "protocol_version": 1, "schema_version": 1, "session_id": "test"}) + "\n"
                text += json.dumps({"id": "check", "batch": {"session_id": "test"}, "result": {"status": "ready"}})
            else:
                text = json.dumps({"result": {"backend": "NetworkX shortest_simple_paths"}})
            return subprocess.CompletedProcess(argv, 0, text, "")

        original = tempfile.TemporaryDirectory
        with patch("shutil.which", side_effect=lambda name: None if name in absent else "/usr/bin/" + name), \
             patch("subprocess.run", side_effect=run), \
             patch("tempfile.TemporaryDirectory", side_effect=lambda **kw: original(dir=Path.cwd(), **kw)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            exec(compile(dependencies.PROBE, "dependency-probe", "exec"), {})
        return json.loads(output.getvalue())

    def test_kali_legacy_collector_and_certipy_ad_do_not_trigger_false_warning(self):
        report = self.probe_with_kali_names()
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["tools"]["bloodhound_collector"], "bloodhound-python")
        self.assertEqual(report["tools"]["certipy"], "certipy-ad")

    def test_enum4linux_is_identified_without_pretending_it_is_ng(self):
        report = self.probe_with_kali_names(enum_ng=False)
        self.assertEqual(report["tools"]["smb_enumerator"], "enum4linux")
        self.assertIn("enum4linux-ng", report["missing"])
        self.assertNotIn("bloodhound-ce-python", report["missing"])


if __name__ == "__main__":
    unittest.main()
