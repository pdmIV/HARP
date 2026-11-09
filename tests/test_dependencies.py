import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import install_dependencies as installer


class DependencyTests(unittest.TestCase):
    def args(self, *args):
        return installer.parser().parse_args(args)

    def test_wsl_uses_explicit_distro_root_apt_and_selected_python_user(self):
        stages = installer.plan(self.args("--runtime", "wsl", "--distro", "my-kali", "--user", "peter"))
        self.assertEqual(len(stages), 2)
        root, user = [stage[0] for stage in stages]
        self.assertEqual(root[:6], ["wsl.exe", "--distribution", "my-kali", "--user", "root", "--exec"])
        self.assertEqual(user[:6], ["wsl.exe", "--distribution", "my-kali", "--user", "peter", "--exec"])
        self.assertIn("--apt-only", root)
        self.assertIn("--python-only", user)
        self.assertTrue(all(stage[1] for stage in stages))

    def test_wsl_check_never_installs_or_runs_as_root(self):
        stages = installer.plan(self.args("--runtime", "wsl", "--distro", "my-kali", "--user", "peter", "--check"))
        self.assertEqual(len(stages), 1)
        self.assertIn("--check", stages[0][0])
        self.assertNotIn("root", stages[0][0])

    def test_native_dashboard_uses_system_auth_only_for_apt(self):
        with patch.object(installer.sys, "platform", "linux"), patch.object(installer.os, "geteuid", return_value=1000, create=True):
            apt, python = installer.plan(self.args("--runtime", "native", "--native-auth", "polkit"))
            self.assertEqual(apt, (["pkexec", "--disable-internal-agent", "/usr/bin/bash",
                                    str(installer.SCRIPT), "--apt-only"], False))
            self.assertEqual(python[0][:2], ["bash", "-s"])
            self.assertIn("--python-only", python[0])
            self.assertTrue(python[1])
            terminal = installer.plan(self.args("--runtime", "native"))
            self.assertEqual(terminal[0][0][:3], ["sudo", "-n", "--"])
            self.assertEqual(installer.plan(self.args("--runtime", "native", "--native-auth", "polkit", "--check")),
                             [(["bash", "-s", "--", "--check"], True)])

    def test_refuses_implicit_users_invalid_refs_and_cross_runtime_options(self):
        for args in [("--runtime", "wsl"),
                     ("--runtime", "wsl", "--distro", "kali", "--user", "root"),
                     ("--runtime", "docker", "--whippet-ref", "main;echo bad"),
                     ("--runtime", "docker", "--distro", "kali"),
                     ("--runtime", "wsl", "--distro", "kali", "--user", "peter", "--native-auth", "polkit")]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                installer.plan(self.args(*args))

    def test_docker_build_includes_ref_then_verifies_nonroot_offline(self):
        build, check = installer.plan(self.args("--runtime", "docker", "--whippet-ref", "abc123"))
        self.assertIn("WHIPPET_REF=abc123", build[0])
        self.assertIn("--no-cache", build[0])
        self.assertEqual(check[0][:7], ["docker", "run", "--rm", "--network", "none", "--pull=never", "harp-kali:latest"])
        self.assertNotIn("--user", check[0])  # Preserve Dockerfile's nonroot default.
        self.assertIn("--check", check[0])
        only = installer.plan(self.args("--runtime", "docker", "--check"))
        self.assertEqual(only, [check])

    def test_wrapper_streams_normalized_script_and_stops_on_stage_failure(self):
        with patch.object(installer.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "apt")) as run, \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            installer.main(["--runtime", "wsl", "--distro", "kali", "--user", "peter"])
        self.assertEqual(run.call_count, 1)
        self.assertIsInstance(run.call_args.kwargs["input"], bytes)
        self.assertNotIn(b"\r\n", run.call_args.kwargs["input"])
        self.assertTrue(run.call_args.kwargs["check"])

    def test_system_auth_failure_gives_terminal_fallback_without_running_pipx(self):
        with patch.object(installer.sys, "platform", "linux"), \
             patch.object(installer.os, "geteuid", return_value=1000, create=True), \
             patch.object(installer.subprocess, "run", side_effect=subprocess.CalledProcessError(126, "pkexec")) as run, \
             contextlib.redirect_stdout(io.StringIO()), \
             self.assertRaisesRegex(RuntimeError, "sudo -v"):
            installer.main(["--runtime", "native", "--native-auth", "polkit"])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][0], "pkexec")

    def smoke_code(self):
        source = installer.SCRIPT.read_text()
        return source.split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]

    def test_offline_smoke_checks_protocol_ranked_paths_and_collectors(self):
        code = self.smoke_code()
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if "--batch-ready" in argv:
                stdout = json.dumps({"event": "ready", "schema_version": 1, "protocol_version": 1,
                                     "session_id": "test", "whippet_version": "0.7.0"}) + "\n"
                stdout += json.dumps({"id": "harp-dependency-check", "batch": {"session_id": "test"},
                                      "result": {"status": "ready"}})
            elif "--k-shortest" in argv:
                stdout = json.dumps({"result": {"backend": "NetworkX shortest_simple_paths"}})
            else:
                stdout = "help"
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        original_temp = tempfile.TemporaryDirectory
        with patch("shutil.which", side_effect=lambda name: "/usr/bin/" + name), \
             patch("subprocess.run", side_effect=run), \
             patch("tempfile.TemporaryDirectory", side_effect=lambda **kw: original_temp(dir=Path.cwd(), **kw)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            exec(compile(code, "installer-smoke", "exec"), {})
        self.assertIn("batch and NetworkX checks passed", output.getvalue())
        self.assertTrue(any(x[0][0] == "bloodhound-ce-python" for x in calls))
        self.assertTrue(any(x[0][0] == "certipy-ad" for x in calls))
        self.assertTrue(all(x[1]["timeout"] == 30 for x in calls))

    def test_missing_tools_fail_instead_of_reporting_success(self):
        with patch("shutil.which", return_value=None), self.assertRaisesRegex(SystemExit, "Missing tools"):
            exec(compile(self.smoke_code(), "installer-smoke", "exec"), {})


if __name__ == "__main__":
    unittest.main()
