import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_dependencies
import harp_secret
import harp_web
from scripts import install_dependencies as installer


class NativeTests(unittest.TestCase):
    def test_native_config_and_dispatch(self):
        cfg = json.loads(Path("harp.native.example.json").read_text())
        cfg["target"] = "192.0.2.10"
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(cfg))
            self.assertEqual(harp.load_config(path)["runtime"], "native")
            cfg["network_policy"] = "internal_lab"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "Native Kali"):
                harp.load_config(path)
        self.assertIs(harp.runtime_class("native"), harp.NativeTerminal)
        with self.assertRaises(ValueError):
            harp.runtime_class("unknown")
        with patch.object(harp, "docker") as docker:
            harp_web.prepare_runtime({"runtime": "native"})
        docker.assert_not_called()

    def test_native_transport_and_root_are_explicit(self):
        with patch.object(sys, "platform", "linux"), patch.object(os, "geteuid", return_value=1000, create=True):
            terminal = harp.NativeTerminal({})
            argv = terminal.command_argv("printf synthetic", 5, False)
            self.assertEqual(argv[:5], ["timeout", "-s", "KILL", "5s", "/bin/sh"])
            self.assertIn("cd ", argv[-1])
            self.assertEqual(terminal.command_argv("id", 5, True)[:3], ["sudo", "-n", "--"])
            self.assertEqual(terminal.batch_argv("pass", ["fixture"]), ["python3", "-c", "pass", "fixture"])
            self.assertEqual(terminal.file_argv("pass", "fixture"), ["python3", "-c", "pass", "fixture"])
        with patch.object(sys, "platform", "win32"), self.assertRaisesRegex(RuntimeError, "Linux"):
            terminal._base()
        with patch.object(sys, "platform", "linux"), patch.object(os, "geteuid", return_value=0, create=True), self.assertRaisesRegex(RuntimeError, "nonroot"):
            terminal._base()

    def test_native_lifecycle_reattaches_without_container_and_preserves_workspace(self):
        import subprocess
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(Path, "home", return_value=Path(temp)), \
             patch.object(sys, "platform", "linux"), \
             patch.object(os, "geteuid", return_value=1000, create=True), \
             patch.object(harp.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as probe, \
             patch.object(harp, "docker") as docker:
            terminal = harp.NativeTerminal({})
            terminal.__enter__()
            self.assertTrue(Path(terminal.workspace).is_dir())
            restored = harp.terminal_for({"status": "active", "runtime": "native", "config": {}, "container": terminal.name})
            self.assertEqual(restored.workspace, terminal.workspace)
            terminal.__exit__(None, None, None)
            self.assertTrue(Path(terminal.workspace).is_dir())
            self.assertNotIn("wsl.exe", probe.call_args.args[0])
            docker.assert_not_called()

    def test_native_installer_keeps_pipx_nonroot_and_checks_offline(self):
        with patch.object(sys, "platform", "linux"), patch.object(os, "geteuid", return_value=1000, create=True):
            stages = installer.plan(installer.parser().parse_args(["--runtime", "native"]))
            self.assertEqual(stages[0][0][:3], ["sudo", "-n", "--"])
            self.assertIn("--apt-only", stages[0][0])
            self.assertEqual(stages[1][0][0], "bash")
            self.assertIn("--python-only", stages[1][0])
            check = installer.plan(installer.parser().parse_args(["--runtime", "native", "--check"]))
            self.assertEqual(check, [(["bash", "-s", "--", "--check"], True)])
            self.assertEqual(harp_dependencies.options({"runtime": "native"}), ["--runtime", "native"])

    def test_fresh_dashboard_uses_platform_default_without_changing_saved_config(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            config = Path(temp) / "harp.json"
            with patch.object(harp_web, "CONFIG", config):
                expected = "wsl" if os.name == "nt" else "native"
                self.assertEqual(harp_web.draft_config()["runtime"], expected)
                config.write_text('{"runtime":"docker"}')
                self.assertEqual(harp_web.draft_config()["runtime"], "docker")

    @unittest.skipUnless(sys.platform == "linux", "Linux transport integration")
    def test_real_native_command_file_and_batch_transport(self):
        if os.geteuid() == 0:
            self.skipTest("Native runtime intentionally refuses root")
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(Path, "home", return_value=Path(temp)):
            terminal = harp.NativeTerminal({})
            Path(terminal.workspace).mkdir(parents=True)
            terminal.print_stdout = False
            result = terminal.run("printf synthetic-native-evidence", 3)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["output"], "synthetic-native-evidence")
            attached = harp.NativeTerminal.attach({}, terminal.name)
            self.assertEqual(attached.workspace, terminal.workspace)
            import subprocess
            result = subprocess.run(terminal.batch_argv("print('batch-ok')", []), capture_output=True, text=True)
            self.assertEqual(result.stdout.strip(), "batch-ok")

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_posix_keys_round_trip_and_reject_open_permissions(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / ".secrets" / "test.key"
            harp_secret.save_key(path, "synthetic-test-key")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(harp_secret.load_key(path), "synthetic-test-key")
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "mode 600"):
                harp_secret.load_key(path)


if __name__ == "__main__":
    unittest.main()
