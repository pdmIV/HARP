import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_cli
import harp_paths
import harp_nim
import harp_openai
import harp_zai
import harp_dependencies
from scripts import install_dependencies


class PackagingTests(unittest.TestCase):
    def test_checkout_preserves_existing_data_and_resources(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(harp_paths.data_dir(), harp_paths.SOURCE)
            self.assertEqual(harp_paths.assets_dir(), harp_paths.SOURCE)

    def test_installed_data_lives_outside_package_and_home_override_wins(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
                patch.object(harp_paths, "source_checkout", return_value=False), \
                patch.dict(os.environ, {"HARP_HOME": str(Path(temp) / "operator-data")}):
            home = harp_paths.ensure_data_dir()
            self.assertEqual(home, Path(temp) / "operator-data")
            self.assertNotEqual(home, harp_paths.assets_dir())
            self.assertTrue(home.is_dir())
        with patch.object(harp_paths, "source_checkout", return_value=False), \
                patch.dict(os.environ, {}, clear=True), \
                patch.object(Path, "home", return_value=harp_paths.SOURCE / "synthetic-user"):
            self.assertEqual(harp_paths.data_dir().name, "harp-ai")
            self.assertNotEqual(harp_paths.data_dir(), harp_paths.SOURCE)

    def test_all_providers_read_the_selected_data_directory(self):
        # Avoid reading the developer's real stored credentials in this test.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
                patch.dict(os.environ, {"HARP_HOME": temp, "NVIDIA_API_KEY": "",
                                       "OPENAI_API_KEY": "", "ZAI_API_KEY": "", "UNSLOTH_API_KEY": ""}):
            keys = Path(temp) / ".secrets"
            keys.mkdir()
            for provider, filename in ((harp_nim, "nvidia.key"), (harp_openai, "openai.key"),
                                       (harp_zai, "zai.key")):
                (keys / filename).touch()
                with patch.object(provider.harp_secret, "load_key", return_value="synthetic") as load:
                    self.assertEqual(provider.key(), "synthetic")
                    load.assert_called_once_with(keys / filename)
            (keys / "unsloth.key").touch()
            with patch.object(harp.harp_secret, "load_key", return_value="synthetic") as load:
                self.assertEqual(harp.local_api_key({"api_key_env": "UNSLOTH_API_KEY"}), "synthetic")
                load.assert_called_once_with(keys / "unsloth.key")

    def test_dependency_arguments_reach_existing_installer_in_order(self):
        options = ["--runtime", "wsl", "--distro", "chosen-kali", "--user", "labuser", "--check"]
        with patch.object(install_dependencies, "main") as install:
            self.assertEqual(harp_cli.main(["deps", *options]), 0)
            install.assert_called_once_with(options)

    def test_installed_dependency_hint_uses_pipx_executable(self):
        with patch.object(harp_paths, "source_checkout", return_value=False):
            status = harp_dependencies.DependencyManager(Path.cwd()).base({"runtime": "wsl",
                            "wsl_distro": "chosen-kali", "wsl_user": "labuser"})
            self.assertTrue(status["command"].startswith("harp-ai deps --runtime wsl"))

    def test_cli_launches_dashboard_by_default_and_selects_home_before_import(self):
        import harp_web
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
                patch.dict(os.environ), patch.object(harp_web, "main") as launch:
            self.assertEqual(harp_cli.main(["--home", temp, "--no-browser", "--port", "9876"]), 0)
            self.assertEqual(os.environ["HARP_HOME"], str(Path(temp).resolve()))
            launch.assert_called_once_with(["--port", "9876", "--no-browser"])

    def test_headless_cli_uses_the_same_data_directory(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
                patch.dict(os.environ, {"HARP_HOME": temp}), \
                patch.object(harp, "load_config", side_effect=ValueError("synthetic")) as load, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(harp_cli.main(["cli", "doctor"]), 1)
            load.assert_called_once_with(Path(temp) / "harp.json")


if __name__ == "__main__":
    unittest.main()
