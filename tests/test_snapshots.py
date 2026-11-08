import copy
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import harp_snapshots as snapshots
import harp_web


class SnapshotTests(unittest.TestCase):
    def config(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg.update(authorized_scope=["192.0.2.0/24"], max_model_calls=17)
        cfg["oracle"].update(web_search_enabled=True)
        cfg["studio"] = {"model": "example/model", "port": 8888, "context": 32768,
                         "cache_k": "q8_0", "cache_v": "bf16", "parallel": 2}
        return cfg

    def test_round_trip_replaces_complete_settings_and_creates_recovery(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            original = self.config()
            path.write_text(json.dumps(original))
            ui = {**snapshots.UI_DEFAULTS, "theme": "amoled", "mode": "frontier-only", "replay_speed": "8"}
            backup = snapshots.export(path, original, ui)
            self.assertNotIn("keys", backup)
            self.assertEqual(backup["config"], original)
            changed = copy.deepcopy(original)
            changed.update(max_steps=50, max_model_calls=30, objective="Changed objective")
            changed["extra_setting"] = "must disappear when restoring older backup"
            path.write_text(json.dumps(changed))
            result = snapshots.apply(path, backup, changed, snapshots.UI_DEFAULTS)
            saved = json.loads(path.read_text())
            self.assertEqual(saved["max_steps"], original["max_steps"])
            self.assertEqual(saved["max_model_calls"], 17)
            self.assertEqual(saved["authorized_scope"], ["192.0.2.0/24"])
            self.assertEqual(saved["studio"], original["studio"])
            self.assertTrue(saved["oracle"]["web_search_enabled"])
            self.assertNotIn("extra_setting", saved)
            self.assertEqual(saved["ui"], ui)
            recovery = snapshots.recovery(path, result["recovery_id"])
            self.assertEqual(recovery["config"], changed)
            self.assertEqual(recovery["ui"], snapshots.UI_DEFAULTS)

    def test_invalid_files_never_change_configuration(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            cfg = self.config()
            path.write_text(json.dumps(cfg))
            before = path.read_bytes()
            valid = snapshots.export(path, cfg, {})
            variants = [None, {}, {**valid, "version": 2}, {**valid, "version": True},
                        {**valid, "ui": {"theme": "unknown"}}, {**valid, "keys": {"unknown": "key"}},
                        {**valid, "keys": {"zai": "has whitespace"}}, {**valid, "created_at": "invalid"},
                        {**valid, "config": {**cfg, "max_steps": 0}},
                        {**valid, "config": {**cfg, "objective": "x" * 50000}},
                        {**valid, "config": {**cfg, "max_steps": float("nan")}}]
            for variant in variants:
                with self.subTest(variant=str(variant)[:40]), self.assertRaises(ValueError):
                    snapshots.apply(path, variant, cfg, {})
                self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(temp).glob("snapshot-validation-*")), [])

    def test_saved_keys_are_optional_environment_and_control_tokens_are_excluded(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            cfg = self.config()
            secret_dir = Path(temp) / ".secrets"
            secret_dir.mkdir()
            (secret_dir / "zai.key").write_bytes(b"opaque")
            with patch.dict(os.environ, {"ZAI_API_KEY": "environment-test-key"}), patch.object(snapshots.harp_secret, "load_key", return_value="saved-test-key") as load:
                backup = snapshots.export(path, cfg, {}, False)
                load.assert_not_called()
                self.assertNotIn("environment-test-key", json.dumps(backup))
                self.assertNotIn("keys", backup)
                backup = snapshots.export(path, cfg, {}, True)
            self.assertEqual(backup["keys"], {"zai": "saved-test-key"})
            preview = snapshots.preview(backup, path)
            self.assertEqual(preview["included_key_providers"], ["zai"])
            self.assertNotIn("saved-test-key", json.dumps(preview))
            with patch.object(snapshots.harp_secret, "save_key") as save:
                snapshots.apply(path, backup, cfg, {}, restore_keys=False)
            save.assert_not_called()
            self.assertEqual((secret_dir / "zai.key").read_bytes(), b"opaque")

    def test_key_restore_uses_platform_store_and_rolls_back_on_partial_failure(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            cfg = self.config()
            path.write_text(json.dumps(cfg))
            before = path.read_bytes()
            secret_dir = Path(temp) / ".secrets"
            secret_dir.mkdir()
            for provider in ("openai", "zai"):
                (secret_dir / snapshots.KEY_FILES[provider]).write_bytes(b"previous-opaque-key")
            backup = snapshots.export(path, cfg, {})
            backup["keys"] = {"openai": "new-openai-key", "zai": "new-zai-key"}
            calls = []
            def save(staged, key):
                calls.append(key)
                if len(calls) == 2:
                    raise OSError("Simulated secret-storage failure")
                staged.write_bytes(b"new-encoded-key")
            with patch.object(snapshots.harp_secret, "load_key", return_value="previous-key"), patch.object(snapshots.harp_secret, "save_key", side_effect=save):
                with self.assertRaisesRegex(RuntimeError, "previous settings were restored"):
                    snapshots.apply(path, backup, cfg, {}, restore_keys=True)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual((secret_dir / "openai.key").read_bytes(), b"previous-opaque-key")
            self.assertEqual((secret_dir / "zai.key").read_bytes(), b"previous-opaque-key")
            self.assertEqual(list(secret_dir.glob("restore-*")), [])
            self.assertEqual(len(list((Path(temp) / ".settings_backups").glob("*.json"))), 1)

    def test_unselected_target_is_valid_and_recovery_id_cannot_escape_directory(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            cfg = self.config()
            cfg["target"] = ""
            self.assertEqual(snapshots.export(path, cfg, {})["config"]["target"], "")
            for identifier in ("../harp", "a" * 32 + "/other", None):
                with self.assertRaises(ValueError):
                    snapshots.recovery(path, identifier)

    def test_successful_key_restore_writes_encoded_key_and_keeps_unlisted_providers(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            cfg = self.config()
            folder = Path(temp) / ".secrets"
            folder.mkdir()
            (folder / "zai.key").write_bytes(b"previous-zai")
            (folder / "openai.key").write_bytes(b"preserved-openai")
            backup = snapshots.export(path, cfg, {})
            backup["keys"] = {"zai": "synthetic-new-key"}
            def save(staged, key):
                self.assertEqual(key, "synthetic-new-key")
                staged.write_bytes(b"encoded-platform-key")
            with patch.object(snapshots.harp_secret, "load_key", return_value="synthetic-previous-key"), patch.object(snapshots.harp_secret, "save_key", side_effect=save) as store:
                result = snapshots.apply(path, backup, cfg, {}, restore_keys=True)
            store.assert_called_once()
            self.assertEqual((folder / "zai.key").read_bytes(), b"encoded-platform-key")
            self.assertEqual((folder / "openai.key").read_bytes(), b"preserved-openai")
            recovery = snapshots.recovery(path, result["recovery_id"])
            self.assertIn("zai", recovery["keys"])

    def test_restore_api_refuses_active_session_before_any_mutation(self):
        handler = object.__new__(harp_web.HARPRequestHandler)
        handler.path = "/api/settings/apply"
        handler._authorized = Mock(return_value=True)
        handler._body = Mock(return_value={"snapshot": {}})
        handler._json = Mock()
        state = SimpleNamespace(lock=threading.RLock(), starting_session=False, session_jobs=set(),
                                dependencies=SimpleNamespace(installing=False), model_process=None,
                                session_list=lambda: [{"status": "active"}])
        handler.server = SimpleNamespace(state=state)
        with patch.object(snapshots, "apply") as apply:
            handler.do_POST()
        apply.assert_not_called()
        self.assertEqual(handler._json.call_args.args[0], 400)
        self.assertIn("Stop active sessions", handler._json.call_args.args[1]["error"])

    @unittest.skipUnless(os.name == "posix", "POSIX file permissions")
    def test_recovery_files_have_owner_only_permissions(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            cfg = self.config()
            backup = snapshots.export(path, cfg, {})
            result = snapshots.apply(path, backup, cfg, {})
            recovery = Path(temp) / ".settings_backups" / (result["recovery_id"] + ".json")
            self.assertEqual(recovery.stat().st_mode & 0o777, 0o600)
            self.assertEqual(recovery.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
