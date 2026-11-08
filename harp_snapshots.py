"""Portable, versioned application settings backups and transactional restore."""
import copy
from datetime import datetime
import json
import os
from pathlib import Path
import re
import uuid

import harp
import harp_secret

FORMAT = "harp-settings"
VERSION = 1
MAX_BYTES = 48 * 1024
KEY_FILES = {"openai": "openai.key", "zai": "zai.key", "nvidia_nim": "nvidia.key", "unsloth": "unsloth.key"}
UI_DEFAULTS = {"theme": "light", "mode": "hybrid", "replay_speed": "1", "replay_skip_idle": True,
               "fresh_recon": False, "api_key_provider": "openai"}


def ui_settings(value):
    if not isinstance(value, dict) or set(value) - set(UI_DEFAULTS):
        raise ValueError("Invalid interface settings")
    result = {**UI_DEFAULTS, **value}
    for name, choices in {"theme": ("light", "dark", "amoled"), "mode": ("hybrid", "local-only", "frontier-only"),
                          "replay_speed": ("1", "2", "4", "8", "16", "32"), "api_key_provider": tuple(KEY_FILES)}.items():
        if result[name] not in choices:
            raise ValueError("Invalid interface setting: " + name)
    if any(type(result[k]) is not bool for k in ("replay_skip_idle", "fresh_recon")):
        raise ValueError("Interface checkbox settings must be booleans")
    return result


def encode(value):
    try:
        raw = json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ValueError("Snapshot must contain ordinary finite JSON values") from None
    if len(raw) > MAX_BYTES:
        raise ValueError("Settings snapshot exceeds 48 KiB")
    return raw


def write_private(path, data):
    """Atomic file replacement, with owner-only file permissions on Linux."""
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def validate(snapshot, config_path):
    encode(snapshot)
    if (not isinstance(snapshot, dict) or set(snapshot) - {"format", "version", "created_at", "config", "ui", "keys"}
            or snapshot.get("format") != FORMAT or type(snapshot.get("version")) is not int or snapshot["version"] != VERSION):
        raise ValueError("Choose a supported HARP settings snapshot (version 1)")
    if not isinstance(snapshot.get("created_at"), str):
        raise ValueError("Snapshot creation timestamp is missing")
    try:
        datetime.fromisoformat(snapshot["created_at"])
    except ValueError:
        raise ValueError("Invalid snapshot creation timestamp") from None
    cfg = copy.deepcopy(snapshot.get("config"))
    if (not isinstance(cfg, dict) or not isinstance(cfg.get("local"), dict)
            or not isinstance(cfg.get("oracle", {}), dict) or not isinstance(cfg.get("studio", {}), dict)):
        raise ValueError("Snapshot configuration must contain valid model settings")
    ui = ui_settings(snapshot.get("ui"))
    keys = snapshot.get("keys", {})
    if not isinstance(keys, dict) or set(keys) - set(KEY_FILES):
        raise ValueError("Snapshot contains an unknown API key provider")
    for value in keys.values():
        if not isinstance(value, str) or not 1 <= len(value) <= 4096 or any(not 33 <= ord(c) <= 126 for c in value):
            raise ValueError("Snapshot contains an invalid API key")
    # Validate using the regular configuration rules, allowing a not-yet-selected target.
    candidate = copy.deepcopy(cfg)
    if candidate.get("target") == "":
        candidate["target"] = "10.10.10.10"
    temporary = config_path.with_name("snapshot-validation-" + uuid.uuid4().hex + ".json")
    try:
        write_private(temporary, json.dumps(candidate, allow_nan=False).encode())
        harp.load_config(temporary)
        if cfg.get("studio"):
            import harp_web
            studio = {**harp_web.studio_settings(cfg), **cfg["studio"]}
            if not studio.get("model"):
                studio["model"] = "snapshot-validation"
            harp_web.build_launch_args(studio)
    except (KeyError, TypeError, OverflowError) as error:
        raise ValueError("Snapshot configuration is incomplete or has invalid field types") from error
    finally:
        temporary.unlink(missing_ok=True)
    return cfg, ui, keys


def export(config_path, cfg, ui, include_keys=False):
    if type(include_keys) is not bool:
        raise ValueError("Include API keys must be a boolean")
    config = copy.deepcopy(cfg)
    config.pop("ui", None)
    result = {"format": FORMAT, "version": VERSION, "created_at": harp.now(), "config": config, "ui": ui_settings(ui)}
    if include_keys:
        result["keys"] = {provider: harp_secret.load_key(config_path.parent / ".secrets" / filename)
                          for provider, filename in KEY_FILES.items() if (config_path.parent / ".secrets" / filename).is_file()}
    validate(result, config_path)
    return result


def preview(snapshot, config_path):
    cfg, ui, keys = validate(snapshot, config_path)
    return {"created_at": snapshot["created_at"], "target": cfg.get("target", ""),
            "runtime": cfg.get("runtime", "docker"), "proxy": {k: cfg["local"].get(k) for k in ("provider", "model")},
            "oracle": {k: cfg.get("oracle", {}).get(k) for k in ("provider", "model", "adaptive_reasoning", "web_search_enabled")},
            "ui": ui, "included_key_providers": sorted(keys)}


def apply(config_path, snapshot, current, current_ui, restore_keys=False):
    if type(restore_keys) is not bool:
        raise ValueError("Restore API keys must be a boolean")
    cfg, ui, keys = validate(snapshot, config_path)
    selected_keys = keys if restore_keys else {}
    recovery = export(config_path, current, current_ui, include_keys=bool(selected_keys))
    folder = config_path.parent / ".settings_backups"
    folder.mkdir(mode=0o700, exist_ok=True)
    if os.name != "nt":
        folder.chmod(0o700)
    recovery_id = uuid.uuid4().hex
    write_private(folder / (recovery_id + ".json"), encode(recovery))
    cfg["ui"] = ui
    new_config = json.dumps(cfg, indent=2, allow_nan=False).encode("utf-8")
    old_config = config_path.read_bytes() if config_path.exists() else None
    secrets_dir = config_path.parent / ".secrets"
    previous = {}
    if selected_keys:
        secrets_dir.mkdir(mode=0o700, exist_ok=True)
        previous = {provider: (secrets_dir / KEY_FILES[provider]).read_bytes() if (secrets_dir / KEY_FILES[provider]).exists() else None
                    for provider in selected_keys}
    changed = []
    try:
        for provider, key in selected_keys.items():
            # Encode through the normal platform-specific secret storage before replacing originals.
            destination = secrets_dir / KEY_FILES[provider]
            staged = secrets_dir / ("restore-" + uuid.uuid4().hex + ".key")
            try:
                harp_secret.save_key(staged, key)
                staged.replace(destination)
                changed.append(provider)
            finally:
                staged.unlink(missing_ok=True)
        write_private(config_path, new_config)
    except Exception as error:
        try:
            for provider in changed:
                path = secrets_dir / KEY_FILES[provider]
                if previous[provider] is None:
                    path.unlink(missing_ok=True)
                else:
                    write_private(path, previous[provider])
            if old_config is None:
                config_path.unlink(missing_ok=True)
            else:
                write_private(config_path, old_config)
        except Exception:
            raise RuntimeError("Restore failed and rollback could not finish; use the saved recovery snapshot") from None
        raise RuntimeError("Settings restore failed; previous settings were restored") from error
    return {"config": cfg, "ui": ui, "recovery_id": recovery_id,
            "message": "Settings restored. No model or session was started."}


def recovery(config_path, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("Invalid recovery snapshot ID")
    return json.loads((config_path.parent / ".settings_backups" / (identifier + ".json")).read_text(encoding="utf-8"))
