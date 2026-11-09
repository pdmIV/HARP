"""Separate installed resources from writable operator data."""
import os
from pathlib import Path


SOURCE = Path(__file__).resolve().parent


def source_checkout():
    return (SOURCE / "pyproject.toml").is_file() and (SOURCE / "harp.py").is_file()


def assets_dir():
    if source_checkout():
        return SOURCE
    return SOURCE / "harp_data"


def data_dir():
    override = os.environ.get("HARP_HOME")
    if override:
        return Path(override).expanduser().resolve()
    # Keep existing checkout sessions/configuration in place.
    if source_checkout():
        return SOURCE
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "harp-ai"


def ensure_data_dir():
    path = data_dir()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path
