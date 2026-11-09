"""Portable, bounded archives for completed HARP sessions."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import uuid
import zipfile

import harp_version


FORMAT_VERSION = 1
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_FILES = 10000


def _reserved_windows_name(part: str) -> bool:
    return bool(re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$",
                             part.split(".", 1)[0], flags=re.IGNORECASE))


def export_session(run_dir: Path, destination: Path) -> None:
    session = json.loads((run_dir / "session.json").read_text(encoding="utf-8"))
    if session.get("status") != "finished":
        raise ValueError("Finish the session before exporting a complete archive")
    files = sorted(path for path in run_dir.rglob("*") if path.is_file() or path.is_symlink())
    if len(files) > MAX_FILES:
        raise ValueError("Session contains too many files to export")
    total = 0
    for path in files:
        if path.is_symlink():
            raise ValueError("Session contains a symbolic link; archive export is unavailable")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise ValueError("A session file exceeds the archive limit")
        total += size
    if total > MAX_EXTRACTED_BYTES:
        raise ValueError("Session exceeds the archive limit")
    manifest = {"format": "harp-session", "format_version": FORMAT_VERSION,
                "harp_version": harp_version.VERSION, "source_session": run_dir.name,
                "exported_at": datetime.now(timezone.utc).isoformat()}
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("harp-session.json", json.dumps(manifest))
        for path in files:
            archive.write(path, "session/" + path.relative_to(run_dir).as_posix())
    if destination.stat().st_size > MAX_ARCHIVE_BYTES:
        destination.unlink(missing_ok=True)
        raise ValueError("Compressed session exceeds the archive limit")


def import_session(archive_path: Path, runs_dir: Path) -> Path:
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Session archive exceeds 512 MiB")
    runs_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if not 2 <= len(infos) <= MAX_FILES + 1:
            raise ValueError("Session archive has an invalid number of entries")
        names = set()
        exact_names = set()
        total = 0
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            if (info.is_dir() or name.startswith("/") or "\\" in name or
                    path.as_posix() != name or any(part in ("", ".", "..") for part in path.parts)
                    or any(":" in part or part.rstrip(" .") != part or _reserved_windows_name(part)
                           for part in path.parts)
                    or (name != "harp-session.json" and (len(path.parts) < 2 or path.parts[0] != "session"))):
                raise ValueError("Session archive contains an unsafe path")
            mode = info.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise ValueError("Session archive contains a non-regular file")
            folded = name.casefold()
            if folded in names:
                raise ValueError("Session archive contains duplicate paths")
            names.add(folded)
            exact_names.add(name)
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError("A session file exceeds the archive limit")
            total += info.file_size
            if total > MAX_EXTRACTED_BYTES:
                raise ValueError("Extracted session exceeds the archive limit")
        if "harp-session.json" not in exact_names or "session/session.json" not in exact_names:
            raise ValueError("This is not a complete HARP session archive")
        if (archive.getinfo("harp-session.json").file_size > 16 * 1024 or
                archive.getinfo("session/session.json").file_size > 64 * 1024 * 1024):
            raise ValueError("Session archive metadata is too large")
        manifest = json.loads(archive.read("harp-session.json"))
        if (not isinstance(manifest, dict) or manifest.get("format") != "harp-session"
                or manifest.get("format_version") != FORMAT_VERSION):
            raise ValueError("Unsupported HARP session archive version")
        session = json.loads(archive.read("session/session.json"))
        if (not isinstance(session, dict) or session.get("status") != "finished"
                or not isinstance(session.get("target"), str) or not session["target"]
                or session.get("mode") not in (None, "hybrid", "local-only", "frontier-only")
                or not isinstance(session.get("config"), dict)
                or not isinstance(session.get("config", {}).get("local"), dict)
                or not isinstance(session.get("config", {}).get("max_steps"), int)
                or not isinstance(session.get("observations"), list)
                or not isinstance(session.get("local_calls"), list)
                or not isinstance(session.get("recon"), list)
                or not isinstance(session.get("started_epoch"), (int, float))
                or not isinstance(session.get("started_at"), str)
                or session.get("success") not in ("yes", "no", "unknown")):
            raise ValueError("Archive does not contain a finished HARP session")
        identifier = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        destination = runs_dir / identifier
        while destination.exists():
            identifier = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
            destination = runs_dir / identifier
        staging = runs_dir / (".import-" + uuid.uuid4().hex)
        staging.mkdir()
        try:
            for info in infos:
                if info.filename == "harp-session.json":
                    continue
                target = staging.joinpath(*PurePosixPath(info.filename).parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
            session["imported_from"] = {"session": str(manifest.get("source_session", ""))[:100],
                                        "harp_version": str(manifest.get("harp_version", ""))[:30],
                                        "imported_at": datetime.now(timezone.utc).isoformat()}
            (staging / "session.json").write_text(json.dumps(session), encoding="utf-8")
            staging.replace(destination)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
    return destination
