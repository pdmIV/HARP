"""Evidence-backed artifact and flag registry for HARP sessions."""

from __future__ import annotations

import json
import hashlib
import re
import subprocess
import uuid
from pathlib import Path, PurePosixPath


KINDS = {"credential", "document", "other", "flag"}
FLAG_NAMES = ("user.txt", "root.txt")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FILE_READ = re.compile(r"(?i)(?<![A-Za-z0-9_-])(?:cat|type|get-content|more|head|tail|sed|awk)(?![A-Za-z0-9_-])")


def list_artifacts(run_dir: Path) -> list[dict]:
    path = run_dir / "artifacts.jsonl"
    if not path.is_file():
        return []
    result = []
    seen = set()
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                if isinstance(item, dict) and item.get("id"):
                    # Older runs may have saved the same evidence under different titles.
                    identity = (item.get("kind"), item.get("value")) if item.get("kind") != "flag" else ("flag", item.get("title"), item.get("value"))
                    if identity in seen:
                        continue
                    seen.add(identity)
                    result.append(item)
            except json.JSONDecodeError:
                continue
    return result


def register_artifact(run_dir: Path, *, kind: str, title: str, value: str,
                      source: str, evidence: str, evidence_backed: bool,
                      artifact_id: str | None = None, attachment: dict | None = None) -> dict:
    if kind not in KINDS:
        raise ValueError("Artifact kind must be credential, document, flag, or other")
    title, value, source, evidence = (str(x).strip() for x in (title, value, source, evidence))
    if not title or not value or len(title) > 160 or len(value) > 8000 or len(source) > 1000:
        raise ValueError("Artifact title or value is empty or too long")
    if kind == "flag" and title not in FLAG_NAMES:
        raise ValueError("Flag title must be user.txt or root.txt")
    for item in list_artifacts(run_dir):
        if item["kind"] == kind and item["value"] == value and (kind != "flag" or item["title"] == title):
            return item
    from harp import append_event, now
    record = {"id": artifact_id or uuid.uuid4().hex, "at": now(), "kind": kind, "title": title,
              "value": value, "source": source, "evidence": evidence[:1200],
              "evidence_backed": bool(evidence_backed)}
    if attachment:
        record["attachment"] = attachment
    with (run_dir / "artifacts.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    append_event(run_dir, {"type": "artifact_recorded", "id": record["id"],
                           "kind": kind, "title": title, "evidence_backed": bool(evidence_backed)})
    return record


def capture_document_file(run_dir: Path, session: dict, container_path: str, title: str) -> dict:
    """Copy one regular session-workspace file through bounded stdout."""
    workspace = session.get("workspace", "/workspace")
    path = PurePosixPath(container_path)
    if (not container_path.startswith(workspace.rstrip("/") + "/") or ".." in path.parts
            or any(ord(c) < 32 for c in container_path) or len(container_path) > 500
            or len(path.name) > 160):
        raise ValueError("Document path must be a normal file under the Kali session workspace")
    if session.get("status") != "active":
        raise ValueError("Documents can be captured only from an active Kali session")
    import harp
    terminal = harp.terminal_for(session)
    script = (
        "import os,stat,sys\n"
        "p=os.path.realpath(sys.argv[1])\n"
        "if not p.startswith(sys.argv[2].rstrip('/')+'/'): sys.exit(2)\n"
        "fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)\n"
        "s=os.fstat(fd)\n"
        "if not stat.S_ISREG(s.st_mode) or s.st_size>8388608: sys.exit(3)\n"
        "left=8388609\n"
        "while left:\n"
        " b=os.read(fd,min(65536,left))\n"
        " if not b: break\n"
        " left-=len(b)\n"
        " sys.stdout.buffer.write(b)\n"
        "if left==0: sys.exit(4)\n"
    )
    result = subprocess.run(terminal.file_argv(script, container_path) + [workspace],
                            capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Could not capture a regular document under the Kali session workspace (8 MiB maximum)")
    data = result.stdout
    if len(data) > 8388608:
        raise ValueError("Document exceeds 8 MiB maximum")
    digest = hashlib.sha256(data).hexdigest()
    filename = path.name
    text_preview = data[:3000].decode("utf-8", errors="replace") if b"\x00" not in data[:3000] else "Binary file"
    value = f"File: {filename}\nSHA-256: {digest}\nSize: {len(data)} bytes\n\nPreview:\n{text_preview}"
    artifact_id = uuid.uuid4().hex
    files = run_dir / "artifact_files"
    files.mkdir(exist_ok=True)
    stored = files / artifact_id
    stored.write_bytes(data)
    try:
        record = register_artifact(run_dir, kind="document", title=title, value=value,
                                   source=container_path, evidence="Copied regular file from Kali session workspace",
                                   evidence_backed=True, artifact_id=artifact_id,
                                   attachment={"filename": filename, "size": len(data), "sha256": digest})
    except Exception:
        stored.unlink(missing_ok=True)
        raise
    if record["id"] != artifact_id:
        stored.unlink(missing_ok=True)
    return record


def capture_flags_from_result(run_dir: Path, result: dict) -> list[dict]:
    command = str(result.get("command", ""))
    output = ANSI.sub("", str(result.get("output", "")))
    mentioned = [name for name in FLAG_NAMES if re.search(r"(?i)(?<![A-Za-z0-9_.-])" + re.escape(name) + r"(?![A-Za-z0-9_.-])", command)]
    hashes = list(dict.fromkeys(line.strip().lower() for line in output.splitlines()
                                if re.fullmatch(r"[0-9a-fA-F]{32}", line.strip())))
    if len(mentioned) != 1 or len(hashes) != 1 or result.get("exit_code") != 0 or not FILE_READ.search(command):
        return []
    name = mentioned[0]
    record = register_artifact(run_dir, kind="flag", title=name, value=hashes[0],
                               source=command, evidence="Flag-shaped value captured from terminal output",
                               evidence_backed=True)
    return [record]


def capture_model_artifact(run_dir: Path, session: dict, proposal: dict) -> dict | None:
    if not isinstance(proposal, dict):
        return None
    kind = proposal.get("kind")
    title = proposal.get("title")
    value = proposal.get("value")
    if kind not in ("credential", "document", "other") or not isinstance(title, str) or not isinstance(value, str):
        return None
    if not 2 <= len(value) <= 8000:
        return None
    for observation in reversed(session.get("observations", [])):
        if value in observation.get("output", ""):
            return register_artifact(run_dir, kind=kind, title=title, value=value,
                                     source=observation["command"], evidence="Exact value appears in terminal output",
                                     evidence_backed=True)
    for probe in reversed(session.get("http_probes", [])):
        if value in probe.get("body_excerpt", ""):
            return register_artifact(run_dir, kind=kind, title=title, value=value,
                                     source=f"Deterministic HTTP probe on port {probe['port']}",
                                     evidence="Exact value appears in HTTP probe response",
                                     evidence_backed=True)
    return None


def flag_status(run_dir: Path) -> dict:
    artifacts = list_artifacts(run_dir)
    seen_path = run_dir / "flag_seen.json"
    try:
        seen = set(json.loads(seen_path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        seen = set()
    flags = {}
    for name in FLAG_NAMES:
        matching = [a for a in artifacts if a["kind"] == "flag" and a["title"] == name and a["evidence_backed"]]
        item = matching[-1] if matching else None
        flags[name] = {"found": item is not None, "unseen": bool(item and item["id"] not in seen),
                       "artifact_id": item["id"] if item else None, "at": item["at"] if item else None}
    return flags


def mark_flags_seen(run_dir: Path, artifact_ids: list[str] | None = None) -> None:
    seen_path = run_dir / "flag_seen.json"
    available = {item["id"] for item in list_artifacts(run_dir) if item["kind"] == "flag"}
    try:
        seen = set(json.loads(seen_path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        seen = set()
    ids = seen | (available if artifact_ids is None else available.intersection(artifact_ids))
    temporary = seen_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(sorted(ids)), encoding="utf-8")
    temporary.replace(seen_path)


def maybe_mark_flag_success(run_dir: Path) -> None:
    flags = flag_status(run_dir)
    if all(flags[name]["found"] for name in FLAG_NAMES):
        import harp
        state = harp.load_session(run_dir)
        if state.get("status") == "active" and state.get("success_epoch") is None:
            ids = ", ".join(flags[name]["artifact_id"] for name in FLAG_NAMES)
            harp.mark_success(run_dir, "Both user.txt and root.txt captured in terminal evidence; artifact IDs: " + ids)
