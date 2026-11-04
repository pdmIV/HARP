"""Dependency-free stdio MCP adapter for Codex. JSON-RPC messages are one line each."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import time
import uuid
from pathlib import Path

import harp
import harp_artifacts

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
GUI_HEARTBEAT = ROOT / ".gui_heartbeat"


def run_path(session: str) -> Path:
    path = Path(session).resolve()
    if not path.is_relative_to(RUNS.resolve()) or not (path / "session.json").is_file():
        raise ValueError("Expected a HARP session directory under runs/")
    return path


def captured(operation) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        operation()
    return out.getvalue()


def start_session(mode: str = "hybrid") -> str:
    return captured(lambda: harp.start_session(harp.load_config(ROOT / "harp.json"), RUNS, mode))


def inspect_session(session: str) -> str:
    state = harp.load_session(run_path(session))
    return json.dumps({"summary": harp.summarize(state), "recon": state["recon"],
                       "http_probes": state.get("http_probes", []),
                       "flags": harp_artifacts.flag_status(run_path(session)),
                       "artifacts": harp_artifacts.list_artifacts(run_path(session)),
                       "recent_observations": state["observations"][-4:],
                       "memory_notes": state["memory_notes"][-12:]}, indent=2)


def record_artifact(session: str, kind: str, title: str, value: str) -> str:
    path = run_path(session)
    state = harp.load_session(path)
    if kind == "flag":
        if title not in harp_artifacts.FLAG_NAMES:
            raise ValueError("Flag title must be user.txt or root.txt")
        candidates = [observation for observation in state["observations"]
                      if title.lower() in observation["command"].lower()
                      and value in observation.get("output", "")]
        if not candidates:
            raise ValueError("Flag value and filename must appear together in terminal evidence")
        observation = candidates[-1]
        harp_artifacts.register_artifact(path, kind=kind, title=title, value=value,
                                         source=observation["command"], evidence="Exact flag value in terminal output",
                                         evidence_backed=True)
        harp_artifacts.maybe_mark_flag_success(path)
    else:
        record = harp_artifacts.capture_model_artifact(path, state,
                                                        {"kind": kind, "title": title, "value": value})
        if record is None:
            raise ValueError("Artifact value must appear in recorded terminal evidence")
    return "Evidence-backed artifact recorded."


def capture_document(session: str, path: str, title: str) -> str:
    run_dir = run_path(session)
    record = harp_artifacts.capture_document_file(run_dir, harp.load_session(run_dir), path, title)
    return f"Document captured as artifact {record['id']} ({record['attachment']['size']} bytes)."


def terminal(session: str, command: str) -> str:
    return captured(lambda: harp.direct_exec(run_path(session), command))


def terminal_root(session: str, command: str) -> str:
    path = run_path(session)
    try:
        gui_running = time.time() - GUI_HEARTBEAT.stat().st_mtime < 4
    except FileNotFoundError:
        gui_running = False
    if gui_running:
        request_id = uuid.uuid4().hex
        approval_dir = path / "approvals"
        approval_dir.mkdir(exist_ok=True)
        request_path = approval_dir / f"{request_id}.request.json"
        decision_path = approval_dir / f"{request_id}.decision.json"
        request_path.write_text(json.dumps({"id": request_id, "command": command,
                                            "requested_at": harp.now(), "source": "oracle"}), encoding="utf-8")
        harp.append_event(path, {"type": "root_approval_requested", "id": request_id,
                                 "command": command, "source": "oracle"})
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if decision_path.is_file():
                decision = json.loads(decision_path.read_text(encoding="utf-8"))
                if decision.get("id") != request_id or decision.get("command") != command:
                    raise RuntimeError("Root approval did not match the exact request")
                if decision.get("approved") is not True:
                    harp.append_event(path, {"type": "root_approval_denied", "id": request_id})
                    return "Root command denied in the HARP command center."
                harp.append_event(path, {"type": "root_approval_granted", "id": request_id})
                break
            try:
                if time.time() - GUI_HEARTBEAT.stat().st_mtime >= 4:
                    decision_path.write_text(json.dumps({"id": request_id, "command": command, "approved": False}), encoding="utf-8")
                    harp.append_event(path, {"type": "root_approval_cancelled", "id": request_id})
                    raise RuntimeError("HARP command center closed before root approval; retry through the Codex prompt")
            except FileNotFoundError as error:
                decision_path.write_text(json.dumps({"id": request_id, "command": command, "approved": False}), encoding="utf-8")
                harp.append_event(path, {"type": "root_approval_cancelled", "id": request_id})
                raise RuntimeError("HARP command center closed before root approval; retry through the Codex prompt") from error
            time.sleep(0.25)
        else:
            decision_path.write_text(json.dumps({"id": request_id, "command": command, "approved": False}), encoding="utf-8")
            harp.append_event(path, {"type": "root_approval_expired", "id": request_id})
            raise RuntimeError("Root approval timed out in the HARP command center")
    return captured(lambda: harp.root_exec(path, command))


def record_oracle_plan(session: str, plan: str) -> str:
    if not plan.strip() or len(plan) > 4000:
        raise ValueError("Plan must be 1 through 4000 characters")
    path = run_path(session)
    harp.append_event(path, {"type": "oracle_plan", "plan": plan.strip()})
    return "Oracle plan recorded for the command center."


def delegate_local(session: str, objective: str, steps: int = 5) -> str:
    return captured(lambda: harp.delegate(run_path(session), objective, steps))


def mark_human_intervention(session: str) -> str:
    harp.mark_human_intervention(run_path(session))
    return "Human tactical intervention recorded."


def record_oracle_usage(session: str, input_tokens: int, output_tokens: int) -> str:
    if input_tokens < 0 or output_tokens < 0:
        raise ValueError("Token counts must be nonnegative")
    path = run_path(session)
    state = harp.load_session(path)
    state["oracle_usage"] = {"input_tokens": input_tokens, "output_tokens": output_tokens,
                             "source": "manual"}
    harp.save_session(path, state)
    return "Oracle token usage recorded."


def mark_success(session: str, evidence: str) -> str:
    harp.mark_success(run_path(session), evidence)
    return "Verified success recorded."


def finish_session(session: str, success: str) -> str:
    if success not in ("yes", "no", "unknown"):
        raise ValueError("success must be yes, no, or unknown")
    return captured(lambda: harp.finish_session(run_path(session), success))


TOOLS = {
    "start_session": (start_session, "Start Kali and deterministic reconnaissance in a selected experiment mode.",
                      {"mode": {"type": "string", "enum": ["local-only", "frontier-only", "hybrid"], "default": "hybrid"}}, []),
    "inspect_session": (inspect_session, "Read recon, recent observations, progress, and metrics.",
                        {"session": {"type": "string"}}, ["session"]),
    "terminal": (terminal, "Run one bounded command as the nonroot Kali user.",
                 {"session": {"type": "string"}, "command": {"type": "string"}}, ["session", "command"]),
    "terminal_root": (terminal_root, "Run one root command after the human approves this exact tool call. Permission is not tactical intervention.",
                      {"session": {"type": "string"}, "command": {"type": "string"}}, ["session", "command"]),
    "record_oracle_plan": (record_oracle_plan, "Publish a concise, user-visible strategy or plan update to the HARP command center.",
                            {"session": {"type": "string"}, "plan": {"type": "string"}}, ["session", "plan"]),
    "record_artifact": (record_artifact, "Record an evidence-backed credential, document excerpt, or flag for the command center.",
                        {"session": {"type": "string"},
                         "kind": {"type": "string", "enum": ["credential", "document", "other", "flag"]},
                         "title": {"type": "string"}, "value": {"type": "string"}},
                        ["session", "kind", "title", "value"]),
    "capture_document": (capture_document, "Preserve one regular file under Kali /workspace (8 MiB maximum) as a downloadable document artifact.",
                         {"session": {"type": "string"}, "path": {"type": "string"},
                          "title": {"type": "string"}}, ["session", "path", "title"]),
    "delegate_local": (delegate_local, "Give Unsloth a narrow objective and bounded autonomous terminal steps; stop on stagnation.",
                       {"session": {"type": "string"}, "objective": {"type": "string"},
                        "steps": {"type": "integer", "minimum": 1, "maximum": 5, "default": 5}},
                       ["session", "objective"]),
    "mark_human_intervention": (mark_human_intervention, "Record human tactical help, not permission approval.",
                                {"session": {"type": "string"}}, ["session"]),
    "record_oracle_usage": (record_oracle_usage, "Attach externally reported Codex token counts when available.",
                            {"session": {"type": "string"}, "input_tokens": {"type": "integer", "minimum": 0},
                             "output_tokens": {"type": "integer", "minimum": 0}},
                            ["session", "input_tokens", "output_tokens"]),
    "mark_success": (mark_success, "Timestamp externally verified target success with evidence.",
                     {"session": {"type": "string"}, "evidence": {"type": "string"}},
                     ["session", "evidence"]),
    "finish_session": (finish_session, "Stop Kali and label the final externally verified outcome.",
                       {"session": {"type": "string"}, "success": {"type": "string", "enum": ["yes", "no", "unknown"]}},
                       ["session", "success"]),
}


def tool_list() -> list[dict]:
    return [
        {"name": name, "description": description,
         "inputSchema": {"type": "object", "properties": properties,
                         "required": required, "additionalProperties": False},
         "annotations": {"readOnlyHint": name == "inspect_session"}}
        for name, (_, description, properties, required) in TOOLS.items()
    ]


def response(request: dict) -> dict | None:
    method = request.get("method")
    request_id = request.get("id")
    if method == "notifications/initialized" or request_id is None:
        return None
    base = {"jsonrpc": "2.0", "id": request_id}
    if method == "initialize":
        version = request.get("params", {}).get("protocolVersion", "2025-06-18")
        return {**base, "result": {"protocolVersion": version,
                                   "capabilities": {"tools": {"listChanged": False}},
                                   "serverInfo": {"name": "harp", "version": "0.1.0"}}}
    if method == "ping":
        return {**base, "result": {}}
    if method == "tools/list":
        return {**base, "result": {"tools": tool_list()}}
    if method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name")
        if name not in TOOLS:
            return {**base, "error": {"code": -32602, "message": "Unknown tool"}}
        function, _, properties, required = TOOLS[name]
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict) or any(k not in arguments for k in required) or any(k not in properties for k in arguments):
            return {**base, "error": {"code": -32602, "message": "Invalid tool arguments"}}
        try:
            value = function(**arguments)
            return {**base, "result": {"content": [{"type": "text", "text": str(value)[:64000]}], "isError": False}}
        except Exception as error:
            return {**base, "result": {"content": [{"type": "text", "text": str(error)}], "isError": True}}
    return {**base, "error": {"code": -32601, "message": "Method not found"}}


def main() -> None:
    for line in sys.stdin:
        try:
            result = response(json.loads(line))
        except Exception as error:
            result = {"jsonrpc": "2.0", "id": None,
                      "error": {"code": -32700, "message": str(error)}}
        if result is not None:
            sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
