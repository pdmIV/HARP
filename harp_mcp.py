"""Dependency-free stdio MCP adapter for Codex. JSON-RPC messages are one line each."""

from __future__ import annotations

import contextlib
from datetime import datetime
import io
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.request import Request, urlopen
import webbrowser

import harp
import harp_artifacts
import harp_whippet

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
GUI_HEARTBEAT = ROOT / ".gui_heartbeat"
CONTROL_STATE = ROOT / ".control_center.json"


def _control_record() -> dict | None:
    try:
        record = json.loads(CONTROL_STATE.read_text(encoding="utf-8"))
        port = int(record["port"])
        token = str(record["token"])
        if not 1024 <= port <= 65535 or not token:
            return None
        request = Request(f"http://127.0.0.1:{port}/api/health", headers={"X-HARP-Token": token})
        with urlopen(request, timeout=1) as response:
            if response.status != 200:
                return None
        return {"port": port, "token": token}
    except (OSError, ValueError, KeyError):
        return None


def launch_control_center() -> str:
    """Start or reopen the browser dashboard without exposing its control token."""
    opened_at = harp.now()
    record = _control_record()
    if record is None:
        flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen([sys.executable, str(ROOT / "harp_web.py"), "--no-browser"],
                                   cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, creationflags=flags,
                                   start_new_session=os.name != "nt")
        for _ in range(100):
            record = _control_record()
            if record:
                break
            if process.poll() is not None:
                raise RuntimeError("HARP command center exited during startup")
            time.sleep(0.1)
        if record is None:
            raise RuntimeError("HARP command center did not become ready")
    url = f"http://127.0.0.1:{record['port']}/#token={record['token']}"
    if not webbrowser.open(url):
        raise RuntimeError("The command center is running, but the browser did not open. Run python harp_web.py from the project folder.")
    return json.dumps({"status": "opened", "url": f"http://127.0.0.1:{record['port']}/",
                       "opened_at": opened_at,
                       "next": "Operator sets model and target in browser and starts Hybrid session. Call wait_for_session with after=opened_at."})


def wait_for_session(after: str, timeout_seconds: int = 1200) -> str:
    """Wait for the operator to start a new hybrid run in the dashboard."""
    try:
        cutoff = datetime.fromisoformat(after)
    except ValueError as error:
        raise ValueError("after must be the timestamp returned by launch_control_center") from error
    if cutoff.tzinfo is None:
        raise ValueError("after must include a timezone")
    if not 1 <= timeout_seconds <= 1200:
        raise ValueError("timeout_seconds must be 1 through 1200")
    end = time.monotonic() + timeout_seconds
    while time.monotonic() < end:
        for path in sorted(RUNS.glob("*/session.json"), reverse=True):
            try:
                state = harp.load_session(path.parent)
                started = datetime.fromisoformat(state["started_at"])
                if started >= cutoff and state["status"] == "active" and state["mode"] == "hybrid":
                    return f"Hybrid session ready: {path.parent.resolve()}\n" + inspect_session(str(path.parent))
            except (OSError, ValueError, KeyError):
                continue
        time.sleep(1)
    return "No new hybrid session appeared before the wait timed out. Reopen the command center or call wait_for_session again with the same after timestamp."


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


def start_session(mode: str = "hybrid", fresh_recon: bool = False) -> str:
    return captured(lambda: harp.start_session(harp.load_config(ROOT / "harp.json"), RUNS, mode,
                                               fresh_recon=fresh_recon))


def inspect_session(session: str) -> str:
    state = harp.load_session(run_path(session))
    return json.dumps({"summary": harp.summarize(state), "recon": state["recon"],
                       "http_probes": state.get("http_probes", []),
                       "smb_probes": state.get("smb_probes", []),
                       "whippet": state.get("whippet"),
                       "whippet_guidance": harp_whippet.guidance(state),
                       "proxy_image_input_available": harp.supports_image_input(state.get("config", {}).get("local", {})),
                       "unverified_local_conclusion": state.get("local_conclusion"),
                       "oracle_help_request": state.get("oracle_help_request"),
                       "smb_tool_guidance": harp_whippet.SMB_TOOL_GUIDANCE,
                       "flags": harp_artifacts.flag_status(run_path(session)),
                       "artifacts": harp_artifacts.list_artifacts(run_path(session)),
                       "recent_observations": [harp_whippet.observation(x, 3000)
                                               if harp_whippet.is_query(x.get("command", "")) else x
                                               for x in state["observations"][-4:]],
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
    if harp_whippet.is_query(command):
        path = run_path(session)
        harp.direct_exec(path, command, quiet=True)
        result = harp.load_session(path)["observations"][-1]
        return json.dumps(harp_whippet.observation(result, 3000))
    return captured(lambda: harp.direct_exec(run_path(session), command))


def whippet_query(session: str, inputs: list[str], request: dict, refresh: bool = False) -> str:
    result = harp.whippet_query(run_path(session), inputs, request, refresh=refresh)
    return json.dumps(harp_whippet.observation(result, 3000))


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


def delegate_local(session: str, objective: str, steps: int | None = None, unbridled: bool = False) -> str:
    path = run_path(session)
    state = harp.load_session(path)
    if harp_whippet.relevant(state) or harp.supports_image_input(state["config"]["local"]):
        harp.delegate(path, objective, steps, quiet=True, unbridled=unbridled)
        return inspect_session(session)
    return captured(lambda: harp.delegate(run_path(session), objective, steps, unbridled=unbridled))


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
    "launch_control_center": (launch_control_center, "Open the local HARP web command center so the operator can configure the model and target and start a session.", {}, []),
    "wait_for_session": (wait_for_session, "Wait for a new Hybrid session started in the web command center. Startup Nmap reconnaissance completes before this returns; use its compact structured findings to publish an oracle plan before any local delegation.",
                         {"after": {"type": "string"}, "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1200, "default": 1200}}, ["after"]),
    "start_session": (start_session, "Start Kali and reuse matching reconnaissance or scan in a selected experiment mode.",
                      {"mode": {"type": "string", "enum": ["local-only", "frontier-only", "hybrid"], "default": "hybrid"},
                       "fresh_recon": {"type": "boolean", "default": False}}, []),
    "inspect_session": (inspect_session, "Read recon, recent observations, progress, and metrics.",
                        {"session": {"type": "string"}}, ["session"]),
    "terminal": (terminal, "Run one bounded command as the nonroot Kali user.",
                 {"session": {"type": "string"}, "command": {"type": "string"}}, ["session", "command"]),
    "whippet_query": (whippet_query, "Query a reused offline Whippet graph in the selected Kali runtime. Capture files must be in the session workspace. Transport failures stop the process; refresh explicitly to restart.",
                      {"session": {"type": "string"}, "inputs": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 32},
                       "request": {"type": "object"}, "refresh": {"type": "boolean", "default": False}},
                      ["session", "inputs", "request"]),
    "terminal_root": (terminal_root, "Run one root command after the human approves this exact tool call. Permission is not tactical intervention.",
                      {"session": {"type": "string"}, "command": {"type": "string"}}, ["session", "command"]),
    "record_oracle_plan": (record_oracle_plan, "Publish a concise, user-visible strategy or plan update to the HARP command center.",
                            {"session": {"type": "string"}, "plan": {"type": "string"}}, ["session", "plan"]),
    "record_artifact": (record_artifact, "Record an evidence-backed credential, document excerpt, or flag for the command center.",
                        {"session": {"type": "string"},
                         "kind": {"type": "string", "enum": ["credential", "document", "other", "flag"]},
                         "title": {"type": "string"}, "value": {"type": "string"}},
                        ["session", "kind", "title", "value"]),
    "capture_document": (capture_document, "Preserve one regular file under the active Kali session workspace (8 MiB maximum). PNG/JPEG files become image artifacts with dashboard previews; other files remain downloadable documents.",
                         {"session": {"type": "string"}, "path": {"type": "string"},
                          "title": {"type": "string"}}, ["session", "path", "title"]),
    "delegate_local": (delegate_local, "Give the proxy model one narrow objective. The configured proxy step limit applies afresh to each delegation; total proxy steps remain a statistic. Unbridled=true removes step, model-call, and repetition limits until done, operator stop, or another required stop. Review terminal evidence and the stop reason afterward.",
                       {"session": {"type": "string"}, "objective": {"type": "string"},
                        "steps": {"type": "integer", "minimum": 1},
                        "unbridled": {"type": "boolean", "default": False}},
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
