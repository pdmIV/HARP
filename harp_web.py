"""Local HARP web command center. Run: python harp_web.py"""

from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timezone
import hmac
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from urllib.parse import parse_qs, urlparse
import uuid
import webbrowser

import harp
import harp_artifacts
import harp_secret
import harp_nim


ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
CONFIG = ROOT / "harp.json"
WEB = ROOT / "web"
HEARTBEAT = ROOT / ".gui_heartbeat"
CONTROL_STATE = ROOT / ".control_center.json"
KV_TYPES = ("f16", "bf16", "q8_0", "q4_0")
SESSION_ID = re.compile(r"\d{8}-\d{6}-[0-9a-f]{6}\Z")
KEY_PATTERN = re.compile(r"API Key:\s*(sk-unsloth-[A-Za-z0-9_-]+)")


def build_launch_args(settings: dict) -> list[str]:
    model = str(settings["model"]).strip()
    if not model or model.startswith("-") or any(c in model for c in "\r\n\x00"):
        raise ValueError("Enter a valid model ID")
    port, context, parallel = (int(settings[k]) for k in ("port", "context", "parallel"))
    cache_k, cache_v = settings["cache_k"], settings["cache_v"]
    if not 1024 <= port <= 65535:
        raise ValueError("Port must be 1024 through 65535")
    if not 1024 <= context <= 131072:
        raise ValueError("Context must be 1024 through 131072 tokens")
    if not 1 <= parallel <= 4:
        raise ValueError("Parallel slots must be 1 through 4")
    if cache_k not in KV_TYPES or cache_v not in KV_TYPES:
        raise ValueError("Choose a listed KV cache type")
    return ["unsloth", "studio", "run", "--model", model, "--port", str(port),
            "--disable-tools", "--parallel", str(parallel), "--max-seq-length", str(context),
            "--cache-type-k", cache_k, "--cache-type-v", cache_v]


def redact_model_log(line: str) -> str:
    line = re.sub(r"sk-unsloth-[A-Za-z0-9_-]+", "[redacted]", line)
    line = re.sub(r"(?i)(API Key:\s*)\S+", r"\1[redacted]", line)
    line = re.sub(r"(?i)(Bearer\s+)\S+", r"\1[redacted]", line)
    return line


def api_port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def studio_settings(cfg: dict) -> dict:
    local = cfg["local"]
    default = {"model": local["model"], "port": urlparse(local["base_url"]).port or 8888,
               "context": 32768, "cache_k": "bf16", "cache_v": "bf16", "parallel": 1}
    return {**default, **(cfg.get("studio") or {})}


def draft_config() -> dict:
    """Load the GUI draft, including before the first valid target is supplied."""
    if CONFIG.is_file():
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    cfg = json.loads((ROOT / "harp.htb.example.json").read_text(encoding="utf-8"))
    cfg["target"] = ""
    cfg["local"]["model"] = ""
    return cfg


def prepare_runtime(cfg: dict) -> None:
    """Create the dedicated bridge and rebuild Kali only when its recipe changes."""
    if cfg.get("runtime") == "wsl":
        return
    try:
        harp.docker("network", "inspect", cfg["network"])
    except RuntimeError:
        if cfg.get("network_policy") != "vpn_bridge":
            raise
        harp.docker("network", "create", cfg["network"], timeout=30)
    harp.check_network(cfg, starting=True)
    recipe_hash = hashlib.sha256((ROOT / "Dockerfile.kali").read_bytes()).hexdigest()
    stamp = ROOT / ".kali_image_stamp"
    if stamp.is_file() and stamp.read_text(encoding="ascii") == recipe_hash:
        try:
            harp.docker("image", "inspect", harp.IMAGE)
            return
        except RuntimeError:
            pass
    built = subprocess.run(["docker", "build", "-f", "Dockerfile.kali", "-t", harp.IMAGE, "."],
                           cwd=ROOT, capture_output=True, text=True, timeout=900)
    if built.returncode:
        raise RuntimeError("Kali image build failed: " + (built.stderr or built.stdout)[-3000:])
    stamp.write_text(recipe_hash, encoding="ascii")


def session_path(session_id: str) -> Path:
    if not SESSION_ID.fullmatch(session_id):
        raise ValueError("Invalid session ID")
    path = RUNS / session_id
    if not (path / "session.json").is_file():
        raise ValueError("Session not found")
    return path


def read_events(run_dir: Path, cursor: int, limit: int = 250) -> tuple[list[dict], int]:
    path = run_dir / "events.jsonl"
    if not path.is_file():
        return [], 0
    size = path.stat().st_size
    if cursor < 0 or cursor > size:
        cursor = 0
    events = []
    with path.open("rb") as stream:
        stream.seek(cursor)
        for _ in range(limit):
            position = stream.tell()
            line = stream.readline()
            if not line or not line.endswith(b"\n"):
                stream.seek(position)
                break
            try:
                events.append(json.loads(line.decode("utf-8", errors="replace")))
            except json.JSONDecodeError:
                continue
        cursor = stream.tell()
    return events, cursor


def latest_activity(run_dir: Path) -> dict:
    plan = None
    local = None
    objective = None
    oracle_stopped = None
    path = run_dir / "events.jsonl"
    if path.is_file():
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = event.get("type")
                if kind == "oracle_plan":
                    plan = event.get("plan")
                elif kind in ("oracle_nim_request", "oracle_nim_resumed"):
                    oracle_stopped = None
                elif kind in ("oracle_nim_stopped", "oracle_nim_error"):
                    oracle_stopped = event.get("reason") or event.get("error") or "error"
                elif kind == "local_action":
                    local = event.get("action")
                elif kind == "delegation":
                    objective = event.get("objective")
    return {"oracle_plan": plan, "local_action": local, "delegated_objective": objective,
            "oracle_stopped": oracle_stopped}


def pending_approval(run_dir: Path, state: dict) -> dict | None:
    if state.get("status") != "active":
        return None
    command = state.get("pending_root_command")
    if command:
        return {"source": "local", "command": command, "id": "local"}
    approval_dir = run_dir / "approvals"
    if approval_dir.is_dir():
        for path in sorted(approval_dir.glob("*.request.json")):
            decision = path.with_name(path.name.replace(".request.json", ".decision.json"))
            if decision.exists():
                continue
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(item["requested_at"])).total_seconds()
                if 0 <= age < 240:
                    return {"source": "oracle", "command": item["command"], "id": item["id"]}
            except (OSError, ValueError, KeyError):
                continue
    return None


class HARPWebState:
    def __init__(self):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.jobs: dict[str, dict] = {}
        self.session_jobs: set[str] = set()
        self.stopping_sessions: set[str] = set()
        self.starting_session = False
        self.model_process: subprocess.Popen | None = None
        self.model_logs: deque[dict] = deque(maxlen=500)
        self.model_log_id = 0
        self.last_browser_seen = 0.0
        self.alive = True
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self.heartbeat_thread.start()

    def _heartbeat_loop(self):
        while self.alive:
            if time.monotonic() - self.last_browser_seen < 75:
                HEARTBEAT.touch()
            else:
                HEARTBEAT.unlink(missing_ok=True)
            time.sleep(1)

    def close(self):
        self.alive = False
        self.heartbeat_thread.join(timeout=2)
        HEARTBEAT.unlink(missing_ok=True)
        if self.model_process is not None and self.model_process.poll() is None:
            self.stop_model()

    def add_model_log(self, line: str):
        with self.lock:
            self.model_log_id += 1
            self.model_logs.append({"id": self.model_log_id, "at": harp.now(),
                                    "line": redact_model_log(line)[:3000]})

    def model_logs_since(self, cursor: int) -> list[dict]:
        with self.lock:
            return [item for item in self.model_logs if item["id"] > cursor]

    def submit(self, name: str, operation, session_id: str | None = None) -> str:
        with self.lock:
            if session_id and session_id in self.stopping_sessions:
                raise ValueError("This session is stopping")
            if session_id and session_id in self.session_jobs:
                raise ValueError("Another operation is already running for this session")
            job_id = uuid.uuid4().hex
            self.jobs[job_id] = {"id": job_id, "name": name, "status": "running",
                                 "started_at": harp.now(), "session_id": session_id}
            if session_id:
                self.session_jobs.add(session_id)

        def work():
            try:
                result = operation()
                status = "done"
                detail = (str(result.get("message", "Done")) if isinstance(result, dict)
                          else str(result) if result is not None else "Done")
            except Exception as error:
                status, detail, result = "error", str(error), None
            with self.lock:
                self.jobs[job_id].update(status=status, detail=detail, result=result,
                                         finished_at=harp.now())
                if session_id:
                    self.session_jobs.discard(session_id)

        threading.Thread(target=work, name="HARP-Web-" + name, daemon=True).start()
        return job_id

    def save_config(self, payload: dict) -> dict:
        with self.lock:
            cfg = draft_config()
            studio = payload.get("studio") or studio_settings(cfg)
            build_launch_args(studio)
            for key in ("target", "runtime", "wsl_distro", "wsl_user", "network", "network_policy", "scan_ports", "objective",
                        "container_memory", "container_cpus", "max_steps", "command_timeout_seconds"):
                if key in payload:
                    cfg[key] = payload[key]
            local_input = payload.get("local") or {}
            for key in ("max_input_tokens", "max_tokens", "temperature", "enable_thinking"):
                if key in local_input:
                    cfg["local"][key] = local_input[key]
            cfg["studio"] = studio
            cfg["local"]["model"] = str(studio["model"]).split(":", 1)[0]
            cfg["local"]["base_url"] = f"http://127.0.0.1:{int(studio['port'])}/v1"
            if "oracle" in payload:
                cfg["oracle"] = {**cfg.get("oracle", {}), **payload["oracle"]}
            temporary = CONFIG.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            try:
                # Model settings may be saved before the operator enters a target.
                if not cfg["target"]:
                    validation = {**cfg, "target": "10.10.10.10"}
                    temporary.write_text(json.dumps(validation), encoding="utf-8")
                    harp.load_config(temporary)
                    temporary.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
                else:
                    harp.load_config(temporary)
                temporary.replace(CONFIG)
            finally:
                temporary.unlink(missing_ok=True)
            return cfg

    def start_model(self) -> str:
        cfg = draft_config()
        settings = studio_settings(cfg)
        args = build_launch_args(settings)
        if api_port_open(int(settings["port"])):
            return "A model is already listening on that port; monitoring it."
        with self.lock:
            if self.model_process is not None and self.model_process.poll() is None:
                raise ValueError("A model launched by HARP is already running")
            executable = shutil.which("unsloth")
            if not executable:
                raise RuntimeError("The unsloth command is not on this Python process's PATH")
            args[0] = executable
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            self.model_process = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                                  errors="replace", bufsize=1, creationflags=flags)
            process = self.model_process
        self.add_model_log("Launching Unsloth Studio with server-side tools disabled.\n")
        threading.Thread(target=self._read_model_output, args=(process,), daemon=True).start()
        return "Unsloth Studio launch started"

    def _read_model_output(self, process):
        assert process.stdout is not None
        for line in process.stdout:
            match = KEY_PATTERN.search(line)
            if match:
                try:
                    harp_secret.save_key(ROOT / ".secrets" / "unsloth.key", match.group(1))
                    self.add_model_log("Model API key stored encrypted for this Windows account.\n")
                except Exception as error:
                    self.add_model_log(f"Could not store model API key: {error}\n")
            self.add_model_log(line)
        self.add_model_log(f"Unsloth Studio exited ({process.wait()}).\n")

    def stop_model(self) -> str:
        with self.lock:
            process = self.model_process
            if process is None or process.poll() is not None:
                return "No model launched by HARP is running"
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=15)
            else:
                process.terminate()
        self.add_model_log("Stopped model launched by HARP.\n")
        return "Model stop requested"

    def session_list(self) -> list[dict]:
        result = []
        for path in sorted((p.parent for p in RUNS.glob("*/session.json")), reverse=True)[:100]:
            try:
                state = harp.load_session(path)
                flags = harp_artifacts.flag_status(path)
                result.append({"id": path.name, "status": state["status"], "mode": state["mode"],
                               "target": state["target"], "started_at": state["started_at"],
                               "pending_approval": bool(pending_approval(path, state)),
                               "unseen_flags": sum(1 for flag in flags.values() if flag["unseen"]),
                               "flags_found": sum(1 for flag in flags.values() if flag["found"])})
            except (OSError, ValueError, KeyError):
                continue
        return result

    def session_view(self, session_id: str, cursor: int) -> dict:
        path = session_path(session_id)
        state = harp.load_session(path)
        events, next_cursor = read_events(path, cursor)
        return {"id": session_id, "summary": harp.summarize(state),
                "started_epoch": state["started_epoch"],
                "duration_seconds": state.get("duration_seconds"),
                "delegation_limit": state["config"]["max_steps"],
                "oracle_provider": state["config"].get("oracle", {}).get("provider", "codex"),
                "objective": state["config"].get("objective", ""),
                "recon": state.get("recon", []), "http_probes": state.get("http_probes", []),
                "smb_probes": state.get("smb_probes", []),
                "activity": latest_activity(path), "pending_approval": pending_approval(path, state),
                "flags": harp_artifacts.flag_status(path),
                "artifacts": harp_artifacts.list_artifacts(path),
                "events": events, "event_cursor": next_cursor}

    def decide_approval(self, session_id: str, request_id: str, approved: bool) -> str | None:
        path = session_path(session_id)
        state = harp.load_session(path)
        pending = pending_approval(path, state)
        if not pending or pending["id"] != request_id:
            raise ValueError("That exact root request is no longer pending")
        command = pending["command"]
        if pending["source"] == "local":
            if not approved:
                state["pending_root_command"] = None
                harp.append_event(path, {"type": "root_approval_denied", "source": "local"})
                harp.save_session(path, state)
                return None
            return self.submit("approved root command", lambda: harp.root_exec(path, command, quiet=True), session_id)
        decision = path / "approvals" / f"{request_id}.decision.json"
        if decision.exists():
            raise ValueError("Root request was already decided")
        temporary = decision.with_suffix(".tmp")
        temporary.write_text(json.dumps({"id": request_id, "command": command,
                                         "approved": approved, "at": harp.now()}), encoding="utf-8")
        temporary.replace(decision)
        return None


class HARPRequestHandler(BaseHTTPRequestHandler):
    server: "HARPHTTPServer"

    def log_message(self, _format, *_args):
        return

    def _headers(self, status: int, content_type: str, length: int):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected_host = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if self.headers.get("Host") not in expected_host:
            self._json(403, {"error": "Invalid host"})
            return False
        if not hmac.compare_digest(self.headers.get("X-HARP-Token", ""), self.server.state.token):
            self._json(403, {"error": "Open HARP from its Python launcher"})
            return False
        if self.command == "POST":
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{host}" for host in expected_host}:
                self._json(403, {"error": "Invalid origin"})
                return False
        self.server.state.last_browser_seen = time.monotonic()
        return True

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 65536:
            raise ValueError("Request body is too large")
        payload = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(payload, dict):
            raise ValueError("Expected a JSON object")
        return payload

    def do_GET(self):
        parsed = urlparse(self.path)
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.css": ("app.css", "text/css; charset=utf-8"),
                  "/app.js": ("app.js", "application/javascript; charset=utf-8")}
        if parsed.path in assets:
            filename, content_type = assets[parsed.path]
            body = (WEB / filename).read_bytes()
            self._headers(200, content_type, len(body))
            self.wfile.write(body)
            return
        if not parsed.path.startswith("/api/"):
            self._json(404, {"error": "Not found"})
            return
        if not self._authorized():
            return
        try:
            if parsed.path == "/api/state":
                query = parse_qs(parsed.query)
                selected = query.get("session", [""])[0]
                cursor = int(query.get("cursor", ["0"])[0])
                model_cursor = int(query.get("model_cursor", ["0"])[0])
                state = self.server.state
                cfg = draft_config()
                port = int(studio_settings(cfg)["port"])
                listed = state.session_list()
                payload = {"config": cfg, "sessions": listed,
                           "selected": state.session_view(selected, cursor) if selected and any(x["id"] == selected for x in listed) else None,
                           "model": {"listening": api_port_open(port), "port": port,
                                     "owned_running": bool(state.model_process and state.model_process.poll() is None),
                                     "logs": state.model_logs_since(model_cursor)}}
                self._json(200, payload)
            elif parsed.path == "/api/health":
                self._json(200, {"ready": True})
            elif parsed.path.startswith("/api/jobs/"):
                job_id = parsed.path.removeprefix("/api/jobs/")
                with self.server.state.lock:
                    job = self.server.state.jobs.get(job_id)
                if job is None:
                    raise ValueError("Job not found")
                self._json(200, {"job": job})
            elif parsed.path == "/api/model/context":
                cfg = harp.load_config(CONFIG)
                self._json(200, {"context": harp.model_context_tokens(cfg["local"])})
            elif parsed.path == "/api/oracle/models":
                self._json(200, {"models": harp_nim.models()})
            elif (match := re.fullmatch(r"/api/sessions/([^/]+)/attachments/([0-9a-f]{32})", parsed.path)):
                session_id, artifact_id = match.groups()
                run_dir = session_path(session_id)
                artifact = next((item for item in harp_artifacts.list_artifacts(run_dir)
                                 if item["id"] == artifact_id and item.get("attachment")), None)
                if artifact is None:
                    raise ValueError("Document attachment not found")
                stored = run_dir / "artifact_files" / artifact_id
                data = stored.read_bytes()
                filename = re.sub(r"[^A-Za-z0-9._-]", "_", artifact["attachment"]["filename"])
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
            else:
                self._json(404, {"error": "Not found"})
        except (ValueError, KeyError, OSError) as error:
            self._json(400, {"error": str(error)})
        except Exception as error:
            self._json(500, {"error": str(error)})

    def do_POST(self):
        if not self.path.startswith("/api/"):
            self._json(404, {"error": "Not found"})
            return
        if not self._authorized():
            return
        try:
            body = self._body()
            state = self.server.state
            path = urlparse(self.path).path
            if path == "/api/config":
                self._json(200, {"config": state.save_config(body)})
                return
            if path == "/api/oracle/key":
                value = str(body.get("key", "")).strip()
                if not value:
                    raise ValueError("Enter a NVIDIA API key")
                harp_secret.save_key(ROOT / ".secrets" / "nvidia.key", value)
                self._json(200, {"message": "NVIDIA key saved encrypted for this Windows account"})
                return
            if path == "/api/oracle/benchmark":
                models = body.get("models")
                if (not isinstance(models, list) or not 1 <= len(models) <= 5
                        or any(not isinstance(item, str) or not re.fullmatch(
                            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", item) for item in models)):
                    raise ValueError("Choose one to five valid NVIDIA model IDs")
                job = state.submit("NIM speed test", lambda: {
                    "message": "Speed test complete", "results": harp_nim.benchmark(models)})
                self._json(202, {"job": job})
                return
            if path == "/api/model/start":
                self._json(200, {"message": state.start_model()})
                return
            if path == "/api/model/stop":
                self._json(200, {"message": state.stop_model()})
                return
            if path == "/api/sessions/start":
                mode = body.get("mode", "hybrid")
                if mode not in ("hybrid", "local-only", "frontier-only"):
                    raise ValueError("Invalid experiment mode")
                with state.lock:
                    if state.starting_session or any(item["status"] in ("active", "recon") for item in state.session_list()):
                        raise ValueError("A session is already starting or active")
                cfg = harp.load_config(CONFIG)
                if mode == "hybrid" and cfg.get("oracle", {}).get("provider") == "nvidia_nim":
                    harp_nim.key()
                if mode != "frontier-only":
                    if not cfg["local"]["model"]:
                        raise ValueError("Choose a local model in the Local model tab first")
                    if not api_port_open(int(studio_settings(cfg)["port"])):
                        raise ValueError("Start the local model in the Local model tab first")
                with state.lock:
                    if state.starting_session or any(item["status"] in ("active", "recon") for item in state.session_list()):
                        raise ValueError("A session is already starting or active")
                    state.starting_session = True
                def start_job():
                    try:
                        prepare_runtime(cfg)
                        run_dir = harp.start_session(cfg, RUNS, mode)
                        if mode == "hybrid" and cfg.get("oracle", {}).get("provider") == "nvidia_nim":
                            def run_oracle():
                                try:
                                    harp_nim.run(run_dir)
                                except Exception as error:
                                    harp.append_event(run_dir, {"type": "oracle_nim_error",
                                                                "error": str(error)[:300]})
                                    raise
                            state.submit("NVIDIA NIM oracle", run_oracle, run_dir.name)
                        return run_dir.name
                    finally:
                        with state.lock:
                            state.starting_session = False
                try:
                    job = state.submit("start session", start_job)
                except Exception:
                    with state.lock:
                        state.starting_session = False
                    raise
                self._json(202, {"job": job})
                return
            match = re.fullmatch(r"/api/sessions/([^/]+)/([a-z-]+)", path)
            if not match:
                self._json(404, {"error": "Not found"})
                return
            session_id, action = match.groups()
            run_dir = session_path(session_id)
            session = harp.load_session(run_dir)
            if action == "flags-seen":
                ids = body.get("ids")
                if not isinstance(ids, list) or any(not isinstance(x, str) for x in ids):
                    raise ValueError("Expected the displayed flag artifact IDs")
                harp_artifacts.mark_flags_seen(run_dir, ids)
                self._json(200, {"message": "Flags marked seen"})
                return
            if action == "approval":
                job = state.decide_approval(session_id, str(body.get("id", "")), body.get("approved") is True)
                self._json(200, {"job": job})
                return
            if action == "delete":
                if session["status"] != "finished":
                    raise ValueError("Stop the session before deleting its logs")
                if session_id in state.session_jobs:
                    raise ValueError("Another operation is still running for this session")
                job = state.submit("delete session", lambda: shutil.rmtree(run_dir), session_id)
                self._json(202, {"job": job})
                return
            if action == "stop-session" and session["status"] == "recon":
                if (run_dir / ".stop_session").exists():
                    raise ValueError("Reconnaissance stop is already requested")
                (run_dir / ".stop_session").touch()
                harp.append_event(run_dir, {"type": "session_stop_requested",
                                            "detail": "Reconnaissance will stop after the current command"})
                self._json(200, {"message": "Reconnaissance will stop after its current command"})
                return
            if session["status"] != "active":
                raise ValueError("Session is not active")
            if action == "resume-oracle":
                if session["mode"] != "hybrid" or session["config"].get("oracle", {}).get("provider") != "nvidia_nim":
                    raise ValueError("Only active Hybrid NIM sessions can resume the oracle")
                if not latest_activity(run_dir)["oracle_stopped"]:
                    raise ValueError("The NIM oracle has not stopped")
                if harp_nim.oracle_history(run_dir)["cycles"] >= int(session["config"]["oracle"].get("max_cycles", 12)):
                    raise ValueError("NIM cycle budget is exhausted")
                def resume_oracle():
                    harp.append_event(run_dir, {"type": "oracle_nim_resumed"})
                    try:
                        harp_nim.run(run_dir)
                    except Exception as error:
                        harp.append_event(run_dir, {"type": "oracle_nim_error", "error": str(error)[:300]})
                        raise
                job = state.submit("resume NVIDIA NIM oracle", resume_oracle, session_id)
                self._json(202, {"job": job})
                return
            if action == "stop-session":
                with state.lock:
                    if session_id in state.stopping_sessions:
                        raise ValueError("Session stop is already in progress")
                    state.stopping_sessions.add(session_id)
                (run_dir / ".stop_session").touch()
                (run_dir / ".stop_local").touch()
                harp.append_event(run_dir, {"type": "session_stop_requested"})
                def stop_job():
                    try:
                        deadline = time.monotonic() + 480
                        while session_id in state.session_jobs and time.monotonic() < deadline:
                            time.sleep(0.25)
                        if session_id in state.session_jobs:
                            raise RuntimeError("An operation is still running; retry after it finishes")
                        current = harp.load_session(run_dir)
                        if current["status"] == "active":
                            harp.finish_session(run_dir, "yes" if current.get("success") == "yes" else "unknown")
                    finally:
                        with state.lock:
                            state.stopping_sessions.discard(session_id)
                job = state.submit("stop session", stop_job)
                self._json(202, {"job": job})
                return
            if action == "delegate":
                if session["mode"] == "frontier-only":
                    raise ValueError("Local delegation is disabled in frontier-only mode")
                objective = str(body.get("objective", "")).strip()
                steps = int(body.get("steps", session["config"]["max_steps"]))
                unbridled = body.get("unbridled") is True
                if not objective or steps < 1 or (not unbridled and steps > int(session["config"]["max_steps"])):
                    raise ValueError("Enter an objective and a positive step count within this session's delegation limit")
                def delegate_job():
                    if objective != session["config"].get("objective", ""):
                        harp.mark_human_intervention(run_dir)
                    harp.delegate(run_dir, objective, steps, quiet=True, unbridled=unbridled)
                job = state.submit("delegate local", delegate_job, session_id)
            elif action == "stop":
                (run_dir / ".stop_local").touch()
                harp.append_event(run_dir, {"type": "operator_stop_requested"})
                self._json(200, {"message": "Local worker will stop after its current step"})
                return
            elif action == "terminal":
                if session["mode"] == "local-only":
                    raise ValueError("Manual terminal is disabled in local-only mode")
                command = str(body.get("command", "")).strip()
                if not command:
                    raise ValueError("Enter a command")
                def terminal_job():
                    harp.mark_human_intervention(run_dir)
                    harp.direct_exec(run_dir, command, quiet=True)
                job = state.submit("manual terminal", terminal_job, session_id)
            elif action == "success":
                evidence = str(body.get("evidence", "")).strip()
                if not evidence:
                    raise ValueError("Enter verified evidence")
                job = state.submit("mark success", lambda: harp.mark_success(run_dir, evidence), session_id)
            elif action == "finish":
                outcome = body.get("outcome", "unknown")
                if outcome not in ("yes", "no", "unknown"):
                    raise ValueError("Invalid outcome")
                if outcome == "yes" and session["success"] != "yes":
                    raise ValueError("Record verified success before finishing as yes")
                job = state.submit("finish session", lambda: harp.finish_session(run_dir, outcome), session_id)
            else:
                self._json(404, {"error": "Not found"})
                return
            self._json(202, {"job": job})
        except (ValueError, KeyError, OSError, json.JSONDecodeError) as error:
            self._json(400, {"error": str(error)})
        except Exception as error:
            self._json(500, {"error": str(error)})


class HARPHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, state: HARPWebState):
        super().__init__(address, HARPRequestHandler)
        self.state = state


def main():
    parser = argparse.ArgumentParser(description="HARP local web command center")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    state = HARPWebState()
    server = HARPHTTPServer(("127.0.0.1", args.port), state)
    url = f"http://127.0.0.1:{server.server_port}/#token={state.token}"
    temporary = CONTROL_STATE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps({"port": server.server_port, "token": state.token,
                                     "pid": os.getpid()}), encoding="utf-8")
    temporary.replace(CONTROL_STATE)
    print(f"HARP Command Center: http://127.0.0.1:{server.server_port}/")
    if not args.no_browser:
        print("Opening a private browser tab. Keep this terminal running.")
        if not webbrowser.open(url):
            print("Browser launch failed. Open this private URL manually:", url)
    else:
        print("Open this private URL in your browser:", url)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        state.close()
        try:
            record = json.loads(CONTROL_STATE.read_text(encoding="utf-8"))
            if record.get("token") == state.token:
                CONTROL_STATE.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    main()
