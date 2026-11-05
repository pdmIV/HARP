"""NVIDIA hosted NIM oracle for HARP Hybrid sessions."""

import json
import os
import shlex
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import urllib.error
import urllib.request

import harp
import harp_artifacts
import harp_secret

BASE = "https://integrate.api.nvidia.com/v1"
RECOVERABLE_STOPS = {"three_unproductive_commands", "null_auth_denied", "repeated_command",
                     "repeated_output", "missing_command", "invalid_replies",
                     "command_validation_failed", "repeated_or_excessive_memory_query"}
FATAL_STOPS = {"operator_stop", "root_requested", "invalid_root_request", "model_call_budget"}


def oracle_model_options(model: str) -> dict:
    # HARP needs a short, visible JSON plan. Ultra otherwise defaults to full reasoning,
    # which can consume the entire completion cap before producing content.
    if model == "nvidia/nemotron-3-ultra-550b-a55b":
        return {"reasoning_effort": "none"}
    if model == "mistralai/mistral-large-4-1t-a52b":
        return {"reasoning_effort": "low"}
    return {}


def key() -> str:
    value = os.environ.get("NVIDIA_API_KEY")
    if value:
        return value
    path = Path(__file__).resolve().parent / ".secrets" / "nvidia.key"
    if not path.is_file():
        raise ValueError("Save a NVIDIA API key in Configuration or set NVIDIA_API_KEY")
    return harp_secret.load_key(path)


def request(path: str, payload: dict | None = None, *, timeout_seconds: int | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=data,
        headers={"Authorization": "Bearer " + key(), "Accept": "application/json",
                 "Content-Type": "application/json"}, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds or (240 if path == "/chat/completions" else 30)) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"NVIDIA NIM returned HTTP {error.code}") from error


def models() -> list[str]:
    data = request("/models")
    return sorted({str(item["id"]) for item in data.get("data", [])
                   if isinstance(item, dict) and isinstance(item.get("id"), str)})


def benchmark_one(model: str) -> dict:
    """Time one representative, synthetic oracle plan without target data."""
    prompt = {"target": "192.0.2.10", "objective": "Review an authorized lab host",
              "recon": [{"port": 445, "service": "microsoft-ds", "product": "Windows"}],
              "smb_probes": [{"option": "--shares", "summary": "Share LAB READ"}], "cycle": 1}
    body = {"model": model, "stream": False, "max_tokens": 1024,
            "messages": [{"role": "system", "content":
                "You are the HARP oracle. Return only JSON with keys plan, objective, stop. "
                "Choose one bounded, non-destructive next step based on the synthetic evidence."},
                {"role": "user", "content": json.dumps(prompt)}]}
    body.update(oracle_model_options(model))
    started = time.monotonic()
    try:
        reply = request("/chat/completions", body, timeout_seconds=90)
        content = reply["choices"][0]["message"].get("content") or ""
        decision = harp.json_object(content)
        valid = bool(str(decision.get("plan", "")).strip()
                     and str(decision.get("objective", "")).strip()
                     and isinstance(decision.get("stop"), bool))
        return {"model": model, "seconds": round(time.monotonic() - started, 2),
                "usable": valid, "status": "usable" if valid else "invalid_plan"}
    except Exception as error:
        return {"model": model, "seconds": round(time.monotonic() - started, 2),
                "usable": False, "status": "timeout" if "timed out" in str(error).lower()
                else "unavailable"}


def benchmark(models_to_test: list[str]) -> list[dict]:
    if not 1 <= len(models_to_test) <= 5 or len(set(models_to_test)) != len(models_to_test):
        raise ValueError("Choose one to five distinct models")
    with ThreadPoolExecutor(max_workers=min(3, len(models_to_test))) as pool:
        results = [future.result() for future in as_completed(
            [pool.submit(benchmark_one, model) for model in models_to_test])]
    return sorted(results, key=lambda item: (not item["usable"], item["seconds"]))


def compact_smb_probes(probes: list[dict]) -> list[dict]:
    compact = []
    for probe in probes:
        option = probe.get("option", "")
        lines = str(probe.get("output_excerpt", "")).splitlines()
        if option == "--shares":
            lines = [line for line in lines if "READ" in line or "WRITE" in line
                     or "Share " in line or "Null Auth:" in line]
        elif option == "--rid-brute":
            lines = [line for line in lines if "SidTypeUser" in line]
        elif option == "--users":
            lines = [line for line in lines if "[+]" in line or "user" in line.lower()]
        compact.append({"option": option, "exit_code": probe.get("exit_code"),
                        "summary": "\n".join(lines)[:1200]})
    return compact


def bound_objective(plan: str, objective: str) -> str:
    """Carry an explicit null-auth plan constraint into the worker's task."""
    if harp.null_auth_objective(plan) and not harp.null_auth_objective(objective):
        return objective + " Use null or guest authentication only; do not try named accounts or passwords."
    return objective


def oracle_probe_issue(command: str, session: dict, objective: str) -> str | None:
    """Allow one simple, nonroot, read-only target probe during recovery."""
    if not command or len(command) > 500 or any(ord(c) < 32 for c in command):
        return "Oracle probe is empty, too long, or contains control characters."
    if any(marker in command for marker in ("$", "`")):
        return "Oracle probe cannot use shell expansion."
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        parts = list(lexer)
    except ValueError:
        return "Oracle probe has invalid shell quoting."
    if not parts or any(part in (";", "&&", "||", "|", "&", ">", ">>", "<", "<<") for part in parts):
        return "Oracle probe must be a single command without shell operators."
    tool = Path(parts[0]).name.lower()
    if tool not in {"nmap", "nxc", "netexec", "crackmapexec", "smbclient", "rpcclient", "curl", "ldapsearch"}:
        return "Oracle probe tool is outside the read-only allowlist."
    if parts[0].lower() != tool:
        return "Oracle probe must use an installed Kali tool by name."
    if session["target"] not in command:
        return "Oracle probe must name the exact authorized target."
    forbidden_by_tool = {
        "nxc": {"-x", "-X", "--exec-method", "--put-file", "--sam", "--ntds", "--lsa",
                "--passwords", "-P"},
        "netexec": {"-x", "-X", "--exec-method", "--put-file", "--sam", "--ntds", "--lsa",
                    "--passwords", "-P"},
        "crackmapexec": {"-x", "-X", "--exec-method", "--put-file", "--sam", "--ntds",
                         "--lsa", "--passwords", "-P"},
        "nmap": {"--script", "--script-args", "-oX", "-oN", "-oA"},
        "curl": {"-X", "--request", "--data", "--data-binary", "-d", "-F",
                 "--upload-file", "-T", "-o", "-O", "--output", "--output-dir"},
    }
    forbidden = forbidden_by_tool.get(tool, set())
    if any(part in forbidden for part in parts[1:]):
        return "Oracle probe includes an action outside read-only discovery."
    if tool == "smbclient":
        commands = [parts[i + 1] for i, part in enumerate(parts[:-1]) if part == "-c"]
        if not commands or any(not all(piece.strip().lower() in ("ls", "dir", "recurse on")
                                   for piece in value.split(";") if piece.strip()) for value in commands):
            return "Oracle smbclient probe may only list files."
    if tool == "rpcclient":
        commands = [parts[i + 1] for i, part in enumerate(parts[:-1]) if part == "-c"]
        if not commands or any(";" in value or not value.split() or value.split()[0].lower() not in
                               {"enumdomusers", "enumdomgroups", "queryuser", "srvinfo",
                                "netshareenum", "netshareenumall"} for value in commands):
            return "Oracle rpcclient probe may only enumerate or query."
    if tool in {"nxc", "netexec", "crackmapexec"} and not any(
            part in ("--shares", "--users", "--rid-brute") for part in parts):
        return "Oracle SMB probe must request shares, users, or RID enumeration."
    return harp.local_command_issue(command, session["target"], objective,
                                    session.get("observations", []))


def oracle_history(run_dir: Path) -> dict:
    """Restore bounded oracle state when an operator resumes an active session."""
    history = {"cycles": 0, "objectives": set(), "probes": set(),
               "rejections": 0, "recovery_streak": 0, "probe_feedback": None}
    path = run_dir / "events.jsonl"
    if not path.is_file():
        return history
    last_stop = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        if kind == "oracle_nim_request":
            history["cycles"] += 1
            last_stop = None
        elif kind == "delegation" and isinstance(event.get("objective"), str):
            history["objectives"].add(event["objective"])
        elif kind == "oracle_nim_probe" and isinstance(event.get("command"), str):
            history["probes"].add(event["command"])
        elif kind == "oracle_nim_probe_rejected":
            history["rejections"] += 1
            history["probe_feedback"] = {"reason": event.get("reason", "Probe rejected")}
        elif kind == "oracle_nim_recovery":
            history["recovery_streak"] = int(event.get("attempt", 1))
        elif kind == "delegation_stopped" and event.get("reason") not in RECOVERABLE_STOPS:
            history["recovery_streak"] = 0
        elif kind == "oracle_nim_stopped":
            last_stop = event
    if last_stop and last_stop.get("reason") == "probe_rejected":
        history["probe_feedback"] = {"reason": last_stop.get("detail", "Probe rejected")}
    return history


def run(run_dir: Path) -> None:
    session = harp.load_session(run_dir)
    cfg = session["config"].get("oracle", {})
    model = cfg["model"]
    history = oracle_history(run_dir)
    prior = history["objectives"]
    recovery_streak = history["recovery_streak"]
    oracle_probes = history["probes"]
    probe_rejections = history["rejections"]
    probe_feedback: dict | None = history["probe_feedback"]
    for cycle in range(history["cycles"], int(cfg.get("max_cycles", 12))):
        session = harp.load_session(run_dir)
        if session["status"] != "active" or (run_dir / ".stop_session").exists() or (run_dir / ".stop_local").exists():
            return
        flags = harp_artifacts.flag_status(run_dir)
        if all(flags.get(name, {}).get("found") for name in ("user.txt", "root.txt")):
            harp.finish_session(run_dir, "yes")
            return
        observations = [{"command": x.get("command"), "exit_code": x.get("exit_code"),
                         "output": x.get("output", "")[-1200:]}
                        for x in session["observations"][-2:]]
        context = {"target": session["target"], "objective": session["config"]["objective"],
                   "recon": session.get("recon", []), "http_probes": session.get("http_probes", []),
                   "smb_probes": compact_smb_probes(session.get("smb_probes", [])),
                   "observations": observations, "last_stop": session.get("last_delegate_stop"),
                   "flags_found": {name: bool(flags.get(name, {}).get("found"))
                                   for name in ("user.txt", "root.txt")}, "cycle": cycle + 1}
        if probe_feedback:
            context["probe_feedback"] = probe_feedback
        model_options = oracle_model_options(model)
        harp.append_event(run_dir, {"type": "oracle_nim_request", "model": model,
                                    "cycle": cycle + 1})
        request_started = time.monotonic()
        reply = request("/chat/completions", {"model": model, "stream": False,
            "max_tokens": min(int(cfg.get("max_tokens", 1024)), 1024)
                          if model_options else int(cfg.get("max_tokens", 1024)),
            **model_options,
            "messages": [{"role": "system", "content":
                "You are the HARP oracle for an authorized lab. Review evidence and choose one bounded "
                "objective for the local worker. Never claim a flag without terminal evidence. "
                "Return only JSON with keys plan (short operator-facing sentence), objective "
                "(specific bounded task), stop (boolean), and optional oracle_command. "
                "If the worker stopped after failed commands, assess the terminal evidence and "
                "choose a corrected objective. You may instead return one nonroot, read-only "
                "oracle_command against the exact target to resolve uncertainty; leave objective "
                "empty in that case. Never repeat a failed command or guess passwords. "
                "If probe_feedback is present, correct the rejected probe or delegate a different "
                "bounded task; a rejected probe has not run. "
                "Copy any authentication limits from the plan into the objective. Stop only when "
                "blocked, repeated after correction, or no evidence-backed step remains."},
                {"role": "user", "content": json.dumps(context)}]})
        usage = reply.get("usage") or {}
        choice = reply["choices"][0]
        message = choice.get("message") or {}
        content = message.get("content") or ""
        harp.append_event(run_dir, {"type": "oracle_nim_usage", "model": model,
            "input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens"),
            "seconds": round(time.monotonic() - request_started, 2),
            "finish_reason": choice.get("finish_reason"), "content_chars": len(content),
            "reasoning_chars": len(message.get("reasoning_content") or "")})
        if (run_dir / ".stop_session").exists():
            harp.append_event(run_dir, {"type": "oracle_nim_stopped", "reason": "operator_stop"})
            return
        if not content.strip():
            harp.append_event(run_dir, {"type": "oracle_nim_stopped", "reason": "empty_model_reply",
                                        "model": model, "finish_reason": choice.get("finish_reason"),
                                        "output_tokens": usage.get("completion_tokens")})
            return
        decision = harp.json_object(content)
        plan = str(decision.get("plan", "")).strip()[:1000]
        objective = bound_objective(plan, str(decision.get("objective", "")).strip()[:1000])
        proposed_command = decision.get("oracle_command")
        oracle_command = proposed_command.strip() if isinstance(proposed_command, str) else ""
        if plan:
            harp.append_event(run_dir, {"type": "oracle_plan", "plan": plan})
        if decision.get("stop"):
            harp.append_event(run_dir, {"type": "oracle_nim_stopped", "reason": "model_stop"})
            return
        if oracle_command:
            issue = ("Oracle probes are available only after a worker failure."
                     if session.get("last_delegate_stop") not in RECOVERABLE_STOPS else
                     oracle_probe_issue(oracle_command, session, plan + " " + objective))
            if oracle_command in oracle_probes:
                issue = "Repeated oracle probe; use the previous result to replan."
            if issue:
                probe_rejections += 1
                probe_feedback = {"rejected_command": oracle_command, "reason": issue}
                harp.append_event(run_dir, {"type": "oracle_nim_probe_rejected",
                                            "reason": issue, "attempt": probe_rejections})
                continue
            probe_feedback = None
            oracle_probes.add(oracle_command)
            harp.append_event(run_dir, {"type": "oracle_nim_probe", "command": oracle_command})
            harp.direct_exec(run_dir, oracle_command, quiet=True)
            continue
        if not objective or objective in prior:
            harp.append_event(run_dir, {"type": "oracle_nim_stopped", "reason": "missing_or_repeated_objective"})
            return
        probe_feedback = None
        prior.add(objective)
        harp.delegate(run_dir, objective, min(int(cfg.get("steps_per_cycle", 6)),
                    int(session["config"]["max_steps"])), quiet=True)
        session = harp.load_session(run_dir)
        stop_reason = session.get("last_delegate_stop")
        if session.get("pending_root_command") or stop_reason in FATAL_STOPS:
            harp.append_event(run_dir, {"type": "oracle_nim_stopped",
                                        "reason": stop_reason})
            return
        if stop_reason in RECOVERABLE_STOPS:
            recovery_streak += 1
            harp.append_event(run_dir, {"type": "oracle_nim_recovery", "reason": stop_reason,
                                        "attempt": recovery_streak})
        else:
            recovery_streak = 0
    harp.append_event(run_dir, {"type": "oracle_nim_stopped", "reason": "cycle_budget"})
