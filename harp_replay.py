"""Read-only reconstruction of a completed run for dashboard playback."""
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path

import harp
import harp_artifacts
import harp_costs
import harp_research
import harp_evidence


def build_replay(run_dir: Path, view: dict, pricing_config: dict | None = None) -> dict:
    original = harp.load_session(run_dir)
    if original.get("status") != "finished":
        raise ValueError("Replay is available only for finished sessions")
    state = deepcopy(original)
    for key in ("capability_ledger", "assessment_history", "prerequisite_ledger"):
        state.pop(key, None)
    state.update(status="recon", success="unknown", success_epoch=None, success_at=None,
                 time_to_success_seconds=None, duration_seconds=0, local_steps=0,
                 local_calls=[], oracle_calls=[], observations=[], recon=[], http_probes=[],
                 smb_probes=[], oracle_actions=0, root_approvals=0, recon_tool_calls=0,
                 review_wait_seconds=0, human_intervention_at=None, last_delegate_stop=None,
                 recon_finished_epoch=None, recon_stage="Preparing reconnaissance", recon_command=None,
                 success_before_human_intervention=False,
                 success_evidence=None, oracle_usage=None, pending_root_command=None)
    registry = {a["id"]: a for a in harp_artifacts.list_artifacts(run_dir)}
    artifacts = []
    activity = {"oracle_plan": None, "local_action": None,
                "delegated_objective": None, "oracle_stopped": None}
    flags = {name: {"found": False, "unseen": False} for name in harp_artifacts.FLAG_NAMES}
    frames = []
    elapsed = 0
    calls = iter(original.get("local_calls", []))
    research_calls = []
    def snapshot(event):
        summary = {**harp.summarize(state), **harp_costs.cost_summary(state, pricing_config or {})}
        summary["research_status"] = harp_research.activity_status(state, research_calls)
        summary["capability_evidence"] = harp_evidence.context(state)
        summary["recon_elapsed_seconds"] = max(0, round(
            (state.get("recon_finished_epoch") or state["started_epoch"] + elapsed)
            - state.get("recon_started_epoch", state["started_epoch"]), 2))
        return deepcopy({"seconds": elapsed, "event": event, "summary": summary,
                         "activity": activity, "recon": state["recon"],
                         "flags": flags, "artifacts": artifacts})
    frames.append(snapshot(None))
    with (run_dir / "events.jsonl").open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
                seconds = datetime.fromisoformat(event["at"]).timestamp() - state["started_epoch"]
            except (ValueError, KeyError, TypeError):
                continue
            elapsed = max(elapsed, seconds, 0)
            kind = event.get("type")
            result = event.get("result", {})
            if kind == "oracle_check":
                harp_evidence.record_check(state, event.get("check"))
            if kind in ("delegation_stopped", "oracle_probe_progress") and state.get("assessment_history"):
                harp_evidence.finish_check(state, state["assessment_history"][-1])
            if kind == "research_started":
                research_calls.append({"id": event.get("id"), "operation": event.get("operation"), "status": "started"})
            if kind == "research_completed":
                pending = next((call for call in reversed(research_calls) if call["id"] == event.get("id")
                                and call["operation"] == event.get("operation")), None)
                if pending is not None:
                    pending["status"] = event.get("status", "completed")
            if kind == "oracle_plan": activity["oracle_plan"] = event.get("plan")
            if kind in ("oracle_nim_request", "oracle_nim_resumed"):
                activity["oracle_stopped"] = None
            if kind == "delegation":
                activity["delegated_objective"] = event.get("objective")
                state["oracle_actions"] += 1
            if kind == "local_action": activity["local_action"] = event.get("action")
            if kind in ("local_action", "invalid_local_reply"):
                call = next(calls, None)
                if call: state["local_calls"].append(call)
            if kind == "oracle_nim_usage":
                state["oracle_calls"].append({**event, "prompt_tokens": event.get("input_tokens") or 0,
                                             "completion_tokens": event.get("output_tokens") or 0})
            if kind == "recon_command_started":
                state.update(recon_stage=event.get("stage"), recon_command=event.get("command"))
            if kind == "recon_command_finished":
                state["recon_tool_calls"] += 1
                state["recon_command"] = None
            if event.get("findings") is not None: state["recon"] = event["findings"]
            if kind == "recon_finished":
                state.update(status="active", recon_stage="Complete", recon_command=None,
                             recon_finished_epoch=state["started_epoch"] + elapsed)
            if kind == "human_intervention": state["human_intervention_at"] = event["at"]
            if kind == "command_review_decided": state["review_wait_seconds"] += event.get("wait_seconds", 0)
            if kind in ("local_terminal", "oracle_terminal", "approved_root_terminal"):
                state["observations"].append(result)
                if kind == "local_terminal": state["local_steps"] += 1
                else: state["oracle_actions"] += 1
                if kind == "approved_root_terminal": state["root_approvals"] += 1
                for name, value in harp_artifacts.flag_values_from_result(result):
                    artifact = next((a for a in registry.values() if a["kind"] == "flag"
                                     and a["title"] == name and a["value"] == value), None)
                    artifact = {**(artifact or {}), "id": (artifact or {}).get("id", "replay-" + name),
                                "kind": "flag", "title": name, "value": value, "at": event["at"],
                                "source": result.get("command"), "evidence_backed": True}
                    if not flags[name]["found"]:
                        artifacts.append(artifact)
                        flags[name] = {"found": True, "unseen": False,
                                       "artifact_id": artifact["id"], "at": event["at"]}
            if kind == "artifact_recorded" and event.get("id") in registry:
                artifact = registry[event["id"]]
                if not any(a["id"] == artifact["id"] for a in artifacts): artifacts.append(artifact)
                if artifact["kind"] == "flag" and artifact["title"] in flags:
                    flags[artifact["title"]] = {"found": True, "unseen": False,
                        "artifact_id": artifact["id"], "at": event["at"]}
            if kind == "delegation_stopped": state["last_delegate_stop"] = event.get("reason")
            if kind in ("oracle_nim_stopped", "oracle_nim_error"):
                activity["oracle_stopped"] = event.get("reason") or event.get("error")
            if all(f["found"] for f in flags.values()) and state["success_epoch"] is None:
                state.update(success="yes", success_epoch=state["started_epoch"] + elapsed,
                             time_to_success_seconds=round(elapsed, 2),
                             success_before_human_intervention=state["human_intervention_at"] is None)
            if kind == "verified_success" and state["success_epoch"] is None:
                state.update(success="yes", success_epoch=state["started_epoch"] + elapsed,
                             time_to_success_seconds=round(elapsed, 2),
                             success_evidence=event.get("evidence"))
            if kind == "finish":
                state.update(status="finished", duration_seconds=elapsed,
                             success="yes" if state["success"] == "yes" else event.get("success", "unknown"))
            frames.append(snapshot(event))
            if kind == "finish": break  # Ignore later annotations and reconciliation timestamps.
    if state["status"] != "finished":
        elapsed = max(elapsed, original.get("duration_seconds") or 0)
        state.update(status="finished", duration_seconds=elapsed)
        frames.append(snapshot(None))
    common = {key: value for key, value in view.items() if key not in
              ("events", "event_cursor", "summary", "activity", "flags", "artifacts", "recon", "http_probes", "smb_probes")}
    common.update(pending_approval=None, replay=True)
    return {"session": common, "frames": frames, "duration_seconds": elapsed}
