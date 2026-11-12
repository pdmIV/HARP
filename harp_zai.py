"""Z.AI standard API transport for HARP oracle and proxy requests."""

import json
import math
import os
import queue
import threading
import time
from pathlib import Path
import urllib.error
import urllib.request

import harp_openai
import harp_secret
import harp_paths
import harp_effort

BASE = "https://api.z.ai/api/paas/v4"
MODELS = ("glm-5.3", "glm-5.3-flash")
MAX_REQUEST_SECONDS = 1800
PROXY_FIRST_OUTPUT_SECONDS = 120
STREAM_IDLE_SECONDS = 60
PROXY_REQUEST_SECONDS = 600
PROGRESS_INTERVAL_SECONDS = 5
WATCH_INTERVAL_SECONDS = 0.25


def validate(config: dict) -> None:
    if config.get("model") not in MODELS:
        raise ValueError("Choose glm-5.3 or glm-5.3-flash for Z.AI")
    if config.get("reasoning_effort", "low") not in ("low", "high", "max"):
        raise ValueError("Z.AI reasoning effort must be low, high, or max")
    if "temperature" in config:
        try:
            temperature = float(config["temperature"])
        except (TypeError, ValueError) as error:
            raise ValueError("Z.AI temperature must be 0 through 2") from error
        if not math.isfinite(temperature) or not 0 <= temperature <= 2:
            raise ValueError("Z.AI temperature must be 0 through 2")
    if "top_p" in config:
        try:
            top_p = float(config["top_p"])
        except (TypeError, ValueError) as error:
            raise ValueError("Z.AI top_p must be greater than 0 and at most 1") from error
        if not math.isfinite(top_p) or not 0 < top_p <= 1:
            raise ValueError("Z.AI top_p must be greater than 0 and at most 1")
    # Reuse the provider-neutral price checks without OpenAI access/cache settings.
    harp_openai.validate({"model": config["model"], **{
        field: config[field] for field in harp_openai.PRICE_FIELDS if field in config}})


def key() -> str:
    value = os.environ.get("ZAI_API_KEY")
    if value:
        return value
    path = harp_paths.data_dir() / ".secrets" / "zai.key"
    if not path.is_file():
        raise ValueError("Import a Z.AI API key in API Keys or set ZAI_API_KEY")
    return harp_secret.load_key(path)


def models() -> list[str]:
    """Documented model presets, not a claim about account entitlement."""
    return list(MODELS)


def response_body(config: dict, body: dict) -> dict:
    validate(config)
    payload = {"model": config["model"], "messages": body["messages"], "stream": True,
            "response_format": {"type": "json_object"},
            "max_tokens": int(body.get("max_tokens", config.get("max_tokens", 8192))),
            "thinking": {"type": "enabled"},
            "reasoning_effort": config.get("reasoning_effort", "low")}
    if "temperature" in config:
        payload["temperature"] = float(config["temperature"])
    if "top_p" in config:
        payload["top_p"] = float(config["top_p"])
    return payload


def streamed_completion(response, *, cancelled=None, progress=None) -> dict:
    """Assemble one complete SSE reply; never expose a partial action to HARP."""
    content, reasoning = [], []
    finish_reason, usage = None, {}
    started = time.monotonic()
    data_lines = []

    def event_data():
        nonlocal finish_reason, usage
        value = "\n".join(data_lines)
        data_lines.clear()
        if value == "[DONE]":
            if finish_reason is None:
                raise ConnectionError("Z.AI stream ended without a completed choice")
            if finish_reason == "network_error":
                raise ConnectionError("Z.AI stream reported a network error; no model action was accepted")
            if finish_reason not in ("stop", "length"):
                raise RuntimeError("Z.AI completion did not finish normally; no model action was accepted")
            return True
        try:
            event = json.loads(value)
            if event.get("error"):
                raise RuntimeError("Z.AI streaming response failed; no model action was accepted")
            if event.get("usage"):
                usage = event["usage"]
            for choice in event.get("choices") or []:
                if choice.get("index", 0) != 0:
                    continue
                delta = choice.get("delta") or {}
                for key, parts in (("content", content), ("reasoning_content", reasoning)):
                    if isinstance(delta.get(key), str):
                        parts.append(delta[key])
                        if delta[key] and progress:
                            progress(key, len(delta[key]))
                if choice.get("finish_reason") is not None:
                    finish_reason = choice["finish_reason"]
        except (ValueError, TypeError, AttributeError):
            raise RuntimeError("Z.AI returned an invalid stream; no model action was accepted") from None
        return False

    for raw in response:
        if cancelled and cancelled():
            raise InterruptedError("Model request stopped by operator")
        if time.monotonic() - started > MAX_REQUEST_SECONDS:
            raise TimeoutError("Z.AI completion exceeded the request deadline")
        line = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        line = line.rstrip("\r\n")
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip(" "))
        elif not line and data_lines and event_data():
            return {"choices": [{"message": {"content": "".join(content),
                    "reasoning_content": "".join(reasoning)}, "finish_reason": finish_reason}], "usage": usage}
    # Some providers omit the final blank line after [DONE].
    if data_lines and event_data():
        return {"choices": [{"message": {"content": "".join(content),
                "reasoning_content": "".join(reasoning)}, "finish_reason": finish_reason}], "usage": usage}
    raise ConnectionError("Z.AI stream was interrupted; no model action was accepted")


def chat(config: dict, body: dict, *, cancelled=None, on_progress=None) -> dict:
    """Watch actual model output independently of blocking HTTP reads/heartbeats."""
    payload = response_body(config, body)
    req = urllib.request.Request(BASE + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + key(), "Content-Type": "application/json",
                 "Accept": "text/event-stream"})
    oracle = body.get("harp_role") == "oracle"
    first_limit = (harp_effort.read_timeout_seconds(payload["reasoning_effort"])
                   if oracle else PROXY_FIRST_OUTPUT_SECONDS)
    total_limit = MAX_REQUEST_SECONDS if oracle else PROXY_REQUEST_SECONDS
    started = time.monotonic()
    lock = threading.Lock()
    aborted = threading.Event()
    result = queue.Queue(maxsize=1)
    state = {"phase": "waiting", "reasoning_chars": 0, "content_chars": 0,
             "last_output": None, "response": None}

    def progress(kind, count):
        with lock:
            state["phase"] = "reasoning" if kind == "reasoning_content" else "responding"
            state["reasoning_chars" if kind == "reasoning_content" else "content_chars"] += count
            state["last_output"] = time.monotonic()

    def receive():
        try:
            # The watchdog also covers connecting and fallback JSON reads. The
            # socket timeout bounds abandoned readers if closing a response blocks.
            with urllib.request.urlopen(req, timeout=max(first_limit, STREAM_IDLE_SECONDS)) as response:
                with lock:
                    state["response"] = response
                if aborted.is_set():
                    return
                content_type = getattr(response, "headers", {}).get("Content-Type", "")
                data = (streamed_completion(response, cancelled=aborted.is_set, progress=progress)
                        if "text/event-stream" in content_type else json.load(response))
                if data.get("error") or not data.get("choices"):
                    raise RuntimeError("Z.AI returned no completion; no model action was accepted")
            result.put((data, None))
        except urllib.error.HTTPError as error:
            # Never expose provider bodies, which can echo secrets/evidence.
            result.put((None, RuntimeError(f"Z.AI returned HTTP {error.code}")))
        except Exception as error:
            result.put((None, error))

    def report(phase=None, reason=None):
        if on_progress:
            with lock:
                now = time.monotonic()
                event = {"phase": phase or state["phase"],
                         "reasoning_chars": state["reasoning_chars"], "content_chars": state["content_chars"],
                         "seconds": round(now - started, 2),
                         "idle_seconds": round(now - (state["last_output"] if state["last_output"] is not None else started), 2)}
            if reason:
                event["reason"] = reason
            if phase in ("cancelled", "timed_out", "failed"):
                event["usage_unknown"] = True
            on_progress(event)

    report()
    if cancelled and cancelled():
        report("cancelled")
        raise InterruptedError("Model request stopped by operator")
    threading.Thread(target=receive, name="harp-zai-reader", daemon=True).start()
    last_report, last_phase = started, "waiting"
    try:
        while True:
            if cancelled and cancelled():
                report("cancelled")
                raise InterruptedError("Model request stopped by operator")
            now = time.monotonic()
            with lock:
                last_output, phase = state["last_output"], state["phase"]
            reason = ("request_deadline" if now - started >= total_limit else
                      "first_output_timeout" if last_output is None and now - started >= first_limit else
                      "stream_idle_timeout" if last_output is not None and now - last_output >= STREAM_IDLE_SECONDS else None)
            if reason:
                report("timed_out", reason)
                raise TimeoutError(f"Z.AI {reason}; no model action was accepted")
            if phase != last_phase or now - last_report >= PROGRESS_INTERVAL_SECONDS:
                report()
                last_report, last_phase = now, phase
            try:
                data, error = result.get(timeout=WATCH_INTERVAL_SECONDS)
            except queue.Empty:
                continue
            # Stop/deadline checks must also apply to a reply received while waiting.
            if cancelled and cancelled():
                report("cancelled")
                raise InterruptedError("Model request stopped by operator")
            if error:
                report("failed", "transport_error")
                raise error
            if time.monotonic() - started >= total_limit:
                report("timed_out", "request_deadline")
                raise TimeoutError("Z.AI request_deadline; no model action was accepted")
            report("completed")
            return data
    finally:
        aborted.set()
        with lock:
            response = state["response"]
        # HTTPResponse.close can wait on a blocked readline lock. Never let it
        # block cancellation or the watchdog on the orchestration thread.
        if response is not None:
            threading.Thread(target=response.close, name="harp-zai-close", daemon=True).start()


def usage_metrics(config: dict, usage: dict) -> dict:
    return harp_openai.usage_metrics(config, usage)
