"""Z.AI standard API transport for HARP oracle and proxy requests."""

import json
import math
import os
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


def streamed_completion(response, *, cancelled=None) -> dict:
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


def chat(config: dict, body: dict, *, cancelled=None) -> dict:
    payload = response_body(config, body)
    req = urllib.request.Request(BASE + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + key(), "Content-Type": "application/json",
                 "Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=harp_effort.read_timeout_seconds(payload["reasoning_effort"])) as response:
            # Retain compatibility if a gateway returns a complete JSON response.
            content_type = getattr(response, "headers", {}).get("Content-Type", "")
            data = (streamed_completion(response, cancelled=cancelled)
                    if "text/event-stream" in content_type else json.load(response))
    except urllib.error.HTTPError as error:
        # Provider error bodies can echo credentials or target evidence.
        raise RuntimeError(f"Z.AI returned HTTP {error.code}") from None
    if data.get("error") or not data.get("choices"):
        raise RuntimeError("Z.AI returned no completion; no model action was accepted")
    return data


def usage_metrics(config: dict, usage: dict) -> dict:
    return harp_openai.usage_metrics(config, usage)
