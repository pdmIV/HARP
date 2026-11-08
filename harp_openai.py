"""OpenAI Responses transport shared by the oracle and proxy."""

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import urllib.error
import urllib.request
from urllib.parse import urlparse

import harp_secret

BASE = "https://api.openai.com/v1"
PRICE_FIELDS = ("input_usd_per_million", "cached_input_usd_per_million",
                "cache_write_usd_per_million", "output_usd_per_million")
STABLE_FIELDS = ("target", "target_os", "objective", "recon", "http_probes", "smb_probes")


def validate(config: dict) -> None:
    url = urlparse(config.get("base_url", BASE))
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment):
        raise ValueError("OpenAI endpoint must be an HTTPS base URL without credentials, query, or fragment")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]*", str(config.get("model", ""))):
        raise ValueError("Choose an OpenAI model ID")
    if config.get("access_program", "daybreak_blue") not in ("standard", "daybreak_blue"):
        raise ValueError("Choose standard or daybreak_blue access")
    if config.get("prompt_cache_ttl", "30m") not in ("30m", "12h"):
        raise ValueError("OpenAI cache lifetime must be 30m or 12h")
    for field in PRICE_FIELDS:
        value = config.get(field)
        if value is not None and (not math.isfinite(float(value)) or float(value) < 0):
            raise ValueError("OpenAI token prices must be finite, nonnegative numbers")


def explicit_cache_supported(model: str) -> bool:
    """GPT-5.6+ uses explicit content-block breakpoints; older models do not."""
    match = re.match(r"^gpt-(\d+)(?:\.(\d+))?(?:[-/]|$)", model)
    return bool(match and (int(match[1]), int(match[2] or 0)) >= (5, 6))


def cache_messages(messages: list[dict]) -> tuple[list[dict], int | None]:
    """Keep evidence in user messages, separating fixed recon from working state."""
    result = copy.deepcopy(messages)
    boundary = len(result) - 2 if len(result) >= 2 else None
    if not result or result[-1].get("role") != "user":
        return result, boundary
    try:
        context = json.loads(result[-1]["content"])
    except (TypeError, ValueError, KeyError):
        return result, boundary
    if not isinstance(context, dict):
        return result, boundary
    stable = {key: context[key] for key in STABLE_FIELDS if key in context}
    if not stable:
        return result, boundary
    dynamic = {key: value for key, value in context.items() if key not in stable}
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    result[-1:] = [{"role": "user", "content": encode(stable)},
                   {"role": "user", "content": encode(dynamic)}]
    return result, len(result) - 2


def response_body(config: dict, body: dict) -> dict:
    messages, boundary = cache_messages(body["messages"])
    payload = {"model": config["model"], "input": messages,
               "max_output_tokens": int(body.get("max_tokens", 4096)), "store": False,
               "access_programs": {"cyber": config.get("access_program", "daybreak_blue")}}
    if body.get("reasoning_effort") is not None:
        payload["reasoning"] = {"effort": body["reasoning_effort"]}
    if boundary is not None:
        prefix = json.dumps(messages[:boundary + 1], sort_keys=True, separators=(",", ":"))
        identity = [config.get("base_url", BASE), config["model"],
                    config.get("access_program", "daybreak_blue"), body.get("harp_role", "proxy"), prefix]
        payload["prompt_cache_key"] = "harp-v1-" + hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:56]
        if explicit_cache_supported(config["model"]):
            message = messages[boundary]
            if isinstance(message.get("content"), str):
                message["content"] = [{"type": "input_text", "text": message["content"],
                                       "prompt_cache_breakpoint": {"mode": "explicit"}}]
                # Cache fixed instructions/recon only. Avoid paying to write changing observations.
                payload["prompt_cache_options"] = {"mode": "explicit",
                    "ttl": config.get("prompt_cache_ttl", "30m")}
    return payload


def usage_metrics(config: dict, usage: dict) -> dict:
    """Cost before account credits/complimentary allowances; unknown prices stay unknown."""
    details = usage.get("prompt_tokens_details") or {}
    total = int(usage.get("prompt_tokens") or 0)
    cached = min(total, max(0, int(details.get("cached_tokens") or 0)))
    written = min(total - cached, max(0, int(details.get("cache_write_tokens") or 0)))
    ordinary = total - cached - written
    output = int(usage.get("completion_tokens") or 0)
    counts = (ordinary, cached, written, output)
    known = bool(usage) and all(config.get(field) is not None for field, count in zip(PRICE_FIELDS, counts) if count)
    cost = (sum(count * float(config.get(field) or 0) for field, count in zip(PRICE_FIELDS, counts))
            / 1_000_000 if known else None)
    return {"cached_input_tokens": cached, "cache_write_tokens": written,
            "uncached_input_tokens": ordinary, "cache_usage_reported": bool(details),
            "cache_hit_fraction": cached / total if total else 0,
            "estimated_usd": cost, "pricing_complete": known,
            "cost_basis": "configured_rates_before_account_allowances"}


def key() -> str:
    value = os.environ.get("OPENAI_API_KEY")
    if value:
        return value
    path = Path(__file__).resolve().parent / ".secrets" / "openai.key"
    if not path.is_file():
        raise ValueError("Import an OpenAI API key in Configuration or set OPENAI_API_KEY")
    return harp_secret.load_key(path)


def request(config: dict, path: str, payload: dict | None = None) -> dict:
    validate({**config, "model": config.get("model") or "discovery"})
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(config.get("base_url", BASE).rstrip("/") + path,
        data=data, headers={"Authorization": "Bearer " + key(),
                            "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=240 if data else 30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Expose bounded diagnostic identifiers, never provider messages or raw bodies:
        # those can echo prompts, credentials, or other evidence.
        diagnostics = {}
        try:
            detail = json.loads(error.read(16384)).get("error", {})
            if isinstance(detail, dict):
                for field in ("code", "type", "param"):
                    value = detail.get(field)
                    if (isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:/\[\]-]{1,160}", value)
                            and not value.startswith("sk-")):
                        diagnostics[field] = value
        except (ValueError, AttributeError, OSError):
            pass
        request_id = (error.headers or {}).get("x-request-id", "")
        if re.fullmatch(r"[A-Za-z0-9_-]{1,120}", request_id):
            diagnostics["request_id"] = request_id
        suffix = "; " + json.dumps(diagnostics) if diagnostics else "; no structured error identifiers returned"
        raise RuntimeError(f"OpenAI returned HTTP {error.code}" + suffix) from None


def models(config: dict) -> list[str]:
    return sorted({item["id"] for item in request(config, "/models").get("data", [])
                   if isinstance(item, dict) and isinstance(item.get("id"), str)})


def chat(config: dict, body: dict) -> dict:
    """Normalize Responses output for HARP's existing evidence/usage consumers."""
    payload = response_body(config, body)
    data = request(config, "/responses", payload)
    if data.get("error") or data.get("status") in ("failed", "cancelled"):
        raise RuntimeError("OpenAI response failed; no model action was accepted")
    content = "".join(part.get("text", "") for item in data.get("output", [])
                      if item.get("type") == "message" for part in item.get("content", [])
                      if part.get("type") == "output_text")
    usage = data.get("usage") or {}
    return {"choices": [{"message": {"content": content},
                         "finish_reason": "length" if data.get("status") == "incomplete" else "stop"}],
            "usage": {"prompt_tokens": usage.get("input_tokens", 0),
                      "completion_tokens": usage.get("output_tokens", 0),
                      "prompt_tokens_details": usage.get("input_tokens_details") or {},
                      "completion_tokens_details": usage.get("output_tokens_details") or {}} if usage else {}}
