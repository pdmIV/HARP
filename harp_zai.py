"""Z.AI standard API transport for HARP oracle and proxy requests."""

import json
import os
from pathlib import Path
import urllib.error
import urllib.request

import harp_openai
import harp_secret

BASE = "https://api.z.ai/api/paas/v4"
MODELS = ("glm-5.3", "glm-5.3-flash")


def validate(config: dict) -> None:
    if config.get("model") not in MODELS:
        raise ValueError("Choose glm-5.3 or glm-5.3-flash for Z.AI")
    if config.get("reasoning_effort", "low") not in ("low", "high", "max"):
        raise ValueError("Z.AI reasoning effort must be low, high, or max")
    # Reuse the provider-neutral price checks without OpenAI access/cache settings.
    harp_openai.validate({"model": config["model"], **{
        field: config[field] for field in harp_openai.PRICE_FIELDS if field in config}})


def key() -> str:
    value = os.environ.get("ZAI_API_KEY")
    if value:
        return value
    path = Path(__file__).resolve().parent / ".secrets" / "zai.key"
    if not path.is_file():
        raise ValueError("Import a Z.AI API key in API Keys or set ZAI_API_KEY")
    return harp_secret.load_key(path)


def models() -> list[str]:
    """Documented model presets, not a claim about account entitlement."""
    return list(MODELS)


def response_body(config: dict, body: dict) -> dict:
    validate(config)
    return {"model": config["model"], "messages": body["messages"], "stream": False,
            "max_tokens": int(body.get("max_tokens", config.get("max_tokens", 8192))),
            "thinking": {"type": "enabled"},
            "reasoning_effort": config.get("reasoning_effort", "low")}


def chat(config: dict, body: dict) -> dict:
    payload = response_body(config, body)
    req = urllib.request.Request(BASE + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + key(), "Content-Type": "application/json",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=240) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        # Provider error bodies can echo credentials or target evidence.
        raise RuntimeError(f"Z.AI returned HTTP {error.code}") from None
    if data.get("error") or not data.get("choices"):
        raise RuntimeError("Z.AI returned no completion; no model action was accepted")
    return data


def usage_metrics(config: dict, usage: dict) -> dict:
    return harp_openai.usage_metrics(config, usage)
