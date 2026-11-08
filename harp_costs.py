"""Display-time pricing of recorded usage. Never rewrites session ledgers."""
import math

PRICE_FIELDS = ("input_usd_per_million", "cached_input_usd_per_million",
                "cache_write_usd_per_million", "output_usd_per_million")


def price_calls(calls: list[dict], rates: dict, model: str | None, *, recorded_fallback: bool = True) -> float | None:
    if not calls:
        return 0.0
    costs = []
    for call in calls:
        # Do not price missing usage as a zero-token request.
        if call.get("usage_reported") is False or not all(key in call for key in ("prompt_tokens", "completion_tokens")):
            costs.append(None)
            continue
        if call.get("model", model) != model:
            costs.append(call.get("estimated_usd") if recorded_fallback else None)
            continue
        total = max(0, int(call.get("prompt_tokens") or 0))
        cached = min(total, max(0, int(call.get("cached_input_tokens") or 0)))
        written = min(total - cached, max(0, int(call.get("cache_write_tokens") or 0)))
        counts = (total - cached - written, cached, written,
                  max(0, int(call.get("completion_tokens") or 0)))
        if not any(rate is not None for rate in rates.values()):
            costs.append(call.get("estimated_usd") if recorded_fallback else None)
            continue
        cost = 0
        for field, count in zip(PRICE_FIELDS, counts):
            if not count:
                continue
            try:
                rate = float(rates[field])
                if not math.isfinite(rate) or rate < 0:
                    raise ValueError("Invalid rate")
            except (TypeError, ValueError):
                cost = None
                break
            cost += count * rate / 1_000_000
        costs.append(cost)
    return sum(costs) if all(cost is not None for cost in costs) else None


def cost_summary(session: dict, current_config: dict) -> dict:
    result = {}
    selected_rates = {}
    for role, prefix, ledger in (("oracle", "oracle", "oracle_calls"),
                                 ("local", "local", "local_calls")):
        original = session.get("config", {}).get(role, {})
        rates = {field: original.get(field) for field in PRICE_FIELDS}
        candidates = [current_config.get(key, {}) for key in (role, "local" if role == "oracle" else "oracle")]
        match = next((candidate for candidate in candidates if original.get("model")
                      and candidate.get("model") == original.get("model")
                      and candidate.get("provider", "unsloth" if role == "local" else "codex")
                      == original.get("provider", "unsloth" if role == "local" else "codex")), None)
        basis = "session_prices"
        if match and any(match.get(field) is not None for field in PRICE_FIELDS):
            rates = {field: match.get(field) for field in PRICE_FIELDS}
            basis = "current_configured_prices"
        calls = session.get(ledger, [])
        cost = price_calls(calls, rates, original.get("model"))
        result[prefix + "_estimated_usd"] = round(cost, 6) if calls and cost is not None else None
        if not any(rate is not None for rate in rates.values()):
            basis = "recorded_estimate"
        selected_rates[role] = rates
        result[prefix + "_cost_basis"] = basis
    oracle_calls = session.get("oracle_calls", [])
    proxy_calls = session.get("local_calls", [])
    oracle_cost = result["oracle_estimated_usd"] if oracle_calls else 0
    proxy_cost = result["local_estimated_usd"] if proxy_calls else 0
    total = oracle_cost + proxy_cost if oracle_cost is not None and proxy_cost is not None else None
    result.update(total_estimated_usd=round(total, 6) if total is not None else None,
                  oracle_only_estimated_usd=None, hybrid_savings_usd=None,
                  hybrid_savings_percent=None, cost_comparison_status="not_hybrid")
    if session.get("mode", "hybrid") == "hybrid" and proxy_calls:
        # Reprice proxy work at oracle rates, retaining recorded planning work and cache mix.
        reassigned = [{**call, "model": session.get("config", {}).get("oracle", {}).get("model")}
                      for call in proxy_calls]
        counterfactual = price_calls(reassigned, selected_rates["oracle"],
            session.get("config", {}).get("oracle", {}).get("model"), recorded_fallback=False)
        result["cost_comparison_status"] = "missing_prices_or_usage"
        if counterfactual is not None and oracle_cost is not None and total is not None:
            baseline = oracle_cost + counterfactual
            saving = baseline - total
            result.update(oracle_only_estimated_usd=round(baseline, 6),
                          hybrid_savings_usd=round(saving, 6),
                          hybrid_savings_percent=round(100 * saving / baseline, 2) if baseline else None,
                          cost_comparison_status="same_workload_estimate")
    return result
