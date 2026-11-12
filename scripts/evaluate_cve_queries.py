"""Score saved CVE search captures offline; never call a model, provider or target."""
import argparse
import json
from pathlib import Path


def score(case, capture):
    attempts = capture.get("attempts")
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= 2:
        raise ValueError("A query capture requires one or two separately recorded attempts")
    expected = set(case["expected_cves"])
    unrelated = set(case.get("unrelated_cves", []))
    rankings, errors, seconds = [], 0, []
    for attempt in attempts:
        if not isinstance(attempt, dict) or not isinstance(attempt.get("results", []), list):
            raise ValueError("Attempts require a results list from a saved research task")
        ids = []
        for row in attempt.get("results", [])[:3]:
            identity = (row.get("advisory") or {}).get("cve_id")
            ids.extend([identity] if identity else row.get("cve_ids", []))
        rankings.append(next((i + 1 for i, identity in enumerate(ids[:3]) if identity in expected), None))
        errors += bool(attempt.get("error") or attempt.get("status") in ("failed", "interrupted"))
        duration = attempt.get("seconds")
        seconds.append(duration if type(duration) in (int, float) and duration >= 0 else None)
    final_ids = []
    for row in attempts[-1].get("results", [])[:3]:
        identity = (row.get("advisory") or {}).get("cve_id")
        final_ids.extend([identity] if identity else row.get("cve_ids", []))
    cost = capture.get("inference_cost_usd")
    if cost is not None and (type(cost) not in (int, float) or cost < 0):
        raise ValueError("Inference cost must be nonnegative or unknown")
    return {"case": case["id"], "synthetic": case.get("synthetic", False),
            "first_query_hit_at_3": rankings[0] is not None, "final_hit_at_3": rankings[-1] is not None,
            "final_expected_rank": rankings[-1], "unrelated_hits_at_3": sum(x in unrelated for x in final_ids[:3]),
            "search_requests": len(attempts), "search_errors": errors,
            "search_seconds": round(sum(seconds), 3) if all(x is not None for x in seconds) else None,
            "inference_cost_usd": cost}


def evaluate(cases, captures):
    indexed = {row["id"]: row for row in cases}
    results, seen = [], set()
    for capture in captures:
        identity = capture.get("case")
        if identity not in indexed or identity in seen:
            raise ValueError("Captures must name a known case exactly once")
        seen.add(identity)
        results.append(score(indexed[identity], capture))
    count = len(results)
    costs = [row["inference_cost_usd"] for row in results]
    return {"evaluated": count, "missing_cases": sorted(set(indexed) - seen),
            "first_query_hit_at_3_rate": sum(row["first_query_hit_at_3"] for row in results) / count if count else None,
            "final_hit_at_3_rate": sum(row["final_hit_at_3"] for row in results) / count if count else None,
            "mean_search_requests": sum(row["search_requests"] for row in results) / count if count else None,
            "inference_cost_usd": sum(costs) if count and all(x is not None for x in costs) else None,
            "results": results,
            "limits": "Offline scoring of supplied captures, not a live retrieval or solve-rate benchmark. Missing costs remain unknown; fixture CVEs are never supplied to the oracle."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("tests/fixtures/cve_query_cases.json"))
    parser.add_argument("--responses", type=Path, required=True, help="JSONL: case, attempts (saved task objects), optional inference_cost_usd")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    report = evaluate(json.loads(args.cases.read_text(encoding="utf-8")),
                      [json.loads(line) for line in args.responses.read_text(encoding="utf-8").splitlines() if line.strip()])
    output = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0 if report["results"] and all(x["final_hit_at_3"] for x in report["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
