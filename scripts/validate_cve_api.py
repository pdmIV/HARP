"""Explicit, bounded CVE API validation outside assessment sessions. No model calls."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import socket
import time
import urllib.error
import uuid

import harp_cve


def cases_from(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = document["cases"]
    if document.get("schema") != 1 or not isinstance(cases, list) or not 1 <= len(cases) <= 12:
        raise ValueError("Require schema 1 with one through twelve public cases")
    identities = set()
    for case in cases:
        if case["id"] in identities or case.get("expect") not in ("hit", "empty", "observe"):
            raise ValueError("Cases require unique IDs and hit/empty/observe expectations")
        identities.add(case["id"])
        if ("input" in case) == ("wire_query" in case):
            raise ValueError("A case requires exactly one input or historical wire_query")
        if case["expect"] == "hit" and not case.get("expected_cves"):
            raise ValueError("Retrieval assertions require expected CVEs")
        body = case_body(case)
        if (len(body["query"]) > 700 or re.search(r"(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b|\.htb\b|hackthebox|user\.txt|root\.txt|\b[0-9a-f]{32}\b|sk-[\w-]+|[?*]", body["query"])):
            raise ValueError("Validation cases must contain bounded public technical terms only")
        if any(identity.casefold() in body["query"].casefold() for identity in case.get("expected_cves", [])):
            raise ValueError("Do not supply expected CVEs as discovery hints")
    return cases


def case_body(case, refine=False):
    if "wire_query" in case:
        if refine:
            raise ValueError("Historical wire replays are not refined")
        return {"query": case["wire_query"], "from": 0, "size": 3,
                "sort": {"property": "relevancy", "order": "desc"}}
    return harp_cve.request_body(case["input"], refine=refine)


def error_kind(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, TimeoutError):
        return "timeout"
    if isinstance(error, (socket.gaierror, urllib.error.URLError)):
        return "network_unavailable"
    if isinstance(error, TimeoutError):
        return "timeout"
    found = re.search(r"HTTP (\d{3})", str(error))
    if found:
        return "rate_limited" if found[1] == "429" else "http_error"
    return "response_contract_error"


def run_case(case, *, pause=lambda: None):
    attempts = []
    refine = False
    while True:
        body = case_body(case, refine)
        attempt = {"phase": "refinement" if refine else "primary", "request": body}
        pause()
        started = time.monotonic()
        try:
            # Current cases go through the public production adapter; historical
            # comparisons share its exact transport and response validation.
            report = (harp_cve._search_request(body) if "wire_query" in case else
                      harp_cve.search(case["input"], refine=refine))
            rows = harp_cve.records(report)
            attempt.update(status="completed", results_total=report["resultsTotal"],
                           metadata=report["searchMetadata"],
                           ids=[row["advisory"]["cve_id"] for row in rows],
                           candidates=[{"cve_id": row["advisory"]["cve_id"], "title": row["title"],
                                        "description": row.get("content", ""),
                                        "affected": row["advisory"].get("affected", []),
                                        "scores": row["advisory"].get("scores", []),
                                        "applicability": "unverified"} for row in rows],
                           response_sha256=hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest())
        except KeyboardInterrupt:
            attempt.update(status="interrupted", error_kind="operator_interrupt",
                           error="Operator interrupted the request; upstream completion is unknown")
        except Exception as error:
            attempt.update(status="failed", error_kind=error_kind(error), error=str(error)[:500])
        attempt["seconds"] = round(time.monotonic() - started, 3)
        attempts.append(attempt)
        if (attempt["status"] != "completed" or attempt["results_total"] != 0 or refine or
                not isinstance(case.get("input"), dict) or
                not harp_cve.query_plan(**case["input"])["refinement"]):
            break
        refine = True
    final = attempts[-1]
    expected = set(case.get("expected_cves", []))
    rank = next((i + 1 for i, identity in enumerate(final.get("ids", [])) if identity in expected), None)
    transport_ok = all(a["status"] == "completed" for a in attempts)
    retrieval_ok = (rank is not None if case["expect"] == "hit" else
                    final.get("results_total") == 0 if case["expect"] == "empty" else None)
    retrieval_issue = None
    if transport_ok and case["expect"] == "hit" and not retrieval_ok:
        retrieval_issue = "positive_results_missing_expected_advisory" if final["results_total"] else "zero_results_after_allowed_searches"
    return {"case": case["id"], "expect": case["expect"], "required": case["expect"] != "observe", "provenance": case.get("provenance"),
            "expected_cves": sorted(expected), "expected_rank": rank,
            "transport_contract_ok": transport_ok, "retrieval_expectation_met": retrieval_ok,
            "retrieval_issue": retrieval_issue,
            "refinement_skipped_reason": "positive_response" if len(attempts) == 1 and final.get("results_total", 0) else None,
            "passed": transport_ok and retrieval_ok is not False, "attempts": attempts}


def run(cases, *, rounds=2, interval=1, progress=None):
    if not 1 <= rounds <= 3:
        raise ValueError("Rounds must be 1 through 3")
    results, blocked, last_request = [], None, None
    def pause():
        nonlocal last_request
        if last_request is not None:
            time.sleep(max(0, interval - (time.monotonic() - last_request)))
        last_request = time.monotonic()
    try:
        for round_index in range(rounds):
            for case in (cases if round_index % 2 == 0 else list(reversed(cases))):
                row = {"round": round_index + 1, **run_case(case, pause=pause)}
                results.append(row)
                if progress:
                    progress(row)
                failures = [a for a in row["attempts"] if a["status"] != "completed"]
                if failures and failures[-1]["error_kind"] in ("network_unavailable", "rate_limited", "operator_interrupt"):
                    blocked = failures[-1]["error_kind"]
                    break
            if blocked:
                break
    except KeyboardInterrupt:
        blocked = "operator_interrupt"
    complete = len(results) == rounds * len(cases)
    required_failures = sum(row["required"] and not row["passed"] for row in results)
    diagnostic_errors = sum(not row["required"] and not row["transport_contract_ok"] for row in results)
    status = ("interrupted" if blocked == "operator_interrupt" else "blocked" if blocked else
              "failed" if not complete or required_failures else
              "passed_with_diagnostic_errors" if diagnostic_errors else "passed")
    return {"schema": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "endpoint": harp_cve.ENDPOINT,
            "adapter_sha256": hashlib.sha256(Path(harp_cve.__file__).read_bytes()).hexdigest(),
            "status": status,
            "complete": complete, "blocked_reason": blocked, "rounds_planned": rounds,
            "case_ids_planned": [case["id"] for case in cases],
            "case_runs_planned": rounds * len(cases), "case_runs_completed": len(results),
            "request_attempts": sum(len(row["attempts"]) for row in results),
            "failed_case_runs": sum(not row["passed"] for row in results),
            "failed_required_case_runs": required_failures, "diagnostic_error_case_runs": diagnostic_errors,
            "results": results,
            "limits": "A live validation snapshot, not a guarantee of future availability or ranking. Historical wire cases are diagnostic. Rounds are explicitly planned repeatability measurements; there are no hidden per-attempt retries, paging, models, paid fallback, target commands or assessment-session mutations."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("tests/fixtures/cve_api_cases.json"))
    parser.add_argument("--live", action="store_true", help="Actually send public requests; otherwise print the request plan only")
    parser.add_argument("--rounds", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--interval", type=float, default=1, help="Minimum seconds between requests (0.5 through 10)")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not 0.5 <= args.interval <= 10:
        parser.error("interval must be 0.5 through 10 seconds")
    cases = cases_from(args.cases)
    if not args.live:
        print(json.dumps({"status": "not_run", "rounds": args.rounds,
            "requests": [{"case": c["id"], "primary": case_body(c)} for c in cases]}, indent=2))
        return 0
    output = args.output or Path("runs/cve-api-validation") / (datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]) / "report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    journal = output.with_suffix(".jsonl")
    journal.write_text("", encoding="utf-8")
    def progress(row):
        with journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row) + "\n")
        outcome = row["attempts"][-1]
        label = ("OBSERVED" if row["passed"] else "OBSERVED ERROR") if not row["required"] else "PASS" if row["passed"] else "FAIL"
        print(f'Round {row["round"]} {row["case"]}: {label}; total={outcome.get("results_total")}; '
              f'IDs={outcome.get("ids", [])}; {outcome.get("error") or row.get("retrieval_issue") or ""}', flush=True)
    report = run(cases, rounds=args.rounds, interval=args.interval, progress=progress)
    report["fixture_sha256"] = hashlib.sha256(args.cases.read_bytes()).hexdigest()
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f'{report["status"].upper()}: {report["request_attempts"]} request attempts; {report["case_runs_completed"]}/{report["case_runs_planned"]} case runs; '
          f'{report["failed_required_case_runs"]} required failures, {report["diagnostic_error_case_runs"]} diagnostic errors. Report: {output.resolve()}')
    return 0 if report["status"] in ("passed", "passed_with_diagnostic_errors") else 130 if report["status"] == "interrupted" else 2 if report["status"] == "blocked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
