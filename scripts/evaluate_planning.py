"""Score saved oracle decisions against synthetic cases, without network or target work."""
import argparse
import copy
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harp_evidence
import harp_research
import harp_strategy


def score(case, decision):
    session = copy.deepcopy(case["session"])
    card = harp_evidence.context(session)
    issue = harp_evidence.check_issue(decision, session)
    if not issue:
        issue = harp_research.review_issue(decision, session)
    if not issue and "research" not in decision:
        issue = harp_strategy.credential_test_issue(copy.deepcopy(decision), session.get("observations", []))
    action = (decision.get("check") or {}).get("action")
    required = case.get("required_observations", [])
    retained = all(any(row["operation"] == item["operation"] and row["status"] == item["status"]
                       for row in card["facts"]) for item in required)
    retained = retained and not any(any(row["operation"] == item["operation"] and row["status"] == item["status"]
                       for row in card["facts"]) for item in case.get("forbidden_observations", []))
    appropriate = action in case["acceptable_actions"]
    toggle = session["config"]["oracle"]["web_search_enabled"]
    respected = toggle or ("research" not in decision and action != "research")
    return {"case": case["id"], "schema_and_evidence_valid": issue is None,
            "capabilities_retained": retained, "appropriate_action": appropriate,
            "research_toggle_respected": respected, "issue": issue,
            "passed": issue is None and retained and appropriate and respected}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("tests/fixtures/planning_cases.json"))
    parser.add_argument("--responses", type=Path, required=True,
                        help="JSONL objects with case and decision, generated separately by the model under evaluation")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    cases = {case["id"]: case for case in json.loads(args.cases.read_text(encoding="utf-8"))}
    results = []
    for line in args.responses.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            results.append(score(cases[row["case"]], row["decision"]))
    report = {"evaluated": len(results), "passed": sum(row["passed"] for row in results),
              "missing_cases": sorted(set(cases) - {row["case"] for row in results}), "results": results,
              "limits": "Checks decision contracts and expected action classes; does not prove exploitability or model solve rate."}
    output = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0 if results and all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
