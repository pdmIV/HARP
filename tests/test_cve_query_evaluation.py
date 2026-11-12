import copy
import json
from pathlib import Path
import unittest

import harp_cve
from scripts import evaluate_cve_queries as evaluation


class QueryEvaluationTests(unittest.TestCase):
    def cases(self):
        return json.loads(Path("tests/fixtures/cve_query_cases.json").read_text(encoding="utf-8"))

    def test_fixture_plans_are_generic_and_keep_their_product_anchor(self):
        for case in self.cases():
            plan = harp_cve.query_plan(case["product"], case["feature"], case["alternatives"])
            self.assertTrue(plan["primary"].startswith(case["product"] + " "))
            self.assertNotIn(case["expected_cves"][0], plan["primary"])
            self.assertTrue(plan["refinement"].startswith(case["product"] + " "))

    def test_offline_score_tracks_first_final_hits_distractors_attempts_and_unknown_costs(self):
        cases = self.cases()
        first, second = cases[:2]
        captures = [{"case": first["id"], "inference_cost_usd": 0.01, "attempts": [
            {"results": [], "seconds": 0.1},
            {"results": [{"advisory": {"cve_id": first["unrelated_cves"][0]}},
                         {"advisory": {"cve_id": first["expected_cves"][0]}}], "seconds": 0.2}]},
            {"case": second["id"], "attempts": [{"results": [{"cve_ids": second["expected_cves"]}]}]}]
        report = evaluation.evaluate(cases, captures)
        self.assertEqual(report["first_query_hit_at_3_rate"], 0.5)
        self.assertEqual(report["final_hit_at_3_rate"], 1)
        self.assertEqual(report["mean_search_requests"], 1.5)
        self.assertIsNone(report["inference_cost_usd"])
        self.assertEqual(report["results"][0]["final_expected_rank"], 2)
        self.assertEqual(report["results"][0]["unrelated_hits_at_3"], 1)
        self.assertEqual(report["results"][0]["search_seconds"], 0.3)
        self.assertIsNone(report["results"][1]["search_seconds"])
        self.assertEqual(report["missing_cases"], [cases[2]["id"]])

    def test_duplicate_cases_and_unbounded_captures_are_rejected(self):
        cases = self.cases()
        capture = {"case": cases[0]["id"], "attempts": [{"results": []}]}
        with self.assertRaises(ValueError):
            evaluation.evaluate(cases, [capture, copy.deepcopy(capture)])
        with self.assertRaises(ValueError):
            evaluation.evaluate(cases, [{**capture, "attempts": [{"results": []}] * 3}])


if __name__ == "__main__":
    unittest.main()
