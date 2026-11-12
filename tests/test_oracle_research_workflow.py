"""Synthetic oracle/research workflow tests: no paid model, API or target calls."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_cve
import harp_nim
import harp_research as research
import harp_zai
import test_cve
import test_harp as fixtures


def catalogue():
    return {"tasks": [{"id": "task1", "kind": "cve", "query": "ExampleProduct document handler",
        "source_ids": ["a", "b", "c"], "results": [
            {"source_id": sid, "url": "https://example.org/" + sid, "title": "ExampleProduct advisory", "excerpt": "Public advisory summary", "cve_ids": [identity], "advisory": {"cve_id": identity,
             "scores": [{"score": 9.8 if sid == "a" else 5.3}]}}
            for sid, identity in (("a", "CVE-2099-12345"), ("b", "CVE-2098-12345"), ("c", "CVE-2097-12345"))],
        "reads": []}], "sources": {}, "calls": [], "cache_hits": 0, "active_task_id": "task1"}


def assessment(sid="b", identity="CVE-2098-12345", **changes):
    return {"source_id": sid, "cve_id": identity, "mechanism_match": "matches",
            "version_match": "unknown", "goal_relevance": "direct", "required_access_state": "available",
            "rationale": "The documented mechanism could advance the goal but the branch is unknown",
            "unmet_prerequisites": ["Verify the effective configuration"],
            "next_verification": "Read the source, then verify one configuration prerequisite", **changes}


class OracleResearchWorkflowTests(unittest.TestCase):
    def session(self, path, enabled=True):
        fixtures.HarpTests.make_session(self, path)
        session = harp.load_session(path)
        session["config"]["oracle"] = {"provider": "zai", "model": "glm-5.3", "max_cycles": 4,
                                        "web_search_enabled": enabled}
        harp.save_session(path, session)
        return session

    def test_query_selection_audits_the_chosen_primary_without_rewriting_or_network(self):
        decision = {"research": {"kind": "cve", "product": "ExampleProduct", "feature": "export command",
                    "alternatives": ["shared folder"], "reason": "Find the documented execution mechanism"},
                    "check": {"query_selection": {"basis": "configuration", "rationale": "Configuration wording is more specific than a resource name", "source_ids": ["source1"]}}}
        before = copy.deepcopy(decision)
        result = research.query_selection(decision, {"tasks": [{"reads": [{"source_id": "source1", "excerpt": "export command"}]}]})
        self.assertEqual(result["primary"], "ExampleProduct export command")
        self.assertEqual(result["alternatives_not_queried"], ["shared folder"])
        self.assertEqual(result["basis"], "configuration")
        self.assertTrue(result["cited_sources_read"])
        self.assertTrue(result["model_assessment_only"])
        self.assertEqual(decision, before)
        decision["research"]["feature"] = "anonymous shared document folder"
        decision["check"]["query_selection"]["basis"] = "resource"
        self.assertEqual(len(research.query_selection(decision, {})["warnings"]), 2)

    def test_candidate_ranking_preserves_unknowns_and_does_not_promote_on_a_read(self):
        state = catalogue()
        ready = assessment(version_match="confirmed", unmet_prerequisites=[])
        accepted, errors = research.candidate_assessments({"check": {"candidate_assessments": [ready]}}, state)
        self.assertFalse(errors)
        self.assertEqual(accepted[0]["priority"], "read_source")
        state["candidate_assessments"] = accepted
        state["tasks"][0]["reads"] = [{"source_id": "b", "excerpt": "CVE-2098-12345"}]
        self.assertEqual(research.candidate_review(state)["candidates"][0]["priority"], "reassess_source")
        decisions = [assessment("a", "CVE-2099-12345", mechanism_match="contradicted", version_match="contradicted"),
                     assessment(), assessment("c", "CVE-2097-12345", goal_relevance="none")]
        accepted, errors = research.candidate_assessments({"check": {"candidate_assessments": decisions}}, state)
        self.assertFalse(errors)
        state["candidate_assessments"] = accepted
        card = research.candidate_review(state)
        self.assertEqual(card["candidates"][0]["source_id"], "b")
        self.assertEqual(card["candidates"][0]["priority"], "verify_prerequisites")
        self.assertTrue(all(row["target_applicability"] == "unverified" for row in card["candidates"]))
        self.assertEqual(card["coverage"], "prerequisites_or_source_review_needed")
        for row in decisions:
            row["mechanism_match"] = "contradicted"
        state["candidate_assessments"], _ = research.candidate_assessments({"check": {"candidate_assessments": decisions}}, state)
        self.assertEqual(research.candidate_review(state)["coverage"], "no_suitable_returned_candidate")

    def test_invented_source_links_do_not_enter_the_ledger(self):
        for item in (assessment("invented"), assessment(identity="CVE-2099-99999"), assessment(version_match="patched")):
            accepted, errors = research.candidate_assessments({"check": {"candidate_assessments": [item]}}, catalogue())
            self.assertEqual(accepted, [])
            self.assertTrue(errors)

    def test_workflow_reviews_are_persistent_toggle_scoped_and_make_no_requests(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(research, "search_api") as web, patch.object(harp_cve, "search") as cve:
            path = Path(temp)
            session = self.session(path)
            research.save(path, catalogue())
            research.record_workflow_review(path, {"check": {"candidate_assessments": [assessment()]}})
            stored = research.load(path)
            self.assertEqual(len(stored["candidate_assessments"]), 1)
            self.assertEqual(research.metrics(path)["search_requests"], 0)
            self.assertEqual(research.context(path, session)["candidate_review"]["candidates"][0]["source_id"], "b")
            self.assertEqual(research.context(path, session, limit=3000)["candidate_review"]["coverage"], "unassessed")
            session["config"]["oracle"]["web_search_enabled"] = False
            harp.save_session(path, session)
            before = (path / "research.json").read_bytes()
            research.record_workflow_review(path, {"check": {"candidate_assessments": [assessment(version_match="confirmed")]}})
            self.assertEqual((path / "research.json").read_bytes(), before)
            self.assertIsNone(research.context(path, session))
            web.assert_not_called()
            cve.assert_not_called()

    def test_hosted_cached_find_recovers_after_first_fetch_without_dedup_poisoning(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.session(path)
            contexts = []
            def chat(config, body, **kwargs):
                context = json.loads(body["messages"][1]["content"])
                contexts.append(context)
                turn = len(contexts)
                if turn == 1:
                    action = {"query": "ExampleProduct export command documentation", "reason": "Read one documented processing prerequisite"}
                else:
                    sid = context["unverified_research"]["latest"]["results"][0]["source_id"]
                    action = {"source_id": sid, "reason": "Read the exact processing mechanism"}
                    if turn in (2, 4):
                        action["find"] = "export command"
                    if turn == 3:
                        self.assertIn("Read this source successfully", context["research_feedback"]["error"])
                    if turn in (5, 6):
                        self.assertIn("export command", context["unverified_research"]["requested_page"]["excerpt"])
                decision = {"plan": "Review the public mechanism", "stop": turn == 6, "objective": ""}
                if turn < 6:
                    decision["research"] = action
                return {"choices": [{"message": {"content": json.dumps(decision)}}]}
            report = {"search_result": [{"title": "ExampleProduct documentation", "link": "https://example.org/doc", "content": "Configuration reference"}]}
            source = {"url": "https://example.org/doc", "final_url": "https://example.org/doc", "text": "export command\nOne documented prerequisite; CVE-2099-12345", "sha256": "a" * 64, "truncated": False}
            with patch.object(harp_zai, "chat", side_effect=chat), \
                 patch.object(research, "search_api", return_value=report) as search, \
                 patch.object(research, "source_fetch", return_value=source) as fetch, \
                 patch.object(harp, "delegate") as delegate:
                harp_nim.run(path)
            self.assertEqual(len(contexts), 6)
            self.assertIn("CVE-2099-12345", contexts[-1]["unverified_research"]["latest"]["reads"][0]["cve_ids"])
            search.assert_called_once()
            fetch.assert_called_once()
            delegate.assert_not_called()
            events = [json.loads(line) for line in (path / "events.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(sum(e["type"] == "research_rejected" for e in events), 1)
            self.assertFalse(any("Repeated oracle research" in e.get("detail", "") for e in events))
            self.assertEqual(research.metrics(path)["source_reads"], 1)

    def test_hosted_query_choice_and_reviews_piggyback_on_existing_turns(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.session(path)
            contexts = []
            def chat(config, body, **kwargs):
                context = json.loads(body["messages"][1]["content"])
                contexts.append(context)
                turn = len(contexts)
                check = {"action": "research", "hypothesis": "A documented processing mechanism may apply",
                         "fact": "processing capability", "resource": "service", "principal": "unknown", "evidence": [],
                         "expected_positive": "A mechanism source is found", "expected_negative": "The mechanism remains unknown"}
                decision = {"plan": "Check one source-supported mechanism", "objective": "", "stop": False, "check": check}
                if turn == 1:
                    self.assertIn("query_selection_guidance", context["unverified_research"])
                    check["query_selection"] = {"basis": "configuration", "rationale": "A processing parameter is more discriminating than a folder name"}
                    decision["research"] = {"kind": "cve", "product": "ExampleProduct", "feature": "export command", "alternatives": ["shared folder"], "reason": "Find one documented processing prerequisite"}
                else:
                    sid = context["unverified_research"]["latest"]["results"][0]["source_id"]
                    check["candidate_assessments"] = [assessment(sid, "CVE-2099-12345")]
                    if turn == 2:
                        self.assertEqual(context["unverified_research"]["last_query_selection"]["feature"], "export command")
                        decision["research"] = {"source_id": sid, "reason": "Read affected versions and prerequisites"}
                    elif turn == 3:
                        self.assertEqual(context["unverified_research"]["candidate_review"]["candidates"][0]["priority"], "reassess_source")
                        check["action"] = "validate_hypothesis"
                        decision["objective"] = "Verify one configuration prerequisite"
                    else:
                        decision = {"plan": "Review finished", "stop": True}
                return {"choices": [{"message": {"content": json.dumps(decision)}}]}
            def delegate(run_dir, *args, **kwargs):
                session = harp.load_session(run_dir)
                session["last_delegate_stop"] = "local_done"
                harp.save_session(run_dir, session)
            with patch.object(harp_zai, "chat", side_effect=chat), \
                 patch.object(harp_cve, "search", return_value=test_cve.report()) as search, \
                 patch.object(harp, "delegate", side_effect=delegate) as delegated:
                harp_nim.run(path)
            self.assertEqual(len(contexts), 4)
            delegated.assert_called_once()
            search.assert_called_once()
            self.assertEqual(search.call_args.args[0]["feature"], "export command")
            state = research.load(path)
            self.assertEqual(state["candidate_assessments"][0]["priority"], "verify_prerequisites")
            self.assertEqual(research.metrics(path)["search_requests"], 1)


if __name__ == "__main__":
    unittest.main()
