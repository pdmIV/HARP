import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

import harp_cve
import harp_research as research
import test_harp as fixtures


def record():
    return {"dataType": "CVE_RECORD", "dataVersion": "5.2",
            "cveMetadata": {"cveId": "CVE-2099-12345", "state": "PUBLISHED", "datePublished": "2099-01-02"},
            "containers": {"cna": {"title": "ExampleProduct document handler issue",
                "providerMetadata": {"shortName": "vendor"},
                "descriptions": [{"lang": "en", "value": "A document metadata field reaches an unsafe command handler."}],
                "affected": [{"vendor": "Example", "product": "ExampleProduct", "defaultStatus": "unaffected",
                              "versions": [{"version": "2.0", "lessThan": "2.5", "status": "affected", "versionType": "semver"}]}],
                "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/test"}}],
                "references": [{"url": "https://vendor.example/advisory"}, {"url": "https://vendor.example/patch"}]},
                "adp": [{"providerMetadata": {"shortName": "enricher"}, "metrics": [
                    {"cvssV3_1": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}]}}


def report(value=None):
    return {"searchMetadata": {"searchStatus": "ok", "version": "test", "errors": [], "notes": ["keyword search"]},
            "resultsTotal": 1, "data": [{"_id": "CVE-2099-12345", "_source": value or record()}]}


class CVETests(unittest.TestCase):
    def structured(self, **changes):
        return {"product": "ExampleProduct", "feature": "document handler", "kind": "cve",
                "reason": "Find an advisory for the observed processing capability", **changes}

    def empty_report(self):
        return {**report(), "resultsTotal": 0, "data": []}

    def test_structured_builder_keeps_product_required_and_alternatives_literal(self):
        fields = {"product": "ExampleProduct", "feature": "document handler", "alternatives": ["document processing"]}
        first = harp_cve.request_body(fields)
        second = harp_cve.request_body(fields, refine=True)
        self.assertEqual(first["query"], 'ExampleProduct document handler')
        self.assertEqual(second["query"], 'ExampleProduct document')
        self.assertEqual(first["size"], 3)
        for changes in ({"product": 'Foo" OR *'}, {"feature": "*"}, {"alternatives": "document"},
                        {"alternatives": ["one", "two", "three"]}, {"feature": "one two three four five"},
                        {"provider": "other"}, {"feature": "print OR command"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                harp_cve.request_body({**fields, **changes})

    def test_zero_result_refinement_has_two_durable_slots_and_reuses_results(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", side_effect=[self.empty_report(), report()]) as official, \
             patch.object(research, "search_api") as paid:
            path = Path(temp)
            session = self.session(path)
            found = research.request(path, self.structured())
            self.assertEqual(found["results_total"], 1)
            self.assertEqual(official.call_count, 2)
            self.assertGreaterEqual(found["seconds"], 0)
            self.assertFalse(official.call_args_list[0].kwargs["refine"])
            self.assertTrue(official.call_args_list[1].kwargs["refine"])
            db = research.load(path)
            self.assertEqual(len(db["tasks"]), 2)
            self.assertEqual(db["tasks"][0]["refinement_task_id"], found["id"])
            self.assertEqual(found["refinement_of"], db["tasks"][0]["id"])
            self.assertEqual(db["tasks"][0]["refinement_status"], "completed")
            self.assertEqual(research.request(path, self.structured())["id"], found["id"])
            self.assertEqual(official.call_count, 2)
            self.assertEqual(research.metrics(path)["search_requests"], 2)
            self.assertEqual(research.context(path, session)["latest"]["refinement_of"], db["tasks"][0]["id"])
            events = [json.loads(line) for line in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(e["type"] == "research_query_refined" for e in events), 1)
            paid.assert_not_called()

    def test_refinement_never_repeats_after_two_empty_results(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", return_value=self.empty_report()) as official:
            path = Path(temp)
            self.session(path)
            found = research.request(path, self.structured())
            self.assertEqual(found["results_total"], 0)
            research.request(path, self.structured())
            self.assertEqual(official.call_count, 2)

    def test_positive_error_and_indistinct_refinement_never_add_an_attempt(self):
        for response, failure, feature in ((report(), None, "document handler"),
                (None, TimeoutError("timed out"), "document handler"),
                (None, RuntimeError("HTTP 429"), "document handler"),
                (self.empty_report(), None, "document")):
            with self.subTest(feature=feature, failure=failure), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
                 patch.object(harp_cve, "search", return_value=response, side_effect=failure) as official, \
                 patch.object(research, "search_api") as paid:
                path = Path(temp)
                self.session(path)
                found = research.request(path, self.structured(feature=feature))
                self.assertEqual(official.call_count, 1)
                self.assertEqual(len(research.load(path)["tasks"]), 1)
                self.assertFalse(found.get("refinement_of"))
                paid.assert_not_called()

    def test_refinement_respects_last_slot_and_stop_requests(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", return_value=self.empty_report()) as official, \
             patch.object(research, "search_api", return_value={"search_result": []}):
            path = Path(temp)
            self.session(path)
            for i in range(3):
                research.request(path, {"query": f"ExampleProduct documentation {i}", "reason": "Read one relevant public fact"})
            found = research.request(path, self.structured())
            self.assertEqual(found["refinement_status"], "budget_exhausted")
            research.request(path, self.structured())
            self.assertEqual(official.call_count, 1)
            self.assertEqual(research.metrics(path)["search_requests"], 4)
        for stop in (".stop_session", ".stop_local"):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                path = Path(temp)
                self.session(path)
                def stopped(*_args, **_kwargs):
                    (path / stop).touch()
                    return self.empty_report()
                with patch.object(harp_cve, "search", side_effect=stopped) as official, self.assertRaisesRegex(ValueError, "active"):
                    research.request(path, self.structured())
                self.assertEqual(official.call_count, 1)

    def test_interrupted_refinement_is_not_reissued_after_restart(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", side_effect=[self.empty_report(), KeyboardInterrupt()]) as official:
            path = Path(temp)
            self.session(path)
            with self.assertRaises(KeyboardInterrupt):
                research.request(path, self.structured())
            before = research.load(path)
            self.assertEqual(len(before["tasks"]), 2)
            self.assertEqual(before["tasks"][1]["status"], "started")
            found = research.request(path, self.structured())
            self.assertEqual(found["status"], "interrupted")
            self.assertIn("no automatic retry", found["error"])
            self.assertEqual(official.call_count, 2)
            self.assertEqual(research.metrics(path)["search_requests"], 2)

    def test_structured_queries_keep_privacy_checks_and_reject_mixed_shapes(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(harp_cve, "search") as official:
            path = Path(temp)
            self.session(path)
            for changes in ({"product": "10.10.10.10"}, {"alternatives": ["host.htb"]},
                            {"query": "extra keywords"}, {"kind": "general"}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    research.request(path, self.structured(**changes))
            official.assert_not_called()

    def test_identical_legacy_and_structured_wire_queries_share_one_result(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(harp_cve, "search", return_value=report()) as official:
            path = Path(temp)
            self.session(path)
            compiled = harp_cve.query_plan("ExampleProduct", "document handler")["primary"]
            research.request(path, {"query": compiled, "kind": "cve", "reason": "Read one relevant advisory"})
            research.request(path, self.structured())
            self.assertEqual(official.call_count, 1)
            research.request(path, self.structured())
            self.assertEqual(official.call_count, 1)

    def test_cached_legacy_zero_can_attach_structured_refinement_without_repeating_primary(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", side_effect=[self.empty_report(), report()]) as official:
            path = Path(temp)
            self.session(path)
            research.request(path, {"query": "ExampleProduct document handler", "kind": "cve", "reason": "Inspect one public advisory"})
            found = research.request(path, self.structured())
            self.assertEqual(found["results_total"], 1)
            self.assertEqual(official.call_count, 2)
            self.assertTrue(official.call_args_list[1].kwargs["refine"])
            self.assertEqual(research.metrics(path)["search_requests"], 2)

    def test_request_is_bounded_unauthenticated_and_has_no_recency_or_severity_filter(self):
        opener = Mock()
        opener.open.return_value = io.BytesIO(json.dumps(report()).encode())
        with patch.object(harp_cve.urllib.request, "build_opener", return_value=opener):
            result = harp_cve.search("ExampleProduct document handler")
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, "https://search.cve.org/webSearch")
        self.assertEqual(json.loads(req.data), {"query": 'ExampleProduct document handler',
                         "from": 0, "size": 3, "sort": {"property": "relevancy", "order": "desc"}})
        self.assertIsNone(req.get_header("Authorization"))
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 20)
        self.assertEqual(result["resultsTotal"], 1)
        self.assertIsNone(harp_cve.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example"))

    def test_keywords_cannot_introduce_broad_query_operators(self):
        with self.assertRaisesRegex(ValueError, "Boolean"):
            harp_cve.request_body('ExampleProduct OR * (document)')
        with self.assertRaises(ValueError):
            harp_cve.request_body("* ? []")

    def test_error_responses_are_rejected_without_echoing_provider_body(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError(harp_cve.ENDPOINT, 429, "limit", {}, io.BytesIO(b"secret detail"))
        with patch.object(harp_cve.urllib.request, "build_opener", return_value=opener), self.assertRaisesRegex(
                RuntimeError, "^CVE Search API returned HTTP 429; no automatic retry or fallback$"):
            harp_cve.search("ExampleProduct document handler")
        self.assertEqual(opener.open.call_count, 1)
        bad = [b"not JSON", json.dumps({**report(), "data": None}).encode(),
               json.dumps({**report(), "resultsTotal": True}).encode(),
               json.dumps({**report(), "searchMetadata": {"searchStatus": "partial", "errors": []}}).encode()]
        for raw in bad:
            with self.subTest(raw=raw[:40]):
                opener.open.side_effect = None
                opener.open.return_value = io.BytesIO(raw)
                with patch.object(harp_cve.urllib.request, "build_opener", return_value=opener), self.assertRaises(RuntimeError):
                    harp_cve.search("ExampleProduct document handler")
        opener.open.return_value = io.BytesIO(b"x" * 17)
        with patch.object(harp_cve, "MAX_RESPONSE_BYTES", 16), \
             patch.object(harp_cve.urllib.request, "build_opener", return_value=opener), self.assertRaisesRegex(RuntimeError, "exceeds"):
            harp_cve.search("ExampleProduct document handler")

    def test_wrapped_and_direct_records_preserve_ranges_and_score_provenance(self):
        for value in (report(), {**report(), "data": [record()]}):
            row = harp_cve.records(value)[0]
            self.assertEqual(row["advisory"]["affected"][0]["versions"][0]["lessThan"], "2.5")
            self.assertEqual([x["source"] for x in row["advisory"]["scores"]], ["vendor", "enricher"])
            self.assertEqual([x["score"] for x in row["advisory"]["scores"]], [8.1, 9.8])
            self.assertEqual(row["advisory"]["applicability"], "unverified")
            self.assertIn('"defaultStatus": "unaffected"', row["retained_source"]["text"])
        rejected = record()
        rejected["cveMetadata"]["state"] = "REJECTED"
        self.assertEqual(harp_cve.records(report(rejected)), [])
        with self.assertRaisesRegex(RuntimeError, "metadata"):
            harp_cve.records({"data": [{}]})

    def session(self, path, enabled=True):
        fixtures.HarpTests.make_session(self, path)
        import harp
        session = harp.load_session(path)
        session["config"]["oracle"]["web_search_enabled"] = enabled
        harp.save_session(path, session)
        return session

    def test_official_results_cache_full_records_and_allow_explicit_vendor_read(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", return_value=report()) as official, \
             patch.object(research, "search_api") as paid, \
             patch.object(research, "source_fetch") as fetch:
            path = Path(temp)
            session = self.session(path)
            action = {"query": "ExampleProduct document handler", "kind": "cve", "reason": "Find a goal-relevant advisory"}
            found = research.request(path, action)
            self.assertEqual(found["provider"], "cve/search")
            self.assertEqual(found["results_total"], 1)
            self.assertEqual(found["provider_metadata"]["notes"], ["keyword search"])
            primary = found["results"][0]
            read = research.request(path, {"source_id": primary["source_id"], "reason": "Inspect the affected versions and exact controlled input"})
            self.assertEqual(read["cve_ids"], ["CVE-2099-12345"])
            fetch.assert_not_called()
            self.assertEqual(len(research.load(path)["tasks"][0]["reads"]), 1)
            fetch.return_value = {"url": "https://vendor.example/advisory", "final_url": "https://vendor.example/advisory",
                                  "text": "Affected versions and configuration prerequisites", "sha256": "a" * 64, "truncated": False}
            reference = primary["references"][0]
            research.request(path, {"source_id": reference["source_id"], "reason": "Read the vendor prerequisite details"})
            fetch.assert_called_once()
            with self.assertRaisesRegex(ValueError, "two sources"):
                research.request(path, {"source_id": primary["references"][1]["source_id"],
                                        "reason": "Try to read a third distinct source"})
            research.request(path, {**action, "year_scope": "earlier"})
            official.assert_called_once()
            paid.assert_not_called()
            usage = research.metrics(path)
            self.assertEqual(usage["cve_search_requests"], 1)
            self.assertEqual(usage["zai_search_requests"], 0)
            self.assertEqual(usage["source_reads"], 2)
            self.assertEqual(usage["source_requests"], 1)
            self.assertLessEqual(len(json.dumps(research.context(path, session))), research.CONTEXT_CHARS)
            self.assertLessEqual(len(json.dumps(research.tool_result(found))), 6000)

    def test_cve_and_web_cache_namespaces_are_distinct_and_failures_do_not_fallback(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, \
             patch.object(harp_cve, "search", side_effect=RuntimeError("CVE API unavailable")) as official, \
             patch.object(research, "search_api", return_value={"search_result": []}) as web:
            path = Path(temp)
            self.session(path)
            action = {"query": "ExampleProduct document handler", "kind": "cve", "reason": "Find a goal-relevant advisory"}
            self.assertIn("error", research.request(path, action))
            web.assert_not_called()
            research.request(path, action)
            official.assert_called_once()
            research.request(path, {**action, "kind": "general"})
            web.assert_called_once()
            self.assertEqual(research.metrics(path)["search_requests"], 2)

    def test_disabled_queries_and_lab_identifiers_never_reach_official_api(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(harp_cve, "search") as official:
            path = Path(temp)
            self.session(path, False)
            action = {"query": "ExampleProduct document handler", "kind": "cve", "reason": "Find a goal-relevant advisory"}
            with self.assertRaisesRegex(ValueError, "disabled"):
                research.request(path, action)
            self.session(path)
            with self.assertRaises(ValueError):
                research.request(path, {**action, "query": "10.10.10.10 CVEs"})
            official.assert_not_called()


if __name__ == "__main__":
    unittest.main()
