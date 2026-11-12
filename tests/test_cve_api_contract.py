"""Real loopback HTTP tests. Only the API origin is substituted, not urllib."""
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import queue
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error
from urllib.parse import urlsplit

import harp_cve
import harp_research
from scripts import validate_cve_api as validation
from test_cve import report, record
import test_harp as fixtures


class CVEHTTPContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.responses, cls.requests = queue.Queue(), []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                cls.requests.append({"path": self.path, "headers": dict(self.headers),
                    "body": json.loads(self.rfile.read(int(self.headers["Content-Length"])))})
                scenario = cls.responses.get(timeout=2)
                body = scenario.get("body", report())
                data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
                self.send_response(scenario.get("status", 200))
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Connection", "close")
                if not scenario.get("omit_length"):
                    self.send_header("Content-Length", str(scenario.get("length", len(data))))
                for key, value in scenario.get("headers", {}).items():
                    self.send_header(key, value)
                self.end_headers()
                time.sleep(scenario.get("delay", 0))
                try:
                    self.wfile.write(data)
                except OSError:
                    pass
            def do_GET(self):
                cls.requests.append({"method": "GET"})
                self.send_error(500)
            def log_message(self, *_args):
                pass
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=lambda: cls.server.serve_forever(poll_interval=.02), daemon=True)
        cls.thread.start()
        cls.endpoint = f"http://127.0.0.1:{cls.server.server_port}/webSearch"
        try:
            with socket.create_connection(("127.0.0.1", cls.server.server_port), timeout=.5):
                pass
        except PermissionError:
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=2)
            raise unittest.SkipTest("Loopback connections are denied by this host; wire-parser tests still run")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.requests.clear()
        self.assertTrue(self.responses.empty())
        self.origin = patch.object(harp_cve, "ENDPOINT", self.endpoint)
        self.origin.start()
        self.addCleanup(self.origin.stop)

    def respond(self, **scenario):
        self.responses.put(scenario)

    def test_real_post_and_phrase_note_preserve_successful_results(self):
        response = report()
        response["searchMetadata"].update(version="2025-08-26", notes=["search text is a phrase (surrounded by double quotes)"])
        self.respond(body=response)
        result = harp_cve.search({"product": "Samba", "feature": "print command"})
        self.assertEqual(result["resultsTotal"], 1)
        self.assertEqual(len(harp_cve.records(result)), 1)
        request = self.requests[0]
        self.assertEqual(request["path"], "/webSearch")
        self.assertEqual(request["body"], harp_cve.request_body({"product": "Samba", "feature": "print command"}))
        self.assertEqual(request["headers"]["Content-Type"], "application/json")
        self.assertNotIn("Authorization", request["headers"])
        self.assertEqual(request["body"]["size"], 3)

    def test_http_failures_are_never_empty_success_or_automatically_retried(self):
        for status in (400, 429, 500, 502, 503, 504):
            with self.subTest(status=status):
                before = len(self.requests)
                self.respond(status=status, body={"error": "provider_body_canary"})
                with self.assertRaisesRegex(RuntimeError, f"HTTP {status}; no automatic retry") as caught:
                    harp_cve.search("Samba print command")
                self.assertNotIn("provider_body_canary", str(caught.exception))
                self.assertEqual(len(self.requests), before + 1)

    def test_redirect_is_not_followed(self):
        self.respond(status=302, headers={"Location": self.endpoint + "/redirect"})
        with self.assertRaisesRegex(RuntimeError, "HTTP 302"):
            harp_cve.search("Samba print command")
        self.assertEqual(len(self.requests), 1)

    def test_partial_status_and_truncated_http_body_are_not_accepted(self):
        self.respond(status=206)
        with self.assertRaisesRegex(RuntimeError, "unexpected HTTP 206"):
            harp_cve.search("Samba print command")
        encoded = json.dumps(report()).encode()
        self.respond(body=encoded, length=len(encoded) + 7)
        with self.assertRaisesRegex(RuntimeError, "incomplete or invalid HTTP body"):
            harp_cve.search("Samba print command")

    def test_valid_close_delimited_utf8_response(self):
        value = record()
        value["containers"]["cna"]["title"] = "Document metadata caf\u00e9"
        self.respond(body={**report(), "data": [value]}, omit_length=True)
        rows = harp_cve.records(harp_cve.search("ExampleProduct document handler"))
        self.assertIn("caf\u00e9", rows[0]["title"])
        self.assertIn("caf\u00e9", rows[0]["retained_source"]["text"])
        encoded = json.dumps(report()).encode()
        self.respond(body=encoded, length=f"{len(encoded)} \t")
        self.assertEqual(harp_cve.search("ExampleProduct document handler")["resultsTotal"], 1)

    def test_malformed_or_incomplete_envelopes_never_become_zero_matches(self):
        malformed = [b"<html>gateway error</html>", b"\xff", b"{", b"null",
                     {**report(), "resultsTotal": True}, {**report(), "resultsTotal": -1},
                     {**report(), "data": None}, {**report(), "data": []},
                     {**report(), "resultsTotal": 3},
                     {**report(), "searchMetadata": {"searchStatus": "partial", "errors": []}},
                     {**report(), "searchMetadata": {"searchStatus": "ok", "errors": {}}},
                     {**report(), "searchMetadata": {"searchStatus": "ok", "errors": ["upstream_failed"]}}]
        for body in malformed:
            with self.subTest(body=repr(body)[:90]):
                self.respond(body=body)
                with self.assertRaises(RuntimeError):
                    harp_cve.search("ExampleProduct document handler")

    def test_response_bound_and_read_deadline(self):
        self.respond(body=b"x" * 17)
        with patch.object(harp_cve, "MAX_RESPONSE_BYTES", 16), self.assertRaisesRegex(RuntimeError, "exceeds"):
            harp_cve.search("Samba print command")
        self.respond(delay=.2)
        with patch.object(harp_cve, "TIMEOUT_SECONDS", .04), self.assertRaises(TimeoutError):
            harp_cve.search("Samba print command")

    def test_research_lifecycle_uses_real_http_and_cached_record_reads(self):
        self.respond(body={**report(), "resultsTotal": 0, "data": []})
        self.respond()
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            import harp
            session = harp.load_session(path)
            session["config"]["oracle"]["web_search_enabled"] = True
            harp.save_session(path, session)
            action = {"kind": "cve", "product": "ExampleProduct", "feature": "document handler",
                      "reason": "Inspect one public advisory for the observed capability"}
            found = harp_research.request(path, action)
            self.assertEqual(len(self.requests), 2)
            self.assertEqual(harp_research.metrics(path)["search_requests"], 2)
            self.assertEqual(harp_research.request(path, action)["id"], found["id"])
            source = found["results"][0]["source_id"]
            reading = harp_research.request(path, {"source_id": source, "reason": "Read the retained CVE record"})
            page = harp_research.request(path, {"source_id": source, "find": "document",
                                               "reason": "Locate the controlled input in retained text"})
            self.assertIn("CVE-2099-12345", reading["cve_ids"])
            self.assertIn("document", page["excerpt"].lower())
            self.assertEqual(len(self.requests), 2)
            self.assertTrue(all(not any(k in req["body"] for k in ("year", "severity")) for req in self.requests))

    def test_live_runner_refines_only_successful_zero_and_detects_retrieval_misses(self):
        case = {"id": "synthetic", "input": {"product": "ExampleProduct", "feature": "document handler"},
                "expected_cves": ["CVE-2099-12345"], "expect": "hit"}
        self.respond(body={**report(), "resultsTotal": 0, "data": []})
        self.respond()
        result = validation.run_case(case)
        self.assertTrue(result["passed"])
        self.assertEqual(result["expected_rank"], 1)
        self.assertEqual(len(result["attempts"]), 2)
        self.respond(status=502)
        result = validation.run_case(case)
        self.assertFalse(result["passed"])
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["error_kind"], "http_error")
        wrong = copy.deepcopy(case)
        wrong["expected_cves"] = ["CVE-2099-99999"]
        self.respond()
        result = validation.run_case(wrong)
        self.assertTrue(result["transport_contract_ok"])
        self.assertFalse(result["retrieval_expectation_met"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["retrieval_issue"], "positive_results_missing_expected_advisory")
        self.assertEqual(result["refinement_skipped_reason"], "positive_response")
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(result["attempts"][0]["candidates"][0]["applicability"], "unverified")

    def test_rate_limit_stops_a_planned_batch(self):
        self.respond(status=429)
        case = {"id": "synthetic", "input": "ExampleProduct document handler", "expect": "observe"}
        result = validation.run([case], rounds=2, interval=0)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blocked_reason"], "rate_limited")
        self.assertFalse(result["complete"])
        self.assertEqual(len(self.requests), 1)

    def test_exact_historical_and_current_case_requests_use_production_transport(self):
        cases = validation.cases_from(Path("tests/fixtures/cve_api_cases.json"))
        for case in cases:
            with self.subTest(case=case["id"]):
                response = {**report(), "resultsTotal": 0, "data": []} if case["expect"] == "empty" else report()
                self.respond(body=response)
                before = len(self.requests)
                result = validation.run_case(case)
                self.assertTrue(result["transport_contract_ok"])
                self.assertEqual(len(self.requests), before + 1)
                self.assertEqual(self.requests[-1]["body"], validation.case_body(case))

    def test_shared_search_cap_includes_real_http_failures_and_cache_reuse(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            import harp
            session = harp.load_session(path)
            session["config"]["oracle"]["web_search_enabled"] = True
            harp.save_session(path, session)
            with patch.object(harp_research, "search_api") as paid:
                for product in ("Samba", "OpenSSH", "Apache Log4j2", "ExampleProduct"):
                    self.respond(status=502)
                    action = {"query": product + " processing", "kind": "cve", "reason": "Find one public advisory"}
                    result = harp_research.request(path, action)
                    self.assertEqual(result["status"], "failed")
                    self.assertIn("HTTP 502", result["error"])
                self.assertEqual(harp_research.request(path, action)["id"], result["id"])
                with self.assertRaisesRegex(ValueError, "four searches"):
                    harp_research.request(path, {**action, "query": "OtherProduct processing"})
                paid.assert_not_called()
            self.assertEqual(len(self.requests), 4)
            self.assertEqual(harp_research.metrics(path)["search_requests"], 4)

    def test_later_success_does_not_erase_an_earlier_live_failure(self):
        case = {"id": "synthetic", "input": "ExampleProduct document handler", "expect": "hit",
                "expected_cves": ["CVE-2099-12345"]}
        self.respond(status=502)
        self.respond()
        result = validation.run([case], rounds=2, interval=0)
        self.assertTrue(result["complete"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_case_runs"], 1)
        self.assertEqual(result["request_attempts"], 2)

    def test_historical_diagnostics_do_not_mask_required_query_failures(self):
        diagnostic = {"id": "historical", "wire_query": '"Example" OR "Other"', "expect": "observe"}
        required = {"id": "current", "input": "ExampleProduct handler", "expect": "hit",
                    "expected_cves": ["CVE-2099-12345"]}
        self.respond(status=502)
        self.respond()
        result = validation.run([diagnostic, required], rounds=1, interval=0)
        self.assertEqual(result["status"], "passed_with_diagnostic_errors")
        self.assertEqual(result["diagnostic_error_case_runs"], 1)
        self.assertEqual(result["failed_required_case_runs"], 0)
        self.assertFalse(result["results"][0]["passed"])
        self.respond(status=502)
        self.respond(status=502)
        result = validation.run([diagnostic, required], rounds=1, interval=0)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failed_required_case_runs"], 1)


class CVEWireContractTests(CVEHTTPContractTests):
    """The same contract matrix using real HTTPResponse parsing, without sockets.

    Only the connection is injected. Status/header/body parsing and all production
    query, envelope, record, cache and refinement code remain real.
    """
    @classmethod
    def setUpClass(cls):
        cls.responses, cls.requests = queue.Queue(), []
        cls.endpoint = "http://127.0.0.1:1/webSearch"

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        super().setUp()
        def open_wire(request, **_kwargs):
            self.requests.append({"path": urlsplit(request.full_url).path,
                "headers": {key.title(): value for key, value in request.header_items()},
                "body": json.loads(request.data)})
            scenario = self.responses.get(timeout=2)
            if scenario.get("delay"):
                raise TimeoutError("Injected stalled HTTP read")
            body = scenario.get("body", report())
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            status = scenario.get("status", 200)
            headers = {"Content-Type": "application/json", "Connection": "close", **scenario.get("headers", {})}
            if not scenario.get("omit_length"):
                headers["Content-Length"] = str(scenario.get("length", len(data)))
            raw = (f"HTTP/1.1 {status} Test\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode() + data
            class WireSocket:
                def makefile(self, *_args):
                    return io.BytesIO(raw)
            response = http.client.HTTPResponse(WireSocket())
            response.begin()
            if status >= 400:
                raise urllib.error.HTTPError(request.full_url, status, "Test", response.headers, response)
            return response
        opener = Mock()
        opener.open.side_effect = open_wire
        connection = patch.object(harp_cve.urllib.request, "build_opener", return_value=opener)
        connection.start()
        self.addCleanup(connection.stop)


class CVEValidationPlanningTests(unittest.TestCase):
    def test_precision_comparison_preserves_original_misses_and_adds_independent_controls(self):
        cases = validation.cases_from(Path("tests/fixtures/cve_api_precision_cases.json"))
        indexed = {case["id"]: case for case in cases}
        self.assertEqual(indexed["original_samba_printer_share"]["expect"], "hit")
        self.assertEqual(indexed["original_openssh_signal_handling"]["expected_cves"], ["CVE-2024-6387"])
        self.assertEqual(validation.case_body(indexed["samba_configuration_mechanism"])["query"], "Samba print command")
        self.assertEqual(validation.case_body(indexed["openssh_signal_handler"])["query"], "OpenSSH signal handler")

    def test_interrupted_request_is_reported_without_a_retry_or_success_claim(self):
        case = {"id": "synthetic", "input": "ExampleProduct document handler", "expect": "observe"}
        with patch.object(harp_cve, "search", side_effect=KeyboardInterrupt) as search:
            result = validation.run([case], rounds=2, interval=0)
        self.assertEqual(result["status"], "interrupted")
        self.assertFalse(result["complete"])
        self.assertEqual(result["request_attempts"], 1)
        self.assertIn("unknown", result["results"][0]["attempts"][0]["error"])
        search.assert_called_once()

    def test_public_fixture_contains_exact_logged_queries_and_labels_stay_local(self):
        cases = validation.cases_from(Path("tests/fixtures/cve_api_cases.json"))
        indexed = {case["id"]: case for case in cases}
        self.assertEqual(indexed["latest_log_structured"]["input"], {
            "product": "Samba", "feature": "printer share anonymous print", "alternatives": ["print command injection"]})
        self.assertEqual(indexed["older_log_legacy_keywords"]["input"], "Samba print job spool")
        for case in cases:
            for identity in case.get("expected_cves", []):
                self.assertNotIn(identity, json.dumps(validation.case_body(case)))

    def test_logged_structured_inputs_never_regenerate_the_failing_boolean_shapes(self):
        cases = validation.cases_from(Path("tests/fixtures/cve_api_cases.json"))
        for case in cases:
            if isinstance(case.get("input"), dict):
                plan = harp_cve.query_plan(**case["input"])
                for wire in (plan["primary"], plan["refinement"]):
                    if wire:
                        self.assertNotIn(" OR ", wire)
                        self.assertNotIn(" AND ", wire)
                        self.assertNotIn("(", wire)
                        self.assertTrue(wire.startswith(case["input"]["product"] + " "))
        latest = next(case for case in cases if case["id"] == "latest_log_structured")
        self.assertEqual(harp_cve.query_plan(**latest["input"])["refinement"], "Samba print")

    def test_dns_failure_is_recorded_as_blocked_not_a_successful_empty_query(self):
        case = {"id": "synthetic", "input": "ExampleProduct document handler", "expect": "observe"}
        with patch.object(harp_cve, "search", side_effect=urllib.error.URLError(socket.gaierror("DNS unavailable"))) as search:
            result = validation.run([case], rounds=2, interval=0)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["complete"])
        self.assertEqual(result["request_attempts"], 1)
        search.assert_called_once()

    def test_default_plan_mode_never_calls_the_api(self):
        with patch.object(harp_cve, "search") as search, patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(validation.main([]), 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "not_run")
        search.assert_not_called()


if __name__ == "__main__":
    unittest.main()
