import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error
from urllib.parse import urlsplit

import harp
import harp_mcp
import harp_nim
import harp_research as research
import harp_web
import harp_zai
import test_harp as fixtures
from scripts import research_fetch


class ResearchTests(unittest.TestCase):
    def setup_session(self, path, enabled=True):
        fixtures.HarpTests.make_session(self, path)
        state = harp.load_session(path)
        state["config"]["oracle"] = {"provider": "zai", "model": "glm-5.3", "web_search_enabled": enabled,
                                      "max_cycles": 5, "steps_per_cycle": 1}
        harp.save_session(path, state)
        return state

    def search(self, path, query="ExampleProduct 2.0 authentication documentation"):
        return research.request(path, {"query": query, "reason": "Confirm the documented authentication prerequisites"})

    def report(self):
        return {"search_result": [{"title": "Official documentation", "link": f"https://example.org/doc{i}", "content": "Relevant public documentation " * 1000} for i in range(3)]}

    def source(self, text="Authentication prerequisites\nExampleProduct 2.0 requires a valid session token\n"):
        return {"url": "https://example.org/docs", "final_url": "https://example.org/docs", "text": text,
                "sha256": "a" * 64, "truncated": False}

    def test_off_by_default_and_local_only_do_not_touch_network(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api") as api:
            path = Path(temp)
            state = self.setup_session(path, False)
            with self.assertRaisesRegex(ValueError, "disabled"):
                self.search(path)
            self.assertIsNone(research.context(path, state))
            state["config"]["oracle"]["web_search_enabled"] = True
            state["mode"] = "local-only"
            harp.save_session(path, state)
            with self.assertRaisesRegex(ValueError, "Hybrid"):
                self.search(path)
            api.assert_not_called()
            self.assertFalse((path / "research.json").exists())

    def test_search_wire_format_has_no_model_or_summarization_call(self):
        with patch.object(harp_zai, "key", return_value="test-key"), patch.object(
                harp_zai.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(self.report()).encode())) as send:
            result = research.search_api("ExampleProduct 2.0 documentation")
        wire = send.call_args.args[0]
        self.assertEqual(wire.full_url, harp_zai.BASE + "/web_search")
        self.assertEqual(json.loads(wire.data), {"search_engine": "search-prime", "search_query": "ExampleProduct 2.0 documentation", "count": 3})
        self.assertEqual(len(result["search_result"]), 3)
        self.assertEqual(send.call_args.kwargs["timeout"], 20)

    def test_durable_search_cache_and_session_budget(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api", side_effect=lambda q: self.report()) as api:
            path = Path(temp)
            state = self.setup_session(path)
            first = self.search(path)
            cached = self.search(path, "EXAMPLEPRODUCT  2.0 authentication documentation")
            self.assertEqual(first["id"], cached["id"])
            api.assert_called_once()
            for i in range(3):
                self.search(path, f"ExampleProduct {i + 3}.0 documentation")
            with self.assertRaisesRegex(ValueError, "budget exhausted"):
                self.search(path, "ExampleProduct 9.0 documentation")
            self.assertEqual(api.call_count, 4)
            self.assertEqual(research.metrics(path)["search_requests"], 4)
            self.assertIsNone(research.metrics(path)["estimated_usd"])
            self.assertLessEqual(len(json.dumps(research.context(path, state))), research.CONTEXT_CHARS)

    def test_two_reads_only_and_repeated_reads_do_not_refetch(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api", return_value=self.report()), \
             patch.object(research, "source_fetch", return_value=self.source()) as fetch:
            path = Path(temp)
            state = self.setup_session(path)
            task = self.search(path)
            read = lambda sid: research.request(path, {"source_id": sid, "reason": "Read the authentication prerequisites for this version"})
            first = read(task["source_ids"][0])
            self.assertIn("L2:", first["excerpt"])
            self.assertEqual(read(task["source_ids"][0]), first)
            self.assertEqual(fetch.call_count, 1)
            read(task["source_ids"][1])
            with self.assertRaisesRegex(ValueError, "two sources"):
                read(task["source_ids"][2])
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(len(list((path / "research_sources").glob("*.json"))), 2)
            self.assertIn("unverified", json.dumps(research.context(path, state)))

    def test_failed_requests_are_reserved_and_not_silently_retried(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api", side_effect=RuntimeError("HTTP 429")) as api:
            path = Path(temp)
            self.setup_session(path)
            self.assertIn("error", self.search(path))
            self.assertIn("error", self.search(path))
            api.assert_called_once()
            self.assertEqual(research.metrics(path)["failed_requests"], 1)
            self.assertFalse((path / ".research_lock").exists())

    def test_public_source_boundary_and_html_extraction(self):
        for url in ("file:///etc/passwd", "https://localhost/a", "http://example.htb/a", "https://user:pass@example.org/a", "http://example.org:5985/a"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                research_fetch.public_endpoint(url)
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1"):
            with patch.object(socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]), self.assertRaises(ValueError):
                research_fetch.public_endpoint("https://example.org/docs")
        reader = research_fetch.TextReader()
        reader.feed("<nav>menus</nav><script>evil()</script><p>Helpful &amp; precise</p><pre>a = 1\n  b = 2</pre>")
        text = "".join(reader.parts)
        self.assertNotIn("evil", text)
        self.assertNotIn("menus", text)
        self.assertIn("Helpful & precise", text)
        self.assertIn("  b = 2", text)

    def test_redirect_is_revalidated_before_another_connection(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 302
        response.getheader.return_value = "http://127.0.0.1/private"
        endpoint = (urlsplit("http://example.org/docs"), "93.184.216.34", 80)
        with patch.object(research_fetch, "public_endpoint", side_effect=[endpoint, ValueError("Private destination")]) as validate, \
             patch.object(research_fetch.socket, "create_connection", return_value=Mock()) as connect, \
             patch.object(research_fetch.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "Private destination"):
                research_fetch.fetch("http://example.org/docs")
        self.assertEqual(validate.call_count, 2)
        connect.assert_called_once_with(("93.184.216.34", 80), timeout=12)
        connection.close.assert_called_once()

    def test_bounded_source_fetch_returns_hash_and_never_executes_content(self):
        raw = b"import os\n# text only; no execution\n"
        for data in (raw, b"x" * 90000 + b"\n" + raw, b"x" * 2_000_001):
            connection = Mock()
            response = connection.getresponse.return_value
            response.status = 200
            response.getheader.side_effect = lambda key, default=None: {"Content-Type": "text/plain"}.get(key, default)
            response.read.side_effect = io.BytesIO(data).read
            endpoint = (urlsplit("http://example.org/docs"), "93.184.216.34", 80)
            with patch.object(research_fetch, "public_endpoint", return_value=endpoint), \
                 patch.object(research_fetch.socket, "create_connection", return_value=Mock()), \
                 patch.object(research_fetch.http.client, "HTTPConnection", return_value=connection):
                if len(data) > 2_000_000:
                    with self.assertRaisesRegex(ValueError, "2 MB"):
                        research_fetch.fetch("http://example.org/docs")
                else:
                    result = research_fetch.fetch("http://example.org/docs")
                    self.assertIn("import os", result["text"])
                    self.assertEqual(result["sha256"], research.hashlib.sha256(data).hexdigest())
                    if len(data) > 80000:
                        self.assertGreater(len(result["text"]), 80000)
                        self.assertFalse(result["truncated"])
            connection.close.assert_called_once()

    def test_provider_errors_do_not_echo_bodies_or_retry(self):
        error = urllib.error.HTTPError(harp_zai.BASE, 429, "rate limit", {}, io.BytesIO(b"private provider diagnostic"))
        with patch.object(harp_zai, "key", return_value="test-key"), patch.object(harp_zai.urllib.request, "urlopen", side_effect=error) as send:
            with self.assertRaisesRegex(RuntimeError, "^Z.AI search returned HTTP 429; no automatic retry$"):
                research.search_api("ExampleProduct documentation")
        send.assert_called_once()

    def test_queries_reject_lab_identifiers_and_context_has_hard_bound(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api", return_value=self.report()) as api:
            path = Path(temp)
            state = self.setup_session(path)
            for query in ("HTB box walkthrough", "root.txt flag value", "10.10.10.10 service exploits", "service cicada.htb vulnerabilities"):
                with self.assertRaises(ValueError):
                    self.search(path, query)
            api.assert_not_called()
            task = self.search(path)
            db = research.load(path)
            db["tasks"][0]["reads"] = [{"source_id": task["source_ids"][0], "excerpt": "漢" * 80000, "error": None}]
            research.save(path, db)
            self.assertLessEqual(len(json.dumps(research.context(path, state, limit=3000))), 3000)

    def test_source_reader_uses_selected_runtime_without_shell_download(self):
        terminal = Mock()
        terminal.file_argv.return_value = ["selected-runtime", "python3", "reader"]
        with patch.object(harp, "terminal_for", return_value=terminal), patch.object(research.subprocess, "run", return_value=Mock(returncode=0, stdout=json.dumps(self.source()).encode())) as run:
            research.source_fetch({"status": "active"}, "https://example.org/docs")
        terminal.file_argv.assert_called_once()
        self.assertEqual(run.call_args.args[0][0], "selected-runtime")

    def test_hosted_oracle_search_read_then_delegate_with_preserved_context(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            self.setup_session(path)
            turns = []
            def chat(cfg, body):
                context = json.loads(body["messages"][1]["content"])
                turns.append(context)
                if len(turns) == 1:
                    action = {"research": {"query": "ExampleProduct 2.0 authentication documentation", "reason": "Resolve authentication requirements before the next probe"}}
                elif len(turns) == 2:
                    sid = context["unverified_research"]["latest"]["results"][0]["source_id"]
                    action = {"research": {"source_id": sid, "reason": "Read the documented authentication prerequisites"}}
                elif len(turns) == 3:
                    self.assertTrue(context["unverified_research"]["latest"]["reads"])
                    action = {"objective": "Verify the documented prerequisite on the target"}
                else:
                    action = {"stop": True}
                return {"choices": [{"message": {"content": json.dumps({"plan": "Resolve one missing technical fact", "objective": "", "stop": False, **action})}}]}
            def delegate(run_dir, *args, **kw):
                state = harp.load_session(run_dir)
                state["last_delegate_stop"] = "local_done"
                harp.save_session(run_dir, state)
            with patch.object(harp_zai, "chat", side_effect=chat), patch.object(research, "search_api", return_value=self.report()) as search, \
                 patch.object(research, "source_fetch", return_value=self.source()), patch.object(harp, "delegate", side_effect=delegate) as delegated:
                harp_nim.run(path)
            self.assertEqual(len(turns), 4)
            search.assert_called_once()
            delegated.assert_called_once()
            self.assertEqual(len(harp.load_session(path)["oracle_calls"]), 4)

    def test_research_limit_rejection_does_not_spend_the_last_execution_cycle(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            state = self.setup_session(path)
            state["config"]["oracle"]["max_cycles"] = 1
            harp.save_session(path, state)
            with patch.object(research, "search_api", return_value=self.report()):
                for i in range(4):
                    self.search(path, f"ExampleProduct {i + 2}.0 documentation")
            calls = []
            def chat(cfg, body):
                context = json.loads(body["messages"][1]["content"])
                calls.append(context)
                if len(calls) == 1:
                    action = {"research": {"query": "ExampleProduct 9.0 documentation", "reason": "Check another prerequisite before selecting the route"}, "objective": ""}
                else:
                    self.assertIn("budget exhausted", context["research_feedback"]["error"])
                    action = {"objective": "Verify the prerequisite using the retained evidence"}
                return {"choices": [{"message": {"content": json.dumps({"plan": "Continue the evidence-backed route", "stop": False, **action})}}]}
            with patch.object(harp_zai, "chat", side_effect=chat), patch.object(harp, "delegate") as delegate, patch.object(research, "search_api") as network:
                harp_nim.run(path)
            delegate.assert_called_once()
            network.assert_not_called()
            self.assertEqual(len(calls), 2)
            history = harp_nim.oracle_history(path)
            self.assertEqual(history["cycles"], 1)
            self.assertEqual(history["research_turns"], 1)
            # A resume cannot replenish either budget.
            with patch.object(harp_zai, "chat") as chat_again:
                harp_nim.run(path)
            chat_again.assert_not_called()

    def test_repeated_research_returns_feedback_and_allows_delegation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            state = self.setup_session(path)
            state["config"]["oracle"]["max_cycles"] = 1
            harp.save_session(path, state)
            action = {"plan": "Check one missing prerequisite", "objective": "", "stop": False,
                      "research": {"query": "ExampleProduct 2.0 documentation", "reason": "Determine the authentication prerequisite for this route"}}
            replies = [action, action, {"plan": "Use the retained evidence", "objective": "Verify one prerequisite", "stop": False}]
            responses = [{"choices": [{"message": {"content": json.dumps(x)}}]} for x in replies]
            with patch.object(harp_zai, "chat", side_effect=responses), patch.object(harp, "delegate") as delegate, patch.object(research, "search_api", return_value=self.report()) as network:
                harp_nim.run(path)
            delegate.assert_called_once()
            network.assert_called_once()
            self.assertEqual(harp_nim.oracle_history(path)["cycles"], 1)
            self.assertEqual(harp_nim.oracle_history(path)["research_turns"], 2)

    def test_cached_pages_recover_late_chain_steps_without_another_fetch(self):
        prefix = "prerequisite details\n" * 5000
        text = prefix + "STAGE_THREE_REQUIRED\nverify_final_condition()\n"
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api", return_value=self.report()), patch.object(research, "source_fetch", return_value=self.source(text)) as fetch:
            path = Path(temp)
            state = self.setup_session(path)
            task = self.search(path)
            sid = task["source_ids"][0]
            research.request(path, {"source_id": sid, "reason": "Read the published prerequisites and implementation"})
            action = {"source_id": sid, "offset": len(prefix), "reason": "Read the final chain stage omitted from the initial excerpt"}
            page = research.request(path, action)
            self.assertEqual(page["excerpt"], text[len(prefix):])
            self.assertIsNone(page["next_offset"])
            self.assertEqual(page["total_characters"], len(text))
            self.assertFalse(page["source_truncated"])
            self.assertEqual(research.context(path, state)["requested_page"]["excerpt"], page["excerpt"])
            self.assertEqual(research.tool_result(page)["excerpt"], page["excerpt"])
            fetch.assert_called_once()
            self.assertEqual(research.metrics(path)["source_requests"], 1)
            self.assertEqual(len(research.load(path)["tasks"][0]["reads"]), 1)

    def test_unicode_pagination_has_no_missing_characters_at_response_boundaries(self):
        text = "\u6f22" * 2000 + "\nFINAL_STAGE"
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp, patch.object(research, "search_api", return_value=self.report()), patch.object(research, "source_fetch", return_value=self.source(text)):
            path = Path(temp)
            state = self.setup_session(path)
            task = self.search(path)
            sid = task["source_ids"][0]
            research.request(path, {"source_id": sid, "reason": "Inspect all prerequisites in the published source"})
            offset, parts = 0, []
            while offset is not None:
                page = research.request(path, {"source_id": sid, "offset": offset, "reason": "Recover the next contiguous portion of the important chain"})
                result = research.tool_result(page)
                parts.append(result["excerpt"])
                if result["next_offset"] is not None:
                    self.assertEqual(result["next_offset"], offset + len(result["excerpt"]))
                self.assertLessEqual(len(json.dumps(result)), 6000)
                self.assertLessEqual(len(json.dumps(research.context(path, state))), research.CONTEXT_CHARS)
                self.assertEqual(research.context(path, state)["requested_page"]["excerpt"], page["excerpt"])
                offset = result["next_offset"]
            self.assertEqual("".join(parts), text)

    def test_config_validation_and_persistence(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            cfg = json.loads(Path("harp.example.json").read_text())
            path.write_text(json.dumps(cfg))
            with patch.object(harp_web, "CONFIG", path):
                saved = harp_web.HARPWebState().save_config({"oracle": {"web_search_enabled": True}})
            self.assertTrue(saved["oracle"]["web_search_enabled"])
            cfg["oracle"]["web_search_enabled"] = "true"
            path.write_text(json.dumps(cfg))
            with self.assertRaisesRegex(ValueError, "web_search_enabled"):
                harp.load_config(path)


if __name__ == "__main__":
    unittest.main()
