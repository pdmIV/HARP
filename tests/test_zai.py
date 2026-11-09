import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import harp
import harp_nim
import harp_web
import harp_zai


class ZAITests(unittest.TestCase):
    def config(self):
        return {"provider": "zai", "model": "glm-5.3", "max_tokens": 8192,
                "reasoning_effort": "low"}

    def test_proxy_wire_format_and_usage(self):
        response = {"choices": [{"message": {"content": '{"done":true}',
                    "reasoning_content": "untrusted reasoning"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                              "prompt_tokens_details": {"cached_tokens": 60}}}
        cfg = {**self.config(), "temperature": 0.65, "top_p": 0.82,
               "base_url": "https://api.openai.com/v1",
               "access_program": "daybreak_blue", "input_usd_per_million": 1,
               "cached_input_usd_per_million": 0.1, "output_usd_per_million": 2}
        with patch.object(harp_zai, "key", return_value="test-key"), patch.object(
                harp_zai.urllib.request, "urlopen", return_value=io.StringIO(json.dumps(response))) as send:
            ledger = []
            result = harp.api_chat(cfg, "system", "evidence", ledger)
        req = send.call_args.args[0]
        self.assertEqual(req.full_url, harp_zai.BASE + "/chat/completions")
        body = json.loads(req.data)
        self.assertEqual(set(body), {"model", "messages", "stream", "max_tokens", "thinking", "reasoning_effort", "temperature", "top_p", "response_format"})
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertEqual(body["thinking"], {"type": "enabled"})
        self.assertEqual(body["temperature"], 0.65)
        self.assertEqual(body["top_p"], 0.82)
        self.assertEqual(body["max_tokens"], 8192)
        self.assertEqual(result, '{"done":true}')
        self.assertEqual(ledger[0]["cached_input_tokens"], 60)
        self.assertAlmostEqual(ledger[0]["estimated_usd"], 0.000086)

    def test_empty_content_does_not_execute_reasoning(self):
        reply = {"choices": [{"message": {"reasoning_content": '{"command":"id"}'},
                              "finish_reason": "length"}]}
        with patch.object(harp_zai, "key", return_value="test-key"), patch.object(harp_zai, "chat", return_value=reply):
            ledger = []
            self.assertEqual(harp.api_chat(self.config(), "s", "u", ledger), "")
        self.assertIsNone(ledger[0]["estimated_usd"])
        self.assertEqual(ledger[0]["finish_reason"], "length")

    def test_oracle_uses_zai(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["oracle"] = {**self.config(), "temperature": 1.1, "top_p": 0.93}
        session = {"config": cfg, "target": "192.0.2.1", "status": "active", "observations": []}
        reply = {"choices": [{"message": {"content": '{"plan":"Blocked","stop":true}'}}],
                 "usage": {"prompt_tokens": 20, "completion_tokens": 10}}
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            harp.save_session(path, session)
            harp.append_event(path, {"type": "test"})
            with patch.object(harp_zai, "chat", return_value=reply) as chat, patch.object(harp_nim, "request") as nim:
                harp_nim.run(path)
            chat.assert_called_once()
            nim.assert_not_called()
            self.assertEqual(chat.call_args.args[0]["temperature"], 1.1)
            self.assertEqual(chat.call_args.args[0]["top_p"], 0.93)
            self.assertEqual(chat.call_args.args[1]["max_tokens"], 8192)
            self.assertIsNone(harp.load_session(path)["oracle_calls"][0]["estimated_usd"])

    def test_oracle_repairs_invalid_json_without_another_execution_cycle(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["oracle"] = {**self.config(), "max_cycles": 1}
        session = {"config": cfg, "target": "192.0.2.1", "status": "active", "observations": []}
        replies = [{"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
                   for content in ('{"plan":"broken",}', '{"plan":"Blocked","stop":true}')]
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            harp.save_session(path, session)
            harp.append_event(path, {"type": "test"})
            with patch.object(harp_zai, "chat", side_effect=replies) as chat, patch.object(harp, "delegate") as delegate:
                harp_nim.run(path)
            delegate.assert_not_called()
            self.assertEqual(chat.call_count, 2)
            self.assertIn("FORMAT RETRY", chat.call_args.args[1]["messages"][-1]["content"])
            self.assertEqual(len(harp.load_session(path)["oracle_calls"]), 2)
            self.assertEqual(harp_nim.oracle_history(path)["cycles"], 1)
            events = [json.loads(x) for x in (path / "events.jsonl").read_text().splitlines()]
            self.assertEqual(events[-1]["reason"], "model_stop")

    def test_oracle_invalid_retries_are_bounded_and_never_delegate(self):
        for content in ('narration without JSON', '{"plan":"bad boolean","stop":"false","objective":"id"}'):
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                path = Path(temp)
                cfg = json.loads(Path("harp.example.json").read_text())
                cfg["oracle"] = {**self.config(), "max_cycles": 1}
                harp.save_session(path, {"config": cfg, "target": "192.0.2.1", "status": "active", "observations": []})
                harp.append_event(path, {"type": "test"})
                reply = {"choices": [{"message": {"content": content, "reasoning_content": "private reasoning"}}]}
                with patch.object(harp_zai, "chat", return_value=reply) as chat, patch.object(harp, "delegate") as delegate:
                    harp_nim.run(path)
                self.assertEqual(chat.call_count, 3)
                delegate.assert_not_called()
                log = (path / "events.jsonl").read_text()
                self.assertNotIn("private reasoning", log)
                self.assertEqual(json.loads(log.splitlines()[-1])["reason"], "invalid_oracle_replies")

    def test_oracle_handoff_keeps_implementation_and_expands_evidence(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["oracle"] = {**self.config(), "max_cycles": 2, "steps_per_cycle": 1,
                         "evidence_depth": "compact"}
        implementation = "Exact implementation: " + "A" * 5000
        session = {"config": cfg, "target": "192.0.2.1", "status": "active",
                   "observations": [{"command": f"probe {i}", "exit_code": 0,
                                      "output": "evidence " * 300} for i in range(8)],
                   "oracle_help_request": "Need protocol framing", "local_steps": 0}
        first = {"plan": "Use a verified protocol implementation", "objective": "Check one response",
                 "implementation": implementation, "stop": False}
        second = {"plan": "Stop after verification", "stop": True}
        replies = [{"choices": [{"message": {"content": json.dumps(item)}}]}
                   for item in (first, second)]
        delegated = []

        def fake_delegate(run_dir, objective, _budget, *, quiet, unlimited_budget):
            delegated.append(objective)
            current = harp.load_session(run_dir)
            current["last_delegate_stop"] = "local_done"
            current["local_steps"] += 1
            current["observations"].append({"command": "probe result", "exit_code": 0,
                                            "output": "verified"})
            harp.save_session(run_dir, current)

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            harp.save_session(path, session)
            harp.append_event(path, {"type": "test"})
            with patch.object(harp_zai, "chat", side_effect=replies) as chat, \
                 patch.object(harp, "delegate", side_effect=fake_delegate):
                harp_nim.run(path)
            self.assertEqual(len(delegated), 1)
            self.assertIn(implementation, delegated[0])
            first_context = json.loads(chat.call_args_list[0].args[1]["messages"][1]["content"])
            self.assertEqual(first_context["oracle_help_request"], "Need protocol framing")
            self.assertEqual(len(first_context["observations"]), 8)
            self.assertGreater(len(first_context["observations"][0]["output"]), 1200)

    def test_oracle_evidence_depth_and_reply_validation(self):
        observations = [{"command": str(i), "exit_code": 0, "output": "x" * 14000}
                        for i in range(40)]
        expanded, recent = harp_nim.oracle_observations({"observations": observations},
                                                         {"evidence_depth": "extended"})
        self.assertEqual((len(expanded), recent), (32, 32))
        self.assertEqual(len(expanded[0]["output"]), 12000)
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["oracle"] = {**self.config(), "evidence_depth": "invalid"}
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "evidence_depth"):
                harp.load_config(path)

    def test_zai_context_and_reply_caps_follow_model_capacity(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        cfg["local"] = {**cfg["local"], **self.config(), "max_input_tokens": 750000,
                        "max_tokens": 131072}
        cfg["oracle"] = {**self.config(), "max_tokens": 131072,
                         "evidence_depth": "extended"}
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(cfg), encoding="utf-8")
            self.assertEqual(harp.load_config(path)["local"]["max_input_tokens"], 750000)
            cfg["local"]["max_input_tokens"] = 800000
            path.write_text(json.dumps(cfg), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "total at most 900000"):
                harp.load_config(path)

    def test_save_both_roles(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            path.write_text(json.dumps(cfg))
            proxy = {**self.config(), "model": "glm-5.3-flash", "reasoning_effort": "high",
                     "temperature": 1.25, "top_p": 0.87}
            oracle = {**self.config(), "temperature": 0.4, "top_p": 0.96}
            with patch.object(harp_web, "CONFIG", path):
                harp_web.HARPWebState().save_config({"local": proxy, "oracle": oracle})
            loaded = harp.load_config(path)
            self.assertEqual(loaded["local"]["model"], "glm-5.3-flash")
            self.assertEqual(loaded["local"]["reasoning_effort"], "high")
            self.assertEqual(loaded["local"]["temperature"], 1.25)
            self.assertEqual(loaded["local"]["top_p"], 0.87)
            self.assertEqual(loaded["oracle"]["provider"], "zai")
            self.assertEqual(loaded["oracle"]["temperature"], 0.4)
            self.assertEqual(loaded["oracle"]["top_p"], 0.96)

    def test_model_and_effort_validation(self):
        for change in ({"model": "bad"}, {"reasoning_effort": "none"},
                       {"temperature": float("nan")}, {"temperature": 2.1},
                       {"top_p": 0}, {"top_p": 1.1}, {"top_p": float("nan")},
                       {"input_usd_per_million": -1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                harp_zai.validate({**self.config(), **change})
        for model in harp_zai.models():
            harp_zai.validate({**self.config(), "model": model})

    def test_http_error_does_not_leak_body(self):
        error = urllib.error.HTTPError(harp_zai.BASE, 401, "unauthorized", {}, io.BytesIO(b'secret target evidence'))
        with patch.object(harp_zai, "key", return_value="key"), patch.object(
                harp_zai.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "^Z.AI returned HTTP 401$"):
                harp_zai.chat(self.config(), {"messages": []})

    def test_environment_key_precedence(self):
        with patch.dict(harp_zai.os.environ, {"ZAI_API_KEY": "test-key"}), patch.object(harp_zai.harp_secret, "load_key") as load:
            self.assertEqual(harp_zai.key(), "test-key")
            load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
