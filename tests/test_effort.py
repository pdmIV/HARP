import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import harp
import harp_effort
import harp_nim
import harp_openai
import harp_zai
import test_harp as fixtures


class AdaptiveEffortTests(unittest.TestCase):
    def test_floor_fallback_and_provider_mapping(self):
        cfg = {"provider": "zai", "adaptive_reasoning": True, "reasoning_effort": "low"}
        for value in (None, "low", "HIGH", {}, [], True):
            self.assertEqual(harp_effort.select(cfg, value), ("high", "default_high"))
        self.assertEqual(harp_effort.select(cfg, "max"), ("max", "proxy_max"))
        self.assertEqual(harp_effort.select({**cfg, "adaptive_reasoning": False}, "max"), ("low", "fixed"))
        for model, effort in [("gpt-6.1-sol", "max"), ("gpt-5.6", "xhigh")]:
            self.assertEqual(harp_effort.select({**cfg, "provider": "openai", "model": model}, "max")[0], effort)
        with self.assertRaises(ValueError):
            harp_effort.ceiling({"provider": "openai", "model": "unknown"})

    def test_proxy_recommendation_only_on_handoff_and_no_extra_calls(self):
        for action, expected in [
            ({"done": True, "recommended_oracle_effort": "max"}, "max"),
            ({"needs_oracle": True, "recommended_oracle_effort": "high"}, "high"),
            ({"done": True, "recommended_oracle_effort": "low"}, None),
            ({"needs_oracle": True}, None),
            ({"needs_root": True, "command": "id", "recommended_oracle_effort": "max"}, None),
        ]:
            with self.subTest(action=action), tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
                path = Path(temp)
                fixtures.HarpTests.make_session(self, path)
                state = harp.load_session(path)
                state["config"]["oracle"] = {"provider": "zai", "adaptive_reasoning": True}
                state["recommended_oracle_effort"] = "max"  # previous delegation must not leak
                harp.save_session(path, state)
                def reply(model, system, user, ledger):
                    self.assertIn('recommended_oracle_effort', system)
                    ledger.append({"finish_reason": "stop"})
                    return json.dumps(action)
                terminal = fixtures.DummyTerminal()
                with patch.object(harp, "terminal_for", return_value=terminal), \
                     patch.object(terminal, "run") as execute, \
                     patch.object(harp, "model_context_tokens", return_value=8192), \
                     patch.object(harp, "count_chat_tokens", return_value=300), \
                     patch.object(harp, "api_chat", side_effect=reply) as chat:
                    harp.delegate(path, "Inspect the service", 2, quiet=True)
                self.assertEqual(harp.load_session(path).get("recommended_oracle_effort"), expected)
                chat.assert_called_once()
                execute.assert_not_called()

    def test_oracle_consumes_recommendation_for_one_request(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            state = harp.load_session(path)
            state["config"]["oracle"] = {"provider": "zai", "model": "glm-5.3",
                "adaptive_reasoning": True, "reasoning_effort": "low", "max_cycles": 3}
            harp.save_session(path, state)
            efforts = []
            def chat(cfg, body):
                efforts.append(harp_zai.response_body(cfg, body)["reasoning_effort"])
                return {"choices": [{"message": {"content": json.dumps({
                    "plan": "Inspect", "objective": "Inspect service " + str(len(efforts)),
                    "stop": len(efforts) == 3})}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
            def delegate(run, *args, **kwargs):
                current = harp.load_session(run)
                current["last_delegate_stop"] = "local_done"
                if len(efforts) == 1:
                    current["recommended_oracle_effort"] = "max"
                harp.save_session(run, current)
            with patch.object(harp_zai, "chat", side_effect=chat), patch.object(harp, "delegate", side_effect=delegate):
                harp_nim.run(path)
            self.assertEqual(efforts, ["high", "max", "high"])
            state = harp.load_session(path)
            self.assertNotIn("recommended_oracle_effort", state)
            self.assertEqual([c["reasoning_effort"] for c in state["oracle_calls"]], efforts)
            self.assertEqual(state["config"]["oracle"]["reasoning_effort"], "low")

    def test_openai_oracle_applies_high_floor_to_real_transport_body(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp)
            fixtures.HarpTests.make_session(self, path)
            state = harp.load_session(path)
            state["config"]["oracle"] = {"provider": "openai", "model": "gpt-6.1-sol",
                "adaptive_reasoning": True, "max_cycles": 1}
            harp.save_session(path, state)
            response = {"status": "completed", "output": [{"type": "message", "content": [
                {"type": "output_text", "text": '{"plan":"Blocked","stop":true}'}]}],
                "usage": {"input_tokens": 10, "output_tokens": 5}}
            with patch.object(harp_openai, "request", return_value=response) as request:
                harp_nim.run(path)
            self.assertEqual(request.call_args.args[2]["reasoning"], {"effort": "high"})

    def test_openai_effort_wire_and_fixed_requests_unchanged(self):
        cfg = {"model": "gpt-6.1-sol"}
        body = {"messages": [{"role": "user", "content": "evidence"}]}
        self.assertNotIn("reasoning", harp_openai.response_body(cfg, body))
        self.assertEqual(harp_openai.response_body(cfg, {**body, "reasoning_effort": "max"})["reasoning"], {"effort": "max"})


if __name__ == "__main__":
    unittest.main()
