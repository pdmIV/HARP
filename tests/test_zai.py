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
        cfg = {**self.config(), "base_url": "https://api.openai.com/v1",
               "access_program": "daybreak_blue", "input_usd_per_million": 1,
               "cached_input_usd_per_million": 0.1, "output_usd_per_million": 2}
        with patch.object(harp_zai, "key", return_value="test-key"), patch.object(
                harp_zai.urllib.request, "urlopen", return_value=io.StringIO(json.dumps(response))) as send:
            ledger = []
            result = harp.api_chat(cfg, "system", "evidence", ledger)
        req = send.call_args.args[0]
        self.assertEqual(req.full_url, harp_zai.BASE + "/chat/completions")
        body = json.loads(req.data)
        self.assertEqual(set(body), {"model", "messages", "stream", "max_tokens", "thinking", "reasoning_effort"})
        self.assertEqual(body["thinking"], {"type": "enabled"})
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
        cfg["oracle"] = self.config()
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
            self.assertEqual(chat.call_args.args[1]["max_tokens"], 8192)
            self.assertIsNone(harp.load_session(path)["oracle_calls"][0]["estimated_usd"])

    def test_save_both_roles(self):
        cfg = json.loads(Path("harp.example.json").read_text())
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            path = Path(temp) / "harp.json"
            path.write_text(json.dumps(cfg))
            proxy = {**self.config(), "model": "glm-5.3-flash", "reasoning_effort": "high"}
            with patch.object(harp_web, "CONFIG", path):
                harp_web.HARPWebState().save_config({"local": proxy, "oracle": self.config()})
            loaded = harp.load_config(path)
            self.assertEqual(loaded["local"]["model"], "glm-5.3-flash")
            self.assertEqual(loaded["local"]["reasoning_effort"], "high")
            self.assertEqual(loaded["oracle"]["provider"], "zai")

    def test_model_and_effort_validation(self):
        for change in ({"model": "bad"}, {"reasoning_effort": "none"}, {"input_usd_per_million": -1}):
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
