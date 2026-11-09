import io
import unittest
from unittest.mock import Mock, patch

import harp_web


class WebDisconnectTests(unittest.TestCase):
    def handler(self):
        handler = object.__new__(harp_web.HARPRequestHandler)
        handler.close_connection = False
        handler.path = "/api/health"
        handler._authorized = Mock(return_value=True)
        handler._headers = Mock()
        handler.wfile = Mock()
        return handler

    def test_aborted_success_response_is_not_retried_as_an_error_response(self):
        for error in (ConnectionAbortedError(10053, "aborted"), ConnectionResetError("reset"), BrokenPipeError("closed")):
            with self.subTest(error=type(error).__name__):
                handler = self.handler()
                handler.wfile.write.side_effect = error
                handler.do_GET()
                self.assertTrue(handler.close_connection)
                self.assertEqual(handler._headers.call_count, 1)
                self.assertEqual(handler._headers.call_args.args[0], 200)
                self.assertEqual(handler.wfile.write.call_count, 1)

    def test_disconnect_while_sending_headers_stops_the_response(self):
        handler = self.handler()
        handler._headers.side_effect = ConnectionAbortedError("closed during headers")
        handler.do_GET()
        self.assertTrue(handler.close_connection)
        self.assertEqual(handler._headers.call_count, 1)
        handler.wfile.write.assert_not_called()

    def test_request_loop_handles_disconnect_but_preserves_other_errors(self):
        handler = self.handler()
        with patch.object(harp_web.BaseHTTPRequestHandler, "handle", side_effect=ConnectionResetError("client left")):
            handler.handle()
        self.assertTrue(handler.close_connection)
        with patch.object(harp_web.BaseHTTPRequestHandler, "handle", side_effect=RuntimeError("application bug")), self.assertRaises(RuntimeError):
            handler.handle()

    def test_healthy_response_still_writes_the_json(self):
        handler = self.handler()
        handler.wfile = io.BytesIO()
        handler._json(200, {"ready": True})
        self.assertEqual(handler.wfile.getvalue(), b'{"ready": true}')
        self.assertFalse(handler.close_connection)

    def test_chomsky_wordmark_font_is_served(self):
        handler = self.handler()
        handler.path = "/fonts/Chomsky.woff2"
        handler.wfile = io.BytesIO()
        handler.do_GET()
        self.assertEqual(handler._headers.call_args.args[1], "font/woff2")
        self.assertEqual(handler.wfile.getvalue()[:4], b"wOF2")


if __name__ == "__main__":
    unittest.main()
