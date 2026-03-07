#!/usr/bin/env python3
"""Basic tests for email_agent.py — validates argument parsing and message construction."""

import base64
import json
import sys
import unittest
from email.mime.text import MIMEText
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent))
import email_agent


class TestSendEmailConstruction(unittest.TestCase):
    """Test that email MIME messages are constructed correctly."""

    @patch.object(email_agent, "gmail_request")
    def test_send_basic(self, mock_req: MagicMock):
        mock_req.return_value = {"id": "msg123", "threadId": "thread456"}
        result = email_agent.send_email("fake-token", "a@b.com", "Hi", "Hello world")
        self.assertEqual(result["id"], "msg123")

        # Verify the raw message was base64-encoded
        call_body = mock_req.call_args[1]["body"] if mock_req.call_args[1] else mock_req.call_args[0][3]
        raw = call_body["raw"]
        decoded = base64.urlsafe_b64decode(raw).decode()
        self.assertIn("To: a@b.com", decoded)
        self.assertIn("Subject: Hi", decoded)
        self.assertIn("Hello world", decoded)

    @patch.object(email_agent, "gmail_request")
    def test_send_with_cc_bcc(self, mock_req: MagicMock):
        mock_req.return_value = {"id": "msg789"}
        email_agent.send_email("fake-token", "a@b.com", "Test", "Body", cc="c@d.com", bcc="e@f.com")
        call_args = mock_req.call_args
        call_body = call_args[1].get("body") or call_args[0][3]
        raw = base64.urlsafe_b64decode(call_body["raw"]).decode()
        self.assertIn("Cc: c@d.com", raw)
        self.assertIn("Bcc: e@f.com", raw)


class TestExtractText(unittest.TestCase):
    """Test body extraction from Gmail payload structures."""

    def test_plain_text_body(self):
        payload = {
            "mimeType": "text/plain",
            "body": {"data": base64.urlsafe_b64encode(b"Hello world").decode()},
        }
        msg_data = {
            "id": "1",
            "payload": payload,
            "snippet": "Hello",
        }
        with patch.object(email_agent, "gmail_request", return_value=msg_data):
            result = email_agent.read_message("token", "1")
        self.assertEqual(result["body"], "Hello world")

    def test_multipart_body(self):
        payload = {
            "mimeType": "multipart/alternative",
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {"data": base64.urlsafe_b64encode(b"Plain text").decode()},
                },
                {
                    "mimeType": "text/html",
                    "body": {"data": base64.urlsafe_b64encode(b"<b>HTML</b>").decode()},
                },
            ],
        }
        msg_data = {
            "id": "2",
            "payload": payload,
            "snippet": "Plain",
        }
        with patch.object(email_agent, "gmail_request", return_value=msg_data):
            result = email_agent.read_message("token", "2")
        self.assertEqual(result["body"], "Plain text")


class TestLoadCredentials(unittest.TestCase):
    def test_missing_env(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(SystemExit):
                email_agent.load_credentials()


if __name__ == "__main__":
    unittest.main()
