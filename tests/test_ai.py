import io
import json
import unittest
from unittest.mock import MagicMock, patch

from osint_toolkit.ai import (
    build_osint_prompt,
    format_ai_briefing_card,
    generate_ai_briefing,
    get_available_models,
    is_ollama_available,
)
from osint_toolkit.cli import main


class AiModuleTests(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_is_ollama_available_true(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        self.assertTrue(is_ollama_available())

    @patch("urllib.request.urlopen")
    def test_is_ollama_available_false_on_connection_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        self.assertFalse(is_ollama_available())

    @patch("urllib.request.urlopen")
    def test_get_available_models(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "models": [{"name": "llama3:latest"}, {"name": "mistral:latest"}]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        models = get_available_models()
        self.assertEqual(models, ["llama3:latest", "mistral:latest"])

    def test_build_osint_prompt_for_username(self):
        report = {
            "target": "drowlink",
            "profiles_found": [{"name": "GitHub", "category": "Tech", "url": "https://github.com/drowlink"}],
            "profiles_not_found": [{"name": "Twitter"}],
        }
        prompt = build_osint_prompt(report)
        self.assertIn("@drowlink", prompt)
        self.assertIn("Profiles Found", prompt)

    def test_build_osint_prompt_for_domain(self):
        report = {
            "target": "example.com",
            "dns": {"addresses": ["93.184.216.34"], "nameservers": ["ns1.example.com"]},
            "web": {"status": 200, "headers": {"present": ["hsts"], "missing": []}},
        }
        prompt = build_osint_prompt(report)
        self.assertIn("example.com", prompt)
        self.assertIn("Infrastructure", prompt)

    @patch("urllib.request.urlopen")
    def test_generate_ai_briefing_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({
            "response": "Subject appears to be a software developer based on GitHub activity."
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        report = {"target": "user123", "profiles_found": []}
        res = generate_ai_briefing(report, model="llama3")

        self.assertTrue(res["success"])
        self.assertEqual(res["model"], "llama3")
        self.assertIn("software developer", res["briefing"])

    @patch("urllib.request.urlopen")
    def test_generate_ai_briefing_offline_handling(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        report = {"target": "user123"}
        res = generate_ai_briefing(report)

        self.assertFalse(res["success"])
        self.assertIn("not accessible", res["error"])

    def test_format_ai_briefing_card(self):
        success_res = {
            "success": True,
            "model": "llama3",
            "endpoint": "http://localhost:11434",
            "briefing": "• Activity: Software engineering\n• Risk: Low",
        }
        card = format_ai_briefing_card(success_res, use_color=False)
        self.assertIn("LOCAL AI INTELLIGENCE BRIEFING (llama3)", card)
        self.assertIn("Activity: Software engineering", card)

        fail_res = {
            "success": False,
            "model": "llama3",
            "endpoint": "http://localhost:11434",
            "error": "Ollama is not running",
        }
        fail_card = format_ai_briefing_card(fail_res, use_color=False)
        self.assertIn("Ollama is not running", fail_card)


class AiCliTests(unittest.TestCase):
    @patch("osint_toolkit.cli.generate_ai_briefing")
    def test_main_with_ai_flag_injects_briefing_into_json(self, mock_ai):
        mock_ai.return_value = {
            "success": True,
            "model": "llama3",
            "briefing": "Mock briefing",
        }
        output = io.StringIO()
        error = io.StringIO()
        exit_code = main(
            ["example.com", "--ai", "-j"],
            stdout=output,
            stderr=error,
            collector=lambda _t, **_k: {"target": "example.com"},
        )
        self.assertEqual(exit_code, 0)
        data = json.loads(output.getvalue())
        self.assertIn("ai_briefing", data)
        self.assertEqual(data["ai_briefing"]["briefing"], "Mock briefing")
