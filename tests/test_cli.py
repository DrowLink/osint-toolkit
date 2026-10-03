import io
import json
import unittest

from osint_toolkit.cli import main


class CliTests(unittest.TestCase):
    def test_writes_json_report(self):
        output = io.StringIO()
        error = io.StringIO()
        fake_report = {"target": "example.com", "schema_version": 1}

        exit_code = main(
            ["example.com"],
            stdout=output,
            stderr=error,
            collector=lambda _target: fake_report,
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue()), fake_report)
        self.assertEqual(error.getvalue(), "")

    def test_returns_usage_error_for_invalid_target(self):
        output = io.StringIO()
        error = io.StringIO()

        exit_code = main(["localhost"], stdout=output, stderr=error)

        self.assertEqual(exit_code, 2)
        self.assertIn("error:", error.getvalue())
        self.assertEqual(output.getvalue(), "")


    def test_writes_json_report_to_file(self):
        import tempfile
        import pathlib

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = pathlib.Path(temp_dir) / "output.json"
            fake_report = {"target": "example.com", "schema_version": 1}
            output = io.StringIO()
            error = io.StringIO()

            exit_code = main(
                ["example.com", "--output", str(file_path)],
                stdout=output,
                stderr=error,
                collector=lambda _target, **_kwargs: fake_report,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(error.getvalue(), "")
            self.assertEqual(output.getvalue(), "")
            self.assertTrue(file_path.exists())
            self.assertEqual(json.loads(file_path.read_text(encoding="utf-8")), fake_report)

    def test_rejects_negative_or_zero_timeout(self):
        for invalid_timeout in ("0", "-2"):
            output = io.StringIO()
            error = io.StringIO()
            exit_code = main(["example.com", "-t", invalid_timeout], stdout=output, stderr=error)
            self.assertEqual(exit_code, 2)
            self.assertIn("timeout must be positive", error.getvalue())

    def test_passes_custom_timeout_to_collector(self):
        captured_kwargs = {}

        def fake_collector(target, **kwargs):
            captured_kwargs.update(kwargs)
            return {"target": target}

        output = io.StringIO()
        error = io.StringIO()
        exit_code = main(
            ["example.com", "-t", "12.5"],
            stdout=output,
            stderr=error,
            collector=fake_collector,
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(captured_kwargs.get("timeout"), 12.5)

    def test_summary_mode_prints_formatted_card(self):
        fake_report = {
            "target": "example.com",
            "schema_version": 1,
            "generated_at": "2026-10-03T00:00:00Z",
            "dns": {"addresses": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]},
            "web": {
                "status": 200,
                "url": "https://example.com/",
                "title": "Example Domain",
                "headers": {
                    "present": ["strict-transport-security"],
                    "missing": ["content-security-policy"],
                    "server": "nginx",
                    "cookie_security": {
                        "has_secure": True,
                        "has_httponly": True,
                        "has_samesite": False,
                    },
                },
            },
            "tls": {
                "subject": {"commonName": "example.com"},
                "issuer": {"commonName": "DigiCert"},
                "protocol": "TLSv1.3",
                "cipher": {"name": "TLS_AES_256_GCM_SHA384", "bits": 256},
                "expires": "2027-01-01T00:00:00Z",
                "days_remaining": 100,
                "is_expired": false if False else False,
            },
            "files": {
                "security_txt": {"found": True, "contacts": ["mailto:sec@example.com"]},
                "robots_txt": {"found": False, "status": 404},
            },
        }

        output = io.StringIO()
        error = io.StringIO()
        exit_code = main(
            ["example.com", "--summary"],
            stdout=output,
            stderr=error,
            collector=lambda _target, **_kwargs: fake_report,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("OSINT REPORT: example.com", output.getvalue())
        self.assertIn("IPv4:       93.184.216.34", output.getvalue())
        self.assertIn("TLSv1.3", output.getvalue())
        self.assertIn("mailto:sec@example.com", output.getvalue())
        self.assertEqual(error.getvalue(), "")

    def test_summary_mode_with_output_file_both_saves_and_prints(self):
        import tempfile
        import pathlib

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = pathlib.Path(temp_dir) / "out.json"
            fake_report = {"target": "example.com", "schema_version": 1}
            output = io.StringIO()
            error = io.StringIO()

            exit_code = main(
                ["example.com", "-s", "-o", str(file_path)],
                stdout=output,
                stderr=error,
                collector=lambda _target, **_kwargs: fake_report,
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(file_path.exists())
            self.assertEqual(json.loads(file_path.read_text(encoding="utf-8")), fake_report)
            self.assertIn("OSINT REPORT: example.com", output.getvalue())


if __name__ == "__main__":
    unittest.main()
