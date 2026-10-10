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

    def test_username_search_json_mode(self):
        output = io.StringIO()
        error = io.StringIO()
        fake_user_report = {
            "mode": "username",
            "target": "johndoe",
            "total_checked": 10,
            "found_count": 1,
            "found": [{"name": "GitHub", "url": "https://github.com/johndoe", "category": "Coding"}],
            "not_found": [],
        }

        exit_code = main(
            ["-u", "johndoe"],
            stdout=output,
            stderr=error,
            username_collector=lambda _u, **_kw: fake_user_report,
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue()), fake_user_report)
        self.assertEqual(error.getvalue(), "")

    def test_username_search_summary_mode(self):
        output = io.StringIO()
        error = io.StringIO()
        fake_user_report = {
            "mode": "username",
            "target": "johndoe",
            "total_checked": 2,
            "found_count": 1,
            "found": [{"name": "GitHub", "url": "https://github.com/johndoe", "category": "Coding & Tech"}],
            "not_found": [{"name": "FakeSite", "category": "Other"}],
        }

        exit_code = main(
            ["--username", "johndoe", "--summary"],
            stdout=output,
            stderr=error,
            username_collector=lambda _u, **_kw: fake_user_report,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("OSINT USERNAME REPORT: @johndoe", output.getvalue())
        self.assertIn("GitHub:", output.getvalue())
        self.assertIn("https://github.com/johndoe", output.getvalue())
        self.assertEqual(error.getvalue(), "")

    def test_missing_both_target_and_username_returns_error(self):
        output = io.StringIO()
        error = io.StringIO()

        exit_code = main([], stdout=output, stderr=error)
        self.assertEqual(exit_code, 2)
        self.assertIn("error:", error.getvalue())

    def test_cli_proxy_flag_passed_to_username_collector(self):
        captured_kwargs = {}

        def mock_user_collector(target, **kwargs):
            captured_kwargs.update(kwargs)
            return {"mode": "username", "target": target, "found": [], "not_found": []}

        output = io.StringIO()
        error = io.StringIO()
        exit_code = main(
            ["-u", "alice", "--proxy", "http://127.0.0.1:9050", "-j"],
            stdout=output,
            stderr=error,
            username_collector=mock_user_collector,
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(captured_kwargs.get("proxy"), "http://127.0.0.1:9050")

    def test_cli_csv_flag_outputs_csv(self):
        fake_user_report = {
            "mode": "username",
            "target": "alice",
            "found": [{"name": "GitHub", "category": "Coding & Tech", "status": 200, "url": "https://github.com/alice"}],
            "not_found": [{"name": "Keybase", "category": "Coding & Tech", "status": 404, "url": "https://keybase.io/alice"}],
        }

        output = io.StringIO()
        error = io.StringIO()
        exit_code = main(
            ["-u", "alice", "--csv"],
            stdout=output,
            stderr=error,
            username_collector=lambda _u, **_kw: fake_user_report,
        )
        self.assertEqual(exit_code, 0)
        csv_text = output.getvalue()
        self.assertIn("target,platform,category,exists,status,url", csv_text)
        self.assertIn("alice,GitHub,Coding & Tech,True,200,https://github.com/alice", csv_text)
        self.assertIn("alice,Keybase,Coding & Tech,False,404,https://keybase.io/alice", csv_text)

    def test_cli_csv_file_output(self):
        import tempfile
        import pathlib

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = pathlib.Path(temp_dir) / "results.csv"
            fake_domain_report = {
                "domain": "example.com",
                "dns": {"A": ["93.184.216.34"]},
            }

            output = io.StringIO()
            error = io.StringIO()
            exit_code = main(
                ["example.com", "-o", str(file_path)],
                stdout=output,
                stderr=error,
                collector=lambda _t, **_kw: fake_domain_report,
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(file_path.exists())
            content = file_path.read_text(encoding="utf-8")
            self.assertIn("target,section,key,value", content)
            self.assertIn("example.com,dns,A,93.184.216.34", content)


if __name__ == "__main__":
    unittest.main()
