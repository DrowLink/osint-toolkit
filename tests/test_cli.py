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

    def test_handles_output_file_error(self):
        output = io.StringIO()
        error = io.StringIO()
        exit_code = main(
            ["example.com", "-o", "/non_existent_dir_12345/report.json"],
            stdout=output,
            stderr=error,
            collector=lambda _target, **_kwargs: {"target": "example.com"},
        )
        self.assertEqual(exit_code, 2)
        self.assertIn("failed to write output file", error.getvalue())


if __name__ == "__main__":
    unittest.main()
