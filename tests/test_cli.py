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


if __name__ == "__main__":
    unittest.main()
