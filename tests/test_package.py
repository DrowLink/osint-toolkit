import subprocess
import sys
import unittest


class PackageIntegrationTests(unittest.TestCase):
    def test_python_module_entrypoint_runs(self):
        result = subprocess.run(
            [sys.executable, "-m", "osint_toolkit", "localhost"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_timed_out_resolver_thread_does_not_block_process_exit(self):
        program = """
import threading
import time
from osint_toolkit.core import DomainValidationError, resolve_public_addresses

def stall(*args, **kwargs):
    threading.Event().wait()

try:
    resolve_public_addresses(
        "example.com", getaddrinfo=stall, deadline=time.monotonic() + 0.02
    )
except DomainValidationError:
    print("bounded")
"""
        result = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "bounded")


if __name__ == "__main__":
    unittest.main()
