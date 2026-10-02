import socket
import threading
import time
import unittest

from osint_toolkit.core import (
    DomainValidationError,
    analyze_security_headers,
    normalize_domain,
    resolve_public_addresses,
)


class NormalizeDomainTests(unittest.TestCase):
    def test_normalizes_hostname_and_url_input(self):
        self.assertEqual(normalize_domain("Example.COM"), "example.com")
        self.assertEqual(
            normalize_domain("https://www.Example.com/path?q=1"), "www.example.com"
        )

    def test_rejects_non_domain_targets(self):
        for target in (
            "localhost",
            "127.0.0.1",
            "https://example.com:8443",
            "bad name.com",
        ):
            with self.subTest(target=target), self.assertRaises(DomainValidationError):
                normalize_domain(target)


class ResolutionTests(unittest.TestCase):
    def test_returns_sorted_unique_public_addresses(self):
        answers = [
            (socket.AF_INET, 1, 6, "", ("93.184.216.34", 0)),
            (
                socket.AF_INET6,
                1,
                6,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0),
            ),
            (socket.AF_INET, 1, 6, "", ("93.184.216.34", 0)),
        ]
        self.assertEqual(
            resolve_public_addresses(
                "example.com", getaddrinfo=lambda *_args, **_kwargs: answers
            ),
            ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
        )

    def test_rejects_any_non_global_resolution(self):
        answers = [(socket.AF_INET, 1, 6, "", ("127.0.0.1", 0))]
        with self.assertRaises(DomainValidationError):
            resolve_public_addresses(
                "example.com", getaddrinfo=lambda *_args, **_kwargs: answers
            )

    def test_rejects_more_than_eight_unique_addresses(self):
        answers = [
            (socket.AF_INET, 1, 6, "", (f"8.8.8.{index}", 0)) for index in range(1, 10)
        ]
        with self.assertRaisesRegex(DomainValidationError, "too many addresses"):
            resolve_public_addresses(
                "example.com", getaddrinfo=lambda *_args, **_kwargs: answers
            )

    def test_rejects_nat64_addresses_embedding_non_global_ipv4(self):
        for translated in ("64:ff9b::7f00:1", "64:ff9b::a00:1"):
            answers = [(socket.AF_INET6, 1, 6, "", (translated, 0, 0, 0))]
            with (
                self.subTest(address=translated),
                self.assertRaisesRegex(DomainValidationError, "non-public"),
            ):
                resolve_public_addresses(
                    "example.com",
                    getaddrinfo=lambda *_args, _answers=answers, **_kwargs: _answers,
                )

    def test_rejects_multicast_answers_even_when_ipaddress_calls_them_global(self):
        for value in ("224.0.0.1", "ff0e::1"):
            family = socket.AF_INET6 if ":" in value else socket.AF_INET
            sockaddr = (value, 0, 0, 0) if family == socket.AF_INET6 else (value, 0)
            answers = [(family, 1, 6, "", sockaddr)]
            with (
                self.subTest(address=value),
                self.assertRaisesRegex(DomainValidationError, "non-public unicast"),
            ):
                resolve_public_addresses(
                    "example.com",
                    getaddrinfo=lambda *_args, _answers=answers, **_kwargs: _answers,
                )

    def test_rejects_other_non_unicast_and_non_routable_categories(self):
        values = (
            "0.0.0.0",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "240.0.0.1",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
        )
        for value in values:
            family = socket.AF_INET6 if ":" in value else socket.AF_INET
            sockaddr = (value, 0, 0, 0) if family == socket.AF_INET6 else (value, 0)
            answers = [(family, 1, 6, "", sockaddr)]
            with (
                self.subTest(address=value),
                self.assertRaisesRegex(DomainValidationError, "non-public unicast"),
            ):
                resolve_public_addresses(
                    "example.com",
                    getaddrinfo=lambda *_args, _answers=answers, **_kwargs: _answers,
                )

    def test_stalled_dns_resolution_obeys_absolute_deadline_in_daemon_thread(self):
        release = threading.Event()
        resolver_thread = []

        def stalled_getaddrinfo(*_args, **_kwargs):
            resolver_thread.append(threading.current_thread())
            release.wait(1.0)
            return []

        started = time.monotonic()
        try:
            with self.assertRaisesRegex(
                DomainValidationError, "DNS resolution deadline exceeded"
            ):
                resolve_public_addresses(
                    "example.com",
                    getaddrinfo=stalled_getaddrinfo,
                    deadline=time.monotonic() + 0.05,
                )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.5)
            self.assertEqual(len(resolver_thread), 1)
            self.assertTrue(resolver_thread[0].daemon)
            self.assertTrue(resolver_thread[0].is_alive())
        finally:
            release.set()
            if resolver_thread:
                resolver_thread[0].join(1.0)

    def test_expired_dns_deadline_does_not_start_resolution(self):
        calls = []

        with self.assertRaisesRegex(DomainValidationError, "DNS resolution deadline"):
            resolve_public_addresses(
                "example.com",
                getaddrinfo=lambda *_args, **_kwargs: calls.append(True),
                deadline=time.monotonic() - 1.0,
            )

        self.assertEqual(calls, [])


class HeaderTests(unittest.TestCase):
    def test_reports_present_and_missing_security_headers(self):
        result = analyze_security_headers(
            {"Strict-Transport-Security": "max-age=31536000", "Server": "nginx"}
        )
        self.assertEqual(result["present"], ["strict-transport-security"])
        self.assertIn("content-security-policy", result["missing"])
        self.assertEqual(result["server"], "nginx")


if __name__ == "__main__":
    unittest.main()
