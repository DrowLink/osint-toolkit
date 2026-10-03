import http.client
import unittest
from unittest.mock import patch

from osint_toolkit import collector
from osint_toolkit.collector import (
    collect_report,
    fetch_public_url,
    probe_tls_certificate,
)


class CollectorTests(unittest.TestCase):
    def test_builds_report_from_passive_sources(self):
        def fake_fetch(url):
            if url.endswith("/.well-known/security.txt"):
                return {
                    "url": url,
                    "status": 200,
                    "headers": {},
                    "title": None,
                    "text": "Contact: mailto:security@example.com",
                }
            if url.endswith("/robots.txt"):
                return {
                    "url": url,
                    "status": 404,
                    "headers": {},
                    "title": None,
                    "text": "",
                }
            return {
                "url": "https://example.com/",
                "status": 200,
                "headers": {"Strict-Transport-Security": "max-age=31536000"},
                "title": "Example Domain",
                "text": "",
            }

        report = collect_report(
            "Example.COM",
            resolver=lambda _domain, **_kwargs: ["93.184.216.34"],
            fetcher=fake_fetch,
            certificate_probe=lambda _domain, _addresses: {
                "expires": "2030-01-01T00:00:00Z"
            },
        )

        self.assertEqual(report["target"], "example.com")
        self.assertEqual(report["dns"]["addresses"], ["93.184.216.34"])
        self.assertEqual(report["web"]["title"], "Example Domain")
        self.assertTrue(report["files"]["security_txt"]["found"])
        self.assertFalse(report["files"]["robots_txt"]["found"])
        self.assertEqual(report["tls"]["expires"], "2030-01-01T00:00:00Z")

    def test_follows_location_header_case_insensitively(self):
        redirect = {
            "url": "https://example.com/",
            "status": 302,
            "headers": {"location": "/final"},
            "title": None,
            "text": "",
        }
        final = {
            "url": "https://example.com/final",
            "status": 200,
            "headers": {},
            "title": None,
            "text": "ok",
        }
        with patch(
            "osint_toolkit.collector._request_once", side_effect=[redirect, final]
        ) as request:
            result = fetch_public_url("https://example.com/")

        self.assertEqual(result, final)
        self.assertEqual(request.call_count, 2)

    def test_redirects_share_one_monotonic_deadline(self):
        redirect = {
            "url": "https://example.com/",
            "status": 302,
            "headers": {"Location": "/final"},
            "title": None,
            "text": "",
        }
        final = {
            "url": "https://example.com/final",
            "status": 200,
            "headers": {},
            "title": None,
            "text": "ok",
        }
        with (
            patch("time.monotonic", return_value=100.0),
            patch(
                "osint_toolkit.collector._request_once", side_effect=[redirect, final]
            ) as request,
        ):
            fetch_public_url("https://example.com/", timeout=8.0)

        self.assertEqual(
            [item.args[1] for item in request.call_args_list], [108.0, 108.0]
        )

    def test_each_redirect_resolves_again_under_original_deadline(self):
        first = {
            "url": "https://example.com/",
            "status": 302,
            "headers": {"Location": "https://www.example.com/final"},
            "title": None,
            "text": "",
        }
        second = {
            "url": "https://www.example.com/final",
            "status": 200,
            "headers": {},
            "title": None,
            "text": "ok",
        }

        with (
            patch("osint_toolkit.collector.time.monotonic", return_value=100.0),
            patch(
                "osint_toolkit.collector.resolve_public_addresses",
                return_value=["93.184.216.34"],
            ) as resolve,
            patch(
                "osint_toolkit.collector._connect_and_request",
                side_effect=[first, second],
            ),
        ):
            result = fetch_public_url("https://example.com/", timeout=8.0)

        self.assertEqual(result, second)
        self.assertEqual(
            resolve.call_args_list,
            [
                unittest.mock.call("example.com", deadline=108.0),
                unittest.mock.call("www.example.com", deadline=108.0),
            ],
        )

    def test_ipv6_only_dns_returns_structured_errors_without_network_probes(self):
        fetch = unittest.mock.Mock()
        certificate = unittest.mock.Mock()

        report = collect_report(
            "example.com",
            resolver=lambda _domain, **_kwargs: ["2606:4700:4700::1111"],
            fetcher=fetch,
            certificate_probe=certificate,
        )

        self.assertEqual(report["dns"]["addresses"], ["2606:4700:4700::1111"])
        self.assertEqual(report["web"]["error"]["type"], "network_probe_error")
        self.assertEqual(report["tls"]["error"]["type"], "network_probe_error")
        self.assertEqual(
            report["files"]["security_txt"]["error"]["type"], "network_probe_error"
        )
        fetch.assert_not_called()
        certificate.assert_not_called()

    def test_fetch_rejects_ipv6_only_dns_without_connecting(self):
        with (
            patch(
                "osint_toolkit.collector.resolve_public_addresses",
                return_value=["2606:4700:4700::1111"],
            ),
            patch("osint_toolkit.collector.socket.create_connection") as connect,
            self.assertRaisesRegex(OSError, "public IPv4"),
        ):
            fetch_public_url("https://example.com/")
        connect.assert_not_called()

    def test_slow_drip_socket_activity_cannot_outlive_deadline(self):
        class DripSocket:
            def __init__(self):
                self.now = 0.0
                self.timeouts = []

            def settimeout(self, timeout):
                self.timeouts.append(timeout)

            def recv_into(self, buffer):
                self.now += 0.6
                buffer[0] = ord("x")
                return 1

        raw = DripSocket()
        with patch(
            "osint_toolkit.collector.time.monotonic", side_effect=lambda: raw.now
        ):
            stream = collector._DeadlineSocket(raw, deadline=1.0)
            stream.recv_into(bytearray(1))
            stream.recv_into(bytearray(1))
            with self.assertRaisesRegex(TimeoutError, "overall request deadline"):
                stream.recv_into(bytearray(1))

        self.assertEqual(raw.timeouts, [1.0, 0.4])

    def test_tls_address_attempts_share_one_monotonic_deadline(self):
        with (
            patch(
                "osint_toolkit.collector.time.monotonic",
                side_effect=[100.0, 102.0, 104.0],
            ),
            patch(
                "osint_toolkit.collector.socket.create_connection",
                side_effect=OSError("no"),
            ) as connect,
            self.assertRaises(OSError),
        ):
            probe_tls_certificate("example.com", ["1.1.1.1", "8.8.8.8"], timeout=8.0)

        self.assertEqual(
            [item.kwargs["timeout"] for item in connect.call_args_list],
            [6.0, 4.0],
        )

    def test_http_protocol_errors_become_structured_collection_errors(self):
        for error in (
            http.client.BadStatusLine("broken status"),
            http.client.IncompleteRead(b"partial", 10),
        ):
            with self.subTest(error=type(error).__name__):

                def broken_fetch(_url, failure=error):
                    raise failure

                report = collect_report(
                    "example.com",
                    resolver=lambda _domain, **_kwargs: ["93.184.216.34"],
                    fetcher=broken_fetch,
                    certificate_probe=lambda _domain, _addresses: {},
                )

                self.assertIn("error", report["web"])
                self.assertIn("error", report["files"]["security_txt"])
                self.assertIn("error", report["files"]["robots_txt"])

    def test_parses_security_txt_and_robots_txt_directives(self):
        def fake_fetch(url):
            if "security.txt" in url:
                return {
                    "url": url,
                    "status": 200,
                    "headers": {},
                    "title": None,
                    "text": (
                        "Contact: mailto:security@example.com\n"
                        "Contact: https://example.com/bounty\n"
                        "Expires: 2030-12-31T23:59:59.000Z\n"
                    ),
                }
            if "robots.txt" in url:
                return {
                    "url": url,
                    "status": 200,
                    "headers": {},
                    "title": None,
                    "text": (
                        "User-agent: *\n"
                        "Disallow: /admin\n"
                        "Sitemap: https://example.com/sitemap.xml\n"
                        "Sitemap: https://example.com/sitemap2.xml\n"
                    ),
                }
            return {
                "url": url,
                "status": 200,
                "headers": {},
                "title": "Home",
                "text": "<html><head><meta name='description' content='Passive tool'></head></html>",
                "meta": {"description": "Passive tool"},
            }

        report = collect_report(
            "example.com",
            resolver=lambda _domain, **_kwargs: ["93.184.216.34"],
            fetcher=fake_fetch,
            certificate_probe=lambda _domain, _addresses: {"expires": "2030-01-01T00:00:00Z"},
        )

        sec = report["files"]["security_txt"]
        self.assertEqual(
            sec["contacts"],
            ["mailto:security@example.com", "https://example.com/bounty"],
        )
        self.assertEqual(sec["expires"], "2030-12-31T23:59:59.000Z")

        rob = report["files"]["robots_txt"]
        self.assertEqual(
            rob["sitemaps"],
            ["https://example.com/sitemap.xml", "https://example.com/sitemap2.xml"],
        )
        self.assertEqual(report["web"]["meta"], {"description": "Passive tool"})

    def test_decompresses_gzip_response(self):
        import gzip
        from unittest.mock import MagicMock

        html = b"<html><head><title>Gzipped Page</title></head><body>Compressed content</body></html>"
        compressed = gzip.compress(html)

        mock_socket = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheaders.return_value = [
            ("Content-Encoding", "gzip"),
            ("Content-Type", "text/html; charset=utf-8"),
        ]
        mock_response.read.return_value = compressed

        with (
            patch("osint_toolkit.collector.socket.create_connection", return_value=mock_socket),
            patch("osint_toolkit.collector._DeadlineSocket", return_value=mock_socket),
            patch("osint_toolkit.collector.http.client.HTTPResponse", return_value=mock_response),
        ):
            result = collector._connect_and_request(
                "http://example.com/",
                "example.com",
                ["93.184.216.34"],
                deadline=collector.time.monotonic() + 10.0,
            )

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["title"], "Gzipped Page")
        self.assertIn("Compressed content", result["text"])

    def test_probe_tls_certificate_extracts_crypto_details(self):
        from unittest.mock import MagicMock

        raw_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "DigiCert"),),),
            "notAfter": "Jan 01 00:00:00 2030 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        }
        mock_raw = MagicMock()
        mock_raw.__enter__.return_value = mock_raw
        mock_secure = MagicMock()
        mock_secure.__enter__.return_value = mock_secure
        mock_secure.getpeercert.side_effect = lambda binary_form=False: (
            b"fake_der" if binary_form else raw_cert
        )
        mock_secure.version.return_value = "TLSv1.3"
        mock_secure.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_secure

        with (
            patch("osint_toolkit.collector.socket.create_connection", return_value=mock_raw),
            patch("osint_toolkit.collector.ssl.create_default_context", return_value=mock_context),
        ):
            res = probe_tls_certificate("example.com", ["93.184.216.34"])

        self.assertEqual(res["protocol"], "TLSv1.3")
        self.assertEqual(res["cipher"]["name"], "TLS_AES_256_GCM_SHA384")
        self.assertEqual(res["cipher"]["bits"], 256)
        self.assertFalse(res["is_expired"])
        self.assertGreater(res["days_remaining"], 365)


if __name__ == "__main__":
    unittest.main()
