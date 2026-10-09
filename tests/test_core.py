import socket
import threading
import time
import unittest

from osint_toolkit.core import (
    DomainValidationError,
    analyze_security_headers,
    extract_meta_tags,
    normalize_domain,
    parse_dmarc_record,
    parse_ip_info,
    parse_mx_records,
    parse_rdap_response,
    parse_soa_record,
    parse_spf_record,
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
        self.assertIn("cross-origin-opener-policy", result["missing"])
        self.assertIn("cross-origin-embedder-policy", result["missing"])
        self.assertIn("cross-origin-resource-policy", result["missing"])
        self.assertEqual(result["server"], "nginx")
        self.assertNotIn("cookie_security", result)

    def test_analyzes_cookie_security_flags(self):
        result = analyze_security_headers(
            {
                "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict",
            }
        )
        self.assertIn("cookie_security", result)
        self.assertTrue(result["cookie_security"]["has_secure"])
        self.assertTrue(result["cookie_security"]["has_httponly"])
        self.assertTrue(result["cookie_security"]["has_samesite"])

        insecure = analyze_security_headers({"Set-Cookie": "tracker=123; path=/"})
        self.assertIn("cookie_security", insecure)
        self.assertFalse(insecure["cookie_security"]["has_secure"])
        self.assertFalse(insecure["cookie_security"]["has_httponly"])
        self.assertFalse(insecure["cookie_security"]["has_samesite"])


class MetaTagTests(unittest.TestCase):
    def test_extracts_description_and_generator(self):
        html = (
            "<html><head>"
            '<meta name="description" content="A safe OSINT toolkit.">'
            '<meta name="generator" content="WordPress 6.4">'
            '<meta name="author" content="Nobody">'
            "</head><body>Hello</body></html>"
        )
        meta = extract_meta_tags(html)
        self.assertEqual(
            meta,
            {
                "description": "A safe OSINT toolkit.",
                "generator": "WordPress 6.4",
            },
        )

    def test_extracts_meta_when_content_precedes_name(self):
        html = '<meta content="My Description" name="description">'
        self.assertEqual(extract_meta_tags(html), {"description": "My Description"})


class DnsParsingTests(unittest.TestCase):
    def test_parses_and_identifies_mail_providers(self):
        records = [
            "20 alt1.aspmx.l.google.com.",
            "10 aspmx.l.google.com.",
            "0 example-com.mail.protection.outlook.com.",
            "10 mail.protonmail.ch.",
            "50 mx.customhost.org.",
        ]
        parsed = parse_mx_records(records)
        self.assertEqual(len(parsed), 5)
        # Should be sorted by preference
        self.assertEqual(parsed[0]["preference"], 0)
        self.assertEqual(parsed[0]["provider"], "Microsoft 365")
        self.assertEqual(parsed[1]["preference"], 10)
        self.assertEqual(parsed[1]["provider"], "Google Workspace")
        self.assertEqual(parsed[2]["preference"], 10)
        self.assertEqual(parsed[2]["provider"], "Proton Mail")
        self.assertEqual(parsed[4]["preference"], 50)
        self.assertEqual(parsed[4]["provider"], "Custom / Self-hosted")

    def test_parses_spf_records(self):
        txt_records = [
            '"v=spf1 include:_spf.google.com ~all"',
            '"google-site-verification=abc"',
        ]
        spf = parse_spf_record(txt_records)
        self.assertIsNotNone(spf)
        self.assertEqual(spf["policy"], "~all")
        self.assertEqual(spf["strength"], "SoftFail (Recommended)")
        self.assertEqual(spf["includes"], ["_spf.google.com"])

        strict_spf = parse_spf_record(['v=spf1 ip4:192.0.2.1 -all'])
        self.assertEqual(strict_spf["policy"], "-all")
        self.assertEqual(strict_spf["strength"], "Fail (Strict)")

        insecure_spf = parse_spf_record(['v=spf1 +all'])
        self.assertEqual(insecure_spf["strength"], "Pass (Insecure)")

        no_spf = parse_spf_record(['some text record'])
        self.assertIsNone(no_spf)

    def test_parses_dmarc_records(self):
        record = '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"'
        dmarc = parse_dmarc_record(record)
        self.assertIsNotNone(dmarc)
        self.assertEqual(dmarc["policy"], "reject")
        self.assertIn("Reject", dmarc["enforcement"])
        self.assertEqual(dmarc["rua"], "mailto:dmarc@example.com")
        self.assertEqual(dmarc["percentage"], "100")

        quar_record = 'v=DMARC1; p=quarantine'
        quar = parse_dmarc_record(quar_record)
        self.assertEqual(quar["policy"], "quarantine")
        self.assertIn("Quarantine", quar["enforcement"])

        none_record = 'v=DMARC1; p=none'
        none_dmarc = parse_dmarc_record(none_record)
        self.assertEqual(none_dmarc["policy"], "none")
        self.assertIn("None", none_dmarc["enforcement"])

        self.assertIsNone(parse_dmarc_record(None))
        self.assertIsNone(parse_dmarc_record("v=spf1 ..."))

    def test_parses_soa_records(self):
        soa_raw = "ns1.google.com. dns-admin.google.com. 996430997 900 900 1800 60"
        soa = parse_soa_record(soa_raw)
        self.assertIsNotNone(soa)
        self.assertEqual(soa["primary_ns"], "ns1.google.com")
        self.assertEqual(soa["admin_email"], "dns-admin@google.com")
        self.assertEqual(soa["serial"], "996430997")
        self.assertIsNone(parse_soa_record(None))


class RdapAndNetworkParsingTests(unittest.TestCase):
    def test_parses_rdap_response(self):
        data = {
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]],
                }
            ],
            "events": [
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2019-09-09T15:39:04Z"},
            ],
            "status": ["clientDeleteProhibited", "clientTransferProhibited"],
        }
        rdap = parse_rdap_response(data)
        self.assertEqual(rdap["registrar"], "MarkMonitor Inc.")
        self.assertEqual(rdap["created"], "1997-09-15T04:00:00Z")
        self.assertEqual(rdap["expires"], "2028-09-14T04:00:00Z")
        self.assertIn("clientDeleteProhibited", rdap["status"])

    def test_parses_ip_info(self):
        data = {
            "ip": "142.251.210.78",
            "asn": "AS15169",
            "org": "Google LLC",
            "country_name": "United States",
            "country_code": "US",
            "city": "Chicago",
            "region": "Illinois",
        }
        info = parse_ip_info(data)
        self.assertEqual(info["asn"], "AS15169")
        self.assertEqual(info["org"], "Google LLC")
        self.assertEqual(info["country"], "United States")
        self.assertEqual(info["city"], "Chicago")


if __name__ == "__main__":
    unittest.main()

