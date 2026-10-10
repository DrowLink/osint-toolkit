import io
import json
import unittest
from unittest.mock import MagicMock, patch

from osint_toolkit.cli import (
    main,
    main_censys,
    main_ip2location,
    main_shodan,
    main_virustotal,
)
from osint_toolkit.services import (
    is_valid_ip,
    resolve_target_ip,
    search_censys,
    search_ip2location,
    search_shodan,
    search_virustotal,
)


class ServicesTests(unittest.TestCase):
    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertTrue(is_valid_ip("2001:4860:4860::8888"))
        self.assertFalse(is_valid_ip("example.com"))
        self.assertFalse(is_valid_ip("invalid_ip"))

    def test_resolve_target_ip_rejects_private(self):
        with self.assertRaises(ValueError):
            resolve_target_ip("127.0.0.1")
        with self.assertRaises(ValueError):
            resolve_target_ip("192.168.1.1")

    @patch("osint_toolkit.services._http_get_json")
    def test_search_shodan_internetdb_success(self, mock_get):
        mock_get.return_value = (
            200,
            {
                "ip": "8.8.8.8",
                "ports": [53, 443],
                "cpes": [],
                "hostnames": ["dns.google"],
                "tags": [],
                "vulns": ["CVE-2020-0001"],
            },
            None,
        )
        res = search_shodan("8.8.8.8")
        self.assertEqual(res["service"], "shodan")
        self.assertTrue(res["found"])
        self.assertEqual(res["ports"], [53, 443])
        self.assertEqual(res["vulns"], ["CVE-2020-0001"])

    @patch("osint_toolkit.services._http_get_json")
    def test_search_shodan_internetdb_not_found(self, mock_get):
        mock_get.return_value = (404, None, "Not found")
        res = search_shodan("8.8.8.8")
        self.assertEqual(res["service"], "shodan")
        self.assertFalse(res["found"])
        self.assertEqual(res["ports"], [])

    @patch("osint_toolkit.services._http_get_json")
    def test_search_ip2location_success(self, mock_get):
        mock_get.return_value = (
            200,
            {
                "country_name": "United States",
                "country_code": "US",
                "city_name": "Mountain View",
                "region_name": "California",
                "latitude": 37.38605,
                "longitude": -122.08385,
                "zip_code": "94043",
                "time_zone": "-07:00",
                "asn": "15169",
                "as": "Google LLC",
                "is_proxy": False,
            },
            None,
        )
        res = search_ip2location("8.8.8.8")
        self.assertEqual(res["service"], "ip2location")
        self.assertTrue(res["found"])
        self.assertEqual(res["country_name"], "United States")
        self.assertEqual(res["asn"], "15169")
        self.assertFalse(res["is_proxy"])

    def test_search_virustotal_unauthenticated(self):
        res = search_virustotal("example.com")
        self.assertEqual(res["service"], "virustotal")
        self.assertFalse(res["authenticated"])
        self.assertIn("API key", res["message"])
        self.assertIn("virustotal.com/gui", res["web_url"])

    @patch("osint_toolkit.services._http_get_json")
    def test_search_virustotal_authenticated_success(self, mock_get):
        mock_get.return_value = (
            200,
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 80,
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 5,
                        },
                        "last_analysis_results": {
                            "BadVendor": {"category": "malicious"}
                        },
                        "reputation": 50,
                    }
                }
            },
            None,
        )
        res = search_virustotal("example.com", api_key="fake-key")
        self.assertTrue(res["authenticated"])
        self.assertTrue(res["found"])
        self.assertEqual(res["malicious_count"], 1)
        self.assertEqual(res["malicious_engines"], ["BadVendor"])

    def test_search_censys_unauthenticated(self):
        res = search_censys("8.8.8.8")
        self.assertEqual(res["service"], "censys")
        self.assertFalse(res["authenticated"])
        self.assertIn("credentials", res["message"])

    @patch("osint_toolkit.services._http_get_json")
    def test_search_censys_authenticated_success(self, mock_get):
        mock_get.return_value = (
            200,
            {
                "result": {
                    "services": [
                        {"port": 443, "service_name": "HTTP", "transport_protocol": "TCP"}
                    ],
                    "autonomous_system": {"asn": 15169, "name": "Google LLC"},
                    "location": {"country": "United States", "city": "Mountain View"},
                }
            },
            None,
        )
        res = search_censys("8.8.8.8", api_id="test_id", api_secret="test_sec")
        self.assertTrue(res["authenticated"])
        self.assertTrue(res["found"])
        self.assertEqual(len(res["services"]), 1)
        self.assertEqual(res["services"][0]["port"], 443)


class ServiceCliTests(unittest.TestCase):
    @patch("osint_toolkit.cli.search_shodan")
    def test_main_shodan_json_mode(self, mock_shodan):
        mock_shodan.return_value = {"service": "shodan", "ip": "8.8.8.8", "found": True}
        output = io.StringIO()
        error = io.StringIO()
        code = main_shodan(["8.8.8.8", "-j"], stdout=output, stderr=error)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["service"], "shodan")

    @patch("osint_toolkit.cli.search_ip2location")
    def test_main_ip2location_summary_mode(self, mock_ip):
        mock_ip.return_value = {
            "service": "ip2location",
            "ip": "8.8.8.8",
            "found": True,
            "country_name": "United States",
            "city_name": "Mountain View",
            "asn": "15169",
        }
        output = io.StringIO()
        error = io.StringIO()
        code = main_ip2location(["8.8.8.8", "-s"], stdout=output, stderr=error)
        self.assertEqual(code, 0)
        self.assertIn("IP2LOCATION INTELLIGENCE", output.getvalue())

    @patch("osint_toolkit.cli.search_virustotal")
    def test_main_subcommand_dispatch_virustotal(self, mock_vt):
        mock_vt.return_value = {
            "service": "virustotal",
            "resource": "google.com",
            "authenticated": False,
            "web_url": "https://www.virustotal.com/gui/domain/google.com",
        }
        output = io.StringIO()
        error = io.StringIO()
        code = main(["virustotal", "google.com", "-s"], stdout=output, stderr=error)
        self.assertEqual(code, 0)
        self.assertIn("VIRUSTOTAL REPORT", output.getvalue())

    @patch("osint_toolkit.cli.search_censys")
    def test_main_subcommand_dispatch_censys(self, mock_censys):
        mock_censys.return_value = {
            "service": "censys",
            "ip": "8.8.8.8",
            "authenticated": False,
            "web_url": "https://search.censys.io/hosts/8.8.8.8",
        }
        output = io.StringIO()
        error = io.StringIO()
        code = main(["censys", "8.8.8.8", "-s"], stdout=output, stderr=error)
        self.assertEqual(code, 0)
        self.assertIn("CENSYS INTELLIGENCE", output.getvalue())
