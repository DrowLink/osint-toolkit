import unittest

from osint_toolkit.username import (
    UsernameValidationError,
    check_site,
    search_username,
    validate_username,
)


class UsernameValidationTests(unittest.TestCase):
    def test_validates_and_normalizes_valid_usernames(self):
        self.assertEqual(validate_username("johndoe"), "johndoe")
        self.assertEqual(validate_username("@johndoe"), "johndoe")
        self.assertEqual(validate_username("john_doe-123.test"), "john_doe-123.test")

    def test_rejects_invalid_usernames(self):
        for invalid in ("", "   ", "@", "user with spaces", "user$name", "a" * 70):
            with self.subTest(username=invalid), self.assertRaises(UsernameValidationError):
                validate_username(invalid)


class SiteCheckTests(unittest.TestCase):
    def test_status_code_detection(self):
        site = {
            "name": "TestPlatform",
            "category": "Tech",
            "url": "https://example.com/{username}",
            "type": "status_code",
        }

        # User exists (200)
        res_exists = check_site(
            site, "johndoe", http_requester=lambda _url, **_kw: (200, "welcome")
        )
        self.assertTrue(res_exists["exists"])
        self.assertEqual(res_exists["status"], 200)

        # User does not exist (404)
        res_missing = check_site(
            site, "johndoe", http_requester=lambda _url, **_kw: (404, "not found")
        )
        self.assertFalse(res_missing["exists"])
        self.assertEqual(res_missing["status"], 404)

    def test_message_absent_pattern_detection(self):
        site = {
            "name": "MessagePlatform",
            "category": "Gaming",
            "url": "https://example.com/id/{username}",
            "type": "message",
            "absent_pattern": "profile could not be found",
        }

        # User exists (pattern not in body)
        res_exists = check_site(
            site, "johndoe", http_requester=lambda _url, **_kw: (200, "hello profile")
        )
        self.assertTrue(res_exists["exists"])

        # User does not exist (pattern is in body)
        res_missing = check_site(
            site, "johndoe", http_requester=lambda _url, **_kw: (200, "The profile could not be found.")
        )
        self.assertFalse(res_missing["exists"])

    def test_message_present_pattern_detection(self):
        site = {
            "name": "TelegramLike",
            "category": "Messaging",
            "url": "https://example.com/{username}",
            "type": "message",
            "present_pattern": "extra_badge",
        }

        # Pattern present in body -> exists
        res_exists = check_site(
            site, "johndoe", http_requester=lambda _url, **_kw: (200, "user extra_badge info")
        )
        self.assertTrue(res_exists["exists"])

        # Pattern absent -> missing
        res_missing = check_site(
            site, "johndoe", http_requester=lambda _url, **_kw: (200, "no user here")
        )
        self.assertFalse(res_missing["exists"])

    def test_handles_network_exceptions_gracefully(self):
        site = {
            "name": "FailingPlatform",
            "category": "Other",
            "url": "https://example.com/{username}",
            "type": "status_code",
        }

        def failing_requester(_url, **_kw):
            raise OSError("Connection timed out")

        res = check_site(site, "johndoe", http_requester=failing_requester)
        self.assertFalse(res["exists"])
        self.assertIn("Error:", str(res["status"]))


class SearchUsernameTests(unittest.TestCase):
    def test_searches_concurrently_across_sites(self):
        mock_sites = [
            {"name": "SiteA", "category": "Coding", "url": "https://sitea.com/{username}", "type": "status_code"},
            {"name": "SiteB", "category": "Social", "url": "https://siteb.com/{username}", "type": "status_code"},
        ]

        def fake_checker(site, username, **_kw):
            exists = site["name"] == "SiteA"
            return {
                "name": site["name"],
                "category": site["category"],
                "url": site["url"].format(username=username),
                "exists": exists,
                "status": 200 if exists else 404,
            }

        report = search_username("alice", sites=mock_sites, checker=fake_checker)

        self.assertEqual(report["target"], "alice")
        self.assertEqual(report["mode"], "username")
        self.assertEqual(report["total_checked"], 2)
        self.assertEqual(report["found_count"], 1)
        self.assertEqual(report["found"][0]["name"], "SiteA")
        self.assertEqual(report["not_found"][0]["name"], "SiteB")

    def test_search_username_with_proxy(self):
        recorded_proxies = []

        def proxy_checker(site, username, timeout=6.0, proxy=None):
            recorded_proxies.append(proxy)
            return {
                "name": site["name"],
                "category": site["category"],
                "url": site["url"].format(username=username),
                "exists": True,
                "status": 200,
            }

        mock_sites = [{"name": "SiteX", "category": "Tech", "url": "https://sitex.com/{username}", "type": "status_code"}]
        report = search_username("alice", sites=mock_sites, checker=proxy_checker, proxy="http://127.0.0.1:8080")

        self.assertEqual(report["proxy_used"], "http://127.0.0.1:8080")
        self.assertEqual(recorded_proxies, ["http://127.0.0.1:8080"])

    def test_sites_registry_has_over_50_verified_platforms(self):
        from osint_toolkit.username import SITES

        self.assertGreaterEqual(len(SITES), 50)
        names = set()
        for site in SITES:
            self.assertIn("name", site)
            self.assertIn("category", site)
            self.assertIn("url", site)
            self.assertIn("type", site)
            self.assertNotIn(site["name"], names, f"Duplicate platform: {site['name']}")
            names.add(site["name"])


if __name__ == "__main__":
    unittest.main()
