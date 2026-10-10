"""Passive username enumeration across public platforms."""

from __future__ import annotations

import concurrent.futures
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")

# Curated registry of platforms with verified passive detection
SITES: list[dict[str, Any]] = [
    # Coding & Tech (17)
    {
        "name": "GitHub",
        "category": "Coding & Tech",
        "url": "https://github.com/{username}",
        "type": "status_code",
    },
    {
        "name": "GitLab",
        "category": "Coding & Tech",
        "url": "https://gitlab.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Codeberg",
        "category": "Coding & Tech",
        "url": "https://codeberg.org/{username}",
        "type": "status_code",
    },
    {
        "name": "Bitbucket",
        "category": "Coding & Tech",
        "url": "https://bitbucket.org/{username}/",
        "type": "status_code",
    },
    {
        "name": "Docker Hub",
        "category": "Coding & Tech",
        "url": "https://hub.docker.com/v2/users/{username}/",
        "profile_url": "https://hub.docker.com/u/{username}",
        "type": "status_code",
    },
    {
        "name": "PyPI",
        "category": "Coding & Tech",
        "url": "https://pypi.org/user/{username}/",
        "type": "status_code",
    },
    {
        "name": "npm",
        "category": "Coding & Tech",
        "url": "https://www.npmjs.com/~{username}",
        "type": "status_code",
    },
    {
        "name": "Crates.io",
        "category": "Coding & Tech",
        "url": "https://crates.io/api/v1/users/{username}",
        "profile_url": "https://crates.io/users/{username}",
        "type": "status_code",
    },
    {
        "name": "Dev.to",
        "category": "Coding & Tech",
        "url": "https://dev.to/{username}",
        "type": "status_code",
    },
    {
        "name": "Hashnode",
        "category": "Coding & Tech",
        "url": "https://hashnode.com/@{username}",
        "type": "status_code",
    },
    {
        "name": "Keybase",
        "category": "Coding & Tech",
        "url": "https://keybase.io/{username}",
        "type": "status_code",
    },
    {
        "name": "HackerNews",
        "category": "Coding & Tech",
        "url": "https://news.ycombinator.com/user?id={username}",
        "type": "message",
        "absent_pattern": "No such user",
    },
    {
        "name": "Kaggle",
        "category": "Coding & Tech",
        "url": "https://www.kaggle.com/{username}",
        "type": "status_code",
    },
    {
        "name": "LeetCode",
        "category": "Coding & Tech",
        "url": "https://leetcode.com/{username}/",
        "type": "status_code",
    },
    {
        "name": "TryHackMe",
        "category": "Coding & Tech",
        "url": "https://tryhackme.com/p/{username}",
        "type": "status_code",
    },
    {
        "name": "Replit",
        "category": "Coding & Tech",
        "url": "https://replit.com/@{username}",
        "type": "status_code",
    },
    {
        "name": "Pastebin",
        "category": "Coding & Tech",
        "url": "https://pastebin.com/u/{username}",
        "type": "status_code",
    },

    # Social & Messaging (13)
    {
        "name": "Telegram",
        "category": "Social & Messaging",
        "url": "https://t.me/{username}",
        "type": "message",
        "present_pattern": "tgme_page_extra",
    },
    {
        "name": "Reddit",
        "category": "Social & Messaging",
        "url": "https://www.reddit.com/user/{username}/about.json",
        "profile_url": "https://www.reddit.com/user/{username}",
        "type": "status_code",
    },
    {
        "name": "Mastodon",
        "category": "Social & Messaging",
        "url": "https://mastodon.social/@{username}",
        "type": "status_code",
    },
    {
        "name": "Bluesky",
        "category": "Social & Messaging",
        "url": "https://bsky.app/profile/{username}.bsky.social",
        "type": "status_code",
    },
    {
        "name": "Disqus",
        "category": "Social & Messaging",
        "url": "https://disqus.com/by/{username}/",
        "type": "status_code",
    },
    {
        "name": "Linktree",
        "category": "Social & Messaging",
        "url": "https://linktr.ee/{username}",
        "type": "status_code",
    },
    {
        "name": "Gravatar",
        "category": "Social & Messaging",
        "url": "https://en.gravatar.com/{username}.json",
        "profile_url": "https://gravatar.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Pinterest",
        "category": "Social & Messaging",
        "url": "https://www.pinterest.com/{username}/",
        "type": "status_code",
    },
    {
        "name": "BuyMeACoffee",
        "category": "Social & Messaging",
        "url": "https://www.buymeacoffee.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Ko-fi",
        "category": "Social & Messaging",
        "url": "https://ko-fi.com/{username}",
        "type": "status_code",
    },
    {
        "name": "ProductHunt",
        "category": "Social & Messaging",
        "url": "https://www.producthunt.com/@{username}",
        "type": "status_code",
    },
    {
        "name": "About.me",
        "category": "Social & Messaging",
        "url": "https://about.me/{username}",
        "type": "status_code",
    },
    {
        "name": "Quora",
        "category": "Social & Messaging",
        "url": "https://www.quora.com/profile/{username}",
        "type": "status_code",
    },

    # Gaming & Entertainment (9)
    {
        "name": "Steam",
        "category": "Gaming & Entertainment",
        "url": "https://steamcommunity.com/id/{username}",
        "type": "message",
        "absent_pattern": "The specified profile could not be found",
    },
    {
        "name": "Chess.com",
        "category": "Gaming & Entertainment",
        "url": "https://api.chess.com/pub/player/{username}",
        "profile_url": "https://www.chess.com/member/{username}",
        "type": "status_code",
    },
    {
        "name": "Lichess",
        "category": "Gaming & Entertainment",
        "url": "https://lichess.org/api/user/{username}",
        "profile_url": "https://lichess.org/@/{username}",
        "type": "status_code",
    },
    {
        "name": "itch.io",
        "category": "Gaming & Entertainment",
        "url": "https://{username}.itch.io",
        "type": "status_code",
    },
    {
        "name": "Roblox",
        "category": "Gaming & Entertainment",
        "url": "https://www.roblox.com/user.aspx?username={username}",
        "type": "status_code",
    },
    {
        "name": "Speedrun.com",
        "category": "Gaming & Entertainment",
        "url": "https://www.speedrun.com/users/{username}",
        "type": "status_code",
    },
    {
        "name": "osu!",
        "category": "Gaming & Entertainment",
        "url": "https://osu.ppy.sh/users/{username}",
        "type": "status_code",
    },
    {
        "name": "Letterboxd",
        "category": "Gaming & Entertainment",
        "url": "https://letterboxd.com/{username}/",
        "type": "status_code",
    },
    {
        "name": "Chessgames",
        "category": "Gaming & Entertainment",
        "url": "https://www.chessgames.com/perl/chessplayer?pid={username}",
        "type": "message",
        "absent_pattern": "not found in our database",
    },

    # Design & Audio (10)
    {
        "name": "SoundCloud",
        "category": "Design & Audio",
        "url": "https://soundcloud.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Spotify",
        "category": "Design & Audio",
        "url": "https://open.spotify.com/user/{username}",
        "type": "status_code",
    },
    {
        "name": "Bandcamp",
        "category": "Design & Audio",
        "url": "https://{username}.bandcamp.com",
        "type": "status_code",
    },
    {
        "name": "Behance",
        "category": "Design & Audio",
        "url": "https://www.behance.net/{username}",
        "type": "status_code",
    },
    {
        "name": "Dribbble",
        "category": "Design & Audio",
        "url": "https://dribbble.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Flickr",
        "category": "Design & Audio",
        "url": "https://www.flickr.com/people/{username}/",
        "type": "status_code",
    },
    {
        "name": "500px",
        "category": "Design & Audio",
        "url": "https://500px.com/p/{username}",
        "type": "status_code",
    },
    {
        "name": "DeviantArt",
        "category": "Design & Audio",
        "url": "https://www.deviantart.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Unsplash",
        "category": "Design & Audio",
        "url": "https://unsplash.com/@{username}",
        "type": "status_code",
    },
    {
        "name": "Mixcloud",
        "category": "Design & Audio",
        "url": "https://www.mixcloud.com/{username}/",
        "type": "status_code",
    },

    # Publishing & Knowledge (7)
    {
        "name": "Substack",
        "category": "Publishing & Knowledge",
        "url": "https://{username}.substack.com",
        "type": "status_code",
    },
    {
        "name": "Medium",
        "category": "Publishing & Knowledge",
        "url": "https://medium.com/@{username}",
        "type": "status_code",
    },
    {
        "name": "Wikipedia",
        "category": "Publishing & Knowledge",
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "type": "message",
        "absent_pattern": ("sockpuppet", "blocked indefinitely", "has been blocked"),
    },
    {
        "name": "Instructables",
        "category": "Publishing & Knowledge",
        "url": "https://www.instructables.com/member/{username}/",
        "type": "status_code",
    },
    {
        "name": "Goodreads",
        "category": "Publishing & Knowledge",
        "url": "https://www.goodreads.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Duolingo",
        "category": "Publishing & Knowledge",
        "url": "https://www.duolingo.com/profile/{username}",
        "type": "status_code",
    },
    {
        "name": "Patreon",
        "category": "Publishing & Knowledge",
        "url": "https://www.patreon.com/{username}",
        "type": "status_code",
    },
]


class UsernameValidationError(ValueError):
    """Raised when an invalid username target is provided."""


def validate_username(username: str) -> str:
    """Validate username string against standard naming constraints."""
    cleaned = username.strip().lstrip("@")
    if not cleaned:
        raise UsernameValidationError("username cannot be empty")
    if not _USERNAME_RE.match(cleaned):
        raise UsernameValidationError(
            f"invalid username '{username}': must be 1-64 alphanumeric characters, dashes, dots, or underscores"
        )
    return cleaned


def check_site(
    site: dict[str, Any],
    username: str,
    *,
    timeout: float = 6.0,
    proxy: str | None = None,
    http_requester: Callable[..., tuple[int, str]] | None = None,
) -> dict[str, Any]:
    """Check whether a username exists on a specific target site."""
    target_url = site["url"].format(username=username)
    display_url = site.get("profile_url", target_url).format(username=username)
    name = site["name"]
    category = site["category"]
    check_type = site.get("type", "status_code")

    if http_requester is not None:
        try:
            try:
                status_code, body = http_requester(target_url, timeout=timeout, proxy=proxy)
            except TypeError:
                status_code, body = http_requester(target_url, timeout=timeout)
        except Exception as exc:
            return {
                "name": name,
                "category": category,
                "url": display_url,
                "exists": False,
                "status": f"Error: {exc}",
            }
    else:
        req = urllib.request.Request(
            target_url,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        if proxy:
            proxy_clean = proxy.strip()
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy_clean, "https": proxy_clean})
            )
        else:
            opener = urllib.request.build_opener()

        try:
            with opener.open(req, timeout=timeout) as response:
                status_code = response.status
                body = response.read(65536).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            body = exc.read(65536).decode("utf-8", errors="replace") if exc.fp else ""
        except Exception as exc:
            return {
                "name": name,
                "category": category,
                "url": display_url,
                "exists": False,
                "status": f"Error: {exc}",
            }

    exists = False
    if check_type == "status_code":
        exists = status_code == 200
    elif check_type == "message":
        if status_code == 200:
            absent = site.get("absent_pattern")
            present = site.get("present_pattern")
            if absent:
                if isinstance(absent, (list, tuple)):
                    exists = not any(p.lower() in body.lower() for p in absent)
                else:
                    exists = absent.lower() not in body.lower()
            elif present:
                if isinstance(present, (list, tuple)):
                    exists = any(p.lower() in body.lower() for p in present)
                else:
                    exists = present.lower() in body.lower()
        else:
            exists = False

    return {
        "name": name,
        "category": category,
        "url": display_url,
        "exists": exists,
        "status": status_code,
    }


def search_username(
    username: str,
    *,
    sites: list[dict[str, Any]] | None = None,
    max_workers: int = 20,
    timeout: float = 6.0,
    proxy: str | None = None,
    checker: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Search for a username across public platforms concurrently."""
    valid_username = validate_username(username)
    site_list = sites if sites is not None else SITES
    site_checker = checker if checker is not None else check_site

    def _call_checker(site_item: dict[str, Any]) -> dict[str, Any]:
        if checker is not None:
            try:
                return checker(site_item, valid_username, timeout=timeout, proxy=proxy)
            except TypeError:
                return checker(site_item, valid_username, timeout=timeout)
        return check_site(site_item, valid_username, timeout=timeout, proxy=proxy)

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(_call_checker, site): site
            for site in site_list
        }
        for future in concurrent.futures.as_completed(future_map):
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                site = future_map[future]
                results.append({
                    "name": site["name"],
                    "category": site.get("category", "Other"),
                    "url": site["url"].format(username=valid_username),
                    "exists": False,
                    "status": f"Error: {exc}",
                })

    found = [r for r in results if r["exists"]]
    not_found = [r for r in results if not r["exists"]]

    found.sort(key=lambda item: (item["category"], item["name"]))
    not_found.sort(key=lambda item: (item["category"], item["name"]))

    return {
        "schema_version": 1,
        "mode": "username",
        "target": valid_username,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "proxy_used": proxy if proxy else None,
        "total_checked": len(results),
        "found_count": len(found),
        "found": found,
        "not_found": not_found,
    }
