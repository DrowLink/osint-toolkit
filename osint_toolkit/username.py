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
    # Coding & Development
    {
        "name": "GitHub",
        "category": "Coding & Tech",
        "url": "https://github.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Codeberg",
        "category": "Coding & Tech",
        "url": "https://codeberg.org/{username}",
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
        "name": "Dev.to",
        "category": "Coding & Tech",
        "url": "https://dev.to/{username}",
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
    # Social & Messaging
    {
        "name": "Telegram",
        "category": "Social & Messaging",
        "url": "https://t.me/{username}",
        "type": "message",
        "present_pattern": "tgme_page_extra",
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
    # Gaming & Entertainment
    {
        "name": "Steam",
        "category": "Gaming & Chess",
        "url": "https://steamcommunity.com/id/{username}",
        "type": "message",
        "absent_pattern": "The specified profile could not be found",
    },
    {
        "name": "Chess.com",
        "category": "Gaming & Chess",
        "url": "https://api.chess.com/pub/player/{username}",
        "profile_url": "https://www.chess.com/member/{username}",
        "type": "status_code",
    },
    {
        "name": "Lichess",
        "category": "Gaming & Chess",
        "url": "https://lichess.org/api/user/{username}",
        "profile_url": "https://lichess.org/@/{username}",
        "type": "status_code",
    },
    {
        "name": "itch.io",
        "category": "Gaming & Chess",
        "url": "https://{username}.itch.io",
        "type": "status_code",
    },
    # Creative & Publishing
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
        "name": "SoundCloud",
        "category": "Design & Audio",
        "url": "https://soundcloud.com/{username}",
        "type": "status_code",
    },
    {
        "name": "Substack",
        "category": "Publishing",
        "url": "https://{username}.substack.com",
        "type": "status_code",
    },
    {
        "name": "Wikipedia",
        "category": "Knowledge",
        "url": "https://en.wikipedia.org/wiki/User:{username}",
        "type": "message",
        "absent_pattern": ("sockpuppet", "blocked indefinitely", "has been blocked"),
    },
    {
        "name": "Instructables",
        "category": "Knowledge",
        "url": "https://www.instructables.com/member/{username}/",
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
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
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
    checker: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Search for a username across public platforms concurrently."""
    valid_username = validate_username(username)
    site_list = sites if sites is not None else SITES
    site_checker = checker if checker is not None else check_site

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(site_checker, site, valid_username, timeout=timeout): site
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
        "total_checked": len(results),
        "found_count": len(found),
        "found": found,
        "not_found": not_found,
    }
