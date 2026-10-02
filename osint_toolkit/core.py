"""Safe, passive OSINT collection primitives."""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit


class DomainValidationError(ValueError):
    """Raised when a target is not a valid public domain name."""


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
_MAX_RESOLVED_ADDRESSES = 8
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_DEFAULT_DNS_TIMEOUT = 8.0


def _has_non_global_embedded_ipv4(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    if not isinstance(address, ipaddress.IPv6Address):
        return False
    embedded: list[ipaddress.IPv4Address] = []
    if address.ipv4_mapped is not None:
        embedded.append(address.ipv4_mapped)
    if address in _NAT64_WELL_KNOWN_PREFIX:
        embedded.append(ipaddress.IPv4Address(int(address) & 0xFFFFFFFF))
    if address.sixtofour is not None:
        embedded.append(address.sixtofour)
    if address.teredo is not None:
        embedded.extend(address.teredo)
    return any(not item.is_global for item in embedded)


def is_public_unicast_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return whether an address is public unicast and safe to report."""
    non_unicast = (
        address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_reserved
    )
    if isinstance(address, ipaddress.IPv6Address):
        non_unicast = non_unicast or address.is_site_local
    return (
        address.is_global
        and not non_unicast
        and not _has_non_global_embedded_ipv4(address)
    )


def _getaddrinfo_before_deadline(
    domain: str,
    getaddrinfo: Callable[..., list[tuple[Any, ...]]],
    deadline: float,
) -> list[tuple[Any, ...]]:
    result: list[list[tuple[Any, ...]]] = []
    failure: list[Exception] = []
    finished = threading.Event()

    def resolve() -> None:
        try:
            result.append(getaddrinfo(domain, None, type=socket.SOCK_STREAM))
        except Exception as exc:  # noqa: BLE001 - propagate resolver failures to the caller
            failure.append(exc)
        finally:
            finished.set()

    if deadline - time.monotonic() <= 0:
        raise DomainValidationError("DNS resolution deadline exceeded")

    worker = threading.Thread(target=resolve, name="osint-toolkit-dns", daemon=True)
    worker.start()
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not finished.wait(remaining):
        raise DomainValidationError("DNS resolution deadline exceeded")
    if failure:
        raise failure[0]
    return result[0]


def normalize_domain(target: str) -> str:
    """Return a normalized ASCII domain or raise DomainValidationError."""
    value = target.strip()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.port is not None:
        raise DomainValidationError("custom ports are not supported")
    hostname = parsed.hostname
    if not hostname:
        raise DomainValidationError("a domain is required")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise DomainValidationError("IP address targets are not supported")
    try:
        domain = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainValidationError("invalid internationalized domain") from exc
    labels = domain.split(".")
    if (
        len(labels) < 2
        or len(domain) > 253
        or any(not _LABEL_RE.fullmatch(label) for label in labels)
    ):
        raise DomainValidationError("invalid domain name")
    if domain.endswith((".local", ".internal", ".localhost")):
        raise DomainValidationError("local domains are not supported")
    return domain


_SECURITY_HEADERS = (
    "content-security-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)


def resolve_public_addresses(
    domain: str,
    *,
    getaddrinfo: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
    deadline: float | None = None,
) -> list[str]:
    """Resolve by a monotonic deadline and reject every non-public-unicast answer."""
    if deadline is None:
        deadline = time.monotonic() + _DEFAULT_DNS_TIMEOUT
    try:
        answers = _getaddrinfo_before_deadline(domain, getaddrinfo, deadline)
    except socket.gaierror as exc:
        raise DomainValidationError(f"DNS resolution failed: {exc}") from exc
    addresses = {str(item[4][0]) for item in answers}
    if not addresses:
        raise DomainValidationError("domain has no A or AAAA records")
    if len(addresses) > _MAX_RESOLVED_ADDRESSES:
        raise DomainValidationError(
            f"domain resolves to too many addresses (maximum {_MAX_RESOLVED_ADDRESSES})"
        )
    try:
        parsed = [ipaddress.ip_address(address) for address in addresses]
    except ValueError as exc:
        raise DomainValidationError("DNS returned an invalid address") from exc
    if any(not is_public_unicast_address(address) for address in parsed):
        raise DomainValidationError("domain resolves to a non-public unicast address")
    return [
        str(address)
        for address in sorted(parsed, key=lambda value: (value.version, int(value)))
    ]


def analyze_security_headers(headers: Mapping[str, str]) -> dict[str, Any]:
    """Summarize common defensive HTTP response headers."""
    normalized = {key.lower(): value for key, value in headers.items()}
    present = sorted(header for header in _SECURITY_HEADERS if normalized.get(header))
    missing = sorted(set(_SECURITY_HEADERS) - set(present))
    return {"present": present, "missing": missing, "server": normalized.get("server")}
