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
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)

_META_NAME_CONTENT = re.compile(
    r'<meta\s+[^>]*?name=["\'](?P<name>[^"\']+)["\'][^>]*?content=["\'](?P<content>[^"\']*)["\']',
    re.IGNORECASE,
)
_META_CONTENT_NAME = re.compile(
    r'<meta\s+[^>]*?content=["\'](?P<content>[^"\']*)["\'][^>]*?name=["\'](?P<name>[^"\']+)["\']',
    re.IGNORECASE,
)


def extract_meta_tags(text: str) -> dict[str, str]:
    """Passively extract meta tags like description and generator from HTML."""
    meta: dict[str, str] = {}
    for match in _META_NAME_CONTENT.finditer(text):
        name = match.group("name").lower()
        if name in {"description", "generator"} and name not in meta:
            meta[name] = match.group("content").strip()
    for match in _META_CONTENT_NAME.finditer(text):
        name = match.group("name").lower()
        if name in {"description", "generator"} and name not in meta:
            meta[name] = match.group("content").strip()
    return meta


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
    """Summarize common defensive HTTP response headers and cookie flags."""
    normalized = {key.lower(): value for key, value in headers.items()}
    present = sorted(header for header in _SECURITY_HEADERS if normalized.get(header))
    missing = sorted(set(_SECURITY_HEADERS) - set(present))
    result: dict[str, Any] = {
        "present": present,
        "missing": missing,
        "server": normalized.get("server"),
    }
    cookie_header = normalized.get("set-cookie")
    if cookie_header:
        cookie_lower = cookie_header.lower()
        result["cookie_security"] = {
            "has_secure": "secure" in cookie_lower,
            "has_httponly": "httponly" in cookie_lower,
            "has_samesite": "samesite" in cookie_lower,
        }
    return result


_KNOWN_MAIL_PROVIDERS = (
    (("google.com", "googlemail.com", "smtp.google.com", "aspmx.l.google.com"), "Google Workspace"),
    (("outlook.com", "protection.outlook.com", "office365.com"), "Microsoft 365"),
    (("protonmail.ch", "proton.me"), "Proton Mail"),
    (("zoho.com", "zoho.eu"), "Zoho Mail"),
    (("messagingengine.com", "fastmail.com"), "Fastmail"),
    (("icloud.com", "mail.me.com", "apple.com"), "Apple iCloud Mail"),
    (("mimecast.com",), "Mimecast"),
    (("pphosted.com", "proofpoint.com"), "Proofpoint"),
    (("barracudanetworks.com",), "Barracuda"),
    (("ovh.net",), "OVHcloud"),
    (("amazonses.com",), "Amazon SES"),
    (("yandex.net", "yandex.ru"), "Yandex 360"),
)


def identify_mail_provider(exchange: str) -> str:
    """Identify well-known email providers from an MX hostname."""
    lowered = exchange.lower().rstrip(".")
    for patterns, provider in _KNOWN_MAIL_PROVIDERS:
        if any(pattern in lowered for pattern in patterns):
            return provider
    return "Custom / Self-hosted"


def parse_mx_records(records: list[str]) -> list[dict[str, Any]]:
    """Parse, sort by preference, and identify provider for MX records."""
    parsed: list[dict[str, Any]] = []
    for item in records:
        cleaned = item.strip().strip('"')
        parts = cleaned.split()
        if len(parts) >= 2:
            try:
                preference = int(parts[0])
                exchange = parts[1].rstrip(".").lower()
                parsed.append({
                    "preference": preference,
                    "exchange": exchange,
                    "provider": identify_mail_provider(exchange),
                })
            except ValueError:
                continue
        elif len(parts) == 1:
            exchange = parts[0].rstrip(".").lower()
            parsed.append({
                "preference": 10,
                "exchange": exchange,
                "provider": identify_mail_provider(exchange),
            })
    return sorted(parsed, key=lambda item: (item["preference"], item["exchange"]))


def parse_spf_record(records: list[str]) -> dict[str, Any] | None:
    """Extract and analyze SPF record from TXT records."""
    for record in records:
        cleaned = record.strip().strip('"')
        if cleaned.lower().startswith("v=spf1"):
            terms = cleaned.split()
            policy = None
            strength = "Unspecified"
            includes: list[str] = []
            for term in terms[1:]:
                term_lower = term.lower()
                if term_lower in {"-all", "~all", "?all", "+all"}:
                    policy = term_lower
                    if term_lower == "-all":
                        strength = "Fail (Strict)"
                    elif term_lower == "~all":
                        strength = "SoftFail (Recommended)"
                    elif term_lower == "?all":
                        strength = "Neutral"
                    elif term_lower == "+all":
                        strength = "Pass (Insecure)"
                elif term_lower.startswith("include:"):
                    includes.append(term[len("include:"):])
            return {
                "raw": cleaned,
                "policy": policy,
                "strength": strength,
                "includes": includes,
            }
    return None


def parse_dmarc_record(record: str | None) -> dict[str, Any] | None:
    """Extract and analyze DMARC record."""
    if not record:
        return None
    cleaned = record.strip().strip('"')
    if not cleaned.lower().startswith("v=dmarc1"):
        return None
    tags: dict[str, str] = {}
    for part in cleaned.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "none").lower()
    if policy == "reject":
        enforcement = "Enforced (Reject) - High Protection"
    elif policy == "quarantine":
        enforcement = "Enforced (Quarantine) - Medium Protection"
    elif policy == "none":
        enforcement = "Monitoring Only (None) - No Enforcement"
    else:
        enforcement = f"Custom ({policy})"
    return {
        "raw": cleaned,
        "policy": policy,
        "enforcement": enforcement,
        "rua": tags.get("rua"),
        "subdomain_policy": tags.get("sp"),
        "percentage": tags.get("pct"),
    }


def parse_soa_record(record: str | None) -> dict[str, Any] | None:
    """Extract primary nameserver and admin email from an SOA record."""
    if not record:
        return None
    cleaned = record.strip().strip('"')
    parts = cleaned.split()
    if not parts:
        return None
    primary_ns = parts[0].rstrip(".")
    admin_email = None
    if len(parts) > 1:
        mailbox = parts[1].rstrip(".")
        if "." in mailbox:
            user, domain = mailbox.split(".", 1)
            admin_email = f"{user}@{domain}"
        else:
            admin_email = mailbox
    serial = parts[2] if len(parts) > 2 else None
    return {
        "primary_ns": primary_ns,
        "admin_email": admin_email,
        "serial": serial,
        "raw": cleaned,
    }


def parse_rdap_response(data: dict[str, Any]) -> dict[str, Any]:
    """Extract registrar, key event dates, and status from RDAP response."""
    registrar = None
    entities = data.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                        registrar = item[3]
                        break
            if not registrar:
                registrar = entity.get("handle")
            break

    dates: dict[str, str] = {}
    for event in data.get("events", []):
        action = event.get("eventAction")
        date_str = event.get("eventDate")
        if action and date_str:
            dates[action] = date_str

    return {
        "registrar": registrar,
        "created": dates.get("registration"),
        "expires": dates.get("expiration"),
        "updated": dates.get("last changed"),
        "status": data.get("status", []),
    }


def parse_ip_info(data: dict[str, Any]) -> dict[str, Any]:
    """Extract ASN, org, and location info from IP geolocation response."""
    return {
        "ip": data.get("ip"),
        "asn": data.get("asn"),
        "org": data.get("org"),
        "country": data.get("country_name") or data.get("country"),
        "country_code": data.get("country_code"),
        "city": data.get("city"),
        "region": data.get("region"),
    }

