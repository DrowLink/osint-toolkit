"""Specialized OSINT reconnaissance services: Shodan, VirusTotal, IP2Location, and Censys.

All methods strictly adhere to the project standards:
- 100% Python standard library
- Bounded monotonic deadlines and response body limits
- Informative and formatted outputs
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .core import resolve_public_addresses

USER_AGENT = "Mozilla/5.0 (compatible; OSINTToolkit/1.0; +https://github.com/DrowLink/osint-toolkit)"
MAX_RESPONSE_BYTES = 256 * 1024


def is_valid_ip(address: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address.strip())
        return True
    except ValueError:
        return False


def resolve_target_ip(target: str, timeout: float = 5.0) -> str:
    """Resolve a target domain or IP string to a public IP address."""
    clean = target.strip()
    if "://" in clean:
        clean = urllib.parse.urlsplit(clean).hostname or clean
    clean = clean.split("/")[0].split(":")[0]

    if is_valid_ip(clean):
        # Validate that it's not private / loopback
        ip_obj = ipaddress.ip_address(clean)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            raise ValueError(f"Target IP {clean} is private or non-routable")
        return clean

    # Resolve domain to public IP
    import time
    deadline = time.monotonic() + timeout
    addresses = resolve_public_addresses(clean, deadline=deadline)
    if not addresses:
        raise ValueError(f"Could not resolve any public IP for domain {clean}")
    # Prefer IPv4
    v4 = [a for a in addresses if ":" not in a]
    return v4[0] if v4 else addresses[0]


def _http_get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 8.0,
    proxy: str | None = None,
) -> tuple[int, dict[str, Any] | None, str | None]:
    """Execute a bounded HTTP GET request returning status code, parsed JSON, or raw body."""
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers, method="GET")
    if proxy:
        proxy_clean = proxy.strip()
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_clean, "https": proxy_clean})
        )
    else:
        opener = urllib.request.build_opener()

    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
                return status, data, None
            except json.JSONDecodeError:
                return status, None, body
    except urllib.error.HTTPError as exc:
        status = exc.code
        body = exc.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        try:
            data = json.loads(body)
            return status, data, None
        except json.JSONDecodeError:
            return status, None, body
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise ConnectionError(f"Network error requesting {url}: {exc}") from exc


# ---------------------------------------------------------------------------
# 1. Shodan
# ---------------------------------------------------------------------------

def search_shodan(
    target: str,
    *,
    api_key: str | None = None,
    timeout: float = 8.0,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Query Shodan for host intelligence, exposed ports, and known CVEs.

    Uses Shodan InternetDB by default (free, no API key required), or the full
    Shodan REST API if an API key is provided or found in SHODAN_API_KEY.
    """
    ip = resolve_target_ip(target, timeout=timeout)
    key = api_key or os.environ.get("SHODAN_API_KEY")

    if key:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        status, data, _ = _http_get_json(url, timeout=timeout, proxy=proxy)
        if status == 200 and isinstance(data, dict):
            return {
                "service": "shodan",
                "target": target,
                "ip": ip,
                "source": "shodan_api",
                "found": True,
                "ports": sorted(data.get("ports", [])),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpe", []),
                "tags": data.get("tags", []),
                "vulns": sorted(data.get("vulns", [])),
                "os": data.get("os"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "web_url": f"https://www.shodan.io/host/{ip}",
            }

    # Free InternetDB fallback (zero-auth, no key needed)
    url = f"https://internetdb.shodan.io/{ip}"
    status, data, _ = _http_get_json(url, timeout=timeout, proxy=proxy)

    if status == 404:
        return {
            "service": "shodan",
            "target": target,
            "ip": ip,
            "source": "internetdb",
            "found": False,
            "proxy_used": proxy if proxy else None,
            "ports": [],
            "cpes": [],
            "hostnames": [],
            "tags": [],
            "vulns": [],
            "web_url": f"https://www.shodan.io/host/{ip}",
            "message": "No open ports or historical services indexed in Shodan InternetDB",
        }

    if status == 200 and isinstance(data, dict):
        return {
            "service": "shodan",
            "target": target,
            "ip": ip,
            "source": "internetdb",
            "found": True,
            "proxy_used": proxy if proxy else None,
            "ports": sorted(data.get("ports", [])),
            "cpes": data.get("cpes", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": sorted(data.get("vulns", [])),
            "web_url": f"https://www.shodan.io/host/{ip}",
        }

    return {
        "service": "shodan",
        "target": target,
        "ip": ip,
        "source": "internetdb",
        "found": False,
        "proxy_used": proxy if proxy else None,
        "error": f"Shodan returned status {status}",
        "web_url": f"https://www.shodan.io/host/{ip}",
    }


# ---------------------------------------------------------------------------
# 2. IP2Location
# ---------------------------------------------------------------------------

def search_ip2location(
    target: str,
    *,
    api_key: str | None = None,
    timeout: float = 8.0,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Query IP2Location for comprehensive IP geolocation, ASN, and proxy detection.

    Works without an API key using the public tier, or with IP2LOCATION_API_KEY.
    """
    ip = resolve_target_ip(target, timeout=timeout)
    key = api_key or os.environ.get("IP2LOCATION_API_KEY")

    url = f"https://api.ip2location.io/?ip={ip}"
    if key:
        url += f"&key={key}"

    status, data, _ = _http_get_json(url, timeout=timeout, proxy=proxy)

    if status == 200 and isinstance(data, dict):
        return {
            "service": "ip2location",
            "target": target,
            "ip": ip,
            "found": True,
            "proxy_used": proxy if proxy else None,
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "region_name": data.get("region_name"),
            "city_name": data.get("city_name"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "zip_code": data.get("zip_code"),
            "time_zone": data.get("time_zone"),
            "asn": data.get("asn"),
            "as": data.get("as"),
            "is_proxy": data.get("is_proxy", False),
            "web_url": f"https://www.ip2location.io/demo/{ip}",
        }

    return {
        "service": "ip2location",
        "target": target,
        "ip": ip,
        "found": False,
        "proxy_used": proxy if proxy else None,
        "error": f"IP2Location returned status {status}",
        "web_url": f"https://www.ip2location.io/demo/{ip}",
    }


# ---------------------------------------------------------------------------
# 3. VirusTotal
# ---------------------------------------------------------------------------

def search_virustotal(
    target: str,
    *,
    api_key: str | None = None,
    timeout: float = 8.0,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Query VirusTotal v3 API for reputation, malware, and detection statistics.

    Target can be an IP address or domain name. Requires VIRUSTOTAL_API_KEY.
    """
    clean = target.strip()
    if "://" in clean:
        clean = urllib.parse.urlsplit(clean).hostname or clean
    clean = clean.split("/")[0].split(":")[0]

    is_ip = is_valid_ip(clean)
    endpoint_type = "ip_addresses" if is_ip else "domains"
    gui_type = "ip-address" if is_ip else "domain"
    web_url = f"https://www.virustotal.com/gui/{gui_type}/{clean}"

    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")
    if not key:
        return {
            "service": "virustotal",
            "target": target,
            "resource": clean,
            "type": "ip" if is_ip else "domain",
            "authenticated": False,
            "found": None,
            "proxy_used": proxy if proxy else None,
            "web_url": web_url,
            "message": (
                "VirusTotal API v3 requires an API key. "
                "Set VIRUSTOTAL_API_KEY environment variable or pass --api-key <KEY>."
            ),
        }

    url = f"https://www.virustotal.com/api/v3/{endpoint_type}/{clean}"
    status, data, _ = _http_get_json(url, headers={"x-apikey": key}, timeout=timeout, proxy=proxy)

    if status == 200 and isinstance(data, dict):
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        results = attr.get("last_analysis_results", {})
        malicious_engines = [
            engine for engine, res in results.items() if res.get("category") == "malicious"
        ]

        return {
            "service": "virustotal",
            "target": target,
            "resource": clean,
            "type": "ip" if is_ip else "domain",
            "authenticated": True,
            "found": True,
            "proxy_used": proxy if proxy else None,
            "stats": stats,
            "reputation": attr.get("reputation", 0),
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "undetected_count": stats.get("undetected", 0),
            "malicious_engines": malicious_engines,
            "categories": attr.get("categories", {}),
            "web_url": web_url,
        }

    if status == 404:
        return {
            "service": "virustotal",
            "target": target,
            "resource": clean,
            "type": "ip" if is_ip else "domain",
            "authenticated": True,
            "found": False,
            "proxy_used": proxy if proxy else None,
            "message": "Resource not found in VirusTotal database",
            "web_url": web_url,
        }

    return {
        "service": "virustotal",
        "target": target,
        "resource": clean,
        "type": "ip" if is_ip else "domain",
        "authenticated": True,
        "found": False,
        "proxy_used": proxy if proxy else None,
        "error": f"VirusTotal returned status {status}",
        "web_url": web_url,
    }


# ---------------------------------------------------------------------------
# 4. Censys
# ---------------------------------------------------------------------------

def search_censys(
    target: str,
    *,
    api_id: str | None = None,
    api_secret: str | None = None,
    timeout: float = 8.0,
    proxy: str | None = None,
) -> dict[str, Any]:
    """Query Censys Search API v2 for host infrastructure, services, and certificates.

    Requires CENSYS_API_ID and CENSYS_API_SECRET credentials.
    """
    ip = resolve_target_ip(target, timeout=timeout)
    web_url = f"https://search.censys.io/hosts/{ip}"

    censys_id = api_id or os.environ.get("CENSYS_API_ID")
    censys_secret = api_secret or os.environ.get("CENSYS_API_SECRET")

    if not (censys_id and censys_secret):
        return {
            "service": "censys",
            "target": target,
            "ip": ip,
            "authenticated": False,
            "found": None,
            "proxy_used": proxy if proxy else None,
            "web_url": web_url,
            "message": (
                "Censys Search API requires API credentials. "
                "Set CENSYS_API_ID and CENSYS_API_SECRET environment variables "
                "or pass --api-id and --api-secret."
            ),
        }

    auth_str = f"{censys_id}:{censys_secret}".encode("utf-8")
    auth_b64 = base64.b64encode(auth_str).decode("ascii")

    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    status, data, _ = _http_get_json(
        url,
        headers={"Authorization": f"Basic {auth_b64}"},
        timeout=timeout,
        proxy=proxy,
    )

    if status == 200 and isinstance(data, dict):
        result = data.get("result", {})
        services_raw = result.get("services", [])
        services = [
            {
                "port": s.get("port"),
                "service_name": s.get("service_name"),
                "transport_protocol": s.get("transport_protocol"),
            }
            for s in services_raw
        ]

        return {
            "service": "censys",
            "target": target,
            "ip": ip,
            "authenticated": True,
            "found": True,
            "services": services,
            "autonomous_system": result.get("autonomous_system", {}),
            "location": result.get("location", {}),
            "operating_system": result.get("operating_system", {}),
            "web_url": web_url,
        }

    if status == 404:
        return {
            "service": "censys",
            "target": target,
            "ip": ip,
            "authenticated": True,
            "found": False,
            "message": "Host not indexed in Censys database",
            "web_url": web_url,
        }

    return {
        "service": "censys",
        "target": target,
        "ip": ip,
        "authenticated": True,
        "found": False,
        "error": f"Censys returned status {status}",
        "web_url": web_url,
    }
