"""Bounded, passive collection for public domain metadata."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.request
import zlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

from .core import (
    analyze_security_headers,
    extract_meta_tags,
    is_public_unicast_address,
    normalize_domain,
    parse_dmarc_record,
    parse_ip_info,
    parse_mx_records,
    parse_rdap_response,
    parse_soa_record,
    parse_spf_record,
    resolve_public_addresses,
)

_USER_AGENT = "DrowLink-OSINT-Toolkit/0.1 (+https://github.com/DrowLink/osint-toolkit)"
_MAX_BODY = 262_144
_MAX_REDIRECTS = 3
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class NetworkProbeError(OSError):
    """Raised when policy leaves no address eligible for a network probe."""


def _decode_body(body: bytes, content_type: str) -> str:
    match = re.search(r"charset=([\w.-]+)", content_type, re.IGNORECASE)
    charset = match.group(1) if match else "utf-8"
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("overall request deadline exceeded")
    return remaining


class _DeadlineSocketReader(io.RawIOBase):
    def __init__(self, stream: _DeadlineSocket) -> None:
        self._stream = stream

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        return self._stream.recv_into(buffer)


class _DeadlineSocket:
    """Apply the remaining overall timeout before every socket operation."""

    def __init__(self, stream: Any, deadline: float) -> None:
        self._stream = stream
        self._deadline = deadline

    def _arm(self) -> None:
        self._stream.settimeout(_remaining_timeout(self._deadline))

    def settimeout(self, timeout: float) -> None:
        self._stream.settimeout(timeout)

    def sendall(self, data: bytes) -> None:
        self._arm()
        self._stream.sendall(data)

    def recv_into(self, buffer: Any) -> int:
        self._arm()
        return self._stream.recv_into(buffer)

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("deadline socket supports only binary reads")
        return io.BufferedReader(_DeadlineSocketReader(self))

    def close(self) -> None:
        self._stream.close()


def _public_ipv4_only(addresses: list[str]) -> list[str]:
    public_ipv4: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise NetworkProbeError(
                "network probe received an invalid IP address"
            ) from exc
        if isinstance(address, ipaddress.IPv4Address) and is_public_unicast_address(
            address
        ):
            public_ipv4.append(str(address))
    if not public_ipv4:
        raise NetworkProbeError(
            "network probes require a validated public IPv4 address; IPv6-only targets are metadata-only"
        )
    return public_ipv4


def _connect_and_request(
    url: str, domain: str, addresses: list[str], deadline: float
) -> dict[str, Any]:
    parsed = urlsplit(url)
    port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    last_error: OSError | None = None
    for address in addresses:
        raw_socket = None
        stream = None
        try:
            raw_socket = socket.create_connection(
                (address, port), timeout=_remaining_timeout(deadline)
            )
            stream = raw_socket
            if parsed.scheme == "https":
                raw_socket.settimeout(_remaining_timeout(deadline))
                stream = ssl.create_default_context().wrap_socket(
                    raw_socket, server_hostname=domain
                )
            stream = _DeadlineSocket(stream, deadline)
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: {_USER_AGENT}\r\n"
                "Accept: text/html,text/plain;q=0.9,*/*;q=0.1\r\n"
                "Accept-Encoding: gzip, deflate, identity\r\n"
                "Connection: close\r\n\r\n"
            )
            stream.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(stream)
            response.begin()
            body = response.read(_MAX_BODY + 1)
            truncated = len(body) > _MAX_BODY
            if truncated:
                body = body[:_MAX_BODY]
            headers = {key: value for key, value in response.getheaders()}
            lower_headers = {key.lower(): value for key, value in headers.items()}
            encoding = lower_headers.get("content-encoding", "").lower().strip()
            if encoding == "gzip":
                try:
                    body = gzip.decompress(body)
                except Exception:
                    pass
            elif encoding == "deflate":
                try:
                    body = zlib.decompress(body)
                except Exception:
                    try:
                        body = zlib.decompress(body, -zlib.MAX_WBITS)
                    except Exception:
                        pass
            text = _decode_body(body, lower_headers.get("content-type", ""))
            title_match = _TITLE_RE.search(text)
            title = (
                re.sub(r"\s+", " ", title_match.group(1)).strip()
                if title_match
                else None
            )
            meta = extract_meta_tags(text)
            result: dict[str, Any] = {
                "url": url,
                "status": response.status,
                "headers": headers,
                "title": title,
                "meta": meta,
                "text": text,
            }
            if truncated:
                result["truncated"] = True
            return result
        except OSError as exc:
            last_error = exc
        finally:
            if stream is not None:
                stream.close()
            elif raw_socket is not None:
                raw_socket.close()
    raise OSError(f"connection failed for all public addresses: {last_error}")


def _request_once(url: str, deadline: float) -> dict[str, Any]:
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username
        or parsed.password
        or parsed.port is not None
    ):
        raise ValueError("only standard-port public HTTP(S) URLs are supported")
    domain = normalize_domain(parsed.hostname or "")
    addresses = resolve_public_addresses(domain, deadline=deadline)
    return _connect_and_request(url, domain, _public_ipv4_only(addresses), deadline)


def fetch_public_url(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Fetch a public HTTP(S) URL with pinned DNS results and strict limits."""
    current = url
    deadline = time.monotonic() + timeout
    for _ in range(_MAX_REDIRECTS + 1):
        result = _request_once(current, deadline)
        if result["status"] not in {301, 302, 303, 307, 308}:
            return result
        location = next(
            (
                value
                for key, value in result["headers"].items()
                if key.lower() == "location"
            ),
            None,
        )
        if not location:
            return result
        current = urljoin(current, location)
    raise ValueError("too many redirects")


def probe_tls_certificate(
    domain: str, addresses: list[str], *, timeout: float = 8.0
) -> dict[str, Any]:
    """Read the verified TLS certificate from the first reachable public address."""
    addresses = _public_ipv4_only(addresses)
    context = ssl.create_default_context()
    last_error: OSError | None = None
    deadline = time.monotonic() + timeout
    for address in addresses:
        try:
            with socket.create_connection(
                (address, 443), timeout=_remaining_timeout(deadline)
            ) as raw:
                raw.settimeout(_remaining_timeout(deadline))
                with context.wrap_socket(raw, server_hostname=domain) as secure:
                    certificate = secure.getpeercert()
                    binary = secure.getpeercert(binary_form=True)
                    protocol = secure.version()
                    cipher_info = secure.cipher()
            issuer = {
                key: value
                for group in certificate.get("issuer", ())
                for key, value in group
            }
            subject = {
                key: value
                for group in certificate.get("subject", ())
                for key, value in group
            }
            sans = [
                value
                for kind, value in certificate.get("subjectAltName", ())
                if kind == "DNS"
            ]
            expires_dt = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(certificate["notAfter"]), tz=UTC
            )
            expires = expires_dt.isoformat().replace("+00:00", "Z")
            now = datetime.now(UTC)
            days_remaining = (expires_dt - now).days
            is_expired = now > expires_dt
            cipher = (
                {
                    "name": cipher_info[0],
                    "protocol": cipher_info[1],
                    "bits": cipher_info[2],
                }
                if cipher_info
                else None
            )
            return {
                "subject": subject,
                "issuer": issuer,
                "expires": expires,
                "days_remaining": days_remaining,
                "is_expired": is_expired,
                "protocol": protocol,
                "cipher": cipher,
                "dns_names": sorted(sans),
                "sha256": hashlib.sha256(binary).hexdigest(),
            }
        except (OSError, ssl.SSLError, KeyError) as exc:
            last_error = exc
    raise OSError(f"TLS probe failed for all public addresses: {last_error}")


def _safe_call(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return operation()
    except NetworkProbeError as exc:
        return {"error": {"type": "network_probe_error", "message": str(exc)}}
    except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"error": str(exc)}


def _parse_directives(text: str, prefixes: tuple[str, ...]) -> list[str]:
    directives: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        for prefix in prefixes:
            if line.lower().startswith(prefix.lower()):
                value = line[len(prefix) :].strip(" :")
                if value and value not in directives:
                    directives.append(value)
    return directives


def _file_summary(result: dict[str, Any], kind: str = "generic") -> dict[str, Any]:
    if "error" in result:
        return result
    found = result.get("status") == 200
    text = result.get("text", "") if found else ""
    summary: dict[str, Any] = {
        "found": found,
        "status": result.get("status"),
        "url": result.get("url"),
        "snippet": text[:500] if found else "",
    }
    if result.get("truncated"):
        summary["truncated"] = True
    if found and kind == "security_txt":
        contacts = _parse_directives(text, ("contact:",))
        expires = _parse_directives(text, ("expires:",))
        if contacts:
            summary["contacts"] = contacts
        if expires:
            summary["expires"] = expires[0]
    elif found and kind == "robots_txt":
        sitemaps = _parse_directives(text, ("sitemap:",))
        if sitemaps:
            summary["sitemaps"] = sitemaps
    return summary


def query_doh_records(name: str, record_type: str, timeout: float = 4.0) -> list[str]:
    """Query DNS records via standard DNS-over-HTTPS (Cloudflare with Google fallback)."""
    endpoints = [
        ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json", "User-Agent": _USER_AGENT}),
        ("https://dns.google/resolve", {"Accept": "application/json", "User-Agent": _USER_AGENT}),
    ]
    for base_url, headers in endpoints:
        try:
            url = f"{base_url}?name={name}&type={record_type}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                answers = data.get("Answer", [])
                results: list[str] = []
                for ans in answers:
                    val = str(ans.get("data", "")).strip()
                    if val:
                        results.append(val)
                return results
        except Exception:
            continue
    return []


def collect_dns_records(
    domain: str,
    *,
    doh_query: Callable[[str, str], list[str]] = query_doh_records,
) -> dict[str, Any]:
    """Collect extended DNS records: MX, TXT (SPF), DMARC, NS, SOA."""
    mx_raw = doh_query(domain, "MX")
    txt_raw = doh_query(domain, "TXT")
    dmarc_raw = doh_query(f"_dmarc.{domain}", "TXT")
    ns_raw = doh_query(domain, "NS")
    soa_raw = doh_query(domain, "SOA")

    clean_txt = [r.strip().strip('"') for r in txt_raw]
    clean_ns = sorted({r.rstrip(".").lower() for r in ns_raw if r.strip()})

    dmarc_text = None
    for r in dmarc_raw:
        cleaned = r.strip().strip('"')
        if cleaned.lower().startswith("v=dmarc1"):
            dmarc_text = cleaned
            break

    return {
        "mx": parse_mx_records(mx_raw),
        "txt": clean_txt,
        "spf": parse_spf_record(txt_raw),
        "dmarc": parse_dmarc_record(dmarc_text),
        "ns": clean_ns,
        "soa": parse_soa_record(soa_raw[0] if soa_raw else None),
    }


def query_rdap(domain: str, timeout: float = 4.0) -> dict[str, Any]:
    """Fetch WHOIS/RDAP registration data via open RDAP service."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/rdap+json,application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return parse_rdap_response(data)
    except Exception as exc:
        return {"error": str(exc)}


def query_ip_info(ip: str, timeout: float = 4.0) -> dict[str, Any]:
    """Fetch ASN, organization and geographic metadata for a public IP."""
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("error"):
                return {"error": data.get("reason", "IP lookup failed")}
            return parse_ip_info(data)
    except Exception as exc:
        return {"error": str(exc)}


def query_subdomains(
    domain: str, timeout: float = 5.0, max_subdomains: int = 40
) -> dict[str, Any]:
    """Passively discover subdomains from Certificate Transparency logs (crt.sh)."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            found = set()
            dot_domain = f".{domain.lower()}"
            for item in data:
                name_val = item.get("name_value", "")
                for sub in name_val.splitlines():
                    sub = sub.strip().lower().lstrip("*.")
                    if (sub.endswith(dot_domain) or sub == domain.lower()) and sub != domain.lower():
                        found.add(sub)
            sorted_subs = sorted(found)
            return {
                "total_found": len(sorted_subs),
                "subdomains": sorted_subs[:max_subdomains],
            }
    except Exception as exc:
        return {"error": str(exc)}


def collect_report(
    target: str,
    *,
    resolver: Callable[..., list[str]] = resolve_public_addresses,
    fetcher: Callable[[str], dict[str, Any]] = fetch_public_url,
    certificate_probe: Callable[
        [str, list[str]], dict[str, Any]
    ] = probe_tls_certificate,
    extended_dns_collector: Callable[..., dict[str, Any]] | None = collect_dns_records,
    rdap_fetcher: Callable[[str], dict[str, Any]] | None = query_rdap,
    ip_info_fetcher: Callable[[str], dict[str, Any]] | None = query_ip_info,
    subdomain_fetcher: Callable[[str], dict[str, Any]] | None = query_subdomains,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Collect a deterministic report from bounded public sources."""
    domain = normalize_domain(target)
    addresses = resolver(domain, deadline=time.monotonic() + timeout)
    try:
        ipv4_addresses = _public_ipv4_only(addresses)
    except NetworkProbeError as exc:
        probe_error = {"error": {"type": "network_probe_error", "message": str(exc)}}
        home = probe_error
        security_txt = probe_error
        robots_txt = probe_error
        tls = probe_error
        dns_extended = probe_error
        whois = probe_error
        network = probe_error
        subdomains = probe_error
    else:
        home = _safe_call(lambda: fetcher(f"https://{domain}/"))
        security_txt = _safe_call(
            lambda: fetcher(f"https://{domain}/.well-known/security.txt")
        )
        robots_txt = _safe_call(lambda: fetcher(f"https://{domain}/robots.txt"))
        tls = _safe_call(lambda: certificate_probe(domain, ipv4_addresses))
        dns_extended = (
            _safe_call(lambda: extended_dns_collector(domain))
            if extended_dns_collector is not None
            else {}
        )
        whois = _safe_call(lambda: rdap_fetcher(domain)) if rdap_fetcher is not None else {}
        network = (
            _safe_call(lambda: ip_info_fetcher(ipv4_addresses[0]))
            if ip_info_fetcher is not None and ipv4_addresses
            else {}
        )
        subdomains = (
            _safe_call(lambda: subdomain_fetcher(domain))
            if subdomain_fetcher is not None
            else {}
        )

    if "error" in home:
        web: dict[str, Any] = home
    else:
        web = {
            "url": home["url"],
            "status": home["status"],
            "title": home.get("title"),
            "meta": home.get("meta", {}),
            "headers": analyze_security_headers(home.get("headers", {})),
        }
        if home.get("truncated"):
            web["truncated"] = True

    dns_section: dict[str, Any] = {"addresses": addresses}
    if isinstance(dns_extended, dict) and "error" not in dns_extended:
        dns_section.update(dns_extended)
    elif isinstance(dns_extended, dict) and "error" in dns_extended:
        dns_section["extended_error"] = dns_extended["error"]

    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "target": domain,
        "dns": dns_section,
        "whois": whois,
        "network": network,
        "subdomains": subdomains,
        "web": web,
        "tls": tls,
        "files": {
            "security_txt": _file_summary(security_txt, kind="security_txt"),
            "robots_txt": _file_summary(robots_txt, kind="robots_txt"),
        },
    }
