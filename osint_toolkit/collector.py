"""Bounded, passive collection for public domain metadata."""

from __future__ import annotations

import hashlib
import http.client
import io
import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

from .core import (
    analyze_security_headers,
    is_public_unicast_address,
    normalize_domain,
    resolve_public_addresses,
)

_USER_AGENT = "PJR-OSINT-Toolkit/0.1 (+https://github.com/DrowLink/osint-toolkit)"
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
                "Accept-Encoding: identity\r\n"
                "Connection: close\r\n\r\n"
            )
            stream.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(stream)
            response.begin()
            body = response.read(_MAX_BODY + 1)
            if len(body) > _MAX_BODY:
                raise ValueError("response exceeded the 256 KiB safety limit")
            headers = {key: value for key, value in response.getheaders()}
            text = _decode_body(body, headers.get("Content-Type", ""))
            title_match = _TITLE_RE.search(text)
            title = (
                re.sub(r"\s+", " ", title_match.group(1)).strip()
                if title_match
                else None
            )
            return {
                "url": url,
                "status": response.status,
                "headers": headers,
                "title": title,
                "text": text,
            }
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
            expires = (
                datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(certificate["notAfter"]), tz=UTC
                )
                .isoformat()
                .replace("+00:00", "Z")
            )
            return {
                "subject": subject,
                "issuer": issuer,
                "expires": expires,
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


def _file_summary(result: dict[str, Any]) -> dict[str, Any]:
    if "error" in result:
        return result
    return {
        "found": result.get("status") == 200,
        "status": result.get("status"),
        "url": result.get("url"),
        "snippet": result.get("text", "")[:500] if result.get("status") == 200 else "",
    }


def collect_report(
    target: str,
    *,
    resolver: Callable[..., list[str]] = resolve_public_addresses,
    fetcher: Callable[[str], dict[str, Any]] = fetch_public_url,
    certificate_probe: Callable[
        [str, list[str]], dict[str, Any]
    ] = probe_tls_certificate,
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
    else:
        home = _safe_call(lambda: fetcher(f"https://{domain}/"))
        security_txt = _safe_call(
            lambda: fetcher(f"https://{domain}/.well-known/security.txt")
        )
        robots_txt = _safe_call(lambda: fetcher(f"https://{domain}/robots.txt"))
        tls = _safe_call(lambda: certificate_probe(domain, ipv4_addresses))

    if "error" in home:
        web: dict[str, Any] = home
    else:
        web = {
            "url": home["url"],
            "status": home["status"],
            "title": home.get("title"),
            "headers": analyze_security_headers(home.get("headers", {})),
        }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "target": domain,
        "dns": {"addresses": addresses},
        "web": web,
        "tls": tls,
        "files": {
            "security_txt": _file_summary(security_txt),
            "robots_txt": _file_summary(robots_txt),
        },
    }
