# PJR OSINT Toolkit

A small, dependency-free Python CLI that collects **bounded, passive metadata** about a public domain and returns a reproducible JSON report.

## What it collects

- Public IPv4 and IPv6 DNS addresses (IPv6 is metadata-only)
- Homepage status, title, final URL, server header, and common security-header coverage
- Verified TLS certificate subject, issuer, expiry, DNS names, and SHA-256 fingerprint
- Presence and a bounded preview of `/.well-known/security.txt` and `/robots.txt`

It does **not** scan ports, brute-force paths, enumerate accounts, bypass access controls, or accept IP/private-network targets.

## Safety properties

- Rejects IP literals, custom ports, local names, every non-public-unicast DNS answer (including multicast), and domains with more than eight distinct addresses
- Pins outbound HTTP/TLS connections to prevalidated public IPv4 addresses only
- Verifies TLS certificates and hostnames
- Limits each response to 256 KiB and each logical HTTP fetch to three redirects under one monotonic eight-second deadline that includes DNS resolution, connection, TLS, writes, and reads
- Bounds the initial DNS metadata lookup with its own monotonic eight-second deadline; timed-out resolver work runs only in a daemon thread and cannot keep the CLI alive
- Makes three logical HTTP fetches, each with at most four URL hops including the initial URL, plus one TLS certificate probe
- Tries at most eight validated public IPv4 addresses per URL hop/probe: at most 96 HTTP connection attempts and eight TLS connection attempts per report (and zero when DNS has no eligible IPv4 address)
- Uses only Python's standard library

### IPv6/NAT64 limitation

The report retains validated public AAAA records as DNS metadata, but the toolkit never opens HTTP or TLS connections to IPv6 addresses. Arbitrary, network-specific NAT64 prefixes cannot be identified reliably from an IPv6 address alone; allowing IPv6 connections could therefore translate a seemingly public address into a private IPv4 destination. An IPv6-only target receives structured `network_probe_error` results for web, TLS, and file probes. IPv4-mapped IPv6, 6to4, Teredo, and the well-known NAT64 prefix are still checked as defense in depth.

The deadlines above are per operation, not one deadline for the complete report. A full report performs one initial DNS lookup, three HTTP operations, and one TLS operation sequentially.

## Requirements

Python 3.11 or newer.

## Run without installing

```bash
python3 -m osint_toolkit example.com
```

Save the JSON report:

```bash
python3 -m osint_toolkit example.com > example.com.json
```

## Install locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
osint-toolkit example.com
```

## Example output shape

```json
{
  "schema_version": 1,
  "target": "example.com",
  "dns": {"addresses": ["93.184.216.34"]},
  "web": {"status": 200, "title": "Example Domain"},
  "tls": {"expires": "...", "sha256": "..."},
  "files": {"security_txt": {}, "robots_txt": {}}
}
```

The exact values depend on the target at collection time. Individual web/TLS failures are represented as structured `error` fields instead of fabricated data.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Responsible use

Use this tool only for lawful research involving public internet resources. Follow applicable law, site terms, and organizational policies. Keep request volume low and obtain authorization before moving from passive collection to active security testing.

## License

MIT — see [LICENSE](LICENSE).
