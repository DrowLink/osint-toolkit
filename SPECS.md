# Technical Specifications & Development Standards

## 1. Core Architectural Principles

1. **Zero External Dependencies**
   - The entire toolkit MUST be built exclusively using Python's standard library (`urllib.request`, `socket`, `ssl`, `json`, `concurrent.futures`, `re`, `argparse`).
   - No third-party packages (`requests`, `beautifulsoup4`, `dns-python`, etc.) may be added to runtime dependencies.

2. **Strict Time and Resource Bounds**
   - Every network operation must obey monotonic deadlines (`time.monotonic()`).
   - Response bodies are capped at 256 KiB to prevent denial-of-service / memory leaks.
   - Background DNS resolvers must run in daemon threads to avoid stalling process exits.

3. **Passive & Defensive Reconnaissance**
   - Only publicly exposed, standard records and endpoints are queried (DoH, RDAP, HTTP headers, TLS, public social profiles).
   - No aggressive port scanning, credential brute-forcing, or access-control bypasses.
   - Private IP addresses, localhost, multicast, and loopback destinations are strictly blocked.

4. **Human-First CLI with Machine Compatibility**
   - Terminal executions (`isatty()`) default to formatted UTF-8 tree box visualization.
   - Pipes (`|`) or the `-j`/`--json` flag default to structured JSON.
   - Commands must support intuitive targets without mandatory flags (e.g., auto-detecting usernames vs. domains).

---

## 2. Mandatory Documentation Policy

> **Policy Requirement:**
> Starting immediately, **every new feature, flag, data source, platform check, parser, or architectural change MUST be fully documented in the project documentation before merging or releasing.**

### Documentation Checklist for Pull Requests & Contributions:
- [ ] **Interactive Web Documentation (`docs/index.html`)**:
  - Update relevant guide sections (Installation, Features, Reference, or CLI Options).
  - If a new social platform is supported in username hunting, add it to the Platforms Directory table.
  - If a new DNS or HTTP probe is added, document its rationale and collected data fields.
- [ ] **Repository README (`README.md`)**:
  - Keep usage examples, flag tables, and badges synchronized with current code.
- [ ] **Unit Tests (`tests/`)**:
  - Maintain 100% test coverage for all new collectors, parsers, and CLI entry points.
- [ ] **Specs Validation**:
  - Confirm compliance with zero-dependency and bounded-timeout guarantees.

---

## 3. Supported Platforms & Detectors Specification

- **Username Hunter Engine**:
  - Platforms must specify detection strategy (`status_code`, `message_present`, or `message_absent`).
  - False positive mitigation (such as Wikipedia sockpuppet detection or reserved namespace filters) must be codified directly in detector rules.
  - Search concurrency uses bounded thread pools (`max_workers=20`) with per-request timeouts.

- **Domain Reconnaissance Engine**:
  - DNS resolution via DoH (`cloudflare-dns.com` with `dns.google` fallback).
  - Anti-spoofing analysis: SPF syntax & enforcement evaluation, DMARC tags & policy strength (`reject`, `quarantine`, `none`), MX provider classification.
  - WHOIS events via ICANN RDAP protocols.
  - TLS certificate inspection via native `ssl.SSLContext`.
