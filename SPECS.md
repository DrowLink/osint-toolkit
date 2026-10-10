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

- **Username Hunter Engine (56 Curated Platforms)**:
  - Curated platform registry verified against false positives and bot hurdles across 5 distinct categories:
    1. **Coding & Tech (17)**: GitHub, GitLab, Codeberg, Bitbucket, Docker Hub, PyPI, npm, Crates.io, Dev.to, Hashnode, Keybase, HackerNews, Kaggle, LeetCode, TryHackMe, Replit, Pastebin.
    2. **Social & Messaging (13)**: Telegram, Reddit, Mastodon, Bluesky, Disqus, Linktree, Gravatar, Pinterest, BuyMeACoffee, Ko-fi, ProductHunt, About.me, Quora.
    3. **Gaming & Entertainment (9)**: Steam, Chess.com, Lichess, itch.io, Roblox, Speedrun.com, osu!, Letterboxd, Chessgames.
    4. **Design & Audio (10)**: SoundCloud, Spotify, Bandcamp, Behance, Dribbble, Flickr, 500px, DeviantArt, Unsplash, Mixcloud.
    5. **Publishing & Knowledge (7)**: Substack, Medium, Wikipedia, Instructables, Goodreads, Duolingo, Patreon.
  - Platforms specify detection strategy (`status_code`, `message_present`, or `message_absent`).
  - False positive mitigation (such as Wikipedia sockpuppet detection or reserved namespace filters) is codified directly in detector rules.
  - Search concurrency uses bounded thread pools (`max_workers=20`) with per-request timeouts.

- **Domain Reconnaissance Engine**:
  - DNS resolution via DoH (`cloudflare-dns.com` with `dns.google` fallback).
  - Anti-spoofing analysis: SPF syntax & enforcement evaluation, DMARC tags & policy strength (`reject`, `quarantine`, `none`), MX provider classification.
  - WHOIS events via ICANN RDAP protocols.
  - TLS certificate inspection via native `ssl.SSLContext`.

---

## 4. Specialized Intelligence Services Specification

The toolkit provides dedicated methods and separate standalone commands for external threat & infrastructure intelligence:

1. **`search_shodan` / `osint shodan` / `search-shodan`**:
   - Primary: Uses Shodan InternetDB (`https://internetdb.shodan.io/{ip}`) for zero-authentication, instant queries returning open ports, CPEs, hostnames, tags, and known CVEs.
   - Enhanced: Accepts `SHODAN_API_KEY` (or `--api-key`) for full authenticated host queries.
   - Automatic domain resolution: If a domain target is passed, it is safely resolved to its public IPv4 address before querying.

2. **`search_ip2location` / `osint ip2location` / `search-ip2location`**:
   - Geolocation & Proxy Engine (`https://api.ip2location.io/?ip={ip}`).
   - Returns country, city, coordinates, timezone, ASN, ISP organization, and proxy/VPN detection.
   - Works on the free public tier without an API key or with `IP2LOCATION_API_KEY`.

3. **`search_virustotal` / `osint virustotal` / `search-virustotal`**:
   - Threat Analysis Engine (`https://www.virustotal.com/api/v3/`).
   - Supports both domain and IP targets.
   - Requires `VIRUSTOTAL_API_KEY` or `--api-key`. Unauthenticated calls return guided configuration instructions and the direct public web report link.
   - Reports engine verdict counts (harmless, malicious, suspicious) and reputation score.

4. **`search_censys` / `osint censys` / `search-censys`**:
   - Host Infrastructure Engine (`https://search.censys.io/api/v2/hosts/{ip}`).
   - Requires `CENSYS_API_ID` and `CENSYS_API_SECRET` credentials. Unauthenticated calls return guided setup instructions and web search portal link.
   - Reports open services, transport protocols, autonomous system, and geolocation.

---

## 5. Local AI Integration Specification (Ollama)

1. **Zero External Dependencies / HTTP Native**:
   - Connects directly to local or network Ollama REST API (`http://localhost:11434/api/generate` and `/api/tags`) using Python's standard library `urllib.request`.
   - No external AI SDKs (`ollama`, `openai`, `langchain`) are permitted.

2. **Automated Intelligence Briefing**:
   - Flag: `--ai` / `--ollama` (with optional `--ai-model` and `--ai-endpoint`).
   - Method: `generate_ai_briefing(report, model=None, endpoint=None, timeout=40.0)`.
   - Functionality: Takes collected metadata from username hunting, domain recon, or threat scans and generates an executive cyber posture / risk summary using a local LLM (e.g., `llama3`, `mistral`, `phi3`, `qwen2.5`).
   - Resiliency: If Ollama is offline or unreachable, the toolkit reports a friendly, non-fatal message without failing the CLI process.

---

## 6. OpSec & Proxy Anonymity Specification

1. **Proxy Support Architecture**:
   - Flag: `-p <URL>` / `--proxy <URL>` (e.g., `http://127.0.0.1:8080`, `http://user:pass@proxy.corp:3128`).
   - Standard Library Implementation: Implemented with `urllib.request.ProxyHandler({"http": proxy, "https": proxy})` and `urllib.request.build_opener()`.
   - Engine Propagation: Proxy configuration seamlessly propagates through username hunting thread workers, Shodan InternetDB queries, IP2Location queries, VirusTotal lookups, and Censys queries.
   - Result Auditing: The resulting report includes `"proxy_used": "<URL>"` metadata confirming routing for chain-of-custody and evidence logging.

---

## 7. Structured Export Formats Specification (JSON & CSV)

1. **JSON Output**:
   - Flag: `-j` / `--json` or `-o <path.json>`.
   - Standard: Indented, key-sorted RFC 8259 JSON structure suitable for SIEM, jq pipelines, and automated ingestion.

2. **CSV Output**:
   - Flag: `--csv` or `-o <path.csv>`.
   - Standard: Strict RFC 4180 format generated via Python's standard `csv` library.
   - Username schema: `target,platform,category,exists,status,url`.
   - Domain schema: `target,section,key,value`.
   - Intelligence services schema: `service,target,key,value`.


