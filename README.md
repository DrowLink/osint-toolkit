<p align="center">
  <br>
  <a href="https://github.com/DrowLink/osint-toolkit" target="_blank">
    <img src="images/logo.png" alt="DrowLink OSINT Toolkit" width="180"/>
  </a>
  <br>
  <br>
  <b>A fast, dependency-free Python CLI for passive domain infrastructure intelligence and multi-platform username hunting.</b>
  <br>
  <span>Hunt down infrastructure metadata, email anti-spoofing configurations, and user accounts across public platforms.</span>
  <br>
</p>

<p align="center">
  <a href="https://drowlink.github.io/osint-toolkit/" target="_blank"><b>Documentation Site</b></a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#installation">Installation</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#general-usage">Usage</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#what-it-collects">Features</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="SPECS.md">Specs</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen.svg" alt="Zero Dependencies"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License"/>
  <img src="https://img.shields.io/badge/tests-83%20passing-success.svg" alt="Tests 83 passing"/>
</p>

<p align="center">
  <img width="85%" src="images/demo.png" alt="DrowLink OSINT Toolkit Demo"/>
</p>

---

## Key Highlights

- ⚡ **Zero External Dependencies**: Built 100% on Python's standard library (`urllib`, `socket`, `ssl`, `concurrent.futures`, `csv`).
- 🌐 **56+ Verified Platforms**: Fast multi-threaded username hunting across 5 major digital ecosystem categories.
- 🕵️ **OpSec Proxy Support (`-p` / `--proxy`)**: Route scans anonymously via HTTP/HTTPS corporate, SOCKS, or Tor proxies.
- 📊 **Flexible Export Formats**: Dual output with human-readable terminal tree UI, raw JSON (`-j`), or standard RFC 4180 CSV (`--csv`).
- 🤖 **Local AI Native (Ollama)**: Automated threat synthesis and identity correlation using local LLMs with zero API keys and complete privacy.
- 🛡️ **Strictly Passive & Bounded**: No port scans, no brute forcing, and no invasive probing.
- 🚀 **High Concurrency**: Multi-threaded execution inspects dozens of platforms and records in seconds.
- 🖥️ **Modern Terminal UI**: Sleek UTF-8 tree hierarchy formatting with colors and status badges.

---

## Installation

| Method | Command | Notes |
| :--- | :--- | :--- |
| **Direct Run** *(No install)* | `./osint <target>` or `python3 -m osint_toolkit <target>` | Works immediately on any system with Python 3.11+ |
| **CLI Command** | `pip install .` | Installs global `osint`, `search-shodan`, `search-virustotal`, etc. |
| **Docker** | `docker run -it --rm osint-toolkit <target>` | Portable container execution |

```bash
# Clone the repository
git clone https://github.com/DrowLink/osint-toolkit.git
cd osint-toolkit

# Run directly without flags!
./osint torvalds
```

---

## General Usage

`osint-toolkit` automatically detects whether your target is a **username** or a **domain**, and defaults to a clean, formatted terminal UI:

### 1. Username Hunting Mode (Sherlock Style)

Just pass any username or `@handle`. It searches concurrently across 56+ verified public platforms:

```bash
# Search a username (auto-detected)
./osint torvalds

# Anonymize scans with an OpSec proxy (Tor / HTTP)
./osint torvalds --proxy http://127.0.0.1:8080

# Export report in standard CSV format
./osint torvalds --csv

# Save findings to a CSV or JSON file
./osint torvalds -o findings.csv
./osint torvalds -o findings.json

# Output pure JSON (for scripting / piping)
./osint torvalds -j
```

### 2. Domain Reconnaissance Mode

Pass any domain name to analyze DNS, email security, WHOIS/RDAP, certificates, and headers:

```bash
# Analyze domain infrastructure (auto-detected)
./osint github.com

# Save complete audit to CSV or JSON
./osint github.com -o audit.csv
./osint github.com -o audit.json

# Route through proxy
./osint github.com --proxy http://127.0.0.1:8080
```

### 3. Specialized Threat & Intel Services

Run standalone commands or subcommands for deep external intelligence:

```bash
# Shodan (zero-auth via InternetDB, or SHODAN_API_KEY)
./osint shodan 8.8.8.8
./search_shodan github.com --csv

# IP2Location (zero-auth public tier, or IP2LOCATION_API_KEY)
./osint ip2location 8.8.8.8
./search_ip2location 1.1.1.1 --proxy http://127.0.0.1:8080

# VirusTotal (with VIRUSTOTAL_API_KEY or guided unauthenticated mode)
./osint virustotal google.com
./search_virustotal 8.8.8.8

# Censys (with CENSYS_API_ID / CENSYS_API_SECRET)
./osint censys 8.8.8.8
./search_censys google.com
```

### 4. Local AI Intelligence Briefing (Ollama)

Generate an automated executive cyber assessment or subject correlation profile using your local LLM (100% private, zero cloud APIs):

```bash
# Run username hunt with local AI analysis
./osint torvalds --ai

# Run domain audit with local AI posture briefing
./osint github.com --ai

# Choose a specific local model (e.g. llama3, mistral, qwen2.5)
./osint torvalds --ai --ai-model mistral
```

### 5. Python Library Usage

All engines are directly importable as pure Python functions:

```python
from osint_toolkit import (
    search_username,
    collect_report,
    search_shodan,
    search_ip2location,
    search_virustotal,
    search_censys,
    generate_ai_briefing,
)

# Search usernames with proxy support
profiles = search_username("torvalds", proxy="http://127.0.0.1:8080")

# Generate local AI intelligence briefing
ai_summary = generate_ai_briefing(profiles, model="llama3")
print(ai_summary["briefing"])
```

---

## What It Collects

### Domain Mode
- **DNS & Nameservers**: Public IPv4 & IPv6 addresses, authoritative nameservers (NS), and SOA primary server/administrator contact.
- **Email & Anti-Spoofing**: MX servers with provider identification (*Google Workspace, Microsoft 365, Proton, etc.*), SPF mechanism strength evaluation, and DMARC enforcement policy (`reject`, `quarantine`, `none`).
- **Domain Registration (RDAP / WHOIS)**: Official registrar, registration/expiration dates, and EPP domain statuses.
- **IP Infrastructure & Geolocation**: Public IP ASN, ISP organization, country, region, and city.
- **Subdomains**: Historical subdomain discovery via Certificate Transparency (crt.sh) logs.
- **Web & Security Headers**: HTTP status, page title, server banner, cookie security flags (`Secure`, `HttpOnly`, `SameSite`), and defensive headers (*HSTS, CSP, COOP, COEP, etc.*).
- **TLS Certificate**: Subject, issuer, cipher suite, protocol, expiry, days remaining, and Subject Alternative Names (SANs).
- **Public Policy Files**: Presence, contacts, and sitemaps in `/.well-known/security.txt` and `/robots.txt`.

### Username Mode (56 Verified Platforms)
- **Coding & Tech (17)**: GitHub, GitLab, Codeberg, Bitbucket, Docker Hub, PyPI, npm, Crates.io, Dev.to, Hashnode, Keybase, HackerNews, Kaggle, LeetCode, TryHackMe, Replit, Pastebin.
- **Social & Messaging (13)**: Telegram, Reddit, Mastodon, Bluesky, Disqus, Linktree, Gravatar, Pinterest, BuyMeACoffee, Ko-fi, ProductHunt, About.me, Quora.
- **Gaming & Entertainment (9)**: Steam, Chess.com, Lichess, itch.io, Roblox, Speedrun.com, osu!, Letterboxd, Chessgames.
- **Design & Audio (10)**: SoundCloud, Spotify, Bandcamp, Behance, Dribbble, Flickr, 500px, DeviantArt, Unsplash, Mixcloud.
- **Publishing & Knowledge (7)**: Substack, Medium, Wikipedia *(with sockpuppet/blocked account detection)*, Instructables, Goodreads, Duolingo, Patreon.

---

## CLI Options

```console
$ ./osint --help
usage: osint-toolkit [-h] [-u USERNAME] [-d DOMAIN] [-p PROXY] [--csv]
                     [-t TIMEOUT] [-o OUTPUT] [-j] [-s] [--ai]
                     [--ai-model AI_MODEL] [--ai-endpoint AI_ENDPOINT]
                     [target]

Fast, dependency-free OSINT toolkit for domains and usernames.

positional arguments:
  target                Target domain (e.g. google.com) or username (e.g. drowlink)

options:
  -h, --help            Show this help message and exit
  -u, --username USER   Explicitly search username across public platforms
  -d, --domain DOMAIN   Explicitly analyze domain infrastructure
  -p, --proxy PROXY     Proxy URL for anonymous scanning (e.g. http://127.0.0.1:8080)
  --csv                 Output report in standard CSV format
  -t, --timeout SECS    Operation deadline in seconds (default: 8.0)
  -o, --output FILE     Path to write report output (JSON or CSV based on extension/flag)
  -j, --json            Output raw JSON instead of human-readable summary
  -s, --summary         Display human-readable summary card (default in terminal)
  --ai, --ollama        Synthesize report with local AI (Ollama) intelligence briefing
  --ai-model AI_MODEL   Local LLM model to use (default: llama3 or first installed model)
  --ai-endpoint URL     Ollama API endpoint (default: http://localhost:11434)
```

---

## Safety Properties

- Rejects IP literals, custom ports, local names, and non-public-unicast DNS answers.
- Pins outbound HTTP/TLS connections to prevalidated public IPv4 addresses only.
- Limits each response body to 256 KiB; large payloads are safely truncated while preserving headers.
- Bounds initial lookups with monotonic per-operation deadlines in daemon threads.
- Strictly uses Python's standard library with zero third-party dependencies.

---

## Tests

Run the complete test suite (83 unit tests covering collectors, parsers, CLI, username search, AI, and intelligence services):

```bash
python3 -m unittest discover -s tests -v
```

---

## Responsible Use

Use this tool only for lawful research involving public internet resources. Follow applicable laws, site terms of service, and organizational policies. Keep request volume low and obtain authorization before transitioning from passive reconnaissance to active security testing.

---

## Contributing

Contributions, bug reports, and site additions are welcome! Please check [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

[MIT](LICENSE) © DrowLink
