# Contributing to OSINT Toolkit

Thank you for your interest in contributing to **OSINT Toolkit**! We welcome contributions from developers, security researchers, and OSINT practitioners of all skill levels.

---

## Code of Conduct & Core Philosophy

This project adheres to a strict design and operational philosophy:

1. **Zero External Dependencies**: 100% Python standard library (`urllib`, `socket`, `ssl`, `json`, `concurrent.futures`, `csv`, `re`). **No external `pip` packages are allowed.**
2. **Strictly Passive & Bounded**: No port scans, brute-forcing, credential attacks, or evasive probes.
3. **OpSec & Safety**: Memory-bounded payloads (max 256 KiB), monotonic deadlines, and strict SSRF / private IP rejection.
4. **Mandatory Documentation Policy**: Any new feature, flag, or platform detector **must** be documented in both `README.md` and `docs/index.html` (see [SPECS.md](SPECS.md)).
5. **100% Test Coverage**: All unit tests must pass without internet access or API keys.

---

## How Can You Contribute?

Here are several ways you can help make this tool even better:

- 🌐 **Add New Platforms**: Help us grow our username reconnaissance database beyond 56+ sites (e.g., developer platforms, gaming networks, forums).
- 🐛 **Report or Fix False Positives**: Verify platform detection accuracy and update error/claim strings for existing sites.
- ⚡ **Performance & Concurrency**: Optimize worker pools and DNS resolution logic.
- 📖 **Documentation & Translations**: Improve usage guides, CLI manual examples, or internationalization.
- 🤖 **AI Threat Prompts**: Enhance local LLM system prompts for sharper correlation and threat summarization.

---

## Adding a New Platform in 5 Minutes

Adding support for a new social network, developer hub, or forum is straightforward:

1. Open `osint_toolkit/username.py`.
2. Append your platform definition to the `PLATFORMS` dictionary:

```python
"PlatformName": {
    "url": "https://example.com/user/{username}",
    "category": "Developers",  # Options: Social & Chat, Code & Tech, Creators & Media, Knowledge & Community, Gaming & Hobbies
    "error_type": "status_code",  # or "message"
    "error_msg": "User not found",  # Required if error_type is "message"
},
```

3. Add corresponding test cases in `tests/test_username.py`.
4. Update the platform count and tables in `README.md` and `docs/index.html`.
5. Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

---

## Development & Testing Workflow

### 1. Clone & Set Up

```bash
git clone https://github.com/DrowLink/osint-toolkit.git
cd osint-toolkit
chmod +x osint
```

### 2. Run Tests

All unit tests run locally using standard library `unittest` (no `pytest` or internet required):

```bash
python3 -m unittest discover -s tests -v
```

### 3. Verify Formatting & Quality

Ensure code follows PEP 8 conventions and does not import third-party packages.

---

## Submitting a Pull Request (PR)

1. **Fork** the repository and create a feature branch (`git checkout -b feature/add-new-platform`).
2. **Commit** your changes with clear, descriptive commit messages (`git commit -m "feat(username): add Devpost and HackTheBox platforms"`).
3. **Push** to your fork (`git push origin feature/add-new-platform`).
4. **Open a Pull Request** describing:
   - What the change does.
   - How it was tested.
   - Confirmation that all unit tests pass.

---

## Questions or Suggestions?

Feel free to open an **Issue** or start a **Discussion** on GitHub. Thank you for helping build a faster, cleaner, and completely open-source OSINT ecosystem!
