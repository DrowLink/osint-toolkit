"""Local AI integration with Ollama for automated OSINT intelligence briefings and semantic validation.

Adheres 100% to project standards:
- 100% Python standard library (no external LLM SDKs or pip dependencies)
- Bounded network calls and strict deadlines
- Zero crashes when Ollama is offline (graceful status messages)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3"


def get_ollama_endpoint() -> str:
    """Return configured Ollama endpoint from environment or default."""
    endpoint = os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_ENDPOINT).strip()
    if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
        endpoint = f"http://{endpoint}"
    return endpoint.rstrip("/")


def is_ollama_available(endpoint: str | None = None, timeout: float = 2.0) -> bool:
    """Check if local Ollama server is running and reachable."""
    base_url = endpoint or get_ollama_endpoint()
    url = f"{base_url}/api/tags"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


def get_available_models(endpoint: str | None = None, timeout: float = 2.0) -> list[str]:
    """Retrieve list of locally installed Ollama models."""
    base_url = endpoint or get_ollama_endpoint()
    url = f"{base_url}/api/tags"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                models = data.get("models", [])
                return [m.get("name") for m in models if m.get("name")]
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
        pass
    return []


def _resolve_model(model: str | None, endpoint: str) -> str:
    """Resolve model name, choosing requested model or first available local model."""
    if model:
        return model
    env_model = os.environ.get("OLLAMA_MODEL")
    if env_model:
        return env_model
    available = get_available_models(endpoint)
    if available:
        # Check if llama3 or mistral is among them
        for preferred in ("llama3", "llama3:latest", "mistral", "qwen2.5", "phi3"):
            if preferred in available:
                return preferred
        return available[0]
    return DEFAULT_OLLAMA_MODEL


def build_osint_prompt(report: dict[str, Any]) -> str:
    """Create a structured prompt for local LLM OSINT analysis."""
    target = report.get("target") or report.get("ip") or "Target"
    
    # Check report type
    if "profiles_found" in report:
        # Username report
        found = report.get("profiles_found", [])
        not_found = report.get("profiles_not_found", [])
        platforms = [f"{p.get('name')} ({p.get('category')}): {p.get('url')}" for p in found]
        missing = [p.get("name") for p in not_found]
        
        prompt = (
            f"You are an expert OSINT and cyber intelligence analyst. "
            f"Analyze the following public digital footprint report for subject '@{target}':\n\n"
            f"- Profiles Found ({len(found)}):\n" + "\n".join(f"  * {p}" for p in platforms) + "\n\n"
            f"- Platforms Not Found ({len(not_found)}): {', '.join(missing[:15])}\n\n"
            f"Provide a concise, professional intelligence brief covering:\n"
            f"1. Identity & Activity Summary (developer, gamer, social, etc.)\n"
            f"2. Cross-platform Correlation & Exposure Assessment\n"
            f"3. Key Takeaways or Investigation Leads\n"
            f"Keep your response concise, objective, and formatted with bullet points (under 180 words)."
        )
        return prompt

    if "dns" in report and "web" in report:
        # Domain report
        dns = report.get("dns", {})
        addrs = dns.get("addresses", [])
        ns = dns.get("nameservers", [])
        mx_items = dns.get("mx_records", [])
        mx_summary = [f"{m.get('exchange')} (Provider: {m.get('provider')})" for m in mx_items]
        spf = dns.get("spf", {})
        dmarc = dns.get("dmarc", {})
        tls = report.get("tls", {})
        web = report.get("web", {})
        headers = web.get("headers", {})

        prompt = (
            f"You are an expert cybersecurity and infrastructure analyst. "
            f"Analyze the following OSINT infrastructure audit for domain '{target}':\n\n"
            f"- IP Addresses: {', '.join(addrs)}\n"
            f"- Nameservers: {', '.join(ns[:4])}\n"
            f"- Mail Servers (MX): {', '.join(mx_summary) if mx_summary else 'None'}\n"
            f"- Anti-Spoofing: SPF={spf.get('status')} ({spf.get('policy')}), DMARC Policy={dmarc.get('policy')} (Enforced: {dmarc.get('enforced')})\n"
            f"- Web Server: {headers.get('server', 'Hidden/Unknown')}, Status={web.get('status')}\n"
            f"- TLS Certificate: Protocol={tls.get('protocol')}, Cipher={tls.get('cipher', {}).get('name')}, Days Left={tls.get('days_remaining')}\n"
            f"- Security Headers Present: {', '.join(headers.get('present', []))}\n"
            f"- Missing Headers: {', '.join(headers.get('missing', []))}\n\n"
            f"Provide an executive cyber posture assessment:\n"
            f"1. Infrastructure & Hosting Profile\n"
            f"2. Email Security & Anti-Phishing Posture (SPF/DMARC evaluation)\n"
            f"3. Security Gaps / Recommendations\n"
            f"Keep it concise, high-impact, and under 180 words."
        )
        return prompt

    # Generic or Specialized service report (Shodan, IP2Location, VirusTotal, etc.)
    service = report.get("service", "osint")
    report_json = json.dumps(report, indent=2)
    return (
        f"You are an expert cyber threat intelligence analyst. "
        f"Analyze this {service.upper()} intelligence record for '{target}':\n\n"
        f"```json\n{report_json}\n```\n\n"
        f"Provide a brief 3-point threat and infrastructure assessment summary (under 150 words)."
    )


def generate_ai_briefing(
    report: dict[str, Any],
    *,
    model: str | None = None,
    endpoint: str | None = None,
    timeout: float = 40.0,
) -> dict[str, Any]:
    """Send an OSINT report to local Ollama and generate an intelligence briefing.

    Returns a dict with:
        - success: bool
        - model: str
        - briefing: str (or error message)
        - endpoint: str
    """
    base_url = endpoint or get_ollama_endpoint()
    target_model = _resolve_model(model, base_url)
    prompt = build_osint_prompt(report)

    payload = {
        "model": target_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    url = f"{base_url}/api/generate"
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                resp_json = json.loads(resp.read().decode("utf-8"))
                briefing_text = resp_json.get("response", "").strip()
                return {
                    "success": True,
                    "model": target_model,
                    "endpoint": base_url,
                    "briefing": briefing_text,
                }
            return {
                "success": False,
                "model": target_model,
                "endpoint": base_url,
                "error": f"Ollama returned HTTP status {resp.status}",
            }
    except urllib.error.URLError as exc:
        return {
            "success": False,
            "model": target_model,
            "endpoint": base_url,
            "error": (
                f"Local Ollama is not accessible at {base_url}. "
                f"Make sure Ollama is running ('ollama serve' or 'ollama run {target_model}')."
            ),
        }
    except (OSError, TimeoutError) as exc:
        return {
            "success": False,
            "model": target_model,
            "endpoint": base_url,
            "error": f"Request to local AI timed out after {timeout}s: {exc}",
        }


def format_ai_briefing_card(
    ai_result: dict[str, Any],
    *,
    use_color: bool = True,
) -> str:
    """Format AI briefing into a beautiful terminal UI card."""
    def c(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if use_color else text

    lines: list[str] = []
    model_name = ai_result.get("model", "local-llm")
    success = ai_result.get("success", False)

    lines.append(c("1;35", "┌" + "─" * 62 + "┐"))
    lines.append(c("1;35", f"│  🤖 LOCAL AI INTELLIGENCE BRIEFING ({model_name})".ljust(63) + "│"))
    lines.append(c("90", f"│  Engine: Ollama Local LLM  •  Endpoint: {ai_result.get('endpoint', '')}".ljust(63) + "│"))
    lines.append(c("1;35", "└" + "─" * 62 + "┘"))
    lines.append("")

    if not success:
        err = ai_result.get("error", "AI analysis unavailable")
        lines.append(c("33", f"⚠️  {err}"))
        return "\n".join(lines)

    briefing = ai_result.get("briefing", "")
    for line in briefing.splitlines():
        if line.strip().startswith("-") or line.strip().startswith("*"):
            lines.append(f"  {c('36', '•')} {line.strip().lstrip('-* ')}")
        elif line.strip().startswith(tuple(f"{i}." for i in range(1, 10))):
            num, _, rest = line.strip().partition(" ")
            lines.append(f"  {c('1;33', num)} {rest}")
        elif line.strip():
            lines.append(f"  {line}")
        else:
            lines.append("")

    return "\n".join(lines)
