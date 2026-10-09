"""Command-line interface for the OSINT toolkit."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any, TextIO

from .collector import collect_report
from .core import DomainValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-toolkit",
        description="Collect bounded, passive OSINT metadata for a public domain.",
    )
    parser.add_argument("target", help="Public domain or HTTPS URL")
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=8.0,
        help="Operation deadline in seconds (default: 8.0)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Path to write JSON report output (default: stdout)",
    )
    parser.add_argument(
        "-s",
        "--summary",
        action="store_true",
        help="Print a human-readable summary instead of raw JSON",
    )
    return parser


def format_summary(report: dict[str, Any], *, use_color: bool = True) -> str:
    """Format an OSINT report into a clean, human-readable terminal summary."""
    def c(code: str, text: str) -> str:
        if not use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    lines: list[str] = []
    target = report.get("target", "unknown")
    generated = report.get("generated_at", "")

    # Header Card
    lines.append(c("1;36", "┌" + "─" * 62 + "┐"))
    lines.append(c("1;36", f"│  ⚡ OSINT REPORT: {target}".ljust(63) + "│"))
    if generated:
        lines.append(c("90", f"│  Target: {target}  •  Generated: {generated}".ljust(63) + "│"))
    lines.append(c("1;36", "└" + "─" * 62 + "┘"))
    lines.append("")

    # DNS & Nameservers
    dns = report.get("dns", {})
    addresses = dns.get("addresses", [])
    v4 = [a for a in addresses if ":" not in a]
    v6 = [a for a in addresses if ":" in a]
    lines.append(c("1;34", "🌐 [DNS & Nameservers]"))
    if v4:
        lines.append(f"  ├── IPv4:       {c('32', ', '.join(v4))}")
    if v6:
        lines.append(f"  ├── IPv6:       {', '.join(v6)} (metadata-only)")
    if not addresses:
        lines.append(c("33", "  ├── Addresses:  No addresses found"))
    ns_list = dns.get("ns", [])
    if ns_list:
        lines.append(f"  ├── Nameservers:{', '.join(ns_list)}")
    soa = dns.get("soa")
    if soa and isinstance(soa, dict):
        soa_details = []
        if soa.get("primary_ns"):
            soa_details.append(f"Primary: {soa['primary_ns']}")
        if soa.get("admin_email"):
            soa_details.append(f"Admin: {soa['admin_email']}")
        if soa_details:
            lines.append(f"  └── SOA:        {' | '.join(soa_details)}")
    else:
        if v4 and not ns_list:
            lines[-1] = lines[-1].replace("├──", "└──")
    lines.append("")

    # Email Infrastructure & Anti-Spoofing
    mx_list = dns.get("mx", [])
    spf = dns.get("spf")
    dmarc = dns.get("dmarc")
    if mx_list or spf or dmarc:
        lines.append(c("1;35", "✉️  [Email & Anti-Spoofing (MX, SPF, DMARC)]"))
        if mx_list:
            mx_desc = [f"{item.get('preference', '')} {item.get('exchange', '')} [{c('35', item.get('provider', 'Custom'))}]" for item in mx_list[:4]]
            lines.append(f"  ├── MX Servers: {', '.join(mx_desc)}")
            if len(mx_list) > 4:
                lines.append(f"  │               (+{len(mx_list) - 4} more mail servers)")
        else:
            lines.append(c("33", "  ├── MX Servers: None configured"))

        if spf:
            strength_color = "32" if "Fail" in spf.get("strength", "") else "33"
            spf_strength = spf.get("strength", "")
            lines.append(f"  ├── SPF:        {c(strength_color, f'✔ [{spf_strength}]')} {spf.get('raw', '')}")
        else:
            lines.append(f"  ├── SPF:        {c('31', '✖ [-] Missing (No SPF protection)')}")

        if dmarc:
            enforce_color = "32" if "Enforced" in dmarc.get("enforcement", "") else "33"
            dmarc_enforce = dmarc.get("enforcement", "")
            lines.append(f"  └── DMARC:      {c(enforce_color, f'🛡️ [{dmarc_enforce}]')} {dmarc.get('raw', '')}")
        else:
            lines.append(f"  └── DMARC:      {c('31', '✖ [-] Missing (Vulnerable to spoofing)')}")
        lines.append("")

    # Domain Registration (RDAP)
    whois = report.get("whois", {})
    if whois and "error" not in whois and whois.get("registrar"):
        lines.append(c("1;33", "🏢 [Domain Registration (RDAP / WHOIS)]"))
        lines.append(f"  ├── Registrar:  {c('36', whois.get('registrar', 'Unknown'))}")
        date_parts = []
        if whois.get("created"):
            date_parts.append(f"Created: {whois['created'][:10]}")
        if whois.get("expires"):
            date_parts.append(f"Expires: {whois['expires'][:10]}")
        if date_parts:
            lines.append(f"  ├── Dates:      {' | '.join(date_parts)}")
        status_list = whois.get("status", [])
        if status_list:
            lines.append(f"  └── Status:     {', '.join(status_list[:3])}")
        lines.append("")

    # IP & Geolocation
    network = report.get("network", {})
    if network and "error" not in network and (network.get("asn") or network.get("country")):
        lines.append(c("1;32", "📍 [IP Infrastructure & Location]"))
        if network.get("asn") or network.get("org"):
            lines.append(f"  ├── ASN/Org:    {network.get('asn', '')} ({c('36', network.get('org', ''))})")
        loc_parts = [p for p in (network.get("city"), network.get("region"), network.get("country")) if p]
        if loc_parts:
            lines.append(f"  └── Location:   {', '.join(loc_parts)}")
        lines.append("")

    # Subdomains (Certificate Transparency)
    subs = report.get("subdomains", {})
    if subs and "error" not in subs and subs.get("total_found", 0) > 0:
        lines.append(c("1;36", "🔍 [Subdomains (Certificate Transparency)]"))
        count = subs.get("total_found", 0)
        sample = subs.get("subdomains", [])
        lines.append(f"  ├── Discovered: {c('32', f'{count} subdomains found via crt.sh')}")
        if sample:
            preview = ", ".join(sample[:6])
            suffix = f" (+{count - 6} more)" if count > 6 else ""
            lines.append(f"  └── Sample:     {preview}{suffix}")
        lines.append("")

    # Web
    web = report.get("web", {})
    lines.append(c("1;35", "🌍 [Web / HTTP]"))
    if "error" in web:
        err = web["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        lines.append(c("31", f"  └── Error:      {msg}"))
    else:
        status = web.get("status")
        status_color = "32" if status == 200 else "33"
        lines.append(f"  ├── Status:     {c(status_color, f'[{status} OK]' if status == 200 else f'[{status}]')}")
        lines.append(f"  ├── URL:        {web.get('url')}")
        if web.get("title"):
            lines.append(f"  ├── Title:      {web.get('title')}")
        if web.get("truncated"):
            lines.append(c("33", "  ├── Notice:     Body truncated at 256 KiB safety boundary"))
        meta = web.get("meta", {})
        if meta.get("description"):
            lines.append(f"  ├── Description:{meta['description']}")
        if meta.get("generator"):
            lines.append(f"  ├── Generator:  {c('35', meta['generator'])}")
        headers = web.get("headers", {})
        if headers.get("server"):
            lines.append(f"  ├── Server:     {headers['server']}")
        present = headers.get("present", [])
        missing = headers.get("missing", [])
        lines.append(
            f"  ├── Headers:    {c('32', f'{len(present)} present')}, {c('33', f'{len(missing)} missing')}"
        )
        if present:
            lines.append(f"  │   ├── {c('32', '[+]')} {', '.join(present)}")
        if missing:
            lines.append(f"  │   └── {c('31', '[-]')} {', '.join(missing)}")
        cookie_sec = headers.get("cookie_security")
        if cookie_sec:
            sec_flags = []
            for flag, key in (
                ("Secure", "has_secure"),
                ("HttpOnly", "has_httponly"),
                ("SameSite", "has_samesite"),
            ):
                val = c("32", "✔ Yes") if cookie_sec.get(key) else c("31", "✖ No")
                sec_flags.append(f"{flag}: {val}")
            lines.append(f"  └── Cookies:    {' │ '.join(sec_flags)}")
        else:
            lines[-1] = lines[-1].replace("├──", "└──")
    lines.append("")

    # TLS
    tls = report.get("tls", {})
    lines.append(c("1;32", "🔒 [TLS Certificate]"))
    if "error" in tls:
        err = tls["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        lines.append(c("31", f"  └── Error:      {msg}"))
    else:
        subj = tls.get("subject", {}).get("commonName", "unknown")
        issuer = (
            tls.get("issuer", {}).get("commonName")
            or tls.get("issuer", {}).get("organizationName", "unknown")
        )
        lines.append(f"  ├── Subject:    {subj}")
        lines.append(f"  ├── Issuer:     {issuer}")
        if tls.get("protocol"):
            lines.append(f"  ├── Protocol:   {c('32', tls['protocol'])}")
        cipher = tls.get("cipher")
        if cipher:
            lines.append(f"  ├── Cipher:     {cipher.get('name')} ({cipher.get('bits')}-bit)")
        expires = tls.get("expires")
        days = tls.get("days_remaining")
        if expires:
            if tls.get("is_expired"):
                exp_str = c("31", f"{expires} (EXPIRED)")
            elif days is not None and days <= 30:
                exp_str = c("33", f"{expires} ({days} days remaining - EXPIRING SOON)")
            elif days is not None:
                exp_str = c("32", f"{expires} ({days} days remaining)")
            else:
                exp_str = expires
            lines.append(f"  ├── Expires:    {exp_str}")
        if tls.get("sha256"):
            lines.append(f"  ├── SHA-256:    {tls['sha256']}")
        if tls.get("dns_names"):
            names = tls["dns_names"]
            if len(names) <= 5:
                lines.append(f"  └── SANs:       {', '.join(names)}")
            else:
                lines.append(
                    f"  └── SANs:       {', '.join(names[:5])} (+{len(names) - 5} more)"
                )
    lines.append("")

    # Policy files
    files = report.get("files", {})
    lines.append(c("1;34", "📄 [Policy Files]"))
    sec_txt = files.get("security_txt", {})
    if "error" in sec_txt:
        lines.append(f"  ├── security.txt: Error ({sec_txt['error']})")
    elif sec_txt.get("found"):
        lines.append(f"  ├── security.txt: {c('32', '✔ Found')}")
        if sec_txt.get("contacts"):
            lines.append(f"  │   └── Contacts: {', '.join(sec_txt['contacts'])}")
        if sec_txt.get("expires"):
            lines.append(f"  │   └── Expires:  {sec_txt['expires']}")
    else:
        lines.append(
            f"  ├── security.txt: {c('33', '✖ Not found')} ({sec_txt.get('status', 'n/a')})"
        )

    rob_txt = files.get("robots_txt", {})
    if "error" in rob_txt:
        lines.append(f"  └── robots.txt:   Error ({rob_txt['error']})")
    elif rob_txt.get("found"):
        lines.append(f"  └── robots.txt:   {c('32', '✔ Found')}")
        if rob_txt.get("sitemaps"):
            lines.append(f"      └── Sitemaps: {', '.join(rob_txt['sitemaps'])}")
    else:
        lines.append(
            f"  └── robots.txt:   {c('33', '✖ Not found')} ({rob_txt.get('status', 'n/a')})"
        )

    lines.append(c("1;36", "└" + "─" * 62 + "┘"))
    return "\n".join(lines)


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    collector: Callable[..., dict[str, Any]] = collect_report,
) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        stderr.write("error: timeout must be positive\n")
        return 2
    try:
        try:
            report = collector(args.target, timeout=args.timeout)
        except TypeError:
            report = collector(args.target)
    except (DomainValidationError, OSError, ValueError) as exc:
        stderr.write(f"error: {exc}\n")
        return 2

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2, sort_keys=True)
                file.write("\n")
        except OSError as exc:
            stderr.write(f"error: failed to write output file: {exc}\n")
            return 2

    if args.summary:
        import os

        is_tty = hasattr(stdout, "isatty") and stdout.isatty()
        use_color = (
            is_tty and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
        )
        stdout.write(format_summary(report, use_color=use_color))
        stdout.write("\n")
    elif not args.output:
        json.dump(report, stdout, indent=2, sort_keys=True)
        stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
