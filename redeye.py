import asyncio
import argparse
import contextlib
import io
import sys
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

# Windows: Set stdout to UTF-8 for Unicode banner (cp1254 compatibility)
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError, ValueError):
        pass

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# Bound to the real stdout so the dashboard keeps drawing while scanner
# chatter (plain print calls) is captured with redirect_stdout.
console = Console(file=sys.stdout)

from utils.domain import normalize_target
from utils.ui import ScanDashboard, collect_findings, findings_report, render_banner, render_findings, render_header

# Importing our newly forged scanners!
from scanners.subdomain_scanner import SubdomainScanner
from scanners.waf_detector import WafDetector
from scanners.github_dorker import GithubDorker
from scanners.tech_analyzer import TechAnalyzer
from scanners.port_scanner import PortScanner
from scanners.ssl_analyzer import SSLAnalyzer
from scanners.dir_scanner import DirScanner
from scanners.dns_scanner import DnsScanner
from scanners.email_harvester import EmailHarvester
from scanners.archive_scanner import ArchiveScanner
from scanners.takeover_scanner import TakeoverScanner
from scanners.js_analyzer import JsAnalyzer
from scanners.sm_scanner import SmScanner
from scanners.backup_scanner import BackupScanner
from scanners.robots_scanner import RobotsScanner
from scanners.cloud_detector import CloudDetector
from scanners.breach_scanner import BreachScanner
from scanners.shodan_scanner import ShodanScanner
from scanners.header_analyzer import HeaderAnalyzer
from scanners.whois_scanner import WhoisScanner
from scanners.origin_scanner import OriginIPFinder
from scanners.jwt_scanner import JwtDecoder

VERSION = "1.7.0"

# --- THE CORE SCANNER DICTIONARY ---
ALL_SCANNERS = {
    "subdomain": SubdomainScanner,
    "waf": WafDetector,
    "github": GithubDorker,
    "tech": TechAnalyzer,
    "port": PortScanner,
    "ssl": SSLAnalyzer,
    "dir": DirScanner,
    "dns": DnsScanner,
    "email": EmailHarvester,
    "archive": ArchiveScanner,
    "takeover": TakeoverScanner,
    "js": JsAnalyzer,
    "sm": SmScanner,
    "backup": BackupScanner,
    "robots": RobotsScanner,
    "cloud": CloudDetector,
    "breach": BreachScanner,
    "shodan": ShodanScanner,
    "headers": HeaderAnalyzer,
    "whois": WhoisScanner,
    "origin": OriginIPFinder,
    "jwt": JwtDecoder,
}

# The terminal shows this many list items per section; the -o report gets all of them.
PREVIEW_LIMIT = 10

CRITICAL_MARKERS = ("CRITICAL", "VULNERABILITY", "VULNERABLE")


def _list_lines(items, full: bool, limit: int = PREVIEW_LIMIT, prefix: str = "  -> ") -> List[str]:
    items = list(items)
    shown = items if full else items[:limit]
    lines = [f"{prefix}{item}" for item in shown]
    if not full and len(items) > limit:
        lines.append(f"  ... and {len(items) - limit} more (full list in the -o report).")
    return lines


def format_result(result, full: bool = False) -> Tuple[str, List[str]]:
    """
    Turns a scanner result into (title, lines). With full=False long lists are
    trimmed for the terminal; full=True is used for the saved report.
    """
    name = type(result).__name__
    lines: List[str] = []
    add = lines.append
    more = lines.extend

    if name == "SubdomainResult":
        title = f"Source: {result.source}"
        add(f"Target: {result.target_domain}")
        add(f"Total Subdomains Found: {len(result.discovered_subdomains)}")
        more(_list_lines(result.discovered_subdomains, full))

    elif name == "WafResult":
        title = "Source: WAF Detector"
        add(f"Target: {result.target_domain}")
        add(f"Protected by WAF: {result.has_waf}")
        add(f"WAF Provider: {result.waf_name}")

    elif name == "GithubResult":
        title = "Source: GitHub Dorker"
        add(f"Target: {result.target_domain}")
        if result.skipped_reason:
            add(f"Skipped: {result.skipped_reason}")
        else:
            add(f"Potential Leaks Found: {result.leaks_found} (GitHub reports {result.total_hits} total hits)")
            if result.sample_urls:
                add("Leak URLs:")
                more(_list_lines(result.sample_urls, full))

    elif name == "TechResult":
        title = "Source: Tech Analyzer"
        add(f"Target: {result.target_domain}")
        add(f"Detected Stack: {', '.join(result.technologies) if result.technologies else 'Unknown'}")

    elif name == "PortResult":
        title = "Source: Port Scanner"
        add(f"Target: {result.target_domain}")
        add(f"Open Ports Found: {', '.join(map(str, result.open_ports)) if result.open_ports else 'None'}")

    elif name == "SSLResult":
        title = "Source: SSL/TLS Analyzer"
        add(f"Target: {result.target_domain}")
        add(f"Certificate Valid: {result.is_valid}")
        if result.is_valid:
            add(f"Issuer: {result.issuer}")
            soon = " [EXPIRING SOON]" if result.days_until_expiry <= 14 else ""
            add(f"Expires In: {result.days_until_expiry} days{soon}")
            add(f"Subject Alternative Names: {len(result.subject_alt_names)}")
            more(_list_lines(result.subject_alt_names, full))
        elif result.error:
            add(f"Reason: {result.error}")

    elif name == "DirResult":
        title = "Source: Directory Scanner"
        add(f"Target: {result.target_domain}")
        add(f"Discovered Paths: {len(result.found_directories)}")
        more(_list_lines(result.found_directories, full))

    elif name == "DnsResult":
        title = "Source: DNS Recon (Extended)"
        add(f"Target: {result.target_domain}")
        add(f"A Records: {', '.join(result.a_records) if result.a_records else 'None'}")
        add(f"NS Records: {', '.join(result.ns_records) if result.ns_records else 'None'}")
        add(f"MX Records: {', '.join(result.mx_records) if result.mx_records else 'None'}")
        if result.caa_records:
            add(f"CAA Records: {', '.join(result.caa_records)}")
        if not result.spf_checked:
            add("SPF Protected: Unknown (lookup failed)")
        else:
            add(f"SPF Protected: {'No — VULNERABLE' if result.is_spoofable else 'Yes'}")
        if not result.dmarc_checked:
            add("DMARC Policy: Unknown (lookup failed)")
        else:
            add(f"DMARC Policy: {'p=' + result.dmarc_policy if result.has_dmarc else 'MISSING — VULNERABLE'}")
        add(f"DKIM Detected: {'Yes (selector: ' + result.dkim_selector + ')' if result.has_dkim else 'Not found on common selectors'}")
        if result.zone_transfer_vulnerable:
            add("ZONE TRANSFER (AXFR): VULNERABLE — Full zone exposed!")
            more(_list_lines(result.zone_transfer_data, full))
        elif result.zone_transfer_checked:
            add("Zone Transfer (AXFR): Protected")
        else:
            add("Zone Transfer (AXFR): Unknown (check unavailable)")
        if result.vulnerabilities:
            add("Vulnerabilities:")
            more(f"  [!] {v}" for v in result.vulnerabilities)
        if result.info:
            add("Notes:")
            more(f"  [i] {i}" for i in result.info)

    elif name == "EmailResult":
        title = "Source: Email Harvester"
        add(f"Target: {result.target_domain}")
        add(f"Emails Harvested: {len(result.harvested_emails)}")
        more(_list_lines(result.harvested_emails, full))

    elif name == "ArchiveResult":
        title = "Source: Wayback Machine Archive"
        add(f"Target: {result.target_domain}")
        add(f"Historical URLs: {result.total_urls_found}")
        add(f"Juicy URLs Found: {len(result.interesting_urls)}")
        more(_list_lines(result.interesting_urls, full))

    elif name == "TakeoverResult":
        title = "Source: Subdomain Takeover"
        add(f"Target: {result.target_domain}")
        add(f"CNAME'd Subdomains Checked: {result.checked_cnames}")
        add(f"Status: {'VULNERABLE' if result.vulnerable_subdomains else 'Secure'}")
        more(_list_lines(result.vulnerable_subdomains, full))

    elif name == "JsResult":
        title = "Source: JavaScript Analyzer"
        add(f"Target: {result.target_domain}")
        add(f"JS Files Scanned: {result.js_files_scanned}")
        if result.secrets_found:
            add("Exposed Secrets & Endpoints:")
            for secret_type, items in result.secrets_found.items():
                add(f"  [{secret_type}]")
                more(_list_lines(items, full, prefix="   -> "))
        else:
            add("No hardcoded secrets or internal endpoints found.")

    elif name == "SmResult":
        title = "Source: Social Media & OSINT"
        add(f"Target: {result.target_domain}")
        if result.platform_mentions:
            add("Platform Mentions Found:")
            for platform, urls in result.platform_mentions.items():
                add(f"  [{platform}]")
                more(_list_lines(urls, full, prefix="   -> "))
        else:
            add("No platform mentions detected.")

    elif name == "BackupResult":
        title = "Source: Backup & Archive Hunter"
        add(f"Target: {result.target_domain}")
        if result.found_backups:
            add(f"CRITICAL - Exposed Files Found ({len(result.found_backups)}):")
            more(_list_lines(result.found_backups, full, limit=20, prefix="   -> "))
        else:
            add("No exposed backups or configuration files found.")

    elif name == "RobotsResult":
        title = "Source: Robots & Sitemap Scanner"
        add(f"Target: {result.target_domain}")
        add(f"Extracted Paths: {len(result.extracted_paths)}")
        if result.extracted_paths:
            more(_list_lines(result.extracted_paths, full))
        else:
            add("No paths found.")

    elif name == "CloudResult":
        title = "Source: Cloud Infrastructure & S3 Hunter"
        add(f"Target: {result.target_domain}")
        add(f"Primary Provider: {result.primary_provider}")
        add(f"Behind Cloudflare: {'Yes' if result.is_cloudflare else 'No'}")
        if result.s3_buckets_found:
            add("S3 Buckets Matching the Target's Name (verify ownership):")
            more(_list_lines(result.s3_buckets_found, full))
        else:
            add("S3 Buckets: None found.")

    elif name == "BreachResult":
        title = "Source: Breach & Leak Intelligence"
        add(f"Target: {result.target_domain}")
        if not result.lookup_ok:
            add(f"Lookup failed: {result.error or 'unknown error'} — breach status unknown.")
        elif result.total_leaks > 0:
            add(f"CRITICAL - Historical Breaches Found: {result.total_leaks}")
            more(_list_lines(result.breaches_found, full, prefix="   -> "))
        else:
            add("Clean: No public breaches recorded (Have I Been Pwned).")

    elif name == "ShodanResult":
        title = "Source: Shodan Intelligence"
        add(f"Target: {result.target_domain}")
        add(f"IP Address: {result.ip_address}")
        if result.organization != "Unknown":
            add(f"Organization: {result.organization}")
        if result.country != "Unknown":
            add(f"Country: {result.country} | ISP: {result.isp}")
        if result.asn != "Unknown":
            add(f"ASN: {result.asn}")
        if result.open_ports:
            add(f"Open Ports: {', '.join(map(str, result.open_ports))}")
        else:
            add("Open Ports: None detected by InternetDB")
        if result.vulns:
            vulns = result.vulns if full else result.vulns[:PREVIEW_LIMIT]
            add(f"CRITICAL - Known CVEs/Vulns: {', '.join(vulns)}")
        else:
            add("CVEs: None listed in Shodan InternetDB")
        if result.tags:
            add(f"Tags: {', '.join(result.tags)}")
        if result.hostnames:
            hostnames = result.hostnames if full else result.hostnames[:5]
            add(f"Hostnames: {', '.join(hostnames)}")

    elif name == "HeaderResult":
        title = "Source: HTTP Security Headers"
        if not result.reachable:
            add(f"Target: {result.target_domain}")
            add("Target unreachable — headers not analyzed.")
        else:
            add(f"Target: {result.url_scanned}")
            add(f"Security Grade: {result.grade} ({result.security_score}/100)")
            if result.missing_headers:
                add(f"Missing Headers ({len(result.missing_headers)}):")
                for hdr, meta in result.missing_headers.items():
                    add(f"  [MISSING/{meta['risk']}] {hdr} — {meta['desc']}")
            if result.misconfigured_headers:
                add(f"Misconfigured Headers ({len(result.misconfigured_headers)}):")
                for hdr, val in result.misconfigured_headers.items():
                    add(f"  [MISCFG] {hdr}: {val}")
            if result.info_leak_headers:
                add(f"Info Disclosure Headers ({len(result.info_leak_headers)}):")
                for hdr, val in result.info_leak_headers.items():
                    add(f"  [LEAK] {hdr}: {val}")

    elif name == "WhoisResult":
        title = "Source: WHOIS Intelligence"
        add(f"Target: {result.target_domain}")
        if not result.source:
            add("No WHOIS data — all sources failed.")
        else:
            add(f"Data Source: {result.source}")
            add(f"Registrar: {result.registrar}")
            add(f"Organization: {result.registrant_org}")
            add(f"Country: {result.registrant_country}")
            add(f"Created: {result.creation_date}")
            expiry = f"Expires: {result.expiry_date}"
            if result.is_expired:
                expiry += " [EXPIRED!]"
            elif result.is_expiring_soon:
                expiry += " [EXPIRING SOON — <30 days]"
            add(expiry)
            add(f"Updated: {result.updated_date}")
            add(f"DNSSEC: {result.dnssec}")
            add(f"Privacy Protected: {'Yes' if result.privacy_protected else 'No'}")
            if result.name_servers:
                add(f"Name Servers: {', '.join(result.name_servers if full else result.name_servers[:4])}")
            if result.status:
                add(f"Status: {', '.join(result.status if full else result.status[:3])}")

    elif name == "CdnBypassResult":
        title = "Source: Origin IP / CDN Bypass Finder"
        add(f"Target: {result.target_domain}")
        add(f"Main IP: {result.main_ip}")
        add(f"Behind CDN/WAF: {'Yes (' + result.cdn_indicator + ')' if result.behind_cdn else 'No'}")
        add(f"MX Host: {result.mx_hostname} -> {result.mx_ip}" + (" [Differs from main IP]" if result.mx_ip_differs else ""))
        if result.candidate_origin_ips:
            add(f"Candidate Origin IPs ({len(result.candidate_origin_ips)}):")
            more(_list_lines(result.candidate_origin_ips, full))
        else:
            add("Candidate Origin IPs: None found.")
        if result.cdn_edge_ips:
            add(f"Ignored CDN Edge IPs: {', '.join(result.cdn_edge_ips)}")
        if result.confirmed_origin_ip:
            add(f"CRITICAL - BYPASS CONFIRMED: {result.confirmed_origin_ip} ({result.confirmed_via})")

    elif name == "JwtResult":
        title = "Source: JWT Decoder & Vulnerability Analyzer"
        add(f"Target: {result.target_domain}")
        add(f"JS Files Scanned: {result.js_files_scanned}")
        add(f"JWTs Found: {result.tokens_found}")
        for token in result.decoded_tokens:
            add(f"  [{token['token_preview']}] alg={token['alg']}" + (", EXPIRED" if token['expired'] else ""))
            if token['sensitive_claims']:
                add(f"    Sensitive claims exposed: {', '.join(token['sensitive_claims'])}")
            if token.get('privilege_claims'):
                add(f"    Privilege claims (tamper targets): {', '.join(token['privilege_claims'])}")
        if result.vulnerabilities:
            add("Vulnerabilities:")
            more(f"  [!] {v}" for v in result.vulnerabilities)
        elif result.tokens_found > 0:
            add("No vulnerabilities flagged on discovered tokens.")

    else:
        title = f"Source: {name}"
        add(str(result))

    return title, lines


def render_panel(title: str, lines: List[str]) -> None:
    body = "\n".join(lines)
    critical = any(marker in body for marker in CRITICAL_MARKERS)
    # Text(...) instead of a markup string: scan data like '/search[/q]' or
    # '[eyJ...]' must be printed literally, never parsed as Rich markup.
    console.print(Panel(
        Text(body),
        title=Text(title, style="bold red" if critical else "bold cyan"),
        border_style="red" if critical else "blue",
        expand=False,
    ))


async def run_engine(target: str, stealth: bool, output_file: Optional[str], selected_modules: Optional[str], proxy: Optional[str], delay: float, wordlist: Optional[str], github_token: Optional[str] = None, shodan_key: Optional[str] = None, verbose: bool = False):

    # --- LOGIC: Module Selection & Initialization ---
    notices: List[Text] = []
    explicit = bool(selected_modules)
    if explicit:
        module_names = []
        for m in (m.strip().lower() for m in selected_modules.split(",")):
            if not m:
                continue
            if m in ALL_SCANNERS:
                if m not in module_names:
                    module_names.append(m)
            else:
                notices.append(Text(f"⚠ Unknown module '{m}' skipped.", style="red"))
    else:
        module_names = list(ALL_SCANNERS)

    if proxy:
        direct = [m for m in module_names if ALL_SCANNERS[m].DIRECT_CONTACT]
        if direct and explicit:
            notices.append(Text(f"⚠ Modules {', '.join(direct)} open raw sockets to the target and BYPASS the proxy.", style="yellow"))
        elif direct:
            module_names = [m for m in module_names if m not in direct]
            notices.append(Text(f"⚠ Skipping {', '.join(direct)} in proxy mode (raw sockets cannot use an HTTP proxy). Request them with -m to run anyway.", style="yellow"))

    console.print(render_header(VERSION, target, len(module_names), stealth, proxy, delay, output_file))
    for notice in notices:
        console.print(notice)

    active_scanners = [
        (m, ALL_SCANNERS[m](target, stealth=stealth, proxy=proxy, delay=delay, wordlist=wordlist,
                            github_token=github_token, shodan_key=shodan_key))
        for m in module_names
    ]

    if not active_scanners:
        console.print("[bold red]✖ No valid modules selected. Aborting scan.[/bold red]")
        return

    # Executing the asynchronous tasks
    # return_exceptions=True: One failing scanner won't abort the others
    dashboard = ScanDashboard(module_names)
    tasks = [dashboard.track(m, scanner.execute()) for m, scanner in active_scanners]

    # Scanners narrate with print(); keep that out of the dashboard unless -v.
    scanner_log = io.StringIO()
    quiet = contextlib.nullcontext() if verbose else contextlib.redirect_stdout(scanner_log)
    console.print()
    with quiet, Live(dashboard, console=console, refresh_per_second=10, transient=True, redirect_stdout=verbose):
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            dashboard.stop()

    findings = collect_findings(module_names, results)

    full_report_text = f"RED EYE SCAN REPORT FOR: {target}\n"
    full_report_text += "=" * 50 + "\n\n"
    full_report_text += findings_report(findings) + "\n"

    # --- RESULT PROCESSING ---
    try:
        for (module, _), result in zip(active_scanners, results):
            # Catch and log scanner exceptions without breaking the flow
            if isinstance(result, BaseException):
                title = f"Scanner Error: {module}"
                preview = full = [f"{type(result).__name__}: {result}"]
            else:
                title, preview = format_result(result)
                _, full = format_result(result, full=True)

            full_report_text += f"--- [ {title} ] ---\n" + "\n".join(full) + "\n" + "-" * 40 + "\n"
            try:
                render_panel(title, preview)
            except Exception as e:
                # A rendering glitch must never cost the user the saved report
                console.print(Text(f"⚠ Could not render {module} result: {e}", style="red"))

        console.rule(Text("SCAN SUMMARY", style="bold"), style="red")
        console.print(dashboard)
        console.print()
        console.print(render_findings(findings))
    finally:
        if output_file:
            log = scanner_log.getvalue()
            if log:
                full_report_text += "\nSCANNER LOG\n" + "=" * 50 + "\n" + log
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(full_report_text)
                console.print(Text(f"✔ Full scan report saved to: {output_file}", style="bold green"))
            except Exception as e:
                console.print(Text(f"✖ Could not save report. Error: {e}", style="bold red"))

    elapsed = dashboard.finished - dashboard.started
    console.print(Text(f"✔ {len(active_scanners)} module(s) finished in {elapsed:.2f}s.", style="bold green"))


def validate_proxy(proxy: str) -> str:
    parts = urlsplit(proxy)
    if parts.scheme in ("socks4", "socks5", "socks5h"):
        raise ValueError("SOCKS proxies are not supported by aiohttp. Use an HTTP proxy (e.g. Burp on http://127.0.0.1:8080, or Tor through an HTTP bridge such as Privoxy).")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("proxy must look like http://host:port")
    return proxy


def main():

    if len(sys.argv) == 1 or any(a in ("-h", "--help") for a in sys.argv[1:]):
        console.print(render_banner(VERSION))

    parser = argparse.ArgumentParser(
        description="Red Eye - Advanced OSINT & Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )

    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument("-t", "--target", help="Single target domain or URL (e.g., target.com, https://target.com, target.com:8443)", required=True)

    scan_group = parser.add_argument_group("Scan Configuration")
    scan_group.add_argument("-m", "--modules", help=f"Comma-separated list of modules ({', '.join(ALL_SCANNERS)}).")
    scan_group.add_argument("-w", "--wordlist", default=None, help="Wordlist name without .txt (e.g., 'common' or 'dir')")
    scan_group.add_argument("-g", "--github-token", default=None, help="GitHub Personal Access Token (required by the github module)")
    scan_group.add_argument("--shodan-key", default=None, help="Shodan API key for full host data (or set SHODAN_API_KEY)")

    perf_group = parser.add_argument_group("Performance & Stealth")
    perf_group.add_argument("-q", "--quiet", action="store_true", help="Stealth mode: Slower requests")
    perf_group.add_argument("-x", "--proxy", help="HTTP/S proxy URL (e.g., http://127.0.0.1:8080)")
    perf_group.add_argument("-d", "--delay", type=float, default=0.0, help="Delay between requests in seconds")

    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument("-o", "--output", help="Save the results to a text file")
    out_group.add_argument("-v", "--verbose", action="store_true", help="Show live scanner logs above the dashboard")

    args = parser.parse_args()

    # Auto-clean the target: 'https://Example.com/path?x=1' -> 'example.com'
    try:
        clean_target = normalize_target(args.target)
        proxy = validate_proxy(args.proxy) if args.proxy else None
        if args.delay < 0:
            raise ValueError("delay cannot be negative")
    except ValueError as e:
        console.print(Text(f"[!] Invalid argument: {e}", style="bold red"))
        sys.exit(2)

    try:
        asyncio.run(run_engine(
            clean_target,
            args.quiet,
            args.output,
            args.modules,
            proxy,
            args.delay,
            args.wordlist,
            args.github_token,
            args.shodan_key,
            args.verbose,
        ))
    except KeyboardInterrupt:
        console.print("\n[bold red]✖ Engine aborted by user. Exiting cleanly...[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
