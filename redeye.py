import asyncio
import argparse
import sys
import time
import io

# Windows: Set stdout to UTF-8 for Unicode banner (cp1254 compatibility)
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

from colorama import init, Fore, Style
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout

console = Console()

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
init(autoreset=True)


async def run_engine(target: str, stealth: bool, output_file: str, selected_modules: str, proxy: str, delay: float, wordlist: str):
    
    console.rule(f"[bold cyan]Target Locked: {target}[/bold cyan]", align="left")
    
    if stealth:
        console.print("[yellow][!] STEALTH MODE ENGAGED (-q): Requests will be slower.[/yellow]")
    if proxy:
        console.print(f"[magenta][!] PROXY ENGAGED (-x): Routing all traffic through {proxy}[/magenta]")

    start_time = time.time()

    # --- THE CORE SCANNER DICTIONARY ---
    # Defined at the start of engine to prevent UnboundLocalError
    all_available_scanners = {
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

    active_scanners = []

    # --- LOGIC: Module Selection & Initialization ---
    if selected_modules:
        mods = [m.strip().lower() for m in selected_modules.split(",")]
        for m in mods:
            if m in all_available_scanners:
                active_scanners.append(all_available_scanners[m](target, stealth, proxy, delay, wordlist))
            else:
                print(Fore.RED + f"[!] Warning: Unknown module '{m}' skipped.")
    else:
        for scanner_class in all_available_scanners.values():
            
            active_scanners.append(scanner_class(target, stealth, proxy, delay, wordlist))

    if not active_scanners:
        console.print("[bold red][!] No valid modules selected. Aborting scan.[/bold red]")
        return

    # Executing the asynchronous tasks
    # return_exceptions=True: One failing scanner won't abort the others
    tasks = [scanner.execute() for scanner in active_scanners]
    
    with console.status(f"[bold green]Firing {len(active_scanners)} scanner(s) simultaneously...[/bold green]", spinner="bouncingBar"):
        results = await asyncio.gather(*tasks, return_exceptions=True)

    console.print("\n[bold green][+] All scanners reported back. Processing results...[/bold green]\n")
    
    full_report_text = f"RED EYE SCAN REPORT FOR: {target}\n"
    full_report_text += "=" * 50 + "\n\n"
    
    # --- RESULT PROCESSING ---
    for result in results:
        # Catch and log scanner exceptions without breaking the flow
        if isinstance(result, Exception):
            print(Fore.RED + f"--- [ Scanner Error ] ---\n{type(result).__name__}: {result}\n" + "-" * 40 + "\n")
            full_report_text += f"--- [ Scanner Error ] ---\n{type(result).__name__}: {result}\n" + "-" * 40 + "\n"
            continue

        block = "" 
        name = type(result).__name__
        
        if name == "SubdomainResult":
            block += f"--- [ Source: {result.source} ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Total Subdomains Found: {len(result.discovered_subdomains)}\n"
            if result.discovered_subdomains:
                block += "First 5 subdomains (for preview):\n"
                for sub in result.discovered_subdomains[:5]:
                    block += f"  -> {sub}\n"
            block += "-" * 40 + "\n"

        elif name == "WafResult":
            block += f"--- [ Source: WAF Detector ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Protected by WAF: {result.has_waf}\n"
            block += f"WAF Provider: {result.waf_name}\n"
            block += "-" * 40 + "\n"

        elif name == "GithubResult":
            block += f"--- [ Source: GitHub Dorker ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Potential Leaks Found: {result.leaks_found}\n"
            if result.leaks_found > 0:
                block += "Sample Leak URLs:\n"
                for url in result.sample_urls[:3]:
                    block += f"  -> {url}\n"
            block += "-" * 40 + "\n"

        elif name == "TechResult":
            block += f"--- [ Source: Tech Analyzer ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Detected Stack: {', '.join(result.technologies) if result.technologies else 'Unknown'}\n"
            block += "-" * 40 + "\n"

        elif name == "PortResult":
            block += f"--- [ Source: Port Scanner ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Open Ports Found: {', '.join(map(str, result.open_ports)) if result.open_ports else 'None'}\n"
            block += "-" * 40 + "\n"

        elif name == "SSLResult":
            block += f"--- [ Source: SSL/TLS Analyzer ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Certificate Valid: {result.is_valid}\n"
            if result.is_valid:
                block += f"Issuer: {result.issuer}\n"
                block += f"Expires In: {result.days_until_expiry} days\n"
            block += "-" * 40 + "\n"
        
        elif name == "DirResult":
            block += f"--- [ Source: Directory Scanner ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Discovered Paths: {len(result.found_directories)}\n"
            if result.found_directories:
                for directory in result.found_directories[:10]:
                    block += f"  -> {directory}\n"
            block += "-" * 40 + "\n"
        
        elif name == "DnsResult":
            block += f"--- [ Source: DNS Recon (Extended) ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"A Records: {', '.join(result.a_records) if result.a_records else 'None'}\n"
            block += f"NS Records: {', '.join(result.ns_records) if result.ns_records else 'None'}\n"
            block += f"MX Records: {len(result.mx_records)} found\n"
            block += f"SPF Protected: {'No — VULNERABLE' if result.is_spoofable else 'Yes'}\n"
            block += f"DMARC Policy: {'p=' + result.dmarc_policy if result.has_dmarc else 'MISSING — VULNERABLE'}\n"
            block += f"DKIM Detected: {'Yes (selector: ' + result.dkim_selector + ')' if result.has_dkim else 'Not Found'}\n"
            if result.zone_transfer_vulnerable:
                block += f"ZONE TRANSFER (AXFR): VULNERABLE — Full zone exposed!\n"
            else:
                block += f"Zone Transfer (AXFR): Protected\n"
            if result.vulnerabilities:
                block += "Vulnerabilities:\n"
                for v in result.vulnerabilities:
                    block += f"  [!] {v}\n"
            if result.info:
                for i in result.info:
                    block += f"  [i] {i}\n"
            block += "-" * 40 + "\n"

        elif name == "EmailResult":
            block += f"--- [ Source: Email Harvester ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Emails Harvested: {len(result.harvested_emails)}\n"
            block += "-" * 40 + "\n"
        
        elif name == "ArchiveResult":
            block += f"--- [ Source: Wayback Machine Archive ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Juicy URLs Found: {len(result.interesting_urls)}\n"
            block += "-" * 40 + "\n"

        elif name == "TakeoverResult":
            block += f"--- [ Source: Subdomain Takeover ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Status: {'VULNERABLE' if result.vulnerable_subdomains else 'Secure'}\n"
            block += "-" * 40 + "\n"

        elif name == "JsResult":
            block += f"--- [ Source: JavaScript Analyzer ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"JS Files Scanned: {result.js_files_scanned}\n"
            if result.secrets_found:
                block += "Exposed Secrets & Endpoints:\n"
                for secret_type, items in result.secrets_found.items():
                    block += f"  [{secret_type}]\n"
                    
                    for item in items:
                        block += f"   -> {item}\n"
            else:
                block += "No hardcoded secrets or internal endpoints found.\n"
            block += "-" * 40 + "\n"
        
        elif name == "SmResult":
            block += f"--- [ Source: Social Media & OSINT ] ---\n"
            block += f"Target: {result.target_domain}\n"
            if result.platform_mentions:
                block += "Platform Mentions Found:\n"
                for platform, urls in result.platform_mentions.items():
                    block += f"  [{platform}]\n"
                    for url in urls:
                        block += f"   -> {url}\n"
            else:
                block += "No platform mentions detected.\n"
            block += "-" * 40 + "\n"

        elif name == "BackupResult":
            block += f"--- [ Source: Backup & Archive Hunter ] ---\n"
            block += f"Target: {result.target_domain}\n"
            if result.found_backups:
                block += f"CRITICAL - Exposed Files Found ({len(result.found_backups)}):\n"
                for file_path in result.found_backups:
                    block += f"   -> {file_path}\n"
            else:
                block += "No exposed backups or configuration files found.\n"
            block += "-" * 40 + "\n"

        elif name == "RobotsResult":
            block += f"--- [ Source: Robots & Sitemap Scanner ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Extracted Paths: {len(result.extracted_paths)}\n"
            if result.extracted_paths:
                # Ekrana çok kusmasın diye ilk 10 tanesini gösteriyoruz
                for path in result.extracted_paths[:10]:
                    block += f"  -> {path}\n"
                if len(result.extracted_paths) > 10:
                    block += f"  ... and {len(result.extracted_paths) - 10} more.\n"
            else:
                block += "No paths found.\n"
            block += "-" * 40 + "\n"

        elif name == "CloudResult":
            block += f"--- [ Source: Cloud Infrastructure & S3 Hunter ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Primary Provider: {result.primary_provider}\n"
            block += f"Behind Cloudflare: {'Yes' if result.is_cloudflare else 'No'}\n"
            
            if result.s3_buckets_found:
                block += "Exposed S3 Buckets:\n"
                for bucket in result.s3_buckets_found:
                    block += f"  -> {bucket}\n"
            else:
                block += "S3 Buckets: None found.\n"
            block += "-" * 40 + "\n"
        
        elif name == "BreachResult":
            block += f"--- [ Source: Breach & Leak Intelligence ] ---\n"
            block += f"Target: {result.target_domain}\n"
            if result.total_leaks > 0:
                block += f"CRITICAL - Historical Breaches Found: {result.total_leaks}\n"
                for breach in result.breaches_found:
                    block += f"   -> {breach}\n"
            else:
                block += "Clean: No public breaches or leaks detected.\n"
            block += "-" * 40 + "\n"

        elif name == "ShodanResult":
            block += f"--- [ Source: Shodan Intelligence ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"IP Address: {result.ip_address}\n"
            if result.organization != "Unknown":
                block += f"Organization: {result.organization}\n"
            if result.country != "Unknown":
                block += f"Country: {result.country} | ISP: {result.isp}\n"
            if result.asn != "Unknown":
                block += f"ASN: {result.asn}\n"
            if result.open_ports:
                block += f"Open Ports: {', '.join(map(str, result.open_ports))}\n"
            else:
                block += "Open Ports: None detected by InternetDB\n"
            if result.vulns:
                block += f"CRITICAL - Known CVEs/Vulns: {', '.join(result.vulns[:10])}\n"
            else:
                block += "CVEs: None listed in Shodan InternetDB\n"
            if result.tags:
                block += f"Tags: {', '.join(result.tags)}\n"
            if result.hostnames:
                block += f"Hostnames: {', '.join(result.hostnames[:5])}\n"
            block += "-" * 40 + "\n"

        elif name == "HeaderResult":
            grade_color = "A" if result.grade.startswith("A") else "B" if result.grade == "B" else "D"
            block += f"--- [ Source: HTTP Security Headers ] ---\n"
            block += f"Target: {result.url_scanned}\n"
            block += f"Security Grade: {result.grade} ({result.security_score}/100)\n"
            if result.missing_headers:
                block += f"Missing Headers ({len(result.missing_headers)}):\n"
                for hdr, meta in result.missing_headers.items():
                    block += f"  [MISSING/{meta['risk']}] {hdr} — {meta['desc']}\n"
            if result.misconfigured_headers:
                block += f"Misconfigured Headers ({len(result.misconfigured_headers)}):\n"
                for hdr, val in result.misconfigured_headers.items():
                    block += f"  [MISCFG] {hdr}: {val}\n"
            if result.info_leak_headers:
                block += f"Info Disclosure Headers ({len(result.info_leak_headers)}):\n"
                for hdr, val in result.info_leak_headers.items():
                    block += f"  [LEAK] {hdr}: {val}\n"
            block += "-" * 40 + "\n"

        elif name == "WhoisResult":
            block += f"--- [ Source: WHOIS Intelligence ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Registrar: {result.registrar}\n"
            block += f"Organization: {result.registrant_org}\n"
            block += f"Country: {result.registrant_country}\n"
            block += f"Created: {result.creation_date}\n"
            block += f"Expires: {result.expiry_date}"
            if result.is_expired:
                block += " [EXPIRED!]\n"
            elif result.is_expiring_soon:
                block += " [EXPIRING SOON — <30 days]\n"
            else:
                block += "\n"
            block += f"Updated: {result.updated_date}\n"
            block += f"DNSSEC: {result.dnssec}\n"
            block += f"Privacy Protected: {'Yes' if result.privacy_protected else 'No'}\n"
            if result.name_servers:
                block += f"Name Servers: {', '.join(result.name_servers[:4])}\n"
            if result.status:
                block += f"Status: {', '.join(result.status[:3])}\n"
            block += "-" * 40 + "\n"

        elif name == "CdnBypassResult":
            block += f"--- [ Source: Origin IP / CDN Bypass Finder ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"Main IP: {result.main_ip}\n"
            block += f"Behind CDN/WAF: {'Yes (' + result.cdn_indicator + ')' if result.behind_cdn else 'No'}\n"
            block += f"MX Host: {result.mx_hostname} -> {result.mx_ip}"
            block += " [Differs from main IP]\n" if result.mx_ip_differs else "\n"
            if result.candidate_origin_ips:
                block += f"Candidate Origin IPs ({len(result.candidate_origin_ips)}):\n"
                for ip in result.candidate_origin_ips:
                    block += f"  -> {ip}\n"
            else:
                block += "Candidate Origin IPs: None found.\n"
            if result.confirmed_origin_ip:
                block += f"CRITICAL - BYPASS CONFIRMED: {result.confirmed_origin_ip} ({result.confirmed_via})\n"
            block += "-" * 40 + "\n"

        elif name == "JwtResult":
            block += f"--- [ Source: JWT Decoder & Vulnerability Analyzer ] ---\n"
            block += f"Target: {result.target_domain}\n"
            block += f"JS Files Scanned: {result.js_files_scanned}\n"
            block += f"JWTs Found: {result.tokens_found}\n"
            if result.decoded_tokens:
                for token in result.decoded_tokens:
                    block += f"  [{token['token_preview']}] alg={token['alg']}"
                    block += ", EXPIRED" if token['expired'] else ""
                    block += "\n"
                    if token['sensitive_claims']:
                        block += f"    Sensitive claims exposed: {', '.join(token['sensitive_claims'])}\n"
            if result.vulnerabilities:
                block += "Vulnerabilities:\n"
                for v in result.vulnerabilities:
                    block += f"  [!] {v}\n"
            elif result.tokens_found > 0:
                block += "No vulnerabilities flagged on discovered tokens.\n"
            block += "-" * 40 + "\n"

        # Use Rich Panel for beautiful UI
        clean_block = block.strip()
        if clean_block.endswith('-' * 40):
            clean_block = clean_block[:-40].strip()
            
        title = "Scanner Result"
        if clean_block.startswith("--- ["):
            lines = clean_block.split('\n')
            title = lines[0].replace("--- [", "").replace("] ---", "").strip()
            clean_block = '\n'.join(lines[1:]).strip()
            
        if "CRITICAL" in clean_block or "VULNERABILITY" in clean_block or "VULNERABLE" in clean_block:
            console.print(Panel(clean_block, title=f"[bold red]{title}[/bold red]", border_style="red", expand=False))
        else:
            console.print(Panel(clean_block, title=f"[bold cyan]{title}[/bold cyan]", border_style="blue", expand=False))
            
        full_report_text += block

    elapsed = time.time() - start_time
    console.print(f"\n[bold green][+] Scan operations completed successfully in {elapsed:.2f} seconds.[/bold green]")

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(full_report_text)
            console.print(f"[bold green][+] Success! Full scan report saved to: {output_file}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Could not save report. Error: {str(e)}[/bold red]")

def main():
   
    banner = """
          
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠱⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡄⢹⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⠴⣶⣶⣺⣿⣼⣄⠀⣟⣇⠀⢠⠀⠀⠀⣿⠀⠀⠀⡿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⢀⣤⡿⠚⣹⣧⣶⠟⣏⢛⢹⣿⣿⢉⠉⡏⡿⣿⢻⠶⣤⣰⣷⡇⠠⣰⣿⣇⢀⠆⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠇⠀⣸⡟⡋⢸⡆⢰⣿⣷⣄⣸⣏⣏⣹⣿⣿⡄⣸⣷⣿⣇⡟⢀⣴⣿⡟⡿⢶⣿⡟⣿⣮⣀⣠⣞⠁⠀⠀⠀⢀⣰⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⣿⣠⣞⣽⣿⡿⢿⣷⣄⣿⣟⣧⣽⣿⣟⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⠟⣼⣿⣿⣷⡟⠿⢧⣄⡀⠀⢠⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠀⢱⡄⠀⣄⣿⣿⡉⠁⢻⣿⣥⡽⢿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣯⣿⣿⣯⣿⣿⣿⡿⡻⠿⣶⡾⠋⢉⣶⡿⠥⠄⣠⠞⠀⣀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠸⣆⠀⢹⣭⣿⣅⠘⣿⣾⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣻⡯⣪⣥⡶⠛⣻⣶⣿⢏⠀⣠⣟⡁⢠⠀⢈⡀⠀⢀⠀
⠀⠀⠀⠀⠀⠀⣼⠀⠘⣶⣾⠏⣿⣿⢿⣿⣿⣿⣿⡿⠟⢉⣽⣿⣿⣿⠿⠛⠉⠉⠁⠀⠀⠈⠉⠉⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⣷⣟⣩⣏⣹⠿⠁⣰⠃⢀⡜⠀
⠀⠀⠀⠀⠀⠀⢻⣥⡴⢋⣹⣿⣿⣽⣿⣿⣿⡿⠏⠀⣠⣿⣿⡿⠋⠀⠀⠀⠀⣀⣀⣤⣤⣄⣀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣟⣿⣶⡾⣷⣶⣾⡟⢉⣾⡇⠀
⠀⠀⠀⠀⠰⠂⣠⡿⣷⣾⣿⣷⣿⣿⣿⣿⠃⠀⠀⢰⣿⣿⠋⠀⠀⠀⢀⣶⣿⣿⣿⠿⠿⣿⣿⣿⣷⣄⠀⠀⠀⠈⢿⣿⣿⣻⢿⣿⣿⣿⣿⣤⣤⣾⣟⣻⣿⣿⣏⣴⡿⢋⣴⠛
⠀⠀⠀⠀⠀⣺⣏⣾⠟⣻⣿⣿⠇⣿⣿⡇⠀⠀⢀⣿⣿⡏⠀⠀⠀⢰⣿⣿⠟⠉⠀⠀⠀⠀⠉⠻⣿⣿⣷⡀⠀⠀⠀⢻⣿⣿⢣⡙⢿⣿⣿⣿⣿⣯⣿⣶⣾⡿⣟⣭⣶⡾⠋⠀
⠀⠠⢤⡆⣴⣳⣿⢿⣿⡿⠟⠁⠀⣿⣿⠁⠀⠀⠸⣿⣿⡇⠀⠀⠀⢸⣿⣿⣤⣤⣴⣶⣦⡀⠀⠀⠈⢿⣿⣷⠀⠀⠀⠘⣿⣿⡆⢻⠠⠟⠿⣿⣿⣿⣿⣟⡛⣻⣿⠟⠋⣀⢀⠀
⠀⠀⠀⣙⣿⣿⣿⣿⠋⣴⡄⠀⠀⣿⣿⡆⠀⠀⠀⢻⣿⣷⡀⠀⠀⠈⠻⠿⠿⠟⠛⣿⣿⣧⠀⠀⠀⢸⣿⣿⡄⠀⠀⠀⣿⣿⣇⡟⠀⠀⠀⢲⣿⣿⣿⣿⣿⣿⣶⣶⣾⡿⠟⠀
⠀⣀⣠⣿⣟⣷⡿⢁⡾⢸⡁⠀⠀⢻⣿⣷⡀⠀⠀⠈⢿⣿⣿⣤⣀⠀⠀⠀⠀⢀⣰⣿⣿⡏⠀⠀⠀⢸⣿⣿⠁⠀⠀⢠⣿⣿⡟⠀⠀⠀⢠⣿⢿⣢⡻⢿⠙⢿⣛⣏⠁⠀⠀⠀
⢠⣾⣿⠟⣽⡟⡇⠙⢿⢄⣇⠀⠀⠀⢿⣿⣷⡄⠀⠀⠀⠙⠿⣿⣿⣿⣷⣶⣿⣿⣿⡿⠋⠀⠀⠀⣠⣿⣿⡟⠀⠀⠀⣾⣿⠋⠀⠀⢀⢀⣿⡿⢷⣾⣿⣯⣄⣹⡿⠋⠀⠀⠀⠀
⠀⠉⠁⢰⣿⠁⣳⡅⠈⣦⡝⣤⡀⠀⠈⠻⣿⣿⣦⡀⠀⠀⠀⠈⠉⠛⠛⠛⠛⠋⠁⠀⠀⠀⢀⣴⣿⣿⠟⠀⠀⢀⣾⠟⠁⠀⠀⢠⣬⣿⣿⣿⣞⠇⢳⡌⢿⣿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⡿⢧⡀⠉⣩⣤⣧⣈⠙⠺⠶⣤⣄⡈⠻⣿⣿⣷⣦⣤⣀⡀⠀⠀⠀⠀⠀⣀⣠⣴⣾⣿⣿⠟⠁⠀⢀⣴⠟⠁⠀⢀⣤⣾⣿⣿⠿⣾⠷⣿⣆⡼⠓⣾⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠹⢦⣉⣉⣀⠤⡜⠉⠛⢶⣤⣄⣀⣉⡉⠛⠻⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠋⠁⣠⠴⠞⣉⣀⣀⣤⣶⢶⣻⣿⡵⣘⠢⠈⣦⠘⢿⠇⢰⡿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⠛⠛⠛⢧⣤⡴⠋⠀⠈⢻⡿⠾⢿⣷⣶⣤⣴⣆⣌⣭⣉⣩⣭⣉⠀⣄⡤⣄⢠⣤⣄⣠⣴⠾⣿⡿⣏⠘⠻⣧⡘⣿⡜⠶⠄⠈⢤⠞⢠⣿⠃⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣯⣭⣽⣳⢦⣉⠲⢤⣠⠏⠀⠀⡼⣱⠋⢹⣿⢻⠟⠛⡟⣿⠟⢻⠟⣟⢿⠻⣟⠛⢯⢻⣯⣆⠘⣿⡌⢳⣄⢻⣷⠈⠀⠀⢀⡤⠋⢠⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⠿⠉⠉⠻⢷⣌⠙⠲⣽⡃⠀⠀⢷⠇⠀⠸⠁⡞⠀⡀⠙⡟⠂⠀⡟⢿⣼⠀⠹⡇⠈⢧⣎⢿⣇⠸⠿⠀⠉⢮⠏⠃⢀⡴⠊⠀⣠⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⢦⡀⠉⠓⢦⣞⠀⠀⠀⠀⠁⠀⠀⠀⡇⠈⠳⡷⠀⡿⠴⠀⠘⠀⠸⠋⠻⣿⠀⠀⠁⠈⢈⡧⠞⠁⠀⠀⠜⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠉⠓⠦⣄⣀⠀⠀⠀⠁⠀⠀⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⡿⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠓⠲⠤⢤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    RED EYE - Advanced OSINT & Reconnaissance Framework
                    Version: 1.6.0
          """
    console.print(Text(banner, style="bold red"))

    parser = argparse.ArgumentParser(
        description="Red Eye - Advanced OSINT & Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument("-t", "--target", help="Single target domain (e.g., target.com)", required=True)

    scan_group = parser.add_argument_group("Scan Configuration")
    scan_group.add_argument("-m", "--modules", help="Comma-separated list of modules (e.g., subdomain, waf, github, tech, port, ssl, dir, dns, email, archive, takeover, js, sm, backup, robots, cloud, breach, shodan, headers, whois, origin, jwt).")

    
    scan_group.add_argument("-w", "--wordlist", default=None, help="Wordlist name without .txt (e.g., 'common' or 'dir')")

    perf_group = parser.add_argument_group("Performance & Stealth")
    perf_group.add_argument("-q", "--quiet", action="store_true", help="Stealth mode: Slower requests")
    perf_group.add_argument("-x", "--proxy", help="HTTP/S proxy URL")
    parser.add_argument("-d", "--delay", type=float, default=0.0, help="Delay between requests in seconds")
    scan_group.add_argument("-g", "--github-token", default=None, help="GitHub Personal Access Token for authenticated scanning")

    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument("-o", "--output", help="Save the results to a text file")
    
    args = parser.parse_args()

    try:
        # MAGIC TRICK: Auto-clean the target! 
        # If user enters http://example.com, it becomes example.com
        import re
        clean_target = re.sub(r'^https?://', '', args.target).strip('/')
        
        asyncio.run(run_engine(
            clean_target,
            args.quiet,
            args.output,
            args.modules,
            args.proxy,
            args.delay,
            args.wordlist 
        ))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Engine aborted by user. Exiting cleanly...[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()