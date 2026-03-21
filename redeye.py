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

init(autoreset=True)  


async def run_engine(target: str, deep_scan: bool, stealth: bool, output_file: str, selected_modules: str, proxy: str, delay: float, wordlist: str):
    
    print(Style.RESET_ALL + f"[*] Target locked: {Fore.CYAN}{target}{Style.RESET_ALL}")
    
    if stealth:
        print(Fore.YELLOW + "[!] STEALTH MODE ENGAGED (-q): Requests will be slower.")
    if deep_scan:
        print(Fore.YELLOW + "[!] DEEP SCAN ENGAGED (-v): Enhanced wordlists & checks activated.")
    if proxy:
        print(Fore.MAGENTA + f"[!] PROXY ENGAGED (-x): Routing all traffic through {proxy}")

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
        "js": JsAnalyzer
    }

    active_scanners = []

    # --- LOGIC: Module Selection & Initialization ---
    if selected_modules:
        mods = [m.strip().lower() for m in selected_modules.split(",")]
        for m in mods:
            if m in all_available_scanners:
                
                active_scanners.append(all_available_scanners[m](target, deep_scan, stealth, proxy, delay, wordlist))
            else:
                print(Fore.RED + f"[!] Warning: Unknown module '{m}' skipped.")
    else:
        for scanner_class in all_available_scanners.values():
            
            active_scanners.append(scanner_class(target, deep_scan, stealth, proxy, delay, wordlist))

    if not active_scanners:
        print(Fore.RED + "[!] No valid modules selected. Aborting scan.")
        return

    print(f"[*] Firing {len(active_scanners)} scanner(s) simultaneously...\n")
    
    # Executing the asynchronous tasks
    # return_exceptions=True: One failing scanner won't abort the others
    tasks = [scanner.execute() for scanner in active_scanners]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    print("\n[+] All scanners reported back. Processing results...\n")
    
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
            block += f"--- [ Source: DNS Recon ] ---\n"
            block += f"Target: {result.target_domain}\n"
            if result.is_spoofable:
                block += f"VULNERABILITY: Missing SPF! Domain is vulnerable to Spoofing.\n"
            else:
                block += f"Security: SPF Record is present.\n"
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

        print(block, end="")
        full_report_text += block

    elapsed = time.time() - start_time
    print(f"\n[+] Scan operations completed successfully in {elapsed:.2f} seconds.")

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(full_report_text)
            print(Fore.GREEN + f"[+] Success! Full scan report saved to: {output_file}")
        except Exception as e:
            print(Fore.RED + f"[!] Could not save report. Error: {str(e)}")

def main():
   
    print(Fore.RED + Style.BRIGHT + f"""
          
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
                    Version: 1.1.0
          """ + Style.RESET_ALL)

    parser = argparse.ArgumentParser(
        description="Red Eye - Advanced OSINT & Reconnaissance Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument("-t", "--target", help="Single target domain (e.g., target.com)", required=True)

    scan_group = parser.add_argument_group("Scan Configuration")
    scan_group.add_argument("-m", "--modules", help="Comma-separated list of modules (e.g., subdomain, waf, github, tech, port, ssl, dir, dns, email, archive, takeover, js).")
    
    scan_group.add_argument("-w", "--wordlist", default=None, help="Wordlist name without .txt (e.g., 'common' or 'dir')")

    perf_group = parser.add_argument_group("Performance & Stealth")
    perf_group.add_argument("-q", "--quiet", action="store_true", help="Stealth mode: Slower requests")
    perf_group.add_argument("-v", "--verbose", action="store_true", help="Deep scan mode")
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
            args.verbose,
            args.quiet,
            args.output,
            args.modules,
            args.proxy,
            args.delay,
            args.wordlist 
        ))
    except KeyboardInterrupt:
        print("\n[!] Engine aborted by user. Exiting cleanly...")
        sys.exit(1)

if __name__ == "__main__":
    main()
