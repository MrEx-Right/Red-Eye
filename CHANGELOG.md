# Changelog

All notable changes to the **Red Eye** project will be documented in this file.

## [v1.0.1] - 2026-03-13
### 🎯 Tactical Optimization & Precision Sniper Update

- **Signature-Based Takeover Sniper (Overhauled):** The `takeover_scanner.py` module has been completely rewritten. Replaced superficial checks with hardcoded error signature matching for over 10 major cloud providers (AWS S3, GitHub Pages, Heroku, Azure, etc.) to actively detect Dangling DNS and Subdomain Takeover vulnerabilities.
- **GitHub Intelligence Engine (Rate-Limit Evasion):** Overhauled `github_dorker.py` to gracefully handle unauthenticated API limits. The engine now reads `Retry-After` and `X-RateLimit-Reset` headers for dynamic shadow-sleeping. Maximized loot extraction by implementing `per_page=100` pagination.
- **Dynamic Directory Fuzzer (Safe Payload & HTTPS):** Upgraded `dir_scanner.py` to enforce `https://` by default for modern targets. Implemented strict URL encoding (`urllib.parse.quote`) to safely process special characters in wordlists. Added a dynamic concurrency gearbox (Semaphore 150 for minigun, 20 for stealth/delay) to prevent accidental target DOS.
- **DNS Recon Logic (Accuracy Patch):** Fixed a critical index shifting bug in `dns_scanner.py` where MX record priorities and exchange servers were parsed incorrectly. Additionally, implemented a cleaner string sanitization to strip residual double quotes from TXT/SPF records for pristine reporting.

## [1.0.0] - Initial Release (Ghost Protocol Edition)

### 🚀 Added (The Arsenal)
- **Asynchronous Core Engine**: Built heavily on `asyncio` and `aiohttp` for blazing fast, concurrent reconnaissance.
- **11 Heavy-Duty Modules**: 
  - `SubdomainScanner` (crt.sh integration)
  - `WafDetector` (Asynchronous Wafw00f wrapper)
  - `GithubDorker` (Token-authenticated secret hunting)
  - `TechAnalyzer` (BuiltWith stack fingerprinting)
  - `PortScanner` (Deep scan capabilities up to 65k ports)
  - `SSLAnalyzer` (Certificate extraction)
  - `DirScanner` (Concurrent directory brute-forcing)
  - `DnsScanner` (Spoofing & SPF vulnerability checks)
  - `EmailHarvester` (Surface-level scraping)
  - `ArchiveScanner` (Wayback Machine historical URL extraction)
  - `TakeoverScanner` (Dangling DNS detection)
- **Ghost Mode (`-q`) & Tactical Delay (`--delay`)**: Intelligent request throttling, sleep intervals, and random jittering to bypass strict WAFs without burning your IP.
- **Custom Wordlist Loader (`-w`)**: Dynamically load massive `.txt` wordlists into the `DirScanner`. Includes an optimized built-in fallback list.
- **Global Proxy Routing (`-x`)**: Funnel all HTTP/S traffic through Tor, Burp Suite, or any custom proxy.
- **Smart Input Parsing**: Automatically sanitizes target inputs (strips `http://` and `https://` to prevent DNS/Port scanner resolution crashes).
- **Dynamic User-Agent Rotation**: Every HTTP request sent by the `AsyncClient` uses a randomized, modern User-Agent to avoid basic fingerprinting traps.
- **Aggressive Timeouts**: Adjusted internal connection timeouts down to 5 seconds to prevent the engine from stalling on dead endpoints.
- **Unified Reporting**: Clean, structured terminal output blocks for each module with the ability to export the full report to a text file (`-o`).
- **Kaslı Terminal Logosu**: Custom ASCII art banner integrated directly into the help (`-h`) menu and engine startup.
