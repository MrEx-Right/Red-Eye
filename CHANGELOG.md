# Changelog

All notable changes to the **Red Eye** project will be documented in this file.

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
