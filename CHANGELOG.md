# Changelog

All notable changes to the **Red Eye** project will be documented in this file.

## [v1.0.2] - 2026-03-18
### ⚙️ Core Stability & Intelligence Tuning

- **Targeted Email Harvester (Smart Filter):** Overhauled the junk filtering logic. Introduced a Target Override feature that natively protects target-specific emails from being discarded. Whitelisted legitimate third-party developer services (e.g., Sentry, Wixpress) to prevent false negatives during deep intel gathering.
- **Dynamic Directory Fuzzer (Pathing Fix):** Hardened execution context reliability. Replaced fragile relative pathing with absolute path resolution. The fuzzer now flawlessly locates and loads custom wordlists regardless of the terminal's working directory or cronjob environment.
- **Tech Stack Analyzer (Thread Safety):** Resolved a critical asynchronous race condition. Eliminated global socket timeout modifications that previously caused thread collisions across the entire scanner suite. The module now relies exclusively on safe, isolated `asyncio.wait_for` mechanics for flawless multi-threading.
- **High-Speed Port Fuzzer (Concurrency Tuning):** Tactically tuned the asynchronous concurrency limit, reducing the active semaphore from 1000 down to 500. This optimization prevents localized network saturation and minimizes packet drops, significantly increasing the accuracy of open-port detection against strict stateful firewalls.

## [v1.0.1] - 2026-03-13
### ⚡ Precision Intelligence & Tactical Evasion Update

- **Subdomain Takeover Sniper (Overhaul):** Deprecated superficial HTTP checks for the takeover module. Integrated direct signature-based error matching for **10+ major cloud providers** (AWS S3, GitHub Pages, Heroku, Azure, etc.) to definitively identify unclaimed CNAME records and potential takeover vectors.
- **GitHub Intelligence Engine (Rate-Limit Evasion):** Added a dynamic evasion mechanism to bypass strict API rate limits. The engine now reads `Retry-After` and `X-RateLimit-Reset` headers to tactically enter sleep mode instead of crashing. Maximized data extraction by implementing `per_page=100` pagination.
- **Dynamic Directory Fuzzer (Protocol Upgrade):** Transitioned the fuzzer to enforce **HTTPS** by default for modern target compatibility. Mandated URL encoding (`urllib.parse.quote`) to prevent custom wordlist payload crashes. Introduced a Dynamic Concurrency Engine (150/20 threads) that automatically shifts gears between speed and stealth modes to prevent target DoS.
- **DNS Architecture Analysis (Precision Patch):** Fixed a critical API index-shifting bug that misparsed MX record priorities and exchange servers. Purged residual quotation marks from TXT/SPF records to ensure pristine, enterprise-grade reporting output.
  
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
