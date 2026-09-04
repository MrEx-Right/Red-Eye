# Changelog

All notable changes to the **Red Eye** project will be documented in this file.

## [1.6.0] - 2026-09-05

### Added
- **Origin IP / CDN Bypass Finder (`origin_scanner.py`)**: Purely passive module that hunts for a target's real origin server IP even when it's hidden behind a CDN/WAF (Cloudflare, Akamai, etc). Resolves the main A-record and fingerprints CDN presence via response headers, compares the MX exchange's IP against the main IP (mail servers are frequently left unproxied), and sweeps a set of common "leaky" subdomain prefixes (`direct`, `origin`, `ftp`, `cpanel`, `mail`, `dev`, `staging`, `api`, `portal`, `webmail`, `autodiscover`) concurrently for IPs that differ from the CDN's. Every candidate IP is then confirmed (not just guessed) via a direct TLS handshake that forces SNI to the real target domain — only a chain-validated match is reported as a confirmed bypass.
- **JWT Decoder & Vulnerability Analyzer (`jwt_scanner.py`)**: Crawls the target's frontend JS files and `Set-Cookie` headers for embedded JWTs, then statically decodes and audits each one: flags `alg: none` signature-bypass tokens, detects expired tokens via the `exp` claim, surfaces sensitive-looking claims (`role`, `admin`, `permissions`, `password`, `secret`, `ssn`, etc.) leaking in the payload, and attempts to crack HS256 signatures against a small built-in list of common weak secrets. No new dependency required — decoding and cracking use only the Python standard library (`base64`, `json`, `hmac`, `hashlib`).

### Changed
- **Main Engine (`redeye.py`)**: Registered `origin` and `jwt` modules to the scanner dictionary. Extended the rendering engine to output the new `CdnBypassResult` and `JwtResult` panels, flagging confirmed origin-IP bypasses and cracked/`alg:none` JWTs as CRITICAL findings. Updated banner version to `1.6.0`.
- **Report Models (`models/report.py`)**: Introduced `CdnBypassResult` and `JwtResult` dataclasses.

## [1.5.0] - 2026-07-05

### Added
- **Shodan Intelligence Scanner (`shodan_scanner.py`)**: Fetches target information using Shodan InternetDB (API Key not required). Extracts open ports, CVEs, CPE banners, hostnames, and tags. Falls back to ip-api.com for GeoIP enrichment. Deep scan mode utilizing full Shodan Host API is available via `SHODAN_API_KEY` or `--shodan-key`.
- **HTTP Security Header Analyzer (`header_analyzer.py`)**: Evaluates the security posture of the target based on OWASP Secure Headers Project. Checks 10 different security headers (HSTS, CSP, X-Frame-Options, etc.), detects 9 info-leak headers (`Server`, `X-Powered-By`), and assigns a security grade from A+ to F.
- **WHOIS Intelligence Scanner (`whois_scanner.py`)**: Performs WHOIS queries without requiring an API key (utilizes HackerTarget and RDAP.org fallback). Gathers Registrar, Organization, Country, Name Servers, DNSSEC status, and expiration dates. Added warnings for domain expiry within 30 days and expired domains.

### Changed
- **Extended DNS Reconnaissance (`dns_scanner.py`)**: Vastly improved DNS analysis.
  - Added DMARC policy evaluation (`none`, `quarantine`, `reject`).
  - Added DKIM selector probing (tests common selectors for cryptographic signing).
  - Added Zone Transfer (AXFR) vulnerability testing.
  - Added extraction for NS and CNAME records.
  - Improved structured output containing explicit "Vulnerabilities" and "Info" flags.
- **Main Engine (`redeye.py`)**: Registered `shodan`, `headers`, and `whois` modules to the scanner dictionary. Extended the rendering engine to beautifully output the results of the newly added scanners and the enhanced DNS data. Updated banner version to `1.4.0`.
- **Report Models (`models/report.py`)**: Introduced `ShodanResult`, `HeaderResult`, and `WhoisResult` dataclasses. Upgraded `DnsResult` to support new metrics (ns_records, cname_records, has_dmarc, dmarc_policy, has_dkim, dkim_selector, zone_transfer_vulnerable, zone_transfer_data, vulnerabilities, info).

### Removed
- **Deep Scan Flag (`-v` / `deep_scan`)**: Completely removed the verbose/deep scan operational mode across the entire framework.
  - **Reason**: The deep scan mode (e.g., scanning 65535 ports, forcing BuiltWith on both HTTP/HTTPS, probing excessive DKIM selectors) was causing frequent timeouts, severe rate-limiting, and firewall blocks, resulting in *less* data being found.
  - **Impact**: Scanners (`port_scanner`, `tech_analyzer`, `dns_scanner`, `shodan_scanner`, `email_harvester`) now run unconditionally in their most optimized and effective state. The `PortScanner` now strictly targets the top 50 critical ports for maximum speed and stealth.

## [v1.4.0] - 2026-04-19
### 💀 Breach Intelligence & Tactical UI Update

- **Breach & Leak Scanner (New Module):** Introduced a highly requested, purely passive OSINT module that cross-references the target domain against massive public breach databases and threat intelligence APIs. This engine asynchronously hunts for compromised employee credentials, exposed passwords, and historical data dumps without sending a single packet to the target infrastructure, providing devastating early-stage leverage.
- **Rich UI & Output Engine (Interface Update):** Completely redesigned the terminal execution environment utilizing the `rich` library. The framework now features an aggressive new ASCII banner, dynamic bouncing-bar progress spinners for asynchronous tasks, and color-coded, border-styled panels for output categorization. Critical vulnerabilities (like missing SPFs, exposed backups, and historical leaks) are now aggressively highlighted in red bounding boxes, ensuring operators never miss a high-value finding amidst the recon noise.

## [v1.3.0] - 2026-04-05
### ☁️ Cloud Footprinting & Passive Recon Update

- **Robots & Sitemap Scanner (New Module):** Introduced a stealthy, passive reconnaissance engine that automatically parses `robots.txt` rules and extracts `<loc>` tags from XML sitemaps (including dynamically discovered sitemap URLs via Regex). This allows operators to silently harvest hidden administrative endpoints and "Disallowed" directories without triggering WAF alerts or relying on noisy directory brute-forcing.
- **Cloud & S3 Detector (New Module):** Deployed an advanced infrastructure analysis engine that utilizes Reverse DNS (PTR) lookups and asynchronous HTTP header inspection to fingerprint the underlying cloud provider (AWS, GCP, Azure, Cloudflare). Furthermore, it features a highly concurrent, semaphore-controlled S3 bucket fuzzer that dynamically generates custom bucket permutations based on the target domain, hunting down critical data exposures in misconfigured public AWS storage.

## [v1.2.0] - 2026-03-23
### 🕵️‍♂️ Deep OSINT & Artifact Recovery Update

- **Social Media & OSINT Engine (New Module):** Deployed a zero-API dorking engine that stealthily scrapes raw HTML search results (via DuckDuckGo Lite) to uncover target mentions across Pastebin, Trello, LinkedIn, and Twitter. This module allows operators to trace external data leaks and digital footprints completely anonymously.
- **Backup & Archive Hunter (New Module):** Introduced a highly targeted fuzzing module designed to hunt down forgotten server backups, database dumps, and residual configuration files. The engine dynamically parses the target's domain name to generate custom, high-probability payloads (e.g., `.zip`, `.sql`, `.bak`) and executes them through our asynchronous concurrency gearbox to uncover catastrophic administrative blunders.

## [v1.1.0] - 2026-03-21
### 🕷️ Arsenal Expansion & Authentication Upgrade

- **JavaScript Secret Hunter (New Module):** Introduced a brand-new reconnaissance engine dedicated to frontend static analysis. The module dynamically crawls targets for referenced JavaScript assets, concurrently downloads them, and utilizes a heavy-duty regex arsenal to extract hardcoded AWS keys, Stripe tokens, Mailgun credentials, and hidden internal API endpoints.
- **GitHub Intelligence Engine (Auth Upgrade):** Upgraded the module with Personal Access Token (PAT) support via the new `-g` flag. Authenticated operators can now completely bypass the restrictive 60 requests/hour anonymous limit, unlocking a massive 5,000 requests/hour capacity for uninterrupted, deep-dive repository scanning.

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