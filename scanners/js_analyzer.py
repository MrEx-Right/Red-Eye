import asyncio
import re
from urllib.parse import urljoin
from collections import defaultdict
from core.base import BaseScanner
from models.report import JsResult
from utils.client import AsyncClient

class JsAnalyzer(BaseScanner):
    """
    Crawls the target's frontend to extract all referenced JavaScript files,
    then concurrently downloads and statically analyzes them for hardcoded 
    secrets, API keys, and hidden internal endpoints.
    """
    async def execute(self) -> JsResult:
        print(f"[*] JsAnalyzer: Hunting for hardcoded secrets in JS files on {self.target}...")
        
        client = AsyncClient(timeout=10, proxy=self.proxy)
        base_url = f"https://{self.target}"
        
        # 1. Fetch the main page to find JS links
        status, data, _ = await client.fetch(base_url, return_type="text")
        if status == 0 or status >= 400:
            # Fallback to HTTP if HTTPS fails
            base_url = f"http://{self.target}"
            status, data, _ = await client.fetch(base_url, return_type="text")
            
        if not data:
            print(f"[-] JsAnalyzer: Could not fetch main page for {self.target}. Aborting JS scan.")
            return JsResult(target_domain=self.target, js_files_scanned=0)

        # Regex to find <script src="..."></script>
        script_pattern = re.compile(r'(?i)src=["\']([^"\']+\.js[^"\']*)["\']')
        js_links = set(script_pattern.findall(data))
        
        if not js_links:
            print(f"[-] JsAnalyzer: No external JS files found on the index page.")
            return JsResult(target_domain=self.target, js_files_scanned=0)

        # Normalize URLs (convert relative paths to absolute URLs)
        js_urls = set()
        for link in js_links:
            full_url = urljoin(base_url, link)
            js_urls.add(full_url)

        print(f"[*] JsAnalyzer: Discovered {len(js_urls)} JS files. Commencing concurrent extraction...")

        # Secret hunting regex arsenal
        regex_arsenal = {
            "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            "Stripe Standard API": re.compile(r'[sr]k_live_[0-9a-zA-Z]{24}'),
            "Mailgun API Key": re.compile(r'key-[0-9a-zA-Z]{32}'),
            "Generic Secret/Token": re.compile(r'(?i)(?:secret|token|api_key|password)["\'\s:=]+([a-zA-Z0-9\-_=]{16,64})'),
            "Internal API Endpoint": re.compile(r'(?i)["\'](\/api\/[a-zA-Z0-9\-\/v_]+)["\']')
        }

        found_secrets = defaultdict(set)
        semaphore = asyncio.Semaphore(10) # Max 10 concurrent JS file downloads

        async def scan_js_file(js_url: str):
            async with semaphore:
                # Add delay if stealth mode is active
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                    
                js_status, js_content, _ = await client.fetch(js_url, return_type="text")
                if js_status == 200 and js_content:
                    # Scan the content against our regex arsenal
                    for secret_name, pattern in regex_arsenal.items():
                        matches = pattern.findall(js_content)
                        for match in matches:
                            # If regex has groups, match is a string. If not, match is the whole matched string.
                            clean_match = match.strip() if isinstance(match, str) else match[0].strip()
                            # Basic false positive filter for generic tokens
                            if len(clean_match) >= 8 and not clean_match.isnumeric():
                                found_secrets[secret_name].add(clean_match)

        # Fire all JS scans concurrently
        tasks = [scan_js_file(url) for url in js_urls]
        await asyncio.gather(*tasks)

        total_secrets = sum(len(v) for v in found_secrets.values())
        
        if total_secrets > 0:
            print(f"[+] JsAnalyzer: BINGO! Uncovered {total_secrets} potential secrets/endpoints across {len(js_urls)} JS files.")
        else:
            print(f"[-] JsAnalyzer: JS files look clean. No obvious hardcoded secrets found.")

        # Convert sets to sorted lists for the final report
        report_secrets = {k: sorted(list(v)) for k, v in found_secrets.items()}

        return JsResult(
            target_domain=self.target,
            js_files_scanned=len(js_urls),
            secrets_found=report_secrets
        )