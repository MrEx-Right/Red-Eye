import asyncio
import re
import os
from typing import List
from core.base import BaseScanner
from models.report import EmailResult
from utils.client import AsyncClient

# Absolute path resolution to prevent execution context errors
WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlist")

class EmailHarvester(BaseScanner):
    """
    Crawls surface pages of the target and uses an optimized Regex 
    to harvest exposed email addresses. Implements a smart junk filter
    that prioritizes target-domain emails and allows valid 3rd party providers.
    """
    async def execute(self) -> EmailResult:
        print(f"[*] EmailHarvester: Deep scraping for any contact emails on {self.target}...")
        
        # DYNAMIC PATH SELECTION
        paths_to_check = ["", "contact", "about", "support"]
        
        if self.deep_scan:
            custom_path_file = os.path.join(WORDLIST_DIR, "email_paths.txt")
            if os.path.exists(custom_path_file):
                try:
                    with open(custom_path_file, "r", encoding="utf-8") as f:
                        paths_to_check = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                except Exception as e:
                    print(f"[!] EmailHarvester: Error reading email_paths.txt: {e}. Using defaults.")
                    paths_to_check = [
                        "", "contact", "contact-us", "about", "team", "support", "help"
                    ]

        client = AsyncClient(timeout=10, proxy=self.proxy)
        found_emails = set()
        
        # UNIVERSAL EMAIL REGEX (Optimized)
        email_pattern = re.compile(r'(?:[a-zA-Z0-9.\-_+%]*[a-zA-Z][a-zA-Z0-9.\-_+%]*)@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        # STRICT JUNK FILTER: Only obvious dummy domains, removed valid services like sentry/wix
        junk_domains = [
            "example.com", "domain.com", "yourdomain.com", 
            "yoursite.com", "mysite.com", "email.com", "test.com"
        ]
        
        junk_locals = ["name", "email", "info@example", "contact@domain"]
        
        # Extract base target to protect native emails (e.g., target.com from www.target.com)
        target_base = self.target.replace("www.", "")

        # Semaphore to prevent overwhelming the target's web server
        semaphore = asyncio.Semaphore(5)

        async def scrape_page(path: str):
            async with semaphore:
                # Always try HTTPS first!
                url_https = f"https://{self.target}/{path}" if path else f"https://{self.target}"
                status, data, _ = await client.fetch(url_https, return_type="text")
                
                # Fallback to HTTP if HTTPS is strictly blocked or missing
                if status == 0 or status >= 400:
                    url_http = f"http://{self.target}/{path}" if path else f"http://{self.target}"
                    status, data, _ = await client.fetch(url_http, return_type="text")

                if status == 200 and data:
                    matches = email_pattern.findall(data)
                    for match in matches:
                        clean_match = match.lower()
                        
                        # 1. FALSE POSITIVE FILTER: Ignore image files caught by regex
                        if clean_match.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')):
                            continue
                            
                        # 2. SMART JUNK FILTER: Precise matching using endswith/startswith
                        is_junk_domain = any(clean_match.endswith(f"@{junk}") for junk in junk_domains)
                        is_junk_local = any(clean_match.startswith(f"{junk}@") for junk in junk_locals)
                        
                        # TARGET OVERRIDE: If the email ends with our target domain, it's NEVER junk
                        if clean_match.endswith(f"@{target_base}"):
                            is_junk_domain = False
                        
                        if not is_junk_domain and not is_junk_local:
                            found_emails.add(clean_match)

        # Fire all page scrapes concurrently
        tasks = [scrape_page(path) for path in paths_to_check]
        await asyncio.gather(*tasks)

        emails_list = sorted(list(found_emails))

        if emails_list:
            print(f"[+] EmailHarvester: Jackpot! Scraped {len(emails_list)} emails from {self.target}.")
        else:
            print(f"[-] EmailHarvester: No emails found on the surface. They are hiding well.")

        return EmailResult(
            target_domain=self.target,
            harvested_emails=emails_list
        )
