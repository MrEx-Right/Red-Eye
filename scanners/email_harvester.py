import asyncio
import re
from typing import List
from core.base import BaseScanner
from models.report import EmailResult
from utils.client import AsyncClient

class EmailHarvester(BaseScanner):
    """
    Crawls surface pages of the target (home, contact, about) and uses 
    a universal Regular Expression to harvest ANY exposed email addresses,
    including generic providers like @outlook.com or @gmail.com.
    """
    async def execute(self) -> EmailResult:
        print(f"[*] EmailHarvester: Deep scraping for any contact emails on {self.target}...")
        
        # DYNAMIC PATH SELECTION BASED ON VITES (-v)
        if self.deep_scan:
            paths_to_check = [
                "", "contact", "contact-us", "contact_us", "about", "about-us", 
                "team", "support", "help", "contact.html", "contact.php", "about.html"
            ]
        else:
            paths_to_check = ["", "contact", "about", "support"]

        client = AsyncClient(timeout=10, proxy=self.proxy)
        found_emails = set()
        
        # UNIVERSAL EMAIL REGEX 
        email_pattern = re.compile(r'[a-zA-Z0-9.\-_+%]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

        # JUNK FILTER: We want to ignore default template emails, but KEEP outlook/gmail
        junk_domains = [
            "example.com", "domain.com", "yourdomain.com", 
            "wixpress.com", "sentry.io", "name@email.com",
            "yoursite.com"
        ]

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
                    # Extract ALL emails from the HTML body
                    matches = email_pattern.findall(data)
                    for match in matches:
                        clean_match = match.lower()
                        
                        # 1. FALSE POSITIVE FILTER: Ignore image files caught by regex (e.g., logo@2x.png)
                        if clean_match.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp')):
                            continue
                            
                        # 2. JUNK FILTER: Ignore useless CMS template emails
                        is_junk = any(junk in clean_match for junk in junk_domains)
                        
                        # If it's not junk, add it! (This includes @outlook.com, @gmail.com, etc.)
                        if not is_junk:
                            found_emails.add(clean_match)

        # Fire all page scrapes concurrently
        tasks = [scrape_page(path) for path in paths_to_check]
        await asyncio.gather(*tasks)

        # Sort alphabetically for a clean report
        emails_list = sorted(list(found_emails))

        if emails_list:
            print(f"[+] EmailHarvester: Jackpot! Scraped {len(emails_list)} emails from {self.target}.")
        else:
            print(f"[-] EmailHarvester: No emails found on the surface. They are hiding well.")

        return EmailResult(
            target_domain=self.target,
            harvested_emails=emails_list
        )