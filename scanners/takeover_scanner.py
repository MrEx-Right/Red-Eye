import asyncio
from typing import List
from core.base import BaseScanner
from models.report import TakeoverResult
from utils.client import AsyncClient

class TakeoverScanner(BaseScanner):
    """
    Hunts for Subdomain Takeover vulnerabilities by checking common prefixes
    against known "service abandoned" fingerprints (GitHub, AWS, Heroku, etc.).
    """
    async def execute(self) -> TakeoverResult:
        print(f"[*] TakeoverScanner: Hunting for dangling DNS records on {self.target}...")
        
        # We check the main target and some of the most commonly abandoned subdomains
        prefixes = ["", "www.", "blog.", "support.", "docs.", "api.", "test.", "shop.", "help."]
        urls_to_check = [f"http://{prefix}{self.target}" for prefix in prefixes]
        
        client = AsyncClient(timeout=8, proxy=self.proxy)
        vulnerable: List[str] = []
        
        # Fingerprints of abandoned cloud services
        signatures = {
            "GitHub Pages": "There isn't a GitHub Pages site here.",
            "AWS S3": "The specified bucket does not exist",
            "Heroku": "No such app",
            "Zendesk": "Help Center Closed",
            "Tumblr": "Whatever you were looking for doesn't currently exist at this address.",
            "Shopify": "Sorry, this shop is currently unavailable.",
            "Webflow": "The page you are looking for doesn't exist or has been moved."
        }

        semaphore = asyncio.Semaphore(10)

        async def check_url(url: str):
            async with semaphore:
                status, data, _ = await client.fetch(url, return_type="text")
                if data:
                    # Check if the response body contains any of the known takeover signatures
                    for provider, sig in signatures.items():
                        if sig in data:
                            vulnerable.append(f"{url} -> [Vulnerable to {provider} Takeover!]")
                            break

        tasks = [check_url(url) for url in urls_to_check]
        await asyncio.gather(*tasks)

        if vulnerable:
            print(f"[+] TakeoverScanner: CRITICAL! Found {len(vulnerable)} potentially hijacked subdomains!")
        else:
            print(f"[-] TakeoverScanner: No obvious takeover vulnerabilities found on common prefixes.")

        return TakeoverResult(
            target_domain=self.target,
            vulnerable_subdomains=vulnerable
        )