import asyncio
import random
from typing import List
from core.base import BaseScanner
from models.report import TakeoverResult
from utils.client import AsyncClient

class TakeoverScanner(BaseScanner):
    """
    Subdomain Takeover Pro: Actively hunts for Dangling DNS and unclaimed 
    third-party services (AWS S3, GitHub Pages, Heroku, Azure, etc.) 
    using high-speed HTTP signature analysis.
    """
    async def execute(self) -> TakeoverResult:
        print(f"[*] TakeoverScanner: Hunting for dangling DNS and vulnerable CNAMEs on {self.target}...")

        # The most common prefixes that companies point to 3rd party cloud services
        # and then forget to delete from their DNS records.
        prefixes = [
            "blog", "shop", "dev", "docs", "help", "support", "api", "cdn", 
            "test", "staging", "beta", "info", "app", "mail", "forum", "news",
            "admin", "portal", "status", "web", "promo", "campaign", "assets"
        ]
        
        # The exact error signatures that prove a subdomain is unclaimed and vulnerable
        signatures = {
            "GitHub Pages": "There isn't a GitHub Pages site here.",
            "Heroku": "No such app",
            "AWS S3": "NoSuchBucket",
            "Azure": "404 Web Site not found",
            "Ghost": "The thing you were looking for is no longer here",
            "Shopify": "Sorry, this shop is currently unavailable.",
            "Tumblr": "Whatever you were looking for doesn't currently exist at this address.",
            "WordPress": "Do you want to register",
            "Pantheon": "The edges you have routed to",
            "Zendesk": "Help Center Closed",
            "Bitbucket": "Repository not found"
        }

        vulnerable_subs: List[str] = []
        client = AsyncClient(timeout=5, proxy=self.proxy)
        
        # High-speed asynchronous execution
        semaphore = asyncio.Semaphore(50)

        async def check_takeover(prefix: str):
            # Constructing the potential dangling subdomain
            url = f"http://{prefix}.{self.target}"
            
            async with semaphore:
                # Tactical Delay / Ghost Mode integration
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                elif self.stealth:
                    await asyncio.sleep(random.uniform(0.5, 2.0))

                status, data, _ = await client.fetch(url, return_type="text")
                
                # If we get content back, we scan it for all known takeover signatures
                if data:
                    for service, sig in signatures.items():
                        if sig in data:
                            vulnerable_subs.append(f"{url} -> [{service} TAKEOVER POSSIBLE!]")
                            break

        # Fire off all checks concurrently
        tasks = [check_takeover(prefix) for prefix in prefixes]
        
        # We also check the root and 'www' just in case they misconfigured the main records
        tasks.append(check_takeover("www"))
        
        await asyncio.gather(*tasks)

        # Reporting the carnage
        if vulnerable_subs:
            # We don't import colorama here to keep it decoupled, the main engine handles colors,
            # but we can format the string to stand out.
            print(f"[!] TakeoverScanner: BINGO! Critical Vulnerability! Found {len(vulnerable_subs)} potential takeovers!")
            for v in vulnerable_subs:
                print(f"  -> {v}")
        else:
            print(f"[-] TakeoverScanner: No obvious takeover vulnerabilities found on common prefixes.")

        return TakeoverResult(
            target_domain=self.target,
            vulnerable_subdomains=vulnerable_subs
        )
