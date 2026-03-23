import asyncio
import urllib.parse
import re
from collections import defaultdict
from core.base import BaseScanner
from models.report import SmResult
from utils.client import AsyncClient

class SmScanner(BaseScanner):
    """
    Social Media & OSINT Scanner.
    Uses search engine dorking (via DuckDuckGo Lite) to find mentions of 
    the target domain on platforms like Twitter, LinkedIn, Pastebin, and Trello
    without requiring any API keys.
    """
    async def execute(self) -> SmResult:
        print(f"[*] SmScanner: Dorking the deep web for {self.target} mentions...")

        platforms = {
            "Twitter": "site:twitter.com",
            "LinkedIn": "site:linkedin.com",
            "Pastebin": "site:pastebin.com",
            "Trello": "site:trello.com",
            "Medium": "site:medium.com"
        }

        client = AsyncClient(timeout=15, proxy=self.proxy)
        found_mentions = defaultdict(list)
        
        # Be gentle to search engines to avoid instant IP blocks
        semaphore = asyncio.Semaphore(2) 

        # Regex to extract duckduckgo redirect URLs from the raw HTML
        url_pattern = re.compile(r'uddg=([^&]+)')

        async def dork_platform(platform_name: str, dork_base: str):
            async with semaphore:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                elif self.stealth:
                    await asyncio.sleep(2.0)

                query = f'{dork_base} "{self.target}"'
                safe_query = urllib.parse.quote(query)
                
                # Using DuckDuckGo Lite for easy HTML parsing without JS rendering
                url = f"https://html.duckduckgo.com/html/?q={safe_query}"

                # Pretend to be a legitimate browser
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                }

                # Bypass standard async fetcher's default headers to avoid detection
                status, data, _ = await client.fetch(url, return_type="text", headers=headers)

                if status == 200 and data:
                    matches = url_pattern.findall(data)
                    for match in matches:
                        clean_url = urllib.parse.unquote(match)
                        # Filter out duckduckgo self-redirects and ensure it's related to the platform
                        if "duckduckgo.com" not in clean_url and platform_name.lower() in clean_url.lower():
                             if clean_url not in found_mentions[platform_name]:
                                 found_mentions[platform_name].append(clean_url)

        tasks = [dork_platform(name, dork) for name, dork in platforms.items()]
        await asyncio.gather(*tasks)

        total_found = sum(len(urls) for urls in found_mentions.values())

        if total_found > 0:
            print(f"[+] SmScanner: Uncovered {total_found} external mentions across {len(found_mentions)} platforms.")
        else:
            print(f"[-] SmScanner: Target maintains a ghost profile. No significant mentions found.")

        # Limit to top 5 results per platform for the report object to keep it clean
        report_data = {k: v[:5] for k, v in found_mentions.items() if v}

        return SmResult(
            target_domain=self.target,
            platform_mentions=report_data
        )