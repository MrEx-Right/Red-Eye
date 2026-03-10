import aiohttp
import asyncio
from typing import List
from core.base import BaseScanner
from models.report import GithubResult

class GithubDorker(BaseScanner):
    """
    Scans GitHub repositories for potential sensitive data leaks
    related to the target domain using GitHub REST API.
    """
    async def execute(self) -> GithubResult:
        print(f"[*] GithubDorker: Hunting for leaked secrets for {self.target} on GitHub...")
        
        # A simple dork query looking for the domain alongside juicy keywords
        query = f'"{self.target}" AND ("password" OR "token" OR "secret" OR "api_key")'
        url = f"https://api.github.com/search/code?q={query}"
        
        # GitHub API strictly requires a User-Agent
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RedEye-OSINT-Framework"
        }
        
        leaks_count = 0
        samples: List[str] = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        items = data.get("items", [])
                        leaks_count = len(items)
                        
                        # Let's just grab the first 3 HTML URLs as proof
                        for item in items[:3]:
                            samples.append(item.get("html_url", "Unknown URL"))
                            
                    elif response.status == 403:
                        # GitHub unauthenticated API limit is 10 req/minute. 
                        print(f"[!] GithubDorker: Rate limited by GitHub API for {self.target}.")
                    else:
                        print(f"[!] GithubDorker: GitHub API returned status {response.status}")
                        
        except asyncio.TimeoutError:
            print(f"[!] GithubDorker: Connection timed out.")
        except Exception as e:
            print(f"[!] GithubDorker: Unexpected error - {str(e)}")

        if leaks_count > 0:
            print(f"[+] GithubDorker: JACKPOT! Found {leaks_count} potential leaks for {self.target}.")
        else:
            print(f"[-] GithubDorker: No obvious leaks found on GitHub public repos.")

        return GithubResult(
            target_domain=self.target,
            leaks_found=leaks_count,
            sample_urls=samples
        )