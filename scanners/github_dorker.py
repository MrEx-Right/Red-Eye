import aiohttp
import asyncio
import time
from typing import List
from core.base import BaseScanner
from models.report import GithubResult

class GithubDorker(BaseScanner):
    """
    Scans GitHub repositories for potential sensitive data leaks
    related to the target domain using GitHub REST API.
    Now with pagination and graceful rate-limit handling!
    """
    async def execute(self) -> GithubResult:
        print(f"[*] GithubDorker: Hunting for leaked secrets for {self.target} on GitHub...")
        
        # A simple dork query looking for the domain alongside juicy keywords
        query = f'"{self.target}" AND ("password" OR "token" OR "secret" OR "api_key")'
        
        # FIX 1: Maximize the loot with per_page=100
        url = f"https://api.github.com/search/code?q={query}&per_page=100"
        
        # GitHub API strictly requires a User-Agent
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RedEye-OSINT-Framework"
        }
        
        leaks_count = 0
        samples: List[str] = []
        max_retries = 2
        
        try:
            async with aiohttp.ClientSession() as session:
                for attempt in range(max_retries):
                    async with session.get(url, headers=headers, timeout=10) as response:
                        if response.status == 200:
                            data = await response.json()
                            items = data.get("items", [])
                            leaks_count = len(items)
                            
                            # Let's just grab the first 3 HTML URLs as proof
                            for item in items[:3]:
                                samples.append(item.get("html_url", "Unknown URL"))
                            
                            break # Success! Break out of the retry loop
                            
                        elif response.status == 403:
                            # FIX 2: Professional Rate Limit Handling
                            retry_after = response.headers.get("Retry-After")
                            reset_time = response.headers.get("X-RateLimit-Reset")
                            wait_time = 0
                            
                            if retry_after:
                                wait_time = int(retry_after) + 1
                            elif reset_time:
                                # Calculate seconds until the reset epoch time
                                wait_time = max(0, int(reset_time) - int(time.time())) + 1
                                
                            # If the wait time is reasonable (e.g., <= 65 seconds), we wait.
                            if wait_time > 0 and wait_time <= 65:
                                print(f"[!] GithubDorker: Rate limited (403). Sleeping in the shadows for {wait_time} seconds...")
                                await asyncio.sleep(wait_time)
                                continue # Retry the request after waking up
                            else:
                                print(f"[!] GithubDorker: Rate limit wait is too long ({wait_time}s). Skipping to avoid hanging.")
                                break
                        else:
                            print(f"[!] GithubDorker: GitHub API returned status {response.status}")
                            break
                        
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
