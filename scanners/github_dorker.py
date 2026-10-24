import asyncio
import time
from typing import Set
from urllib.parse import urlencode
from core.base import BaseScanner
from models.report import GithubResult
from utils.client import AsyncClient

KEYWORDS = ["password", "token", "secret", "api_key"]

class GithubDorker(BaseScanner):
    """
    Scans GitHub repositories for potential sensitive data leaks
    related to the target domain using GitHub REST API.
    GitHub's code search endpoint requires authentication, so this module
    needs a token (-g). Graceful rate-limit handling included.
    """

    def _rate_limit_wait(self, headers) -> int:
        if headers is None:
            return 0
        retry_after = headers.get("Retry-After")
        reset_time = headers.get("X-RateLimit-Reset")
        try:
            if retry_after:
                return int(retry_after) + 1
            if reset_time:
                # Calculate seconds until the reset epoch time
                return max(0, int(reset_time) - int(time.time())) + 1
        except ValueError:
            pass
        return 0

    async def execute(self) -> GithubResult:
        print(f"[*] GithubDorker: Hunting for leaked secrets for {self.zone} on GitHub...")

        if not self.github_token:
            reason = "GitHub code search requires authentication — pass a token with -g."
            print(f"[-] GithubDorker: {reason}")
            return GithubResult(target_domain=self.zone, skipped_reason=reason)

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "RedEye-OSINT-Framework",
            "Authorization": f"Bearer {self.github_token}",
        }

        sample_urls: Set[str] = set()
        total_hits = 0
        max_retries = 2

        async with AsyncClient(timeout=15, proxy=self.proxy) as client:
            # One query per keyword: the code search API has no grouping parentheses
            for keyword in KEYWORDS:
                query = f'"{self.zone}" {keyword}'
                url = f"https://api.github.com/search/code?{urlencode({'q': query, 'per_page': 100})}"

                for attempt in range(max_retries + 1):
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    status, data, resp_headers = await client.fetch(url, headers=headers, return_type="json")

                    if status == 200 and isinstance(data, dict):
                        total_hits += int(data.get("total_count", 0))
                        for item in data.get("items", []):
                            if item.get("html_url"):
                                sample_urls.add(item["html_url"])
                        break

                    if status in (403, 429):
                        # Professional Rate Limit Handling
                        wait_time = self._rate_limit_wait(resp_headers)
                        if attempt < max_retries and 0 < wait_time <= 65:
                            print(f"[!] GithubDorker: Rate limited ({status}). Sleeping in the shadows for {wait_time} seconds...")
                            await asyncio.sleep(wait_time)
                            continue
                        print(f"[!] GithubDorker: Rate limit wait is too long ({wait_time}s). Skipping remaining queries.")
                        break

                    if status == 401:
                        reason = "GitHub rejected the token (401). Check the value passed with -g."
                        print(f"[!] GithubDorker: {reason}")
                        return GithubResult(target_domain=self.zone, skipped_reason=reason)

                    print(f"[!] GithubDorker: GitHub API returned status {status} for '{keyword}'")
                    break

        leaks_count = len(sample_urls)
        if leaks_count > 0:
            print(f"[+] GithubDorker: JACKPOT! Found {leaks_count} potential leaks for {self.zone} ({total_hits} total hits).")
        else:
            print("[-] GithubDorker: No obvious leaks found on GitHub public repos.")

        return GithubResult(
            target_domain=self.zone,
            leaks_found=leaks_count,
            sample_urls=sorted(sample_urls),
            total_hits=total_hits
        )
