import re
from core.base import BaseScanner
from utils.client import AsyncClient
from models.report import RobotsResult

MAX_SITEMAPS = 15  # follow sitemap indexes, but never crawl a whole site

class RobotsScanner(BaseScanner):
    """
    Extracts paths from robots.txt and sitemap.xml.
    A passive reconnaissance module for discovering hidden or indexed endpoints.
    """
    async def execute(self) -> RobotsResult:
        found_paths = set()
        sitemaps_to_check = []

        print(f"[*] RobotsScanner: Analyzing robots.txt and sitemaps for {self.target}...")

        async with AsyncClient(timeout=10, proxy=self.proxy) as client:
            base_url = await client.detect_base_url(self.target)
            if not base_url:
                print(f"[-] RobotsScanner: {self.target} is unreachable over HTTPS and HTTP. Skipping.")
                return RobotsResult(target_domain=self.target, extracted_paths=[])

            # --- Phase 1: robots.txt Extraction ---
            status, text, _ = await client.fetch(f"{base_url}/robots.txt")

            if status == 200 and text:
                print("[+] RobotsScanner: Successfully retrieved robots.txt")
                for line in text.splitlines():
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue

                    key, _, value = line.partition(":")
                    key, value = key.strip().lower(), value.strip()
                    if key in ("allow", "disallow") and value and value != "/":
                        found_paths.add(value)
                    elif key == "sitemap" and value:
                        sitemaps_to_check.append(value)
            else:
                print(f"[-] RobotsScanner: robots.txt not found or inaccessible (Status: {status})")

            # --- Phase 2: sitemap.xml Extraction ---
            default_sitemap = f"{base_url}/sitemap.xml"
            if default_sitemap not in sitemaps_to_check:
                sitemaps_to_check.append(default_sitemap)

            seen = set()
            while sitemaps_to_check and len(seen) < MAX_SITEMAPS:
                sitemap_url = sitemaps_to_check.pop(0)
                if sitemap_url in seen:
                    continue
                seen.add(sitemap_url)

                s_status, s_text, _ = await client.fetch(sitemap_url)
                if s_status == 200 and s_text:
                    print(f"[+] RobotsScanner: Discovered sitemap: {sitemap_url}")
                    locs = [loc.strip() for loc in re.findall(r"<loc>(.*?)</loc>", s_text, re.IGNORECASE | re.DOTALL)]
                    if re.search(r"<sitemapindex", s_text, re.IGNORECASE):
                        # A sitemap index lists more sitemaps, not pages
                        sitemaps_to_check.extend(locs)
                    else:
                        found_paths.update(loc for loc in locs if loc)
                elif sitemap_url != default_sitemap:
                    print(f"[-] RobotsScanner: Failed to fetch sitemap: {sitemap_url} (Status: {s_status})")

        sorted_paths = sorted(found_paths)

        if sorted_paths:
            print(f"[+] RobotsScanner: Extracted {len(sorted_paths)} unique paths.")
        else:
            print("[-] RobotsScanner: No paths extracted from robots.txt or sitemaps.")

        return RobotsResult(
            target_domain=self.target,
            extracted_paths=sorted_paths
        )
