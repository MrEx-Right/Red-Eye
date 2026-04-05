import re
from typing import List
from core.base import BaseScanner
from utils.client import AsyncClient
from models.report import RobotsResult

class RobotsScanner(BaseScanner):
    """
    Extracts paths from robots.txt and sitemap.xml.
    A passive reconnaissance module for discovering hidden or indexed endpoints.
    """
    async def execute(self) -> RobotsResult:
        client = AsyncClient(timeout=10, proxy=self.proxy)
        found_paths = set()
        sitemaps_to_check = set()
        
        print(f"[*] RobotsScanner: Analyzing robots.txt and sitemaps for {self.target}...")

        # --- Phase 1: robots.txt Extraction ---
        robots_url = f"https://{self.target}/robots.txt"
        status, text, _ = await client.fetch(robots_url)
        
        if status == 200 and text:
            print(f"[+] RobotsScanner: Successfully retrieved robots.txt")
            lines = text.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if line.lower().startswith('allow:') or line.lower().startswith('disallow:'):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if path and path != '/':
                            found_paths.add(path)
                
                elif line.lower().startswith('sitemap:'):
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        sitemaps_to_check.add(parts[1].strip())
        else:
            print(f"[-] RobotsScanner: robots.txt not found or inaccessible (Status: {status})")

        # --- Phase 2: sitemap.xml Extraction ---
        default_sitemap = f"https://{self.target}/sitemap.xml"
        sitemaps_to_check.add(default_sitemap)

        for sitemap_url in sitemaps_to_check:
            s_status, s_text, _ = await client.fetch(sitemap_url)
            if s_status == 200 and s_text:
                print(f"[+] RobotsScanner: Discovered sitemap: {sitemap_url}")
                locs = re.findall(r"<loc>(.*?)</loc>", s_text, re.IGNORECASE)
                for loc in locs:
                    found_paths.add(loc.strip())
            else:
                if sitemap_url != default_sitemap: 
                    print(f"[-] RobotsScanner: Failed to fetch sitemap: {sitemap_url} (Status: {s_status})")

        sorted_paths = sorted(list(found_paths))
        
        if sorted_paths:
            print(f"[+] RobotsScanner: Extracted {len(sorted_paths)} unique paths.")
        else:
            print(f"[-] RobotsScanner: No paths extracted from robots.txt or sitemaps.")

        return RobotsResult(
            target_domain=self.target,
            extracted_paths=sorted_paths
        )