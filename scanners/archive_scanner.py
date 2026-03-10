import asyncio
from typing import List
from core.base import BaseScanner
from models.report import ArchiveResult
from utils.client import AsyncClient

class ArchiveScanner(BaseScanner):
    """
    Queries the Wayback Machine (archive.org) CDX API to find historical, 
    forgotten, or hidden URLs associated with the target domain.
    """
    async def execute(self) -> ArchiveResult:
        print(f"[*] ArchiveScanner: Digging through internet history for {self.target}...")
        
        # We query the CDX API. 
        # fl=original gets just the URLs, collapse=urlkey removes duplicates, limit=1000 keeps it fast.
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original&collapse=urlkey&limit=1000"
        
        client = AsyncClient(timeout=15, proxy=self.proxy)
        status, data, _ = await client.fetch(url, return_type="json")
        
        found_urls: List[str] = []
        interesting_urls: List[str] = []
        
        # Juicy keywords we want to highlight from the past
        juicy_keywords = [
            ".sql", ".bak", ".zip", ".tar.gz", "api/", "admin", 
            "login", "config", ".env", "phpinfo", "test"
        ]

        if status == 200 and isinstance(data, list):
            # The CDX API returns a list of lists: [ ["original"], ["http://target.com/"] ... ]
            # We skip the first element because it's just the header ["original"]
            for item in data[1:]:
                if len(item) > 0:
                    url_str = item[0]
                    found_urls.append(url_str)
                    
                    # Check if this URL contains any of our juicy keywords
                    if any(keyword in url_str.lower() for keyword in juicy_keywords):
                        interesting_urls.append(url_str)

        if found_urls:
            print(f"[+] ArchiveScanner: Uncovered {len(found_urls)} historical URLs! ({len(interesting_urls)} look very juicy).")
        else:
            print(f"[-] ArchiveScanner: No historical records found or API blocked us.")

        return ArchiveResult(
            target_domain=self.target,
            total_urls_found=len(found_urls),
            # Let's return only the juicy ones to the main engine to keep the terminal clean
            interesting_urls=sorted(list(set(interesting_urls)))
        )