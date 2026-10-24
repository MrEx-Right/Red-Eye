import asyncio
from core.base import BaseScanner
from models.report import SubdomainResult
from utils.client import AsyncClient

class SubdomainScanner(BaseScanner):
    """
    Scans for subdomains using Certificate Transparency logs (crt.sh).
    """
    
    async def execute(self) -> SubdomainResult:
        print(f"[*] SubdomainScanner: Initiating scan for {self.zone} via crt.sh...")
        
        # We query the crt.sh database for the target domain and ask for JSON output
        url = f"https://crt.sh/?q=%25.{self.zone}&output=json"
        discovered = set() # Using a set to automatically remove duplicates

        # crt.sh is slow and flaky (frequent 502/504), so it gets a long timeout and one retry
        client = AsyncClient(timeout=45, proxy=self.proxy)
        status, data = 0, None
        for attempt in range(2):
            status, data, _ = await client.fetch(url, return_type="json")
            if status == 200:
                break
            if attempt == 0:
                await asyncio.sleep(3)

        if status == 200 and isinstance(data, list):
            for entry in data:
                # A certificate can have multiple subdomains separated by newlines
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    # Skip e-mail SANs and names belonging to other domains
                    if "@" in name or not (name == self.zone or name.endswith(f".{self.zone}")):
                        continue
                    discovered.add(name)
        elif status == 200:
            print(f"[!] SubdomainScanner: Failed to parse JSON from crt.sh for {self.zone}")
        elif status == 408:
            print(f"[!] SubdomainScanner: Connection to crt.sh timed out for {self.zone}")
        else:
            print(f"[!] SubdomainScanner: crt.sh returned HTTP {status}")

        # Convert the set back to a sorted list for a clean output
        subdomain_list = sorted(discovered)
        print(f"[+] SubdomainScanner: Found {len(subdomain_list)} unique subdomains.")

        # Pack the findings into our data model and return it
        return SubdomainResult(
            target_domain=self.zone,
            discovered_subdomains=subdomain_list,
            source="crt.sh"
        )
