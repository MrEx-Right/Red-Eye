import aiohttp
import asyncio
import json
from core.base import BaseScanner
from models.report import SubdomainResult

class SubdomainScanner(BaseScanner):
    """
    Scans for subdomains using Certificate Transparency logs (crt.sh).
    """
    
    async def execute(self) -> SubdomainResult:
        print(f"[*] SubdomainScanner: Initiating scan for {self.target} via crt.sh...")
        
        # We query the crt.sh database for the target domain and ask for JSON output
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        discovered = set() # Using a set to automatically remove duplicates
        
        # Async HTTP request handling (Requires: pip install aiohttp)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=15) as response:
                    if response.status == 200:
                        # crt.sh can sometimes return malformed JSON, so we handle it carefully
                        try:
                            data = await response.json()
                            for entry in data:
                                name_value = entry.get("name_value", "")
                                # A certificate can have multiple subdomains separated by newlines
                                if "\n" in name_value:
                                    for sub in name_value.split("\n"):
                                        discovered.add(sub.strip().lower())
                                else:
                                    discovered.add(name_value.strip().lower())
                        except json.JSONDecodeError:
                            print(f"[!] SubdomainScanner: Failed to parse JSON from crt.sh for {self.target}")
                    else:
                        print(f"[!] SubdomainScanner: crt.sh returned HTTP {response.status}")
                        
        except asyncio.TimeoutError:
            print(f"[!] SubdomainScanner: Connection to crt.sh timed out for {self.target}")
        except Exception as e:
            print(f"[!] SubdomainScanner: An unexpected error occurred: {str(e)}")

        # Convert the set back to a sorted list for a clean output
        subdomain_list = sorted(list(discovered))
        print(f"[+] SubdomainScanner: Found {len(subdomain_list)} unique subdomains.")

        # Pack the findings into our data model and return it
        return SubdomainResult(
            target_domain=self.target,
            discovered_subdomains=subdomain_list,
            source="crt.sh"
        )