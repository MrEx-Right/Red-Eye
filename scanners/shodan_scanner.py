import asyncio
import os
import socket
from typing import Optional
from core.base import BaseScanner
from models.report import ShodanResult
from utils.client import AsyncClient
from utils.domain import is_ip


class ShodanScanner(BaseScanner):
    """
    Shodan Intelligence Scanner — queries Shodan's InternetDB (no API key required)
    and optionally the full Shodan host API for authenticated deep scans.

    Free tier  : InternetDB (ports, tags, vulns, CPEs) — no API key needed.
    Deep scan  : Full Shodan host endpoint — requires --shodan-key or the SHODAN_API_KEY env var.
    """

    SHODAN_INTERNETDB = "https://internetdb.shodan.io/{ip}"
    SHODAN_HOST_API   = "https://api.shodan.io/shodan/host/{ip}?key={key}"

    async def _resolve_ip(self) -> Optional[str]:
        """Resolve domain to an IPv4 address (InternetDB is IPv4-only)."""
        if is_ip(self.host):
            return self.host
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(self.host, None, family=socket.AF_INET)
            return infos[0][4][0]
        except Exception:
            return None

    async def execute(self) -> ShodanResult:
        print(f"[*] ShodanScanner: Resolving and querying Shodan intelligence for {self.host}...")

        result = ShodanResult(target_domain=self.host)
        client = AsyncClient(timeout=12, proxy=self.proxy)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # Step 1: Resolve domain -> IP
        ip = await self._resolve_ip()
        if not ip:
            print(f"[-] ShodanScanner: Could not resolve IP for {self.host}. Skipping.")
            return result

        result.ip_address = ip
        print(f"[*] ShodanScanner: Resolved {self.host} -> {ip}. Querying InternetDB...")

        # Step 2: Query Shodan InternetDB (free, no key required)
        idb_url = self.SHODAN_INTERNETDB.format(ip=ip)
        status, data, _ = await client.fetch(idb_url, return_type="json")

        if status == 200 and isinstance(data, dict):
            result.open_ports  = data.get("ports", [])
            result.hostnames   = data.get("hostnames", [])
            result.tags        = data.get("tags", [])
            result.vulns       = data.get("vulns", [])

            cpes = data.get("cpes", [])
            if cpes:
                result.banners = cpes  # CPE strings describe detected software

            print(f"[+] ShodanScanner: InternetDB hit! Ports: {result.open_ports}, Vulns: {len(result.vulns)}")
        else:
            print(f"[-] ShodanScanner: InternetDB returned no data (status {status}).")

        # Step 3: If API key is available, query full Shodan host endpoint
        shodan_key = self.shodan_key or os.environ.get("SHODAN_API_KEY", "")

        if shodan_key:
                print("[*] ShodanScanner: Deep scan active — querying full Shodan host API...")
                host_url = self.SHODAN_HOST_API.format(ip=ip, key=shodan_key)
                s_status, s_data, _ = await client.fetch(host_url, return_type="json")

                if s_status == 200 and isinstance(s_data, dict):
                    result.organization = s_data.get("org", "Unknown")
                    result.country      = s_data.get("country_name", "Unknown")
                    result.isp          = s_data.get("isp", "Unknown")
                    result.asn          = s_data.get("asn", "Unknown")
                    result.os           = s_data.get("os") or "Unknown"

                    # Extract unique banners from service data blocks
                    for svc in s_data.get("data", []):
                        banner = svc.get("data", "").strip()
                        if banner and banner not in result.banners:
                            result.banners.append(banner[:200])  # Cap banner length

                    print(f"[+] ShodanScanner: Full host data retrieved. Org: {result.organization}")
                else:
                    print(f"[-] ShodanScanner: Host API returned status {s_status}. Check API key.")
        else:
            # Fallback: use ip-api.com for geo/org data — no key needed
            geo_url = f"http://ip-api.com/json/{ip}?fields=status,org,country,isp,as"
            g_status, g_data, _ = await client.fetch(geo_url, return_type="json")
            if g_status == 200 and isinstance(g_data, dict) and g_data.get("status") != "fail":
                result.organization = g_data.get("org") or "Unknown"
                result.country      = g_data.get("country") or "Unknown"
                result.isp          = g_data.get("isp") or "Unknown"
                result.asn          = g_data.get("as") or "Unknown"
                print(f"[+] ShodanScanner: Geo-IP enrichment complete. Country: {result.country}")

        return result
