import asyncio
import builtwith
import warnings
import urllib3
import re
from core.base import BaseScanner
from models.report import TechResult
from utils.client import AsyncClient

# Suppress noisy warnings from dependencies
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TechAnalyzer(BaseScanner):
    """
    BuiltWith + fallback header-based tech detection.
    30s timeout, 2 retries, resilient thread execution.
    """
    async def execute(self) -> TechResult:
        print(f"[*] TechAnalyzer: Consulting BuiltWith + headers for {self.target}...")

        discovered_tech = set()
        loop = asyncio.get_running_loop()
        timeout_sec = 30.0  # Controlled safely by asyncio.wait_for
        max_retries = 2

        def run_builtwith(url):
            # FIX: Removed global socket.setdefaulttimeout() to prevent thread collision across the engine.
            # Relying entirely on asyncio.wait_for to kill hanging executions safely.
            try:
                return builtwith.builtwith(url)
            except Exception:
                return {}

        urls = [f"https://{self.target}"]
        if self.deep_scan:
            urls.append(f"http://{self.target}")

        # 1. BuiltWith (with retries)
        for url in urls:
            for attempt in range(max_retries + 1):
                try:
                    results = await asyncio.wait_for(
                        loop.run_in_executor(None, run_builtwith, url),
                        timeout=timeout_sec
                    )
                    if results:
                        for category, techs in results.items():
                            for tech in techs:
                                discovered_tech.add(tech)
                        break
                except asyncio.TimeoutError:
                    if attempt < max_retries:
                        await asyncio.sleep(2)
                        continue
                    print(f"[!] TechAnalyzer: BuiltWith timed out for {url} (after {max_retries + 1} tries)")
                except Exception as e:
                    if attempt < max_retries:
                        await asyncio.sleep(2)
                        continue
                    print(f"[!] TechAnalyzer: BuiltWith failed for {url}: {e}")

        # 2. Fallback: extract tech from HTTP headers when BuiltWith returns empty
        if not discovered_tech or self.deep_scan:
            header_tech = await self._detect_from_headers()
            discovered_tech.update(header_tech)

        final_list = sorted(list(discovered_tech))

        if final_list:
            print(f"[+] TechAnalyzer: Mapped {len(final_list)} technologies.")
        else:
            print(f"[-] TechAnalyzer: No tech detected (target unreachable or stealth).")

        return TechResult(
            target_domain=self.target,
            technologies=final_list
        )

    async def _detect_from_headers(self) -> set:
        """Detect technology from HTTP response headers (BuiltWith fallback)."""
        tech = set()
        client = AsyncClient(timeout=15, proxy=self.proxy)
        urls = [f"https://{self.target}", f"http://{self.target}"]

        # Known header -> technology mappings
        server_signatures = {
            "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
            "microsoft-iis": "IIS", "litespeed": "LiteSpeed", "openresty": "OpenResty",
            "caddy": "Caddy", "gws": "Google Web Server"
        }
        x_powered = re.compile(r"([A-Za-z0-9.\-]+)", re.I)

        for url in urls:
            status, _, headers = await client.fetch(url, return_type="text")
            if status != 200 or headers is None:
                continue
            server = (headers.get("Server") or "").lower()
            x_pwr = (headers.get("X-Powered-By") or headers.get("x-powered-by") or "")
            for sig, name in server_signatures.items():
                if sig in server:
                    tech.add(name)
                    break
            if x_pwr:
                match = x_powered.search(x_pwr)
                if match:
                    tech.add(match.group(1).strip())
        return tech
