import asyncio
import builtwith
import warnings
import re
from core.base import BaseScanner
from models.report import TechResult
from utils.client import AsyncClient

# builtwith's bundled regexes trigger noisy warnings on modern Python
warnings.filterwarnings("ignore", module="builtwith")

# Known header -> technology mappings
SERVER_SIGNATURES = {
    "nginx": "Nginx", "apache": "Apache", "cloudflare": "Cloudflare",
    "microsoft-iis": "IIS", "litespeed": "LiteSpeed", "openresty": "OpenResty",
    "caddy": "Caddy", "gws": "Google Web Server"
}
X_POWERED = re.compile(r"([A-Za-z0-9.\-]+)")


class TechAnalyzer(BaseScanner):
    """
    BuiltWith fingerprinting + header-based tech detection.
    The page is downloaded by our own async client (proxy, timeout, stealth
    headers) and handed to BuiltWith, so the library never opens its own
    blocking, timeout-less connection.
    """
    async def execute(self) -> TechResult:
        print(f"[*] TechAnalyzer: Consulting BuiltWith + headers for {self.target}...")

        discovered_tech = set()

        async with AsyncClient(timeout=15, proxy=self.proxy) as client:
            base_url = await client.detect_base_url(self.target)
            if not base_url:
                print(f"[-] TechAnalyzer: {self.target} is unreachable over HTTPS and HTTP.")
                return TechResult(target_domain=self.target, technologies=[])

            status, html, headers = await client.fetch(base_url, return_type="text", max_bytes=3_000_000)

        if headers is not None:
            # 1. BuiltWith signatures (pure regex work, run off the event loop)
            try:
                results = await asyncio.wait_for(
                    asyncio.to_thread(builtwith.builtwith, base_url, headers=headers, html=html or ""),
                    timeout=30.0
                )
                for techs in (results or {}).values():
                    discovered_tech.update(techs)
            except Exception as e:
                print(f"[!] TechAnalyzer: BuiltWith analysis failed: {e}")

            # 2. Header fingerprints (catch what BuiltWith misses)
            discovered_tech.update(self._detect_from_headers(headers))

        final_list = sorted(discovered_tech)

        if final_list:
            print(f"[+] TechAnalyzer: Mapped {len(final_list)} technologies.")
        else:
            print(f"[-] TechAnalyzer: No tech detected (status {status}).")

        return TechResult(
            target_domain=self.target,
            technologies=final_list
        )

    @staticmethod
    def _detect_from_headers(headers) -> set:
        """Detect technology from HTTP response headers."""
        tech = set()
        server = (headers.get("Server") or "").lower()
        x_pwr = headers.get("X-Powered-By") or ""
        for sig, name in SERVER_SIGNATURES.items():
            if sig in server:
                tech.add(name)
                break
        if x_pwr:
            match = X_POWERED.search(x_pwr)
            if match:
                tech.add(match.group(1).strip())
        return tech
