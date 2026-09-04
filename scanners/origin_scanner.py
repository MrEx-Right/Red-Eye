import asyncio
import socket
import ssl
from typing import Tuple
from core.base import BaseScanner
from utils.client import AsyncClient
from models.report import CdnBypassResult

# Common "leaky" prefixes that admins often forget to route through the CDN/WAF.
LEAKY_PREFIXES = [
    "direct", "origin", "origin-www", "ftp", "cpanel", "mail",
    "dev", "staging", "api", "portal", "webmail", "autodiscover",
]

CDN_SERVER_HINTS = ("cloudflare", "cloudfront", "akamai", "fastly", "sucuri", "incapsula")


class OriginIPFinder(BaseScanner):
    """
    Hunts for a target's real origin server IP even when it's hidden behind
    a CDN/WAF (Cloudflare, Akamai, etc). Every technique used here is purely
    passive: DNS resolution of likely-leaky hostnames, then a TLS handshake
    (forcing SNI to the real domain) to confirm a candidate IP genuinely
    serves the target's own certificate.
    """

    async def _resolve(self, hostname: str) -> str:
        """Resolve a hostname to its first A-record IP. Empty string on failure."""
        loop = asyncio.get_event_loop()
        try:
            addr_info = await loop.getaddrinfo(hostname, None)
            return addr_info[0][4][0]
        except Exception:
            return ""

    async def _detect_cdn(self, client: AsyncClient) -> Tuple[bool, str]:
        """Lightweight CDN/WAF fingerprint via response headers."""
        _, _, headers = await client.fetch(f"https://{self.target}")
        if not headers:
            return False, "None detected"

        server_header = headers.get("Server", "").lower()
        header_keys = [k.lower() for k in headers.keys()]

        if "cf-ray" in header_keys or "cloudflare" in server_header:
            return True, "Cloudflare (cf-ray/Server header)"
        for hint in CDN_SERVER_HINTS:
            if hint in server_header:
                return True, f"{hint.capitalize()} (Server header)"
        return False, "None detected"

    async def _get_mx_hostname(self, client: AsyncClient) -> str:
        """Grabs the first MX exchange hostname via HackerTarget's free DNS API."""
        url = f"https://api.hackertarget.com/dnslookup/?q={self.target}"
        status, data, _ = await client.fetch(url, return_type="text")
        if status != 200 or not data or "error" in data.lower()[:30]:
            return ""

        for line in data.split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[1].upper() == "MX":
                return parts[3].rstrip(".")
        return ""

    async def _confirm_via_cert(self, candidate_ip: str) -> bool:
        """
        Connects directly to candidate_ip on port 443 but forces SNI to the
        real target domain. A successful, chain-validated handshake proves
        this IP genuinely serves the target's own certificate — not just
        some unrelated host that happened to resolve on a leaky subdomain.
        """
        def fetch_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((candidate_ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    return ssock.getpeercert()

        try:
            cert = await asyncio.to_thread(fetch_cert)
            return bool(cert)
        except Exception:
            return False

    async def execute(self) -> CdnBypassResult:
        print(f"[*] OriginIPFinder: Hunting for the real origin IP behind {self.target}...")
        client = AsyncClient(timeout=8, proxy=self.proxy)

        main_ip = await self._resolve(self.target)
        behind_cdn, cdn_indicator = await self._detect_cdn(client)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # --- Lead 1: MX exchange often sits outside the CDN ---
        mx_hostname = await self._get_mx_hostname(client)
        mx_ip = await self._resolve(mx_hostname) if mx_hostname else ""
        mx_differs = bool(mx_ip and main_ip and mx_ip != main_ip)

        # --- Lead 2: sweep common leaky subdomains concurrently ---
        candidate_ips = set()
        semaphore = asyncio.Semaphore(8)

        async def check_prefix(prefix: str):
            async with semaphore:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                sub_ip = await self._resolve(f"{prefix}.{self.target}")
                if sub_ip and sub_ip != main_ip:
                    candidate_ips.add(sub_ip)

        tasks = [check_prefix(p) for p in LEAKY_PREFIXES]
        await asyncio.gather(*tasks)

        if mx_differs:
            candidate_ips.add(mx_ip)

        # --- Confirmation pass: does any candidate actually serve the target's cert? ---
        confirmed_ip = ""
        confirmed_via = ""
        for ip in sorted(candidate_ips):
            if await self._confirm_via_cert(ip):
                confirmed_ip = ip
                confirmed_via = f"TLS certificate for {self.target} served directly by {ip}"
                break

        if confirmed_ip:
            print(f"[+] OriginIPFinder: BYPASS CONFIRMED! Real origin is {confirmed_ip}.")
        elif candidate_ips:
            print(f"[+] OriginIPFinder: Found {len(candidate_ips)} candidate IP(s), none cert-confirmed.")
        else:
            print(f"[-] OriginIPFinder: No origin bypass candidates found. Target may be fully proxied.")

        return CdnBypassResult(
            target_domain=self.target,
            main_ip=main_ip or "Unresolved",
            behind_cdn=behind_cdn,
            cdn_indicator=cdn_indicator,
            mx_hostname=mx_hostname or "None found",
            mx_ip=mx_ip or "Unresolved",
            mx_ip_differs=mx_differs,
            candidate_origin_ips=sorted(candidate_ips),
            confirmed_origin_ip=confirmed_ip,
            confirmed_via=confirmed_via
        )
