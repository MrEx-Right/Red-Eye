import asyncio
import socket
import ssl
from typing import List, Set
from core.base import BaseScanner
from utils.client import AsyncClient
from utils.cdn import cdn_from_headers, is_cloudflare_ip
from utils.dns import resolve
from models.report import CdnBypassResult

# Common "leaky" prefixes that admins often forget to route through the CDN/WAF.
LEAKY_PREFIXES = [
    "direct", "origin", "origin-www", "ftp", "cpanel", "mail",
    "dev", "staging", "api", "portal", "webmail", "autodiscover",
]


class OriginIPFinder(BaseScanner):
    """
    Hunts for a target's real origin server IP even when it's hidden behind
    a CDN/WAF (Cloudflare, Akamai, etc). DNS resolution of likely-leaky
    hostnames produces candidates; each candidate is then confirmed with a
    direct TLS handshake (SNI forced to the real domain) and an HTTP request
    proving the answer does not come from yet another CDN edge.
    """

    DIRECT_CONTACT = True  # TLS handshakes go straight to candidate IPs

    async def _resolve_ipv4(self, client: AsyncClient, hostname: str) -> List[str]:
        answer = await resolve(client, hostname, "A")
        if answer is not None:
            return answer.records
        # DoH unreachable: fall back to the system resolver
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(hostname, None, family=socket.AF_INET)
            return sorted({info[4][0] for info in infos})
        except Exception:
            return []

    async def _get_mx_hostname(self, client: AsyncClient) -> str:
        """Grabs the highest-priority MX exchange hostname."""
        answer = await resolve(client, self.zone, "MX")
        if not answer or not answer.records:
            return ""
        best = None
        for record in answer.records:
            priority, _, exchange = record.partition(" ")
            if not exchange:
                continue  # Null MX ('0 .') — domain accepts no mail
            key = int(priority) if priority.isdigit() else 65535
            if best is None or key < best[0]:
                best = (key, exchange)
        return best[1] if best else ""

    async def _confirm_via_cert(self, candidate_ip: str) -> bool:
        """
        Connects directly to candidate_ip on port 443 but forces SNI to the
        real target domain. A successful, chain-validated handshake proves
        this IP holds a valid certificate for the target.
        """
        def fetch_cert():
            ctx = ssl.create_default_context()
            with socket.create_connection((candidate_ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return ssock.getpeercert()

        try:
            cert = await asyncio.to_thread(fetch_cert)
            return bool(cert)
        except Exception:
            return False

    async def _served_by_cdn(self, client: AsyncClient, candidate_ip: str) -> bool:
        """
        A valid cert alone is not proof: a second CDN edge IP serves the same
        certificate. Ask the IP for the site and look for CDN fingerprints.
        """
        _, _, headers = await client.fetch(
            f"https://{candidate_ip}/", headers={"Host": self.host},
            server_hostname=self.host, return_type="none", allow_redirects=False
        )
        return cdn_from_headers(headers) is not None

    async def execute(self) -> CdnBypassResult:
        print(f"[*] OriginIPFinder: Hunting for the real origin IP behind {self.host}...")

        async with AsyncClient(timeout=8, proxy=self.proxy) as client:
            main_ips: Set[str] = set(await self._resolve_ipv4(client, self.host))
            main_ip = sorted(main_ips)[0] if main_ips else ""

            base_url = await client.detect_base_url(self.target)
            headers = None
            if base_url:
                _, _, headers = await client.fetch(base_url, return_type="none")
            cdn_indicator = cdn_from_headers(headers)
            if not cdn_indicator and main_ips and all(is_cloudflare_ip(ip) for ip in main_ips):
                cdn_indicator = "Cloudflare (IP range)"
            behind_cdn = cdn_indicator is not None

            if self.delay > 0:
                await asyncio.sleep(self.delay)

            # --- Lead 1: MX exchange often sits outside the CDN ---
            mx_hostname = await self._get_mx_hostname(client)
            mx_ips = await self._resolve_ipv4(client, mx_hostname) if mx_hostname else []
            mx_ip = mx_ips[0] if mx_ips else ""
            mx_differs = bool(mx_ip and main_ips and mx_ip not in main_ips)

            # --- Lead 2: sweep common leaky subdomains concurrently ---
            candidate_ips: Set[str] = set()
            semaphore = asyncio.Semaphore(8)

            async def check_prefix(prefix: str):
                async with semaphore:
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    for sub_ip in await self._resolve_ipv4(client, f"{prefix}.{self.zone}"):
                        if sub_ip not in main_ips:
                            candidate_ips.add(sub_ip)

            await asyncio.gather(*(check_prefix(p) for p in LEAKY_PREFIXES))

            if mx_differs:
                candidate_ips.add(mx_ip)

            # Other Cloudflare anycast IPs are just more edges, not origins
            cdn_edges = sorted(ip for ip in candidate_ips if is_cloudflare_ip(ip))
            candidate_ips -= set(cdn_edges)

            # --- Confirmation pass: valid cert for the target AND no CDN in front ---
            confirmed_ip = ""
            confirmed_via = ""
            for ip in sorted(candidate_ips):
                if not await self._confirm_via_cert(ip):
                    continue
                if behind_cdn and await self._served_by_cdn(client, ip):
                    cdn_edges.append(ip)
                    continue
                confirmed_ip = ip
                confirmed_via = f"valid TLS certificate for {self.host} served directly by {ip}, no CDN headers"
                break
            candidate_ips -= set(cdn_edges)

        if confirmed_ip and behind_cdn:
            print(f"[+] OriginIPFinder: BYPASS CONFIRMED! Real origin is {confirmed_ip}.")
        elif candidate_ips:
            print(f"[+] OriginIPFinder: Found {len(candidate_ips)} candidate IP(s), none cert-confirmed behind a CDN.")
        else:
            print("[-] OriginIPFinder: No origin bypass candidates found. Target may be fully proxied.")

        return CdnBypassResult(
            target_domain=self.host,
            main_ip=main_ip or "Unresolved",
            behind_cdn=behind_cdn,
            cdn_indicator=cdn_indicator or "None detected",
            mx_hostname=mx_hostname or "None found",
            mx_ip=mx_ip or "Unresolved",
            mx_ip_differs=mx_differs,
            candidate_origin_ips=sorted(candidate_ips),
            cdn_edge_ips=sorted(set(cdn_edges)),
            # A "bypass" only means something when there is a CDN to bypass
            confirmed_origin_ip=confirmed_ip if behind_cdn else "",
            confirmed_via=confirmed_via if behind_cdn else "",
        )
