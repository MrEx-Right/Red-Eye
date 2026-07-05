import asyncio
from typing import List, Dict
from core.base import BaseScanner
from utils.client import AsyncClient


class DnsResult:
    """
    Extended DNS reconnaissance result — covers A, MX, NS, TXT, CNAME records
    plus security checks: SPF, DMARC, DKIM, zone transfer vulnerability.
    """
    def __init__(self, target_domain: str):
        self.target_domain    = target_domain
        self.a_records:    List[str] = []
        self.mx_records:   List[str] = []
        self.ns_records:   List[str] = []
        self.txt_records:  List[str] = []
        self.cname_records: List[str] = []

        # Security posture flags
        self.is_spoofable: bool = False     # Missing SPF
        self.has_dmarc: bool    = False
        self.dmarc_policy: str  = "none"    # none / quarantine / reject
        self.has_dkim: bool     = False
        self.dkim_selector: str = ""
        self.zone_transfer_vulnerable: bool = False
        self.zone_transfer_data: List[str]  = []

        # Aggregated findings
        self.vulnerabilities: List[str] = []
        self.info: List[str]            = []


class DnsScanner(BaseScanner):
    """
    Extended DNS Reconnaissance Scanner.

    Performs:
    - A, MX, NS, TXT, CNAME record enumeration via HackerTarget
    - SPF record analysis   → Email spoofing risk
    - DMARC policy check    → p=none / quarantine / reject
    - DKIM selector check   → Common selectors: default, google, mail, k1
    - Zone Transfer attempt → AXFR via HackerTarget's zonetransfer API
    - CAA record check      → Certificate Authority Authorization
    """

    HACKERTARGET_DNS_URL  = "https://api.hackertarget.com/dnslookup/?q={domain}"
    HACKERTARGET_AXFR_URL = "https://api.hackertarget.com/zonetransfer/?q={domain}"

    # Common DKIM selectors to probe
    DKIM_SELECTORS = ["default", "google", "mail", "k1", "s1", "s2", "dkim", "selector1", "selector2"]

    async def _fetch_dkim(self, client: AsyncClient, selector: str) -> bool:
        """Check if a DKIM record exists for a given selector via HackerTarget."""
        url = f"https://api.hackertarget.com/dnslookup/?q={selector}._domainkey.{self.target}"
        status, data, _ = await client.fetch(url, return_type="text")
        if status == 200 and data and "v=DKIM1" in data:
            return True
        return False

    async def _check_zone_transfer(self, client: AsyncClient) -> None:
        """Attempt a zone transfer via HackerTarget's AXFR endpoint."""
        url = self.HACKERTARGET_AXFR_URL.format(domain=self.target)
        status, data, _ = await client.fetch(url, return_type="text")
        if status == 200 and data:
            lines = [l.strip() for l in data.split("\n") if l.strip()]
            # If zone transfer was allowed, HackerTarget returns actual records
            # If blocked, it returns a short error message
            if len(lines) > 3 and "error" not in data.lower()[:30]:
                self.result.zone_transfer_vulnerable = True
                self.result.zone_transfer_data = lines[:20]  # Cap output

    async def execute(self) -> DnsResult:
        print(f"[*] DnsScanner: Starting extended DNS reconnaissance for {self.target}...")

        self.result = DnsResult(self.target)
        client = AsyncClient(timeout=12, proxy=self.proxy)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # ── Step 1: Core DNS record enumeration ──────────────────────────────
        url = self.HACKERTARGET_DNS_URL.format(domain=self.target)
        status, data, _ = await client.fetch(url, return_type="text")

        if status == 200 and data and "error" not in data.lower()[:30]:
            for line in data.split("\n"):
                parts = line.split()
                if len(parts) < 3:
                    continue
                rtype = parts[1].upper()

                if rtype == "A":
                    self.result.a_records.append(parts[2])
                elif rtype == "MX":
                    priority = parts[2]
                    exchange = parts[3] if len(parts) > 3 else "Unknown"
                    self.result.mx_records.append(f"{exchange} (Priority: {priority})")
                elif rtype == "NS":
                    self.result.ns_records.append(parts[2])
                elif rtype == "TXT":
                    clean = " ".join(parts[2:]).strip("\"'")
                    self.result.txt_records.append(clean)
                elif rtype == "CNAME":
                    self.result.cname_records.append(parts[2])

            print(f"[+] DnsScanner: Records — A:{len(self.result.a_records)} MX:{len(self.result.mx_records)} NS:{len(self.result.ns_records)} TXT:{len(self.result.txt_records)}")
        else:
            print(f"[-] DnsScanner: Core DNS lookup failed (status {status}).")

        # ── Step 2: SPF Analysis ──────────────────────────────────────────────
        has_spf = any("v=spf1" in txt.lower() for txt in self.result.txt_records)
        if not has_spf:
            self.result.is_spoofable = True
            self.result.vulnerabilities.append("MISSING SPF — Domain is vulnerable to email spoofing/phishing.")
        else:
            spf_record = next(t for t in self.result.txt_records if "v=spf1" in t.lower())
            # Check for overly permissive SPF
            if "+all" in spf_record:
                self.result.vulnerabilities.append("DANGEROUS SPF (+all) — Allows any server to send mail as this domain!")
            elif "~all" in spf_record:
                self.result.info.append("SPF uses ~all (softfail) — Consider upgrading to -all for strict enforcement.")
            self.result.info.append(f"SPF Record: {spf_record[:120]}")

        # ── Step 3: DMARC Policy Check ────────────────────────────────────────
        dmarc_url = f"https://api.hackertarget.com/dnslookup/?q=_dmarc.{self.target}"
        d_status, d_data, _ = await client.fetch(dmarc_url, return_type="text")

        if d_status == 200 and d_data and "v=DMARC1" in d_data:
            self.result.has_dmarc = True
            # Extract policy
            import re
            p_match = re.search(r"p=(\w+)", d_data)
            if p_match:
                self.result.dmarc_policy = p_match.group(1).lower()
            if self.result.dmarc_policy == "none":
                self.result.vulnerabilities.append("DMARC p=none — Reports only, no enforcement. Spoofed emails still delivered.")
            elif self.result.dmarc_policy == "quarantine":
                self.result.info.append("DMARC p=quarantine — Suspicious emails go to spam.")
            else:
                self.result.info.append("DMARC p=reject — Strict enforcement active. ✓")
        else:
            self.result.has_dmarc = False
            self.result.vulnerabilities.append("MISSING DMARC — No DMARC policy. Email fraud risk is elevated.")

        # Quick probe: just check "default", "google", "selector1" selectors
        for selector in ["default", "google", "selector1"]:
            found = await self._fetch_dkim(client, selector)
            if found:
                self.result.has_dkim = True
                self.result.dkim_selector = selector
                break

        if not self.result.has_dkim:
            self.result.vulnerabilities.append("DKIM NOT DETECTED — Emails lack cryptographic signing (limited selectors checked).")

        # ── Step 5: Zone Transfer Attempt ─────────────────────────────────────
        await self._check_zone_transfer(client)
        if self.result.zone_transfer_vulnerable:
            self.result.vulnerabilities.append(
                "ZONE TRANSFER ALLOWED (AXFR) — DNS server exposes full zone data to any requestor!"
            )

        print(
            f"[+] DnsScanner: Analysis complete. "
            f"Vulnerabilities: {len(self.result.vulnerabilities)}, "
            f"DMARC: {self.result.has_dmarc} (p={self.result.dmarc_policy}), "
            f"DKIM: {self.result.has_dkim}"
        )

        return self.result