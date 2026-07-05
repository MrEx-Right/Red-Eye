import asyncio
import re
from typing import Optional
from core.base import BaseScanner
from utils.client import AsyncClient


class WhoisResult:
    """Holds WHOIS intelligence data for a target domain."""
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.registrar: str = "Unknown"
        self.registrant_org: str = "Unknown"
        self.registrant_country: str = "Unknown"
        self.creation_date: str = "Unknown"
        self.expiry_date: str = "Unknown"
        self.updated_date: str = "Unknown"
        self.name_servers: list = []
        self.status: list = []
        self.dnssec: str = "Unknown"
        self.is_expired: bool = False
        self.is_expiring_soon: bool = False  # < 30 days
        self.privacy_protected: bool = False
        self.raw_whois: str = ""


class WhoisScanner(BaseScanner):
    """
    WHOIS Intelligence Scanner — retrieves domain registration metadata
    using the WhoisXML API (free tier) and HackerTarget WHOIS as fallback.

    Extracts:
    - Registrar, registrant org/country
    - Creation, expiry, and update dates
    - Name servers (NS records)
    - Domain status flags (clientDeleteProhibited, etc.)
    - DNSSEC status
    - Privacy protection detection
    - Expiry warnings (domain expiring within 30 days)
    """

    # HackerTarget offers free WHOIS lookups — no API key required
    HACKERTARGET_URL = "https://api.hackertarget.com/whois/?q={domain}"

    # Field patterns to extract from raw WHOIS text
    FIELD_PATTERNS = {
        "registrar":          r"(?:Registrar|registrar):\s*(.+)",
        "registrant_org":     r"(?:Registrant Organization|org):\s*(.+)",
        "registrant_country": r"(?:Registrant Country|country):\s*(.+)",
        "creation_date":      r"(?:Creation Date|created):\s*(.+)",
        "expiry_date":        r"(?:Registry Expiry Date|Expiry Date|expires):\s*(.+)",
        "updated_date":       r"(?:Updated Date|last-modified):\s*(.+)",
        "dnssec":             r"DNSSEC:\s*(.+)",
    }

    PRIVACY_KEYWORDS = [
        "privacy", "redacted", "whoisguard", "domains by proxy",
        "perfect privacy", "withheld", "data protected"
    ]

    def _parse_whois(self, raw: str, result: WhoisResult) -> None:
        """Parse raw WHOIS text into structured fields."""
        result.raw_whois = raw

        for field, pattern in self.FIELD_PATTERNS.items():
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                setattr(result, field, value)

        # Name servers — can appear multiple times
        ns_matches = re.findall(r"(?:Name Server|nserver):\s*(.+)", raw, re.IGNORECASE)
        result.name_servers = list({ns.strip().lower() for ns in ns_matches if ns.strip()})

        # Domain status flags
        status_matches = re.findall(r"(?:Domain Status|status):\s*(.+)", raw, re.IGNORECASE)
        result.status = [s.strip() for s in status_matches if s.strip()]

        # Privacy protection detection
        raw_lower = raw.lower()
        result.privacy_protected = any(kw in raw_lower for kw in self.PRIVACY_KEYWORDS)

        # Expiry checks
        if result.expiry_date and result.expiry_date != "Unknown":
            try:
                from datetime import datetime, timezone
                # Handle multiple date formats
                for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S.%fZ"):
                    try:
                        expiry_dt = datetime.strptime(result.expiry_date[:25].strip(), fmt)
                        now = datetime.utcnow()
                        days_left = (expiry_dt - now).days
                        if days_left < 0:
                            result.is_expired = True
                        elif days_left <= 30:
                            result.is_expiring_soon = True
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

    async def execute(self) -> WhoisResult:
        print(f"[*] WhoisScanner: Querying WHOIS intelligence for {self.target}...")

        result = WhoisResult(self.target)
        client = AsyncClient(timeout=15, proxy=self.proxy)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # Primary source: HackerTarget WHOIS (free, no key)
        url = self.HACKERTARGET_URL.format(domain=self.target)
        status, data, _ = await client.fetch(url, return_type="text")

        if status == 200 and data and "error" not in data.lower()[:50]:
            self._parse_whois(data, result)
            print(
                f"[+] WhoisScanner: WHOIS data retrieved. "
                f"Registrar: {result.registrar}, "
                f"Expires: {result.expiry_date}, "
                f"Privacy: {result.privacy_protected}"
            )
        else:
            # Fallback: rdap.org provides RDAP (modern WHOIS) as JSON — no key needed
            print(f"[*] WhoisScanner: HackerTarget failed (status {status}), trying RDAP fallback...")
            rdap_url = f"https://rdap.org/domain/{self.target}"
            r_status, r_data, _ = await client.fetch(rdap_url, return_type="json")

            if r_status == 200 and isinstance(r_data, dict):
                # Parse RDAP response
                result.registrar = r_data.get("registrarName", "Unknown")
                result.dnssec    = "signedDelegation" if r_data.get("secureDNS", {}).get("delegationSigned") else "unsigned"

                for event in r_data.get("events", []):
                    action = event.get("eventAction", "")
                    date   = event.get("eventDate", "")[:10]
                    if action == "registration":
                        result.creation_date = date
                    elif action == "expiration":
                        result.expiry_date = date
                    elif action == "last changed":
                        result.updated_date = date

                for ns in r_data.get("nameservers", []):
                    result.name_servers.append(ns.get("ldhName", "").lower())

                for entity in r_data.get("entities", []):
                    for vcard in entity.get("vcardArray", [[]]):
                        for item in (vcard if isinstance(vcard, list) else []):
                            if isinstance(item, list) and item[0] == "org":
                                result.registrant_org = item[-1]
                            if isinstance(item, list) and item[0] == "adr":
                                addr = item[-1]
                                if isinstance(addr, list) and len(addr) >= 6:
                                    result.registrant_country = addr[-1]

                print(f"[+] WhoisScanner: RDAP data retrieved for {self.target}.")
            else:
                print(f"[-] WhoisScanner: All sources failed for {self.target}.")

        return result
