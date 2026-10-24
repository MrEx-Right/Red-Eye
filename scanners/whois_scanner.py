import asyncio
import re
from datetime import datetime, timezone
from typing import Optional
from core.base import BaseScanner
from models.report import WhoisResult
from utils.client import AsyncClient, hackertarget_failed


def parse_date(value: str) -> Optional[datetime]:
    """Parses the date formats registries actually use into an aware UTC datetime."""
    value = value.strip()
    if not value or value == "Unknown":
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
        for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d"):
            try:
                parsed = datetime.strptime(value[:11].strip(), fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class WhoisScanner(BaseScanner):
    """
    WHOIS Intelligence Scanner — retrieves domain registration metadata
    from RDAP (the structured successor of WHOIS, via rdap.org) with the
    HackerTarget text WHOIS as fallback. No API key required.

    Extracts:
    - Registrar, registrant org/country
    - Creation, expiry, and update dates
    - Name servers (NS records)
    - Domain status flags (clientDeleteProhibited, etc.)
    - DNSSEC status
    - Privacy protection detection
    - Expiry warnings (domain expiring within 30 days)
    """

    RDAP_URL = "https://rdap.org/domain/{domain}"
    HACKERTARGET_URL = "https://api.hackertarget.com/whois/?q={domain}"

    # Field patterns to extract from raw WHOIS text (anchored to line starts)
    FIELD_PATTERNS = {
        "registrar":          r"^\s*(?:Registrar|Sponsoring Registrar|registrar):\s*(.+)$",
        "registrant_org":     r"^\s*(?:Registrant Organization|org):\s*(.+)$",
        "registrant_country": r"^\s*(?:Registrant Country|country):\s*(.+)$",
        "creation_date":      r"^\s*(?:Creation Date|created):\s*(.+)$",
        "expiry_date":        r"^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|expires):\s*(.+)$",
        "updated_date":       r"^\s*(?:Updated Date|last-modified):\s*(.+)$",
        "dnssec":             r"^\s*DNSSEC:\s*(.+)$",
    }

    PRIVACY_KEYWORDS = [
        "privacy", "redacted", "whoisguard", "domains by proxy",
        "perfect privacy", "withheld", "data protected"
    ]

    def _evaluate_expiry(self, result: WhoisResult) -> None:
        expiry = parse_date(result.expiry_date)
        if expiry is None:
            return
        days_left = (expiry - datetime.now(timezone.utc)).days
        result.is_expired = days_left < 0
        result.is_expiring_soon = 0 <= days_left <= 30

    def _parse_whois(self, raw: str, result: WhoisResult) -> None:
        """Parse raw WHOIS text into structured fields."""
        result.raw_whois = raw

        for field_name, pattern in self.FIELD_PATTERNS.items():
            match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
            if match:
                setattr(result, field_name, match.group(1).strip())

        # Name servers — can appear multiple times
        ns_matches = re.findall(r"^\s*(?:Name Server|nserver):\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
        result.name_servers = sorted({ns.strip().lower() for ns in ns_matches if ns.strip()})

        # Domain status flags
        status_matches = re.findall(r"^\s*(?:Domain Status|status):\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
        result.status = list(dict.fromkeys(s.strip().split(" ")[0] for s in status_matches if s.strip()))

        # Privacy protection detection
        raw_lower = raw.lower()
        result.privacy_protected = any(kw in raw_lower for kw in self.PRIVACY_KEYWORDS)

    @staticmethod
    def _vcard_value(entity: dict, prop: str):
        vcard = entity.get("vcardArray") or []
        if len(vcard) < 2 or not isinstance(vcard[1], list):
            return None
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == prop:
                return item[3]
        return None

    def _parse_rdap(self, data: dict, result: WhoisResult) -> None:
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")
            if action == "registration":
                result.creation_date = date
            elif action == "expiration":
                result.expiry_date = date
            elif action == "last changed":
                result.updated_date = date

        result.name_servers = sorted({ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) if ns.get("ldhName")})
        result.status = list(data.get("status", []))
        result.dnssec = "signedDelegation" if data.get("secureDNS", {}).get("delegationSigned") else "unsigned"

        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                result.registrar = self._vcard_value(entity, "fn") or result.registrar
            if "registrant" in roles:
                org = self._vcard_value(entity, "org") or self._vcard_value(entity, "fn")
                if org:
                    result.registrant_org = org if isinstance(org, str) else str(org)
                adr = self._vcard_value(entity, "adr")
                if isinstance(adr, list) and adr and adr[-1]:
                    result.registrant_country = str(adr[-1])

        blob = str(data).lower()
        result.privacy_protected = any(kw in blob for kw in self.PRIVACY_KEYWORDS)

    async def execute(self) -> WhoisResult:
        domain = self.zone
        print(f"[*] WhoisScanner: Querying WHOIS intelligence for {domain}...")

        result = WhoisResult(target_domain=domain)
        client = AsyncClient(timeout=15, proxy=self.proxy)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # Primary source: RDAP — structured JSON, no quota
        r_status, r_data, _ = await client.fetch(self.RDAP_URL.format(domain=domain), return_type="json")
        if r_status == 200 and isinstance(r_data, dict) and r_data.get("objectClassName") == "domain":
            self._parse_rdap(r_data, result)
            result.source = "RDAP (rdap.org)"
        else:
            # Fallback: HackerTarget text WHOIS (free, rate limited)
            print(f"[*] WhoisScanner: RDAP failed (status {r_status}), trying HackerTarget fallback...")
            status, data, _ = await client.fetch(self.HACKERTARGET_URL.format(domain=domain), return_type="text")
            if status == 200 and not hackertarget_failed(data):
                self._parse_whois(data, result)
                result.source = "WHOIS (HackerTarget)"

        if result.source:
            self._evaluate_expiry(result)
            print(
                f"[+] WhoisScanner: {result.source} data retrieved. "
                f"Registrar: {result.registrar}, "
                f"Expires: {result.expiry_date}, "
                f"Privacy: {result.privacy_protected}"
            )
        else:
            print(f"[-] WhoisScanner: All sources failed for {domain}.")

        return result
