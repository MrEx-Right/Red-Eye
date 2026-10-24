import asyncio
import re
import uuid
from typing import List, Optional, Tuple
from core.base import BaseScanner
from models.report import DnsResult
from utils.client import AsyncClient, hackertarget_failed
from utils.dns import resolve


def analyze_spf(txt_records: List[str]) -> Tuple[List[str], List[str]]:
    """Returns (vulnerabilities, info) for the SPF posture of a TXT record set."""
    vulns: List[str] = []
    info: List[str] = []
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]

    if not spf_records:
        vulns.append("MISSING SPF — Domain is vulnerable to email spoofing/phishing.")
        return vulns, info

    if len(spf_records) > 1:
        vulns.append("MULTIPLE SPF RECORDS — RFC 7208 permerror, receivers may ignore SPF entirely.")

    spf = spf_records[0]
    all_mechanism = next((tok for tok in spf.lower().split() if tok.lstrip("+-~?") == "all"), None)
    if all_mechanism in ("all", "+all"):
        vulns.append("DANGEROUS SPF (+all) — Allows any server to send mail as this domain!")
    elif all_mechanism == "?all":
        vulns.append("WEAK SPF (?all) — Neutral policy, spoofed mail is not rejected.")
    elif all_mechanism == "~all":
        info.append("SPF uses ~all (softfail) — Consider upgrading to -all for strict enforcement.")
    elif all_mechanism is None and "redirect=" not in spf.lower():
        info.append("SPF has no 'all' mechanism — unmatched senders default to neutral.")
    info.append(f"SPF Record: {spf[:120]}")
    return vulns, info


def dkim_has_key(record: str) -> bool:
    """An empty 'p=' tag means the key was revoked (RFC 6376 §3.6.1)."""
    return re.search(r"(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/]", record) is not None


def parse_dmarc_policy(record: str) -> str:
    match = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", record, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def parse_axfr(text: Optional[str]) -> Tuple[bool, bool, List[str]]:
    """
    Parses HackerTarget's zonetransfer output (raw dig transcripts).
    Returns (checked, vulnerable, records). A refused transfer prints
    '; Transfer failed.' — only real resource records mean exposure.
    """
    if hackertarget_failed(text):
        return False, False, []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    records = [line for line in lines if not line.startswith(";") and re.search(r"\sIN\s", line)]
    if records:
        return True, True, records
    checked = any("DiG" in line or "Transfer failed" in line for line in lines)
    return checked, False, []


class DnsScanner(BaseScanner):
    """
    Extended DNS Reconnaissance Scanner.

    Performs:
    - A, MX, NS, TXT, CNAME, CAA record enumeration via DNS-over-HTTPS
    - SPF record analysis   → Email spoofing risk
    - DMARC policy check    → p=none / quarantine / reject
    - DKIM selector check   → Common selectors: default, google, mail, k1, ...
    - Zone Transfer attempt → AXFR via HackerTarget's zonetransfer API
    """

    HACKERTARGET_AXFR_URL = "https://api.hackertarget.com/zonetransfer/?q={domain}"

    # Common DKIM selectors to probe
    DKIM_SELECTORS = ["default", "google", "mail", "k1", "s1", "s2", "dkim", "selector1", "selector2"]

    async def _find_dkim(self, client: AsyncClient, result: DnsResult) -> str:
        """
        Probes common DKIM selectors concurrently; returns the first one that
        publishes a usable key. A random selector is probed too, so wildcard
        _domainkey records are not mistaken for real selectors.
        """
        async def probe(selector: str) -> Optional[str]:
            answer = await resolve(client, f"{selector}._domainkey.{self.zone}", "TXT")
            if not answer:
                return None
            return next((r for r in answer.records if "p=" in r), None)

        random_selector = f"redeye{uuid.uuid4().hex[:10]}"
        records = await asyncio.gather(*(probe(s) for s in [random_selector] + self.DKIM_SELECTORS))
        wildcard, selector_records = records[0], records[1:]

        if wildcard is not None:
            if dkim_has_key(wildcard):
                return "* (wildcard record)"
            result.info.append("Wildcard DKIM record with an empty key (p=) — revoked, domain signs no mail.")
            return ""

        for selector, record in zip(self.DKIM_SELECTORS, selector_records):
            if record is not None and dkim_has_key(record):
                return selector
            if record is not None:
                result.info.append(f"DKIM selector '{selector}' has an empty key (revoked).")
        return ""

    async def _check_zone_transfer(self, client: AsyncClient, result: DnsResult) -> None:
        url = self.HACKERTARGET_AXFR_URL.format(domain=self.zone)
        status, data, _ = await client.fetch(url, return_type="text")
        if status != 200:
            return
        checked, vulnerable, records = parse_axfr(data)
        result.zone_transfer_checked = checked
        result.zone_transfer_vulnerable = vulnerable
        result.zone_transfer_data = records[:20]  # Cap output

    async def execute(self) -> DnsResult:
        print(f"[*] DnsScanner: Starting extended DNS reconnaissance for {self.zone}...")

        # Mail-auth and delegation records belong to the zone, not to www.
        result = DnsResult(target_domain=self.zone)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        async with AsyncClient(timeout=12, proxy=self.proxy) as client:
            # ── Step 1: Core DNS record enumeration ──────────────────────────
            rtypes = ["A", "MX", "NS", "TXT", "CNAME", "CAA"]
            # A/CNAME describe the exact host scanned; the rest are zone records
            names = {"A": self.host, "CNAME": self.host}
            answers = dict(zip(rtypes, await asyncio.gather(*(resolve(client, names.get(r, self.zone), r) for r in rtypes))))

            if answers["A"] is None and answers["TXT"] is None:
                print("[-] DnsScanner: DNS-over-HTTPS resolvers unreachable. Skipping DNS checks.")
                result.info.append("DNS lookups failed — no checks were performed.")
                return result

            result.a_records = answers["A"].records if answers["A"] else []
            result.ns_records = answers["NS"].records if answers["NS"] else []
            result.txt_records = answers["TXT"].records if answers["TXT"] else []
            result.cname_records = answers["CNAME"].records if answers["CNAME"] else []
            result.caa_records = answers["CAA"].records if answers["CAA"] else []
            if answers["MX"]:
                # Lowest preference value first, like a mail server would try them
                for mx in sorted(answers["MX"].records, key=lambda r: int(r.split(" ")[0]) if r.split(" ")[0].isdigit() else 65535):
                    priority, _, exchange = mx.partition(" ")
                    if not exchange.strip():
                        result.info.append("Null MX (RFC 7505) — domain explicitly accepts no mail.")
                        continue
                    result.mx_records.append(f"{exchange.strip()} (Priority: {priority})")

            if answers["A"] and answers["A"].nxdomain:
                result.info.append("Domain does not exist (NXDOMAIN).")

            print(f"[+] DnsScanner: Records — A:{len(result.a_records)} MX:{len(result.mx_records)} NS:{len(result.ns_records)} TXT:{len(result.txt_records)}")

            # ── Step 2: SPF Analysis ─────────────────────────────────────────
            if answers["TXT"] is not None:
                result.spf_checked = True
                spf_vulns, spf_info = analyze_spf(result.txt_records)
                result.is_spoofable = any(v.startswith(("MISSING SPF", "DANGEROUS SPF")) for v in spf_vulns)
                result.vulnerabilities.extend(spf_vulns)
                result.info.extend(spf_info)
            else:
                result.info.append("TXT lookup failed — SPF not evaluated.")

            # ── Step 3: DMARC Policy Check ───────────────────────────────────
            dmarc = await resolve(client, f"_dmarc.{self.zone}", "TXT")
            if dmarc is None:
                result.info.append("DMARC lookup failed — policy not evaluated.")
            else:
                result.dmarc_checked = True
                record = next((r for r in dmarc.records if r.lower().startswith("v=dmarc1")), "")
                if record:
                    result.has_dmarc = True
                    result.dmarc_policy = parse_dmarc_policy(record)
                    if result.dmarc_policy == "none":
                        result.vulnerabilities.append("DMARC p=none — Reports only, no enforcement. Spoofed emails still delivered.")
                    elif result.dmarc_policy == "quarantine":
                        result.info.append("DMARC p=quarantine — Suspicious emails go to spam.")
                    elif result.dmarc_policy == "reject":
                        result.info.append("DMARC p=reject — Strict enforcement active. ✓")
                    else:
                        result.vulnerabilities.append(f"DMARC p={result.dmarc_policy} — Unknown policy value, receivers fall back to none.")
                else:
                    result.vulnerabilities.append("MISSING DMARC — No DMARC policy. Email fraud risk is elevated.")

            # ── Step 4: DKIM selector probe ──────────────────────────────────
            result.dkim_selector = await self._find_dkim(client, result)
            result.has_dkim = bool(result.dkim_selector)
            if not result.has_dkim and result.mx_records:
                result.info.append(f"DKIM not found on {len(self.DKIM_SELECTORS)} common selectors (custom selectors may exist).")

            # ── Step 5: Zone Transfer Attempt ────────────────────────────────
            await self._check_zone_transfer(client, result)
            if result.zone_transfer_vulnerable:
                result.vulnerabilities.append(
                    "ZONE TRANSFER ALLOWED (AXFR) — DNS server exposes full zone data to any requestor!"
                )
            elif not result.zone_transfer_checked:
                result.info.append("Zone transfer check unavailable (HackerTarget error or quota).")

        print(
            "[+] DnsScanner: Analysis complete. "
            f"Vulnerabilities: {len(result.vulnerabilities)}, "
            f"DMARC: {result.has_dmarc} (p={result.dmarc_policy}), "
            f"DKIM: {result.has_dkim}"
        )

        return result
