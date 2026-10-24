import asyncio
from core.base import BaseScanner
from models.report import BreachResult
from utils.client import AsyncClient

class BreachScanner(BaseScanner):
    """
    Breach & Leak Intelligence. Queries Have I Been Pwned's public breach
    catalogue (no API key needed) for breaches of services hosted on the
    target's domain. A failed lookup is reported as such — never as "clean".
    """

    HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches?domain={domain}"

    async def execute(self) -> BreachResult:
        domain = self.zone
        print(f"[*] BreachScanner: Checking public breach records for {domain}...")

        result = BreachResult(target_domain=domain)

        # Enforce stealth mode delays if configured
        if self.delay > 0:
            await asyncio.sleep(self.delay)

        client = AsyncClient(timeout=15, proxy=self.proxy)
        # HIBP requires a descriptive User-Agent and rejects generic ones
        status, data, _ = await client.fetch(
            self.HIBP_URL.format(domain=domain),
            headers={"User-Agent": "RedEye-OSINT-Framework"},
            return_type="json"
        )

        if status == 200 and isinstance(data, list):
            result.lookup_ok = True
            breaches = sorted(data, key=lambda b: b.get("BreachDate", ""), reverse=True)
            for breach in breaches[:10]:  # Cap at 10 to avoid terminal flood
                title = breach.get("Title") or breach.get("Name", "Unknown DB")
                date = breach.get("BreachDate", "Unknown Date")
                pwned = breach.get("PwnCount")
                classes = ", ".join(breach.get("DataClasses", [])[:4])
                line = f"{title} ({date})"
                if isinstance(pwned, int):
                    line += f" — {pwned:,} accounts"
                if classes:
                    line += f" [{classes}]"
                result.breaches_found.append(line)
            result.total_leaks = len(data)
        else:
            result.error = f"HIBP lookup failed (HTTP {status})" if status else "HIBP unreachable"

        if not result.lookup_ok:
            print(f"[!] BreachScanner: {result.error}")
        elif result.total_leaks:
            print(f"[+] BreachScanner: {result.total_leaks} public breach(es) recorded for {domain}.")
        else:
            print(f"[-] BreachScanner: No public breaches recorded for {domain}.")

        return result
