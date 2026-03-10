import asyncio
from typing import List
from core.base import BaseScanner
from models.report import DnsResult
from utils.client import AsyncClient

class DnsScanner(BaseScanner):
    """
    Performs DNS reconnaissance (A, MX, NS, TXT) and checks for missing
    SPF records which could allow email spoofing/phishing.
    """
    async def execute(self) -> DnsResult:
        print(f"[*] DnsScanner: Pulling DNS records and checking SPF for {self.target}...")
        
        # We use HackerTarget's free API to avoid installing massive DNS libraries like dnspython
        url = f"https://api.hackertarget.com/dnslookup/?q={self.target}"
        client = AsyncClient(timeout=10, proxy=self.proxy)
        
        status, data, _ = await client.fetch(url, return_type="text")
        
        a_recs: List[str] = []
        mx_recs: List[str] = []
        txt_recs: List[str] = []
        spoofable = False
        
        # Parse the raw text output from the API
        if status == 200 and "error" not in data.lower():
            lines = data.split('\n')
            for line in lines:
                if not line.strip(): 
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    record_type = parts[1]
                    # We just format it nicely depending on the record type
                    if record_type == "A":
                        a_recs.append(parts[2])
                    elif record_type == "MX":
                        mx_recs.append(f"{parts[2]} (Priority: {parts[3] if len(parts)>3 else 'N/A'})")
                    elif record_type == "TXT":
                        # TXT records can have spaces, so we join the rest
                        txt_recs.append(" ".join(parts[2:]))

        # Vulnerability Check: Is there an SPF record protecting the domain?
        # If not, attackers can send forged emails from admin@target.com
        has_spf = any("v=spf1" in txt for txt in txt_recs)
        if not has_spf:
            spoofable = True

        if a_recs or mx_recs or txt_recs:
            print(f"[+] DnsScanner: DNS records extracted! Spoofable: {spoofable}")
        else:
            print(f"[-] DnsScanner: Failed to extract meaningful DNS records.")

        return DnsResult(
            target_domain=self.target,
            a_records=a_recs,
            mx_records=mx_recs,
            txt_records=txt_recs,
            is_spoofable=spoofable
        )