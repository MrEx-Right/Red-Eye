import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlencode
from utils.client import AsyncClient

# DNS-over-HTTPS JSON endpoints. Unlike HackerTarget they accept service
# labels (_dmarc, _domainkey), have no daily quota, and their traffic goes
# through the user's proxy like every other HTTP request.
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

_TXT_SEGMENT = re.compile(r'"((?:[^"\\]|\\.)*)"')


@dataclass
class DnsAnswer:
    rcode: int
    records: List[str] = field(default_factory=list)

    @property
    def nxdomain(self) -> bool:
        return self.rcode == RCODE_NXDOMAIN


def _clean_record(data: str, rtype: str) -> str:
    data = data.strip()
    if rtype == "TXT":
        # Long TXT records arrive split into quoted chunks: "v=spf1 ..." "... -all"
        segments = _TXT_SEGMENT.findall(data)
        return "".join(segments) if segments else data.strip('"')
    if rtype in ("NS", "CNAME", "MX"):
        return data.rstrip(".")
    return data


async def resolve(client: AsyncClient, name: str, rtype: str) -> Optional[DnsAnswer]:
    """
    Resolves `name` over DoH. Returns a DnsAnswer for NOERROR/NXDOMAIN
    (records may be empty), or None when every resolver failed — callers
    must treat None as "unknown", never as "record missing".
    """
    wanted = RTYPES[rtype]
    for endpoint in DOH_ENDPOINTS:
        url = f"{endpoint}?{urlencode({'name': name, 'type': rtype})}"
        status, data, _ = await client.fetch(url, headers={"Accept": "application/dns-json"}, return_type="json")
        if status != 200 or not isinstance(data, dict):
            continue
        rcode = data.get("Status")
        if rcode not in (RCODE_NOERROR, RCODE_NXDOMAIN):
            continue  # SERVFAIL / REFUSED — try the next resolver
        records = [
            _clean_record(str(answer.get("data", "")), rtype)
            for answer in data.get("Answer", []) or []
            if answer.get("type") == wanted
        ]
        return DnsAnswer(rcode=rcode, records=records)
    return None
