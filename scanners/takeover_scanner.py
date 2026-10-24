import asyncio
import random
from typing import List, Optional, Tuple
from core.base import BaseScanner
from models.report import TakeoverResult
from utils.client import AsyncClient
from utils.dns import resolve

# service -> (CNAME suffixes that point at it, body signature of an unclaimed resource)
# A signature only counts when the subdomain's CNAME really points at that
# service; matching page text alone produces endless false positives.
SERVICES = {
    "GitHub Pages": ((".github.io",), "There isn't a GitHub Pages site here."),
    "Heroku": ((".herokuapp.com", ".herokudns.com", ".herokussl.com"), "No such app"),
    "AWS S3": ((".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"), "NoSuchBucket"),
    "Azure": ((".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azureedge.net"), "404 Web Site not found"),
    "Ghost": ((".ghost.io",), "The thing you were looking for is no longer here"),
    "Shopify": ((".myshopify.com",), "Sorry, this shop is currently unavailable."),
    "Tumblr": (("domains.tumblr.com",), "Whatever you were looking for doesn't currently exist at this address."),
    "WordPress": ((".wordpress.com",), "Do you want to register"),
    "Pantheon": ((".pantheonsite.io",), "The gods are wise, but do not know of the site which you seek."),
    "Zendesk": ((".zendesk.com",), "Help Center Closed"),
    "Bitbucket": ((".bitbucket.io",), "Repository not found"),
}

# Services where a CNAME to a non-existent resource name is itself claimable
NXDOMAIN_CLAIMABLE = {"Azure", "AWS S3", "Heroku"}


def match_service(cname: str) -> Optional[str]:
    cname = cname.lower()
    for service, (suffixes, _) in SERVICES.items():
        if any(cname.endswith(s) or s in cname for s in suffixes):
            return service
    return None


class TakeoverScanner(BaseScanner):
    """
    Subdomain Takeover Pro: Actively hunts for Dangling DNS and unclaimed
    third-party services (AWS S3, GitHub Pages, Heroku, Azure, etc.).
    Each candidate's CNAME is resolved first; only subdomains pointing at a
    known service are fingerprinted, against that service's own signature.
    """
    async def execute(self) -> TakeoverResult:
        print(f"[*] TakeoverScanner: Hunting for dangling DNS and vulnerable CNAMEs on {self.zone}...")

        # The most common prefixes that companies point to 3rd party cloud services
        # and then forget to delete from their DNS records.
        prefixes = [
            "www", "blog", "shop", "dev", "docs", "help", "support", "api", "cdn",
            "test", "staging", "beta", "info", "app", "mail", "forum", "news",
            "admin", "portal", "status", "web", "promo", "campaign", "assets"
        ]

        vulnerable_subs: List[str] = []
        checked_cnames = 0
        semaphore = asyncio.Semaphore(10 if self.stealth else 30)

        async with AsyncClient(timeout=8, proxy=self.proxy) as client:

            async def check_takeover(prefix: str) -> Tuple[bool, Optional[str]]:
                subdomain = f"{prefix}.{self.zone}"
                async with semaphore:
                    # Tactical Delay / Ghost Mode integration
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    elif self.stealth:
                        await asyncio.sleep(random.uniform(0.5, 2.0))

                    answer = await resolve(client, subdomain, "CNAME")
                    if not answer or not answer.records:
                        return False, None
                    cname = answer.records[0]
                    service = match_service(cname)
                    if not service:
                        return True, None

                    # Dangling: the CNAME target itself no longer exists
                    target_answer = await resolve(client, cname, "A")
                    if target_answer is not None and target_answer.nxdomain and service in NXDOMAIN_CLAIMABLE:
                        return True, f"{subdomain} -> CNAME {cname} (NXDOMAIN) [{service} TAKEOVER POSSIBLE!]"

                    signature = SERVICES[service][1]
                    for scheme in ("https", "http"):
                        status, data, _ = await client.fetch(f"{scheme}://{subdomain}", return_type="text", max_bytes=65536)
                        if status in (0, 408):
                            continue
                        if data and signature in data:
                            return True, f"{subdomain} -> CNAME {cname} [{service} TAKEOVER POSSIBLE!]"
                        break
                    return True, None

            outcomes = await asyncio.gather(*(check_takeover(p) for p in prefixes))

        for has_cname, finding in outcomes:
            checked_cnames += int(has_cname)
            if finding:
                vulnerable_subs.append(finding)

        # Reporting the carnage
        if vulnerable_subs:
            print(f"[!] TakeoverScanner: BINGO! Critical Vulnerability! Found {len(vulnerable_subs)} potential takeovers!")
            for v in vulnerable_subs:
                print(f"  -> {v}")
        else:
            print(f"[-] TakeoverScanner: No takeover candidates among {checked_cnames} CNAME'd subdomains.")

        return TakeoverResult(
            target_domain=self.zone,
            vulnerable_subdomains=sorted(vulnerable_subs),
            checked_cnames=checked_cnames
        )
