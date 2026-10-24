import asyncio
import socket
from typing import List
from core.base import BaseScanner
from utils.client import AsyncClient
from utils.domain import base_name, is_ip
from models.report import CloudResult

class CloudDetector(BaseScanner):
    """
    Identifies the underlying cloud infrastructure (AWS, Azure, GCP, Cloudflare)
    using HTTP Header analysis and Reverse DNS (PTR) lookups.
    Also vigorously hunts for exposed Amazon S3 buckets.
    """
    async def get_reverse_dns(self, target: str) -> str:
        """Attempts to resolve the IP to a hostname to detect cloud ranges."""
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(target, None)
            ip_address = addr_info[0][4][0]
            hostname_info = await loop.run_in_executor(None, socket.gethostbyaddr, ip_address)
            return hostname_info[0].lower()
        except Exception:
            return ""

    async def execute(self) -> CloudResult:
        provider = "Unknown"
        is_cf = False
        found_buckets: List[str] = []

        print(f"[*] CloudDetector: Analyzing infrastructure and IP footprint for {self.host}...")

        async with AsyncClient(timeout=8, proxy=self.proxy) as client:
            # --- Phase 1: Header & Infrastructure Analysis ---
            headers = None
            base_url = await client.detect_base_url(self.target)
            if base_url:
                _, _, headers = await client.fetch(base_url, return_type="none")

            ptr_record = await self.get_reverse_dns(self.host)

            if ptr_record:
                if "amazonaws.com" in ptr_record:
                    provider = "Amazon Web Services (AWS)"
                elif "1e100.net" in ptr_record or "googleusercontent.com" in ptr_record:
                    provider = "Google Cloud Platform (GCP)"
                elif "cloudapp.net" in ptr_record or "azure.com" in ptr_record:
                    provider = "Microsoft Azure"

            if headers:
                server_header = headers.get("Server", "").lower()
                header_keys = [k.lower() for k in headers.keys()]
                if "cloudflare" in server_header or "cf-ray" in header_keys:
                    is_cf = True
                    provider = "Cloudflare (WAF/CDN Proxy)"
                elif provider == "Unknown":
                    if "awselb" in server_header or any(k.startswith("x-amz") for k in header_keys):
                        provider = "Amazon Web Services (AWS)"
                    elif "azure" in server_header or any(k.startswith("x-ms-") for k in header_keys):
                        provider = "Microsoft Azure"
                    elif server_header in ("gws", "google frontend") or "x-cloud-trace-context" in header_keys:
                        provider = "Google Cloud Platform (GCP)"

            if provider != "Unknown":
                print(f"[+] CloudDetector: Target infrastructure resolved to: {provider}")
            else:
                print("[-] CloudDetector: Infrastructure masked or self-hosted. Could not fingerprint provider.")

            # --- Phase 2: S3 Bucket Bruteforcing ---
            # Bucket names derive from the organisation keyword, which an IP does not have.
            if "Azure" not in provider and "Google" not in provider and not is_ip(self.host):
                print("[*] CloudDetector: Hunting for exposed S3 buckets...")

                org = base_name(self.host)
                bucket_permutations = sorted({
                    self.host,
                    self.host.replace(".", "-"),
                    org,
                    f"{org}-assets",
                    f"{org}-media",
                    f"{org}-public",
                    f"{org}-backup",
                    f"{org}-dev",
                })

                # S3 isteklerini 4'er 4'er atıyoruz ki soket şişmesin.
                semaphore = asyncio.Semaphore(4)

                async def check_bucket(bucket_name: str):
                    async with semaphore:
                        b_url = f"https://{bucket_name}.s3.amazonaws.com"
                        b_status, body, _ = await client.fetch(b_url, return_type="text", max_bytes=4096)

                        if b_status == 200 and body and "<ListBucketResult" in body:
                            found_buckets.append(f"{b_url} [PUBLIC LISTING (CRITICAL)]")
                        elif b_status == 403:
                            # The name exists but anyone in the world could own it
                            found_buckets.append(f"{b_url} [Exists, access denied — ownership unverified]")

                await asyncio.gather(*(check_bucket(b) for b in bucket_permutations))

                if found_buckets:
                    print(f"[+] CloudDetector: Found {len(found_buckets)} S3 bucket(s) matching the target's name.")
                else:
                    print("[-] CloudDetector: No obvious S3 buckets discovered.")

        return CloudResult(
            target_domain=self.host,
            primary_provider=provider,
            is_cloudflare=is_cf,
            s3_buckets_found=sorted(found_buckets)
        )
