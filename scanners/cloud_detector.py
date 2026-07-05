import asyncio
import socket
from typing import List, Optional
from core.base import BaseScanner
from utils.client import AsyncClient
from models.report import CloudResult

class CloudDetector(BaseScanner):
    """
    Identifies the underlying cloud infrastructure (AWS, Azure, GCP, Cloudflare)
    using HTTP Header analysis and Reverse DNS (PTR) lookups.
    Also vigorously hunts for exposed Amazon S3 buckets.
    """
    async def get_reverse_dns(self, target: str) -> str:
        """Attempts to resolve the IP to a hostname to detect cloud ranges."""
        loop = asyncio.get_event_loop()
        try:
            addr_info = await loop.getaddrinfo(target, None)
            ip_address = addr_info[0][4][0]
            hostname_info = await loop.run_in_executor(None, socket.gethostbyaddr, ip_address)
            return hostname_info[0].lower()
        except Exception:
            return ""

    async def execute(self) -> CloudResult:
        client = AsyncClient(timeout=8, proxy=self.proxy)
        provider = "Unknown"
        is_cf = False
        found_buckets: List[str] = []
        
        print(f"[*] CloudDetector: Analyzing infrastructure and IP footprint for {self.target}...")

        # --- Phase 1: Header & Infrastructure Analysis ---
        url = f"https://{self.target}"
        status, _, headers = await client.fetch(url)
        
        ptr_record = await self.get_reverse_dns(self.target)
        
        if ptr_record:
            if "amazonaws.com" in ptr_record:
                provider = "Amazon Web Services (AWS)"
            elif "1e100.net" in ptr_record or "googleusercontent.com" in ptr_record:
                provider = "Google Cloud Platform (GCP)"
            elif "cloudapp.net" in ptr_record or "azure.com" in ptr_record:
                provider = "Microsoft Azure"

        if headers:
            server_header = headers.get("Server", "").lower()
            if "cloudflare" in server_header or "cf-ray" in [k.lower() for k in headers.keys()]:
                is_cf = True
                provider = "Cloudflare (WAF/CDN Proxy)"
            elif provider == "Unknown":
                if "awselb" in server_header or any(k.lower().startswith("x-amz") for k in headers.keys()):
                    provider = "Amazon Web Services (AWS)"
                elif "azure" in server_header or any(k.lower().startswith("x-ms-") for k in headers.keys()):
                    provider = "Microsoft Azure"
                elif "gws" in server_header or "Google Frontend" in server_header:
                    provider = "Google Cloud Platform (GCP)"

        if provider != "Unknown":
            print(f"[+] CloudDetector: Target infrastructure resolved to: {provider}")
        else:
            print(f"[-] CloudDetector: Infrastructure masked or self-hosted. Could not fingerprint provider.")

        # --- Phase 2: S3 Bucket Bruteforcing ---
        if "Azure" not in provider and "Google" not in provider:
            print(f"[*] CloudDetector: Hunting for exposed S3 buckets...")
            
            base_name = self.target.split('.')[0]
            tld_dashed = self.target.replace('.', '-')
            
            bucket_permutations = [
                self.target,
                base_name,
                f"{base_name}-assets",
                f"{base_name}-media",
                f"{base_name}-public",
                f"{base_name}-backup",
                f"{base_name}-dev",
                tld_dashed
            ]
            
            # KANKA DİKKAT: Burası hayat kurtarır. S3 isteklerini 4'er 4'er atacağız ki soket şişmesin.
            semaphore = asyncio.Semaphore(4)
            
            async def check_bucket(bucket_name: str):
                async with semaphore:
                    try:
                        b_url = f"https://{bucket_name}.s3.amazonaws.com"
                        b_status, _, _ = await client.fetch(b_url)
                        
                        if b_status in [200, 403]:
                            state = "PUBLIC (CRITICAL)" if b_status == 200 else "Access Denied (403)"
                            found_buckets.append(f"{b_url} [{state}]")
                    except Exception:
                        # Patlayan istek olursa tüm modülü çökertmemesi için yutuyoruz
                        pass 
                    
            # Bütün görevleri fırlatıyoruz, artık hata olsa da try-except onu tutacak
            tasks = [check_bucket(b) for b in bucket_permutations]
            await asyncio.gather(*tasks)

            # Ve mutlu son! Artık print çalışacak.
            if found_buckets:
                print(f"[+] CloudDetector: Jackpot! Found {len(found_buckets)} related S3 buckets.")
            else:
                print(f"[-] CloudDetector: No obvious S3 buckets discovered.")

        return CloudResult(
            target_domain=self.target,
            primary_provider=provider,
            is_cloudflare=is_cf,
            s3_buckets_found=sorted(found_buckets)
        )