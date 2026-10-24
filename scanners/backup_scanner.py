import asyncio
import random
import urllib.parse
from typing import List
from core.base import BaseScanner
from models.report import BackupResult
from utils.client import AsyncClient
from utils.domain import base_name, is_ip
from utils.soft404 import PROBE_BYTES, Soft404Filter

class BackupScanner(BaseScanner):
    """
    Actively hunts for forgotten backup archives, database dumps,
    and residual configuration files left by developers on the web root.
    Dynamically generates targeted payloads based on the domain name.
    """
    async def execute(self) -> BackupResult:
        print(f"[*] BackupScanner: Hunting for exposed backups and archives on {self.target}...")

        found_backups: List[str] = []

        # 1. Base keywords for backup files
        base_words = ["backup", "bak", "db", "database", "dump", "config", "archive", "source", "www", "web", "old"]

        # 2. Extract domain specific keywords (e.g. "example" from "www.example.co.uk")
        if not is_ip(self.host):
            main_name = base_name(self.host)  # usually the company name
            base_words.extend([self.host, main_name, f"{main_name}2023", f"{main_name}2024", f"{main_name}2025"])

        # 3. High-value extensions
        extensions = [".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".sql", ".bak", ".old", ".swp", "~", ".txt", ".env.bak"]

        # Additional exact-match payloads
        exact_payloads = [
            ".bash_history", "docker-compose.yml.bak", "wp-config.php.bak", "config.php.old"
        ]

        # Generate the ultimate payload list
        payloads = exact_payloads.copy()
        for word in base_words:
            for ext in extensions:
                payloads.append(f"{word}{ext}")

        # Deduplicate
        payloads = sorted(set(payloads))

        # Dynamic Concurrency: We don't want to crash the server if it actually starts serving a 10GB .zip
        concurrency_limit = 10 if self.stealth else 50
        semaphore = asyncio.Semaphore(concurrency_limit)

        async with AsyncClient(timeout=8, proxy=self.proxy, limit=concurrency_limit) as client:
            base_url = await client.detect_base_url(self.target)
            if not base_url:
                print(f"[-] BackupScanner: {self.target} is unreachable over HTTPS and HTTP. Skipping.")
                return BackupResult(target_domain=self.target, found_backups=[])

            soft404 = Soft404Filter()
            await soft404.calibrate(client, base_url, allow_redirects=True)

            async def check_backup(payload: str):
                async with semaphore:
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    elif self.stealth:
                        await asyncio.sleep(random.uniform(0.5, 2.0))

                    url = f"{base_url}/{urllib.parse.quote(payload)}"
                    # Only the first bytes are read — a real 10GB dump is never downloaded
                    status, body, headers = await client.fetch(url, return_type="text", max_bytes=PROBE_BYTES)

                if status != 200:
                    return
                # An HTML page is a site template answering, not a backup file
                content_type = headers.get("Content-Type", "").lower() if headers is not None else ""
                if "text/html" in content_type:
                    return
                if soft404.is_soft404(payload, status, body, headers):
                    return
                found_backups.append(f"/{payload}")

            print(f"[*] BackupScanner: Generated {len(payloads)} targeted payloads. Firing at {base_url}...")
            await asyncio.gather(*(check_backup(payload) for payload in payloads))

        found_backups.sort()

        if found_backups:
            print(f"[+] BackupScanner: JACKPOT! Found {len(found_backups)} exposed backup/archive files!")
        else:
            print("[-] BackupScanner: Target looks clean. No exposed backups detected.")

        return BackupResult(
            target_domain=self.target,
            found_backups=found_backups
        )
