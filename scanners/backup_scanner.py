import asyncio
import urllib.parse
from typing import List
from core.base import BaseScanner
from models.report import BackupResult
from utils.client import AsyncClient

class BackupScanner(BaseScanner):
    """
    Actively hunts for forgotten backup archives, database dumps, 
    and residual configuration files left by developers on the web root.
    Dynamically generates targeted payloads based on the domain name.
    """
    async def execute(self) -> BackupResult:
        print(f"[*] BackupScanner: Hunting for exposed backups and archives on {self.target}...")

        client = AsyncClient(timeout=8, proxy=self.proxy)
        found_backups: List[str] = []
        
        # 1. Base keywords for backup files
        base_words = ["backup", "bak", "db", "database", "dump", "config", "archive", "source", "www", "web", "old"]
        
        # 2. Extract domain specific keywords (e.g. "example" from "example.com")
        domain_parts = self.target.split('.')
        if len(domain_parts) >= 2:
            main_name = domain_parts[-2] # usually the company name
            base_words.extend([self.target, main_name, f"{main_name}2023", f"{main_name}2024"])

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
        payloads = list(set(payloads))

        # Dynamic Concurrency: We don't want to crash the server if it actually starts serving a 10GB .zip
        concurrency_limit = 10 if self.stealth else 50
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def check_backup(payload: str):
            async with semaphore:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)

                safe_payload = urllib.parse.quote(payload)
                url = f"https://{self.target}/{safe_payload}"
                
                # We use HTTP GET, but the AsyncClient handles timeouts if the file is massive
                status, _, _ = await client.fetch(url, return_type="text")
                
                # Fallback to HTTP if HTTPS fails completely
                if status == 0:
                    url = f"http://{self.target}/{safe_payload}"
                    status, _, _ = await client.fetch(url, return_type="text")

                # If status is 200, it means the file exists and is accessible
                if status == 200:
                    found_backups.append(f"/{payload}")

        print(f"[*] BackupScanner: Generated {len(payloads)} targeted payloads. Firing...")

        tasks = [check_backup(payload) for payload in payloads]
        await asyncio.gather(*tasks)

        found_backups.sort()

        if found_backups:
            print(f"[+] BackupScanner: JACKPOT! Found {len(found_backups)} exposed backup/archive files!")
        else:
            print(f"[-] BackupScanner: Target looks clean. No exposed backups detected.")

        return BackupResult(
            target_domain=self.target,
            found_backups=found_backups
        )