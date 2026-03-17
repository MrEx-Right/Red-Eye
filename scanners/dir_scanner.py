import asyncio
from typing import List
import random
import os
import urllib.parse
from core.base import BaseScanner
from models.report import DirResult
from utils.client import AsyncClient

# Absolute path resolution to prevent execution context errors
WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlist")

class DirScanner(BaseScanner):

    async def execute(self) -> DirResult:
        wordlist_data = []
        w_name = ""

        # Check if the user specifically provided a wordlist argument
        if self.wordlist:
            w_name = self.wordlist.replace(".txt", "")
            wordlist_path = os.path.join(WORDLIST_DIR, f"{w_name}.txt")
            
            # File reading logic
            if os.path.exists(wordlist_path):
                try:
                    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                        wordlist_data = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                except Exception as e:
                    print(f"[!] DirScanner: Error reading '{w_name}.txt': {str(e)}")
            else:
                print(f"[!] DirScanner: '{w_name}.txt' not found! Falling back to default built-in list.")

        # If no custom list was provided, or the file was missing/empty, use the default list
        if not wordlist_data:
            w_name = "built-in default list"
            wordlist_data = [
                "admin", "login", "api", ".git", ".env",
                "backup", "config", "db", "test", "old", "dev", "staging",
                "secret", "hidden", "private", "data", "files", "uploads",
                "wp-admin", "wp-login", "vendor", "assets", "css", "js",
                "backup.zip", "backup.tar.gz", "db.sql", "config.php", "index.php.bak"
            ]

        print(f"[*] DirScanner: Starting directory brute-force for {self.target} using '{w_name}' ({len(wordlist_data)} paths)...")

        found_dirs: List[str] = []
        client = AsyncClient(timeout=5, proxy=self.proxy)
        
        # Dynamic Concurrency Limit. Gentle if stealth/delay is on, minigun otherwise.
        concurrency_limit = 20 if (self.stealth or self.delay > 0) else 150
        semaphore = asyncio.Semaphore(concurrency_limit) 
        
        async def check_dir(word: str):
            # URL encode the payload to handle spaces and special characters safely
            safe_word = urllib.parse.quote(word)
            
            # Enforce HTTPS scheme for modern web targets
            url = f"https://{self.target}/{safe_word}"
            
            async with semaphore:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                elif self.stealth:
                    await asyncio.sleep(random.uniform(1.0, 3.0))
                
                status, _, _ = await client.fetch(url, return_type="text")
                
                if status in [200, 301, 302, 403]:
                    # Keeping the original word in the report for readability
                    found_dirs.append(f"/{word} (Status: {status})")

        tasks = [check_dir(word) for word in wordlist_data]
        await asyncio.gather(*tasks)

        found_dirs.sort()

        if found_dirs:
            print(f"[+] DirScanner: Found {len(found_dirs)} interesting directories/files!")
        else:
            print(f"[-] DirScanner: Target looks clean. No common hidden paths found.")

        return DirResult(
            target_domain=self.target,
            found_directories=found_dirs
        )
