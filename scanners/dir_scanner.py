import asyncio
from typing import List
import random
import os
import urllib.parse
from core.base import BaseScanner
from models.report import DirResult
from utils.client import AsyncClient
from utils.soft404 import PROBE_BYTES, Soft404Filter

# Absolute path resolution to prevent execution context errors
WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlist")

INTERESTING_STATUSES = {200, 204, 301, 302, 307, 308, 401, 403}
REDIRECT_STATUSES = {301, 302, 307, 308}

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
        # Strip leading slashes and duplicates without losing the list order
        wordlist_data = list(dict.fromkeys(w.lstrip("/") for w in wordlist_data if w.lstrip("/")))

        found_dirs: List[str] = []

        # Dynamic Concurrency Limit. Gentle if stealth/delay is on, minigun otherwise.
        concurrency_limit = 20 if (self.stealth or self.delay > 0) else 150
        semaphore = asyncio.Semaphore(concurrency_limit)

        async with AsyncClient(timeout=5, proxy=self.proxy, limit=concurrency_limit) as client:
            base_url = await client.detect_base_url(self.target)
            if not base_url:
                print(f"[-] DirScanner: {self.target} is unreachable over HTTPS and HTTP. Skipping.")
                return DirResult(target_domain=self.target, found_directories=[])

            print(f"[*] DirScanner: Starting directory brute-force for {base_url} using '{w_name}' ({len(wordlist_data)} paths)...")

            # Learn what "does not exist" looks like before trusting any status code
            soft404 = Soft404Filter()
            await soft404.calibrate(client, base_url)

            async def check_dir(word: str):
                # URL encode the payload to handle spaces and special characters safely
                safe_word = urllib.parse.quote(word)
                url = f"{base_url}/{safe_word}"

                async with semaphore:
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    elif self.stealth:
                        await asyncio.sleep(random.uniform(1.0, 3.0))

                    # Redirects are not followed: '/admin -> /login' must not look like a hit
                    status, body, headers = await client.fetch(url, return_type="text", allow_redirects=False, max_bytes=PROBE_BYTES)

                if status not in INTERESTING_STATUSES or soft404.is_soft404(word, status, body, headers):
                    return

                # Keeping the original word in the report for readability
                entry = f"/{word} (Status: {status})"
                if status in REDIRECT_STATUSES and headers is not None and headers.get("Location"):
                    entry += f" -> {headers['Location']}"
                found_dirs.append(entry)

            await asyncio.gather(*(check_dir(word) for word in wordlist_data))

        found_dirs.sort()

        if found_dirs:
            print(f"[+] DirScanner: Found {len(found_dirs)} interesting directories/files!")
        else:
            print("[-] DirScanner: Target looks clean. No common hidden paths found.")

        return DirResult(
            target_domain=self.target,
            found_directories=found_dirs
        )
