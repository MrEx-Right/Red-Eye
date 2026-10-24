import asyncio
import re
import base64
import json
import hmac
import hashlib
from datetime import datetime, timezone
from urllib.parse import urljoin
from core.base import BaseScanner
from models.report import JwtResult
from utils.client import AsyncClient
from utils.domain import base_name

JWT_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

# Claims that should never travel inside a readable token payload
SECRET_CLAIM_KEYS = ("password", "passwd", "secret", "ssn", "api_key", "apikey", "private_key", "credit_card")

# Claims that are normal in JWTs but tell an attacker what to tamper with
PRIVILEGE_CLAIM_KEYS = ("role", "admin", "is_admin", "permissions", "internal", "scope", "groups")

# Symmetric algorithms that can be cracked offline with a wordlist
HMAC_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# Small, built-in list of extremely common weak HS256 signing secrets.
WEAK_SECRETS = ["secret", "123456", "password", "jwt_secret", "changeme", "admin"]


class JwtDecoder(BaseScanner):
    """
    Crawls the target's frontend JS files (and the main page's cookies) for
    embedded JWTs, decodes their header/payload, and flags common
    misconfigurations: alg:none, expired tokens, sensitive claims exposed
    in the payload, and HMAC tokens signed with a common weak secret.
    """

    def _b64url_decode(self, segment: str) -> bytes:
        padded = segment + "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(padded)

    def _decode_token(self, token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        header_b64, payload_b64, signature_b64 = parts

        try:
            header = json.loads(self._b64url_decode(header_b64))
            payload = json.loads(self._b64url_decode(payload_b64))
        except Exception:
            return {}
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return {}

        entry = {
            # Head + tail: every HS256 token starts with the same header bytes
            "token_preview": f"{token[:10]}...{token[-8:]}",
            "alg": str(header.get("alg", "Unknown")),
            "alg_none": False,
            "expired": False,
            "sensitive_claims": [],
            "privilege_claims": [],
            "cracked_secret": ""
        }
        entry["alg_none"] = entry["alg"].strip().lower() == "none"

        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            entry["expired"] = datetime.now(timezone.utc).timestamp() > exp

        for key in payload:
            lowered = str(key).lower()
            if any(sensitive in lowered for sensitive in SECRET_CLAIM_KEYS):
                entry["sensitive_claims"].append(key)
            elif any(privileged in lowered for privileged in PRIVILEGE_CLAIM_KEYS):
                entry["privilege_claims"].append(key)

        # Only symmetric HMAC signatures can be feasibly cracked with a
        # small offline wordlist — RS/ES/PS algorithms need the private key.
        digest = HMAC_ALGORITHMS.get(entry["alg"].upper())
        if digest:
            signing_input = f"{header_b64}.{payload_b64}".encode()
            try:
                target_sig = self._b64url_decode(signature_b64)
            except Exception:
                target_sig = b""

            if target_sig:
                candidates = WEAK_SECRETS + [self.host, base_name(self.host)]
                for secret in candidates:
                    computed = hmac.new(secret.encode(), signing_input, digest).digest()
                    if hmac.compare_digest(computed, target_sig):
                        entry["cracked_secret"] = secret
                        break

        return entry

    async def execute(self) -> JwtResult:
        # One pooled session for the index page and every JS file
        async with AsyncClient(timeout=10, proxy=self.proxy) as client:
            return await self._scan(client)

    async def _scan(self, client: AsyncClient) -> JwtResult:
        print(f"[*] JwtDecoder: Hunting for embedded JWTs on {self.target}...")

        base_url = f"https://{self.target}"

        # 1. Fetch the main page (also gives us Set-Cookie headers for free)
        status, data, main_headers = await client.fetch(base_url, return_type="text")
        if status == 0 or status >= 400:
            base_url = f"http://{self.target}"
            status, data, main_headers = await client.fetch(base_url, return_type="text")

        if not data:
            print(f"[-] JwtDecoder: Could not fetch main page for {self.target}. Aborting JWT scan.")
            return JwtResult(target_domain=self.target, js_files_scanned=0, tokens_found=0)

        found_tokens = set(JWT_PATTERN.findall(data))

        if main_headers:
            try:
                cookie_values = main_headers.getall("Set-Cookie", [])
            except AttributeError:
                single = main_headers.get("Set-Cookie", "")
                cookie_values = [single] if single else []
            for cookie_value in cookie_values:
                found_tokens.update(JWT_PATTERN.findall(cookie_value))

        # 2. Discover and crawl referenced JS files (same pattern as JsAnalyzer)
        script_pattern = re.compile(r'(?i)src=["\']([^"\']+\.js[^"\']*)["\']')
        js_links = set(script_pattern.findall(data))

        js_urls = set()
        for link in js_links:
            js_urls.add(urljoin(base_url, link))

        if js_urls:
            print(f"[*] JwtDecoder: Discovered {len(js_urls)} JS files. Commencing concurrent extraction...")
            semaphore = asyncio.Semaphore(10)

            async def scan_js_file(js_url: str):
                async with semaphore:
                    if self.delay > 0:
                        await asyncio.sleep(self.delay)
                    js_status, js_content, _ = await client.fetch(js_url, return_type="text", max_bytes=10_000_000)
                    if js_status == 200 and js_content:
                        found_tokens.update(JWT_PATTERN.findall(js_content))

            tasks = [scan_js_file(url) for url in js_urls]
            await asyncio.gather(*tasks)

        # 3. Decode and analyze every unique token found
        decoded_tokens = []
        vulnerabilities = []

        for token in sorted(found_tokens):
            entry = self._decode_token(token)
            if not entry:
                continue
            decoded_tokens.append(entry)

            if entry["alg_none"]:
                vulnerabilities.append(f"CRITICAL - Token {entry['token_preview']} uses alg:none — signature bypass possible.")
            if entry["cracked_secret"]:
                vulnerabilities.append(f"CRITICAL - Token {entry['token_preview']} signed with weak {entry['alg']} secret: '{entry['cracked_secret']}'")
            if entry["sensitive_claims"]:
                vulnerabilities.append(f"VULNERABLE - Token {entry['token_preview']} exposes sensitive claims: {', '.join(entry['sensitive_claims'])}")

        if decoded_tokens:
            print(f"[+] JwtDecoder: Found {len(decoded_tokens)} JWT(s), {len(vulnerabilities)} issue(s) flagged.")
        else:
            print("[-] JwtDecoder: No JWTs found in JS files or cookies.")

        return JwtResult(
            target_domain=self.target,
            js_files_scanned=len(js_urls),
            tokens_found=len(decoded_tokens),
            decoded_tokens=decoded_tokens,
            vulnerabilities=vulnerabilities
        )
