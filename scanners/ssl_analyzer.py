import ssl
import socket
import asyncio
import time
from typing import List
from core.base import BaseScanner
from models.report import SSLResult

class SSLAnalyzer(BaseScanner):
    """
    Analyzes the SSL/TLS certificate of the target domain to extract
    issuer details, expiration date, and Subject Alternative Names (SANs).
    """

    DIRECT_CONTACT = True  # raw TLS socket to the target

    async def execute(self) -> SSLResult:
        port = self.port or 443
        print(f"[*] SSLAnalyzer: Extracting certificate data for {self.host}:{port}...")

        issuer = "Unknown"
        days_left = 0
        is_valid = False
        error = ""
        sans: List[str] = []

        # We run the synchronous socket/ssl operations in a separate thread
        # to avoid blocking our main asyncio event loop. Smooth and fast!
        def fetch_cert():
            ctx = ssl.create_default_context()
            # Set a tight timeout so we don't hang if the port is dead
            with socket.create_connection((self.host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    return ssock.getpeercert()

        try:
            # Awaiting the background thread
            cert = await asyncio.to_thread(fetch_cert)
            is_valid = True

            # 1. Parse Issuer (Who signed this?)
            for item in cert.get('issuer', []):
                for key, value in item:
                    if key == 'organizationName':
                        issuer = value
                    elif key == 'commonName' and issuer == "Unknown":
                        issuer = value

            # 2. Parse Expiry Date (How many days left?)
            not_after = cert.get('notAfter')
            if not_after:
                # Format example: 'May 24 12:00:00 2025 GMT'
                days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)

            # 3. Parse Subject Alternative Names (SANs) - The real juicy part!
            for key, value in cert.get('subjectAltName', []):
                if key == 'DNS':
                    sans.append(value)

        except ssl.SSLCertVerificationError as e:
            error = e.verify_message or "certificate verification failed"
            print(f"[!] SSLAnalyzer: Certificate is INVALID for {self.host}: {error}.")
        except Exception:
            error = f"no TLS service reachable on port {port}"
            print(f"[-] SSLAnalyzer: Could not fetch SSL info (Port {port} might be closed or no SSL).")

        if is_valid:
            print(f"[+] SSLAnalyzer: Valid cert found! Issued by {issuer}, {days_left} days remaining.")

        return SSLResult(
            target_domain=self.host,
            is_valid=is_valid,
            issuer=issuer,
            days_until_expiry=days_left,
            subject_alt_names=sorted(set(sans)),
            error=error
        )
