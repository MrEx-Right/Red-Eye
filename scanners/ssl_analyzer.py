import ssl
import socket
import asyncio
from datetime import datetime
from typing import List
from core.base import BaseScanner
from models.report import SSLResult

class SSLAnalyzer(BaseScanner):
    """
    Analyzes the SSL/TLS certificate of the target domain to extract
    issuer details, expiration date, and Subject Alternative Names (SANs).
    """
    async def execute(self) -> SSLResult:
        print(f"[*] SSLAnalyzer: Extracting certificate data for {self.target}...")
        
        issuer = "Unknown"
        days_left = 0
        is_valid = False
        sans: List[str] = []

        # We run the synchronous socket/ssl operations in a separate thread
        # to avoid blocking our main asyncio event loop. Smooth and fast!
        def fetch_cert():
            ctx = ssl.create_default_context()
            # Set a tight timeout so we don't hang if the port is dead
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
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
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.utcnow()).days
                
            # 3. Parse Subject Alternative Names (SANs) - The real juicy part!
            for key, value in cert.get('subjectAltName', []):
                if key == 'DNS':
                    sans.append(value)
                    
        except ssl.SSLCertVerificationError as e:
            print(f"[!] SSLAnalyzer: Certificate is INVALID or EXPIRED for {self.target}.")
        except Exception as e:
            print(f"[-] SSLAnalyzer: Could not fetch SSL info (Port 443 might be closed or no SSL).")

        if is_valid:
            print(f"[+] SSLAnalyzer: Valid cert found! Issued by {issuer}, {days_left} days remaining.")

        return SSLResult(
            target_domain=self.target,
            is_valid=is_valid,
            issuer=issuer,
            days_until_expiry=days_left,
            subject_alt_names=sorted(list(set(sans)))
        )