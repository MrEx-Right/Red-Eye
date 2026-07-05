import asyncio
from typing import Dict, List
from core.base import BaseScanner
from utils.client import AsyncClient


# Security headers and their recommended values/descriptions
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HSTS — Forces HTTPS, prevents SSL stripping attacks.",
        "risk": "HIGH",
        "check": lambda v: "max-age" in v.lower()
    },
    "Content-Security-Policy": {
        "desc": "CSP — Prevents XSS and data injection attacks.",
        "risk": "HIGH",
        "check": lambda v: len(v) > 0
    },
    "X-Frame-Options": {
        "desc": "Clickjacking protection (DENY / SAMEORIGIN).",
        "risk": "MEDIUM",
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN")
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME-type sniffing attacks.",
        "risk": "MEDIUM",
        "check": lambda v: v.lower() == "nosniff"
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information sent in requests.",
        "risk": "LOW",
        "check": lambda v: len(v) > 0
    },
    "Permissions-Policy": {
        "desc": "Restricts browser feature access (camera, mic, geo).",
        "risk": "LOW",
        "check": lambda v: len(v) > 0
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter for older browsers.",
        "risk": "LOW",
        "check": lambda v: v.startswith("1")
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "COOP — Isolates browser context from cross-origin attacks.",
        "risk": "MEDIUM",
        "check": lambda v: len(v) > 0
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "CORP — Restricts cross-origin resource loading.",
        "risk": "MEDIUM",
        "check": lambda v: len(v) > 0
    },
    "Cache-Control": {
        "desc": "Caching policy — sensitive data should not be cached.",
        "risk": "LOW",
        "check": lambda v: "no-store" in v.lower() or "no-cache" in v.lower()
    },
}

# Headers that leak server/tech info and should ideally be absent
INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-Backend-Server",
]


class HeaderResult:
    """Holds HTTP security header analysis results."""
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.url_scanned: str = ""
        self.present_headers: Dict[str, str] = {}        # header -> value
        self.missing_headers: Dict[str, dict] = {}       # header -> meta
        self.misconfigured_headers: Dict[str, str] = {}  # header -> value (present but wrong)
        self.info_leak_headers: Dict[str, str] = {}      # header -> value (tech disclosure)
        self.security_score: int = 0                     # 0-100
        self.grade: str = "F"


class HeaderAnalyzer(BaseScanner):
    """
    HTTP Security Header Analyzer — fetches the target's response headers
    and evaluates security posture based on OWASP Secure Headers Project guidelines.

    Detects:
    - Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
    - Misconfigured headers (wrong values)
    - Information disclosure headers (Server, X-Powered-By, etc.)
    - Calculates a security grade (A+ to F)
    """

    async def execute(self) -> HeaderResult:
        print(f"[*] HeaderAnalyzer: Fetching and analyzing security headers for {self.target}...")

        result = HeaderResult(self.target)
        client  = AsyncClient(timeout=10, proxy=self.proxy)

        if self.delay > 0:
            await asyncio.sleep(self.delay)

        # Try HTTPS first, fall back to HTTP
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            status, _, headers = await client.fetch(url, return_type="text")

            if status not in (0, 408) and headers is not None:
                result.url_scanned = url
                break
        else:
            print(f"[-] HeaderAnalyzer: Could not reach {self.target}.")
            return result

        # Normalize headers to a plain dict (case-insensitive comparison)
        raw_headers: Dict[str, str] = {}
        if headers:
            for k, v in headers.items():
                raw_headers[k] = v

        # --- Analyze security headers ---
        found_score = 0
        max_score   = 0

        for header_name, meta in SECURITY_HEADERS.items():
            # Case-insensitive header lookup
            matched_key = next((k for k in raw_headers if k.lower() == header_name.lower()), None)

            risk_weight = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(meta["risk"], 5)
            max_score += risk_weight

            if matched_key:
                value = raw_headers[matched_key]
                result.present_headers[header_name] = value

                # Check if the value is correct
                try:
                    if meta["check"](value):
                        found_score += risk_weight
                    else:
                        result.misconfigured_headers[header_name] = value
                        found_score += risk_weight // 2  # Partial credit
                except Exception:
                    pass
            else:
                result.missing_headers[header_name] = meta

        # --- Detect information disclosure headers ---
        for leak_header in INFO_LEAK_HEADERS:
            matched = next((k for k in raw_headers if k.lower() == leak_header.lower()), None)
            if matched:
                result.info_leak_headers[leak_header] = raw_headers[matched]

        # --- Calculate security score & grade ---
        if max_score > 0:
            raw_pct = (found_score / max_score) * 100

            # Penalty for info leaks
            leak_penalty = min(len(result.info_leak_headers) * 5, 20)
            result.security_score = max(0, int(raw_pct - leak_penalty))
        else:
            result.security_score = 0

        score = result.security_score
        if score >= 90:
            result.grade = "A+"
        elif score >= 80:
            result.grade = "A"
        elif score >= 70:
            result.grade = "B"
        elif score >= 55:
            result.grade = "C"
        elif score >= 40:
            result.grade = "D"
        else:
            result.grade = "F"

        print(
            f"[+] HeaderAnalyzer: Analysis complete. "
            f"Grade: {result.grade} ({result.security_score}/100). "
            f"Missing: {len(result.missing_headers)}, Leaking: {len(result.info_leak_headers)}"
        )

        return result
