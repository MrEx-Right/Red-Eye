import difflib
import uuid
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import quote
from utils.client import AsyncClient

# How much of each body we keep for comparison. Enough to tell an error
# template from real content, small enough to never download a full archive.
PROBE_BYTES = 16384

# Random probes covering the shapes the brute-forcers request: bare words,
# scripts, archives, text files and dotfiles often hit different handlers.
PROBE_SUFFIXES = ["", ".php", ".zip", ".txt", ".bak"]


@dataclass
class _Fingerprint:
    status: int
    location: str
    body: str


class Soft404Filter:
    """
    Learns what the target answers for paths that certainly do not exist,
    then flags look-alike responses. Catches catch-all 200 pages, "redirect
    everything to /login" setups and WAFs that 403 every unknown path.
    """

    def __init__(self) -> None:
        self.baselines: List[_Fingerprint] = []

    async def calibrate(self, client: AsyncClient, base_url: str, allow_redirects: bool = False) -> None:
        for suffix in PROBE_SUFFIXES:
            path = f"{uuid.uuid4().hex[:12]}{suffix}"
            status, body, headers = await client.fetch(
                f"{base_url}/{path}", return_type="text",
                allow_redirects=allow_redirects, max_bytes=PROBE_BYTES
            )
            if status not in (0, 408):
                self.baselines.append(self._fingerprint(path, status, body, headers))

    @staticmethod
    def _fingerprint(path: str, status: int, body: Optional[str], headers) -> _Fingerprint:
        # Error pages and redirects usually echo the requested path back,
        # so we mask it before comparing.
        variants = {path, quote(path)}

        def mask(text: str) -> str:
            for variant in variants:
                text = text.replace(variant, "§")
            return text

        location = headers.get("Location", "") if headers is not None else ""
        return _Fingerprint(status, mask(location), mask(body or ""))

    @staticmethod
    def _similar(a: str, b: str) -> bool:
        if a == b:
            return True
        longest = max(len(a), len(b))
        if longest == 0 or abs(len(a) - len(b)) > longest * 0.1:
            return False
        matcher = difflib.SequenceMatcher(None, a[:2048], b[:2048])
        return matcher.quick_ratio() >= 0.9 and matcher.ratio() >= 0.9

    def is_soft404(self, path: str, status: int, body: Optional[str], headers) -> bool:
        candidate = self._fingerprint(path, status, body, headers)
        for baseline in self.baselines:
            if baseline.status != candidate.status or baseline.location != candidate.location:
                continue
            if self._similar(baseline.body, candidate.body):
                return True
        return False
