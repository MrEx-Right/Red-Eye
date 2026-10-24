import aiohttp
import random
import asyncio
import json
from typing import Optional, Dict, Tuple, Any

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
]


def hackertarget_failed(text: Optional[str]) -> bool:
    """HackerTarget answers errors and quota exhaustion with HTTP 200 + a plain-text message."""
    if not text:
        return True
    head = text.strip().lower()[:120]
    return (
        head.startswith("error")
        or "api count exceeded" in head
        or "increase quota" in head
        or "input invalid" in head
    )


class AsyncClient:
    """
    A centralized, robust asynchronous HTTP client for the Red Eye framework.
    Prevents code duplication across scanner modules and handles timeouts,
    SSL bypasses, proxy routing, and custom headers globally.

    Use it as `async with AsyncClient(...) as client:` to share one connection
    pool across many requests. Used without the context manager, every fetch
    opens (and closes) its own short-lived session.
    """
    def __init__(self, timeout: int = 5, proxy: Optional[str] = None, limit: int = 100):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.limit = limit
        self._session: Optional[aiohttp.ClientSession] = None
        self.default_headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate"
        }

    def _new_session(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(ssl=False, limit=self.limit)
        return aiohttp.ClientSession(connector=connector, timeout=self.timeout)

    async def __aenter__(self) -> "AsyncClient":
        self._session = self._new_session()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None

    def get_random_ua(self) -> str:
        return random.choice(USER_AGENTS)

    async def fetch(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        return_type: str = "text",
        allow_redirects: bool = True,
        max_bytes: Optional[int] = None,
        **request_kwargs: Any,
    ) -> Tuple[int, Any, Any]:
        """
        Fires an async GET request to the target with dynamic User-Agent rotation.

        return_type: "text" (decoded leniently, never fails on binary bodies),
                     "json", "bytes" or "none" (status + headers only).
        max_bytes:   read at most this many bytes of the body — keeps probes
                     cheap when the server happens to serve a multi-GB archive.

        Returns (status, data, headers). status is 408 on timeout and 0 on any
        connection/protocol error.
        """
        merged_headers = self.default_headers.copy()
        if headers:
            merged_headers.update(headers)

        # Ghost Mode: rotate the User-Agent unless the caller pinned one
        if not any(k.lower() == "user-agent" for k in merged_headers):
            merged_headers["User-Agent"] = self.get_random_ua()

        try:
            if self._session is not None and not self._session.closed:
                return await self._request(self._session, url, merged_headers, return_type, allow_redirects, max_bytes, request_kwargs)
            async with self._new_session() as session:
                return await self._request(session, url, merged_headers, return_type, allow_redirects, max_bytes, request_kwargs)
        except asyncio.TimeoutError:
            return 408, None, None
        except Exception:
            return 0, None, None

    async def _request(self, session, url, headers, return_type, allow_redirects, max_bytes, request_kwargs):
        async with session.get(url, headers=headers, proxy=self.proxy, allow_redirects=allow_redirects, **request_kwargs) as response:
            status = response.status
            resp_headers = response.headers

            if return_type == "none":
                return status, None, resp_headers

            raw = await (response.content.read(max_bytes) if max_bytes else response.read())

            if return_type == "bytes":
                return status, raw, resp_headers

            text = self._decode(raw, response.charset)
            if return_type == "json":
                try:
                    return status, json.loads(text), resp_headers
                except ValueError:
                    return status, None, resp_headers
            return status, text, resp_headers

    @staticmethod
    def _decode(raw: bytes, charset: Optional[str]) -> str:
        try:
            return raw.decode(charset or "utf-8", errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")

    async def detect_base_url(self, target: str) -> Optional[str]:
        """
        Returns 'https://target' if it answers over TLS, else 'http://target',
        or None when the host is unreachable on both. Any HTTP status counts
        as reachable — a 404 on '/' still means the web server is there.
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            status, _, _ = await self.fetch(url + "/", return_type="none", allow_redirects=False)
            if status not in (0, 408):
                return url
        return None
