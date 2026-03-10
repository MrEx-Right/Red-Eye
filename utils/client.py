import aiohttp
import random
import asyncio
from typing import Optional, Dict, Tuple, Any

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
]

class AsyncClient:
    """
    A centralized, robust asynchronous HTTP client for the Red Eye framework.
    Prevents code duplication across scanner modules and handles timeouts,
    SSL bypasses, proxy routing, and custom headers globally.
    """
    def __init__(self, timeout: int = 5, proxy: Optional[str] = None):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.proxy = proxy
        self.default_headers = {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate"
        }

    def get_random_ua(self) -> str:
        return random.choice(USER_AGENTS)

    async def fetch(self, url: str, headers: Optional[Dict[str, str]] = None, return_type: str = "text") -> Tuple[int, Any, Any]:
        """
        Fires an async GET request to the target with dynamic User-Agent rotation.
        """
        merged_headers = self.default_headers.copy()
        if headers:
            merged_headers.update(headers)
            
        # Ghost Mode: Always rotate the User-Agent!
        merged_headers["User-Agent"] = self.get_random_ua()

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
                async with session.get(url, headers=merged_headers, proxy=self.proxy) as response:
                    status = response.status
                    resp_headers = response.headers
                    
                    if return_type == "json":
                        try:
                            data = await response.json()
                        except Exception:
                            data = {} 
                    else:
                        data = await response.text()
                        
                    return status, data, resp_headers
                    
        except asyncio.TimeoutError:
            return 408, None, None
        except Exception:
            return 0, None, None