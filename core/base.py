from abc import ABC, abstractmethod
from typing import Any, Optional

class BaseScanner(ABC):
    """
    The absolute foundation for all scanner modules in the framework.
    Now supports proxy routing, tactical delays, custom wordlists, and API tokens!
    """
    def __init__(self, target: str, deep_scan: bool = False, stealth: bool = False, proxy: Optional[str] = None, delay: float = 0.0, wordlist: str = "common", github_token: Optional[str] = None):
        self.target = target
        self.deep_scan = deep_scan
        self.stealth = stealth
        self.proxy = proxy
        self.delay = delay
        self.wordlist = wordlist 
        self.github_token = github_token 

    @abstractmethod
    async def execute(self) -> Any:
        pass
