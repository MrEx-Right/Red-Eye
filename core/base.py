from abc import ABC, abstractmethod
from typing import Any, Optional

class BaseScanner(ABC):
    """
    The absolute foundation for all scanner modules in the framework.
    Now supports proxy routing, tactical delays, and custom wordlists!
    """
    def __init__(self, target: str, deep_scan: bool = False, stealth: bool = False, proxy: Optional[str] = None, delay: float = 0.0, wordlist: str = "common"):
        self.target = target
        self.deep_scan = deep_scan
        self.stealth = stealth
        self.proxy = proxy
        self.delay = delay
        self.wordlist = wordlist 

    @abstractmethod
    async def execute(self) -> Any:
        pass