from abc import ABC, abstractmethod
from typing import Any, Optional
from utils.domain import is_ip, registered_domain, split_target

class BaseScanner(ABC):
    """
    The absolute foundation for all scanner modules in the framework.
    Now supports proxy routing, tactical delays, custom wordlists, and API tokens!

    self.target is 'host' or 'host:port' and is what web URLs are built from.
    self.host is the bare hostname/IP for DNS, sockets and third-party lookups.
    self.zone is the registered domain (www.acme.co.uk -> acme.co.uk): zone-level
    records (NS, MX, SPF, DMARC) and subdomain enumeration live there.
    """

    # True for modules that open raw sockets to the target. Those connections
    # cannot be routed through an HTTP proxy, so the engine skips such modules
    # in proxy mode unless the user asks for them explicitly.
    DIRECT_CONTACT = False

    def __init__(
        self,
        target: str,
        stealth: bool = False,
        proxy: Optional[str] = None,
        delay: float = 0.0,
        wordlist: Optional[str] = None,
        github_token: Optional[str] = None,
        shodan_key: Optional[str] = None,
    ):
        self.target = target
        self.host, self.port = split_target(target)
        self.zone = self.host if is_ip(self.host) else registered_domain(self.host)
        self.stealth = stealth
        self.proxy = proxy
        self.delay = delay
        self.wordlist = wordlist
        self.github_token = github_token
        self.shodan_key = shodan_key

    @abstractmethod
    async def execute(self) -> Any:
        pass
