import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlsplit

# RFC 1123 hostname labels (underscores tolerated for service records like _dmarc)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

# Second-level labels that sit under a ccTLD (acme.co.uk, acme.com.tr, ...)
_COMMON_SLDS = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "nic", "biz", "info", "gen", "web", "k12", "bel", "av", "pol", "tsk"}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_target(raw: str) -> str:
    """
    Turns whatever the user typed (URL, host, host:port) into a clean
    'host' or 'host:port' string. Scheme, credentials, path, query and
    default ports are stripped. Raises ValueError on garbage input.
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("empty target")

    scheme = ""
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
    else:
        raw = "//" + raw

    parts = urlsplit(raw)
    host = (parts.hostname or "").rstrip(".")
    port = parts.port  # raises ValueError on a non-numeric/out-of-range port

    if not host:
        raise ValueError("no hostname found")

    if not is_ip(host):
        labels = host.split(".")
        if len(host) > 253 or not all(_LABEL_RE.match(label) for label in labels):
            raise ValueError(f"invalid hostname '{host}'")

    if (scheme, port) in (("https", 443), ("http", 80)):
        port = None

    shown_host = f"[{host}]" if ":" in host else host
    return f"{shown_host}:{port}" if port else shown_host


def split_target(target: str) -> Tuple[str, Optional[int]]:
    """'example.com:8443' -> ('example.com', 8443); '[::1]' -> ('::1', None)."""
    parts = urlsplit("//" + target)
    return (parts.hostname or target), parts.port


def registered_domain(host: str) -> str:
    """Best-effort registrable domain: 'www.shop.acme.co.uk' -> 'acme.co.uk'."""
    if is_ip(host):
        return host
    labels = host.lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _COMMON_SLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def base_name(host: str) -> str:
    """Organisation keyword of a domain: 'www.acme.co.uk' -> 'acme'."""
    return registered_domain(host).split(".")[0]
