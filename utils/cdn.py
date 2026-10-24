import ipaddress
from typing import Optional

# Published Cloudflare edge ranges (https://www.cloudflare.com/ips-v4). Any IP
# in here is a shared CDN edge, never a customer's origin server.
CLOUDFLARE_RANGES = [ipaddress.ip_network(net) for net in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)]

# Server header substrings of the big CDN/WAF edges
CDN_SERVER_HINTS = ("cloudflare", "cloudfront", "akamai", "fastly", "sucuri", "incapsula", "imperva", "stackpath", "bunnycdn", "keycdn")

# Response headers only CDN edges add
CDN_HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "CloudFront",
    "x-amz-cf-pop": "CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-iinfo": "Imperva Incapsula",
    "x-cdn": "Generic CDN",
}


def is_cloudflare_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in CLOUDFLARE_RANGES if net.version == address.version)


def cdn_from_headers(headers) -> Optional[str]:
    """Names the CDN/WAF that produced a response, or None if it looks direct."""
    if not headers:
        return None
    keys = {k.lower() for k in headers.keys()}
    for header, name in CDN_HEADER_HINTS.items():
        if header in keys:
            return f"{name} ({header} header)"
    server = headers.get("Server", "").lower()
    for hint in CDN_SERVER_HINTS:
        if hint in server:
            return f"{hint.capitalize()} (Server header)"
    return None
