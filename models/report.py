from dataclasses import dataclass, field
from typing import List

# Every scanner returns one of these. They are the single source of truth
# for result shapes — the engine renders them by class name.

@dataclass
class SubdomainResult:
    target_domain: str
    discovered_subdomains: List[str]
    source: str

@dataclass
class WafResult:
    target_domain: str
    has_waf: bool
    waf_name: str

@dataclass
class GithubResult:
    target_domain: str
    leaks_found: int = 0
    sample_urls: List[str] = field(default_factory=list)
    total_hits: int = 0
    skipped_reason: str = ""

@dataclass
class TechResult:
    target_domain: str
    technologies: List[str]

@dataclass
class PortResult:
    target_domain: str
    open_ports: List[int]

@dataclass
class SSLResult:
    target_domain: str
    is_valid: bool
    issuer: str
    days_until_expiry: int
    subject_alt_names: List[str]
    error: str = ""

@dataclass
class DirResult:
    target_domain: str
    found_directories: List[str]

@dataclass
class DnsResult:
    target_domain: str
    a_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    caa_records: List[str] = field(default_factory=list)
    # Security posture. A check that could not be performed stays False in
    # its *_checked flag and is never reported as a vulnerability.
    spf_checked: bool = False
    is_spoofable: bool = False
    dmarc_checked: bool = False
    has_dmarc: bool = False
    dmarc_policy: str = "none"
    has_dkim: bool = False
    dkim_selector: str = ""
    zone_transfer_checked: bool = False
    zone_transfer_vulnerable: bool = False
    zone_transfer_data: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

@dataclass
class EmailResult:
    target_domain: str
    harvested_emails: List[str]

@dataclass
class ArchiveResult:
    target_domain: str
    total_urls_found: int
    interesting_urls: List[str]

@dataclass
class TakeoverResult:
    target_domain: str
    vulnerable_subdomains: List[str]
    checked_cnames: int = 0

@dataclass
class JsResult:
    target_domain: str
    js_files_scanned: int
    secrets_found: dict = field(default_factory=dict)

@dataclass
class SmResult:
    target_domain: str
    platform_mentions: dict = field(default_factory=dict)

@dataclass
class BackupResult:
    target_domain: str
    found_backups: List[str]

@dataclass
class RobotsResult:
    target_domain: str
    extracted_paths: List[str]

@dataclass
class CloudResult:
    target_domain: str
    primary_provider: str
    is_cloudflare: bool
    s3_buckets_found: List[str]

@dataclass
class BreachResult:
    target_domain: str
    total_leaks: int = 0
    breaches_found: List[str] = field(default_factory=list)
    lookup_ok: bool = False
    error: str = ""

@dataclass
class ShodanResult:
    target_domain: str
    ip_address: str = "Unknown"
    organization: str = "Unknown"
    country: str = "Unknown"
    isp: str = "Unknown"
    asn: str = "Unknown"
    open_ports: List[int] = field(default_factory=list)
    banners: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    os: str = "Unknown"
    tags: List[str] = field(default_factory=list)

@dataclass
class HeaderResult:
    target_domain: str
    url_scanned: str = ""
    reachable: bool = False
    security_score: int = 0
    grade: str = "F"
    present_headers: dict = field(default_factory=dict)
    missing_headers: dict = field(default_factory=dict)
    misconfigured_headers: dict = field(default_factory=dict)
    info_leak_headers: dict = field(default_factory=dict)

@dataclass
class WhoisResult:
    target_domain: str
    registrar: str = "Unknown"
    registrant_org: str = "Unknown"
    registrant_country: str = "Unknown"
    creation_date: str = "Unknown"
    expiry_date: str = "Unknown"
    updated_date: str = "Unknown"
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: str = "Unknown"
    is_expired: bool = False
    is_expiring_soon: bool = False
    privacy_protected: bool = False
    source: str = ""
    raw_whois: str = ""

@dataclass
class CdnBypassResult:
    target_domain: str
    main_ip: str
    behind_cdn: bool
    cdn_indicator: str
    mx_hostname: str
    mx_ip: str
    mx_ip_differs: bool
    candidate_origin_ips: List[str] = field(default_factory=list)
    cdn_edge_ips: List[str] = field(default_factory=list)
    confirmed_origin_ip: str = ""
    confirmed_via: str = ""

@dataclass
class JwtResult:
    target_domain: str
    js_files_scanned: int
    tokens_found: int
    decoded_tokens: List[dict] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
