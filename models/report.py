from dataclasses import dataclass, field
from typing import List

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
    leaks_found: int
    sample_urls: List[str]

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

@dataclass
class DirResult:
    target_domain: str
    found_directories: List[str]

@dataclass
class DnsResult:
    target_domain: str
    a_records: List[str]
    mx_records: List[str]
    ns_records: List[str]
    txt_records: List[str]
    cname_records: List[str]
    is_spoofable: bool
    has_dmarc: bool
    dmarc_policy: str
    has_dkim: bool
    dkim_selector: str
    zone_transfer_vulnerable: bool
    zone_transfer_data: List[str]
    vulnerabilities: List[str]
    info: List[str]

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
    total_leaks: int
    breaches_found: List[str] = field(default_factory=list)

@dataclass
class ShodanResult:
    target_domain: str
    ip_address: str
    organization: str
    country: str
    isp: str
    asn: str
    open_ports: List[str]
    banners: List[str]
    vulns: List[str]
    hostnames: List[str]
    os: str
    tags: List[str]

@dataclass
class HeaderResult:
    target_domain: str
    url_scanned: str
    security_score: int
    grade: str
    present_headers: dict = field(default_factory=dict)
    missing_headers: dict = field(default_factory=dict)
    misconfigured_headers: dict = field(default_factory=dict)
    info_leak_headers: dict = field(default_factory=dict)

@dataclass
class WhoisResult:
    target_domain: str
    registrar: str
    registrant_org: str
    registrant_country: str
    creation_date: str
    expiry_date: str
    updated_date: str
    name_servers: List[str]
    status: List[str]
    dnssec: str
    is_expired: bool
    is_expiring_soon: bool
    privacy_protected: bool