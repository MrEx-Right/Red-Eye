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
    txt_records: List[str]
    is_spoofable: bool

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
