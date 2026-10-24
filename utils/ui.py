import time
from dataclasses import dataclass
from typing import Any, Awaitable, Dict, List, Optional, Sequence, Tuple

from rich import box
from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from utils.eye import render_eye, render_wordmark

# The logo's red, used for the brand accents around it.
ACCENT = "#ff3030"

# Severity levels, most severe first. A module's row takes the worst severity
# among its findings; modules without findings keep their own status.
CRITICAL, WARN, INFO, OK, UNKNOWN = "critical", "warn", "info", "ok", "unknown"
SEVERITY_RANK = {CRITICAL: 0, WARN: 1, INFO: 2, OK: 3, UNKNOWN: 4}
SEVERITY_STYLE = {CRITICAL: "bold red", WARN: "yellow", INFO: "cyan", OK: "green", UNKNOWN: "dim"}
SEVERITY_ICON = {CRITICAL: "✖", WARN: "⚠", INFO: "•", OK: "✔", UNKNOWN: "?"}

# JS findings that are real credentials, not just noisy matches or endpoints.
JS_CREDENTIALS = ("AWS Access Key", "Google API Key", "Stripe Standard API", "Mailgun API Key")

# The terminal findings panel shows this many entries; the -o report gets all of them.
FINDINGS_LIMIT = 15

Finding = Tuple[str, str]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _strip_marker(text: str) -> str:
    for marker in ("CRITICAL - ", "CRITICAL: "):
        if text.startswith(marker):
            return text[len(marker):]
    return text


def assess(result: Any) -> Tuple[str, str, List[Finding]]:
    """
    Condenses a scanner result into (severity, one-line summary, findings).
    Findings are the (severity, text) items worth surfacing at the end of a scan.
    """
    name = type(result).__name__
    findings: List[Finding] = []
    flag = lambda sev, text: findings.append((sev, text))
    status = INFO

    if name == "SubdomainResult":
        summary = _plural(len(result.discovered_subdomains), "subdomain")

    elif name == "WafResult":
        summary = result.waf_name if result.has_waf else "no WAF detected"

    elif name == "GithubResult":
        if result.skipped_reason:
            status, summary = UNKNOWN, f"skipped — {result.skipped_reason}"
        elif result.leaks_found:
            summary = _plural(result.leaks_found, "potential leak")
            flag(WARN, f"{_plural(result.leaks_found, 'potential code leak')} on GitHub")
        else:
            status, summary = OK, "no leaks"

    elif name == "TechResult":
        tech = result.technologies
        if tech:
            summary = ", ".join(tech[:4]) + (f" +{len(tech) - 4}" if len(tech) > 4 else "")
        else:
            status, summary = UNKNOWN, "stack unknown"

    elif name == "PortResult":
        ports = result.open_ports
        if ports:
            summary = "open: " + ", ".join(map(str, ports[:8])) + (f" +{len(ports) - 8}" if len(ports) > 8 else "")
        else:
            summary = "no open ports"

    elif name == "SSLResult":
        if not result.is_valid:
            status, summary = WARN, "invalid" + (f" — {result.error}" if result.error else "")
            flag(WARN, "TLS certificate invalid" + (f": {result.error}" if result.error else ""))
        elif result.days_until_expiry <= 14:
            summary = f"expires in {result.days_until_expiry}d · {result.issuer}"
            flag(WARN, f"TLS certificate expires in {result.days_until_expiry} days")
        else:
            status, summary = OK, f"valid · {result.days_until_expiry}d left · {result.issuer}"

    elif name == "DirResult":
        summary = _plural(len(result.found_directories), "path")

    elif name == "DnsResult":
        summary = f"{len(result.a_records)} A · {len(result.mx_records)} MX · {len(result.ns_records)} NS"
        for v in result.vulnerabilities:
            flag(CRITICAL if v.startswith("ZONE TRANSFER") or "+all" in v else WARN, v)
        if findings:
            summary += f" · {_plural(len(findings), 'issue')}"
        elif result.spf_checked and result.dmarc_checked:
            status = OK
        else:
            status, summary = UNKNOWN, summary + " · SPF/DMARC unknown"

    elif name == "EmailResult":
        summary = _plural(len(result.harvested_emails), "email")

    elif name == "ArchiveResult":
        summary = f"{len(result.interesting_urls)} juicy of {_plural(result.total_urls_found, 'URL')}"

    elif name == "TakeoverResult":
        summary = f"{_plural(result.checked_cnames, 'CNAME')} checked"
        for sub in result.vulnerable_subdomains:
            flag(CRITICAL, f"Subdomain takeover: {sub}")
        if not findings:
            status = OK

    elif name == "JsResult":
        hits = sum(len(items) for items in result.secrets_found.values())
        summary = f"{_plural(result.js_files_scanned, 'file')} · {_plural(hits, 'hit')}"
        for kind, items in result.secrets_found.items():
            if kind == "Internal API Endpoint":
                continue
            flag(CRITICAL if kind in JS_CREDENTIALS else WARN, f"{kind} in JavaScript ({len(items)} found)")

    elif name == "SmResult":
        summary = _plural(len(result.platform_mentions), "platform")

    elif name == "BackupResult":
        summary = _plural(len(result.found_backups), "exposed file")
        for path in result.found_backups:
            flag(CRITICAL, f"Exposed file: {path}")
        if not findings:
            status = OK

    elif name == "RobotsResult":
        summary = _plural(len(result.extracted_paths), "path")

    elif name == "CloudResult":
        summary = result.primary_provider + (" · Cloudflare" if result.is_cloudflare else "")
        for bucket in result.s3_buckets_found:
            flag(WARN, f"S3 bucket matching target name: {bucket}")

    elif name == "BreachResult":
        if not result.lookup_ok:
            status, summary = UNKNOWN, "lookup failed" + (f" — {result.error}" if result.error else "")
        elif result.total_leaks:
            summary = _plural(result.total_leaks, "breach")
            flag(CRITICAL, f"{_plural(result.total_leaks, 'historical breach')} (Have I Been Pwned)")
        else:
            status, summary = OK, "no public breaches"

    elif name == "ShodanResult":
        summary = f"{result.ip_address} · {_plural(len(result.open_ports), 'port')}"
        if result.vulns:
            summary += f" · {_plural(len(result.vulns), 'CVE')}"
            shown = ", ".join(result.vulns[:5]) + (f" +{len(result.vulns) - 5}" if len(result.vulns) > 5 else "")
            flag(CRITICAL, f"Known CVEs on {result.ip_address}: {shown}")

    elif name == "HeaderResult":
        if not result.reachable:
            status, summary = UNKNOWN, "unreachable"
        else:
            summary = f"grade {result.grade} ({result.security_score}/100)"
            if result.grade in ("D", "E", "F"):
                flag(WARN, f"Weak security headers: grade {result.grade}, {len(result.missing_headers)} missing")
            elif result.grade in ("A", "A+", "B"):
                status = OK

    elif name == "WhoisResult":
        if not result.source:
            status, summary = UNKNOWN, "no WHOIS data"
        else:
            summary = f"{result.registrar} · expires {result.expiry_date[:10]}"
            if result.is_expired:
                flag(CRITICAL, f"Domain registration expired ({result.expiry_date})")
            elif result.is_expiring_soon:
                flag(WARN, f"Domain registration expires soon ({result.expiry_date})")

    elif name == "CdnBypassResult":
        summary = f"behind {result.cdn_indicator}" if result.behind_cdn else "no CDN"
        if result.candidate_origin_ips:
            summary += f" · {_plural(len(result.candidate_origin_ips), 'candidate')}"
        if result.confirmed_origin_ip:
            flag(CRITICAL, f"Origin IP exposed: {result.confirmed_origin_ip} ({result.confirmed_via})")
        elif result.behind_cdn and result.candidate_origin_ips:
            flag(WARN, f"{_plural(len(result.candidate_origin_ips), 'candidate origin IP')} behind the CDN (unconfirmed)")

    elif name == "JwtResult":
        summary = f"{_plural(result.tokens_found, 'token')} in {_plural(result.js_files_scanned, 'file')}"
        for v in result.vulnerabilities:
            flag(CRITICAL, _strip_marker(v))

    else:
        summary = name

    if findings:
        status = min((sev for sev, _ in findings), key=SEVERITY_RANK.__getitem__)
    return status, summary, findings


def collect_findings(modules: Sequence[str], results: Sequence[Any]) -> List[Tuple[str, str, str]]:
    """(severity, module, text) for every finding, most severe first, scan order within a level."""
    found = []
    for module, result in zip(modules, results):
        if isinstance(result, BaseException):
            continue
        found.extend((sev, module, text) for sev, text in assess(result)[2])
    return sorted(found, key=lambda f: SEVERITY_RANK[f[0]])


def render_banner(version: str):
    """The big logo for -h and bare invocations."""
    title = Text.assemble(("Advanced OSINT & Reconnaissance Framework", "dim italic"), ("  v" + version, ACCENT))
    return Group(Text(), Align.center(render_eye(44, 12)), Text(), Align.center(render_wordmark()),
                 Text(), Align.center(title), Text())


def render_header(version: str, target: str, modules: int, stealth: bool, proxy: Optional[str], delay: float,
                  output: Optional[str] = None):
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", justify="right")
    grid.add_column()
    grid.add_row("", Text("Advanced OSINT & Reconnaissance Framework", style="dim italic"))
    grid.add_row("target", Text(target, style="bold"))
    settings = Text(_plural(modules, "module"))
    settings.append("  ·  mode ", style="dim")
    settings.append("stealth" if stealth else "normal", style="yellow" if stealth else "green")
    if delay:
        settings.append("  ·  delay ", style="dim")
        settings.append(f"{delay:g}s")
    grid.add_row("scan", settings)
    if proxy:
        grid.add_row("proxy", Text(proxy, style="magenta"))
    grid.add_row("report", Text(output) if output else Text("terminal only (-o to save)", style="dim"))
    panel = Panel(
        grid,
        title=Text.assemble(("◉ ", f"bold {ACCENT}"), ("RED EYE ", "bold"), (f"v{version}", ACCENT)),
        title_align="left",
        border_style="red",
        box=box.ROUNDED,
        expand=False,
        padding=(0, 1),
    )
    # The eye matches the panel's height: borders plus one row per grid line.
    layout = Table.grid(padding=(0, 2))
    layout.add_row(render_eye(24, grid.row_count + 2), panel)
    return layout


@dataclass
class ModuleRow:
    name: str
    state: str = "pending"  # pending | running | done | error
    started: float = 0.0
    finished: float = 0.0
    severity: str = INFO
    summary: str = ""

    def elapsed(self, now: float) -> Optional[float]:
        if not self.started:
            return None
        return (self.finished or now) - self.started


class ScanDashboard:
    """Live per-module status table. Rich re-renders it through __rich__ on every refresh."""

    def __init__(self, modules: Sequence[str]):
        self.rows: Dict[str, ModuleRow] = {m: ModuleRow(m) for m in modules}
        self.started = time.monotonic()
        self.finished = 0.0
        self.spinner = Spinner("dots", style="cyan")

    async def track(self, module: str, coro: Awaitable[Any]) -> Any:
        row = self.rows[module]
        row.state, row.started = "running", time.monotonic()
        try:
            result = await coro
        except Exception as e:
            row.state, row.severity, row.summary = "error", UNKNOWN, f"{type(e).__name__}: {e}"
            raise
        finally:
            row.finished = time.monotonic()
        try:
            row.severity, row.summary, _ = assess(result)
        except Exception:
            # A summary glitch must not turn a finished scan into an error.
            row.severity, row.summary = INFO, "done"
        row.state = "done"
        return result

    def stop(self) -> None:
        self.finished = time.monotonic()

    def _status_cell(self, row: ModuleRow):
        if row.state == "running":
            return self.spinner
        if row.state == "pending":
            return Text("·", style="dim")
        if row.state == "error":
            return Text("✖", style="red")
        return Text(SEVERITY_ICON[row.severity], style=SEVERITY_STYLE[row.severity])

    def __rich__(self):
        now = time.monotonic()
        table = Table(box=box.SIMPLE_HEAD, header_style="bold dim", show_edge=False, pad_edge=False, expand=False)
        table.add_column("", width=1, no_wrap=True)
        table.add_column("MODULE", style="bold", no_wrap=True)
        table.add_column("TIME", justify="right", style="dim", no_wrap=True)
        table.add_column("RESULT", no_wrap=True, overflow="ellipsis", max_width=80)

        for row in self.rows.values():
            elapsed = row.elapsed(now)
            if row.state == "running":
                result = Text("scanning…", style="dim italic")
            elif row.state == "pending":
                result = Text("queued", style="dim")
            elif row.state == "error":
                result = Text(row.summary, style="red")
            else:
                style = SEVERITY_STYLE[row.severity] if row.severity in (CRITICAL, WARN) else ""
                result = Text(row.summary, style=style)
            table.add_row(self._status_cell(row), row.name, f"{elapsed:.1f}s" if elapsed is not None else "", result)

        done = sum(r.state in ("done", "error") for r in self.rows.values())
        total = len(self.rows)
        footer = Table.grid(padding=(0, 1))
        footer.add_row(
            ProgressBar(total=total, completed=done, width=36, complete_style="red", finished_style="green"),
            Text(f"{done}/{total}", style="bold"),
            Text(f"· {(self.finished or now) - self.started:.1f}s", style="dim"),
        )
        return Group(table, footer)


def render_findings(findings: List[Tuple[str, str, str]], limit: int = FINDINGS_LIMIT) -> Panel:
    critical = sum(f[0] == CRITICAL for f in findings)
    warnings = sum(f[0] == WARN for f in findings)
    shown = [f for f in findings if f[0] in (CRITICAL, WARN)]

    if not shown:
        return Panel(
            Text("✔ No critical findings or warnings flagged.", style="green"),
            title=Text("FINDINGS", style="bold green"), title_align="left",
            border_style="green", box=box.ROUNDED, expand=False,
        )

    body = Table.grid(padding=(0, 1))
    body.add_column(no_wrap=True)
    body.add_column(style="dim", no_wrap=True)
    body.add_column()
    for sev, module, text in shown[:limit]:
        # Text(...) keeps scan data like '[eyJ...]' literal instead of Rich markup.
        body.add_row(Text(SEVERITY_ICON[sev], style=SEVERITY_STYLE[sev]), module, Text(text))
    if len(shown) > limit:
        body.add_row("", "", Text(f"… and {len(shown) - limit} more (full list in the -o report).", style="dim"))

    title = Text("FINDINGS  ", style="bold")
    if critical:
        title.append(f"{critical} critical", style="bold red")
    if critical and warnings:
        title.append("  ·  ", style="dim")
    if warnings:
        title.append(_plural(warnings, "warning"), style="yellow")
    return Panel(
        body, title=title, title_align="left",
        border_style="red" if critical else "yellow", box=box.ROUNDED, expand=False,
    )


def findings_report(findings: List[Tuple[str, str, str]]) -> str:
    """Plain-text findings block for the top of the -o report."""
    shown = [f for f in findings if f[0] in (CRITICAL, WARN)]
    if not shown:
        return "FINDINGS: none flagged.\n"
    lines = [f"FINDINGS ({len(shown)}):"]
    lines.extend(f"  [{sev.upper()}] {module}: {text}" for sev, module, text in shown)
    return "\n".join(lines) + "\n"
