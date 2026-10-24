"""Offline unit tests for the pure parsing/normalisation helpers."""
import base64
import hashlib
import hmac
import io
import json
import unittest

from rich.console import Console

from utils.domain import base_name, normalize_target, registered_domain, split_target
from utils.dns import _clean_record
from utils.client import hackertarget_failed
from scanners.dns_scanner import analyze_spf, dkim_has_key, parse_axfr, parse_dmarc_policy
from scanners.jwt_scanner import JwtDecoder
from scanners.takeover_scanner import match_service
from models.report import BackupResult, BreachResult, DnsResult, JwtResult, RobotsResult
from utils.eye import render_eye
from utils.ui import CRITICAL, OK, UNKNOWN, WARN, assess, collect_findings, render_findings
import redeye


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = b64(json.dumps(payload).encode())
    digest = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]
    sig = b64(hmac.new(secret.encode(), f"{header}.{body}".encode(), digest).digest())
    return f"{header}.{body}.{sig}"


class TargetNormalizationTests(unittest.TestCase):
    def test_strips_scheme_credentials_path_and_default_port(self):
        self.assertEqual(normalize_target("https://user:pw@Example.COM:443/path?x=1#frag"), "example.com")
        self.assertEqual(normalize_target("http://example.com:80/"), "example.com")
        self.assertEqual(normalize_target("  example.com/  "), "example.com")

    def test_keeps_custom_port(self):
        self.assertEqual(normalize_target("https://example.com:8443/app"), "example.com:8443")
        self.assertEqual(split_target("example.com:8443"), ("example.com", 8443))

    def test_ip_targets(self):
        self.assertEqual(normalize_target("127.0.0.1:8080"), "127.0.0.1:8080")
        self.assertEqual(normalize_target("http://[::1]:8080/"), "[::1]:8080")
        self.assertEqual(split_target("[::1]:8080"), ("::1", 8080))

    def test_rejects_garbage(self):
        for bad in ("", "bad host!", "exa mple.com", "-lead.com", "example.com:99999"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_target(bad)

    def test_registered_domain_and_base_name(self):
        self.assertEqual(registered_domain("www.shop.acme.co.uk"), "acme.co.uk")
        self.assertEqual(registered_domain("api.acme.com"), "acme.com")
        self.assertEqual(base_name("www.acme.com.tr"), "acme")
        self.assertEqual(base_name("www.example.com"), "example")


class DnsParsingTests(unittest.TestCase):
    def test_txt_chunks_are_joined(self):
        self.assertEqual(_clean_record('"v=spf1 include:a.com " "-all"', "TXT"), "v=spf1 include:a.com -all")
        self.assertEqual(_clean_record("v=spf1 -all", "TXT"), "v=spf1 -all")
        self.assertEqual(_clean_record("10 mail.example.com.", "MX"), "10 mail.example.com")

    def test_spf_strict_record_is_not_vulnerable(self):
        vulns, info = analyze_spf(["v=spf1 -all", "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9"])
        self.assertEqual(vulns, [])
        self.assertTrue(any("v=spf1 -all" in i for i in info))

    def test_spf_variants(self):
        self.assertTrue(analyze_spf([])[0][0].startswith("MISSING SPF"))
        self.assertTrue(analyze_spf(["v=spf1 +all"])[0][0].startswith("DANGEROUS SPF"))
        self.assertTrue(analyze_spf(["v=spf1 a mx all"])[0][0].startswith("DANGEROUS SPF"))
        self.assertTrue(analyze_spf(["v=spf1 ?all"])[0][0].startswith("WEAK SPF"))
        self.assertEqual(analyze_spf(["v=spf1 ~all"])[0], [])
        self.assertTrue(analyze_spf(["v=spf1 -all", "v=spf1 ~all"])[0][0].startswith("MULTIPLE SPF"))

    def test_dmarc_policy(self):
        self.assertEqual(parse_dmarc_policy("v=DMARC1;p=reject;sp=none"), "reject")
        self.assertEqual(parse_dmarc_policy("v=DMARC1; sp=none; p=quarantine"), "quarantine")
        self.assertEqual(parse_dmarc_policy("v=DMARC1; rua=mailto:x@y.com"), "none")

    def test_dkim_empty_key_is_revoked(self):
        self.assertFalse(dkim_has_key("v=DKIM1; p="))
        self.assertFalse(dkim_has_key("v=DKIM1; p= ; t=y"))
        self.assertTrue(dkim_has_key("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"))

    def test_refused_axfr_is_not_vulnerable(self):
        transcript = (
            "\n; > DiG > -t axfr @hera.ns.cloudflare.com example.com\n; (6 servers found)\n"
            ";; global options: +cmd\n; Transfer failed.\n\n"
            "; > DiG > -t axfr @elliott.ns.cloudflare.com example.com\n; (6 servers found)\n"
            ";; global options: +cmd\n; Transfer failed.\n"
        )
        self.assertEqual(parse_axfr(transcript), (True, False, []))

    def test_open_axfr_is_vulnerable(self):
        transcript = (
            "; > DiG > -t axfr @nsztm1.digi.ninja zonetransfer.me\n;; global options: +cmd\n"
            "zonetransfer.me.\t7200\tIN\tSOA\tnsztm1.digi.ninja. robin.digi.ninja. 2019100801 172800 900 1209600 3600\n"
            "zonetransfer.me.\t7200\tIN\tA\t5.196.105.14\n;; XFR size: 2 records\n"
        )
        checked, vulnerable, records = parse_axfr(transcript)
        self.assertTrue(checked and vulnerable)
        self.assertEqual(len(records), 2)

    def test_hackertarget_errors_are_unknown_not_findings(self):
        for message in ("error input invalid - enter IP or Hostname", "API count exceeded - Increase Quota with Membership", ""):
            self.assertTrue(hackertarget_failed(message))
            self.assertEqual(parse_axfr(message), (False, False, []))


class TakeoverMatchingTests(unittest.TestCase):
    def test_service_matching_by_cname(self):
        self.assertEqual(match_service("acme.github.io"), "GitHub Pages")
        self.assertEqual(match_service("acme-prod.herokuapp.com"), "Heroku")
        self.assertEqual(match_service("acme.azurewebsites.net"), "Azure")
        self.assertIsNone(match_service("acme.example.net"))


class JwtTests(unittest.TestCase):
    def setUp(self):
        self.scanner = JwtDecoder("acme.com")

    def test_weak_secret_and_claim_classification(self):
        entry = self.scanner._decode_token(make_jwt({"sub": "1", "role": "admin", "password": "x"}))
        self.assertEqual(entry["cracked_secret"], "secret")
        self.assertEqual(entry["sensitive_claims"], ["password"])
        self.assertEqual(entry["privilege_claims"], ["role"])

    def test_hs512_and_domain_secret(self):
        entry = self.scanner._decode_token(make_jwt({"sub": "1"}, secret="acme", alg="HS512"))
        self.assertEqual(entry["cracked_secret"], "acme")

    def test_previews_differ_between_tokens(self):
        a = self.scanner._decode_token(make_jwt({"sub": "1"}))["token_preview"]
        b = self.scanner._decode_token(make_jwt({"sub": "2"}))["token_preview"]
        self.assertNotEqual(a, b)

    def test_garbage_token_is_ignored(self):
        self.assertEqual(self.scanner._decode_token("eyJ.eyJ.x"), {})


class RenderingTests(unittest.TestCase):
    def render(self, result) -> str:
        buffer = io.StringIO()
        original = redeye.console
        redeye.console = Console(file=buffer, width=200, color_system=None)
        try:
            redeye.render_panel(*redeye.format_result(result))
        finally:
            redeye.console = original
        return buffer.getvalue()

    def test_bracketed_scan_data_is_printed_literally(self):
        robots = RobotsResult(target_domain="t", extracted_paths=["/search[/q]", "/docs/[i]ndex", "[bold]x"])
        out = self.render(robots)
        for path in robots.extracted_paths:
            self.assertIn(path, out)

    def test_jwt_preview_and_dns_info_survive_rendering(self):
        jwt = JwtResult("t", 1, 1, decoded_tokens=[{"token_preview": "eyJhbGciOi...abcdefgh", "alg": "HS256", "expired": False, "sensitive_claims": [], "privilege_claims": []}])
        self.assertIn("[eyJhbGciOi...abcdefgh]", self.render(jwt))
        dns = DnsResult("t", spf_checked=True, info=["SPF Record: v=spf1 -all"])
        self.assertIn("[i] SPF Record", self.render(dns))

    def test_unchecked_dns_never_claims_vulnerable(self):
        _, lines = redeye.format_result(DnsResult("t"))
        text = "\n".join(lines)
        self.assertNotIn("VULNERABLE", text)
        self.assertIn("Unknown", text)

    def test_preview_is_trimmed_but_report_is_full(self):
        robots = RobotsResult("t", [f"/p{i}" for i in range(25)])
        _, preview = redeye.format_result(robots)
        _, full = redeye.format_result(robots, full=True)
        self.assertIn("/p24", "\n".join(full))
        self.assertNotIn("/p24", "\n".join(preview))


class FindingsTests(unittest.TestCase):
    def test_unchecked_lookups_are_unknown_not_findings(self):
        self.assertEqual(assess(DnsResult("t"))[0], UNKNOWN)
        self.assertEqual(assess(DnsResult("t"))[2], [])
        self.assertEqual(assess(BreachResult("t", lookup_ok=False, error="timeout"))[0], UNKNOWN)

    def test_severity_follows_worst_finding(self):
        dns = DnsResult("t", spf_checked=True, dmarc_checked=True, vulnerabilities=["MISSING DMARC — x"])
        self.assertEqual(assess(dns)[0], WARN)
        self.assertEqual(assess(BackupResult("t", ["/.git/config"]))[0], CRITICAL)
        self.assertEqual(assess(BackupResult("t", []))[0], OK)

    def test_findings_are_ranked_and_errors_skipped(self):
        results = [
            DnsResult("t", spf_checked=True, dmarc_checked=True, vulnerabilities=["MISSING DMARC — x"]),
            RuntimeError("boom"),
            JwtResult("t", 1, 1, vulnerabilities=["CRITICAL - Token [eyJ..ab] uses alg:none"]),
        ]
        findings = collect_findings(["dns", "port", "jwt"], results)
        self.assertEqual([(sev, module) for sev, module, _ in findings], [(CRITICAL, "jwt"), (WARN, "dns")])
        self.assertEqual(findings[0][2], "Token [eyJ..ab] uses alg:none")

    def test_eye_fits_requested_size(self):
        for columns, rows in ((26, 6), (26, 7), (56, 13)):
            lines = render_eye(columns, rows).plain.split("\n")
            self.assertEqual(len(lines), rows)
            self.assertTrue(all(len(line) == columns for line in lines))

    def test_findings_panel_prints_scan_data_literally(self):
        buffer = io.StringIO()
        Console(file=buffer, width=200, color_system=None).print(render_findings([(CRITICAL, "jwt", "Token [eyJ..ab] [bold]x")]))
        self.assertIn("Token [eyJ..ab] [bold]x", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
