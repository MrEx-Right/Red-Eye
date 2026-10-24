"""
Integration tests against throwaway local HTTP servers — no traffic leaves
the machine. Covers the regressions found in the October 2026 audit:
binary files misread as errors, catch-all (soft-404) false positives,
redirect handling, and target-controlled data crashing the report.
"""
import asyncio
import contextlib
import io
import os
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rich.console import Console

from utils.client import AsyncClient
from utils.soft404 import Soft404Filter
from scanners.backup_scanner import BackupScanner
from scanners.dir_scanner import DirScanner
from scanners.robots_scanner import RobotsScanner
import redeye


def make_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("dump.sql", "\x00\xff" * 4000)
    return buffer.getvalue()


ZIP_BYTES = make_zip()

REAL_ROUTES = {
    "/": (200, "text/html", b"<html><body>Home</body></html>", {}),
    "/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /admin\nDisallow: /search[/q]\n", {}),
    "/backup.zip": (200, "application/zip", ZIP_BYTES, {}),
    "/db.sql": (200, "text/plain", b"CREATE TABLE users (id int);", {}),
    "/admin": (301, "text/html", b"", {"Location": "/admin/"}),
}


class _Server:
    """A tiny HTTP server: 'real' mode serves REAL_ROUTES and 404s the rest,
    'catchall' answers 200 with the same page for every path."""

    def __init__(self, mode: str):
        mode_ = mode

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                path = self.path.split("?")[0]
                if mode_ == "catchall":
                    status, ctype, body, extra = 200, "text/html", f"<html>Sorry, {path} was not found</html>".encode(), {}
                else:
                    status, ctype, body, extra = REAL_ROUTES.get(path, (404, "text/html", b"<html>404</html>", {}))
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for key, value in extra.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.target = f"127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_quietly(coro):
    with contextlib.redirect_stdout(io.StringIO()):
        return asyncio.run(coro)


class HttpScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = _Server("real")
        cls.catchall = _Server("catchall")

    @classmethod
    def tearDownClass(cls):
        cls.real.close()
        cls.catchall.close()

    def test_client_reads_binary_bodies(self):
        async def go():
            async with AsyncClient(timeout=5) as client:
                return await client.fetch(f"http://{self.real.target}/backup.zip", return_type="text", max_bytes=1024)
        status, body, _ = run_quietly(go())
        self.assertEqual(status, 200)
        self.assertIsInstance(body, str)

    def test_detect_base_url_falls_back_to_http(self):
        async def go():
            return await AsyncClient(timeout=5).detect_base_url(self.real.target)
        self.assertEqual(run_quietly(go()), f"http://{self.real.target}")

    def test_soft404_filter_learns_catchall_pages(self):
        async def go():
            async with AsyncClient(timeout=5) as client:
                base = f"http://{self.catchall.target}"
                filt = Soft404Filter()
                await filt.calibrate(client, base)
                status, body, headers = await client.fetch(f"{base}/backup.zip", allow_redirects=False)
                return filt.is_soft404("backup.zip", status, body, headers)
        self.assertTrue(run_quietly(go()))

    def test_backup_scanner_finds_binary_archives(self):
        result = run_quietly(BackupScanner(self.real.target).execute())
        self.assertIn("/backup.zip", result.found_backups)
        self.assertIn("/db.sql", result.found_backups)

    def test_backup_scanner_ignores_catchall_site(self):
        result = run_quietly(BackupScanner(self.catchall.target).execute())
        self.assertEqual(result.found_backups, [])

    def test_dir_scanner_reports_redirects_and_binaries(self):
        found = run_quietly(DirScanner(self.real.target).execute()).found_directories
        self.assertIn("/admin (Status: 301) -> /admin/", found)
        self.assertIn("/backup.zip (Status: 200)", found)
        self.assertIn("/db.sql (Status: 200)", found)

    def test_dir_scanner_ignores_catchall_site(self):
        self.assertEqual(run_quietly(DirScanner(self.catchall.target).execute()).found_directories, [])

    def test_robots_over_plain_http(self):
        result = run_quietly(RobotsScanner(self.real.target).execute())
        self.assertIn("/search[/q]", result.extracted_paths)

    def test_engine_survives_hostile_robots_and_saves_report(self):
        fd, report_path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        original = redeye.console
        redeye.console = Console(file=io.StringIO(), width=160, color_system=None)
        try:
            run_quietly(redeye.run_engine(self.real.target, False, report_path, "robots,backup", None, 0.0, None))
            terminal = redeye.console.file.getvalue()
        finally:
            redeye.console = original
        with open(report_path, encoding="utf-8") as f:
            report = f.read()
        os.remove(report_path)
        self.assertIn("/search[/q]", terminal)
        self.assertIn("/search[/q]", report)
        self.assertIn("/backup.zip", report)


if __name__ == "__main__":
    unittest.main()
