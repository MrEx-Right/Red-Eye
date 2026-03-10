import asyncio
import re
import sys
from core.base import BaseScanner
from models.report import WafResult

class WafDetector(BaseScanner):
    """
    wafw00f required. On Windows 'wafw00f' may not be in PATH; invokes via Python API.
    wafw00f 2.4.x: no --delay, use --no-colors.
    """
    async def execute(self) -> WafResult:
        print(f"[*] WafDetector: Running wafw00f for {self.target}...")

        url = f"https://{self.target}"
        
        args = [url, "-a", "--no-colors", "-T", "15"]
        if self.proxy:
            args.extend(["-p", self.proxy])

        detected_waf, has_waf = await self._run_wafw00f(args)

        if has_waf:
            print(f"[+] WafDetector: Target is behind {detected_waf}.")
        elif detected_waf == "None":
            print(f"[-] WafDetector: No WAF detected.")
        elif "Error" in detected_waf or "Timeout" in detected_waf:
            print(f"[!] WafDetector: {detected_waf}")

        return WafResult(
            target_domain=self.target,
            has_waf=has_waf,
            waf_name=detected_waf
        )

    async def _run_wafw00f(self, args: list) -> tuple:
        """Run wafw00f via Python API subprocess -> (waf_name, has_waf)"""
        detected_waf, has_waf = "Unknown/None", False
       
        args_str = ",".join(repr(a) for a in args)
        inline = f"import sys; sys.argv=['wafw00f',{args_str}]; from wafw00f.main import main; main()"
        cmd = [sys.executable, "-c", inline]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
            output = stdout.decode("utf-8", errors="ignore")
            err = stderr.decode("utf-8", errors="ignore")

            if process.returncode != 0 and "No module named" in err:
                detected_waf = "Error (pip install wafw00f)"
                return detected_waf, has_waf

            # ANSI strip
            clean = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", output)

            # Format: "[+] The site ... is behind Cloudflare (Cloudflare Inc.) WAF."
            m = re.search(r"is behind (.+?) WAF", clean)
            if m:
                has_waf = True
                detected_waf = m.group(1).strip().rstrip(".")
            elif "No WAF detected" in clean or "no WAF" in clean.lower():
                detected_waf = "None"
            elif "seems to be behind a WAF" in clean:
                has_waf = True
                detected_waf = "Generic/Unknown WAF"
            else:
                detected_waf = "Error / Unreachable"

            return detected_waf, has_waf

        except asyncio.TimeoutError:
            return "Timeout", False
        except Exception as e:
            print(f"[!] WafDetector: {e}")
            return f"Error ({e})", False