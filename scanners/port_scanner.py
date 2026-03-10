import asyncio
from typing import List
from core.base import BaseScanner
from models.report import PortResult

class PortScanner(BaseScanner):
    """
    An asynchronous port scanner designed for speed and stealth.
    Normal mode: Conducts a rapid scan of the top 20 critical ports.
    Deep Scan (-v): Conducts a full 65535 port scan utilizing a strict 
    Semaphore to prevent OS socket exhaustion (Too many open files).
    """
    async def execute(self) -> PortResult:
        
        # Determine operational mode based on the deep_scan flag
        if self.deep_scan:
            print(f"[*] PortScanner: [DEEP SCAN] Initiating full 65535 port scan for {self.target}...")
            ports_to_scan = range(1, 65536)
            concurrent_limit = 1000
            timeout_val = 2.0  # 2s for firewalled/filtered ports
        else:
            # Expanded port list: web, DB, API, admin panels, dev servers
            print(f"[*] PortScanner: Initiating port scan (Top 50) for {self.target}...")
            ports_to_scan = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
                443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379,
                8000, 8080, 8081, 8443, 8888, 9000, 9200, 27017,
                3000, 4443, 5000, 5001, 7000, 9001, 9999,
                1433, 1521, 389, 636, 161, 162, 514, 587, 465,
                2082, 2083, 2086, 2087, 2095, 2096  # cPanel, webmail
            ]
            concurrent_limit = 30
            timeout_val = 3.0  # 3s for slow/remote targets

        open_ports: List[int] = []
        
        # Semaphore controls the maximum number of concurrent open connections
        semaphore = asyncio.Semaphore(concurrent_limit)

        async def check_port(port: int):
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.target, port),
                        timeout=timeout_val
                    )
                    # If we reach here, the connection was successful
                    open_ports.append(port)
                    
                    # Cleanly close the connection to avoid resource leaks
                    writer.close()
                    await writer.wait_closed()
                    
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    # Port is closed, heavily filtered by a WAF/Firewall, or host is unreachable.
                    pass

        # Queue all port checking tasks
        tasks = [check_port(port) for port in ports_to_scan]
        
        # Execute tasks concurrently
        await asyncio.gather(*tasks)

        # Sort numerically for cleaner report generation
        open_ports.sort()

        if open_ports:
            print(f"[+] PortScanner: Successfully identified {len(open_ports)} open ports on {self.target}.")
        else:
            print(f"[-] PortScanner: No open ports discovered. Target may be dead or heavily firewalled.")

        return PortResult(
            target_domain=self.target,
            open_ports=open_ports
        )