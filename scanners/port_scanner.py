import asyncio
import random
from typing import List
from core.base import BaseScanner
from models.report import PortResult

class PortScanner(BaseScanner):
    """
    An asynchronous port scanner designed for speed and stealth.
    Conducts a rapid TCP connect scan of the top 50 critical ports.
    """

    DIRECT_CONTACT = True  # raw TCP connections to the target

    async def execute(self) -> PortResult:
        
        # Expanded port list: web, DB, API, admin panels, dev servers
        print(f"[*] PortScanner: Initiating port scan (Top 50) for {self.host}...")
        # TCP only: UDP services (SNMP 161/162, syslog 514) cannot be probed with connect()
        ports_to_scan = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            443, 445, 993, 995, 3306, 3389, 5432, 5900, 6379,
            8000, 8080, 8081, 8443, 8888, 9000, 9200, 27017,
            3000, 4443, 5000, 5001, 7000, 9001, 9999,
            1433, 1521, 389, 636, 5985, 6443, 11211, 587, 465,
            2082, 2083, 2086, 2087, 2095, 2096  # cPanel, webmail
        ]
        concurrent_limit = 5 if (self.stealth or self.delay > 0) else 30
        timeout_val = 3.0  # 3s for slow/remote targets

        open_ports: List[int] = []
        
        # Semaphore controls the maximum number of concurrent open connections
        semaphore = asyncio.Semaphore(concurrent_limit)

        async def check_port(port: int):
            async with semaphore:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                elif self.stealth:
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(self.host, port),
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
            print(f"[+] PortScanner: Successfully identified {len(open_ports)} open ports on {self.host}.")
        else:
            print("[-] PortScanner: No open ports discovered. Target may be dead or heavily firewalled.")

        return PortResult(
            target_domain=self.host,
            open_ports=open_ports
        )