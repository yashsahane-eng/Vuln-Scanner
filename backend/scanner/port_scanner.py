"""
Port Scanner Module
Performs threaded TCP connect scans against a list of common ports.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse


PORTS_TO_SCAN = [21, 22, 23, 25, 53, 80, 443, 3000, 3306, 3389, 5432, 6379, 8080, 8443, 8888]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3000: "Node.js / Dev Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    8888: "Jupyter / Dev",
}

PORT_SEVERITY = {
    21: "high",
    22: "medium",
    23: "critical",
    25: "medium",
    53: "low",
    80: "info",
    443: "info",
    3000: "medium",
    3306: "high",
    3389: "high",
    5432: "high",
    6379: "high",
    8080: "medium",
    8443: "low",
    8888: "medium",
}

PORT_RECOMMENDATIONS = {
    21: "Disable FTP if not required. Use SFTP (port 22) instead. FTP transmits credentials in plaintext.",
    22: "Ensure SSH uses key-based authentication only. Disable PasswordAuthentication in sshd_config. Use fail2ban to prevent brute-force.",
    23: "Disable Telnet immediately — it transmits all data (including credentials) in cleartext. Use SSH instead.",
    25: "Restrict SMTP relay. Configure SPF, DKIM, and DMARC records. Consider blocking external access.",
    3000: "Development server detected. Never run dev servers in production. Move to a production-grade server.",
    3306: "MySQL should be bound to 127.0.0.1. Never expose to public internet. Use a firewall rule to restrict access.",
    3389: "RDP should not be internet-facing. Place behind VPN or bastion host. Apply latest patches (BlueKeep, DejaBlue).",
    5432: "PostgreSQL should bind to localhost only. Use pg_hba.conf to restrict access by IP and require strong authentication.",
    6379: "Redis has no authentication by default. Set 'requirepass' in redis.conf. Bind to 127.0.0.1 only.",
    8080: "HTTP alternate port open. Ensure this is intentional. Check for unintended admin interfaces.",
    8443: "HTTPS alternate port — verify this is expected and the certificate is valid.",
    8888: "Jupyter Notebook port detected. Ensure token/password auth is configured and access is restricted.",
}


class PortScanner:
    """Threaded TCP connect scanner for common service ports."""

    def __init__(self, target_url: str, timeout: float = 1.5):
        parsed = urlparse(target_url)
        self.host = parsed.hostname or target_url.split("//")[-1].split("/")[0].split(":")[0]
        self.timeout = timeout
        self.ports = PORTS_TO_SCAN

    def _check_port(self, port: int) -> Optional[dict]:
        """Attempt a TCP connection to host:port. Returns a finding dict if open, else None."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.host, port))
                if result == 0:
                    service = PORT_SERVICES.get(port, "Unknown")
                    severity = PORT_SEVERITY.get(port, "medium")
                    unexpected = port not in {80, 443}
                    recommendation = PORT_RECOMMENDATIONS.get(
                        port,
                        f"Review whether {service} on port {port} should be publicly accessible."
                    )
                    return {
                        "finding": f"Port {port}/TCP ({service}) is open"
                                   + (" — verify this is intentional" if unexpected else ""),
                        "location": f"{self.host}:{port}",
                        "severity": severity,
                        "recommendation": recommendation,
                        "module": "Port Scanner",
                        "details": {
                            "port": port,
                            "service": service,
                            "is_unexpected": unexpected,
                        },
                    }
                return None
        except (socket.timeout, OSError):
            return None

    def scan(self) -> list[dict]:
        """Run full scan and return list of findings for open ports."""
        findings = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_port, port): port for port in self.ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
        return sorted(findings, key=lambda x: x["details"]["port"])

    def scan_with_progress(self):
        """Generator yielding (progress_pct: int, finding: dict | None) as each port resolves."""
        total = len(self.ports)
        completed = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_port, port): port for port in self.ports}
            for future in as_completed(futures):
                completed += 1
                progress = int(completed / total * 100)
                result = future.result()
                yield progress, result
