"""
Endpoint Discovery Module
Probes a wordlist of sensitive paths and flags any that respond unexpectedly.
"""
import warnings
import requests
from urllib.parse import urljoin
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

WORDLIST = [
    "/admin", "/login", "/logout", "/.env", "/backup", "/api",
    "/config", "/phpmyadmin", "/wp-admin", "/wp-login.php",
    "/debug", "/test", "/swagger", "/swagger-ui", "/api-docs",
    "/.git", "/server-status", "/actuator", "/health", "/metrics",
    "/console", "/.htaccess", "/robots.txt", "/sitemap.xml",
    "/api/v1", "/api/v2", "/graphql", "/admin/config",
]

STATUS_SEVERITY = {
    200: "high",
    201: "high",
    301: "low",
    302: "low",
    401: "info",
    403: "medium",
    500: "medium",
}

STATUS_FINDINGS = {
    200: "Path returned 200 OK — potentially exposed without authentication",
    201: "Path returned 201 Created — endpoint may be publicly writable",
    301: "Path redirects (301) — may exist at redirect target",
    302: "Path redirects (302) — may exist at redirect target",
    403: "Path returned 403 Forbidden — resource exists but access is restricted",
    500: "Path returned 500 Internal Server Error — may reveal debug information",
}

RECOMMENDATIONS = {
    "/.env":           "Remove .env from web root. Add to .gitignore. Store secrets in environment variables or a vault.",
    "/admin":          "Restrict admin interfaces to internal networks only. Add IP allowlisting.",
    "/phpmyadmin":     "Do not expose phpMyAdmin publicly. Use a SSH tunnel or VPN for database admin access.",
    "/wp-admin":       "Restrict /wp-admin to known IPs. Enforce 2FA on all admin accounts.",
    "/.git":           "Remove .git from web root immediately — full source code may be exposed.",
    "/actuator":       "Restrict Spring Boot Actuator endpoints. Expose only /health publicly, not /env or /shutdown.",
    "/swagger":        "Disable Swagger UI in production or restrict it to authenticated users.",
    "/swagger-ui":     "Disable Swagger UI in production or restrict it to authenticated users.",
    "/api-docs":       "Restrict API documentation to authenticated sessions in production.",
    "/graphql":        "Enable authentication on GraphQL endpoint. Disable introspection in production.",
    "/server-status":  "Disable Apache mod_status in production. It exposes server internals.",
    "/.htaccess":      "Configure web server to deny direct access to .htaccess files.",
}


class EndpointDiscovery:
    """Probes sensitive paths against the target and flags accessible ones."""

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.wordlist = WORDLIST

    def _check_path(self, path: str) -> dict | None:
        url = self.target_url + path
        try:
            response = requests.get(
                url,
                timeout=5,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "VulnScanner/1.0 (authorized-security-assessment)"},
            )
            status = response.status_code

            if status in STATUS_FINDINGS:
                finding_text = STATUS_FINDINGS[status]
                severity = STATUS_SEVERITY.get(status, "low")

                # Downgrade known-safe paths
                if path in ("/robots.txt", "/sitemap.xml", "/health") and status == 200:
                    severity = "info"
                    finding_text = f"Standard path {path} is accessible (expected)"

                recommendation = RECOMMENDATIONS.get(
                    path,
                    f"Review whether {path} should be publicly accessible. "
                    "Add authentication or restrict access via firewall rules if not intentional.",
                )

                return {
                    "finding": f"HTTP {status}: {finding_text}",
                    "location": url,
                    "severity": severity,
                    "recommendation": recommendation,
                    "module": "Endpoint Discovery",
                    "details": {
                        "path": path,
                        "status_code": status,
                        "full_url": url,
                    },
                }
            return None

        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

    def scan(self) -> list[dict]:
        """Scan all paths and return findings."""
        findings = []
        for path in self.wordlist:
            result = self._check_path(path)
            if result:
                findings.append(result)
        return findings

    def scan_with_progress(self):
        """Generator yielding (progress_pct, finding_or_None) for each path checked."""
        total = len(self.wordlist)
        for idx, path in enumerate(self.wordlist):
            progress = int((idx + 1) / total * 100)
            result = self._check_path(path)
            yield progress, result
