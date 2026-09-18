"""
Security Header Checker Module
Fetches the target URL and inspects HTTP response headers for missing security controls.
"""
import warnings
import requests
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "high",
        "recommendation": (
            "Add a Content-Security-Policy header to restrict which resources can be loaded. "
            "Start with: Content-Security-Policy: default-src 'self'"
        ),
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "recommendation": (
            "Add HSTS to enforce HTTPS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    "X-Frame-Options": {
        "severity": "medium",
        "recommendation": (
            "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks."
        ),
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "recommendation": (
            "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks."
        ),
    },
    "X-XSS-Protection": {
        "severity": "low",
        "recommendation": (
            "Add X-XSS-Protection: 1; mode=block (legacy browsers). Modern browsers use CSP instead."
        ),
    },
    "Referrer-Policy": {
        "severity": "low",
        "recommendation": (
            "Add Referrer-Policy: strict-origin-when-cross-origin to control referrer information leakage."
        ),
    },
    "Permissions-Policy": {
        "severity": "low",
        "recommendation": (
            "Add Permissions-Policy to control browser feature access: "
            "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    },
}

LEAKY_HEADERS = {
    "Server": "Reveals web server software and version. Remove or genericise this header.",
    "X-Powered-By": "Reveals backend technology stack. Remove this header from server configuration.",
    "X-AspNet-Version": "Reveals ASP.NET version. Disable via <httpRuntime enableVersionHeader='false'/>.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version. Disable in Global.asax: MvcHandler.DisableMvcResponseHeader = true;",
}


class HeaderChecker:
    """Checks HTTP response headers against a list of recommended security headers."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def check(self) -> list[dict]:
        findings = []
        try:
            response = requests.get(
                self.target_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "VulnScanner/1.0 (authorized-security-assessment)"},
            )
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Check for missing security headers
            for header_name, meta in REQUIRED_HEADERS.items():
                header_lower = header_name.lower()
                is_present = header_lower in headers

                # HSTS is only relevant for HTTPS targets
                if header_name == "Strict-Transport-Security" and not self.target_url.startswith("https://"):
                    continue

                if not is_present:
                    findings.append({
                        "finding": f"Missing security header: {header_name}",
                        "location": self.target_url,
                        "severity": meta["severity"],
                        "recommendation": meta["recommendation"],
                        "module": "Header Checker",
                        "details": {
                            "header": header_name,
                            "present": False,
                            "value": None,
                        },
                    })
                else:
                    findings.append({
                        "finding": f"Security header present: {header_name}",
                        "location": self.target_url,
                        "severity": "info",
                        "recommendation": "Header is configured. Review its policy for strictness.",
                        "module": "Header Checker",
                        "details": {
                            "header": header_name,
                            "present": True,
                            "value": headers[header_lower],
                        },
                    })

            # Check for information-leaking headers
            for header_name, recommendation in LEAKY_HEADERS.items():
                header_lower = header_name.lower()
                if header_lower in headers:
                    findings.append({
                        "finding": f"Information-leaking header present: {header_name}: {headers[header_lower]}",
                        "location": self.target_url,
                        "severity": "low",
                        "recommendation": recommendation,
                        "module": "Header Checker",
                        "details": {
                            "header": header_name,
                            "present": True,
                            "value": headers[header_lower],
                        },
                    })

        except requests.exceptions.ConnectionError:
            findings.append({
                "finding": "Could not connect to target URL",
                "location": self.target_url,
                "severity": "critical",
                "recommendation": "Ensure the target is running and accessible.",
                "module": "Header Checker",
                "details": {"header": None, "present": False, "value": None},
            })
        except requests.exceptions.Timeout:
            findings.append({
                "finding": "Connection timed out when checking headers",
                "location": self.target_url,
                "severity": "medium",
                "recommendation": "Target took too long to respond. Check if service is running.",
                "module": "Header Checker",
                "details": {"header": None, "present": False, "value": None},
            })
        except Exception as exc:
            findings.append({
                "finding": f"Unexpected error during header check: {exc}",
                "location": self.target_url,
                "severity": "medium",
                "recommendation": "Review connectivity and target configuration.",
                "module": "Header Checker",
                "details": {"header": None, "present": False, "value": None},
            })

        return findings
