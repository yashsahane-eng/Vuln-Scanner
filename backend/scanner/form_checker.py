"""
Form Checker Module
Parses HTML forms with BeautifulSoup, submits harmless test inputs,
and checks whether they are reflected unescaped in the response (potential XSS/injection).
"""
import warnings
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Harmless payloads that reveal reflection/injection issues in dev environments
TEST_PAYLOADS = [
    "<script>test_vuln_xss_marker</script>",
    "' OR '1'='1' --",
    "{{7*7}}",
]

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "VulnScanner/1.0 (authorized-security-assessment)"})


class FormChecker:
    """Parses forms from the target page and checks for input reflection and missing CSRF tokens."""

    def __init__(self, target_url: str):
        self.target_url = target_url

    def _fetch_page(self, url: str) -> tuple[str | None, BeautifulSoup | None]:
        try:
            resp = SESSION.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, "html.parser")
            return resp.text, soup
        except Exception:
            return None, None

    def _resolve_action(self, form_action: str) -> str:
        if not form_action or form_action.startswith("#"):
            return self.target_url
        parsed = urlparse(form_action)
        if parsed.scheme:
            return form_action
        return urljoin(self.target_url, form_action)

    def _has_csrf_token(self, form) -> bool:
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            inp_type = (inp.get("type") or "").lower()
            if inp_type == "hidden" and any(
                kw in name for kw in ("csrf", "token", "_token", "nonce", "authenticity")
            ):
                return True
        return False

    def _submit_payload(self, action_url: str, fields: dict) -> str | None:
        try:
            resp = SESSION.post(action_url, data=fields, timeout=8, verify=False, allow_redirects=True)
            return resp.text
        except Exception:
            return None

    def check(self) -> list[dict]:
        findings = []
        raw_html, soup = self._fetch_page(self.target_url)
        if soup is None:
            return [{
                "finding": "Could not fetch page for form analysis",
                "location": self.target_url,
                "severity": "medium",
                "recommendation": "Ensure the target URL is reachable and returns HTML.",
                "module": "Form Checker",
                "details": {"form_action": None, "payload": None, "reflected": False, "fields": []},
            }]

        forms = soup.find_all("form")
        if not forms:
            findings.append({
                "finding": "No HTML forms detected on the page",
                "location": self.target_url,
                "severity": "info",
                "recommendation": "No form-based attack surface found on this page.",
                "module": "Form Checker",
                "details": {"form_action": None, "payload": None, "reflected": False, "fields": []},
            })
            return findings

        for form in forms:
            action_url = self._resolve_action(form.get("action", ""))
            method = (form.get("method") or "get").lower()
            field_names = [
                inp.get("name") for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name") and inp.get("type", "text") not in ("submit", "button", "image", "reset")
            ]

            # Check for missing CSRF protection
            if method == "post" and not self._has_csrf_token(form):
                findings.append({
                    "finding": "Form submits via POST without a detectable CSRF token",
                    "location": action_url,
                    "severity": "medium",
                    "recommendation": (
                        "Implement CSRF protection: use the Synchronizer Token Pattern or "
                        "SameSite cookie attribute. Frameworks like Django, Rails, and Spring "
                        "provide built-in CSRF middleware."
                    ),
                    "module": "Form Checker",
                    "details": {
                        "form_action": action_url,
                        "payload": None,
                        "reflected": False,
                        "fields": field_names,
                    },
                })

            # Check for non-HTTPS form actions
            if action_url.startswith("http://") and not action_url.startswith("http://localhost"):
                findings.append({
                    "finding": "Form action submits data over unencrypted HTTP",
                    "location": action_url,
                    "severity": "high",
                    "recommendation": (
                        "Update form action URL to use HTTPS to protect credentials and "
                        "user data in transit."
                    ),
                    "module": "Form Checker",
                    "details": {
                        "form_action": action_url,
                        "payload": None,
                        "reflected": False,
                        "fields": field_names,
                    },
                })

            # Test for input reflection (potential XSS / SSTI)
            if field_names and method == "post":
                for payload in TEST_PAYLOADS:
                    test_data = {name: payload for name in field_names}
                    response_text = self._submit_payload(action_url, test_data)

                    if response_text and payload in response_text:
                        if payload.startswith("<script>"):
                            finding_text = "XSS: Script tag payload reflected unescaped in response"
                            severity = "high"
                            recommendation = (
                                "Output encoding is missing. Escape all user-supplied input before "
                                "rendering in HTML context. Use your framework's auto-escaping "
                                "(e.g., Jinja2 autoescape, Django templates, React JSX)."
                            )
                        elif "OR" in payload:
                            finding_text = "Possible SQL injection: SQL payload reflected in response"
                            severity = "high"
                            recommendation = (
                                "Use parameterized queries or prepared statements instead of "
                                "string concatenation. ORMs like SQLAlchemy handle this automatically."
                            )
                        elif "{{" in payload:
                            finding_text = "Possible SSTI: Template expression reflected in response"
                            severity = "high"
                            recommendation = (
                                "Server-Side Template Injection may be present. Never render "
                                "user input directly into template strings. Use sandboxed template rendering."
                            )
                        else:
                            finding_text = f"Payload reflected unescaped: {payload[:40]}"
                            severity = "medium"
                            recommendation = "Sanitize and encode all user input before reflection in responses."

                        findings.append({
                            "finding": finding_text,
                            "location": action_url,
                            "severity": severity,
                            "recommendation": recommendation,
                            "module": "Form Checker",
                            "details": {
                                "form_action": action_url,
                                "payload": payload,
                                "reflected": True,
                                "fields": field_names,
                            },
                        })
                        break  # One reflected payload per form is sufficient

        return findings
