"""
Report Generator Module
Aggregates all scan findings and renders them as JSON or a styled HTML report.
"""
import json
from datetime import datetime, timezone
from jinja2 import Environment, BaseLoader

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScan Report — {{ target }}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;600;700&display=swap');
  :root {
    --bg: #0a0a0a; --panel: #111827; --green: #00FF41; --cyan: #00FFFF;
    --yellow: #FFD700; --orange: #FF6B00; --red: #FF003C; --dim: #4a9960;
    --border: #1a3a2a; --font: 'Fira Code', 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--green); font-family: var(--font); padding: 40px 20px; }
  .header { text-align: center; border-bottom: 1px solid var(--border); padding-bottom: 30px; margin-bottom: 30px; }
  .logo { font-size: 22px; letter-spacing: 4px; color: var(--green); text-shadow: 0 0 20px var(--green); }
  .subtitle { color: var(--dim); font-size: 12px; margin-top: 8px; letter-spacing: 2px; }
  .meta { display: flex; justify-content: space-between; color: var(--dim); font-size: 12px; margin-top: 16px; }
  .risk-block { text-align: center; padding: 30px; margin: 20px auto; max-width: 400px;
    border: 1px solid; border-radius: 4px; }
  .risk-score { font-size: 72px; font-weight: 700; line-height: 1; }
  .risk-label { font-size: 18px; letter-spacing: 4px; margin-top: 8px; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 24px 0; }
  .summary-cell { background: var(--panel); border: 1px solid var(--border); padding: 16px;
    text-align: center; border-radius: 4px; }
  .summary-count { font-size: 32px; font-weight: 700; }
  .summary-label { font-size: 11px; color: var(--dim); margin-top: 4px; letter-spacing: 1px; }
  .section { margin: 24px 0; }
  .section-title { font-size: 14px; letter-spacing: 3px; color: var(--cyan); border-bottom: 1px solid var(--border);
    padding-bottom: 8px; margin-bottom: 16px; text-shadow: 0 0 8px var(--cyan); }
  .finding { background: var(--panel); border: 1px solid var(--border); border-radius: 4px;
    margin: 10px 0; padding: 16px; border-left: 4px solid; }
  .finding.critical { border-left-color: var(--red); }
  .finding.high { border-left-color: var(--orange); }
  .finding.medium { border-left-color: var(--yellow); }
  .finding.low { border-left-color: var(--green); }
  .finding.info { border-left-color: var(--dim); }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
  .badge { padding: 2px 10px; border-radius: 2px; font-size: 10px; letter-spacing: 2px; font-weight: 600; }
  .badge.critical { background: var(--red); color: #000; }
  .badge.high { background: var(--orange); color: #000; }
  .badge.medium { background: var(--yellow); color: #000; }
  .badge.low { background: var(--green); color: #000; }
  .badge.info { background: var(--dim); color: #000; }
  .finding-text { font-size: 13px; flex: 1; }
  .finding-location { font-size: 11px; color: var(--dim); margin-top: 4px; }
  .finding-rec { font-size: 12px; color: #7aaa8a; margin-top: 10px; padding-top: 10px;
    border-top: 1px solid var(--border); }
  .finding-rec::before { content: "REC: "; color: var(--cyan); }
  .no-findings { color: var(--dim); font-size: 12px; padding: 12px; font-style: italic; }
  footer { text-align: center; color: var(--dim); font-size: 11px; margin-top: 40px;
    padding-top: 20px; border-top: 1px solid var(--border); }
  .color-critical { color: var(--red); text-shadow: 0 0 10px var(--red); }
  .color-high { color: var(--orange); text-shadow: 0 0 10px var(--orange); }
  .color-medium { color: var(--yellow); text-shadow: 0 0 10px var(--yellow); }
  .color-low { color: var(--green); text-shadow: 0 0 10px var(--green); }
</style>
</head>
<body>
<div class="header">
  <div class="logo">[ VULNSCAN // MISSION DEBRIEF ]</div>
  <div class="subtitle">VULNERABILITY ASSESSMENT REPORT — AUTHORIZED TESTING ONLY</div>
  <div class="meta">
    <span>TARGET: {{ target }}</span>
    <span>TIMESTAMP: {{ timestamp }}</span>
    <span>TOTAL FINDINGS: {{ total_findings }}</span>
  </div>
</div>

<div class="risk-block" style="border-color: {{ risk.color }};">
  <div class="risk-score" style="color: {{ risk.color }}; text-shadow: 0 0 20px {{ risk.color }};">
    {{ risk.score }}
  </div>
  <div class="risk-label" style="color: {{ risk.color }};">{{ risk.rating }} RISK</div>
  <div style="color: #4a9960; font-size: 12px; margin-top: 8px;">Overall Risk Score (out of 100)</div>
</div>

<div class="summary-grid">
  <div class="summary-cell">
    <div class="summary-count color-critical">{{ counts.critical }}</div>
    <div class="summary-label">CRITICAL</div>
  </div>
  <div class="summary-cell">
    <div class="summary-count color-high">{{ counts.high }}</div>
    <div class="summary-label">HIGH</div>
  </div>
  <div class="summary-cell">
    <div class="summary-count color-medium">{{ counts.medium }}</div>
    <div class="summary-label">MEDIUM</div>
  </div>
  <div class="summary-cell">
    <div class="summary-count color-low">{{ counts.low }}</div>
    <div class="summary-label">LOW</div>
  </div>
  <div class="summary-cell">
    <div class="summary-count" style="color: #4a9960;">{{ counts.info }}</div>
    <div class="summary-label">INFO</div>
  </div>
</div>

{% for module_name, module_findings in modules.items() %}
<div class="section">
  <div class="section-title">// {{ module_name | upper }}</div>
  {% if module_findings %}
    {% for f in module_findings %}
    <div class="finding {{ f.severity }}">
      <div class="finding-header">
        <span class="badge {{ f.severity }}">{{ f.severity | upper }}</span>
        <span class="finding-text">{{ f.finding }}</span>
      </div>
      <div class="finding-location">{{ f.location }}</div>
      {% if f.recommendation %}
      <div class="finding-rec">{{ f.recommendation }}</div>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
    <div class="no-findings">No significant findings in this module.</div>
  {% endif %}
</div>
{% endfor %}

<footer>
  Generated by VulnScan v1.0.0 &nbsp;|&nbsp; For authorized security assessment only &nbsp;|&nbsp; {{ timestamp }}
</footer>
</body>
</html>"""


class ReportGenerator:
    """Aggregates scan findings and renders reports as JSON or styled HTML."""

    def __init__(self, target: str, findings: list[dict]):
        self.target = target
        self.findings = findings
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def calculate_risk_score(self) -> dict:
        raw = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 1) for f in self.findings)
        score = min(raw, 100)

        if score <= 25:
            rating, color = "LOW", "#00FF41"
        elif score <= 50:
            rating, color = "MEDIUM", "#FFD700"
        elif score <= 75:
            rating, color = "HIGH", "#FF6B00"
        else:
            rating, color = "CRITICAL", "#FF003C"

        return {"score": score, "rating": rating, "color": color}

    def _count_by_severity(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _group_by_module(self) -> dict:
        modules: dict[str, list] = {
            "Port Scanner": [],
            "Header Checker": [],
            "Endpoint Discovery": [],
            "Form Checker": [],
        }
        for f in self.findings:
            mod = f.get("module", "Other")
            if mod not in modules:
                modules[mod] = []
            modules[mod].append(f)
        # Sort each module's findings by severity
        sev_idx = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        for mod in modules:
            modules[mod].sort(key=lambda x: sev_idx.get(x.get("severity", "info"), 99))
        return modules

    def to_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "timestamp": self.timestamp,
            "risk_score": self.calculate_risk_score(),
            "summary": {
                "total": len(self.findings),
                "by_severity": self._count_by_severity(),
            },
            "findings": self.findings,
        }, indent=2, ensure_ascii=False)

    def to_html(self) -> str:
        env = Environment(loader=BaseLoader())
        template = env.from_string(REPORT_TEMPLATE)
        return template.render(
            target=self.target,
            timestamp=self.timestamp,
            total_findings=len(self.findings),
            risk=self.calculate_risk_score(),
            counts=self._count_by_severity(),
            modules=self._group_by_module(),
        )
