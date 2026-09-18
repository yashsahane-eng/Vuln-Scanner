"""
VulnScan Dashboard — FastAPI Backend
Main application entry point: WebSocket scan pipeline, REST endpoints, static file serving.
"""
import asyncio
import ipaddress
import json
import socket as sock
import threading
import uuid
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner.port_scanner import PortScanner
from scanner.header_checker import HeaderChecker
from scanner.endpoint_discovery import EndpointDiscovery
from scanner.form_checker import FormChecker
from scanner.report_generator import ReportGenerator

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="VulnScan Dashboard", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan result store  {scan_id: {...}}
scan_results: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Safety enforcement: Block prohibited real-world domains
# ---------------------------------------------------------------------------

BLOCKED_REAL_WORLD_DOMAINS = {
    "google.com", "apple.com", "microsoft.com", "amazon.com", "meta.com",
    "facebook.com", "twitter.com", "x.com", "github.com", "gov", "mil",
    "whitehouse.gov", "paypal.com", "chase.com", "wellsfargo.com",
    "bankofamerica.com", "netflix.com", "cloudflare.com", "openai.com",
    "youtube.com", "instagram.com", "linkedin.com"
}

def is_target_safe(url: str) -> tuple[bool, str]:
    """
    Validates the target URL.
    - Requires http:// or https://
    - Strictly blocks any hardcoded real-world / critical infrastructure domains
    - Allows localhost, private testbeds, and authorized user-owned URLs
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https"):
            return False, "Target must specify http:// or https://"

        host = parsed.hostname or ""
        if not host:
            return False, "Invalid host in target URL"

        host_lower = host.lower()

        # Check against prohibited real-world domains & TLDs
        for blocked in BLOCKED_REAL_WORLD_DOMAINS:
            if host_lower == blocked or host_lower.endswith("." + blocked):
                return False, f"Scanning '{blocked}' is prohibited by safety policy."

        return True, ""

    except Exception as exc:
        return False, f"Invalid URL: {exc}"



# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    confirmation: str


# ---------------------------------------------------------------------------
# Helper: stream a scan_with_progress generator via asyncio.Queue
# ---------------------------------------------------------------------------

async def _stream_progress_module(
    gen_factory,
    module_name: str,
    websocket: WebSocket,
    loop: asyncio.AbstractEventLoop,
    all_findings: list,
) -> list[dict]:
    """
    Runs a synchronous scan_with_progress() generator in a background thread
    and streams progress / finding messages to the WebSocket.
    Returns the list of findings from this module.
    """
    queue: asyncio.Queue = asyncio.Queue()

    def run():
        try:
            for progress, finding in gen_factory():
                asyncio.run_coroutine_threadsafe(
                    queue.put(("item", progress, finding)), loop
                ).result()
        except Exception as exc:
            asyncio.run_coroutine_threadsafe(
                queue.put(("error", 0, str(exc))), loop
            ).result()
        finally:
            asyncio.run_coroutine_threadsafe(
                queue.put(("done", 100, None)), loop
            ).result()

    t = threading.Thread(target=run, daemon=True)
    t.start()

    module_findings: list[dict] = []

    while True:
        status, progress, data = await queue.get()

        if status == "error":
            await websocket.send_json({
                "type": "error", "module": module_name,
                "message": f"Module error: {data}", "severity": "critical",
            })
            break

        if status == "done":
            break

        # status == "item"
        await websocket.send_json({
            "type": "progress", "module": module_name,
            "message": "", "severity": "info",
            "data": {"progress": progress},
        })

        if data:
            module_findings.append(data)
            all_findings.append(data)
            await websocket.send_json({
                "type": "finding",
                "module": module_name,
                "message": f"[{module_name.upper().replace(' ', '_')}] {data['location']}: {data['finding']}",
                "severity": data.get("severity", "info"),
                "data": data,
            })

    t.join(timeout=5)
    return module_findings


async def _stream_list_module(
    findings_list: list[dict],
    module_name: str,
    websocket: WebSocket,
    all_findings: list,
) -> None:
    """
    Streams a pre-computed list of findings to the WebSocket with synthetic progress ticks.
    Used for modules that return all results at once (HeaderChecker, FormChecker).
    """
    total = max(len(findings_list), 1)
    for idx, finding in enumerate(findings_list):
        all_findings.append(finding)
        progress = int((idx + 1) / total * 100)
        await websocket.send_json({
            "type": "finding",
            "module": module_name,
            "message": f"[{module_name.upper().replace(' ', '_')}] {finding['location']}: {finding['finding']}",
            "severity": finding.get("severity", "info"),
            "data": finding,
        })
        await websocket.send_json({
            "type": "progress", "module": module_name,
            "message": "", "severity": "info",
            "data": {"progress": progress},
        })
        await asyncio.sleep(0.05)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.post("/api/scan")
async def initiate_scan(request: ScanRequest):
    """Validate target and create a scan session ID."""
    if request.target.strip() != request.confirmation.strip():
        raise HTTPException(status_code=400, detail="Target URL and confirmation field do not match.")

    safe, reason = is_target_safe(request.target)
    if not safe:
        raise HTTPException(status_code=403, detail=f"Target prohibited: {reason}")

    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {"status": "pending", "target": request.target}
    return {"scan_id": scan_id}


@app.get("/api/report/{scan_id}/json")
async def get_json_report(scan_id: str):
    entry = scan_results.get(scan_id)
    if not entry or entry.get("status") != "complete":
        raise HTTPException(status_code=404, detail="Scan not found or not yet complete.")
    return JSONResponse(
        content=json.loads(entry["report_json"]),
        headers={"Content-Disposition": f'attachment; filename="vulnscan-{scan_id[:8]}.json"'},
    )


@app.get("/api/report/{scan_id}/html")
async def get_html_report(scan_id: str):
    entry = scan_results.get(scan_id)
    if not entry or entry.get("status") != "complete":
        raise HTTPException(status_code=404, detail="Scan not found or not yet complete.")
    return HTMLResponse(
        content=entry["report_html"],
        headers={"Content-Disposition": f'attachment; filename="vulnscan-{scan_id[:8]}.html"'},
    )


# ---------------------------------------------------------------------------
# WebSocket — scan pipeline
# ---------------------------------------------------------------------------

@app.websocket("/ws/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str, target: str = ""):
    """
    Full scan pipeline streamed over WebSocket.
    Query param: target (URL-encoded target URL).
    """
    await websocket.accept()

    # Validate again on WS connection
    safe, reason = is_target_safe(target)
    if not safe:
        await websocket.send_json({
            "type": "error", "module": "system",
            "message": f"Target prohibited: {reason}", "severity": "critical",
        })
        await websocket.close()
        return

    loop = asyncio.get_event_loop()
    all_findings: list[dict] = []

    async def send(msg_type: str, module: str, message: str,
                   severity: str = "info", data: dict | None = None):
        payload = {"type": msg_type, "module": module, "message": message, "severity": severity}
        if data:
            payload["data"] = data
        await websocket.send_json(payload)

    try:
        # ── MODULE 1: Port Scanner ──────────────────────────────────────────
        await send("module_start", "port_scan", f"Initiating port scan on {target}...")
        await _stream_progress_module(
            lambda: PortScanner(target).scan_with_progress(),
            "port_scan", websocket, loop, all_findings,
        )
        await send("module_done", "port_scan",
                   f"Port scan complete — {sum(1 for f in all_findings if f['module'] == 'Port Scanner')} open port(s) found.",
                   data={"progress": 100})

        # ── MODULE 2: Header Checker ────────────────────────────────────────
        await send("module_start", "headers", "Checking HTTP security headers...")
        await send("progress", "headers", "Fetching response...", data={"progress": 10})
        header_findings = await asyncio.get_event_loop().run_in_executor(
            None, lambda: HeaderChecker(target).check()
        )
        await _stream_list_module(header_findings, "headers", websocket, all_findings)
        await send("module_done", "headers",
                   f"Header check complete — {len(header_findings)} finding(s).",
                   data={"progress": 100})

        # ── MODULE 3: Endpoint Discovery ────────────────────────────────────
        await send("module_start", "endpoints", "Probing sensitive endpoints...")
        await _stream_progress_module(
            lambda: EndpointDiscovery(target).scan_with_progress(),
            "endpoints", websocket, loop, all_findings,
        )
        ep_count = sum(1 for f in all_findings if f["module"] == "Endpoint Discovery")
        await send("module_done", "endpoints",
                   f"Endpoint discovery complete — {ep_count} path(s) flagged.",
                   data={"progress": 100})

        # ── MODULE 4: Form Checker ──────────────────────────────────────────
        await send("module_start", "forms", "Analyzing HTML forms for input handling issues...")
        await send("progress", "forms", "Parsing page...", data={"progress": 10})
        form_findings = await asyncio.get_event_loop().run_in_executor(
            None, lambda: FormChecker(target).check()
        )
        await _stream_list_module(form_findings, "forms", websocket, all_findings)
        await send("module_done", "forms",
                   f"Form analysis complete — {len(form_findings)} finding(s).",
                   data={"progress": 100})

        # ── Report Generation ───────────────────────────────────────────────
        await send("system", "system", "Generating report...", "system")
        report = ReportGenerator(target, all_findings)
        risk = report.calculate_risk_score()

        scan_results[scan_id] = {
            "status": "complete",
            "target": target,
            "findings": all_findings,
            "report_html": report.to_html(),
            "report_json": report.to_json(),
            "risk_score": risk,
        }

        await send("complete", "system",
                   f"Scan complete. {len(all_findings)} total findings. Risk score: {risk['score']}/100 ({risk['rating']})",
                   "info",
                   {
                       "scan_id": scan_id,
                       "risk_score": risk,
                       "finding_count": len(all_findings),
                       "findings": all_findings,
                   })

    except WebSocketDisconnect:
        scan_results[scan_id] = {"status": "aborted", "target": target}
    except Exception as exc:
        try:
            await websocket.send_json({
                "type": "error", "module": "system",
                "message": f"Scan pipeline error: {exc}", "severity": "critical",
            })
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Serve React build (production)
# ---------------------------------------------------------------------------

_dist = Path(__file__).parent.parent / "frontend" / "dist"
if _dist.exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="static")
