# VulnScan Dashboard

A hacker/cyberpunk-themed **Vulnerability Scanner Dashboard** built with Python FastAPI (backend) and React + Vite (frontend).

> **IMPORTANT — AUTHORIZED USE ONLY**
> This tool is strictly for security testing of systems **you own** or have **explicit written authorization** to test.
> The application enforces this by only allowing scans of `localhost`, loopback addresses, and RFC-1918 private IP ranges.
> It will refuse to scan any public internet host.

---

## Recommended Safe Test Targets

Run one of these intentionally-vulnerable apps locally before scanning:

| App | Docker command |
|---|---|
| **OWASP Juice Shop** | `docker run -p 3000:3000 bkimminich/juice-shop` |
| **DVWA** | `docker run -p 80:80 vulnerables/web-dvwa` |
| **WebGoat** | `docker run -p 8080:8080 webgoat/goat-and-wolf` |

---

## Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- npm

### 1. Backend

```powershell
cd vuln-scanner\backend
python -m venv venv
.\venv\Scripts\Activate
pip install -r requirements.txt
```

### 2. Frontend

```powershell
cd vuln-scanner\frontend
npm install
```

---

## Running (Development)

Run **both** servers simultaneously (two terminals):

**Terminal 1 — Backend:**
```powershell
cd vuln-scanner\backend
.\venv\Scripts\Activate
uvicorn main:app --reload --port 8000
```

**Terminal 2 — Frontend:**
```powershell
cd vuln-scanner\frontend
npm run dev
```

Then open: **http://localhost:5173**

The Vite dev server proxies `/api` and `/ws` requests to the FastAPI backend at `http://localhost:8000`.

---

## Running (Production Build)

```powershell
# Build the React frontend
cd vuln-scanner\frontend
npm run build

# Run FastAPI (serves the built React app at /)
cd ..\backend
.\venv\Scripts\Activate
uvicorn main:app --port 8000
```

Open: **http://localhost:8000**

---

## Scanner Modules

| Module | What it checks |
|---|---|
| **Port Scanner** | TCP connect scan on 15 common ports using ThreadPoolExecutor |
| **Header Checker** | Inspects HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) |
| **Endpoint Discovery** | Probes 25 sensitive paths for unexpected exposure |
| **Form Checker** | Parses HTML forms, checks for CSRF tokens and input reflection |

---

## Project Structure

```
vuln-scanner/
├── backend/
│   ├── main.py                     # FastAPI app, WebSocket pipeline
│   ├── requirements.txt
│   └── scanner/
│       ├── port_scanner.py
│       ├── header_checker.py
│       ├── endpoint_discovery.py
│       ├── form_checker.py
│       └── report_generator.py
└── frontend/
    ├── package.json
    ├── vite.config.js
    ├── index.html
    └── src/
        ├── App.jsx
        ├── main.jsx
        ├── components/
        │   ├── Banner.jsx
        │   ├── ScanForm.jsx
        │   ├── ModuleProgress.jsx
        │   ├── Terminal.jsx
        │   ├── ReportView.jsx
        │   └── RiskScore.jsx
        └── styles/
            └── cyberpunk.css
```

---

## Sample Scan Walkthrough

1. Start OWASP Juice Shop: `docker run -p 3000:3000 bkimminich/juice-shop`
2. Start the backend and frontend (dev mode above)
3. Open http://localhost:5173
4. Enter `http://localhost:3000` in both TARGET fields
5. Check the authorization checkbox
6. Click `> INITIATE SCAN_`
7. Watch findings stream in real-time in the terminal panel
8. After completion, download the JSON or HTML report from the mission debrief view

**Expected findings against Juice Shop:**
- Ports open: 3000 (Node.js dev server)
- Missing headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options
- Accessible endpoints: `/api`, `/api-docs` (Swagger), `/metrics`
- Forms: login form without CSRF token

---

## Safety Policy

- The backend **double-validates** every scan request (REST + WebSocket)
- Only targets resolving to `127.x.x.x`, `::1`, `10.x.x.x`, `172.16-31.x.x`, or `192.168.x.x` are permitted
- The frontend requires typing the target URL twice and checking an authorization checkbox
- Scanning `google.com`, `github.com`, or any public host returns HTTP 403

