"""
CyberGuard AI — REST API Server.

Endpoints:
    Auth
        POST /auth/token            — login, get JWT
    Health / Status
        GET  /health                — system health + detector status
        GET  /detectors             — list all detectors
        GET  /events                — recent event log
    Dashboard Stats
        GET  /stats/summary         — threat counts by type and severity
        GET  /stats/timeline        — hourly threat counts (last 24 h)
    Network Monitor
        GET  /network/status        — anomaly detector metrics
        GET  /network/live          — live active connections (real psutil data)
        GET  /network/system        — CPU / memory / disk / net I/O stats
        POST /analyze/upload        — analyze uploaded CSV
    Gmail
        GET  /gmail/status          — is Gmail connected?
        GET  /gmail/auth            — start OAuth flow (open in browser on Mac)
        GET  /gmail/callback        — OAuth callback (handled automatically)
        POST /gmail/scan            — fetch real inbox + phishing scan
        POST /gmail/disconnect      — revoke Gmail access
    Log Analyzer
        POST /scan/log              — analyze pasted log text
        GET  /scan/system-logs      — fetch + analyze real macOS system logs
    Vulnerability Scanner
        POST /scan/vulnerability    — scan a host for open/risky ports
    Defense (Phase 6 — Auto IP Blocking)
        GET  /defense/status        — pf firewall status + active block count
        GET  /defense/blocklist     — all currently blocked IPs with countdowns
        POST /defense/block         — block an IP {ip, reason, duration_hours}
        POST /defense/unblock       — unblock an IP ?ip=<ip>
        GET  /defense/history       — full block/unblock audit log
    Process Monitor (Phase 7a)
        GET  /processes/suspicious  — flagged processes with risk reasons
        GET  /processes/all         — all running processes sorted by CPU
        POST /processes/kill/{pid}  — terminate a process by PID
    Persistence Monitor (Phase 7b)
        GET  /persistence/status    — baseline status + recent changes
        POST /persistence/baseline  — take a fresh baseline snapshot
        POST /persistence/approve   — approve a change (update baseline)
    USB Monitor (Phase 7c)
        GET  /usb/devices           — all connected USB devices
        GET  /usb/suspicious        — untrusted / risky USB devices
        POST /usb/trust             — mark a device as trusted
    Signature Detector (Phase 5b)
        POST /signatures/scan       — scan arbitrary text/payload for attack signatures
        GET  /signatures/info       — signature library stats (count, categories)
    File Scanner / FIM (Phase 8)
        POST /files/scan            — hash + script-analyze one or more files
        GET  /files/fim/status      — FIM diff against stored baseline
        POST /files/fim/baseline    — take a fresh FIM baseline snapshot
        POST /files/fim/approve     — mark a FIM change as approved
        GET  /files/hashdb          — malware hash DB stats
    Auto-Response Rules Engine (Phase 9)
        GET  /response/rules        — list all rules
        POST /response/rules        — create/update a rule
        DELETE /response/rules/{name} — delete a rule by name
        PATCH /response/rules/{name}/enable  — enable a rule
        PATCH /response/rules/{name}/disable — disable a rule
        POST /response/rules/reset  — restore built-in default rules
        GET  /response/log          — recent rule execution log
        GET  /response/pending      — manual-confirmation queue
        POST /response/pending/{id}/confirm  — confirm a pending action
        POST /response/pending/{id}/dismiss  — dismiss a pending action
    WebSocket
        WS   /ws/alerts             — live alert stream
"""

from __future__ import annotations

from collections import defaultdict
from contextlib import asynccontextmanager
from io import StringIO
from pathlib import Path

import pandas as pd
import uvicorn
import yaml
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from src.api.auth import authenticate_user, create_access_token
from src.api.websocket import broadcast_event, ws_manager
from src.api import gmail_oauth
from src.api.system_monitor import get_live_connections, get_system_stats, get_real_logs
from src.core.events import EventType
from src.core.pipeline import PipelineManager
from src.detectors.network_detector import NetworkAnomalyDetector
from src.detectors.log_analyzer import LogAnalyzer
from src.detectors.vuln_scanner import VulnerabilityScanner
from src.detectors.process_monitor import ProcessMonitor
from src.detectors.persistence_monitor import PersistenceMonitor
from src.detectors.usb_monitor import USBMonitor
from src.detectors.signature_detector import SignatureDetector
from src.detectors.file_scanner import FileScanner
from src.response.rules_engine import RulesEngine
from src.defense import block_store, firewall

# ---------------------------------------------------------------------------
# Global pipeline instance
# ---------------------------------------------------------------------------

pipeline: PipelineManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and tear down the full detection pipeline."""
    global pipeline
    pipeline = PipelineManager()

    # Register all detectors
    pipeline.register_detector(
        NetworkAnomalyDetector(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        LogAnalyzer(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        VulnerabilityScanner(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        ProcessMonitor(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        PersistenceMonitor(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        USBMonitor(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        SignatureDetector(config=pipeline.config, event_bus=pipeline.event_bus)
    )
    pipeline.register_detector(
        FileScanner(config=pipeline.config, event_bus=pipeline.event_bus)
    )

    # Hook WebSocket broadcaster into every event type
    for event_type in EventType:
        pipeline.event_bus.subscribe(event_type, broadcast_event)

    # Initialise block store DB + re-apply any active blocks from previous run
    await block_store.init_db()

    # Start auto-response rules engine
    rules_engine = RulesEngine(event_bus=pipeline.event_bus, pipeline=pipeline)
    rules_engine.start()
    app.state.rules_engine = rules_engine

    # Background task: expire timed blocks every 60 s
    import asyncio as _asyncio
    expiry_task = _asyncio.create_task(block_store.run_expiry_loop())

    await pipeline.start_all()
    yield
    rules_engine.stop()
    await pipeline.stop_all()
    expiry_task.cancel()


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CyberGuard AI",
    description="AI-powered cybersecurity defense system",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    version: str
    detectors: list[dict]
    websocket_clients: int


class AnalysisResponse(BaseModel):
    total_flows: int
    anomalies_detected: int
    anomaly_rate: float
    results: list[dict]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in_hours: int


class LogScanRequest(BaseModel):
    content: str
    log_type: str = "auto"   # "auto", "auth", "web"


class VulnScanRequest(BaseModel):
    target: str              # IP, hostname, or CIDR (max /24)
    ports: list[int] | None = None
    timeout: float = 1.0


class BlockRequest(BaseModel):
    ip: str
    reason: str
    attack_type: str = "manual"
    severity: str = "high"
    duration_hours: float = 1.0  # 0 = permanent


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login with username + password and receive a JWT bearer token.

    Default credentials (change via env vars):
        username: admin
        password: cyberguard
    """
    if not authenticate_user(form_data.username, form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(form_data.username)
    return TokenResponse(
        access_token=token,
        token_type="bearer",  # nosec B106 — OAuth2 token type, not a password
        expires_in_hours=24,
    )


# ---------------------------------------------------------------------------
# Health / Status endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["Status"])
async def health_check():
    """System health check — detector status and WebSocket client count."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        detectors=pipeline.get_all_status() if pipeline else [],
        websocket_clients=ws_manager.connection_count,
    )


@app.get("/detectors", tags=["Status"])
async def list_detectors():
    """List all registered detectors and their runtime status."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    return {"detectors": pipeline.get_all_status()}


@app.get("/events", tags=["Status"])
async def get_events(limit: int = 100):
    """Get recent events from the event bus (most recent first)."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    events = pipeline.event_bus.get_recent_events(limit)
    return {"events": list(reversed(events))}


# ---------------------------------------------------------------------------
# Dashboard stats endpoints
# ---------------------------------------------------------------------------

@app.get("/stats/summary", tags=["Dashboard"])
async def stats_summary():
    """
    Threat count summary for the dashboard.

    Returns total events broken down by:
    - severity (critical / high / medium / low / info)
    - event type (anomaly.detected, threat.confirmed, etc.)
    - detector source
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    events = pipeline.event_bus.get_recent_events(10_000)

    by_severity: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    by_source: dict[str, int] = defaultdict(int)
    by_attack: dict[str, int] = defaultdict(int)

    for e in events:
        by_severity[e["severity"]] += 1
        by_type[e["event_type"]] += 1
        by_source[e["source"]] += 1
        attack = e.get("data", {}).get("attack_type", "unknown")
        by_attack[attack] += 1

    return {
        "total_events": len(events),
        "by_severity": dict(by_severity),
        "by_type": dict(by_type),
        "by_source": dict(by_source),
        "by_attack_type": dict(by_attack),
    }


@app.get("/stats/timeline", tags=["Dashboard"])
async def stats_timeline(hours: int = 24):
    """
    Hourly threat counts for the last N hours (default 24).

    Returns a list of { hour, count, critical_count } objects,
    sorted oldest-to-newest — ideal for a line chart.
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    from datetime import datetime, timezone, timedelta

    events = pipeline.event_bus.get_recent_events(10_000)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours)

    # Build hourly buckets
    buckets: dict[str, dict] = {}
    for h in range(hours):
        bucket_time = cutoff + timedelta(hours=h)
        key = bucket_time.strftime("%Y-%m-%dT%H:00")
        buckets[key] = {"hour": key, "count": 0, "critical_count": 0}

    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts < cutoff:
                continue
            key = ts.strftime("%Y-%m-%dT%H:00")
            if key in buckets:
                buckets[key]["count"] += 1
                if e["severity"] == "critical":
                    buckets[key]["critical_count"] += 1
        except (KeyError, ValueError):
            continue

    return {"hours": hours, "timeline": list(buckets.values())}


# ---------------------------------------------------------------------------
# Network monitor endpoints
# ---------------------------------------------------------------------------

@app.get("/network/status", tags=["Network"])
async def network_status():
    """Current network anomaly detector metrics + recent anomalies."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("network_anomaly_detector")
    if not detector:
        raise HTTPException(status_code=404, detail="Network detector not found")

    status_dict = detector.get_status().to_dict()

    all_events = pipeline.event_bus.get_recent_events(10_000)
    network_events = [
        e for e in all_events
        if e["source"] == "network_anomaly_detector"
    ][-20:]

    return {
        "detector": status_dict,
        "recent_anomalies": list(reversed(network_events)),
    }


@app.get("/network/live", tags=["Network"])
async def network_live():
    """
    Real-time active network connections on this machine.
    Annotated with risk levels for suspicious ports.
    """
    return get_live_connections()


@app.get("/network/system", tags=["Network"])
async def network_system():
    """Real-time CPU, memory, disk and network I/O stats."""
    return get_system_stats()


@app.post("/analyze/upload", response_model=AnalysisResponse, tags=["Network"])
async def analyze_upload(file: UploadFile = File(...)):
    """
    Analyze an uploaded CSV file of network traffic.
    Expected columns: src_ip, dst_ip, src_port, dst_port, protocol,
                      timestamp, duration, packets, bytes
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")

    detector = pipeline.get_detector("network_anomaly_detector")
    if not detector:
        raise HTTPException(status_code=404, detail="Network detector not found")

    content = await file.read()
    df = pd.read_csv(StringIO(content.decode("utf-8")))
    results = await detector.analyze(df)
    anomalies = [r for r in results if r["is_anomaly"]]

    return AnalysisResponse(
        total_flows=len(results),
        anomalies_detected=len(anomalies),
        anomaly_rate=len(anomalies) / len(results) if results else 0,
        results=anomalies[:50],
    )


# ---------------------------------------------------------------------------
# Gmail OAuth + real email scanning endpoints
# ---------------------------------------------------------------------------

@app.get("/gmail/status", tags=["Gmail"])
async def gmail_status():
    """Check if Gmail is connected (OAuth token exists and is valid)."""
    connected = gmail_oauth.is_connected()
    return {
        "connected": connected,
        "setup_required": not Path("config/gmail_credentials.json").exists(),
    }


@app.get("/gmail/auth", tags=["Gmail"])
async def gmail_auth():
    """
    Start Gmail OAuth2 flow.
    Open this URL in a browser on your Mac — it will redirect to Google
    and then back to /gmail/callback automatically.
    """
    from fastapi.responses import RedirectResponse
    try:
        redirect_uri = "http://localhost:8000/gmail/callback"
        auth_url = gmail_oauth.get_auth_url(redirect_uri)
        return RedirectResponse(url=auth_url)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/gmail/callback", tags=["Gmail"])
async def gmail_callback(code: str, state: str = ""):
    """Handle Google OAuth2 callback — exchange code for token."""
    from fastapi.responses import HTMLResponse
    try:
        redirect_uri = "http://localhost:8000/gmail/callback"
        gmail_oauth.exchange_code(code, redirect_uri)
        return HTMLResponse("""
            <html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#0a0a0f;color:#00ff9d">
            <h2>✓ Gmail Connected</h2>
            <p style="color:#aaa">CyberGuard AI can now scan your inbox for phishing.</p>
            <p style="color:#666;font-size:13px">You can close this tab and return to the app.</p>
            </body></html>
        """)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OAuth failed: {e}")


@app.post("/gmail/scan", tags=["Gmail"])
async def gmail_scan(max_emails: int = 50):
    """
    Fetch real emails from your Gmail inbox and scan for phishing.
    Gmail must be connected first via GET /gmail/auth.
    """
    from src.core.events import EventBus
    from src.detectors.phishing_detector import PhishingEmailDetector
    from src.api.gmail_integration import format_scan_result

    if not gmail_oauth.is_connected():
        raise HTTPException(
            status_code=401,
            detail="Gmail not connected. Open http://localhost:8000/gmail/auth in your browser."
        )

    try:
        emails = gmail_oauth.fetch_inbox(max_results=max_emails)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch emails: {e}")

    if not emails:
        return {
            "total_scanned": 0,
            "safe_count": 0,
            "suspicious_count": 0,
            "dangerous_count": 0,
            "results": [],
        }

    event_bus = EventBus()
    detector = PhishingEmailDetector(config={}, event_bus=event_bus)
    await detector.start()
    results = await detector.analyze(emails)
    await detector.stop()

    formatted = [
        format_scan_result(email_data, analysis)
        for email_data, analysis in zip(emails, results)
    ]

    return {
        "total_scanned": len(formatted),
        "safe_count": sum(1 for r in formatted if r["verdict"] == "safe"),
        "suspicious_count": sum(1 for r in formatted if r["verdict"] in ("caution", "monitor", "warning")),
        "dangerous_count": sum(1 for r in formatted if r["verdict"] == "danger"),
        "results": formatted,
    }


@app.post("/gmail/disconnect", tags=["Gmail"])
async def gmail_disconnect():
    """Revoke Gmail access and delete stored token."""
    gmail_oauth.disconnect()
    return {"disconnected": True}


# ---------------------------------------------------------------------------
# Log analyzer endpoints
# ---------------------------------------------------------------------------

@app.post("/scan/log", tags=["Log Analyzer"])
async def scan_log(request: LogScanRequest):
    """
    Analyze pasted log text for security threats.
    Supports auth logs (syslog, auth.log) and web server logs (Apache/Nginx).
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("log_analyzer")
    if not detector:
        raise HTTPException(status_code=404, detail="Log analyzer not found")

    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Log content cannot be empty")

    results = await detector.analyze({
        "content": request.content,
        "log_type": request.log_type,
    })

    clean = []
    for r in results:
        r_copy = dict(r)
        r_copy.pop("severity_enum", None)
        clean.append(r_copy)

    return {
        "total_findings": len(clean),
        "critical": sum(1 for r in clean if r["severity"] == "critical"),
        "high":     sum(1 for r in clean if r["severity"] == "high"),
        "medium":   sum(1 for r in clean if r["severity"] == "medium"),
        "low":      sum(1 for r in clean if r["severity"] == "low"),
        "findings": clean,
    }


@app.get("/scan/system-logs", tags=["Log Analyzer"])
async def scan_system_logs(hours: int = 1, log_type: str = "all"):
    """
    Fetch real macOS system logs and run them through the log analyzer.

    Args:
        hours:    Hours back to look (1–24, default 1)
        log_type: auth | network | security | all
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("log_analyzer")
    if not detector:
        raise HTTPException(status_code=404, detail="Log analyzer not found")

    hours = max(1, min(hours, 24))
    log_content = await get_real_logs(hours=hours, log_type=log_type)

    if log_content.startswith("#"):
        return {
            "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "findings": [], "raw_lines": 0, "message": log_content,
        }

    results = await detector.analyze({
        "content": log_content,
        "log_type": "auto",
    })

    clean = []
    for r in results:
        r_copy = dict(r)
        r_copy.pop("severity_enum", None)
        clean.append(r_copy)

    return {
        "total_findings": len(clean),
        "critical": sum(1 for r in clean if r["severity"] == "critical"),
        "high":     sum(1 for r in clean if r["severity"] == "high"),
        "medium":   sum(1 for r in clean if r["severity"] == "medium"),
        "low":      sum(1 for r in clean if r["severity"] == "low"),
        "raw_lines": len(log_content.splitlines()),
        "hours_scanned": hours,
        "log_type": log_type,
        "findings": clean,
    }


# ---------------------------------------------------------------------------
# Vulnerability scanner endpoint
# ---------------------------------------------------------------------------

@app.post("/scan/vulnerability", tags=["Vulnerability"])
async def scan_vulnerability(request: VulnScanRequest):
    """
    Scan a host or CIDR range for open / dangerous ports.

    The scan is async and fast (all ports probed concurrently).
    Max CIDR range: /24 (254 hosts).

    Examples:
        { "target": "192.168.1.1" }
        { "target": "192.168.1.0/24", "timeout": 0.5 }
        { "target": "localhost", "ports": [22, 23, 3306, 6379] }
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("vuln_scanner")
    if not detector:
        raise HTTPException(status_code=404, detail="Vulnerability scanner not found")

    scan_input: dict = {"target": request.target, "timeout": request.timeout}
    if request.ports:
        scan_input["ports"] = request.ports

    results = await detector.analyze(scan_input)

    # Strip non-serializable fields
    clean = []
    for r in results:
        r_copy = dict(r)
        r_copy.pop("severity_enum", None)
        clean.append(r_copy)

    return {
        "target": request.target,
        "total_findings": len(clean),
        "critical": sum(1 for r in clean if r["severity"] == "critical"),
        "high":     sum(1 for r in clean if r["severity"] == "high"),
        "medium":   sum(1 for r in clean if r["severity"] == "medium"),
        "low":      sum(1 for r in clean if r["severity"] == "low"),
        "findings": clean,
    }


# ---------------------------------------------------------------------------
# Process Monitor endpoints (Phase 7a)
# ---------------------------------------------------------------------------

@app.get("/processes/suspicious", tags=["Process Monitor"])
async def processes_suspicious():
    """Scan all running processes and return flagged ones with risk reasons."""
    detector = pipeline.get_detector("process_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Process monitor not available")
    findings = await detector.analyze()
    return {
        "count": len(findings),
        "critical": sum(1 for f in findings if f["risk"] == "critical"),
        "high": sum(1 for f in findings if f["risk"] == "high"),
        "medium": sum(1 for f in findings if f["risk"] == "medium"),
        "findings": findings,
    }


@app.get("/processes/all", tags=["Process Monitor"])
async def processes_all():
    """Return all running processes sorted by CPU usage."""
    detector = pipeline.get_detector("process_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Process monitor not available")
    procs = await detector.get_all_processes()
    return {"count": len(procs), "processes": procs}


@app.post("/processes/kill/{pid}", tags=["Process Monitor"])
async def process_kill(pid: int):
    """
    Terminate a process by PID.
    Tries SIGTERM first, then SIGKILL if the process doesn't exit within 3 s.
    Requires the process to be owned by the current user (or run server with sudo).
    """
    detector = pipeline.get_detector("process_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Process monitor not available")
    result = await detector.kill_process(pid)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ---------------------------------------------------------------------------
# Persistence Monitor endpoints (Phase 7b)
# ---------------------------------------------------------------------------

@app.get("/persistence/status", tags=["Persistence Monitor"])
async def persistence_status():
    """Check baseline status and run a scan for any changes since last baseline."""
    detector = pipeline.get_detector("persistence_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Persistence monitor not available")
    from src.detectors.persistence_monitor import BASELINE_PATH, _load_baseline
    has_baseline = BASELINE_PATH.exists()
    changes = await detector.analyze() if has_baseline else []
    baseline = _load_baseline()
    return {
        "has_baseline": has_baseline,
        "files_watched": len(baseline),
        "changes_detected": len(changes),
        "changes": changes,
    }


@app.post("/persistence/baseline", tags=["Persistence Monitor"])
async def persistence_baseline():
    """Take a fresh baseline snapshot of all watched files."""
    detector = pipeline.get_detector("persistence_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Persistence monitor not available")
    return detector.take_baseline()


@app.post("/persistence/approve", tags=["Persistence Monitor"])
async def persistence_approve(path: str):
    """
    Mark a detected change as intentional (updates baseline for this path only).
    Use this after making a known-good change to stop repeated alerts.
    """
    detector = pipeline.get_detector("persistence_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Persistence monitor not available")
    ok = detector.approve_change(path)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Path not found in watched locations: {path}")
    return {"approved": True, "path": path}


# ---------------------------------------------------------------------------
# USB Monitor endpoints (Phase 7c)
# ---------------------------------------------------------------------------

@app.get("/usb/devices", tags=["USB Monitor"])
async def usb_devices():
    """Return all currently connected USB devices with trust status."""
    detector = pipeline.get_detector("usb_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="USB monitor not available")
    devices = await detector.get_all_devices()
    return {"count": len(devices), "devices": devices}


@app.get("/usb/suspicious", tags=["USB Monitor"])
async def usb_suspicious():
    """Return connected USB devices that are untrusted or high-risk."""
    detector = pipeline.get_detector("usb_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="USB monitor not available")
    findings = await detector.analyze()
    return {"count": len(findings), "devices": findings}


@app.post("/usb/trust", tags=["USB Monitor"])
async def usb_trust(device_id: str):
    """Mark a USB device as trusted so it won't be flagged again."""
    detector = pipeline.get_detector("usb_monitor") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="USB monitor not available")
    detector.trust_device(device_id)
    return {"trusted": True, "device_id": device_id}


# ---------------------------------------------------------------------------
# Signature Detector endpoints (Phase 5b)
# ---------------------------------------------------------------------------

class SignatureScanRequest(BaseModel):
    text: str = ""
    payload: str = ""
    url: str = ""


@app.post("/signatures/scan", tags=["Signature Detector"])
async def signatures_scan(req: SignatureScanRequest):
    """
    Scan arbitrary text, payload, or URL for known attack signatures.
    Returns all matched signatures with severity and category.
    """
    detector = pipeline.get_detector("signature_detector") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Signature detector not available")

    data = {k: v for k, v in req.model_dump().items() if v}
    if not data:
        return {"matches": [], "match_count": 0, "highest_severity": None}

    findings = await detector.analyze(data)
    if not findings:
        return {"matches": [], "match_count": 0, "highest_severity": None}

    all_matches = [m for f in findings for m in f["matched_signatures"]]
    sev_order = ["critical", "high", "medium", "low"]
    severities = {m["severity"] for m in all_matches}
    highest = next((s for s in sev_order if s in severities), None)

    return {
        "match_count": len(all_matches),
        "highest_severity": highest,
        "attack_types": list({t for f in findings for t in f["attack_types"]}),
        "matches": all_matches,
    }


@app.get("/signatures/info", tags=["Signature Detector"])
async def signatures_info():
    """Return statistics about the built-in signature library."""
    detector = pipeline.get_detector("signature_detector") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="Signature detector not available")
    return {
        "signature_count": detector.get_signature_count(),
        "categories": detector.get_categories(),
    }


# ---------------------------------------------------------------------------
# File Scanner / FIM endpoints (Phase 8)
# ---------------------------------------------------------------------------

class FileScanRequest(BaseModel):
    paths: list[str] = []
    dirs: list[str] = []


class FIMApproveRequest(BaseModel):
    path: str


@app.post("/files/scan", tags=["File Scanner"])
async def files_scan(req: FileScanRequest):
    """
    Hash-check and script-analyze specific files or all files in directories.
    Returns findings for any file with risk != clean.
    """
    detector = pipeline.get_detector("file_scanner") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="File scanner not available")
    data: dict = {}
    if req.paths:
        data["paths"] = req.paths
    elif req.dirs:
        data["dirs"] = req.dirs
    else:
        return {"count": 0, "findings": []}
    findings = await detector.analyze(data)
    return {"count": len(findings), "findings": findings}


@app.get("/files/fim/status", tags=["File Scanner"])
async def files_fim_status():
    """Return FIM diff: files added, modified, or deleted since last baseline."""
    detector = pipeline.get_detector("file_scanner") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="File scanner not available")
    changes = await detector.analyze(None)  # FIM mode
    return {
        "changes_detected": len(changes),
        "changes": changes,
    }


@app.post("/files/fim/baseline", tags=["File Scanner"])
async def files_fim_baseline():
    """Take a fresh FIM baseline snapshot of all watched directories."""
    detector = pipeline.get_detector("file_scanner") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="File scanner not available")
    return detector.take_fim_baseline()


@app.post("/files/fim/approve", tags=["File Scanner"])
async def files_fim_approve(req: FIMApproveRequest):
    """Mark a FIM change as intentional — update baseline for that path only."""
    detector = pipeline.get_detector("file_scanner") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="File scanner not available")
    ok = detector.fim_approve(req.path)
    if not ok:
        raise HTTPException(status_code=404, detail="Path not found in current snapshot")
    return {"approved": True, "path": req.path}


@app.get("/files/hashdb", tags=["File Scanner"])
async def files_hashdb():
    """Return malware hash database statistics."""
    detector = pipeline.get_detector("file_scanner") if pipeline else None
    if not detector:
        raise HTTPException(status_code=503, detail="File scanner not available")
    return {
        "hash_count": detector.get_hash_db_size(),
        "db_path": "data/malware_hashes.txt",
    }


# ---------------------------------------------------------------------------
# Auto-Response Rules Engine endpoints (Phase 9)
# ---------------------------------------------------------------------------

def _get_rules_engine() -> "RulesEngine":
    if not hasattr(app.state, "rules_engine") or app.state.rules_engine is None:
        raise HTTPException(status_code=503, detail="Rules engine not available")
    return app.state.rules_engine


@app.get("/response/rules", tags=["Response Engine"])
async def response_rules_list():
    """List all auto-response rules."""
    engine = _get_rules_engine()
    return {"count": len(engine.get_rules()), "rules": engine.get_rules()}


@app.post("/response/rules", tags=["Response Engine"])
async def response_rules_upsert(rule: dict):
    """Create or update a response rule (matched by name)."""
    if "name" not in rule:
        raise HTTPException(status_code=400, detail="Rule must have a 'name' field")
    engine = _get_rules_engine()
    updated = engine.upsert_rule(rule)
    return {"saved": True, "updated": updated, "name": rule["name"]}


@app.delete("/response/rules/{name}", tags=["Response Engine"])
async def response_rules_delete(name: str):
    """Delete a rule by name."""
    engine = _get_rules_engine()
    if not engine.delete_rule(name):
        raise HTTPException(status_code=404, detail=f"Rule '{name}' not found")
    return {"deleted": True, "name": name}


@app.patch("/response/rules/{name}/enable", tags=["Response Engine"])
async def response_rules_enable(name: str):
    """Enable a rule."""
    engine = _get_rules_engine()
    if not engine.set_rule_enabled(name, True):
        raise HTTPException(status_code=404, detail=f"Rule '{name}' not found")
    return {"enabled": True, "name": name}


@app.patch("/response/rules/{name}/disable", tags=["Response Engine"])
async def response_rules_disable(name: str):
    """Disable a rule without deleting it."""
    engine = _get_rules_engine()
    if not engine.set_rule_enabled(name, False):
        raise HTTPException(status_code=404, detail=f"Rule '{name}' not found")
    return {"enabled": False, "name": name}


@app.post("/response/rules/reset", tags=["Response Engine"])
async def response_rules_reset():
    """Restore all built-in default rules (custom rules are preserved)."""
    engine = _get_rules_engine()
    total = engine.reset_rules_to_default()
    return {"reset": True, "total_rules": total}


@app.get("/response/log", tags=["Response Engine"])
async def response_log(limit: int = 50):
    """Return recent rule execution log entries."""
    engine = _get_rules_engine()
    entries = engine.get_execution_log(limit=limit)
    return {"count": len(entries), "log": entries}


@app.get("/response/pending", tags=["Response Engine"])
async def response_pending():
    """Return actions waiting for manual confirmation."""
    engine = _get_rules_engine()
    pending = engine.get_pending_actions()
    return {"count": len(pending), "pending": pending}


@app.post("/response/pending/{action_id}/confirm", tags=["Response Engine"])
async def response_pending_confirm(action_id: str):
    """Confirm and execute a pending action."""
    engine = _get_rules_engine()
    result = await engine.confirm_action(action_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@app.post("/response/pending/{action_id}/dismiss", tags=["Response Engine"])
async def response_pending_dismiss(action_id: str):
    """Dismiss a pending action without executing it."""
    engine = _get_rules_engine()
    if not engine.dismiss_action(action_id):
        raise HTTPException(status_code=404, detail="Pending action not found")
    return {"dismissed": True, "id": action_id}


# ---------------------------------------------------------------------------
# Defense endpoints (Phase 6 — Auto IP Blocking)
# ---------------------------------------------------------------------------

@app.get("/defense/status", tags=["Defense"])
async def defense_status():
    """
    Return whether the pf firewall anchor is active and how many IPs
    are currently blocked.
    """
    pf_active = await firewall.is_pf_available()
    active_blocks = await block_store.list_active()
    return {
        "pf_active": pf_active,
        "active_block_count": len(active_blocks),
        "setup_required": not pf_active,
        "setup_command": "sudo python -m src.defense.setup_pf" if not pf_active else None,
    }


@app.get("/defense/blocklist", tags=["Defense"])
async def defense_blocklist():
    """List all currently active blocked IPs with countdown timers."""
    active = await block_store.list_active()
    return {
        "count": len(active),
        "blocks": active,
    }


@app.post("/defense/block", tags=["Defense"])
async def defense_block(request: BlockRequest):
    """
    Block an IP address.

    duration_hours=0 means permanent. Requires pf to be set up with:
        sudo python -m src.defense.setup_pf

    Even without pf (no sudo), the block is recorded in the database.
    """
    duration_seconds = int(request.duration_hours * 3600)
    result = await block_store.add_block(
        ip=request.ip,
        reason=request.reason,
        attack_type=request.attack_type,
        severity=request.severity,
        duration_seconds=duration_seconds,
        auto_block=True,
    )
    return result


@app.post("/defense/unblock", tags=["Defense"])
async def defense_unblock(ip: str):
    """Remove a block on an IP address."""
    if not await block_store.is_blocked(ip):
        raise HTTPException(status_code=404, detail=f"{ip} is not currently blocked")
    await block_store.remove_block(ip)
    return {"unblocked": True, "ip": ip}


@app.get("/defense/history", tags=["Defense"])
async def defense_history(limit: int = 100):
    """Full block/unblock audit log (most recent first)."""
    history = await block_store.list_history(limit=limit)
    return {"count": len(history), "history": history}


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    """
    Live alert stream via WebSocket.

    Connect from the mobile app:
        ws://localhost:8000/ws/alerts

    Every event published by any detector is forwarded here in real time
    as a JSON object matching the Event.to_dict() schema.
    """
    await ws_manager.handle_connection(websocket)


# ---------------------------------------------------------------------------
# Server entry point
# ---------------------------------------------------------------------------

def start_server():
    """Entry point for running the API server (called from main.py --serve)."""
    config_path = Path("config/default.yaml")
    api_config = {}
    if config_path.exists():
        with open(config_path) as f:
            full_config = yaml.safe_load(f)
            api_config = full_config.get("api", {})

    uvicorn.run(
        "src.api.server:app",
        host=api_config.get("host", "127.0.0.1"),
        port=api_config.get("port", 8000),
        reload=True,
    )


if __name__ == "__main__":
    start_server()
