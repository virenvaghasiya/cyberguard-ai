"""
CyberGuard AI — REST API Server (Phase 3).

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
        GET  /network/status        — network detector metrics
        POST /analyze/demo          — run demo on synthetic traffic
        POST /analyze/upload        — analyze uploaded CSV
    Email / Phishing
        POST /scan/emails           — scan email list for phishing
        POST /scan/demo-emails      — demo phishing scan
    Log Analyzer
        POST /scan/log              — analyze raw log text
    Vulnerability Scanner
        POST /scan/vulnerability    — scan a host for open/risky ports
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

from src.api.auth import authenticate_user, create_access_token, require_auth
from src.api.websocket import broadcast_event, ws_manager
from src.core.events import EventType
from src.core.pipeline import PipelineManager
from src.detectors.network_detector import NetworkAnomalyDetector
from src.detectors.log_analyzer import LogAnalyzer
from src.detectors.vuln_scanner import VulnerabilityScanner
from src.utils.sample_data import generate_sample_traffic

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

    # Hook WebSocket broadcaster into every event type
    for event_type in EventType:
        pipeline.event_bus.subscribe(event_type, broadcast_event)

    await pipeline.start_all()
    yield
    await pipeline.stop_all()


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


class EmailScanRequest(BaseModel):
    emails: list[dict]


class EmailScanResponse(BaseModel):
    total_scanned: int
    safe_count: int
    suspicious_count: int
    dangerous_count: int
    results: list[dict]


class LogScanRequest(BaseModel):
    content: str
    log_type: str = "auto"   # "auto", "auth", "web"


class VulnScanRequest(BaseModel):
    target: str              # IP, hostname, or CIDR (max /24)
    ports: list[int] | None = None
    timeout: float = 1.0


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
        token_type="bearer",
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
    """Current network anomaly detector metrics."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("network_anomaly_detector")
    if not detector:
        raise HTTPException(status_code=404, detail="Network detector not found")

    status_dict = detector.get_status().to_dict()

    # Include recent network events
    all_events = pipeline.event_bus.get_recent_events(10_000)
    network_events = [
        e for e in all_events
        if e["source"] == "network_anomaly_detector"
    ][-20:]

    return {
        "detector": status_dict,
        "recent_anomalies": list(reversed(network_events)),
    }


@app.post("/analyze/demo", response_model=AnalysisResponse, tags=["Network"])
async def analyze_demo():
    """Run network anomaly detection on synthetic demo traffic."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("network_anomaly_detector")
    if not detector:
        raise HTTPException(status_code=404, detail="Network detector not found")

    traffic = generate_sample_traffic(n_normal=2000, n_anomalous=100)
    results = await detector.analyze(traffic)
    anomalies = [r for r in results if r["is_anomaly"]]

    return AnalysisResponse(
        total_flows=len(results),
        anomalies_detected=len(anomalies),
        anomaly_rate=len(anomalies) / len(results) if results else 0,
        results=anomalies[:50],
    )


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
# Email / phishing scan endpoints
# ---------------------------------------------------------------------------

@app.post("/scan/emails", response_model=EmailScanResponse, tags=["Email"])
async def scan_emails(request: EmailScanRequest):
    """Scan a list of emails for phishing indicators."""
    from src.core.events import EventBus
    from src.detectors.phishing_detector import PhishingEmailDetector
    from src.api.gmail_integration import format_scan_result

    event_bus = EventBus()
    detector = PhishingEmailDetector(config={}, event_bus=event_bus)
    await detector.start()
    results = await detector.analyze(request.emails)
    await detector.stop()

    formatted = [
        format_scan_result(email_data, analysis)
        for email_data, analysis in zip(request.emails, results)
    ]

    return EmailScanResponse(
        total_scanned=len(formatted),
        safe_count=sum(1 for r in formatted if r["verdict"] == "safe"),
        suspicious_count=sum(1 for r in formatted if r["verdict"] in ("caution", "monitor", "warning")),
        dangerous_count=sum(1 for r in formatted if r["verdict"] == "danger"),
        results=formatted,
    )


@app.post("/scan/demo-emails", tags=["Email"])
async def scan_demo_emails():
    """Run phishing scan on built-in sample emails (for demo/testing)."""
    from src.core.events import EventBus
    from src.detectors.phishing_detector import PhishingEmailDetector
    from src.utils.sample_emails import generate_sample_emails
    from src.api.gmail_integration import format_scan_result

    event_bus = EventBus()
    detector = PhishingEmailDetector(config={}, event_bus=event_bus)
    await detector.start()
    emails = generate_sample_emails()
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


# ---------------------------------------------------------------------------
# Log analyzer endpoint
# ---------------------------------------------------------------------------

@app.post("/scan/log", tags=["Log Analyzer"])
async def scan_log(request: LogScanRequest):
    """
    Analyze raw log text for security threats.

    Supports auth logs (syslog, auth.log) and web server logs
    (Apache / Nginx combined format). Set log_type to 'auto' to
    let the detector guess the format.
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

    # Strip non-serializable severity_enum before returning
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
        host=api_config.get("host", "0.0.0.0"),
        port=api_config.get("port", 8000),
        reload=True,
    )


if __name__ == "__main__":
    start_server()
