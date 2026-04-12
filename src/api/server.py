"""
CyberGuard AI — REST API Server.

Provides endpoints for:
- Running analysis on uploaded traffic data
- Checking detector status
- Viewing recent alerts and events
- System health checks

This is a lightweight API meant for local dev and integration testing.
Production deployments would add auth, rate limiting, and TLS.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from io import StringIO

import pandas as pd
import uvicorn
import yaml
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.core.pipeline import PipelineManager
from src.detectors.network_detector import NetworkAnomalyDetector
from src.utils.sample_data import generate_sample_traffic

# Global pipeline instance
pipeline: PipelineManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and tear down the detection pipeline."""
    global pipeline
    pipeline = PipelineManager()

    # Register the network detector
    detector = NetworkAnomalyDetector(
        config=pipeline.config,
        event_bus=pipeline.event_bus,
    )
    pipeline.register_detector(detector)
    await pipeline.start_all()

    yield

    await pipeline.stop_all()


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


# --- Response Models ---

class HealthResponse(BaseModel):
    status: str
    version: str
    detectors: list[dict]


class AnalysisResponse(BaseModel):
    total_flows: int
    anomalies_detected: int
    anomaly_rate: float
    results: list[dict]


# --- Endpoints ---

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """System health check with detector status."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        detectors=pipeline.get_all_status() if pipeline else [],
    )


@app.get("/events")
async def get_events(limit: int = 100):
    """Get recent events from the event bus."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    return {"events": pipeline.event_bus.get_recent_events(limit)}


@app.post("/analyze/demo", response_model=AnalysisResponse)
async def analyze_demo():
    """
    Run analysis on synthetic demo data.
    Generates sample traffic with injected anomalies and detects them.
    """
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    detector = pipeline.get_detector("network_anomaly_detector")
    if not detector:
        raise HTTPException(status_code=404, detail="Network detector not found")

    # Generate sample data
    traffic = generate_sample_traffic(n_normal=2000, n_anomalous=100)
    results = await detector.analyze(traffic)

    anomalies = [r for r in results if r["is_anomaly"]]

    return AnalysisResponse(
        total_flows=len(results),
        anomalies_detected=len(anomalies),
        anomaly_rate=len(anomalies) / len(results) if results else 0,
        results=anomalies[:50],  # Return top 50 anomalies
    )


@app.post("/analyze/upload", response_model=AnalysisResponse)
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

    # Read uploaded CSV
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


@app.get("/detectors")
async def list_detectors():
    """List all registered detectors and their status."""
    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")
    return {"detectors": pipeline.get_all_status()}


# --- Email Scanning Endpoints ---

class EmailScanRequest(BaseModel):
    """Request body for scanning emails."""
    emails: list[dict]


class EmailScanResult(BaseModel):
    """Single email scan result."""
    message_id: str = ""
    subject: str = ""
    sender_name: str = ""
    sender_email: str = ""
    date: str = ""
    verdict: str = "safe"
    verdict_label: str = "Safe"
    phishing_score: float = 0.0
    confidence: float = 0.0
    severity: str | None = None
    indicator_count: int = 0
    indicators: list[str] = []
    features: dict = {}


class EmailScanResponse(BaseModel):
    """Response from email scanning."""
    total_scanned: int
    safe_count: int
    suspicious_count: int
    dangerous_count: int
    results: list[dict]


@app.post("/scan/emails", response_model=EmailScanResponse)
async def scan_emails(request: EmailScanRequest):
    """
    Scan a list of emails for phishing.
    Accepts emails in the format produced by gmail_integration.parse_email_for_scanning().
    """
    from src.core.events import EventBus
    from src.detectors.phishing_detector import PhishingEmailDetector
    from src.api.gmail_integration import format_scan_result

    event_bus = EventBus()
    detector = PhishingEmailDetector(config={}, event_bus=event_bus)
    await detector.start()

    results = await detector.analyze(request.emails)
    await detector.stop()

    # Format results
    formatted = []
    for email_data, analysis in zip(request.emails, results):
        formatted.append(format_scan_result(email_data, analysis))

    safe = sum(1 for r in formatted if r["verdict"] == "safe")
    suspicious = sum(1 for r in formatted if r["verdict"] in ("caution", "monitor", "warning"))
    dangerous = sum(1 for r in formatted if r["verdict"] == "danger")

    return EmailScanResponse(
        total_scanned=len(formatted),
        safe_count=safe,
        suspicious_count=suspicious,
        dangerous_count=dangerous,
        results=formatted,
    )


@app.post("/scan/demo-emails")
async def scan_demo_emails():
    """Run phishing scan on sample emails for demo purposes."""
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

    formatted = []
    for email_data, analysis in zip(emails, results):
        formatted.append(format_scan_result(email_data, analysis))

    safe = sum(1 for r in formatted if r["verdict"] == "safe")
    suspicious = sum(1 for r in formatted if r["verdict"] in ("caution", "monitor", "warning"))
    dangerous = sum(1 for r in formatted if r["verdict"] == "danger")

    return {
        "total_scanned": len(formatted),
        "safe_count": safe,
        "suspicious_count": suspicious,
        "dangerous_count": dangerous,
        "results": formatted,
    }


def start_server():
    """Entry point for running the API server."""
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
