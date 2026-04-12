"""Tests for the CyberGuard API server."""

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.server import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


@pytest.mark.asyncio
async def test_health_check(client):
    """Health endpoint should return status and version."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "detectors" in data


@pytest.mark.asyncio
async def test_list_detectors(client):
    """Detectors endpoint should list registered detectors."""
    response = await client.get("/detectors")
    assert response.status_code == 200
    data = response.json()
    assert "detectors" in data
    assert len(data["detectors"]) >= 1

    detector = data["detectors"][0]
    assert detector["name"] == "network_anomaly_detector"
    assert detector["running"] is True


@pytest.mark.asyncio
async def test_demo_analysis(client):
    """Demo endpoint should run analysis and return results."""
    response = await client.post("/analyze/demo")
    assert response.status_code == 200
    data = response.json()

    assert "total_flows" in data
    assert "anomalies_detected" in data
    assert "anomaly_rate" in data
    assert "results" in data
    assert data["total_flows"] > 0
    assert data["anomalies_detected"] > 0


@pytest.mark.asyncio
async def test_get_events(client):
    """Events endpoint should return recent events."""
    # Run a demo first to generate events
    await client.post("/analyze/demo")

    response = await client.get("/events?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
