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
async def test_live_connections(client):
    """Live network connections endpoint should return real connection data."""
    response = await client.get("/network/live")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "suspicious" in data
    assert "connections" in data
    assert isinstance(data["connections"], list)


@pytest.mark.asyncio
async def test_system_stats(client):
    """System stats endpoint should return CPU/memory/disk data."""
    response = await client.get("/network/system")
    assert response.status_code == 200
    data = response.json()
    assert "cpu_percent" in data
    assert "memory" in data
    assert "disk" in data
    assert "network_io" in data


@pytest.mark.asyncio
async def test_gmail_status(client):
    """Gmail status endpoint should return connection state."""
    response = await client.get("/gmail/status")
    assert response.status_code == 200
    data = response.json()
    assert "connected" in data
    assert "setup_required" in data


@pytest.mark.asyncio
async def test_get_events(client):
    """Events endpoint should return recent events list."""
    response = await client.get("/events?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
