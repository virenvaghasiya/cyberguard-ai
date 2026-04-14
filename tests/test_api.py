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


@pytest.mark.asyncio
async def test_defense_status(client):
    """Defense status endpoint should return pf state and block count."""
    response = await client.get("/defense/status")
    assert response.status_code == 200
    data = response.json()
    assert "pf_active" in data
    assert "active_block_count" in data
    assert isinstance(data["active_block_count"], int)


@pytest.mark.asyncio
async def test_defense_blocklist(client):
    """Blocklist endpoint should return list structure."""
    response = await client.get("/defense/blocklist")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "blocks" in data
    assert isinstance(data["blocks"], list)


@pytest.mark.asyncio
async def test_defense_block_and_unblock(client):
    """Block an IP then unblock it — full round trip."""
    test_ip = "10.255.255.1"

    # Block
    response = await client.post("/defense/block", json={
        "ip": test_ip,
        "reason": "pytest test block",
        "attack_type": "test",
        "severity": "high",
        "duration_hours": 1,
    })
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == test_ip
    assert data["active"] is True

    # Should appear in blocklist
    response = await client.get("/defense/blocklist")
    assert response.status_code == 200
    ips = [b["ip"] for b in response.json()["blocks"]]
    assert test_ip in ips

    # Unblock
    response = await client.post(f"/defense/unblock?ip={test_ip}")
    assert response.status_code == 200
    assert response.json()["unblocked"] is True

    # Should no longer be in blocklist
    response = await client.get("/defense/blocklist")
    ips = [b["ip"] for b in response.json()["blocks"]]
    assert test_ip not in ips


@pytest.mark.asyncio
async def test_defense_history(client):
    """History endpoint should return audit log."""
    response = await client.get("/defense/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "history" in data
    assert isinstance(data["history"], list)


@pytest.mark.asyncio
async def test_defense_unblock_unknown_ip(client):
    """Unblocking an IP that is not blocked should return 404."""
    response = await client.post("/defense/unblock?ip=192.0.2.99")
    assert response.status_code == 404


# ── Phase 7 tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_processes_suspicious(client):
    """Suspicious processes endpoint should return structured findings."""
    response = await client.get("/processes/suspicious")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "findings" in data
    assert isinstance(data["findings"], list)


@pytest.mark.asyncio
async def test_processes_all(client):
    """All-processes endpoint should return running processes."""
    response = await client.get("/processes/all")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "processes" in data
    assert data["count"] > 0  # there must be at least some processes running


@pytest.mark.asyncio
async def test_process_kill_invalid_pid(client):
    """Killing a non-existent PID should return 400."""
    response = await client.post("/processes/kill/9999999")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_persistence_baseline(client):
    """Taking a baseline should return file count."""
    response = await client.post("/persistence/baseline")
    assert response.status_code == 200
    data = response.json()
    assert data["baseline_taken"] is True
    assert data["files_watched"] >= 0


@pytest.mark.asyncio
async def test_persistence_status(client):
    """Persistence status should return change list after baseline exists."""
    # Ensure baseline exists first
    await client.post("/persistence/baseline")
    response = await client.get("/persistence/status")
    assert response.status_code == 200
    data = response.json()
    assert "has_baseline" in data
    assert "changes_detected" in data
    assert "changes" in data


@pytest.mark.asyncio
async def test_usb_devices(client):
    """USB devices endpoint should return device list."""
    response = await client.get("/usb/devices")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "devices" in data
    assert isinstance(data["devices"], list)


@pytest.mark.asyncio
async def test_usb_suspicious(client):
    """USB suspicious endpoint should return structured findings."""
    response = await client.get("/usb/suspicious")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "devices" in data


@pytest.mark.asyncio
async def test_usb_trust(client):
    """Trusting a USB device ID should succeed."""
    response = await client.post("/usb/trust?device_id=05ac:1234")
    assert response.status_code == 200
    assert response.json()["trusted"] is True
