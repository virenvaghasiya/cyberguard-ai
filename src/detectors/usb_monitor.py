"""
CyberGuard AI — USB Device Monitor (Phase 7c).

Alerts when a new USB device connects to the Mac.
Higher risk for HID (Human Interface) devices — these can be BadUSB
attacks where a malicious device pretends to be a keyboard and types commands.

Uses macOS `system_profiler SPUSBDataType` (built-in, no install needed).
Falls back to /sys/bus/usb on Linux.

Maintains a list of trusted (user-approved) devices.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity
from typing import Any

logger = structlog.get_logger()

TRUSTED_DEVICES_PATH = Path("data/trusted_usb_devices.json")

# Device classes considered higher risk (BadUSB)
HIGH_RISK_CLASSES = {
    "hid",          # Human Interface Device (keyboard/mouse)
    "hub",          # USB hub (can hide devices)
    "cdc",          # Communications — can be used for network access
}


def _load_trusted() -> set[str]:
    """Load set of trusted device IDs (vendor_id:product_id)."""
    if not TRUSTED_DEVICES_PATH.exists():
        return set()
    try:
        return set(json.loads(TRUSTED_DEVICES_PATH.read_text()))
    except (json.JSONDecodeError, OSError):
        return set()


def _save_trusted(trusted: set[str]) -> None:
    TRUSTED_DEVICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    TRUSTED_DEVICES_PATH.write_text(json.dumps(sorted(trusted), indent=2))


def _device_id(vendor_id: str, product_id: str) -> str:
    return f"{vendor_id}:{product_id}"


async def _get_usb_devices_macos() -> list[dict]:
    """Parse macOS system_profiler output for USB devices."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "system_profiler", "SPUSBDataType",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode("utf-8", errors="replace")
    except (FileNotFoundError, asyncio.TimeoutError):
        return []

    devices: list[dict] = []
    current: dict = {}

    for line in output.splitlines():
        line = line.strip()

        # New device block starts with an indented name (2-4 spaces + word chars)
        if re.match(r"^[A-Z].*:$", line) and not line.startswith(" "):
            if current.get("vendor_id"):
                devices.append(current)
            current = {"name": line.rstrip(":")}
            continue

        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            val = val.strip()
            current[key] = val

    if current.get("vendor_id"):
        devices.append(current)

    return devices


async def _get_usb_devices_linux() -> list[dict]:
    """Read USB devices from /sys/bus/usb/devices on Linux."""
    devices: list[dict] = []
    usb_root = Path("/sys/bus/usb/devices")
    if not usb_root.exists():
        return devices

    for dev_path in usb_root.iterdir():
        vendor_file = dev_path / "idVendor"
        product_file = dev_path / "idProduct"
        name_file = dev_path / "product"
        class_file = dev_path / "bDeviceClass"

        if not vendor_file.exists():
            continue

        try:
            devices.append({
                "vendor_id": vendor_file.read_text().strip(),
                "product_id": product_file.read_text().strip() if product_file.exists() else "0000",
                "name": name_file.read_text().strip() if name_file.exists() else "Unknown",
                "device_class": class_file.read_text().strip() if class_file.exists() else "",
            })
        except OSError:
            continue

    return devices


async def get_usb_devices() -> list[dict]:
    """Return current USB device list (cross-platform)."""
    if sys.platform == "darwin":
        return await _get_usb_devices_macos()
    return await _get_usb_devices_linux()


def _assess_device(device: dict, trusted_ids: set[str]) -> tuple[str, list[str]]:
    """Return (risk_level, reasons) for a USB device."""
    reasons: list[str] = []
    risk = "low"

    vid = device.get("vendor_id", "")
    pid = device.get("product_id", "")
    dev_id = _device_id(vid, pid)
    name = (device.get("name") or "").lower()
    dev_class = (device.get("device_class") or "").lower()

    # Unknown device (not in trusted list)
    if dev_id not in trusted_ids and vid:
        risk = "medium"
        reasons.append("New unrecognised USB device")

    # HID device (keyboard/mouse) = higher risk
    if "hid" in dev_class or "keyboard" in name or "mouse" in name:
        if risk != "low":
            risk = "high"
        reasons.append("HID device (keyboard/mouse) — possible BadUSB")

    # Hub = can hide additional devices
    if "hub" in dev_class or "hub" in name:
        if risk == "low":
            risk = "medium"
        reasons.append("USB hub connected — can conceal additional devices")

    return risk, reasons


class USBMonitor(BaseDetector):
    """Detects new USB device connections."""

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="usb_monitor", config=config, event_bus=event_bus)

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("usb_monitor_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("usb_monitor_stopped")

    async def analyze(self, data=None) -> list[dict]:
        """
        Get current USB devices and flag any that are not in the trusted list.
        """
        trusted = _load_trusted()
        devices = await get_usb_devices()
        findings: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()

        for device in devices:
            vid = device.get("vendor_id", "")
            pid = device.get("product_id", "")
            if not vid:
                continue

            dev_id = _device_id(vid, pid)
            risk, reasons = _assess_device(device, trusted)

            if risk == "low":
                continue

            finding = {
                "device_id": dev_id,
                "vendor_id": vid,
                "product_id": pid,
                "name": device.get("name") or "Unknown",
                "risk": risk,
                "reasons": reasons,
                "trusted": dev_id in trusted,
                "timestamp": now,
            }
            findings.append(finding)

            if risk in ("high", "critical"):
                sev = Severity.CRITICAL if risk == "critical" else Severity.HIGH
                await self.event_bus.publish(Event(
                    event_type=EventType.ALERT_CREATED,
                    source=self.name,
                    severity=sev,
                    data={
                        "attack_type": "suspicious_usb_device",
                        "device_id": dev_id,
                        "device_name": device.get("name") or "Unknown",
                        "reasons": reasons,
                    },
                ))

        return findings

    async def get_all_devices(self) -> list[dict]:
        """Return all connected USB devices with trust status."""
        trusted = _load_trusted()
        devices = await get_usb_devices()
        now = datetime.now(timezone.utc).isoformat()
        result = []
        for d in devices:
            vid = d.get("vendor_id", "")
            pid = d.get("product_id", "")
            dev_id = _device_id(vid, pid)
            _, reasons = _assess_device(d, trusted)
            result.append({
                **d,
                "device_id": dev_id,
                "trusted": dev_id in trusted,
                "reasons": reasons,
                "timestamp": now,
            })
        return result

    def trust_device(self, device_id: str) -> bool:
        """Mark a device as trusted. Returns True on success."""
        trusted = _load_trusted()
        trusted.add(device_id)
        _save_trusted(trusted)
        logger.info("usb_device_trusted", device_id=device_id)
        return True

    def untrust_device(self, device_id: str) -> bool:
        """Remove a device from the trusted list."""
        trusted = _load_trusted()
        trusted.discard(device_id)
        _save_trusted(trusted)
        return True
