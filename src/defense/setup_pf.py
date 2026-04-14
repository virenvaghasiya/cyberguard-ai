"""
CyberGuard AI — macOS pf Firewall Setup (run once as sudo).

Usage:
    sudo python -m src.defense.setup_pf

What this does:
    1. Creates /etc/pf.anchors/cyberguard with the block rule
    2. Adds the anchor reference to /etc/pf.conf (if not already there)
    3. Creates the empty blocklist table
    4. Reloads pf

After this runs once, the server can block/unblock IPs at any time
using pfctl without needing to reload the firewall config.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ANCHOR_PATH = Path("/etc/pf.anchors/cyberguard")
PF_CONF_PATH = Path("/etc/pf.conf")

ANCHOR_CONTENT = """\
# CyberGuard AI — auto-generated anchor
# Blocks IPs added by: pfctl -t cyberguard_blocklist -T add <ip>

table <cyberguard_blocklist> persist
block drop quick from <cyberguard_blocklist> to any
block drop quick from any to <cyberguard_blocklist>
"""

PF_CONF_ADDITION = """\

# CyberGuard AI anchor (auto-added by setup_pf.py)
anchor "cyberguard"
load anchor "cyberguard" from "/etc/pf.anchors/cyberguard"
"""


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)  # noqa: S603


def setup():
    if sys.platform != "darwin":
        print("ERROR: pf setup is macOS-only.")
        sys.exit(1)

    # 1. Write anchor file
    print(f"Writing {ANCHOR_PATH} ...")
    ANCHOR_PATH.write_text(ANCHOR_CONTENT)
    print("  Done.")

    # 2. Patch /etc/pf.conf if anchor not already there
    pf_conf = PF_CONF_PATH.read_text()
    if "cyberguard" not in pf_conf:
        print(f"Patching {PF_CONF_PATH} ...")
        PF_CONF_PATH.write_text(pf_conf + PF_CONF_ADDITION)
        print("  Done.")
    else:
        print(f"{PF_CONF_PATH} already contains cyberguard anchor — skipping.")

    # 3. Reload pf config
    print("Reloading pf ...")
    result = _run(["pfctl", "-f", str(PF_CONF_PATH)], check=False)
    if result.returncode != 0:
        print(f"  WARNING: pfctl reload returned {result.returncode}: {result.stderr}")
    else:
        print("  pf reloaded.")

    # 4. Enable pf if not already running
    result = _run(["pfctl", "-e"], check=False)
    if result.returncode == 0:
        print("  pf enabled.")

    # 5. Verify table exists
    result = _run(["pfctl", "-t", "cyberguard_blocklist", "-T", "show"], check=False)
    if result.returncode == 0:
        print("\n✅ CyberGuard pf anchor is active.")
        print("   Block an IP with: pfctl -t cyberguard_blocklist -T add <ip>")
    else:
        print("\n⚠️  Table check failed — you may need to run with sudo.")
        print("   Try: sudo python -m src.defense.setup_pf")


def teardown():
    """Remove the CyberGuard anchor from pf (for uninstall)."""
    print("Removing CyberGuard pf anchor ...")

    # Flush blocklist
    _run(["pfctl", "-t", "cyberguard_blocklist", "-T", "flush"], check=False)

    # Remove anchor file
    if ANCHOR_PATH.exists():
        ANCHOR_PATH.unlink()
        print(f"  Removed {ANCHOR_PATH}")

    # Remove lines from pf.conf
    pf_conf = PF_CONF_PATH.read_text()
    if "cyberguard" in pf_conf:
        cleaned = "\n".join(
            line for line in pf_conf.splitlines()
            if "cyberguard" not in line
        )
        PF_CONF_PATH.write_text(cleaned)
        print(f"  Cleaned {PF_CONF_PATH}")

    _run(["pfctl", "-f", str(PF_CONF_PATH)], check=False)
    print("✅ CyberGuard pf anchor removed.")


if __name__ == "__main__":
    if "--remove" in sys.argv:
        teardown()
    else:
        setup()
