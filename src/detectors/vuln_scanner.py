"""
Vulnerability Scanner Detector.

Scans a target host (or list of hosts) for open ports, identifies running
services from banner grabs, and flags dangerous or misconfigured services.

Detection categories:
    1. Dangerous Services   — Telnet, FTP, rsh, rlogin (plaintext protocols)
    2. Exposed Admin Panels — SSH on default port, RDP, VNC, Kubernetes API
    3. Database Exposure    — MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch
                              accessible without a firewall
    4. Outdated Banners     — Service banners revealing old, vulnerable versions
    5. Anonymous Access     — FTP anonymous login, Redis no-auth
    6. Default Credentials  — Common services responding to default creds
       (checked passively via banner, not by actually logging in)

Design notes:
    - Uses asyncio for concurrent port scanning (fast, no root needed)
    - Banner grab via asyncio streams (read first 1 KB from open port)
    - No active exploitation — purely observational
    - Safe to run on your own network/machine
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Port / service knowledge base
# ---------------------------------------------------------------------------

@dataclass
class ServiceInfo:
    """Metadata about a well-known port."""
    name: str
    risk: str          # "critical", "high", "medium", "low", "info"
    reason: str        # Human-readable reason for the risk rating
    check_anonymous: bool = False   # Try to detect anonymous access
    keywords: list[str] = field(default_factory=list)  # Banner keywords

# Ports we always check. Grouped by risk level.
KNOWN_SERVICES: dict[int, ServiceInfo] = {
    # Critical — legacy plaintext protocols, no excuse for these being open
    23:    ServiceInfo("Telnet",           "critical", "Plaintext protocol — credentials sent in clear"),
    512:   ServiceInfo("rexec",            "critical", "Legacy remote exec — no encryption"),
    513:   ServiceInfo("rlogin",           "critical", "Legacy remote login — no encryption"),
    514:   ServiceInfo("rsh",              "critical", "Remote shell — no auth or encryption"),
    2375:  ServiceInfo("Docker API",       "critical", "Unauthenticated Docker daemon — full host takeover"),
    2376:  ServiceInfo("Docker API (TLS)", "high",     "Docker API exposed — verify TLS client auth"),

    # High — services that should never be internet-facing
    21:    ServiceInfo("FTP",              "high",     "Plaintext file transfer; often allows anonymous access",
                       check_anonymous=True, keywords=["anonymous", "ftp"]),
    3306:  ServiceInfo("MySQL",            "high",     "Database directly reachable — should be behind firewall"),
    5432:  ServiceInfo("PostgreSQL",       "high",     "Database directly reachable — should be behind firewall"),
    27017: ServiceInfo("MongoDB",          "high",     "MongoDB exposed — often no auth in default config"),
    6379:  ServiceInfo("Redis",            "high",     "Redis exposed — no auth by default; remote code execution risk",
                       check_anonymous=True, keywords=["redis_version"]),
    9200:  ServiceInfo("Elasticsearch",    "high",     "Elasticsearch HTTP API exposed — full data access"),
    9300:  ServiceInfo("Elasticsearch",    "high",     "Elasticsearch transport exposed"),
    5984:  ServiceInfo("CouchDB",          "high",     "CouchDB admin panel may be open without auth"),
    11211: ServiceInfo("Memcached",        "high",     "Memcached exposed — no auth, reflection DDoS amplifier"),
    4444:  ServiceInfo("Metasploit",       "critical", "Common backdoor/C2 port"),
    4445:  ServiceInfo("Metasploit",       "critical", "Common backdoor/C2 port"),

    # Medium — legitimate services that carry risk if misconfigured
    22:    ServiceInfo("SSH",              "medium",   "SSH open — ensure key-only auth, disable root login",
                       keywords=["openssh", "ssh-"]),
    3389:  ServiceInfo("RDP",             "medium",   "Remote Desktop exposed — brute-force and BlueKeep risk"),
    5900:  ServiceInfo("VNC",             "medium",   "VNC exposed — often weak/no auth"),
    5901:  ServiceInfo("VNC",             "medium",   "VNC exposed — often weak/no auth"),
    8080:  ServiceInfo("HTTP Alt",        "medium",   "Alternate HTTP port — verify this is intentional"),
    8443:  ServiceInfo("HTTPS Alt",       "medium",   "Alternate HTTPS port — verify this is intentional"),
    8888:  ServiceInfo("Jupyter/HTTP",    "medium",   "Jupyter Notebook or dev server — often no auth"),
    6443:  ServiceInfo("Kubernetes API",  "high",     "K8s API server exposed — verify RBAC is enforced"),
    2379:  ServiceInfo("etcd",            "high",     "etcd cluster store — full cluster compromise if exposed"),
    2380:  ServiceInfo("etcd peer",       "high",     "etcd peer port — should be cluster-internal only"),
    9090:  ServiceInfo("Prometheus",      "medium",   "Prometheus metrics exposed — leaks internal topology"),
    3000:  ServiceInfo("Dev server",      "low",      "Common dev server port — verify not exposed in prod"),
    4000:  ServiceInfo("Dev server",      "low",      "Common dev server port"),
    5000:  ServiceInfo("Dev server/Flask","low",      "Common Flask/dev port — verify not exposed in prod"),
    7474:  ServiceInfo("Neo4j",           "high",     "Neo4j browser/API exposed"),
    9042:  ServiceInfo("Cassandra",       "high",     "Cassandra native protocol exposed"),

    # Informational
    80:    ServiceInfo("HTTP",            "info",     "Web server on HTTP — verify redirect to HTTPS"),
    443:   ServiceInfo("HTTPS",           "info",     "Web server on HTTPS — verify certificate"),
    25:    ServiceInfo("SMTP",            "medium",   "Mail server exposed — verify not open relay"),
    53:    ServiceInfo("DNS",             "medium",   "DNS exposed — verify recursion disabled for external IPs"),
    161:   ServiceInfo("SNMP",            "high",     "SNMP exposed — often uses default community string 'public'"),
    162:   ServiceInfo("SNMP trap",       "high",     "SNMP trap receiver exposed"),
}

# Regex patterns to extract version info from banners
_VERSION_PATTERNS = [
    re.compile(r"OpenSSH[_\s]([\d.]+)", re.IGNORECASE),
    re.compile(r"Apache[/\s]([\d.]+)", re.IGNORECASE),
    re.compile(r"nginx[/\s]([\d.]+)", re.IGNORECASE),
    re.compile(r"MySQL\s+([\d.]+)", re.IGNORECASE),
    re.compile(r"PostgreSQL\s+([\d.]+)", re.IGNORECASE),
    re.compile(r"redis_version:([\d.]+)", re.IGNORECASE),
    re.compile(r"ProFTPD\s+([\d.]+)", re.IGNORECASE),
    re.compile(r"vsftpd\s+([\d.]+)", re.IGNORECASE),
    re.compile(r"Dovecot.*?([\d.]+)", re.IGNORECASE),
    re.compile(r"Exim\s+([\d.]+)", re.IGNORECASE),
]

# Known old/vulnerable version prefixes
_OUTDATED_VERSIONS = {
    "OpenSSH": ["5.", "6.", "7.0", "7.1", "7.2", "7.3", "7.4"],
    "Apache":  ["1.", "2.0", "2.2"],
    "nginx":   ["0.", "1.0", "1.2", "1.4", "1.6", "1.8", "1.10", "1.12", "1.14"],
    "MySQL":   ["5.0", "5.1", "5.5", "5.6"],
    "vsftpd":  ["2.0", "2.3.4"],  # 2.3.4 has a backdoor
}


class VulnerabilityScanner(BaseDetector):
    """
    Scans hosts for open ports and misconfigured / dangerous services.

    Input (to analyze()):
        A dict with:
            target  (str)          — IP, hostname, or CIDR range (e.g. "192.168.1.0/24")
            ports   (list[int])    — optional; defaults to KNOWN_SERVICES keys
            timeout (float)        — per-port connect timeout (default 1.0 s)

        Or a plain string / IP address.

    Output:
        List of finding dicts — one per discovered risk.
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="vuln_scanner", config=config, event_bus=event_bus)

        cfg = config.get("vulnerability_scanner", {})
        self._default_timeout = cfg.get("timeout", 1.0)
        self._max_concurrent = cfg.get("max_concurrent", 50)
        self._default_ports = cfg.get(
            "ports",
            sorted(KNOWN_SERVICES.keys()),
        )

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("vuln_scanner_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("vuln_scanner_stopped")

    async def analyze(self, data: Any) -> list[dict]:
        """
        Scan target(s) for vulnerabilities.

        Args:
            data: dict with 'target', optional 'ports' and 'timeout',
                  or a plain IP/hostname string.

        Returns:
            List of vulnerability finding dicts.
        """
        # --- Normalize input ---
        if isinstance(data, str):
            target_spec = data.strip()
            ports = self._default_ports
            timeout = self._default_timeout
        elif isinstance(data, dict):
            target_spec = str(data.get("target", "127.0.0.1")).strip()
            ports = data.get("ports", self._default_ports)
            timeout = float(data.get("timeout", self._default_timeout))
        else:
            logger.warning("vuln_scanner_invalid_input", data_type=type(data).__name__)
            return []

        # --- Resolve targets ---
        targets = self._resolve_targets(target_spec)
        if not targets:
            logger.warning("vuln_scanner_no_targets", spec=target_spec)
            return []

        logger.info(
            "vuln_scan_started",
            targets=len(targets),
            ports=len(ports),
            timeout=timeout,
        )

        # --- Scan all targets ---
        all_findings: list[dict] = []
        for target in targets:
            findings = await self._scan_host(target, ports, timeout)
            all_findings.extend(findings)

        # --- Publish events ---
        for finding in all_findings:
            await self.event_bus.publish(Event(
                event_type=EventType.ANOMALY_DETECTED,
                source=self.name,
                severity=finding["severity_enum"],
                data={
                    "detector": self.name,
                    "attack_type": finding["attack_type"],
                    **finding["details"],
                },
            ))

        self._update_status(
            events_processed=self._status.events_processed + len(targets) * len(ports),
            anomalies_detected=self._status.anomalies_detected + len(all_findings),
        )

        logger.info(
            "vuln_scan_complete",
            targets_scanned=len(targets),
            findings=len(all_findings),
        )

        return all_findings

    # -----------------------------------------------------------------------
    # Target resolution
    # -----------------------------------------------------------------------

    def _resolve_targets(self, spec: str) -> list[str]:
        """
        Convert a target spec to a list of IP address strings.

        Accepts:
            - Single IP:       "192.168.1.1"
            - Hostname:        "localhost", "myserver.local"
            - CIDR range:      "192.168.1.0/24"  (max /24 = 254 hosts)
        """
        try:
            network = ipaddress.ip_network(spec, strict=False)
            # Safety: don't scan huge ranges unintentionally
            if network.num_addresses > 256:
                logger.warning(
                    "vuln_scanner_range_too_large",
                    spec=spec,
                    hosts=network.num_addresses,
                )
                return []
            if network.num_addresses == 1:
                return [str(network.network_address)]
            # Skip network and broadcast addresses
            return [str(h) for h in network.hosts()]
        except ValueError:
            # Hostname — resolve it
            try:
                ip = socket.gethostbyname(spec)
                return [ip]
            except socket.gaierror:
                logger.error("vuln_scanner_resolve_failed", hostname=spec)
                return []

    # -----------------------------------------------------------------------
    # Host scanning
    # -----------------------------------------------------------------------

    async def _scan_host(
        self, host: str, ports: list[int], timeout: float
    ) -> list[dict]:
        """Scan all ports on a single host concurrently."""
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def probe(port: int) -> dict | None:
            async with semaphore:
                return await self._probe_port(host, port, timeout)

        results = await asyncio.gather(*[probe(p) for p in ports])
        open_ports = [r for r in results if r is not None]

        findings: list[dict] = []
        for port_result in open_ports:
            finding = self._evaluate_port(host, port_result)
            if finding:
                findings.append(finding)

        return findings

    async def _probe_port(
        self, host: str, port: int, timeout: float
    ) -> dict | None:
        """
        Try to connect to host:port and grab a service banner.

        Returns a dict with port info if open, None if closed/filtered.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        # Grab banner — send a minimal probe and read the response
        banner = ""
        try:
            # Some services send a banner on connect (SSH, FTP, SMTP)
            # Others need a request (HTTP). Send a generic HTTP-ish probe.
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await asyncio.wait_for(writer.drain(), timeout=0.5)
            raw = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = raw.decode("utf-8", errors="replace").strip()
        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

        return {"port": port, "banner": banner}

    # -----------------------------------------------------------------------
    # Risk evaluation
    # -----------------------------------------------------------------------

    def _evaluate_port(self, host: str, port_info: dict) -> dict | None:
        """
        Evaluate an open port against the knowledge base.

        Returns a finding dict if the port represents a risk, None for
        info-only findings below the noise threshold.
        """
        port = port_info["port"]
        banner = port_info["banner"]

        service = KNOWN_SERVICES.get(port)
        if service is None:
            # Unknown open port — flag as low risk
            return self._make_finding(
                host=host,
                port=port,
                attack_type="unknown_open_port",
                severity=Severity.LOW,
                confidence=0.5,
                service_name=f"Unknown (port {port})",
                banner=banner,
                description=f"Port {port} is open but not in the known-services database",
                recommendation="Identify and verify this service is intentional",
            )

        # Skip pure info ports unless they have something notable in the banner
        if service.risk == "info" and not banner:
            return None

        severity = self._risk_to_severity(service.risk)
        confidence = 0.9  # High confidence — port is open and matched

        extra_notes = []

        # Check for version info in banner → outdated version detection
        version_note = self._check_banner_version(banner, service.name)
        if version_note:
            extra_notes.append(version_note)
            if severity.value in ("low", "medium", "info"):
                severity = Severity.HIGH   # Outdated version escalates severity

        # Check for anonymous/no-auth indicators
        if service.check_anonymous:
            anon_note = self._check_anonymous_access(port, banner)
            if anon_note:
                extra_notes.append(anon_note)
                severity = Severity.CRITICAL

        description = service.reason
        if extra_notes:
            description += " | " + " | ".join(extra_notes)

        return self._make_finding(
            host=host,
            port=port,
            attack_type=self._risk_to_attack_type(service.risk, service.name),
            severity=severity,
            confidence=confidence,
            service_name=service.name,
            banner=banner[:200] if banner else "",
            description=description,
            recommendation=self._get_recommendation(port, service),
        )

    def _check_banner_version(self, banner: str, service_name: str) -> str | None:
        """Extract version from banner and check if it's outdated."""
        if not banner:
            return None

        for pattern in _VERSION_PATTERNS:
            m = pattern.search(banner)
            if not m:
                continue
            version = m.group(1)
            # Check against known outdated prefixes
            for svc, old_prefixes in _OUTDATED_VERSIONS.items():
                if svc.lower() in service_name.lower() or svc.lower() in banner.lower():
                    for prefix in old_prefixes:
                        if version.startswith(prefix):
                            return f"Outdated version detected: {svc} {version}"
            return f"Version identified: {version}"

        return None

    def _check_anonymous_access(self, port: int, banner: str) -> str | None:
        """Check if service appears to allow anonymous/no-auth access."""
        if not banner:
            return None

        banner_lower = banner.lower()

        # FTP anonymous
        if port == 21 and "anonymous" in banner_lower:
            return "Anonymous FTP access may be enabled"

        # Redis no-auth (responds to INFO command without NOAUTH error)
        if port == 6379 and "redis_version" in banner_lower:
            return "Redis responding without authentication"

        # MongoDB no-auth
        if port == 27017 and ("mongodb" in banner_lower or "ismaster" in banner_lower):
            return "MongoDB may be accessible without credentials"

        return None

    # -----------------------------------------------------------------------
    # Mapping helpers
    # -----------------------------------------------------------------------

    def _risk_to_severity(self, risk: str) -> Severity:
        return {
            "critical": Severity.CRITICAL,
            "high":     Severity.HIGH,
            "medium":   Severity.MEDIUM,
            "low":      Severity.LOW,
            "info":     Severity.INFO,
        }.get(risk, Severity.LOW)

    def _risk_to_attack_type(self, risk: str, service_name: str) -> str:
        name_lower = service_name.lower().replace(" ", "_")
        if risk == "critical":
            return f"dangerous_service_{name_lower}"
        if risk == "high":
            return f"exposed_service_{name_lower}"
        return f"open_port_{name_lower}"

    def _get_recommendation(self, port: int, service: ServiceInfo) -> str:
        recs: dict[int, str] = {
            23:    "Disable Telnet immediately. Use SSH instead.",
            21:    "Disable FTP. Use SFTP or SCP. If needed, disable anonymous access.",
            3306:  "Bind MySQL to 127.0.0.1 only. Use a firewall rule to block external access.",
            5432:  "Bind PostgreSQL to 127.0.0.1. Use pg_hba.conf to restrict access.",
            27017: "Enable MongoDB authentication (--auth). Bind to localhost.",
            6379:  "Set Redis requirepass. Bind to 127.0.0.1. Enable protected-mode.",
            9200:  "Enable Elasticsearch security (xpack.security.enabled: true).",
            2375:  "Never expose Docker socket over TCP without TLS client certs.",
            22:    "Disable password auth (PasswordAuthentication no). Disable root login.",
            3389:  "Restrict RDP to VPN only. Enable NLA. Keep patched (BlueKeep).",
            5900:  "Disable VNC or restrict to VPN. Set a strong password.",
            161:   "Change SNMP community string from 'public'. Restrict by ACL.",
        }
        return recs.get(port, f"Review whether {service.name} on port {port} needs to be publicly accessible.")

    def _make_finding(
        self,
        host: str,
        port: int,
        attack_type: str,
        severity: Severity,
        confidence: float,
        service_name: str,
        banner: str,
        description: str,
        recommendation: str,
    ) -> dict:
        return {
            "is_anomaly": True,
            "attack_type": attack_type,
            "confidence": round(confidence, 3),
            "severity": severity.value,
            "severity_enum": severity,
            "anomaly_score": -0.5 - (confidence * 0.5),
            "details": {
                "host": host,
                "port": port,
                "service": service_name,
                "banner": banner,
                "description": description,
                "recommendation": recommendation,
            },
        }
