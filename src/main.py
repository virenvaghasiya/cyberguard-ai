"""
CyberGuard AI — Main Entry Point.

Run with:
    python -m src.main --demo          # Run demo with synthetic data
    python -m src.main --input file.csv # Analyze a traffic file
    python -m src.main --serve          # Start the API server
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src.core.pipeline import PipelineManager
from src.detectors.network_detector import NetworkAnomalyDetector
from src.detectors.port_scan_detector import PortScanDetector
from src.detectors.c2_beacon_detector import C2BeaconDetector
from src.utils.sample_data import generate_sample_traffic

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

console = Console()


def print_banner():
    """Print the startup banner."""
    banner = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                         AI-Powered Cybersecurity Defense
    """
    console.print(Panel(banner, style="bold cyan", title="v0.1.0"))


async def run_demo():
    """Run the full demo: generate synthetic traffic, detect anomalies, display results."""
    print_banner()
    console.print("\n[bold yellow]Running demo with synthetic network traffic...[/bold yellow]\n")

    # Initialize pipeline with all three detectors
    pipeline = PipelineManager()

    network_detector = NetworkAnomalyDetector(
        config=pipeline.config,
        event_bus=pipeline.event_bus,
    )
    port_scan_detector = PortScanDetector(
        config=pipeline.config,
        event_bus=pipeline.event_bus,
    )
    c2_beacon_detector = C2BeaconDetector(
        config=pipeline.config,
        event_bus=pipeline.event_bus,
    )

    pipeline.register_detector(network_detector)
    pipeline.register_detector(port_scan_detector)
    pipeline.register_detector(c2_beacon_detector)
    await pipeline.start_all()

    # Generate synthetic traffic
    console.print("[dim]Generating 5000 normal + 250 anomalous flow records...[/dim]")
    traffic = generate_sample_traffic(n_normal=5000, n_anomalous=250)

    # Save sample data for reference
    sample_path = Path("data/sample/traffic.csv")
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    traffic.to_csv(sample_path, index=False)
    console.print(f"[dim]Sample data saved to {sample_path}[/dim]\n")

    # --- Run all three detectors ---

    # 1. Isolation Forest (volumetric anomalies — DDoS, exfiltration)
    console.print("[bold]Running Isolation Forest detector...[/bold]")
    ml_results = await network_detector.analyze(traffic)

    # 2. Port scan detector (sequential pattern analysis)
    console.print("[bold]Running port scan detector...[/bold]")
    scan_results = await port_scan_detector.analyze(traffic)

    # 3. C2 beacon detector (timing regularity analysis)
    console.print("[bold]Running C2 beacon detector...[/bold]\n")
    beacon_results = await c2_beacon_detector.analyze(traffic)

    # --- Merge results ---
    # The ML detector returns per-flow results. The scan and beacon detectors
    # return per-pair results with flow_indices. We merge by marking flows
    # that belong to detected scans or beacons as anomalous.

    for scan in scan_results:
        for idx in scan.get("flow_indices", []):
            if idx < len(ml_results):
                if not ml_results[idx]["is_anomaly"]:
                    ml_results[idx]["is_anomaly"] = True
                    ml_results[idx]["severity"] = scan["severity"]
                    ml_results[idx]["anomaly_score"] = scan["anomaly_score"]
                ml_results[idx]["details"]["attack_type"] = "port_scan"
                ml_results[idx]["details"]["scan_type"] = scan.get("scan_type", "unknown")

    for beacon in beacon_results:
        for idx in beacon.get("flow_indices", []):
            if idx < len(ml_results):
                if not ml_results[idx]["is_anomaly"]:
                    ml_results[idx]["is_anomaly"] = True
                    ml_results[idx]["severity"] = beacon["severity"]
                    ml_results[idx]["anomaly_score"] = beacon["anomaly_score"]
                ml_results[idx]["details"]["attack_type"] = "c2_beacon"
                ml_results[idx]["details"]["beacon_interval"] = beacon["details"].get(
                    "beacon_interval_seconds", "?"
                )

    # Display merged results
    _display_results(ml_results, traffic)

    # Display specialized detector summaries
    if scan_results:
        console.print("\n[bold magenta]Port Scan Detections:[/bold magenta]")
        scan_table = Table(show_header=True, header_style="bold magenta")
        scan_table.add_column("Source IP")
        scan_table.add_column("Target IP")
        scan_table.add_column("Unique Ports", justify="right")
        scan_table.add_column("Scan Type")
        scan_table.add_column("Confidence", justify="right")
        scan_table.add_column("Severity")

        for s in scan_results:
            d = s["details"]
            sev = s["severity"]
            color = {"high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            scan_table.add_row(
                d["src_ip"], d["dst_ip"], str(d["unique_ports"]),
                d["scan_type"], f"{s['confidence']:.1%}",
                f"[{color}]{sev.upper()}[/{color}]",
            )
        console.print(scan_table)

    if beacon_results:
        console.print("\n[bold magenta]C2 Beacon Detections:[/bold magenta]")
        beacon_table = Table(show_header=True, header_style="bold magenta")
        beacon_table.add_column("Source IP")
        beacon_table.add_column("C2 Server")
        beacon_table.add_column("Interval", justify="right")
        beacon_table.add_column("Flows", justify="right")
        beacon_table.add_column("Timing CV", justify="right")
        beacon_table.add_column("Confidence", justify="right")
        beacon_table.add_column("Severity")

        for b in beacon_results:
            d = b["details"]
            sev = b["severity"]
            color = {"high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            beacon_table.add_row(
                d["src_ip"], d["dst_ip"],
                f"{d['beacon_interval_seconds']}s",
                str(d["flow_count"]),
                f"{d['timing_cv']:.4f}",
                f"{b['confidence']:.1%}",
                f"[{color}]{sev.upper()}[/{color}]",
            )
        console.print(beacon_table)

    # Show all detector statuses
    console.print("\n[bold]Detector Status:[/bold]")
    for det in [network_detector, port_scan_detector, c2_beacon_detector]:
        status = det.get_status()
        console.print(f"  [{det.name}]")
        console.print(f"    Events processed:  {status.events_processed}")
        console.print(f"    Anomalies found:   {status.anomalies_detected}")

    await pipeline.stop_all()
    console.print("\n[bold green]Demo complete.[/bold green]")


async def run_analysis(input_path: str):
    """Analyze a specific traffic file."""
    print_banner()

    path = Path(input_path)
    if not path.exists():
        console.print(f"[bold red]Error: File not found: {path}[/bold red]")
        sys.exit(1)

    console.print(f"\n[bold yellow]Analyzing traffic file: {path}[/bold yellow]\n")

    pipeline = PipelineManager()
    detector = NetworkAnomalyDetector(
        config=pipeline.config,
        event_bus=pipeline.event_bus,
    )
    pipeline.register_detector(detector)
    await pipeline.start_all()

    results = await detector.analyze(str(path))

    import pandas as pd
    traffic = pd.read_csv(path)
    _display_results(results, traffic)

    await pipeline.stop_all()


def _display_results(results: list[dict], traffic):
    """Render detection results as a rich table."""
    anomalies = [r for r in results if r["is_anomaly"]]

    # Summary
    console.print(Panel(
        f"[bold]Total flows analyzed:[/bold]  {len(results)}\n"
        f"[bold]Anomalies detected:[/bold]   {len(anomalies)}\n"
        f"[bold]Anomaly rate:[/bold]          {len(anomalies) / len(results) * 100:.1f}%",
        title="Detection Summary",
        style="bold",
    ))

    if not anomalies:
        console.print("[green]No anomalies detected.[/green]")
        return

    # Severity breakdown
    severity_counts = {}
    for a in anomalies:
        sev = a.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    console.print("\n[bold]Severity Breakdown:[/bold]")
    for sev in ["high", "medium", "low"]:
        count = severity_counts.get(sev, 0)
        color = {"high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
        console.print(f"  [{color}]{sev.upper():8s}[/{color}]: {count}")

    # If we have labels in the data (demo mode), show detection accuracy
    if "label" in traffic.columns:
        console.print("\n[bold]Detection by Attack Type:[/bold]")
        label_table = Table(show_header=True, header_style="bold")
        label_table.add_column("Attack Type")
        label_table.add_column("Total", justify="right")
        label_table.add_column("Detected", justify="right")
        label_table.add_column("Rate", justify="right")

        for label in traffic["label"].unique():
            if label == "normal":
                continue
            total = len(traffic[traffic["label"] == label])
            indices = traffic[traffic["label"] == label].index.tolist()
            detected = sum(1 for r in results if r["index"] in indices and r["is_anomaly"])
            rate = detected / total * 100 if total > 0 else 0
            label_table.add_row(label, str(total), str(detected), f"{rate:.0f}%")

        # False positive rate on normal traffic
        normal_indices = traffic[traffic["label"] == "normal"].index.tolist()
        false_positives = sum(1 for r in results if r["index"] in normal_indices and r["is_anomaly"])
        fp_rate = false_positives / len(normal_indices) * 100 if normal_indices else 0
        label_table.add_row(
            "[dim]false positives (normal)[/dim]",
            str(len(normal_indices)),
            str(false_positives),
            f"[{'red' if fp_rate > 10 else 'green'}]{fp_rate:.1f}%[/]",
        )

        console.print(label_table)

    # Top anomalies detail table
    console.print("\n[bold]Top 15 Anomalies:[/bold]")
    detail_table = Table(show_header=True, header_style="bold magenta")
    detail_table.add_column("Score", justify="right")
    detail_table.add_column("Severity")
    detail_table.add_column("Source IP")
    detail_table.add_column("Dest IP")
    detail_table.add_column("Dst Port", justify="right")
    detail_table.add_column("Proto")
    detail_table.add_column("Packets", justify="right")
    detail_table.add_column("Bytes", justify="right")

    # Sort by anomaly score (most anomalous first)
    sorted_anomalies = sorted(anomalies, key=lambda x: x["anomaly_score"])[:15]

    for a in sorted_anomalies:
        d = a["details"]
        sev = a.get("severity", "?")
        color = {"high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
        detail_table.add_row(
            f"{a['anomaly_score']:.3f}",
            f"[{color}]{sev.upper()}[/{color}]",
            d.get("src_ip", "?"),
            d.get("dst_ip", "?"),
            str(d.get("dst_port", "?")),
            str(d.get("protocol", "?")),
            str(d.get("packets", "?")),
            str(d.get("bytes", "?")),
        )

    console.print(detail_table)


@click.command()
@click.option("--demo", is_flag=True, help="Run demo with synthetic traffic data")
@click.option("--phishing-demo", is_flag=True, help="Run phishing email detection demo")
@click.option("--input", "input_path", type=str, help="Path to a CSV traffic file to analyze")
@click.option("--serve", is_flag=True, help="Start the REST API server")
def main(demo: bool, phishing_demo: bool, input_path: str | None, serve: bool):
    """CyberGuard AI — AI-Powered Cybersecurity Defense System."""
    if serve:
        from src.api.server import start_server
        print_banner()
        console.print("\n[bold yellow]Starting API server...[/bold yellow]\n")
        start_server()
    elif demo:
        asyncio.run(run_demo())
    elif phishing_demo:
        asyncio.run(run_phishing_demo())
    elif input_path:
        asyncio.run(run_analysis(input_path))
    else:
        print_banner()
        console.print("\nUsage:")
        console.print("  python -m src.main --demo              Run network traffic demo")
        console.print("  python -m src.main --phishing-demo     Run phishing email demo")
        console.print("  python -m src.main --input file.csv    Analyze a traffic file")
        console.print("  python -m src.main --serve             Start the API server")
        console.print("\nRun [bold]python -m src.main --help[/bold] for all options.\n")


async def run_phishing_demo():
    """Run the phishing email detection demo."""
    from src.core.events import EventBus
    from src.detectors.phishing_detector import PhishingEmailDetector
    from src.utils.sample_emails import generate_sample_emails

    print_banner()
    console.print("\n[bold yellow]Running phishing email detection demo...[/bold yellow]\n")

    event_bus = EventBus()
    detector = PhishingEmailDetector(config={}, event_bus=event_bus)
    await detector.start()

    emails = generate_sample_emails()
    console.print(f"[dim]Analyzing {len(emails)} emails ({sum(1 for e in emails if e.get('label') == 'phishing')} phishing, {sum(1 for e in emails if e.get('label') == 'legitimate')} legitimate)...[/dim]\n")

    results = await detector.analyze(emails)

    # Summary
    phishing_detected = [r for r in results if r["is_phishing"]]
    console.print(Panel(
        f"[bold]Total emails analyzed:[/bold]   {len(results)}\n"
        f"[bold]Phishing detected:[/bold]       {len(phishing_detected)}\n"
        f"[bold]Detection rate:[/bold]           {len(phishing_detected) / len(results) * 100:.1f}%",
        title="Phishing Detection Summary",
        style="bold",
    ))

    # Detection accuracy if labels are available
    if all("label" in e for e in emails):
        console.print("\n[bold]Detection Accuracy:[/bold]")
        acc_table = Table(show_header=True, header_style="bold")
        acc_table.add_column("Category")
        acc_table.add_column("Total", justify="right")
        acc_table.add_column("Correct", justify="right")
        acc_table.add_column("Rate", justify="right")

        # True positives
        phishing_emails = [i for i, e in enumerate(emails) if e["label"] == "phishing"]
        tp = sum(1 for i in phishing_emails if results[i]["is_phishing"])
        acc_table.add_row("Phishing caught", str(len(phishing_emails)), str(tp),
                          f"[green]{tp / len(phishing_emails) * 100:.0f}%[/green]")

        # False positives
        legit_emails = [i for i, e in enumerate(emails) if e["label"] == "legitimate"]
        fp = sum(1 for i in legit_emails if results[i]["is_phishing"])
        fp_rate = fp / len(legit_emails) * 100 if legit_emails else 0
        fp_color = "red" if fp_rate > 10 else "green"
        acc_table.add_row("False positives", str(len(legit_emails)), str(fp),
                          f"[{fp_color}]{fp_rate:.0f}%[/{fp_color}]")

        console.print(acc_table)

    # Detailed results table
    console.print("\n[bold]Detailed Results:[/bold]")
    detail_table = Table(show_header=True, header_style="bold magenta")
    detail_table.add_column("Score", justify="right")
    detail_table.add_column("Verdict")
    detail_table.add_column("Severity")
    detail_table.add_column("Subject")
    detail_table.add_column("Sender")
    detail_table.add_column("Indicators", justify="right")
    detail_table.add_column("Actual")

    for i, r in enumerate(results):
        score = r["phishing_score"]
        is_phish = r["is_phishing"]
        sev = r.get("severity") or "-"
        actual = emails[i].get("label", "?")

        verdict_color = "red" if is_phish else "green"
        verdict = f"[{verdict_color}]{'PHISHING' if is_phish else 'CLEAN'}[/{verdict_color}]"

        sev_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(sev, "dim")
        sev_display = f"[{sev_color}]{sev.upper()}[/{sev_color}]" if sev != "-" else "[dim]-[/dim]"

        # Check if detection matches actual label
        correct = (is_phish and actual == "phishing") or (not is_phish and actual == "legitimate")
        actual_display = f"[green]{actual}[/green]" if correct else f"[red]{actual}[/red]"

        detail_table.add_row(
            f"{score:.1f}",
            verdict,
            sev_display,
            r["details"]["subject"][:45],
            r["details"]["sender_email"][:35],
            str(r["details"]["indicator_count"]),
            actual_display,
        )

    console.print(detail_table)

    # Show top indicators for flagged emails
    console.print("\n[bold]Top Phishing Indicators Found:[/bold]")
    for r in sorted(phishing_detected, key=lambda x: x["phishing_score"], reverse=True):
        indicators = r["details"].get("indicators", [])
        if indicators:
            console.print(f"\n  [bold]{r['details']['subject'][:50]}[/bold] (score: {r['phishing_score']})")
            for ind in indicators[:4]:
                console.print(f"    [red]•[/red] {ind}")

    await detector.stop()
    console.print("\n[bold green]Phishing demo complete.[/bold green]")


if __name__ == "__main__":
    main()
