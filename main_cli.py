#!/usr/bin/env python3
"""
Security Scan CLI - Professional Security Analysis Suite
Version 4.0.0

Modern, professional security scanning tool for developers.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from pathlib import Path
from typing import Optional
import sys

from modules import (
    LocalScanner,
    URLScannerEnhanced,
    BlackBoxScanner,
    BenchmarkEngine,
    PerformanceMonitor,
    PDFReportGenerator,
    CSVExporter,
    UpdateChecker,
    RulesEngine,
    PluginManager,
    ScanType,
)

app = typer.Typer(
    name="security-scan",
    help="Professional Security Analysis Suite - Secure your code, protect your apps",
    add_completion=False
)

console = Console()

# Version
VERSION = "4.0.0"


def print_banner():
    """Print professional banner"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          SECURITY SCAN CLI - Version {VERSION}                    ║
║                                                                  ║
║          Professional Security Analysis Suite                    ║
║          Secure your code, protect your applications             ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")


@app.command()
def scan_local(
    path: str = typer.Argument(..., help="Path to scan (file or directory)"),
    output: Optional[str] = typer.Option("output", "--output", "-o", help="Output directory for reports"),
    format: str = typer.Option("all", "--format", "-f", help="Report format: pdf, csv, json, html, all"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI verification"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    Scan local project for security issues.

    Detects:
    - Hardcoded secrets (API keys, passwords, tokens)
    - Security vulnerabilities (SQLi, XSS, etc.)
    - Insecure configurations
    - Dangerous code patterns
    """
    if not quiet:
        print_banner()

    console.print(f"\n🔍 [bold]Scanning:[/bold] {path}\n")

    try:
        # Initialize components
        rules_engine = RulesEngine()
        local_scanner = LocalScanner(rules_engine)

        # Scan with performance monitoring
        with PerformanceMonitor() as monitor:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Scanning files...", total=None)

                result = local_scanner.scan(path, enable_ai=not no_ai)

                progress.update(task, description="✓ Scan complete!")

            # Sample final metrics
            monitor.sample()

            # Get benchmark results
            benchmark = monitor.get_result(
                scan_type=ScanType.LOCAL,
                target=path,
                files_scanned=result.statistics.total_files_scanned,
                lines_scanned=result.statistics.total_lines_scanned,
                findings_detected=len(result.secrets) + len(result.vulnerabilities)
            )

            result.benchmark = benchmark

        # Display results
        _display_scan_results(result, quiet)

        # Generate reports
        _generate_reports(result, Path(output), format)

        # Exit code based on severity
        if result.statistics.critical_count > 0:
            sys.exit(1)

    except Exception as e:
        console.print(f"\n❌ [bold red]Error:[/bold red] {str(e)}\n")
        sys.exit(1)


@app.command()
def scan_url(
    url: str = typer.Argument(..., help="URL to scan"),
    output: Optional[str] = typer.Option("output", "--output", "-o", help="Output directory for reports"),
    format: str = typer.Option("all", "--format", "-f", help="Report format: pdf, csv, json, html, all"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    Scan remote URL or repository.

    Performs:
    - Security headers analysis
    - Server configuration check
    - SSL/TLS validation
    - robots.txt analysis
    - Common path exposure check
    """
    if not quiet:
        print_banner()

    console.print(f"\n🌐 [bold]Scanning URL:[/bold] {url}\n")

    try:
        # Initialize components
        rules_engine = RulesEngine()
        url_scanner = URLScannerEnhanced()
        local_scanner = LocalScanner(rules_engine)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing URL...", total=None)

            result = url_scanner.scan(url, local_scanner)

            progress.update(task, description="✓ Analysis complete!")

        # Display results
        _display_scan_results(result, quiet)

        # Generate reports
        _generate_reports(result, Path(output), format)

    except Exception as e:
        console.print(f"\n❌ [bold red]Error:[/bold red] {str(e)}\n")
        sys.exit(1)


@app.command()
def scan_blackbox(
    url: str = typer.Argument(..., help="URL to test"),
    output: Optional[str] = typer.Option("output", "--output", "-o", help="Output directory for reports"),
    format: str = typer.Option("all", "--format", "-f", help="Report format: pdf, csv, json, html, all"),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Request timeout in seconds"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    Black-box security testing (safe, passive checks only).

    Tests:
    - Security headers
    - Cookie security
    - SSL/TLS configuration
    - Common misconfigurations
    - Information disclosure
    """
    if not quiet:
        print_banner()

    console.print(f"\n🛡️  [bold]Black-box testing:[/bold] {url}\n")
    console.print("[yellow]Note: Only safe, passive checks are performed[/yellow]\n")

    try:
        blackbox_scanner = BlackBoxScanner(timeout=timeout)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running security tests...", total=None)

            result = blackbox_scanner.scan(url)

            progress.update(task, description="✓ Testing complete!")

        # Display results
        _display_scan_results(result, quiet)

        # Generate reports
        _generate_reports(result, Path(output), format)

    except Exception as e:
        console.print(f"\n❌ [bold red]Error:[/bold red] {str(e)}\n")
        sys.exit(1)


@app.command()
def benchmark(
    target: str = typer.Argument(..., help="Path or URL to benchmark"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Benchmark name"),
):
    """
    Run performance benchmark.

    Measures:
    - Scan duration
    - Files/lines processed per second
    - Memory usage
    - CPU utilization
    """
    print_banner()

    console.print(f"\n⚡ [bold]Benchmarking:[/bold] {target}\n")

    try:
        rules_engine = RulesEngine()
        local_scanner = LocalScanner(rules_engine)

        with PerformanceMonitor() as monitor:
            result = local_scanner.scan(target)
            monitor.sample()

            benchmark_result = monitor.get_result(
                scan_type=ScanType.LOCAL,
                target=target,
                files_scanned=result.statistics.total_files_scanned,
                lines_scanned=result.statistics.total_lines_scanned,
                findings_detected=len(result.secrets) + len(result.vulnerabilities)
            )

        # Display benchmark summary
        engine = BenchmarkEngine()
        summary = engine.get_summary(benchmark_result)
        console.print(summary)

    except Exception as e:
        console.print(f"\n❌ [bold red]Error:[/bold red] {str(e)}\n")
        sys.exit(1)


@app.command()
def check_update():
    """Check for updates to Security Scan CLI"""
    print_banner()

    console.print("\n🔄 [bold]Checking for updates...[/bold]\n")

    checker = UpdateChecker(current_version=VERSION)
    checker.check_and_notify(silent=False)


@app.command()
def version():
    """Display version information"""
    info = f"""
╔══════════════════════════════════════════════════════════════╗
║  Security Scan CLI                                           ║
║  Version: {VERSION}                                             ║
║                                                              ║
║  Professional security analysis for modern applications      ║
║  MIT License                                                 ║
╚══════════════════════════════════════════════════════════════╝
"""
    console.print(info, style="bold cyan")


@app.command()
def menu():
    """
    Interactive menu (main interface)
    """
    print_banner()

    while True:
        console.print("\n")
        table = Table(title="Available Commands", show_header=True, header_style="bold cyan")
        table.add_column("Command", style="green", width=25)
        table.add_column("Description", width=50)

        table.add_row("scan-local <path>", "Scan local project for secrets & vulnerabilities")
        table.add_row("scan-url <url>", "Scan remote URL or repository")
        table.add_row("scan-blackbox <url>", "Black-box security testing")
        table.add_row("benchmark <target>", "Run performance benchmark")
        table.add_row("check-update", "Check for updates")
        table.add_row("version", "Show version information")
        table.add_row("exit", "Exit program")

        console.print(table)

        choice = console.input("\n[bold cyan]Select command or type 'exit' to quit:[/bold cyan] ").strip()

        if choice.lower() == 'exit':
            console.print("\n[green]Goodbye! Stay secure! 🔒[/green]\n")
            break
        elif choice:
            console.print(f"\n[yellow]Tip: Run 'security-scan {choice}' directly from command line[/yellow]")
            console.print("[yellow]Interactive execution coming in next version![/yellow]\n")


def _display_scan_results(result, quiet: bool = False):
    """Display scan results in a formatted table"""
    if quiet:
        console.print(f"\n{result.get_summary()}\n")
        return

    # Summary panel
    summary_text = f"""
[bold]Scan ID:[/bold] {result.scan_id}
[bold]Target:[/bold] {result.target}
[bold]Scan Type:[/bold] {result.scan_type.value.upper()}
[bold]Duration:[/bold] {result.statistics.scan_duration:.2f}s

[bold]Security Grade:[/bold] [{_get_grade_color(result.statistics.security_grade)}]{result.statistics.security_grade}[/]
[bold]Risk Score:[/bold] {result.statistics.risk_score:.1f}/100
"""

    console.print(Panel(summary_text, title="📊 Scan Summary", border_style="cyan"))

    # Findings table
    findings_table = Table(title="Findings by Severity", show_header=True)
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Count", justify="right")

    severity_data = [
        ("Critical", result.statistics.critical_count, "red"),
        ("High", result.statistics.high_count, "orange1"),
        ("Medium", result.statistics.medium_count, "yellow"),
        ("Low", result.statistics.low_count, "blue"),
        ("Info", result.statistics.info_count, "cyan"),
    ]

    for severity, count, color in severity_data:
        findings_table.add_row(
            f"[{color}]{severity}[/{color}]",
            f"[{color}]{count}[/{color}]"
        )

    console.print("\n", findings_table)

    # Secrets summary
    if result.secrets:
        console.print(f"\n[red]⚠️  {len(result.secrets)} secrets detected![/red]")

    # Vulnerabilities summary
    if result.vulnerabilities:
        console.print(f"[orange1]⚠️  {len(result.vulnerabilities)} vulnerabilities found![/orange1]")

    # Security headers summary
    if result.security_headers:
        missing_headers = [h for h in result.security_headers if not h.present]
        if missing_headers:
            console.print(f"[yellow]⚠️  {len(missing_headers)} security headers missing[/yellow]")


def _generate_reports(result, output_dir: Path, format: str):
    """Generate reports in requested formats"""
    console.print(f"\n📝 [bold]Generating reports...[/bold]\n")

    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files = []

    try:
        # PDF Report
        if format in ["pdf", "all"]:
            pdf_gen = PDFReportGenerator(output_dir)
            pdf_path = pdf_gen.generate_report(result)
            generated_files.append(("PDF", pdf_path))
            console.print(f"✓ PDF report: [cyan]{pdf_path}[/cyan]")

        # CSV Export
        if format in ["csv", "all"]:
            csv_exp = CSVExporter(output_dir)
            csv_files = csv_exp.export_complete_report(result)
            for file_type, path in csv_files.items():
                generated_files.append((f"CSV ({file_type})", path))
                console.print(f"✓ CSV export ({file_type}): [cyan]{path}[/cyan]")

        # JSON Report
        if format in ["json", "all"]:
            import json
            json_path = output_dir / f"{result.scan_id}.json"
            with open(json_path, 'w') as f:
                json.dump(result.dict(), f, indent=2, default=str)
            generated_files.append(("JSON", json_path))
            console.print(f"✓ JSON report: [cyan]{json_path}[/cyan]")

        console.print(f"\n[green]✓ {len(generated_files)} report(s) generated successfully![/green]\n")

    except Exception as e:
        console.print(f"\n[red]❌ Error generating reports: {str(e)}[/red]\n")


def _get_grade_color(grade: str) -> str:
    """Get color for security grade"""
    colors = {
        "A+": "green",
        "A": "green",
        "B": "yellow",
        "C": "orange1",
        "D": "red",
        "F": "red bold",
    }
    return colors.get(grade, "white")


def main():
    """Main entry point"""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Scan interrupted by user[/yellow]\n")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]❌ Fatal error: {str(e)}[/red]\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
