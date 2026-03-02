#!/usr/bin/env python3
"""
Basic Usage Example for Security Scan CLI v4.0.0
Demonstrates how to use the new modular architecture programmatically
"""

from pathlib import Path
from modules import (
    LocalScanner,
    RulesEngine,
    PDFReportGenerator,
    CSVExporter,
    PerformanceMonitor,
    ScanType,
)


def main():
    """Example: Scan a local project and generate reports"""

    # 1. Initialize the rules engine
    print("🔧 Initializing rules engine...")
    rules_engine = RulesEngine()

    # 2. Create a local scanner
    print("🔍 Creating scanner...")
    scanner = LocalScanner(
        rules_engine=rules_engine,
        entropy_threshold=3.5,
        num_threads=4
    )

    # 3. Perform scan with performance monitoring
    print("📊 Scanning project...")
    target_path = "."

    with PerformanceMonitor() as monitor:
        # Run the scan
        result = scanner.scan(target_path, enable_ai=False)

        # Sample metrics
        monitor.sample()

        # Get benchmark results
        benchmark = monitor.get_result(
            scan_type=ScanType.LOCAL,
            target=target_path,
            files_scanned=result.statistics.total_files_scanned,
            lines_scanned=result.statistics.total_lines_scanned,
            findings_detected=len(result.secrets) + len(result.vulnerabilities)
        )

        result.benchmark = benchmark

    # 4. Display results
    print("\n" + "="*60)
    print("📋 SCAN RESULTS")
    print("="*60)
    print(f"Security Grade: {result.statistics.security_grade}")
    print(f"Risk Score: {result.statistics.risk_score:.1f}/100")
    print(f"Total Files Scanned: {result.statistics.total_files_scanned}")
    print(f"Total Lines Scanned: {result.statistics.total_lines_scanned:,}")
    print(f"\nFindings:")
    print(f"  - Critical: {result.statistics.critical_count}")
    print(f"  - High: {result.statistics.high_count}")
    print(f"  - Medium: {result.statistics.medium_count}")
    print(f"  - Low: {result.statistics.low_count}")
    print(f"\nSecrets Found: {len(result.secrets)}")
    print(f"Vulnerabilities Found: {len(result.vulnerabilities)}")

    # 5. Generate PDF report
    print("\n📄 Generating PDF report...")
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    pdf_generator = PDFReportGenerator(output_dir)
    pdf_path = pdf_generator.generate_report(result)
    print(f"✅ PDF report saved to: {pdf_path}")

    # 6. Export to CSV
    print("\n📊 Exporting to CSV...")
    csv_exporter = CSVExporter(output_dir)
    csv_files = csv_exporter.export_complete_report(result)

    print("✅ CSV files generated:")
    for file_type, path in csv_files.items():
        print(f"   - {file_type}: {path}")

    # 7. Performance metrics
    if benchmark:
        print("\n⚡ PERFORMANCE METRICS")
        print("="*60)
        print(f"Duration: {benchmark.duration_seconds:.2f} seconds")
        print(f"Files/sec: {benchmark.files_per_second:.2f}")
        print(f"Lines/sec: {benchmark.lines_per_second:.0f}")
        print(f"Peak Memory: {benchmark.peak_memory_mb:.1f} MB")
        print(f"Avg CPU: {benchmark.avg_cpu_percent:.1f}%")

    print("\n✅ Scan complete!")


if __name__ == "__main__":
    main()
