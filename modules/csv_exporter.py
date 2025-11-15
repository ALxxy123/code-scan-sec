"""
CSV Export Module for Security Scan CLI
Export scan results to CSV format for analysis in spreadsheet applications
"""

import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from .data_models import ScanResult, SecretFinding, VulnerabilityFinding


class CSVExporter:
    """
    CSV export functionality for security scan results.

    Exports:
    - Secrets to CSV
    - Vulnerabilities to CSV
    - Statistics summary to CSV
    - Combined findings report
    """

    def __init__(self, output_dir: Path = Path("output")):
        """
        Initialize CSV exporter.

        Args:
            output_dir: Directory to save CSV files
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_complete_report(self, scan_result: ScanResult, base_filename: str = None) -> Dict[str, Path]:
        """
        Export a complete scan report to multiple CSV files.

        Args:
            scan_result: The scan result to export
            base_filename: Base filename (without extension)

        Returns:
            Dictionary mapping file types to paths
        """
        if base_filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"security_scan_{timestamp}"

        exported_files = {}

        # Export secrets
        if scan_result.secrets:
            secrets_path = self.export_secrets(
                scan_result.secrets,
                f"{base_filename}_secrets.csv"
            )
            exported_files['secrets'] = secrets_path

        # Export vulnerabilities
        if scan_result.vulnerabilities:
            vulns_path = self.export_vulnerabilities(
                scan_result.vulnerabilities,
                f"{base_filename}_vulnerabilities.csv"
            )
            exported_files['vulnerabilities'] = vulns_path

        # Export statistics
        stats_path = self.export_statistics(
            scan_result,
            f"{base_filename}_statistics.csv"
        )
        exported_files['statistics'] = stats_path

        # Export combined findings
        combined_path = self.export_combined_findings(
            scan_result,
            f"{base_filename}_all_findings.csv"
        )
        exported_files['combined'] = combined_path

        return exported_files

    def export_secrets(self, secrets: List[SecretFinding], filename: str) -> Path:
        """
        Export secrets to CSV.

        Args:
            secrets: List of secret findings
            filename: Output filename

        Returns:
            Path to the created CSV file
        """
        output_path = self.output_dir / filename

        fieldnames = [
            'File Path',
            'Line Number',
            'Rule Name',
            'Matched Text',
            'Entropy',
            'Severity',
            'Confidence',
            'AI Verified',
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for secret in secrets:
                writer.writerow({
                    'File Path': secret.file_path,
                    'Line Number': secret.line_number,
                    'Rule Name': secret.rule_name,
                    'Matched Text': secret.matched_text[:100],  # Truncate for safety
                    'Entropy': f"{secret.entropy:.2f}" if secret.entropy else "N/A",
                    'Severity': secret.severity,
                    'Confidence': f"{secret.confidence:.0%}",
                    'AI Verified': self._format_ai_verified(secret.ai_verified),
                })

        return output_path

    def export_vulnerabilities(self, vulnerabilities: List[VulnerabilityFinding], filename: str) -> Path:
        """
        Export vulnerabilities to CSV.

        Args:
            vulnerabilities: List of vulnerability findings
            filename: Output filename

        Returns:
            Path to the created CSV file
        """
        output_path = self.output_dir / filename

        fieldnames = [
            'Vulnerability Name',
            'File Path',
            'Line Number',
            'Severity',
            'Category',
            'CWE',
            'OWASP',
            'Description',
            'Recommendation',
            'Confidence',
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for vuln in vulnerabilities:
                writer.writerow({
                    'Vulnerability Name': vuln.name,
                    'File Path': vuln.file_path,
                    'Line Number': vuln.line_number,
                    'Severity': vuln.severity,
                    'Category': vuln.category,
                    'CWE': vuln.cwe or "N/A",
                    'OWASP': vuln.owasp or "N/A",
                    'Description': vuln.description,
                    'Recommendation': vuln.recommendation,
                    'Confidence': f"{vuln.confidence:.0%}",
                })

        return output_path

    def export_statistics(self, scan_result: ScanResult, filename: str) -> Path:
        """
        Export scan statistics to CSV.

        Args:
            scan_result: The scan result with statistics
            filename: Output filename

        Returns:
            Path to the created CSV file
        """
        output_path = self.output_dir / filename
        stats = scan_result.statistics

        # Create key-value pairs for statistics
        statistics_data = [
            ('Metric', 'Value'),
            ('Scan ID', scan_result.scan_id),
            ('Scan Type', scan_result.scan_type),
            ('Target', scan_result.target),
            ('Scan Date', scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')),
            ('Scanner Version', scan_result.scanner_version),
            ('', ''),  # Empty row for separation
            ('Files Scanned', stats.total_files_scanned),
            ('Lines Scanned', stats.total_lines_scanned),
            ('Secrets Found', stats.secrets_found),
            ('Vulnerabilities Found', stats.vulnerabilities_found),
            ('False Positives Filtered', stats.false_positives_filtered),
            ('', ''),
            ('Critical Findings', stats.critical_count),
            ('High Severity', stats.high_count),
            ('Medium Severity', stats.medium_count),
            ('Low Severity', stats.low_count),
            ('Info Findings', stats.info_count),
            ('', ''),
            ('Scan Duration (seconds)', f"{stats.scan_duration:.2f}"),
            ('Files per Second', f"{stats.files_per_second:.2f}"),
            ('Risk Score (0-100)', f"{stats.risk_score:.1f}"),
            ('Security Grade', stats.security_grade),
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerows(statistics_data)

        return output_path

    def export_combined_findings(self, scan_result: ScanResult, filename: str) -> Path:
        """
        Export all findings (secrets + vulnerabilities) to a single CSV.

        Args:
            scan_result: The scan result
            filename: Output filename

        Returns:
            Path to the created CSV file
        """
        output_path = self.output_dir / filename

        fieldnames = [
            'Type',
            'Name/Rule',
            'File Path',
            'Line Number',
            'Severity',
            'Category',
            'Description',
            'Confidence',
        ]

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Add secrets
            for secret in scan_result.secrets:
                writer.writerow({
                    'Type': 'Secret',
                    'Name/Rule': secret.rule_name,
                    'File Path': secret.file_path,
                    'Line Number': secret.line_number,
                    'Severity': secret.severity,
                    'Category': 'Hardcoded Secret',
                    'Description': f"Potential secret detected (Entropy: {secret.entropy:.2f})" if secret.entropy else "Potential secret detected",
                    'Confidence': f"{secret.confidence:.0%}",
                })

            # Add vulnerabilities
            for vuln in scan_result.vulnerabilities:
                writer.writerow({
                    'Type': 'Vulnerability',
                    'Name/Rule': vuln.name,
                    'File Path': vuln.file_path,
                    'Line Number': vuln.line_number,
                    'Severity': vuln.severity,
                    'Category': vuln.category,
                    'Description': vuln.description[:200],  # Truncate long descriptions
                    'Confidence': f"{vuln.confidence:.0%}",
                })

        return output_path

    def export_benchmark_results(self, benchmark_results: List[Dict[str, Any]], filename: str = "benchmark_results.csv") -> Path:
        """
        Export benchmark results to CSV.

        Args:
            benchmark_results: List of benchmark result dictionaries
            filename: Output filename

        Returns:
            Path to the created CSV file
        """
        output_path = self.output_dir / filename

        if not benchmark_results:
            # Create empty file with headers
            fieldnames = [
                'Timestamp', 'Scan Type', 'Target', 'Duration (s)',
                'Files Scanned', 'Lines Scanned', 'Findings',
                'Files/Second', 'Lines/Second', 'Peak Memory (MB)',
                'Avg CPU %', 'Network Latency (ms)'
            ]
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
            return output_path

        # Get fieldnames from first result
        fieldnames = list(benchmark_results[0].keys())

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in benchmark_results:
                writer.writerow(result)

        return output_path

    def _format_ai_verified(self, ai_verified: bool = None) -> str:
        """Format AI verification status for CSV"""
        if ai_verified is None:
            return "Not Checked"
        return "Real Secret" if ai_verified else "False Positive"
