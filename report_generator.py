"""
Report Generation Module.

This module handles generating various report formats (HTML, Markdown, JSON, Text)
for security scan results and vulnerability findings.
"""

from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime
import json
import webbrowser
import subprocess
import os
from logger import get_logger
from vulnerability_scanner import Vulnerability

logger = get_logger()


class PathJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles Path objects."""

    def default(self, obj):
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


class ReportGenerator:
    """
    Generates security scan reports in multiple formats.

    Supports HTML, Markdown, JSON, and plain text report generation.
    """

    def __init__(self, output_dir: str = "output"):
        """
        Initialize report generator.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        logger.info(f"Report output directory: {self.output_dir}")

    def write_text_report(
        self,
        findings: List[Dict],
        vulnerabilities: Optional[List[Vulnerability]] = None
    ) -> Path:
        """
        Generate plain text report.

        Args:
            findings: List of secret/credential findings
            vulnerabilities: Optional list of vulnerability findings

        Returns:
            Path: Path to generated report
        """
        report_path = self.output_dir / "results.txt"
        logger.info(f"Generating text report: {report_path}")

        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("="* 70 + "\n")
                f.write("   AI-POWERED SECURITY SCAN REPORT\n")
                f.write("="* 70 + "\n\n")

                # Secret findings section
                if findings:
                    f.write(f"SECRETS & CREDENTIALS DETECTED: {len(findings)}\n")
                    f.write("-" * 70 + "\n\n")
                    for i, finding in enumerate(findings, 1):
                        f.write(f"Finding #{i}:\n")
                        f.write(f"  File:     {finding['file']}:{finding['line']}\n")
                        f.write(f"  Rule:     {finding['rule']}\n")
                        f.write(f"  Match:    {finding['match']}\n")
                        if 'ai_verified' in finding:
                            f.write(f"  AI Verified: {finding['ai_verified']}\n")
                        f.write("-" * 70 + "\n")

                # Vulnerability findings section
                if vulnerabilities:
                    f.write(f"\n\nVULNERABILITIES DETECTED: {len(vulnerabilities)}\n")
                    f.write("=" * 70 + "\n\n")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        f.write(f"Vulnerability #{i}:\n")
                        f.write(f"  Name:          {vuln.name}\n")
                        f.write(f"  Severity:      {vuln.severity.upper()}\n")
                        f.write(f"  Category:      {vuln.category}\n")
                        f.write(f"  CWE:           {vuln.cwe}\n")
                        f.write(f"  OWASP:         {vuln.owasp}\n")
                        f.write(f"  File:          {vuln.file_path}:{vuln.line_number}\n")
                        f.write(f"  Match:         {vuln.matched_text}\n")
                        f.write(f"  Description:   {vuln.description}\n")
                        f.write(f"  Recommendation: {vuln.recommendation}\n")
                        f.write("-" * 70 + "\n")

                f.write(f"\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

            logger.info("Text report generated successfully")
            return report_path

        except Exception as e:
            logger.error(f"Failed to generate text report: {e}")
            raise

    def write_json_report(
        self,
        findings: List[Dict],
        vulnerabilities: Optional[List[Vulnerability]] = None,
        stats: Optional[Dict] = None
    ) -> Path:
        """
        Generate JSON report.

        Args:
            findings: List of secret/credential findings
            vulnerabilities: Optional list of vulnerability findings
            stats: Optional statistics dictionary

        Returns:
            Path: Path to generated report
        """
        report_path = self.output_dir / "results.json"
        logger.info(f"Generating JSON report: {report_path}")

        try:
            report_data = {
                "scan_date": datetime.now().isoformat(),
                "summary": {
                    "total_secrets": len(findings),
                    "total_vulnerabilities": len(vulnerabilities) if vulnerabilities else 0
                },
                "secrets": findings,
                "vulnerabilities": [],
                "statistics": stats or {}
            }

            if vulnerabilities:
                report_data["vulnerabilities"] = [v.to_dict() for v in vulnerabilities]

            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, cls=PathJSONEncoder)

            logger.info("JSON report generated successfully")
            return report_path

        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise

    def write_md_report(
        self,
        findings: List[Dict],
        affected_files: int,
        vulnerabilities: Optional[List[Vulnerability]] = None,
        vuln_stats: Optional[Dict] = None
    ) -> Path:
        """
        Generate Markdown report.

        Args:
            findings: List of secret/credential findings
            affected_files: Number of affected files
            vulnerabilities: Optional list of vulnerability findings
            vuln_stats: Optional vulnerability statistics

        Returns:
            Path: Path to generated report
        """
        report_path = self.output_dir / "report.md"
        logger.info(f"Generating Markdown report: {report_path}")

        try:
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with open(report_path, "w", encoding="utf-8") as f:
                f.write("# 🛡️ Security Scan Report\n\n")

                # Summary Section
                f.write("## 📊 Summary\n\n")
                f.write(f"- **Total Secrets Found:** {len(findings)}\n")
                if vulnerabilities:
                    f.write(f"- **Total Vulnerabilities:** {len(vulnerabilities)}\n")
                    if vuln_stats:
                        f.write(f"- **Critical/High Severity:** {vuln_stats.get('critical_and_high', 0)}\n")
                f.write(f"- **Affected Files:** {affected_files}\n")
                f.write(f"- **Scan Date:** {scan_date}\n\n")

                # Vulnerability Statistics
                if vuln_stats and vuln_stats.get('by_severity'):
                    f.write("### Vulnerability Breakdown by Severity\n\n")
                    for severity, count in vuln_stats['by_severity'].items():
                        emoji = {
                            'critical': '🔴',
                            'high': '🟠',
                            'medium': '🟡',
                            'low': '🟢',
                            'info': '🔵'
                        }.get(severity, '⚪')
                        f.write(f"- {emoji} **{severity.upper()}**: {count}\n")
                    f.write("\n")

                f.write("---\n\n")

                # Secrets Section
                if findings:
                    f.write("## 🔐 Secrets & Credentials\n\n")
                    f.write("| File | Line | Rule | Match | AI Verified |\n")
                    f.write("|------|------|------|-------|-------------|\n")
                    for finding in findings:
                        ai_status = finding.get('ai_verified', 'N/A')
                        f.write(
                            f"| `{finding['file']}` | {finding['line']} | "
                            f"`{finding['rule']}` | `{finding['match']}` | {ai_status} |\n"
                        )
                    f.write("\n")

                # Vulnerabilities Section
                if vulnerabilities:
                    f.write("## 🐛 Security Vulnerabilities\n\n")
                    f.write("| Severity | Name | File | Line | CWE | OWASP |\n")
                    f.write("|----------|------|------|------|-----|-------|\n")
                    for vuln in vulnerabilities:
                        severity_emoji = {
                            'critical': '🔴 CRITICAL',
                            'high': '🟠 HIGH',
                            'medium': '🟡 MEDIUM',
                            'low': '🟢 LOW',
                            'info': '🔵 INFO'
                        }.get(vuln.severity.lower(), vuln.severity)
                        f.write(
                            f"| {severity_emoji} | {vuln.name} | "
                            f"`{vuln.file_path}` | {vuln.line_number} | "
                            f"{vuln.cwe} | {vuln.owasp} |\n"
                        )
                    f.write("\n")

                    # Detailed vulnerability descriptions
                    f.write("### Vulnerability Details\n\n")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        f.write(f"#### {i}. {vuln.name}\n\n")
                        f.write(f"- **Severity:** {vuln.severity.upper()}\n")
                        f.write(f"- **Category:** {vuln.category}\n")
                        f.write(f"- **Location:** `{vuln.file_path}:{vuln.line_number}`\n")
                        f.write(f"- **CWE:** {vuln.cwe}\n")
                        f.write(f"- **OWASP:** {vuln.owasp}\n\n")
                        f.write(f"**Description:**  \n{vuln.description}\n\n")
                        f.write(f"**Recommendation:**  \n{vuln.recommendation}\n\n")
                        f.write(f"**Matched Code:**\n```\n{vuln.matched_text}\n```\n\n")
                        f.write("---\n\n")

            logger.info("Markdown report generated successfully")
            return report_path

        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            raise

    def write_html_report(
        self,
        findings: List[Dict],
        affected_files: int,
        vulnerabilities: Optional[List[Vulnerability]] = None,
        vuln_stats: Optional[Dict] = None
    ) -> Path:
        """
        Generate HTML report with professional styling.

        Args:
            findings: List of secret/credential findings
            affected_files: Number of affected files
            vulnerabilities: Optional list of vulnerability findings
            vuln_stats: Optional vulnerability statistics

        Returns:
            Path: Path to generated report
        """
        report_path = self.output_dir / "report.html"
        logger.info(f"Generating HTML report: {report_path}")

        try:
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Build secrets table rows
            secrets_rows = ""
            for finding in findings:
                ai_status = finding.get('ai_verified', 'N/A')
                secrets_rows += (
                    f"<tr>"
                    f"<td><code>{finding['file']}</code></td>"
                    f"<td>{finding['line']}</td>"
                    f"<td><code>{finding['rule'][:50]}...</code></td>"
                    f"<td><code>{finding['match']}</code></td>"
                    f"<td>{ai_status}</td>"
                    f"</tr>\n"
                )

            # Build vulnerabilities table rows
            vuln_rows = ""
            if vulnerabilities:
                for vuln in vulnerabilities:
                    severity_class = vuln.severity.lower()
                    vuln_rows += (
                        f"<tr class='severity-{severity_class}'>"
                        f"<td><span class='badge badge-{severity_class}'>{vuln.severity.upper()}</span></td>"
                        f"<td>{vuln.name}</td>"
                        f"<td><code>{vuln.file_path}</code></td>"
                        f"<td>{vuln.line_number}</td>"
                        f"<td>{vuln.cwe}</td>"
                        f"<td>{vuln.owasp}</td>"
                        f"<td title='{vuln.description}'><code>{vuln.matched_text[:50]}...</code></td>"
                        f"</tr>\n"
                    )

            # Build statistics cards
            stats_html = ""
            if vuln_stats and vuln_stats.get('by_severity'):
                for severity, count in vuln_stats['by_severity'].items():
                    color = {
                        'critical': '#c0392b',
                        'high': '#e67e22',
                        'medium': '#f39c12',
                        'low': '#27ae60',
                        'info': '#3498db'
                    }.get(severity, '#95a5a6')
                    stats_html += f"""
                    <div class="stat-card" style="border-left-color: {color};">
                        <div class="stat-value" style="color: {color};">{count}</div>
                        <div class="stat-label">{severity.upper()}</div>
                    </div>
                    """

            html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2em;
            color: #333;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2em;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 0.3em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5em;
            padding: 2em;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }}
        .summary-item {{
            text-align: center;
            padding: 1.5em;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .summary-item .value {{
            font-size: 3em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 0.2em;
        }}
        .summary-item .label {{
            font-size: 0.95em;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1em;
            padding: 2em;
            background: white;
        }}
        .stat-card {{
            padding: 1.5em;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 0.85em;
            color: #6c757d;
            margin-top: 0.5em;
        }}
        .section {{
            padding: 2em;
        }}
        .section h2 {{
            font-size: 1.8em;
            color: #2c3e50;
            margin-bottom: 1em;
            padding-bottom: 0.5em;
            border-bottom: 3px solid #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1em;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        tbody tr:hover {{
            background: #f8f9fa;
        }}
        code {{
            background: #e9ecef;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }}
        .badge-critical {{ background: #c0392b; }}
        .badge-high {{ background: #e67e22; }}
        .badge-medium {{ background: #f39c12; }}
        .badge-low {{ background: #27ae60; }}
        .badge-info {{ background: #3498db; }}
        .footer {{
            text-align: center;
            padding: 1.5em;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.9em;
            border-top: 2px solid #e9ecef;
        }}
        .no-data {{
            text-align: center;
            padding: 3em;
            color: #6c757d;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Comprehensive Security Analysis Results</p>
        </div>

        <div class="summary">
            <div class="summary-item">
                <div class="value">{len(findings)}</div>
                <div class="label">Secrets Found</div>
            </div>
            <div class="summary-item">
                <div class="value">{len(vulnerabilities) if vulnerabilities else 0}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="summary-item">
                <div class="value">{vuln_stats.get('critical_and_high', 0) if vuln_stats else 0}</div>
                <div class="label">Critical/High</div>
            </div>
            <div class="summary-item">
                <div class="value">{affected_files}</div>
                <div class="label">Affected Files</div>
            </div>
        </div>

        {f'<div class="stats-grid">{stats_html}</div>' if stats_html else ''}

        <div class="section">
            <h2>🔐 Secrets & Credentials</h2>
            {f'''<table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Line</th>
                        <th>Rule</th>
                        <th>Match</th>
                        <th>AI Verified</th>
                    </tr>
                </thead>
                <tbody>
                    {secrets_rows}
                </tbody>
            </table>''' if findings else '<div class="no-data">✓ No secrets or credentials detected</div>'}
        </div>

        {f'''<div class="section">
            <h2>🐛 Security Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Name</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>CWE</th>
                        <th>OWASP</th>
                        <th>Match</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>''' if vulnerabilities else ''}

        <div class="footer">
            <p>Report generated on {scan_date}</p>
            <p>Powered by AI-Powered Security Scanner</p>
        </div>
    </div>
</body>
</html>
            """

            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html_template)

            logger.info("HTML report generated successfully")
            return report_path

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def open_in_browser(self, file_path: Path) -> bool:
        """
        Open report in default web browser.

        Args:
            file_path: Path to HTML file

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            url = f"file://{file_path.resolve()}"

            # Check if running in WSL
            if "WSL_DISTRO_NAME" in os.environ:
                windows_path = subprocess.check_output(
                    ["wslpath", "-w", str(file_path.resolve())]
                ).decode("utf-8").strip()
                subprocess.run(["explorer.exe", windows_path], check=True)
            else:
                webbrowser.open(url)

            logger.info(f"Opened report in browser: {file_path}")
            return True

        except Exception as e:
            logger.warning(f"Failed to open browser: {e}")
            logger.info(f"You can open the file manually at: {url}")
            return False
