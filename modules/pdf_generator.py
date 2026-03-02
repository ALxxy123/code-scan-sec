"""
PDF Report Generator for Security Scan CLI
Professional PDF reports using ReportLab
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import hashlib

from .data_models import ScanResult, SeverityLevel


class PDFReportGenerator:
    """
    Professional PDF report generator for security scan results.

    Features:
    - Title page with branding
    - Executive summary
    - Detailed findings with severity color coding
    - Statistics and charts
    - Recommendations
    - Metadata and versioning
    """

    def __init__(self, output_dir: Path = Path("output")):
        """
        Initialize PDF generator.

        Args:
            output_dir: Directory to save PDF reports
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Color scheme for severity levels
        self.severity_colors = {
            SeverityLevel.CRITICAL: colors.HexColor("#DC143C"),  # Crimson
            SeverityLevel.HIGH: colors.HexColor("#FF6347"),      # Tomato
            SeverityLevel.MEDIUM: colors.HexColor("#FFA500"),    # Orange
            SeverityLevel.LOW: colors.HexColor("#FFD700"),       # Gold
            SeverityLevel.INFO: colors.HexColor("#4682B4"),      # SteelBlue
        }

        # Styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor("#1F4788"),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))

        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor("#2C5AA0"),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))

        # Section heading
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor("#333333"),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))

        # Finding style
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            fontName='Helvetica'
        ))

    def generate_report(self, scan_result: ScanResult, filename: Optional[str] = None) -> Path:
        """
        Generate a comprehensive PDF report.

        Args:
            scan_result: The scan result data
            filename: Optional custom filename

        Returns:
            Path to the generated PDF file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_scan_report_{timestamp}.pdf"

        output_path = self.output_dir / filename

        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Build content
        story = []

        # Add title page
        story.extend(self._create_title_page(scan_result))
        story.append(PageBreak())

        # Add executive summary
        story.extend(self._create_executive_summary(scan_result))
        story.append(Spacer(1, 0.2 * inch))

        # Add statistics section
        story.extend(self._create_statistics_section(scan_result))
        story.append(Spacer(1, 0.2 * inch))

        # Add findings sections
        if scan_result.secrets:
            story.extend(self._create_secrets_section(scan_result.secrets))
            story.append(Spacer(1, 0.2 * inch))

        if scan_result.vulnerabilities:
            story.extend(self._create_vulnerabilities_section(scan_result.vulnerabilities))
            story.append(Spacer(1, 0.2 * inch))

        if scan_result.security_headers:
            story.extend(self._create_headers_section(scan_result.security_headers))
            story.append(Spacer(1, 0.2 * inch))

        # Add recommendations
        story.extend(self._create_recommendations_section(scan_result))
        story.append(PageBreak())

        # Add metadata
        story.extend(self._create_metadata_section(scan_result, output_path))

        # Build PDF
        doc.build(story)

        return output_path

    def _create_title_page(self, scan_result: ScanResult) -> List:
        """Create the title page"""
        elements = []

        # Spacer to center content
        elements.append(Spacer(1, 2 * inch))

        # Main title
        title = Paragraph(
            "<b>Security Scan Report</b>",
            self.styles['CustomTitle']
        )
        elements.append(title)
        elements.append(Spacer(1, 0.3 * inch))

        # Subtitle with scan type
        subtitle = Paragraph(
            f"<b>{scan_result.scan_type.upper()} Security Analysis</b>",
            self.styles['CustomSubtitle']
        )
        elements.append(subtitle)
        elements.append(Spacer(1, 0.5 * inch))

        # Target information
        target_text = f"<b>Target:</b> {scan_result.target}"
        elements.append(Paragraph(target_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.1 * inch))

        # Scan date
        date_text = f"<b>Scan Date:</b> {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        elements.append(Paragraph(date_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.1 * inch))

        # Scanner version
        version_text = f"<b>Scanner Version:</b> {scan_result.scanner_version}"
        elements.append(Paragraph(version_text, self.styles['Normal']))
        elements.append(Spacer(1, 1 * inch))

        # Security grade (large and prominent)
        grade = scan_result.statistics.security_grade
        grade_color = self._get_grade_color(grade)
        grade_text = f"<font size=48 color='{grade_color}'><b>{grade}</b></font>"
        elements.append(Paragraph(grade_text, self.styles['CustomTitle']))

        risk_score_text = f"<b>Risk Score: {scan_result.statistics.risk_score:.1f}/100</b>"
        elements.append(Paragraph(risk_score_text, self.styles['Normal']))

        return elements

    def _create_executive_summary(self, scan_result: ScanResult) -> List:
        """Create executive summary section"""
        elements = []

        elements.append(Paragraph("<b>Executive Summary</b>", self.styles['SectionHeading']))

        stats = scan_result.statistics
        total_findings = len(scan_result.secrets) + len(scan_result.vulnerabilities)

        summary_data = [
            ["Metric", "Value"],
            ["Total Findings", str(total_findings)],
            ["Critical Issues", str(stats.critical_count)],
            ["High Severity", str(stats.high_count)],
            ["Medium Severity", str(stats.medium_count)],
            ["Low Severity", str(stats.low_count)],
            ["Files Scanned", str(stats.total_files_scanned)],
            ["Lines Scanned", f"{stats.total_lines_scanned:,}"],
            ["Scan Duration", f"{stats.scan_duration:.2f}s"],
        ]

        table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1F4788")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))

        elements.append(table)

        return elements

    def _create_statistics_section(self, scan_result: ScanResult) -> List:
        """Create statistics section with severity breakdown"""
        elements = []

        elements.append(Paragraph("<b>Findings by Severity</b>", self.styles['SectionHeading']))

        stats = scan_result.statistics

        severity_data = [
            ["Severity", "Count", "Status"],
        ]

        severities = [
            ("Critical", stats.critical_count, SeverityLevel.CRITICAL),
            ("High", stats.high_count, SeverityLevel.HIGH),
            ("Medium", stats.medium_count, SeverityLevel.MEDIUM),
            ("Low", stats.low_count, SeverityLevel.LOW),
            ("Info", stats.info_count, SeverityLevel.INFO),
        ]

        for name, count, level in severities:
            severity_data.append([name, str(count), "⚠" if count > 0 else "✓"])

        table = Table(severity_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])

        # Create table style with severity colors
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1F4788")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]

        # Add row colors based on severity
        for i, (name, count, level) in enumerate(severities, start=1):
            if count > 0:
                table_style.append(('BACKGROUND', (0, i), (-1, i), self.severity_colors[level]))
                table_style.append(('TEXTCOLOR', (0, i), (-1, i), colors.white))

        table.setStyle(TableStyle(table_style))
        elements.append(table)

        return elements

    def _create_secrets_section(self, secrets: List) -> List:
        """Create secrets findings section"""
        elements = []

        elements.append(Paragraph(
            f"<b>Secret Findings ({len(secrets)})</b>",
            self.styles['SectionHeading']
        ))

        for i, secret in enumerate(secrets[:50], 1):  # Limit to first 50
            finding_text = (
                f"<b>{i}. {secret.rule_name}</b><br/>"
                f"<b>File:</b> {secret.file_path}:{secret.line_number}<br/>"
                f"<b>Severity:</b> {secret.severity}<br/>"
                f"<b>Confidence:</b> {secret.confidence:.0%}<br/>"
            )

            if secret.ai_verified is not None:
                status = "✓ Verified Real Secret" if secret.ai_verified else "✗ Likely False Positive"
                finding_text += f"<b>AI Verification:</b> {status}<br/>"

            elements.append(Paragraph(finding_text, self.styles['Finding']))
            elements.append(Spacer(1, 0.1 * inch))

        if len(secrets) > 50:
            elements.append(Paragraph(
                f"<i>... and {len(secrets) - 50} more secrets (see JSON report for complete list)</i>",
                self.styles['Finding']
            ))

        return elements

    def _create_vulnerabilities_section(self, vulnerabilities: List) -> List:
        """Create vulnerabilities section"""
        elements = []

        elements.append(Paragraph(
            f"<b>Vulnerability Findings ({len(vulnerabilities)})</b>",
            self.styles['SectionHeading']
        ))

        for i, vuln in enumerate(vulnerabilities[:50], 1):  # Limit to first 50
            finding_text = (
                f"<b>{i}. {vuln.name}</b><br/>"
                f"<b>File:</b> {vuln.file_path}:{vuln.line_number}<br/>"
                f"<b>Severity:</b> {vuln.severity} | "
                f"<b>Category:</b> {vuln.category}<br/>"
            )

            if vuln.cwe:
                finding_text += f"<b>CWE:</b> {vuln.cwe} | "
            if vuln.owasp:
                finding_text += f"<b>OWASP:</b> {vuln.owasp}<br/>"
            else:
                finding_text += "<br/>"

            finding_text += f"<b>Description:</b> {vuln.description}<br/>"
            finding_text += f"<b>Recommendation:</b> {vuln.recommendation}<br/>"

            elements.append(Paragraph(finding_text, self.styles['Finding']))
            elements.append(Spacer(1, 0.15 * inch))

        if len(vulnerabilities) > 50:
            elements.append(Paragraph(
                f"<i>... and {len(vulnerabilities) - 50} more vulnerabilities (see JSON report for complete list)</i>",
                self.styles['Finding']
            ))

        return elements

    def _create_headers_section(self, headers: List) -> List:
        """Create security headers section"""
        elements = []

        elements.append(Paragraph(
            f"<b>Security Headers Analysis ({len(headers)})</b>",
            self.styles['SectionHeading']
        ))

        header_data = [["Header", "Present", "Recommendation"]]

        for header in headers:
            status = "✓" if header.present else "✗"
            header_data.append([
                header.header_name,
                status,
                header.recommendation[:50] + "..." if len(header.recommendation) > 50 else header.recommendation
            ])

        table = Table(header_data, colWidths=[2 * inch, 1 * inch, 3 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1F4788")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))

        elements.append(table)

        return elements

    def _create_recommendations_section(self, scan_result: ScanResult) -> List:
        """Create recommendations section"""
        elements = []

        elements.append(Paragraph("<b>Recommendations</b>", self.styles['SectionHeading']))

        recommendations = []

        # Generate recommendations based on findings
        stats = scan_result.statistics

        if stats.critical_count > 0:
            recommendations.append(
                "🔴 <b>CRITICAL:</b> Address all critical severity issues immediately. "
                "These represent severe security risks that could lead to system compromise."
            )

        if stats.high_count > 0:
            recommendations.append(
                "🟠 <b>HIGH PRIORITY:</b> Fix high severity vulnerabilities as soon as possible. "
                "These issues pose significant security risks."
            )

        if len(scan_result.secrets) > 0:
            recommendations.append(
                "🔑 <b>SECRETS MANAGEMENT:</b> Remove all hardcoded secrets and use environment "
                "variables or secret management systems (e.g., AWS Secrets Manager, HashiCorp Vault)."
            )

        if len(scan_result.vulnerabilities) > 0:
            recommendations.append(
                "🛡️ <b>VULNERABILITY REMEDIATION:</b> Review and fix all detected vulnerabilities "
                "following the specific recommendations provided for each finding."
            )

        if scan_result.statistics.security_grade in ["D", "F"]:
            recommendations.append(
                "⚠️ <b>OVERALL SECURITY:</b> Your application has significant security concerns. "
                "Consider a comprehensive security audit and implement a security development lifecycle."
            )

        recommendations.append(
            "✅ <b>CONTINUOUS MONITORING:</b> Integrate this scanner into your CI/CD pipeline "
            "to catch security issues early in the development process."
        )

        recommendations.append(
            "📚 <b>SECURITY TRAINING:</b> Ensure your development team receives regular security "
            "training to prevent future vulnerabilities."
        )

        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles['Normal']))
            elements.append(Spacer(1, 0.1 * inch))

        return elements

    def _create_metadata_section(self, scan_result: ScanResult, pdf_path: Path) -> List:
        """Create metadata and file information section"""
        elements = []

        elements.append(Paragraph("<b>Report Metadata</b>", self.styles['SectionHeading']))

        # Calculate file hash
        file_hash = "N/A"
        if pdf_path.exists():
            with open(pdf_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

        metadata = [
            f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"<b>Scanner Version:</b> {scan_result.scanner_version}",
            f"<b>Scan ID:</b> {scan_result.scan_id}",
            f"<b>Scan Type:</b> {scan_result.scan_type}",
        ]

        if scan_result.ai_provider:
            metadata.append(f"<b>AI Provider:</b> {scan_result.ai_provider}")

        metadata.extend([
            f"<b>Report File:</b> {pdf_path.name}",
            "<br/><b>Note:</b> This report is generated automatically. "
            "Please verify all findings before taking action."
        ])

        for item in metadata:
            elements.append(Paragraph(item, self.styles['Normal']))
            elements.append(Spacer(1, 0.05 * inch))

        return elements

    def _get_grade_color(self, grade: str) -> str:
        """Get color for security grade"""
        colors_map = {
            "A+": "#00C851",
            "A": "#2E7D32",
            "B": "#FFA000",
            "C": "#FF6F00",
            "D": "#E64A19",
            "F": "#C62828",
        }
        return colors_map.get(grade, "#000000")
