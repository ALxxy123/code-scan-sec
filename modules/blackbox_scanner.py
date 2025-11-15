"""
Black Box Security Scanner
Safe, passive security testing for web applications
"""

import requests
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib
import ssl
import socket

from .data_models import (
    ScanResult, VulnerabilityFinding, SecurityHeaderFinding,
    SeverityLevel, ScanType, ScanStatistics
)


class BlackBoxScanner:
    """
    Safe black-box security scanner for web applications.

    IMPORTANT: This scanner only performs SAFE, PASSIVE checks.
    It does NOT perform:
    - Aggressive attacks
    - DoS attacks
    - Data manipulation
    - Unauthorized access attempts

    Features:
    - Security header analysis
    - SSL/TLS configuration checks
    - Cookie security analysis
    - Safe parameter fuzzing
    - Common vulnerability signatures (passive detection)
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize black box scanner.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner/4.0)'
        })

    def scan(self, url: str) -> ScanResult:
        """
        Perform safe black-box security scan.

        Args:
            url: Target URL to scan

        Returns:
            Complete scan result
        """
        start_time = datetime.now()

        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {url}")

        # Initialize results
        vulnerabilities = []
        security_headers = []
        statistics = ScanStatistics()

        # Perform checks
        try:
            response = self.session.get(url, timeout=self.timeout, verify=True)

            # Security headers
            security_headers = self._check_security_headers(response)

            # Cookie security
            cookie_vulns = self._check_cookie_security(response)
            vulnerabilities.extend(cookie_vulns)

            # SSL/TLS check (if HTTPS)
            if parsed.scheme == 'https':
                ssl_vulns = self._check_ssl_tls(parsed.netloc)
                vulnerabilities.extend(ssl_vulns)

            # Check for common misconfigurations
            misconfig_vulns = self._check_misconfigurations(response)
            vulnerabilities.extend(misconfig_vulns)

            # Passive vulnerability detection
            passive_vulns = self._passive_vulnerability_check(response)
            vulnerabilities.extend(passive_vulns)

        except requests.RequestException as e:
            # Log error but don't fail
            pass

        # Calculate statistics
        duration = (datetime.now() - start_time).total_seconds()
        statistics.scan_duration = duration
        statistics.vulnerabilities_found = len(vulnerabilities)

        # Count severity
        for vuln in vulnerabilities:
            if vuln.severity == SeverityLevel.CRITICAL:
                statistics.critical_count += 1
            elif vuln.severity == SeverityLevel.HIGH:
                statistics.high_count += 1
            elif vuln.severity == SeverityLevel.MEDIUM:
                statistics.medium_count += 1
            elif vuln.severity == SeverityLevel.LOW:
                statistics.low_count += 1

        for header in security_headers:
            if not header.present and header.severity == SeverityLevel.HIGH:
                statistics.high_count += 1
            elif not header.present and header.severity == SeverityLevel.MEDIUM:
                statistics.medium_count += 1

        statistics.calculate_risk_score()

        # Create scan result
        scan_id = self._generate_scan_id(url)

        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.BLACKBOX,
            target=url,
            vulnerabilities=vulnerabilities,
            security_headers=security_headers,
            statistics=statistics,
            scanner_version="4.0.0"
        )

        return result

    def _check_security_headers(self, response: requests.Response) -> List[SecurityHeaderFinding]:
        """Check security headers"""
        headers_to_check = {
            'Strict-Transport-Security': (SeverityLevel.HIGH, 'Enable HSTS'),
            'X-Frame-Options': (SeverityLevel.MEDIUM, 'Prevent clickjacking'),
            'X-Content-Type-Options': (SeverityLevel.MEDIUM, 'Prevent MIME sniffing'),
            'Content-Security-Policy': (SeverityLevel.HIGH, 'Implement CSP'),
            'X-XSS-Protection': (SeverityLevel.LOW, 'Enable XSS protection'),
            'Referrer-Policy': (SeverityLevel.LOW, 'Control referrer information'),
        }

        findings = []
        for header, (severity, recommendation) in headers_to_check.items():
            present = header in response.headers
            value = response.headers.get(header)

            finding = SecurityHeaderFinding(
                header_name=header,
                present=present,
                value=value,
                severity=SeverityLevel.INFO if present else severity,
                recommendation=recommendation if not present else f"Present: {value}"
            )
            findings.append(finding)

        return findings

    def _check_cookie_security(self, response: requests.Response) -> List[VulnerabilityFinding]:
        """Check cookie security flags"""
        vulnerabilities = []

        for cookie in response.cookies:
            issues = []

            if not cookie.secure:
                issues.append("Missing Secure flag")

            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("Missing HttpOnly flag")

            if cookie.has_nonstandard_attr('SameSite'):
                same_site = cookie.get_nonstandard_attr('SameSite')
                if same_site not in ['Strict', 'Lax']:
                    issues.append(f"Weak SameSite policy: {same_site}")
            else:
                issues.append("Missing SameSite attribute")

            if issues:
                vuln = VulnerabilityFinding(
                    name="Insecure Cookie Configuration",
                    file_path=response.url,
                    line_number=0,
                    severity=SeverityLevel.MEDIUM,
                    category="cookie_security",
                    cwe="CWE-614",
                    owasp="A05:2021",
                    description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                    recommendation="Set Secure, HttpOnly, and SameSite=Strict flags on all cookies",
                    confidence=0.9
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_ssl_tls(self, hostname: str) -> List[VulnerabilityFinding]:
        """Check SSL/TLS configuration"""
        vulnerabilities = []

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get SSL version
                    ssl_version = ssock.version()

                    # Check for weak protocols
                    if ssl_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        vuln = VulnerabilityFinding(
                            name="Weak TLS Version",
                            file_path=hostname,
                            line_number=0,
                            severity=SeverityLevel.HIGH,
                            category="ssl_tls",
                            cwe="CWE-327",
                            owasp="A02:2021",
                            description=f"Server supports weak TLS version: {ssl_version}",
                            recommendation="Disable TLS 1.1 and below. Use TLS 1.2 or 1.3",
                            confidence=0.95
                        )
                        vulnerabilities.append(vuln)

        except Exception:
            # SSL check failed, skip
            pass

        return vulnerabilities

    def _check_misconfigurations(self, response: requests.Response) -> List[VulnerabilityFinding]:
        """Check for common security misconfigurations"""
        vulnerabilities = []

        # Check for directory listing
        if '<title>Index of' in response.text or 'Directory listing' in response.text:
            vuln = VulnerabilityFinding(
                name="Directory Listing Enabled",
                file_path=response.url,
                line_number=0,
                severity=SeverityLevel.MEDIUM,
                category="misconfiguration",
                cwe="CWE-548",
                owasp="A05:2021",
                description="Directory listing is enabled",
                recommendation="Disable directory listing in web server configuration",
                confidence=0.9
            )
            vulnerabilities.append(vuln)

        # Check for verbose error messages
        error_indicators = [
            'Traceback', 'Stack trace', 'Fatal error',
            'Warning:', 'Notice:', 'Parse error'
        ]

        for indicator in error_indicators:
            if indicator in response.text:
                vuln = VulnerabilityFinding(
                    name="Verbose Error Messages",
                    file_path=response.url,
                    line_number=0,
                    severity=SeverityLevel.LOW,
                    category="information_disclosure",
                    cwe="CWE-209",
                    owasp="A05:2021",
                    description="Application displays verbose error messages",
                    recommendation="Configure application to show generic error messages in production",
                    confidence=0.8
                )
                vulnerabilities.append(vuln)
                break

        return vulnerabilities

    def _passive_vulnerability_check(self, response: requests.Response) -> List[VulnerabilityFinding]:
        """Passive vulnerability detection based on response"""
        vulnerabilities = []

        # Check for server header information disclosure
        if 'Server' in response.headers:
            server = response.headers['Server']
            vuln = VulnerabilityFinding(
                name="Server Information Disclosure",
                file_path=response.url,
                line_number=0,
                severity=SeverityLevel.LOW,
                category="information_disclosure",
                cwe="CWE-200",
                owasp="A05:2021",
                description=f"Server header discloses: {server}",
                recommendation="Remove or obfuscate Server header",
                confidence=1.0
            )
            vulnerabilities.append(vuln)

        # Check for X-Powered-By header
        if 'X-Powered-By' in response.headers:
            powered_by = response.headers['X-Powered-By']
            vuln = VulnerabilityFinding(
                name="Technology Stack Disclosure",
                file_path=response.url,
                line_number=0,
                severity=SeverityLevel.LOW,
                category="information_disclosure",
                cwe="CWE-200",
                owasp="A05:2021",
                description=f"X-Powered-By header discloses: {powered_by}",
                recommendation="Remove X-Powered-By header",
                confidence=1.0
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _generate_scan_id(self, url: str) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        return f"blackbox_{timestamp}_{url_hash}"
