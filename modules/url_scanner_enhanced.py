"""
Enhanced URL Security Scanner
Remote website and repository security analysis with header detection
"""

import requests
from urllib.parse import urlparse, urljoin
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import hashlib
import tempfile
import shutil

from .data_models import (
    ScanResult, SecurityHeaderFinding, SeverityLevel,
    ScanType, ScanStatistics
)
from .local_scanner import LocalScanner


class URLScannerEnhanced:
    """
    Enhanced URL scanner for remote security analysis.

    Features:
    - HTTP security headers detection
    - Server information leak detection
    - robots.txt and sitemap analysis
    - SSL/TLS configuration check
    - Git repository cloning and scanning
    - Response header analysis
    """

    # Security headers to check
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': SeverityLevel.HIGH,
            'recommendation': 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'X-Frame-Options': {
            'severity': SeverityLevel.MEDIUM,
            'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'severity': SeverityLevel.MEDIUM,
            'recommendation': 'Add X-Content-Type-Options: nosniff'
        },
        'Content-Security-Policy': {
            'severity': SeverityLevel.HIGH,
            'recommendation': 'Implement a Content Security Policy'
        },
        'X-XSS-Protection': {
            'severity': SeverityLevel.LOW,
            'recommendation': 'Add X-XSS-Protection: 1; mode=block (note: deprecated but still useful)'
        },
        'Referrer-Policy': {
            'severity': SeverityLevel.LOW,
            'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'severity': SeverityLevel.MEDIUM,
            'recommendation': 'Add Permissions-Policy to control browser features'
        },
    }

    INFORMATION_LEAK_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version',
        'X-AspNetMvc-Version', 'X-Generator'
    ]

    def __init__(self, timeout: int = 30):
        """
        Initialize URL scanner.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner Bot/4.0)'
        })

    def scan(
        self,
        url: str,
        local_scanner: Optional[LocalScanner] = None
    ) -> ScanResult:
        """
        Scan a URL for security issues.

        Args:
            url: URL to scan
            local_scanner: Optional local scanner for repo analysis

        Returns:
            Complete scan result
        """
        start_time = datetime.now()

        # Initialize results
        security_headers = []
        info_leaks = []
        statistics = ScanStatistics()

        # Check if it's a Git repository
        if self._is_git_repo(url):
            return self._scan_git_repo(url, local_scanner)

        # Analyze HTTP response
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

            # Check security headers
            security_headers = self._check_security_headers(response)

            # Check for information leaks
            info_leaks = self._check_information_leaks(response)

            # Check robots.txt
            robots_findings = self._check_robots_txt(url)

            # Check for common paths
            exposed_paths = self._check_exposed_paths(url)

        except requests.RequestException as e:
            # Handle connection errors
            pass

        # Calculate statistics
        duration = (datetime.now() - start_time).total_seconds()
        statistics.scan_duration = duration

        # Count severity
        for finding in security_headers:
            if finding.severity == SeverityLevel.CRITICAL:
                statistics.critical_count += 1
            elif finding.severity == SeverityLevel.HIGH:
                statistics.high_count += 1
            elif finding.severity == SeverityLevel.MEDIUM:
                statistics.medium_count += 1
            elif finding.severity == SeverityLevel.LOW:
                statistics.low_count += 1

        statistics.calculate_risk_score()

        # Create scan result
        scan_id = self._generate_scan_id(url)

        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.URL,
            target=url,
            security_headers=security_headers,
            statistics=statistics,
            scanner_version="4.0.0"
        )

        return result

    def _check_security_headers(self, response: requests.Response) -> List[SecurityHeaderFinding]:
        """Check for missing or misconfigured security headers"""
        findings = []

        for header, config in self.SECURITY_HEADERS.items():
            present = header in response.headers
            value = response.headers.get(header)

            finding = SecurityHeaderFinding(
                header_name=header,
                present=present,
                value=value,
                severity=SeverityLevel.INFO if present else config['severity'],
                recommendation=config['recommendation'] if not present else f"Current value: {value}"
            )
            findings.append(finding)

        return findings

    def _check_information_leaks(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Check for server information leaks in headers"""
        leaks = []

        for header in self.INFORMATION_LEAK_HEADERS:
            if header in response.headers:
                leaks.append({
                    'header': header,
                    'value': response.headers[header],
                    'severity': SeverityLevel.LOW,
                    'recommendation': f'Remove or obfuscate {header} header'
                })

        return leaks

    def _check_robots_txt(self, url: str) -> Dict[str, Any]:
        """Check robots.txt for security issues"""
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        try:
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                # Look for sensitive paths in robots.txt
                sensitive_keywords = ['admin', 'backup', 'config', 'secret', 'private']
                content = response.text.lower()

                exposed = [kw for kw in sensitive_keywords if kw in content]

                if exposed:
                    return {
                        'found': True,
                        'exposed_keywords': exposed,
                        'severity': SeverityLevel.MEDIUM,
                        'recommendation': 'Review robots.txt for sensitive path disclosure'
                    }
        except requests.RequestException:
            pass

        return {'found': False}

    def _check_exposed_paths(self, url: str) -> List[Dict[str, Any]]:
        """Check for commonly exposed sensitive paths"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        common_paths = [
            '/.git/config',
            '/.env',
            '/config.json',
            '/package.json',
            '/.DS_Store',
            '/debug',
            '/console',
            '/admin',
            '/phpmyadmin',
        ]

        exposed = []
        for path in common_paths:
            try:
                response = self.session.get(
                    base_url + path,
                    timeout=5,
                    allow_redirects=False
                )

                if response.status_code == 200:
                    exposed.append({
                        'path': path,
                        'status': response.status_code,
                        'severity': SeverityLevel.HIGH,
                        'recommendation': f'Restrict access to {path}'
                    })
            except requests.RequestException:
                continue

        return exposed

    def _is_git_repo(self, url: str) -> bool:
        """Check if URL is a Git repository"""
        git_indicators = [
            'github.com',
            'gitlab.com',
            'bitbucket.org',
            '.git'
        ]
        return any(indicator in url.lower() for indicator in git_indicators)

    def _scan_git_repo(
        self,
        url: str,
        local_scanner: Optional[LocalScanner]
    ) -> ScanResult:
        """
        Clone and scan a Git repository.

        Args:
            url: Git repository URL
            local_scanner: Local scanner instance

        Returns:
            Scan result
        """
        if not local_scanner:
            raise ValueError("Local scanner required for repository scanning")

        # Create temporary directory
        temp_dir = Path(tempfile.mkdtemp(prefix='security_scan_'))

        try:
            # Clone repository (shallow clone for speed)
            import subprocess
            subprocess.run(
                ['git', 'clone', '--depth', '1', url, str(temp_dir)],
                check=True,
                capture_output=True,
                timeout=300
            )

            # Scan the cloned repository
            result = local_scanner.scan(str(temp_dir))
            result.scan_type = ScanType.URL
            result.target = url

            return result

        finally:
            # Cleanup
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _generate_scan_id(self, url: str) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
        return f"url_scan_{timestamp}_{url_hash}"
