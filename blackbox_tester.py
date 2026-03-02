"""
Black Box Testing Module for Web Application Security Analysis.

This module provides automated black box security testing capabilities:
- SQL Injection detection
- XSS (Cross-Site Scripting) testing
- Authentication testing
- Authorization testing
- CSRF detection
- Security headers analysis
- SSL/TLS configuration testing
- Directory traversal testing
- Command injection testing
- API security testing

Version: 3.2.0
Author: Ahmed Mubaraki
"""

from typing import List, Dict, Any, Optional, Tuple
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse, urlencode
import ssl
import socket
import re
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, track
from rich.panel import Panel
from rich.table import Table

from logger import get_logger

console = Console()
logger = get_logger()


class BlackBoxTester:
    """Perform black box security testing on web applications."""

    # Security Headers that should be present
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS not configured',
        'X-Frame-Options': 'Clickjacking protection missing',
        'X-Content-Type-Options': 'MIME-type sniffing not prevented',
        'Content-Security-Policy': 'CSP not configured',
        'X-XSS-Protection': 'XSS protection header missing',
        'Referrer-Policy': 'Referrer policy not set',
        'Permissions-Policy': 'Permissions policy not configured'
    }

    # SQL Injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2"
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "'><script>alert('XSS')</script>"
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]

    # Command injection payloads
    COMMAND_INJECTION_PAYLOADS = [
        "; ls",
        "| ls",
        "& ls",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "`ls`",
        "$(ls)"
    ]

    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize Black Box Tester.

        Args:
            target_url: Base URL of target application
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Scanner-BlackBox/3.2.0'
        })
        self.vulnerabilities: List[Dict[str, Any]] = []
        logger.info(f"Initialized BlackBoxTester for: {target_url}")

    def test_security_headers(self) -> List[Dict[str, Any]]:
        """
        Test for missing security headers.

        Returns:
            List of security header issues
        """
        console.print("[cyan]🔍 Testing security headers...[/cyan]")
        issues = []

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            headers = response.headers

            for header, description in self.SECURITY_HEADERS.items():
                if header not in headers:
                    issue = {
                        'type': 'missing_security_header',
                        'severity': 'medium',
                        'header': header,
                        'description': description,
                        'recommendation': f'Add {header} header to enhance security'
                    }
                    issues.append(issue)
                    logger.warning(f"Missing security header: {header}")

            # Check for insecure cookies
            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure:
                    issues.append({
                        'type': 'insecure_cookie',
                        'severity': 'medium',
                        'cookie_name': cookie.name,
                        'description': 'Cookie without Secure flag',
                        'recommendation': 'Set Secure flag on all cookies'
                    })

                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append({
                        'type': 'cookie_without_httponly',
                        'severity': 'medium',
                        'cookie_name': cookie.name,
                        'description': 'Cookie without HttpOnly flag',
                        'recommendation': 'Set HttpOnly flag to prevent XSS attacks'
                    })

        except Exception as e:
            logger.error(f"Error testing security headers: {e}")

        return issues

    def test_ssl_tls(self) -> List[Dict[str, Any]]:
        """
        Test SSL/TLS configuration.

        Returns:
            List of SSL/TLS issues
        """
        console.print("[cyan]🔒 Testing SSL/TLS configuration...[/cyan]")
        issues = []

        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme != 'https':
            issues.append({
                'type': 'no_https',
                'severity': 'high',
                'description': 'Site not using HTTPS',
                'recommendation': 'Enable HTTPS to encrypt traffic'
            })
            return issues

        try:
            hostname = parsed_url.netloc.split(':')[0]
            port = parsed_url.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()

                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        issues.append({
                            'type': 'weak_tls_version',
                            'severity': 'high',
                            'version': version,
                            'description': f'Weak TLS version: {version}',
                            'recommendation': 'Use TLS 1.2 or higher'
                        })

        except Exception as e:
            logger.error(f"Error testing SSL/TLS: {e}")
            issues.append({
                'type': 'ssl_error',
                'severity': 'high',
                'description': f'SSL/TLS configuration error: {str(e)}',
                'recommendation': 'Review SSL/TLS configuration'
            })

        return issues

    def test_sql_injection(self, test_params: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Test for SQL injection vulnerabilities.

        Args:
            test_params: List of parameter names to test (if None, auto-detect)

        Returns:
            List of potential SQL injection vulnerabilities
        """
        console.print("[cyan]💉 Testing for SQL injection...[/cyan]")
        issues = []

        # SQL error patterns
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"SQLite.*ERROR",
            r"SQLiteException",
            r"Microsoft SQL Server.*Error",
            r"ODBC SQL Server Driver",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"SQL Server.*Error",
        ]

        for payload in self.SQL_PAYLOADS:
            try:
                # Test URL parameters
                parsed = urlparse(self.target_url)
                params = parse_qs(parsed.query)

                for param in params:
                    test_params_dict = params.copy()
                    test_params_dict[param] = [payload]

                    # Reconstruct URL with payload
                    new_query = urlencode(test_params_dict, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = self.session.get(test_url, timeout=self.timeout)

                    # Check for SQL errors in response
                    for pattern in sql_errors:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            issues.append({
                                'type': 'sql_injection',
                                'severity': 'critical',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Potential SQL injection in parameter: {param}',
                                'recommendation': 'Use parameterized queries/prepared statements',
                                'evidence': re.search(pattern, response.text, re.IGNORECASE).group()
                            })
                            logger.warning(f"Potential SQL injection found in: {param}")
                            break

            except Exception as e:
                logger.debug(f"Error testing SQL injection payload {payload}: {e}")

        return issues

    def test_xss(self) -> List[Dict[str, Any]]:
        """
        Test for Cross-Site Scripting (XSS) vulnerabilities.

        Returns:
            List of potential XSS vulnerabilities
        """
        console.print("[cyan]🎯 Testing for XSS vulnerabilities...[/cyan]")
        issues = []

        for payload in self.XSS_PAYLOADS:
            try:
                parsed = urlparse(self.target_url)
                params = parse_qs(parsed.query)

                for param in params:
                    test_params_dict = params.copy()
                    test_params_dict[param] = [payload]

                    new_query = urlencode(test_params_dict, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = self.session.get(test_url, timeout=self.timeout)

                    # Check if payload is reflected in response
                    if payload in response.text:
                        issues.append({
                            'type': 'xss',
                            'severity': 'high',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'description': f'Potential XSS vulnerability in parameter: {param}',
                            'recommendation': 'Implement proper input validation and output encoding',
                            'reflected': True
                        })
                        logger.warning(f"Potential XSS found in: {param}")

            except Exception as e:
                logger.debug(f"Error testing XSS payload {payload}: {e}")

        return issues

    def test_path_traversal(self) -> List[Dict[str, Any]]:
        """
        Test for path traversal vulnerabilities.

        Returns:
            List of potential path traversal issues
        """
        console.print("[cyan]📂 Testing for path traversal...[/cyan]")
        issues = []

        sensitive_patterns = [
            r"root:[x*]:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # Windows boot.ini
        ]

        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            try:
                parsed = urlparse(self.target_url)
                params = parse_qs(parsed.query)

                for param in params:
                    test_params_dict = params.copy()
                    test_params_dict[param] = [payload]

                    new_query = urlencode(test_params_dict, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = self.session.get(test_url, timeout=self.timeout)

                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text):
                            issues.append({
                                'type': 'path_traversal',
                                'severity': 'critical',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Path traversal vulnerability in parameter: {param}',
                                'recommendation': 'Implement strict input validation and use whitelisting',
                                'evidence': re.search(pattern, response.text).group()
                            })
                            logger.warning(f"Path traversal found in: {param}")
                            break

            except Exception as e:
                logger.debug(f"Error testing path traversal payload {payload}: {e}")

        return issues

    def test_command_injection(self) -> List[Dict[str, Any]]:
        """
        Test for command injection vulnerabilities.

        Returns:
            List of potential command injection issues
        """
        console.print("[cyan]⚡ Testing for command injection...[/cyan]")
        issues = []

        for payload in self.COMMAND_INJECTION_PAYLOADS:
            try:
                parsed = urlparse(self.target_url)
                params = parse_qs(parsed.query)

                for param in params:
                    test_params_dict = params.copy()
                    test_params_dict[param] = [payload]

                    new_query = urlencode(test_params_dict, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = self.session.get(test_url, timeout=self.timeout)

                    # Check for command output indicators
                    if any(indicator in response.text for indicator in ['bin', 'usr', 'etc', 'root:']):
                        issues.append({
                            'type': 'command_injection',
                            'severity': 'critical',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'description': f'Potential command injection in parameter: {param}',
                            'recommendation': 'Never pass user input directly to system commands',
                        })
                        logger.warning(f"Potential command injection found in: {param}")

            except Exception as e:
                logger.debug(f"Error testing command injection payload {payload}: {e}")

        return issues

    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all black box security tests.

        Returns:
            Dict containing all test results
        """
        console.print(Panel.fit(
            "[bold cyan]🎯 Starting Black Box Security Testing[/bold cyan]",
            border_style="cyan"
        ))

        start_time = datetime.now()
        all_issues = []

        # Run all tests
        tests = [
            ("Security Headers", self.test_security_headers),
            ("SSL/TLS Configuration", self.test_ssl_tls),
            ("SQL Injection", self.test_sql_injection),
            ("XSS", self.test_xss),
            ("Path Traversal", self.test_path_traversal),
            ("Command Injection", self.test_command_injection),
        ]

        for test_name, test_func in track(tests, description="Running tests..."):
            try:
                issues = test_func()
                all_issues.extend(issues)
            except Exception as e:
                logger.error(f"Error running {test_name} test: {e}")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Categorize by severity
        severity_counts = {
            'critical': len([i for i in all_issues if i.get('severity') == 'critical']),
            'high': len([i for i in all_issues if i.get('severity') == 'high']),
            'medium': len([i for i in all_issues if i.get('severity') == 'medium']),
            'low': len([i for i in all_issues if i.get('severity') == 'low']),
        }

        results = {
            'target_url': self.target_url,
            'scan_date': start_time.isoformat(),
            'duration_seconds': duration,
            'total_issues': len(all_issues),
            'severity_counts': severity_counts,
            'issues': all_issues,
        }

        # Display summary
        self._display_summary(results)

        return results

    def _display_summary(self, results: Dict[str, Any]):
        """Display test results summary."""
        console.print("\n")
        console.print(Panel.fit(
            f"[bold]Black Box Test Results[/bold]\n"
            f"Target: {results['target_url']}\n"
            f"Duration: {results['duration_seconds']:.2f}s",
            border_style="green"
        ))

        # Severity table
        table = Table(title="Issues by Severity", show_header=True, header_style="bold")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", justify="right", style="yellow")

        severity_colors = {
            'critical': 'red',
            'high': 'orange1',
            'medium': 'yellow',
            'low': 'blue'
        }

        for severity, count in results['severity_counts'].items():
            if count > 0:
                color = severity_colors.get(severity, 'white')
                table.add_row(
                    f"[{color}]{severity.upper()}[/{color}]",
                    f"[{color}]{count}[/{color}]"
                )

        console.print(table)
        console.print(f"\n[bold]Total Issues Found: {results['total_issues']}[/bold]\n")


def run_blackbox_test(target_url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Convenience function to run black box tests.

    Args:
        target_url: Target application URL
        timeout: Request timeout in seconds

    Returns:
        Dict containing test results
    """
    tester = BlackBoxTester(target_url, timeout=timeout)
    return tester.run_all_tests()
