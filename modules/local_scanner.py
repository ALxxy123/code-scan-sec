"""
Enhanced Local Project Scanner
Professional local codebase security scanning with improved detection
"""

import re
import math
from pathlib import Path
from typing import List, Dict, Any, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from datetime import datetime
import hashlib

from .data_models import (
    ScanResult, SecretFinding, VulnerabilityFinding,
    ScanStatistics, SeverityLevel, ScanType
)
from .rules_engine import RulesEngine


class LocalScanner:
    """
    Enhanced local project scanner with advanced secret and vulnerability detection.

    Features:
    - Recursive directory scanning
    - Multi-threaded file processing
    - Shannon entropy-based secret detection
    - Pattern-based vulnerability detection
    - AI verification support (optional)
    - Comprehensive statistics
    """

    def __init__(
        self,
        rules_engine: RulesEngine,
        entropy_threshold: float = 3.5,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        num_threads: int = 4,
        ignore_patterns: List[str] = None
    ):
        """
        Initialize local scanner.

        Args:
            rules_engine: Rules engine instance
            entropy_threshold: Shannon entropy threshold (0-8)
            max_file_size: Maximum file size to scan in bytes
            num_threads: Number of worker threads
            ignore_patterns: List of glob patterns to ignore
        """
        self.rules_engine = rules_engine
        self.entropy_threshold = entropy_threshold
        self.max_file_size = max_file_size
        self.num_threads = num_threads

        # Default ignore patterns
        self.ignore_patterns = ignore_patterns or [
            "*.pyc", "*.pyo", "*.so", "*.dylib",
            "*/.git/*", "*/.svn/*", "*/.hg/*",
            "*/node_modules/*", "*/venv/*", "*/env/*",
            "*/.venv/*", "*/.env/*", "*/vendor/*",
            "*/dist/*", "*/build/*", "*/target/*",
            "*.min.js", "*.min.css", "*.map",
            "*.jpg", "*.jpeg", "*.png", "*.gif",
            "*.pdf", "*.zip", "*.tar", "*.gz",
        ]

        # File extensions to scan
        self.scannable_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx',
            '.java', '.kt', '.go', '.rs', '.rb',
            '.php', '.c', '.cpp', '.h', '.hpp',
            '.cs', '.swift', '.m', '.scala',
            '.sh', '.bash', '.zsh', '.fish',
            '.yaml', '.yml', '.json', '.xml',
            '.env', '.config', '.conf', '.ini',
            '.properties', '.gradle', '.maven',
            '.sql', '.html', '.css', '.scss',
        }

    def scan(
        self,
        path: str,
        enable_ai: bool = False,
        ai_provider: Any = None
    ) -> ScanResult:
        """
        Scan a local directory or file.

        Args:
            path: Path to scan
            enable_ai: Whether to use AI verification
            ai_provider: AI provider instance (if enable_ai=True)

        Returns:
            Complete scan result
        """
        start_time = datetime.now()
        scan_path = Path(path).resolve()

        # Validate path
        if not scan_path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        # Collect files to scan
        files_to_scan = self._collect_files(scan_path)

        # Initialize statistics
        stats = ScanStatistics()
        stats.total_files_scanned = len(files_to_scan)

        # Scan for secrets
        secrets = self._scan_for_secrets(files_to_scan, stats)

        # Scan for vulnerabilities
        vulnerabilities = self._scan_for_vulnerabilities(files_to_scan, stats)

        # AI verification (if enabled)
        if enable_ai and ai_provider and secrets:
            secrets, filtered_count = self._ai_verify_secrets(secrets, ai_provider)
            stats.false_positives_filtered = filtered_count

        # Calculate statistics
        stats.secrets_found = len(secrets)
        stats.vulnerabilities_found = len(vulnerabilities)

        # Count by severity
        for secret in secrets:
            self._increment_severity_count(stats, secret.severity)

        for vuln in vulnerabilities:
            self._increment_severity_count(stats, vuln.severity)

        # Calculate timing
        duration = (datetime.now() - start_time).total_seconds()
        stats.scan_duration = duration
        stats.files_per_second = stats.total_files_scanned / duration if duration > 0 else 0

        # Calculate risk score
        stats.calculate_risk_score()

        # Create scan result
        scan_id = self._generate_scan_id(scan_path)

        result = ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.LOCAL,
            target=str(scan_path),
            secrets=secrets,
            vulnerabilities=vulnerabilities,
            statistics=stats,
            scanner_version="4.0.0",
            ai_provider=ai_provider.__class__.__name__ if ai_provider else None
        )

        return result

    def _collect_files(self, path: Path) -> List[Path]:
        """
        Collect all files to scan.

        Args:
            path: Root path to scan

        Returns:
            List of file paths to scan
        """
        files = []

        if path.is_file():
            if self._should_scan_file(path):
                files.append(path)
            return files

        # Recursively collect files
        for file_path in path.rglob('*'):
            if file_path.is_file() and self._should_scan_file(file_path):
                files.append(file_path)

        return files

    def _should_scan_file(self, file_path: Path) -> bool:
        """
        Determine if a file should be scanned.

        Args:
            file_path: File to check

        Returns:
            True if file should be scanned
        """
        # Check ignore patterns
        path_str = str(file_path)
        for pattern in self.ignore_patterns:
            if Path(path_str).match(pattern):
                return False

        # Check file size
        try:
            if file_path.stat().st_size > self.max_file_size:
                return False
        except OSError:
            return False

        # Check extension
        if file_path.suffix.lower() not in self.scannable_extensions:
            return False

        return True

    def _scan_for_secrets(self, files: List[Path], stats: ScanStatistics) -> List[SecretFinding]:
        """
        Scan files for secrets using pattern matching and entropy analysis.

        Args:
            files: List of files to scan
            stats: Statistics object to update

        Returns:
            List of detected secrets
        """
        all_secrets = []
        patterns = self.rules_engine.get_secret_patterns()

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {
                executor.submit(self._scan_file_for_secrets, file_path, patterns): file_path
                for file_path in files
            }

            for future in as_completed(futures):
                try:
                    secrets, line_count = future.result()
                    all_secrets.extend(secrets)
                    stats.total_lines_scanned += line_count
                except Exception as e:
                    # Skip files that cause errors
                    pass

        return all_secrets

    def _scan_file_for_secrets(
        self,
        file_path: Path,
        patterns: Dict[str, re.Pattern]
    ) -> Tuple[List[SecretFinding], int]:
        """
        Scan a single file for secrets.

        Args:
            file_path: File to scan
            patterns: Dictionary of patterns to match

        Returns:
            Tuple of (secrets found, line count)
        """
        secrets = []
        line_count = 0

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_count += 1

                    for rule_name, pattern in patterns.items():
                        matches = pattern.finditer(line)

                        for match in matches:
                            # Extract matched value
                            matched_text = match.group(0)
                            value = self._extract_value_from_match(match)

                            # Calculate entropy
                            entropy = self._calculate_entropy(value) if value else 0

                            # Filter by entropy threshold
                            if entropy >= self.entropy_threshold:
                                secret = SecretFinding(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    rule_name=rule_name,
                                    matched_text=matched_text[:100],  # Truncate
                                    entropy=entropy,
                                    severity=SeverityLevel.HIGH,
                                    confidence=self._calculate_confidence(entropy, rule_name),
                                    context=line.strip()[:200]
                                )
                                secrets.append(secret)

        except Exception as e:
            # Skip problematic files
            pass

        return secrets, line_count

    def _scan_for_vulnerabilities(
        self,
        files: List[Path],
        stats: ScanStatistics
    ) -> List[VulnerabilityFinding]:
        """
        Scan files for vulnerabilities.

        Args:
            files: List of files to scan
            stats: Statistics object to update

        Returns:
            List of detected vulnerabilities
        """
        all_vulns = []

        # Get all vulnerability rules
        vuln_rules = self.rules_engine.get_vulnerability_rules()

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = {
                executor.submit(self._scan_file_for_vulnerabilities, file_path, vuln_rules): file_path
                for file_path in files
            }

            for future in as_completed(futures):
                try:
                    vulns = future.result()
                    all_vulns.extend(vulns)
                except Exception:
                    pass

        return all_vulns

    def _scan_file_for_vulnerabilities(
        self,
        file_path: Path,
        rules: List[Dict]
    ) -> List[VulnerabilityFinding]:
        """
        Scan a single file for vulnerabilities.

        Args:
            file_path: File to scan
            rules: Vulnerability rules to check

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        file_ext = file_path.suffix.lstrip('.')

        # Language mapping
        language_map = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'java': 'java',
            'php': 'php',
            'rb': 'ruby',
            'go': 'go',
            'rs': 'rust',
            'c': 'c',
            'cpp': 'cpp',
            'cs': 'csharp',
        }

        language = language_map.get(file_ext, file_ext)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                for rule in rules:
                    # Check if rule applies to this language
                    if 'languages' in rule and rule['languages']:
                        if language not in rule['languages']:
                            continue

                    # Try to match pattern
                    if 'compiled_pattern' in rule:
                        pattern = rule['compiled_pattern']
                    elif 'pattern' in rule:
                        try:
                            pattern = re.compile(rule['pattern'], re.IGNORECASE | re.MULTILINE)
                        except re.error:
                            continue
                    else:
                        continue

                    # Find matches
                    for match in pattern.finditer(content):
                        # Determine line number
                        line_num = content[:match.start()].count('\n') + 1

                        # Get code snippet
                        snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                        vuln = VulnerabilityFinding(
                            name=rule.get('name', 'Unknown Vulnerability'),
                            file_path=str(file_path),
                            line_number=line_num,
                            severity=SeverityLevel(rule.get('severity', 'medium')),
                            category=rule.get('category', 'unknown'),
                            cwe=rule.get('cwe'),
                            owasp=rule.get('owasp'),
                            description=rule.get('description', ''),
                            recommendation=rule.get('recommendation', ''),
                            code_snippet=snippet[:200],
                            confidence=0.8
                        )
                        vulnerabilities.append(vuln)

        except Exception:
            pass

        return vulnerabilities

    def _calculate_entropy(self, value: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            value: String to analyze

        Returns:
            Entropy value (0-8)
        """
        if not value:
            return 0.0

        # Count character frequencies
        counts = Counter(value)
        total = len(value)

        # Calculate entropy
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def _extract_value_from_match(self, match: re.Match) -> str:
        """Extract the actual value from a regex match"""
        # Try to get the first capturing group
        if match.groups():
            return match.group(1)
        return match.group(0)

    def _calculate_confidence(self, entropy: float, rule_name: str) -> float:
        """
        Calculate confidence score for a finding.

        Args:
            entropy: Shannon entropy value
            rule_name: Name of the rule that matched

        Returns:
            Confidence score (0-1)
        """
        # Base confidence on entropy
        if entropy >= 4.5:
            confidence = 0.95
        elif entropy >= 4.0:
            confidence = 0.90
        elif entropy >= 3.5:
            confidence = 0.80
        else:
            confidence = 0.70

        # Adjust based on rule name
        high_confidence_rules = ['AWS_KEY', 'API_KEY', 'GITHUB_TOKEN', 'OPENAI_KEY']
        if any(keyword in rule_name.upper() for keyword in high_confidence_rules):
            confidence = min(1.0, confidence + 0.1)

        return confidence

    def _ai_verify_secrets(
        self,
        secrets: List[SecretFinding],
        ai_provider: Any
    ) -> Tuple[List[SecretFinding], int]:
        """
        Use AI to verify secrets and filter false positives.

        Args:
            secrets: List of potential secrets
            ai_provider: AI provider instance

        Returns:
            Tuple of (verified secrets, filtered count)
        """
        # Implementation would integrate with AI provider
        # For now, return unmodified
        return secrets, 0

    def _increment_severity_count(self, stats: ScanStatistics, severity: SeverityLevel):
        """Increment the appropriate severity counter"""
        if severity == SeverityLevel.CRITICAL:
            stats.critical_count += 1
        elif severity == SeverityLevel.HIGH:
            stats.high_count += 1
        elif severity == SeverityLevel.MEDIUM:
            stats.medium_count += 1
        elif severity == SeverityLevel.LOW:
            stats.low_count += 1
        elif severity == SeverityLevel.INFO:
            stats.info_count += 1

    def _generate_scan_id(self, path: Path) -> str:
        """Generate a unique scan ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        path_hash = hashlib.md5(str(path).encode()).hexdigest()[:8]
        return f"scan_{timestamp}_{path_hash}"
