"""
Data Models for Security Scan CLI
Professional data structures using Pydantic for validation and serialization
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
from pathlib import Path


class SeverityLevel(str, Enum):
    """Security finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanType(str, Enum):
    """Types of security scans"""
    LOCAL = "local"
    URL = "url"
    BLACKBOX = "blackbox"
    BENCHMARK = "benchmark"


class SecretFinding(BaseModel):
    """Model for a detected secret or sensitive information"""
    file_path: str = Field(..., description="Path to the file containing the secret")
    line_number: int = Field(..., description="Line number where secret was found")
    rule_name: str = Field(..., description="Name of the rule that triggered")
    matched_text: str = Field(..., description="The matched text (may be truncated)")
    entropy: Optional[float] = Field(None, description="Shannon entropy value")
    severity: SeverityLevel = Field(default=SeverityLevel.HIGH, description="Severity level")
    ai_verified: Optional[bool] = Field(None, description="Whether AI verified this as a real secret")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Confidence score (0-1)")
    context: Optional[str] = Field(None, description="Surrounding code context")

    class Config:
        use_enum_values = True


class VulnerabilityFinding(BaseModel):
    """Model for a detected vulnerability"""
    name: str = Field(..., description="Vulnerability name")
    file_path: str = Field(..., description="Path to vulnerable file")
    line_number: int = Field(..., description="Line number of vulnerable code")
    severity: SeverityLevel = Field(..., description="Severity level")
    category: str = Field(..., description="Vulnerability category")
    cwe: Optional[str] = Field(None, description="CWE identifier")
    owasp: Optional[str] = Field(None, description="OWASP category")
    description: str = Field(..., description="Detailed description")
    recommendation: str = Field(..., description="How to fix this vulnerability")
    code_snippet: Optional[str] = Field(None, description="Vulnerable code snippet")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Confidence score")

    class Config:
        use_enum_values = True


class SecurityHeaderFinding(BaseModel):
    """Model for security header analysis"""
    header_name: str = Field(..., description="Name of the security header")
    present: bool = Field(..., description="Whether the header is present")
    value: Optional[str] = Field(None, description="Header value if present")
    severity: SeverityLevel = Field(..., description="Severity if missing")
    recommendation: str = Field(..., description="Recommended value or action")


class ScanStatistics(BaseModel):
    """Statistics for a security scan"""
    total_files_scanned: int = Field(default=0, description="Total files scanned")
    total_lines_scanned: int = Field(default=0, description="Total lines of code scanned")
    secrets_found: int = Field(default=0, description="Number of secrets detected")
    vulnerabilities_found: int = Field(default=0, description="Number of vulnerabilities found")
    false_positives_filtered: int = Field(default=0, description="False positives removed by AI")

    # Severity breakdown
    critical_count: int = Field(default=0, description="Critical findings")
    high_count: int = Field(default=0, description="High severity findings")
    medium_count: int = Field(default=0, description="Medium severity findings")
    low_count: int = Field(default=0, description="Low severity findings")
    info_count: int = Field(default=0, description="Info findings")

    # Performance metrics
    scan_duration: float = Field(default=0.0, description="Scan duration in seconds")
    files_per_second: float = Field(default=0.0, description="Processing speed")

    # Risk scoring
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Overall risk score (0-100)")
    security_grade: str = Field(default="F", description="Security grade (A+ to F)")

    def calculate_risk_score(self):
        """Calculate overall risk score based on findings"""
        # Weighted scoring system
        score = (
            self.critical_count * 25 +
            self.high_count * 15 +
            self.medium_count * 8 +
            self.low_count * 3 +
            self.info_count * 1
        )
        self.risk_score = min(100.0, float(score))

        # Calculate security grade
        if self.risk_score == 0:
            self.security_grade = "A+"
        elif self.risk_score <= 5:
            self.security_grade = "A"
        elif self.risk_score <= 15:
            self.security_grade = "B"
        elif self.risk_score <= 30:
            self.security_grade = "C"
        elif self.risk_score <= 50:
            self.security_grade = "D"
        else:
            self.security_grade = "F"


class BenchmarkResult(BaseModel):
    """Performance benchmark results"""
    scan_type: ScanType
    target: str = Field(..., description="Path or URL that was scanned")
    duration_seconds: float = Field(..., description="Total scan duration")
    files_scanned: int = Field(default=0, description="Number of files processed")
    lines_scanned: int = Field(default=0, description="Number of lines processed")
    findings_detected: int = Field(default=0, description="Total findings")

    # Performance metrics
    files_per_second: float = Field(default=0.0, description="Processing speed")
    lines_per_second: float = Field(default=0.0, description="Line processing speed")
    peak_memory_mb: float = Field(default=0.0, description="Peak memory usage in MB")
    avg_cpu_percent: float = Field(default=0.0, description="Average CPU utilization")

    # Network metrics (for URL scans)
    network_latency_ms: Optional[float] = Field(None, description="Network latency")
    download_speed_mbps: Optional[float] = Field(None, description="Download speed")

    timestamp: datetime = Field(default_factory=datetime.now, description="When benchmark was run")

    class Config:
        use_enum_values = True


class ScanResult(BaseModel):
    """Complete scan result with all findings and metadata"""
    scan_id: str = Field(..., description="Unique scan identifier")
    scan_type: ScanType = Field(..., description="Type of scan performed")
    target: str = Field(..., description="Scan target (path or URL)")
    timestamp: datetime = Field(default_factory=datetime.now, description="Scan timestamp")

    # Findings
    secrets: List[SecretFinding] = Field(default_factory=list, description="Detected secrets")
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list, description="Detected vulnerabilities")
    security_headers: List[SecurityHeaderFinding] = Field(default_factory=list, description="Security header findings")

    # Statistics
    statistics: ScanStatistics = Field(default_factory=ScanStatistics, description="Scan statistics")
    benchmark: Optional[BenchmarkResult] = Field(None, description="Benchmark data if available")

    # Metadata
    scanner_version: str = Field(default="4.0.0", description="Scanner version")
    ai_provider: Optional[str] = Field(None, description="AI provider used")
    config_used: Dict[str, Any] = Field(default_factory=dict, description="Configuration snapshot")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return self.dict()

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings in a unified format"""
        findings = []

        for secret in self.secrets:
            findings.append({
                "type": "secret",
                "severity": secret.severity,
                "file": secret.file_path,
                "line": secret.line_number,
                "description": f"Secret detected: {secret.rule_name}",
            })

        for vuln in self.vulnerabilities:
            findings.append({
                "type": "vulnerability",
                "severity": vuln.severity,
                "file": vuln.file_path,
                "line": vuln.line_number,
                "description": vuln.name,
            })

        return findings

    def get_summary(self) -> str:
        """Get a human-readable summary"""
        total_findings = len(self.secrets) + len(self.vulnerabilities)
        return (
            f"Scan completed: {total_findings} findings detected\n"
            f"Critical: {self.statistics.critical_count} | "
            f"High: {self.statistics.high_count} | "
            f"Medium: {self.statistics.medium_count} | "
            f"Low: {self.statistics.low_count}\n"
            f"Security Grade: {self.statistics.security_grade} | "
            f"Risk Score: {self.statistics.risk_score:.1f}/100"
        )

    class Config:
        use_enum_values = True


class PluginMetadata(BaseModel):
    """Metadata for a scanner plugin"""
    name: str = Field(..., description="Plugin name")
    version: str = Field(..., description="Plugin version")
    author: str = Field(..., description="Plugin author")
    description: str = Field(..., description="Plugin description")
    enabled: bool = Field(default=True, description="Whether plugin is enabled")
    dependencies: List[str] = Field(default_factory=list, description="Required dependencies")


class CustomRule(BaseModel):
    """Custom security rule definition"""
    name: str = Field(..., description="Rule name")
    pattern: str = Field(..., description="Regex pattern to match")
    severity: SeverityLevel = Field(..., description="Severity level")
    category: str = Field(default="custom", description="Rule category")
    description: str = Field(..., description="What this rule detects")
    recommendation: str = Field(..., description="How to remediate")
    enabled: bool = Field(default=True, description="Whether rule is active")
    languages: List[str] = Field(default_factory=list, description="Applicable languages")

    class Config:
        use_enum_values = True


class ScanConfig(BaseModel):
    """Configuration for a scan operation"""
    enable_ai: bool = Field(default=True, description="Enable AI verification")
    enable_vulnerability_scan: bool = Field(default=True, description="Enable vulnerability scanning")
    max_file_size: int = Field(default=10485760, description="Max file size in bytes")
    entropy_threshold: float = Field(default=3.5, ge=0.0, le=8.0, description="Entropy threshold")
    threads: int = Field(default=4, ge=1, le=32, description="Number of worker threads")
    timeout: int = Field(default=300, description="Scan timeout in seconds")
    ignore_patterns: List[str] = Field(default_factory=list, description="Patterns to ignore")
    custom_rules: List[CustomRule] = Field(default_factory=list, description="Custom rules")
