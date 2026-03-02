"""
Security Scan CLI - Professional Security Analysis Suite
Modular Architecture Package

This package contains all core modules for the security scanning system.
"""

__version__ = "4.0.0"
__author__ = "Security Scan Team"
__license__ = "MIT"

from .data_models import (
    ScanResult,
    SecretFinding,
    VulnerabilityFinding,
    ScanStatistics,
    BenchmarkResult,
    SeverityLevel,
    ScanType
)

from .local_scanner import LocalScanner
from .url_scanner_enhanced import URLScannerEnhanced
from .blackbox_scanner import BlackBoxScanner
from .benchmark_engine import BenchmarkEngine, PerformanceMonitor
from .pdf_generator import PDFReportGenerator
from .csv_exporter import CSVExporter
from .plugin_system import PluginManager, BasePlugin
from .update_checker import UpdateChecker
from .rules_engine import RulesEngine

__all__ = [
    # Data Models
    "ScanResult",
    "SecretFinding",
    "VulnerabilityFinding",
    "ScanStatistics",
    "BenchmarkResult",
    "SeverityLevel",
    "ScanType",

    # Scanner Modules
    "LocalScanner",
    "URLScannerEnhanced",
    "BlackBoxScanner",
    "BenchmarkEngine",
    "PerformanceMonitor",

    # Report & Export
    "PDFReportGenerator",
    "CSVExporter",

    # Systems
    "PluginManager",
    "BasePlugin",
    "UpdateChecker",
    "RulesEngine",
]
