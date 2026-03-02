# Security Scan CLI - Complete Usage Guide

## Version 4.0.0

Welcome to the comprehensive usage guide for Security Scan CLI, your professional security analysis suite.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Core Commands](#core-commands)
4. [Features](#features)
5. [Report Formats](#report-formats)
6. [Configuration](#configuration)
7. [Plugin System](#plugin-system)
8. [Custom Rules](#custom-rules)
9. [CI/CD Integration](#cicd-integration)
10. [Advanced Usage](#advanced-usage)
11. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Install
pip install -e .

# Scan local project
security-scan scan-local /path/to/project

# Scan remote URL
security-scan scan-url https://github.com/user/repo

# Black-box security test
security-scan scan-blackbox https://example.com

# Run benchmark
security-scan benchmark /path/to/project

# Check for updates
security-scan check-update
```

---

## Installation

### Standard Installation

```bash
# Clone repository
git clone https://github.com/your-repo/security-scan-cli.git
cd security-scan-cli

# Install with pip
pip install -e .
```

### Installation with Optional Dependencies

```bash
# Development tools
pip install -e ".[dev]"

# API server
pip install -e ".[server]"

# Everything
pip install -e ".[all]"
```

### Verify Installation

```bash
security-scan version
```

---

## Core Commands

### 1. Local Project Scan

Scan local files and directories for security issues.

```bash
security-scan scan-local <path> [OPTIONS]
```

**Arguments:**
- `path`: Path to file or directory to scan (required)

**Options:**
- `--output, -o`: Output directory for reports (default: `output`)
- `--format, -f`: Report format: `pdf`, `csv`, `json`, `html`, `all` (default: `all`)
- `--no-ai`: Disable AI verification
- `--quiet, -q`: Minimal output

**Examples:**

```bash
# Basic scan
security-scan scan-local .

# Scan with custom output directory
security-scan scan-local /project --output ./reports

# Generate only PDF reports
security-scan scan-local . --format pdf

# Disable AI verification
security-scan scan-local . --no-ai

# Quiet mode
security-scan scan-local . --quiet
```

**What it detects:**
- Hardcoded API keys, tokens, passwords
- AWS keys, Google API keys, GitHub tokens
- Security vulnerabilities (SQLi, XSS, etc.)
- Insecure configurations
- Dangerous code patterns

---

### 2. URL Scan

Scan remote URLs or Git repositories.

```bash
security-scan scan-url <url> [OPTIONS]
```

**Arguments:**
- `url`: URL to scan (required)

**Options:**
- `--output, -o`: Output directory for reports
- `--format, -f`: Report format
- `--quiet, -q`: Minimal output

**Examples:**

```bash
# Scan GitHub repository
security-scan scan-url https://github.com/user/repo

# Scan website
security-scan scan-url https://example.com

# Custom output
security-scan scan-url https://example.com --output ./url-reports
```

**What it checks:**
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Server information leaks
- SSL/TLS configuration
- robots.txt analysis
- Common path exposure
- Git repository scanning (if applicable)

---

### 3. Black-Box Security Test

Safe, passive security testing for web applications.

```bash
security-scan scan-blackbox <url> [OPTIONS]
```

**Arguments:**
- `url`: URL to test (required)

**Options:**
- `--output, -o`: Output directory
- `--format, -f`: Report format
- `--timeout, -t`: Request timeout in seconds (default: 30)
- `--quiet, -q`: Minimal output

**Examples:**

```bash
# Basic black-box test
security-scan scan-blackbox https://example.com

# With custom timeout
security-scan scan-blackbox https://example.com --timeout 60

# PDF report only
security-scan scan-blackbox https://example.com --format pdf
```

**Important:** Only performs SAFE, PASSIVE checks. No aggressive attacks.

**What it tests:**
- Security headers
- Cookie security (Secure, HttpOnly, SameSite flags)
- SSL/TLS configuration
- Common misconfigurations
- Information disclosure
- Directory listing
- Verbose error messages

---

### 4. Performance Benchmark

Measure scanning performance.

```bash
security-scan benchmark <target> [OPTIONS]
```

**Arguments:**
- `target`: Path or URL to benchmark (required)

**Options:**
- `--name, -n`: Benchmark name

**Examples:**

```bash
# Benchmark local scan
security-scan benchmark .

# Benchmark with name
security-scan benchmark . --name "v4.0.0-baseline"
```

**Metrics measured:**
- Scan duration
- Files/lines processed per second
- Peak memory usage
- Average CPU utilization
- Network metrics (for URL scans)

---

### 5. Additional Commands

```bash
# Check for updates
security-scan check-update

# Show version
security-scan version

# Interactive menu
security-scan menu
```

---

## Features

### Security Detection

#### 1. Secret Detection
- **Pattern-based matching**: 20+ built-in patterns
- **Entropy analysis**: Shannon entropy filtering
- **AI verification**: Reduce false positives by 90%+
- **Context capture**: View surrounding code

**Detected secrets:**
- API keys (AWS, Google, OpenAI, etc.)
- Authentication tokens (GitHub, JWT, etc.)
- Database passwords
- Private keys
- Authorization headers

#### 2. Vulnerability Detection
- **50+ vulnerability patterns**
- **OWASP Top 10 mapping**
- **CWE identification**
- **Language-specific rules** (20+ languages)

**Detected vulnerabilities:**
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Cryptographic failures
- Security misconfigurations
- Path traversal
- Insecure deserialization
- XXE, SSRF, and more

#### 3. Security Headers Analysis
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

---

## Report Formats

### PDF Reports

Professional PDF reports with:
- Title page with security grade
- Executive summary
- Findings by severity
- Detailed recommendations
- Metadata and timestamps

**Example:**
```bash
security-scan scan-local . --format pdf
# Generates: output/security_scan_report_20250115_143022.pdf
```

### CSV Exports

Structured CSV files for analysis:
- `*_secrets.csv`: All detected secrets
- `*_vulnerabilities.csv`: All vulnerabilities
- `*_statistics.csv`: Scan statistics
- `*_all_findings.csv`: Combined report

**Example:**
```bash
security-scan scan-local . --format csv
# Generates multiple CSV files in output/
```

### JSON Reports

Machine-readable JSON with complete scan data:
- All findings
- Statistics
- Configuration used
- Benchmark data
- Metadata

**Example:**
```bash
security-scan scan-local . --format json
# Generates: output/scan_YYYYMMDDHHMMSS_XXXXXXXX.json
```

### HTML Reports

Interactive HTML reports with:
- Charts and graphs
- Sortable tables
- Color-coded severity
- Responsive design

---

## Configuration

### Configuration Files

1. **config.yaml** - Main configuration
2. **rules.txt** - Secret detection patterns
3. **vulnerability_rules.yaml** - Vulnerability patterns
4. **custom_rules.yaml** - Your custom rules

### Sample config.yaml

```yaml
scan:
  entropy_threshold: 3.5
  max_file_size: 10485760  # 10MB
  enable_ai_verification: true
  enable_vulnerability_scan: true

  ignore_patterns:
    - "*.pyc"
    - "*/.git/*"
    - "*/node_modules/*"
    - "*/venv/*"

  scan_extensions:
    - .py
    - .js
    - .ts
    - .java
    - .php

ai:
  default_provider: "gemini"  # gemini | openai | claude
  max_retries: 5
  timeout: 30

report:
  output_dir: "output"
  default_formats: [html, json, pdf]
  auto_open_browser: false

performance:
  worker_threads: 4
  enable_cache: true
```

---

## Plugin System

### Creating a Custom Plugin

1. Create a Python file in `plugins/` directory
2. Inherit from `BasePlugin`
3. Implement required methods

**Example plugin:**

```python
# plugins/my_custom_plugin.py

from modules import BasePlugin, PluginMetadata, SeverityLevel

class MyCustomPlugin(BasePlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="my-custom-scanner",
            version="1.0.0",
            author="Your Name",
            description="Custom security scanner",
            enabled=True,
            dependencies=["requests"]
        )

    def scan(self, target, config):
        findings = []

        # Your custom scanning logic here
        # Example: scan for specific patterns

        return findings
```

### Using Plugins

```python
from modules import PluginManager

# Initialize plugin manager
plugin_manager = PluginManager(plugin_dir="plugins")

# Load all plugins
count = plugin_manager.load_plugins()
print(f"Loaded {count} plugins")

# Execute plugins
results = plugin_manager.execute_plugins(
    target="/path/to/scan",
    config={}
)
```

---

## Custom Rules

### Adding Custom Secret Patterns

Create `custom_rules.yaml`:

```yaml
custom_rules:
  - name: "Company API Key"
    pattern: "COMPANY_API_[A-Za-z0-9]{32}"
    severity: "high"
    category: "api_key"
    description: "Detects company-specific API keys"
    recommendation: "Move to environment variables"
    enabled: true
    languages: ["python", "javascript"]

  - name: "Database Connection String"
    pattern: "mongodb://[^\\s]+"
    severity: "critical"
    category: "credential"
    description: "Detects MongoDB connection strings"
    recommendation: "Use secret manager"
    enabled: true
    languages: []
```

### Adding to rules.txt

```text
# Custom pattern format: NAME:REGEX

INTERNAL_TOKEN:[Ii]nternal[-_]?[Tt]oken[\s:=]+['\"]?([A-Za-z0-9_-]{20,})['\"]?
PRIVATE_KEY:-----BEGIN PRIVATE KEY-----
CREDIT_CARD:\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install Security Scan CLI
        run: pip install security-scan-cli

      - name: Run scan
        run: |
          security-scan scan-local . --format json --quiet

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: output/

      - name: Fail on critical issues
        run: |
          # Parse JSON and fail if critical issues found
          python -c "import json; data=json.load(open('output/*.json')); exit(1) if data['statistics']['critical_count'] > 0 else exit(0)"
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.11
  script:
    - pip install security-scan-cli
    - security-scan scan-local . --format pdf
  artifacts:
    paths:
      - output/
    expire_in: 1 week
  allow_failure: true
```

---

## Advanced Usage

### Programmatic Usage

```python
from modules import LocalScanner, RulesEngine, PDFReportGenerator

# Initialize components
rules_engine = RulesEngine()
scanner = LocalScanner(
    rules_engine=rules_engine,
    entropy_threshold=3.5,
    num_threads=4
)

# Perform scan
result = scanner.scan("/path/to/project")

# Generate PDF report
pdf_gen = PDFReportGenerator(output_dir="reports")
pdf_path = pdf_gen.generate_report(result)

print(f"Scan complete! Report: {pdf_path}")
print(f"Security Grade: {result.statistics.security_grade}")
print(f"Total findings: {len(result.secrets) + len(result.vulnerabilities)}")
```

### Custom Reporting

```python
from modules import CSVExporter

# Export to CSV
csv_exporter = CSVExporter(output_dir="exports")
files = csv_exporter.export_complete_report(result)

for file_type, path in files.items():
    print(f"{file_type}: {path}")
```

### Benchmarking Integration

```python
from modules import PerformanceMonitor, ScanType

with PerformanceMonitor() as monitor:
    result = scanner.scan("/path/to/project")
    monitor.sample()

    benchmark = monitor.get_result(
        scan_type=ScanType.LOCAL,
        target="/path/to/project",
        files_scanned=result.statistics.total_files_scanned,
        lines_scanned=result.statistics.total_lines_scanned
    )

print(f"Duration: {benchmark.duration_seconds:.2f}s")
print(f"Files/sec: {benchmark.files_per_second:.2f}")
```

---

## Troubleshooting

### Common Issues

#### 1. Module Import Errors

```bash
# Solution: Reinstall in editable mode
pip uninstall security-scan-cli
pip install -e .
```

#### 2. AI Provider Errors

```bash
# Set API keys
export GEMINI_API_KEY="your-api-key"
export OPENAI_API_KEY="your-api-key"
export ANTHROPIC_API_KEY="your-api-key"

# Or disable AI
security-scan scan-local . --no-ai
```

#### 3. Permission Errors

```bash
# Run with appropriate permissions
sudo security-scan scan-local /system/path

# Or change output directory
security-scan scan-local . --output ~/reports
```

#### 4. Performance Issues

```yaml
# Reduce threads in config.yaml
performance:
  worker_threads: 2

# Increase max file size limit
scan:
  max_file_size: 52428800  # 50MB
```

### Debug Mode

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Then run scan
from modules import LocalScanner, RulesEngine
scanner = LocalScanner(RulesEngine())
result = scanner.scan(".")
```

---

## Best Practices

1. **Run scans regularly** - Integrate into CI/CD pipeline
2. **Review findings** - Not all findings are real issues
3. **Use AI verification** - Significantly reduces false positives
4. **Customize rules** - Add patterns specific to your organization
5. **Track metrics** - Use benchmarking to monitor performance
6. **Archive reports** - Keep historical records of scans
7. **Train your team** - Understand what the tool detects and why

---

## Support & Contributing

- **GitHub Issues**: https://github.com/your-repo/security-scan-cli/issues
- **Documentation**: See README.md
- **License**: MIT

---

**Security Scan CLI v4.0.0** - Professional security analysis for modern applications.
