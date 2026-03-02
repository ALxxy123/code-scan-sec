# 🛡️ Security Scan CLI - Professional Security Analysis Suite

[![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)](https://github.com/ALxxy123/code-scan-sec)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

**The most advanced, professional security scanning tool** for modern developers. Detect secrets, vulnerabilities, and security misconfigurations with AI-powered analysis, PDF reports, and extensible plugin architecture.

---

## 🚀 What's New in v4.0.0

**Complete redesign and upgrade** - The most significant release yet!

### 🎯 Major Features

✅ **Professional PDF Reports** - Beautiful, comprehensive PDF reports with:
  - Title page with security grade
  - Executive summary
  - Detailed findings with recommendations
  - Color-coded severity levels
  - Metadata and timestamps

✅ **CSV Data Export** - Export scan results to CSV for analysis:
  - Secrets export
  - Vulnerabilities export
  - Statistics summary
  - Combined findings report

✅ **Modular Architecture** - Clean, professional code structure:
  - Separate `modules/` package
  - Pydantic data models
  - Type-safe interfaces
  - Easy to extend and maintain

✅ **Plugin System** - Extensible plugin architecture:
  - Create custom scanners
  - Load plugins dynamically
  - Plugin dependency management
  - Configure plugins via YAML

✅ **Enhanced Rules Engine** - Advanced rule management:
  - Custom rule support
  - Rule import/export
  - Dynamic rule updates
  - Rule search and filtering

✅ **Update Checker** - Stay current automatically:
  - Check PyPI for updates
  - GitHub release notifications
  - Cached results
  - Upgrade instructions

✅ **Improved CLI** - Clear, English-only professional interface:
  - Simple command structure
  - Rich formatted output
  - Progress bars
  - Interactive menu

✅ **Performance Monitoring** - Comprehensive benchmarking:
  - Scan duration tracking
  - Memory usage monitoring
  - CPU utilization
  - Throughput metrics

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Commands](#-commands)
- [Report Formats](#-report-formats)
- [Configuration](#-configuration)
- [Plugin Development](#-plugin-development)
- [CI/CD Integration](#-cicd-integration)
- [Documentation](#-documentation)
- [License](#-license)

---

## ✨ Features

### 🔍 Local Project Scanner

Scan your codebase for security issues:
- **Secret Detection**: API keys, tokens, passwords, AWS keys
- **Entropy Analysis**: Shannon entropy-based filtering
- **Pattern Matching**: 20+ built-in patterns
- **AI Verification**: Reduce false positives by 90%+
- **Vulnerability Detection**: 50+ security patterns
- **OWASP Mapping**: Based on OWASP Top 10
- **CWE Identification**: Common Weakness Enumeration

### 🌐 URL Security Scanner

Analyze remote websites and repositories:
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **SSL/TLS Checks**: Certificate validation, protocol versions
- **Information Leaks**: Server headers, version disclosure
- **robots.txt Analysis**: Sensitive path exposure
- **Git Repository Scanning**: Clone and analyze repos
- **Response Analysis**: HTTP header inspection

### 🎯 Black-Box Testing

Safe, passive security testing:
- **Header Analysis**: Complete security header checks
- **Cookie Security**: Secure, HttpOnly, SameSite flags
- **TLS Configuration**: Version and cipher checks
- **Misconfiguration Detection**: Common security issues
- **Passive Vulnerability Checks**: Information disclosure

### 📊 Performance Benchmarking

Measure and track performance:
- **Scan Metrics**: Duration, files/sec, lines/sec
- **Resource Monitoring**: Memory and CPU usage
- **Historical Tracking**: Compare over time
- **Network Metrics**: Latency and bandwidth (URL scans)

### 📄 Professional Reports

Multiple export formats:
- **PDF**: Professional reports with charts and recommendations
- **CSV**: Structured data for spreadsheet analysis
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Interactive web reports

### 🔌 Plugin System

Extend functionality:
- **Custom Scanners**: Write your own detection logic
- **Plugin API**: Easy-to-use base classes
- **Dynamic Loading**: Load plugins at runtime
- **Configuration**: YAML-based plugin config

### 🎨 Modern UI

Beautiful, professional interface:
- **Rich Formatting**: Color-coded output
- **Progress Bars**: Real-time scan progress
- **Tables**: Organized findings display
- **Security Grades**: A+ to F scoring
- **Interactive Menu**: Easy navigation

---

## 🔧 Installation

### Quick Install

```bash
# Clone repository
git clone https://github.com/ALxxy123/code-scan-sec.git
cd code-scan-sec

# Install
pip install -e .
```

### With Optional Dependencies

```bash
# Development tools
pip install -e ".[dev]"

# API server
pip install -e ".[server]"

# Everything
pip install -e ".[all]"
```

### Requirements

- Python 3.8+
- pip
- Git (for repository scanning)

---

## 🚀 Quick Start

### 1. Scan Local Project

```bash
security-scan scan-local .
```

### 2. Scan Remote URL

```bash
security-scan scan-url https://github.com/user/repo
```

### 3. Black-Box Test

```bash
security-scan scan-blackbox https://example.com
```

### 4. Run Benchmark

```bash
security-scan benchmark .
```

### 5. Check for Updates

```bash
security-scan check-update
```

---

## 📖 Commands

### `scan-local` - Scan Local Project

Scan files and directories for security issues.

```bash
security-scan scan-local <path> [OPTIONS]
```

**Options:**
- `--output, -o`: Output directory (default: `output`)
- `--format, -f`: Report format: `pdf`, `csv`, `json`, `html`, `all` (default: `all`)
- `--no-ai`: Disable AI verification
- `--quiet, -q`: Minimal output

**Example:**
```bash
security-scan scan-local /path/to/project --format pdf --output ./reports
```

---

### `scan-url` - Scan Remote URL

Analyze remote websites or repositories.

```bash
security-scan scan-url <url> [OPTIONS]
```

**Options:**
- `--output, -o`: Output directory
- `--format, -f`: Report format
- `--quiet, -q`: Minimal output

**Example:**
```bash
security-scan scan-url https://github.com/user/repo
```

---

### `scan-blackbox` - Black-Box Testing

Perform safe security testing on web applications.

```bash
security-scan scan-blackbox <url> [OPTIONS]
```

**Options:**
- `--output, -o`: Output directory
- `--format, -f`: Report format
- `--timeout, -t`: Timeout in seconds (default: 30)
- `--quiet, -q`: Minimal output

**Example:**
```bash
security-scan scan-blackbox https://example.com --timeout 60
```

---

### `benchmark` - Performance Benchmark

Measure scanning performance.

```bash
security-scan benchmark <target> [OPTIONS]
```

**Options:**
- `--name, -n`: Benchmark name

**Example:**
```bash
security-scan benchmark . --name "baseline-v4"
```

---

### `check-update` - Check for Updates

Check for new versions.

```bash
security-scan check-update
```

---

### `version` - Show Version

Display version information.

```bash
security-scan version
```

---

### `menu` - Interactive Menu

Launch interactive menu.

```bash
security-scan menu
```

---

## 📊 Report Formats

### PDF Reports

Professional PDF reports include:
- **Title Page**: Security grade and scan metadata
- **Executive Summary**: Key statistics and metrics
- **Findings**: Detailed list with severity colors
- **Recommendations**: Actionable remediation steps
- **Metadata**: Timestamps, version, scan ID

**Generated files:** `output/security_scan_report_TIMESTAMP.pdf`

### CSV Exports

Multiple CSV files for analysis:
- `*_secrets.csv`: All secret findings
- `*_vulnerabilities.csv`: All vulnerabilities
- `*_statistics.csv`: Scan statistics
- `*_all_findings.csv`: Combined report

**Generated files:** `output/security_scan_TIMESTAMP_*.csv`

### JSON Reports

Complete machine-readable data:
- All findings with full details
- Statistics and metrics
- Configuration snapshot
- Benchmark results
- Metadata

**Generated files:** `output/scan_ID.json`

---

## ⚙️ Configuration

### Main Configuration (`config.yaml`)

```yaml
scan:
  entropy_threshold: 3.5
  max_file_size: 10485760
  enable_ai_verification: true
  enable_vulnerability_scan: true

  ignore_patterns:
    - "*.pyc"
    - "*/.git/*"
    - "*/node_modules/*"

ai:
  default_provider: "gemini"
  max_retries: 5
  timeout: 30

report:
  output_dir: "output"
  default_formats: [html, json, pdf]

performance:
  worker_threads: 4
  enable_cache: true
```

### Custom Rules (`custom_rules.yaml`)

```yaml
custom_rules:
  - name: "Company API Key"
    pattern: "COMPANY_API_[A-Za-z0-9]{32}"
    severity: "high"
    category: "api_key"
    description: "Detects company API keys"
    recommendation: "Move to environment variables"
    enabled: true
    languages: ["python", "javascript"]
```

---

## 🔌 Plugin Development

### Creating a Plugin

1. Create file in `plugins/` directory
2. Inherit from `BasePlugin`
3. Implement required methods

**Example:**

```python
from modules import BasePlugin, PluginMetadata

class MyPlugin(BasePlugin):
    def get_metadata(self):
        return PluginMetadata(
            name="my-scanner",
            version="1.0.0",
            author="Your Name",
            description="Custom scanner",
            enabled=True
        )

    def scan(self, target, config):
        findings = []
        # Your scanning logic
        return findings
```

### Using Plugins

```python
from modules import PluginManager

plugin_manager = PluginManager()
plugin_manager.load_plugins()
results = plugin_manager.execute_plugins(target=".", config={})
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install scanner
        run: pip install security-scan-cli

      - name: Run scan
        run: security-scan scan-local . --format json

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: output/
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
```

---

## 📚 Documentation

- **[Usage Guide](USAGE_GUIDE.md)** - Complete usage documentation
- **[API Documentation](docs/API.md)** - Programmatic usage
- **[Plugin Guide](docs/PLUGINS.md)** - Plugin development
- **[Configuration](docs/CONFIGURATION.md)** - Advanced configuration
- **[Examples](examples/)** - Sample code and workflows

---

## 🎯 Use Cases

- **Continuous Security**: Integrate into CI/CD pipelines
- **Code Review**: Scan before code reviews
- **Compliance**: Meet security compliance requirements
- **Audit**: Regular security audits
- **Education**: Learn about security vulnerabilities
- **Bug Bounty**: Find vulnerabilities in web apps

---

## 🔒 Security & Privacy

- **Safe Scanning**: No code is sent to external services (except AI verification)
- **Local Processing**: All scanning happens locally
- **No Telemetry**: No usage data collected
- **Open Source**: Full transparency

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- OWASP for security standards
- CWE for vulnerability classifications
- Community contributors

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ALxxy123/code-scan-sec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ALxxy123/code-scan-sec/discussions)
- **Documentation**: [Full Docs](USAGE_GUIDE.md)

---

## 🗺️ Roadmap

**Planned for v4.1:**
- Dockerfile scanning
- Kubernetes manifest analysis
- Infrastructure as Code (Terraform, CloudFormation)
- Enhanced web dashboard
- VS Code extension

**Planned for v4.2:**
- Machine learning-based detection
- SARIF format support
- Integration with SIEM systems
- Custom report templates

---

**Security Scan CLI v4.0.0** - Secure your code, protect your applications.

Made with ❤️ by the security community.
