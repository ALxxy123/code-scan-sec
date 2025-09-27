# Security Scan 🛡️

[![Security Scan CI](https://github.com/ALxxy123/code-scan-sec/actions/workflows/security_scan.yml/badge.svg)](https://github.com/ALxxy123/code-scan-sec/actions/workflows/security_scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/ALxxy123/code-scan-sec/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-lightgrey.svg)](https://github.com/ALxxy123/code-scan-sec)

A enterprise-grade, DevSecOps-focused security scanner designed to detect hardcoded secrets, API keys, passwords, and sensitive data in source code repositories. Built with performance and CI/CD integration in mind.

## 🎯 Why Security Scan?

In modern software development, **secrets management** is critical. A single exposed API key can lead to:
- **Data breaches** costing millions in damages
- **Compliance violations** (GDPR, SOX, HIPAA)
- **Reputation damage** and customer trust loss
- **Unauthorized access** to production systems

Security Scan provides **proactive protection** by catching secrets before they reach your repository, integrating seamlessly into your development workflow.

---

## ✨ Features

### 🚀 Core Capabilities
- **High-Performance Scanning**: Optimized Bash engine with parallel processing support
- **Regex-Based Detection**: Customizable pattern matching for various secret types
- **Smart Filtering**: Advanced ignore lists to minimize false positives
- **Multi-Format Reporting**: JSON, Markdown, and interactive HTML reports
- **Git Integration**: Pre-commit hooks and repository-wide scanning

### 🔧 DevSecOps Integration
- **CI/CD Ready**: Native GitHub Actions, GitLab CI, and Jenkins support
- **Slack Notifications**: Real-time alerts for security teams
- **Exit Code Strategy**: Fail builds automatically when secrets are detected
- **Audit Trail**: Complete scan history and violation tracking

### 🎛️ Enterprise Features
- **Custom Rule Sets**: Industry-specific detection patterns
- **Whitelist Management**: Exception handling for legitimate patterns
- **Performance Metrics**: Scan time and coverage statistics
- **Docker Support**: Containerized deployment for any environment

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Source Code   │───▶│  Security Scan   │───▶│   Reports &     │
│   Repository    │    │     Engine       │    │ Notifications   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Configuration   │
                    │  • rules.txt     │
                    │  • ignore.txt    │
                    │  • settings.conf │
                    └──────────────────┘
```

### Detection Patterns

The scanner identifies multiple categories of sensitive data:

| Category | Examples | Risk Level |
|----------|----------|------------|
| **API Keys** | AWS, Google Cloud, GitHub tokens | 🔴 Critical |
| **Database** | Connection strings, passwords | 🔴 Critical |
| **Credentials** | Username/password pairs | 🟡 High |
| **Certificates** | Private keys, SSL certificates | 🔴 Critical |
| **Cloud Secrets** | Service account keys, access tokens | 🔴 Critical |

---

## 🚀 Quick Start

### Prerequisites
- **Linux/macOS/WSL** environment
- **Bash 4.0+** and standard Unix tools (`grep`, `find`, `jq`)
- **Git** (optional, for repository integration)

### Installation Options

#### Option 1: System Installation (Recommended)
```bash
# Clone and install system-wide
git clone https://github.com/ALxxy123/code-scan-sec.git
cd code-scan-sec
sudo bash install.sh

# Verify installation
security-scan --version
```

#### Option 2: Docker Deployment
```bash
# Build the container
docker build -t security-scan:latest .

# Scan a project directory
docker run --rm \
  -v "$(pwd):/workspace" \
  security-scan:latest /workspace
```

#### Option 3: Portable Usage
```bash
# Clone and run directly
git clone https://github.com/ALxxy123/code-scan-sec.git
cd code-scan-sec
./bin/scan.sh /path/to/target/project
```

---

## 💻 Usage

### Basic Scanning
```bash
# Scan current directory
security-scan .

# Scan specific project with custom output
security-scan /path/to/project --output ./security-results

# Generate specific report formats
security-scan . --format json,html --verbose
```

### Advanced Configuration
```bash
# Use custom rules file
security-scan . --rules /path/to/custom-rules.txt

# Exclude specific directories
security-scan . --ignore "node_modules,*.log,build/"

# Performance mode for large repositories
security-scan . --parallel --max-depth 10
```

### Output Examples

**JSON Report Structure:**
```json
{
  "scan_info": {
    "timestamp": "2024-03-15T10:30:00Z",
    "target_path": "/home/user/project",
    "files_scanned": 247,
    "scan_duration": "1.2s"
  },
  "findings": [
    {
      "file": "src/config/database.js",
      "line": 15,
      "type": "database_password",
      "severity": "critical",
      "pattern_matched": "password=.*",
      "context": "const dbPassword = 'super_secret_123';"
    }
  ],
  "summary": {
    "total_findings": 3,
    "critical": 2,
    "high": 1,
    "medium": 0
  }
}
```

---

## 🔧 Configuration

### Rules Configuration (`config/rules.txt`)
```bash
# API Keys
aws_access_key:AKIA[0-9A-Z]{16}
github_token:ghp_[a-zA-Z0-9]{36}
google_api:AIza[0-9A-Za-z\\-_]{35}

# Database Connections
db_connection:mongodb://.*:.*@
mysql_conn:mysql://.*:.*@

# Generic Secrets
private_key:-----BEGIN.*PRIVATE KEY-----
password_field:password\s*[:=]\s*["\'].*["\']
```

### Ignore Patterns (`config/ignore.txt`)
```bash
# Directories
node_modules/
.git/
build/
dist/
coverage/

# File Types
*.log
*.tmp
*.cache
*.min.js
*.map

# Specific Files
package-lock.json
yarn.lock
README.md
```

### Environment Variables
```bash
# Slack Integration
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export SLACK_CHANNEL="#security-alerts"

# Performance Tuning
export SCAN_MAX_PARALLEL=4
export SCAN_TIMEOUT=300

# Output Control
export SCAN_VERBOSE=true
export SCAN_COLOR_OUTPUT=true
```

---

## 🤖 CI/CD Integration

### GitHub Actions
Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    name: 🛡️ Security Scan
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout Repository
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Setup Security Scanner
      run: |
        git clone https://github.com/ALxxy123/code-scan-sec.git scanner
        sudo bash scanner/install.sh
    
    - name: Run Security Scan
      run: |
        security-scan . --format json,html
        
        # Check if any secrets were found
        findings=$(jq '.summary.total_findings' scanner/output/results.json)
        
        if [ "$findings" -gt 0 ]; then
          echo "::error::🚨 Security scan failed! Found $findings potential secrets"
          echo "::error::Check the generated report for details"
          exit 1
        fi
        
        echo "✅ Security scan passed - no secrets detected"
    
    - name: Upload Security Report
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-report
        path: scanner/output/
        
    - name: Notify Security Team
      if: failure()
      env:
        SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK_URL }}
      run: |
        curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 Security Alert: Secrets detected in ${{ github.repository }} - Branch: ${{ github.ref_name }}\"}" \
        $SLACK_WEBHOOK
```

### GitLab CI
Add to `.gitlab-ci.yml`:

```yaml
security_scan:
  stage: test
  image: ubuntu:latest
  before_script:
    - apt-get update && apt-get install -y git jq curl
    - git clone https://github.com/ALxxy123/code-scan-sec.git scanner
    - bash scanner/install.sh
  script:
    - security-scan . --format json
    - |
      findings=$(jq '.summary.total_findings' scanner/output/results.json)
      if [ "$findings" -gt 0 ]; then
        echo "Security scan failed! Found $findings potential secrets"
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - scanner/output/
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

---

## 📊 Performance & Benchmarks

### Scan Performance
| Repository Size | Files | Scan Time | Memory Usage |
|----------------|-------|-----------|--------------|
| Small (< 100 files) | 50 | 0.3s | 15MB |
| Medium (< 1K files) | 500 | 1.2s | 45MB |
| Large (< 10K files) | 5,000 | 8.5s | 120MB |
| Enterprise (10K+ files) | 25,000 | 35s | 300MB |

### Optimization Tips
- **Use `.gitignore` patterns**: Automatically excludes unnecessary files
- **Parallel processing**: Enable with `--parallel` flag for large repositories
- **Selective scanning**: Use `--include` patterns for targeted scans
- **Docker caching**: Pre-build containers for faster CI/CD execution

---

## 🔍 Troubleshooting

### Common Issues

**Q: Scanner reports false positives**
```bash
# Add patterns to ignore.txt or use custom rules
echo "test_password_123" >> config/ignore.txt
security-scan . --ignore-pattern "test_.*"
```

**Q: Performance issues on large repositories**
```bash
# Enable parallel processing and limit depth
security-scan . --parallel --max-depth 5 --exclude "node_modules,vendor"
```

**Q: CI/CD integration failing**
```bash
# Check exit codes and permissions
security-scan . --exit-zero  # Don't fail build, just report
sudo chown -R $(id -u):$(id -g) scanner/output/
```

### Debug Mode
```bash
# Enable verbose logging
export SCAN_DEBUG=true
security-scan . --verbose --log-file debug.log
```

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/code-scan-sec.git
cd code-scan-sec

# Create a feature branch
git checkout -b feature/new-detection-rule

# Make your changes and test
./bin/scan.sh test/sample-project

# Submit a pull request
```

### Adding New Detection Rules
1. **Research the pattern**: Study the secret format and create a precise regex
2. **Test thoroughly**: Ensure low false positive rate
3. **Document the rule**: Add comments explaining the pattern
4. **Submit with examples**: Include test cases in your PR

### Code Style Guidelines
- **Shell scripting**: Follow [Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
- **Documentation**: Use clear, concise comments
- **Error handling**: Implement proper error checking and user feedback
- **Performance**: Consider impact on scan speed

---



## 🙏 Acknowledgments

- **OWASP** for security best practices and guidelines
- **TruffleHog** and **GitLeaks** for inspiration on detection patterns
- **DevSecOps Community** for feedback and contributions
- **Open Source Contributors** who help improve this tool

---

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/ALxxy123/code-scan-sec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ALxxy123/code-scan-sec/discussions)
- **Security Reports**: Please report security vulnerabilities privately via email
- **Feature Requests**: Use GitHub Issues with the "enhancement" label
- **Connect with Developer**: [Social Media & Links](https://v0-social-media-dashboard-ebon.vercel.app)

---

**Made with ❤️ by [Ahmed Mubaraki](https://github.com/ALxxy123) | ETRA Development**
