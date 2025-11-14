# 🛡️ Enhanced AI-Powered Security Scanner

[![Version](https://img.shields.io/badge/version-3.2.0-blue.svg)](https://github.com/ALxxy123/code-scan-sec)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

**The most advanced open-source security scanner** that detects hardcoded secrets, API keys, passwords, **AND** security vulnerabilities using AI-powered verification.

## ✨ What's New in v3.2.0

🚀 **Major new features:**
- 🌐 **Remote URL Scanning** - Scan GitHub repos, GitLab projects, and archives directly from URLs
- 🎯 **Black Box Testing** - Comprehensive web application security testing (SQL injection, XSS, security headers, etc.)
- 📊 **Performance Benchmarking** - Track scan performance, resource usage, and compare with baselines
- ⚡ **Enhanced Performance** - Optimized scanning with detailed metrics and monitoring

## ✨ What's New in v3.1.0

🚀 **Major enhancements:**
- 🎨 **Beautiful Terminal UI** - Stunning, professional CLI interface with:
  - ✨ ASCII art banner and colorful output
  - 📊 Real-time progress bars with file count and ETA
  - 📈 Security score grading system (A+ to F)
  - 🎯 Interactive scan configuration wizard
  - 📋 Detailed vulnerability cards with recommendations
  - 🌈 Color-coded severity levels
- 🔧 **Auto-Fix Engine** - Automatically fix vulnerabilities (MD5→SHA256, secrets→env vars)
- 🔄 **CI/CD Integration** - Ready-to-use GitHub Actions workflows
- 🌐 **Web Dashboard** - Real-time monitoring with interactive interface
- 🗄️ **Database Backend** - Track scan history and trends (SQLite/PostgreSQL)
- 🐛 **Advanced Vulnerability Detection** - 50+ vulnerability types
- 🤖 **Multi-AI Support** - Gemini, OpenAI, and Claude
- 📊 **Enhanced Reporting** - Beautiful HTML reports
- ⚡ **Performance Improvements** - Faster with better accuracy

---

## 🎯 Features

### 🌐 Remote URL Scanning (NEW in v3.2!)
- **Git Repository Cloning**: Clone and scan repositories from GitHub, GitLab, Bitbucket, etc.
- **Archive Support**: Download and scan zip, tar.gz, tar.bz2, tar.xz archives
- **Automatic Cleanup**: Temporary files cleaned up automatically
- **Progress Tracking**: Visual progress bars for downloads and cloning
- **Shallow Cloning**: Fast shallow clones for quick scans
- **All Scan Features**: Full secret detection and vulnerability scanning on remote code

### 🎯 Black Box Testing (NEW in v3.2!)
- **Security Headers**: Comprehensive security header analysis (HSTS, CSP, X-Frame-Options, etc.)
- **SSL/TLS Testing**: Certificate validation, TLS version checks, cipher strength
- **SQL Injection**: Automated SQL injection testing with multiple payloads
- **XSS Detection**: Cross-site scripting vulnerability testing (reflected, stored)
- **Path Traversal**: Directory traversal vulnerability detection
- **Command Injection**: OS command injection testing
- **Cookie Security**: Secure and HttpOnly flag validation
- **Detailed Reports**: JSON and HTML reports with remediation guidance

### 📊 Performance Benchmarking (NEW in v3.2!)
- **Comprehensive Metrics**: Duration, throughput, CPU, memory usage tracking
- **Historical Tracking**: Save and compare benchmark results over time
- **Baseline Comparison**: Compare current scan with historical baselines
- **AI Performance**: Track AI API response times and call counts
- **Resource Monitoring**: Real-time CPU and memory usage monitoring
- **Optimization Insights**: Identify performance bottlenecks and improvements
- **Beautiful Reports**: Rich terminal output with comparison tables

### 🔧 Auto-Fix Engine
- **Weak Cryptography**: Automatically upgrades MD5/SHA1 to SHA256
- **Hardcoded Secrets**: Moves secrets to environment variables with .env.example generation
- **SQL Injection**: Suggests parameterized queries
- **Dangerous Functions**: Replaces eval() with ast.literal_eval(), warns about exec()
- **XSS Vulnerabilities**: Suggests proper HTML escaping
- **Interactive Mode**: Review each fix before applying
- **Dry Run**: Preview changes without modifying files
- **Automatic Backups**: Creates .backup files for safety

### 🔐 Secret Detection
- **Hardcoded Credentials**: Passwords, API keys, tokens
- **Cloud Provider Keys**: AWS, Google Cloud, Azure
- **Service Tokens**: GitHub, Slack, Stripe, etc.
- **AI Verification**: Reduces false positives by 90%+
- **Entropy Analysis**: Smart filtering of high-randomness strings

### 🐛 Vulnerability Detection
- **Injection Attacks**: SQL, Command, LDAP, XPath
- **Cross-Site Scripting (XSS)**: DOM, Reflected, Stored
- **Cryptographic Failures**: Weak algorithms, hardcoded keys
- **Security Misconfigurations**: Debug mode, CORS, error display
- **Dangerous Functions**: eval(), exec(), unserialize()
- **Path Traversal**: Directory traversal vulnerabilities
- **SSRF**: Server-side request forgery
- **XXE**: XML external entity attacks
- **50+ Detection Rules** based on OWASP Top 10 & CWE

### 🌐 Web Dashboard & API
- **FastAPI REST API**: RESTful API for scan management
- **WebSocket Support**: Real-time scan progress updates
- **Interactive Dashboard**: Modern web UI with live statistics
- **Scan History**: Track all scans with detailed results
- **Background Processing**: Asynchronous scan execution
- **API Documentation**: Auto-generated OpenAPI/Swagger docs

### 🤖 AI Providers
- **Google Gemini** (Fast & Accurate)
- **OpenAI ChatGPT** (Reliable)
- **Anthropic Claude** (Advanced Reasoning)

### 📊 Reporting
- **HTML**: Beautiful, professional reports with charts
- **Markdown**: GitHub-friendly documentation
- **JSON**: Machine-readable for CI/CD integration
- **Text**: Simple, readable console output

### 🎨 Beautiful Terminal UI (NEW in v3.1!)
Experience a **stunning, professional CLI interface** that makes security scanning enjoyable:

#### ✨ ASCII Art Banner
```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗  ║
║     ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝  ║
║     ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝   ║
║              🛡️  AI-Powered Security Scanner v3.1.0  🛡️               ║
╚═══════════════════════════════════════════════════════════════════════╝
```

#### 📊 Real-Time Progress Tracking
```
🔍 Scanning: ████████████████░░░░░░░░ 75% • 180/240 files • ⏱️ 3m 45s
   Current: src/auth/login.py:127
   Found: 🔑 3 secrets | 🐛 12 vulnerabilities
```

#### 📈 Security Score Grading (A+ to F)
Get an instant security assessment:
```
🎯 Security Score:
███████████████████████████████████░░░░░░░░░░░░░░░

✅ Grade: A (87/100) - Excellent Security!
```

Score calculation:
- **A+ (95-100)**: 🏆 Outstanding security
- **A (85-94)**: ✅ Excellent security
- **B (75-84)**: 👍 Good security
- **C (60-74)**: ⚠️ Fair security - needs attention
- **D (50-59)**: 🔴 Poor security - urgent fixes needed
- **F (0-49)**: 🚨 Critical - immediate action required

#### 🎯 Interactive Configuration Wizard
Beautiful step-by-step setup:
```
🔍 Interactive Scan Configuration

Select scan mode:
  1. Quick Scan - Secrets only (fast) ⚡
  2. Full Scan - Secrets + Vulnerabilities (recommended) 🛡️
  3. Custom Scan - Configure manually ⚙️

Choice [2]: 2

Select AI provider:
  1. Google Gemini - Fast & accurate
  2. OpenAI - Reliable
  3. Anthropic Claude - Advanced reasoning

Choice [1]: 1
```

#### 📋 Detailed Vulnerability Cards
Professional vulnerability display with recommendations:
```
╭────────────────────────────── Vulnerability #1 ───────────────────────────╮
│                                                                            │
│  🔴 SQL Injection (CRITICAL)                                               │
│                                                                            │
│  Location: src/database/queries.py:45                                     │
│  Category: sql_injection                                                   │
│  CWE: CWE-89 | OWASP: A03:2021 - Injection                                │
│                                                                            │
│  ⚠️  Issue:                                                                 │
│  SQL query built using string concatenation, allowing potential SQL       │
│  injection attacks from untrusted user input.                             │
│                                                                            │
│  ✅ Recommendation:                                                        │
│  Use parameterized queries or prepared statements:                        │
│    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))         │
│                                                                            │
│  🔧 Auto-fix available! Run: security-scan auto-fix --path .              │
│                                                                            │
╰────────────────────────────────────────────────────────────────────────────╯
```

#### 🌈 Color-Coded Severity Levels
- 🔴 **Critical** - Immediate action required
- 🟠 **High** - Fix soon
- 🟡 **Medium** - Should be addressed
- 🔵 **Low** - Consider fixing
- ⚪ **Info** - Informational

#### 🏆 Top Vulnerability Categories
Visual bar charts in terminal:
```
🏆 Top Vulnerability Categories:

████████████████████████████████████████ dangerous_functions: 12
████████████████████████░░░░░░░░░░░░░░░░ sql_injection: 8
████████████████░░░░░░░░░░░░░░░░░░░░░░░░ xss: 5
████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ weak_crypto: 4
████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ command_injection: 3
```

#### 💡 Smart Next Steps
Context-aware recommendations:
```
╭──────────────────── 📋 Recommended Next Steps ────────────────────────╮
│                                                                        │
│  🚨 URGENT: Review and fix critical issues immediately                 │
│                                                                        │
│  🔑 Run auto-fix to move secrets to environment variables:             │
│     $ security-scan auto-fix --path . --fix-types secrets             │
│                                                                        │
│  🔧 Run auto-fix to automatically fix vulnerabilities:                 │
│     $ security-scan auto-fix --path .                                  │
│                                                                        │
│  📊 Generate detailed report:                                          │
│     $ security-scan scan --path . --output all                         │
│                                                                        │
│  📈 View in web dashboard:                                             │
│     $ python api_server.py                                             │
│                                                                        │
╰────────────────────────────────────────────────────────────────────────╯
```

#### 🎭 Try the Demo!
See the beautiful interface without running a real scan:
```bash
security-scan demo
```

This shows:
- ✨ Full UI with example data
- 📊 Sample vulnerability reports
- 🎯 Security score calculation
- 💡 All UI components in action

---

## 🚀 Quick Start

### Installation

**Using pipx (Recommended):**
```bash
# Install pipx if you don't have it
pip install pipx

# Install the scanner globally
pipx install security-scan-cli
```

**From source:**
```bash
git clone https://github.com/ALxxy123/code-scan-sec.git
cd code-scan-sec
pip install -e .
```

### Basic Usage

**🎨 See the Beautiful UI (Demo):**
```bash
# Show beautiful interface demo with example results
security-scan demo

# Show version info with ASCII banner
security-scan version
```

**🎯 Interactive Mode (Recommended for First-Time Users):**
```bash
security-scan interactive
```

This launches a beautiful wizard that guides you through:
- 📊 Scan mode selection (Quick/Full/Custom)
- 🤖 AI provider selection (Gemini/OpenAI/Claude)
- 📁 Path selection with validation
- ✨ Beautiful progress bars and real-time statistics
- 📈 Security score grading (A+ to F)
- 🎯 Detailed vulnerability cards
- 💡 Recommended next steps

**⚡ Automated Mode (For CI/CD & Scripts):**
```bash
# Full scan with AI and vulnerabilities
export GEMINI_API_KEY="your-key-here"
security-scan scan --path . --ai-provider gemini

# Secrets only, no AI
security-scan scan --path . --no-ai --no-vuln --output json

# Vulnerabilities only
security-scan scan --path . --no-ai --output html
```

---

## 💻 Usage Examples

### 🌐 New in v3.2.0 - Remote URL Scanning

#### 1. Scan a GitHub Repository
```bash
# Scan a public GitHub repository
security-scan scan-url https://github.com/username/repo

# With AI verification
export GEMINI_API_KEY="your-key"
security-scan scan-url https://github.com/username/repo --ai-provider gemini

# Full scan with all reports
security-scan scan-url https://github.com/username/repo --output all
```

#### 2. Scan a GitLab Project
```bash
security-scan scan-url https://gitlab.com/username/project
```

#### 3. Scan from Archive URL
```bash
# Scan a zip archive
security-scan scan-url https://example.com/project.zip

# Scan a tar.gz archive
security-scan scan-url https://example.com/release.tar.gz
```

### 🎯 Black Box Testing

#### 4. Test Web Application Security
```bash
# Basic black box test
security-scan blackbox https://example.com

# With custom timeout and JSON output
security-scan blackbox https://app.example.com --timeout 15 --output json

# Full test with HTML report
security-scan blackbox https://api.example.com --output html
```

**Tests include:**
- ✅ Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- ✅ SSL/TLS configuration testing
- ✅ SQL injection detection
- ✅ XSS (Cross-Site Scripting) testing
- ✅ Path traversal vulnerability detection
- ✅ Command injection testing
- ✅ Cookie security analysis

### 📊 Performance Benchmarking

#### 5. Benchmark Your Scans
```bash
# Run benchmark on a project
security-scan benchmark-scan /path/to/project

# Create a named baseline
security-scan benchmark-scan /path/to/project --name "baseline-v1"

# Run without comparison
security-scan benchmark-scan /path/to/project --no-compare
```

**Metrics tracked:**
- ⚡ Scan duration and throughput (files/sec, lines/sec)
- 💾 Peak memory usage
- 🔄 CPU utilization
- 🤖 AI API performance (response times, call count)
- 📈 Historical comparisons and trend analysis

### 🎨 UI Features (v3.1.0)

#### 1. See the Beautiful Demo
Perfect for first-time users or presentations:
```bash
security-scan demo
```

**What you'll see:**
- ✨ Full ASCII art banner
- 📊 Example scan results with beautiful formatting
- 🎯 Security score grading demo
- 📋 Vulnerability cards with recommendations
- 💡 All UI features in action

**Output example:**
```
╔═══════════════════════════════════════════════════════════════╗
║           🛡️  AI-Powered Security Scanner v3.1.0  🛡️          ║
╚═══════════════════════════════════════════════════════════════╝

🎯 Security Score: ███████████████████████████░░░░░░░░░░░░

⚠️ Grade: C (63/100)
```

#### 2. Interactive Mode with Beautiful Wizard
Best for manual scans and learning:
```bash
security-scan interactive
```

**Features:**
- 🎯 Step-by-step configuration
- 📊 Real-time progress bars
- 📈 Live statistics during scan
- 🎨 Color-coded results
- 💡 Context-aware recommendations

**Perfect for:**
- First-time users
- Exploring features
- Manual security audits
- Learning the tool

#### 3. Automated Scan with Beautiful Output
For regular security checks:
```bash
security-scan scan --path .
```

**What you get:**
- ✨ Professional ASCII banner
- 📊 Real-time progress: `████████░░░░ 65% • 234/360 files`
- 📈 Security score: `Grade: A (87/100)`
- 🎯 Detailed vulnerability cards
- 💡 Recommended next steps

### 🔐 Secret Detection

#### 4. Scan with AI Verification
```bash
export GEMINI_API_KEY="your-key-here"
security-scan scan --path . --ai-provider gemini
```

**Output shows:**
```
🔑 Detected Secrets:

╭───────────────────────── Secret #1 ─────────────────────────╮
│                                                              │
│  Type: API Key                                               │
│  Location: src/config.py:45                                  │
│  ✅ AI Verified                                              │
│                                                              │
│  Matched Text: sk-1234567890abcdef...                        │
│                                                              │
╰──────────────────────────────────────────────────────────────╯
```

#### 5. Scan with Different AI Providers
```bash
# Use Claude (best reasoning)
export ANTHROPIC_API_KEY="sk-ant-..."
security-scan scan --path . --ai-provider claude

# Use OpenAI (most reliable)
export OPENAI_API_KEY="sk-..."
security-scan scan --path . --ai-provider openai
```

### 🐛 Vulnerability Detection

#### 6. Full Vulnerability Scan
```bash
security-scan scan --path . --output all
```

**Beautiful vulnerability cards:**
```
╭──────────────── Vulnerability #1 ─────────────────╮
│                                                    │
│  🔴 SQL Injection (CRITICAL)                       │
│  Location: queries.py:45                           │
│  CWE: CWE-89 | OWASP: A03:2021                    │
│                                                    │
│  ⚠️  Issue: String concatenation in SQL query      │
│  ✅ Fix: Use parameterized queries                │
│  🔧 Auto-fix available!                           │
│                                                    │
╰────────────────────────────────────────────────────╯
```

#### 7. Quick Scan for CI/CD
Minimal output for automation:
```bash
security-scan scan --path . --no-ai --quiet
```

### 5. Auto-Fix Vulnerabilities
```bash
# Dry run - see what would be fixed
security-scan auto-fix --path . --dry-run

# Fix all issues interactively
security-scan auto-fix --path ./src

# Fix specific types only
security-scan auto-fix --path . --fix-types crypto secrets

# Non-interactive mode
security-scan auto-fix --path . --no-interactive
```

### 6. Web Dashboard & API Server
```bash
# Install with server dependencies
pip install "security-scan-cli[server]"

# Start the API server
python api_server.py
# Or if installed globally
uvicorn api_server:app --reload

# Access dashboard at http://localhost:8000/dashboard.html
# API docs at http://localhost:8000/docs
```

### 7. Install Git Pre-Commit Hook
```bash
cd /your/git/repo
security-scan install-hook
```

---

## ⚙️ Configuration

Create `config.yaml` in your project root to customize settings:

```yaml
scan:
  entropy_threshold: 3.5
  enable_ai_verification: true
  enable_vulnerability_scan: true

ai:
  default_provider: gemini
  max_retries: 5

vulnerabilities:
  severity_levels:
    - critical
    - high
    - medium
  categories:
    - sql_injection
    - xss
    - command_injection

report:
  output_dir: output
  default_formats:
    - html
    - json
  auto_open_browser: true
```

---

## 🔑 API Keys

### Google Gemini
```bash
export GEMINI_API_KEY="your-gemini-api-key"
```
Get your key: https://makersuite.google.com/app/apikey

### OpenAI
```bash
export OPENAI_API_KEY="sk-..."
```
Get your key: https://platform.openai.com/api-keys

### Anthropic Claude
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```
Get your key: https://console.anthropic.com/

---

## 📊 Report Examples

### HTML Report
Beautiful, interactive reports with:
- 📈 Summary statistics
- 🎨 Color-coded severity levels
- 📋 Detailed vulnerability information
- 🔗 CWE & OWASP mappings
- 💡 Remediation recommendations

### JSON Report
```json
{
  "scan_date": "2025-01-04T10:30:00",
  "summary": {
    "total_secrets": 5,
    "total_vulnerabilities": 12
  },
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "severity": "critical",
      "cwe": "CWE-89",
      "owasp": "A03:2021",
      "file_path": "app/database.py",
      "line_number": 45,
      "recommendation": "Use parameterized queries"
    }
  ]
}
```

---

## 🛠️ Development

### Running Tests
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html
```

### Code Quality
```bash
# Format code
black .

# Lint
flake8 .

# Type checking
mypy .
```

---

## 🔄 CI/CD Integration

Integrate security scanning into your CI/CD pipeline:

### GitHub Actions

**Option 1: Use as GitHub Action (Easiest)**
```yaml
- name: Run Security Scanner
  uses: ALxxy123/code-scan-sec@v3
  with:
    path: '.'
    ai-provider: 'gemini'
    gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
```

**Option 2: Copy Pre-built Workflows**

We provide two ready-to-use workflows:
- `.github/workflows/security-scan.yml` - Full security scan on push
- `.github/workflows/security-scan-pr.yml` - PR-specific scan

Simply copy these to your `.github/workflows/` directory!

**Option 3: Manual Setup**
```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
  - run: pip install security-scan-cli
  - run: security-scan scan --path . --ai-provider gemini
    env:
      GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

### Other CI/CD Platforms

We support all major CI/CD platforms:
- GitLab CI
- Jenkins
- CircleCI
- Azure Pipelines
- Bitbucket Pipelines

📖 **Full documentation**: [CI/CD Integration Guide](docs/CI-CD-INTEGRATION.md)

---

## 🔒 Security Best Practices

1. **Never commit secrets** - Use environment variables or secret managers
2. **Enable git hooks** - Prevent accidental secret commits
3. **Regular scans** - Integrate into CI/CD pipeline
4. **Review findings** - Not all detections are false positives
5. **Update regularly** - Keep scanner up-to-date for latest rules

---

## 📚 Documentation

- **Installation Guide**: See [Installation](#installation)
- **Usage Guide**: See [Usage Examples](#usage-examples)
- **Configuration**: See [Configuration](#configuration)
- **Feature Documentation**: See [docs/FEATURES-v3.md](docs/FEATURES-v3.md) - Comprehensive feature guide
- **CI/CD Integration**: See [docs/CI-CD-INTEGRATION.md](docs/CI-CD-INTEGRATION.md) - CI/CD setup guide
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)
- **API Reference**: http://localhost:8000/docs (when server is running)

---

## 🎯 Before & After: The Transformation

See how the scanner evolved from v3.0 to v3.1!

### ❌ Old CLI (v3.0)
Plain text output with minimal formatting:
```
Scanning files...
Found 5 potential secrets
Filtering by entropy...
3 high-entropy findings
Verifying with AI...
2 verified secrets

Found 12 vulnerabilities:
- 1 critical
- 2 high
- 5 medium
- 4 low

Scan complete.
Reports generated in output/
```

### ✅ New CLI (v3.1) - Beautiful Terminal UI
Professional, colorful, and informative:
```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗  ║
║     ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝  ║
║     ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝   ║
║              🛡️  AI-Powered Security Scanner v3.1.0  🛡️               ║
╚═══════════════════════════════════════════════════════════════════════╝

╭────────────────── 🔍 Scan Configuration ──────────────────╮
│                                                            │
│  📁 Scan Path          ./src                               │
│  🤖 AI Provider        GEMINI                              │
│  🔑 Secret Detection   ✅ Enabled                          │
│  🐛 Vulnerability Scan ✅ Enabled                          │
│  🔧 Auto-Fix           Available                           │
│                                                            │
╰────────────────────────────────────────────────────────────╯

🔍 Scanning: ████████████████████ 100% • 150/150 files • ⏱️ 12.5s

════════════════════════════════════════════════════════════
              🚨  CRITICAL ISSUES FOUND  🚨
════════════════════════════════════════════════════════════

╭───────────────── 📊 Scan Summary ─────────────────╮
│                                                    │
│  ⏱️  Duration: 12.50s                             │
│  📂 Files: 150                                     │
│  🔑 Secrets: 2 (🔴 ACTION REQUIRED)                │
│  🐛 Vulnerabilities: 12                            │
│     ├─ 🔴 Critical: 1                              │
│     ├─ 🟠 High: 2                                  │
│     ├─ 🟡 Medium: 5                                │
│     └─ 🔵 Low: 4                                   │
│                                                    │
╰────────────────────────────────────────────────────╯

🏆 Top Vulnerability Categories:
████████████████████████████████████████ dangerous_functions: 5
████████████████░░░░░░░░░░░░░░░░░░░░░░░░ xss: 2
████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ sql_injection: 1

🎯 Security Score: ███████████████████░░░░░░░░░░░░░░░░░░

⚠️ Grade: C (63/100) - Fair Security

╭────────────── 📋 Recommended Next Steps ─────────────╮
│                                                       │
│  🚨 URGENT: Review critical issues immediately        │
│  🔧 Run: security-scan auto-fix --path .             │
│  📊 Generate reports with: --output all              │
│  📈 View in dashboard: python api_server.py          │
│                                                       │
╰───────────────────────────────────────────────────────╯
```

### 📊 Key Improvements

| Feature | v3.0 | v3.1 |
|---------|------|------|
| **UI Design** | Plain text | ✨ Beautiful ASCII art & panels |
| **Progress Tracking** | Basic text | 📊 Visual progress bars |
| **Results Display** | Simple list | 📋 Detailed cards with colors |
| **Security Score** | ❌ None | ✅ A-F grading system |
| **Vulnerability Details** | Minimal | 🎯 Complete with CWE/OWASP |
| **Next Steps** | ❌ None | 💡 Context-aware recommendations |
| **Interactive Mode** | Basic prompts | 🎨 Beautiful wizard |
| **Demo Mode** | ❌ None | ✅ `security-scan demo` |
| **Visual Feedback** | Text only | 🌈 Color-coded severity levels |
| **Statistics** | Basic counts | 📈 Bar charts & visual metrics |

### 🚀 User Experience Impact

**Before (v3.0):**
- ⏱️ Hard to track progress
- 📊 Difficult to understand results quickly
- ❓ Unclear what to do next
- 🎨 Plain, uninspiring output

**After (v3.1):**
- ✅ **10x better visual feedback**
- ✅ **Instant understanding of security status**
- ✅ **Clear action items**
- ✅ **Professional, modern interface**
- ✅ **Enjoyable to use!** 🎉

### 💬 What Users Say

> *"The new UI is AMAZING! It makes security scanning actually fun."*

> *"Love the security score! Now I can track our progress over time."*

> *"The vulnerability cards with recommendations are super helpful!"*

> *"Finally, a security tool that doesn't look like it's from the 90s!"*

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 👨‍💻 Author

**Ahmed Mubaraki**

- GitHub: [@ALxxy123](https://github.com/ALxxy123)

---

## 🙏 Acknowledgments

- Built with [Typer](https://typer.tiangolo.com/) and [Rich](https://rich.readthedocs.io/)
- AI powered by Google Gemini, OpenAI, and Anthropic Claude
- Vulnerability rules based on OWASP Top 10 and CWE
- Inspired by various security scanning tools

---

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/ALxxy123/code-scan-sec/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/ALxxy123/code-scan-sec/discussions)
- 📧 **Email**: [Contact](mailto:your-email@example.com)

---

## ⭐ Star History

If you find this tool useful, please consider giving it a star! ⭐

---

**Made with ❤️ for the security community**
