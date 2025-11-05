# 🛡️ Enhanced AI-Powered Security Scanner

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/ALxxy123/code-scan-sec)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

**The most advanced open-source security scanner** that detects hardcoded secrets, API keys, passwords, **AND** security vulnerabilities using AI-powered verification.

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

### 1. Scan Current Directory
```bash
security-scan scan --path .
```

### 2. Scan with Claude AI
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
security-scan scan --path /my/project --ai-provider claude
```

### 3. Generate All Report Formats
```bash
security-scan scan --path . --output all
```

### 4. Quick Scan for CI/CD
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
