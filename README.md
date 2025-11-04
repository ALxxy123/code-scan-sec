# 🛡️ Enhanced AI-Powered Security Scanner

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/ALxxy123/code-scan-sec)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

**The most advanced open-source security scanner** that detects hardcoded secrets, API keys, passwords, **AND** security vulnerabilities using AI-powered verification.

## ✨ What's New in v3.0

🚀 **Major enhancements:**
- 🐛 **Advanced Vulnerability Detection** - Detects SQL Injection, XSS, Command Injection, and 50+ vulnerability types
- 🤖 **Claude AI Support** - Added Anthropic Claude alongside Gemini and OpenAI
- 📊 **Enhanced Reporting** - Beautiful HTML reports with severity breakdowns
- ⚙️ **YAML Configuration** - Flexible configuration system
- 📝 **Comprehensive Logging** - Detailed logging with file rotation
- 🧪 **Unit Tests** - Full test coverage for reliability
- 🎯 **OWASP & CWE Mapping** - Industry-standard vulnerability classification
- ⚡ **Performance Improvements** - Faster scanning with better accuracy

---

## 🎯 Features

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

**Interactive Mode (Easiest):**
```bash
security-scan interactive
```

This wizard will guide you through:
1. ✅ AI verification setup
2. 🤖 AI provider selection (Gemini/OpenAI/Claude)
3. 🐛 Vulnerability scanning options
4. 📁 Path selection
5. 📊 Report format choice

**Automated Mode (CI/CD):**
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

### 5. Install Git Pre-Commit Hook
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
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)
- **API Reference**: Coming soon

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
