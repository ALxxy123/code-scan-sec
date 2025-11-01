---

## 🚀 Quick Start & Installation

Security Scan is a modern Python CLI application that is easily installed using `pipx`, which creates an isolated environment for the tool.

### Prerequisites

- **Python 3.8+** (Must be installed and added to PATH on Windows)
- **pipx** (Highly recommended for installing CLI tools)
- **Git** (Required for installing directly from the GitHub repository)

### 1. Python CLI Installation (Recommended for All Users)

This is the easiest and most reliable method for all platforms (Windows, macOS, Linux).

```bash
# First, install pipx if you don't have it
pip install pipx

# Install the Security Scan CLI globally from PyPI
pipx install security-scan-cli
```

**(Note: If you are testing the latest unreleased features, you can install directly from the master branch using: `pipx install git+https://github.com/ALxxy123/code-scan-sec.git@master`)**

### 2. Run the Interactive Wizard 🧙‍♂️

Start the guided setup and scanning process instantly:

```bash
security-scan interactive
```

---

## 💻 Usage

### Interactive Wizard Mode 🧙‍♂️

The easiest way to get started:

```bash
# Launch the interactive wizard
security-scan interactive
```

The wizard will guide you through:
1. ✅ Enable AI verification (Yes/No)
2. 🤖 Choose AI provider (Gemini/OpenAI)
3. 🔑 Enter your API key
4. 📁 Select path to scan
5. 📄 Choose report format (JSON/Markdown/HTML)

### Automated Mode (For CI/CD)

Perfect for scripts and CI/CD pipelines:

```bash
# Basic scan without AI
security-scan scan -p . --no-ai -o html

# Scan with OpenAI verification
export OPENAI_API_KEY="sk-..."
security-scan scan -p /path/to/project --ai-provider openai

# Scan with Gemini and JSON output
export GEMINI_API_KEY="..."
security-scan scan -p . --ai-provider gemini -o json
```

### Git Pre-Commit Hook Installation

Automatically prevent secrets from being committed:

```bash
# Navigate to your repository
cd /path/to/your/git/repo

# Install the pre-commit hook
security-scan install-hook

# Now every commit will be scanned automatically
git commit -m "Changes will be scanned for secrets"
```

### Legacy Bash Engine (For Advanced Users)

**Note:** The Bash engine is now considered legacy and is only recommended for specific use cases where you need shell-native integration.

**Requirements:**
- Linux/macOS/WSL environment
- Bash 4.0+ and standard Unix tools

```bash
# Clone and install system-wide
git clone https://github.com/ALxxy123/code-scan-sec.git
cd code-scan-sec
sudo bash install.sh

# Verify installation
security-scan --version
```

---