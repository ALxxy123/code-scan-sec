# Security Scanner v3.0 - Feature Documentation

This document provides detailed documentation for all features in version 3.0.

## Table of Contents

1. [Auto-Fix Engine](#auto-fix-engine)
2. [Web Dashboard & API Server](#web-dashboard--api-server)
3. [Database Backend](#database-backend)
4. [CI/CD Integration](#cicd-integration)
5. [Advanced Features](#advanced-features)

---

## Auto-Fix Engine

The Auto-Fix Engine automatically fixes common security vulnerabilities in your codebase.

### Supported Fixes

#### 1. Weak Cryptography
- **MD5 → SHA256**: Automatically upgrades weak MD5 hashing to SHA256
- **SHA1 → SHA256**: Replaces SHA1 with stronger SHA256
- **DES → AES**: Upgrades weak DES encryption to AES

**Example:**
```python
# Before
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# After
import hashlib
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

#### 2. Hardcoded Secrets
- Moves hardcoded secrets to environment variables
- Creates `.env.example` file with placeholder values
- Adds `os.getenv()` calls automatically

**Example:**
```python
# Before
api_key = "sk-1234567890abcdef"
secret = "my-secret-key"

# After
import os
api_key = os.getenv("API_KEY", "")
secret = os.getenv("SECRET", "")
```

**Generated `.env.example`:**
```
API_KEY=your_api_key_here
SECRET=your_secret_here
```

#### 3. Dangerous Functions
- **eval()**: Replaces with `ast.literal_eval()` where safe
- **exec()**: Adds warning comments
- **pickle.loads()**: Suggests JSON alternatives

**Example:**
```python
# Before
result = eval(user_input)

# After
import ast
result = ast.literal_eval(user_input)
```

#### 4. SQL Injection
- Detects string concatenation in SQL queries
- Adds comments suggesting parameterized queries
- Flags for manual review

#### 5. XSS Vulnerabilities
- Detects innerHTML assignments
- Suggests HTML escaping
- Flags unsafe HTML string formatting

### Usage

```bash
# Interactive mode (default)
security-scan auto-fix --path ./src

# Dry run (preview changes)
security-scan auto-fix --path . --dry-run

# Fix specific types only
security-scan auto-fix --path . --fix-types crypto secrets

# Non-interactive mode
security-scan auto-fix --path . --no-interactive

# Single file
security-scan auto-fix --path ./vulnerable.py
```

### Configuration

```yaml
auto_fix:
  enabled: true
  interactive: true
  fix_types:
    - crypto
    - secrets
    - dangerous
    - xss
  extensions:
    - .py
    - .js
    - .ts
    - .php
    - .java
  create_backups: true
```

### Safety Features

- **Backups**: Creates `.backup` files before modifying
- **Interactive Mode**: Review each fix before applying
- **Dry Run**: Preview changes without modifying files
- **Confidence Levels**: Each fix has high/medium/low confidence
- **Revert Support**: Easy rollback with backup files

---

## Web Dashboard & API Server

Real-time web interface for monitoring and managing security scans.

### Features

- **Real-time Updates**: WebSocket-based live updates
- **Interactive Dashboard**: Modern UI with statistics
- **Scan Management**: Start, monitor, and review scans
- **API Documentation**: Auto-generated OpenAPI/Swagger docs
- **Background Processing**: Asynchronous scan execution
- **Scan History**: Track all scans with detailed results

### Starting the Server

```bash
# Install server dependencies
pip install "security-scan-cli[server]"

# Start the server
python api_server.py

# Or with auto-reload
uvicorn api_server:app --reload

# Access dashboard
open http://localhost:8000/dashboard.html

# API documentation
open http://localhost:8000/docs
```

### API Endpoints

#### GET /api/v1/health
Health check endpoint

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-04T10:30:00",
  "active_scans": 2,
  "websocket_connections": 5
}
```

#### POST /api/v1/scan
Start a new security scan

**Request:**
```json
{
  "path": "./src",
  "enable_ai": true,
  "ai_provider": "gemini",
  "enable_vulnerabilities": true,
  "output_format": "json"
}
```

**Response:**
```json
{
  "scan_id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "status": "queued",
  "message": "Scan initiated for ./src"
}
```

#### GET /api/v1/scan/{scan_id}
Get scan status and results

**Response:**
```json
{
  "scan_id": "a1b2c3d4...",
  "status": "completed",
  "progress": 100,
  "start_time": "2025-01-04T10:30:00",
  "end_time": "2025-01-04T10:35:00",
  "results": {
    "secrets": [...],
    "vulnerabilities": [...],
    "statistics": {...}
  }
}
```

#### GET /api/v1/scans
List all scans with pagination

**Parameters:**
- `limit`: Maximum number of scans (default: 50)
- `offset`: Number of scans to skip (default: 0)

#### POST /api/v1/auto-fix
Run auto-fix on code

**Request:**
```json
{
  "path": "./src",
  "fix_types": ["crypto", "secrets"],
  "interactive": false
}
```

#### GET /api/v1/dashboard/stats
Get dashboard statistics

**Response:**
```json
{
  "total_scans": 150,
  "active_scans": 2,
  "total_secrets_found": 45,
  "total_vulnerabilities_found": 128,
  "critical_vulnerabilities": 15,
  "recent_scans": [...]
}
```

#### WebSocket /ws
Real-time updates via WebSocket

**Message Types:**
- `connection`: Initial connection message
- `scan_progress`: Progress updates (0-100%)
- `scan_complete`: Scan finished successfully
- `scan_error`: Scan failed with error
- `heartbeat`: Keep-alive ping

---

## Database Backend

Persistent storage for scan history and trend analysis.

### Features

- **SQLite Support**: Default, no setup required
- **PostgreSQL Support**: For larger deployments
- **Scan History**: Complete scan records with results
- **Trend Analysis**: Historical data and statistics
- **Data Export**: Export to JSON for backup/analysis
- **Automatic Cleanup**: Remove old scans

### Database Schema

#### Scans Table
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    scan_id TEXT UNIQUE NOT NULL,
    path TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    status TEXT NOT NULL,
    total_secrets INTEGER,
    total_vulnerabilities INTEGER,
    critical_vulnerabilities INTEGER,
    -- ... more fields
);
```

#### Secrets Table
```sql
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    matched_text TEXT NOT NULL,
    ai_verified INTEGER,
    created_at TEXT NOT NULL
);
```

#### Vulnerabilities Table
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    scan_id TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    cwe TEXT,
    owasp TEXT,
    -- ... more fields
);
```

### Usage

```python
from database import get_database, ScanRecord

# Get database instance
db = get_database()

# Save scan
scan = ScanRecord(
    scan_id="abc123",
    path="./src",
    status="completed",
    total_secrets=5,
    total_vulnerabilities=12
)
db.save_scan(scan)

# Get scan
scan = db.get_scan("abc123")

# List scans
scans = db.list_scans(limit=10)

# Get statistics
stats = db.get_statistics()

# Get trends
trends = db.get_trends(days=30)

# Get top vulnerable files
files = db.get_top_vulnerable_files(limit=10)

# Export to JSON
db.export_to_json("backup.json")

# Cleanup old scans
db.cleanup_old_scans(days=90)
```

### PostgreSQL Configuration

```python
# Using PostgreSQL instead of SQLite
from database import get_database

db = get_database(
    db_path="postgresql://user:pass@localhost/scanner",
    db_type="postgresql"
)
```

### API Integration

The database is automatically integrated with the API server:

```python
# In api_server.py
from database import get_database

db = get_database()

# Scan results are automatically persisted
# Retrieve historical data via API endpoints
```

---

## CI/CD Integration

Pre-built workflows for automated security scanning in CI/CD pipelines.

### GitHub Actions

#### Option 1: Use as GitHub Action

```yaml
- name: Run Security Scanner
  uses: ALxxy123/code-scan-sec@v3
  with:
    path: '.'
    ai-provider: 'gemini'
    gemini-api-key: ${{ secrets.GEMINI_API_KEY }}
```

#### Option 2: Copy Pre-built Workflows

Two ready-to-use workflows included:

1. **`.github/workflows/security-scan.yml`**
   - Runs on push to main/develop
   - Daily scheduled scans
   - Creates GitHub issues for critical findings
   - Posts scan results

2. **`.github/workflows/security-scan-pr.yml`**
   - Runs on pull requests
   - Scans only changed files
   - Posts results as PR comment
   - Blocks merge if critical issues found

#### Features

- ✅ Automatic issue creation for critical findings
- ✅ PR comments with scan results
- ✅ Artifact uploads for reports
- ✅ Fail on critical vulnerabilities/secrets
- ✅ WebSocket support for real-time updates
- ✅ Scheduled daily scans
- ✅ Manual workflow dispatch

### Other CI/CD Platforms

Full documentation and examples provided for:
- GitLab CI
- Jenkins
- CircleCI
- Azure Pipelines
- Bitbucket Pipelines

See [CI-CD-INTEGRATION.md](CI-CD-INTEGRATION.md) for complete examples.

---

## Advanced Features

### Entropy-Based Secret Detection

Uses Shannon entropy to filter out false positives:

```python
# High entropy strings are more likely to be secrets
entropy = calculate_entropy("sk-1234567890abcdef")
# entropy ≈ 3.9 (likely a secret)

entropy = calculate_entropy("password")
# entropy ≈ 2.8 (likely not a secret)
```

### AI-Powered Verification

Reduces false positives by 90%+ using AI:

```python
# Verify with AI
is_real_secret = ai_provider.verify(matched_text)

# Only reports if AI confirms it's a real secret
```

### Multi-Format Reporting

Generate reports in multiple formats:

```bash
# HTML (beautiful, interactive)
security-scan scan --path . --output html

# Markdown (GitHub-friendly)
security-scan scan --path . --output markdown

# JSON (machine-readable)
security-scan scan --path . --output json

# All formats
security-scan scan --path . --output all
```

### Git Pre-Commit Hooks

Prevent committing secrets:

```bash
# Install hook
security-scan install-hook

# Hook runs automatically before each commit
# Blocks commit if secrets found
```

### Custom Rules

Add custom vulnerability detection rules:

```yaml
# vulnerability_rules.yaml
vulnerabilities:
  custom_category:
    - name: "My Custom Vulnerability"
      severity: high
      cwe: CWE-XXX
      pattern: 'my_pattern_here'
      description: "Description"
      recommendation: "How to fix"
      languages: [python, javascript]
```

### Configuration

Fully customizable via `config.yaml`:

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

report:
  output_dir: output
  default_formats:
    - html
    - json
```

---

## Performance

- **Fast Scanning**: Optimized file processing
- **Parallel Processing**: Multiple files scanned concurrently
- **Smart Caching**: Reduce redundant AI API calls
- **Incremental Scans**: Only scan changed files (PR mode)

## Security

- **API Key Protection**: Never logged or stored
- **Secure Communication**: HTTPS for AI providers
- **Rate Limiting**: Built-in retry with exponential backoff
- **Input Validation**: All inputs sanitized

## Support

- **Documentation**: Comprehensive guides and examples
- **Testing**: Full test coverage with pytest
- **Logging**: Detailed logs with rotation
- **Error Handling**: Graceful failures with helpful messages

---

**For more information, see:**
- [README.md](../README.md) - Getting started
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guide
- [CI-CD-INTEGRATION.md](CI-CD-INTEGRATION.md) - CI/CD setup
