# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2025-01-14

### 🚀 Added

#### Remote URL Scanning
- **URL Scanner Module** (`url_scanner.py`): Comprehensive remote project scanning
  - Git repository cloning (GitHub, GitLab, Bitbucket, etc.)
  - Support for shallow and deep clones
  - Archive file support (zip, tar.gz, tar.bz2, tar.xz)
  - Direct file downloads from URLs
  - Automatic cleanup of temporary files
  - Progress bars for downloads and cloning
  - Context manager for safe resource handling

- **New CLI Command**: `scan-url`
  - Scan remote repositories directly from URLs
  - Full integration with existing scan features
  - AI verification support
  - Vulnerability scanning
  - Multiple output formats (text, JSON, HTML)
  - Example: `security-scan scan-url https://github.com/user/repo`

#### Black Box Testing
- **Black Box Tester Module** (`blackbox_tester.py`): Automated web application security testing
  - **Security Headers Analysis**:
    - HSTS (HTTP Strict Transport Security)
    - Content Security Policy (CSP)
    - X-Frame-Options (Clickjacking protection)
    - X-Content-Type-Options (MIME sniffing prevention)
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
  - **SSL/TLS Testing**:
    - Certificate validation
    - TLS version checking (identifies weak versions like TLSv1.0, TLSv1.1)
    - Cipher strength analysis
  - **Vulnerability Testing**:
    - SQL Injection detection with multiple payloads
    - XSS (Cross-Site Scripting) testing
    - Path Traversal detection
    - Command Injection testing
    - Cookie security validation (Secure, HttpOnly flags)
  - **Comprehensive Reporting**:
    - Severity categorization (critical, high, medium, low)
    - Detailed recommendations for each finding
    - Evidence capture for vulnerabilities
    - JSON and HTML report generation

- **New CLI Command**: `blackbox`
  - Perform comprehensive black box security tests
  - Configurable timeout settings
  - Multiple output formats
  - Real-time progress tracking
  - Example: `security-scan blackbox https://example.com`

#### Performance Benchmarking
- **Benchmark Module** (`benchmark.py`): Performance monitoring and analysis
  - **Performance Metrics**:
    - Scan duration and timing
    - File and line processing throughput (files/sec, lines/sec)
    - Peak memory usage tracking
    - Average CPU utilization
    - AI API performance metrics (call count, response times)
  - **Historical Tracking**:
    - Save benchmark results to JSON history
    - Compare current scans with baselines
    - Identify performance regressions
    - Track improvements over time
  - **Resource Monitoring**:
    - Real-time CPU monitoring
    - Memory usage tracking
    - Process-level metrics using psutil
  - **Beautiful Reports**:
    - Rich terminal output with tables
    - Comparison visualizations
    - Performance improvement indicators
    - Baseline comparison analysis

- **New CLI Command**: `benchmark-scan`
  - Run scans with comprehensive performance tracking
  - Create named baselines for comparison
  - Historical trend analysis
  - Example: `security-scan benchmark-scan /path/to/project`

### 📦 Dependencies

- Added `requests>=2.31.0` for HTTP operations
- Added `psutil>=5.9.0` for system resource monitoring

### 📝 Documentation

- Updated README.md with v3.2.0 features
- Added comprehensive usage examples for new features
- Updated feature descriptions
- Added installation requirements

### 🔧 Technical Changes

- Updated `pyproject.toml` to version 3.2.0
- Added new modules to setuptools configuration
- Enhanced scanner.py with new CLI commands
- Improved error handling and logging
- Added context managers for resource management

### 🎯 Use Cases

1. **Remote Repository Scanning**:
   - Scan third-party dependencies before integration
   - Audit open-source projects
   - CI/CD integration for remote repositories
   - Quick security checks without local cloning

2. **Black Box Testing**:
   - Web application security audits
   - Pre-deployment security checks
   - Compliance validation (OWASP best practices)
   - Security header verification
   - SSL/TLS configuration testing

3. **Performance Benchmarking**:
   - Measure scan performance improvements
   - Identify optimization opportunities
   - Track resource usage trends
   - Compare different scanning strategies
   - Validate performance before releases

---

## [3.1.0] - 2025-01-04

### Added

- Beautiful Terminal UI with ASCII art banner
- Real-time progress bars with file count and ETA
- Security score grading system (A+ to F)
- Interactive scan configuration wizard
- Detailed vulnerability cards with recommendations
- Color-coded severity levels
- Auto-Fix Engine for automatic vulnerability remediation
- CI/CD Integration with GitHub Actions
- Web Dashboard with real-time monitoring
- Database Backend for scan history tracking
- Advanced Vulnerability Detection (50+ types)
- Multi-AI Support (Gemini, OpenAI, Claude)
- Enhanced HTML reporting

---

## [3.0.0] - Previous Release

### Added

- Initial release with core security scanning features
- Secret detection with regex patterns
- Entropy-based filtering
- AI-powered verification
- Basic vulnerability scanning
- Multiple output formats (JSON, HTML, Markdown, Text)

---

## Migration Guide

### From 3.1.0 to 3.2.0

1. **Install New Dependencies**:
   ```bash
   pip install --upgrade security-scan-cli
   # Or if installing from source:
   pip install -e .
   ```

2. **New Commands Available**:
   - `security-scan scan-url <url>` - Scan remote repositories
   - `security-scan blackbox <url>` - Black box web testing
   - `security-scan benchmark-scan <path>` - Performance benchmarking

3. **No Breaking Changes**: All existing commands and features remain fully compatible

4. **New Configuration Options**: None required, all new features work out of the box

---

## Future Roadmap

- 🔄 Automated dependency scanning
- 🌐 Multi-language support for black box testing
- 📊 Advanced visualization dashboards
- 🔗 Integration with popular CI/CD platforms
- 🤖 Enhanced AI models for better accuracy
- 📱 Mobile-friendly reporting
- 🔐 Secret rotation recommendations
- 🎯 Custom rule engine for black box tests
