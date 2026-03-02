# Contributing to Security Scanner

Thank you for your interest in contributing to the Enhanced AI-Powered Security Scanner! This document provides guidelines and information for contributors.

## 🤝 Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints and experiences

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of security concepts
- Familiarity with Python development

### Setting Up Development Environment

1. **Fork and clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/code-scan-sec.git
cd code-scan-sec
```

2. **Create a virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install development dependencies:**
```bash
pip install -e ".[dev]"
```

4. **Install pre-commit hooks:**
```bash
pre-commit install
```

## 📝 Development Workflow

### 1. Create a Branch

Create a descriptive branch name:
```bash
git checkout -b feature/add-new-vulnerability-rule
git checkout -b fix/false-positive-in-secret-detection
git checkout -b docs/improve-readme
```

### 2. Make Your Changes

- Write clean, readable code
- Follow Python PEP 8 style guidelines
- Add docstrings to functions and classes
- Include type hints where appropriate
- Keep functions small and focused

### 3. Write Tests

Every new feature or bug fix should include tests:

```python
# tests/test_my_feature.py
import pytest
from my_module import my_function

def test_my_function():
    """Test that my_function works correctly."""
    result = my_function(input_data)
    assert result == expected_output
```

Run tests:
```bash
pytest
pytest --cov=. --cov-report=html  # With coverage
```

### 4. Code Quality

Format your code:
```bash
black .
```

Lint your code:
```bash
flake8 .
```

Type checking:
```bash
mypy .
```

### 5. Commit Your Changes

Write clear, descriptive commit messages:
```bash
git add .
git commit -m "feat: Add detection for hardcoded database credentials"
git commit -m "fix: Resolve false positive in entropy calculation"
git commit -m "docs: Update installation instructions"
```

**Commit Message Format:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### 6. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear description of changes
- Reference to related issues
- Screenshots (if UI changes)
- Test results

## 🎯 Contribution Ideas

### Adding New Vulnerability Rules

1. Research the vulnerability type
2. Create regex pattern in `vulnerability_rules.yaml`
3. Include:
   - Name and description
   - Severity level
   - CWE and OWASP mappings
   - Remediation recommendations
   - Supported languages

Example:
```yaml
vulnerabilities:
  my_category:
    - name: "My Vulnerability"
      severity: high
      cwe: CWE-XXX
      owasp: AXX:2021
      pattern: 'regex_pattern_here'
      description: "Clear description of the vulnerability"
      recommendation: "How to fix it"
      languages: [python, javascript]
```

4. Add tests for the new rule
5. Update documentation

### Adding New AI Providers

1. Create `ai_providers/my_provider.py`
2. Inherit from `BaseAIProvider`
3. Implement `initialize()` and `verify()` methods
4. Add to `AI_PROVIDERS` dict in `scanner.py`
5. Update README with API key instructions
6. Add tests

### Improving Detection Accuracy

- Reduce false positives
- Add context-aware detection
- Improve entropy calculation
- Better pattern matching

### Performance Improvements

- Optimize file scanning
- Implement caching
- Add async/parallel processing
- Reduce memory usage

## 🧪 Testing Guidelines

### Test Coverage

- Aim for >80% code coverage
- Test both happy paths and edge cases
- Test error handling
- Mock external API calls

### Test Structure

```python
class TestMyFeature:
    """Test suite for my feature."""

    @pytest.fixture
    def sample_data(self):
        """Create sample test data."""
        return {"key": "value"}

    def test_normal_case(self, sample_data):
        """Test normal operation."""
        result = my_function(sample_data)
        assert result is not None

    def test_edge_case(self):
        """Test edge case handling."""
        result = my_function(None)
        assert result == expected_default

    def test_error_handling(self):
        """Test error handling."""
        with pytest.raises(ValueError):
            my_function(invalid_input)
```

## 📚 Documentation

### Code Documentation

- Add docstrings to all public functions and classes
- Use Google-style docstrings:

```python
def my_function(param1: str, param2: int) -> bool:
    """
    Brief description of the function.

    Detailed explanation if needed.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When invalid input is provided
    """
    pass
```

### README Updates

- Update README.md for user-facing changes
- Add examples for new features
- Update version numbers
- Add to changelog

## 🐛 Reporting Bugs

### Before Reporting

1. Check if the bug has already been reported
2. Verify it's reproducible
3. Test with the latest version

### Bug Report Template

```markdown
**Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Step one
2. Step two
3. Step three

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.10.5]
- Scanner Version: [e.g., 3.0.0]

**Additional Context:**
Any other relevant information
```

## 💡 Feature Requests

### Feature Request Template

```markdown
**Feature Description:**
Clear description of the proposed feature

**Problem It Solves:**
What problem does this feature address?

**Proposed Solution:**
How would this feature work?

**Alternatives Considered:**
Other approaches you've thought about

**Additional Context:**
Mockups, examples, references
```

## 🏷️ Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Documentation improvements
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `question`: Further information requested

## 🔍 Code Review Process

### For Contributors

- Respond to feedback promptly
- Make requested changes
- Keep PRs focused and small
- Rebase if needed

### For Reviewers

- Be constructive and respectful
- Explain reasoning for requested changes
- Approve when ready
- Test the changes locally

## 📦 Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create release branch
4. Run all tests
5. Create GitHub release
6. Publish to PyPI

## 🎓 Learning Resources

### Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE List](https://cwe.mitre.org/)
- [NIST Guidelines](https://www.nist.gov/cybersecurity)

### Python Resources

- [Python Style Guide (PEP 8)](https://pep8.org/)
- [Type Hints (PEP 484)](https://www.python.org/dev/peps/pep-0484/)
- [Pytest Documentation](https://docs.pytest.org/)

### Tools Documentation

- [Typer](https://typer.tiangolo.com/)
- [Rich](https://rich.readthedocs.io/)
- [PyYAML](https://pyyaml.org/)

## 🙏 Thank You!

Your contributions make this project better for everyone. Whether it's:
- Reporting a bug
- Suggesting a feature
- Writing code
- Improving documentation
- Helping others

Every contribution is valued and appreciated!

## 📧 Contact

- **Issues**: https://github.com/ALxxy123/code-scan-sec/issues
- **Discussions**: https://github.com/ALxxy123/code-scan-sec/discussions
- **Email**: your-email@example.com

---

**Happy Contributing! 🚀**
