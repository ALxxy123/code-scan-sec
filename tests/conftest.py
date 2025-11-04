"""
Pytest configuration and shared fixtures.
"""

import pytest
from pathlib import Path
import tempfile
import yaml


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_config_file(temp_dir):
    """Create sample configuration file."""
    config_file = temp_dir / "config.yaml"
    config_data = {
        'scan': {
            'entropy_threshold': 3.5,
            'max_file_size': 10485760,
            'enable_ai_verification': True
        },
        'ai': {
            'default_provider': 'gemini',
            'max_retries': 5
        }
    }

    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)

    return config_file


@pytest.fixture
def sample_rules_file(temp_dir):
    """Create sample rules file."""
    rules_file = temp_dir / "rules.txt"
    rules = """
# Test rules
password\\s*[:=]\\s*['"][^'"]+['"]
token\\s*[:=]\\s*['"][^'"]+['"]
API_KEY\\s*[:=]\\s*['"][^'"]+['"]
"""
    rules_file.write_text(rules)
    return rules_file


@pytest.fixture
def sample_vulnerable_file(temp_dir):
    """Create sample file with vulnerabilities."""
    vuln_file = temp_dir / "vulnerable.py"
    code = """
import os

# SQL Injection
query = "SELECT * FROM users WHERE id = " + user_id

# Command Injection
os.system(user_input)

# Hardcoded secret
api_key = "sk-1234567890abcdef1234567890abcdef12345678"

# Weak crypto
import hashlib
hash = hashlib.md5(password)
"""
    vuln_file.write_text(code)
    return vuln_file


@pytest.fixture
def sample_clean_file(temp_dir):
    """Create sample clean file."""
    clean_file = temp_dir / "clean.py"
    code = """
import os
from pathlib import Path

def process_file(file_path):
    '''Process a file safely.'''
    path = Path(file_path)
    if not path.exists():
        return None

    with open(path, 'r') as f:
        return f.read()
"""
    clean_file.write_text(code)
    return clean_file
