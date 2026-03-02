"""
Tests for configuration management.
"""

import pytest
from pathlib import Path
import yaml
from config import Config, ScanConfig, AIConfig, get_config, reload_config


class TestConfig:
    """Test suite for configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()

        assert config.scan.entropy_threshold == 3.5
        assert config.scan.max_file_size == 10485760
        assert config.ai.default_provider == "gemini"
        assert config.ai.max_retries == 5

    def test_scan_config(self):
        """Test scan configuration."""
        scan_config = ScanConfig(
            entropy_threshold=4.0,
            max_file_size=5000000,
            enable_ai_verification=True
        )

        assert scan_config.entropy_threshold == 4.0
        assert scan_config.max_file_size == 5000000
        assert scan_config.enable_ai_verification is True

    def test_ai_config(self):
        """Test AI configuration."""
        ai_config = AIConfig(
            default_provider="openai",
            max_retries=3,
            timeout=60
        )

        assert ai_config.default_provider == "openai"
        assert ai_config.max_retries == 3
        assert ai_config.timeout == 60

    def test_config_from_dict(self, tmp_path):
        """Test loading configuration from YAML file."""
        config_file = tmp_path / "test_config.yaml"
        config_data = {
            'scan': {
                'entropy_threshold': 4.5,
                'max_file_size': 20000000
            },
            'ai': {
                'default_provider': 'claude',
                'max_retries': 10
            }
        }

        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = Config.from_file(str(config_file))

        assert config.scan.entropy_threshold == 4.5
        assert config.scan.max_file_size == 20000000
        assert config.ai.default_provider == 'claude'
        assert config.ai.max_retries == 10

    def test_config_to_dict(self):
        """Test converting configuration to dictionary."""
        config = Config()
        config_dict = config.to_dict()

        assert 'scan' in config_dict
        assert 'ai' in config_dict
        assert 'logging' in config_dict
        assert config_dict['scan']['entropy_threshold'] == 3.5

    def test_missing_config_file(self):
        """Test loading with missing config file."""
        config = Config.from_file("nonexistent.yaml")
        # Should return default config
        assert config.scan.entropy_threshold == 3.5
