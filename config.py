"""
Configuration management for Security Scanner.

This module handles loading and validating configuration from YAML files.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
import yaml
from pathlib import Path
import os


@dataclass
class ScanConfig:
    """Scan configuration settings."""
    entropy_threshold: float = 3.5
    max_file_size: int = 10485760  # 10MB
    enable_ai_verification: bool = True
    enable_vulnerability_scan: bool = True
    ignore_patterns: List[str] = field(default_factory=lambda: [
        "*.log", "*.tmp", "*.cache", "**/node_modules/**",
        "**/.git/**", "**/venv/**", "**/__pycache__/**"
    ])
    scan_extensions: List[str] = field(default_factory=lambda: [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
        ".php", ".rb", ".sh", ".bash", ".yaml", ".yml", ".json"
    ])


@dataclass
class AIConfig:
    """AI provider configuration settings."""
    default_provider: str = "gemini"
    max_retries: int = 5
    timeout: int = 30
    rate_limit_delay: float = 0.5
    batch_size: int = 10


@dataclass
class GeminiConfig:
    """Gemini-specific configuration."""
    model: str = "gemini-2.0-flash"
    temperature: float = 0.0
    max_tokens: int = 10


@dataclass
class OpenAIConfig:
    """OpenAI-specific configuration."""
    model: str = "gpt-3.5-turbo"
    temperature: float = 0.0
    max_tokens: int = 2


@dataclass
class ClaudeConfig:
    """Claude-specific configuration."""
    model: str = "claude-3-5-sonnet-20241022"
    temperature: float = 0.0
    max_tokens: int = 10


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    file_logging: bool = True
    log_file: str = "security_scan.log"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_size: int = 10485760  # 10MB
    backup_count: int = 3


@dataclass
class ReportConfig:
    """Report generation configuration."""
    output_dir: str = "output"
    default_formats: List[str] = field(default_factory=lambda: ["html", "json"])
    include_ai_details: bool = True
    include_vulnerability_details: bool = True
    auto_open_browser: bool = True


@dataclass
class PerformanceConfig:
    """Performance optimization settings."""
    enable_async: bool = True
    worker_threads: int = 4
    enable_cache: bool = True
    cache_expiration: int = 3600  # 1 hour


@dataclass
class VulnerabilityConfig:
    """Vulnerability detection settings."""
    severity_levels: List[str] = field(default_factory=lambda: [
        "critical", "high", "medium", "low", "info"
    ])
    categories: List[str] = field(default_factory=lambda: [
        "sql_injection", "xss", "command_injection", "path_traversal",
        "xxe", "ssrf", "insecure_deserialization", "weak_crypto",
        "hardcoded_secrets", "dangerous_functions"
    ])
    enable_cwe_mapping: bool = True
    enable_owasp_mapping: bool = True


@dataclass
class GitHookConfig:
    """Git hook configuration."""
    block_on_critical: bool = True
    block_on_secrets: bool = True
    show_details: bool = True


@dataclass
class Config:
    """Main configuration container."""
    scan: ScanConfig = field(default_factory=ScanConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    gemini: GeminiConfig = field(default_factory=GeminiConfig)
    openai: OpenAIConfig = field(default_factory=OpenAIConfig)
    claude: ClaudeConfig = field(default_factory=ClaudeConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    vulnerabilities: VulnerabilityConfig = field(default_factory=VulnerabilityConfig)
    git_hook: GitHookConfig = field(default_factory=GitHookConfig)

    @classmethod
    def from_file(cls, config_path: str = "config.yaml") -> "Config":
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to configuration file

        Returns:
            Config: Loaded configuration object

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid
        """
        path = Path(config_path)

        # If config file doesn't exist, use defaults
        if not path.exists():
            return cls()

        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        if not data:
            return cls()

        config = cls()

        # Load scan settings
        if 'scan' in data:
            scan_data = data['scan']
            config.scan = ScanConfig(
                entropy_threshold=scan_data.get('entropy_threshold', 3.5),
                max_file_size=scan_data.get('max_file_size', 10485760),
                enable_ai_verification=scan_data.get('enable_ai_verification', True),
                enable_vulnerability_scan=scan_data.get('enable_vulnerability_scan', True),
                ignore_patterns=scan_data.get('ignore_patterns', []),
                scan_extensions=scan_data.get('scan_extensions', [])
            )

        # Load AI settings
        if 'ai' in data:
            ai_data = data['ai']
            config.ai = AIConfig(
                default_provider=ai_data.get('default_provider', 'gemini'),
                max_retries=ai_data.get('max_retries', 5),
                timeout=ai_data.get('timeout', 30),
                rate_limit_delay=ai_data.get('rate_limit_delay', 0.5),
                batch_size=ai_data.get('batch_size', 10)
            )

        # Load provider-specific settings
        if 'gemini' in data:
            gemini_data = data['gemini']
            config.gemini = GeminiConfig(**gemini_data)

        if 'openai' in data:
            openai_data = data['openai']
            config.openai = OpenAIConfig(**openai_data)

        if 'claude' in data:
            claude_data = data['claude']
            config.claude = ClaudeConfig(**claude_data)

        # Load logging settings
        if 'logging' in data:
            log_data = data['logging']
            config.logging = LoggingConfig(**log_data)

        # Load report settings
        if 'report' in data:
            report_data = data['report']
            config.report = ReportConfig(
                output_dir=report_data.get('output_dir', 'output'),
                default_formats=report_data.get('default_formats', ['html', 'json']),
                include_ai_details=report_data.get('include_ai_details', True),
                include_vulnerability_details=report_data.get('include_vulnerability_details', True),
                auto_open_browser=report_data.get('auto_open_browser', True)
            )

        # Load performance settings
        if 'performance' in data:
            perf_data = data['performance']
            config.performance = PerformanceConfig(**perf_data)

        # Load vulnerability settings
        if 'vulnerabilities' in data:
            vuln_data = data['vulnerabilities']
            config.vulnerabilities = VulnerabilityConfig(
                severity_levels=vuln_data.get('severity_levels', []),
                categories=vuln_data.get('categories', []),
                enable_cwe_mapping=vuln_data.get('enable_cwe_mapping', True),
                enable_owasp_mapping=vuln_data.get('enable_owasp_mapping', True)
            )

        # Load git hook settings
        if 'git_hook' in data:
            hook_data = data['git_hook']
            config.git_hook = GitHookConfig(**hook_data)

        return config

    def to_dict(self) -> Dict:
        """
        Convert configuration to dictionary.

        Returns:
            Dict: Configuration as dictionary
        """
        return {
            'scan': {
                'entropy_threshold': self.scan.entropy_threshold,
                'max_file_size': self.scan.max_file_size,
                'enable_ai_verification': self.scan.enable_ai_verification,
                'enable_vulnerability_scan': self.scan.enable_vulnerability_scan,
                'ignore_patterns': self.scan.ignore_patterns,
                'scan_extensions': self.scan.scan_extensions
            },
            'ai': {
                'default_provider': self.ai.default_provider,
                'max_retries': self.ai.max_retries,
                'timeout': self.ai.timeout,
                'rate_limit_delay': self.ai.rate_limit_delay,
                'batch_size': self.ai.batch_size
            },
            'logging': {
                'level': self.logging.level,
                'file_logging': self.logging.file_logging,
                'log_file': self.logging.log_file
            }
        }


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """
    Get global configuration instance (singleton pattern).

    Returns:
        Config: Global configuration object
    """
    global _config
    if _config is None:
        _config = Config.from_file()
    return _config


def reload_config(config_path: str = "config.yaml") -> Config:
    """
    Reload configuration from file.

    Args:
        config_path: Path to configuration file

    Returns:
        Config: Reloaded configuration object
    """
    global _config
    _config = Config.from_file(config_path)
    return _config
