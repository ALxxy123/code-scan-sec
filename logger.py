"""
Logging configuration for Security Scanner.

This module provides centralized logging with file rotation, formatting,
and different log levels.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
from config import get_config


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output."""

    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }

    def format(self, record):
        """Format log record with colors."""
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = (
                    f"{self.COLORS[levelname]}{levelname}{self.COLORS['RESET']}"
                )
        return super().format(record)


class SecurityLogger:
    """
    Centralized logger for the security scanner application.

    Provides both file and console logging with rotation and formatting.
    """

    _instance: Optional['SecurityLogger'] = None
    _initialized: bool = False

    def __new__(cls):
        """Singleton pattern to ensure only one logger instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize logger with configuration from config file."""
        if self._initialized:
            return

        self.config = get_config()
        self.logger = logging.getLogger('security_scanner')
        self.logger.setLevel(self._get_log_level())
        self.logger.propagate = False

        # Clear any existing handlers
        self.logger.handlers.clear()

        # Add console handler
        self._add_console_handler()

        # Add file handler if enabled
        if self.config.logging.file_logging:
            self._add_file_handler()

        self._initialized = True

    def _get_log_level(self) -> int:
        """
        Convert string log level to logging constant.

        Returns:
            int: Logging level constant
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return level_map.get(self.config.logging.level.upper(), logging.INFO)

    def _add_console_handler(self):
        """Add colored console handler."""
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(self._get_log_level())

        # Use colored formatter for console
        formatter = ColoredFormatter(
            '%(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def _add_file_handler(self):
        """Add rotating file handler with size-based rotation."""
        try:
            # Create logs directory if it doesn't exist
            log_path = Path(self.config.logging.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Create rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                self.config.logging.log_file,
                maxBytes=self.config.logging.max_size,
                backupCount=self.config.logging.backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(self._get_log_level())

            # Use detailed formatter for file
            formatter = logging.Formatter(self.config.logging.format)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

        except Exception as e:
            # If file handler fails, log to console only
            self.logger.warning(f"Failed to setup file logging: {e}")

    def get_logger(self) -> logging.Logger:
        """
        Get the configured logger instance.

        Returns:
            logging.Logger: Configured logger
        """
        return self.logger

    def debug(self, message: str, *args, **kwargs):
        """Log debug message."""
        self.logger.debug(message, *args, **kwargs)

    def info(self, message: str, *args, **kwargs):
        """Log info message."""
        self.logger.info(message, *args, **kwargs)

    def warning(self, message: str, *args, **kwargs):
        """Log warning message."""
        self.logger.warning(message, *args, **kwargs)

    def error(self, message: str, *args, **kwargs):
        """Log error message."""
        self.logger.error(message, *args, **kwargs)

    def critical(self, message: str, *args, **kwargs):
        """Log critical message."""
        self.logger.critical(message, *args, **kwargs)

    def exception(self, message: str, *args, **kwargs):
        """Log exception with traceback."""
        self.logger.exception(message, *args, **kwargs)


# Global logger instance
_logger: Optional[SecurityLogger] = None


def get_logger() -> SecurityLogger:
    """
    Get global logger instance (singleton pattern).

    Returns:
        SecurityLogger: Global logger object
    """
    global _logger
    if _logger is None:
        _logger = SecurityLogger()
    return _logger


def setup_logging(log_level: Optional[str] = None, log_file: Optional[str] = None):
    """
    Setup logging with custom configuration.

    Args:
        log_level: Optional log level override
        log_file: Optional log file path override
    """
    config = get_config()

    if log_level:
        config.logging.level = log_level

    if log_file:
        config.logging.log_file = log_file

    global _logger
    _logger = SecurityLogger()


# Convenience functions for direct logging
def debug(message: str, *args, **kwargs):
    """Log debug message."""
    get_logger().debug(message, *args, **kwargs)


def info(message: str, *args, **kwargs):
    """Log info message."""
    get_logger().info(message, *args, **kwargs)


def warning(message: str, *args, **kwargs):
    """Log warning message."""
    get_logger().warning(message, *args, **kwargs)


def error(message: str, *args, **kwargs):
    """Log error message."""
    get_logger().error(message, *args, **kwargs)


def critical(message: str, *args, **kwargs):
    """Log critical message."""
    get_logger().critical(message, *args, **kwargs)


def exception(message: str, *args, **kwargs):
    """Log exception with traceback."""
    get_logger().exception(message, *args, **kwargs)
