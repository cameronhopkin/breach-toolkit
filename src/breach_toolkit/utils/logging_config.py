#!/usr/bin/env python3
"""
Breach Toolkit - Logging Configuration
Centralized logging setup for the application.

Author: Cameron Hopkin
License: MIT
"""
import logging
import sys
from typing import Optional
from pathlib import Path


# Default format for log messages
DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
SIMPLE_FORMAT = "%(levelname)s: %(message)s"


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
    include_timestamp: bool = True
) -> logging.Logger:
    """
    Set up logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging
        format_string: Custom format string
        include_timestamp: Include timestamps in output

    Returns:
        Configured root logger
    """
    # Determine format
    if format_string:
        log_format = format_string
    elif include_timestamp:
        log_format = DEFAULT_FORMAT
    else:
        log_format = SIMPLE_FORMAT

    # Get numeric level
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(logging.Formatter(log_format))
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)

    # Ensure at least one handler exists
    if not logger.handlers and not logger.parent.handlers:
        setup_logging()

    return logger


class LoggerAdapter(logging.LoggerAdapter):
    """
    Logger adapter for adding context to log messages.

    Useful for adding request IDs, user context, etc.
    """

    def process(self, msg, kwargs):
        """Add extra context to log messages."""
        extra = self.extra.copy()
        extra.update(kwargs.get('extra', {}))

        # Format extra context
        context_parts = [f"{k}={v}" for k, v in extra.items()]
        if context_parts:
            context_str = " [" + ", ".join(context_parts) + "]"
            msg = f"{msg}{context_str}"

        return msg, kwargs


def get_context_logger(name: str, **context) -> LoggerAdapter:
    """
    Get a logger with additional context.

    Args:
        name: Logger name
        **context: Key-value pairs to include in all messages

    Returns:
        LoggerAdapter with context
    """
    logger = get_logger(name)
    return LoggerAdapter(logger, context)


# Silence noisy loggers
def silence_loggers(*names):
    """
    Set specified loggers to WARNING level.

    Args:
        *names: Logger names to silence
    """
    for name in names:
        logging.getLogger(name).setLevel(logging.WARNING)


# Default silencing of noisy libraries
silence_loggers(
    'urllib3',
    'aiohttp',
    'asyncio',
)
