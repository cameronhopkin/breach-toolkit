#!/usr/bin/env python3
"""
Breach Toolkit - Configuration Management

Author: Cameron Hopkin
License: MIT
"""
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import json


@dataclass
class HIBPConfig:
    """Configuration for Have I Been Pwned API."""
    api_key: Optional[str] = None
    rate_limit: float = 1.5  # requests per second
    timeout: int = 10
    user_agent: str = "BreachToolkit/1.0"

    @classmethod
    def from_env(cls) -> "HIBPConfig":
        """Create config from environment variables."""
        return cls(
            api_key=os.getenv("HIBP_API_KEY"),
            rate_limit=float(os.getenv("BREACH_TOOLKIT_RATE_LIMIT", "1.5")),
            timeout=int(os.getenv("BREACH_TOOLKIT_TIMEOUT", "10")),
            user_agent=os.getenv("BREACH_TOOLKIT_USER_AGENT", "BreachToolkit/1.0")
        )


@dataclass
class ParserConfig:
    """Configuration for log parsers."""
    deduplicate: bool = True
    validate_emails: bool = True
    min_password_length: int = 1
    supported_extensions: tuple = ('.txt', '.log', '.csv')


@dataclass
class ReporterConfig:
    """Configuration for report generation."""
    include_timestamps: bool = True
    mask_passwords: bool = False
    max_password_display: int = 0  # 0 = show full, >0 = show first N chars


@dataclass
class Config:
    """Main configuration class for Breach Toolkit."""
    hibp: HIBPConfig = field(default_factory=HIBPConfig.from_env)
    parser: ParserConfig = field(default_factory=ParserConfig)
    reporter: ReporterConfig = field(default_factory=ReporterConfig)
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, filepath: str) -> "Config":
        """Load configuration from JSON file."""
        path = Path(filepath)
        if not path.exists():
            return cls()

        with open(path) as f:
            data = json.load(f)

        config = cls()

        if "hibp" in data:
            config.hibp = HIBPConfig(**data["hibp"])

        if "parser" in data:
            parser_data = data["parser"]
            if "supported_extensions" in parser_data:
                parser_data["supported_extensions"] = tuple(parser_data["supported_extensions"])
            config.parser = ParserConfig(**parser_data)

        if "reporter" in data:
            config.reporter = ReporterConfig(**data["reporter"])

        if "log_level" in data:
            config.log_level = data["log_level"]

        return config

    @classmethod
    def from_env(cls) -> "Config":
        """Create configuration from environment variables."""
        return cls(
            hibp=HIBPConfig.from_env(),
            log_level=os.getenv("BREACH_TOOLKIT_LOG_LEVEL", "INFO")
        )

    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            "hibp": {
                "api_key": "***" if self.hibp.api_key else None,
                "rate_limit": self.hibp.rate_limit,
                "timeout": self.hibp.timeout,
                "user_agent": self.hibp.user_agent
            },
            "parser": {
                "deduplicate": self.parser.deduplicate,
                "validate_emails": self.parser.validate_emails,
                "min_password_length": self.parser.min_password_length,
                "supported_extensions": list(self.parser.supported_extensions)
            },
            "reporter": {
                "include_timestamps": self.reporter.include_timestamps,
                "mask_passwords": self.reporter.mask_passwords,
                "max_password_display": self.reporter.max_password_display
            },
            "log_level": self.log_level
        }

    def save(self, filepath: str):
        """Save configuration to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Global default configuration
_default_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _default_config
    if _default_config is None:
        _default_config = Config.from_env()
    return _default_config


def set_config(config: Config):
    """Set the global configuration instance."""
    global _default_config
    _default_config = config
