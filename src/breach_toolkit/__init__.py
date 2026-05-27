"""
Breach Toolkit - Credential breach detection toolkit.

Open-source toolkit for checking credentials against breach databases
using k-anonymity for secure, privacy-preserving verification.

Author: Cameron Hopkin
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Cameron Hopkin"

from .core.password_checker import PasswordChecker, check_password_sync, BreachResult
from .core.email_checker import EmailChecker, EmailBreachResult
from .parsers.stealer_log_parser import StealerLogParser, Credential

__all__ = [
    "PasswordChecker",
    "check_password_sync",
    "BreachResult",
    "EmailChecker",
    "EmailBreachResult",
    "StealerLogParser",
    "Credential",
]
