# Breach Toolkit

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)

**Open-source credential breach detection toolkit using k-anonymity for secure password verification.**

Check if credentials have been compromised without exposing sensitive data. Built for security teams who need to verify credential exposure while maintaining privacy.

## Features

- **K-anonymity password checks** - Verify passwords against HIBP without sending the full hash
- **Email breach lookups** - Check if emails appear in known breaches
- **Stealer log parsing** - Parse Redline, Vidar, Raccoon, and other formats
- **Multiple output formats** - JSON, CSV, and HTML reports
- **Async and bulk processing** - Handle large credential lists efficiently
- **Privacy-first design** - Your data never leaves your system

## Installation

```bash
pip install breach-toolkit

# Or from source
git clone https://github.com/cameronhopkin/breach-toolkit.git
cd breach-toolkit
pip install -e .
```

## Quick Start

### Check a Password

```bash
# K-anonymity check - password never sent to HIBP
breach-toolkit check-password "MyPassword123"
```

### Check an Email

```bash
export HIBP_API_KEY="your-key"
breach-toolkit check-email user@example.com
```

### Parse Stealer Logs

```bash
breach-toolkit parse-logs /path/to/logs/ -o results.json
```

### Python API

```python
from breach_toolkit import PasswordChecker, check_password_sync

# Simple synchronous check
result = check_password_sync("password123")
print(f"Breached: {result.is_breached}, Count: {result.breach_count}")

# Async bulk checking
import asyncio

async def check_many():
    async with PasswordChecker() as checker:
        results = await checker.check_passwords_bulk([
            "password1",
            "password2",
            "password3"
        ])
        return results

results = asyncio.run(check_many())
```

## How K-Anonymity Works

Instead of sending your full password hash to HIBP, we:

1. Hash the password with SHA-1
2. Send only the first 5 characters of the hash
3. HIBP returns all hashes matching that prefix (~500 results)
4. We check locally if our full hash is in the results

**HIBP never knows which password you're checking.**

## Configuration

```bash
# Environment variables
export HIBP_API_KEY="your-hibp-api-key"  # Required for email checks
export BREACH_TOOLKIT_RATE_LIMIT="1.5"  # Requests per second
export BREACH_TOOLKIT_LOG_LEVEL="INFO"
```

## Supported Stealer Formats

| Format | Detection Pattern |
|--------|------------------|
| Redline | `URL:` / `Username:` / `Password:` |
| Vidar | `Url:` / `Login:` / `Password:` |
| Raccoon | `URL:` \| `USER:` \| `PASS:` |
| Generic | `url:user:pass` or `url|user|pass` |

## CLI Commands

```bash
# Check single password
breach-toolkit check-password <password>

# Check single email
breach-toolkit check-email <email> --api-key <key>

# Parse stealer log file
breach-toolkit parse-logs <file> -o output.json

# Parse directory of logs
breach-toolkit parse-directory <dir> -o output.csv -f csv

# Bulk check passwords from file
breach-toolkit check-passwords-bulk <file> -o results.json
```

## Security Considerations

- Passwords are never logged or stored
- All API communications use HTTPS
- Rate limiting prevents API abuse
- Deduplication uses one-way hashes

## Project Structure

```
breach-toolkit/
├── src/breach_toolkit/
│   ├── core/              # Password & email checkers
│   ├── parsers/           # Log file parsers
│   ├── reporters/         # Output formatters
│   └── utils/             # Rate limiting, logging
├── tests/                 # Unit tests
├── examples/              # Usage examples
└── docs/                  # Documentation
```

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

```bash
# Development setup
git clone https://github.com/cameronhopkin/breach-toolkit.git
cd breach-toolkit
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
```

## License

MIT License - see [LICENSE](LICENSE)

## Author

Cameron Hopkin. [LinkedIn](https://linkedin.com/in/cameronhopkin), [GitHub](https://github.com/cameronhopkin).
