# Breach Toolkit Usage Guide

This guide covers common usage patterns for Breach Toolkit.

## Table of Contents

- [Installation](#installation)
- [Command Line Interface](#command-line-interface)
- [Python API](#python-api)
- [Configuration](#configuration)
- [Advanced Usage](#advanced-usage)

## Installation

### From PyPI

```bash
pip install breach-toolkit
```

### From Source

```bash
git clone https://github.com/cameronhopkin/breach-toolkit.git
cd breach-toolkit
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

## Command Line Interface

### Check a Password

Check if a password has been exposed in data breaches:

```bash
breach-toolkit check-password "YourPassword123"
```

The password is never sent to any external service. Only the first 5 characters of the SHA-1 hash are sent to HIBP (k-anonymity).

### Check an Email

Check if an email address appears in known breaches:

```bash
# Set your HIBP API key
export HIBP_API_KEY="your-api-key"

# Check email
breach-toolkit check-email user@example.com
```

### Parse Stealer Logs

Extract credentials from infostealer log files:

```bash
# Parse a single file
breach-toolkit parse-logs /path/to/logfile.txt -o results.json

# Parse with CSV output
breach-toolkit parse-logs /path/to/logfile.txt -o results.csv -f csv
```

### Parse Directory of Logs

```bash
breach-toolkit parse-directory /path/to/logs/ -o all_results.json
```

### Bulk Password Check

Check multiple passwords from a file:

```bash
breach-toolkit check-passwords-bulk passwords.txt -o results.json -c 5
```

Where `passwords.txt` contains one password per line.

## Python API

### Basic Password Check

```python
from breach_toolkit import check_password_sync

result = check_password_sync("password123")

if result.is_breached:
    print(f"Found in {result.breach_count:,} breaches!")
else:
    print("Password not found in breaches")
```

### Async Password Check

```python
import asyncio
from breach_toolkit import PasswordChecker

async def check_passwords():
    async with PasswordChecker() as checker:
        # Single check
        result = await checker.check_password("mypassword")

        # Bulk check
        results = await checker.check_passwords_bulk([
            "password1",
            "password2",
            "password3"
        ], concurrency=5)

    return results

results = asyncio.run(check_passwords())
```

### Email Breach Check

```python
import asyncio
from breach_toolkit.core.email_checker import EmailChecker

async def check_email():
    async with EmailChecker(hibp_api_key="your-key") as checker:
        result = await checker.check_email_hibp("user@example.com")

    if result.is_breached:
        print(f"Found in {result.breach_count} breaches:")
        for breach in result.breaches:
            print(f"  - {breach}")

asyncio.run(check_email())
```

### Parsing Stealer Logs

```python
from breach_toolkit.parsers.stealer_log_parser import StealerLogParser

parser = StealerLogParser(deduplicate=True)

for credential in parser.parse_file("/path/to/logfile.txt"):
    print(f"Domain: {credential.domain}")
    print(f"User: {credential.username}")
    print(f"Type: {credential.stealer_type}")
```

### Generating Reports

```python
from breach_toolkit.parsers.stealer_log_parser import StealerLogParser
from breach_toolkit.reporters.json_reporter import JSONReporter
from breach_toolkit.reporters.html_reporter import HTMLReporter

# Parse credentials
parser = StealerLogParser()
credentials = list(parser.parse_file("logfile.txt"))

# JSON report
json_reporter = JSONReporter(mask_passwords=True)
json_reporter.save(credentials, "report.json")

# HTML report
html_reporter = HTMLReporter(title="Breach Report")
html_reporter.save(credentials, "report.html")
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HIBP_API_KEY` | API key for HIBP email checks | None |
| `BREACH_TOOLKIT_RATE_LIMIT` | Requests per second | 1.5 |
| `BREACH_TOOLKIT_TIMEOUT` | Request timeout (seconds) | 10 |
| `BREACH_TOOLKIT_LOG_LEVEL` | Logging level | INFO |

### Configuration File

Create a `config.json` file:

```json
{
  "hibp": {
    "rate_limit": 1.5,
    "timeout": 10
  },
  "parser": {
    "deduplicate": true,
    "validate_emails": true,
    "min_password_length": 1
  },
  "reporter": {
    "mask_passwords": false,
    "include_timestamps": true
  },
  "log_level": "INFO"
}
```

Load in Python:

```python
from breach_toolkit.config import Config, set_config

config = Config.from_file("config.json")
set_config(config)
```

## Advanced Usage

### Custom Rate Limiting

```python
from breach_toolkit import PasswordChecker

checker = PasswordChecker(
    rate_limit=0.5,  # 0.5 requests per second
    timeout=30,
    user_agent="MyApp/1.0"
)
```

### Parsing Multiple Stealer Formats

```python
from breach_toolkit.parsers.stealer_log_parser import StealerLogParser

parser = StealerLogParser()

# Auto-detect format
for cred in parser.parse_file("unknown_format.txt"):
    print(cred)

# Force specific format
for cred in parser.parse_file("file.txt", stealer_type="redline"):
    print(cred)
```

### Combo List Parsing

```python
from breach_toolkit.parsers.combo_parser import ComboParser

parser = ComboParser(
    validate_emails=True,
    min_password_length=8,
    deduplicate=True
)

for entry in parser.parse_file("combo.txt"):
    print(f"{entry.email}: {entry.password}")

# Get statistics
print(parser.get_stats())
```

### Custom Reporting

```python
from breach_toolkit.reporters.json_reporter import JSONReporter

reporter = JSONReporter(
    indent=4,
    include_metadata=True,
    mask_passwords=True
)

# Generate summary
summary_json = reporter.generate_summary(credentials, breach_results)
print(summary_json)
```

## Best Practices

1. **Rate Limiting**: Always respect API rate limits. The default settings are conservative.

2. **Privacy**: Passwords are never logged or transmitted in plaintext. Use `mask_passwords=True` in reporters.

3. **Error Handling**: Wrap API calls in try/except blocks for production use.

4. **Concurrency**: Adjust `concurrency` parameter based on your network and API limits.

5. **Deduplication**: Enable deduplication when parsing large files to reduce API calls.
