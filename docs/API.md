# Breach Toolkit API Reference

## Core Modules

### breach_toolkit.core.password_checker

#### BreachResult

Dataclass representing the result of a password breach check.

```python
@dataclass
class BreachResult:
    is_breached: bool      # Whether password was found in breaches
    breach_count: int      # Number of times found (0 if not breached)
    hash_prefix: str       # First 5 chars of SHA-1 hash
    source: str = "hibp"   # Data source
```

#### PasswordChecker

Async password checker using k-anonymity.

```python
class PasswordChecker:
    def __init__(
        self,
        rate_limit: float = 1.5,    # Requests per second
        timeout: int = 10,          # Timeout in seconds
        user_agent: str = "BreachToolkit/1.0"
    )

    async def check_password(self, password: str) -> BreachResult:
        """Check single password against HIBP."""

    async def check_passwords_bulk(
        self,
        passwords: list[str],
        concurrency: int = 5
    ) -> list[BreachResult]:
        """Check multiple passwords concurrently."""
```

**Usage:**
```python
async with PasswordChecker() as checker:
    result = await checker.check_password("test123")
```

#### check_password_sync

Synchronous wrapper for simple usage.

```python
def check_password_sync(password: str) -> BreachResult:
    """Synchronous password check."""
```

---

### breach_toolkit.core.email_checker

#### EmailBreachResult

```python
@dataclass
class EmailBreachResult:
    email: str
    is_breached: bool
    breach_count: int
    breaches: List[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=datetime.utcnow)
```

#### EmailChecker

```python
class EmailChecker:
    def __init__(
        self,
        hibp_api_key: Optional[str] = None,
        rate_limit: float = 1.5,
        timeout: int = 10
    )

    async def check_email_hibp(self, email: str) -> EmailBreachResult:
        """Check email against HIBP."""

    async def check_emails_bulk(
        self,
        emails: List[str],
        concurrency: int = 3
    ) -> List[EmailBreachResult]:
        """Check multiple emails."""
```

---

### breach_toolkit.core.hash_utils

#### HashUtils

Static utility class for hashing operations.

```python
class HashUtils:
    @staticmethod
    def sha1(data: str) -> str:
        """Generate SHA-1 hash (uppercase)."""

    @staticmethod
    def sha256(data: str) -> str:
        """Generate SHA-256 hash."""

    @staticmethod
    def md5(data: str) -> str:
        """Generate MD5 hash."""

    @staticmethod
    def ntlm(password: str) -> str:
        """Generate NTLM hash (Windows)."""

    @staticmethod
    def k_anonymity_prefix(password: str, prefix_length: int = 5) -> tuple[str, str]:
        """Split hash for k-anonymity lookup."""

    @staticmethod
    def identify_hash_type(hash_string: str) -> Optional[HashAlgorithm]:
        """Identify hash algorithm by format."""
```

---

## Parsers

### breach_toolkit.parsers.stealer_log_parser

#### Credential

```python
@dataclass
class Credential:
    url: str
    username: str
    password: str
    source_file: str
    stealer_type: str
    parsed_at: datetime = None

    @property
    def domain(self) -> str:
        """Extract domain from URL."""
```

#### StealerLogParser

```python
class StealerLogParser:
    PATTERNS = {
        "redline": ...,
        "vidar": ...,
        "raccoon": ...,
        "generic_colon": ...,
        "generic_pipe": ...
    }

    def __init__(self, deduplicate: bool = True)

    def parse_file(
        self,
        filepath: str,
        stealer_type: Optional[str] = None
    ) -> Iterator[Credential]:
        """Parse a stealer log file."""

    def parse_directory(
        self,
        directory: str,
        extensions: tuple = ('.txt', '.log')
    ) -> Iterator[Credential]:
        """Parse all log files in directory."""
```

---

### breach_toolkit.parsers.combo_parser

#### ComboEntry

```python
@dataclass
class ComboEntry:
    email: str
    password: str
    source_file: str
    line_number: int
    parsed_at: datetime = None

    @property
    def domain(self) -> str:
        """Extract domain from email."""

    @property
    def username(self) -> str:
        """Extract username from email."""
```

#### ComboParser

```python
class ComboParser:
    DELIMITERS = [':', ';', '|', '\t']

    def __init__(
        self,
        deduplicate: bool = True,
        validate_emails: bool = True,
        min_password_length: int = 1
    )

    def parse_file(
        self,
        filepath: str,
        delimiter: Optional[str] = None,
        encoding: str = 'utf-8'
    ) -> Iterator[ComboEntry]:
        """Parse combo list file."""

    def get_stats(self) -> dict:
        """Get parsing statistics."""

    def reset(self):
        """Reset deduplication cache."""
```

---

## Reporters

### breach_toolkit.reporters.json_reporter

#### JSONReporter

```python
class JSONReporter:
    def __init__(
        self,
        indent: int = 2,
        include_metadata: bool = True,
        mask_passwords: bool = False
    )

    def generate(
        self,
        data: List[Union[Credential, ComboEntry, BreachResult, EmailBreachResult]],
        title: Optional[str] = None
    ) -> str:
        """Generate JSON string."""

    def save(
        self,
        data: List[...],
        filepath: str,
        title: Optional[str] = None
    ):
        """Save to file."""

    def generate_summary(
        self,
        credentials: List[Credential],
        breach_results: Optional[List[BreachResult]] = None
    ) -> str:
        """Generate summary report."""
```

---

### breach_toolkit.reporters.csv_reporter

#### CSVReporter

```python
class CSVReporter:
    def __init__(
        self,
        include_header: bool = True,
        mask_passwords: bool = False,
        delimiter: str = ","
    )

    def generate(self, data: List[...]) -> str:
        """Generate CSV string."""

    def save(self, data: List[...], filepath: str):
        """Save to file."""
```

---

### breach_toolkit.reporters.html_reporter

#### HTMLReporter

```python
class HTMLReporter:
    def __init__(
        self,
        title: str = "Breach Toolkit Report",
        mask_passwords: bool = True
    )

    def generate(
        self,
        data: List[Union[Credential, ComboEntry]],
        breach_results: Optional[List[BreachResult]] = None
    ) -> str:
        """Generate HTML string."""

    def save(
        self,
        data: List[...],
        filepath: str,
        breach_results: Optional[List[BreachResult]] = None
    ):
        """Save to file."""
```

---

## Utilities

### breach_toolkit.utils.rate_limiter

#### RateLimiter

Token bucket rate limiter.

```python
class RateLimiter:
    def __init__(
        self,
        rate: float = 1.5,     # Requests per second
        burst: Optional[int] = None
    )

    async def acquire(self):
        """Acquire permission (async)."""

    def acquire_sync(self):
        """Acquire permission (sync)."""

    @property
    def available_tokens(self) -> float:
        """Current available tokens."""

    def reset(self):
        """Reset to full capacity."""
```

---

### breach_toolkit.utils.logging_config

```python
def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
    include_timestamp: bool = True
) -> logging.Logger:
    """Configure application logging."""

def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""

def get_context_logger(name: str, **context) -> LoggerAdapter:
    """Get logger with context."""
```

---

## Configuration

### breach_toolkit.config

#### Config

```python
@dataclass
class Config:
    hibp: HIBPConfig
    parser: ParserConfig
    reporter: ReporterConfig
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, filepath: str) -> "Config":
        """Load from JSON file."""

    @classmethod
    def from_env(cls) -> "Config":
        """Load from environment."""

    def save(self, filepath: str):
        """Save to file."""
```

#### Global Configuration

```python
def get_config() -> Config:
    """Get global config."""

def set_config(config: Config):
    """Set global config."""
```
