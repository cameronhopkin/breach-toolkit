# Contributing to Breach Toolkit

Thank you for your interest in contributing to Breach Toolkit! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building security tools to help the community, and we welcome contributors of all experience levels.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/cameronhopkin/breach-toolkit/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS
   - Relevant logs or error messages

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would benefit users

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Write or update tests
5. Run the test suite
6. Commit with clear messages
7. Push and open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/breach-toolkit.git
cd breach-toolkit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .

# Run type checking
mypy src/
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints for function signatures
- Write docstrings for public functions and classes
- Keep functions focused and small
- Use meaningful variable names

### Example

```python
def check_password(password: str, timeout: int = 10) -> BreachResult:
    """
    Check if a password has been breached using k-anonymity.

    Args:
        password: The plaintext password to check
        timeout: Request timeout in seconds

    Returns:
        BreachResult with breach status and count

    Raises:
        NetworkError: If the API request fails
    """
    # Implementation
```

## Testing

- Write tests for new features
- Maintain or improve code coverage
- Use pytest fixtures for common setup
- Mock external API calls

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=breach_toolkit

# Run specific test file
pytest tests/test_password_checker.py
```

## Commit Messages

Use clear, descriptive commit messages:

```
Add bulk password checking feature

- Implement concurrent password checks with semaphore
- Add progress callback for bulk operations
- Update CLI with new bulk-check command
```

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md if applicable
5. Request review from maintainers

## Security Considerations

Since this is a security tool:

- Never log or expose passwords in plaintext
- Use secure defaults
- Validate all inputs
- Follow the principle of least privilege
- Report security vulnerabilities privately to the maintainer

## Questions?

Feel free to open an issue for questions or reach out to the maintainer.

Thank you for contributing! 🛡️
