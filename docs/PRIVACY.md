# Privacy & Security

Breach Toolkit is designed with privacy as a core principle. This document explains how your data is protected.

## K-Anonymity: How Password Checks Work

When you check a password, Breach Toolkit uses a technique called **k-anonymity** to protect your privacy.

### The Problem

Traditional breach checking would require sending your password (or its full hash) to a third-party service. This is risky because:

1. The service would know exactly which password you're checking
2. Your password could be logged or intercepted
3. You'd have to trust the service completely

### The Solution: K-Anonymity

Instead of sending your full password hash, Breach Toolkit:

1. **Hashes your password locally** using SHA-1
2. **Sends only the first 5 characters** of the 40-character hash to HIBP
3. **HIBP returns ~500 matching hash suffixes** (all hashes starting with those 5 characters)
4. **Breach Toolkit checks locally** if your full hash is in the returned list

```
Your Password: "secret123"
Full SHA-1: 7C4A8D09CA3762AF61E59520943DC26494F8941B

What's sent to HIBP: "7C4A8"
What HIBP returns: ~500 hashes starting with "7C4A8"
What stays on your machine: Your full hash, your password
```

### Privacy Guarantee

- HIBP receives 1 out of ~500 possible passwords (the prefix)
- HIBP cannot determine which specific password you checked
- Your actual password never leaves your computer
- Even if network traffic is intercepted, attackers only see the prefix

## Data Handling

### What Never Leaves Your Machine

- ✅ Your actual passwords
- ✅ The full hash of your passwords
- ✅ Your credential files
- ✅ Parsed credentials
- ✅ Generated reports

### What Is Sent Externally

- 🌐 First 5 characters of SHA-1 hash (password checks)
- 🌐 Email addresses (only for HIBP email breach checks, requires API key)

## Local Processing

All credential parsing, report generation, and analysis happens entirely on your local machine:

- Log files are parsed locally
- Reports are generated locally
- No credentials are ever transmitted
- No analytics or telemetry

## API Key Security

If you use the HIBP API for email breach checks:

- Store your API key in environment variables, not in code
- The API key is sent via secure HTTPS headers
- Never commit API keys to version control

```bash
# Secure: Environment variable
export HIBP_API_KEY="your-key"

# Insecure: Hardcoded (don't do this)
EmailChecker(hibp_api_key="your-key")  # ❌
```

## Network Security

- All API communications use HTTPS/TLS
- No fallback to insecure HTTP
- Certificate validation is enforced
- Rate limiting prevents abuse

## File Security

When working with credential files:

1. **Input files** are read-only and never modified
2. **Output reports** are created locally
3. **No temporary files** contain plaintext passwords
4. **Deduplication** uses one-way hashes

## Best Practices

### DO

- ✅ Use environment variables for API keys
- ✅ Keep credential files on encrypted storage
- ✅ Use `mask_passwords=True` in reporters
- ✅ Delete reports after analysis
- ✅ Run in isolated environments for sensitive data

### DON'T

- ❌ Commit API keys to repositories
- ❌ Share reports containing passwords
- ❌ Process credentials on untrusted networks
- ❌ Store credential files in cloud sync folders
- ❌ Run with elevated privileges unnecessarily

## Compliance Considerations

While Breach Toolkit is designed for security research and incident response, consider:

- **Data Protection Laws**: Ensure you have authorization to process credentials
- **Breach Notification**: Follow applicable notification requirements
- **Data Retention**: Delete credential data when no longer needed
- **Access Control**: Limit who can run breach analysis

## Audit Trail

Breach Toolkit can be configured for logging:

```python
from breach_toolkit.config import Config, set_config

config = Config(log_level="DEBUG")
set_config(config)
```

This helps maintain audit trails for compliance purposes.

## Questions?

If you have security concerns or questions about data handling, please:

1. Review the source code (it's open source)
2. Open an issue on GitHub
3. Contact the maintainer

## References

- [HIBP API Privacy](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [K-Anonymity Explained](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
- [SHA-1 vs Passwords](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/)
