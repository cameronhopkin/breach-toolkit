#!/usr/bin/env python3
"""
Breach Toolkit - Hash Utilities
Common hashing functions for credential processing.

Author: Cameron Hopkin
License: MIT
"""
import hashlib
import hmac
from typing import Optional
from enum import Enum


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    MD5 = "md5"
    BCRYPT = "bcrypt"
    ARGON2 = "argon2"


class HashUtils:
    """
    Utility class for hashing operations.

    Provides consistent hashing interfaces for credential processing,
    supporting multiple algorithms commonly found in breach data.
    """

    @staticmethod
    def sha1(data: str, encoding: str = "utf-8") -> str:
        """
        Generate SHA-1 hash (used by HIBP).

        Args:
            data: String to hash
            encoding: Character encoding

        Returns:
            Uppercase hex digest
        """
        # SHA-1 used for HIBP API compatibility, not for security
        return hashlib.sha1(data.encode(encoding), usedforsecurity=False).hexdigest().upper()

    @staticmethod
    def sha256(data: str, encoding: str = "utf-8") -> str:
        """
        Generate SHA-256 hash.

        Args:
            data: String to hash
            encoding: Character encoding

        Returns:
            Lowercase hex digest
        """
        return hashlib.sha256(data.encode(encoding)).hexdigest()

    @staticmethod
    def sha512(data: str, encoding: str = "utf-8") -> str:
        """
        Generate SHA-512 hash.

        Args:
            data: String to hash
            encoding: Character encoding

        Returns:
            Lowercase hex digest
        """
        return hashlib.sha512(data.encode(encoding)).hexdigest()

    @staticmethod
    def md5(data: str, encoding: str = "utf-8") -> str:
        """
        Generate MD5 hash (common in older breaches).

        Note: MD5 is cryptographically broken and should not be used
        for security purposes. Included for breach data compatibility.

        Args:
            data: String to hash
            encoding: Character encoding

        Returns:
            Lowercase hex digest
        """
        # MD5 used for breach data compatibility, not for security
        return hashlib.md5(data.encode(encoding), usedforsecurity=False).hexdigest()

    @staticmethod
    def ntlm(password: str) -> str:
        """
        Generate NTLM hash (Windows password hash).

        NTLM is MD4(UTF-16-LE(password)).

        Args:
            password: Password to hash

        Returns:
            Uppercase hex digest
        """
        # MD4 used for NTLM hash compatibility, not for security
        return hashlib.new(
            'md4',
            password.encode('utf-16-le'),
            usedforsecurity=False
        ).hexdigest().upper()

    @staticmethod
    def k_anonymity_prefix(password: str, prefix_length: int = 5) -> tuple[str, str]:
        """
        Split a password hash for k-anonymity lookup.

        Used for privacy-preserving HIBP queries where only the
        prefix is sent to the API.

        Args:
            password: Password to hash
            prefix_length: Length of prefix (default 5 for HIBP)

        Returns:
            Tuple of (prefix, suffix)
        """
        full_hash = HashUtils.sha1(password)
        return full_hash[:prefix_length], full_hash[prefix_length:]

    @staticmethod
    def hmac_sha256(key: str, message: str, encoding: str = "utf-8") -> str:
        """
        Generate HMAC-SHA256.

        Args:
            key: Secret key
            message: Message to authenticate
            encoding: Character encoding

        Returns:
            Hex digest
        """
        return hmac.new(
            key.encode(encoding),
            message.encode(encoding),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def identify_hash_type(hash_string: str) -> Optional[HashAlgorithm]:
        """
        Attempt to identify hash type by length and format.

        Args:
            hash_string: Hash to identify

        Returns:
            HashAlgorithm or None if unknown
        """
        length = len(hash_string)

        # Check if it's a valid hex string
        try:
            int(hash_string, 16)
        except ValueError:
            # Could be bcrypt or argon2
            if hash_string.startswith("$2"):
                return HashAlgorithm.BCRYPT
            elif hash_string.startswith("$argon2"):
                return HashAlgorithm.ARGON2
            return None

        # Identify by length
        length_map = {
            32: HashAlgorithm.MD5,
            40: HashAlgorithm.SHA1,
            64: HashAlgorithm.SHA256,
            128: HashAlgorithm.SHA512,
        }

        return length_map.get(length)

    @staticmethod
    def normalize_hash(hash_string: str) -> str:
        """
        Normalize a hash string (lowercase, strip whitespace).

        Args:
            hash_string: Hash to normalize

        Returns:
            Normalized hash
        """
        return hash_string.strip().lower()

    @staticmethod
    def compare_constant_time(hash1: str, hash2: str) -> bool:
        """
        Constant-time comparison to prevent timing attacks.

        Args:
            hash1: First hash
            hash2: Second hash

        Returns:
            True if equal
        """
        return hmac.compare_digest(hash1, hash2)


if __name__ == "__main__":
    # Example usage
    test_password = "password123"  # nosec B105 - example only, not a real password

    print(f"SHA-1:   {HashUtils.sha1(test_password)}")
    print(f"SHA-256: {HashUtils.sha256(test_password)}")
    print(f"MD5:     {HashUtils.md5(test_password)}")
    print(f"NTLM:    {HashUtils.ntlm(test_password)}")

    prefix, suffix = HashUtils.k_anonymity_prefix(test_password)
    print(f"K-anonymity: prefix={prefix}, suffix={suffix[:10]}...")
