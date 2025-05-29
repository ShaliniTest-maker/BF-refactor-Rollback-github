"""
Cryptographic utility functions providing secure token generation, data signing, and encryption operations.

This module implements comprehensive cryptographic operations using ItsDangerous and Python cryptography
libraries to support Flask session security, JWT token management, and secure data transmission across
the authentication system. Essential for maintaining cryptographic consistency and security standards
throughout the auth module during the Node.js to Flask migration.

Key Features:
- ItsDangerous secure data signing for Flask session management (Section 6.4.1.3)
- AES-GCM encryption for field-level data protection (Section 6.4.3.1)
- Secure random token generation for authentication workflows (Section 4.6.2)
- PBKDF2 key derivation for password hashing enhancement (Section 6.4.3.2)
- Timing-safe comparison utilities for authentication security (Section 4.6.2)

Dependencies:
- ItsDangerous 2.2+ for secure token signing and session management
- cryptography library for AES-GCM encryption operations
- secrets module for cryptographically secure random generation
- hashlib for PBKDF2 key derivation functions
- hmac for constant-time comparison operations

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import os
import secrets
import hmac
import hashlib
import base64
import logging
from typing import Optional, Union, Dict, Any, Tuple
from datetime import datetime, timedelta

# Core cryptographic libraries
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

# ItsDangerous for Flask session security
from itsdangerous import (
    URLSafeTimedSerializer,
    URLSafeSerializer,
    SignatureExpired,
    BadSignature,
    BadTimeSignature,
    TimestampSigner,
    URLSafeTimedJSONWebSignatureSerializer,
    JSONWebSignatureSerializer
)

# Flask integration for logging and configuration
from flask import current_app, has_app_context

# Initialize module logger
logger = logging.getLogger(__name__)


class CryptoConfig:
    """
    Centralized cryptographic configuration management.
    
    This class manages all cryptographic parameters and settings required for
    secure operations across the authentication system, including key lengths,
    iteration counts, and algorithm selections based on security best practices.
    """
    
    # AES-GCM encryption configuration
    AES_KEY_SIZE = 32  # 256-bit key for AES-256-GCM
    AES_NONCE_SIZE = 12  # 96-bit nonce for GCM mode
    AES_TAG_SIZE = 16  # 128-bit authentication tag
    
    # PBKDF2 configuration (NIST recommended minimum)
    PBKDF2_ITERATIONS = 100000  # NIST SP 800-132 recommended minimum
    PBKDF2_SALT_SIZE = 32  # 256-bit salt
    PBKDF2_KEY_SIZE = 32  # 256-bit derived key
    
    # Token generation configuration
    TOKEN_SIZE = 32  # 256-bit tokens for session IDs and CSRF
    URL_SAFE_TOKEN_SIZE = 43  # Base64-encoded 32-byte token length
    
    # ItsDangerous configuration
    DEFAULT_TOKEN_AGE = 3600  # 1 hour default token lifetime
    SESSION_TOKEN_AGE = 86400  # 24 hours for session tokens
    CSRF_TOKEN_AGE = 3600  # 1 hour for CSRF tokens
    
    # Signature algorithms
    SIGNATURE_ALGORITHM = 'HS256'  # HMAC-SHA256 for JWT-style signatures
    HASH_ALGORITHM = hashes.SHA256()  # SHA-256 for all hash operations


class TokenGenerationError(Exception):
    """Exception raised when secure token generation fails."""
    pass


class EncryptionError(Exception):
    """Exception raised when encryption operations fail."""
    pass


class DecryptionError(Exception):
    """Exception raised when decryption operations fail."""
    pass


class SigningError(Exception):
    """Exception raised when data signing operations fail."""
    pass


class VerificationError(Exception):
    """Exception raised when signature verification fails."""
    pass


class SecureTokenGenerator:
    """
    Secure random token generation utilities.
    
    Provides cryptographically secure random token generation for session IDs,
    CSRF tokens, and other authentication-related identifiers using Python's
    secrets module for maximum entropy and security.
    """
    
    @staticmethod
    def generate_token(size: int = CryptoConfig.TOKEN_SIZE) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            size: Number of bytes to generate (default: 32 for 256-bit tokens)
            
        Returns:
            Cryptographically secure random bytes
            
        Raises:
            TokenGenerationError: If token generation fails
            
        Example:
            >>> token = SecureTokenGenerator.generate_token(32)
            >>> len(token)
            32
        """
        try:
            return secrets.token_bytes(size)
        except Exception as e:
            logger.error(f"Token generation failed: {str(e)}")
            raise TokenGenerationError(f"Failed to generate secure token: {str(e)}")
    
    @staticmethod
    def generate_url_safe_token(size: int = CryptoConfig.TOKEN_SIZE) -> str:
        """
        Generate URL-safe base64-encoded random token.
        
        Perfect for session IDs, CSRF tokens, and other identifiers that need
        to be transmitted safely in URLs and forms without encoding issues.
        
        Args:
            size: Number of random bytes before encoding (default: 32)
            
        Returns:
            URL-safe base64-encoded token string
            
        Raises:
            TokenGenerationError: If token generation fails
            
        Example:
            >>> token = SecureTokenGenerator.generate_url_safe_token(32)
            >>> len(token)  # Base64 encoding increases length
            43
        """
        try:
            return secrets.token_urlsafe(size)
        except Exception as e:
            logger.error(f"URL-safe token generation failed: {str(e)}")
            raise TokenGenerationError(f"Failed to generate URL-safe token: {str(e)}")
    
    @staticmethod
    def generate_hex_token(size: int = CryptoConfig.TOKEN_SIZE) -> str:
        """
        Generate hexadecimal-encoded random token.
        
        Useful for tokens that need to be displayed or logged in hex format
        for debugging and audit purposes.
        
        Args:
            size: Number of random bytes before encoding (default: 32)
            
        Returns:
            Hexadecimal-encoded token string
            
        Raises:
            TokenGenerationError: If token generation fails
            
        Example:
            >>> token = SecureTokenGenerator.generate_hex_token(32)
            >>> len(token)  # Hex encoding doubles length
            64
        """
        try:
            return secrets.token_hex(size)
        except Exception as e:
            logger.error(f"Hex token generation failed: {str(e)}")
            raise TokenGenerationError(f"Failed to generate hex token: {str(e)}")
    
    @staticmethod
    def generate_session_id() -> str:
        """
        Generate secure session identifier.
        
        Creates a URL-safe token specifically for Flask session IDs with
        appropriate length and entropy for session management security.
        
        Returns:
            URL-safe session identifier string
            
        Raises:
            TokenGenerationError: If session ID generation fails
        """
        try:
            return SecureTokenGenerator.generate_url_safe_token(CryptoConfig.TOKEN_SIZE)
        except Exception as e:
            logger.error(f"Session ID generation failed: {str(e)}")
            raise TokenGenerationError(f"Failed to generate session ID: {str(e)}")
    
    @staticmethod
    def generate_csrf_token() -> str:
        """
        Generate secure CSRF token.
        
        Creates a URL-safe token specifically for CSRF protection with
        appropriate entropy for preventing cross-site request forgery attacks.
        
        Returns:
            URL-safe CSRF token string
            
        Raises:
            TokenGenerationError: If CSRF token generation fails
        """
        try:
            return SecureTokenGenerator.generate_url_safe_token(CryptoConfig.TOKEN_SIZE)
        except Exception as e:
            logger.error(f"CSRF token generation failed: {str(e)}")
            raise TokenGenerationError(f"Failed to generate CSRF token: {str(e)}")


class AESGCMCipher:
    """
    AES-GCM encryption and decryption utilities.
    
    Provides authenticated encryption using AES-256-GCM for field-level data
    protection. GCM mode provides both confidentiality and authenticity,
    making it ideal for protecting sensitive data in database fields.
    """
    
    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize AES-GCM cipher with encryption key.
        
        Args:
            key: 256-bit encryption key. If None, generates a new key.
            
        Raises:
            EncryptionError: If key is invalid
        """
        if key is None:
            self.key = self._generate_key()
        else:
            if len(key) != CryptoConfig.AES_KEY_SIZE:
                raise EncryptionError(f"Invalid key size. Expected {CryptoConfig.AES_KEY_SIZE} bytes, got {len(key)}")
            self.key = key
        
        self.cipher = AESGCM(self.key)
    
    @staticmethod
    def _generate_key() -> bytes:
        """
        Generate new 256-bit encryption key.
        
        Returns:
            Cryptographically secure 256-bit key
        """
        return SecureTokenGenerator.generate_token(CryptoConfig.AES_KEY_SIZE)
    
    def encrypt(self, plaintext: Union[str, bytes], associated_data: Optional[bytes] = None) -> Dict[str, str]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            associated_data: Optional associated data for authentication
            
        Returns:
            Dictionary containing base64-encoded nonce and ciphertext
            
        Raises:
            EncryptionError: If encryption fails
            
        Example:
            >>> cipher = AESGCMCipher()
            >>> result = cipher.encrypt("sensitive data")
            >>> 'nonce' in result and 'ciphertext' in result
            True
        """
        try:
            # Convert string to bytes if necessary
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate random nonce
            nonce = SecureTokenGenerator.generate_token(CryptoConfig.AES_NONCE_SIZE)
            
            # Encrypt with GCM mode
            ciphertext = self.cipher.encrypt(nonce, plaintext, associated_data)
            
            # Return base64-encoded components for safe storage
            return {
                'nonce': base64.b64encode(nonce).decode('ascii'),
                'ciphertext': base64.b64encode(ciphertext).decode('ascii')
            }
            
        except Exception as e:
            logger.error(f"AES-GCM encryption failed: {str(e)}")
            raise EncryptionError(f"Encryption operation failed: {str(e)}")
    
    def decrypt(self, encrypted_data: Dict[str, str], associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary with base64-encoded nonce and ciphertext
            associated_data: Optional associated data for authentication
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            DecryptionError: If decryption or authentication fails
            
        Example:
            >>> cipher = AESGCMCipher()
            >>> encrypted = cipher.encrypt("sensitive data")
            >>> decrypted = cipher.decrypt(encrypted)
            >>> decrypted.decode('utf-8')
            'sensitive data'
        """
        try:
            # Decode base64 components
            nonce = base64.b64decode(encrypted_data['nonce'].encode('ascii'))
            ciphertext = base64.b64decode(encrypted_data['ciphertext'].encode('ascii'))
            
            # Decrypt and verify authentication tag
            plaintext = self.cipher.decrypt(nonce, ciphertext, associated_data)
            
            return plaintext
            
        except (InvalidTag, InvalidSignature) as e:
            logger.warning(f"AES-GCM authentication failed: {str(e)}")
            raise DecryptionError("Data authentication failed - tampering detected")
        except Exception as e:
            logger.error(f"AES-GCM decryption failed: {str(e)}")
            raise DecryptionError(f"Decryption operation failed: {str(e)}")
    
    def decrypt_to_string(self, encrypted_data: Dict[str, str], associated_data: Optional[bytes] = None) -> str:
        """
        Decrypt data and return as UTF-8 string.
        
        Args:
            encrypted_data: Dictionary with base64-encoded nonce and ciphertext
            associated_data: Optional associated data for authentication
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            DecryptionError: If decryption fails or result is not valid UTF-8
        """
        try:
            plaintext_bytes = self.decrypt(encrypted_data, associated_data)
            return plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            logger.error(f"Decrypted data is not valid UTF-8: {str(e)}")
            raise DecryptionError("Decrypted data is not valid UTF-8 text")


class PBKDF2KeyDerivation:
    """
    PBKDF2 key derivation utilities for password hashing enhancement.
    
    Provides secure key derivation using PBKDF2 with SHA-256 and configurable
    iteration counts. Used for enhancing password security and deriving
    encryption keys from passwords or passphrases.
    """
    
    @staticmethod
    def derive_key(
        password: Union[str, bytes],
        salt: Optional[bytes] = None,
        iterations: int = CryptoConfig.PBKDF2_ITERATIONS,
        key_length: int = CryptoConfig.PBKDF2_KEY_SIZE
    ) -> Tuple[bytes, bytes]:
        """
        Derive cryptographic key from password using PBKDF2.
        
        Args:
            password: Password or passphrase to derive key from
            salt: Optional salt bytes. If None, generates new random salt.
            iterations: Number of PBKDF2 iterations (default: 100,000)
            key_length: Length of derived key in bytes (default: 32)
            
        Returns:
            Tuple of (derived_key, salt) as bytes
            
        Raises:
            Exception: If key derivation fails
            
        Example:
            >>> key, salt = PBKDF2KeyDerivation.derive_key("password123")
            >>> len(key)
            32
            >>> len(salt)
            32
        """
        try:
            # Convert string password to bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Generate random salt if not provided
            if salt is None:
                salt = SecureTokenGenerator.generate_token(CryptoConfig.PBKDF2_SALT_SIZE)
            
            # Create PBKDF2 key derivation function
            kdf = PBKDF2HMAC(
                algorithm=CryptoConfig.HASH_ALGORITHM,
                length=key_length,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            
            # Derive the key
            derived_key = kdf.derive(password)
            
            return derived_key, salt
            
        except Exception as e:
            logger.error(f"PBKDF2 key derivation failed: {str(e)}")
            raise
    
    @staticmethod
    def verify_key(
        password: Union[str, bytes],
        salt: bytes,
        expected_key: bytes,
        iterations: int = CryptoConfig.PBKDF2_ITERATIONS
    ) -> bool:
        """
        Verify password against derived key using PBKDF2.
        
        Args:
            password: Password to verify
            salt: Salt used in original derivation
            expected_key: Expected derived key
            iterations: Number of PBKDF2 iterations used
            
        Returns:
            True if password is valid, False otherwise
            
        Example:
            >>> key, salt = PBKDF2KeyDerivation.derive_key("password123")
            >>> PBKDF2KeyDerivation.verify_key("password123", salt, key)
            True
            >>> PBKDF2KeyDerivation.verify_key("wrongpass", salt, key)
            False
        """
        try:
            # Convert string password to bytes
            if isinstance(password, str):
                password = password.encode('utf-8')
            
            # Create PBKDF2 key derivation function
            kdf = PBKDF2HMAC(
                algorithm=CryptoConfig.HASH_ALGORITHM,
                length=len(expected_key),
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            
            # Verify the key (raises exception if wrong)
            kdf.verify(password, expected_key)
            return True
            
        except Exception:
            # Verification failed - wrong password
            return False
    
    @staticmethod
    def hash_password(password: str, iterations: int = CryptoConfig.PBKDF2_ITERATIONS) -> str:
        """
        Hash password for secure storage using PBKDF2.
        
        Creates a complete password hash including salt and iteration count
        that can be stored in the database and verified later.
        
        Args:
            password: Password to hash
            iterations: Number of PBKDF2 iterations
            
        Returns:
            Base64-encoded password hash string with embedded metadata
            
        Example:
            >>> hash_str = PBKDF2KeyDerivation.hash_password("password123")
            >>> len(hash_str) > 0
            True
        """
        try:
            # Derive key with new random salt
            derived_key, salt = PBKDF2KeyDerivation.derive_key(password, iterations=iterations)
            
            # Create hash structure with metadata
            hash_data = {
                'algorithm': 'pbkdf2_sha256',
                'iterations': iterations,
                'salt': base64.b64encode(salt).decode('ascii'),
                'hash': base64.b64encode(derived_key).decode('ascii')
            }
            
            # Encode as colon-separated string for storage
            return f"{hash_data['algorithm']}${hash_data['iterations']}${hash_data['salt']}${hash_data['hash']}"
            
        except Exception as e:
            logger.error(f"Password hashing failed: {str(e)}")
            raise
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Password to verify
            password_hash: Stored password hash from hash_password()
            
        Returns:
            True if password is valid, False otherwise
            
        Example:
            >>> hash_str = PBKDF2KeyDerivation.hash_password("password123")
            >>> PBKDF2KeyDerivation.verify_password("password123", hash_str)
            True
            >>> PBKDF2KeyDerivation.verify_password("wrongpass", hash_str)
            False
        """
        try:
            # Parse hash components
            parts = password_hash.split('$')
            if len(parts) != 4:
                return False
            
            algorithm, iterations_str, salt_b64, hash_b64 = parts
            
            if algorithm != 'pbkdf2_sha256':
                return False
            
            iterations = int(iterations_str)
            salt = base64.b64decode(salt_b64.encode('ascii'))
            expected_hash = base64.b64decode(hash_b64.encode('ascii'))
            
            # Verify using PBKDF2
            return PBKDF2KeyDerivation.verify_key(password, salt, expected_hash, iterations)
            
        except Exception:
            return False


class ItsDangerousTokenManager:
    """
    ItsDangerous token management for Flask session security.
    
    Provides secure token generation, signing, and verification using ItsDangerous
    library for Flask session management, CSRF protection, and secure data
    transmission. Integrates with Flask application configuration.
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize token manager with secret key.
        
        Args:
            secret_key: Secret key for signing. Uses Flask app secret if None.
        """
        if secret_key is None and has_app_context():
            secret_key = current_app.config.get('SECRET_KEY')
        
        if not secret_key:
            raise SigningError("No secret key available for token signing")
        
        self.secret_key = secret_key
        
        # Initialize serializers for different use cases
        self.session_serializer = URLSafeTimedSerializer(secret_key)
        self.csrf_serializer = URLSafeTimedSerializer(secret_key, salt='csrf-token')
        self.general_serializer = URLSafeSerializer(secret_key)
        self.timestamp_signer = TimestampSigner(secret_key)
    
    def generate_session_token(self, data: Dict[str, Any], max_age: int = CryptoConfig.SESSION_TOKEN_AGE) -> str:
        """
        Generate secure session token with embedded data.
        
        Args:
            data: Dictionary of data to embed in token
            max_age: Token lifetime in seconds
            
        Returns:
            Signed and serialized token string
            
        Raises:
            SigningError: If token generation fails
        """
        try:
            # Add metadata to token
            token_data = {
                'data': data,
                'created_at': datetime.utcnow().isoformat(),
                'max_age': max_age
            }
            
            return self.session_serializer.dumps(token_data)
            
        except Exception as e:
            logger.error(f"Session token generation failed: {str(e)}")
            raise SigningError(f"Failed to generate session token: {str(e)}")
    
    def verify_session_token(self, token: str, max_age: int = CryptoConfig.SESSION_TOKEN_AGE) -> Dict[str, Any]:
        """
        Verify and extract data from session token.
        
        Args:
            token: Signed token string
            max_age: Maximum token age in seconds
            
        Returns:
            Dictionary of embedded data
            
        Raises:
            VerificationError: If token is invalid or expired
        """
        try:
            token_data = self.session_serializer.loads(token, max_age=max_age)
            return token_data.get('data', {})
            
        except SignatureExpired:
            raise VerificationError("Session token has expired")
        except (BadSignature, BadTimeSignature):
            raise VerificationError("Session token signature is invalid")
        except Exception as e:
            logger.error(f"Session token verification failed: {str(e)}")
            raise VerificationError(f"Failed to verify session token: {str(e)}")
    
    def generate_csrf_token(self, user_id: Optional[str] = None) -> str:
        """
        Generate CSRF protection token.
        
        Args:
            user_id: Optional user identifier to bind token to specific user
            
        Returns:
            CSRF token string
            
        Raises:
            SigningError: If token generation fails
        """
        try:
            csrf_data = {
                'purpose': 'csrf-protection',
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat()
            }
            
            return self.csrf_serializer.dumps(csrf_data)
            
        except Exception as e:
            logger.error(f"CSRF token generation failed: {str(e)}")
            raise SigningError(f"Failed to generate CSRF token: {str(e)}")
    
    def verify_csrf_token(self, token: str, user_id: Optional[str] = None) -> bool:
        """
        Verify CSRF protection token.
        
        Args:
            token: CSRF token to verify
            user_id: Optional user ID to verify token binding
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            csrf_data = self.csrf_serializer.loads(token, max_age=CryptoConfig.CSRF_TOKEN_AGE)
            
            # Verify token purpose
            if csrf_data.get('purpose') != 'csrf-protection':
                return False
            
            # Verify user binding if specified
            if user_id is not None and csrf_data.get('user_id') != user_id:
                return False
            
            return True
            
        except (SignatureExpired, BadSignature, BadTimeSignature):
            return False
        except Exception as e:
            logger.error(f"CSRF token verification failed: {str(e)}")
            return False
    
    def sign_data(self, data: Any) -> str:
        """
        Sign arbitrary data for tamper protection.
        
        Args:
            data: Data to sign (will be JSON serialized)
            
        Returns:
            Signed data string
            
        Raises:
            SigningError: If signing fails
        """
        try:
            return self.general_serializer.dumps(data)
        except Exception as e:
            logger.error(f"Data signing failed: {str(e)}")
            raise SigningError(f"Failed to sign data: {str(e)}")
    
    def verify_signed_data(self, signed_data: str) -> Any:
        """
        Verify and extract signed data.
        
        Args:
            signed_data: Signed data string
            
        Returns:
            Original data
            
        Raises:
            VerificationError: If signature is invalid
        """
        try:
            return self.general_serializer.loads(signed_data)
        except BadSignature:
            raise VerificationError("Data signature is invalid")
        except Exception as e:
            logger.error(f"Signed data verification failed: {str(e)}")
            raise VerificationError(f"Failed to verify signed data: {str(e)}")


class TimingSafeComparison:
    """
    Timing-safe comparison utilities for authentication security.
    
    Provides constant-time comparison functions to prevent timing attacks
    during authentication operations. Essential for comparing passwords,
    tokens, and other sensitive data safely.
    """
    
    @staticmethod
    def compare_digest(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        Timing-safe comparison of two digests.
        
        Uses hmac.compare_digest for constant-time comparison to prevent
        timing attacks against authentication tokens and passwords.
        
        Args:
            a: First value to compare
            b: Second value to compare
            
        Returns:
            True if values are equal, False otherwise
            
        Example:
            >>> TimingSafeComparison.compare_digest("token1", "token1")
            True
            >>> TimingSafeComparison.compare_digest("token1", "token2")
            False
        """
        try:
            # Convert strings to bytes for comparison
            if isinstance(a, str):
                a = a.encode('utf-8')
            if isinstance(b, str):
                b = b.encode('utf-8')
            
            return hmac.compare_digest(a, b)
            
        except Exception as e:
            logger.error(f"Timing-safe comparison failed: {str(e)}")
            return False
    
    @staticmethod
    def compare_hashes(hash1: str, hash2: str) -> bool:
        """
        Timing-safe comparison of password hashes.
        
        Specifically designed for comparing password hashes in authentication
        systems to prevent timing attacks.
        
        Args:
            hash1: First hash to compare
            hash2: Second hash to compare
            
        Returns:
            True if hashes are equal, False otherwise
        """
        return TimingSafeComparison.compare_digest(hash1, hash2)
    
    @staticmethod
    def compare_tokens(token1: str, token2: str) -> bool:
        """
        Timing-safe comparison of authentication tokens.
        
        Used for comparing session tokens, CSRF tokens, and other
        authentication credentials safely.
        
        Args:
            token1: First token to compare
            token2: Second token to compare
            
        Returns:
            True if tokens are equal, False otherwise
        """
        return TimingSafeComparison.compare_digest(token1, token2)


# Convenience functions for common operations
def generate_secure_token(size: int = CryptoConfig.TOKEN_SIZE) -> str:
    """
    Generate a secure URL-safe token.
    
    Convenience function for generating secure tokens for general use.
    
    Args:
        size: Size in bytes of the underlying random data
        
    Returns:
        URL-safe token string
    """
    return SecureTokenGenerator.generate_url_safe_token(size)


def encrypt_sensitive_data(data: Union[str, bytes], key: Optional[bytes] = None) -> Dict[str, str]:
    """
    Encrypt sensitive data using AES-GCM.
    
    Convenience function for encrypting sensitive data with AES-256-GCM.
    
    Args:
        data: Data to encrypt
        key: Encryption key. If None, generates a new key.
        
    Returns:
        Dictionary with encrypted data and metadata
    """
    cipher = AESGCMCipher(key)
    return cipher.encrypt(data)


def decrypt_sensitive_data(encrypted_data: Dict[str, str], key: bytes) -> str:
    """
    Decrypt sensitive data using AES-GCM.
    
    Convenience function for decrypting data encrypted with encrypt_sensitive_data.
    
    Args:
        encrypted_data: Dictionary with encrypted data and metadata
        key: Decryption key
        
    Returns:
        Decrypted data as string
    """
    cipher = AESGCMCipher(key)
    return cipher.decrypt_to_string(encrypted_data)


def hash_password_secure(password: str) -> str:
    """
    Hash password using PBKDF2 with secure defaults.
    
    Convenience function for password hashing with security best practices.
    
    Args:
        password: Password to hash
        
    Returns:
        Secure password hash string
    """
    return PBKDF2KeyDerivation.hash_password(password)


def verify_password_secure(password: str, password_hash: str) -> bool:
    """
    Verify password against secure hash.
    
    Convenience function for password verification with timing-safe comparison.
    
    Args:
        password: Password to verify
        password_hash: Stored password hash
        
    Returns:
        True if password is valid, False otherwise
    """
    return PBKDF2KeyDerivation.verify_password(password, password_hash)


def create_session_token(data: Dict[str, Any], secret_key: Optional[str] = None) -> str:
    """
    Create secure session token with embedded data.
    
    Convenience function for creating session tokens with ItsDangerous.
    
    Args:
        data: Data to embed in token
        secret_key: Secret key for signing
        
    Returns:
        Signed session token
    """
    token_manager = ItsDangerousTokenManager(secret_key)
    return token_manager.generate_session_token(data)


def verify_session_token(token: str, secret_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify and extract data from session token.
    
    Convenience function for session token verification.
    
    Args:
        token: Session token to verify
        secret_key: Secret key for verification
        
    Returns:
        Embedded data dictionary
        
    Raises:
        VerificationError: If token is invalid
    """
    token_manager = ItsDangerousTokenManager(secret_key)
    return token_manager.verify_session_token(token)


# Module initialization and configuration
def init_crypto_helpers(app=None):
    """
    Initialize cryptographic helpers with Flask application.
    
    This function configures the crypto helpers module with Flask application
    settings and validates the cryptographic configuration.
    
    Args:
        app: Flask application instance
    """
    if app is not None:
        # Validate Flask secret key
        secret_key = app.config.get('SECRET_KEY')
        if not secret_key:
            logger.warning("No SECRET_KEY configured - some crypto operations may fail")
        
        # Log cryptographic configuration
        logger.info("Cryptographic helpers initialized with Flask application")
        logger.info(f"AES key size: {CryptoConfig.AES_KEY_SIZE} bytes")
        logger.info(f"PBKDF2 iterations: {CryptoConfig.PBKDF2_ITERATIONS}")
        logger.info(f"Token size: {CryptoConfig.TOKEN_SIZE} bytes")


# Export main classes and functions
__all__ = [
    # Configuration
    'CryptoConfig',
    
    # Exceptions
    'TokenGenerationError',
    'EncryptionError', 
    'DecryptionError',
    'SigningError',
    'VerificationError',
    
    # Core classes
    'SecureTokenGenerator',
    'AESGCMCipher',
    'PBKDF2KeyDerivation',
    'ItsDangerousTokenManager',
    'TimingSafeComparison',
    
    # Convenience functions
    'generate_secure_token',
    'encrypt_sensitive_data',
    'decrypt_sensitive_data',
    'hash_password_secure',
    'verify_password_secure',
    'create_session_token',
    'verify_session_token',
    'init_crypto_helpers'
]