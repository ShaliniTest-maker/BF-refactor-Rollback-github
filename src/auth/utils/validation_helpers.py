"""
Authentication Input Validation and Sanitization Utilities

This module provides comprehensive security checks for user credentials, tokens, and 
authentication data. Implements input sanitization, format validation, and security 
pattern detection to prevent injection attacks and ensure data integrity across all 
authentication workflows.

Critical for maintaining security posture during the Node.js to Flask migration.
Integrates with Flask-WTF, Werkzeug security utilities, and Flask-SQLAlchemy for 
comprehensive security validation.

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import re
import html
import urllib.parse
import ipaddress
import secrets
import string
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass
from enum import Enum
import unicodedata

# Core Flask imports
from flask import current_app, request, g
from werkzeug.security import safe_str_cmp

# Third-party security libraries with fallbacks
try:
    import bleach
except ImportError:
    bleach = None

try:
    from markupsafe import Markup, escape
except ImportError:
    # Fallback for older versions
    try:
        from flask import Markup, escape
    except ImportError:
        def escape(text):
            return html.escape(str(text), quote=True)
        Markup = str

try:
    from email_validator import validate_email, EmailNotValidError
except ImportError:
    EmailNotValidError = ValueError
    def validate_email(email, **kwargs):
        # Basic email validation fallback
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            raise EmailNotValidError("Invalid email format")
        return type('EmailInfo', (), {'email': email.lower()})()

try:
    import phonenumbers
    from phonenumbers import NumberParseException, PhoneNumberFormat
except ImportError:
    phonenumbers = None
    NumberParseException = ValueError
    PhoneNumberFormat = None

try:
    import structlog
except ImportError:
    # Fallback to standard logging
    import logging
    structlog = type('MockStructlog', (), {
        'get_logger': lambda name: logging.getLogger(name)
    })()

try:
    from sqlalchemy import text
    from sqlalchemy.sql import sqltypes
except ImportError:
    # SQLAlchemy not available - disable SQL-related features
    text = None
    sqltypes = None

# Initialize structured logger for security events
logger = structlog.get_logger("auth_validation")


class ValidationSeverity(Enum):
    """Validation severity levels for security incident classification"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationErrorType(Enum):
    """Types of validation errors for comprehensive error categorization"""
    FORMAT_ERROR = "format_error"
    SECURITY_VIOLATION = "security_violation"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    INVALID_CHARACTERS = "invalid_characters"
    LENGTH_VIOLATION = "length_violation"
    PATTERN_MISMATCH = "pattern_mismatch"
    ENCODING_ERROR = "encoding_error"


@dataclass
class ValidationResult:
    """
    Comprehensive validation result with security context
    
    Provides detailed validation feedback including sanitized values,
    error information, and security incident data for monitoring.
    """
    is_valid: bool
    sanitized_value: Optional[str] = None
    error_type: Optional[ValidationErrorType] = None
    error_message: Optional[str] = None
    severity: ValidationSeverity = ValidationSeverity.LOW
    security_context: Optional[Dict[str, Any]] = None
    suggestions: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary for API responses"""
        return {
            'is_valid': self.is_valid,
            'sanitized_value': self.sanitized_value,
            'error_type': self.error_type.value if self.error_type else None,
            'error_message': self.error_message,
            'severity': self.severity.value,
            'suggestions': self.suggestions or []
        }


class SecurityPatterns:
    """
    Security pattern definitions for threat detection
    
    Comprehensive patterns for identifying common security threats
    including SQL injection, XSS, and other malicious input patterns.
    """
    
    # SQL Injection Patterns - Enhanced for Flask-SQLAlchemy
    SQL_INJECTION_PATTERNS = [
        # Common SQL injection attempts
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(\b(UNION|JOIN|WHERE|HAVING|GROUP\s+BY|ORDER\s+BY)\b)",
        r"(\b(OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?)",
        r"(\b(OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?0['\"]?)",
        r"(--|#|/\*|\*/)",
        r"(\bSYSTEM\b|\bEXEC\b|\bSP_\w+)",
        r"(\b(CAST|CONVERT|CHAR|CHR|ASCII)\s*\()",
        r"(\b(WAITFOR|DELAY)\s+['\"]?\d+['\"]?)",
        r"(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)",
        # SQLAlchemy specific patterns
        r"(\btext\s*\([^)]*\))",
        r"(\braw\s*\([^)]*\))",
        r"(\bexecute\s*\([^)]*\))",
    ]
    
    # XSS Patterns - Enhanced for web form processing
    XSS_PATTERNS = [
        # Script tags and javascript
        r"<\s*script[^>]*>.*?</\s*script\s*>",
        r"<\s*script[^>]*>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"on\w+\s*=",
        # Event handlers
        r"(onclick|onload|onerror|onmouseover|onfocus|onblur)\s*=",
        # Data URLs and expressions
        r"data\s*:\s*text\s*/\s*html",
        r"expression\s*\(",
        # Meta refresh and other dangerous tags
        r"<\s*meta[^>]*refresh",
        r"<\s*iframe[^>]*>",
        r"<\s*embed[^>]*>",
        r"<\s*object[^>]*>",
        # CSS expression attacks
        r"@import",
        r"expression\s*\(",
        r"behavior\s*:",
    ]
    
    # Path Traversal Patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e/",
        r"%2e%2e\\",
        r"\.%2f",
        r"\.%5c",
    ]
    
    # Command Injection Patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$\(\)]",
        r"(nc|netcat|telnet|wget|curl)\s+",
        r"(cat|ls|ps|id|whoami|uname)\s+",
        r"/bin/|/usr/bin/|/sbin/",
        r"\\x[0-9a-fA-F]{2}",
    ]


class InputSanitizer:
    """
    Comprehensive input sanitization for authentication data
    
    Provides secure sanitization methods for user input including
    HTML escaping, SQL injection prevention, and character normalization.
    """
    
    # Allowed HTML tags for rich text (if needed)
    ALLOWED_TAGS = ['b', 'i', 'u', 'em', 'strong']
    ALLOWED_ATTRIBUTES = {}
    
    # Character restrictions for different input types
    USERNAME_ALLOWED_CHARS = string.ascii_letters + string.digits + '_-.'
    PASSWORD_ALLOWED_CHARS = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    @staticmethod
    def sanitize_html(input_str: str, strip_dangerous: bool = True) -> str:
        """
        Sanitize HTML input to prevent XSS attacks
        
        Args:
            input_str: Input string that may contain HTML
            strip_dangerous: Whether to strip or escape dangerous content
            
        Returns:
            Sanitized string safe for display
        """
        if not input_str:
            return ""
        
        try:
            # First normalize Unicode characters
            normalized = unicodedata.normalize('NFKC', input_str)
            
            if strip_dangerous and bleach is not None:
                # Use bleach to strip dangerous HTML
                sanitized = bleach.clean(
                    normalized,
                    tags=InputSanitizer.ALLOWED_TAGS,
                    attributes=InputSanitizer.ALLOWED_ATTRIBUTES,
                    strip=True
                )
            else:
                # Escape all HTML characters (fallback or explicit escaping)
                sanitized = html.escape(normalized, quote=True)
            
            # Additional cleanup for common XSS patterns
            sanitized = re.sub(r'javascript\s*:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'vbscript\s*:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'data\s*:\s*text\s*/\s*html', '', sanitized, flags=re.IGNORECASE)
            
            return sanitized.strip()
            
        except Exception as e:
            logger.error(
                "HTML sanitization error",
                input_str=input_str[:100],  # Log first 100 chars only
                error=str(e)
            )
            # Fallback to basic escaping
            return html.escape(str(input_str), quote=True)
    
    @staticmethod
    def sanitize_sql_input(input_str: str) -> str:
        """
        Sanitize input for SQL operations to prevent injection
        
        Args:
            input_str: Input string for SQL operations
            
        Returns:
            Sanitized string safe for SQL operations
        """
        if not input_str:
            return ""
        
        try:
            # Remove null bytes and control characters
            sanitized = input_str.replace('\x00', '').replace('\r', '').replace('\n', ' ')
            
            # Normalize Unicode
            sanitized = unicodedata.normalize('NFKC', sanitized)
            
            # Remove common SQL injection patterns
            for pattern in SecurityPatterns.SQL_INJECTION_PATTERNS:
                sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
            
            # Additional character filtering
            sanitized = re.sub(r'[^\w\s@.\-+]', '', sanitized)
            
            return sanitized.strip()
            
        except Exception as e:
            logger.error(
                "SQL sanitization error",
                input_str=input_str[:100],
                error=str(e)
            )
            # Fallback to alphanumeric only
            return re.sub(r'[^\w]', '', str(input_str))
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal attacks
        
        Args:
            filename: Original filename
            
        Returns:
            Safe filename without dangerous characters
        """
        if not filename:
            return ""
        
        # Remove path traversal patterns
        sanitized = filename
        for pattern in SecurityPatterns.PATH_TRAVERSAL_PATTERNS:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Remove dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', sanitized)
        
        # Limit length and ensure it's not empty
        sanitized = sanitized[:255].strip()
        if not sanitized:
            return "untitled"
        
        return sanitized
    
    @staticmethod
    def normalize_unicode(input_str: str) -> str:
        """
        Normalize Unicode strings to prevent encoding attacks
        
        Args:
            input_str: Input string with potential Unicode issues
            
        Returns:
            Normalized Unicode string
        """
        if not input_str:
            return ""
        
        try:
            # Normalize to canonical composition
            normalized = unicodedata.normalize('NFC', input_str)
            
            # Remove non-printable characters except common whitespace
            cleaned = ''.join(
                char for char in normalized
                if unicodedata.category(char) not in ['Cc', 'Cf', 'Cs', 'Co', 'Cn']
                or char in [' ', '\t', '\n']
            )
            
            return cleaned.strip()
            
        except Exception as e:
            logger.error(
                "Unicode normalization error",
                input_str=input_str[:100],
                error=str(e)
            )
            # Fallback to ASCII-only
            return input_str.encode('ascii', 'ignore').decode('ascii')


class AuthenticationValidator:
    """
    Comprehensive authentication input validation
    
    Provides validation methods for usernames, emails, passwords, and other
    authentication-related data with security pattern detection and comprehensive
    error handling.
    """
    
    # Validation patterns
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]{3,30}$')
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}'
        r'[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )
    
    # Password requirements
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    
    # Security thresholds
    MAX_USERNAME_LENGTH = 30
    MAX_EMAIL_LENGTH = 254
    MAX_INPUT_LENGTH = 1000
    
    def __init__(self):
        self.security_monitor = SecurityMonitor()
    
    def validate_username(self, username: str, context: Optional[Dict] = None) -> ValidationResult:
        """
        Validate username with security checks
        
        Args:
            username: Username to validate
            context: Additional validation context
            
        Returns:
            ValidationResult with validation outcome and security details
        """
        context = context or {}
        
        # Initial checks
        if not username:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Username is required",
                severity=ValidationSeverity.LOW,
                suggestions=["Please provide a username"]
            )
        
        # Length validation
        if len(username) > self.MAX_USERNAME_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.LENGTH_VIOLATION,
                error_message=f"Username must be {self.MAX_USERNAME_LENGTH} characters or less",
                severity=ValidationSeverity.LOW,
                suggestions=[f"Shorten username to {self.MAX_USERNAME_LENGTH} characters or less"]
            )
        
        # Security pattern detection
        security_result = self.security_monitor.detect_security_patterns(username, "username")
        if not security_result.is_safe:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.SECURITY_VIOLATION,
                error_message="Username contains potentially dangerous patterns",
                severity=security_result.severity,
                security_context=security_result.details,
                suggestions=["Use only letters, numbers, dots, hyphens, and underscores"]
            )
        
        # Sanitize input
        sanitized_username = InputSanitizer.sanitize_sql_input(username)
        
        # Pattern validation
        if not self.USERNAME_PATTERN.match(sanitized_username):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.PATTERN_MISMATCH,
                error_message="Username must contain only letters, numbers, dots, hyphens, and underscores (3-30 characters)",
                severity=ValidationSeverity.LOW,
                suggestions=[
                    "Use 3-30 characters",
                    "Include only letters, numbers, dots, hyphens, and underscores",
                    "Start with a letter or number"
                ]
            )
        
        # Reserved username check
        if self._is_reserved_username(sanitized_username):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Username is reserved and cannot be used",
                severity=ValidationSeverity.MEDIUM,
                suggestions=["Choose a different username"]
            )
        
        # Log successful validation
        logger.info(
            "Username validation successful",
            username_length=len(sanitized_username),
            sanitized=True,
            request_id=getattr(g, 'request_id', None)
        )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=sanitized_username,
            severity=ValidationSeverity.LOW
        )
    
    def validate_email(self, email: str, context: Optional[Dict] = None) -> ValidationResult:
        """
        Validate email address with comprehensive security checks
        
        Args:
            email: Email address to validate
            context: Additional validation context
            
        Returns:
            ValidationResult with validation outcome and security details
        """
        context = context or {}
        
        # Initial checks
        if not email:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Email address is required",
                severity=ValidationSeverity.LOW,
                suggestions=["Please provide an email address"]
            )
        
        # Length validation
        if len(email) > self.MAX_EMAIL_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.LENGTH_VIOLATION,
                error_message=f"Email address must be {self.MAX_EMAIL_LENGTH} characters or less",
                severity=ValidationSeverity.LOW,
                suggestions=[f"Use an email address with {self.MAX_EMAIL_LENGTH} characters or less"]
            )
        
        # Security pattern detection
        security_result = self.security_monitor.detect_security_patterns(email, "email")
        if not security_result.is_safe:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.SECURITY_VIOLATION,
                error_message="Email address contains potentially dangerous patterns",
                severity=security_result.severity,
                security_context=security_result.details,
                suggestions=["Use a standard email format without special characters"]
            )
        
        # Sanitize input
        sanitized_email = InputSanitizer.sanitize_html(email.strip().lower())
        
        # Advanced email validation using email-validator
        try:
            validated_email = validate_email(
                sanitized_email,
                check_deliverability=True if context.get('check_deliverability') else False
            )
            normalized_email = validated_email.email
            
        except EmailNotValidError as e:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message=f"Invalid email format: {str(e)}",
                severity=ValidationSeverity.LOW,
                suggestions=[
                    "Use a valid email format (user@domain.com)",
                    "Check for typos in the email address",
                    "Ensure the domain exists"
                ]
            )
        
        # Additional pattern validation as backup
        if not self.EMAIL_PATTERN.match(normalized_email):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.PATTERN_MISMATCH,
                error_message="Email address format is invalid",
                severity=ValidationSeverity.LOW,
                suggestions=[
                    "Use a valid email format (user@domain.com)",
                    "Avoid special characters except allowed ones"
                ]
            )
        
        # Disposable email detection (if configured)
        if context.get('check_disposable') and self._is_disposable_email(normalized_email):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Disposable email addresses are not allowed",
                severity=ValidationSeverity.MEDIUM,
                suggestions=["Use a permanent email address"]
            )
        
        # Log successful validation
        logger.info(
            "Email validation successful",
            email_domain=normalized_email.split('@')[1],
            normalized=True,
            request_id=getattr(g, 'request_id', None)
        )
        
        return ValidationResult(
            is_valid=True,
            sanitized_value=normalized_email,
            severity=ValidationSeverity.LOW
        )
    
    def validate_password(self, password: str, context: Optional[Dict] = None) -> ValidationResult:
        """
        Validate password with comprehensive security requirements
        
        Args:
            password: Password to validate
            context: Additional validation context (username, old_password, etc.)
            
        Returns:
            ValidationResult with validation outcome and security details
        """
        context = context or {}
        
        # Initial checks
        if not password:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Password is required",
                severity=ValidationSeverity.MEDIUM,
                suggestions=["Please provide a password"]
            )
        
        # Length validation
        if len(password) < self.PASSWORD_MIN_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.LENGTH_VIOLATION,
                error_message=f"Password must be at least {self.PASSWORD_MIN_LENGTH} characters long",
                severity=ValidationSeverity.MEDIUM,
                suggestions=[f"Use at least {self.PASSWORD_MIN_LENGTH} characters"]
            )
        
        if len(password) > self.PASSWORD_MAX_LENGTH:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.LENGTH_VIOLATION,
                error_message=f"Password must be {self.PASSWORD_MAX_LENGTH} characters or less",
                severity=ValidationSeverity.LOW,
                suggestions=[f"Use {self.PASSWORD_MAX_LENGTH} characters or less"]
            )
        
        # Security pattern detection
        security_result = self.security_monitor.detect_security_patterns(password, "password")
        if not security_result.is_safe:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.SECURITY_VIOLATION,
                error_message="Password contains potentially dangerous patterns",
                severity=security_result.severity,
                security_context=security_result.details,
                suggestions=["Avoid special characters that could be used in attacks"]
            )
        
        # Password strength validation
        strength_result = self._validate_password_strength(password)
        if not strength_result.is_valid:
            return strength_result
        
        # Context-specific validations
        if context.get('username'):
            if password.lower() == context['username'].lower():
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.FORMAT_ERROR,
                    error_message="Password cannot be the same as username",
                    severity=ValidationSeverity.MEDIUM,
                    suggestions=["Choose a password different from your username"]
                )
        
        # Common password check
        if self._is_common_password(password):
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Password is too common and easily guessed",
                severity=ValidationSeverity.HIGH,
                suggestions=[
                    "Use a unique password that's not easily guessed",
                    "Combine multiple unrelated words",
                    "Include numbers and special characters"
                ]
            )
        
        # Log successful validation (without logging actual password)
        logger.info(
            "Password validation successful",
            password_length=len(password),
            has_uppercase=any(c.isupper() for c in password),
            has_lowercase=any(c.islower() for c in password),
            has_digits=any(c.isdigit() for c in password),
            has_special=any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password),
            request_id=getattr(g, 'request_id', None)
        )
        
        return ValidationResult(
            is_valid=True,
            severity=ValidationSeverity.LOW
        )
    
    def validate_phone_number(self, phone: str, country_code: str = 'US') -> ValidationResult:
        """
        Validate phone number with international format support
        
        Args:
            phone: Phone number to validate
            country_code: ISO country code for phone validation
            
        Returns:
            ValidationResult with validation outcome
        """
        if not phone:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Phone number is required",
                severity=ValidationSeverity.LOW
            )
        
        # Security pattern detection
        security_result = self.security_monitor.detect_security_patterns(phone, "phone")
        if not security_result.is_safe:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.SECURITY_VIOLATION,
                error_message="Phone number contains invalid characters",
                severity=security_result.severity,
                security_context=security_result.details
            )
        
        # Check if phonenumbers library is available
        if phonenumbers is None:
            # Fallback to basic phone validation
            cleaned_phone = re.sub(r'[^\d+\-\(\)\s]', '', phone)
            if len(cleaned_phone) < 10:
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.FORMAT_ERROR,
                    error_message="Phone number too short",
                    severity=ValidationSeverity.LOW,
                    suggestions=["Use a valid phone number format"]
                )
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=cleaned_phone,
                severity=ValidationSeverity.LOW
            )
        
        try:
            # Parse and validate phone number
            parsed_number = phonenumbers.parse(phone, country_code)
            
            if not phonenumbers.is_valid_number(parsed_number):
                return ValidationResult(
                    is_valid=False,
                    error_type=ValidationErrorType.FORMAT_ERROR,
                    error_message="Invalid phone number format",
                    severity=ValidationSeverity.LOW,
                    suggestions=["Use a valid phone number format for your country"]
                )
            
            # Format the number
            formatted_number = phonenumbers.format_number(
                parsed_number,
                PhoneNumberFormat.E164
            )
            
            return ValidationResult(
                is_valid=True,
                sanitized_value=formatted_number,
                severity=ValidationSeverity.LOW
            )
            
        except NumberParseException as e:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message=f"Phone number parsing error: {str(e)}",
                severity=ValidationSeverity.LOW,
                suggestions=["Use a valid phone number format"]
            )
    
    def _validate_password_strength(self, password: str) -> ValidationResult:
        """
        Validate password strength requirements
        
        Args:
            password: Password to check
            
        Returns:
            ValidationResult with strength assessment
        """
        suggestions = []
        
        # Check character types
        has_uppercase = any(c.isupper() for c in password)
        has_lowercase = any(c.islower() for c in password)
        has_digits = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        # Require at least 3 of 4 character types for passwords >= 8 chars
        # Require all 4 for passwords >= 12 chars
        char_type_count = sum([has_uppercase, has_lowercase, has_digits, has_special])
        
        if len(password) >= 12 and char_type_count < 4:
            if not has_uppercase:
                suggestions.append("Include uppercase letters")
            if not has_lowercase:
                suggestions.append("Include lowercase letters")
            if not has_digits:
                suggestions.append("Include numbers")
            if not has_special:
                suggestions.append("Include special characters (!@#$%^&*)")
                
        elif len(password) >= 8 and char_type_count < 3:
            if not has_uppercase:
                suggestions.append("Include uppercase letters")
            if not has_lowercase:
                suggestions.append("Include lowercase letters")
            if not has_digits:
                suggestions.append("Include numbers")
            if not has_special:
                suggestions.append("Include special characters (!@#$%^&*)")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            suggestions.append("Avoid repeating the same character more than twice")
        
        # Check for sequential characters
        if self._has_sequential_chars(password):
            suggestions.append("Avoid sequential characters (abc, 123, etc.)")
        
        if suggestions:
            return ValidationResult(
                is_valid=False,
                error_type=ValidationErrorType.FORMAT_ERROR,
                error_message="Password does not meet strength requirements",
                severity=ValidationSeverity.MEDIUM,
                suggestions=suggestions
            )
        
        return ValidationResult(is_valid=True)
    
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters in password"""
        sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm'
        ]
        
        password_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password_lower or seq[i:i+3][::-1] in password_lower:
                    return True
        return False
    
    def _is_common_password(self, password: str) -> bool:
        """Check if password is in common password list"""
        # Common passwords to reject
        common_passwords = {
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'abc123',
            'Password1', 'password1', '123456789', 'welcome123'
        }
        return password.lower() in common_passwords
    
    def _is_reserved_username(self, username: str) -> bool:
        """Check if username is reserved"""
        reserved_usernames = {
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'api', 'system', 'support', 'help', 'info', 'mail', 'email',
            'www', 'ftp', 'ssh', 'null', 'undefined', 'anonymous'
        }
        return username.lower() in reserved_usernames
    
    def _is_disposable_email(self, email: str) -> bool:
        """Check if email is from disposable email provider"""
        # Common disposable email domains
        disposable_domains = {
            '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
            'tempmail.org', 'throwaway.email', 'temp-mail.org'
        }
        domain = email.split('@')[1].lower() if '@' in email else ''
        return domain in disposable_domains


@dataclass
class SecurityThreatResult:
    """Result of security threat detection"""
    is_safe: bool
    severity: ValidationSeverity
    threat_types: List[str]
    details: Dict[str, Any]


class SecurityMonitor:
    """
    Security threat detection and monitoring
    
    Monitors input for security threats including SQL injection, XSS,
    path traversal, and command injection attempts.
    """
    
    def detect_security_patterns(self, input_str: str, input_type: str) -> SecurityThreatResult:
        """
        Detect security threat patterns in input
        
        Args:
            input_str: Input string to analyze
            input_type: Type of input (username, email, password, etc.)
            
        Returns:
            SecurityThreatResult with threat assessment
        """
        if not input_str:
            return SecurityThreatResult(
                is_safe=True,
                severity=ValidationSeverity.LOW,
                threat_types=[],
                details={}
            )
        
        threat_types = []
        max_severity = ValidationSeverity.LOW
        details = {}
        
        # SQL Injection Detection
        sql_threats = self._detect_sql_injection(input_str)
        if sql_threats:
            threat_types.append('sql_injection')
            max_severity = max(max_severity, ValidationSeverity.HIGH, key=lambda x: x.value)
            details['sql_patterns'] = sql_threats
        
        # XSS Detection
        xss_threats = self._detect_xss_patterns(input_str)
        if xss_threats:
            threat_types.append('xss_attempt')
            max_severity = max(max_severity, ValidationSeverity.HIGH, key=lambda x: x.value)
            details['xss_patterns'] = xss_threats
        
        # Path Traversal Detection
        path_threats = self._detect_path_traversal(input_str)
        if path_threats:
            threat_types.append('path_traversal')
            max_severity = max(max_severity, ValidationSeverity.MEDIUM, key=lambda x: x.value)
            details['path_patterns'] = path_threats
        
        # Command Injection Detection
        cmd_threats = self._detect_command_injection(input_str)
        if cmd_threats:
            threat_types.append('command_injection')
            max_severity = max(max_severity, ValidationSeverity.HIGH, key=lambda x: x.value)
            details['command_patterns'] = cmd_threats
        
        # Log security events
        if threat_types:
            logger.warning(
                "Security threat detected",
                input_type=input_type,
                threat_types=threat_types,
                severity=max_severity.value,
                input_sample=input_str[:50],  # Log only first 50 chars
                request_id=getattr(g, 'request_id', None),
                source_ip=getattr(request, 'remote_addr', None) if request else None
            )
        
        return SecurityThreatResult(
            is_safe=len(threat_types) == 0,
            severity=max_severity,
            threat_types=threat_types,
            details=details
        )
    
    def _detect_sql_injection(self, input_str: str) -> List[str]:
        """Detect SQL injection patterns"""
        detected_patterns = []
        input_lower = input_str.lower()
        
        for pattern in SecurityPatterns.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        return detected_patterns
    
    def _detect_xss_patterns(self, input_str: str) -> List[str]:
        """Detect XSS attack patterns"""
        detected_patterns = []
        input_lower = input_str.lower()
        
        for pattern in SecurityPatterns.XSS_PATTERNS:
            if re.search(pattern, input_lower, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        return detected_patterns
    
    def _detect_path_traversal(self, input_str: str) -> List[str]:
        """Detect path traversal patterns"""
        detected_patterns = []
        
        for pattern in SecurityPatterns.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        return detected_patterns
    
    def _detect_command_injection(self, input_str: str) -> List[str]:
        """Detect command injection patterns"""
        detected_patterns = []
        
        for pattern in SecurityPatterns.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, input_str, re.IGNORECASE):
                detected_patterns.append(pattern)
        
        return detected_patterns


class CSRFProtectionHelper:
    """
    CSRF protection utilities for Flask-WTF integration
    
    Provides utilities for CSRF token validation and secure form processing
    compatible with Flask-WTF framework.
    """
    
    @staticmethod
    def generate_csrf_token() -> str:
        """
        Generate a cryptographically secure CSRF token
        
        Returns:
            Base64-encoded CSRF token
        """
        try:
            # Generate 32 bytes of random data
            token_bytes = secrets.token_bytes(32)
            # Encode as base64 for URL-safe transmission
            return secrets.token_urlsafe(32)
        except Exception as e:
            logger.error("CSRF token generation failed", error=str(e))
            # Fallback token generation
            return secrets.token_hex(16)
    
    @staticmethod
    def validate_csrf_token(token: str, session_token: str) -> bool:
        """
        Validate CSRF token against session token
        
        Args:
            token: Token from request
            session_token: Token from user session
            
        Returns:
            True if tokens match securely
        """
        if not token or not session_token:
            return False
        
        try:
            # Use constant-time comparison to prevent timing attacks
            return safe_str_cmp(str(token), str(session_token))
        except Exception as e:
            logger.error("CSRF token validation error", error=str(e))
            return False


class ValidationErrorHandler:
    """
    Comprehensive validation error handling with user feedback
    
    Provides standardized error responses and logging for validation failures
    with appropriate security context and user-friendly messages.
    """
    
    @staticmethod
    def handle_validation_error(
        result: ValidationResult,
        field_name: str,
        context: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Handle validation error with comprehensive logging and user feedback
        
        Args:
            result: ValidationResult with error details
            field_name: Name of the field that failed validation
            context: Additional error context
            
        Returns:
            Formatted error response for API
        """
        context = context or {}
        
        # Log validation error with security context
        log_data = {
            'field': field_name,
            'error_type': result.error_type.value if result.error_type else 'unknown',
            'severity': result.severity.value,
            'request_id': getattr(g, 'request_id', None),
            'user_id': getattr(g, 'user_id', None),
            'blueprint': getattr(g, 'blueprint_name', None),
            'endpoint': getattr(g, 'endpoint_name', None)
        }
        
        # Add security context if available
        if result.security_context:
            log_data['security_context'] = result.security_context
        
        # Add request context
        if request:
            log_data.update({
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', '')[:100],  # Limit length
                'method': request.method,
                'path': request.path
            })
        
        # Log appropriate level based on severity
        if result.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]:
            logger.error("High severity validation error", **log_data)
            
            # Trigger security monitoring if configured
            if hasattr(current_app, 'security_monitor'):
                current_app.security_monitor.track_security_event(
                    event_type='validation_failure',
                    severity=result.severity.value,
                    details=log_data
                )
                
        elif result.severity == ValidationSeverity.MEDIUM:
            logger.warning("Medium severity validation error", **log_data)
        else:
            logger.info("Validation error", **log_data)
        
        # Create user-friendly error response
        error_response = {
            'field': field_name,
            'error': result.error_message,
            'type': result.error_type.value if result.error_type else 'validation_error',
            'suggestions': result.suggestions or []
        }
        
        # Add sanitized value if available and safe to return
        if result.sanitized_value and result.severity == ValidationSeverity.LOW:
            error_response['sanitized_value'] = result.sanitized_value
        
        return error_response
    
    @staticmethod
    def create_validation_summary(
        results: List[Tuple[str, ValidationResult]]
    ) -> Dict[str, Any]:
        """
        Create a comprehensive validation summary for multiple fields
        
        Args:
            results: List of (field_name, ValidationResult) tuples
            
        Returns:
            Summary of validation results with overall status
        """
        errors = []
        warnings = []
        has_critical = False
        
        for field_name, result in results:
            if not result.is_valid:
                error_data = ValidationErrorHandler.handle_validation_error(
                    result, field_name
                )
                
                if result.severity in [ValidationSeverity.HIGH, ValidationSeverity.CRITICAL]:
                    errors.append(error_data)
                    if result.severity == ValidationSeverity.CRITICAL:
                        has_critical = True
                else:
                    warnings.append(error_data)
        
        summary = {
            'is_valid': len(errors) == 0,
            'has_critical_errors': has_critical,
            'error_count': len(errors),
            'warning_count': len(warnings),
            'errors': errors,
            'warnings': warnings
        }
        
        # Add overall recommendations
        if errors:
            summary['message'] = "Please correct the errors and try again"
        elif warnings:
            summary['message'] = "Please review the warnings"
        else:
            summary['message'] = "Validation successful"
        
        return summary


# Utility functions for common validation scenarios
def validate_login_credentials(username: str, password: str) -> Dict[str, Any]:
    """
    Validate login credentials with comprehensive security checks
    
    Args:
        username: Username or email address
        password: User password
        
    Returns:
        Validation summary with results for both fields
    """
    validator = AuthenticationValidator()
    results = []
    
    # Determine if username is email format
    if '@' in username:
        email_result = validator.validate_email(username)
        results.append(('email', email_result))
    else:
        username_result = validator.validate_username(username)
        results.append(('username', username_result))
    
    # Always validate password
    password_result = validator.validate_password(
        password,
        context={'username': username}
    )
    results.append(('password', password_result))
    
    return ValidationErrorHandler.create_validation_summary(results)


def validate_registration_data(
    username: str,
    email: str,
    password: str,
    confirm_password: str,
    **kwargs
) -> Dict[str, Any]:
    """
    Validate user registration data with comprehensive checks
    
    Args:
        username: Desired username
        email: Email address
        password: Password
        confirm_password: Password confirmation
        **kwargs: Additional fields (phone, etc.)
        
    Returns:
        Validation summary with results for all fields
    """
    validator = AuthenticationValidator()
    results = []
    
    # Validate username
    username_result = validator.validate_username(username)
    results.append(('username', username_result))
    
    # Validate email
    email_result = validator.validate_email(
        email,
        context={'check_deliverability': kwargs.get('check_email_deliverability', False)}
    )
    results.append(('email', email_result))
    
    # Validate password
    password_result = validator.validate_password(
        password,
        context={'username': username}
    )
    results.append(('password', password_result))
    
    # Validate password confirmation
    if password != confirm_password:
        confirm_result = ValidationResult(
            is_valid=False,
            error_type=ValidationErrorType.FORMAT_ERROR,
            error_message="Password confirmation does not match",
            severity=ValidationSeverity.MEDIUM,
            suggestions=["Ensure both password fields match exactly"]
        )
    else:
        confirm_result = ValidationResult(is_valid=True)
    
    results.append(('confirm_password', confirm_result))
    
    # Validate phone if provided
    if kwargs.get('phone'):
        phone_result = validator.validate_phone_number(
            kwargs['phone'],
            kwargs.get('country_code', 'US')
        )
        results.append(('phone', phone_result))
    
    return ValidationErrorHandler.create_validation_summary(results)


def sanitize_user_input(input_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize user input data for safe processing
    
    Args:
        input_data: Dictionary of user input data
        
    Returns:
        Dictionary with sanitized values
    """
    sanitized = {}
    
    for key, value in input_data.items():
        if isinstance(value, str):
            # Apply appropriate sanitization based on field type
            if key in ['username', 'email']:
                sanitized[key] = InputSanitizer.sanitize_sql_input(value)
            elif key in ['name', 'first_name', 'last_name', 'display_name']:
                sanitized[key] = InputSanitizer.sanitize_html(value)
            elif key == 'filename':
                sanitized[key] = InputSanitizer.sanitize_filename(value)
            else:
                # Default sanitization
                sanitized[key] = InputSanitizer.sanitize_html(value)
        else:
            # Non-string values pass through
            sanitized[key] = value
    
    return sanitized


# Export main classes and functions
__all__ = [
    'ValidationResult',
    'ValidationSeverity',
    'ValidationErrorType',
    'SecurityPatterns',
    'InputSanitizer',
    'AuthenticationValidator',
    'SecurityMonitor',
    'CSRFProtectionHelper',
    'ValidationErrorHandler',
    'validate_login_credentials',
    'validate_registration_data',
    'sanitize_user_input'
]