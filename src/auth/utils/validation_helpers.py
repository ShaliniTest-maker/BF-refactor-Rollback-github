"""
Authentication Input Validation and Sanitization Utilities

This module provides comprehensive security validation and sanitization utilities for
Flask authentication operations during the Node.js to Flask migration. Implements
input sanitization, format validation, and security pattern detection to prevent
injection attacks and ensure data integrity across all authentication workflows.

Key Security Features:
- Input sanitization for authentication data per Section 6.4.6.1
- Email and username format validation with security compliance per Section 6.4.1.5
- SQL injection prevention for Flask-SQLAlchemy operations per Section 6.4.6.1
- XSS prevention utilities for web form processing per Section 6.4.6.1
- Comprehensive validation error handling with user feedback per Section 4.6.3

Dependencies:
- bleach: HTML sanitization and XSS prevention
- sqlalchemy: SQL injection pattern detection
- wtforms: Form validation integration
- flask: Request context and validation utilities
- re: Pattern matching for security validation
"""

import re
import html
import unicodedata
import logging
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs

# Third-party imports for security validation
try:
    import bleach
except ImportError:
    bleach = None

from flask import request, current_app
from werkzeug.datastructures import MultiDict
from markupsafe import Markup, escape
import structlog

# WTForms integration for form validation
try:
    from wtforms import ValidationError
    from wtforms.validators import Email, Length, Regexp
except ImportError:
    ValidationError = Exception
    Email = None
    Length = None
    Regexp = None


class ValidationSeverity(Enum):
    """Security validation severity levels for threat assessment"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ValidationType(Enum):
    """Types of validation performed for security monitoring"""
    EMAIL = "email"
    USERNAME = "username"
    PASSWORD = "password"
    TOKEN = "token"
    GENERAL_INPUT = "general_input"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF_TOKEN = "csrf_token"
    AUTH_HEADER = "auth_header"


@dataclass
class ValidationResult:
    """Comprehensive validation result with security context"""
    is_valid: bool
    sanitized_value: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    severity: ValidationSeverity = ValidationSeverity.LOW
    validation_type: ValidationType = ValidationType.GENERAL_INPUT
    threat_indicators: List[str] = field(default_factory=list)
    original_length: int = 0
    sanitized_length: int = 0
    
    def add_error(self, message: str, severity: ValidationSeverity = ValidationSeverity.MEDIUM):
        """Add validation error with severity tracking"""
        self.errors.append(message)
        self.is_valid = False
        if severity.value > self.severity.value:
            self.severity = severity
    
    def add_warning(self, message: str):
        """Add validation warning for suspicious patterns"""
        self.warnings.append(message)
    
    def add_threat_indicator(self, indicator: str):
        """Add detected security threat indicator"""
        self.threat_indicators.append(indicator)
        if self.severity == ValidationSeverity.LOW:
            self.severity = ValidationSeverity.MEDIUM


class AuthenticationValidator:
    """
    Comprehensive authentication input validation and sanitization service
    
    Provides enterprise-grade security validation for all authentication data
    including email addresses, usernames, passwords, tokens, and form inputs.
    Implements multiple layers of security checking including format validation,
    content sanitization, and threat pattern detection.
    """
    
    def __init__(self, app=None):
        """Initialize validator with Flask application context"""
        self.app = app
        self.logger = structlog.get_logger("auth_validator")
        
        # Security patterns for threat detection
        self._sql_injection_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bSELECT\b.*\bFROM\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bCREATE\b.*\bTABLE\b)",
            r"(\bALTER\b.*\bTABLE\b)",
            r"(;.*(-{2}|\/\*))",
            r"(\'\s*OR\s*\'\w*\'\s*=\s*\'\w*)",
            r"(\'\s*OR\s*1\s*=\s*1)",
            r"(\bEXEC\b|\bEXECUTE\b)",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)"
        ]
        
        self._xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"<iframe[^>]*>",
            r"<embed[^>]*>",
            r"<object[^>]*>",
            r"<applet[^>]*>",
            r"<meta[^>]*>",
            r"<link[^>]*>",
            r"<style[^>]*>.*?</style>",
            r"expression\s*\(",
            r"url\s*\(",
            r"@import",
            r"<svg[^>]*>.*?</svg>",
            r"<math[^>]*>.*?</math>"
        ]
        
        # Username security patterns
        self._username_security_patterns = [
            r"^admin$|^administrator$|^root$|^system$",  # Reserved usernames
            r".*[<>\"'&].*",  # HTML injection characters
            r".*[\x00-\x1f\x7f-\x9f].*",  # Control characters
            r"^\.+$|^\-+$|^_+$",  # Special character only usernames
            r".*\.(exe|bat|cmd|scr|com|pif)$",  # Executable extensions
            r".*(script|javascript|vbscript).*",  # Script injection
        ]
        
        # Email security patterns
        self._email_security_patterns = [
            r".*[<>\"'&].*",  # HTML injection characters
            r".*[\x00-\x1f\x7f-\x9f].*",  # Control characters
            r".*\.(exe|bat|cmd|scr|com|pif).*",  # Executable patterns
            r".*(script|javascript|vbscript).*",  # Script injection
            r".*\+.*\+.*",  # Multiple plus signs (potential bypass)
        ]
        
        # Compile regex patterns for performance
        self._compiled_sql_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self._sql_injection_patterns]
        self._compiled_xss_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self._xss_patterns]
        self._compiled_username_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self._username_security_patterns]
        self._compiled_email_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self._email_security_patterns]
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize validator with Flask application factory pattern"""
        app.auth_validator = self
        
        # Configure validation settings from Flask config
        self.max_input_length = app.config.get('AUTH_MAX_INPUT_LENGTH', 1024)
        self.strict_validation = app.config.get('AUTH_STRICT_VALIDATION', True)
        self.log_security_events = app.config.get('AUTH_LOG_SECURITY_EVENTS', True)
        
        self.logger.info(
            "Authentication validator initialized",
            max_input_length=self.max_input_length,
            strict_validation=self.strict_validation
        )
    
    def validate_email(self, email: str, strict: bool = True) -> ValidationResult:
        """
        Comprehensive email validation with security pattern detection
        
        Validates email format, length, and security compliance per Section 6.4.1.5.
        Includes domain validation, internationalization support, and threat detection.
        
        Args:
            email: Email address to validate
            strict: Enable strict validation mode for additional security checks
            
        Returns:
            ValidationResult with sanitized email and security assessment
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.EMAIL,
            original_length=len(email) if email else 0
        )
        
        if not email:
            result.add_error("Email address is required", ValidationSeverity.HIGH)
            return result
        
        # Length validation
        if len(email) > self.max_input_length:
            result.add_error(
                f"Email address exceeds maximum length of {self.max_input_length} characters",
                ValidationSeverity.HIGH
            )
            return result
        
        # Basic sanitization
        sanitized_email = self._sanitize_input(email, preserve_email_chars=True)
        result.sanitized_value = sanitized_email
        result.sanitized_length = len(sanitized_email)
        
        # Check for security threats
        self._check_security_patterns(sanitized_email, self._compiled_email_patterns, result, "email")
        
        # Normalize Unicode characters
        try:
            normalized_email = unicodedata.normalize('NFKC', sanitized_email).lower().strip()
        except Exception as e:
            result.add_error(f"Email normalization failed: {str(e)}", ValidationSeverity.MEDIUM)
            return result
        
        # RFC 5322 compliant email validation
        email_pattern = re.compile(
            r'^[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+/=?^_`{|}~-]+)*'
            r'@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'
        )
        
        if not email_pattern.match(normalized_email):
            result.add_error("Invalid email format", ValidationSeverity.MEDIUM)
            return result
        
        # Domain validation
        try:
            local_part, domain = normalized_email.split('@', 1)
            
            # Local part validation
            if len(local_part) > 64:
                result.add_error("Email local part exceeds 64 characters", ValidationSeverity.MEDIUM)
            
            if local_part.startswith('.') or local_part.endswith('.'):
                result.add_error("Email local part cannot start or end with period", ValidationSeverity.MEDIUM)
            
            if '..' in local_part:
                result.add_error("Email local part cannot contain consecutive periods", ValidationSeverity.MEDIUM)
            
            # Domain validation
            if len(domain) > 253:
                result.add_error("Email domain exceeds 253 characters", ValidationSeverity.MEDIUM)
            
            if not domain or domain.startswith('.') or domain.endswith('.'):
                result.add_error("Invalid email domain format", ValidationSeverity.MEDIUM)
            
            # Check for suspicious domains in strict mode
            if strict:
                self._validate_email_domain_security(domain, result)
                
        except ValueError:
            result.add_error("Email format validation failed", ValidationSeverity.MEDIUM)
        
        # Additional security validation for authentication context
        if strict and result.is_valid:
            self._validate_authentication_email_security(normalized_email, result)
        
        # Update sanitized value with normalized result
        if result.is_valid:
            result.sanitized_value = normalized_email
        
        # Log security events
        if result.threat_indicators and self.log_security_events:
            self.logger.warning(
                "Email security threats detected",
                email_hash=hash(normalized_email),
                threats=result.threat_indicators,
                severity=result.severity.value
            )
        
        return result
    
    def validate_username(self, username: str, strict: bool = True) -> ValidationResult:
        """
        Comprehensive username validation with security pattern detection
        
        Validates username format, length, character restrictions, and security
        compliance per Section 6.4.1.5. Includes reserved username checking
        and injection attack prevention.
        
        Args:
            username: Username to validate
            strict: Enable strict validation mode for additional security checks
            
        Returns:
            ValidationResult with sanitized username and security assessment
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.USERNAME,
            original_length=len(username) if username else 0
        )
        
        if not username:
            result.add_error("Username is required", ValidationSeverity.HIGH)
            return result
        
        # Length validation
        if len(username) < 3:
            result.add_error("Username must be at least 3 characters long", ValidationSeverity.MEDIUM)
            return result
        
        if len(username) > 50:  # Reasonable username length limit
            result.add_error("Username cannot exceed 50 characters", ValidationSeverity.MEDIUM)
            return result
        
        # Basic sanitization
        sanitized_username = self._sanitize_input(username, preserve_username_chars=True)
        result.sanitized_value = sanitized_username
        result.sanitized_length = len(sanitized_username)
        
        # Check for security threats
        self._check_security_patterns(sanitized_username, self._compiled_username_patterns, result, "username")
        
        # Normalize and validate character set
        try:
            normalized_username = unicodedata.normalize('NFKC', sanitized_username).strip()
        except Exception as e:
            result.add_error(f"Username normalization failed: {str(e)}", ValidationSeverity.MEDIUM)
            return result
        
        # Character validation - allow alphanumeric, underscore, hyphen, and period
        username_pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
        if not username_pattern.match(normalized_username):
            result.add_error(
                "Username can only contain letters, numbers, periods, underscores, and hyphens",
                ValidationSeverity.MEDIUM
            )
            return result
        
        # Cannot start or end with special characters
        if normalized_username[0] in '._-' or normalized_username[-1] in '._-':
            result.add_error(
                "Username cannot start or end with period, underscore, or hyphen",
                ValidationSeverity.MEDIUM
            )
        
        # Cannot contain consecutive special characters
        if re.search(r'[._-]{2,}', normalized_username):
            result.add_error(
                "Username cannot contain consecutive special characters",
                ValidationSeverity.MEDIUM
            )
        
        # Reserved username validation
        reserved_usernames = {
            'admin', 'administrator', 'root', 'system', 'user', 'guest',
            'api', 'www', 'mail', 'ftp', 'test', 'demo', 'support',
            'info', 'null', 'undefined', 'anonymous', 'public'
        }
        
        if normalized_username.lower() in reserved_usernames:
            result.add_error("Username is reserved and cannot be used", ValidationSeverity.HIGH)
        
        # Strict mode additional validations
        if strict and result.is_valid:
            # Check for common attack patterns
            if any(pattern in normalized_username.lower() for pattern in ['script', 'admin', 'test']):
                result.add_warning("Username contains potentially suspicious patterns")
            
            # Check for excessive special characters
            special_char_count = sum(1 for c in normalized_username if c in '._-')
            if special_char_count > len(normalized_username) // 3:
                result.add_warning("Username contains high ratio of special characters")
        
        # Update sanitized value
        if result.is_valid:
            result.sanitized_value = normalized_username
        
        # Log security events
        if result.threat_indicators and self.log_security_events:
            self.logger.warning(
                "Username security threats detected",
                username_hash=hash(normalized_username),
                threats=result.threat_indicators,
                severity=result.severity.value
            )
        
        return result
    
    def validate_password_strength(self, password: str) -> ValidationResult:
        """
        Password strength validation with security policy enforcement
        
        Validates password strength according to security requirements while
        preventing common password attacks and ensuring compliance with
        authentication security standards.
        
        Args:
            password: Password to validate
            
        Returns:
            ValidationResult with strength assessment and recommendations
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.PASSWORD,
            original_length=len(password) if password else 0
        )
        
        if not password:
            result.add_error("Password is required", ValidationSeverity.HIGH)
            return result
        
        # Length requirements
        if len(password) < 8:
            result.add_error("Password must be at least 8 characters long", ValidationSeverity.HIGH)
        
        if len(password) > 128:  # Prevent DoS through excessive length
            result.add_error("Password cannot exceed 128 characters", ValidationSeverity.MEDIUM)
        
        # Character requirements
        has_lower = re.search(r'[a-z]', password)
        has_upper = re.search(r'[A-Z]', password)
        has_digit = re.search(r'\d', password)
        has_special = re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
        
        requirements_met = sum([bool(has_lower), bool(has_upper), bool(has_digit), bool(has_special)])
        
        if requirements_met < 3:
            result.add_error(
                "Password must contain at least 3 of: lowercase, uppercase, numbers, special characters",
                ValidationSeverity.HIGH
            )
        
        # Check for common weak patterns
        common_patterns = [
            (r'(.)\1{2,}', "Password contains repeated characters"),
            (r'(012|123|234|345|456|567|678|789|890)', "Password contains sequential numbers"),
            (r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', "Password contains sequential letters"),
            (r'(qwer|asdf|zxcv|1234|pass|word)', "Password contains common keyboard patterns")
        ]
        
        for pattern, message in common_patterns:
            if re.search(pattern, password.lower()):
                result.add_warning(message)
        
        # Common password blacklist check (basic)
        common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey'
        }
        
        if password.lower() in common_passwords:
            result.add_error("Password is too common and easily guessable", ValidationSeverity.HIGH)
        
        # Password strength scoring
        strength_score = self._calculate_password_strength(password)
        
        if strength_score < 30:
            result.add_error("Password is too weak", ValidationSeverity.HIGH)
        elif strength_score < 50:
            result.add_warning("Password strength is below recommended level")
        
        # No sanitization for passwords - return original
        result.sanitized_value = password
        result.sanitized_length = len(password)
        
        return result
    
    def sanitize_authentication_input(self, input_data: str, input_type: str = "general") -> ValidationResult:
        """
        General authentication input sanitization per Section 6.4.6.1
        
        Provides comprehensive input sanitization for authentication forms,
        tokens, and general user input to prevent injection attacks and
        ensure data integrity.
        
        Args:
            input_data: Raw input data to sanitize
            input_type: Type of input for context-aware sanitization
            
        Returns:
            ValidationResult with sanitized input and security assessment
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.GENERAL_INPUT,
            original_length=len(input_data) if input_data else 0
        )
        
        if input_data is None:
            result.sanitized_value = ""
            return result
        
        # Convert to string if not already
        input_str = str(input_data)
        
        # Length validation
        if len(input_str) > self.max_input_length:
            result.add_error(
                f"Input exceeds maximum length of {self.max_input_length} characters",
                ValidationSeverity.HIGH
            )
            return result
        
        # Basic sanitization
        sanitized = self._sanitize_input(input_str)
        
        # SQL injection detection
        sql_result = self.detect_sql_injection(sanitized)
        if not sql_result.is_valid:
            result.errors.extend(sql_result.errors)
            result.threat_indicators.extend(sql_result.threat_indicators)
            result.severity = max(result.severity, sql_result.severity, key=lambda x: x.value)
        
        # XSS detection
        xss_result = self.detect_xss_attempt(sanitized)
        if not xss_result.is_valid:
            result.errors.extend(xss_result.errors)
            result.threat_indicators.extend(xss_result.threat_indicators)
            result.severity = max(result.severity, xss_result.severity, key=lambda x: x.value)
        
        # Apply XSS prevention sanitization
        sanitized = self._sanitize_xss(sanitized)
        
        result.sanitized_value = sanitized
        result.sanitized_length = len(sanitized)
        
        # Log security events
        if result.threat_indicators and self.log_security_events:
            self.logger.warning(
                "Input security threats detected",
                input_type=input_type,
                threats=result.threat_indicators,
                severity=result.severity.value
            )
        
        return result
    
    def detect_sql_injection(self, input_str: str) -> ValidationResult:
        """
        SQL injection detection for Flask-SQLAlchemy integration per Section 6.4.6.1
        
        Detects potential SQL injection patterns in user input to prevent
        database attacks and ensure SQLAlchemy query safety.
        
        Args:
            input_str: Input string to analyze
            
        Returns:
            ValidationResult with injection detection results
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.SQL_INJECTION,
            sanitized_value=input_str,
            original_length=len(input_str) if input_str else 0
        )
        
        if not input_str:
            return result
        
        # Check against SQL injection patterns
        threat_count = 0
        detected_patterns = []
        
        for pattern in self._compiled_sql_patterns:
            if pattern.search(input_str):
                threat_count += 1
                detected_patterns.append(pattern.pattern)
                result.add_threat_indicator(f"SQL pattern: {pattern.pattern}")
        
        if threat_count > 0:
            result.add_error(
                f"Potential SQL injection detected ({threat_count} patterns)",
                ValidationSeverity.CRITICAL
            )
            result.is_valid = False
        
        # Additional heuristic checks
        suspicious_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        char_count = sum(1 for char in suspicious_chars if char in input_str.lower())
        
        if char_count >= 3:
            result.add_warning("Input contains multiple SQL injection indicators")
            result.add_threat_indicator(f"Suspicious character count: {char_count}")
        
        # Check for encoded injection attempts
        encoded_patterns = ['%27', '%22', '%3B', '%2D%2D', '%2F%2A', '%2A%2F']
        for pattern in encoded_patterns:
            if pattern.lower() in input_str.lower():
                result.add_threat_indicator(f"Encoded SQL character: {pattern}")
                result.add_warning("Potential encoded SQL injection attempt")
        
        result.sanitized_length = len(result.sanitized_value)
        
        return result
    
    def detect_xss_attempt(self, input_str: str) -> ValidationResult:
        """
        XSS attack detection for web form processing per Section 6.4.6.1
        
        Detects Cross-Site Scripting (XSS) attempts in user input to prevent
        script injection and ensure form processing security.
        
        Args:
            input_str: Input string to analyze
            
        Returns:
            ValidationResult with XSS detection results
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.XSS,
            sanitized_value=input_str,
            original_length=len(input_str) if input_str else 0
        )
        
        if not input_str:
            return result
        
        # Check against XSS patterns
        threat_count = 0
        detected_patterns = []
        
        for pattern in self._compiled_xss_patterns:
            if pattern.search(input_str):
                threat_count += 1
                detected_patterns.append(pattern.pattern)
                result.add_threat_indicator(f"XSS pattern: {pattern.pattern}")
        
        if threat_count > 0:
            result.add_error(
                f"Potential XSS attack detected ({threat_count} patterns)",
                ValidationSeverity.HIGH
            )
            result.is_valid = False
        
        # Check for event handlers
        event_handlers = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseout',
            'onfocus', 'onblur', 'onchange', 'onsubmit', 'onkeydown',
            'onkeyup', 'onkeypress'
        ]
        
        for handler in event_handlers:
            if handler.lower() in input_str.lower():
                result.add_threat_indicator(f"Event handler: {handler}")
                result.add_warning(f"Potential XSS event handler detected: {handler}")
        
        # Check for JavaScript protocols
        if re.search(r'javascript\s*:', input_str, re.IGNORECASE):
            result.add_threat_indicator("JavaScript protocol")
            result.add_error("JavaScript protocol detected", ValidationSeverity.HIGH)
            result.is_valid = False
        
        # Check for data URLs with script content
        if re.search(r'data\s*:[^,]*script', input_str, re.IGNORECASE):
            result.add_threat_indicator("Data URL with script")
            result.add_error("Data URL with script content detected", ValidationSeverity.HIGH)
            result.is_valid = False
        
        # Check for encoded XSS attempts
        encoded_patterns = {
            '%3Cscript%3E': '<script>',
            '%3C%2Fscript%3E': '</script>',
            '&lt;script&gt;': '<script>',
            '&lt;/script&gt;': '</script>',
            '&#60;script&#62;': '<script>',
            '&#x3C;script&#x3E;': '<script>'
        }
        
        for encoded, decoded in encoded_patterns.items():
            if encoded.lower() in input_str.lower():
                result.add_threat_indicator(f"Encoded XSS: {encoded}")
                result.add_warning(f"Encoded XSS pattern detected: {decoded}")
        
        result.sanitized_length = len(result.sanitized_value)
        
        return result
    
    def validate_csrf_token(self, token: str, session_token: str = None) -> ValidationResult:
        """
        CSRF token validation for form security per Section 4.6.2
        
        Validates CSRF tokens to prevent Cross-Site Request Forgery attacks
        in authentication forms and AJAX requests.
        
        Args:
            token: CSRF token to validate
            session_token: Session token for comparison (optional)
            
        Returns:
            ValidationResult with CSRF validation results
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.CSRF_TOKEN,
            original_length=len(token) if token else 0
        )
        
        if not token:
            result.add_error("CSRF token is required", ValidationSeverity.HIGH)
            return result
        
        # Basic format validation
        csrf_pattern = re.compile(r'^[A-Za-z0-9+/=_-]{20,}$')
        if not csrf_pattern.match(token):
            result.add_error("Invalid CSRF token format", ValidationSeverity.HIGH)
            return result
        
        # Length validation
        if len(token) < 20 or len(token) > 256:
            result.add_error("CSRF token length invalid", ValidationSeverity.HIGH)
            return result
        
        # Token entropy check (basic)
        unique_chars = len(set(token))
        if unique_chars < 10:  # Too few unique characters
            result.add_error("CSRF token has insufficient entropy", ValidationSeverity.HIGH)
            return result
        
        # Check for obvious patterns
        if re.search(r'(.)\1{4,}', token):  # 5+ repeated characters
            result.add_error("CSRF token contains suspicious patterns", ValidationSeverity.MEDIUM)
        
        # Session token comparison if provided
        if session_token and len(session_token) > 0:
            if token == session_token:
                result.add_error("CSRF token cannot match session token", ValidationSeverity.HIGH)
                return result
        
        result.sanitized_value = token
        result.sanitized_length = len(token)
        
        return result
    
    def validate_authentication_header(self, auth_header: str) -> ValidationResult:
        """
        Authentication header validation for API security
        
        Validates Authorization headers for Bearer tokens, Basic auth,
        and other authentication schemes with security compliance.
        
        Args:
            auth_header: Authorization header value
            
        Returns:
            ValidationResult with header validation results
        """
        result = ValidationResult(
            is_valid=True,
            validation_type=ValidationType.AUTH_HEADER,
            original_length=len(auth_header) if auth_header else 0
        )
        
        if not auth_header:
            result.add_error("Authorization header is required", ValidationSeverity.HIGH)
            return result
        
        # Basic format validation
        parts = auth_header.strip().split(' ', 1)
        if len(parts) != 2:
            result.add_error("Invalid authorization header format", ValidationSeverity.HIGH)
            return result
        
        scheme, credentials = parts
        scheme = scheme.lower()
        
        # Validate authentication scheme
        valid_schemes = {'bearer', 'basic', 'digest', 'api-key'}
        if scheme not in valid_schemes:
            result.add_error(f"Unsupported authentication scheme: {scheme}", ValidationSeverity.MEDIUM)
            return result
        
        # Scheme-specific validation
        if scheme == 'bearer':
            self._validate_bearer_token(credentials, result)
        elif scheme == 'basic':
            self._validate_basic_auth(credentials, result)
        
        # General security checks
        self._check_auth_header_security(auth_header, result)
        
        result.sanitized_value = auth_header
        result.sanitized_length = len(auth_header)
        
        return result
    
    def validate_form_data(self, form_data: Dict[str, Any], required_fields: List[str] = None) -> Dict[str, ValidationResult]:
        """
        Comprehensive form data validation for authentication forms
        
        Validates entire form submissions with field-specific validation
        and comprehensive security checking per Section 4.6.3.
        
        Args:
            form_data: Dictionary of form field data
            required_fields: List of required field names
            
        Returns:
            Dictionary mapping field names to ValidationResult objects
        """
        results = {}
        required_fields = required_fields or []
        
        # Validate required fields
        for field_name in required_fields:
            if field_name not in form_data or not form_data[field_name]:
                results[field_name] = ValidationResult(
                    is_valid=False,
                    validation_type=ValidationType.GENERAL_INPUT
                )
                results[field_name].add_error(f"{field_name} is required", ValidationSeverity.HIGH)
        
        # Validate each field
        for field_name, field_value in form_data.items():
            if field_name in results:
                continue  # Already processed as required field
            
            # Field-specific validation
            if field_name.lower() in ['email', 'email_address']:
                results[field_name] = self.validate_email(str(field_value))
            elif field_name.lower() in ['username', 'user_name', 'login']:
                results[field_name] = self.validate_username(str(field_value))
            elif field_name.lower() in ['password', 'pass', 'pwd']:
                results[field_name] = self.validate_password_strength(str(field_value))
            elif field_name.lower() in ['csrf_token', 'csrftoken', '_token']:
                results[field_name] = self.validate_csrf_token(str(field_value))
            else:
                results[field_name] = self.sanitize_authentication_input(str(field_value), field_name)
        
        # Log form validation summary
        if self.log_security_events:
            error_count = sum(1 for result in results.values() if not result.is_valid)
            threat_count = sum(len(result.threat_indicators) for result in results.values())
            
            if error_count > 0 or threat_count > 0:
                self.logger.warning(
                    "Form validation security issues",
                    error_count=error_count,
                    threat_count=threat_count,
                    fields=list(form_data.keys())
                )
        
        return results
    
    # Private helper methods
    
    def _sanitize_input(self, input_str: str, preserve_email_chars: bool = False, preserve_username_chars: bool = False) -> str:
        """Basic input sanitization with context-aware character preservation"""
        if not input_str:
            return ""
        
        # HTML entity decode first
        sanitized = html.unescape(input_str)
        
        # Remove control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
        
        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        # Context-specific preservation
        if preserve_email_chars:
            # Keep email-specific characters
            return sanitized
        elif preserve_username_chars:
            # Keep username-safe characters only
            return ''.join(char for char in sanitized if char.isalnum() or char in '._-')
        else:
            # General sanitization - escape HTML
            return escape(sanitized)
    
    def _sanitize_xss(self, input_str: str) -> str:
        """XSS prevention sanitization using bleach library if available"""
        if not input_str:
            return ""
        
        if bleach:
            # Use bleach for comprehensive XSS prevention
            allowed_tags = []  # No tags allowed for authentication data
            allowed_attributes = {}
            return bleach.clean(input_str, tags=allowed_tags, attributes=allowed_attributes, strip=True)
        else:
            # Fallback XSS sanitization
            xss_chars = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '/': '&#x2F;',
                '&': '&amp;'
            }
            
            sanitized = input_str
            for char, replacement in xss_chars.items():
                sanitized = sanitized.replace(char, replacement)
            
            return sanitized
    
    def _check_security_patterns(self, input_str: str, patterns: List[re.Pattern], result: ValidationResult, context: str):
        """Check input against security threat patterns"""
        for pattern in patterns:
            if pattern.search(input_str):
                result.add_threat_indicator(f"{context} security pattern: {pattern.pattern}")
                result.add_warning(f"Suspicious {context} pattern detected")
    
    def _validate_email_domain_security(self, domain: str, result: ValidationResult):
        """Additional email domain security validation"""
        # Check for suspicious TLDs (basic list)
        suspicious_tlds = {'.tk', '.ml', '.cf', '.ga', '.edu.mn'}
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            result.add_warning("Email domain uses potentially suspicious TLD")
        
        # Check for homograph attacks (basic check)
        if any(ord(char) > 127 for char in domain):
            result.add_warning("Email domain contains non-ASCII characters")
        
        # Check for too many subdomains
        if domain.count('.') > 4:
            result.add_warning("Email domain has excessive subdomains")
    
    def _validate_authentication_email_security(self, email: str, result: ValidationResult):
        """Additional authentication-specific email validation"""
        # Check for plus addressing abuse
        if email.count('+') > 1:
            result.add_warning("Email contains multiple plus signs")
        
        # Check for suspicious local part patterns
        local_part = email.split('@')[0]
        if len(local_part) > 30:
            result.add_warning("Email local part unusually long")
        
        if re.search(r'\d{8,}', local_part):
            result.add_warning("Email contains long numeric sequence")
    
    def _calculate_password_strength(self, password: str) -> int:
        """Calculate password strength score (0-100)"""
        score = 0
        
        # Length scoring
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        
        # Character variety scoring
        if re.search(r'[a-z]', password):
            score += 5
        if re.search(r'[A-Z]', password):
            score += 5
        if re.search(r'\d', password):
            score += 5
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 10
        
        # Complexity scoring
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:
            score += 20
        elif unique_chars >= len(password) * 0.5:
            score += 10
        
        # Pattern penalties
        if re.search(r'(.)\1{2,}', password):
            score -= 10
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            score -= 15
        
        return max(0, min(100, score))
    
    def _validate_bearer_token(self, token: str, result: ValidationResult):
        """Validate Bearer token format and security"""
        # JWT token pattern (basic check)
        jwt_pattern = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')
        
        if jwt_pattern.match(token):
            # JWT token validation
            parts = token.split('.')
            if len(parts) != 3:
                result.add_error("Invalid JWT token structure", ValidationSeverity.HIGH)
            else:
                # Basic JWT part length validation
                for i, part in enumerate(parts):
                    if len(part) < 4:
                        result.add_error(f"JWT part {i+1} too short", ValidationSeverity.MEDIUM)
        else:
            # Generic token validation
            if len(token) < 10:
                result.add_error("Bearer token too short", ValidationSeverity.HIGH)
            elif len(token) > 2048:
                result.add_error("Bearer token too long", ValidationSeverity.MEDIUM)
            
            # Check token format
            if not re.match(r'^[A-Za-z0-9+/=_-]+$', token):
                result.add_error("Bearer token contains invalid characters", ValidationSeverity.HIGH)
    
    def _validate_basic_auth(self, credentials: str, result: ValidationResult):
        """Validate Basic authentication credentials"""
        try:
            import base64
            decoded = base64.b64decode(credentials).decode('utf-8')
            if ':' not in decoded:
                result.add_error("Invalid Basic auth format", ValidationSeverity.HIGH)
            else:
                username, password = decoded.split(':', 1)
                if not username or not password:
                    result.add_error("Basic auth missing username or password", ValidationSeverity.HIGH)
        except Exception:
            result.add_error("Basic auth decoding failed", ValidationSeverity.HIGH)
    
    def _check_auth_header_security(self, header: str, result: ValidationResult):
        """General authentication header security checks"""
        # Check for injection attempts
        if any(char in header for char in ['<', '>', '"', "'"]):
            result.add_warning("Authentication header contains potentially dangerous characters")
        
        # Check for reasonable length
        if len(header) > 4096:
            result.add_error("Authentication header too long", ValidationSeverity.MEDIUM)


# Module-level convenience functions for easy import and usage

def validate_email(email: str, strict: bool = True) -> ValidationResult:
    """Convenience function for email validation"""
    validator = AuthenticationValidator()
    return validator.validate_email(email, strict)


def validate_username(username: str, strict: bool = True) -> ValidationResult:
    """Convenience function for username validation"""
    validator = AuthenticationValidator()
    return validator.validate_username(username, strict)


def sanitize_input(input_data: str, input_type: str = "general") -> ValidationResult:
    """Convenience function for input sanitization"""
    validator = AuthenticationValidator()
    return validator.sanitize_authentication_input(input_data, input_type)


def detect_sql_injection(input_str: str) -> ValidationResult:
    """Convenience function for SQL injection detection"""
    validator = AuthenticationValidator()
    return validator.detect_sql_injection(input_str)


def detect_xss_attempt(input_str: str) -> ValidationResult:
    """Convenience function for XSS detection"""
    validator = AuthenticationValidator()
    return validator.detect_xss_attempt(input_str)


# Flask integration helper
def init_validation_helpers(app):
    """Initialize validation helpers with Flask application factory pattern"""
    validator = AuthenticationValidator(app)
    app.extensions = getattr(app, 'extensions', {})
    app.extensions['auth_validator'] = validator
    return validator