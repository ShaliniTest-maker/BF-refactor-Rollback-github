"""
Data validation and sanitization utilities providing comprehensive input validation,
schema validation, and security pattern detection for Flask application migration.

This module offers reusable validation functions for API inputs, data transformation
validation, and security compliance checks that support the migration from Node.js
validation patterns to Python-based validation with enhanced security features.

Requirements satisfied:
- Input validation and sanitization for security compliance per Section 6.4.6.1
- Schema validation for API endpoints and data processing per Section 2.2
- SQL injection and XSS prevention utilities per Section 6.4.6.1
- Data type validation and conversion utilities per Section 5.2.3
- Validation error handling with user-friendly messages per Section 5.4.3
"""

import re
import html
import urllib.parse
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Union, Callable, Type
from functools import wraps
from dataclasses import dataclass
import json
import logging
import bleach
from flask import request, jsonify, current_app
from marshmallow import Schema, ValidationError as MarshmallowValidationError
from email_validator import validate_email, EmailNotValidError
import structlog

# Structured logging for security events
logger = structlog.get_logger("validation")


class ValidationError(Exception):
    """
    Custom validation exception with detailed error information.
    
    Provides structured error information for validation failures
    with support for multiple field errors and user-friendly messages.
    """
    
    def __init__(
        self, 
        message: str, 
        field: Optional[str] = None, 
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.field = field
        self.code = code or 'validation_error'
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation error to dictionary format for API responses."""
        error_dict = {
            'message': self.message,
            'code': self.code,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if self.field:
            error_dict['field'] = self.field
        
        if self.details:
            error_dict['details'] = self.details
            
        return error_dict


@dataclass
class ValidationResult:
    """
    Result container for validation operations.
    
    Provides structured validation results with support for
    error accumulation and success/failure status tracking.
    """
    is_valid: bool
    errors: List[ValidationError]
    cleaned_data: Optional[Dict[str, Any]] = None
    warnings: Optional[List[str]] = None
    
    def add_error(self, error: ValidationError) -> None:
        """Add validation error to result."""
        self.errors.append(error)
        self.is_valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add validation warning to result."""
        if self.warnings is None:
            self.warnings = []
        self.warnings.append(warning)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary format."""
        result = {
            'is_valid': self.is_valid,
            'errors': [error.to_dict() for error in self.errors]
        }
        
        if self.cleaned_data is not None:
            result['data'] = self.cleaned_data
        
        if self.warnings:
            result['warnings'] = self.warnings
            
        return result


class SecuritySanitizer:
    """
    Security-focused input sanitization utilities.
    
    Provides comprehensive input sanitization to prevent XSS, SQL injection,
    and other security vulnerabilities per Section 6.4.6.1 requirements.
    """
    
    # SQL injection patterns (basic detection)
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|#|\/\*|\*\/)",
        r"(\bOR\b\s+\b\d+\b\s*=\s*\b\d+\b)",
        r"(\bAND\b\s+\b\d+\b\s*=\s*\b\d+\b)",
        r"(\'\s*(OR|AND)\s*\')",
        r"(\;\s*(DROP|DELETE|INSERT|UPDATE))",
    ]
    
    # XSS patterns for detection and cleaning
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>",
        r"<object[^>]*>.*?</object>",
        r"<embed[^>]*>.*?</embed>",
    ]
    
    # Allowed HTML tags for content (configurable)
    ALLOWED_HTML_TAGS = [
        'p', 'br', 'strong', 'em', 'u', 'i', 'b',
        'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'blockquote', 'code', 'pre'
    ]
    
    ALLOWED_HTML_ATTRIBUTES = {
        '*': ['class', 'id'],
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }
    
    @classmethod
    def sanitize_input(cls, value: Any, allow_html: bool = False) -> str:
        """
        Comprehensive input sanitization for security compliance.
        
        Args:
            value: Input value to sanitize
            allow_html: Whether to allow safe HTML tags
            
        Returns:
            Sanitized string value
            
        Raises:
            ValidationError: If input contains malicious content
        """
        if value is None:
            return ""
        
        # Convert to string
        if not isinstance(value, str):
            value = str(value)
        
        # Check for SQL injection patterns
        if cls.detect_sql_injection(value):
            logger.warning(
                "SQL injection attempt detected",
                input_value=value[:100],  # Log first 100 chars only
                client_ip=getattr(request, 'remote_addr', 'unknown'),
                user_agent=getattr(request, 'headers', {}).get('User-Agent', 'unknown')
            )
            raise ValidationError(
                "Input contains potentially malicious SQL patterns",
                code="sql_injection_detected"
            )
        
        # Check for XSS patterns
        if cls.detect_xss(value):
            logger.warning(
                "XSS attempt detected",
                input_value=value[:100],  # Log first 100 chars only
                client_ip=getattr(request, 'remote_addr', 'unknown'),
                user_agent=getattr(request, 'headers', {}).get('User-Agent', 'unknown')
            )
            raise ValidationError(
                "Input contains potentially malicious script content",
                code="xss_detected"
            )
        
        # HTML sanitization
        if allow_html:
            # Use bleach for safe HTML cleaning
            sanitized = bleach.clean(
                value,
                tags=cls.ALLOWED_HTML_TAGS,
                attributes=cls.ALLOWED_HTML_ATTRIBUTES,
                strip=True
            )
        else:
            # HTML escape for complete protection
            sanitized = html.escape(value, quote=True)
        
        # URL decode to prevent encoding-based attacks
        try:
            # Single URL decode (avoid double-decoding attacks)
            decoded = urllib.parse.unquote(sanitized)
            if decoded != sanitized:
                # Re-check decoded content for malicious patterns
                if cls.detect_sql_injection(decoded) or cls.detect_xss(decoded):
                    raise ValidationError(
                        "Input contains encoded malicious content",
                        code="encoded_malicious_content"
                    )
                sanitized = decoded
        except Exception:
            # If URL decoding fails, keep original sanitized value
            pass
        
        return sanitized.strip()
    
    @classmethod
    def detect_sql_injection(cls, value: str) -> bool:
        """
        Detect potential SQL injection patterns.
        
        Args:
            value: Input string to check
            
        Returns:
            True if SQL injection patterns detected
        """
        if not isinstance(value, str):
            return False
        
        # Convert to lowercase for case-insensitive matching
        lower_value = value.lower()
        
        # Check each SQL injection pattern
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, lower_value, re.IGNORECASE):
                return True
        
        return False
    
    @classmethod
    def detect_xss(cls, value: str) -> bool:
        """
        Detect potential XSS patterns.
        
        Args:
            value: Input string to check
            
        Returns:
            True if XSS patterns detected
        """
        if not isinstance(value, str):
            return False
        
        # Convert to lowercase for case-insensitive matching
        lower_value = value.lower()
        
        # Check each XSS pattern
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, lower_value, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """
        Sanitize filename to prevent directory traversal attacks.
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        if not filename:
            return "unknown"
        
        # Remove directory traversal patterns
        sanitized = re.sub(r'[/\\]', '', filename)
        sanitized = re.sub(r'\.\.+', '.', sanitized)
        
        # Remove dangerous characters
        sanitized = re.sub(r'[<>:"|?*]', '', sanitized)
        
        # Limit length
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            sanitized = name[:250] + ('.' + ext if ext else '')
        
        return sanitized or "unknown"


class DataTypeValidator:
    """
    Data type validation and conversion utilities.
    
    Provides comprehensive data type validation with conversion capabilities
    for Flask request processing per Section 5.2.3 requirements.
    """
    
    @staticmethod
    def validate_string(
        value: Any, 
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        required: bool = True,
        allow_empty: bool = False
    ) -> ValidationResult:
        """
        Validate and convert value to string with constraints.
        
        Args:
            value: Value to validate
            min_length: Minimum string length
            max_length: Maximum string length
            pattern: Regex pattern to match
            required: Whether field is required
            allow_empty: Whether empty strings are allowed
            
        Returns:
            ValidationResult with cleaned string data
        """
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        # Handle None/missing values
        if value is None or value == "":
            if required and not allow_empty:
                result.add_error(ValidationError(
                    "This field is required",
                    code="required"
                ))
                return result
            result.cleaned_data = "" if allow_empty else None
            return result
        
        # Convert to string
        if not isinstance(value, str):
            try:
                str_value = str(value)
            except Exception as e:
                result.add_error(ValidationError(
                    f"Cannot convert value to string: {str(e)}",
                    code="conversion_error"
                ))
                return result
        else:
            str_value = value
        
        # Sanitize for security
        try:
            str_value = SecuritySanitizer.sanitize_input(str_value)
        except ValidationError as e:
            result.add_error(e)
            return result
        
        # Length validation
        if min_length is not None and len(str_value) < min_length:
            result.add_error(ValidationError(
                f"String must be at least {min_length} characters long",
                code="min_length"
            ))
        
        if max_length is not None and len(str_value) > max_length:
            result.add_error(ValidationError(
                f"String must be no more than {max_length} characters long",
                code="max_length"
            ))
        
        # Pattern validation
        if pattern and not re.match(pattern, str_value):
            result.add_error(ValidationError(
                "String does not match required pattern",
                code="pattern_mismatch"
            ))
        
        if result.is_valid:
            result.cleaned_data = str_value
        
        return result
    
    @staticmethod
    def validate_integer(
        value: Any,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None,
        required: bool = True
    ) -> ValidationResult:
        """
        Validate and convert value to integer with constraints.
        
        Args:
            value: Value to validate
            min_value: Minimum integer value
            max_value: Maximum integer value
            required: Whether field is required
            
        Returns:
            ValidationResult with cleaned integer data
        """
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        # Handle None/missing values
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "This field is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        # Convert to integer
        try:
            if isinstance(value, bool):
                # Prevent bool to int conversion (True->1, False->0)
                raise ValueError("Boolean values not allowed")
            
            int_value = int(value)
        except (ValueError, TypeError) as e:
            result.add_error(ValidationError(
                "Invalid integer value",
                code="invalid_integer",
                details={"original_value": str(value)}
            ))
            return result
        
        # Range validation
        if min_value is not None and int_value < min_value:
            result.add_error(ValidationError(
                f"Value must be at least {min_value}",
                code="min_value"
            ))
        
        if max_value is not None and int_value > max_value:
            result.add_error(ValidationError(
                f"Value must be no more than {max_value}",
                code="max_value"
            ))
        
        if result.is_valid:
            result.cleaned_data = int_value
        
        return result
    
    @staticmethod
    def validate_decimal(
        value: Any,
        min_value: Optional[Decimal] = None,
        max_value: Optional[Decimal] = None,
        max_digits: Optional[int] = None,
        decimal_places: Optional[int] = None,
        required: bool = True
    ) -> ValidationResult:
        """
        Validate and convert value to Decimal with constraints.
        
        Args:
            value: Value to validate
            min_value: Minimum decimal value
            max_value: Maximum decimal value
            max_digits: Maximum total digits
            decimal_places: Maximum decimal places
            required: Whether field is required
            
        Returns:
            ValidationResult with cleaned Decimal data
        """
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        # Handle None/missing values
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "This field is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        # Convert to Decimal
        try:
            decimal_value = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError) as e:
            result.add_error(ValidationError(
                "Invalid decimal value",
                code="invalid_decimal",
                details={"original_value": str(value)}
            ))
            return result
        
        # Range validation
        if min_value is not None and decimal_value < min_value:
            result.add_error(ValidationError(
                f"Value must be at least {min_value}",
                code="min_value"
            ))
        
        if max_value is not None and decimal_value > max_value:
            result.add_error(ValidationError(
                f"Value must be no more than {max_value}",
                code="max_value"
            ))
        
        # Precision validation
        sign, digits, exponent = decimal_value.as_tuple()
        
        if max_digits is not None and len(digits) > max_digits:
            result.add_error(ValidationError(
                f"Number has too many digits (max: {max_digits})",
                code="max_digits"
            ))
        
        if decimal_places is not None and exponent < -decimal_places:
            result.add_error(ValidationError(
                f"Number has too many decimal places (max: {decimal_places})",
                code="decimal_places"
            ))
        
        if result.is_valid:
            result.cleaned_data = decimal_value
        
        return result
    
    @staticmethod
    def validate_email(value: Any, required: bool = True) -> ValidationResult:
        """
        Validate email address format.
        
        Args:
            value: Email value to validate
            required: Whether field is required
            
        Returns:
            ValidationResult with cleaned email data
        """
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        # Handle None/missing values
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "Email address is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        # Convert to string and sanitize
        str_value = str(value).strip().lower()
        
        try:
            str_value = SecuritySanitizer.sanitize_input(str_value)
        except ValidationError as e:
            result.add_error(e)
            return result
        
        # Validate email format
        try:
            valid = validate_email(str_value)
            result.cleaned_data = valid.email
        except EmailNotValidError as e:
            result.add_error(ValidationError(
                f"Invalid email address: {str(e)}",
                code="invalid_email"
            ))
        
        return result
    
    @staticmethod
    def validate_datetime(
        value: Any, 
        date_format: Optional[str] = None,
        required: bool = True
    ) -> ValidationResult:
        """
        Validate and convert value to datetime.
        
        Args:
            value: Value to validate
            date_format: Expected datetime format string
            required: Whether field is required
            
        Returns:
            ValidationResult with cleaned datetime data
        """
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        # Handle None/missing values
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "Date/time is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        # If already datetime, validate and return
        if isinstance(value, datetime):
            result.cleaned_data = value
            return result
        
        # Convert string to datetime
        if isinstance(value, str):
            str_value = value.strip()
            
            # Try specified format first
            if date_format:
                try:
                    dt_value = datetime.strptime(str_value, date_format)
                    result.cleaned_data = dt_value
                    return result
                except ValueError:
                    pass
            
            # Try common ISO formats
            iso_formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO with microseconds and Z
                '%Y-%m-%dT%H:%M:%SZ',     # ISO with Z
                '%Y-%m-%dT%H:%M:%S',      # ISO basic
                '%Y-%m-%d %H:%M:%S',      # SQL datetime
                '%Y-%m-%d',               # Date only
            ]
            
            for fmt in iso_formats:
                try:
                    dt_value = datetime.strptime(str_value, fmt)
                    result.cleaned_data = dt_value
                    return result
                except ValueError:
                    continue
            
            # Try parsing as timestamp
            try:
                timestamp = float(str_value)
                dt_value = datetime.fromtimestamp(timestamp)
                result.cleaned_data = dt_value
                return result
            except (ValueError, OSError):
                pass
        
        # If all parsing attempts failed
        result.add_error(ValidationError(
            "Invalid date/time format",
            code="invalid_datetime",
            details={"original_value": str(value)}
        ))
        
        return result


class SchemaValidator:
    """
    Schema validation utilities for API endpoints.
    
    Provides comprehensive schema validation for Flask request processing
    per Section 2.2 requirements maintaining Node.js implementation parity.
    """
    
    def __init__(self, schema: Dict[str, Any]):
        """
        Initialize schema validator.
        
        Args:
            schema: Schema definition dictionary
        """
        self.schema = schema
        self.logger = structlog.get_logger("schema_validator")
    
    def validate(self, data: Dict[str, Any]) -> ValidationResult:
        """
        Validate data against schema.
        
        Args:
            data: Data to validate
            
        Returns:
            ValidationResult with validation status and cleaned data
        """
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        cleaned_data = {}
        
        # Validate each field in schema
        for field_name, field_config in self.schema.items():
            field_value = data.get(field_name)
            
            # Get field validation result
            field_result = self._validate_field(field_name, field_value, field_config)
            
            # Add field errors to result
            for error in field_result.errors:
                error.field = field_name
                result.add_error(error)
            
            # Add cleaned data if validation passed
            if field_result.is_valid and field_result.cleaned_data is not None:
                cleaned_data[field_name] = field_result.cleaned_data
        
        # Check for unknown fields if strict mode enabled
        if self.schema.get('_strict', False):
            unknown_fields = set(data.keys()) - set(self.schema.keys()) - {'_strict'}
            for field in unknown_fields:
                result.add_error(ValidationError(
                    f"Unknown field '{field}' not allowed",
                    field=field,
                    code="unknown_field"
                ))
        
        if result.is_valid:
            result.cleaned_data = cleaned_data
        
        return result
    
    def _validate_field(
        self, 
        field_name: str, 
        value: Any, 
        config: Dict[str, Any]
    ) -> ValidationResult:
        """
        Validate individual field against configuration.
        
        Args:
            field_name: Name of the field
            value: Field value to validate
            config: Field validation configuration
            
        Returns:
            ValidationResult for the field
        """
        field_type = config.get('type', 'string')
        required = config.get('required', False)
        
        # Type-specific validation
        if field_type == 'string':
            return DataTypeValidator.validate_string(
                value,
                min_length=config.get('min_length'),
                max_length=config.get('max_length'),
                pattern=config.get('pattern'),
                required=required,
                allow_empty=config.get('allow_empty', False)
            )
        
        elif field_type == 'integer':
            return DataTypeValidator.validate_integer(
                value,
                min_value=config.get('min_value'),
                max_value=config.get('max_value'),
                required=required
            )
        
        elif field_type == 'decimal':
            return DataTypeValidator.validate_decimal(
                value,
                min_value=config.get('min_value'),
                max_value=config.get('max_value'),
                max_digits=config.get('max_digits'),
                decimal_places=config.get('decimal_places'),
                required=required
            )
        
        elif field_type == 'email':
            return DataTypeValidator.validate_email(value, required=required)
        
        elif field_type == 'datetime':
            return DataTypeValidator.validate_datetime(
                value,
                date_format=config.get('format'),
                required=required
            )
        
        elif field_type == 'boolean':
            return self._validate_boolean(value, required)
        
        elif field_type == 'array':
            return self._validate_array(value, config, required)
        
        elif field_type == 'object':
            return self._validate_object(value, config, required)
        
        else:
            result = ValidationResult(is_valid=False, errors=[])
            result.add_error(ValidationError(
                f"Unknown field type: {field_type}",
                code="unknown_type"
            ))
            return result
    
    def _validate_boolean(self, value: Any, required: bool) -> ValidationResult:
        """Validate boolean field."""
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "This field is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        if isinstance(value, bool):
            result.cleaned_data = value
        elif isinstance(value, str):
            lower_value = value.lower().strip()
            if lower_value in ('true', '1', 'yes', 'on'):
                result.cleaned_data = True
            elif lower_value in ('false', '0', 'no', 'off'):
                result.cleaned_data = False
            else:
                result.add_error(ValidationError(
                    "Invalid boolean value",
                    code="invalid_boolean"
                ))
        elif isinstance(value, (int, float)):
            result.cleaned_data = bool(value)
        else:
            result.add_error(ValidationError(
                "Invalid boolean value",
                code="invalid_boolean"
            ))
        
        return result
    
    def _validate_array(self, value: Any, config: Dict[str, Any], required: bool) -> ValidationResult:
        """Validate array field."""
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "This field is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        if not isinstance(value, (list, tuple)):
            result.add_error(ValidationError(
                "Value must be an array",
                code="invalid_array"
            ))
            return result
        
        # Validate array length
        min_items = config.get('min_items')
        max_items = config.get('max_items')
        
        if min_items is not None and len(value) < min_items:
            result.add_error(ValidationError(
                f"Array must have at least {min_items} items",
                code="min_items"
            ))
        
        if max_items is not None and len(value) > max_items:
            result.add_error(ValidationError(
                f"Array must have no more than {max_items} items",
                code="max_items"
            ))
        
        # Validate array items if item schema provided
        item_schema = config.get('items')
        if item_schema and result.is_valid:
            cleaned_items = []
            for i, item in enumerate(value):
                item_result = self._validate_field(f"[{i}]", item, item_schema)
                if not item_result.is_valid:
                    for error in item_result.errors:
                        error.field = f"[{i}]"
                        result.add_error(error)
                else:
                    cleaned_items.append(item_result.cleaned_data)
            
            if result.is_valid:
                result.cleaned_data = cleaned_items
        else:
            result.cleaned_data = list(value)
        
        return result
    
    def _validate_object(self, value: Any, config: Dict[str, Any], required: bool) -> ValidationResult:
        """Validate object field."""
        result = ValidationResult(is_valid=True, errors=[], cleaned_data={})
        
        if value is None or value == "":
            if required:
                result.add_error(ValidationError(
                    "This field is required",
                    code="required"
                ))
            else:
                result.cleaned_data = None
            return result
        
        if not isinstance(value, dict):
            result.add_error(ValidationError(
                "Value must be an object",
                code="invalid_object"
            ))
            return result
        
        # Validate nested properties if schema provided
        properties = config.get('properties')
        if properties:
            nested_validator = SchemaValidator(properties)
            nested_result = nested_validator.validate(value)
            
            for error in nested_result.errors:
                result.add_error(error)
            
            if nested_result.is_valid:
                result.cleaned_data = nested_result.cleaned_data
        else:
            result.cleaned_data = dict(value)
        
        return result


def validate_request_data(schema: Dict[str, Any]):
    """
    Decorator for automatic Flask request data validation.
    
    Validates incoming request data against provided schema and
    provides cleaned data to the decorated function.
    
    Args:
        schema: Schema definition for validation
        
    Returns:
        Decorator function
        
    Usage:
        @validate_request_data({
            'name': {'type': 'string', 'required': True, 'min_length': 1},
            'email': {'type': 'email', 'required': True},
            'age': {'type': 'integer', 'min_value': 0, 'max_value': 150}
        })
        def create_user():
            # Access validated data via request.validated_data
            data = request.validated_data
            # ... implementation
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get request data
            if request.is_json:
                data = request.get_json() or {}
            else:
                data = request.form.to_dict() if request.form else {}
            
            # Add query parameters
            data.update(request.args.to_dict())
            
            # Validate against schema
            validator = SchemaValidator(schema)
            result = validator.validate(data)
            
            if not result.is_valid:
                # Return validation error response
                return jsonify({
                    'error': 'Validation failed',
                    'errors': [error.to_dict() for error in result.errors],
                    'timestamp': datetime.utcnow().isoformat()
                }), 400
            
            # Add validated data to request context
            request.validated_data = result.cleaned_data
            
            # Log successful validation
            logger.info(
                "Request validation successful",
                endpoint=request.endpoint,
                method=request.method,
                validated_fields=list(result.cleaned_data.keys())
            )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def validate_query_params(schema: Dict[str, Any]):
    """
    Decorator for query parameter validation.
    
    Validates URL query parameters against provided schema.
    
    Args:
        schema: Schema definition for query parameters
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get query parameters
            data = request.args.to_dict()
            
            # Validate against schema
            validator = SchemaValidator(schema)
            result = validator.validate(data)
            
            if not result.is_valid:
                return jsonify({
                    'error': 'Query parameter validation failed',
                    'errors': [error.to_dict() for error in result.errors],
                    'timestamp': datetime.utcnow().isoformat()
                }), 400
            
            # Add validated data to request context
            request.validated_query = result.cleaned_data
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


class ValidationMiddleware:
    """
    Flask request validation middleware.
    
    Provides centralized request validation and security checks
    for all incoming requests to enhance security posture.
    """
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize validation middleware with Flask app."""
        app.before_request(self._before_request)
        app.teardown_appcontext(self._teardown_request)
    
    def _before_request(self):
        """
        Pre-request validation and security checks.
        
        Performs basic security validation on all incoming requests
        including content type validation and basic input sanitization.
        """
        # Skip validation for certain endpoints
        if request.endpoint in ['static', 'health', 'metrics']:
            return
        
        # Validate Content-Type for JSON endpoints
        if request.method in ['POST', 'PUT', 'PATCH']:
            if request.is_json:
                try:
                    # Attempt to parse JSON to validate format
                    request.get_json()
                except Exception as e:
                    logger.warning(
                        "Invalid JSON in request",
                        error=str(e),
                        endpoint=request.endpoint,
                        method=request.method
                    )
                    return jsonify({
                        'error': 'Invalid JSON format',
                        'message': 'Request body must contain valid JSON',
                        'timestamp': datetime.utcnow().isoformat()
                    }), 400
        
        # Basic security headers validation
        user_agent = request.headers.get('User-Agent', '')
        if len(user_agent) > 1000:  # Prevent overly long user agents
            logger.warning(
                "Suspiciously long User-Agent header",
                user_agent_length=len(user_agent),
                client_ip=request.remote_addr
            )
            return jsonify({
                'error': 'Invalid request headers',
                'timestamp': datetime.utcnow().isoformat()
            }), 400
        
        # Check for basic XSS in query parameters
        for key, value in request.args.items():
            if SecuritySanitizer.detect_xss(value):
                logger.warning(
                    "XSS attempt in query parameters",
                    parameter=key,
                    value=value[:100],
                    client_ip=request.remote_addr
                )
                return jsonify({
                    'error': 'Invalid request parameters',
                    'timestamp': datetime.utcnow().isoformat()
                }), 400
    
    def _teardown_request(self, exception):
        """Post-request cleanup and logging."""
        if hasattr(request, 'validated_data'):
            # Clear validated data from request context
            delattr(request, 'validated_data')
        
        if hasattr(request, 'validated_query'):
            # Clear validated query data from request context
            delattr(request, 'validated_query')


# Convenience functions for common validation patterns

def sanitize_html_input(value: str, allow_tags: bool = False) -> str:
    """
    Convenience function for HTML input sanitization.
    
    Args:
        value: Input value to sanitize
        allow_tags: Whether to allow safe HTML tags
        
    Returns:
        Sanitized string
    """
    return SecuritySanitizer.sanitize_input(value, allow_html=allow_tags)


def validate_api_input(data: Dict[str, Any], schema: Dict[str, Any]) -> ValidationResult:
    """
    Convenience function for API input validation.
    
    Args:
        data: Input data to validate
        schema: Schema definition
        
    Returns:
        ValidationResult with validation status and cleaned data
    """
    validator = SchemaValidator(schema)
    return validator.validate(data)


def create_error_response(errors: List[ValidationError], status_code: int = 400) -> tuple:
    """
    Create standardized error response for validation failures.
    
    Args:
        errors: List of validation errors
        status_code: HTTP status code for response
        
    Returns:
        Tuple of (response_dict, status_code) for Flask response
    """
    return jsonify({
        'error': 'Validation failed',
        'errors': [error.to_dict() for error in errors],
        'timestamp': datetime.utcnow().isoformat(),
        'status': status_code
    }), status_code


# Export main classes and functions
__all__ = [
    'ValidationError',
    'ValidationResult',
    'SecuritySanitizer', 
    'DataTypeValidator',
    'SchemaValidator',
    'ValidationMiddleware',
    'validate_request_data',
    'validate_query_params',
    'sanitize_html_input',
    'validate_api_input',
    'create_error_response'
]