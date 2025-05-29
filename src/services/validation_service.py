"""
Business Validation Service Implementation

This module implements comprehensive data validation, business rule enforcement, and
constraint checking across all business operations. The service centralizes validation
logic using Python dataclasses and type hints while maintaining all original Node.js
validation patterns through the Service Layer pattern.

Key Features:
- Python dataclasses and type hints integration for robust validation per Section 4.5.1
- Business rule enforcement and validation logic preservation per Feature F-005
- Data validation and constraint checking per Section 4.12.1 validation rules
- Input validation and sanitization patterns preservation per Section 2.1.9
- Consistent validation error handling across all business operations per Section 4.5.3
- Database integrity validation per Section 6.2.2.2 constraint requirements
- Service Layer pattern implementation for workflow orchestration per Feature F-006

Technical Specification References:
- Section 4.5.1: Python dataclasses and type hints integration for robust validation
- Section 4.12.1: Business Rules and Validation Checkpoints implementation
- Feature F-005: Business Logic Preservation with validation pattern maintenance
- Section 2.1.9: Input validation and sanitization patterns preservation
- Section 4.5.3: Validation error handling with consistent error responses
- Section 6.2.2.2: Database integrity validation and constraint checking
"""

import re
import bleach
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import (
    Any, Dict, List, Optional, Union, Type, TypeVar, Generic,
    get_type_hints, get_origin, get_args
)

from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from injector import inject, singleton
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest

from .base import BaseService, ValidationError, ServiceError

# Type variables for generic validation operations
T = TypeVar("T")
ModelType = TypeVar("ModelType")
DataClassType = TypeVar("DataClassType")

# Logger configuration for validation service operations
logger = logging.getLogger(__name__)


class ValidationSeverity(Enum):
    """
    Enumeration of validation severity levels for consistent error categorization.
    """
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationType(Enum):
    """
    Enumeration of validation types for comprehensive business rule categorization.
    """
    DATA_TYPE = "data_type"
    BUSINESS_RULE = "business_rule"
    CONSTRAINT = "constraint"
    SANITIZATION = "sanitization"
    INTEGRITY = "integrity"
    SECURITY = "security"


@dataclass
class ValidationResult:
    """
    Dataclass representing validation result with comprehensive error details.
    
    Provides structured validation feedback using Python dataclasses and type hints
    as specified in Section 4.5.1 for robust validation implementation.
    
    Attributes:
        is_valid: Boolean indicating overall validation success
        errors: List of validation error messages
        warnings: List of validation warning messages
        field_errors: Dictionary mapping field names to specific error messages
        sanitized_data: Cleaned and sanitized input data
        validation_type: Type of validation performed
        severity: Overall severity level of validation issues
        metadata: Additional validation context and details
    """
    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    field_errors: Dict[str, List[str]] = field(default_factory=dict)
    sanitized_data: Dict[str, Any] = field(default_factory=dict)
    validation_type: ValidationType = ValidationType.DATA_TYPE
    severity: ValidationSeverity = ValidationSeverity.INFO
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_error(self, message: str, field_name: Optional[str] = None,
                  severity: ValidationSeverity = ValidationSeverity.ERROR) -> None:
        """
        Add validation error with optional field-specific assignment.
        
        Args:
            message: Error message describing the validation failure
            field_name: Optional field name for field-specific errors
            severity: Severity level of the validation error
        """
        self.is_valid = False
        self.errors.append(message)
        
        if field_name:
            if field_name not in self.field_errors:
                self.field_errors[field_name] = []
            self.field_errors[field_name].append(message)
        
        # Update overall severity if current error is more severe
        if severity.value in ["critical", "error"] and self.severity.value in ["info", "warning"]:
            self.severity = severity
    
    def add_warning(self, message: str, field_name: Optional[str] = None) -> None:
        """
        Add validation warning without affecting validation success.
        
        Args:
            message: Warning message describing the validation concern
            field_name: Optional field name for field-specific warnings
        """
        self.warnings.append(message)
        
        if field_name:
            if field_name not in self.field_errors:
                self.field_errors[field_name] = []
            self.field_errors[field_name].append(f"Warning: {message}")
    
    def merge(self, other: 'ValidationResult') -> 'ValidationResult':
        """
        Merge another validation result into this one.
        
        Args:
            other: Another ValidationResult to merge
            
        Returns:
            Self for method chaining
        """
        self.is_valid = self.is_valid and other.is_valid
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)
        
        # Merge field errors
        for field_name, field_errors in other.field_errors.items():
            if field_name not in self.field_errors:
                self.field_errors[field_name] = []
            self.field_errors[field_name].extend(field_errors)
        
        # Update sanitized data
        self.sanitized_data.update(other.sanitized_data)
        
        # Use more severe severity level
        if other.severity.value in ["critical", "error"] and self.severity.value in ["info", "warning"]:
            self.severity = other.severity
        
        return self


@dataclass
class FieldValidationRule:
    """
    Dataclass representing individual field validation rules with comprehensive configuration.
    
    Implements Python dataclasses pattern for structured validation rule definition
    as specified in Section 4.5.1 for type-safe validation configuration.
    
    Attributes:
        field_name: Name of the field to validate
        required: Whether the field is required
        data_type: Expected data type for the field
        min_length: Minimum string length (for string fields)
        max_length: Maximum string length (for string fields)
        min_value: Minimum numeric value (for numeric fields)
        max_value: Maximum numeric value (for numeric fields)
        pattern: Regular expression pattern for string validation
        custom_validator: Custom validation function
        sanitizer: Data sanitization function
        business_rules: List of business rule validation functions
        error_message: Custom error message for validation failures
    """
    field_name: str
    required: bool = False
    data_type: Optional[Type] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float, Decimal]] = None
    max_value: Optional[Union[int, float, Decimal]] = None
    pattern: Optional[str] = None
    custom_validator: Optional[callable] = None
    sanitizer: Optional[callable] = None
    business_rules: List[callable] = field(default_factory=list)
    error_message: Optional[str] = None


class BaseValidator(ABC):
    """
    Abstract base class for implementing field-specific validators.
    
    Provides consistent validation interface for all field types while enabling
    extensible validation patterns for complex business rules.
    """
    
    @abstractmethod
    def validate(self, value: Any, rule: FieldValidationRule) -> ValidationResult:
        """
        Abstract method for field-specific validation implementation.
        
        Args:
            value: Value to validate
            rule: Validation rule configuration
            
        Returns:
            ValidationResult with validation outcome
        """
        pass
    
    @abstractmethod
    def sanitize(self, value: Any) -> Any:
        """
        Abstract method for field-specific data sanitization.
        
        Args:
            value: Value to sanitize
            
        Returns:
            Sanitized value
        """
        pass


class StringValidator(BaseValidator):
    """
    String field validator implementing comprehensive text validation and sanitization.
    
    Provides input validation and sanitization patterns preservation per Section 2.1.9
    with HTML sanitization, pattern matching, and length constraints.
    """
    
    def validate(self, value: Any, rule: FieldValidationRule) -> ValidationResult:
        """
        Validate string field with comprehensive checks and sanitization.
        
        Args:
            value: String value to validate
            rule: String validation rule configuration
            
        Returns:
            ValidationResult with validation outcome and sanitized data
        """
        result = ValidationResult(validation_type=ValidationType.DATA_TYPE)
        
        # Convert to string if not None
        if value is None:
            if rule.required:
                result.add_error(
                    f"Field '{rule.field_name}' is required",
                    rule.field_name,
                    ValidationSeverity.ERROR
                )
            return result
        
        # Convert to string and sanitize
        str_value = str(value)
        sanitized_value = self.sanitize(str_value)
        result.sanitized_data[rule.field_name] = sanitized_value
        
        # Length validation
        if rule.min_length is not None and len(sanitized_value) < rule.min_length:
            result.add_error(
                f"Field '{rule.field_name}' must be at least {rule.min_length} characters",
                rule.field_name
            )
        
        if rule.max_length is not None and len(sanitized_value) > rule.max_length:
            result.add_error(
                f"Field '{rule.field_name}' must be at most {rule.max_length} characters",
                rule.field_name
            )
        
        # Pattern validation
        if rule.pattern and sanitized_value:
            try:
                if not re.match(rule.pattern, sanitized_value):
                    error_msg = rule.error_message or f"Field '{rule.field_name}' does not match required pattern"
                    result.add_error(error_msg, rule.field_name)
            except re.error as e:
                result.add_error(
                    f"Invalid regex pattern for field '{rule.field_name}': {e}",
                    rule.field_name,
                    ValidationSeverity.CRITICAL
                )
        
        return result
    
    def sanitize(self, value: Any) -> str:
        """
        Sanitize string input with HTML cleaning and whitespace normalization.
        
        Implements input sanitization patterns preservation per Section 2.1.9
        with comprehensive security-focused sanitization.
        
        Args:
            value: String value to sanitize
            
        Returns:
            Sanitized string value
        """
        if value is None:
            return ""
        
        str_value = str(value)
        
        # Strip leading/trailing whitespace
        str_value = str_value.strip()
        
        # HTML sanitization using bleach
        # Allow basic formatting tags but remove potentially dangerous content
        allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        allowed_attributes = {}
        
        sanitized = bleach.clean(
            str_value,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        
        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        return sanitized


class NumericValidator(BaseValidator):
    """
    Numeric field validator implementing comprehensive number validation and type coercion.
    
    Supports integer, float, and Decimal validation with range checking and precision handling.
    """
    
    def validate(self, value: Any, rule: FieldValidationRule) -> ValidationResult:
        """
        Validate numeric field with type checking and range validation.
        
        Args:
            value: Numeric value to validate
            rule: Numeric validation rule configuration
            
        Returns:
            ValidationResult with validation outcome and sanitized data
        """
        result = ValidationResult(validation_type=ValidationType.DATA_TYPE)
        
        if value is None:
            if rule.required:
                result.add_error(
                    f"Field '{rule.field_name}' is required",
                    rule.field_name,
                    ValidationSeverity.ERROR
                )
            return result
        
        # Type conversion and validation
        try:
            if rule.data_type == int:
                numeric_value = int(value)
            elif rule.data_type == float:
                numeric_value = float(value)
            elif rule.data_type == Decimal:
                numeric_value = Decimal(str(value))
            else:
                # Default to float for unspecified numeric types
                numeric_value = float(value)
            
            result.sanitized_data[rule.field_name] = numeric_value
            
            # Range validation
            if rule.min_value is not None and numeric_value < rule.min_value:
                result.add_error(
                    f"Field '{rule.field_name}' must be at least {rule.min_value}",
                    rule.field_name
                )
            
            if rule.max_value is not None and numeric_value > rule.max_value:
                result.add_error(
                    f"Field '{rule.field_name}' must be at most {rule.max_value}",
                    rule.field_name
                )
                
        except (ValueError, TypeError, InvalidOperation) as e:
            result.add_error(
                f"Field '{rule.field_name}' must be a valid number: {e}",
                rule.field_name
            )
        
        return result
    
    def sanitize(self, value: Any) -> Union[int, float, Decimal]:
        """
        Sanitize numeric input with type coercion and precision handling.
        
        Args:
            value: Numeric value to sanitize
            
        Returns:
            Sanitized numeric value
        """
        if value is None:
            return 0
        
        # Remove whitespace for string numbers
        if isinstance(value, str):
            value = value.strip()
        
        try:
            # Try to preserve the most appropriate numeric type
            if isinstance(value, (int, float, Decimal)):
                return value
            elif isinstance(value, str):
                # Check if it's an integer
                if '.' not in value and 'e' not in value.lower():
                    return int(value)
                else:
                    return float(value)
            else:
                return float(value)
        except (ValueError, TypeError):
            return 0


class EmailValidator(BaseValidator):
    """
    Email field validator implementing comprehensive email validation and normalization.
    
    Provides email-specific validation with format checking, domain validation,
    and normalization patterns for consistent email handling.
    """
    
    # RFC 5322 compliant email regex pattern
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    def validate(self, value: Any, rule: FieldValidationRule) -> ValidationResult:
        """
        Validate email field with format checking and domain validation.
        
        Args:
            value: Email value to validate
            rule: Email validation rule configuration
            
        Returns:
            ValidationResult with validation outcome and sanitized data
        """
        result = ValidationResult(validation_type=ValidationType.DATA_TYPE)
        
        if value is None:
            if rule.required:
                result.add_error(
                    f"Email field '{rule.field_name}' is required",
                    rule.field_name,
                    ValidationSeverity.ERROR
                )
            return result
        
        # Sanitize email
        sanitized_email = self.sanitize(value)
        result.sanitized_data[rule.field_name] = sanitized_email
        
        # Format validation
        if sanitized_email and not self.EMAIL_PATTERN.match(sanitized_email):
            result.add_error(
                f"Field '{rule.field_name}' must be a valid email address",
                rule.field_name
            )
        
        # Additional length checks
        if len(sanitized_email) > 254:  # RFC 5321 limit
            result.add_error(
                f"Email address '{rule.field_name}' is too long (max 254 characters)",
                rule.field_name
            )
        
        return result
    
    def sanitize(self, value: Any) -> str:
        """
        Sanitize email input with normalization and case handling.
        
        Args:
            value: Email value to sanitize
            
        Returns:
            Sanitized email string
        """
        if value is None:
            return ""
        
        email = str(value).strip().lower()
        
        # Remove potentially dangerous characters
        email = re.sub(r'[<>"\']', '', email)
        
        return email


class DateTimeValidator(BaseValidator):
    """
    DateTime field validator implementing comprehensive date/time validation and parsing.
    
    Supports multiple date formats, timezone handling, and range validation for
    temporal data validation requirements.
    """
    
    def validate(self, value: Any, rule: FieldValidationRule) -> ValidationResult:
        """
        Validate datetime field with format parsing and range checking.
        
        Args:
            value: DateTime value to validate
            rule: DateTime validation rule configuration
            
        Returns:
            ValidationResult with validation outcome and sanitized data
        """
        result = ValidationResult(validation_type=ValidationType.DATA_TYPE)
        
        if value is None:
            if rule.required:
                result.add_error(
                    f"DateTime field '{rule.field_name}' is required",
                    rule.field_name,
                    ValidationSeverity.ERROR
                )
            return result
        
        # Parse and sanitize datetime
        try:
            sanitized_datetime = self.sanitize(value)
            result.sanitized_data[rule.field_name] = sanitized_datetime
            
            # Range validation if min/max values are provided
            if rule.min_value and isinstance(rule.min_value, datetime):
                if sanitized_datetime < rule.min_value:
                    result.add_error(
                        f"DateTime '{rule.field_name}' must be after {rule.min_value}",
                        rule.field_name
                    )
            
            if rule.max_value and isinstance(rule.max_value, datetime):
                if sanitized_datetime > rule.max_value:
                    result.add_error(
                        f"DateTime '{rule.field_name}' must be before {rule.max_value}",
                        rule.field_name
                    )
                    
        except ValueError as e:
            result.add_error(
                f"Field '{rule.field_name}' must be a valid datetime: {e}",
                rule.field_name
            )
        
        return result
    
    def sanitize(self, value: Any) -> datetime:
        """
        Sanitize datetime input with parsing and timezone normalization.
        
        Args:
            value: DateTime value to sanitize
            
        Returns:
            Sanitized datetime object with UTC timezone
        """
        if isinstance(value, datetime):
            # Ensure UTC timezone
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        
        if isinstance(value, str):
            # Try to parse common datetime formats
            datetime_formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%d',
                '%m/%d/%Y',
                '%d/%m/%Y'
            ]
            
            for fmt in datetime_formats:
                try:
                    parsed_dt = datetime.strptime(value.strip(), fmt)
                    return parsed_dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            
            # If no format matches, raise error
            raise ValueError(f"Unable to parse datetime string: {value}")
        
        # Try to convert other types
        return datetime.fromtimestamp(float(value), tz=timezone.utc)


@singleton
class ValidationService(BaseService):
    """
    Business Validation Service implementing comprehensive data validation, business rule
    enforcement, and constraint checking across all business operations.
    
    This service centralizes validation logic using Python dataclasses and type hints
    while maintaining all original Node.js validation patterns through the Service Layer
    pattern as specified in Section 4.5.1 and Feature F-005.
    
    Key Features:
    - Python dataclasses and type hints integration for robust validation
    - Business rule enforcement with consistent validation patterns
    - Input validation and sanitization preservation from Node.js implementation
    - Constraint checking with database integrity validation
    - Consistent validation error handling across all business operations
    - Service Layer pattern implementation for workflow orchestration
    
    Technical Specification References:
    - Section 4.5.1: Business Logic Preservation Process with dataclasses
    - Section 4.12.1: Validation Rules Implementation
    - Feature F-005: Business Logic Preservation
    - Section 2.1.9: Input validation and sanitization patterns
    - Section 4.5.3: Validation error handling
    - Section 6.2.2.2: Database integrity validation
    """
    
    @inject
    def __init__(self, db: SQLAlchemy):
        """
        Initialize validation service with Flask-SQLAlchemy database instance.
        
        Args:
            db: Flask-SQLAlchemy database instance for integrity validation
        """
        super().__init__(db)
        
        # Initialize field validators
        self._validators: Dict[Type, BaseValidator] = {
            str: StringValidator(),
            int: NumericValidator(),
            float: NumericValidator(),
            Decimal: NumericValidator(),
            datetime: DateTimeValidator()
        }
        
        # Email validator for email-specific fields
        self._email_validator = EmailValidator()
        
        # Cache for validation rules to improve performance
        self._validation_cache: Dict[str, Dict[str, FieldValidationRule]] = {}
        
        # Business rule registry for dynamic rule loading
        self._business_rules: Dict[str, List[callable]] = {}
        
        self.logger.info("Initialized ValidationService with comprehensive validation patterns")
    
    def validate_business_rules(self, data: Dict[str, Any]) -> bool:
        """
        Validate business rules for the validation service domain.
        
        Args:
            data: Data to validate against business rules
            
        Returns:
            True if validation passes
            
        Raises:
            ValidationError: When business rules are violated
        """
        # Basic validation service business rules
        if not isinstance(data, dict):
            raise ValidationError("Validation data must be a dictionary")
        
        # Validate that critical validation fields are present for validation operations
        if 'validation_type' in data:
            valid_types = [vt.value for vt in ValidationType]
            if data['validation_type'] not in valid_types:
                raise ValidationError(f"Invalid validation type. Must be one of: {valid_types}")
        
        return True
    
    def validate_field(self, field_name: str, value: Any, 
                      validation_rule: FieldValidationRule) -> ValidationResult:
        """
        Validate individual field with comprehensive validation logic.
        
        Implements field-level validation with type checking, business rules,
        and sanitization as specified in Section 4.5.1 validation patterns.
        
        Args:
            field_name: Name of the field being validated
            value: Value to validate
            validation_rule: Validation rule configuration
            
        Returns:
            ValidationResult with validation outcome and sanitized data
        """
        self.log_service_operation(f"Validating field: {field_name}", {"type": type(value).__name__})
        
        # Get appropriate validator for the field type
        validator = self._get_validator_for_type(validation_rule.data_type)
        
        # Perform type-specific validation
        result = validator.validate(value, validation_rule)
        
        # Apply custom validator if provided
        if validation_rule.custom_validator and result.is_valid:
            try:
                custom_result = validation_rule.custom_validator(value, validation_rule)
                if isinstance(custom_result, ValidationResult):
                    result.merge(custom_result)
                elif not custom_result:
                    result.add_error(
                        f"Custom validation failed for field '{field_name}'",
                        field_name
                    )
            except Exception as e:
                result.add_error(
                    f"Custom validator error for field '{field_name}': {e}",
                    field_name,
                    ValidationSeverity.CRITICAL
                )
        
        # Apply business rules if provided
        for business_rule in validation_rule.business_rules:
            if result.is_valid:
                try:
                    rule_result = business_rule(value, validation_rule)
                    if isinstance(rule_result, ValidationResult):
                        result.merge(rule_result)
                    elif not rule_result:
                        result.add_error(
                            f"Business rule validation failed for field '{field_name}'",
                            field_name
                        )
                except Exception as e:
                    result.add_error(
                        f"Business rule error for field '{field_name}': {e}",
                        field_name,
                        ValidationSeverity.ERROR
                    )
        
        self.log_service_operation(
            f"Field validation completed for: {field_name}",
            {"valid": result.is_valid, "errors": len(result.errors)}
        )
        
        return result
    
    def validate_data(self, data: Dict[str, Any], 
                     validation_rules: Dict[str, FieldValidationRule],
                     entity_type: Optional[str] = None) -> ValidationResult:
        """
        Validate complete data dictionary with comprehensive business rule enforcement.
        
        Implements comprehensive data validation as specified in Section 4.12.1
        with business rule enforcement and consistent error handling.
        
        Args:
            data: Data dictionary to validate
            validation_rules: Dictionary of field validation rules
            entity_type: Optional entity type for business rule context
            
        Returns:
            ValidationResult with comprehensive validation outcome
        """
        self.log_service_operation(
            f"Validating data for entity: {entity_type or 'unknown'}",
            {"fields": len(data), "rules": len(validation_rules)}
        )
        
        overall_result = ValidationResult(validation_type=ValidationType.BUSINESS_RULE)
        
        # Validate each field according to its rules
        for field_name, rule in validation_rules.items():
            field_value = data.get(field_name)
            field_result = self.validate_field(field_name, field_value, rule)
            overall_result.merge(field_result)
        
        # Check for required fields that are missing
        for field_name, rule in validation_rules.items():
            if rule.required and field_name not in data:
                overall_result.add_error(
                    f"Required field '{field_name}' is missing",
                    field_name,
                    ValidationSeverity.ERROR
                )
        
        # Apply entity-specific business rules if available
        if entity_type and entity_type in self._business_rules:
            for business_rule in self._business_rules[entity_type]:
                try:
                    rule_result = business_rule(data, validation_rules)
                    if isinstance(rule_result, ValidationResult):
                        overall_result.merge(rule_result)
                    elif not rule_result:
                        overall_result.add_error(
                            f"Entity business rule validation failed for {entity_type}",
                            severity=ValidationSeverity.ERROR
                        )
                except Exception as e:
                    overall_result.add_error(
                        f"Entity business rule error for {entity_type}: {e}",
                        severity=ValidationSeverity.CRITICAL
                    )
        
        self.log_service_operation(
            f"Data validation completed for entity: {entity_type or 'unknown'}",
            {
                "valid": overall_result.is_valid,
                "errors": len(overall_result.errors),
                "warnings": len(overall_result.warnings)
            }
        )
        
        return overall_result
    
    def validate_database_constraints(self, model_class: Type, 
                                    data: Dict[str, Any]) -> ValidationResult:
        """
        Validate database integrity constraints before persistence operations.
        
        Implements database integrity validation per Section 6.2.2.2 with
        constraint checking and referential integrity validation.
        
        Args:
            model_class: SQLAlchemy model class for constraint validation
            data: Data to validate against database constraints
            
        Returns:
            ValidationResult with database constraint validation outcome
        """
        self.log_service_operation(
            f"Validating database constraints for model: {model_class.__name__}",
            {"fields": len(data)}
        )
        
        result = ValidationResult(validation_type=ValidationType.CONSTRAINT)
        
        try:
            # Check unique constraints
            self._validate_unique_constraints(model_class, data, result)
            
            # Check foreign key constraints
            self._validate_foreign_key_constraints(model_class, data, result)
            
            # Check check constraints
            self._validate_check_constraints(model_class, data, result)
            
            # Check not null constraints
            self._validate_not_null_constraints(model_class, data, result)
            
        except Exception as e:
            result.add_error(
                f"Database constraint validation error: {e}",
                severity=ValidationSeverity.CRITICAL
            )
            self.logger.error(f"Database constraint validation failed: {e}", exc_info=True)
        
        self.log_service_operation(
            f"Database constraint validation completed for: {model_class.__name__}",
            {"valid": result.is_valid, "constraint_errors": len(result.errors)}
        )
        
        return result
    
    def sanitize_input(self, data: Dict[str, Any], 
                      sanitization_rules: Optional[Dict[str, callable]] = None) -> Dict[str, Any]:
        """
        Sanitize input data with comprehensive security-focused cleaning.
        
        Implements input sanitization patterns preservation per Section 2.1.9
        with HTML cleaning, script removal, and data normalization.
        
        Args:
            data: Data dictionary to sanitize
            sanitization_rules: Optional custom sanitization rules per field
            
        Returns:
            Sanitized data dictionary
        """
        self.log_service_operation(
            "Sanitizing input data",
            {"fields": len(data), "custom_rules": len(sanitization_rules or {})}
        )
        
        sanitized_data = {}
        
        for field_name, value in data.items():
            try:
                # Apply custom sanitization rule if available
                if sanitization_rules and field_name in sanitization_rules:
                    sanitized_value = sanitization_rules[field_name](value)
                else:
                    # Apply default sanitization based on type
                    sanitized_value = self._sanitize_by_type(value)
                
                sanitized_data[field_name] = sanitized_value
                
            except Exception as e:
                self.logger.warning(f"Sanitization failed for field {field_name}: {e}")
                # Keep original value if sanitization fails
                sanitized_data[field_name] = value
        
        self.log_service_operation(
            "Input sanitization completed",
            {"original_fields": len(data), "sanitized_fields": len(sanitized_data)}
        )
        
        return sanitized_data
    
    def register_business_rule(self, entity_type: str, rule_function: callable) -> None:
        """
        Register business rule for specific entity type.
        
        Enables dynamic business rule registration for entity-specific validation
        as specified in Feature F-005 business logic preservation.
        
        Args:
            entity_type: Entity type identifier
            rule_function: Callable business rule validation function
        """
        if entity_type not in self._business_rules:
            self._business_rules[entity_type] = []
        
        self._business_rules[entity_type].append(rule_function)
        
        self.log_service_operation(
            f"Registered business rule for entity: {entity_type}",
            {"total_rules": len(self._business_rules[entity_type])}
        )
    
    def create_validation_rules(self, dataclass_type: Type[DataClassType]) -> Dict[str, FieldValidationRule]:
        """
        Create validation rules from dataclass type hints and annotations.
        
        Implements Python dataclasses integration per Section 4.5.1 with
        automatic validation rule generation from type hints.
        
        Args:
            dataclass_type: Dataclass type to analyze for validation rules
            
        Returns:
            Dictionary of field validation rules
        """
        self.log_service_operation(
            f"Creating validation rules from dataclass: {dataclass_type.__name__}"
        )
        
        if dataclass_type.__name__ in self._validation_cache:
            return self._validation_cache[dataclass_type.__name__]
        
        validation_rules = {}
        
        # Get type hints for the dataclass
        type_hints = get_type_hints(dataclass_type)
        
        # Get dataclass fields
        dataclass_fields = fields(dataclass_type)
        
        for field_info in dataclass_fields:
            field_name = field_info.name
            field_type = type_hints.get(field_name, str)
            
            # Handle Optional types
            is_optional = False
            if get_origin(field_type) is Union:
                args = get_args(field_type)
                if len(args) == 2 and type(None) in args:
                    is_optional = True
                    field_type = next(arg for arg in args if arg is not type(None))
            
            # Create validation rule
            rule = FieldValidationRule(
                field_name=field_name,
                required=not is_optional and field_info.default == dataclass.MISSING,
                data_type=field_type
            )
            
            # Apply default constraints based on type
            if field_type == str:
                rule.max_length = 255  # Default string length limit
            elif field_type in (int, float):
                pass  # No default constraints for numbers
            elif field_type == datetime:
                pass  # No default constraints for datetime
            
            validation_rules[field_name] = rule
        
        # Cache the validation rules
        self._validation_cache[dataclass_type.__name__] = validation_rules
        
        self.log_service_operation(
            f"Created validation rules for dataclass: {dataclass_type.__name__}",
            {"rules_count": len(validation_rules)}
        )
        
        return validation_rules
    
    def validate_with_dataclass(self, data: Dict[str, Any], 
                               dataclass_type: Type[DataClassType]) -> ValidationResult:
        """
        Validate data using dataclass type hints and create validated instance.
        
        Combines Python dataclasses with validation service for type-safe
        business object creation as specified in Section 4.5.1.
        
        Args:
            data: Data dictionary to validate
            dataclass_type: Target dataclass type for validation
            
        Returns:
            ValidationResult with validated dataclass instance
        """
        self.log_service_operation(
            f"Validating data with dataclass: {dataclass_type.__name__}",
            {"input_fields": len(data)}
        )
        
        # Get or create validation rules for the dataclass
        validation_rules = self.create_validation_rules(dataclass_type)
        
        # Validate the data
        result = self.validate_data(data, validation_rules, dataclass_type.__name__)
        
        # If validation passes, create the dataclass instance
        if result.is_valid:
            try:
                # Use sanitized data if available, otherwise original data
                instance_data = result.sanitized_data if result.sanitized_data else data
                
                # Filter data to only include fields defined in the dataclass
                filtered_data = {
                    k: v for k, v in instance_data.items()
                    if k in validation_rules
                }
                
                # Create dataclass instance
                instance = dataclass_type(**filtered_data)
                result.metadata['dataclass_instance'] = instance
                
            except TypeError as e:
                result.add_error(
                    f"Failed to create {dataclass_type.__name__} instance: {e}",
                    severity=ValidationSeverity.CRITICAL
                )
        
        self.log_service_operation(
            f"Dataclass validation completed for: {dataclass_type.__name__}",
            {"valid": result.is_valid, "instance_created": 'dataclass_instance' in result.metadata}
        )
        
        return result
    
    def _get_validator_for_type(self, data_type: Optional[Type]) -> BaseValidator:
        """
        Get appropriate validator for the specified data type.
        
        Args:
            data_type: Data type to get validator for
            
        Returns:
            BaseValidator instance for the type
        """
        if data_type in self._validators:
            return self._validators[data_type]
        
        # Default to string validator for unknown types
        return self._validators[str]
    
    def _sanitize_by_type(self, value: Any) -> Any:
        """
        Apply type-appropriate sanitization to a value.
        
        Args:
            value: Value to sanitize
            
        Returns:
            Sanitized value
        """
        if value is None:
            return None
        
        # Determine type and apply appropriate sanitization
        if isinstance(value, str):
            return self._validators[str].sanitize(value)
        elif isinstance(value, (int, float, Decimal)):
            return self._validators[type(value)].sanitize(value)
        elif isinstance(value, datetime):
            return self._validators[datetime].sanitize(value)
        else:
            # Default string sanitization for unknown types
            return self._validators[str].sanitize(str(value))
    
    def _validate_unique_constraints(self, model_class: Type, 
                                   data: Dict[str, Any], 
                                   result: ValidationResult) -> None:
        """
        Validate unique constraints for database model.
        
        Args:
            model_class: SQLAlchemy model class
            data: Data to validate
            result: ValidationResult to update with constraint violations
        """
        # Get unique constraints from the model
        for constraint in model_class.__table__.constraints:
            if hasattr(constraint, 'columns') and len(constraint.columns) == 1:
                column = list(constraint.columns)[0]
                field_name = column.name
                
                if field_name in data and data[field_name] is not None:
                    # Check if value already exists
                    existing = self.session.query(model_class).filter(
                        getattr(model_class, field_name) == data[field_name]
                    ).first()
                    
                    if existing:
                        result.add_error(
                            f"Value for field '{field_name}' already exists",
                            field_name
                        )
    
    def _validate_foreign_key_constraints(self, model_class: Type,
                                        data: Dict[str, Any],
                                        result: ValidationResult) -> None:
        """
        Validate foreign key constraints for database model.
        
        Args:
            model_class: SQLAlchemy model class
            data: Data to validate
            result: ValidationResult to update with constraint violations
        """
        # Get foreign key constraints from the model
        for column in model_class.__table__.columns:
            if column.foreign_keys:
                field_name = column.name
                
                if field_name in data and data[field_name] is not None:
                    # Get the referenced table and column
                    fk = list(column.foreign_keys)[0]
                    referenced_table = fk.column.table
                    referenced_column = fk.column
                    
                    # Check if referenced record exists
                    query = text(f"SELECT 1 FROM {referenced_table.name} WHERE {referenced_column.name} = :value")
                    exists = self.session.execute(query, {"value": data[field_name]}).first()
                    
                    if not exists:
                        result.add_error(
                            f"Referenced record for field '{field_name}' does not exist",
                            field_name
                        )
    
    def _validate_check_constraints(self, model_class: Type,
                                  data: Dict[str, Any],
                                  result: ValidationResult) -> None:
        """
        Validate check constraints for database model.
        
        Args:
            model_class: SQLAlchemy model class
            data: Data to validate
            result: ValidationResult to update with constraint violations
        """
        # Check constraints are typically handled by the database
        # but we can validate common patterns here
        for column in model_class.__table__.columns:
            field_name = column.name
            
            if field_name in data:
                value = data[field_name]
                
                # Validate length constraints
                if hasattr(column.type, 'length') and column.type.length:
                    if isinstance(value, str) and len(value) > column.type.length:
                        result.add_error(
                            f"Field '{field_name}' exceeds maximum length of {column.type.length}",
                            field_name
                        )
    
    def _validate_not_null_constraints(self, model_class: Type,
                                     data: Dict[str, Any],
                                     result: ValidationResult) -> None:
        """
        Validate not null constraints for database model.
        
        Args:
            model_class: SQLAlchemy model class
            data: Data to validate
            result: ValidationResult to update with constraint violations
        """
        for column in model_class.__table__.columns:
            field_name = column.name
            
            # Skip primary key and timestamp fields that are auto-populated
            if column.primary_key or field_name in ('created_at', 'updated_at'):
                continue
            
            if not column.nullable:
                if field_name not in data or data[field_name] is None:
                    result.add_error(
                        f"Field '{field_name}' cannot be null",
                        field_name
                    )


# Export validation service and related classes for application use
__all__ = [
    'ValidationService',
    'ValidationResult',
    'FieldValidationRule',
    'ValidationSeverity',
    'ValidationType',
    'BaseValidator',
    'StringValidator',
    'NumericValidator',
    'EmailValidator',
    'DateTimeValidator'
]