"""
Validation Service Implementation for Flask Application

This module provides comprehensive input validation, business rule enforcement, and 
standardized error handling following the Service Layer pattern. The validation service 
converts Node.js middleware validation patterns to Flask Service Layer architecture 
with type-safe validation logic and standardized error responses.

Key Features:
- Type-hinted validation logic with comprehensive error handling
- Business rule enforcement maintaining existing validation patterns  
- Service Layer pattern integration for enhanced testability
- Standardized ValidationResult objects with field-level error mapping
- Flask request context integration for user attribution
- Comprehensive logging and monitoring integration
- Support for custom validation rules and business logic constraints
- Integration with Flask-SQLAlchemy models for database validation

Architecture:
This implementation follows the Service Layer pattern as specified in Section 4.5.1.2
of the technical specification, providing clear separation between presentation logic
and business rule validation while enabling comprehensive unit testing through
dependency injection patterns.
"""

from __future__ import annotations

import re
import logging
import ipaddress
from abc import ABC, abstractmethod
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from email.utils import parseaddr
from typing import (
    Any, 
    Dict, 
    List, 
    Optional, 
    Union, 
    Callable, 
    Type,
    Pattern,
    Tuple,
    Set
)
from urllib.parse import urlparse
from dataclasses import dataclass, field

from flask import current_app, request, g
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from .base_service import (
    BaseService, 
    ValidationResult, 
    ServiceResult, 
    ServiceException,
    ValidationException,
    DatabaseSession
)


# Type definitions for validation
ValidationRule = Callable[[Any], bool]
ValidationRuleSet = Dict[str, Dict[str, Any]]
FieldErrors = Dict[str, List[str]]


@dataclass
class ValidationContext:
    """
    Validation context providing additional information for business rule evaluation.
    
    This class encapsulates request context, user information, and other contextual
    data that may be required for comprehensive validation of business rules and
    data constraints.
    
    Attributes:
        user_id: Current authenticated user identifier
        request_path: HTTP request path for audit logging
        request_method: HTTP method for context-aware validation
        ip_address: Client IP address for security validation
        timestamp: Validation execution timestamp
        additional_context: Additional context data for custom validation rules
    """
    user_id: Optional[int] = None
    request_path: Optional[str] = None
    request_method: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationConstraints:
    """
    Comprehensive validation constraints for field-level validation.
    
    This class provides a structured approach to defining validation rules
    with support for both basic data type validation and complex business
    rule enforcement.
    
    Attributes:
        required: Field is required and cannot be None or empty
        data_type: Expected Python data type for the field
        min_length: Minimum string length or collection size
        max_length: Maximum string length or collection size
        min_value: Minimum numeric value
        max_value: Maximum numeric value
        pattern: Regular expression pattern for string validation
        allowed_values: Set of allowed values for enumeration validation
        custom_validator: Custom validation function for complex rules
        business_rules: List of business rule validation functions
        error_message: Custom error message for validation failures
    """
    required: bool = False
    data_type: Optional[Type] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float, Decimal]] = None
    max_value: Optional[Union[int, float, Decimal]] = None
    pattern: Optional[Union[str, Pattern]] = None
    allowed_values: Optional[Set[Any]] = None
    custom_validator: Optional[ValidationRule] = None
    business_rules: List[ValidationRule] = field(default_factory=list)
    error_message: Optional[str] = None


class ValidationServiceException(ServiceException):
    """Exception raised for validation service-specific errors."""
    
    def __init__(
        self, 
        message: str, 
        validation_result: Optional[ValidationResult] = None,
        field_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize validation service exception with detailed context."""
        super().__init__(message, 'VALIDATION_SERVICE_ERROR', details)
        self.validation_result = validation_result
        self.field_name = field_name


class ValidatorRegistry:
    """
    Registry for custom validation functions and business rules.
    
    This class provides a centralized mechanism for registering and retrieving
    custom validation functions, enabling modular and extensible validation
    logic throughout the application.
    """
    
    def __init__(self):
        """Initialize validator registry with built-in validators."""
        self._validators: Dict[str, ValidationRule] = {}
        self._business_rules: Dict[str, ValidationRule] = {}
        self._register_builtin_validators()
    
    def register_validator(self, name: str, validator: ValidationRule) -> None:
        """Register a custom validation function."""
        if not callable(validator):
            raise ValueError(f"Validator {name} must be callable")
        self._validators[name] = validator
    
    def register_business_rule(self, name: str, rule: ValidationRule) -> None:
        """Register a business rule validation function."""
        if not callable(rule):
            raise ValueError(f"Business rule {name} must be callable")
        self._business_rules[name] = rule
    
    def get_validator(self, name: str) -> Optional[ValidationRule]:
        """Retrieve a registered validation function by name."""
        return self._validators.get(name)
    
    def get_business_rule(self, name: str) -> Optional[ValidationRule]:
        """Retrieve a registered business rule by name."""
        return self._business_rules.get(name)
    
    def _register_builtin_validators(self) -> None:
        """Register built-in validation functions."""
        self._validators.update({
            'email': self._validate_email,
            'url': self._validate_url,
            'phone': self._validate_phone,
            'ip_address': self._validate_ip_address,
            'credit_card': self._validate_credit_card,
            'postal_code': self._validate_postal_code,
            'alphanumeric': self._validate_alphanumeric,
            'alpha': self._validate_alpha,
            'numeric': self._validate_numeric
        })
    
    @staticmethod
    def _validate_email(value: str) -> bool:
        """Validate email address format."""
        if not isinstance(value, str):
            return False
        name, addr = parseaddr(value)
        return '@' in addr and '.' in addr.split('@')[1]
    
    @staticmethod
    def _validate_url(value: str) -> bool:
        """Validate URL format."""
        if not isinstance(value, str):
            return False
        try:
            result = urlparse(value)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def _validate_phone(value: str) -> bool:
        """Validate phone number format (international format)."""
        if not isinstance(value, str):
            return False
        # Remove all non-numeric characters except +
        clean_phone = re.sub(r'[^\d+]', '', value)
        # Basic validation for international format
        return re.match(r'^\+?[1-9]\d{6,14}$', clean_phone) is not None
    
    @staticmethod
    def _validate_ip_address(value: str) -> bool:
        """Validate IP address (IPv4 or IPv6)."""
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _validate_credit_card(value: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        if not isinstance(value, str):
            return False
        # Remove spaces and hyphens
        card_number = re.sub(r'[\s-]', '', value)
        if not card_number.isdigit() or len(card_number) < 13 or len(card_number) > 19:
            return False
        
        # Luhn algorithm
        total = 0
        reverse_digits = card_number[::-1]
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:  # Every second digit
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        
        return total % 10 == 0
    
    @staticmethod
    def _validate_postal_code(value: str) -> bool:
        """Validate postal code format (US ZIP code)."""
        if not isinstance(value, str):
            return False
        return re.match(r'^\d{5}(-\d{4})?$', value) is not None
    
    @staticmethod
    def _validate_alphanumeric(value: str) -> bool:
        """Validate alphanumeric characters only."""
        if not isinstance(value, str):
            return False
        return value.isalnum()
    
    @staticmethod
    def _validate_alpha(value: str) -> bool:
        """Validate alphabetic characters only."""
        if not isinstance(value, str):
            return False
        return value.isalpha()
    
    @staticmethod
    def _validate_numeric(value: str) -> bool:
        """Validate numeric characters only."""
        if not isinstance(value, str):
            return False
        return value.isdigit()


class ValidationService(BaseService[None]):
    """
    Comprehensive validation service implementing Flask Service Layer pattern.
    
    This service provides input validation, business rule enforcement, and 
    standardized error handling for Flask applications. It converts Node.js 
    middleware validation patterns to Service Layer architecture with enhanced 
    type safety and comprehensive error reporting.
    
    Key Features:
    - Type-hinted validation methods for all common data types
    - Business rule enforcement with contextual validation
    - Field-level validation with detailed error mapping
    - Integration with Flask request context for audit logging
    - Support for custom validation rules and business logic
    - Comprehensive error handling and recovery mechanisms
    - Performance monitoring and validation metrics collection
    
    Architecture:
    The service follows the Service Layer pattern with dependency injection
    of SQLAlchemy sessions, enabling comprehensive testing and modular 
    validation logic organization.
    """
    
    def __init__(
        self, 
        db_session: DatabaseSession,
        validator_registry: Optional[ValidatorRegistry] = None
    ) -> None:
        """
        Initialize validation service with dependency injection.
        
        Args:
            db_session: SQLAlchemy database session for data validation
            validator_registry: Custom validator registry for extensible validation
            
        Raises:
            TypeError: If db_session doesn't implement DatabaseSession protocol
        """
        super().__init__(db_session, model_class=None)
        self.validator_registry = validator_registry or ValidatorRegistry()
        
        # Validation metrics for monitoring
        self._validation_count = 0
        self._validation_error_count = 0
        self._business_rule_violation_count = 0
        
        self.logger.info("ValidationService initialized with Service Layer pattern")
    
    def validate_data(
        self, 
        data: Dict[str, Any], 
        rules: Optional[ValidationRuleSet] = None,
        context: Optional[ValidationContext] = None
    ) -> ValidationResult:
        """
        Comprehensive data validation with business rule enforcement.
        
        This method performs multi-layer validation including data type validation,
        constraint checking, business rule enforcement, and contextual validation
        based on user permissions and request context.
        
        Args:
            data: Dictionary containing data to validate
            rules: Validation rules dictionary defining constraints and business rules
            context: Validation context for business rule evaluation
            
        Returns:
            ValidationResult: Comprehensive validation result with field-level errors
            
        Example:
            ```python
            rules = {
                'email': {
                    'required': True,
                    'type': str,
                    'validator': 'email',
                    'max_length': 255
                },
                'age': {
                    'required': True,
                    'type': int,
                    'min_value': 18,
                    'max_value': 120
                }
            }
            
            result = validation_service.validate_data(
                {'email': 'user@example.com', 'age': 25},
                rules
            )
            
            if not result.is_valid:
                return jsonify({'errors': result.field_errors}), 400
            ```
        """
        self._increment_operation_count()
        
        # Create validation context if not provided
        if context is None:
            context = self._create_validation_context()
        
        validation_result = ValidationResult(is_valid=True, errors=[])
        
        try:
            # Log validation request for audit trail
            self.logger.debug(
                f"Validating data with {len(data)} fields for user {context.user_id}"
            )
            
            # Basic data structure validation
            if not isinstance(data, dict):
                validation_result.add_error("Data must be a dictionary")
                return validation_result
            
            # Apply validation rules if provided
            if rules:
                self._apply_validation_rules(data, rules, validation_result, context)
            
            # Apply business rules validation
            self._apply_business_rules(data, validation_result, context)
            
            # Update validation metrics
            self._validation_count += 1
            if not validation_result.is_valid:
                self._validation_error_count += 1
            
            # Log validation results
            self.logger.info(
                f"Validation completed: {'PASSED' if validation_result.is_valid else 'FAILED'} "
                f"with {len(validation_result.errors)} errors for user {context.user_id}"
            )
            
            return validation_result
            
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Validation service error: {str(e)}")
            
            validation_result.is_valid = False
            validation_result.add_error(f"Validation service error: {str(e)}")
            
            return validation_result
    
    def validate_field(
        self, 
        field_name: str, 
        value: Any, 
        constraints: ValidationConstraints,
        context: Optional[ValidationContext] = None
    ) -> ValidationResult:
        """
        Validate individual field with comprehensive constraint checking.
        
        This method provides detailed validation for a single field value
        against defined constraints including type checking, length validation,
        range validation, pattern matching, and custom business rules.
        
        Args:
            field_name: Name of the field being validated
            value: Value to validate
            constraints: ValidationConstraints object defining validation rules
            context: Optional validation context for business rule evaluation
            
        Returns:
            ValidationResult: Detailed validation result for the field
            
        Example:
            ```python
            constraints = ValidationConstraints(
                required=True,
                data_type=str,
                min_length=5,
                max_length=50,
                pattern=r'^[a-zA-Z0-9_]+$'
            )
            
            result = validation_service.validate_field(
                'username', 
                'john_doe123', 
                constraints
            )
            ```
        """
        if context is None:
            context = self._create_validation_context()
        
        validation_result = ValidationResult(is_valid=True, errors=[])
        
        try:
            # Required field validation
            if constraints.required and (value is None or value == ''):
                validation_result.add_error(
                    constraints.error_message or f"Field '{field_name}' is required",
                    field=field_name
                )
                return validation_result
            
            # Skip further validation if field is not required and empty
            if not constraints.required and (value is None or value == ''):
                return validation_result
            
            # Data type validation
            if constraints.data_type and not isinstance(value, constraints.data_type):
                validation_result.add_error(
                    f"Field '{field_name}' must be of type {constraints.data_type.__name__}",
                    field=field_name
                )
                return validation_result
            
            # Length validation for strings and collections
            if constraints.min_length is not None or constraints.max_length is not None:
                self._validate_length(field_name, value, constraints, validation_result)
            
            # Numeric range validation
            if constraints.min_value is not None or constraints.max_value is not None:
                self._validate_range(field_name, value, constraints, validation_result)
            
            # Pattern validation for strings
            if constraints.pattern and isinstance(value, str):
                self._validate_pattern(field_name, value, constraints, validation_result)
            
            # Allowed values validation
            if constraints.allowed_values and value not in constraints.allowed_values:
                validation_result.add_error(
                    f"Field '{field_name}' must be one of: {list(constraints.allowed_values)}",
                    field=field_name
                )
            
            # Custom validator
            if constraints.custom_validator:
                if not constraints.custom_validator(value):
                    validation_result.add_error(
                        constraints.error_message or f"Field '{field_name}' failed custom validation",
                        field=field_name
                    )
            
            # Business rules validation
            for business_rule in constraints.business_rules:
                if not business_rule(value):
                    validation_result.add_error(
                        f"Field '{field_name}' violates business rule",
                        field=field_name
                    )
                    self._business_rule_violation_count += 1
            
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Field validation error for {field_name}: {str(e)}")
            validation_result.add_error(
                f"Validation error for field '{field_name}': {str(e)}",
                field=field_name
            )
            return validation_result
    
    def validate_business_entity(
        self, 
        entity_data: Dict[str, Any],
        entity_type: str,
        context: Optional[ValidationContext] = None
    ) -> ValidationResult:
        """
        Validate business entity data with domain-specific rules.
        
        This method provides comprehensive validation for business entities
        including cross-field validation, business logic constraints, and
        entity-specific rules based on the entity type.
        
        Args:
            entity_data: Business entity data to validate
            entity_type: Type of business entity (e.g., 'user', 'order', 'product')
            context: Validation context for business rule evaluation
            
        Returns:
            ValidationResult: Comprehensive validation result for the entity
            
        Example:
            ```python
            user_data = {
                'email': 'user@example.com',
                'password': 'SecurePass123!',
                'confirm_password': 'SecurePass123!',
                'age': 25
            }
            
            result = validation_service.validate_business_entity(
                user_data, 
                'user'
            )
            ```
        """
        if context is None:
            context = self._create_validation_context()
        
        validation_result = ValidationResult(is_valid=True, errors=[])
        
        try:
            # Get entity-specific validation rules
            entity_rules = self.get_business_rules().get(entity_type, {})
            
            # Apply entity-specific validation
            if entity_rules:
                self._apply_validation_rules(
                    entity_data, 
                    entity_rules, 
                    validation_result, 
                    context
                )
            
            # Apply cross-field validation
            self._apply_cross_field_validation(
                entity_data, 
                entity_type, 
                validation_result, 
                context
            )
            
            # Apply entity-specific business rules
            self._apply_entity_business_rules(
                entity_data, 
                entity_type, 
                validation_result, 
                context
            )
            
            self.logger.debug(
                f"Business entity validation for {entity_type}: "
                f"{'PASSED' if validation_result.is_valid else 'FAILED'}"
            )
            
            return validation_result
            
        except Exception as e:
            self.logger.error(f"Business entity validation error: {str(e)}")
            validation_result.add_error(f"Entity validation error: {str(e)}")
            return validation_result
    
    def validate_database_constraints(
        self, 
        model_class: Type, 
        data: Dict[str, Any],
        context: Optional[ValidationContext] = None
    ) -> ValidationResult:
        """
        Validate data against database model constraints and relationships.
        
        This method validates data against SQLAlchemy model constraints including
        unique constraints, foreign key relationships, and database-level validation
        rules to prevent constraint violations during database operations.
        
        Args:
            model_class: SQLAlchemy model class for constraint validation
            data: Data to validate against model constraints
            context: Validation context for audit logging
            
        Returns:
            ValidationResult: Database constraint validation result
            
        Example:
            ```python
            from models.user import User
            
            user_data = {'email': 'user@example.com', 'username': 'johndoe'}
            
            result = validation_service.validate_database_constraints(
                User, 
                user_data
            )
            ```
        """
        if context is None:
            context = self._create_validation_context()
        
        validation_result = ValidationResult(is_valid=True, errors=[])
        
        try:
            # Validate required model fields
            if hasattr(model_class, '__table__'):
                for column in model_class.__table__.columns:
                    column_name = column.name
                    
                    # Check required fields
                    if not column.nullable and column.default is None:
                        if column_name not in data or data[column_name] is None:
                            validation_result.add_error(
                                f"Field '{column_name}' is required by database schema",
                                field=column_name
                            )
                    
                    # Check field length constraints
                    if hasattr(column.type, 'length') and column.type.length:
                        if column_name in data and isinstance(data[column_name], str):
                            if len(data[column_name]) > column.type.length:
                                validation_result.add_error(
                                    f"Field '{column_name}' exceeds maximum length of {column.type.length}",
                                    field=column_name
                                )
            
            # Validate unique constraints
            self._validate_unique_constraints(model_class, data, validation_result)
            
            # Validate foreign key relationships
            self._validate_foreign_key_constraints(model_class, data, validation_result)
            
            return validation_result
            
        except SQLAlchemyError as e:
            self.logger.error(f"Database constraint validation error: {str(e)}")
            validation_result.add_error(f"Database validation error: {str(e)}")
            return validation_result
    
    def get_validation_metrics(self) -> Dict[str, Any]:
        """
        Get validation service performance metrics.
        
        Returns:
            Dictionary containing validation metrics for monitoring and analysis
        """
        base_metrics = self.operation_metrics
        validation_metrics = {
            'validation_count': self._validation_count,
            'validation_error_count': self._validation_error_count,
            'business_rule_violation_count': self._business_rule_violation_count,
            'validation_error_rate': (
                self._validation_error_count / max(self._validation_count, 1)
            ) * 100,
            'business_rule_violation_rate': (
                self._business_rule_violation_count / max(self._validation_count, 1)
            ) * 100
        }
        
        return {**base_metrics, **validation_metrics}
    
    def register_custom_validator(self, name: str, validator: ValidationRule) -> None:
        """
        Register custom validation function for application-specific validation.
        
        Args:
            name: Unique name for the validator
            validator: Validation function that returns bool
            
        Example:
            ```python
            def validate_business_id(value):
                return isinstance(value, str) and len(value) == 10 and value.isalnum()
            
            validation_service.register_custom_validator('business_id', validate_business_id)
            ```
        """
        self.validator_registry.register_validator(name, validator)
        self.logger.info(f"Registered custom validator: {name}")
    
    def register_business_rule(self, name: str, rule: ValidationRule) -> None:
        """
        Register business rule for domain-specific validation.
        
        Args:
            name: Unique name for the business rule
            rule: Business rule function that returns bool
            
        Example:
            ```python
            def minimum_age_rule(age_value):
                return isinstance(age_value, int) and age_value >= 18
            
            validation_service.register_business_rule('minimum_age', minimum_age_rule)
            ```
        """
        self.validator_registry.register_business_rule(name, rule)
        self.logger.info(f"Registered business rule: {name}")
    
    def get_business_rules(self) -> Dict[str, Any]:
        """
        Get business rules configuration for entity validation.
        
        This method provides business rules specific to different entity types
        for comprehensive validation. Rules are organized by entity type with
        field-level validation constraints and cross-field business rules.
        
        Returns:
            Dictionary containing business rules organized by entity type
        """
        return {
            'user': {
                'email': {
                    'required': True,
                    'type': str,
                    'validator': 'email',
                    'max_length': 255
                },
                'username': {
                    'required': True,
                    'type': str,
                    'min_length': 3,
                    'max_length': 50,
                    'pattern': r'^[a-zA-Z0-9_]+$'
                },
                'password': {
                    'required': True,
                    'type': str,
                    'min_length': 8,
                    'max_length': 128
                },
                'age': {
                    'required': False,
                    'type': int,
                    'min_value': 13,
                    'max_value': 120
                }
            },
            'business_entity': {
                'name': {
                    'required': True,
                    'type': str,
                    'min_length': 2,
                    'max_length': 100
                },
                'email': {
                    'required': True,
                    'type': str,
                    'validator': 'email',
                    'max_length': 255
                },
                'phone': {
                    'required': False,
                    'type': str,
                    'validator': 'phone'
                },
                'website': {
                    'required': False,
                    'type': str,
                    'validator': 'url'
                }
            },
            'address': {
                'street': {
                    'required': True,
                    'type': str,
                    'max_length': 255
                },
                'city': {
                    'required': True,
                    'type': str,
                    'max_length': 100
                },
                'state': {
                    'required': True,
                    'type': str,
                    'max_length': 50
                },
                'postal_code': {
                    'required': True,
                    'type': str,
                    'validator': 'postal_code'
                },
                'country': {
                    'required': True,
                    'type': str,
                    'max_length': 100
                }
            }
        }
    
    def _create_validation_context(self) -> ValidationContext:
        """Create validation context from Flask request context."""
        context = ValidationContext()
        
        # Extract user information from Flask context
        if hasattr(g, 'current_user_id'):
            context.user_id = g.current_user_id
        
        # Extract request information
        if request:
            context.request_path = request.path
            context.request_method = request.method
            context.ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        return context
    
    def _apply_validation_rules(
        self, 
        data: Dict[str, Any], 
        rules: ValidationRuleSet, 
        validation_result: ValidationResult,
        context: ValidationContext
    ) -> None:
        """Apply validation rules to data fields."""
        for field_name, field_rules in rules.items():
            value = data.get(field_name)
            
            # Create validation constraints from rules
            constraints = self._create_constraints_from_rules(field_rules)
            
            # Validate field
            field_result = self.validate_field(field_name, value, constraints, context)
            
            # Merge field validation results
            if not field_result.is_valid:
                validation_result.is_valid = False
                validation_result.errors.extend(field_result.errors)
                
                # Merge field errors
                for field, errors in field_result.field_errors.items():
                    if field not in validation_result.field_errors:
                        validation_result.field_errors[field] = []
                    validation_result.field_errors[field].extend(errors)
    
    def _create_constraints_from_rules(self, rules: Dict[str, Any]) -> ValidationConstraints:
        """Create ValidationConstraints object from rules dictionary."""
        constraints = ValidationConstraints()
        
        # Map rules to constraints
        constraints.required = rules.get('required', False)
        constraints.data_type = rules.get('type')
        constraints.min_length = rules.get('min_length')
        constraints.max_length = rules.get('max_length')
        constraints.min_value = rules.get('min_value')
        constraints.max_value = rules.get('max_value')
        constraints.pattern = rules.get('pattern')
        constraints.error_message = rules.get('error_message')
        
        # Handle allowed values
        if 'allowed_values' in rules:
            constraints.allowed_values = set(rules['allowed_values'])
        
        # Handle custom validator
        validator_name = rules.get('validator')
        if validator_name:
            constraints.custom_validator = self.validator_registry.get_validator(validator_name)
        
        # Handle business rules
        business_rule_names = rules.get('business_rules', [])
        for rule_name in business_rule_names:
            rule = self.validator_registry.get_business_rule(rule_name)
            if rule:
                constraints.business_rules.append(rule)
        
        return constraints
    
    def _validate_length(
        self, 
        field_name: str, 
        value: Any, 
        constraints: ValidationConstraints,
        validation_result: ValidationResult
    ) -> None:
        """Validate length constraints for strings and collections."""
        if hasattr(value, '__len__'):
            length = len(value)
            
            if constraints.min_length is not None and length < constraints.min_length:
                validation_result.add_error(
                    f"Field '{field_name}' must be at least {constraints.min_length} characters",
                    field=field_name
                )
            
            if constraints.max_length is not None and length > constraints.max_length:
                validation_result.add_error(
                    f"Field '{field_name}' must not exceed {constraints.max_length} characters",
                    field=field_name
                )
    
    def _validate_range(
        self, 
        field_name: str, 
        value: Any, 
        constraints: ValidationConstraints,
        validation_result: ValidationResult
    ) -> None:
        """Validate numeric range constraints."""
        if isinstance(value, (int, float, Decimal)):
            if constraints.min_value is not None and value < constraints.min_value:
                validation_result.add_error(
                    f"Field '{field_name}' must be at least {constraints.min_value}",
                    field=field_name
                )
            
            if constraints.max_value is not None and value > constraints.max_value:
                validation_result.add_error(
                    f"Field '{field_name}' must not exceed {constraints.max_value}",
                    field=field_name
                )
    
    def _validate_pattern(
        self, 
        field_name: str, 
        value: str, 
        constraints: ValidationConstraints,
        validation_result: ValidationResult
    ) -> None:
        """Validate string against regular expression pattern."""
        try:
            pattern = constraints.pattern
            if isinstance(pattern, str):
                pattern = re.compile(pattern)
            
            if not pattern.match(value):
                validation_result.add_error(
                    f"Field '{field_name}' does not match required pattern",
                    field=field_name
                )
        except re.error as e:
            self.logger.error(f"Invalid regex pattern for field {field_name}: {e}")
            validation_result.add_error(
                f"Invalid validation pattern for field '{field_name}'",
                field=field_name
            )
    
    def _apply_business_rules(
        self, 
        data: Dict[str, Any], 
        validation_result: ValidationResult,
        context: ValidationContext
    ) -> None:
        """Apply global business rules to data."""
        # Example business rules - customize based on application requirements
        
        # Password confirmation rule
        if 'password' in data and 'confirm_password' in data:
            if data['password'] != data['confirm_password']:
                validation_result.add_error(
                    "Password and password confirmation must match",
                    field='confirm_password'
                )
                self._business_rule_violation_count += 1
        
        # Age and terms acceptance rule
        if 'age' in data and 'terms_accepted' in data:
            if data['age'] < 18 and not data.get('parental_consent'):
                validation_result.add_error(
                    "Users under 18 require parental consent",
                    field='parental_consent'
                )
                self._business_rule_violation_count += 1
    
    def _apply_cross_field_validation(
        self, 
        entity_data: Dict[str, Any], 
        entity_type: str,
        validation_result: ValidationResult,
        context: ValidationContext
    ) -> None:
        """Apply cross-field validation rules specific to entity types."""
        if entity_type == 'user':
            # Username and email uniqueness will be checked at database level
            # Password strength validation
            if 'password' in entity_data:
                self._validate_password_strength(
                    entity_data['password'], 
                    validation_result
                )
        
        elif entity_type == 'business_entity':
            # Business entity specific cross-field validation
            if 'email' in entity_data and 'website' in entity_data:
                # Ensure email domain matches website domain for consistency
                email = entity_data['email']
                website = entity_data['website']
                if '@' in email and website:
                    email_domain = email.split('@')[1].lower()
                    try:
                        website_domain = urlparse(website).netloc.lower()
                        if website_domain and email_domain not in website_domain:
                            validation_result.add_warning(
                                "Email domain does not match website domain"
                            )
                    except Exception:
                        pass  # Website validation will catch invalid URLs
    
    def _apply_entity_business_rules(
        self, 
        entity_data: Dict[str, Any], 
        entity_type: str,
        validation_result: ValidationResult,
        context: ValidationContext
    ) -> None:
        """Apply entity-specific business rules."""
        # Time-based business rules
        current_time = datetime.utcnow()
        
        if entity_type == 'user':
            # User registration business rules
            if 'registration_date' in entity_data:
                reg_date = entity_data['registration_date']
                if isinstance(reg_date, datetime) and reg_date > current_time:
                    validation_result.add_error(
                        "Registration date cannot be in the future",
                        field='registration_date'
                    )
                    self._business_rule_violation_count += 1
        
        # Context-based business rules
        if context.user_id:
            # User can only modify their own data (basic example)
            if 'user_id' in entity_data and entity_data['user_id'] != context.user_id:
                # This would typically be handled by authorization, but including as example
                validation_result.add_error(
                    "Users can only modify their own data",
                    field='user_id'
                )
                self._business_rule_violation_count += 1
    
    def _validate_password_strength(
        self, 
        password: str, 
        validation_result: ValidationResult
    ) -> None:
        """Validate password strength requirements."""
        if not isinstance(password, str):
            return
        
        # Password strength criteria
        if len(password) < 8:
            validation_result.add_error(
                "Password must be at least 8 characters long",
                field='password'
            )
        
        if not re.search(r'[A-Z]', password):
            validation_result.add_error(
                "Password must contain at least one uppercase letter",
                field='password'
            )
        
        if not re.search(r'[a-z]', password):
            validation_result.add_error(
                "Password must contain at least one lowercase letter",
                field='password'
            )
        
        if not re.search(r'\d', password):
            validation_result.add_error(
                "Password must contain at least one digit",
                field='password'
            )
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            validation_result.add_error(
                "Password must contain at least one special character",
                field='password'
            )
    
    def _validate_unique_constraints(
        self, 
        model_class: Type, 
        data: Dict[str, Any],
        validation_result: ValidationResult
    ) -> None:
        """Validate unique constraints against existing database records."""
        try:
            # Get unique columns from model
            if hasattr(model_class, '__table__'):
                for constraint in model_class.__table__.constraints:
                    if hasattr(constraint, 'columns') and len(constraint.columns) == 1:
                        column = list(constraint.columns)[0]
                        column_name = column.name
                        
                        if column_name in data:
                            # Check if value already exists
                            existing = self.db_session.query(model_class).filter(
                                getattr(model_class, column_name) == data[column_name]
                            ).first()
                            
                            if existing:
                                validation_result.add_error(
                                    f"Value for '{column_name}' already exists",
                                    field=column_name
                                )
        
        except SQLAlchemyError as e:
            self.logger.error(f"Error validating unique constraints: {e}")
    
    def _validate_foreign_key_constraints(
        self, 
        model_class: Type, 
        data: Dict[str, Any],
        validation_result: ValidationResult
    ) -> None:
        """Validate foreign key constraints."""
        try:
            # Get foreign key columns from model
            if hasattr(model_class, '__table__'):
                for fk in model_class.__table__.foreign_keys:
                    column_name = fk.parent.name
                    
                    if column_name in data and data[column_name] is not None:
                        # Get referenced table and column
                        referenced_table = fk.column.table
                        referenced_column = fk.column
                        
                        # Check if referenced record exists
                        # This is a simplified check - in practice, you'd need to
                        # get the actual model class for the referenced table
                        query = self.db_session.query(referenced_column).filter(
                            referenced_column == data[column_name]
                        )
                        
                        if not query.first():
                            validation_result.add_error(
                                f"Referenced record for '{column_name}' does not exist",
                                field=column_name
                            )
        
        except SQLAlchemyError as e:
            self.logger.error(f"Error validating foreign key constraints: {e}")


def create_validation_service_factory(db_session: DatabaseSession) -> ValidationService:
    """
    Factory function for creating ValidationService instances.
    
    This factory function facilitates Flask application factory pattern integration
    by providing a standardized way to create validation service instances with
    proper dependency injection.
    
    Args:
        db_session: Database session for dependency injection
        
    Returns:
        Configured ValidationService instance ready for use
        
    Example:
        ```python
        # In Flask application factory
        @app.route('/users', methods=['POST'])
        def create_user():
            validation_service = create_validation_service_factory(db.session)
            
            result = validation_service.validate_business_entity(
                request.json, 
                'user'
            )
            
            if not result.is_valid:
                return jsonify({'errors': result.field_errors}), 400
            
            # Proceed with user creation
            return jsonify({'status': 'success'}), 201
        ```
    """
    return ValidationService(db_session)


# Utility functions for validation service integration

def validate_request_data(
    data: Dict[str, Any], 
    entity_type: str,
    db_session: DatabaseSession
) -> Tuple[bool, Dict[str, Any]]:
    """
    Utility function for validating Flask request data.
    
    This function provides a convenient interface for validating request data
    in Flask route handlers with standardized error response formatting.
    
    Args:
        data: Request data to validate
        entity_type: Type of entity being validated
        db_session: Database session for validation
        
    Returns:
        Tuple of (is_valid, response_data) for Flask response handling
        
    Example:
        ```python
        @app.route('/users', methods=['POST'])
        def create_user():
            is_valid, response = validate_request_data(
                request.json, 
                'user', 
                db.session
            )
            
            if not is_valid:
                return jsonify(response), 400
            
            # Proceed with user creation
            return jsonify({'status': 'success'}), 201
        ```
    """
    validation_service = ValidationService(db_session)
    
    result = validation_service.validate_business_entity(data, entity_type)
    
    if result.is_valid:
        return True, {'status': 'valid'}
    else:
        return False, {
            'status': 'validation_failed',
            'errors': result.errors,
            'field_errors': result.field_errors
        }


def get_validation_service_metrics(db_session: DatabaseSession) -> Dict[str, Any]:
    """
    Get validation service metrics for monitoring and analysis.
    
    Args:
        db_session: Database session for service instantiation
        
    Returns:
        Dictionary containing comprehensive validation metrics
    """
    validation_service = ValidationService(db_session)
    return validation_service.get_validation_metrics()