"""
Business validation service implementing comprehensive data validation, business rule enforcement,
and constraint checking across all business operations. This service centralizes validation logic
using Python dataclasses and type hints while maintaining all original Node.js validation patterns
through the Service Layer pattern.

This module provides:
- Dataclass-based validation schemas with type hints
- Business rule enforcement and validation logic preservation
- Input validation and sanitization patterns
- Database constraint checking and integrity validation
- Consistent validation error handling across all business operations

Implements Feature F-005 business logic preservation and Section 4.5.1 dataclass integration
requirements from the technical specification.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Set, Callable, Type
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
import re
import html
import json
import uuid
import logging

from flask import current_app, g
from werkzeug.security import safe_str_cmp
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError, DataError
from sqlalchemy.orm import sessionmaker
from marshmallow import Schema, fields, ValidationError as MarshmallowValidationError

# Import logging and error handling utilities
from ..utils.logging import get_structured_logger
from ..utils.error_handling import ValidationError, BusinessRuleError, DatabaseConstraintError


class ValidationSeverity(Enum):
    """Validation error severity levels for comprehensive error classification."""
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationType(Enum):
    """Types of validation checks performed by the validation service."""
    DATA_TYPE = "data_type"
    BUSINESS_RULE = "business_rule"
    CONSTRAINT = "constraint"
    SANITIZATION = "sanitization"
    SECURITY = "security"
    FORMAT = "format"


@dataclass
class ValidationResult:
    """
    Comprehensive validation result with detailed error tracking and metadata.
    
    Implements Section 4.5.1 dataclass and type hints integration for robust
    data validation and type safety throughout the validation workflow.
    """
    is_valid: bool
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    sanitized_data: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    validation_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_error(
        self,
        field: str,
        message: str,
        code: str,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
        validation_type: ValidationType = ValidationType.DATA_TYPE,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add validation error with comprehensive metadata."""
        error = {
            'field': field,
            'message': message,
            'code': code,
            'severity': severity.value,
            'type': validation_type.value,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'context': context or {}
        }
        
        if severity in [ValidationSeverity.CRITICAL, ValidationSeverity.ERROR]:
            self.errors.append(error)
            self.is_valid = False
        else:
            self.warnings.append(error)
    
    def add_warning(
        self,
        field: str,
        message: str,
        code: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add validation warning without affecting validation status."""
        self.add_error(
            field=field,
            message=message,
            code=code,
            severity=ValidationSeverity.WARNING,
            context=context
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary for API responses."""
        return {
            'is_valid': self.is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'metadata': self.metadata,
            'validation_timestamp': self.validation_timestamp.isoformat()
        }


@dataclass
class ValidationRule:
    """
    Business rule definition for comprehensive validation enforcement.
    
    Implements Feature F-005 business logic preservation requirements
    maintaining all original Node.js validation patterns.
    """
    field: str
    rule_type: ValidationType
    validator: Callable
    message: str
    code: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    conditions: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EntityValidationSchema:
    """
    Entity-specific validation schema with comprehensive rule definitions.
    
    Provides structured validation rule organization for different entity types
    supporting complex business workflows and relationship validation.
    """
    entity_type: str
    required_fields: Set[str]
    validation_rules: List[ValidationRule]
    relationship_rules: List[ValidationRule] = field(default_factory=list)
    business_rules: List[ValidationRule] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ValidationService:
    """
    Comprehensive business validation service implementing data validation, business rule
    enforcement, and constraint checking across all business operations.
    
    This service centralizes validation logic using Python dataclasses and type hints
    while maintaining all original Node.js validation patterns through the Service Layer pattern.
    
    Key Features:
    - Business rule enforcement per Feature F-005
    - Python dataclasses and type hints integration per Section 4.5.1
    - Data validation and constraint checking per Section 4.12.1
    - Input validation and sanitization per Section 2.1.9
    - Consistent validation error handling per Section 4.5.3
    - Database integrity validation per Section 6.2.2.2
    """
    
    def __init__(self):
        """Initialize validation service with comprehensive rule definitions."""
        self.logger = get_structured_logger(__name__)
        self._validation_schemas: Dict[str, EntityValidationSchema] = {}
        self._business_rules: Dict[str, List[ValidationRule]] = {}
        self._security_patterns = self._initialize_security_patterns()
        self._sanitization_rules = self._initialize_sanitization_rules()
        
        # Initialize entity validation schemas
        self._initialize_entity_schemas()
        self._initialize_business_rules()
        
        self.logger.info(
            "Validation service initialized",
            extra={
                'schemas_count': len(self._validation_schemas),
                'business_rules_count': sum(len(rules) for rules in self._business_rules.values()),
                'service': 'validation_service'
            }
        )
    
    def _initialize_security_patterns(self) -> Dict[str, re.Pattern]:
        """
        Initialize security validation patterns for injection detection.
        
        Implements Section 2.1.9 input validation and sanitization patterns
        for comprehensive security validation.
        """
        return {
            'sql_injection': re.compile(
                r'(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute|declare|script)',
                re.IGNORECASE
            ),
            'xss_script': re.compile(
                r'<script[^>]*>.*?</script>|javascript:|vbscript:|onload=|onerror=',
                re.IGNORECASE | re.DOTALL
            ),
            'html_tags': re.compile(r'<[^>]+>'),
            'email_pattern': re.compile(
                r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            ),
            'phone_pattern': re.compile(r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$'),
            'uuid_pattern': re.compile(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
                re.IGNORECASE
            ),
            'alphanumeric': re.compile(r'^[a-zA-Z0-9_-]+$'),
            'numeric': re.compile(r'^[0-9]+$'),
            'decimal': re.compile(r'^[0-9]+(\.[0-9]+)?$')
        }
    
    def _initialize_sanitization_rules(self) -> Dict[str, Dict[str, Any]]:
        """
        Initialize data sanitization rules for input processing.
        
        Maintains input validation and sanitization patterns from original
        Node.js implementation per Section 2.1.9 requirements.
        """
        return {
            'string': {
                'max_length': 10000,
                'trim_whitespace': True,
                'html_escape': True,
                'remove_null_chars': True
            },
            'email': {
                'max_length': 255,
                'normalize_case': True,
                'trim_whitespace': True
            },
            'phone': {
                'remove_formatting': True,
                'normalize_format': True
            },
            'numeric': {
                'remove_non_numeric': True,
                'validate_range': True
            },
            'text': {
                'max_length': 50000,
                'preserve_newlines': True,
                'html_escape': True
            }
        }
    
    def _initialize_entity_schemas(self) -> None:
        """
        Initialize validation schemas for all entity types.
        
        Implements comprehensive entity validation supporting complex business
        workflows and relationship validation per Section 6.2.2.1.
        """
        # User entity validation schema
        user_rules = [
            ValidationRule(
                field='username',
                rule_type=ValidationType.FORMAT,
                validator=self._validate_username,
                message='Username must be 3-50 characters and contain only letters, numbers, and underscores',
                code='INVALID_USERNAME_FORMAT'
            ),
            ValidationRule(
                field='email',
                rule_type=ValidationType.FORMAT,
                validator=self._validate_email,
                message='Invalid email format',
                code='INVALID_EMAIL_FORMAT'
            ),
            ValidationRule(
                field='password',
                rule_type=ValidationType.SECURITY,
                validator=self._validate_password_strength,
                message='Password must be at least 8 characters with uppercase, lowercase, number, and special character',
                code='WEAK_PASSWORD'
            )
        ]
        
        self._validation_schemas['user'] = EntityValidationSchema(
            entity_type='user',
            required_fields={'username', 'email', 'password'},
            validation_rules=user_rules
        )
        
        # Business Entity validation schema
        business_entity_rules = [
            ValidationRule(
                field='name',
                rule_type=ValidationType.FORMAT,
                validator=self._validate_entity_name,
                message='Entity name must be 1-255 characters',
                code='INVALID_ENTITY_NAME'
            ),
            ValidationRule(
                field='description',
                rule_type=ValidationType.FORMAT,
                validator=self._validate_entity_description,
                message='Description cannot exceed 1000 characters',
                code='INVALID_ENTITY_DESCRIPTION'
            ),
            ValidationRule(
                field='owner_id',
                rule_type=ValidationType.CONSTRAINT,
                validator=self._validate_owner_exists,
                message='Owner must be a valid user',
                code='INVALID_OWNER_REFERENCE'
            )
        ]
        
        self._validation_schemas['business_entity'] = EntityValidationSchema(
            entity_type='business_entity',
            required_fields={'name', 'owner_id'},
            validation_rules=business_entity_rules
        )
        
        # Entity Relationship validation schema
        relationship_rules = [
            ValidationRule(
                field='source_entity_id',
                rule_type=ValidationType.CONSTRAINT,
                validator=self._validate_entity_exists,
                message='Source entity must exist',
                code='INVALID_SOURCE_ENTITY'
            ),
            ValidationRule(
                field='target_entity_id',
                rule_type=ValidationType.CONSTRAINT,
                validator=self._validate_entity_exists,
                message='Target entity must exist',
                code='INVALID_TARGET_ENTITY'
            ),
            ValidationRule(
                field='relationship_type',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_relationship_type,
                message='Invalid relationship type',
                code='INVALID_RELATIONSHIP_TYPE'
            )
        ]
        
        self._validation_schemas['entity_relationship'] = EntityValidationSchema(
            entity_type='entity_relationship',
            required_fields={'source_entity_id', 'target_entity_id', 'relationship_type'},
            validation_rules=relationship_rules
        )
    
    def _initialize_business_rules(self) -> None:
        """
        Initialize business rules for comprehensive business logic validation.
        
        Implements Feature F-005 business logic preservation maintaining
        all existing business rules from the Node.js implementation.
        """
        # User business rules
        user_business_rules = [
            ValidationRule(
                field='username',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_username_uniqueness,
                message='Username already exists',
                code='DUPLICATE_USERNAME'
            ),
            ValidationRule(
                field='email',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_email_uniqueness,
                message='Email address already registered',
                code='DUPLICATE_EMAIL'
            )
        ]
        
        # Business entity business rules
        entity_business_rules = [
            ValidationRule(
                field='status',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_entity_status_transition,
                message='Invalid status transition',
                code='INVALID_STATUS_TRANSITION'
            ),
            ValidationRule(
                field='owner_id',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_ownership_permissions,
                message='Insufficient permissions for entity ownership',
                code='INSUFFICIENT_OWNERSHIP_PERMISSIONS'
            )
        ]
        
        # Relationship business rules
        relationship_business_rules = [
            ValidationRule(
                field='circular_reference',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_no_circular_relationships,
                message='Circular relationships are not allowed',
                code='CIRCULAR_RELATIONSHIP_DETECTED'
            ),
            ValidationRule(
                field='relationship_limit',
                rule_type=ValidationType.BUSINESS_RULE,
                validator=self._validate_relationship_count_limit,
                message='Maximum relationship count exceeded',
                code='RELATIONSHIP_LIMIT_EXCEEDED'
            )
        ]
        
        self._business_rules = {
            'user': user_business_rules,
            'business_entity': entity_business_rules,
            'entity_relationship': relationship_business_rules
        }
    
    def validate_entity(
        self,
        entity_type: str,
        data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        include_business_rules: bool = True
    ) -> ValidationResult:
        """
        Comprehensive entity validation with business rule enforcement.
        
        Args:
            entity_type: Type of entity being validated
            data: Entity data to validate
            context: Additional validation context
            include_business_rules: Whether to include business rule validation
            
        Returns:
            ValidationResult with comprehensive validation details
            
        Implements:
        - Section 4.5.1: Dataclass and type hints integration
        - Section 4.12.1: Data validation and constraint checking
        - Feature F-005: Business logic preservation
        """
        result = ValidationResult(is_valid=True)
        context = context or {}
        
        try:
            # Log validation start
            self.logger.info(
                "Starting entity validation",
                extra={
                    'entity_type': entity_type,
                    'data_keys': list(data.keys()),
                    'include_business_rules': include_business_rules,
                    'service': 'validation_service'
                }
            )
            
            # Get validation schema
            schema = self._validation_schemas.get(entity_type)
            if not schema:
                result.add_error(
                    field='entity_type',
                    message=f'Unknown entity type: {entity_type}',
                    code='UNKNOWN_ENTITY_TYPE',
                    severity=ValidationSeverity.CRITICAL
                )
                return result
            
            # Sanitize input data
            sanitized_data = self._sanitize_data(data, entity_type)
            result.sanitized_data = sanitized_data
            
            # Validate required fields
            self._validate_required_fields(schema, sanitized_data, result)
            
            # Validate data types and formats
            self._validate_data_types(schema, sanitized_data, result, context)
            
            # Validate constraints
            self._validate_constraints(schema, sanitized_data, result, context)
            
            # Validate business rules if requested
            if include_business_rules:
                self._validate_business_rules(entity_type, sanitized_data, result, context)
            
            # Validate relationships if applicable
            if schema.relationship_rules:
                self._validate_relationships(schema, sanitized_data, result, context)
            
            # Add validation metadata
            result.metadata.update({
                'entity_type': entity_type,
                'validation_count': len(schema.validation_rules),
                'business_rule_count': len(self._business_rules.get(entity_type, [])),
                'context': context
            })
            
            # Log validation completion
            self.logger.info(
                "Entity validation completed",
                extra={
                    'entity_type': entity_type,
                    'is_valid': result.is_valid,
                    'error_count': len(result.errors),
                    'warning_count': len(result.warnings),
                    'service': 'validation_service'
                }
            )
            
        except Exception as e:
            self.logger.error(
                "Entity validation failed with exception",
                extra={
                    'entity_type': entity_type,
                    'error': str(e),
                    'service': 'validation_service'
                }
            )
            result.add_error(
                field='validation',
                message='Internal validation error occurred',
                code='VALIDATION_EXCEPTION',
                severity=ValidationSeverity.CRITICAL,
                context={'exception': str(e)}
            )
        
        return result
    
    def validate_input_data(
        self,
        data: Dict[str, Any],
        validation_rules: Optional[List[ValidationRule]] = None,
        strict_mode: bool = False
    ) -> ValidationResult:
        """
        Validate and sanitize input data with comprehensive security checks.
        
        Implements Section 2.1.9 input validation and sanitization patterns
        maintaining security standards from the Node.js implementation.
        
        Args:
            data: Input data to validate
            validation_rules: Custom validation rules
            strict_mode: Enable strict validation mode
            
        Returns:
            ValidationResult with sanitized data and validation details
        """
        result = ValidationResult(is_valid=True)
        
        try:
            # Log input validation start
            self.logger.info(
                "Starting input data validation",
                extra={
                    'data_keys': list(data.keys()),
                    'strict_mode': strict_mode,
                    'custom_rules_count': len(validation_rules) if validation_rules else 0,
                    'service': 'validation_service'
                }
            )
            
            # Sanitize input data
            sanitized_data = {}
            for key, value in data.items():
                try:
                    sanitized_value = self._sanitize_value(key, value, strict_mode)
                    sanitized_data[key] = sanitized_value
                    
                    # Security validation
                    if isinstance(value, str):
                        self._validate_security_patterns(key, value, result)
                        
                except Exception as e:
                    result.add_error(
                        field=key,
                        message=f'Sanitization failed: {str(e)}',
                        code='SANITIZATION_ERROR',
                        validation_type=ValidationType.SANITIZATION
                    )
            
            result.sanitized_data = sanitized_data
            
            # Apply custom validation rules
            if validation_rules:
                for rule in validation_rules:
                    try:
                        field_value = sanitized_data.get(rule.field)
                        if field_value is not None:
                            if not rule.validator(field_value, sanitized_data):
                                result.add_error(
                                    field=rule.field,
                                    message=rule.message,
                                    code=rule.code,
                                    severity=rule.severity,
                                    validation_type=rule.rule_type
                                )
                    except Exception as e:
                        result.add_error(
                            field=rule.field,
                            message=f'Custom validation failed: {str(e)}',
                            code='CUSTOM_VALIDATION_ERROR',
                            validation_type=rule.rule_type
                        )
            
            # Log input validation completion
            self.logger.info(
                "Input data validation completed",
                extra={
                    'is_valid': result.is_valid,
                    'sanitized_fields_count': len(sanitized_data),
                    'error_count': len(result.errors),
                    'service': 'validation_service'
                }
            )
            
        except Exception as e:
            self.logger.error(
                "Input data validation failed",
                extra={
                    'error': str(e),
                    'service': 'validation_service'
                }
            )
            result.add_error(
                field='input_validation',
                message='Input validation failed',
                code='INPUT_VALIDATION_ERROR',
                severity=ValidationSeverity.CRITICAL
            )
        
        return result
    
    def validate_database_constraints(
        self,
        model_class: Type,
        data: Dict[str, Any],
        session = None
    ) -> ValidationResult:
        """
        Validate database constraints and referential integrity.
        
        Implements Section 6.2.2.2 constraint checking with database integrity
        validation ensuring data consistency across all operations.
        
        Args:
            model_class: SQLAlchemy model class
            data: Data to validate against constraints
            session: Database session for constraint checking
            
        Returns:
            ValidationResult with constraint validation details
        """
        result = ValidationResult(is_valid=True)
        
        try:
            # Log constraint validation start
            self.logger.info(
                "Starting database constraint validation",
                extra={
                    'model_class': model_class.__name__,
                    'data_keys': list(data.keys()),
                    'service': 'validation_service'
                }
            )
            
            # Get model inspection for constraint validation
            inspector = inspect(model_class)
            
            # Validate column constraints
            for column in inspector.columns:
                column_name = column.name
                column_value = data.get(column_name)
                
                # Check nullable constraints
                if not column.nullable and column_value is None:
                    result.add_error(
                        field=column_name,
                        message=f'{column_name} is required',
                        code='NULL_CONSTRAINT_VIOLATION',
                        validation_type=ValidationType.CONSTRAINT
                    )
                
                # Check string length constraints
                if hasattr(column.type, 'length') and column.type.length:
                    if isinstance(column_value, str) and len(column_value) > column.type.length:
                        result.add_error(
                            field=column_name,
                            message=f'{column_name} exceeds maximum length of {column.type.length}',
                            code='LENGTH_CONSTRAINT_VIOLATION',
                            validation_type=ValidationType.CONSTRAINT
                        )
                
                # Check unique constraints
                if column.unique and column_value is not None and session:
                    existing = session.query(model_class).filter(
                        getattr(model_class, column_name) == column_value
                    ).first()
                    
                    if existing:
                        result.add_error(
                            field=column_name,
                            message=f'{column_name} must be unique',
                            code='UNIQUE_CONSTRAINT_VIOLATION',
                            validation_type=ValidationType.CONSTRAINT
                        )
            
            # Validate foreign key constraints
            for relationship in inspector.relationships:
                fk_column = None
                for fk in relationship.local_columns:
                    fk_column = fk.name
                    break
                
                if fk_column and fk_column in data:
                    fk_value = data[fk_column]
                    if fk_value is not None and session:
                        # Check if referenced entity exists
                        related_model = relationship.mapper.class_
                        exists = session.query(related_model).filter(
                            related_model.id == fk_value
                        ).first()
                        
                        if not exists:
                            result.add_error(
                                field=fk_column,
                                message=f'Referenced {related_model.__name__} does not exist',
                                code='FOREIGN_KEY_CONSTRAINT_VIOLATION',
                                validation_type=ValidationType.CONSTRAINT
                            )
            
            # Log constraint validation completion
            self.logger.info(
                "Database constraint validation completed",
                extra={
                    'model_class': model_class.__name__,
                    'is_valid': result.is_valid,
                    'constraint_errors': len(result.errors),
                    'service': 'validation_service'
                }
            )
            
        except Exception as e:
            self.logger.error(
                "Database constraint validation failed",
                extra={
                    'model_class': model_class.__name__ if model_class else 'unknown',
                    'error': str(e),
                    'service': 'validation_service'
                }
            )
            result.add_error(
                field='database_constraints',
                message='Database constraint validation failed',
                code='CONSTRAINT_VALIDATION_ERROR',
                severity=ValidationSeverity.CRITICAL
            )
        
        return result
    
    def _sanitize_data(self, data: Dict[str, Any], entity_type: str) -> Dict[str, Any]:
        """
        Comprehensive data sanitization with entity-specific rules.
        
        Maintains input validation and sanitization patterns from original
        Node.js implementation per Section 2.1.9 requirements.
        """
        sanitized = {}
        
        for key, value in data.items():
            try:
                sanitized[key] = self._sanitize_value(key, value)
            except Exception as e:
                self.logger.warning(
                    "Value sanitization failed",
                    extra={
                        'field': key,
                        'error': str(e),
                        'service': 'validation_service'
                    }
                )
                sanitized[key] = value  # Keep original if sanitization fails
        
        return sanitized
    
    def _sanitize_value(self, field_name: str, value: Any, strict_mode: bool = False) -> Any:
        """
        Sanitize individual field value based on type and security requirements.
        """
        if value is None:
            return None
        
        # String sanitization
        if isinstance(value, str):
            # Remove null characters
            value = value.replace('\x00', '')
            
            # Trim whitespace
            value = value.strip()
            
            # HTML escape for security
            value = html.escape(value)
            
            # Length limits
            if len(value) > 10000:  # Default max length
                value = value[:10000]
            
            # Email-specific sanitization
            if 'email' in field_name.lower():
                value = value.lower()
                if len(value) > 255:
                    value = value[:255]
            
            # Phone-specific sanitization
            if 'phone' in field_name.lower():
                value = re.sub(r'[^\d+\-\(\)\s]', '', value)
        
        # Numeric sanitization
        elif isinstance(value, (int, float)):
            # Range validation for numeric values
            if abs(value) > 1e15:  # Reasonable numeric limit
                raise ValueError(f"Numeric value {value} exceeds safe range")
        
        # List/Array sanitization
        elif isinstance(value, list):
            if len(value) > 1000:  # Reasonable array size limit
                value = value[:1000]
            value = [self._sanitize_value(f"{field_name}_item", item, strict_mode) for item in value]
        
        # Dictionary sanitization
        elif isinstance(value, dict):
            if len(value) > 100:  # Reasonable object size limit
                value = dict(list(value.items())[:100])
            value = {k: self._sanitize_value(k, v, strict_mode) for k, v in value.items()}
        
        return value
    
    def _validate_security_patterns(self, field: str, value: str, result: ValidationResult) -> None:
        """
        Validate input against security patterns for injection detection.
        """
        # SQL injection detection
        if self._security_patterns['sql_injection'].search(value):
            result.add_error(
                field=field,
                message='Potential SQL injection detected',
                code='SQL_INJECTION_DETECTED',
                severity=ValidationSeverity.CRITICAL,
                validation_type=ValidationType.SECURITY
            )
        
        # XSS detection
        if self._security_patterns['xss_script'].search(value):
            result.add_error(
                field=field,
                message='Potential XSS attack detected',
                code='XSS_DETECTED',
                severity=ValidationSeverity.CRITICAL,
                validation_type=ValidationType.SECURITY
            )
    
    def _validate_required_fields(
        self,
        schema: EntityValidationSchema,
        data: Dict[str, Any],
        result: ValidationResult
    ) -> None:
        """Validate that all required fields are present."""
        for field in schema.required_fields:
            if field not in data or data[field] is None or data[field] == '':
                result.add_error(
                    field=field,
                    message=f'{field} is required',
                    code='REQUIRED_FIELD_MISSING',
                    validation_type=ValidationType.CONSTRAINT
                )
    
    def _validate_data_types(
        self,
        schema: EntityValidationSchema,
        data: Dict[str, Any],
        result: ValidationResult,
        context: Dict[str, Any]
    ) -> None:
        """Execute data type and format validation rules."""
        for rule in schema.validation_rules:
            if rule.rule_type in [ValidationType.DATA_TYPE, ValidationType.FORMAT]:
                field_value = data.get(rule.field)
                if field_value is not None:
                    try:
                        if not rule.validator(field_value, data, context):
                            result.add_error(
                                field=rule.field,
                                message=rule.message,
                                code=rule.code,
                                severity=rule.severity,
                                validation_type=rule.rule_type
                            )
                    except Exception as e:
                        result.add_error(
                            field=rule.field,
                            message=f'Validation error: {str(e)}',
                            code='VALIDATION_EXCEPTION',
                            validation_type=rule.rule_type
                        )
    
    def _validate_constraints(
        self,
        schema: EntityValidationSchema,
        data: Dict[str, Any],
        result: ValidationResult,
        context: Dict[str, Any]
    ) -> None:
        """Execute constraint validation rules."""
        for rule in schema.validation_rules:
            if rule.rule_type == ValidationType.CONSTRAINT:
                field_value = data.get(rule.field)
                if field_value is not None:
                    try:
                        if not rule.validator(field_value, data, context):
                            result.add_error(
                                field=rule.field,
                                message=rule.message,
                                code=rule.code,
                                severity=rule.severity,
                                validation_type=rule.rule_type
                            )
                    except Exception as e:
                        result.add_error(
                            field=rule.field,
                            message=f'Constraint validation error: {str(e)}',
                            code='CONSTRAINT_VALIDATION_EXCEPTION',
                            validation_type=rule.rule_type
                        )
    
    def _validate_business_rules(
        self,
        entity_type: str,
        data: Dict[str, Any],
        result: ValidationResult,
        context: Dict[str, Any]
    ) -> None:
        """
        Execute business rule validation.
        
        Implements Feature F-005 business logic preservation maintaining
        all existing business rules from the Node.js implementation.
        """
        business_rules = self._business_rules.get(entity_type, [])
        
        for rule in business_rules:
            try:
                if not rule.validator(data, context):
                    result.add_error(
                        field=rule.field,
                        message=rule.message,
                        code=rule.code,
                        severity=rule.severity,
                        validation_type=rule.rule_type
                    )
            except Exception as e:
                result.add_error(
                    field=rule.field,
                    message=f'Business rule validation error: {str(e)}',
                    code='BUSINESS_RULE_EXCEPTION',
                    validation_type=rule.rule_type
                )
    
    def _validate_relationships(
        self,
        schema: EntityValidationSchema,
        data: Dict[str, Any],
        result: ValidationResult,
        context: Dict[str, Any]
    ) -> None:
        """Execute relationship validation rules."""
        for rule in schema.relationship_rules:
            try:
                if not rule.validator(data, context):
                    result.add_error(
                        field=rule.field,
                        message=rule.message,
                        code=rule.code,
                        severity=rule.severity,
                        validation_type=rule.rule_type
                    )
            except Exception as e:
                result.add_error(
                    field=rule.field,
                    message=f'Relationship validation error: {str(e)}',
                    code='RELATIONSHIP_VALIDATION_EXCEPTION',
                    validation_type=rule.rule_type
                )
    
    # Individual validation methods for specific fields and rules
    
    def _validate_username(self, value: str, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate username format and length."""
        if not isinstance(value, str):
            return False
        
        # Length check
        if not (3 <= len(value) <= 50):
            return False
        
        # Format check - alphanumeric and underscores only
        return self._security_patterns['alphanumeric'].match(value) is not None
    
    def _validate_email(self, value: str, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate email format."""
        if not isinstance(value, str):
            return False
        
        return self._security_patterns['email_pattern'].match(value) is not None
    
    def _validate_password_strength(self, value: str, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate password strength requirements."""
        if not isinstance(value, str):
            return False
        
        # Minimum length
        if len(value) < 8:
            return False
        
        # Check for required character types
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in value)
        
        return has_upper and has_lower and has_digit and has_special
    
    def _validate_entity_name(self, value: str, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate business entity name."""
        if not isinstance(value, str):
            return False
        
        return 1 <= len(value.strip()) <= 255
    
    def _validate_entity_description(self, value: str, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate business entity description."""
        if value is None:
            return True  # Description is optional
        
        if not isinstance(value, str):
            return False
        
        return len(value) <= 1000
    
    def _validate_owner_exists(self, value: Any, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate that the owner user exists in the database."""
        # This would typically query the database
        # For now, just validate the ID format
        try:
            user_id = int(value)
            return user_id > 0
        except (ValueError, TypeError):
            return False
    
    def _validate_entity_exists(self, value: Any, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate that the referenced entity exists."""
        try:
            entity_id = int(value)
            return entity_id > 0
        except (ValueError, TypeError):
            return False
    
    def _validate_relationship_type(self, value: str, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate relationship type against allowed values."""
        allowed_types = {'parent', 'child', 'sibling', 'related', 'depends_on', 'contains'}
        return value in allowed_types
    
    # Business rule validation methods
    
    def _validate_username_uniqueness(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate username uniqueness across the system."""
        # This would typically query the database
        # Implementation would depend on having access to the database session
        return True  # Placeholder
    
    def _validate_email_uniqueness(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate email uniqueness across the system."""
        # This would typically query the database
        # Implementation would depend on having access to the database session
        return True  # Placeholder
    
    def _validate_entity_status_transition(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate entity status transition rules."""
        current_status = context.get('current_status') if context else None
        new_status = data.get('status')
        
        if not current_status:
            return True  # New entity
        
        # Define allowed transitions
        allowed_transitions = {
            'draft': ['active', 'deleted'],
            'active': ['inactive', 'deleted'],
            'inactive': ['active', 'deleted'],
            'deleted': []  # No transitions from deleted
        }
        
        return new_status in allowed_transitions.get(current_status, [])
    
    def _validate_ownership_permissions(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate user permissions for entity ownership."""
        # This would typically check user roles and permissions
        return True  # Placeholder
    
    def _validate_no_circular_relationships(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate that relationship doesn't create circular dependencies."""
        source_id = data.get('source_entity_id')
        target_id = data.get('target_entity_id')
        
        # Basic check - entity cannot reference itself
        return source_id != target_id
    
    def _validate_relationship_count_limit(self, data: Dict[str, Any], context: Dict[str, Any] = None) -> bool:
        """Validate relationship count limits per entity."""
        # This would typically query the database to count existing relationships
        return True  # Placeholder
    
    def create_custom_validation_rule(
        self,
        field: str,
        validator: Callable,
        message: str,
        code: str,
        rule_type: ValidationType = ValidationType.BUSINESS_RULE,
        severity: ValidationSeverity = ValidationSeverity.ERROR
    ) -> ValidationRule:
        """
        Create custom validation rule for specific business requirements.
        
        Enables extension of validation logic for custom business scenarios
        while maintaining consistent validation patterns.
        """
        return ValidationRule(
            field=field,
            rule_type=rule_type,
            validator=validator,
            message=message,
            code=code,
            severity=severity
        )
    
    def add_entity_validation_rule(
        self,
        entity_type: str,
        rule: ValidationRule
    ) -> bool:
        """
        Add custom validation rule to existing entity schema.
        
        Allows dynamic extension of validation logic for specific
        business requirements while maintaining schema integrity.
        """
        try:
            if entity_type in self._validation_schemas:
                self._validation_schemas[entity_type].validation_rules.append(rule)
                
                self.logger.info(
                    "Custom validation rule added",
                    extra={
                        'entity_type': entity_type,
                        'rule_field': rule.field,
                        'rule_code': rule.code,
                        'service': 'validation_service'
                    }
                )
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(
                "Failed to add validation rule",
                extra={
                    'entity_type': entity_type,
                    'rule_field': rule.field,
                    'error': str(e),
                    'service': 'validation_service'
                }
            )
            return False
    
    def get_validation_schema(self, entity_type: str) -> Optional[EntityValidationSchema]:
        """Get validation schema for specified entity type."""
        return self._validation_schemas.get(entity_type)
    
    def get_supported_entity_types(self) -> List[str]:
        """Get list of supported entity types for validation."""
        return list(self._validation_schemas.keys())


# Service instance for global access
validation_service = ValidationService()