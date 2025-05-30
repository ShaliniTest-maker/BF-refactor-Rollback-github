"""
Validation Service

Input validation service implementing comprehensive data validation, business rule 
enforcement, and error handling. This service converts Node.js middleware validation 
patterns to Flask Service Layer architecture with type-safe validation logic and 
standardized error responses.

This module provides:
- Comprehensive data validation with Python type hints
- Business rule enforcement maintaining existing validation patterns
- Type-safe validation interfaces with standardized error responses
- Service Layer pattern integration for modular validation
- Enhanced testability through Pytest fixture compatibility

Author: Flask Migration Team
Created: 2024
Version: 1.0.0
"""

from typing import (
    Dict, List, Any, Optional, Union, Callable, Protocol, TypeVar, Generic,
    Tuple, Set, Type, cast
)
from dataclasses import dataclass, field
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
import re
import logging
from enum import Enum

# Import Flask-specific modules
from flask import current_app
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

# Type definitions for enhanced type safety
ValidatorFunction = Callable[[Any], Tuple[bool, Optional[str]]]
ValidationRules = Dict[str, List[ValidatorFunction]]
ErrorCode = str
FieldName = str

# Configure logging for validation service
logger = logging.getLogger(__name__)


class ValidationSeverity(Enum):
    """Enumeration for validation message severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class BusinessRuleType(Enum):
    """Enumeration for business rule classification."""
    DATA_INTEGRITY = "data_integrity"
    BUSINESS_LOGIC = "business_logic"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    PERFORMANCE = "performance"


@dataclass
class ValidationMessage:
    """
    Standardized validation message with severity and context.
    
    Provides comprehensive error reporting with field-level context,
    error codes for programmatic handling, and severity classification.
    """
    field: FieldName
    message: str
    severity: ValidationSeverity
    error_code: Optional[ErrorCode] = None
    context: Optional[Dict[str, Any]] = None
    rule_type: Optional[BusinessRuleType] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation message to dictionary format for API responses."""
        result = {
            'field': self.field,
            'message': self.message,
            'severity': self.severity.value
        }
        
        if self.error_code:
            result['error_code'] = self.error_code
        if self.context:
            result['context'] = self.context
        if self.rule_type:
            result['rule_type'] = self.rule_type.value
            
        return result


@dataclass
class ValidationResult:
    """
    Type-safe validation result object with comprehensive reporting.
    
    Provides standardized validation results with error categorization,
    warning reporting, and success status for consistent API responses.
    """
    is_valid: bool
    errors: List[ValidationMessage] = field(default_factory=list)
    warnings: List[ValidationMessage] = field(default_factory=list)
    info: List[ValidationMessage] = field(default_factory=list)
    validated_data: Optional[Dict[str, Any]] = None
    
    def add_error(
        self, 
        field: FieldName, 
        message: str, 
        error_code: Optional[ErrorCode] = None,
        context: Optional[Dict[str, Any]] = None,
        rule_type: Optional[BusinessRuleType] = None
    ) -> None:
        """Add validation error with comprehensive context."""
        self.errors.append(ValidationMessage(
            field=field,
            message=message,
            severity=ValidationSeverity.ERROR,
            error_code=error_code,
            context=context,
            rule_type=rule_type
        ))
        self.is_valid = False
    
    def add_warning(
        self, 
        field: FieldName, 
        message: str, 
        error_code: Optional[ErrorCode] = None,
        context: Optional[Dict[str, Any]] = None,
        rule_type: Optional[BusinessRuleType] = None
    ) -> None:
        """Add validation warning with context."""
        self.warnings.append(ValidationMessage(
            field=field,
            message=message,
            severity=ValidationSeverity.WARNING,
            error_code=error_code,
            context=context,
            rule_type=rule_type
        ))
    
    def add_info(
        self, 
        field: FieldName, 
        message: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Add informational validation message."""
        self.info.append(ValidationMessage(
            field=field,
            message=message,
            severity=ValidationSeverity.INFO,
            context=context
        ))
    
    def has_errors(self) -> bool:
        """Check if validation result contains errors."""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Check if validation result contains warnings."""
        return len(self.warnings) > 0
    
    def get_error_count(self) -> int:
        """Get total number of validation errors."""
        return len(self.errors)
    
    def get_warning_count(self) -> int:
        """Get total number of validation warnings."""
        return len(self.warnings)
    
    def get_all_messages(self) -> List[ValidationMessage]:
        """Get all validation messages regardless of severity."""
        return self.errors + self.warnings + self.info
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary format for API responses."""
        return {
            'is_valid': self.is_valid,
            'errors': [error.to_dict() for error in self.errors],
            'warnings': [warning.to_dict() for warning in self.warnings],
            'info': [info.to_dict() for info in self.info],
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
            'validated_data': self.validated_data
        }


class DatabaseSession(Protocol):
    """Protocol definition for database session dependency injection."""
    def add(self, instance: Any) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def query(self, *args: Any) -> Any: ...
    def close(self) -> None: ...


class BaseService:
    """
    Base service class providing dependency injection framework and common functionality.
    
    Implements the Service Layer pattern with SQLAlchemy session management
    and standardized service initialization for Flask application integration.
    """
    
    def __init__(self, db_session: Optional[Session] = None) -> None:
        """
        Initialize base service with dependency injection.
        
        Args:
            db_session: SQLAlchemy session for database operations
        """
        self.db_session = db_session
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def _log_operation(self, operation: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Log service operations for debugging and monitoring."""
        log_data = {'operation': operation, 'service': self.__class__.__name__}
        if details:
            log_data.update(details)
        self.logger.info(f"Service operation: {operation}", extra=log_data)


class ValidationService(BaseService):
    """
    Comprehensive validation service implementing Flask Service Layer pattern.
    
    Provides type-safe data validation, business rule enforcement, and standardized
    error handling. Converts Node.js middleware validation patterns to Python
    service-oriented architecture while maintaining functional equivalence.
    """
    
    def __init__(self, db_session: Optional[Session] = None) -> None:
        """
        Initialize validation service with dependency injection.
        
        Args:
            db_session: SQLAlchemy session for database validation operations
        """
        super().__init__(db_session)
        self._built_in_validators = self._initialize_built_in_validators()
        self._business_rules = self._initialize_business_rules()
        self._field_patterns = self._initialize_field_patterns()
    
    def _initialize_built_in_validators(self) -> Dict[str, ValidatorFunction]:
        """Initialize built-in validation functions maintaining Node.js equivalence."""
        return {
            'required': self._validate_required,
            'email': self._validate_email,
            'phone': self._validate_phone,
            'url': self._validate_url,
            'numeric': self._validate_numeric,
            'integer': self._validate_integer,
            'decimal': self._validate_decimal,
            'date': self._validate_date,
            'datetime': self._validate_datetime,
            'boolean': self._validate_boolean,
            'string': self._validate_string,
            'min_length': self._validate_min_length,
            'max_length': self._validate_max_length,
            'pattern': self._validate_pattern,
            'enum': self._validate_enum,
            'range': self._validate_range,
            'positive': self._validate_positive,
            'negative': self._validate_negative,
            'alphanumeric': self._validate_alphanumeric,
            'alpha': self._validate_alpha,
            'unique': self._validate_unique,
            'exists': self._validate_exists
        }
    
    def _initialize_business_rules(self) -> Dict[str, ValidatorFunction]:
        """Initialize business rule validators maintaining existing validation patterns."""
        return {
            'user_email_unique': self._validate_user_email_unique,
            'username_unique': self._validate_username_unique,
            'password_strength': self._validate_password_strength,
            'role_permissions': self._validate_role_permissions,
            'business_entity_owner': self._validate_business_entity_owner,
            'audit_trail_integrity': self._validate_audit_trail_integrity,
            'session_validity': self._validate_session_validity,
            'user_active_status': self._validate_user_active_status,
            'permission_hierarchy': self._validate_permission_hierarchy,
            'data_consistency': self._validate_data_consistency
        }
    
    def _initialize_field_patterns(self) -> Dict[str, str]:
        """Initialize regex patterns for field validation."""
        return {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'phone': r'^\+?1?[-.\s]?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}$',
            'url': r'^https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:\#(?:[\w.])*)?)?$',
            'alphanumeric': r'^[a-zA-Z0-9]+$',
            'alpha': r'^[a-zA-Z]+$',
            'username': r'^[a-zA-Z0-9_]{3,30}$',
            'auth0_user_id': r'^(auth0|google-oauth2|facebook|twitter|github|linkedin)\|[a-zA-Z0-9]+$'
        }
    
    # Core validation interface methods
    
    def validate_data(
        self, 
        data: Dict[str, Any], 
        rules: ValidationRules,
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate data against comprehensive validation rules.
        
        Args:
            data: Dictionary of field values to validate
            rules: Dictionary mapping field names to lists of validator functions
            context: Optional validation context for business rules
            
        Returns:
            ValidationResult with comprehensive validation status and messages
        """
        self._log_operation('validate_data', {
            'fields': list(data.keys()),
            'rule_count': sum(len(validators) for validators in rules.values())
        })
        
        result = ValidationResult(is_valid=True)
        validated_data = {}
        
        try:
            # Validate each field against its rules
            for field_name, validators in rules.items():
                field_value = data.get(field_name)
                
                # Apply all validators for this field
                field_valid = True
                for validator in validators:
                    try:
                        is_valid, error_message = validator(field_value)
                        if not is_valid:
                            result.add_error(
                                field=field_name,
                                message=error_message or f"Validation failed for field {field_name}",
                                error_code=f"VALIDATION_{field_name.upper()}_FAILED",
                                rule_type=BusinessRuleType.DATA_INTEGRITY
                            )
                            field_valid = False
                    except Exception as e:
                        self.logger.error(f"Validator error for field {field_name}: {str(e)}")
                        result.add_error(
                            field=field_name,
                            message=f"Internal validation error: {str(e)}",
                            error_code="VALIDATION_INTERNAL_ERROR",
                            rule_type=BusinessRuleType.DATA_INTEGRITY
                        )
                        field_valid = False
                
                # Add valid data to validated result
                if field_valid:
                    validated_data[field_name] = field_value
            
            # Apply business rules if context is provided
            if context and not result.has_errors():
                self._apply_business_rules(data, result, context)
            
            # Set validated data if validation succeeded
            if result.is_valid:
                result.validated_data = validated_data
                
        except Exception as e:
            self.logger.error(f"Data validation error: {str(e)}")
            result.add_error(
                field="__global__",
                message=f"Validation system error: {str(e)}",
                error_code="VALIDATION_SYSTEM_ERROR",
                rule_type=BusinessRuleType.DATA_INTEGRITY
            )
        
        return result
    
    def validate_request_data(
        self, 
        request_data: Dict[str, Any], 
        schema: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate Flask request data against schema definition.
        
        Args:
            request_data: Request data from Flask request
            schema: Schema definition with field requirements and validators
            context: Optional validation context
            
        Returns:
            ValidationResult with validation status and processed data
        """
        self._log_operation('validate_request_data', {
            'schema_fields': list(schema.keys()),
            'data_fields': list(request_data.keys())
        })
        
        # Convert schema to validation rules
        rules = self._convert_schema_to_rules(schema)
        
        # Validate data against rules
        return self.validate_data(request_data, rules, context)
    
    def validate_business_rules(
        self, 
        data: Dict[str, Any], 
        rule_names: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate data against specific business rules.
        
        Args:
            data: Data to validate
            rule_names: List of business rule names to apply
            context: Optional validation context
            
        Returns:
            ValidationResult with business rule validation status
        """
        self._log_operation('validate_business_rules', {
            'rules': rule_names,
            'data_fields': list(data.keys())
        })
        
        result = ValidationResult(is_valid=True)
        
        try:
            for rule_name in rule_names:
                if rule_name in self._business_rules:
                    validator = self._business_rules[rule_name]
                    is_valid, error_message = validator(data)
                    
                    if not is_valid:
                        result.add_error(
                            field=rule_name,
                            message=error_message or f"Business rule {rule_name} validation failed",
                            error_code=f"BUSINESS_RULE_{rule_name.upper()}_FAILED",
                            rule_type=BusinessRuleType.BUSINESS_LOGIC
                        )
                else:
                    result.add_warning(
                        field=rule_name,
                        message=f"Unknown business rule: {rule_name}",
                        error_code="UNKNOWN_BUSINESS_RULE"
                    )
        
        except Exception as e:
            self.logger.error(f"Business rule validation error: {str(e)}")
            result.add_error(
                field="__global__",
                message=f"Business rule validation system error: {str(e)}",
                error_code="BUSINESS_RULE_SYSTEM_ERROR",
                rule_type=BusinessRuleType.BUSINESS_LOGIC
            )
        
        return result
    
    # Built-in validator implementations
    
    def _validate_required(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate that a value is present and not empty."""
        if value is None:
            return False, "Field is required"
        
        if isinstance(value, str) and not value.strip():
            return False, "Field cannot be empty"
        
        if isinstance(value, (list, dict)) and len(value) == 0:
            return False, "Field cannot be empty"
        
        return True, None
    
    def _validate_email(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate email format using regex pattern."""
        if value is None:
            return True, None  # Optional field
        
        if not isinstance(value, str):
            return False, "Email must be a string"
        
        pattern = self._field_patterns['email']
        if not re.match(pattern, value):
            return False, "Invalid email format"
        
        return True, None
    
    def _validate_phone(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate phone number format."""
        if value is None:
            return True, None  # Optional field
        
        if not isinstance(value, str):
            return False, "Phone number must be a string"
        
        pattern = self._field_patterns['phone']
        if not re.match(pattern, value):
            return False, "Invalid phone number format"
        
        return True, None
    
    def _validate_url(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate URL format."""
        if value is None:
            return True, None  # Optional field
        
        if not isinstance(value, str):
            return False, "URL must be a string"
        
        pattern = self._field_patterns['url']
        if not re.match(pattern, value):
            return False, "Invalid URL format"
        
        return True, None
    
    def _validate_numeric(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate numeric value."""
        if value is None:
            return True, None  # Optional field
        
        try:
            float(value)
            return True, None
        except (ValueError, TypeError):
            return False, "Value must be numeric"
    
    def _validate_integer(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate integer value."""
        if value is None:
            return True, None  # Optional field
        
        try:
            int(value)
            return True, None
        except (ValueError, TypeError):
            return False, "Value must be an integer"
    
    def _validate_decimal(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate decimal value with proper precision."""
        if value is None:
            return True, None  # Optional field
        
        try:
            Decimal(str(value))
            return True, None
        except (InvalidOperation, TypeError):
            return False, "Value must be a valid decimal"
    
    def _validate_date(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate date format."""
        if value is None:
            return True, None  # Optional field
        
        if isinstance(value, date):
            return True, None
        
        if isinstance(value, str):
            try:
                datetime.strptime(value, '%Y-%m-%d')
                return True, None
            except ValueError:
                return False, "Invalid date format. Expected YYYY-MM-DD"
        
        return False, "Date must be a string in YYYY-MM-DD format or date object"
    
    def _validate_datetime(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate datetime format."""
        if value is None:
            return True, None  # Optional field
        
        if isinstance(value, datetime):
            return True, None
        
        if isinstance(value, str):
            try:
                datetime.fromisoformat(value.replace('Z', '+00:00'))
                return True, None
            except ValueError:
                return False, "Invalid datetime format. Expected ISO format"
        
        return False, "Datetime must be ISO format string or datetime object"
    
    def _validate_boolean(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate boolean value."""
        if value is None:
            return True, None  # Optional field
        
        if isinstance(value, bool):
            return True, None
        
        if isinstance(value, str) and value.lower() in ['true', 'false', '1', '0']:
            return True, None
        
        return False, "Value must be boolean or boolean string"
    
    def _validate_string(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate string value."""
        if value is None:
            return True, None  # Optional field
        
        if not isinstance(value, str):
            return False, "Value must be a string"
        
        return True, None
    
    def _validate_min_length(self, min_length: int) -> ValidatorFunction:
        """Create minimum length validator."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            if not isinstance(value, str):
                return False, "Value must be a string"
            
            if len(value) < min_length:
                return False, f"Value must be at least {min_length} characters long"
            
            return True, None
        
        return validator
    
    def _validate_max_length(self, max_length: int) -> ValidatorFunction:
        """Create maximum length validator."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            if not isinstance(value, str):
                return False, "Value must be a string"
            
            if len(value) > max_length:
                return False, f"Value must be no more than {max_length} characters long"
            
            return True, None
        
        return validator
    
    def _validate_pattern(self, pattern: str) -> ValidatorFunction:
        """Create pattern validator with custom regex."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            if not isinstance(value, str):
                return False, "Value must be a string"
            
            if not re.match(pattern, value):
                return False, f"Value does not match required pattern"
            
            return True, None
        
        return validator
    
    def _validate_enum(self, valid_values: List[Any]) -> ValidatorFunction:
        """Create enum validator for allowed values."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            if value not in valid_values:
                return False, f"Value must be one of: {', '.join(map(str, valid_values))}"
            
            return True, None
        
        return validator
    
    def _validate_range(self, min_val: Union[int, float], max_val: Union[int, float]) -> ValidatorFunction:
        """Create range validator for numeric values."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            try:
                num_value = float(value)
                if num_value < min_val or num_value > max_val:
                    return False, f"Value must be between {min_val} and {max_val}"
                return True, None
            except (ValueError, TypeError):
                return False, "Value must be numeric"
        
        return validator
    
    def _validate_positive(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate positive numeric value."""
        if value is None:
            return True, None  # Optional field
        
        try:
            num_value = float(value)
            if num_value <= 0:
                return False, "Value must be positive"
            return True, None
        except (ValueError, TypeError):
            return False, "Value must be numeric"
    
    def _validate_negative(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate negative numeric value."""
        if value is None:
            return True, None  # Optional field
        
        try:
            num_value = float(value)
            if num_value >= 0:
                return False, "Value must be negative"
            return True, None
        except (ValueError, TypeError):
            return False, "Value must be numeric"
    
    def _validate_alphanumeric(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate alphanumeric string."""
        if value is None:
            return True, None  # Optional field
        
        if not isinstance(value, str):
            return False, "Value must be a string"
        
        pattern = self._field_patterns['alphanumeric']
        if not re.match(pattern, value):
            return False, "Value must contain only letters and numbers"
        
        return True, None
    
    def _validate_alpha(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate alphabetic string."""
        if value is None:
            return True, None  # Optional field
        
        if not isinstance(value, str):
            return False, "Value must be a string"
        
        pattern = self._field_patterns['alpha']
        if not re.match(pattern, value):
            return False, "Value must contain only letters"
        
        return True, None
    
    def _validate_unique(self, field_name: str, model_class: Type) -> ValidatorFunction:
        """Create database uniqueness validator."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            if not self.db_session:
                return True, None  # Skip if no database session
            
            try:
                existing = self.db_session.query(model_class).filter(
                    getattr(model_class, field_name) == value
                ).first()
                
                if existing:
                    return False, f"Value already exists in database"
                
                return True, None
            except SQLAlchemyError as e:
                self.logger.error(f"Database validation error: {str(e)}")
                return False, "Database validation error"
        
        return validator
    
    def _validate_exists(self, field_name: str, model_class: Type) -> ValidatorFunction:
        """Create database existence validator."""
        def validator(value: Any) -> Tuple[bool, Optional[str]]:
            if value is None:
                return True, None  # Optional field
            
            if not self.db_session:
                return True, None  # Skip if no database session
            
            try:
                existing = self.db_session.query(model_class).filter(
                    getattr(model_class, field_name) == value
                ).first()
                
                if not existing:
                    return False, f"Value does not exist in database"
                
                return True, None
            except SQLAlchemyError as e:
                self.logger.error(f"Database validation error: {str(e)}")
                return False, "Database validation error"
        
        return validator
    
    # Business rule validators maintaining existing validation patterns
    
    def _validate_user_email_unique(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate user email uniqueness business rule."""
        email = data.get('email')
        if not email or not self.db_session:
            return True, None
        
        try:
            # Import here to avoid circular imports
            from models.user import User
            
            existing_user = self.db_session.query(User).filter(
                User.email == email
            ).first()
            
            if existing_user:
                return False, "Email address is already registered"
            
            return True, None
        except Exception as e:
            self.logger.error(f"User email uniqueness validation error: {str(e)}")
            return False, "Unable to validate email uniqueness"
    
    def _validate_username_unique(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate username uniqueness business rule."""
        username = data.get('username')
        if not username or not self.db_session:
            return True, None
        
        try:
            from models.user import User
            
            existing_user = self.db_session.query(User).filter(
                User.username == username
            ).first()
            
            if existing_user:
                return False, "Username is already taken"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Username uniqueness validation error: {str(e)}")
            return False, "Unable to validate username uniqueness"
    
    def _validate_password_strength(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate password strength business rule."""
        password = data.get('password')
        if not password:
            return True, None  # Skip if no password provided
        
        # Password strength requirements
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, None
    
    def _validate_role_permissions(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate role permission assignments business rule."""
        role_id = data.get('role_id')
        permission_ids = data.get('permission_ids', [])
        
        if not role_id or not permission_ids or not self.db_session:
            return True, None
        
        try:
            from models.rbac import Role, Permission
            
            # Validate role exists
            role = self.db_session.query(Role).filter(Role.id == role_id).first()
            if not role:
                return False, "Invalid role specified"
            
            # Validate all permissions exist
            existing_permissions = self.db_session.query(Permission).filter(
                Permission.id.in_(permission_ids)
            ).all()
            
            if len(existing_permissions) != len(permission_ids):
                return False, "One or more invalid permissions specified"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Role permission validation error: {str(e)}")
            return False, "Unable to validate role permissions"
    
    def _validate_business_entity_owner(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate business entity ownership business rule."""
        owner_id = data.get('owner_id')
        if not owner_id or not self.db_session:
            return True, None
        
        try:
            from models.user import User
            
            owner = self.db_session.query(User).filter(
                User.id == owner_id,
                User.is_active == True
            ).first()
            
            if not owner:
                return False, "Invalid or inactive user specified as owner"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Business entity owner validation error: {str(e)}")
            return False, "Unable to validate business entity owner"
    
    def _validate_audit_trail_integrity(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate audit trail integrity business rule."""
        # Ensure audit fields are properly populated
        required_audit_fields = ['created_by', 'updated_by']
        
        for field in required_audit_fields:
            if field in data and not data[field]:
                return False, f"Audit field {field} cannot be empty"
        
        return True, None
    
    def _validate_session_validity(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate session validity business rule."""
        session_token = data.get('session_token')
        if not session_token or not self.db_session:
            return True, None
        
        try:
            from models.user import UserSession
            
            session = self.db_session.query(UserSession).filter(
                UserSession.session_token == session_token,
                UserSession.expires_at > datetime.utcnow(),
                UserSession.is_active == True
            ).first()
            
            if not session:
                return False, "Invalid or expired session"
            
            return True, None
        except Exception as e:
            self.logger.error(f"Session validity validation error: {str(e)}")
            return False, "Unable to validate session"
    
    def _validate_user_active_status(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate user active status business rule."""
        user_id = data.get('user_id')
        if not user_id or not self.db_session:
            return True, None
        
        try:
            from models.user import User
            
            user = self.db_session.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User not found"
            
            if not user.is_active:
                return False, "User account is inactive"
            
            return True, None
        except Exception as e:
            self.logger.error(f"User active status validation error: {str(e)}")
            return False, "Unable to validate user status"
    
    def _validate_permission_hierarchy(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate permission hierarchy business rule."""
        # Example: admin permissions require user permissions
        permissions = data.get('permissions', [])
        if not permissions:
            return True, None
        
        admin_permissions = [p for p in permissions if 'admin' in p.lower()]
        user_permissions = [p for p in permissions if 'user' in p.lower()]
        
        if admin_permissions and not user_permissions:
            return False, "Admin permissions require basic user permissions"
        
        return True, None
    
    def _validate_data_consistency(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate data consistency business rule."""
        # Example: ensure start_date is before end_date
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if start_date and end_date:
            try:
                if isinstance(start_date, str):
                    start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                if isinstance(end_date, str):
                    end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                
                if start_date >= end_date:
                    return False, "Start date must be before end date"
            except ValueError:
                return False, "Invalid date format for consistency validation"
        
        return True, None
    
    # Helper methods
    
    def _apply_business_rules(
        self, 
        data: Dict[str, Any], 
        result: ValidationResult,
        context: Dict[str, Any]
    ) -> None:
        """Apply business rules based on validation context."""
        business_rules = context.get('business_rules', [])
        
        for rule_name in business_rules:
            if rule_name in self._business_rules:
                validator = self._business_rules[rule_name]
                is_valid, error_message = validator(data)
                
                if not is_valid:
                    result.add_error(
                        field=rule_name,
                        message=error_message or f"Business rule {rule_name} validation failed",
                        error_code=f"BUSINESS_RULE_{rule_name.upper()}_FAILED",
                        rule_type=BusinessRuleType.BUSINESS_LOGIC
                    )
    
    def _convert_schema_to_rules(self, schema: Dict[str, Any]) -> ValidationRules:
        """Convert schema definition to validation rules."""
        rules = {}
        
        for field_name, field_config in schema.items():
            validators = []
            
            # Handle different schema configurations
            if isinstance(field_config, dict):
                # Required field validation
                if field_config.get('required', False):
                    validators.append(self._built_in_validators['required'])
                
                # Type validation
                field_type = field_config.get('type')
                if field_type and field_type in self._built_in_validators:
                    validators.append(self._built_in_validators[field_type])
                
                # Length validation
                min_length = field_config.get('min_length')
                if min_length is not None:
                    validators.append(self._validate_min_length(min_length))
                
                max_length = field_config.get('max_length')
                if max_length is not None:
                    validators.append(self._validate_max_length(max_length))
                
                # Pattern validation
                pattern = field_config.get('pattern')
                if pattern:
                    validators.append(self._validate_pattern(pattern))
                
                # Enum validation
                enum_values = field_config.get('enum')
                if enum_values:
                    validators.append(self._validate_enum(enum_values))
                
                # Range validation
                min_val = field_config.get('min')
                max_val = field_config.get('max')
                if min_val is not None and max_val is not None:
                    validators.append(self._validate_range(min_val, max_val))
                
            elif isinstance(field_config, str) and field_config in self._built_in_validators:
                # Simple type validation
                validators.append(self._built_in_validators[field_config])
            
            if validators:
                rules[field_name] = validators
        
        return rules
    
    def get_available_validators(self) -> List[str]:
        """Get list of available validator names."""
        return list(self._built_in_validators.keys())
    
    def get_available_business_rules(self) -> List[str]:
        """Get list of available business rule names."""
        return list(self._business_rules.keys())
    
    def create_custom_validator(
        self, 
        name: str, 
        validator_func: ValidatorFunction
    ) -> None:
        """Register a custom validator function."""
        self._built_in_validators[name] = validator_func
        self._log_operation('register_custom_validator', {'name': name})
    
    def create_custom_business_rule(
        self, 
        name: str, 
        rule_func: ValidatorFunction
    ) -> None:
        """Register a custom business rule."""
        self._business_rules[name] = rule_func
        self._log_operation('register_custom_business_rule', {'name': name})


# Factory function for service creation
def create_validation_service(db_session: Optional[Session] = None) -> ValidationService:
    """
    Factory function to create ValidationService instance.
    
    Args:
        db_session: Optional SQLAlchemy session for database operations
        
    Returns:
        Configured ValidationService instance
    """
    return ValidationService(db_session=db_session)