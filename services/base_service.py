"""
Base Service Layer Implementation for Flask Application

This module provides the foundational Service Layer pattern implementation for the Flask 3.1.1
application, featuring dependency injection framework, SQLAlchemy session management, and 
comprehensive type-safe database operations. The base service class establishes the architecture
for business logic abstraction with enhanced testability through dependency injection patterns.

Key Features:
- Dependency injection framework with SQLAlchemy session management
- Type-safe database operations with comprehensive type annotations
- Service Layer pattern implementation for business logic abstraction
- Flask application factory pattern compatibility
- Enhanced testability through dependency injection for Pytest fixtures
- Transaction management with automatic rollback capabilities
- Comprehensive error handling and logging integration

Architecture:
This implementation follows the Service Layer pattern as specified in Section 4.5.1.2 of the
technical specification, providing clear separation between presentation, business logic, and
data access layers within the Flask monolithic architecture.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import (
    Any, 
    Dict, 
    Generic, 
    List, 
    Optional, 
    Protocol, 
    Type, 
    TypeVar, 
    Union,
    runtime_checkable,
    ContextManager
)
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_, func
from flask import current_app, g
from werkzeug.exceptions import BadRequest, NotFound, InternalServerError


# Type variables for generic implementations
ModelType = TypeVar('ModelType')
CreateSchemaType = TypeVar('CreateSchemaType')
UpdateSchemaType = TypeVar('UpdateSchemaType')


@runtime_checkable
class DatabaseSession(Protocol):
    """
    Protocol defining the expected interface for database session objects.
    
    This protocol ensures type safety for dependency injection while maintaining
    flexibility for testing with mock objects and different session implementations.
    
    Methods defined here represent the core database operations required by all
    service layer implementations for CRUD operations and transaction management.
    """
    
    def add(self, instance: Any) -> None:
        """Add an instance to the session for persistence."""
        ...
    
    def delete(self, instance: Any) -> None:
        """Mark an instance for deletion from the database."""
        ...
    
    def commit(self) -> None:
        """Commit the current transaction to the database."""
        ...
    
    def rollback(self) -> None:
        """Rollback the current transaction."""
        ...
    
    def flush(self) -> None:
        """Flush pending changes to the database without committing."""
        ...
    
    def close(self) -> None:
        """Close the database session."""
        ...
    
    def query(self, *entities: Any) -> Any:
        """Create a query object for database operations."""
        ...
    
    def get(self, entity: Type[ModelType], ident: Any) -> Optional[ModelType]:
        """Get an entity by its primary key identifier."""
        ...
    
    def merge(self, instance: ModelType) -> ModelType:
        """Merge an object into the session."""
        ...


@dataclass
class ServiceResult:
    """
    Standardized service operation result container.
    
    This class provides consistent return value structure for all service layer
    operations, enabling standardized error handling, success validation, and
    result data access patterns throughout the application.
    
    Attributes:
        success: Boolean indicating operation success/failure
        data: The actual result data from the operation
        error: Error message if the operation failed
        error_code: Standardized error code for error categorization
        metadata: Additional context information about the operation
    """
    
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    @classmethod
    def success_result(
        cls, 
        data: Any = None, 
        metadata: Optional[Dict[str, Any]] = None
    ) -> ServiceResult:
        """Create a successful service result."""
        return cls(success=True, data=data, metadata=metadata)
    
    @classmethod
    def error_result(
        cls,
        error: str,
        error_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ServiceResult:
        """Create an error service result."""
        return cls(
            success=False, 
            error=error, 
            error_code=error_code, 
            metadata=metadata
        )


@dataclass
class ValidationResult:
    """
    Business logic validation result container.
    
    This class provides structured validation results for business rule enforcement,
    data validation, and constraint checking throughout the service layer.
    
    Attributes:
        is_valid: Boolean indicating validation success/failure
        errors: List of validation error messages
        warnings: List of validation warning messages
        field_errors: Dictionary mapping field names to specific errors
    """
    
    is_valid: bool
    errors: List[str]
    warnings: List[str] = None
    field_errors: Dict[str, List[str]] = None
    
    def __post_init__(self):
        """Initialize optional attributes with default values."""
        if self.warnings is None:
            self.warnings = []
        if self.field_errors is None:
            self.field_errors = {}
    
    def add_error(self, error: str, field: Optional[str] = None) -> None:
        """Add a validation error to the result."""
        self.errors.append(error)
        if field:
            if field not in self.field_errors:
                self.field_errors[field] = []
            self.field_errors[field].append(error)
        self.is_valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add a validation warning to the result."""
        self.warnings.append(warning)


class ServiceException(Exception):
    """
    Base exception class for service layer operations.
    
    This exception provides structured error handling for service layer operations
    with standardized error codes, messages, and context information for debugging
    and error reporting.
    
    Attributes:
        message: Human-readable error message
        error_code: Standardized error code for categorization
        details: Additional error context and debugging information
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize service exception with error details."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code or 'SERVICE_ERROR'
        self.details = details or {}


class ValidationException(ServiceException):
    """Exception raised for business logic validation failures."""
    
    def __init__(
        self, 
        message: str, 
        validation_result: Optional[ValidationResult] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize validation exception with validation result context."""
        super().__init__(message, 'VALIDATION_ERROR', details)
        self.validation_result = validation_result


class DatabaseException(ServiceException):
    """Exception raised for database operation failures."""
    
    def __init__(
        self, 
        message: str, 
        original_exception: Optional[Exception] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize database exception with original exception context."""
        super().__init__(message, 'DATABASE_ERROR', details)
        self.original_exception = original_exception


class BaseService(ABC, Generic[ModelType]):
    """
    Abstract base service class implementing the Service Layer pattern.
    
    This class provides the foundational architecture for all business logic services
    in the Flask application. It implements dependency injection for SQLAlchemy sessions,
    type-safe database operations, comprehensive error handling, and transaction management.
    
    The base service follows the Service Layer pattern as specified in Section 4.5.1.2
    of the technical specification, enabling clear separation of concerns between
    presentation, business logic, and data access layers.
    
    Key Features:
    - Dependency injection with type-safe session management
    - Comprehensive transaction management with automatic rollback
    - Standardized error handling and logging integration
    - Type-safe CRUD operations with validation support
    - Enhanced testability through dependency injection patterns
    - Flask application factory pattern compatibility
    
    Generic Parameters:
        ModelType: The SQLAlchemy model type this service manages
    
    Attributes:
        db_session: Injected database session for all operations
        logger: Service-specific logger for operation tracking
        model_class: The SQLAlchemy model class managed by this service
    """
    
    def __init__(
        self, 
        db_session: DatabaseSession,
        model_class: Optional[Type[ModelType]] = None
    ) -> None:
        """
        Initialize base service with dependency injection.
        
        Args:
            db_session: SQLAlchemy database session for data operations
            model_class: Optional SQLAlchemy model class for CRUD operations
            
        Raises:
            TypeError: If db_session doesn't implement DatabaseSession protocol
        """
        # Validate session protocol compliance for type safety
        if not isinstance(db_session, DatabaseSession):
            raise TypeError(
                f"db_session must implement DatabaseSession protocol, "
                f"got {type(db_session).__name__}"
            )
        
        self.db_session = db_session
        self.model_class = model_class
        
        # Initialize service-specific logger
        self.logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")
        
        # Service operation metrics for monitoring
        self._operation_count = 0
        self._error_count = 0
        
        self.logger.debug(
            f"Initialized {self.__class__.__name__} with session type: {type(db_session).__name__}"
        )
    
    @property
    def operation_metrics(self) -> Dict[str, int]:
        """Get service operation metrics for monitoring."""
        return {
            'operation_count': self._operation_count,
            'error_count': self._error_count,
            'success_rate': (
                (self._operation_count - self._error_count) / max(self._operation_count, 1)
            ) * 100
        }
    
    def _increment_operation_count(self) -> None:
        """Increment operation counter for metrics tracking."""
        self._operation_count += 1
    
    def _increment_error_count(self) -> None:
        """Increment error counter for metrics tracking."""
        self._error_count += 1
    
    @contextmanager
    def transaction(self) -> ContextManager[None]:
        """
        Context manager for database transaction management.
        
        This context manager provides automatic transaction handling with
        commit on success and rollback on any exception. It ensures data
        consistency and proper error handling for all database operations.
        
        Yields:
            None
            
        Raises:
            DatabaseException: If transaction operations fail
            
        Example:
            ```python
            with self.transaction():
                self.db_session.add(new_entity)
                # Transaction automatically committed on success
                # or rolled back on exception
            ```
        """
        self._increment_operation_count()
        
        try:
            self.logger.debug("Starting database transaction")
            yield
            self.db_session.commit()
            self.logger.debug("Database transaction committed successfully")
            
        except SQLAlchemyError as e:
            self._increment_error_count()
            self.logger.error(f"Database error in transaction: {str(e)}")
            try:
                self.db_session.rollback()
                self.logger.debug("Database transaction rolled back")
            except Exception as rollback_error:
                self.logger.error(f"Failed to rollback transaction: {str(rollback_error)}")
            
            raise DatabaseException(
                message=f"Database operation failed: {str(e)}",
                original_exception=e,
                details={'transaction_error': True}
            )
            
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error in transaction: {str(e)}")
            try:
                self.db_session.rollback()
                self.logger.debug("Database transaction rolled back due to unexpected error")
            except Exception as rollback_error:
                self.logger.error(f"Failed to rollback transaction: {str(rollback_error)}")
            
            raise ServiceException(
                message=f"Service operation failed: {str(e)}",
                error_code='TRANSACTION_ERROR',
                details={'original_error': str(e)}
            )
    
    def validate_data(
        self, 
        data: Dict[str, Any], 
        rules: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate data against business rules and constraints.
        
        This method provides comprehensive data validation for business rule
        enforcement, field validation, and constraint checking. It can be
        extended by subclasses to implement domain-specific validation logic.
        
        Args:
            data: Dictionary containing data to validate
            rules: Optional validation rules dictionary
            
        Returns:
            ValidationResult: Structured validation result with errors and warnings
            
        Example:
            ```python
            validation = self.validate_data(
                {'email': 'invalid-email'},
                {'email': {'required': True, 'format': 'email'}}
            )
            if not validation.is_valid:
                raise ValidationException("Invalid data", validation)
            ```
        """
        self.logger.debug(f"Validating data with {len(data)} fields")
        
        validation_result = ValidationResult(is_valid=True, errors=[])
        
        # Basic validation implementation - can be extended by subclasses
        if rules:
            for field, field_rules in rules.items():
                value = data.get(field)
                
                # Required field validation
                if field_rules.get('required', False) and not value:
                    validation_result.add_error(
                        f"Field '{field}' is required", 
                        field=field
                    )
                
                # Type validation
                expected_type = field_rules.get('type')
                if expected_type and value is not None:
                    if not isinstance(value, expected_type):
                        validation_result.add_error(
                            f"Field '{field}' must be of type {expected_type.__name__}",
                            field=field
                        )
        
        self.logger.debug(
            f"Validation completed: {'PASSED' if validation_result.is_valid else 'FAILED'} "
            f"with {len(validation_result.errors)} errors"
        )
        
        return validation_result
    
    def get_by_id(self, entity_id: Any) -> Optional[ModelType]:
        """
        Retrieve entity by primary key identifier.
        
        Args:
            entity_id: Primary key value for entity lookup
            
        Returns:
            Model instance if found, None otherwise
            
        Raises:
            ValueError: If model_class is not configured
            DatabaseException: If database operation fails
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        self._increment_operation_count()
        
        try:
            self.logger.debug(f"Retrieving {self.model_class.__name__} with ID: {entity_id}")
            entity = self.db_session.get(self.model_class, entity_id)
            
            if entity:
                self.logger.debug(f"Found {self.model_class.__name__} with ID: {entity_id}")
            else:
                self.logger.debug(f"No {self.model_class.__name__} found with ID: {entity_id}")
            
            return entity
            
        except SQLAlchemyError as e:
            self._increment_error_count()
            self.logger.error(f"Database error retrieving entity: {str(e)}")
            raise DatabaseException(
                message=f"Failed to retrieve {self.model_class.__name__} with ID {entity_id}",
                original_exception=e
            )
    
    def get_all(
        self, 
        limit: Optional[int] = None, 
        offset: Optional[int] = None,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None
    ) -> List[ModelType]:
        """
        Retrieve multiple entities with optional filtering and pagination.
        
        Args:
            limit: Maximum number of entities to return
            offset: Number of entities to skip for pagination
            filters: Dictionary of field/value pairs for filtering
            order_by: Field name for result ordering
            
        Returns:
            List of model instances matching criteria
            
        Raises:
            ValueError: If model_class is not configured
            DatabaseException: If database operation fails
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        self._increment_operation_count()
        
        try:
            self.logger.debug(
                f"Retrieving {self.model_class.__name__} entities with "
                f"limit={limit}, offset={offset}, filters={filters}"
            )
            
            query = self.db_session.query(self.model_class)
            
            # Apply filters if provided
            if filters:
                for field, value in filters.items():
                    if hasattr(self.model_class, field):
                        query = query.filter(getattr(self.model_class, field) == value)
            
            # Apply ordering if specified
            if order_by and hasattr(self.model_class, order_by):
                query = query.order_by(getattr(self.model_class, order_by))
            
            # Apply pagination
            if offset:
                query = query.offset(offset)
            if limit:
                query = query.limit(limit)
            
            entities = query.all()
            
            self.logger.debug(f"Retrieved {len(entities)} {self.model_class.__name__} entities")
            return entities
            
        except SQLAlchemyError as e:
            self._increment_error_count()
            self.logger.error(f"Database error retrieving entities: {str(e)}")
            raise DatabaseException(
                message=f"Failed to retrieve {self.model_class.__name__} entities",
                original_exception=e
            )
    
    def create(self, data: Dict[str, Any]) -> ServiceResult:
        """
        Create new entity with validation and transaction management.
        
        Args:
            data: Dictionary containing entity data
            
        Returns:
            ServiceResult: Result containing created entity or error information
            
        Raises:
            ValueError: If model_class is not configured
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        try:
            # Validate data before creation
            validation_result = self.validate_data(data)
            if not validation_result.is_valid:
                return ServiceResult.error_result(
                    error="Validation failed",
                    error_code="VALIDATION_ERROR",
                    metadata={'validation_errors': validation_result.errors}
                )
            
            with self.transaction():
                # Create new entity instance
                entity = self.model_class(**data)
                self.db_session.add(entity)
                self.db_session.flush()  # Flush to get generated ID
                
                self.logger.info(f"Created new {self.model_class.__name__} entity")
                
                return ServiceResult.success_result(
                    data=entity,
                    metadata={'operation': 'create', 'entity_type': self.model_class.__name__}
                )
                
        except (ValidationException, DatabaseException) as e:
            self.logger.error(f"Failed to create entity: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'operation': 'create', 'entity_type': self.model_class.__name__}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error creating entity: {str(e)}")
            return ServiceResult.error_result(
                error=f"Failed to create entity: {str(e)}",
                error_code="UNEXPECTED_ERROR",
                metadata={'operation': 'create', 'entity_type': self.model_class.__name__}
            )
    
    def update(self, entity_id: Any, data: Dict[str, Any]) -> ServiceResult:
        """
        Update existing entity with validation and transaction management.
        
        Args:
            entity_id: Primary key of entity to update
            data: Dictionary containing updated field values
            
        Returns:
            ServiceResult: Result containing updated entity or error information
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        try:
            # Retrieve existing entity
            entity = self.get_by_id(entity_id)
            if not entity:
                return ServiceResult.error_result(
                    error=f"{self.model_class.__name__} not found",
                    error_code="NOT_FOUND",
                    metadata={'entity_id': entity_id, 'operation': 'update'}
                )
            
            # Validate update data
            validation_result = self.validate_data(data)
            if not validation_result.is_valid:
                return ServiceResult.error_result(
                    error="Validation failed",
                    error_code="VALIDATION_ERROR",
                    metadata={'validation_errors': validation_result.errors}
                )
            
            with self.transaction():
                # Update entity attributes
                for field, value in data.items():
                    if hasattr(entity, field):
                        setattr(entity, field, value)
                
                self.db_session.flush()
                
                self.logger.info(f"Updated {self.model_class.__name__} entity with ID: {entity_id}")
                
                return ServiceResult.success_result(
                    data=entity,
                    metadata={'operation': 'update', 'entity_id': entity_id}
                )
                
        except (ValidationException, DatabaseException) as e:
            self.logger.error(f"Failed to update entity: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'operation': 'update', 'entity_id': entity_id}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error updating entity: {str(e)}")
            return ServiceResult.error_result(
                error=f"Failed to update entity: {str(e)}",
                error_code="UNEXPECTED_ERROR",
                metadata={'operation': 'update', 'entity_id': entity_id}
            )
    
    def delete(self, entity_id: Any) -> ServiceResult:
        """
        Delete entity by primary key with transaction management.
        
        Args:
            entity_id: Primary key of entity to delete
            
        Returns:
            ServiceResult: Result indicating success or failure
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        try:
            # Retrieve entity to delete
            entity = self.get_by_id(entity_id)
            if not entity:
                return ServiceResult.error_result(
                    error=f"{self.model_class.__name__} not found",
                    error_code="NOT_FOUND",
                    metadata={'entity_id': entity_id, 'operation': 'delete'}
                )
            
            with self.transaction():
                self.db_session.delete(entity)
                
                self.logger.info(f"Deleted {self.model_class.__name__} entity with ID: {entity_id}")
                
                return ServiceResult.success_result(
                    data={'deleted_id': entity_id},
                    metadata={'operation': 'delete', 'entity_id': entity_id}
                )
                
        except DatabaseException as e:
            self.logger.error(f"Failed to delete entity: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'operation': 'delete', 'entity_id': entity_id}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error deleting entity: {str(e)}")
            return ServiceResult.error_result(
                error=f"Failed to delete entity: {str(e)}",
                error_code="UNEXPECTED_ERROR",
                metadata={'operation': 'delete', 'entity_id': entity_id}
            )
    
    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """
        Count entities matching optional filters.
        
        Args:
            filters: Optional dictionary of field/value pairs for filtering
            
        Returns:
            Integer count of matching entities
            
        Raises:
            ValueError: If model_class is not configured
            DatabaseException: If database operation fails
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        self._increment_operation_count()
        
        try:
            query = self.db_session.query(func.count(self.model_class.id))
            
            # Apply filters if provided
            if filters:
                for field, value in filters.items():
                    if hasattr(self.model_class, field):
                        query = query.filter(getattr(self.model_class, field) == value)
            
            count = query.scalar()
            
            self.logger.debug(f"Counted {count} {self.model_class.__name__} entities")
            return count
            
        except SQLAlchemyError as e:
            self._increment_error_count()
            self.logger.error(f"Database error counting entities: {str(e)}")
            raise DatabaseException(
                message=f"Failed to count {self.model_class.__name__} entities",
                original_exception=e
            )
    
    def exists(self, entity_id: Any) -> bool:
        """
        Check if entity exists by primary key.
        
        Args:
            entity_id: Primary key value to check
            
        Returns:
            Boolean indicating entity existence
            
        Raises:
            ValueError: If model_class is not configured
            DatabaseException: If database operation fails
        """
        if not self.model_class:
            raise ValueError("model_class must be configured for CRUD operations")
        
        try:
            entity = self.get_by_id(entity_id)
            exists = entity is not None
            
            self.logger.debug(
                f"{self.model_class.__name__} with ID {entity_id} "
                f"{'exists' if exists else 'does not exist'}"
            )
            
            return exists
            
        except DatabaseException:
            # Re-raise database exceptions
            raise
    
    @abstractmethod
    def get_business_rules(self) -> Dict[str, Any]:
        """
        Abstract method for service-specific business rules definition.
        
        Subclasses must implement this method to define validation rules,
        constraints, and business logic specific to their domain.
        
        Returns:
            Dictionary containing business rules and validation constraints
        """
        pass
    
    def __enter__(self) -> BaseService[ModelType]:
        """Context manager entry for resource management."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        try:
            if exc_type is None:
                # No exception occurred, normal exit
                pass
            else:
                # Exception occurred, ensure rollback
                try:
                    self.db_session.rollback()
                    self.logger.debug("Rolled back transaction due to exception")
                except Exception as rollback_error:
                    self.logger.error(f"Failed to rollback on context exit: {str(rollback_error)}")
        finally:
            self.logger.debug(f"Exiting {self.__class__.__name__} context")


def create_service_factory(
    service_class: Type[BaseService[ModelType]],
    model_class: Optional[Type[ModelType]] = None
) -> callable:
    """
    Factory function for creating service instances with dependency injection.
    
    This factory function facilitates Flask application factory pattern integration
    by providing a standardized way to create service instances with proper
    dependency injection for database sessions and model classes.
    
    Args:
        service_class: The service class to instantiate
        model_class: Optional model class for CRUD operations
        
    Returns:
        Factory function that creates service instances with injected dependencies
        
    Example:
        ```python
        # In Flask application factory
        user_service_factory = create_service_factory(UserService, User)
        
        # In blueprint or route handler
        @app.route('/users')
        def get_users():
            with user_service_factory(db.session) as service:
                return service.get_all()
        ```
    """
    def factory(db_session: DatabaseSession) -> BaseService[ModelType]:
        """
        Create service instance with injected dependencies.
        
        Args:
            db_session: Database session for dependency injection
            
        Returns:
            Configured service instance ready for use
        """
        return service_class(db_session=db_session, model_class=model_class)
    
    return factory


def get_current_user_id() -> Optional[int]:
    """
    Utility function to get current authenticated user ID from Flask context.
    
    This function integrates with Flask-Login for user context tracking
    in audit trails and user attribution for service operations.
    
    Returns:
        Current user ID if authenticated, None otherwise
    """
    try:
        # Try to get user from Flask-Login current_user
        from flask_login import current_user
        if hasattr(current_user, 'id') and current_user.is_authenticated:
            return current_user.id
    except ImportError:
        # Flask-Login not available, try Flask g context
        pass
    
    # Fallback to Flask g context
    return getattr(g, 'user_id', None)


def get_service_logger(service_name: str) -> logging.Logger:
    """
    Get configured logger instance for service operations.
    
    Args:
        service_name: Name of the service for logger identification
        
    Returns:
        Configured logger instance with appropriate formatting
    """
    logger = logging.getLogger(f"services.{service_name}")
    
    # Configure logger if not already configured
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger