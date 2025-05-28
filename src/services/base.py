"""
Base Service Layer Implementation for Flask Application

This module provides the foundational base service class implementing the Service Layer
pattern as specified in Section 5.2.3. All business logic services inherit from this
base class to ensure uniform behavior, transaction management, and architectural
consistency throughout the Flask application.

Key Features:
- Service Layer pattern implementation with transaction boundary control
- Flask-SQLAlchemy session management for consistent data operations
- Flask-Injector dependency injection support for clean architectural separation
- Flask application context integration for seamless service registration
- Comprehensive error handling with automatic retry mechanisms
- Service composition patterns for complex business operations
"""

import logging
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union

from flask import current_app, g, has_app_context
from flask_sqlalchemy import SQLAlchemy
from injector import Injector, inject, singleton
from sqlalchemy.exc import (
    DatabaseError,
    IntegrityError,
    OperationalError,
    SQLAlchemyError,
)
from werkzeug.exceptions import BadRequest, InternalServerError

# Type variables for generic service operations
T = TypeVar("T")
ServiceType = TypeVar("ServiceType", bound="BaseService")

# Logger configuration for service layer operations
logger = logging.getLogger(__name__)


class ServiceError(Exception):
    """
    Base exception class for all service layer errors.
    
    Provides consistent error handling and messaging across all business logic
    services while maintaining separation from HTTP-specific errors.
    """
    
    def __init__(self, message: str, original_error: Optional[Exception] = None, 
                 retry_count: int = 0):
        self.message = message
        self.original_error = original_error
        self.retry_count = retry_count
        super().__init__(self.message)


class TransactionError(ServiceError):
    """Exception raised when database transaction operations fail."""
    pass


class ValidationError(ServiceError):
    """Exception raised when business logic validation fails."""
    pass


class ConcurrencyError(ServiceError):
    """Exception raised when concurrent access conflicts occur."""
    pass


def retry_on_failure(max_retries: int = 3, delay: float = 0.1, 
                    backoff_factor: float = 2.0, 
                    exceptions: tuple = (OperationalError, DatabaseError)):
    """
    Decorator implementing automatic retry mechanism for database operations.
    
    Provides resilient operation support as specified in Section 4.5.3 with
    configurable retry logic, exponential backoff, and selective exception handling.
    
    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff_factor: Multiplier for exponential backoff
        exceptions: Tuple of exception types to retry on
    
    Returns:
        Decorated function with retry logic
    """
    
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_retries:
                        logger.error(
                            f"Operation failed after {max_retries} retries: {e}",
                            exc_info=True
                        )
                        raise ServiceError(
                            f"Operation failed after {max_retries} retries",
                            original_error=e,
                            retry_count=attempt
                        )
                    
                    logger.warning(
                        f"Retry attempt {attempt + 1}/{max_retries} for {func.__name__}: {e}"
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff_factor
                except Exception as e:
                    # Don't retry on non-retryable exceptions
                    logger.error(f"Non-retryable error in {func.__name__}: {e}", exc_info=True)
                    raise ServiceError(
                        f"Non-retryable error in service operation",
                        original_error=e
                    )
            
            return func(*args, **kwargs)  # This should never be reached
        
        return wrapper
    return decorator


def require_app_context(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator ensuring Flask application context availability for service operations.
    
    Provides Flask application context integration as specified in Section 4.5.2
    and ensures proper context management for dependency injection.
    """
    
    @wraps(func)
    def wrapper(*args, **kwargs) -> T:
        if not has_app_context():
            raise ServiceError(
                "Flask application context required for service operation"
            )
        return func(*args, **kwargs)
    
    return wrapper


@singleton
class BaseService(ABC):
    """
    Abstract base class for all business logic services implementing the Service
    Layer pattern as specified in Section 5.2.3.
    
    This foundational class provides:
    - Transaction boundary management with Flask-SQLAlchemy
    - Flask application context integration
    - Dependency injection support through Flask-Injector
    - Error management and retry mechanisms
    - Service composition capabilities
    - Consistent session handling across all business operations
    
    All business logic services must inherit from this class to ensure
    architectural consistency and uniform behavior patterns.
    """
    
    @inject
    def __init__(self, db: SQLAlchemy):
        """
        Initialize base service with Flask-SQLAlchemy database instance.
        
        Args:
            db: Flask-SQLAlchemy database instance for session management
        """
        self.db = db
        self._session_cache: Dict[str, Any] = {}
        self._composition_services: Dict[str, "BaseService"] = {}
        
        # Initialize service-specific logger
        self.logger = logging.getLogger(self.__class__.__module__)
        
        # Verify Flask application context during initialization
        if has_app_context():
            self.logger.info(f"Initialized {self.__class__.__name__} service")
    
    @property
    def session(self):
        """
        Get the current SQLAlchemy session with proper context management.
        
        Provides consistent session access across all service operations
        as specified in Section 5.2.4 for Flask-SQLAlchemy integration.
        
        Returns:
            SQLAlchemy session instance
        """
        return self.db.session
    
    @contextmanager
    def transaction_boundary(self, nested: bool = False):
        """
        Context manager providing transaction boundary control for service operations.
        
        Implements transaction boundary management as specified in Section 5.2.3
        with support for nested transactions and automatic rollback on errors.
        
        Args:
            nested: Whether to create a nested transaction (savepoint)
        
        Yields:
            SQLAlchemy session within transaction boundary
        
        Raises:
            TransactionError: When transaction operations fail
        """
        if nested and self.session.in_transaction():
            # Use savepoint for nested transactions
            savepoint = self.session.begin_nested()
            try:
                self.logger.debug("Starting nested transaction (savepoint)")
                yield self.session
                savepoint.commit()
                self.logger.debug("Committed nested transaction")
            except Exception as e:
                self.logger.error(f"Rolling back nested transaction: {e}")
                savepoint.rollback()
                raise TransactionError(
                    "Nested transaction failed", 
                    original_error=e
                )
        else:
            # Use regular transaction
            try:
                self.logger.debug("Starting transaction boundary")
                yield self.session
                self.session.commit()
                self.logger.debug("Committed transaction")
            except Exception as e:
                self.logger.error(f"Rolling back transaction: {e}")
                self.session.rollback()
                raise TransactionError(
                    "Transaction boundary failed", 
                    original_error=e
                )
    
    @retry_on_failure(max_retries=3)
    def execute_with_retry(self, operation: Callable[[], T], 
                          context: str = "database operation") -> T:
        """
        Execute operation with automatic retry mechanism.
        
        Implements comprehensive error handling with retry logic as specified
        in Section 4.5.3 for resilient operation.
        
        Args:
            operation: Callable operation to execute
            context: Description of operation for logging
        
        Returns:
            Result of the operation
        
        Raises:
            ServiceError: When operation fails after all retries
        """
        try:
            self.logger.debug(f"Executing {context}")
            result = operation()
            self.logger.debug(f"Successfully completed {context}")
            return result
        except SQLAlchemyError as e:
            self.logger.error(f"Database error in {context}: {e}")
            raise TransactionError(
                f"Database operation failed: {context}",
                original_error=e
            )
        except Exception as e:
            self.logger.error(f"Service error in {context}: {e}")
            raise ServiceError(
                f"Service operation failed: {context}",
                original_error=e
            )
    
    def validate_input(self, data: Dict[str, Any], 
                      required_fields: List[str] = None) -> Dict[str, Any]:
        """
        Validate input data for service operations.
        
        Provides consistent input validation across all service operations
        with support for required field checking and data sanitization.
        
        Args:
            data: Input data dictionary to validate
            required_fields: List of required field names
        
        Returns:
            Validated and sanitized data dictionary
        
        Raises:
            ValidationError: When validation fails
        """
        if not isinstance(data, dict):
            raise ValidationError("Input data must be a dictionary")
        
        validated_data = data.copy()
        
        # Check required fields
        if required_fields:
            missing_fields = [
                field for field in required_fields 
                if field not in validated_data or validated_data[field] is None
            ]
            if missing_fields:
                raise ValidationError(
                    f"Required fields missing: {', '.join(missing_fields)}"
                )
        
        # Basic sanitization - remove None values and empty strings
        validated_data = {
            k: v for k, v in validated_data.items()
            if v is not None and v != ""
        }
        
        self.logger.debug(f"Validated input data with {len(validated_data)} fields")
        return validated_data
    
    def compose_service(self, service_class: Type[ServiceType]) -> ServiceType:
        """
        Compose with another service for complex business operations.
        
        Implements service composition patterns as specified in Section 5.2.3
        enabling coordination of multiple services for complex workflows.
        
        Args:
            service_class: Service class to compose with
        
        Returns:
            Instance of the requested service
        """
        service_name = service_class.__name__
        
        if service_name not in self._composition_services:
            if not has_app_context():
                raise ServiceError(
                    "Flask application context required for service composition"
                )
            
            # Get service instance through dependency injection
            injector = current_app.injector
            service_instance = injector.get(service_class)
            self._composition_services[service_name] = service_instance
            
            self.logger.debug(f"Composed service: {service_name}")
        
        return self._composition_services[service_name]
    
    def handle_integrity_error(self, error: IntegrityError, 
                             context: str = "database operation") -> None:
        """
        Handle database integrity constraint violations.
        
        Provides consistent handling of database integrity errors with
        proper error translation and logging.
        
        Args:
            error: SQLAlchemy IntegrityError instance
            context: Operation context for error reporting
        
        Raises:
            ValidationError: Translated validation error for business logic
        """
        error_message = str(error.orig) if error.orig else str(error)
        
        # Common integrity constraint patterns
        if "unique constraint" in error_message.lower():
            field_match = error_message.split(".")[-1] if "." in error_message else "field"
            raise ValidationError(f"Duplicate value for {field_match}")
        elif "foreign key constraint" in error_message.lower():
            raise ValidationError("Referenced entity does not exist")
        elif "not null constraint" in error_message.lower():
            field_match = error_message.split(".")[-1] if "." in error_message else "field"
            raise ValidationError(f"Required field {field_match} cannot be empty")
        else:
            self.logger.error(f"Unhandled integrity error in {context}: {error}")
            raise ValidationError(f"Data integrity violation in {context}")
    
    @require_app_context
    def get_current_user_id(self) -> Optional[int]:
        """
        Get current user ID from Flask application context.
        
        Provides consistent user context access across all service operations
        with Flask-Login integration support.
        
        Returns:
            Current user ID if authenticated, None otherwise
        """
        # Check Flask-Login current user if available
        if hasattr(g, "current_user") and hasattr(g.current_user, "id"):
            return g.current_user.id
        
        # Fallback to manual user_id in request context
        if hasattr(g, "user_id"):
            return g.user_id
        
        return None
    
    def cache_result(self, key: str, value: Any, ttl: int = 300) -> None:
        """
        Cache service operation result for performance optimization.
        
        Provides simple in-memory caching for expensive service operations
        with configurable time-to-live support.
        
        Args:
            key: Cache key identifier
            value: Value to cache
            ttl: Time to live in seconds
        """
        cache_entry = {
            "value": value,
            "timestamp": time.time(),
            "ttl": ttl
        }
        self._session_cache[key] = cache_entry
        self.logger.debug(f"Cached result for key: {key}")
    
    def get_cached_result(self, key: str) -> Optional[Any]:
        """
        Retrieve cached service operation result.
        
        Args:
            key: Cache key identifier
        
        Returns:
            Cached value if valid, None if expired or not found
        """
        if key not in self._session_cache:
            return None
        
        cache_entry = self._session_cache[key]
        current_time = time.time()
        
        if current_time - cache_entry["timestamp"] > cache_entry["ttl"]:
            # Cache expired, remove entry
            del self._session_cache[key]
            self.logger.debug(f"Cache expired for key: {key}")
            return None
        
        self.logger.debug(f"Cache hit for key: {key}")
        return cache_entry["value"]
    
    def clear_cache(self) -> None:
        """
        Clear all cached results for this service instance.
        """
        cache_size = len(self._session_cache)
        self._session_cache.clear()
        self.logger.debug(f"Cleared cache ({cache_size} entries)")
    
    @abstractmethod
    def validate_business_rules(self, data: Dict[str, Any]) -> bool:
        """
        Abstract method for implementing service-specific business rule validation.
        
        Each service must implement this method to define custom business
        logic validation rules specific to their domain.
        
        Args:
            data: Data to validate against business rules
        
        Returns:
            True if validation passes
        
        Raises:
            ValidationError: When business rules are violated
        """
        pass
    
    def log_service_operation(self, operation: str, data: Dict[str, Any] = None,
                            level: str = "info") -> None:
        """
        Log service operation with consistent formatting.
        
        Provides standardized logging across all service operations for
        debugging, auditing, and monitoring purposes.
        
        Args:
            operation: Description of the operation
            data: Optional data context for the operation
            level: Logging level (debug, info, warning, error)
        """
        log_message = f"{self.__class__.__name__}: {operation}"
        
        if data:
            # Sanitize sensitive data for logging
            safe_data = {
                k: v for k, v in data.items()
                if not any(sensitive in k.lower() 
                          for sensitive in ["password", "token", "secret", "key"])
            }
            log_message += f" - Data: {safe_data}"
        
        log_method = getattr(self.logger, level, self.logger.info)
        log_method(log_message)


def register_service_dependencies(injector: Injector) -> None:
    """
    Register service layer dependencies with Flask-Injector.
    
    Provides centralized dependency registration for the Service Layer pattern
    as specified in Section 4.5.1 for clean architectural separation.
    
    Args:
        injector: Flask-Injector instance for dependency registration
    """
    # Base service dependencies will be registered here
    # Specific service implementations will extend this in their modules
    logger.info("Registered base service dependencies with Flask-Injector")