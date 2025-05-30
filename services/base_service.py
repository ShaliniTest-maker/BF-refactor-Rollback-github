"""
Base Service Layer Implementation for Flask Application

This module provides the foundational Service Layer pattern implementation for the Flask 3.1.1
application architecture, establishing dependency injection framework, SQLAlchemy session management,
and common service functionality. The base service class serves as the foundation for all business
logic services within the application, ensuring consistent database transaction handling, type safety,
and enhanced testability.

Key Features:
- Dependency injection pattern with SQLAlchemy session management per Section 4.5.1.2
- Type-safe database operations with comprehensive type annotations per Section 4.5.1.3
- Service class structure implementing business logic abstraction per Section 4.5.1.2
- Flask application factory pattern compatibility per Section 6.1.5
- Enhanced testability through dependency injection for Pytest fixtures per Section 4.5.1.4

Architecture Benefits:
- Clear separation of concerns between presentation, business logic, and data access layers
- Comprehensive error handling and transaction management
- Database session isolation and connection pooling optimization
- Service-oriented design enabling modular business logic organization
- Type-safe interface definitions for improved IDE support and static analysis

Dependencies:
- Flask-SQLAlchemy 3.1.1: Database ORM and session management
- SQLAlchemy: Core database abstraction and type definitions
- typing: Comprehensive type annotations for enhanced code clarity
- abc: Abstract base class definitions for service contracts
- contextlib: Context manager support for transaction handling
"""

import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import (
    Any, Dict, List, Optional, TypeVar, Generic, Protocol, Union,
    Type, Callable, ClassVar, runtime_checkable, ContextManager
)
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from flask import current_app, has_app_context
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from sqlalchemy.engine import Engine
from sqlalchemy import event, text

# Import database instance from models module
from models import db

# Configure logging for service layer operations
logger = logging.getLogger(__name__)

# Generic type variables for enhanced type safety
T = TypeVar('T')
ModelType = TypeVar('ModelType')
ServiceType = TypeVar('ServiceType', bound='BaseService')


class ServiceError(Exception):
    """Base exception for service layer operations."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, 
                 cause: Optional[Exception] = None) -> None:
        """
        Initialize service error with comprehensive error information.
        
        Args:
            message: Human-readable error description
            error_code: Optional error code for programmatic handling
            cause: Optional underlying exception that caused this error
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.cause = cause
        self.timestamp = datetime.now(timezone.utc)


class DatabaseError(ServiceError):
    """Database-specific service error for transaction and query failures."""
    pass


class ValidationError(ServiceError):
    """Business rule validation error for constraint violations."""
    pass


class NotFoundError(ServiceError):
    """Resource not found error for entity lookup failures."""
    pass


class TransactionStatus(Enum):
    """Database transaction status enumeration."""
    PENDING = "pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass
class ServiceResult(Generic[T]):
    """
    Standardized service operation result container with comprehensive metadata.
    
    Provides consistent result handling across all service layer operations
    with success/failure indication, error details, and operation metadata.
    """
    
    success: bool
    data: Optional[T] = None
    error: Optional[ServiceError] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self) -> None:
        """Validate result consistency after initialization."""
        if self.success and self.error is not None:
            raise ValueError("Successful result cannot contain error information")
        if not self.success and self.error is None:
            raise ValueError("Failed result must contain error information")
    
    @classmethod
    def success_result(cls, data: T, metadata: Optional[Dict[str, Any]] = None) -> 'ServiceResult[T]':
        """
        Create successful service result with data and optional metadata.
        
        Args:
            data: Result data payload
            metadata: Optional operation metadata
            
        Returns:
            ServiceResult instance indicating successful operation
        """
        return cls(
            success=True,
            data=data,
            metadata=metadata or {}
        )
    
    @classmethod
    def error_result(cls, error: ServiceError, metadata: Optional[Dict[str, Any]] = None) -> 'ServiceResult[T]':
        """
        Create failed service result with error information and optional metadata.
        
        Args:
            error: Service error instance
            metadata: Optional operation metadata
            
        Returns:
            ServiceResult instance indicating failed operation
        """
        return cls(
            success=False,
            error=error,
            metadata=metadata or {}
        )


@runtime_checkable
class DatabaseSession(Protocol):
    """
    Type protocol defining database session interface for dependency injection.
    
    Provides type-safe database session contract for service layer operations
    enabling enhanced testing capabilities and clear interface boundaries.
    """
    
    def add(self, instance: Any) -> None:
        """Add instance to session for persistence."""
        ...
    
    def delete(self, instance: Any) -> None:
        """Mark instance for deletion from session."""
        ...
    
    def commit(self) -> None:
        """Commit current transaction."""
        ...
    
    def rollback(self) -> None:
        """Rollback current transaction."""
        ...
    
    def flush(self) -> None:
        """Flush pending changes without committing."""
        ...
    
    def close(self) -> None:
        """Close database session."""
        ...
    
    def query(self, *entities: Any) -> Any:
        """Query database entities."""
        ...
    
    def execute(self, statement: Any) -> Any:
        """Execute raw SQL statement."""
        ...


@runtime_checkable
class ServiceRegistry(Protocol):
    """
    Type protocol defining service registry interface for dependency resolution.
    
    Enables service discovery and dependency injection within Flask application
    context while maintaining type safety and clear interface contracts.
    """
    
    def register_service(self, service_class: Type[ServiceType], instance: ServiceType) -> None:
        """Register service instance in registry."""
        ...
    
    def get_service(self, service_class: Type[ServiceType]) -> ServiceType:
        """Retrieve service instance from registry."""
        ...
    
    def has_service(self, service_class: Type[ServiceType]) -> bool:
        """Check if service is registered in registry."""
        ...


class BaseService(ABC):
    """
    Abstract base service class providing dependency injection framework,
    SQLAlchemy session management, and common service functionality.
    
    This foundational class establishes the Service Layer pattern architecture
    with type-safe database operations and standardized service initialization.
    All business logic services inherit from this base class to ensure
    consistent transaction handling, error management, and testing capabilities.
    
    Key Features:
    - Dependency injection of SQLAlchemy sessions for database operations
    - Comprehensive transaction management with automatic rollback on errors
    - Type-safe database operations with full type annotations
    - Flask application factory pattern integration
    - Enhanced testability through constructor injection and session mocking
    - Standardized error handling and result containers
    - Connection pooling optimization through SQLAlchemy session management
    
    Usage Example:
        class UserService(BaseService):
            def create_user(self, username: str, email: str) -> ServiceResult[User]:
                try:
                    user = User(username=username, email=email)
                    self.db_session.add(user)
                    self.db_session.commit()
                    return ServiceResult.success_result(user)
                except Exception as e:
                    self.db_session.rollback()
                    return ServiceResult.error_result(
                        ServiceError(f"Failed to create user: {e}")
                    )
    """
    
    # Class-level configuration for service behavior
    _enable_transaction_logging: ClassVar[bool] = True
    _enable_performance_monitoring: ClassVar[bool] = True
    _default_query_timeout: ClassVar[int] = 30  # seconds
    
    def __init__(self, db_session: Optional[DatabaseSession] = None) -> None:
        """
        Initialize base service with dependency injection of database session.
        
        Implements constructor injection pattern enabling comprehensive testing
        with mock sessions while supporting Flask application context integration
        for production usage with Flask-SQLAlchemy session management.
        
        Args:
            db_session: Optional database session for dependency injection.
                       If None, uses Flask-SQLAlchemy session from application context.
                       
        Raises:
            RuntimeError: If no session provided and Flask application context unavailable
            DatabaseError: If database session initialization fails
        """
        # Initialize database session through dependency injection or Flask context
        if db_session is not None:
            self.db_session = db_session
            logger.debug(f"Service {self.__class__.__name__} initialized with injected database session")
        elif has_app_context():
            self.db_session = db.session
            logger.debug(f"Service {self.__class__.__name__} initialized with Flask-SQLAlchemy session")
        else:
            raise RuntimeError(
                f"Service {self.__class__.__name__} requires database session injection "
                "or Flask application context for session access"
            )
        
        # Initialize service metadata and performance tracking
        self._service_name = self.__class__.__name__
        self._initialization_time = datetime.now(timezone.utc)
        self._operation_count = 0
        self._error_count = 0
        
        # Validate database session compatibility
        self._validate_database_session()
        
        # Initialize service-specific configuration
        self._initialize_service_configuration()
        
        logger.info(f"Service {self._service_name} initialized successfully")
    
    def _validate_database_session(self) -> None:
        """
        Validate database session compatibility and connectivity.
        
        Performs comprehensive validation of database session including
        protocol compliance, connection verification, and transaction capability.
        
        Raises:
            DatabaseError: If session validation fails
        """
        try:
            # Verify session implements required protocol methods
            if not hasattr(self.db_session, 'add') or not hasattr(self.db_session, 'commit'):
                raise DatabaseError(
                    "Database session does not implement required protocol methods",
                    error_code="SESSION_PROTOCOL_ERROR"
                )
            
            # Test database connectivity with simple query
            if hasattr(self.db_session, 'execute'):
                result = self.db_session.execute(text('SELECT 1')).scalar()
                if result != 1:
                    raise DatabaseError(
                        "Database connectivity test failed",
                        error_code="CONNECTIVITY_TEST_FAILED"
                    )
                    
                logger.debug(f"Database session validation successful for {self._service_name}")
                
        except SQLAlchemyError as e:
            raise DatabaseError(
                f"Database session validation failed: {e}",
                error_code="SESSION_VALIDATION_ERROR",
                cause=e
            )
    
    def _initialize_service_configuration(self) -> None:
        """
        Initialize service-specific configuration and performance monitoring.
        
        Override this method in derived services to implement service-specific
        initialization logic, configuration loading, and dependency setup.
        """
        # Configure transaction logging if enabled
        if self._enable_transaction_logging and hasattr(self.db_session, 'bind'):
            self._setup_transaction_logging()
        
        # Initialize performance monitoring if enabled
        if self._enable_performance_monitoring:
            self._setup_performance_monitoring()
    
    def _setup_transaction_logging(self) -> None:
        """Configure SQLAlchemy event listeners for transaction logging."""
        try:
            engine = self.db_session.bind
            
            @event.listens_for(engine, "begin")
            def log_transaction_begin(conn):
                logger.debug(f"Transaction started for service {self._service_name}")
            
            @event.listens_for(engine, "commit")
            def log_transaction_commit(conn):
                logger.debug(f"Transaction committed for service {self._service_name}")
            
            @event.listens_for(engine, "rollback")
            def log_transaction_rollback(conn):
                logger.warning(f"Transaction rolled back for service {self._service_name}")
                
        except Exception as e:
            logger.warning(f"Failed to setup transaction logging for {self._service_name}: {e}")
    
    def _setup_performance_monitoring(self) -> None:
        """Initialize performance monitoring capabilities."""
        self._performance_metrics = {
            'total_operations': 0,
            'successful_operations': 0,
            'failed_operations': 0,
            'total_execution_time': 0.0,
            'average_execution_time': 0.0
        }
        
        logger.debug(f"Performance monitoring initialized for {self._service_name}")
    
    @contextmanager
    def transaction_scope(self, autocommit: bool = True) -> ContextManager[DatabaseSession]:
        """
        Context manager for explicit database transaction control.
        
        Provides comprehensive transaction management with automatic rollback
        on exceptions and optional autocommit behavior for complex operations
        spanning multiple database entities.
        
        Args:
            autocommit: Whether to automatically commit transaction on success
            
        Yields:
            Database session for transaction operations
            
        Raises:
            DatabaseError: If transaction operations fail
            
        Example:
            with self.transaction_scope() as session:
                user = User.create(username='test')
                session.add(user)
                profile = UserProfile.create(user_id=user.id)
                session.add(profile)
                # Automatic commit on success, rollback on exception
        """
        transaction_start = datetime.now(timezone.utc)
        transaction_status = TransactionStatus.PENDING
        
        try:
            # Begin transaction if not already active
            if not self.db_session.in_transaction() if hasattr(self.db_session, 'in_transaction') else True:
                self.db_session.begin()
            
            logger.debug(f"Transaction scope started for {self._service_name}")
            
            yield self.db_session
            
            # Commit transaction if autocommit enabled
            if autocommit:
                self.db_session.commit()
                transaction_status = TransactionStatus.COMMITTED
                logger.debug(f"Transaction committed successfully for {self._service_name}")
            
        except Exception as e:
            # Rollback transaction on any exception
            try:
                self.db_session.rollback()
                transaction_status = TransactionStatus.ROLLED_BACK
                logger.warning(f"Transaction rolled back for {self._service_name}: {e}")
            except Exception as rollback_error:
                transaction_status = TransactionStatus.FAILED
                logger.error(f"Transaction rollback failed for {self._service_name}: {rollback_error}")
                raise DatabaseError(
                    f"Transaction rollback failed: {rollback_error}",
                    error_code="ROLLBACK_FAILED",
                    cause=rollback_error
                )
            
            # Re-raise original exception as DatabaseError
            raise DatabaseError(
                f"Transaction failed: {e}",
                error_code="TRANSACTION_FAILED",
                cause=e
            )
        
        finally:
            # Record transaction metrics
            transaction_duration = (datetime.now(timezone.utc) - transaction_start).total_seconds()
            self._record_transaction_metrics(transaction_status, transaction_duration)
    
    def _record_transaction_metrics(self, status: TransactionStatus, duration: float) -> None:
        """Record transaction performance metrics for monitoring."""
        if hasattr(self, '_performance_metrics'):
            self._performance_metrics['total_operations'] += 1
            self._performance_metrics['total_execution_time'] += duration
            
            if status == TransactionStatus.COMMITTED:
                self._performance_metrics['successful_operations'] += 1
            else:
                self._performance_metrics['failed_operations'] += 1
            
            # Update average execution time
            total_ops = self._performance_metrics['total_operations']
            total_time = self._performance_metrics['total_execution_time']
            self._performance_metrics['average_execution_time'] = total_time / total_ops if total_ops > 0 else 0.0
    
    def execute_query(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> ServiceResult[List[Dict[str, Any]]]:
        """
        Execute raw SQL query with comprehensive error handling and result processing.
        
        Provides type-safe query execution with parameter binding, error handling,
        and standardized result formatting for complex database operations.
        
        Args:
            query: SQL query string to execute
            parameters: Optional query parameters for safe parameter binding
            
        Returns:
            ServiceResult containing query results or error information
        """
        operation_start = datetime.now(timezone.utc)
        
        try:
            # Execute query with parameter binding
            if parameters:
                result = self.db_session.execute(text(query), parameters)
            else:
                result = self.db_session.execute(text(query))
            
            # Process query results into standardized format
            if result.returns_rows:
                rows = []
                for row in result:
                    # Convert row to dictionary for consistent API
                    if hasattr(row, '_asdict'):
                        rows.append(row._asdict())
                    else:
                        rows.append(dict(row))
                
                result_data = rows
            else:
                # For non-SELECT queries, return affected row count
                result_data = [{'affected_rows': result.rowcount}]
            
            # Record successful operation metrics
            execution_time = (datetime.now(timezone.utc) - operation_start).total_seconds()
            metadata = {
                'execution_time': execution_time,
                'query': query,
                'parameters': parameters,
                'row_count': len(result_data)
            }
            
            logger.debug(f"Query executed successfully in {execution_time:.3f}s: {query[:100]}...")
            
            return ServiceResult.success_result(result_data, metadata)
            
        except SQLAlchemyError as e:
            # Handle database-specific errors
            execution_time = (datetime.now(timezone.utc) - operation_start).total_seconds()
            metadata = {
                'execution_time': execution_time,
                'query': query,
                'parameters': parameters
            }
            
            error = DatabaseError(
                f"Query execution failed: {e}",
                error_code="QUERY_EXECUTION_ERROR",
                cause=e
            )
            
            logger.error(f"Query execution failed after {execution_time:.3f}s: {e}")
            
            return ServiceResult.error_result(error, metadata)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive performance metrics for service operations.
        
        Returns:
            Dictionary containing performance metrics and operational statistics
        """
        base_metrics = {
            'service_name': self._service_name,
            'initialization_time': self._initialization_time.isoformat(),
            'uptime_seconds': (datetime.now(timezone.utc) - self._initialization_time).total_seconds(),
            'operation_count': self._operation_count,
            'error_count': self._error_count,
            'error_rate': self._error_count / max(self._operation_count, 1)
        }
        
        # Add performance monitoring metrics if available
        if hasattr(self, '_performance_metrics'):
            base_metrics.update(self._performance_metrics)
        
        return base_metrics
    
    def validate_business_rules(self, entity: Any, operation: str) -> ServiceResult[bool]:
        """
        Validate business rules for entity operations.
        
        Override this method in derived services to implement specific
        business rule validation logic for create, update, and delete operations.
        
        Args:
            entity: Entity instance to validate
            operation: Operation type ('create', 'update', 'delete')
            
        Returns:
            ServiceResult indicating validation success or failure with error details
        """
        # Default implementation returns success - override in derived services
        return ServiceResult.success_result(
            True,
            metadata={'operation': operation, 'entity_type': type(entity).__name__}
        )
    
    @abstractmethod
    def get_service_name(self) -> str:
        """
        Get service name for identification and logging purposes.
        
        Abstract method requiring implementation in derived service classes
        to provide clear service identification for monitoring and debugging.
        
        Returns:
            Service name string for identification
        """
        pass
    
    @abstractmethod
    def health_check(self) -> ServiceResult[Dict[str, Any]]:
        """
        Perform comprehensive service health check including database connectivity.
        
        Abstract method requiring implementation in derived service classes
        to provide service-specific health validation including external
        dependencies, business logic validation, and resource availability.
        
        Returns:
            ServiceResult containing health status and diagnostic information
        """
        pass


class ServiceFactory:
    """
    Service factory class for dependency injection and service lifecycle management.
    
    Provides centralized service creation, configuration, and dependency resolution
    supporting Flask application factory pattern integration with comprehensive
    service registry and dependency injection capabilities.
    """
    
    def __init__(self) -> None:
        """Initialize service factory with empty service registry."""
        self._services: Dict[Type[BaseService], BaseService] = {}
        self._configuration: Dict[str, Any] = {}
        self._logger = logging.getLogger(f"{__name__}.ServiceFactory")
    
    def register_service(self, service_class: Type[BaseService], 
                        session: Optional[DatabaseSession] = None) -> BaseService:
        """
        Register service instance with optional session injection.
        
        Args:
            service_class: Service class to instantiate and register
            session: Optional database session for dependency injection
            
        Returns:
            Configured service instance
            
        Raises:
            ServiceError: If service registration fails
        """
        try:
            # Create service instance with session injection
            if session:
                service_instance = service_class(db_session=session)
            else:
                service_instance = service_class()
            
            # Register service in registry
            self._services[service_class] = service_instance
            
            self._logger.info(f"Service {service_class.__name__} registered successfully")
            
            return service_instance
            
        except Exception as e:
            error_msg = f"Failed to register service {service_class.__name__}: {e}"
            self._logger.error(error_msg)
            raise ServiceError(error_msg, error_code="SERVICE_REGISTRATION_ERROR", cause=e)
    
    def get_service(self, service_class: Type[ServiceType]) -> ServiceType:
        """
        Retrieve registered service instance with type safety.
        
        Args:
            service_class: Service class to retrieve
            
        Returns:
            Configured service instance
            
        Raises:
            ServiceError: If service not found in registry
        """
        if service_class not in self._services:
            raise ServiceError(
                f"Service {service_class.__name__} not found in registry",
                error_code="SERVICE_NOT_FOUND"
            )
        
        return self._services[service_class]  # type: ignore
    
    def has_service(self, service_class: Type[BaseService]) -> bool:
        """
        Check if service is registered in factory.
        
        Args:
            service_class: Service class to check
            
        Returns:
            True if service is registered, False otherwise
        """
        return service_class in self._services
    
    def configure_services(self, configuration: Dict[str, Any]) -> None:
        """
        Apply configuration to all registered services.
        
        Args:
            configuration: Configuration dictionary for services
        """
        self._configuration.update(configuration)
        
        for service_instance in self._services.values():
            if hasattr(service_instance, 'configure'):
                service_instance.configure(configuration)
        
        self._logger.info("Service configuration applied to all registered services")
    
    def get_service_registry(self) -> Dict[str, Dict[str, Any]]:
        """
        Get comprehensive service registry information for monitoring.
        
        Returns:
            Dictionary containing service registry metadata and health information
        """
        registry_info = {
            'total_services': len(self._services),
            'registered_services': {},
            'configuration': self._configuration
        }
        
        for service_class, service_instance in self._services.items():
            registry_info['registered_services'][service_class.__name__] = {
                'class': service_class.__name__,
                'instance_id': id(service_instance),
                'performance_metrics': service_instance.get_performance_metrics()
            }
        
        return registry_info


# Global service factory instance for Flask application integration
service_factory = ServiceFactory()


def init_service_layer(app) -> None:
    """
    Initialize service layer for Flask application factory pattern.
    
    Configures service factory, database session management, and service
    registration for Flask application context integration.
    
    Args:
        app: Flask application instance
    """
    try:
        # Configure service factory with Flask application configuration
        service_config = {
            'database_uri': app.config.get('SQLALCHEMY_DATABASE_URI'),
            'enable_transaction_logging': app.config.get('SERVICE_TRANSACTION_LOGGING', True),
            'enable_performance_monitoring': app.config.get('SERVICE_PERFORMANCE_MONITORING', True),
            'query_timeout': app.config.get('SERVICE_QUERY_TIMEOUT', 30)
        }
        
        service_factory.configure_services(service_config)
        
        # Store service factory in Flask application instance
        app.service_factory = service_factory
        
        logger.info("Service layer initialized successfully for Flask application")
        
    except Exception as e:
        logger.error(f"Failed to initialize service layer: {e}")
        raise ServiceError(
            f"Service layer initialization failed: {e}",
            error_code="SERVICE_LAYER_INIT_ERROR",
            cause=e
        )


def get_service(service_class: Type[ServiceType]) -> ServiceType:
    """
    Get service instance from Flask application context.
    
    Convenience function for retrieving service instances within Flask
    request context with automatic service factory access.
    
    Args:
        service_class: Service class to retrieve
        
    Returns:
        Configured service instance
        
    Raises:
        RuntimeError: If called outside Flask application context
        ServiceError: If service not found or retrieval fails
    """
    if not has_app_context():
        raise RuntimeError("get_service() must be called within Flask application context")
    
    if not hasattr(current_app, 'service_factory'):
        raise ServiceError(
            "Service factory not initialized in Flask application",
            error_code="SERVICE_FACTORY_NOT_INITIALIZED"
        )
    
    return current_app.service_factory.get_service(service_class)


# Export all public classes and functions for service layer integration
__all__ = [
    # Base service classes
    'BaseService',
    'ServiceFactory',
    
    # Result and error types
    'ServiceResult',
    'ServiceError',
    'DatabaseError',
    'ValidationError',
    'NotFoundError',
    'TransactionStatus',
    
    # Protocol types for dependency injection
    'DatabaseSession',
    'ServiceRegistry',
    
    # Flask integration functions
    'init_service_layer',
    'get_service',
    'service_factory',
    
    # Type variables
    'T',
    'ModelType',
    'ServiceType'
]