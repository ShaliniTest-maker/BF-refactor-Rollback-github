"""
Service Package Initialization Module for Flask Application

This module provides centralized service registration, dependency injection configuration,
and service layer interface exports for the Flask 3.1.1 application migration from Node.js.
It establishes the Service Layer pattern foundation enabling organized service access,
dependency injection framework, and Flask application factory integration.

Key Features:
- Service Layer pattern implementation with Python classes in /services
- Flask application factory pattern integration per Section 6.1.5
- Dependency injection framework for SQLAlchemy session management
- Centralized service registration supporting Flask blueprint integration
- Service interface abstraction enabling comprehensive unit testing
- Service lifecycle management and configuration
- Type-safe service interfaces with comprehensive error handling

Architecture:
This implementation follows the Service Layer pattern as specified in Section 4.5.1.2
of the technical specification, providing clear separation between presentation, business
logic, and data access layers while maintaining Flask application factory compatibility.

Service Registry:
The service registry pattern enables Flask blueprints to access business logic services
through dependency injection, facilitating modular development and comprehensive testing
with Pytest fixtures and mock dependencies.
"""

from __future__ import annotations

import logging
from typing import (
    Dict, 
    Any, 
    Optional, 
    Type, 
    TypeVar, 
    Protocol,
    Union,
    Callable,
    runtime_checkable
)
from contextlib import contextmanager
from functools import wraps

from flask import Flask, current_app, g
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

# Import base service infrastructure
from .base_service import (
    BaseService,
    DatabaseSession,
    ServiceResult,
    ValidationResult,
    ServiceException,
    ValidationException,
    DatabaseException
)

# Import specific service implementations
from .auth_service import AuthService
from .user_service import UserService
from .validation_service import ValidationService

# Type variables for service management
ServiceType = TypeVar('ServiceType', bound=BaseService)


@runtime_checkable
class ServiceRegistry(Protocol):
    """
    Protocol defining the service registry interface for dependency injection.
    
    This protocol ensures type safety for service registration and retrieval
    while maintaining flexibility for testing with mock service implementations.
    """
    
    def register_service(
        self, 
        service_name: str, 
        service_class: Type[ServiceType],
        **kwargs: Any
    ) -> None:
        """Register a service class with optional configuration."""
        ...
    
    def get_service(self, service_name: str) -> ServiceType:
        """Retrieve a registered service instance."""
        ...
    
    def has_service(self, service_name: str) -> bool:
        """Check if a service is registered."""
        ...


class FlaskServiceRegistry:
    """
    Service registry implementation for Flask application factory pattern.
    
    This registry manages service lifecycle, dependency injection, and provides
    centralized access to business logic services throughout the Flask application.
    It supports both development and testing configurations with mock dependency
    injection capabilities.
    
    Features:
    - Centralized service registration and retrieval
    - SQLAlchemy session injection for all services
    - Flask application context integration
    - Service lifecycle management with proper cleanup
    - Mock service support for comprehensive testing
    - Type-safe service access with error handling
    
    Attributes:
        app: Flask application instance
        services: Dictionary of registered service instances
        service_classes: Dictionary of registered service classes
        session_factory: Factory function for database session creation
    """
    
    def __init__(self, app: Optional[Flask] = None) -> None:
        """
        Initialize service registry with optional Flask application.
        
        Args:
            app: Optional Flask application for immediate initialization
        """
        self.services: Dict[str, BaseService] = {}
        self.service_classes: Dict[str, Type[BaseService]] = {}
        self.session_factory: Optional[Callable[[], Session]] = None
        self._initialized = False
        
        # Initialize logger for service registry operations
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize service registry with Flask application factory pattern.
        
        This method configures the service registry for use with the Flask
        application, sets up database session factory, and registers core
        services required for application functionality.
        
        Args:
            app: Flask application instance
            
        Raises:
            ServiceException: If service registry initialization fails
        """
        try:
            self.app = app
            
            # Configure session factory from Flask-SQLAlchemy
            from flask_sqlalchemy import SQLAlchemy
            db = SQLAlchemy()
            db.init_app(app)
            
            # Set up session factory for dependency injection
            self.session_factory = lambda: db.session
            
            # Register core services with dependency injection
            self._register_core_services()
            
            # Set up Flask teardown handlers for proper cleanup
            app.teardown_appcontext(self._cleanup_services)
            
            # Store registry in Flask app for access from blueprints
            app.service_registry = self
            
            self._initialized = True
            self.logger.info("Service registry initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize service registry: {str(e)}")
            raise ServiceException(
                message=f"Service registry initialization failed: {str(e)}",
                error_code='REGISTRY_INIT_ERROR',
                details={'initialization_error': True}
            )
    
    def _register_core_services(self) -> None:
        """
        Register core business logic services with dependency injection.
        
        This method registers all essential services required for application
        functionality, including authentication, user management, validation,
        and other business logic services following the Service Layer pattern.
        
        Raises:
            ServiceException: If core service registration fails
        """
        try:
            # Register authentication service for session management
            self.register_service(
                'auth', 
                AuthService,
                description="Authentication and session management service"
            )
            
            # Register user management service for business logic
            self.register_service(
                'user', 
                UserService,
                description="User management and profile operations service"
            )
            
            # Register validation service for business rule enforcement
            self.register_service(
                'validation', 
                ValidationService,
                description="Input validation and business rule enforcement service"
            )
            
            self.logger.debug("Core services registered successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to register core services: {str(e)}")
            raise ServiceException(
                message=f"Core service registration failed: {str(e)}",
                error_code='CORE_SERVICE_ERROR',
                details={'service_registration_error': True}
            )
    
    def register_service(
        self, 
        service_name: str, 
        service_class: Type[BaseService],
        **kwargs: Any
    ) -> None:
        """
        Register a service class with the registry.
        
        This method registers a service class for later instantiation with
        dependency injection. Services are created on-demand with proper
        session management and configuration.
        
        Args:
            service_name: Unique identifier for the service
            service_class: Service class implementing BaseService
            **kwargs: Additional configuration for service initialization
            
        Raises:
            ServiceException: If service registration fails
            TypeError: If service_class doesn't inherit from BaseService
        """
        if not issubclass(service_class, BaseService):
            raise TypeError(
                f"Service class {service_class.__name__} must inherit from BaseService"
            )
        
        if service_name in self.service_classes:
            self.logger.warning(f"Overriding existing service registration: {service_name}")
        
        self.service_classes[service_name] = service_class
        
        # Store service configuration for instantiation
        setattr(self, f"_{service_name}_config", kwargs)
        
        self.logger.debug(
            f"Registered service '{service_name}' with class {service_class.__name__}"
        )
    
    def get_service(self, service_name: str) -> BaseService:
        """
        Retrieve a service instance with dependency injection.
        
        This method provides lazy instantiation of services with proper
        SQLAlchemy session injection and configuration. Services are
        cached per request context for efficient resource utilization.
        
        Args:
            service_name: Name of the service to retrieve
            
        Returns:
            BaseService: Configured service instance with injected dependencies
            
        Raises:
            ServiceException: If service is not registered or instantiation fails
        """
        if not self._initialized:
            raise ServiceException(
                message="Service registry not initialized",
                error_code='REGISTRY_NOT_INITIALIZED'
            )
        
        if service_name not in self.service_classes:
            raise ServiceException(
                message=f"Service '{service_name}' not registered",
                error_code='SERVICE_NOT_FOUND',
                details={'available_services': list(self.service_classes.keys())}
            )
        
        # Check for cached service instance in Flask request context
        if not hasattr(g, 'services'):
            g.services = {}
        
        if service_name in g.services:
            return g.services[service_name]
        
        try:
            # Get service class and configuration
            service_class = self.service_classes[service_name]
            config = getattr(self, f"_{service_name}_config", {})
            
            # Create database session for dependency injection
            if self.session_factory is None:
                raise ServiceException(
                    message="Session factory not configured",
                    error_code='SESSION_FACTORY_ERROR'
                )
            
            db_session = self.session_factory()
            
            # Instantiate service with dependency injection
            service_instance = service_class(db_session=db_session, **config)
            
            # Cache service instance in request context
            g.services[service_name] = service_instance
            
            self.logger.debug(f"Created service instance: {service_name}")
            return service_instance
            
        except Exception as e:
            self.logger.error(f"Failed to create service '{service_name}': {str(e)}")
            raise ServiceException(
                message=f"Service instantiation failed: {str(e)}",
                error_code='SERVICE_INSTANTIATION_ERROR',
                details={'service_name': service_name, 'error': str(e)}
            )
    
    def has_service(self, service_name: str) -> bool:
        """
        Check if a service is registered in the registry.
        
        Args:
            service_name: Name of the service to check
            
        Returns:
            bool: True if service is registered, False otherwise
        """
        return service_name in self.service_classes
    
    def list_services(self) -> Dict[str, str]:
        """
        Get a dictionary of registered services with their class names.
        
        Returns:
            Dict[str, str]: Mapping of service names to class names
        """
        return {
            name: cls.__name__ 
            for name, cls in self.service_classes.items()
        }
    
    def _cleanup_services(self, exception: Optional[Exception] = None) -> None:
        """
        Clean up services at the end of request context.
        
        This method ensures proper resource cleanup, including database
        session management and service state reset for the next request.
        
        Args:
            exception: Optional exception that triggered cleanup
        """
        if hasattr(g, 'services'):
            for service_name, service_instance in g.services.items():
                try:
                    # Perform service-specific cleanup if available
                    if hasattr(service_instance, 'cleanup'):
                        service_instance.cleanup()
                        
                    self.logger.debug(f"Cleaned up service: {service_name}")
                    
                except Exception as cleanup_error:
                    self.logger.error(
                        f"Error cleaning up service '{service_name}': {str(cleanup_error)}"
                    )
            
            # Clear service cache
            g.services.clear()


# Global service registry instance for application-wide access
service_registry = FlaskServiceRegistry()


def get_service(service_name: str) -> BaseService:
    """
    Convenience function to get a service instance from the global registry.
    
    This function provides easy access to services from Flask blueprints
    and other application components without direct registry access.
    
    Args:
        service_name: Name of the service to retrieve
        
    Returns:
        BaseService: Configured service instance
        
    Raises:
        ServiceException: If service is not available
        
    Example:
        ```python
        from services import get_service
        
        # In a Flask blueprint
        @blueprint.route('/users')
        def get_users():
            user_service = get_service('user')
            return user_service.get_all_users()
        ```
    """
    if current_app and hasattr(current_app, 'service_registry'):
        return current_app.service_registry.get_service(service_name)
    else:
        return service_registry.get_service(service_name)


def with_service(service_name: str):
    """
    Decorator for injecting services into Flask route handlers.
    
    This decorator provides clean dependency injection for Flask blueprints,
    automatically providing the requested service as a function parameter.
    
    Args:
        service_name: Name of the service to inject
        
    Returns:
        Decorator function that injects the service
        
    Raises:
        ServiceException: If service injection fails
        
    Example:
        ```python
        from services import with_service
        
        @blueprint.route('/users/<int:user_id>')
        @with_service('user')
        def get_user(user_id: int, user_service):
            return user_service.get_user_by_id(user_id)
        ```
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                service_instance = get_service(service_name)
                return func(*args, **kwargs, **{f"{service_name}_service": service_instance})
            except Exception as e:
                logger = logging.getLogger(__name__)
                logger.error(f"Service injection failed for '{service_name}': {str(e)}")
                raise ServiceException(
                    message=f"Service injection failed: {str(e)}",
                    error_code='SERVICE_INJECTION_ERROR',
                    details={'service_name': service_name}
                )
        return wrapper
    return decorator


@contextmanager
def service_transaction(*service_names: str):
    """
    Context manager for coordinating transactions across multiple services.
    
    This context manager ensures consistent transaction boundaries when
    operations span multiple services, providing atomic operations with
    proper rollback capabilities on any failure.
    
    Args:
        *service_names: Names of services to include in transaction
        
    Yields:
        Dict[str, BaseService]: Dictionary of service instances
        
    Raises:
        ServiceException: If transaction coordination fails
        
    Example:
        ```python
        from services import service_transaction
        
        with service_transaction('user', 'auth') as services:
            user_service = services['user']
            auth_service = services['auth']
            
            # Operations within shared transaction boundary
            user_service.create_user(user_data)
            auth_service.setup_user_auth(user_id, auth_data)
            # Automatically committed on success or rolled back on failure
        ```
    """
    services = {}
    
    try:
        # Get all requested services
        for service_name in service_names:
            services[service_name] = get_service(service_name)
        
        # Start transaction context for all services
        with services[list(services.keys())[0]].transaction():
            yield services
            
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Service transaction failed: {str(e)}")
        raise ServiceException(
            message=f"Service transaction failed: {str(e)}",
            error_code='SERVICE_TRANSACTION_ERROR',
            details={'services': list(service_names)}
        )


# Export all public interfaces for package access
__all__ = [
    # Core service classes
    'BaseService',
    'AuthService', 
    'UserService',
    'ValidationService',
    
    # Service registry and management
    'FlaskServiceRegistry',
    'service_registry',
    'get_service',
    'with_service',
    'service_transaction',
    
    # Service infrastructure
    'ServiceRegistry',
    'DatabaseSession',
    'ServiceResult',
    'ValidationResult',
    
    # Exception classes
    'ServiceException',
    'ValidationException',
    'DatabaseException'
]


# Package-level configuration and initialization
def init_services(app: Flask) -> None:
    """
    Initialize the service layer for Flask application factory pattern.
    
    This function should be called from the Flask application factory to
    set up the service layer with proper dependency injection and configuration.
    
    Args:
        app: Flask application instance
        
    Example:
        ```python
        from services import init_services
        
        def create_app():
            app = Flask(__name__)
            init_services(app)
            return app
        ```
    """
    service_registry.init_app(app)
    
    logger = logging.getLogger(__name__)
    logger.info("Service layer initialized for Flask application")


# Service Layer Pattern validation
def validate_service_layer() -> bool:
    """
    Validate service layer configuration and dependencies.
    
    This function performs comprehensive validation of the service layer
    setup, including dependency availability, configuration consistency,
    and interface compliance.
    
    Returns:
        bool: True if service layer is properly configured
        
    Raises:
        ServiceException: If validation fails
    """
    try:
        # Validate core service registrations
        required_services = ['auth', 'user', 'validation']
        
        for service_name in required_services:
            if not service_registry.has_service(service_name):
                raise ServiceException(
                    message=f"Required service '{service_name}' not registered",
                    error_code='SERVICE_VALIDATION_ERROR'
                )
        
        # Validate service class inheritance
        for service_name, service_class in service_registry.service_classes.items():
            if not issubclass(service_class, BaseService):
                raise ServiceException(
                    message=f"Service '{service_name}' doesn't inherit from BaseService",
                    error_code='SERVICE_INHERITANCE_ERROR'
                )
        
        logger = logging.getLogger(__name__)
        logger.debug("Service layer validation completed successfully")
        return True
        
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Service layer validation failed: {str(e)}")
        raise ServiceException(
            message=f"Service layer validation failed: {str(e)}",
            error_code='SERVICE_LAYER_VALIDATION_ERROR'
        )