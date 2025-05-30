"""
Service Layer Package Initialization

This module provides centralized service registration, dependency injection configuration,
and service layer interface exports for the Flask 3.1.1 application. It establishes
the service layer foundation for Flask application integration and enables organized
service access throughout the application.

The service layer implements the Service Layer pattern as specified in Section 4.5.1.2,
providing business logic abstraction with clear separation of concerns, enhanced testability
through dependency injection, and comprehensive integration with Flask's application
factory pattern per Section 6.1.5.

Key Features:
- Centralized service registration supporting Flask blueprint integration per Section 5.2.2
- Dependency injection framework for SQLAlchemy session management per Section 4.5.1.2
- Service interface abstraction enabling comprehensive unit testing per Section 4.5.1.4
- Flask application factory pattern integration per Section 6.1.5
- Type-safe service access with comprehensive error handling
- Service discovery and lifecycle management
- Performance monitoring and health check capabilities

Architecture Benefits:
- Clear separation between presentation layer (blueprints) and business logic (services)
- Enhanced testability through dependency injection and service mocking
- Centralized service configuration and lifecycle management
- Type-safe service interfaces with comprehensive static analysis support
- Streamlined integration with Flask application factory pattern
- Service registry pattern enabling dynamic service discovery and resolution

Dependencies:
- Flask 3.1.1: Web framework integration and application context
- Flask-SQLAlchemy 3.1.1: Database ORM and session management
- typing: Comprehensive type annotations for enhanced code clarity
- Base service classes: Foundation for service layer implementation
"""

import logging
from typing import (
    Dict, List, Optional, Type, TypeVar, Any, Union, Protocol,
    runtime_checkable, ContextManager
)
from dataclasses import dataclass
from datetime import datetime, timezone

from flask import Flask, current_app, has_app_context

# Import base service layer components
from .base_service import (
    BaseService,
    ServiceFactory,
    ServiceResult,
    ServiceError,
    DatabaseError,
    ValidationError,
    NotFoundError,
    TransactionStatus,
    DatabaseSession,
    ServiceRegistry,
    init_service_layer as _init_service_layer,
    get_service as _get_service,
    service_factory as _service_factory,
    T,
    ModelType,
    ServiceType
)

# Import concrete service implementations
from .auth_service import AuthService
from .user_service import UserService
from .validation_service import ValidationService

# Configure logging for service layer package
logger = logging.getLogger(__name__)

# Type alias for service class registration
ServiceClass = TypeVar('ServiceClass', bound=BaseService)


@dataclass
class ServiceRegistrationInfo:
    """
    Service registration metadata for comprehensive service discovery.
    
    Provides detailed information about registered services including
    dependencies, registration timestamp, and health status for
    monitoring and debugging purposes.
    """
    
    service_name: str
    service_class: Type[BaseService]
    dependencies: List[str]
    registration_time: datetime
    is_healthy: bool = True
    last_health_check: Optional[datetime] = None
    configuration: Dict[str, Any] = None
    
    def __post_init__(self) -> None:
        """Initialize default values after creation."""
        if self.configuration is None:
            self.configuration = {}


@runtime_checkable
class ServiceProvider(Protocol):
    """
    Protocol defining service provider interface for dependency injection.
    
    Enables service discovery and resolution within Flask application context
    while maintaining type safety and clear interface contracts for testing.
    """
    
    def register_service(self, service_class: Type[ServiceClass]) -> ServiceClass:
        """Register service class and return configured instance."""
        ...
    
    def get_service(self, service_class: Type[ServiceClass]) -> ServiceClass:
        """Retrieve registered service instance with type safety."""
        ...
    
    def has_service(self, service_class: Type[ServiceClass]) -> bool:
        """Check if service is registered in provider."""
        ...
    
    def get_all_services(self) -> Dict[str, BaseService]:
        """Get all registered services for monitoring purposes."""
        ...


class ServiceManager:
    """
    Centralized service management providing registration, configuration,
    and lifecycle management for all application services.
    
    The ServiceManager implements the service registry pattern enabling
    comprehensive service discovery, dependency injection, and health
    monitoring throughout the Flask application lifecycle.
    
    Key Features:
    - Automatic service registration with dependency resolution
    - Service health monitoring and performance tracking
    - Configuration management for environment-specific settings
    - Integration with Flask application factory pattern
    - Comprehensive error handling and fallback mechanisms
    - Type-safe service access with static analysis support
    """
    
    def __init__(self) -> None:
        """Initialize service manager with empty registry."""
        self._service_registry: Dict[Type[BaseService], ServiceRegistrationInfo] = {}
        self._service_instances: Dict[Type[BaseService], BaseService] = {}
        self._service_factory = _service_factory
        self._initialization_time = datetime.now(timezone.utc)
        self._logger = logging.getLogger(f"{__name__}.ServiceManager")
        
        # Service configuration defaults
        self._default_config = {
            'enable_health_checks': True,
            'health_check_interval': 300,  # 5 minutes
            'enable_performance_monitoring': True,
            'auto_register_services': True
        }
        
        self._logger.info("ServiceManager initialized successfully")
    
    def register_core_services(self, db_session: Optional[DatabaseSession] = None) -> None:
        """
        Register all core application services with optional session injection.
        
        Performs automatic registration of all essential services required
        for application functionality including authentication, user management,
        and validation services with proper dependency resolution.
        
        Args:
            db_session: Optional database session for dependency injection
                       If None, services will use Flask-SQLAlchemy session
                       
        Raises:
            ServiceError: If service registration fails
        """
        try:
            # Define core services with their dependencies
            core_services = [
                (AuthService, ['models', 'config']),
                (UserService, ['base_service', 'auth_service', 'models']),
                (ValidationService, ['base_service'])
            ]
            
            # Register services in dependency order
            for service_class, dependencies in core_services:
                self._register_service_with_dependencies(
                    service_class, 
                    dependencies, 
                    db_session
                )
            
            self._logger.info(f"Registered {len(core_services)} core services successfully")
            
        except Exception as e:
            error_msg = f"Failed to register core services: {e}"
            self._logger.error(error_msg)
            raise ServiceError(error_msg, error_code="CORE_SERVICE_REGISTRATION_ERROR", cause=e)
    
    def _register_service_with_dependencies(
        self, 
        service_class: Type[ServiceClass], 
        dependencies: List[str],
        db_session: Optional[DatabaseSession] = None
    ) -> ServiceClass:
        """
        Register individual service with dependency validation and resolution.
        
        Args:
            service_class: Service class to register
            dependencies: List of dependency identifiers
            db_session: Optional database session for injection
            
        Returns:
            Configured service instance
            
        Raises:
            ServiceError: If service registration or dependency resolution fails
        """
        try:
            # Check if service already registered
            if service_class in self._service_instances:
                self._logger.debug(f"Service {service_class.__name__} already registered")
                return self._service_instances[service_class]
            
            # Register service using service factory
            service_instance = self._service_factory.register_service(service_class, db_session)
            
            # Create registration metadata
            registration_info = ServiceRegistrationInfo(
                service_name=service_class.__name__,
                service_class=service_class,
                dependencies=dependencies,
                registration_time=datetime.now(timezone.utc),
                configuration=self._default_config.copy()
            )
            
            # Store registration information
            self._service_registry[service_class] = registration_info
            self._service_instances[service_class] = service_instance
            
            self._logger.info(f"Service {service_class.__name__} registered with dependencies: {dependencies}")
            
            return service_instance
            
        except Exception as e:
            error_msg = f"Failed to register service {service_class.__name__}: {e}"
            self._logger.error(error_msg)
            raise ServiceError(error_msg, error_code="SERVICE_REGISTRATION_ERROR", cause=e)
    
    def get_service(self, service_class: Type[ServiceClass]) -> ServiceClass:
        """
        Retrieve registered service instance with comprehensive error handling.
        
        Args:
            service_class: Service class to retrieve
            
        Returns:
            Configured service instance
            
        Raises:
            ServiceError: If service not found or retrieval fails
        """
        if service_class not in self._service_instances:
            raise ServiceError(
                f"Service {service_class.__name__} not registered in service manager",
                error_code="SERVICE_NOT_REGISTERED"
            )
        
        service_instance = self._service_instances[service_class]
        
        # Perform optional health check before returning service
        if self._should_perform_health_check(service_class):
            self._perform_service_health_check(service_class)
        
        return service_instance  # type: ignore
    
    def has_service(self, service_class: Type[BaseService]) -> bool:
        """
        Check if service is registered in manager.
        
        Args:
            service_class: Service class to check
            
        Returns:
            True if service is registered, False otherwise
        """
        return service_class in self._service_instances
    
    def get_all_services(self) -> Dict[str, BaseService]:
        """
        Get all registered services for monitoring and management purposes.
        
        Returns:
            Dictionary mapping service names to service instances
        """
        return {
            service_class.__name__: service_instance
            for service_class, service_instance in self._service_instances.items()
        }
    
    def get_service_registry(self) -> Dict[str, Dict[str, Any]]:
        """
        Get comprehensive service registry information for monitoring.
        
        Returns:
            Dictionary containing complete service registry metadata
        """
        registry_info = {
            'manager_initialization_time': self._initialization_time.isoformat(),
            'total_registered_services': len(self._service_registry),
            'services': {},
            'factory_info': self._service_factory.get_service_registry()
        }
        
        for service_class, registration_info in self._service_registry.items():
            service_instance = self._service_instances[service_class]
            
            registry_info['services'][service_class.__name__] = {
                'service_name': registration_info.service_name,
                'dependencies': registration_info.dependencies,
                'registration_time': registration_info.registration_time.isoformat(),
                'is_healthy': registration_info.is_healthy,
                'last_health_check': registration_info.last_health_check.isoformat() if registration_info.last_health_check else None,
                'configuration': registration_info.configuration,
                'performance_metrics': service_instance.get_performance_metrics()
            }
        
        return registry_info
    
    def _should_perform_health_check(self, service_class: Type[BaseService]) -> bool:
        """
        Determine if health check should be performed for service.
        
        Args:
            service_class: Service class to check
            
        Returns:
            True if health check should be performed, False otherwise
        """
        if service_class not in self._service_registry:
            return False
        
        registration_info = self._service_registry[service_class]
        
        if not registration_info.configuration.get('enable_health_checks', True):
            return False
        
        # Check if health check interval has passed
        if registration_info.last_health_check is None:
            return True
        
        health_check_interval = registration_info.configuration.get('health_check_interval', 300)
        time_since_last_check = (datetime.now(timezone.utc) - registration_info.last_health_check).total_seconds()
        
        return time_since_last_check >= health_check_interval
    
    def _perform_service_health_check(self, service_class: Type[BaseService]) -> None:
        """
        Perform health check for specified service.
        
        Args:
            service_class: Service class to health check
        """
        try:
            service_instance = self._service_instances[service_class]
            health_result = service_instance.health_check()
            
            # Update registration info with health check results
            registration_info = self._service_registry[service_class]
            registration_info.is_healthy = health_result.success
            registration_info.last_health_check = datetime.now(timezone.utc)
            
            if not health_result.success:
                self._logger.warning(
                    f"Health check failed for service {service_class.__name__}: {health_result.error}"
                )
            else:
                self._logger.debug(f"Health check passed for service {service_class.__name__}")
                
        except Exception as e:
            self._logger.error(f"Health check error for service {service_class.__name__}: {e}")
            
            # Mark service as unhealthy on health check failure
            if service_class in self._service_registry:
                self._service_registry[service_class].is_healthy = False
                self._service_registry[service_class].last_health_check = datetime.now(timezone.utc)
    
    def configure_services(self, configuration: Dict[str, Any]) -> None:
        """
        Apply configuration to all registered services.
        
        Args:
            configuration: Configuration dictionary for services
        """
        try:
            # Update default configuration
            self._default_config.update(configuration)
            
            # Apply configuration to service factory
            self._service_factory.configure_services(configuration)
            
            # Update individual service configurations
            for registration_info in self._service_registry.values():
                registration_info.configuration.update(configuration)
            
            self._logger.info("Configuration applied to all registered services")
            
        except Exception as e:
            self._logger.error(f"Failed to configure services: {e}")
            raise ServiceError(
                f"Service configuration failed: {e}",
                error_code="SERVICE_CONFIGURATION_ERROR",
                cause=e
            )
    
    def perform_health_checks(self) -> Dict[str, bool]:
        """
        Perform health checks for all registered services.
        
        Returns:
            Dictionary mapping service names to health status
        """
        health_status = {}
        
        for service_class in self._service_instances:
            try:
                self._perform_service_health_check(service_class)
                health_status[service_class.__name__] = self._service_registry[service_class].is_healthy
            except Exception as e:
                self._logger.error(f"Health check failed for {service_class.__name__}: {e}")
                health_status[service_class.__name__] = False
        
        return health_status


# Global service manager instance for application-wide service access
service_manager = ServiceManager()


def init_services(app: Flask, db_session: Optional[DatabaseSession] = None) -> None:
    """
    Initialize service layer for Flask application factory pattern integration.
    
    Configures service manager, registers core services, and establishes
    service layer integration with Flask application context per Section 6.1.5.
    
    Args:
        app: Flask application instance
        db_session: Optional database session for dependency injection
                   If None, services will use Flask-SQLAlchemy session
                   
    Raises:
        ServiceError: If service initialization fails
    """
    try:
        # Initialize base service layer
        _init_service_layer(app)
        
        # Configure service manager with Flask application settings
        service_config = {
            'enable_health_checks': app.config.get('SERVICE_HEALTH_CHECKS', True),
            'health_check_interval': app.config.get('SERVICE_HEALTH_CHECK_INTERVAL', 300),
            'enable_performance_monitoring': app.config.get('SERVICE_PERFORMANCE_MONITORING', True),
            'auto_register_services': app.config.get('SERVICE_AUTO_REGISTER', True)
        }
        
        service_manager.configure_services(service_config)
        
        # Register core application services
        if service_config.get('auto_register_services', True):
            service_manager.register_core_services(db_session)
        
        # Store service manager in Flask application instance
        app.service_manager = service_manager
        
        logger.info("Service layer initialized successfully for Flask application")
        
    except Exception as e:
        error_msg = f"Service layer initialization failed: {e}"
        logger.error(error_msg)
        raise ServiceError(error_msg, error_code="SERVICE_LAYER_INIT_ERROR", cause=e)


def get_service(service_class: Type[ServiceClass]) -> ServiceClass:
    """
    Get service instance from Flask application context with comprehensive error handling.
    
    Convenience function for retrieving service instances within Flask request context
    with automatic service manager access and fallback to service factory.
    
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
    
    # Try service manager first (preferred method)
    if hasattr(current_app, 'service_manager'):
        try:
            return current_app.service_manager.get_service(service_class)
        except ServiceError:
            # Fall back to service factory if service manager fails
            logger.warning(f"Service manager failed for {service_class.__name__}, falling back to service factory")
    
    # Fallback to base service layer get_service function
    return _get_service(service_class)


def get_all_services() -> Dict[str, BaseService]:
    """
    Get all registered services from Flask application context.
    
    Returns:
        Dictionary mapping service names to service instances
        
    Raises:
        RuntimeError: If called outside Flask application context
    """
    if not has_app_context():
        raise RuntimeError("get_all_services() must be called within Flask application context")
    
    if hasattr(current_app, 'service_manager'):
        return current_app.service_manager.get_all_services()
    
    # Fallback to service factory
    factory_registry = _service_factory.get_service_registry()
    return factory_registry.get('registered_services', {})


def get_service_health() -> Dict[str, bool]:
    """
    Get health status for all registered services.
    
    Returns:
        Dictionary mapping service names to health status
        
    Raises:
        RuntimeError: If called outside Flask application context
    """
    if not has_app_context():
        raise RuntimeError("get_service_health() must be called within Flask application context")
    
    if hasattr(current_app, 'service_manager'):
        return current_app.service_manager.perform_health_checks()
    
    # Fallback: assume all services are healthy if no manager available
    logger.warning("Service manager not available, returning optimistic health status")
    return {}


# Export all public classes and functions for service layer integration
__all__ = [
    # Core service classes
    'AuthService',
    'UserService', 
    'ValidationService',
    
    # Base service layer components
    'BaseService',
    'ServiceFactory',
    'ServiceManager',
    'ServiceProvider',
    
    # Result and error types
    'ServiceResult',
    'ServiceError',
    'DatabaseError',
    'ValidationError',
    'NotFoundError',
    'TransactionStatus',
    
    # Registration and metadata types
    'ServiceRegistrationInfo',
    
    # Protocol types for dependency injection
    'DatabaseSession',
    'ServiceRegistry',
    
    # Flask integration functions
    'init_services',
    'get_service',
    'get_all_services',
    'get_service_health',
    
    # Global instances
    'service_manager',
    
    # Type variables for type safety
    'T',
    'ModelType',
    'ServiceType',
    'ServiceClass'
]