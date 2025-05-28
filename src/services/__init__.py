"""
Services Module Package Initialization

This module establishes the Service Layer pattern namespace for the Flask application,
providing centralized imports and dependency injection integration for all business
logic orchestration components. The Service Layer pattern enables clean architectural
separation between presentation layer (blueprints), business logic layer (services),
and data access layer (models).

Key Features:
- Service Layer architectural pattern implementation per Section 5.2.3
- Flask-Injector dependency injection architecture per Section 4.5.1
- Flask application factory pattern integration per Section 5.1.1
- Business logic preservation during Node.js to Flask migration per Feature F-005
- Python 3.13.3 package structure with proper initialization per Section 4.5.1

Architecture:
The services module provides the business logic abstraction layer that orchestrates
complex workflows and use cases, enabling efficient testing of both domain models
and complete workflow implementations. Service classes coordinate between Flask
blueprints for presentation logic and Flask-SQLAlchemy models for data persistence,
ensuring transaction boundary management and data consistency.

Integration Points:
- Flask blueprints: Service layer interfaces for business operation exposure
- Database models: Coordination for data persistence and transaction management
- External services: Integration points for third-party system communication
- Authentication: Session management and user context coordination

Migration Context:
This module maintains functional equivalence with original Node.js business logic
while implementing enhanced Python-specific patterns including dataclasses, type
hints, and dependency injection for improved maintainability and testability.
"""

import logging
from typing import Dict, Type, Optional, Any
from flask import Flask
from flask_injector import FlaskInjector
from injector import Injector, singleton

# Import all service classes for centralized access
from .base import BaseService
from .user_service import UserService  
from .business_entity_service import BusinessEntityService
from .validation_service import ValidationService
from .workflow_orchestrator import WorkflowOrchestrator

# Configure logging for service layer operations
logger = logging.getLogger(__name__)

# Public API exports for the services package
__all__ = [
    'BaseService',
    'UserService', 
    'BusinessEntityService',
    'ValidationService',
    'WorkflowOrchestrator',
    'ServiceRegistry',
    'configure_services',
    'get_service',
    'register_services_with_app'
]

# Version information for API compatibility tracking
__version__ = '1.0.0'

# Service registry for centralized service management and discovery
class ServiceRegistry:
    """
    Centralized service registry implementing dependency injection patterns
    for Flask-Injector integration and service discovery capabilities.
    
    This registry maintains service instances and provides controlled access
    to business logic components throughout the application lifecycle,
    supporting the Flask application factory pattern integration.
    """
    
    def __init__(self):
        """Initialize the service registry with empty service mapping."""
        self._services: Dict[str, Type[BaseService]] = {}
        self._injector: Optional[Injector] = None
        self._configured: bool = False
        
    def register_service(self, name: str, service_class: Type[BaseService]) -> None:
        """
        Register a service class with the registry for dependency injection.
        
        Args:
            name (str): Service identifier for registry lookup
            service_class (Type[BaseService]): Service class implementing BaseService
            
        Raises:
            ValueError: If service name already registered or invalid service class
        """
        if name in self._services:
            raise ValueError(f"Service '{name}' is already registered")
            
        if not issubclass(service_class, BaseService):
            raise ValueError(f"Service class must inherit from BaseService")
            
        self._services[name] = service_class
        logger.info(f"Registered service: {name} -> {service_class.__name__}")
        
    def get_service(self, name: str) -> Optional[Type[BaseService]]:
        """
        Retrieve a registered service class by name.
        
        Args:
            name (str): Service identifier for registry lookup
            
        Returns:
            Optional[Type[BaseService]]: Service class if found, None otherwise
        """
        return self._services.get(name)
        
    def list_services(self) -> Dict[str, Type[BaseService]]:
        """
        Get all registered services for introspection and debugging.
        
        Returns:
            Dict[str, Type[BaseService]]: Mapping of service names to classes
        """
        return self._services.copy()
        
    def configure_injector(self, injector: Injector) -> None:
        """
        Configure the service registry with Flask-Injector instance.
        
        Args:
            injector (Injector): Configured injector for dependency resolution
        """
        self._injector = injector
        self._configured = True
        logger.info("Service registry configured with Flask-Injector")
        
    @property
    def is_configured(self) -> bool:
        """Check if the service registry has been configured with injector."""
        return self._configured
        
    def get_injector(self) -> Optional[Injector]:
        """Get the configured injector instance."""
        return self._injector

# Global service registry instance for application-wide access
_service_registry = ServiceRegistry()

def configure_services(app: Flask) -> ServiceRegistry:
    """
    Configure the service layer with Flask application factory pattern integration.
    
    This function establishes the Service Layer pattern by registering all business
    logic services with Flask-Injector for dependency injection and configuring
    the service registry for centralized service management throughout the
    application lifecycle.
    
    Args:
        app (Flask): Flask application instance from application factory
        
    Returns:
        ServiceRegistry: Configured service registry for service discovery
        
    Example:
        ```python
        from flask import Flask
        from src.services import configure_services
        
        def create_app():
            app = Flask(__name__)
            service_registry = configure_services(app)
            return app
        ```
    """
    logger.info("Configuring service layer for Flask application")
    
    # Register all service classes with the service registry
    _service_registry.register_service('base', BaseService)
    _service_registry.register_service('user', UserService)
    _service_registry.register_service('business_entity', BusinessEntityService)  
    _service_registry.register_service('validation', ValidationService)
    _service_registry.register_service('workflow', WorkflowOrchestrator)
    
    # Configure dependency injection bindings for Flask-Injector
    def configure_dependencies(binder):
        """
        Configure dependency injection bindings for service layer components.
        
        This configuration enables clean separation of business logic dependencies
        and enhanced unit testing through mock object injection, supporting both
        development and production environments per Section 4.5.1 requirements.
        """
        # Bind service classes as singletons for application-wide access
        binder.bind(BaseService, to=BaseService, scope=singleton)
        binder.bind(UserService, to=UserService, scope=singleton)
        binder.bind(BusinessEntityService, to=BusinessEntityService, scope=singleton)
        binder.bind(ValidationService, to=ValidationService, scope=singleton)
        binder.bind(WorkflowOrchestrator, to=WorkflowOrchestrator, scope=singleton)
        
        logger.debug("Configured dependency injection bindings for service layer")
    
    # Initialize Flask-Injector with the Flask application
    try:
        flask_injector = FlaskInjector(app=app, modules=[configure_dependencies])
        _service_registry.configure_injector(flask_injector.injector)
        
        logger.info("Successfully configured Flask-Injector for service layer")
        
    except Exception as e:
        logger.error(f"Failed to configure Flask-Injector: {str(e)}")
        raise RuntimeError(f"Service layer configuration failed: {str(e)}")
    
    # Store service registry in Flask application context for blueprint access
    app.extensions['service_registry'] = _service_registry
    
    logger.info("Service layer configuration complete")
    return _service_registry

def get_service(service_name: str, app: Optional[Flask] = None) -> Optional[Any]:
    """
    Retrieve a service instance from the configured service registry.
    
    This function provides service discovery capabilities for Flask blueprints
    and other application components, enabling clean access to business logic
    services through the dependency injection architecture.
    
    Args:
        service_name (str): Name of the service to retrieve
        app (Optional[Flask]): Flask application instance for context
        
    Returns:
        Optional[Any]: Service instance if found and configured, None otherwise
        
    Example:
        ```python
        from src.services import get_service
        
        user_service = get_service('user')
        if user_service:
            user = user_service.create_user(user_data)
        ```
    """
    try:
        # Use provided app or get from current Flask context
        if app is None:
            from flask import current_app
            app = current_app
            
        # Get service registry from Flask application extensions
        registry = app.extensions.get('service_registry', _service_registry)
        
        if not registry.is_configured:
            logger.warning("Service registry not configured with injector")
            return None
            
        # Retrieve service class from registry
        service_class = registry.get_service(service_name)
        if service_class is None:
            logger.warning(f"Service '{service_name}' not found in registry")
            return None
            
        # Get service instance from injector
        injector = registry.get_injector()
        if injector is None:
            logger.error("No injector configured for service retrieval")
            return None
            
        service_instance = injector.get(service_class)
        logger.debug(f"Retrieved service instance: {service_name}")
        return service_instance
        
    except Exception as e:
        logger.error(f"Failed to retrieve service '{service_name}': {str(e)}")
        return None

def register_services_with_app(app: Flask) -> None:
    """
    Register service layer with Flask application factory pattern.
    
    This function provides a streamlined interface for integrating the service
    layer with Flask application initialization, supporting the application
    factory pattern requirements per Section 5.1.1.
    
    Args:
        app (Flask): Flask application instance from application factory
        
    Example:
        ```python
        from flask import Flask
        from src.services import register_services_with_app
        
        def create_app():
            app = Flask(__name__)
            register_services_with_app(app)
            return app
        ```
    """
    try:
        # Configure the complete service layer
        service_registry = configure_services(app)
        
        # Add service access helper to application context
        @app.context_processor
        def inject_services():
            """Inject service access function into template context."""
            return {'get_service': lambda name: get_service(name, app)}
        
        logger.info("Service layer successfully registered with Flask application")
        
    except Exception as e:
        logger.error(f"Failed to register services with Flask app: {str(e)}")
        raise RuntimeError(f"Service registration failed: {str(e)}")

# Package initialization logging
logger.info(f"Services package initialized (version {__version__})")
logger.debug(f"Available services: {', '.join(__all__)}")