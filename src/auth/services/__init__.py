"""
Authentication Services Package Initialization Module

This module establishes the services package namespace and provides centralized imports 
for all Service Layer authentication components. Implements the Service Layer architectural 
pattern per Section 6.1.3 for authentication business logic orchestration and workflow 
coordination while integrating with Flask application factory pattern for systematic 
service registration and dependency injection.

The services package contains the core authentication business logic components that 
coordinate authentication workflows, manage user lifecycle operations, enforce security 
policies, and provide integration coordination between external services and Flask 
application modules.

Architecture Pattern: Service Layer with Flask Application Factory Integration
Python Version: 3.13.3
Flask Version: 3.1.1

Dependencies:
    - Flask 3.1.1 for application factory pattern integration
    - Python 3.13.3 for enhanced runtime performance and security features
    - Service Layer components for business logic orchestration

Module Structure:
    - AuthenticationService: Core authentication workflow orchestration
    - UserLifecycleService: User account lifecycle management operations
    - SecurityPolicyService: Security policy enforcement and threat detection
    - IntegrationCoordinationService: Cross-component integration coordination
"""

import logging
from typing import Dict, Any, Optional, Type, List
from functools import lru_cache
from flask import Flask

# Configure structured logging for service coordination
logger = logging.getLogger(__name__)

# Service Layer Pattern Implementation - Core Service Imports
# These imports enable centralized service discovery and Flask application factory integration
try:
    from .authentication_service import AuthenticationService
    from .user_lifecycle_service import UserLifecycleService  
    from .security_policy_service import SecurityPolicyService
    from .integration_coordination_service import IntegrationCoordinationService
    
    logger.info("Authentication services imported successfully")
    
except ImportError as e:
    logger.error(f"Failed to import authentication services: {e}")
    # Graceful degradation - define placeholder services for development
    AuthenticationService = None
    UserLifecycleService = None
    SecurityPolicyService = None
    IntegrationCoordinationService = None


# Service Registry for Dependency Injection Pattern
# Implements service registration and coordination per Section 6.1.3
class AuthenticationServiceRegistry:
    """
    Service registry implementing dependency injection pattern for authentication services.
    
    Provides centralized service registration, dependency resolution, and lifecycle 
    management for all authentication Service Layer components. Integrates with Flask 
    application factory pattern to ensure systematic service initialization and 
    configuration management across development, staging, and production environments.
    
    Features:
        - Service registration and discovery
        - Dependency injection coordination  
        - Service lifecycle management
        - Flask application factory integration
        - Configuration-driven service initialization
    """
    
    def __init__(self):
        """Initialize the service registry with empty service containers."""
        self._services: Dict[str, Any] = {}
        self._service_classes: Dict[str, Type] = {}
        self._initialized: bool = False
        self._app: Optional[Flask] = None
        
        logger.debug("Authentication service registry initialized")
        
    def register_service(self, name: str, service_class: Type, **kwargs) -> None:
        """
        Register a service class with the registry for dependency injection.
        
        Args:
            name: Service identifier for registry lookup
            service_class: Service class to register for instantiation
            **kwargs: Configuration parameters for service initialization
            
        Raises:
            ValueError: If service name is already registered
            TypeError: If service_class is not a valid class type
        """
        if name in self._service_classes:
            raise ValueError(f"Service '{name}' is already registered")
            
        if not isinstance(service_class, type):
            raise TypeError(f"service_class must be a class type, got {type(service_class)}")
            
        self._service_classes[name] = service_class
        logger.info(f"Registered service: {name}")
        
    def get_service(self, name: str) -> Any:
        """
        Retrieve a service instance from the registry.
        
        Implements lazy loading pattern where services are instantiated on first access.
        Ensures proper dependency injection and configuration management for Service 
        Layer components.
        
        Args:
            name: Service identifier for registry lookup
            
        Returns:
            Service instance configured for current Flask application context
            
        Raises:
            KeyError: If service name is not registered
            RuntimeError: If registry is not initialized with Flask application
        """
        if not self._initialized:
            raise RuntimeError("Service registry not initialized. Call init_app() first.")
            
        if name not in self._service_classes:
            raise KeyError(f"Service '{name}' not registered")
            
        # Lazy loading pattern - instantiate service on first access
        if name not in self._services:
            service_class = self._service_classes[name]
            
            try:
                # Pass Flask application context to service for configuration access
                self._services[name] = service_class(app=self._app)
                logger.info(f"Instantiated service: {name}")
                
            except Exception as e:
                logger.error(f"Failed to instantiate service '{name}': {e}")
                raise
                
        return self._services[name]
        
    def init_app(self, app: Flask) -> None:
        """
        Initialize the service registry with Flask application factory pattern.
        
        Configures service registry for systematic service registration and dependency 
        injection coordination. Integrates with Flask application configuration for 
        environment-specific service initialization and component coordination.
        
        Args:
            app: Flask application instance from application factory
            
        Raises:
            TypeError: If app is not a Flask application instance
            RuntimeError: If registry is already initialized
        """
        if not isinstance(app, Flask):
            raise TypeError("app must be a Flask application instance")
            
        if self._initialized:
            raise RuntimeError("Service registry already initialized")
            
        self._app = app
        self._initialized = True
        
        # Register core authentication services for dependency injection
        self._register_core_services()
        
        logger.info("Authentication service registry initialized with Flask application")
        
    def _register_core_services(self) -> None:
        """Register core authentication services with the registry."""
        # Only register services that were successfully imported
        service_mappings = {
            'authentication': AuthenticationService,
            'user_lifecycle': UserLifecycleService,
            'security_policy': SecurityPolicyService,
            'integration_coordination': IntegrationCoordinationService
        }
        
        for service_name, service_class in service_mappings.items():
            if service_class is not None:
                try:
                    self.register_service(service_name, service_class)
                except ValueError:
                    # Service already registered - skip
                    pass
                except Exception as e:
                    logger.error(f"Failed to register service '{service_name}': {e}")
                    
    def get_all_services(self) -> Dict[str, Any]:
        """
        Retrieve all registered service instances.
        
        Returns:
            Dictionary mapping service names to instantiated service objects
        """
        return {name: self.get_service(name) for name in self._service_classes.keys()}
        
    def clear_services(self) -> None:
        """Clear all service instances for testing or reinitialization."""
        self._services.clear()
        logger.debug("All service instances cleared from registry")
        
    @property
    def is_initialized(self) -> bool:
        """Check if service registry is initialized with Flask application."""
        return self._initialized
        
    @property 
    def registered_services(self) -> List[str]:
        """Get list of registered service names."""
        return list(self._service_classes.keys())


# Global service registry instance for Flask application factory integration
# Implements singleton pattern for consistent service access across blueprints
service_registry = AuthenticationServiceRegistry()


# Service Factory Functions for Flask Application Factory Pattern Integration
# These functions provide structured service access for Flask blueprints and components

@lru_cache(maxsize=None)
def get_authentication_service() -> Optional[Any]:
    """
    Get the core authentication service instance.
    
    Provides centralized access to authentication workflow orchestration including
    Flask-Login session management, Auth0 integration, and token management. 
    Implements caching for performance optimization across multiple blueprint access.
    
    Returns:
        AuthenticationService instance or None if not available
        
    Raises:
        RuntimeError: If service registry is not initialized
    """
    try:
        return service_registry.get_service('authentication')
    except (KeyError, RuntimeError) as e:
        logger.warning(f"Authentication service not available: {e}")
        return None


@lru_cache(maxsize=None)
def get_user_lifecycle_service() -> Optional[Any]:
    """
    Get the user lifecycle management service instance.
    
    Provides centralized access to user account operations including registration,
    profile management, password reset, and account deactivation workflows with 
    Auth0 and Flask-SQLAlchemy synchronization.
    
    Returns:
        UserLifecycleService instance or None if not available
        
    Raises:
        RuntimeError: If service registry is not initialized
    """
    try:
        return service_registry.get_service('user_lifecycle')
    except (KeyError, RuntimeError) as e:
        logger.warning(f"User lifecycle service not available: {e}")
        return None


@lru_cache(maxsize=None)
def get_security_policy_service() -> Optional[Any]:
    """
    Get the security policy enforcement service instance.
    
    Provides centralized access to security rule validation, access control policies,
    and threat detection capabilities including role-based access control and 
    automated security response coordination.
    
    Returns:
        SecurityPolicyService instance or None if not available
        
    Raises:
        RuntimeError: If service registry is not initialized
    """
    try:
        return service_registry.get_service('security_policy')
    except (KeyError, RuntimeError) as e:
        logger.warning(f"Security policy service not available: {e}")
        return None


@lru_cache(maxsize=None)
def get_integration_coordination_service() -> Optional[Any]:
    """
    Get the integration coordination service instance.
    
    Provides centralized access to workflow orchestration between authentication 
    components, external services, and Flask application modules including 
    cross-component state management and error handling coordination.
    
    Returns:
        IntegrationCoordinationService instance or None if not available
        
    Raises:
        RuntimeError: If service registry is not initialized
    """
    try:
        return service_registry.get_service('integration_coordination')
    except (KeyError, RuntimeError) as e:
        logger.warning(f"Integration coordination service not available: {e}")
        return None


def init_authentication_services(app: Flask) -> None:
    """
    Initialize all authentication services with Flask application factory pattern.
    
    Provides systematic service registration and dependency injection coordination
    for all Service Layer authentication components. Integrates with Flask 
    application configuration for environment-specific service initialization.
    
    This function should be called from the Flask application factory to ensure
    proper service initialization and configuration management across all 
    deployment environments.
    
    Args:
        app: Flask application instance from application factory
        
    Example:
        ```python
        from flask import Flask
        from src.auth.services import init_authentication_services
        
        def create_app():
            app = Flask(__name__)
            init_authentication_services(app)
            return app
        ```
        
    Raises:
        TypeError: If app is not a Flask application instance
        RuntimeError: If services are already initialized
    """
    try:
        service_registry.init_app(app)
        logger.info("Authentication services initialized successfully")
        
        # Clear function caches to ensure fresh service instances
        get_authentication_service.cache_clear()
        get_user_lifecycle_service.cache_clear()
        get_security_policy_service.cache_clear()
        get_integration_coordination_service.cache_clear()
        
    except Exception as e:
        logger.error(f"Failed to initialize authentication services: {e}")
        raise


def get_service_status() -> Dict[str, Any]:
    """
    Get comprehensive status information for all authentication services.
    
    Provides diagnostic information for service registry state, registered services,
    and initialization status. Useful for health checks and debugging service 
    coordination issues.
    
    Returns:
        Dictionary containing service registry status and service availability
    """
    return {
        'registry_initialized': service_registry.is_initialized,
        'registered_services': service_registry.registered_services,
        'available_services': {
            'authentication': get_authentication_service() is not None,
            'user_lifecycle': get_user_lifecycle_service() is not None,
            'security_policy': get_security_policy_service() is not None,
            'integration_coordination': get_integration_coordination_service() is not None
        },
        'service_count': len(service_registry.registered_services)
    }


# Public API Exports for Package Interface
# Provides centralized access to Service Layer authentication components

__all__ = [
    # Service Registry and Initialization
    'service_registry',
    'init_authentication_services',
    'get_service_status',
    
    # Core Service Access Functions
    'get_authentication_service',
    'get_user_lifecycle_service', 
    'get_security_policy_service',
    'get_integration_coordination_service',
    
    # Service Classes (for direct import if needed)
    'AuthenticationService',
    'UserLifecycleService',
    'SecurityPolicyService', 
    'IntegrationCoordinationService',
    
    # Service Registry Class
    'AuthenticationServiceRegistry'
]


# Module-level initialization logging
logger.info("Authentication services package initialized - Service Layer pattern implementation ready")