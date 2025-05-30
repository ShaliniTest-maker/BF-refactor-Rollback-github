"""
Flask Blueprint Package Initialization

This module provides centralized blueprint registration functionality for the Flask 3.1.1 application
factory pattern, implementing automated blueprint discovery and registration mechanisms that replace
Express.js router patterns with Flask's modular blueprint architecture per Section 5.2.2.

Key Features:
- Centralized blueprint registration function for Flask application factory pattern per Section 5.2.2
- Automatic blueprint discovery mechanism enabling modular route organization per Section 4.3.1.2
- URL prefix assignment for API versioning and namespace management per Section 5.2.2
- Blueprint interdependency resolution supporting Service Layer pattern integration per Section 6.1.6
- Blueprint health monitoring and registration validation per Section 6.1.5
- Error handling and logging for blueprint registration failures

Architecture Benefits:
- Replaces Express.js router patterns with structured Flask blueprint architecture
- Enables automatic discovery and registration of blueprint modules per Section 4.3.1.2
- Provides URL prefix management for API versioning and namespace organization
- Supports Service Layer pattern coordination across blueprint boundaries
- Implements comprehensive error handling for blueprint registration failures
- Facilitates testing and development through modular blueprint isolation

Blueprint Organization:
- main_bp: Core application routes and navigation endpoints
- api_bp: RESTful API endpoints with comprehensive HTTP method support
- auth_bp: Authentication and session management routes  
- health_bp: System monitoring and health check endpoints

Dependencies:
- Flask 3.1.1: Core blueprint functionality and application factory pattern
- Python logging: Comprehensive logging and error tracking
- Service Layer: Business logic coordination across blueprint boundaries
- Type hints: Enhanced code maintainability and IDE support

This package orchestrates all blueprint modules and ensures proper registration sequence,
enabling the Flask application to locate and register all route definitions while maintaining
clear separation of concerns and modular architecture benefits.
"""

import logging
import inspect
from typing import Dict, List, Optional, Tuple, Any, Type, Union
from importlib import import_module
from dataclasses import dataclass
from datetime import datetime, timezone

# Core Flask imports for blueprint management
from flask import Flask, Blueprint, current_app
from flask.blueprints import BlueprintSetupState

# Configure logging for blueprint registration operations
logger = logging.getLogger(__name__)


@dataclass
class BlueprintConfig:
    """
    Configuration class for blueprint registration metadata.
    
    Provides structured configuration data for blueprint registration including
    dependency relationships, URL prefix assignments, and initialization requirements.
    """
    name: str
    module_path: str
    blueprint_name: str
    url_prefix: Optional[str] = None
    dependencies: List[str] = None
    init_function: Optional[str] = None
    enabled: bool = True
    priority: int = 0
    description: str = ""
    
    def __post_init__(self):
        """Initialize default values after dataclass creation."""
        if self.dependencies is None:
            self.dependencies = []


class BlueprintRegistrationError(Exception):
    """Custom exception for blueprint registration failures."""
    
    def __init__(self, message: str, blueprint_name: str = None, error_code: str = None):
        super().__init__(message)
        self.message = message
        self.blueprint_name = blueprint_name
        self.error_code = error_code or 'BLUEPRINT_REGISTRATION_ERROR'


class BlueprintRegistry:
    """
    Centralized blueprint registry for automated discovery and registration.
    
    Implements comprehensive blueprint management including automatic discovery,
    dependency resolution, URL prefix assignment, and registration validation
    for Flask application factory pattern integration per Section 5.2.2.
    """
    
    def __init__(self):
        """Initialize blueprint registry with configuration and tracking."""
        self._blueprints: Dict[str, BlueprintConfig] = {}
        self._registered_blueprints: Dict[str, Blueprint] = {}
        self._registration_order: List[str] = []
        self._failed_registrations: Dict[str, str] = {}
        
        # Initialize default blueprint configurations
        self._initialize_default_blueprints()
    
    def _initialize_default_blueprints(self):
        """
        Initialize default blueprint configurations for core application modules.
        
        Defines blueprint metadata including dependencies, URL prefixes, and
        initialization requirements based on Flask application architecture.
        """
        # Define core blueprint configurations per Section 5.2.2
        default_configs = [
            BlueprintConfig(
                name='health',
                module_path='blueprints.health',
                blueprint_name='health_bp',
                url_prefix='/health',
                dependencies=[],
                enabled=True,
                priority=1,
                description='System health monitoring and container orchestration endpoints'
            ),
            BlueprintConfig(
                name='auth',
                module_path='blueprints.auth',
                blueprint_name='auth_bp',
                url_prefix='/auth',
                dependencies=['health'],
                init_function='init_auth_blueprint',
                enabled=True,
                priority=2,
                description='Authentication and session management routes'
            ),
            BlueprintConfig(
                name='api',
                module_path='blueprints.api',
                blueprint_name='api_bp',
                url_prefix='/api/v1',
                dependencies=['health', 'auth'],
                init_function='register_api_blueprint',
                enabled=True,
                priority=3,
                description='RESTful API endpoints with comprehensive HTTP method support'
            ),
            BlueprintConfig(
                name='main',
                module_path='blueprints.main',
                blueprint_name='main_bp',
                url_prefix='/',
                dependencies=['health', 'auth', 'api'],
                init_function='init_main_blueprint',
                enabled=True,
                priority=4,
                description='Core application routes and navigation endpoints'
            )
        ]
        
        # Register default configurations
        for config in default_configs:
            self._blueprints[config.name] = config
        
        logger.info(f"Initialized {len(default_configs)} default blueprint configurations")
    
    def register_blueprint_config(self, config: BlueprintConfig) -> bool:
        """
        Register a new blueprint configuration for discovery and registration.
        
        Args:
            config: Blueprint configuration instance
            
        Returns:
            Boolean indicating successful configuration registration
        """
        try:
            # Validate configuration
            if not config.name or not config.module_path or not config.blueprint_name:
                raise BlueprintRegistrationError(
                    f"Invalid blueprint configuration: missing required fields",
                    blueprint_name=config.name
                )
            
            # Check for naming conflicts
            if config.name in self._blueprints:
                logger.warning(f"Blueprint configuration '{config.name}' already exists, updating")
            
            # Register configuration
            self._blueprints[config.name] = config
            logger.info(f"Registered blueprint configuration: {config.name}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to register blueprint configuration '{config.name}': {e}")
            return False
    
    def discover_blueprints(self) -> List[str]:
        """
        Discover available blueprint modules through configuration registry.
        
        Returns blueprint configurations in dependency-resolved order for proper
        registration sequence and Service Layer pattern coordination.
        
        Returns:
            List of blueprint names in registration order
        """
        try:
            # Get enabled blueprints
            enabled_blueprints = {
                name: config for name, config in self._blueprints.items()
                if config.enabled
            }
            
            # Resolve dependencies and sort by priority
            registration_order = self._resolve_dependencies(enabled_blueprints)
            
            logger.info(f"Discovered {len(registration_order)} blueprint modules: {registration_order}")
            return registration_order
            
        except Exception as e:
            logger.error(f"Blueprint discovery failed: {e}")
            return []
    
    def _resolve_dependencies(self, blueprints: Dict[str, BlueprintConfig]) -> List[str]:
        """
        Resolve blueprint dependencies and determine registration order.
        
        Implements topological sorting to ensure blueprints with dependencies are
        registered after their dependencies, supporting Service Layer integration.
        
        Args:
            blueprints: Dictionary of blueprint configurations
            
        Returns:
            List of blueprint names in dependency-resolved order
        """
        try:
            # Build dependency graph
            dependency_graph = {}
            in_degree = {}
            
            for name, config in blueprints.items():
                dependency_graph[name] = []
                in_degree[name] = 0
            
            # Populate dependency relationships
            for name, config in blueprints.items():
                for dependency in config.dependencies:
                    if dependency in blueprints:
                        dependency_graph[dependency].append(name)
                        in_degree[name] += 1
                    else:
                        logger.warning(f"Blueprint '{name}' depends on unknown blueprint '{dependency}'")
            
            # Topological sort with priority consideration
            result = []
            queue = []
            
            # Find blueprints with no dependencies, sorted by priority
            initial_blueprints = [
                (config.priority, name) for name, config in blueprints.items()
                if in_degree[name] == 0
            ]
            initial_blueprints.sort()
            queue.extend([name for _, name in initial_blueprints])
            
            # Process dependencies
            while queue:
                current = queue.pop(0)
                result.append(current)
                
                # Update in-degrees for dependent blueprints
                dependent_blueprints = []
                for dependent in dependency_graph[current]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        config = blueprints[dependent]
                        dependent_blueprints.append((config.priority, dependent))
                
                # Sort dependents by priority before adding to queue
                dependent_blueprints.sort()
                queue.extend([name for _, name in dependent_blueprints])
            
            # Check for circular dependencies
            if len(result) != len(blueprints):
                remaining = [name for name in blueprints.keys() if name not in result]
                logger.error(f"Circular dependencies detected in blueprints: {remaining}")
                # Add remaining blueprints anyway to prevent complete failure
                result.extend(remaining)
            
            return result
            
        except Exception as e:
            logger.error(f"Dependency resolution failed: {e}")
            # Fallback to priority-based ordering
            fallback_order = sorted(
                blueprints.items(),
                key=lambda x: x[1].priority
            )
            return [name for name, _ in fallback_order]
    
    def load_blueprint(self, blueprint_name: str) -> Optional[Blueprint]:
        """
        Load blueprint module and extract blueprint object.
        
        Dynamically imports blueprint module and retrieves the blueprint object
        for registration with Flask application instance.
        
        Args:
            blueprint_name: Name of blueprint to load
            
        Returns:
            Blueprint object or None if loading fails
        """
        try:
            # Get blueprint configuration
            if blueprint_name not in self._blueprints:
                raise BlueprintRegistrationError(
                    f"Unknown blueprint: {blueprint_name}",
                    blueprint_name=blueprint_name
                )
            
            config = self._blueprints[blueprint_name]
            
            # Import blueprint module
            logger.debug(f"Importing blueprint module: {config.module_path}")
            module = import_module(config.module_path)
            
            # Extract blueprint object
            if not hasattr(module, config.blueprint_name):
                raise BlueprintRegistrationError(
                    f"Blueprint object '{config.blueprint_name}' not found in module '{config.module_path}'",
                    blueprint_name=blueprint_name
                )
            
            blueprint = getattr(module, config.blueprint_name)
            
            # Validate blueprint object
            if not isinstance(blueprint, Blueprint):
                raise BlueprintRegistrationError(
                    f"Object '{config.blueprint_name}' is not a valid Flask Blueprint",
                    blueprint_name=blueprint_name
                )
            
            # Store loaded blueprint
            self._registered_blueprints[blueprint_name] = blueprint
            
            logger.info(f"Successfully loaded blueprint: {blueprint_name}")
            return blueprint
            
        except Exception as e:
            error_msg = f"Failed to load blueprint '{blueprint_name}': {e}"
            logger.error(error_msg)
            self._failed_registrations[blueprint_name] = error_msg
            return None
    
    def register_blueprint_with_app(
        self, 
        app: Flask, 
        blueprint: Blueprint, 
        blueprint_name: str
    ) -> bool:
        """
        Register blueprint with Flask application instance.
        
        Performs blueprint registration with proper URL prefix assignment,
        error handling, and initialization function execution if configured.
        
        Args:
            app: Flask application instance
            blueprint: Blueprint object to register
            blueprint_name: Name of blueprint for configuration lookup
            
        Returns:
            Boolean indicating successful registration
        """
        try:
            # Get blueprint configuration
            config = self._blueprints.get(blueprint_name)
            if not config:
                raise BlueprintRegistrationError(
                    f"Configuration not found for blueprint: {blueprint_name}",
                    blueprint_name=blueprint_name
                )
            
            # Prepare registration options
            registration_options = {}
            
            # Apply URL prefix from configuration
            if config.url_prefix is not None:
                registration_options['url_prefix'] = config.url_prefix
            
            # Register blueprint with Flask application
            logger.debug(f"Registering blueprint '{blueprint_name}' with options: {registration_options}")
            app.register_blueprint(blueprint, **registration_options)
            
            # Execute initialization function if specified
            if config.init_function:
                try:
                    # Import module to access initialization function
                    module = import_module(config.module_path)
                    
                    if hasattr(module, config.init_function):
                        init_func = getattr(module, config.init_function)
                        logger.debug(f"Executing initialization function: {config.init_function}")
                        init_func(app)
                        logger.info(f"Blueprint '{blueprint_name}' initialization completed")
                    else:
                        logger.warning(f"Initialization function '{config.init_function}' not found for blueprint '{blueprint_name}'")
                
                except Exception as init_error:
                    logger.error(f"Blueprint '{blueprint_name}' initialization failed: {init_error}")
                    # Continue registration even if initialization fails
            
            # Track successful registration
            self._registration_order.append(blueprint_name)
            
            logger.info(f"Successfully registered blueprint: {blueprint_name} -> {config.url_prefix}")
            return True
            
        except Exception as e:
            error_msg = f"Failed to register blueprint '{blueprint_name}': {e}"
            logger.error(error_msg)
            self._failed_registrations[blueprint_name] = error_msg
            return False
    
    def get_registration_status(self) -> Dict[str, Any]:
        """
        Get comprehensive blueprint registration status and metrics.
        
        Returns:
            Dictionary containing registration statistics and status information
        """
        return {
            'total_configured': len(self._blueprints),
            'total_registered': len(self._registration_order),
            'registration_order': self._registration_order.copy(),
            'failed_registrations': self._failed_registrations.copy(),
            'enabled_blueprints': [
                name for name, config in self._blueprints.items() 
                if config.enabled
            ],
            'blueprint_configs': {
                name: {
                    'module_path': config.module_path,
                    'url_prefix': config.url_prefix,
                    'dependencies': config.dependencies,
                    'priority': config.priority,
                    'description': config.description
                }
                for name, config in self._blueprints.items()
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Global blueprint registry instance
_blueprint_registry = BlueprintRegistry()


def register_all_blueprints(app: Flask) -> Dict[str, Any]:
    """
    Centralized blueprint registration function for Flask application factory pattern.
    
    Implements automatic blueprint discovery and registration mechanism that replaces
    Express.js router patterns with Flask's modular blueprint architecture per Section 5.2.2.
    Provides URL prefix assignment for API versioning support and blueprint interdependency
    resolution for Service Layer pattern integration per Section 6.1.6.
    
    Args:
        app: Flask application instance
        
    Returns:
        Dictionary containing registration results and status information
        
    Raises:
        BlueprintRegistrationError: If critical blueprint registration fails
    """
    try:
        logger.info("Starting centralized blueprint registration process")
        start_time = datetime.now(timezone.utc)
        
        # Validate Flask application instance
        if not isinstance(app, Flask):
            raise BlueprintRegistrationError("Invalid Flask application instance provided")
        
        # Discover available blueprints in dependency order
        blueprint_names = _blueprint_registry.discover_blueprints()
        
        if not blueprint_names:
            logger.warning("No blueprints discovered for registration")
            return {
                'success': False,
                'message': 'No blueprints found for registration',
                'results': {}
            }
        
        # Track registration results
        registration_results = {
            'successful': [],
            'failed': [],
            'total_attempted': len(blueprint_names)
        }
        
        # Register each blueprint in dependency order
        for blueprint_name in blueprint_names:
            try:
                logger.debug(f"Processing blueprint: {blueprint_name}")
                
                # Load blueprint module and object
                blueprint = _blueprint_registry.load_blueprint(blueprint_name)
                
                if blueprint is None:
                    registration_results['failed'].append(blueprint_name)
                    continue
                
                # Register blueprint with Flask application
                success = _blueprint_registry.register_blueprint_with_app(
                    app, blueprint, blueprint_name
                )
                
                if success:
                    registration_results['successful'].append(blueprint_name)
                else:
                    registration_results['failed'].append(blueprint_name)
                
            except Exception as e:
                logger.error(f"Blueprint registration error for '{blueprint_name}': {e}")
                registration_results['failed'].append(blueprint_name)
        
        # Calculate registration metrics
        end_time = datetime.now(timezone.utc)
        registration_duration = (end_time - start_time).total_seconds()
        
        # Log registration summary
        logger.info(
            f"Blueprint registration completed: "
            f"{len(registration_results['successful'])}/{registration_results['total_attempted']} successful "
            f"({registration_duration:.3f}s)"
        )
        
        if registration_results['failed']:
            logger.warning(f"Failed blueprint registrations: {registration_results['failed']}")
        
        # Build comprehensive results
        results = {
            'success': len(registration_results['failed']) == 0,
            'message': f"Registered {len(registration_results['successful'])} of {registration_results['total_attempted']} blueprints",
            'results': registration_results,
            'registration_order': _blueprint_registry._registration_order.copy(),
            'duration_seconds': registration_duration,
            'timestamp': end_time.isoformat(),
            'detailed_status': _blueprint_registry.get_registration_status()
        }
        
        # Store results in application config for debugging
        app.config['BLUEPRINT_REGISTRATION_RESULTS'] = results
        
        return results
        
    except Exception as e:
        logger.error(f"Critical error during blueprint registration: {e}")
        raise BlueprintRegistrationError(f"Blueprint registration system failure: {e}")


def get_blueprint_registry() -> BlueprintRegistry:
    """
    Get the global blueprint registry instance for external configuration.
    
    Provides access to the blueprint registry for custom blueprint registration,
    configuration management, and status monitoring.
    
    Returns:
        BlueprintRegistry instance
    """
    return _blueprint_registry


def register_custom_blueprint(
    name: str,
    module_path: str,
    blueprint_name: str,
    url_prefix: Optional[str] = None,
    dependencies: List[str] = None,
    **kwargs
) -> bool:
    """
    Register a custom blueprint configuration for discovery and registration.
    
    Enables dynamic blueprint registration for extension modules and custom
    application components with proper dependency management.
    
    Args:
        name: Unique blueprint identifier
        module_path: Python module path containing blueprint
        blueprint_name: Name of blueprint object in module
        url_prefix: URL prefix for blueprint routes
        dependencies: List of blueprint dependencies
        **kwargs: Additional configuration options
        
    Returns:
        Boolean indicating successful configuration registration
    """
    try:
        config = BlueprintConfig(
            name=name,
            module_path=module_path,
            blueprint_name=blueprint_name,
            url_prefix=url_prefix,
            dependencies=dependencies or [],
            **kwargs
        )
        
        return _blueprint_registry.register_blueprint_config(config)
        
    except Exception as e:
        logger.error(f"Failed to register custom blueprint '{name}': {e}")
        return False


def validate_blueprint_registration(app: Flask) -> Dict[str, Any]:
    """
    Validate blueprint registration status and provide diagnostic information.
    
    Performs comprehensive validation of blueprint registration including
    route availability, URL prefix conflicts, and Service Layer integration.
    
    Args:
        app: Flask application instance
        
    Returns:
        Dictionary containing validation results and diagnostic information
    """
    try:
        with app.app_context():
            validation_results = {
                'blueprint_count': len(app.blueprints),
                'registered_blueprints': list(app.blueprints.keys()),
                'route_count': len(list(app.url_map.iter_rules())),
                'url_prefixes': {},
                'validation_errors': [],
                'warnings': []
            }
            
            # Analyze registered blueprints
            for blueprint_name, blueprint in app.blueprints.items():
                url_rules = [
                    rule for rule in app.url_map.iter_rules()
                    if rule.endpoint.startswith(f"{blueprint_name}.")
                ]
                
                validation_results['url_prefixes'][blueprint_name] = {
                    'url_prefix': getattr(blueprint, 'url_prefix', None),
                    'route_count': len(url_rules),
                    'endpoints': [rule.endpoint for rule in url_rules[:5]]  # Sample endpoints
                }
            
            # Check for potential issues
            registered_names = set(app.blueprints.keys())
            expected_names = set(_blueprint_registry._blueprints.keys())
            
            missing_blueprints = expected_names - registered_names
            if missing_blueprints:
                validation_results['validation_errors'].append(
                    f"Missing expected blueprints: {list(missing_blueprints)}"
                )
            
            unexpected_blueprints = registered_names - expected_names
            if unexpected_blueprints:
                validation_results['warnings'].append(
                    f"Unexpected blueprints registered: {list(unexpected_blueprints)}"
                )
            
            # Get registration status from registry
            registration_status = _blueprint_registry.get_registration_status()
            validation_results['registration_status'] = registration_status
            
            return validation_results
            
    except Exception as e:
        logger.error(f"Blueprint validation failed: {e}")
        return {
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Export public interface for application factory pattern integration
__all__ = [
    'register_all_blueprints',
    'get_blueprint_registry', 
    'register_custom_blueprint',
    'validate_blueprint_registration',
    'BlueprintConfig',
    'BlueprintRegistrationError',
    'BlueprintRegistry'
]


# Module initialization logging
logger.info("Blueprint package initialized with centralized registration system")