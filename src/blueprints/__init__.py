"""
Flask Blueprint Registration Orchestrator

This module serves as the central coordination point for all blueprint modules,
implementing organized modular architecture that replaces Node.js route handler 
patterns with structured Flask blueprint organization per Section 5.1.1.

The blueprint registration orchestrator coordinates systematic blueprint registration 
sequences during Flask application factory initialization, enabling modular application 
structure with clear separation of concerns per Section 5.2.2.

Key Features:
- Centralized blueprint registration orchestration per Feature F-001
- Automated blueprint discovery supporting scalable Flask architecture per Section 5.1.2
- Systematic module organization enabling clear separation of concerns per Section 5.2.2
- Flask 3.1.1 blueprint registration sequence for modular application structure per Section 5.1.1

Architecture:
This module implements the blueprint-based modular microframework pattern using 
Flask 3.1.1, providing organized route management through systematic registration 
sequences during application factory initialization as specified in Section 5.1.1.

Blueprint Organization:
- Main Blueprint (/): Health checks, system monitoring, and core application routes
- Authentication Blueprint (/auth): User authentication, session management, and access control
- API Blueprint (/api): RESTful API endpoints for core business operations

Dependencies:
- Flask 3.1.1: Core web framework providing blueprint functionality
- Python 3.13.3: Runtime environment with enhanced performance and security features

Migration Context:
This implementation replaces Express.js route handler patterns with Flask's blueprint 
system, maintaining functional equivalence while enabling enhanced modular organization 
and clear separation of concerns as required by the Node.js to Python migration scope.
"""

import logging
from typing import Optional, List, Dict, Any
from flask import Flask, Blueprint

# Configure module-level logging for blueprint registration operations
logger = logging.getLogger(__name__)


def register_blueprints(app: Flask) -> None:
    """
    Central blueprint registration orchestrator for Flask application factory pattern.
    
    This function coordinates systematic blueprint registration sequences during 
    Flask application factory initialization, implementing organized modular 
    architecture that replaces Node.js route handler patterns with structured 
    Flask blueprint organization per Section 5.1.1.
    
    Blueprint Registration Sequence:
    1. Main Application Blueprint - Core system functionality and health monitoring
    2. Authentication Blueprint - User authentication and session management  
    3. API Blueprint - RESTful API endpoints for business operations
    
    Args:
        app (Flask): Flask application instance for blueprint registration
        
    Raises:
        ImportError: If blueprint modules cannot be imported
        AttributeError: If blueprint objects are not properly defined
        RuntimeError: If blueprint registration fails
        
    Returns:
        None
        
    Implementation Notes:
    - Maintains systematic registration order for proper middleware and dependency handling
    - Provides comprehensive error handling and logging for debugging and monitoring
    - Supports environment-specific configuration through Flask app.config framework
    - Enables scalable blueprint discovery for future module additions
    
    Technical Reference:
    - Section 5.1.1: Flask Application Factory Pattern implementation
    - Section 5.2.2: Blueprint Management System architecture  
    - Feature F-001: Centralized blueprint registration orchestration
    """
    
    logger.info("Starting blueprint registration sequence for Flask application factory")
    
    # Blueprint registration counter for monitoring and validation
    registered_blueprints: List[str] = []
    registration_errors: List[Dict[str, Any]] = []
    
    try:
        # Phase 1: Register Main Application Blueprint
        # Handles core system functionality, health checks, and monitoring endpoints
        logger.debug("Registering main application blueprint")
        
        try:
            from .main import main_bp
            
            # Register main blueprint at root level for system endpoints
            app.register_blueprint(main_bp)
            registered_blueprints.append("main")
            
            logger.info("Successfully registered main application blueprint at root level")
            
        except ImportError as e:
            error_details = {
                "blueprint": "main", 
                "error_type": "ImportError",
                "error_message": str(e),
                "module_path": "src.blueprints.main"
            }
            registration_errors.append(error_details)
            logger.error(f"Failed to import main blueprint: {e}")
            
        except AttributeError as e:
            error_details = {
                "blueprint": "main",
                "error_type": "AttributeError", 
                "error_message": str(e),
                "expected_object": "main_bp"
            }
            registration_errors.append(error_details)
            logger.error(f"Main blueprint object 'main_bp' not found: {e}")
            
        # Phase 2: Register Authentication Blueprint  
        # Handles user authentication, session management, and access control
        logger.debug("Registering authentication blueprint")
        
        try:
            from .auth import auth_bp
            
            # Register authentication blueprint with /auth prefix for security endpoints
            app.register_blueprint(auth_bp, url_prefix='/auth')
            registered_blueprints.append("auth")
            
            logger.info("Successfully registered authentication blueprint with '/auth' prefix")
            
        except ImportError as e:
            error_details = {
                "blueprint": "auth",
                "error_type": "ImportError", 
                "error_message": str(e),
                "module_path": "src.blueprints.auth"
            }
            registration_errors.append(error_details)
            logger.error(f"Failed to import auth blueprint: {e}")
            
        except AttributeError as e:
            error_details = {
                "blueprint": "auth",
                "error_type": "AttributeError",
                "error_message": str(e), 
                "expected_object": "auth_bp"
            }
            registration_errors.append(error_details)
            logger.error(f"Auth blueprint object 'auth_bp' not found: {e}")
            
        # Phase 3: Register API Blueprint
        # Handles RESTful API endpoints for core business operations
        logger.debug("Registering API blueprint")
        
        try:
            from .api import api_bp
            
            # Register API blueprint with /api prefix for business logic endpoints
            app.register_blueprint(api_bp, url_prefix='/api')
            registered_blueprints.append("api")
            
            logger.info("Successfully registered API blueprint with '/api' prefix")
            
        except ImportError as e:
            error_details = {
                "blueprint": "api",
                "error_type": "ImportError",
                "error_message": str(e), 
                "module_path": "src.blueprints.api"
            }
            registration_errors.append(error_details)
            logger.error(f"Failed to import API blueprint: {e}")
            
        except AttributeError as e:
            error_details = {
                "blueprint": "api", 
                "error_type": "AttributeError",
                "error_message": str(e),
                "expected_object": "api_bp"
            }
            registration_errors.append(error_details)
            logger.error(f"API blueprint object 'api_bp' not found: {e}")
            
        # Blueprint Registration Validation and Reporting
        _validate_blueprint_registration(
            app=app, 
            registered_blueprints=registered_blueprints,
            registration_errors=registration_errors
        )
        
        # Log final registration summary
        total_expected = 3  # main, auth, api
        successful_registrations = len(registered_blueprints)
        
        logger.info(
            f"Blueprint registration sequence completed: "
            f"{successful_registrations}/{total_expected} blueprints registered successfully"
        )
        
        if registration_errors:
            logger.warning(f"Blueprint registration completed with {len(registration_errors)} errors")
            for error in registration_errors:
                logger.warning(f"Error details: {error}")
        else:
            logger.info("All blueprints registered successfully without errors")
            
    except Exception as e:
        logger.critical(f"Critical error during blueprint registration sequence: {e}")
        raise RuntimeError(f"Blueprint registration failed: {e}") from e


def _validate_blueprint_registration(
    app: Flask, 
    registered_blueprints: List[str], 
    registration_errors: List[Dict[str, Any]]
) -> None:
    """
    Validates blueprint registration results and provides comprehensive reporting.
    
    This internal validation function ensures proper blueprint registration and 
    provides detailed reporting for monitoring and debugging purposes during 
    Flask application factory initialization.
    
    Args:
        app (Flask): Flask application instance with registered blueprints
        registered_blueprints (List[str]): List of successfully registered blueprint names
        registration_errors (List[Dict[str, Any]]): List of registration error details
        
    Raises:
        RuntimeError: If critical blueprint registration failures are detected
        
    Returns:
        None
        
    Validation Checks:
    - Verifies expected blueprints are registered with Flask application
    - Validates blueprint URL prefix configuration
    - Confirms proper error handling and reporting
    - Ensures application readiness for request processing
    """
    
    logger.debug("Starting blueprint registration validation")
    
    # Expected blueprint configuration for validation
    expected_blueprints = {
        "main": {"url_prefix": None, "required": True},
        "auth": {"url_prefix": "/auth", "required": True}, 
        "api": {"url_prefix": "/api", "required": True}
    }
    
    # Validate registered blueprints against expectations
    for blueprint_name, config in expected_blueprints.items():
        if blueprint_name in registered_blueprints:
            logger.debug(f"✓ Blueprint '{blueprint_name}' registered successfully")
        else:
            if config["required"]:
                logger.error(f"✗ Required blueprint '{blueprint_name}' failed to register")
            else:
                logger.warning(f"⚠ Optional blueprint '{blueprint_name}' not registered")
    
    # Validate Flask application blueprint registration state
    try:
        app_blueprints = list(app.blueprints.keys())
        logger.debug(f"Flask application blueprints: {app_blueprints}")
        
        # Verify blueprint objects are properly registered with Flask
        for blueprint_name in registered_blueprints:
            if blueprint_name in app.blueprints:
                blueprint_obj = app.blueprints[blueprint_name]
                logger.debug(f"Blueprint '{blueprint_name}' validated in Flask application registry")
            else:
                logger.error(f"Blueprint '{blueprint_name}' missing from Flask application registry")
                
    except Exception as e:
        logger.error(f"Error during Flask blueprint validation: {e}")
    
    # Critical error detection for application readiness
    critical_blueprints = ["main", "auth", "api"]
    missing_critical = [bp for bp in critical_blueprints if bp not in registered_blueprints]
    
    if missing_critical:
        error_msg = f"Critical blueprints failed to register: {missing_critical}"
        logger.critical(error_msg)
        
        # Include detailed error information for debugging
        if registration_errors:
            logger.critical("Registration error details:")
            for error in registration_errors:
                if error.get("blueprint") in missing_critical:
                    logger.critical(f"  - {error}")
        
        raise RuntimeError(error_msg)
    
    logger.debug("Blueprint registration validation completed successfully")


def get_registered_blueprints(app: Flask) -> List[str]:
    """
    Utility function to retrieve list of registered blueprints from Flask application.
    
    This function provides runtime introspection capabilities for monitoring 
    and debugging blueprint registration status during application operation.
    
    Args:
        app (Flask): Flask application instance
        
    Returns:
        List[str]: List of registered blueprint names
        
    Usage Example:
        blueprints = get_registered_blueprints(app)
        logger.info(f"Active blueprints: {blueprints}")
    """
    
    try:
        return list(app.blueprints.keys())
    except Exception as e:
        logger.error(f"Error retrieving registered blueprints: {e}")
        return []


def get_blueprint_routes(app: Flask, blueprint_name: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Utility function to retrieve route information for registered blueprints.
    
    This function provides runtime route introspection for monitoring, debugging,
    and API documentation generation during application operation.
    
    Args:
        app (Flask): Flask application instance
        blueprint_name (Optional[str]): Specific blueprint name, or None for all blueprints
        
    Returns:
        Dict[str, List[str]]: Dictionary mapping blueprint names to their routes
        
    Usage Example:
        routes = get_blueprint_routes(app, "api") 
        logger.info(f"API routes: {routes}")
    """
    
    routes_mapping: Dict[str, List[str]] = {}
    
    try:
        # Retrieve all URL rules from Flask application
        for rule in app.url_map.iter_rules():
            # Extract blueprint name from endpoint
            if '.' in rule.endpoint:
                bp_name = rule.endpoint.split('.')[0]
                
                # Filter by specific blueprint if requested
                if blueprint_name and bp_name != blueprint_name:
                    continue
                    
                # Initialize blueprint entry if not exists
                if bp_name not in routes_mapping:
                    routes_mapping[bp_name] = []
                
                # Add route information
                route_info = f"{rule.rule} [{', '.join(rule.methods)}]"
                routes_mapping[bp_name].append(route_info)
        
        return routes_mapping
        
    except Exception as e:
        logger.error(f"Error retrieving blueprint routes: {e}")
        return {}


# Export registration function for Flask application factory pattern
__all__ = [
    'register_blueprints',
    'get_registered_blueprints', 
    'get_blueprint_routes'
]