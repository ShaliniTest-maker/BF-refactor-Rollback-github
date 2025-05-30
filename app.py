"""
Flask Application Factory - Main Entry Point

This module implements the Flask application factory pattern as specified in Section 0
of the technical specification, serving as the core orchestrator for the Flask 3.1.1
application architecture. It replaces the Node.js app.js/server.js entry point with
a production-ready Python Flask implementation that maintains complete functional
parity while enabling access to Python's extensive AI/ML ecosystem.

Key Features:
- Flask 3.1.1 application factory pattern with environment-specific configuration
- Flask-SQLAlchemy 3.1.1 database initialization with PostgreSQL backend support
- Flask-Migrate 4.1.0 integration for Alembic-based database schema management
- Blueprint-based modular architecture replacing Express.js route handlers
- Production-ready WSGI configuration for Gunicorn/uWSGI deployment
- Comprehensive error handling, logging, and monitoring capabilities
- Environment variable management through python-dotenv integration
- Connection pooling optimization (pool_size=20, max_overflow=30, pool_timeout=30)

Architecture:
The application factory implements a three-tier architecture (presentation, business
logic, data access) within a monolithic Flask application boundary, utilizing:
- Blueprint Management System for modular route organization
- Service Layer Pattern for enhanced business logic orchestration
- Declarative Database Models with Flask-SQLAlchemy relationship mapping
- Centralized Configuration Management with environment-specific settings

Security & Performance:
- SSL/TLS encryption enforcement for PostgreSQL connections
- Secure session management with ItsDangerous 2.2+ cryptographic protection
- Connection pool validation and lifecycle management
- Comprehensive audit trails and security event logging
- Production-grade error handling with automatic rollback capabilities

Author: Flask Migration System
Version: 1.0.0
Compatibility: Flask 3.1.1, Flask-SQLAlchemy 3.1.1, PostgreSQL 14.12+, Python 3.13.3
"""

import os
import sys
import logging
import traceback
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

# Core Flask and extension imports
from flask import Flask, request, jsonify, g
from flask.logging import default_handler
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

# Environment and configuration management
from dotenv import load_dotenv

# Application components
from config import get_config, validate_database_connection
from models import (
    init_database, 
    db, 
    migrate, 
    get_database_health,
    validate_model_relationships
)
from blueprints import (
    register_blueprints, 
    get_blueprint_info,
    validate_blueprint_health,
    BlueprintRegistrationError
)

# Configure module-level logging
logger = logging.getLogger(__name__)


class FlaskApplicationError(Exception):
    """Custom exception for Flask application initialization errors."""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


def load_environment_variables() -> bool:
    """
    Load environment variables from .env files using python-dotenv.
    
    Implements environment variable management per Section 5.1.1 configuration
    management requirements, supporting development, testing, and production
    environment configurations with proper precedence handling.
    
    Returns:
        bool: True if environment variables loaded successfully, False otherwise
        
    Environment Search Order:
        1. .env.local (local development overrides)
        2. .env.{FLASK_ENV} (environment-specific settings)
        3. .env (default environment settings)
        4. System environment variables (highest precedence)
    """
    try:
        # Determine current environment
        flask_env = os.environ.get('FLASK_ENV', 'development')
        
        # Define .env file search order (reverse precedence)
        env_files = [
            '.env',                    # Base configuration
            f'.env.{flask_env}',      # Environment-specific
            '.env.local'              # Local overrides
        ]
        
        loaded_files = []
        
        # Load environment files in order
        for env_file in env_files:
            if Path(env_file).exists():
                load_dotenv(env_file, override=False)  # Don't override existing vars
                loaded_files.append(env_file)
                logger.debug(f"Loaded environment file: {env_file}")
        
        # Log loaded configuration
        if loaded_files:
            logger.info(f"Environment variables loaded from: {', '.join(loaded_files)}")
        else:
            logger.info("No .env files found, using system environment variables only")
        
        # Validate critical environment variables
        critical_vars = ['FLASK_ENV', 'SECRET_KEY', 'DATABASE_URL']
        missing_vars = []
        
        for var in critical_vars:
            if not os.environ.get(var):
                missing_vars.append(var)
        
        if missing_vars:
            logger.warning(f"Missing critical environment variables: {missing_vars}")
            if flask_env == 'production':
                logger.error("Critical environment variables missing in production")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to load environment variables: {e}")
        return False


def configure_logging(app: Flask) -> None:
    """
    Configure comprehensive logging for Flask application with environment-specific settings.
    
    Implements structured logging per Section 5.1.1 monitoring requirements with
    configurable log levels, formatters, and handlers for development, testing,
    and production environments.
    
    Args:
        app: Flask application instance
        
    Features:
        - Environment-specific log levels and formats
        - File rotation for production environments
        - Structured logging with request context
        - Database and blueprint operation logging
        - Security event and audit trail logging
    """
    try:
        # Remove default Flask handler to avoid duplicate logs
        app.logger.removeHandler(default_handler)
        
        # Get log level from configuration
        log_level_str = app.config.get('LOG_LEVEL', 'INFO')
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        
        # Create custom formatter with request context
        log_format = app.config.get(
            'LOG_FORMAT', 
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        formatter = logging.Formatter(log_format)
        
        # Configure console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        
        # Add console handler to app logger
        app.logger.addHandler(console_handler)
        app.logger.setLevel(log_level)
        
        # Configure file logging for production
        if not app.debug and not app.testing:
            # Create logs directory if it doesn't exist
            logs_dir = Path('logs')
            logs_dir.mkdir(exist_ok=True)
            
            # Configure rotating file handler
            from logging.handlers import RotatingFileHandler
            
            file_handler = RotatingFileHandler(
                logs_dir / 'flask_app.log',
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=10
            )
            
            file_handler.setLevel(logging.INFO)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            
            app.logger.addHandler(file_handler)
        
        # Configure request/response logging
        @app.before_request
        def log_request_info():
            """Log incoming request information for monitoring and debugging."""
            if app.debug:
                logger.debug(
                    f"Request: {request.method} {request.url} "
                    f"from {request.remote_addr}"
                )
        
        @app.after_request
        def log_response_info(response):
            """Log response information for monitoring and performance tracking."""
            if app.debug:
                logger.debug(
                    f"Response: {response.status_code} "
                    f"for {request.method} {request.url}"
                )
            return response
        
        logger.info(f"Logging configured successfully (level: {log_level_str})")
        
    except Exception as e:
        # Fallback logging configuration
        logging.basicConfig(
            level=logging.WARNING,
            format='%(asctime)s [%(levelname)s] %(message)s'
        )
        logger.error(f"Failed to configure advanced logging: {e}")


def configure_extensions(app: Flask) -> bool:
    """
    Initialize and configure Flask extensions with error handling and validation.
    
    Configures Flask-SQLAlchemy 3.1.1 and Flask-Migrate 4.1.0 per Section 3.2.2
    database integration requirements, implementing connection pooling, SSL
    enforcement, and comprehensive database health monitoring.
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if all extensions configured successfully, False otherwise
        
    Raises:
        FlaskApplicationError: If critical extension initialization fails
    """
    try:
        logger.info("Initializing Flask extensions...")
        
        # Initialize database with Flask-SQLAlchemy and Flask-Migrate
        logger.debug("Initializing database connection and ORM...")
        init_database(app)
        
        # Validate database configuration
        database_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if not database_uri:
            raise FlaskApplicationError(
                "Database URI not configured",
                error_code="DATABASE_CONFIG_MISSING"
            )
        
        # Test database connectivity
        logger.debug("Validating database connection...")
        if not validate_database_connection(database_uri):
            logger.warning("Database connection validation failed - continuing with initialization")
        
        # Validate model relationships
        logger.debug("Validating model relationships...")
        try:
            validate_model_relationships()
        except Exception as e:
            logger.warning(f"Model relationship validation failed: {e}")
        
        # Configure additional extensions here if needed
        # Example: Flask-Login, Flask-CORS, Flask-Caching, etc.
        
        logger.info("Flask extensions initialized successfully")
        return True
        
    except FlaskApplicationError:
        raise
    except Exception as e:
        logger.error(f"Extension configuration failed: {e}")
        raise FlaskApplicationError(
            f"Failed to configure Flask extensions: {str(e)}",
            error_code="EXTENSION_CONFIG_ERROR",
            details={'error': str(e), 'traceback': traceback.format_exc()}
        )


def register_error_handlers(app: Flask) -> None:
    """
    Register comprehensive error handlers for robust error management and user experience.
    
    Implements error handling per Section 4.8 error handling and recovery workflows,
    providing appropriate error responses while maintaining security and system stability.
    
    Args:
        app: Flask application instance
        
    Features:
        - HTTP error handling with appropriate status codes
        - Database error recovery with automatic rollback
        - Blueprint registration error handling
        - Security error logging and monitoring
        - Production-safe error messages
    """
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle bad request errors with appropriate JSON response."""
        logger.warning(f"Bad request: {request.url} - {error}")
        return jsonify({
            'error': 'Bad Request',
            'message': 'The request could not be understood by the server',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle unauthorized access with security logging."""
        logger.warning(f"Unauthorized access attempt: {request.url} from {request.remote_addr}")
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle forbidden access with security logging."""
        logger.warning(f"Forbidden access attempt: {request.url} from {request.remote_addr}")
        return jsonify({
            'error': 'Forbidden',
            'message': 'Access denied',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle not found errors."""
        logger.debug(f"Page not found: {request.url}")
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle internal server errors with database rollback."""
        logger.error(f"Internal server error: {error}")
        
        # Rollback database session on internal errors
        try:
            db.session.rollback()
        except Exception as rollback_error:
            logger.error(f"Database rollback failed: {rollback_error}")
        
        # Return production-safe error message
        error_response = {
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }
        
        # Add debug information in development
        if app.debug:
            error_response['debug_info'] = str(error)
        
        return jsonify(error_response), 500
    
    @app.errorhandler(BlueprintRegistrationError)
    def blueprint_error(error):
        """Handle blueprint registration errors."""
        logger.error(f"Blueprint registration error: {error.message}")
        return jsonify({
            'error': 'Blueprint Registration Error',
            'message': 'Application module registration failed',
            'error_code': error.error_code,
            'status_code': 500
        }), 500
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle unexpected errors with comprehensive logging."""
        logger.error(f"Unexpected error: {error}", exc_info=True)
        
        # Attempt database rollback
        try:
            db.session.rollback()
        except Exception:
            pass
        
        return jsonify({
            'error': 'Unexpected Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500


def register_health_endpoints(app: Flask) -> None:
    """
    Register application health and monitoring endpoints for system observability.
    
    Implements health check endpoints per Section 8.5 infrastructure monitoring
    requirements, providing comprehensive system status information for container
    orchestration, load balancers, and monitoring systems.
    
    Args:
        app: Flask application instance
        
    Endpoints:
        - /health: Basic application health check
        - /health/detailed: Comprehensive system status
        - /health/database: Database connectivity status
        - /health/blueprints: Blueprint registration status
    """
    
    @app.route('/health')
    def health_check():
        """Basic health check endpoint for load balancer and container orchestration."""
        try:
            # Simple application responsiveness check
            return jsonify({
                'status': 'healthy',
                'timestamp': g.get('request_start_time'),
                'service': 'flask_app',
                'version': '1.0.0'
            }), 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({
                'status': 'unhealthy',
                'error': 'Health check failed'
            }), 503
    
    @app.route('/health/detailed')
    def detailed_health_check():
        """Comprehensive health check with system component status."""
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': g.get('request_start_time'),
                'service': 'flask_app',
                'version': '1.0.0',
                'components': {}
            }
            
            # Database health check
            try:
                db_health = get_database_health()
                health_status['components']['database'] = db_health
            except Exception as e:
                health_status['components']['database'] = {
                    'status': 'error',
                    'error': str(e)
                }
                health_status['status'] = 'degraded'
            
            # Blueprint health check
            try:
                blueprint_health = validate_blueprint_health(app)
                health_status['components']['blueprints'] = blueprint_health
                if blueprint_health['overall_status'] != 'healthy':
                    health_status['status'] = 'degraded'
            except Exception as e:
                health_status['components']['blueprints'] = {
                    'status': 'error',
                    'error': str(e)
                }
                health_status['status'] = 'degraded'
            
            # Application configuration status
            health_status['components']['configuration'] = {
                'status': 'healthy',
                'environment': app.config.get('FLASK_ENV', 'unknown'),
                'debug_mode': app.debug,
                'testing_mode': app.testing
            }
            
            # Determine overall HTTP status code
            status_code = 200
            if health_status['status'] == 'degraded':
                status_code = 200  # Still operational
            elif health_status['status'] == 'unhealthy':
                status_code = 503  # Service unavailable
            
            return jsonify(health_status), status_code
            
        except Exception as e:
            logger.error(f"Detailed health check failed: {e}")
            return jsonify({
                'status': 'error',
                'error': 'Health check system failure'
            }), 503
    
    @app.route('/health/database')
    def database_health_check():
        """Database-specific health check endpoint."""
        try:
            db_health = get_database_health()
            status_code = 200 if db_health['status'] == 'healthy' else 503
            return jsonify(db_health), status_code
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 503
    
    @app.route('/health/blueprints')
    def blueprint_health_check():
        """Blueprint registration health check endpoint."""
        try:
            blueprint_info = get_blueprint_info()
            blueprint_health = validate_blueprint_health(app)
            
            response = {
                'info': blueprint_info,
                'health': blueprint_health
            }
            
            status_code = 200
            if blueprint_health['overall_status'] != 'healthy':
                status_code = 503
            
            return jsonify(response), status_code
            
        except Exception as e:
            logger.error(f"Blueprint health check failed: {e}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 503


def configure_request_context(app: Flask) -> None:
    """
    Configure request context processors for enhanced request handling and monitoring.
    
    Implements request processing per Section 5.1.3 data flow description,
    providing request timing, user context, and security monitoring capabilities
    throughout the Flask application request lifecycle.
    
    Args:
        app: Flask application instance
        
    Features:
        - Request timing and performance monitoring
        - User context and session management
        - Security event logging and audit trails
        - Database session management
    """
    
    @app.before_request
    def before_request():
        """Initialize request context and timing."""
        import time
        g.request_start_time = time.time()
        
        # Log request start for debugging
        if app.debug:
            logger.debug(
                f"Request started: {request.method} {request.url} "
                f"from {request.remote_addr}"
            )
    
    @app.after_request
    def after_request(response):
        """Process response and cleanup request context."""
        import time
        
        # Calculate request duration
        if hasattr(g, 'request_start_time'):
            request_duration = time.time() - g.request_start_time
            response.headers['X-Response-Time'] = f"{request_duration:.3f}s"
            
            # Log slow requests
            if request_duration > 1.0:  # Log requests over 1 second
                logger.warning(
                    f"Slow request: {request.method} {request.url} "
                    f"took {request_duration:.3f}s"
                )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add CORS headers if configured
        if app.config.get('CORS_ENABLED', False):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response
    
    @app.teardown_appcontext
    def cleanup_database_session(error):
        """Clean up database session after request completion."""
        try:
            if error:
                db.session.rollback()
                logger.debug("Database session rolled back due to error")
            else:
                db.session.remove()
                logger.debug("Database session cleaned up successfully")
        except Exception as e:
            logger.error(f"Database session cleanup failed: {e}")


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Flask application factory function implementing the Flask 3.1.1 application factory pattern.
    
    This function serves as the main entry point for Flask application creation, replacing
    the Node.js app.js/server.js initialization pattern per Section 0 summary of changes.
    It implements comprehensive Flask application initialization with environment-specific
    configuration, database setup, blueprint registration, and production-ready features.
    
    Args:
        config_name: Environment configuration name ('development', 'testing', 'staging', 'production')
                    If None, determined from FLASK_CONFIG environment variable
    
    Returns:
        Flask: Fully configured Flask application instance ready for WSGI deployment
        
    Raises:
        FlaskApplicationError: If critical application initialization fails
        
    Features:
        - Environment-specific configuration loading with python-dotenv support
        - Flask-SQLAlchemy 3.1.1 database initialization with PostgreSQL backend
        - Flask-Migrate 4.1.0 integration for Alembic-based schema management
        - Automatic blueprint discovery and registration with dependency resolution
        - Production-ready error handling with database rollback capabilities
        - Comprehensive health monitoring endpoints for container orchestration
        - Security headers and request monitoring for production deployment
        - WSGI configuration for Gunicorn/uWSGI deployment compatibility
    
    Environment Variables:
        FLASK_ENV: Environment name (development, testing, staging, production)
        FLASK_CONFIG: Configuration class override
        SECRET_KEY: Flask application secret key for session management
        DATABASE_URL: PostgreSQL connection string with SSL configuration
        SQLALCHEMY_POOL_SIZE: Database connection pool size (default: 20)
        SQLALCHEMY_MAX_OVERFLOW: Additional connections beyond pool size (default: 30)
        LOG_LEVEL: Application logging level (DEBUG, INFO, WARNING, ERROR)
    
    Example:
        # Development server
        from app import create_app
        app = create_app('development')
        app.run(debug=True)
        
        # Production WSGI
        from app import create_app
        application = create_app('production')
    """
    
    # Load environment variables before application initialization
    logger.info("Starting Flask application factory initialization...")
    
    try:
        # Load environment variables from .env files
        if not load_environment_variables():
            logger.warning("Environment variable loading completed with warnings")
        
        # Create Flask application instance
        app = Flask(__name__)
        
        # Configure proxy handling for production deployment
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
        
        # Load configuration based on environment
        config_class = get_config(config_name)
        app.config.from_object(config_class)
        
        # Initialize configuration-specific settings
        config_class.init_app(app)
        
        logger.info(f"Flask application created with {config_class.__name__} configuration")
        
        # Configure logging system
        configure_logging(app)
        
        # Initialize Flask extensions
        if not configure_extensions(app):
            raise FlaskApplicationError(
                "Failed to configure Flask extensions",
                error_code="EXTENSION_INIT_FAILED"
            )
        
        # Register error handlers
        register_error_handlers(app)
        
        # Configure request context processing
        configure_request_context(app)
        
        # Register health monitoring endpoints
        register_health_endpoints(app)
        
        # Register application blueprints
        logger.info("Registering application blueprints...")
        try:
            blueprint_results = register_blueprints(app)
            
            successful_blueprints = sum(1 for success in blueprint_results.values() if success)
            total_blueprints = len(blueprint_results)
            
            logger.info(
                f"Blueprint registration completed: {successful_blueprints}/{total_blueprints} "
                f"blueprints registered successfully"
            )
            
            # Validate minimum required blueprints
            required_blueprints = ['main', 'health']
            missing_required = [
                name for name in required_blueprints 
                if not blueprint_results.get(name, False)
            ]
            
            if missing_required:
                logger.warning(f"Some required blueprints failed to register: {missing_required}")
            
        except BlueprintRegistrationError as e:
            logger.error(f"Blueprint registration failed: {e.message}")
            raise FlaskApplicationError(
                f"Critical blueprint registration failed: {e.message}",
                error_code="BLUEPRINT_REGISTRATION_FAILED",
                details={'blueprint_error': e.error_code, 'blueprint_name': e.blueprint_name}
            )
        
        # Application initialization success
        logger.info(
            f"Flask application factory initialization completed successfully "
            f"(Environment: {app.config.get('FLASK_ENV', 'unknown')}, "
            f"Debug: {app.debug}, Testing: {app.testing})"
        )
        
        return app
        
    except FlaskApplicationError as e:
        logger.error(f"Flask application factory failed: {e.message}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during application factory initialization: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise FlaskApplicationError(
            f"Application factory initialization failed: {str(e)}",
            error_code="FACTORY_INIT_ERROR",
            details={'error': str(e), 'traceback': traceback.format_exc()}
        )


def get_application_info() -> Dict[str, Any]:
    """
    Get comprehensive application information for monitoring and diagnostics.
    
    Returns:
        Dictionary containing application metadata, configuration, and status
        
    Useful for:
        - Application monitoring and health dashboards
        - Debugging and diagnostic information
        - API introspection and documentation
        - Container orchestration health checks
    """
    try:
        from flask import current_app
        
        if not current_app:
            return {'error': 'Application context not available'}
        
        app_info = {
            'application': {
                'name': 'Flask Migration App',
                'version': '1.0.0',
                'environment': current_app.config.get('FLASK_ENV', 'unknown'),
                'debug_mode': current_app.debug,
                'testing_mode': current_app.testing,
                'flask_version': getattr(Flask, '__version__', 'unknown')
            },
            'configuration': {
                'secret_key_configured': bool(current_app.config.get('SECRET_KEY')),
                'database_configured': bool(current_app.config.get('SQLALCHEMY_DATABASE_URI')),
                'session_lifetime': str(current_app.config.get('PERMANENT_SESSION_LIFETIME', 'unknown')),
                'max_content_length': current_app.config.get('MAX_CONTENT_LENGTH')
            },
            'extensions': {
                'sqlalchemy_configured': 'db' in globals(),
                'migrate_configured': 'migrate' in globals(),
                'blueprint_count': len(current_app.config.get('REGISTERED_BLUEPRINTS', []))
            },
            'system': {
                'python_version': sys.version,
                'platform': sys.platform
            }
        }
        
        return app_info
        
    except Exception as e:
        logger.error(f"Failed to get application info: {e}")
        return {'error': f'Failed to retrieve application information: {str(e)}'}


# WSGI Application Instance for Production Deployment
# This creates the application instance that WSGI servers (Gunicorn, uWSGI) will use
try:
    # Create application instance for WSGI server deployment
    application = create_app(config_name=os.environ.get('FLASK_CONFIG'))
    
    # Log successful WSGI application creation
    with application.app_context():
        logger.info("WSGI application instance created successfully for production deployment")
        
except Exception as e:
    # Create a minimal application for error reporting
    application = Flask(__name__)
    
    @application.route('/error')
    def initialization_error():
        return jsonify({
            'error': 'Application Initialization Failed',
            'message': str(e),
            'status': 'critical_error'
        }), 503
    
    logger.error(f"WSGI application creation failed: {e}")


# Development Server Entry Point
if __name__ == '__main__':
    """
    Development server entry point for local development and testing.
    
    This section provides a convenient way to run the Flask application during
    development using the built-in Flask development server. It should not be
    used in production - use WSGI servers like Gunicorn or uWSGI instead.
    
    Usage:
        python app.py                    # Run with default configuration
        FLASK_ENV=development python app.py   # Development mode
        FLASK_ENV=testing python app.py       # Testing mode
    """
    
    try:
        # Create application for development server
        dev_app = create_app()
        
        # Development server configuration
        dev_config = {
            'host': os.environ.get('FLASK_HOST', '0.0.0.0'),
            'port': int(os.environ.get('FLASK_PORT', 5000)),
            'debug': dev_app.debug,
            'use_reloader': dev_app.debug,
            'use_debugger': dev_app.debug,
            'threaded': True
        }
        
        logger.info(
            f"Starting Flask development server: "
            f"http://{dev_config['host']}:{dev_config['port']} "
            f"(Debug: {dev_config['debug']})"
        )
        
        # Start development server
        dev_app.run(**dev_config)
        
    except FlaskApplicationError as e:
        logger.error(f"Development server startup failed: {e.message}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error starting development server: {e}")
        sys.exit(1)