"""
Flask Application Factory and Entry Point

This module serves as the main Flask application orchestrator that coordinates Flask-SQLAlchemy 3.1.1 
database initialization, blueprint registration for modular routing, and environment-specific 
configuration loading. It implements the Flask application factory pattern enabling flexible 
configuration across development, testing, and production environments.

Key Features:
- Flask 3.1.1 application factory pattern with environment-specific configuration management
- Flask-SQLAlchemy 3.1.1 database initialization with PostgreSQL enterprise-grade connection pooling
- Blueprint-based modular architecture replacing Express.js router patterns per Section 5.2.2
- Flask-Migrate 4.1.0 integration for Alembic-based database migration management
- Werkzeug 3.1+ WSGI interface for production deployment with Gunicorn/uWSGI compatibility
- Comprehensive error handling, logging, and health monitoring for container orchestration
- Security integration with ItsDangerous 2.2+ for secure session management
- Environment variable management through python-dotenv 1.0.1 per Section 5.1.1

Architecture Benefits:
- Replaces Node.js/Express.js patterns with Flask's micro-framework approach per Section 0.1.1
- Enables Python ecosystem access for future AI/ML capabilities (TensorFlow, Scikit-learn, PyTorch)
- Maintains complete functional parity with original Node.js implementation
- Provides enhanced maintainability through Python's cleaner syntax and Flask's lightweight design
- Supports horizontal scaling through WSGI server configurations equivalent to Node.js performance

Production Configuration:
- WSGI server compatibility for Gunicorn 20.x and uWSGI 2.x deployment
- Container orchestration integration with health check endpoints and graceful shutdown
- Resource optimization for Python 3.13.3 runtime environment
- Security posture preservation with enhanced cryptographic session protection
- Database connection optimization with connection pooling and transaction management

Author: Flask Migration System
Version: 1.0.0
Compatibility: Flask 3.1.1, Flask-SQLAlchemy 3.1.1, Flask-Migrate 4.1.0, PostgreSQL 14.12+
"""

import os
import sys
import logging
from typing import Optional, Dict, Any, Union
from datetime import datetime, timezone
import traceback

# Core Flask imports for application factory pattern
from flask import Flask, jsonify, request, g, current_app
from flask.logging import default_handler

# Environment variable management
from dotenv import load_dotenv

# Configuration management
from config import get_config, validate_database_connection, Config

# Database initialization
from models import (
    init_database, 
    create_all_tables, 
    DatabaseManager, 
    DatabaseError,
    validate_model_integrity,
    get_model_info
)

# Blueprint registration system
from blueprints import (
    register_all_blueprints, 
    validate_blueprint_registration,
    get_blueprint_registry,
    BlueprintRegistrationError
)

# Load environment variables at module level
load_dotenv()

# Configure module-level logging
logger = logging.getLogger(__name__)


class FlaskApplicationError(Exception):
    """Custom exception for Flask application initialization and configuration errors."""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or 'FLASK_APPLICATION_ERROR'
        self.details = details or {}


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Flask application factory function implementing comprehensive application initialization.
    
    This function creates and configures a Flask application instance with environment-specific
    configuration, database initialization, blueprint registration, and production-ready
    settings for WSGI deployment. It replaces Node.js/Express.js application initialization
    patterns with Flask's application factory pattern per Section 0.1.1.
    
    Args:
        config_name: Environment configuration name (development, testing, production, staging)
                    If None, uses FLASK_CONFIG environment variable or defaults to 'development'
    
    Returns:
        Flask: Fully configured Flask application instance ready for WSGI deployment
        
    Raises:
        FlaskApplicationError: If application initialization fails
        DatabaseError: If database initialization fails
        BlueprintRegistrationError: If blueprint registration fails
        
    Example:
        # Development environment
        app = create_app('development')
        
        # Production environment with environment variable
        os.environ['FLASK_CONFIG'] = 'production'
        app = create_app()
        
        # WSGI deployment
        application = create_app('production')
    """
    try:
        logger.info(f"Initializing Flask application factory (config: {config_name})")
        start_time = datetime.now(timezone.utc)
        
        # Determine configuration environment
        if config_name is None:
            config_name = os.environ.get('FLASK_CONFIG', 'development')
        
        # Get configuration class
        config_class = get_config(config_name)
        logger.info(f"Using configuration: {config_class.__name__}")
        
        # Create Flask application instance
        app = Flask(__name__)
        
        # Configure application with environment-specific settings
        app.config.from_object(config_class)
        
        # Store configuration metadata for debugging and monitoring
        app.config['FLASK_CONFIG_NAME'] = config_name
        app.config['FLASK_CONFIG_CLASS'] = config_class.__name__
        app.config['APPLICATION_START_TIME'] = start_time.isoformat()
        
        # Initialize configuration-specific settings
        config_class.init_app(app)
        
        # Validate critical configuration
        if not _validate_app_configuration(app):
            raise FlaskApplicationError(
                "Critical application configuration validation failed",
                error_code='CONFIG_VALIDATION_ERROR'
            )
        
        # Configure application logging
        _configure_application_logging(app)
        
        # Initialize database system
        logger.info("Initializing database system with Flask-SQLAlchemy 3.1.1")
        init_database(app)
        
        # Validate database connectivity
        with app.app_context():
            if not DatabaseManager.validate_database_connection(app):
                raise DatabaseError("Database connection validation failed during application initialization")
            
            # Validate model integrity
            model_validation = validate_model_integrity()
            if model_validation['status'] != 'valid':
                logger.warning(f"Model validation warnings: {model_validation}")
        
        # Register Flask extensions
        _register_flask_extensions(app)
        
        # Register application blueprints
        logger.info("Registering application blueprints with centralized registration system")
        blueprint_results = register_all_blueprints(app)
        
        if not blueprint_results.get('success', False):
            failed_blueprints = blueprint_results.get('results', {}).get('failed', [])
            if failed_blueprints:
                logger.error(f"Critical blueprint registration failures: {failed_blueprints}")
                raise BlueprintRegistrationError(
                    f"Critical blueprint registration failed: {failed_blueprints}",
                    error_code='BLUEPRINT_REGISTRATION_CRITICAL_FAILURE'
                )
        
        # Register error handlers
        _register_error_handlers(app)
        
        # Register application request handlers and middleware
        _register_request_handlers(app)
        
        # Register application health and monitoring endpoints
        _register_monitoring_endpoints(app)
        
        # Store application metadata for monitoring and debugging
        _store_application_metadata(app, start_time, blueprint_results)
        
        # Perform final application validation
        _perform_final_validation(app)
        
        # Log successful initialization
        initialization_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(
            f"Flask application factory initialization completed successfully "
            f"({initialization_duration:.3f}s) - Ready for WSGI deployment"
        )
        
        return app
        
    except Exception as e:
        error_msg = f"Flask application factory initialization failed: {str(e)}"
        logger.error(error_msg)
        logger.error(f"Error details: {traceback.format_exc()}")
        
        if isinstance(e, (FlaskApplicationError, DatabaseError, BlueprintRegistrationError)):
            raise
        else:
            raise FlaskApplicationError(
                error_msg,
                error_code='APPLICATION_FACTORY_FAILURE',
                details={'original_error': str(e), 'error_type': type(e).__name__}
            )


def _validate_app_configuration(app: Flask) -> bool:
    """
    Validate critical Flask application configuration for production deployment.
    
    Args:
        app: Flask application instance
        
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    try:
        # Required configuration parameters
        required_configs = [
            'SECRET_KEY',
            'SQLALCHEMY_DATABASE_URI'
        ]
        
        validation_errors = []
        
        # Validate required configuration
        for config_key in required_configs:
            if not app.config.get(config_key):
                validation_errors.append(f"Missing required configuration: {config_key}")
        
        # Validate SECRET_KEY security
        secret_key = app.config.get('SECRET_KEY', '')
        if secret_key == 'dev-key-change-in-production' and not app.config.get('TESTING'):
            validation_errors.append("SECRET_KEY must be changed from default value in production")
        
        if len(secret_key) < 32:
            validation_errors.append("SECRET_KEY should be at least 32 characters for security")
        
        # Validate database URI format
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if not db_uri.startswith(('postgresql://', 'postgresql+psycopg2://')):
            validation_errors.append("SQLALCHEMY_DATABASE_URI must be PostgreSQL format")
        
        # Log validation results
        if validation_errors:
            logger.error(f"Configuration validation errors: {validation_errors}")
            return False
        
        logger.info("Application configuration validation passed")
        return True
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {str(e)}")
        return False


def _configure_application_logging(app: Flask) -> None:
    """
    Configure comprehensive application logging for production deployment.
    
    Args:
        app: Flask application instance
    """
    try:
        # Configure log level from configuration
        log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO').upper())
        
        # Configure Flask application logger
        app.logger.setLevel(log_level)
        
        # Remove default handler to prevent duplicate logs
        if default_handler in app.logger.handlers:
            app.logger.removeHandler(default_handler)
        
        # Create custom formatter
        formatter = logging.Formatter(
            app.config.get('LOG_FORMAT', '%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        )
        
        # Configure console handler for development
        if app.config.get('DEBUG') or app.config.get('TESTING'):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
            app.logger.addHandler(console_handler)
        
        # Configure file handler for production
        if not app.config.get('DEBUG') and not app.config.get('TESTING'):
            # Ensure logs directory exists
            if not os.path.exists('logs'):
                os.makedirs('logs')
            
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                'logs/flask_app.log',
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=10
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            app.logger.addHandler(file_handler)
        
        # Log configuration completion
        app.logger.info(f"Application logging configured (level: {logging.getLevelName(log_level)})")
        
    except Exception as e:
        # Fallback logging configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        logger.error(f"Logging configuration failed, using fallback: {str(e)}")


def _register_flask_extensions(app: Flask) -> None:
    """
    Register additional Flask extensions for enhanced functionality.
    
    Args:
        app: Flask application instance
    """
    try:
        # Flask-Migrate is automatically configured through models.init_database()
        # Additional extensions can be registered here if needed
        
        # Configure session security
        app.config.setdefault('SESSION_COOKIE_SECURE', not app.config.get('DEBUG', False))
        app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
        app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
        
        # Configure CSRF protection if available
        if not app.config.get('TESTING'):
            app.config.setdefault('WTF_CSRF_ENABLED', True)
        
        logger.info("Flask extensions registered successfully")
        
    except Exception as e:
        logger.error(f"Flask extensions registration failed: {str(e)}")
        raise FlaskApplicationError(f"Extension registration failed: {str(e)}")


def _register_error_handlers(app: Flask) -> None:
    """
    Register comprehensive error handlers for production deployment.
    
    Args:
        app: Flask application instance
    """
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 Not Found errors with JSON response."""
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'status_code': 404,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 404
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle 400 Bad Request errors with JSON response."""
        return jsonify({
            'error': 'Bad Request',
            'message': 'The request could not be understood or was missing required parameters',
            'status_code': 400,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 400
    
    @app.errorhandler(401)
    def handle_unauthorized(error):
        """Handle 401 Unauthorized errors with JSON response."""
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required to access this resource',
            'status_code': 401,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 401
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        """Handle 403 Forbidden errors with JSON response."""
        return jsonify({
            'error': 'Forbidden',
            'message': 'Access to this resource is forbidden',
            'status_code': 403,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 403
    
    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle 500 Internal Server Error with comprehensive error information."""
        # Log the error details
        app.logger.error(f"Internal server error: {str(error)}")
        app.logger.error(f"Error traceback: {traceback.format_exc()}")
        
        # Return generic error response for security
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred. Please try again later.',
            'status_code': 500,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500
    
    @app.errorhandler(DatabaseError)
    def handle_database_error(error):
        """Handle database-specific errors with appropriate response."""
        app.logger.error(f"Database error: {str(error)}")
        
        return jsonify({
            'error': 'Database Error',
            'message': 'A database error occurred. Please try again later.',
            'status_code': 503,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 503
    
    @app.errorhandler(BlueprintRegistrationError)
    def handle_blueprint_error(error):
        """Handle blueprint registration errors during application startup."""
        app.logger.error(f"Blueprint registration error: {str(error)}")
        
        return jsonify({
            'error': 'Application Configuration Error',
            'message': 'Application initialization error. Please contact support.',
            'status_code': 503,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 503
    
    logger.info("Error handlers registered successfully")


def _register_request_handlers(app: Flask) -> None:
    """
    Register request processing middleware and handlers.
    
    Args:
        app: Flask application instance
    """
    @app.before_request
    def before_request():
        """Execute before each request for logging and tracking."""
        g.request_start_time = datetime.now(timezone.utc)
        g.request_id = f"{int(g.request_start_time.timestamp())}-{os.getpid()}"
        
        # Log incoming request (excluding health checks to reduce noise)
        if not request.path.startswith('/health'):
            app.logger.debug(
                f"Request {g.request_id}: {request.method} {request.path} "
                f"from {request.remote_addr}"
            )
    
    @app.after_request
    def after_request(response):
        """Execute after each request for logging and metrics."""
        if hasattr(g, 'request_start_time'):
            duration = (datetime.now(timezone.utc) - g.request_start_time).total_seconds()
            
            # Log response (excluding health checks to reduce noise)
            if not request.path.startswith('/health'):
                app.logger.debug(
                    f"Response {getattr(g, 'request_id', 'unknown')}: "
                    f"{response.status_code} ({duration:.3f}s)"
                )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add CORS headers if needed (configure based on requirements)
        if app.config.get('CORS_ENABLED', False):
            response.headers['Access-Control-Allow-Origin'] = app.config.get('CORS_ORIGIN', '*')
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response
    
    @app.teardown_appcontext
    def teardown_appcontext(error=None):
        """Execute at the end of each request context."""
        if error:
            app.logger.error(f"Request context teardown error: {str(error)}")
    
    logger.info("Request handlers registered successfully")


def _register_monitoring_endpoints(app: Flask) -> None:
    """
    Register health monitoring and diagnostic endpoints for container orchestration.
    
    Args:
        app: Flask application instance
    """
    @app.route('/health', methods=['GET'])
    def health_check():
        """
        Comprehensive health check endpoint for container orchestration.
        
        Returns detailed health status including database connectivity,
        application metrics, and system information for monitoring systems.
        """
        try:
            health_status = {
                'status': 'healthy',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'application': {
                    'name': 'Flask Application',
                    'version': '1.0.0',
                    'config': app.config.get('FLASK_CONFIG_NAME', 'unknown'),
                    'debug': app.config.get('DEBUG', False),
                    'testing': app.config.get('TESTING', False)
                },
                'services': {},
                'metrics': {}
            }
            
            # Check database health
            try:
                from models import DatabaseManager
                db_health = DatabaseManager.check_database_health()
                health_status['services']['database'] = db_health
                
                if db_health.get('status') != 'healthy':
                    health_status['status'] = 'degraded'
                    
            except Exception as e:
                health_status['services']['database'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health_status['status'] = 'unhealthy'
            
            # Check blueprint registration status
            try:
                blueprint_status = validate_blueprint_registration(app)
                health_status['services']['blueprints'] = {
                    'status': 'healthy',
                    'registered_count': blueprint_status.get('blueprint_count', 0),
                    'routes_count': blueprint_status.get('route_count', 0)
                }
            except Exception as e:
                health_status['services']['blueprints'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health_status['status'] = 'unhealthy'
            
            # Application metrics
            try:
                start_time_str = app.config.get('APPLICATION_START_TIME')
                if start_time_str:
                    start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
                    uptime_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()
                    health_status['metrics']['uptime_seconds'] = uptime_seconds
                
                # Get model information
                model_info = get_model_info()
                health_status['metrics']['models'] = model_info
                
            except Exception as e:
                health_status['metrics']['error'] = str(e)
            
            # Determine final status code
            status_code = 200 if health_status['status'] == 'healthy' else 503
            
            return jsonify(health_status), status_code
            
        except Exception as e:
            app.logger.error(f"Health check endpoint error: {str(e)}")
            return jsonify({
                'status': 'unhealthy',
                'error': 'Health check failed',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 503
    
    @app.route('/health/ready', methods=['GET'])
    def readiness_check():
        """
        Kubernetes readiness probe endpoint for container orchestration.
        
        Returns 200 if application is ready to receive traffic,
        503 if application is starting up or unhealthy.
        """
        try:
            # Check critical services readiness
            from models import DatabaseManager
            
            # Quick database connectivity check
            db_accessible = DatabaseManager.check_database_health().get('database_accessible', False)
            
            if db_accessible:
                return jsonify({
                    'status': 'ready',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 200
            else:
                return jsonify({
                    'status': 'not_ready',
                    'reason': 'database_not_accessible',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 503
                
        except Exception as e:
            app.logger.error(f"Readiness check failed: {str(e)}")
            return jsonify({
                'status': 'not_ready',
                'reason': 'readiness_check_error',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 503
    
    @app.route('/health/live', methods=['GET'])
    def liveness_check():
        """
        Kubernetes liveness probe endpoint for container orchestration.
        
        Returns 200 if application process is alive and responsive,
        used by Kubernetes to determine if container should be restarted.
        """
        return jsonify({
            'status': 'alive',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    
    @app.route('/info', methods=['GET'])
    def application_info():
        """
        Application information endpoint for debugging and monitoring.
        
        Returns comprehensive application metadata including configuration,
        blueprint registration results, and system information.
        """
        try:
            info = {
                'application': {
                    'name': 'Flask Application',
                    'version': '1.0.0',
                    'flask_version': getattr(app, '__version__', 'unknown'),
                    'python_version': sys.version,
                    'config_name': app.config.get('FLASK_CONFIG_NAME'),
                    'config_class': app.config.get('FLASK_CONFIG_CLASS'),
                    'start_time': app.config.get('APPLICATION_START_TIME'),
                    'debug': app.config.get('DEBUG'),
                    'testing': app.config.get('TESTING')
                },
                'blueprints': {},
                'models': {},
                'configuration': {
                    'database_configured': bool(app.config.get('SQLALCHEMY_DATABASE_URI')),
                    'secret_key_configured': bool(app.config.get('SECRET_KEY')),
                    'session_cookie_secure': app.config.get('SESSION_COOKIE_SECURE'),
                    'csrf_enabled': app.config.get('WTF_CSRF_ENABLED')
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Get blueprint information
            blueprint_results = app.config.get('BLUEPRINT_REGISTRATION_RESULTS', {})
            info['blueprints'] = blueprint_results
            
            # Get model information
            model_info = get_model_info()
            info['models'] = model_info
            
            return jsonify(info), 200
            
        except Exception as e:
            app.logger.error(f"Application info endpoint error: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve application information',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 500
    
    logger.info("Monitoring endpoints registered successfully")


def _store_application_metadata(app: Flask, start_time: datetime, blueprint_results: Dict[str, Any]) -> None:
    """
    Store application metadata for monitoring and debugging.
    
    Args:
        app: Flask application instance
        start_time: Application initialization start time
        blueprint_results: Blueprint registration results
    """
    try:
        # Calculate initialization duration
        initialization_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Store comprehensive metadata
        app.config['APPLICATION_METADATA'] = {
            'initialization': {
                'start_time': start_time.isoformat(),
                'duration_seconds': initialization_duration,
                'success': True,
                'timestamp': datetime.now(timezone.utc).isoformat()
            },
            'blueprints': blueprint_results,
            'database': {
                'configured': bool(app.config.get('SQLALCHEMY_DATABASE_URI')),
                'pool_size': app.config.get('SQLALCHEMY_POOL_SIZE'),
                'max_overflow': app.config.get('SQLALCHEMY_MAX_OVERFLOW')
            },
            'security': {
                'secret_key_configured': bool(app.config.get('SECRET_KEY')),
                'session_cookie_secure': app.config.get('SESSION_COOKIE_SECURE'),
                'csrf_enabled': app.config.get('WTF_CSRF_ENABLED')
            }
        }
        
        logger.info(f"Application metadata stored (initialization: {initialization_duration:.3f}s)")
        
    except Exception as e:
        logger.error(f"Failed to store application metadata: {str(e)}")


def _perform_final_validation(app: Flask) -> None:
    """
    Perform final application validation before deployment.
    
    Args:
        app: Flask application instance
        
    Raises:
        FlaskApplicationError: If final validation fails
    """
    try:
        with app.app_context():
            # Validate blueprint registration
            blueprint_validation = validate_blueprint_registration(app)
            if blueprint_validation.get('validation_errors'):
                logger.warning(f"Blueprint validation warnings: {blueprint_validation['validation_errors']}")
            
            # Validate database models
            model_validation = validate_model_integrity()
            if model_validation['status'] != 'valid':
                logger.warning(f"Model validation issues: {model_validation}")
            
            # Validate critical endpoints exist
            critical_endpoints = ['/health', '/health/ready', '/health/live']
            url_map_rules = [rule.rule for rule in app.url_map.iter_rules()]
            
            missing_endpoints = [endpoint for endpoint in critical_endpoints if endpoint not in url_map_rules]
            if missing_endpoints:
                raise FlaskApplicationError(f"Missing critical endpoints: {missing_endpoints}")
            
            logger.info("Final application validation completed successfully")
            
    except Exception as e:
        if isinstance(e, FlaskApplicationError):
            raise
        else:
            raise FlaskApplicationError(f"Final validation failed: {str(e)}")


# WSGI application variable for production deployment
application = None


def get_wsgi_application(config_name: Optional[str] = None) -> Flask:
    """
    Get or create WSGI application instance for production deployment.
    
    This function provides a cached WSGI application instance for production
    deployment with Gunicorn or uWSGI servers. It ensures single application
    initialization for worker processes.
    
    Args:
        config_name: Environment configuration name
        
    Returns:
        Flask: WSGI-ready Flask application instance
    """
    global application
    
    if application is None:
        application = create_app(config_name)
        logger.info("WSGI application instance created and cached")
    
    return application


def main() -> None:
    """
    Main entry point for development server execution.
    
    This function provides a convenient entry point for running the Flask
    development server during development and testing phases.
    """
    try:
        # Load environment-specific configuration
        config_name = os.environ.get('FLASK_CONFIG', 'development')
        
        # Create application instance
        app = create_app(config_name)
        
        # Development server configuration
        host = os.environ.get('FLASK_HOST', '127.0.0.1')
        port = int(os.environ.get('FLASK_PORT', 5000))
        debug = app.config.get('DEBUG', False)
        
        # Log development server startup
        app.logger.info(f"Starting Flask development server on {host}:{port} (debug={debug})")
        
        # Run development server
        app.run(
            host=host,
            port=port,
            debug=debug,
            use_reloader=debug,
            threaded=True
        )
        
    except Exception as e:
        logger.error(f"Development server startup failed: {str(e)}")
        sys.exit(1)


# Export application factory and WSGI interface
__all__ = [
    'create_app',
    'get_wsgi_application',
    'FlaskApplicationError',
    'main'
]


# WSGI application initialization for production deployment
if __name__ != '__main__':
    # Production WSGI deployment - create application instance
    application = get_wsgi_application()
else:
    # Development execution - run development server
    if __name__ == '__main__':
        main()


# Module initialization logging
logger.info("Flask application factory module initialized successfully")