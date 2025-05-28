"""
Flask Application Factory Pattern Entry Point

This module implements the Flask 3.1.1 application factory pattern for organized
application initialization, configuration management, and WSGI server coordination.
Serves as the central application orchestrator utilizing Python 3.13.3 runtime
foundation and coordinates between all system components while managing HTTP
request lifecycle, route registration, and response generation.

The application factory pattern provides:
- Environment-specific configuration loading through Flask's app.config framework
- Blueprint registration orchestration for modular application structure
- Extension integration management replacing Node.js application initialization patterns
- Gunicorn WSGI server configuration for production-grade deployment

Architecture:
- Flask 3.1.1 application factory pattern implementation
- Blueprint-based modular architecture replacing Express.js route handlers
- Service Layer pattern integration for business logic orchestration
- Flask-SQLAlchemy 3.1.1 for database model management
- Flask-Migrate 4.1.0 for database version control
- Flask-Login for authentication and session management
- ItsDangerous 2.2+ for secure session cookie protection
- Comprehensive error handling and monitoring integration

Dependencies:
- Flask 3.1.1 with Werkzeug 3.1+, Jinja2 3.1.2+, ItsDangerous 2.2+
- Flask-SQLAlchemy 3.1.1 for PostgreSQL 14 integration
- Flask-Migrate 4.1.0 for database migration management
- Flask-Login for authentication decorator patterns
- Flask-WTF for CSRF protection
- Flask-Limiter for rate limiting and security
- Gunicorn for production WSGI server deployment

Author: Flask Migration Team
Version: 1.0.0
Last Updated: 2024
"""

import os
import sys
import logging
import traceback
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timedelta
import click
from flask import Flask, request, jsonify, g, current_app
from flask.cli import with_appcontext
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

# Configuration management
from config import get_config, validate_environment, get_config_summary

# Extension imports for Flask application initialization
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask extensions globally for import in other modules
# Flask-SQLAlchemy 3.1.1 database integration
db = SQLAlchemy()

# Flask-Migrate 4.1.0 database migration management
migrate = Migrate()

# Flask-Login authentication and session management
login_manager = LoginManager()

# Flask-WTF CSRF protection
csrf = CSRFProtect()

# Flask-Limiter rate limiting for security and performance
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",  # Will be configured with Redis in production
)


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Flask application factory pattern implementation for organized application
    initialization and configuration management.
    
    This factory function creates and configures a Flask application instance
    with environment-specific configuration loading, systematic blueprint
    registration, extension integration, and comprehensive error handling.
    Replaces Node.js application initialization patterns with Python 3.13.3
    runtime-based architecture.
    
    The factory pattern enables:
    - Environment-specific configuration loading (development, testing, production)
    - Systematic blueprint registration for modular route organization
    - Extension integration with proper initialization order
    - Database connection and migration management
    - Authentication and security configuration
    - Monitoring and observability setup
    - Error handling and recovery workflows
    
    Args:
        config_name: Environment configuration name (development, testing, 
                    staging, production). If None, uses FLASK_ENV environment
                    variable or defaults to 'development'.
                    
    Returns:
        Flask: Configured Flask application instance ready for WSGI deployment
        
    Raises:
        ValueError: If configuration validation fails
        RuntimeError: If critical application setup fails
        
    Examples:
        >>> # Create development application
        >>> app = create_app('development')
        >>> 
        >>> # Create production application
        >>> app = create_app('production')
        >>> 
        >>> # Auto-detect environment
        >>> app = create_app()  # Uses FLASK_ENV or defaults to development
    """
    
    # Create Flask application instance with optimal configuration
    app = Flask(__name__)
    
    # Load environment-specific configuration
    config_class = get_config(config_name)
    app.config.from_object(config_class)
    
    # Apply configuration-specific initialization
    config_class.init_app(app)
    
    # Configure proxy headers for production deployment behind load balancers
    if app.config.get('FLASK_ENV') == 'production':
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,
            x_proto=1,
            x_host=1,
            x_prefix=1
        )
    
    # Initialize Flask extensions with proper order
    _initialize_extensions(app)
    
    # Configure authentication and security
    _configure_authentication(app)
    
    # Register application blueprints
    _register_blueprints(app)
    
    # Configure error handlers
    _configure_error_handlers(app)
    
    # Set up logging and monitoring
    _configure_logging(app)
    
    # Register CLI commands
    _register_cli_commands(app)
    
    # Configure request/response middleware
    _configure_middleware(app)
    
    # Add health check and monitoring endpoints
    _register_health_endpoints(app)
    
    # Validate application configuration
    _validate_application_config(app)
    
    # Log successful application creation
    app.logger.info(
        f"Flask application created successfully - Environment: {app.config.get('FLASK_ENV')}"
    )
    
    return app


def _initialize_extensions(app: Flask) -> None:
    """
    Initialize Flask extensions with proper configuration and order.
    
    Initializes all Flask extensions required for the application including
    database integration, migration management, authentication, security,
    and rate limiting. Ensures proper initialization order to prevent
    circular dependencies and configuration conflicts.
    
    Extensions initialized:
    - Flask-SQLAlchemy for database ORM functionality
    - Flask-Migrate for database version control
    - Flask-Login for authentication and session management
    - Flask-WTF for CSRF protection
    - Flask-Limiter for rate limiting and security
    
    Args:
        app: Flask application instance
        
    Raises:
        RuntimeError: If extension initialization fails
    """
    try:
        # Initialize database ORM (Flask-SQLAlchemy 3.1.1)
        db.init_app(app)
        app.logger.debug("Flask-SQLAlchemy initialized successfully")
        
        # Initialize database migrations (Flask-Migrate 4.1.0)
        migrate.init_app(app, db, directory='migrations')
        app.logger.debug("Flask-Migrate initialized successfully")
        
        # Initialize authentication manager (Flask-Login)
        login_manager.init_app(app)
        app.logger.debug("Flask-Login initialized successfully")
        
        # Initialize CSRF protection (Flask-WTF)
        if app.config.get('WTF_CSRF_ENABLED', True):
            csrf.init_app(app)
            app.logger.debug("Flask-WTF CSRF protection enabled")
        
        # Initialize rate limiting (Flask-Limiter)
        # Configure Redis storage for production environments
        if app.config.get('RATELIMIT_ENABLED', True):
            redis_url = app.config.get('RATELIMIT_STORAGE_URL')
            if redis_url and redis_url != 'memory://':
                limiter.storage_uri = redis_url
            limiter.init_app(app)
            app.logger.debug("Flask-Limiter rate limiting enabled")
        
        app.logger.info("All Flask extensions initialized successfully")
        
    except Exception as e:
        app.logger.error(f"Failed to initialize Flask extensions: {str(e)}")
        raise RuntimeError(f"Extension initialization failed: {str(e)}")


def _configure_authentication(app: Flask) -> None:
    """
    Configure Flask-Login authentication and session management.
    
    Sets up authentication configuration including login manager settings,
    user loader callback, authentication decorators, and session management.
    Integrates with ItsDangerous for secure session cookie protection and
    maintains compatibility with existing user access patterns.
    
    Authentication features configured:
    - Flask-Login session management with secure cookies
    - User loader callback for session restoration
    - Login view and message configuration
    - Session protection and security settings
    - Remember-me functionality for user convenience
    
    Args:
        app: Flask application instance
    """
    # Configure Flask-Login settings
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'
    login_manager.remember_cookie_duration = timedelta(
        hours=app.config.get('SESSION_TIMEOUT_HOURS', 24)
    )
    login_manager.remember_cookie_secure = app.config.get('FLASK_ENV') == 'production'
    login_manager.remember_cookie_httponly = True
    
    # User loader callback for Flask-Login session restoration
    @login_manager.user_loader
    def load_user(user_id: str):
        """
        Flask-Login user loader callback for session restoration.
        
        Loads user from database using user ID stored in session.
        Required for Flask-Login authentication decorator functionality.
        
        Args:
            user_id: String representation of user primary key
            
        Returns:
            User: User model instance or None if user not found
        """
        try:
            # Import here to avoid circular imports
            from src.models.user import User
            return User.query.get(int(user_id))
        except (ValueError, TypeError):
            return None
        except Exception as e:
            app.logger.error(f"Error loading user {user_id}: {str(e)}")
            return None
    
    # Unauthorized handler for authentication failures
    @login_manager.unauthorized_handler
    def unauthorized():
        """
        Handle unauthorized access attempts.
        
        Returns appropriate response for unauthenticated users based on
        request type (JSON API vs web page).
        
        Returns:
            Response: Redirect to login page or JSON error response
        """
        if request.is_json:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource',
                'status': 401
            }), 401
        else:
            return redirect(url_for('auth.login', next=request.url))
    
    app.logger.debug("Flask-Login authentication configured successfully")


def _register_blueprints(app: Flask) -> None:
    """
    Register Flask blueprints for modular application structure.
    
    Implements systematic blueprint registration sequence for organized
    route management and API endpoint definitions. Replaces Express.js
    route handler patterns with Flask's blueprint-based modular architecture.
    
    Blueprints registered:
    - Main blueprint: Core application routes and health checks
    - API blueprint: RESTful API endpoints for business operations
    - Auth blueprint: Authentication and authorization endpoints
    
    Args:
        app: Flask application instance
        
    Raises:
        ImportError: If blueprint modules cannot be imported
        RuntimeError: If blueprint registration fails
    """
    try:
        # Import blueprint modules
        from src.blueprints import register_blueprints
        
        # Register all blueprints through centralized registration
        register_blueprints(app)
        
        app.logger.info("All application blueprints registered successfully")
        
    except ImportError as e:
        app.logger.error(f"Failed to import blueprint modules: {str(e)}")
        raise RuntimeError(f"Blueprint import failed: {str(e)}")
    except Exception as e:
        app.logger.error(f"Failed to register blueprints: {str(e)}")
        raise RuntimeError(f"Blueprint registration failed: {str(e)}")


def _configure_error_handlers(app: Flask) -> None:
    """
    Configure global error handlers for comprehensive error management.
    
    Implements standardized error handling with consistent JSON responses
    for API endpoints and appropriate error pages for web requests.
    Provides comprehensive error logging for debugging and monitoring.
    
    Error handlers configured:
    - 400 Bad Request
    - 401 Unauthorized
    - 403 Forbidden
    - 404 Not Found
    - 405 Method Not Allowed
    - 422 Unprocessable Entity
    - 429 Too Many Requests
    - 500 Internal Server Error
    - Generic exception handler
    
    Args:
        app: Flask application instance
    """
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle 400 Bad Request errors."""
        return _format_error_response(error, 400, 'Bad Request')
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle 401 Unauthorized errors."""
        return _format_error_response(error, 401, 'Unauthorized')
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 Forbidden errors."""
        return _format_error_response(error, 403, 'Forbidden')
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found errors."""
        return _format_error_response(error, 404, 'Not Found')
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        """Handle 405 Method Not Allowed errors."""
        return _format_error_response(error, 405, 'Method Not Allowed')
    
    @app.errorhandler(422)
    def unprocessable_entity(error):
        """Handle 422 Unprocessable Entity errors."""
        return _format_error_response(error, 422, 'Unprocessable Entity')
    
    @app.errorhandler(429)
    def too_many_requests(error):
        """Handle 429 Too Many Requests errors."""
        return _format_error_response(error, 429, 'Too Many Requests')
    
    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 Internal Server Error."""
        # Log full traceback for debugging
        app.logger.error(f"Internal server error: {str(error)}")
        app.logger.error(traceback.format_exc())
        
        # Rollback database session if active
        try:
            db.session.rollback()
        except:
            pass
        
        return _format_error_response(error, 500, 'Internal Server Error')
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle all unhandled exceptions."""
        # Log the full exception with traceback
        app.logger.error(f"Unhandled exception: {str(error)}")
        app.logger.error(traceback.format_exc())
        
        # Rollback database session if active
        try:
            db.session.rollback()
        except:
            pass
        
        # Return appropriate response based on exception type
        if isinstance(error, HTTPException):
            return _format_error_response(error, error.code, error.name)
        else:
            return _format_error_response(error, 500, 'Internal Server Error')
    
    app.logger.debug("Global error handlers configured successfully")


def _format_error_response(error, status_code: int, error_type: str) -> tuple:
    """
    Format standardized error responses for API and web requests.
    
    Creates consistent error response format with appropriate status codes
    and error messages. Supports both JSON API responses and HTML error pages.
    
    Args:
        error: Exception or error object
        status_code: HTTP status code
        error_type: Human-readable error type
        
    Returns:
        tuple: (response, status_code) for Flask error handler
    """
    # Determine if this is an API request
    is_api_request = (
        request.is_json or 
        request.path.startswith('/api/') or
        'application/json' in request.headers.get('Accept', '')
    )
    
    # Create error response data
    error_data = {
        'error': error_type,
        'message': getattr(error, 'description', str(error)),
        'status': status_code,
        'timestamp': datetime.utcnow().isoformat(),
        'path': request.path
    }
    
    # Add request ID if available
    if hasattr(g, 'request_id'):
        error_data['request_id'] = g.request_id
    
    if is_api_request:
        # Return JSON response for API requests
        return jsonify(error_data), status_code
    else:
        # For web requests, you might want to render an error template
        # For now, return JSON for consistency
        return jsonify(error_data), status_code


def _configure_logging(app: Flask) -> None:
    """
    Configure application logging for monitoring and debugging.
    
    Sets up structured logging with appropriate formatters, handlers,
    and log levels based on environment configuration. Integrates with
    external monitoring systems and provides comprehensive audit trails.
    
    Logging features configured:
    - Environment-specific log levels and formats
    - Structured JSON logging for production
    - Request/response logging for debugging
    - Security event logging
    - Performance monitoring integration
    
    Args:
        app: Flask application instance
    """
    # Configure logging based on environment
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    log_format = app.config.get('LOG_FORMAT', 'text')
    
    # Remove default Flask handlers
    app.logger.handlers.clear()
    
    # Create handler based on configuration
    if app.config.get('LOG_TO_STDOUT', True):
        handler = logging.StreamHandler(sys.stdout)
    else:
        # File logging for development
        log_file = app.config.get('LOG_FILE', 'flask_app.log')
        handler = logging.FileHandler(log_file)
    
    # Configure formatter based on environment
    if log_format == 'json':
        # Structured JSON logging for production
        formatter = _get_json_formatter()
    else:
        # Human-readable logging for development
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    handler.setFormatter(formatter)
    handler.setLevel(log_level)
    
    # Add handler to app logger
    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)
    
    # Configure other loggers
    for logger_name in ['flask.app', 'werkzeug', 'sqlalchemy.engine']:
        logger = logging.getLogger(logger_name)
        logger.handlers = [handler]
        logger.setLevel(log_level)
        logger.propagate = False
    
    app.logger.info(f"Logging configured - Level: {app.config.get('LOG_LEVEL')}, Format: {log_format}")


def _get_json_formatter() -> logging.Formatter:
    """
    Create JSON formatter for structured logging.
    
    Returns:
        logging.Formatter: JSON formatter for production logging
    """
    import json
    
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            log_entry = {
                'timestamp': self.formatTime(record),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno
            }
            
            # Add request context if available
            if request:
                log_entry.update({
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent')
                })
            
            # Add request ID if available
            if hasattr(g, 'request_id'):
                log_entry['request_id'] = g.request_id
            
            # Add exception info if present
            if record.exc_info:
                log_entry['exception'] = self.formatException(record.exc_info)
            
            return json.dumps(log_entry)
    
    return JsonFormatter()


def _register_cli_commands(app: Flask) -> None:
    """
    Register Flask CLI commands for management and administration.
    
    Provides command-line interface for common administrative tasks
    including database operations, user management, and system maintenance.
    Integrates with Click 8.1.3+ for comprehensive CLI functionality.
    
    CLI commands registered:
    - Database initialization and migration
    - User management operations
    - Configuration validation
    - Health checks and diagnostics
    
    Args:
        app: Flask application instance
    """
    
    @app.cli.command('init-db')
    @with_appcontext
    def init_db_command():
        """Initialize the database with all tables."""
        try:
            db.create_all()
            click.echo('Database initialized successfully.')
        except Exception as e:
            click.echo(f'Error initializing database: {str(e)}', err=True)
    
    @app.cli.command('validate-config')
    @with_appcontext
    def validate_config_command():
        """Validate application configuration."""
        try:
            validation_results = validate_environment()
            
            if validation_results['valid']:
                click.echo('✓ Configuration is valid')
            else:
                click.echo('✗ Configuration validation failed:', err=True)
                for error in validation_results['errors']:
                    click.echo(f'  - {error}', err=True)
            
            if validation_results['warnings']:
                click.echo('Warnings:')
                for warning in validation_results['warnings']:
                    click.echo(f'  - {warning}')
                    
        except Exception as e:
            click.echo(f'Configuration validation error: {str(e)}', err=True)
    
    @app.cli.command('create-admin')
    @click.option('--username', prompt=True, help='Admin username')
    @click.option('--email', prompt=True, help='Admin email')
    @click.option('--password', prompt=True, hide_input=True, help='Admin password')
    @with_appcontext
    def create_admin_command(username, email, password):
        """Create an admin user."""
        try:
            from src.models.user import User
            from werkzeug.security import generate_password_hash
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                click.echo(f'User {username} already exists', err=True)
                return
            
            # Create new admin user
            admin_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_admin=True,
                is_active=True
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            click.echo(f'Admin user {username} created successfully')
            
        except Exception as e:
            db.session.rollback()
            click.echo(f'Error creating admin user: {str(e)}', err=True)
    
    @app.cli.command('health-check')
    @with_appcontext
    def health_check_command():
        """Perform application health check."""
        try:
            # Check database connection
            db.session.execute('SELECT 1')
            click.echo('✓ Database connection: OK')
            
            # Check configuration
            validation_results = validate_environment()
            if validation_results['valid']:
                click.echo('✓ Configuration: OK')
            else:
                click.echo('✗ Configuration: FAILED', err=True)
                return
            
            # Check Redis connection if configured
            redis_url = app.config.get('REDIS_URL')
            if redis_url and redis_url != 'memory://':
                try:
                    import redis
                    r = redis.from_url(redis_url)
                    r.ping()
                    click.echo('✓ Redis connection: OK')
                except:
                    click.echo('✗ Redis connection: FAILED', err=True)
            
            click.echo('Application health check completed successfully')
            
        except Exception as e:
            click.echo(f'Health check failed: {str(e)}', err=True)
    
    app.logger.debug("CLI commands registered successfully")


def _configure_middleware(app: Flask) -> None:
    """
    Configure request/response middleware for enhanced functionality.
    
    Sets up middleware components for request processing including
    request ID generation, security headers, CORS configuration,
    and performance monitoring. Replaces Express.js middleware
    patterns with Flask's request processing mechanisms.
    
    Middleware configured:
    - Request ID generation for request tracking
    - Security headers for enhanced protection
    - Request/response timing for performance monitoring
    - Database session management
    
    Args:
        app: Flask application instance
    """
    
    @app.before_request
    def before_request():
        """Execute before each request."""
        import uuid
        
        # Generate unique request ID for tracking
        g.request_id = str(uuid.uuid4())
        g.start_time = datetime.utcnow()
        
        # Log request start
        app.logger.debug(
            f"Request started - {request.method} {request.path} "
            f"(ID: {g.request_id})"
        )
    
    @app.after_request
    def after_request(response):
        """Execute after each request."""
        # Calculate request duration
        if hasattr(g, 'start_time'):
            duration = (datetime.utcnow() - g.start_time).total_seconds()
            response.headers['X-Response-Time'] = f"{duration:.3f}s"
        
        # Add request ID to response headers
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        
        # Add security headers
        if app.config.get('FLASK_ENV') == 'production':
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains'
            )
        
        # Log request completion
        app.logger.debug(
            f"Request completed - {request.method} {request.path} "
            f"Status: {response.status_code} "
            f"(ID: {getattr(g, 'request_id', 'unknown')})"
        )
        
        return response
    
    @app.teardown_appcontext
    def teardown_appcontext(exception):
        """Clean up application context."""
        if exception:
            # Rollback database session on exception
            try:
                db.session.rollback()
            except:
                pass
        else:
            # Commit successful transactions
            try:
                db.session.commit()
            except Exception as e:
                app.logger.error(f"Error committing database session: {str(e)}")
                db.session.rollback()
        
        # Remove database session
        db.session.remove()
    
    app.logger.debug("Request/response middleware configured successfully")


def _register_health_endpoints(app: Flask) -> None:
    """
    Register health check and monitoring endpoints.
    
    Provides endpoints for system health monitoring, application status,
    and observability integration. Supports container orchestration
    health checks and external monitoring systems.
    
    Endpoints registered:
    - /health: Basic health check endpoint
    - /health/detailed: Comprehensive health status
    - /metrics: Prometheus-compatible metrics (if enabled)
    - /status: Application status and configuration summary
    
    Args:
        app: Flask application instance
    """
    
    @app.route('/health')
    def health_check():
        """Basic health check endpoint for load balancer monitoring."""
        try:
            # Quick database connectivity check
            db.session.execute('SELECT 1')
            
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0'
            }), 200
            
        except Exception as e:
            app.logger.error(f"Health check failed: {str(e)}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 503
    
    @app.route('/health/detailed')
    def detailed_health_check():
        """Comprehensive health check with component status."""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0',
            'environment': app.config.get('FLASK_ENV'),
            'components': {}
        }
        
        overall_healthy = True
        
        # Database health check
        try:
            db.session.execute('SELECT 1')
            health_status['components']['database'] = {
                'status': 'healthy',
                'response_time_ms': 0  # Could add timing here
            }
        except Exception as e:
            health_status['components']['database'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            overall_healthy = False
        
        # Redis health check (if configured)
        redis_url = app.config.get('REDIS_URL')
        if redis_url and redis_url != 'memory://':
            try:
                import redis
                r = redis.from_url(redis_url)
                r.ping()
                health_status['components']['redis'] = {
                    'status': 'healthy'
                }
            except Exception as e:
                health_status['components']['redis'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                overall_healthy = False
        
        # Configuration validation
        try:
            validation_results = validate_environment()
            if validation_results['valid']:
                health_status['components']['configuration'] = {
                    'status': 'healthy'
                }
            else:
                health_status['components']['configuration'] = {
                    'status': 'unhealthy',
                    'errors': validation_results['errors']
                }
                overall_healthy = False
        except Exception as e:
            health_status['components']['configuration'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            overall_healthy = False
        
        # Update overall status
        if not overall_healthy:
            health_status['status'] = 'unhealthy'
        
        return jsonify(health_status), 200 if overall_healthy else 503
    
    @app.route('/status')
    def application_status():
        """Application status and configuration summary."""
        try:
            status_info = {
                'application': 'Flask Application',
                'version': '1.0.0',
                'environment': app.config.get('FLASK_ENV'),
                'debug': app.config.get('DEBUG', False),
                'timestamp': datetime.utcnow().isoformat(),
                'configuration': get_config_summary(),
                'uptime': _get_application_uptime(),
                'python_version': sys.version,
                'flask_version': app.config.get('FLASK_VERSION', 'Unknown')
            }
            
            return jsonify(status_info), 200
            
        except Exception as e:
            app.logger.error(f"Status endpoint error: {str(e)}")
            return jsonify({
                'error': 'Unable to retrieve application status',
                'message': str(e)
            }), 500
    
    # Metrics endpoint (if enabled)
    if app.config.get('METRICS_ENABLED', False):
        @app.route('/metrics')
        def metrics():
            """Prometheus-compatible metrics endpoint."""
            try:
                # Basic metrics - in production, you might use prometheus_client
                metrics_data = f"""
# HELP flask_requests_total Total number of HTTP requests
# TYPE flask_requests_total counter
flask_requests_total {{method="GET"}} 0

# HELP flask_request_duration_seconds Request duration in seconds
# TYPE flask_request_duration_seconds histogram
flask_request_duration_seconds_bucket {{le="0.1"}} 0

# HELP flask_app_info Application information
# TYPE flask_app_info gauge
flask_app_info {{version="1.0.0",environment="{app.config.get('FLASK_ENV')}"}} 1
"""
                return metrics_data, 200, {'Content-Type': 'text/plain'}
                
            except Exception as e:
                app.logger.error(f"Metrics endpoint error: {str(e)}")
                return "Error generating metrics", 500
    
    app.logger.debug("Health check and monitoring endpoints registered successfully")


def _get_application_uptime() -> Dict[str, Any]:
    """
    Calculate application uptime information.
    
    Returns:
        Dict[str, Any]: Uptime information including start time and duration
    """
    # This is a simplified implementation
    # In production, you might track actual application start time
    return {
        'start_time': datetime.utcnow().isoformat(),
        'uptime_seconds': 0
    }


def _validate_application_config(app: Flask) -> None:
    """
    Validate application configuration after initialization.
    
    Performs final validation of application configuration to ensure
    all required components are properly configured and accessible.
    
    Args:
        app: Flask application instance
        
    Raises:
        RuntimeError: If critical configuration validation fails
    """
    try:
        # Validate environment configuration
        validation_results = validate_environment()
        
        if not validation_results['valid']:
            error_msg = f"Configuration validation failed: {validation_results['errors']}"
            app.logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        # Log configuration warnings
        if validation_results['warnings']:
            for warning in validation_results['warnings']:
                app.logger.warning(f"Configuration warning: {warning}")
        
        # Test database connection
        with app.app_context():
            db.session.execute('SELECT 1')
            app.logger.debug("Database connection validated successfully")
        
        app.logger.info("Application configuration validation completed successfully")
        
    except Exception as e:
        app.logger.error(f"Application configuration validation failed: {str(e)}")
        raise RuntimeError(f"Configuration validation failed: {str(e)}")


# WSGI application instance for Gunicorn deployment
# This enables direct WSGI server integration for production deployment
def get_wsgi_application() -> Flask:
    """
    Get WSGI application instance for production deployment.
    
    Creates and returns a Flask application instance configured for
    production WSGI server deployment with Gunicorn. Used by WSGI
    servers and container orchestration platforms.
    
    Returns:
        Flask: Production-ready Flask application instance
    """
    return create_app(config_name='production')


# Application factory for development server
if __name__ == '__main__':
    """
    Development server entry point for local development.
    
    Creates Flask application in development mode and starts the built-in
    development server. Not suitable for production deployment - use
    Gunicorn WSGI server for production environments.
    """
    # Create development application
    app = create_app('development')
    
    # Get host and port from environment or use defaults
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = app.config.get('DEBUG', True)
    
    # Log development server startup
    app.logger.info(f"Starting Flask development server on {host}:{port}")
    
    # Start development server
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True,  # Enable threading for better concurrent handling
        use_reloader=debug,  # Auto-reload on code changes in debug mode
        use_debugger=debug   # Enable Werkzeug debugger in debug mode
    )