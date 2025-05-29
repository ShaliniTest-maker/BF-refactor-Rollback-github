#!/usr/bin/env python3
"""
Flask Application Factory Pattern Entry Point

This module implements the Flask 3.1.1 application factory pattern as the central
application orchestrator utilizing Python 3.13.3 runtime foundation. It coordinates
between all system components while managing HTTP request lifecycle, route registration,
and response generation as specified in Section 5.1.

The application factory pattern provides structured initialization sequences with
environment-specific configuration loading, blueprint registration orchestration,
and extension integration management, replacing traditional Node.js application
initialization patterns with organized, maintainable Python 3.13.3-based
application lifecycle management.

Author: DevSecOps Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import os
import sys
import logging
from typing import Optional, Dict, Any
from datetime import datetime

# Flask core imports for application factory pattern
from flask import Flask, request, g, current_app, jsonify
from flask.logging import default_handler

# Configuration management imports
from config import Config, DevelopmentConfig, ProductionConfig, StagingConfig

# Database and migration imports - Section 6.2.1
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Authentication imports - Section 6.4.1
from flask_login import LoginManager

# Security and monitoring imports - Section 6.4.6.1
from prometheus_client import CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
import structlog

# Utility imports
from src.utils.config import ConfigValidator, SecureConfigManager
from src.utils.database import DatabaseManager
from src.utils.response import ResponseFormatter

# Import all models for SQLAlchemy metadata creation
from src.models.base import db  # SQLAlchemy instance
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship

# Service layer imports - Section 5.2.3
from src.services.user_service import UserService
from src.services.business_entity_service import BusinessEntityService
from src.services.validation_service import ValidationService
from src.services.workflow_orchestrator import WorkflowOrchestrator

# Authentication system imports - Section 6.4.1
from src.auth.session_manager import FlaskSessionManager
from src.auth.auth0_integration import Auth0Integration
from src.auth.decorators import AuthenticationDecorators

# Monitoring and security imports - Section 6.4.6.1
from src.monitoring.prometheus_metrics import PrometheusSecurityMetrics
from src.monitoring.anomaly_detector import PythonRuntimeAnomalyDetector
from src.security.incident_response import FlaskIncidentResponseSystem


# Global extension instances for Flask application factory pattern
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

# Global service instances
user_service = None
business_entity_service = None
validation_service = None
workflow_orchestrator = None

# Security and monitoring instances
prometheus_metrics = None
anomaly_detector = None
incident_response = None

# Configuration environment mapping
config_mapping = {
    'development': DevelopmentConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'testing': Config  # Base configuration for testing
}


def create_app(config_name: Optional[str] = None) -> Flask:
    """
    Flask Application Factory Pattern Implementation
    
    Creates and configures a Flask application instance with comprehensive
    initialization sequences including environment-specific configuration loading,
    blueprint registration orchestration, and extension integration management
    per Section 5.1.1.
    
    This factory pattern enables structured application lifecycle management
    with systematic database connectivity, authentication system initialization,
    security monitoring setup, and service layer integration while maintaining
    compatibility with existing infrastructure.
    
    Args:
        config_name: Environment configuration name (development|staging|production)
    
    Returns:
        Configured Flask application instance ready for WSGI deployment
    
    Raises:
        RuntimeError: If configuration validation fails or required services unavailable
        ConfigurationError: If environment variables missing or invalid
    """
    
    # Initialize structured logging for application factory
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    logger = structlog.get_logger("flask_factory")
    logger.info(
        "Flask application factory initialization started",
        python_version="3.13.3",
        flask_version="3.1.1",
        config_name=config_name or "auto-detect"
    )
    
    # Create Flask application instance with enhanced configuration
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder='static',
        template_folder='templates'
    )
    
    # Environment-specific configuration loading per Section 5.1.1
    config_name = config_name or os.getenv('FLASK_ENV', 'production')
    
    try:
        # Load and validate configuration
        config_class = config_mapping.get(config_name, ProductionConfig)
        app.config.from_object(config_class)
        
        # Additional configuration from environment variables
        _load_environment_configuration(app)
        
        # Validate configuration integrity
        config_validator = ConfigValidator()
        config_validator.validate_flask_config(app.config)
        
        logger.info(
            "Configuration loaded successfully",
            config_name=config_name,
            database_url_configured=bool(app.config.get('SQLALCHEMY_DATABASE_URI')),
            secret_key_configured=bool(app.config.get('SECRET_KEY'))
        )
        
    except Exception as e:
        logger.error(
            "Configuration loading failed",
            error=str(e),
            config_name=config_name
        )
        raise RuntimeError(f"Failed to load configuration: {str(e)}")
    
    # Initialize database and migration system
    try:
        _initialize_database(app, logger)
        logger.info("Database initialization completed successfully")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        raise RuntimeError(f"Database initialization failed: {str(e)}")
    
    # Initialize authentication system
    try:
        _initialize_authentication(app, logger)
        logger.info("Authentication system initialized successfully")
    except Exception as e:
        logger.error("Authentication initialization failed", error=str(e))
        raise RuntimeError(f"Authentication initialization failed: {str(e)}")
    
    # Initialize service layer
    try:
        _initialize_services(app, logger)
        logger.info("Service layer initialized successfully")
    except Exception as e:
        logger.error("Service layer initialization failed", error=str(e))
        raise RuntimeError(f"Service layer initialization failed: {str(e)}")
    
    # Initialize security and monitoring
    try:
        _initialize_security_monitoring(app, logger)
        logger.info("Security monitoring initialized successfully")
    except Exception as e:
        logger.error("Security monitoring initialization failed", error=str(e))
        raise RuntimeError(f"Security monitoring initialization failed: {str(e)}")
    
    # Register blueprints and routes
    try:
        _register_blueprints(app, logger)
        logger.info("Blueprint registration completed successfully")
    except Exception as e:
        logger.error("Blueprint registration failed", error=str(e))
        raise RuntimeError(f"Blueprint registration failed: {str(e)}")
    
    # Configure error handlers
    _configure_error_handlers(app, logger)
    
    # Configure request/response middleware
    _configure_request_middleware(app, logger)
    
    # Initialize CLI commands
    _register_cli_commands(app, logger)
    
    logger.info(
        "Flask application factory initialization completed",
        app_name=app.name,
        environment=config_name,
        debug_mode=app.debug
    )
    
    return app


def _load_environment_configuration(app: Flask) -> None:
    """
    Load additional configuration from environment variables
    
    Implements environment-specific configuration loading through Flask's
    app.config framework with secure configuration management for sensitive
    settings and API keys per Section 8.4.4.
    
    Args:
        app: Flask application instance
    """
    
    # Database configuration
    if database_url := os.getenv('SQLALCHEMY_DATABASE_URI'):
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    
    # Secret key for session management
    if secret_key := os.getenv('SECRET_KEY'):
        app.config['SECRET_KEY'] = secret_key
    
    # Auth0 configuration
    app.config.update({
        'AUTH0_DOMAIN': os.getenv('AUTH0_DOMAIN'),
        'AUTH0_CLIENT_ID': os.getenv('AUTH0_CLIENT_ID'),
        'AUTH0_CLIENT_SECRET': os.getenv('AUTH0_CLIENT_SECRET'),
        'AUTH0_AUDIENCE': os.getenv('AUTH0_AUDIENCE'),
    })
    
    # AWS configuration
    app.config.update({
        'AWS_REGION': os.getenv('AWS_REGION', 'us-east-1'),
        'AWS_KMS_CMK_ID': os.getenv('AWS_KMS_CMK_ID'),
        'FIELD_ENCRYPTION_KEY': os.getenv('FIELD_ENCRYPTION_KEY'),
    })
    
    # Monitoring configuration
    app.config.update({
        'PROMETHEUS_METRICS_ENABLED': os.getenv('PROMETHEUS_METRICS_ENABLED', 'true').lower() == 'true',
        'INCIDENT_SNS_TOPIC_ARN': os.getenv('INCIDENT_SNS_TOPIC_ARN'),
    })


def _initialize_database(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Initialize Flask-SQLAlchemy database and migration system
    
    Implements PostgreSQL 15.x relational database integration via
    Flask-SQLAlchemy 3.1.1 declarative model system with Flask-Migrate 4.1.0
    for comprehensive schema management per Section 6.2.1.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    # Initialize SQLAlchemy with Flask application
    db.init_app(app)
    
    # Initialize Flask-Migrate for database versioning
    migrate.init_app(app, db)
    
    # Configure database engine options for connection pooling
    engine_options = {
        'pool_size': int(os.getenv('DATABASE_POOL_SIZE', '20')),
        'max_overflow': int(os.getenv('DATABASE_MAX_OVERFLOW', '10')),
        'pool_timeout': int(os.getenv('DATABASE_POOL_TIMEOUT', '30')),
        'pool_recycle': int(os.getenv('DATABASE_POOL_RECYCLE', '3600')),
        'pool_pre_ping': True,  # Essential for containerized environments
    }
    
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options
    
    # Create database tables in application context
    with app.app_context():
        try:
            # Import all models to ensure metadata creation
            from src.models import user, session, business_entity, entity_relationship
            
            # Create database tables if they don't exist
            db.create_all()
            
            logger.info(
                "Database tables created successfully",
                pool_size=engine_options['pool_size'],
                max_overflow=engine_options['max_overflow']
            )
            
        except Exception as e:
            logger.error("Database table creation failed", error=str(e))
            raise
    
    # Initialize database manager utility
    db_manager = DatabaseManager(app, db)
    app.db_manager = db_manager


def _initialize_authentication(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Initialize comprehensive authentication system
    
    Implements Flask-Login integration with Auth0 external identity provider
    and ItsDangerous secure session management per Section 6.4.1.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    # Initialize Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Configure session protection
    login_manager.session_protection = 'strong'
    
    @login_manager.user_loader
    def load_user(user_id: str) -> Optional[User]:
        """
        Load user for Flask-Login session management
        
        Args:
            user_id: User identifier string
            
        Returns:
            User instance or None if not found
        """
        try:
            from src.models.user import User
            return User.query.get(int(user_id))
        except (ValueError, AttributeError):
            return None
    
    # Initialize Flask session manager
    session_manager = FlaskSessionManager(app)
    app.session_manager = session_manager
    
    # Initialize Auth0 integration
    auth0_integration = Auth0Integration(app)
    app.auth0_integration = auth0_integration
    
    # Initialize authentication decorators
    auth_decorators = AuthenticationDecorators(app)
    app.auth_decorators = auth_decorators
    
    logger.info(
        "Authentication system initialized",
        auth0_configured=bool(app.config.get('AUTH0_DOMAIN')),
        session_protection='strong'
    )


def _initialize_services(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Initialize Service Layer pattern implementation
    
    Implements business logic orchestration and workflow implementation
    utilizing the Service Layer architectural pattern per Section 5.2.3.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    global user_service, business_entity_service, validation_service, workflow_orchestrator
    
    # Initialize validation service
    validation_service = ValidationService()
    app.validation_service = validation_service
    
    # Initialize user service
    user_service = UserService(db)
    app.user_service = user_service
    
    # Initialize business entity service
    business_entity_service = BusinessEntityService(db)
    app.business_entity_service = business_entity_service
    
    # Initialize workflow orchestrator
    workflow_orchestrator = WorkflowOrchestrator(
        user_service=user_service,
        business_entity_service=business_entity_service,
        validation_service=validation_service
    )
    app.workflow_orchestrator = workflow_orchestrator
    
    logger.info(
        "Service layer initialized",
        services=['UserService', 'BusinessEntityService', 'ValidationService', 'WorkflowOrchestrator']
    )


def _initialize_security_monitoring(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Initialize security monitoring and incident response systems
    
    Implements Prometheus metrics collection, Python runtime anomaly detection,
    and automated incident response capabilities per Section 6.4.6.1.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    global prometheus_metrics, anomaly_detector, incident_response
    
    # Initialize Prometheus metrics collection
    if app.config.get('PROMETHEUS_METRICS_ENABLED', True):
        prometheus_metrics = PrometheusSecurityMetrics(app)
        app.prometheus_metrics = prometheus_metrics
        
        # Register metrics endpoint
        @app.route('/metrics')
        def metrics_endpoint():
            """Prometheus metrics exposition endpoint"""
            try:
                return generate_latest(prometheus_metrics.security_registry), 200, {
                    'Content-Type': CONTENT_TYPE_LATEST
                }
            except Exception as e:
                logger.error("Metrics endpoint error", error=str(e))
                return jsonify({'error': 'Metrics unavailable'}), 500
    
    # Initialize Python runtime anomaly detector
    anomaly_detector = PythonRuntimeAnomalyDetector()
    app.anomaly_detector = anomaly_detector
    anomaly_detector.start_monitoring()
    
    # Initialize incident response system
    incident_response = FlaskIncidentResponseSystem(app)
    app.incident_response = incident_response
    
    logger.info(
        "Security monitoring initialized",
        prometheus_enabled=app.config.get('PROMETHEUS_METRICS_ENABLED', True),
        anomaly_detection_enabled=True,
        incident_response_enabled=True
    )


def _register_blueprints(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Register Flask blueprints for modular application structure
    
    Implements blueprint registration orchestration during application factory
    initialization, creating modular application structure per Section 5.1.1.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    # Health check endpoint for deployment validation
    @app.route('/health')
    def health_check():
        """
        Application health check endpoint
        
        Returns:
            JSON response with application health status
        """
        try:
            # Test database connectivity
            with app.app_context():
                db.session.execute('SELECT 1')
            
            health_status = {
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'environment': app.config.get('ENV', 'production'),
                'database': 'connected',
                'services': {
                    'authentication': 'available',
                    'user_service': 'available',
                    'business_entity_service': 'available',
                    'validation_service': 'available'
                }
            }
            
            return jsonify(health_status), 200
            
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }), 503
    
    # API info endpoint
    @app.route('/')
    def api_info():
        """
        API information endpoint
        
        Returns:
            JSON response with API information
        """
        return jsonify({
            'name': 'Flask Application',
            'version': '1.0.0',
            'description': 'Flask 3.1.1 application migrated from Node.js',
            'python_version': '3.13.3',
            'endpoints': {
                'health': '/health',
                'metrics': '/metrics' if app.config.get('PROMETHEUS_METRICS_ENABLED') else 'disabled'
            }
        })
    
    # TODO: Register additional blueprints as they are created
    # Example blueprint registration pattern:
    # from src.blueprints.auth import auth_bp
    # app.register_blueprint(auth_bp, url_prefix='/auth')
    # 
    # from src.blueprints.api import api_bp
    # app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    logger.info(
        "Blueprint registration completed",
        registered_routes=['/health', '/', '/metrics'] if app.config.get('PROMETHEUS_METRICS_ENABLED') else ['/health', '/']
    )


def _configure_error_handlers(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Configure comprehensive error handling
    
    Implements error handling with consistent HTTP status codes and
    security incident detection per Section 4.6.3.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 Not Found errors"""
        logger.warning(
            "404 Not Found",
            path=request.path,
            method=request.method,
            ip_address=request.remote_addr
        )
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(401)
    def unauthorized_error(error):
        """Handle 401 Unauthorized errors"""
        logger.warning(
            "401 Unauthorized",
            path=request.path,
            method=request.method,
            ip_address=request.remote_addr
        )
        
        # Track authentication failure with Prometheus metrics
        if hasattr(app, 'prometheus_metrics'):
            app.prometheus_metrics.track_authentication_attempt(
                success=False,
                method='unknown'
            )
        
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden_error(error):
        """Handle 403 Forbidden errors"""
        logger.warning(
            "403 Forbidden",
            path=request.path,
            method=request.method,
            ip_address=request.remote_addr,
            user_id=getattr(g, 'user_id', None)
        )
        
        # Track security event
        if hasattr(app, 'prometheus_metrics'):
            app.prometheus_metrics.track_security_event(
                event_type='authorization_failure',
                severity='warning'
            )
        
        return jsonify({
            'error': 'Forbidden',
            'message': 'Insufficient permissions',
            'status_code': 403
        }), 403
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server errors"""
        logger.error(
            "500 Internal Server Error",
            path=request.path,
            method=request.method,
            error=str(error),
            ip_address=request.remote_addr
        )
        
        # Rollback database session on error
        db.session.rollback()
        
        # Track Python runtime error
        if hasattr(app, 'anomaly_detector'):
            app.anomaly_detector.record_python_error(
                error_type=type(error).__name__,
                blueprint=getattr(g, 'blueprint_name', 'unknown'),
                function=getattr(g, 'endpoint_name', 'unknown'),
                traceback_info=str(error)
            )
        
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    logger.info("Error handlers configured successfully")


def _configure_request_middleware(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Configure request/response middleware for monitoring and security
    
    Implements request context initialization, security monitoring,
    and performance tracking per Section 6.4.6.1.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    @app.before_request
    def before_request():
        """Process requests before route handler execution"""
        import uuid
        import time
        
        # Initialize request context
        g.request_id = str(uuid.uuid4())
        g.start_time = time.time()
        g.blueprint_name = request.blueprint or 'main'
        g.endpoint_name = request.endpoint or 'unknown'
        
        # Track blueprint invocation
        if hasattr(app, 'anomaly_detector'):
            user_id = getattr(g, 'user_id', 'anonymous')
            app.anomaly_detector.record_blueprint_invocation(
                blueprint_name=g.blueprint_name,
                endpoint=g.endpoint_name,
                user_id=user_id,
                duration=0  # Will be updated in after_request
            )
    
    @app.after_request
    def after_request(response):
        """Process responses after route handler execution"""
        if hasattr(g, 'start_time'):
            request_duration = time.time() - g.start_time
            
            # Update Prometheus metrics
            if hasattr(app, 'prometheus_metrics'):
                app.prometheus_metrics._after_request(response)
            
            # Log request completion
            logger.info(
                "Request completed",
                request_id=g.request_id,
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                duration_ms=round(request_duration * 1000, 2),
                blueprint=g.blueprint_name,
                endpoint=g.endpoint_name
            )
        
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
    
    logger.info("Request middleware configured successfully")


def _register_cli_commands(app: Flask, logger: structlog.BoundLogger) -> None:
    """
    Register Flask CLI commands for application management
    
    Implements Click-based command-line interface for database operations,
    user management, and administrative tasks per Section 6.2.3.1.
    
    Args:
        app: Flask application instance
        logger: Structured logger instance
    """
    
    @app.cli.command()
    def init_db():
        """Initialize database with default data"""
        try:
            with app.app_context():
                db.create_all()
                logger.info("Database initialized successfully")
                print("Database initialized successfully")
        except Exception as e:
            logger.error("Database initialization failed", error=str(e))
            print(f"Database initialization failed: {str(e)}")
            sys.exit(1)
    
    @app.cli.command()
    def create_admin():
        """Create admin user"""
        try:
            with app.app_context():
                from src.models.user import User
                from werkzeug.security import generate_password_hash
                
                admin_user = User(
                    username='admin',
                    email='admin@example.com',
                    password_hash=generate_password_hash('admin_password_change_me'),
                    is_active=True
                )
                
                db.session.add(admin_user)
                db.session.commit()
                
                logger.info("Admin user created successfully")
                print("Admin user created successfully")
                print("Username: admin")
                print("Password: admin_password_change_me")
                print("Please change the password immediately!")
                
        except Exception as e:
            logger.error("Admin user creation failed", error=str(e))
            print(f"Admin user creation failed: {str(e)}")
            db.session.rollback()
            sys.exit(1)
    
    @app.cli.command()
    def test_auth():
        """Test authentication system"""
        try:
            with app.app_context():
                if hasattr(app, 'auth0_integration'):
                    print("Auth0 integration: Available")
                else:
                    print("Auth0 integration: Not available")
                
                if hasattr(app, 'session_manager'):
                    print("Session manager: Available")
                else:
                    print("Session manager: Not available")
                
                logger.info("Authentication system test completed")
                
        except Exception as e:
            logger.error("Authentication test failed", error=str(e))
            print(f"Authentication test failed: {str(e)}")
            sys.exit(1)
    
    logger.info("CLI commands registered successfully")


# WSGI Application Entry Point for Gunicorn Deployment
# This enables production deployment with Gunicorn WSGI server per Section 8.1.1
def create_wsgi_app() -> Flask:
    """
    Create WSGI application for Gunicorn deployment
    
    Returns:
        Flask application instance configured for production WSGI deployment
    """
    return create_app(os.getenv('FLASK_ENV', 'production'))


# Application instance for development server and testing
app = create_wsgi_app()


if __name__ == '__main__':
    """
    Development server entry point
    
    Provides Flask development server for local development and testing.
    Production deployments should use Gunicorn WSGI server configuration.
    """
    
    # Development server configuration
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.getenv('FLASK_PORT', '5000'))
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    
    print(f"""
    =============================================================
    Flask Application Development Server
    =============================================================
    Environment: {os.getenv('FLASK_ENV', 'production')}
    Python Version: 3.13.3
    Flask Version: 3.1.1
    Debug Mode: {debug_mode}
    Host: {host}
    Port: {port}
    =============================================================
    Available Endpoints:
    - Health Check: http://{host}:{port}/health
    - API Info: http://{host}:{port}/
    - Metrics: http://{host}:{port}/metrics
    =============================================================
    """)
    
    try:
        app.run(
            host=host,
            port=port,
            debug=debug_mode,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\nApplication shutdown requested by user")
        
        # Cleanup monitoring systems
        if hasattr(app, 'anomaly_detector'):
            app.anomaly_detector.stop_monitoring()
        
        print("Application shutdown completed")
    except Exception as e:
        print(f"Application startup failed: {str(e)}")
        sys.exit(1)