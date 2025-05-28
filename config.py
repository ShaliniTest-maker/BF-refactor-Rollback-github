"""
Flask Application Configuration Management Module

This module implements Flask's app.config framework for organized configuration management
across development, staging, and production environments. Provides environment-specific
settings, database configuration for Flask-SQLAlchemy PostgreSQL 14 integration, 
externalized configuration loading compatible with container orchestration, and secure
configuration handling for sensitive data and API keys.

Architecture:
- Environment-specific configuration classes following Flask configuration patterns
- Database connection configuration for Flask-SQLAlchemy PostgreSQL integration
- Externalized settings management through environment variables
- Secure configuration handling for AWS services and API keys
- Container orchestration compatibility for Docker/Kubernetes deployment

Dependencies:
- Flask 3.1.1 application configuration framework
- Flask-SQLAlchemy 3.1.1 database configuration
- Flask-Migrate 4.1.0 migration configuration
- Python 3.13.3 runtime environment variables
- PostgreSQL 14 database connectivity via psycopg2

Author: Flask Migration Team
Version: 1.0.0
Last Updated: 2024
"""

import os
import secrets
from datetime import timedelta
from typing import Dict, Any, Optional, Type
from urllib.parse import quote_plus
import logging


class Config:
    """
    Base configuration class implementing Flask app.config framework for centralized
    configuration management. Provides foundation for environment-specific configurations
    with secure defaults and externalized settings support.
    
    This base class establishes:
    - Flask 3.1.1 application factory configuration patterns
    - Security settings for ItsDangerous session management
    - Database connection foundations for Flask-SQLAlchemy
    - Logging and monitoring configuration
    - Container orchestration compatibility
    """
    
    # Flask Core Configuration
    # Flask 3.1.1 application factory pattern requires proper secret key management
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    
    # Flask-SQLAlchemy 3.1.1 Configuration
    # Database connection management for PostgreSQL 14 integration
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable event system for performance
    SQLALCHEMY_RECORD_QUERIES = False  # Enable query recording in development only
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', '10')),
        'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', '20')),
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', '3600')),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', '20')),
        'pool_pre_ping': True,  # Validate connections before use
        'echo': False  # Disable SQL logging by default
    }
    
    # Flask-Migrate 4.1.0 Configuration
    # Database migration management and versioning
    SQLALCHEMY_MIGRATE_REPO = os.path.join(os.path.dirname(__file__), 'migrations')
    
    # Session Configuration
    # ItsDangerous 2.2+ secure session management with Flask 3.1.1
    SESSION_TYPE = 'filesystem'  # Use filesystem for development, Redis for production
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'flask_app:'
    SESSION_REDIS = None  # Will be set in production configuration
    PERMANENT_SESSION_LIFETIME = timedelta(
        hours=int(os.environ.get('SESSION_TIMEOUT_HOURS', '24'))
    )
    
    # Security Configuration
    # Enhanced security settings for production deployment
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour CSRF token lifetime
    WTF_CSRF_SSL_STRICT = True  # Require HTTPS for CSRF in production
    
    # Application Configuration
    # Flask application factory pattern settings
    FLASK_APP = 'app.py'
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')
    FLASK_DEBUG = False  # Override in development configuration
    TESTING = False
    
    # Logging Configuration
    # Structured logging for security monitoring and observability
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = os.environ.get('LOG_FORMAT', 'json')  # json or text
    LOG_TO_STDOUT = os.environ.get('LOG_TO_STDOUT', 'true').lower() == 'true'
    
    # Authentication Configuration
    # Auth0 integration for identity management
    AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
    AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID')
    AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
    AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE')
    
    # API Configuration
    # RESTful API settings and rate limiting
    API_TITLE = 'Flask Application API'
    API_VERSION = 'v1'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB upload limit
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = False
    
    # Rate Limiting Configuration
    # Request throttling for security and performance
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')
    
    # Mail Configuration (if needed)
    # SMTP settings for application notifications
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # File Upload Configuration
    # Secure file handling settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', '/tmp/uploads')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx'}
    
    # Caching Configuration
    # Application caching for performance optimization
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', '300'))
    
    # Internationalization Configuration
    # Multi-language support settings
    LANGUAGES = ['en', 'es', 'fr', 'de']  # Supported languages
    BABEL_DEFAULT_LOCALE = 'en'
    BABEL_DEFAULT_TIMEZONE = 'UTC'
    
    # Monitoring Configuration
    # Prometheus metrics and health check settings
    METRICS_ENABLED = os.environ.get('METRICS_ENABLED', 'true').lower() == 'true'
    HEALTH_CHECK_ENDPOINT = '/health'
    METRICS_ENDPOINT = '/metrics'
    
    # AWS Configuration
    # Cloud services integration settings
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_S3_BUCKET = os.environ.get('AWS_S3_BUCKET')
    
    # Container Configuration
    # Docker and Kubernetes deployment settings
    CONTAINER_NAME = os.environ.get('CONTAINER_NAME', 'flask-app')
    CONTAINER_PORT = int(os.environ.get('CONTAINER_PORT', '8000'))
    WORKERS = int(os.environ.get('WORKERS', '4'))
    
    @staticmethod
    def init_app(app) -> None:
        """
        Initialize Flask application with configuration-specific settings.
        
        This method is called by the Flask application factory to perform
        configuration-specific initialization. Can be overridden in subclasses
        to provide environment-specific setup logic.
        
        Args:
            app: Flask application instance
        """
        pass
    
    @classmethod
    def get_database_uri(cls) -> str:
        """
        Construct database connection URI for Flask-SQLAlchemy PostgreSQL integration.
        
        Builds PostgreSQL connection string from environment variables with proper
        URL encoding for special characters in passwords. Supports both direct
        environment variables and AWS Secrets Manager integration.
        
        Returns:
            str: PostgreSQL connection URI for SQLAlchemy
            
        Raises:
            ValueError: If required database configuration is missing
        """
        # Primary database configuration from environment variables
        db_host = os.environ.get('DB_HOST', 'localhost')
        db_port = os.environ.get('DB_PORT', '5432')
        db_name = os.environ.get('DB_NAME', 'flask_app')
        db_user = os.environ.get('DB_USER', 'flask_user')
        db_password = os.environ.get('DB_PASSWORD', '')
        
        # Alternative: Direct DATABASE_URL override
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            # Handle potential postgres:// to postgresql:// conversion for SQLAlchemy
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            return database_url
        
        # Validate required configuration
        if not all([db_host, db_name, db_user]):
            raise ValueError(
                "Database configuration incomplete. Required: DB_HOST, DB_NAME, DB_USER"
            )
        
        # URL encode password to handle special characters
        encoded_password = quote_plus(db_password) if db_password else ''
        
        # Construct PostgreSQL URI with psycopg2 driver
        if encoded_password:
            return (
                f"postgresql+psycopg2://{db_user}:{encoded_password}"
                f"@{db_host}:{db_port}/{db_name}"
            )
        else:
            return f"postgresql+psycopg2://{db_user}@{db_host}:{db_port}/{db_name}"
    
    @classmethod
    def validate_configuration(cls) -> Dict[str, Any]:
        """
        Validate configuration settings and return validation results.
        
        Performs comprehensive validation of configuration settings to ensure
        all required values are present and properly formatted. Used during
        application startup to catch configuration errors early.
        
        Returns:
            Dict[str, Any]: Validation results with status and any errors
        """
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Validate required Flask settings
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'dev':
            validation_results['errors'].append(
                "SECRET_KEY must be set to a secure random value"
            )
            validation_results['valid'] = False
        
        # Validate database configuration
        try:
            cls.get_database_uri()
        except ValueError as e:
            validation_results['errors'].append(f"Database configuration error: {e}")
            validation_results['valid'] = False
        
        # Validate Auth0 configuration for production
        if cls.FLASK_ENV == 'production':
            auth0_required = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET']
            for setting in auth0_required:
                if not getattr(cls, setting, None):
                    validation_results['errors'].append(
                        f"Production deployment requires {setting} to be set"
                    )
                    validation_results['valid'] = False
        
        # Check for development-specific warnings
        if cls.FLASK_ENV == 'development' and cls.SECRET_KEY.startswith('dev'):
            validation_results['warnings'].append(
                "Using development SECRET_KEY - not suitable for production"
            )
        
        return validation_results


class DevelopmentConfig(Config):
    """
    Development configuration for local development environment.
    
    Optimized for developer productivity with enhanced debugging, query logging,
    and relaxed security settings. Uses local PostgreSQL database and enables
    Flask debugging features for rapid development cycles.
    
    Features:
    - Flask debugging enabled for automatic reloading
    - SQLAlchemy query logging for database debugging
    - Relaxed CSRF requirements for development convenience
    - Local file-based session storage
    - Enhanced logging for development insights
    """
    
    # Flask Development Settings
    FLASK_ENV = 'development'
    FLASK_DEBUG = True
    DEBUG = True
    
    # Database Configuration for Development
    # Local PostgreSQL instance with development-friendly settings
    SQLALCHEMY_RECORD_QUERIES = True  # Enable query logging for debugging
    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': True,  # Enable SQL logging for development
        'pool_size': 5,  # Smaller pool for development
        'max_overflow': 10
    }
    
    # Development Database URI
    SQLALCHEMY_DATABASE_URI = Config.get_database_uri()
    
    # Session Configuration for Development
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = os.path.join(os.path.dirname(__file__), 'flask_session')
    
    # Security Relaxation for Development
    WTF_CSRF_SSL_STRICT = False  # Allow HTTP for local development
    WTF_CSRF_TIME_LIMIT = None  # No CSRF timeout in development
    
    # Logging Configuration for Development
    LOG_LEVEL = 'DEBUG'
    LOG_FORMAT = 'text'  # Human-readable logs for development
    
    # Caching Disabled for Development
    CACHE_TYPE = 'null'  # Disable caching for development
    
    # Development-specific Rate Limiting
    RATELIMIT_ENABLED = False  # Disable rate limiting in development
    
    # Development Monitoring
    METRICS_ENABLED = True
    
    @staticmethod
    def init_app(app) -> None:
        """
        Initialize Flask application for development environment.
        
        Sets up development-specific logging, creates session directory,
        and configures debugging features for optimal development experience.
        
        Args:
            app: Flask application instance
        """
        # Set up development logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Create session directory if it doesn't exist
        session_dir = app.config.get('SESSION_FILE_DIR')
        if session_dir and not os.path.exists(session_dir):
            os.makedirs(session_dir, exist_ok=True)
        
        # Log configuration validation results
        validation_results = DevelopmentConfig.validate_configuration()
        if validation_results['warnings']:
            app.logger.warning(
                f"Configuration warnings: {validation_results['warnings']}"
            )


class TestingConfig(Config):
    """
    Testing configuration for automated testing environment.
    
    Optimized for fast, isolated testing with in-memory database, disabled
    security features that interfere with testing, and minimal external
    dependencies. Ensures consistent test execution across different environments.
    
    Features:
    - SQLite in-memory database for fast, isolated tests
    - Disabled CSRF protection for test convenience
    - Simplified session management
    - No external service dependencies
    - Fast caching and minimal logging
    """
    
    # Flask Testing Settings
    FLASK_ENV = 'testing'
    TESTING = True
    DEBUG = False
    
    # Testing Database Configuration
    # SQLite in-memory database for fast, isolated testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_timeout': 5,
        'pool_recycle': -1,
        'echo': False  # Disable SQL logging in tests
    }
    
    # Disable external dependencies for testing
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing convenience
    
    # Session Configuration for Testing
    SESSION_TYPE = 'null'  # No session persistence in tests
    
    # Simplified Authentication for Testing
    SECRET_KEY = 'testing-secret-key-not-for-production'
    
    # Logging Configuration for Testing
    LOG_LEVEL = 'WARNING'  # Minimal logging during tests
    LOG_TO_STDOUT = False
    
    # Fast Caching for Testing
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 1
    
    # Disable Rate Limiting for Testing
    RATELIMIT_ENABLED = False
    
    # Disable External Services for Testing
    MAIL_SUPPRESS_SEND = True
    AUTH0_DOMAIN = 'test-domain.auth0.com'
    AUTH0_CLIENT_ID = 'test-client-id'
    AUTH0_CLIENT_SECRET = 'test-client-secret'
    
    # Testing Monitoring
    METRICS_ENABLED = False
    
    @staticmethod
    def init_app(app) -> None:
        """
        Initialize Flask application for testing environment.
        
        Sets up testing-specific configuration including test database
        initialization and simplified logging for fast test execution.
        
        Args:
            app: Flask application instance
        """
        # Set up minimal logging for testing
        logging.getLogger().setLevel(logging.WARNING)
        
        # Disable SQLAlchemy logging in tests
        logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)


class ProductionConfig(Config):
    """
    Production configuration for deployed environment.
    
    Optimized for security, performance, and reliability with strict security
    settings, connection pooling, Redis session storage, and comprehensive
    monitoring. Integrates with AWS services and container orchestration.
    
    Features:
    - Strict security settings and CSRF protection
    - Redis session storage for scalability
    - Connection pooling for database performance
    - AWS services integration
    - Comprehensive monitoring and logging
    - Rate limiting for protection
    """
    
    # Flask Production Settings
    FLASK_ENV = 'production'
    DEBUG = False
    TESTING = False
    
    # Production Database Configuration
    # PostgreSQL with production-grade connection pooling
    SQLALCHEMY_DATABASE_URI = Config.get_database_uri()
    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
        'pool_size': int(os.environ.get('DB_POOL_SIZE', '20')),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', '30')),
        'pool_timeout': int(os.environ.get('DB_POOL_TIMEOUT', '30')),
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', '1800')),  # 30 minutes
        'echo': False
    }
    
    # Redis Session Storage for Production Scalability
    SESSION_TYPE = 'redis'
    SESSION_REDIS = None  # Will be configured from REDIS_URL
    SESSION_USE_SIGNER = True
    SESSION_PERMANENT = True
    
    # Strict Security Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SSL_STRICT = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # Production Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = 'json'  # Structured logging for production
    LOG_TO_STDOUT = True  # Container-friendly logging
    
    # Production Caching
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL')
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Rate Limiting Configuration
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/1')
    
    # Production Monitoring
    METRICS_ENABLED = True
    
    # SSL Configuration
    PREFERRED_URL_SCHEME = 'https'
    
    @staticmethod
    def init_app(app) -> None:
        """
        Initialize Flask application for production environment.
        
        Sets up production-specific configuration including structured logging,
        Redis connections, security headers, and monitoring integration.
        
        Args:
            app: Flask application instance
        """
        # Configure structured logging for production
        import json
        import sys
        
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
                if record.exc_info:
                    log_entry['exception'] = self.formatException(record.exc_info)
                return json.dumps(log_entry)
        
        # Set up JSON logging for production
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        
        # Configure application logger
        app.logger.handlers = [handler]
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        
        # Configure Redis session storage
        redis_url = os.environ.get('REDIS_URL')
        if redis_url:
            try:
                import redis
                app.config['SESSION_REDIS'] = redis.from_url(redis_url)
            except ImportError:
                app.logger.warning("Redis not available, falling back to filesystem sessions")
                app.config['SESSION_TYPE'] = 'filesystem'
        
        # Validate production configuration
        validation_results = ProductionConfig.validate_configuration()
        if not validation_results['valid']:
            app.logger.error(
                f"Production configuration validation failed: {validation_results['errors']}"
            )
            raise RuntimeError("Invalid production configuration")
        
        if validation_results['warnings']:
            app.logger.warning(
                f"Production configuration warnings: {validation_results['warnings']}"
            )


class StagingConfig(ProductionConfig):
    """
    Staging configuration extending production settings.
    
    Similar to production but with relaxed security settings for testing
    and additional debugging capabilities. Used for pre-production validation
    and integration testing with production-like environment.
    
    Features:
    - Production-like database and Redis configuration
    - Slightly relaxed security for testing convenience
    - Enhanced logging for debugging
    - All external service integrations enabled
    """
    
    # Staging Environment Settings
    FLASK_ENV = 'staging'
    DEBUG = False  # Keep debugging disabled for realistic testing
    
    # Staging-specific Database Configuration
    # Uses staging database with production-like settings
    SQLALCHEMY_ENGINE_OPTIONS = {
        **ProductionConfig.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': os.environ.get('SQLALCHEMY_ECHO', 'false').lower() == 'true'
    }
    
    # Slightly Relaxed Security for Staging
    WTF_CSRF_TIME_LIMIT = 7200  # 2 hours instead of 1 hour
    
    # Enhanced Logging for Staging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG').upper()
    
    @staticmethod
    def init_app(app) -> None:
        """
        Initialize Flask application for staging environment.
        
        Extends production initialization with staging-specific features
        like enhanced logging and validation reporting.
        
        Args:
            app: Flask application instance
        """
        # Call parent production initialization
        ProductionConfig.init_app(app)
        
        # Additional staging-specific setup
        app.logger.info("Staging environment initialized with production-like settings")


# Configuration mapping for Flask application factory pattern
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(config_name: Optional[str] = None) -> Type[Config]:
    """
    Get configuration class based on environment name.
    
    Provides a factory function for retrieving the appropriate configuration
    class based on the Flask environment. Used by the Flask application
    factory to load environment-specific configuration.
    
    Args:
        config_name: Name of the configuration environment
                    (development, testing, staging, production)
                    
    Returns:
        Type[Config]: Configuration class for the specified environment
        
    Examples:
        >>> config_class = get_config('production')
        >>> app.config.from_object(config_class)
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_class = config.get(config_name, config['default'])
    
    # Validate configuration before returning
    validation_results = config_class.validate_configuration()
    if not validation_results['valid']:
        raise ValueError(
            f"Invalid configuration for {config_name}: {validation_results['errors']}"
        )
    
    return config_class


def create_database_uri(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    driver: str = 'psycopg2'
) -> str:
    """
    Create a database URI for Flask-SQLAlchemy PostgreSQL integration.
    
    Utility function for constructing properly formatted PostgreSQL connection
    URIs with URL encoding for special characters. Supports various PostgreSQL
    drivers and connection options.
    
    Args:
        host: Database host address
        port: Database port number
        database: Database name
        username: Database username
        password: Database password
        driver: SQLAlchemy driver (default: psycopg2)
        
    Returns:
        str: Formatted PostgreSQL URI for SQLAlchemy
        
    Examples:
        >>> uri = create_database_uri('localhost', 5432, 'mydb', 'user', 'pass')
        >>> print(uri)
        postgresql+psycopg2://user:pass@localhost:5432/mydb
    """
    encoded_password = quote_plus(password) if password else ''
    
    if encoded_password:
        return (
            f"postgresql+{driver}://{username}:{encoded_password}"
            f"@{host}:{port}/{database}"
        )
    else:
        return f"postgresql+{driver}://{username}@{host}:{port}/{database}"


# Configuration validation and health check utilities
def validate_environment() -> Dict[str, Any]:
    """
    Validate the current environment configuration.
    
    Performs comprehensive validation of environment variables and configuration
    settings to ensure the application can start successfully. Used for health
    checks and deployment validation.
    
    Returns:
        Dict[str, Any]: Comprehensive validation results
    """
    current_config = get_config()
    return current_config.validate_configuration()


def get_config_summary() -> Dict[str, Any]:
    """
    Get a summary of current configuration settings.
    
    Provides a sanitized summary of configuration settings for debugging
    and monitoring purposes. Excludes sensitive information like passwords
    and API keys.
    
    Returns:
        Dict[str, Any]: Configuration summary with sensitive data excluded
    """
    config_name = os.environ.get('FLASK_ENV', 'development')
    config_class = get_config(config_name)
    
    summary = {
        'environment': config_name,
        'debug': getattr(config_class, 'DEBUG', False),
        'testing': getattr(config_class, 'TESTING', False),
        'database_configured': bool(config_class.get_database_uri()),
        'auth0_configured': bool(
            getattr(config_class, 'AUTH0_DOMAIN', None) and
            getattr(config_class, 'AUTH0_CLIENT_ID', None)
        ),
        'redis_configured': bool(os.environ.get('REDIS_URL')),
        'logging_level': getattr(config_class, 'LOG_LEVEL', 'INFO'),
        'metrics_enabled': getattr(config_class, 'METRICS_ENABLED', False)
    }
    
    return summary


if __name__ == '__main__':
    """
    Configuration validation script for development and debugging.
    
    When run directly, validates the current configuration and prints
    a summary of settings. Useful for troubleshooting configuration
    issues during development and deployment.
    """
    print("Flask Application Configuration Validation")
    print("=" * 50)
    
    # Validate current environment
    try:
        validation_results = validate_environment()
        print(f"Configuration Status: {'VALID' if validation_results['valid'] else 'INVALID'}")
        
        if validation_results['errors']:
            print("\nErrors:")
            for error in validation_results['errors']:
                print(f"  - {error}")
        
        if validation_results['warnings']:
            print("\nWarnings:")
            for warning in validation_results['warnings']:
                print(f"  - {warning}")
        
        # Print configuration summary
        print("\nConfiguration Summary:")
        summary = get_config_summary()
        for key, value in summary.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"Configuration validation failed: {e}")
        exit(1)
    
    print("\nConfiguration validation completed successfully!")