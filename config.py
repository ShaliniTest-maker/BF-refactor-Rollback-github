"""
Flask Configuration Management

This module provides environment-specific configuration classes for development, testing, 
and production deployments. It defines database connection strings, security keys, Flask 
settings, and environment variable mapping to replace Node.js config/*.js files.

The configuration system supports:
- PostgreSQL 14.12+ database connections with SQLAlchemy URI format
- Environment variable management through python-dotenv 1.0.1
- Connection pool configuration with environment-driven sizing
- Flask session security with SECRET_KEY configuration
- Environment-specific optimization settings

Author: Flask Migration System
Version: 1.0.0
Compatibility: Flask 3.1.1, Flask-SQLAlchemy 3.1.1, PostgreSQL 14.12+
"""

import os
import logging
from datetime import timedelta
from typing import Optional
from urllib.parse import urlparse


class Config:
    """
    Base configuration class containing common settings for all environments.
    
    This class defines default values and common configuration parameters that are
    inherited by environment-specific configuration classes. It handles environment
    variable loading, database connection configuration, and Flask application settings.
    """
    
    # Flask Core Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    FLASK_APP = os.environ.get('FLASK_APP', 'app.py')
    
    # Database Configuration - PostgreSQL Connection
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://localhost:5432/flask_app_dev'
    
    # SQLAlchemy Configuration Settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable modification tracking for performance
    SQLALCHEMY_RECORD_QUERIES = False      # Disable query recording in production
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,              # Validate connections before use
        'pool_recycle': 3600,               # Recycle connections every hour
        'connect_args': {
            'connect_timeout': 10,           # Connection timeout in seconds
            'application_name': 'flask_app'  # Application identifier for monitoring
        }
    }
    
    # Connection Pool Configuration - Environment Driven
    SQLALCHEMY_POOL_SIZE = int(os.environ.get('SQLALCHEMY_POOL_SIZE', '20'))
    SQLALCHEMY_MAX_OVERFLOW = int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', '30'))
    SQLALCHEMY_POOL_TIMEOUT = int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', '30'))
    SQLALCHEMY_POOL_RECYCLE = int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', '3600'))
    SQLALCHEMY_POOL_PRE_PING = os.environ.get('SQLALCHEMY_POOL_PRE_PING', 'true').lower() == 'true'
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_LIFETIME_MINUTES', '30')))
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Security Configuration
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    
    # Application Settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    
    # Auth0 Configuration (if used)
    AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
    AUTH0_CLIENT_ID = os.environ.get('AUTH0_CLIENT_ID')
    AUTH0_CLIENT_SECRET = os.environ.get('AUTH0_CLIENT_SECRET')
    AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE')
    
    # Cache Configuration
    CACHE_TYPE = os.environ.get('CACHE_TYPE', 'simple')
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get('CACHE_DEFAULT_TIMEOUT', '300'))
    
    # Redis Configuration (if used for caching or sessions)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    @staticmethod
    def init_app(app):
        """
        Initialize application with configuration-specific settings.
        
        This method is called after the Flask application is created and configured.
        It can be overridden in subclasses to perform environment-specific initialization.
        
        Args:
            app: Flask application instance
        """
        pass

    @classmethod
    def get_database_uri(cls) -> str:
        """
        Get the database URI with proper SSL and connection parameters.
        
        Returns:
            str: Complete PostgreSQL connection URI with SSL and connection parameters
        """
        base_uri = cls.SQLALCHEMY_DATABASE_URI
        
        # Parse the URI to add SSL parameters if not present
        parsed = urlparse(base_uri)
        
        # Add SSL mode for production if not specified
        if 'sslmode' not in base_uri and parsed.hostname != 'localhost':
            connector = '&' if '?' in base_uri else '?'
            base_uri += f'{connector}sslmode=require'
        
        return base_uri
    
    @classmethod
    def validate_required_config(cls) -> bool:
        """
        Validate that all required configuration variables are set.
        
        Returns:
            bool: True if all required configuration is valid, False otherwise
        """
        required_vars = ['SECRET_KEY', 'SQLALCHEMY_DATABASE_URI']
        
        for var in required_vars:
            value = getattr(cls, var)
            if not value or (isinstance(value, str) and value == 'dev-key-change-in-production'):
                logging.warning(f"Configuration warning: {var} not properly set")
                return False
        
        return True


class DevelopmentConfig(Config):
    """
    Development environment configuration.
    
    This configuration enables debug mode, detailed logging, and development-specific
    settings for local development environments. It uses relaxed security settings
    and enables Flask debugging tools.
    """
    
    DEBUG = True
    TESTING = False
    
    # Development Database - Local PostgreSQL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://postgres:password@localhost:5432/flask_app_dev'
    
    # Enable detailed logging in development
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_ECHO = os.environ.get('SQLALCHEMY_ECHO', 'false').lower() == 'true'
    
    # Development-specific settings
    SESSION_COOKIE_SECURE = False  # Allow HTTP cookies in development
    WTF_CSRF_ENABLED = False       # Disable CSRF in development for easier testing
    
    # Smaller connection pool for development
    SQLALCHEMY_POOL_SIZE = int(os.environ.get('SQLALCHEMY_POOL_SIZE', '5'))
    SQLALCHEMY_MAX_OVERFLOW = int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', '10'))
    
    # Development logging
    LOG_LEVEL = 'DEBUG'
    
    @staticmethod
    def init_app(app):
        """Initialize development-specific settings."""
        Config.init_app(app)
        
        # Configure development logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        
        # Log configuration validation
        app.logger.info("Development configuration loaded")
        if not DevelopmentConfig.validate_required_config():
            app.logger.warning("Some configuration values are using defaults")


class TestingConfig(Config):
    """
    Testing environment configuration.
    
    This configuration is optimized for automated testing with isolated database
    connections, disabled external services, and fast execution settings. It uses
    in-memory or test-specific databases and simplified authentication.
    """
    
    TESTING = True
    DEBUG = False
    
    # Test Database - Isolated test database
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'postgresql://postgres:password@localhost:5432/flask_app_test'
    
    # Testing-specific settings
    WTF_CSRF_ENABLED = False       # Disable CSRF for easier testing
    LOGIN_DISABLED = True          # Disable login requirement for tests
    
    # Minimal connection pool for testing
    SQLALCHEMY_POOL_SIZE = int(os.environ.get('SQLALCHEMY_POOL_SIZE', '2'))
    SQLALCHEMY_MAX_OVERFLOW = int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', '5'))
    SQLALCHEMY_POOL_TIMEOUT = 10   # Shorter timeout for tests
    
    # Fast session expiration for testing
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    
    # Disable caching in tests
    CACHE_TYPE = 'null'
    
    # Test-specific logging
    LOG_LEVEL = 'WARNING'  # Reduce log noise during testing
    
    @staticmethod
    def init_app(app):
        """Initialize testing-specific settings."""
        Config.init_app(app)
        
        # Configure test logging to reduce noise
        logging.basicConfig(
            level=logging.WARNING,
            format='%(levelname)s: %(message)s'
        )
        
        app.logger.info("Testing configuration loaded")


class ProductionConfig(Config):
    """
    Production environment configuration.
    
    This configuration provides production-optimized settings with enhanced security,
    performance optimizations, comprehensive logging, and robust error handling.
    It requires proper SSL configuration and external service credentials.
    """
    
    DEBUG = False
    TESTING = False
    
    # Production Database - Secure PostgreSQL with SSL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://app_user:secure_password@prod-db.company.com:5432/flask_app_prod?sslmode=require'
    
    # Production Security Settings
    SESSION_COOKIE_SECURE = True   # Require HTTPS for session cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Enhanced SSL and Security Configuration
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'connect_args': {
            'sslmode': 'require',
            'connect_timeout': 10,
            'application_name': 'flask_app_prod',
            'options': '-c default_transaction_isolation=serializable'
        }
    }
    
    # Production Connection Pool - High Concurrency
    SQLALCHEMY_POOL_SIZE = int(os.environ.get('SQLALCHEMY_POOL_SIZE', '20'))
    SQLALCHEMY_MAX_OVERFLOW = int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', '30'))
    SQLALCHEMY_POOL_TIMEOUT = int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', '30'))
    SQLALCHEMY_POOL_RECYCLE = int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', '3600'))
    
    # Production logging
    LOG_LEVEL = 'INFO'
    
    # Production caching
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis-server:6379/0')
    CACHE_DEFAULT_TIMEOUT = 300
    
    @staticmethod
    def init_app(app):
        """Initialize production-specific settings."""
        Config.init_app(app)
        
        # Configure production logging
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Set up file logging with rotation
        if not app.debug and not app.testing:
            if not os.path.exists('logs'):
                os.mkdir('logs')
            
            file_handler = RotatingFileHandler(
                'logs/flask_app.log',
                maxBytes=10240000,  # 10MB
                backupCount=10
            )
            
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Flask application startup (Production)')
        
        # Validate production configuration
        if not ProductionConfig.validate_required_config():
            app.logger.error("Production configuration validation failed")
            raise RuntimeError("Invalid production configuration")
        
        # Additional production validations
        if app.config['SECRET_KEY'] == 'dev-key-change-in-production':
            app.logger.error("Production SECRET_KEY not configured properly")
            raise RuntimeError("Production SECRET_KEY must be set")


class StagingConfig(ProductionConfig):
    """
    Staging environment configuration.
    
    This configuration provides production-like settings for staging environments
    with slightly relaxed security settings for testing and debugging purposes.
    """
    
    # Allow some debugging in staging
    DEBUG = os.environ.get('STAGING_DEBUG', 'false').lower() == 'true'
    
    # Staging Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://staging_user:staging_password@staging-db.company.com:5432/flask_app_staging?sslmode=require'
    
    # Moderate connection pool for staging
    SQLALCHEMY_POOL_SIZE = int(os.environ.get('SQLALCHEMY_POOL_SIZE', '10'))
    SQLALCHEMY_MAX_OVERFLOW = int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', '20'))
    
    # Staging logging - more verbose than production
    LOG_LEVEL = 'DEBUG'
    
    @staticmethod
    def init_app(app):
        """Initialize staging-specific settings."""
        ProductionConfig.init_app(app)
        app.logger.info('Flask application startup (Staging)')


# Configuration mapping for environment-based selection
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


def get_config(config_name: Optional[str] = None) -> Config:
    """
    Get configuration class based on environment name.
    
    Args:
        config_name: Name of the configuration environment
        
    Returns:
        Config: Configuration class instance for the specified environment
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    return config.get(config_name, DevelopmentConfig)


def validate_database_connection(database_uri: str) -> bool:
    """
    Validate database connection string format and accessibility.
    
    Args:
        database_uri: PostgreSQL connection URI
        
    Returns:
        bool: True if connection string is valid and accessible
    """
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.exc import SQLAlchemyError
        
        # Create engine with connection validation
        engine = create_engine(
            database_uri,
            pool_pre_ping=True,
            connect_args={'connect_timeout': 5}
        )
        
        # Test connection
        with engine.connect() as conn:
            conn.execute('SELECT 1')
        
        return True
        
    except SQLAlchemyError as e:
        logging.error(f"Database connection validation failed: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during database validation: {e}")
        return False


# Export commonly used configuration classes
__all__ = [
    'Config',
    'DevelopmentConfig', 
    'TestingConfig',
    'StagingConfig',
    'ProductionConfig',
    'config',
    'get_config',
    'validate_database_connection'
]