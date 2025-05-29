"""
Flask Application Configuration Management Module

This module implements the Flask app.config framework for environment-specific configuration
loading, database connection management, and secure handling of sensitive settings. Provides
organized configuration management across development, staging, and production environments
while supporting container orchestration and AWS cloud deployment.

Architecture:
- Environment-specific configuration classes following Flask 3.1.1 patterns
- PostgreSQL 14 database configuration with Flask-SQLAlchemy 3.1.1 integration
- Secure configuration management for API keys and sensitive data
- Container orchestration support with environment variable loading
- Flask-Migrate 4.x migration configuration support
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Union
from urllib.parse import quote_plus


class BaseConfig:
    """
    Base configuration class containing common settings shared across all environments.
    
    Implements Flask app.config framework standards with secure configuration handling
    and externalized settings management compatible with container orchestration.
    """
    
    # Flask Core Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Flask-SQLAlchemy Database Configuration
    # PostgreSQL 14 integration with connection pooling optimization
    SQLALCHEMY_DATABASE_URI = None  # Override in environment-specific classes
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', '10')),
        'pool_overflow': int(os.environ.get('DB_POOL_OVERFLOW', '20')),
        'pool_pre_ping': True,
        'pool_recycle': int(os.environ.get('DB_POOL_RECYCLE', '3600')),
        'echo': os.environ.get('SQLALCHEMY_ECHO', 'False').lower() == 'true'
    }
    
    # Flask-Migrate Configuration
    # Alembic-managed database migrations with /migrations directory support
    SQLALCHEMY_MIGRATE_REPO = os.path.join(
        Path(__file__).parent, 'migrations'
    )
    
    # Application Factory Configuration
    # Blueprint registration and extension integration settings
    BLUEPRINTS_AUTO_REGISTER = True
    APP_NAME = os.environ.get('APP_NAME', 'blitzy-flask-app')
    APP_VERSION = os.environ.get('APP_VERSION', '1.0.0')
    
    # Security Configuration
    # Authentication and session management with ItsDangerous integration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('SESSION_LIFETIME', '3600'))
    
    # API Configuration
    # RESTful API settings maintaining Node.js parity
    JSONIFY_PRETTYPRINT_REGULAR = False
    JSON_SORT_KEYS = False
    RESTFUL_JSON = {'indent': None, 'separators': (',', ':')}
    
    # CORS Configuration
    # Cross-origin resource sharing for client application support
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization', 'X-Requested-With']
    
    # Logging Configuration
    # Application logging levels and output configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Rate Limiting Configuration
    # API rate limiting to prevent abuse
    RATELIMIT_ENABLED = os.environ.get('RATELIMIT_ENABLED', 'True').lower() == 'true'
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', '100 per hour')
    
    # Monitoring and Observability
    # Prometheus metrics and health check endpoints
    METRICS_ENABLED = os.environ.get('METRICS_ENABLED', 'True').lower() == 'true'
    HEALTH_CHECK_PATH = '/health'
    METRICS_PATH = '/metrics'
    
    @staticmethod
    def init_app(app):
        """
        Initialize application with base configuration settings.
        
        Args:
            app: Flask application instance
        """
        pass


class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration with debugging enabled and local database.
    
    Provides optimized settings for local development including debug mode,
    detailed logging, and development-friendly database configuration.
    """
    
    DEBUG = True
    TESTING = False
    
    # Development Database Configuration
    # Local PostgreSQL instance for development
    DB_HOST = os.environ.get('DEV_DB_HOST', 'localhost')
    DB_PORT = int(os.environ.get('DEV_DB_PORT', '5432'))
    DB_NAME = os.environ.get('DEV_DB_NAME', 'blitzy_dev')
    DB_USER = os.environ.get('DEV_DB_USER', 'postgres')
    DB_PASSWORD = os.environ.get('DEV_DB_PASSWORD', 'postgres')
    
    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    
    # Development-specific Engine Options
    SQLALCHEMY_ENGINE_OPTIONS = {
        **BaseConfig.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': True,  # Enable SQL query logging in development
        'pool_size': 5,  # Smaller pool for development
        'pool_overflow': 10
    }
    
    # Development Security (Relaxed)
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-do-not-use-in-production')
    
    # Development Logging
    LOG_LEVEL = 'DEBUG'
    
    @staticmethod
    def init_app(app):
        """Initialize development-specific application settings."""
        import logging
        logging.basicConfig(level=logging.DEBUG)


class StagingConfig(BaseConfig):
    """
    Staging environment configuration mirroring production settings for testing.
    
    Provides production-like configuration for integration testing and validation
    while maintaining debugging capabilities for troubleshooting.
    """
    
    DEBUG = False
    TESTING = True
    
    # Staging Database Configuration
    # Staging PostgreSQL instance with production-like settings
    DB_HOST = os.environ.get('STAGING_DB_HOST', 'staging-db.internal')
    DB_PORT = int(os.environ.get('STAGING_DB_PORT', '5432'))
    DB_NAME = os.environ.get('STAGING_DB_NAME', 'blitzy_staging')
    DB_USER = os.environ.get('STAGING_DB_USER')
    DB_PASSWORD = os.environ.get('STAGING_DB_PASSWORD')
    
    if not DB_USER or not DB_PASSWORD:
        raise ValueError("Staging database credentials must be provided via environment variables")
    
    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    
    # Staging-specific Engine Options
    SQLALCHEMY_ENGINE_OPTIONS = {
        **BaseConfig.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': False,
        'pool_size': 8,
        'pool_overflow': 15
    }
    
    # Staging Security
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be provided for staging environment")
    
    # Staging Logging
    LOG_LEVEL = 'INFO'
    
    @staticmethod
    def init_app(app):
        """Initialize staging-specific application settings."""
        import logging
        logging.basicConfig(level=logging.INFO)


class ProductionConfig(BaseConfig):
    """
    Production environment configuration with security and performance optimization.
    
    Implements enterprise-grade security settings, optimized database configuration,
    and comprehensive monitoring for production deployment environments.
    """
    
    DEBUG = False
    TESTING = False
    
    # Production Database Configuration
    # Production PostgreSQL instance with high availability and performance optimization
    DB_HOST = os.environ.get('PROD_DB_HOST')
    DB_PORT = int(os.environ.get('PROD_DB_PORT', '5432'))
    DB_NAME = os.environ.get('PROD_DB_NAME')
    DB_USER = os.environ.get('PROD_DB_USER')
    DB_PASSWORD = os.environ.get('PROD_DB_PASSWORD')
    
    # Validate required production environment variables
    if not all([DB_HOST, DB_NAME, DB_USER, DB_PASSWORD]):
        raise ValueError(
            "Production database configuration requires all environment variables: "
            "PROD_DB_HOST, PROD_DB_NAME, PROD_DB_USER, PROD_DB_PASSWORD"
        )
    
    SQLALCHEMY_DATABASE_URI = (
        f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    
    # Production-specific Engine Options
    # Optimized for high concurrency and performance
    SQLALCHEMY_ENGINE_OPTIONS = {
        **BaseConfig.SQLALCHEMY_ENGINE_OPTIONS,
        'echo': False,
        'pool_size': int(os.environ.get('PROD_DB_POOL_SIZE', '10')),
        'pool_overflow': int(os.environ.get('PROD_DB_POOL_OVERFLOW', '20')),
        'pool_timeout': int(os.environ.get('PROD_DB_POOL_TIMEOUT', '30')),
        'max_overflow': int(os.environ.get('PROD_DB_MAX_OVERFLOW', '50'))
    }
    
    # Production Security Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY must be provided for production environment")
    
    # Enhanced security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('PROD_SESSION_LIFETIME', '1800'))
    
    # Production Logging
    LOG_LEVEL = 'WARNING'
    
    # Production Rate Limiting
    RATELIMIT_DEFAULT = os.environ.get('PROD_RATELIMIT_DEFAULT', '50 per hour')
    
    # Production CORS (Restrictive)
    CORS_ORIGINS = os.environ.get('PROD_CORS_ORIGINS', '').split(',')
    if not CORS_ORIGINS or CORS_ORIGINS == ['']:
        raise ValueError("Production CORS origins must be explicitly configured")
    
    @staticmethod
    def init_app(app):
        """Initialize production-specific application settings."""
        import logging
        import sys
        
        # Production logging configuration
        logging.basicConfig(
            level=logging.WARNING,
            format='%(asctime)s %(levelname)s %(name)s %(message)s',
            stream=sys.stdout
        )
        
        # Production error handling
        if not app.debug:
            # Configure production error logging
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.WARNING)
            formatter = logging.Formatter(
                '%(asctime)s %(levelname)s %(name)s %(message)s'
            )
            handler.setFormatter(formatter)
            app.logger.addHandler(handler)
            app.logger.setLevel(logging.WARNING)


class TestingConfig(BaseConfig):
    """
    Testing environment configuration for unit and integration tests.
    
    Provides isolated testing environment with in-memory database options,
    disabled security features for testing, and optimized settings for test execution.
    """
    
    DEBUG = True
    TESTING = True
    
    # Testing Database Configuration
    # In-memory SQLite for fast test execution or dedicated test PostgreSQL
    TESTING_DATABASE_TYPE = os.environ.get('TESTING_DATABASE_TYPE', 'sqlite')
    
    if TESTING_DATABASE_TYPE == 'sqlite':
        SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        SQLALCHEMY_ENGINE_OPTIONS = {
            'echo': False,
            'pool_pre_ping': False
        }
    else:
        # Dedicated test PostgreSQL database
        DB_HOST = os.environ.get('TEST_DB_HOST', 'localhost')
        DB_PORT = int(os.environ.get('TEST_DB_PORT', '5432'))
        DB_NAME = os.environ.get('TEST_DB_NAME', 'blitzy_test')
        DB_USER = os.environ.get('TEST_DB_USER', 'postgres')
        DB_PASSWORD = os.environ.get('TEST_DB_PASSWORD', 'postgres')
        
        SQLALCHEMY_DATABASE_URI = (
            f"postgresql://{DB_USER}:{quote_plus(DB_PASSWORD)}"
            f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        )
        SQLALCHEMY_ENGINE_OPTIONS = {
            'echo': False,
            'pool_size': 1,
            'pool_overflow': 0
        }
    
    # Testing Security (Disabled for testing)
    SECRET_KEY = 'testing-secret-key-not-secure'
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False
    
    # Testing Configuration
    SERVER_NAME = 'localhost.localdomain'
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    
    @staticmethod
    def init_app(app):
        """Initialize testing-specific application settings."""
        import logging
        logging.disable(logging.CRITICAL)


# Configuration Registry
# Maps environment names to configuration classes
CONFIG_REGISTRY: Dict[str, type] = {
    'development': DevelopmentConfig,
    'staging': StagingConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(config_name: Optional[str] = None) -> type:
    """
    Retrieve configuration class based on environment name.
    
    Args:
        config_name: Environment configuration name ('development', 'staging', 
                    'production', 'testing'). If None, uses FLASK_ENV environment 
                    variable or defaults to 'development'.
    
    Returns:
        Configuration class for the specified environment.
        
    Raises:
        ValueError: If the specified configuration name is not found.
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    if config_name not in CONFIG_REGISTRY:
        raise ValueError(
            f"Configuration '{config_name}' not found. "
            f"Available configurations: {list(CONFIG_REGISTRY.keys())}"
        )
    
    return CONFIG_REGISTRY[config_name]


def validate_config(config: Any) -> bool:
    """
    Validate configuration class for required settings and proper values.
    
    Args:
        config: Configuration class instance to validate.
        
    Returns:
        bool: True if configuration is valid.
        
    Raises:
        ValueError: If configuration validation fails.
    """
    required_attrs = [
        'SECRET_KEY', 'SQLALCHEMY_DATABASE_URI', 'SQLALCHEMY_TRACK_MODIFICATIONS'
    ]
    
    for attr in required_attrs:
        if not hasattr(config, attr):
            raise ValueError(f"Required configuration attribute '{attr}' is missing")
        
        value = getattr(config, attr)
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValueError(f"Configuration attribute '{attr}' cannot be empty")
    
    # Validate database URI format
    db_uri = getattr(config, 'SQLALCHEMY_DATABASE_URI')
    if not (db_uri.startswith('postgresql://') or db_uri.startswith('sqlite://')):
        raise ValueError("SQLALCHEMY_DATABASE_URI must be a valid PostgreSQL or SQLite URI")
    
    return True


# AWS Secrets Manager Integration
def load_secrets_from_aws(secret_name: str, region_name: str = 'us-east-1') -> Dict[str, str]:
    """
    Load configuration secrets from AWS Secrets Manager.
    
    Args:
        secret_name: Name of the secret in AWS Secrets Manager.
        region_name: AWS region where the secret is stored.
        
    Returns:
        Dictionary containing secret key-value pairs.
        
    Note:
        This function requires boto3 to be installed and AWS credentials configured.
        Secrets are automatically loaded in production environments.
    """
    try:
        import boto3
        import json
        
        client = boto3.client('secretsmanager', region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        
        return json.loads(response['SecretString'])
    except ImportError:
        # boto3 not available, skip AWS secrets loading
        return {}
    except Exception as e:
        # Log the error but don't fail configuration loading
        import logging
        logging.warning(f"Failed to load secrets from AWS: {e}")
        return {}


# Container Orchestration Support
def load_kubernetes_config() -> Dict[str, str]:
    """
    Load configuration from Kubernetes ConfigMaps and Secrets.
    
    Returns:
        Dictionary containing configuration values from Kubernetes.
        
    Note:
        This function reads mounted ConfigMaps and Secrets in containerized environments.
    """
    config = {}
    
    # Standard Kubernetes mount paths
    configmap_path = Path('/etc/config')
    secrets_path = Path('/etc/secrets')
    
    # Load ConfigMap values
    if configmap_path.exists():
        for config_file in configmap_path.glob('*'):
            if config_file.is_file():
                try:
                    with open(config_file, 'r') as f:
                        config[config_file.name.upper()] = f.read().strip()
                except Exception:
                    pass
    
    # Load Secret values
    if secrets_path.exists():
        for secret_file in secrets_path.glob('*'):
            if secret_file.is_file():
                try:
                    with open(secret_file, 'r') as f:
                        config[secret_file.name.upper()] = f.read().strip()
                except Exception:
                    pass
    
    return config


# Auto-load container configuration if available
_container_config = load_kubernetes_config()
for key, value in _container_config.items():
    if key not in os.environ:
        os.environ[key] = value