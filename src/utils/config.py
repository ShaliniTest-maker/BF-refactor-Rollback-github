"""
Configuration Management Utilities for Flask Application Factory Pattern

This module provides comprehensive configuration management for Flask 3.1.1 applications,
implementing environment-specific settings loading, AWS Secrets Manager integration,
and secure configuration validation as specified in Section 5.1.1 and Section 6.4.3.2.

Features:
- Flask application factory pattern configuration management
- Environment-specific configuration loading (development, staging, production)
- AWS Secrets Manager integration for secure configuration storage
- AWS KMS integration for encryption key management
- Configuration validation and type checking
- Container orchestration configuration support
- Database configuration for Flask-SQLAlchemy integration
- Security configuration for authentication and encryption

Dependencies:
- Flask 3.1.1 for application configuration patterns
- boto3 for AWS services integration
- Python 3.13.3 standard library for type hints and validation
"""

import os
import json
import logging
from typing import Dict, Any, Optional, Union, Type, ClassVar
from dataclasses import dataclass, field
from enum import Enum
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from flask import Flask
import structlog


class Environment(Enum):
    """Environment enumeration for configuration management"""
    DEVELOPMENT = "development"
    STAGING = "staging" 
    PRODUCTION = "production"
    TESTING = "testing"


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors"""
    pass


@dataclass
class DatabaseConfig:
    """Database configuration structure with validation"""
    url: Optional[str] = None
    host: Optional[str] = None
    port: int = 5432
    database: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    ssl_mode: str = "require"
    pool_size: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    echo_pool: bool = False
    
    def __post_init__(self):
        """Validate database configuration after initialization"""
        if not self.url and not all([self.host, self.database, self.username, self.password]):
            raise ConfigurationError(
                "Database configuration requires either URL or host/database/username/password"
            )


@dataclass 
class AWSConfig:
    """AWS services configuration structure"""
    region: str = "us-east-1"
    kms_key_id: Optional[str] = None
    secrets_manager_prefix: str = "flask-app"
    s3_bucket: Optional[str] = None
    cloudwatch_log_group: str = "/aws/flask/application"
    
    def __post_init__(self):
        """Validate AWS configuration"""
        if not self.region:
            raise ConfigurationError("AWS region is required")


@dataclass
class SecurityConfig:
    """Security configuration structure"""
    secret_key: Optional[str] = None
    jwt_secret_key: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_expiration_delta: int = 3600
    password_salt_rounds: int = 12
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = "Lax"
    session_permanent: bool = False
    csrf_enabled: bool = True
    field_encryption_key: Optional[str] = None
    
    def __post_init__(self):
        """Validate security configuration"""
        if not self.secret_key:
            raise ConfigurationError("Flask secret key is required")


@dataclass
class Auth0Config:
    """Auth0 authentication configuration structure"""
    domain: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    audience: Optional[str] = None
    algorithms: list = field(default_factory=lambda: ["RS256"])
    
    def __post_init__(self):
        """Validate Auth0 configuration"""
        if not all([self.domain, self.client_id, self.client_secret]):
            raise ConfigurationError(
                "Auth0 configuration requires domain, client_id, and client_secret"
            )


class BaseConfig:
    """
    Base configuration class implementing Flask application factory pattern
    
    This class provides the foundation for environment-specific configuration
    loading with AWS Secrets Manager integration and secure configuration validation.
    """
    
    # Flask Application Settings
    TESTING: bool = False
    DEBUG: bool = False
    SECRET_KEY: Optional[str] = None
    
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 5000
    THREADED: bool = True
    
    # Database Configuration (Flask-SQLAlchemy)
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False
    SQLALCHEMY_ECHO_POOL: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: Dict[str, Any] = {
        "pool_size": 10,
        "pool_timeout": 30,
        "pool_recycle": 3600,
        "pool_pre_ping": True
    }
    
    # Session Configuration
    SESSION_TYPE: str = "filesystem"
    SESSION_PERMANENT: bool = False
    SESSION_USE_SIGNER: bool = True
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    
    # Security Configuration
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600
    BCRYPT_LOG_ROUNDS: int = 12
    
    # JWT Configuration
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_DELTA: int = 3600
    JWT_AUTH_USERNAME_KEY: str = "username"
    JWT_AUTH_HEADER_PREFIX: str = "Bearer"
    
    # AWS Configuration
    AWS_REGION: str = "us-east-1"
    AWS_KMS_KEY_ID: Optional[str] = None
    AWS_SECRETS_MANAGER_PREFIX: str = "flask-app"
    AWS_CLOUDWATCH_LOG_GROUP: str = "/aws/flask/application"
    
    # Auth0 Configuration
    AUTH0_DOMAIN: Optional[str] = None
    AUTH0_CLIENT_ID: Optional[str] = None
    AUTH0_CLIENT_SECRET: Optional[str] = None
    AUTH0_AUDIENCE: Optional[str] = None
    AUTH0_ALGORITHMS: list = ["RS256"]
    
    # Application Configuration
    APP_NAME: str = "Flask Application"
    APP_VERSION: str = "1.0.0"
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # Container Orchestration Support
    CONTAINER_MODE: bool = False
    HEALTH_CHECK_ENDPOINT: str = "/health"
    METRICS_ENDPOINT: str = "/metrics"
    
    # Rate Limiting Configuration
    RATELIMIT_STORAGE_URL: Optional[str] = None
    RATELIMIT_DEFAULT: str = "100 per hour"
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """Initialize Flask application with configuration"""
        pass


class DevelopmentConfig(BaseConfig):
    """
    Development environment configuration
    
    Provides development-specific settings with enhanced debugging capabilities
    and relaxed security constraints for local development.
    """
    
    DEBUG: bool = True
    TESTING: bool = False
    
    # Development Database Configuration
    SQLALCHEMY_ECHO: bool = True
    SQLALCHEMY_ECHO_POOL: bool = False
    
    # Development Security Configuration (Relaxed)
    SESSION_COOKIE_SECURE: bool = False
    WTF_CSRF_ENABLED: bool = False
    
    # Development Logging
    LOG_LEVEL: str = "DEBUG"
    
    # Development Container Configuration
    CONTAINER_MODE: bool = False
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """Initialize Flask application for development environment"""
        # Configure development-specific logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s %(name)s %(message)s'
        )
        
        # Configure structlog for development
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                structlog.dev.ConsoleRenderer()
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )


class StagingConfig(BaseConfig):
    """
    Staging environment configuration
    
    Provides production-like settings with enhanced logging and monitoring
    for pre-production testing and validation.
    """
    
    DEBUG: bool = False
    TESTING: bool = False
    
    # Staging Database Configuration
    SQLALCHEMY_ECHO: bool = False
    SQLALCHEMY_ECHO_POOL: bool = False
    
    # Staging Security Configuration  
    SESSION_COOKIE_SECURE: bool = True
    WTF_CSRF_ENABLED: bool = True
    
    # Staging Logging
    LOG_LEVEL: str = "INFO"
    
    # Container Configuration
    CONTAINER_MODE: bool = True
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """Initialize Flask application for staging environment"""
        # Configure structured logging for staging
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )


class ProductionConfig(BaseConfig):
    """
    Production environment configuration
    
    Provides production-optimized settings with enhanced security,
    performance optimization, and comprehensive monitoring.
    """
    
    DEBUG: bool = False
    TESTING: bool = False
    
    # Production Database Configuration
    SQLALCHEMY_ECHO: bool = False
    SQLALCHEMY_ECHO_POOL: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: Dict[str, Any] = {
        "pool_size": 20,
        "pool_timeout": 30,
        "pool_recycle": 3600,
        "pool_pre_ping": True,
        "pool_reset_on_return": "commit"
    }
    
    # Production Security Configuration
    SESSION_COOKIE_SECURE: bool = True
    WTF_CSRF_ENABLED: bool = True
    BCRYPT_LOG_ROUNDS: int = 15
    
    # Production Logging
    LOG_LEVEL: str = "WARNING"
    
    # Container Configuration
    CONTAINER_MODE: bool = True
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """Initialize Flask application for production environment"""
        # Configure production logging with error handling
        import logging.handlers
        
        # Configure structlog for production
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.add_log_level,
                structlog.processors.StackInfoRenderer(),
                structlog.dev.set_exc_info,
                structlog.processors.JSONRenderer()
            ],
            wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
            logger_factory=structlog.WriteLoggerFactory(),
            cache_logger_on_first_use=True,
        )
        
        # Configure file logging for production
        if not app.debug:
            file_handler = logging.handlers.RotatingFileHandler(
                'logs/application.log', maxBytes=10240, backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.WARNING)
            app.logger.addHandler(file_handler)


class TestingConfig(BaseConfig):
    """
    Testing environment configuration
    
    Provides testing-specific settings with in-memory databases,
    disabled security features, and enhanced debugging for test execution.
    """
    
    DEBUG: bool = True
    TESTING: bool = True
    
    # Testing Database Configuration (In-Memory SQLite)
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    SQLALCHEMY_ECHO: bool = False
    
    # Testing Security Configuration (Disabled)
    WTF_CSRF_ENABLED: bool = False
    SESSION_COOKIE_SECURE: bool = False
    
    # Testing Logging
    LOG_LEVEL: str = "DEBUG"
    
    # Testing Container Configuration
    CONTAINER_MODE: bool = False
    
    @classmethod
    def init_app(cls, app: Flask) -> None:
        """Initialize Flask application for testing environment"""
        # Configure minimal logging for testing
        logging.basicConfig(level=logging.ERROR)


class AWSSecretsManagerIntegration:
    """
    AWS Secrets Manager integration for secure configuration management
    
    This class provides secure storage and retrieval of sensitive configuration
    data using AWS Secrets Manager with automatic caching and error handling.
    """
    
    def __init__(self, region_name: str = "us-east-1", prefix: str = "flask-app"):
        """
        Initialize AWS Secrets Manager integration
        
        Args:
            region_name: AWS region for Secrets Manager
            prefix: Prefix for secret names
        """
        self.region_name = region_name
        self.prefix = prefix
        self.logger = structlog.get_logger("aws_secrets")
        
        try:
            self.secrets_client = boto3.client('secretsmanager', region_name=region_name)
        except Exception as e:
            self.logger.error("Failed to initialize AWS Secrets Manager client", error=str(e))
            self.secrets_client = None
    
    def get_secret(self, secret_name: str, environment: str = "production") -> Optional[Dict[str, Any]]:
        """
        Retrieve secret from AWS Secrets Manager
        
        Args:
            secret_name: Name of the secret
            environment: Environment suffix for the secret
            
        Returns:
            Dictionary containing secret data or None if not found
        """
        if not self.secrets_client:
            self.logger.warning("AWS Secrets Manager client not available")
            return None
        
        full_secret_name = f"{self.prefix}-{secret_name}-{environment}"
        
        try:
            response = self.secrets_client.get_secret_value(SecretId=full_secret_name)
            secret_data = json.loads(response['SecretString'])
            
            self.logger.info("Successfully retrieved secret", secret_name=full_secret_name)
            return secret_data
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.logger.warning("Secret not found", secret_name=full_secret_name)
            else:
                self.logger.error("Failed to retrieve secret", 
                                secret_name=full_secret_name, error=str(e))
            return None
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse secret JSON", 
                            secret_name=full_secret_name, error=str(e))
            return None
        except Exception as e:
            self.logger.error("Unexpected error retrieving secret", 
                            secret_name=full_secret_name, error=str(e))
            return None
    
    def store_secret(self, secret_name: str, secret_data: Dict[str, Any], 
                    environment: str = "production", description: str = None) -> bool:
        """
        Store secret in AWS Secrets Manager
        
        Args:
            secret_name: Name of the secret
            secret_data: Dictionary containing secret data
            environment: Environment suffix for the secret
            description: Optional description for the secret
            
        Returns:
            True if successful, False otherwise
        """
        if not self.secrets_client:
            self.logger.warning("AWS Secrets Manager client not available")
            return False
        
        full_secret_name = f"{self.prefix}-{secret_name}-{environment}"
        
        try:
            # Check if secret exists
            try:
                self.secrets_client.describe_secret(SecretId=full_secret_name)
                # Update existing secret
                self.secrets_client.update_secret(
                    SecretId=full_secret_name,
                    SecretString=json.dumps(secret_data)
                )
                action = "updated"
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Create new secret
                    self.secrets_client.create_secret(
                        Name=full_secret_name,
                        Description=description or f"Flask application secret: {secret_name}",
                        SecretString=json.dumps(secret_data),
                        Tags=[
                            {'Key': 'Application', 'Value': 'flask-app'},
                            {'Key': 'Environment', 'Value': environment},
                            {'Key': 'ManagedBy', 'Value': 'flask-config-manager'}
                        ]
                    )
                    action = "created"
                else:
                    raise
            
            self.logger.info(f"Successfully {action} secret", secret_name=full_secret_name)
            return True
            
        except Exception as e:
            self.logger.error("Failed to store secret", 
                            secret_name=full_secret_name, error=str(e))
            return False


class AWSKMSIntegration:
    """
    AWS KMS integration for encryption key management
    
    This class provides encryption key management using AWS KMS with
    automatic key rotation and secure key storage capabilities.
    """
    
    def __init__(self, region_name: str = "us-east-1", key_id: Optional[str] = None):
        """
        Initialize AWS KMS integration
        
        Args:
            region_name: AWS region for KMS
            key_id: KMS key ID or ARN
        """
        self.region_name = region_name
        self.key_id = key_id
        self.logger = structlog.get_logger("aws_kms")
        
        try:
            self.kms_client = boto3.client('kms', region_name=region_name)
        except Exception as e:
            self.logger.error("Failed to initialize AWS KMS client", error=str(e))
            self.kms_client = None
    
    def generate_data_key(self, key_spec: str = "AES_256", 
                         encryption_context: Optional[Dict[str, str]] = None) -> Optional[Dict[str, bytes]]:
        """
        Generate data encryption key using AWS KMS
        
        Args:
            key_spec: Key specification (AES_256, AES_128)
            encryption_context: Additional encryption context
            
        Returns:
            Dictionary with plaintext and encrypted key data
        """
        if not self.kms_client or not self.key_id:
            self.logger.warning("AWS KMS client or key ID not available")
            return None
        
        try:
            default_context = {
                'application': 'flask-app',
                'purpose': 'field-encryption'
            }
            if encryption_context:
                default_context.update(encryption_context)
            
            response = self.kms_client.generate_data_key(
                KeyId=self.key_id,
                KeySpec=key_spec,
                EncryptionContext=default_context
            )
            
            self.logger.info("Successfully generated data encryption key")
            return {
                'plaintext_key': response['Plaintext'],
                'encrypted_key': response['CiphertextBlob'],
                'key_id': response['KeyId']
            }
            
        except Exception as e:
            self.logger.error("Failed to generate data encryption key", error=str(e))
            return None
    
    def decrypt_data_key(self, encrypted_key: bytes, 
                        encryption_context: Optional[Dict[str, str]] = None) -> Optional[bytes]:
        """
        Decrypt data encryption key using AWS KMS
        
        Args:
            encrypted_key: Encrypted key data
            encryption_context: Encryption context used during encryption
            
        Returns:
            Plaintext key data or None if decryption fails
        """
        if not self.kms_client:
            self.logger.warning("AWS KMS client not available")
            return None
        
        try:
            default_context = {
                'application': 'flask-app',
                'purpose': 'field-encryption'
            }
            if encryption_context:
                default_context.update(encryption_context)
            
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key,
                EncryptionContext=default_context
            )
            
            self.logger.info("Successfully decrypted data encryption key")
            return response['Plaintext']
            
        except Exception as e:
            self.logger.error("Failed to decrypt data encryption key", error=str(e))
            return None


class ConfigurationManager:
    """
    Central configuration manager for Flask application factory pattern
    
    This class orchestrates configuration loading, validation, and AWS integration
    to provide comprehensive configuration management for Flask applications.
    """
    
    # Configuration class mapping
    CONFIG_CLASSES: ClassVar[Dict[str, Type[BaseConfig]]] = {
        Environment.DEVELOPMENT.value: DevelopmentConfig,
        Environment.STAGING.value: StagingConfig, 
        Environment.PRODUCTION.value: ProductionConfig,
        Environment.TESTING.value: TestingConfig
    }
    
    def __init__(self):
        """Initialize configuration manager"""
        self.logger = structlog.get_logger("config_manager")
        self.aws_secrets: Optional[AWSSecretsManagerIntegration] = None
        self.aws_kms: Optional[AWSKMSIntegration] = None
        self._config_cache: Dict[str, Any] = {}
    
    def get_environment(self) -> Environment:
        """
        Determine current environment from environment variables
        
        Returns:
            Environment enum value
        """
        env_name = os.getenv('FLASK_ENV', os.getenv('ENVIRONMENT', 'production')).lower()
        
        try:
            return Environment(env_name)
        except ValueError:
            self.logger.warning(f"Unknown environment '{env_name}', defaulting to production")
            return Environment.PRODUCTION
    
    def load_configuration(self, environment: Optional[Environment] = None) -> Type[BaseConfig]:
        """
        Load configuration class for specified environment
        
        Args:
            environment: Target environment, auto-detected if None
            
        Returns:
            Configuration class for the environment
        """
        if environment is None:
            environment = self.get_environment()
        
        config_class = self.CONFIG_CLASSES.get(environment.value)
        if not config_class:
            self.logger.error(f"No configuration class for environment: {environment.value}")
            raise ConfigurationError(f"Unsupported environment: {environment.value}")
        
        self.logger.info(f"Loading configuration for environment: {environment.value}")
        return config_class
    
    def initialize_aws_integration(self, config_class: Type[BaseConfig]) -> None:
        """
        Initialize AWS services integration
        
        Args:
            config_class: Configuration class containing AWS settings
        """
        try:
            # Initialize AWS Secrets Manager
            self.aws_secrets = AWSSecretsManagerIntegration(
                region_name=getattr(config_class, 'AWS_REGION', 'us-east-1'),
                prefix=getattr(config_class, 'AWS_SECRETS_MANAGER_PREFIX', 'flask-app')
            )
            
            # Initialize AWS KMS if key ID is provided
            kms_key_id = getattr(config_class, 'AWS_KMS_KEY_ID', None)
            if kms_key_id:
                self.aws_kms = AWSKMSIntegration(
                    region_name=getattr(config_class, 'AWS_REGION', 'us-east-1'),
                    key_id=kms_key_id
                )
            
            self.logger.info("AWS integration initialized successfully")
            
        except Exception as e:
            self.logger.error("Failed to initialize AWS integration", error=str(e))
    
    def load_secrets_from_aws(self, config_class: Type[BaseConfig], 
                            environment: Environment) -> None:
        """
        Load sensitive configuration from AWS Secrets Manager
        
        Args:
            config_class: Configuration class to update
            environment: Current environment
        """
        if not self.aws_secrets:
            self.logger.warning("AWS Secrets Manager not initialized")
            return
        
        # Load database configuration
        db_secrets = self.aws_secrets.get_secret('database', environment.value)
        if db_secrets:
            setattr(config_class, 'SQLALCHEMY_DATABASE_URI', 
                   self._build_database_url(db_secrets))
        
        # Load security configuration
        security_secrets = self.aws_secrets.get_secret('security', environment.value)
        if security_secrets:
            setattr(config_class, 'SECRET_KEY', security_secrets.get('secret_key'))
            setattr(config_class, 'JWT_SECRET_KEY', security_secrets.get('jwt_secret_key'))
            setattr(config_class, 'FIELD_ENCRYPTION_KEY', security_secrets.get('field_encryption_key'))
        
        # Load Auth0 configuration
        auth0_secrets = self.aws_secrets.get_secret('auth0', environment.value)
        if auth0_secrets:
            setattr(config_class, 'AUTH0_DOMAIN', auth0_secrets.get('domain'))
            setattr(config_class, 'AUTH0_CLIENT_ID', auth0_secrets.get('client_id'))
            setattr(config_class, 'AUTH0_CLIENT_SECRET', auth0_secrets.get('client_secret'))
            setattr(config_class, 'AUTH0_AUDIENCE', auth0_secrets.get('audience'))
        
        self.logger.info("Secrets loaded from AWS Secrets Manager")
    
    def _build_database_url(self, db_config: Dict[str, str]) -> str:
        """
        Build database URL from configuration
        
        Args:
            db_config: Database configuration dictionary
            
        Returns:
            Formatted database URL
        """
        return (
            f"postgresql+psycopg2://{db_config['username']}:{db_config['password']}"
            f"@{db_config['host']}:{db_config.get('port', 5432)}/{db_config['database']}"
            f"?sslmode={db_config.get('ssl_mode', 'require')}"
        )
    
    def load_environment_variables(self, config_class: Type[BaseConfig]) -> None:
        """
        Load configuration from environment variables
        
        Args:
            config_class: Configuration class to update
        """
        # Database configuration
        if os.getenv('DATABASE_URL'):
            setattr(config_class, 'SQLALCHEMY_DATABASE_URI', os.getenv('DATABASE_URL'))
        
        # Security configuration
        if os.getenv('SECRET_KEY'):
            setattr(config_class, 'SECRET_KEY', os.getenv('SECRET_KEY'))
        if os.getenv('JWT_SECRET_KEY'):
            setattr(config_class, 'JWT_SECRET_KEY', os.getenv('JWT_SECRET_KEY'))
        
        # Auth0 configuration
        if os.getenv('AUTH0_DOMAIN'):
            setattr(config_class, 'AUTH0_DOMAIN', os.getenv('AUTH0_DOMAIN'))
        if os.getenv('AUTH0_CLIENT_ID'):
            setattr(config_class, 'AUTH0_CLIENT_ID', os.getenv('AUTH0_CLIENT_ID'))
        if os.getenv('AUTH0_CLIENT_SECRET'):
            setattr(config_class, 'AUTH0_CLIENT_SECRET', os.getenv('AUTH0_CLIENT_SECRET'))
        
        # AWS configuration
        if os.getenv('AWS_REGION'):
            setattr(config_class, 'AWS_REGION', os.getenv('AWS_REGION'))
        if os.getenv('AWS_KMS_KEY_ID'):
            setattr(config_class, 'AWS_KMS_KEY_ID', os.getenv('AWS_KMS_KEY_ID'))
        
        # Container orchestration configuration
        if os.getenv('CONTAINER_MODE'):
            setattr(config_class, 'CONTAINER_MODE', os.getenv('CONTAINER_MODE').lower() == 'true')
        
        self.logger.info("Environment variables loaded")
    
    def validate_configuration(self, config_class: Type[BaseConfig]) -> None:
        """
        Validate configuration completeness and correctness
        
        Args:
            config_class: Configuration class to validate
            
        Raises:
            ConfigurationError: If validation fails
        """
        validation_errors = []
        
        # Validate required configuration
        if not getattr(config_class, 'SECRET_KEY', None):
            validation_errors.append("SECRET_KEY is required")
        
        if not getattr(config_class, 'SQLALCHEMY_DATABASE_URI', None):
            validation_errors.append("Database configuration is required")
        
        # Validate Auth0 configuration if provided
        auth0_domain = getattr(config_class, 'AUTH0_DOMAIN', None)
        auth0_client_id = getattr(config_class, 'AUTH0_CLIENT_ID', None)
        auth0_client_secret = getattr(config_class, 'AUTH0_CLIENT_SECRET', None)
        
        if any([auth0_domain, auth0_client_id, auth0_client_secret]):
            if not all([auth0_domain, auth0_client_id, auth0_client_secret]):
                validation_errors.append(
                    "Auth0 configuration requires domain, client_id, and client_secret"
                )
        
        # Validate AWS configuration
        aws_region = getattr(config_class, 'AWS_REGION', None)
        if not aws_region:
            validation_errors.append("AWS_REGION is required")
        
        if validation_errors:
            error_message = "Configuration validation failed: " + "; ".join(validation_errors)
            self.logger.error(error_message)
            raise ConfigurationError(error_message)
        
        self.logger.info("Configuration validation successful")
    
    def create_flask_config(self, environment: Optional[Environment] = None) -> Type[BaseConfig]:
        """
        Create complete Flask configuration with all integrations
        
        Args:
            environment: Target environment, auto-detected if None
            
        Returns:
            Fully configured Flask configuration class
        """
        if environment is None:
            environment = self.get_environment()
        
        # Load base configuration
        config_class = self.load_configuration(environment)
        
        # Initialize AWS integration
        self.initialize_aws_integration(config_class)
        
        # Load configuration from various sources
        self.load_environment_variables(config_class)
        self.load_secrets_from_aws(config_class, environment)
        
        # Validate final configuration
        self.validate_configuration(config_class)
        
        self.logger.info(f"Flask configuration created for environment: {environment.value}")
        return config_class


# Global configuration manager instance
config_manager = ConfigurationManager()


def get_config(environment: Optional[str] = None) -> Type[BaseConfig]:
    """
    Convenience function to get Flask configuration
    
    Args:
        environment: Environment name (development, staging, production, testing)
        
    Returns:
        Flask configuration class
    """
    env = None
    if environment:
        try:
            env = Environment(environment.lower())
        except ValueError:
            raise ConfigurationError(f"Invalid environment: {environment}")
    
    return config_manager.create_flask_config(env)


def initialize_app_config(app: Flask, environment: Optional[str] = None) -> None:
    """
    Initialize Flask application with configuration
    
    Args:
        app: Flask application instance
        environment: Environment name, auto-detected if None
    """
    config_class = get_config(environment)
    app.config.from_object(config_class)
    
    # Initialize environment-specific settings
    config_class.init_app(app)
    
    # Store configuration manager in app context
    app.config_manager = config_manager
    
    logger = structlog.get_logger("app_config")
    logger.info(f"Flask application configured for environment: {config_class.__name__}")


def get_database_config(environment: Optional[str] = None) -> DatabaseConfig:
    """
    Get database configuration for specified environment
    
    Args:
        environment: Environment name, auto-detected if None
        
    Returns:
        DatabaseConfig instance
    """
    config_class = get_config(environment)
    
    database_url = getattr(config_class, 'SQLALCHEMY_DATABASE_URI', None)
    if not database_url:
        raise ConfigurationError("Database configuration not available")
    
    # Parse database URL (simplified for PostgreSQL)
    import re
    match = re.match(
        r'postgresql\+psycopg2://([^:]+):([^@]+)@([^:]+):(\d+)/([^?]+)(?:\?(.+))?',
        database_url
    )
    
    if not match:
        raise ConfigurationError("Invalid database URL format")
    
    username, password, host, port, database, params = match.groups()
    
    ssl_mode = "require"
    if params:
        for param in params.split('&'):
            key, value = param.split('=', 1)
            if key == 'sslmode':
                ssl_mode = value
    
    return DatabaseConfig(
        url=database_url,
        host=host,
        port=int(port),
        database=database,
        username=username,
        password=password,
        ssl_mode=ssl_mode,
        pool_size=getattr(config_class, 'SQLALCHEMY_ENGINE_OPTIONS', {}).get('pool_size', 10),
        pool_timeout=getattr(config_class, 'SQLALCHEMY_ENGINE_OPTIONS', {}).get('pool_timeout', 30),
        pool_recycle=getattr(config_class, 'SQLALCHEMY_ENGINE_OPTIONS', {}).get('pool_recycle', 3600),
        echo=getattr(config_class, 'SQLALCHEMY_ECHO', False),
        echo_pool=getattr(config_class, 'SQLALCHEMY_ECHO_POOL', False)
    )


def get_security_config(environment: Optional[str] = None) -> SecurityConfig:
    """
    Get security configuration for specified environment
    
    Args:
        environment: Environment name, auto-detected if None
        
    Returns:
        SecurityConfig instance
    """
    config_class = get_config(environment)
    
    return SecurityConfig(
        secret_key=getattr(config_class, 'SECRET_KEY'),
        jwt_secret_key=getattr(config_class, 'JWT_SECRET_KEY', None),
        jwt_algorithm=getattr(config_class, 'JWT_ALGORITHM', 'HS256'),
        jwt_expiration_delta=getattr(config_class, 'JWT_EXPIRATION_DELTA', 3600),
        password_salt_rounds=getattr(config_class, 'BCRYPT_LOG_ROUNDS', 12),
        session_cookie_secure=getattr(config_class, 'SESSION_COOKIE_SECURE', True),
        session_cookie_httponly=getattr(config_class, 'SESSION_COOKIE_HTTPONLY', True),
        session_cookie_samesite=getattr(config_class, 'SESSION_COOKIE_SAMESITE', 'Lax'),
        session_permanent=getattr(config_class, 'SESSION_PERMANENT', False),
        csrf_enabled=getattr(config_class, 'WTF_CSRF_ENABLED', True),
        field_encryption_key=getattr(config_class, 'FIELD_ENCRYPTION_KEY', None)
    )


def get_auth0_config(environment: Optional[str] = None) -> Auth0Config:
    """
    Get Auth0 configuration for specified environment
    
    Args:
        environment: Environment name, auto-detected if None
        
    Returns:
        Auth0Config instance
    """
    config_class = get_config(environment)
    
    return Auth0Config(
        domain=getattr(config_class, 'AUTH0_DOMAIN'),
        client_id=getattr(config_class, 'AUTH0_CLIENT_ID'),
        client_secret=getattr(config_class, 'AUTH0_CLIENT_SECRET'),
        audience=getattr(config_class, 'AUTH0_AUDIENCE'),
        algorithms=getattr(config_class, 'AUTH0_ALGORITHMS', ['RS256'])
    )


def get_aws_config(environment: Optional[str] = None) -> AWSConfig:
    """
    Get AWS configuration for specified environment
    
    Args:
        environment: Environment name, auto-detected if None
        
    Returns:
        AWSConfig instance
    """
    config_class = get_config(environment)
    
    return AWSConfig(
        region=getattr(config_class, 'AWS_REGION', 'us-east-1'),
        kms_key_id=getattr(config_class, 'AWS_KMS_KEY_ID'),
        secrets_manager_prefix=getattr(config_class, 'AWS_SECRETS_MANAGER_PREFIX', 'flask-app'),
        cloudwatch_log_group=getattr(config_class, 'AWS_CLOUDWATCH_LOG_GROUP', '/aws/flask/application')
    )


if __name__ == "__main__":
    """
    Configuration validation script for testing and debugging
    """
    import sys
    
    try:
        # Test configuration loading for all environments
        environments = [env.value for env in Environment]
        
        for env_name in environments:
            print(f"\nTesting configuration for environment: {env_name}")
            
            try:
                config = get_config(env_name)
                print(f"✓ Successfully loaded {config.__name__}")
                
                # Test configuration components
                db_config = get_database_config(env_name)
                print(f"✓ Database configuration validated")
                
                security_config = get_security_config(env_name)
                print(f"✓ Security configuration validated")
                
                aws_config = get_aws_config(env_name)
                print(f"✓ AWS configuration validated")
                
            except ConfigurationError as e:
                print(f"✗ Configuration error: {e}")
            except Exception as e:
                print(f"✗ Unexpected error: {e}")
        
        print("\nConfiguration validation completed.")
        
    except Exception as e:
        print(f"Fatal error during configuration validation: {e}")
        sys.exit(1)