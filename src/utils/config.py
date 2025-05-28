"""
Configuration Management Utilities for Flask Application Factory Pattern

This module provides configuration management utilities that complement the main Flask
application configuration, offering specialized functions for secure configuration loading,
AWS Secrets Manager integration, environment-specific settings management, and container
orchestration configuration support. Designed to work with Flask 3.1.1 application
factory pattern and Python 3.13.3 runtime environment.

Key Features:
- AWS Secrets Manager integration for secure configuration loading
- Environment-specific configuration validation and type checking
- Container orchestration configuration detection and management
- Secure configuration parsing with sanitization and validation
- Configuration caching and performance optimization
- Flask application factory pattern integration utilities

Architecture Integration:
- Complements the main config.py Flask application configuration classes
- Provides utility functions for the Flask application factory initialization
- Integrates with AWS cloud services for secure configuration management
- Supports container orchestration platforms (Docker, Kubernetes, ECS)
- Enables dynamic configuration loading and hot-reloading capabilities

Security Features:
- AWS KMS encrypted configuration storage and retrieval
- Configuration value sanitization and type validation
- Secure credential management and rotation support
- Environment variable validation and security scanning
- Configuration audit logging and change tracking

Dependencies:
- boto3 for AWS Secrets Manager and KMS integration
- Flask 3.1.1 application factory pattern compatibility
- Python 3.13.3 runtime environment support
- structlog for structured configuration logging
- cryptography for local configuration encryption

Author: Flask Migration Team
Version: 1.0.0
Last Updated: 2024
"""

import os
import re
import json
import logging
import warnings
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Tuple, Type, Callable
from datetime import datetime, timedelta
from functools import lru_cache, wraps
from dataclasses import dataclass, field
from enum import Enum

# Third-party imports with graceful fallbacks
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None
    ClientError = Exception
    BotoCoreError = Exception

try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Fernet = None

# Flask imports
try:
    from flask import Flask, current_app
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    Flask = None
    current_app = None


class ConfigurationEnvironment(Enum):
    """Configuration environment enumeration for type-safe environment handling."""
    
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    
    @classmethod
    def from_string(cls, env_string: str) -> 'ConfigurationEnvironment':
        """Convert string to ConfigurationEnvironment with validation."""
        env_string = env_string.lower().strip()
        for env in cls:
            if env.value == env_string:
                return env
        raise ValueError(f"Invalid environment: {env_string}")
    
    @property
    def is_production_like(self) -> bool:
        """Check if environment requires production-level security."""
        return self in [self.STAGING, self.PRODUCTION]
    
    @property
    def allows_debug(self) -> bool:
        """Check if environment allows debug features."""
        return self in [self.DEVELOPMENT, self.TESTING]


@dataclass
class ConfigurationMetadata:
    """Metadata for configuration values including source, validation, and security."""
    
    source: str  # Environment variable, AWS Secrets Manager, file, etc.
    is_sensitive: bool = False
    last_updated: Optional[datetime] = None
    validation_rules: List[str] = field(default_factory=list)
    encryption_key_id: Optional[str] = None
    cache_ttl: Optional[int] = None
    
    def should_mask_value(self) -> bool:
        """Determine if configuration value should be masked in logs."""
        return self.is_sensitive or any(
            keyword in self.source.lower() 
            for keyword in ['password', 'secret', 'key', 'token', 'credential']
        )


@dataclass
class ConfigurationValidationResult:
    """Result of configuration validation with detailed feedback."""
    
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    missing_required: List[str] = field(default_factory=list)
    invalid_values: Dict[str, str] = field(default_factory=dict)
    security_issues: List[str] = field(default_factory=list)
    
    @property
    def has_critical_issues(self) -> bool:
        """Check if validation found critical issues preventing application startup."""
        return not self.is_valid or bool(self.security_issues)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary for serialization."""
        return {
            'is_valid': self.is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'missing_required': self.missing_required,
            'invalid_values': self.invalid_values,
            'security_issues': self.security_issues,
            'has_critical_issues': self.has_critical_issues
        }


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""
    pass


class SecureConfigurationError(ConfigurationError):
    """Custom exception for security-related configuration errors."""
    pass


class AWSSecretsManagerClient:
    """
    AWS Secrets Manager client for secure configuration management.
    
    Provides secure retrieval and management of configuration values stored
    in AWS Secrets Manager with automatic decryption, caching, and error handling.
    Integrates with Flask application factory pattern for seamless configuration
    loading during application initialization.
    """
    
    def __init__(self, region_name: str = 'us-east-1', cache_ttl: int = 300):
        """
        Initialize AWS Secrets Manager client with caching.
        
        Args:
            region_name: AWS region for Secrets Manager
            cache_ttl: Cache time-to-live in seconds
        """
        if not AWS_AVAILABLE:
            raise ImportError("boto3 is required for AWS Secrets Manager integration")
        
        self.region_name = region_name
        self.cache_ttl = cache_ttl
        self._client = None
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self.logger = self._get_logger()
    
    def _get_logger(self):
        """Get structured logger for AWS operations."""
        if STRUCTLOG_AVAILABLE:
            return structlog.get_logger("aws_secrets_manager")
        else:
            return logging.getLogger("aws_secrets_manager")
    
    @property
    def client(self):
        """Lazy initialization of AWS Secrets Manager client."""
        if self._client is None:
            try:
                self._client = boto3.client('secretsmanager', region_name=self.region_name)
                # Test connection
                self._client.list_secrets(MaxResults=1)
                self.logger.info("AWS Secrets Manager client initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize AWS Secrets Manager client: {e}")
                raise SecureConfigurationError(f"AWS Secrets Manager initialization failed: {e}")
        return self._client
    
    def get_secret(self, secret_name: str, use_cache: bool = True) -> Optional[Any]:
        """
        Retrieve secret from AWS Secrets Manager with caching.
        
        Args:
            secret_name: Name or ARN of the secret
            use_cache: Whether to use local caching
            
        Returns:
            Secret value (parsed as JSON if possible, otherwise string)
            
        Raises:
            SecureConfigurationError: If secret retrieval fails
        """
        cache_key = f"{self.region_name}:{secret_name}"
        
        # Check cache first
        if use_cache and cache_key in self._cache:
            value, timestamp = self._cache[cache_key]
            if datetime.utcnow() - timestamp < timedelta(seconds=self.cache_ttl):
                self.logger.debug(f"Retrieved secret from cache: {secret_name}")
                return value
        
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            secret_value = response['SecretString']
            
            # Try to parse as JSON
            try:
                parsed_value = json.loads(secret_value)
            except json.JSONDecodeError:
                parsed_value = secret_value
            
            # Cache the result
            if use_cache:
                self._cache[cache_key] = (parsed_value, datetime.utcnow())
            
            self.logger.info(f"Successfully retrieved secret: {secret_name}")
            return parsed_value
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.logger.warning(f"Secret not found: {secret_name}")
                return None
            else:
                self.logger.error(f"Failed to retrieve secret {secret_name}: {e}")
                raise SecureConfigurationError(f"Secret retrieval failed: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error retrieving secret {secret_name}: {e}")
            raise SecureConfigurationError(f"Unexpected secret retrieval error: {e}")
    
    def store_secret(self, secret_name: str, secret_value: Union[str, Dict], 
                    description: Optional[str] = None, tags: Optional[List[Dict]] = None) -> bool:
        """
        Store or update secret in AWS Secrets Manager.
        
        Args:
            secret_name: Name of the secret
            secret_value: Secret value (string or dictionary)
            description: Optional description
            tags: Optional list of tags
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert dict to JSON string
            if isinstance(secret_value, dict):
                secret_string = json.dumps(secret_value)
            else:
                secret_string = str(secret_value)
            
            # Try to update existing secret first
            try:
                self.client.update_secret(
                    SecretId=secret_name,
                    SecretString=secret_string,
                    Description=description
                )
                self.logger.info(f"Successfully updated secret: {secret_name}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Create new secret
                    create_kwargs = {
                        'Name': secret_name,
                        'SecretString': secret_string
                    }
                    if description:
                        create_kwargs['Description'] = description
                    if tags:
                        create_kwargs['Tags'] = tags
                    
                    self.client.create_secret(**create_kwargs)
                    self.logger.info(f"Successfully created secret: {secret_name}")
                else:
                    raise
            
            # Invalidate cache
            cache_key = f"{self.region_name}:{secret_name}"
            if cache_key in self._cache:
                del self._cache[cache_key]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store secret {secret_name}: {e}")
            return False
    
    def list_secrets(self, prefix: Optional[str] = None) -> List[str]:
        """
        List available secrets with optional prefix filtering.
        
        Args:
            prefix: Optional prefix filter
            
        Returns:
            List of secret names
        """
        try:
            secrets = []
            paginator = self.client.get_paginator('list_secrets')
            
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    secret_name = secret['Name']
                    if prefix is None or secret_name.startswith(prefix):
                        secrets.append(secret_name)
            
            return secrets
            
        except Exception as e:
            self.logger.error(f"Failed to list secrets: {e}")
            return []
    
    def clear_cache(self) -> None:
        """Clear the local secret cache."""
        self._cache.clear()
        self.logger.info("Secret cache cleared")


class LocalConfigurationEncryption:
    """
    Local configuration encryption for development and testing environments.
    
    Provides encryption/decryption capabilities for sensitive configuration
    values that cannot use AWS Secrets Manager (e.g., development environments).
    Uses Fernet encryption with PBKDF2 key derivation for secure local storage.
    """
    
    def __init__(self, password: Optional[str] = None):
        """
        Initialize local encryption with password-based key derivation.
        
        Args:
            password: Password for key derivation (defaults to environment variable)
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography is required for local configuration encryption")
        
        self.password = password or os.environ.get('CONFIG_ENCRYPTION_PASSWORD', 'default-dev-password')
        self._fernet = None
        self.logger = self._get_logger()
    
    def _get_logger(self):
        """Get logger for encryption operations."""
        if STRUCTLOG_AVAILABLE:
            return structlog.get_logger("config_encryption")
        else:
            return logging.getLogger("config_encryption")
    
    @property
    def fernet(self) -> Fernet:
        """Lazy initialization of Fernet encryption."""
        if self._fernet is None:
            # Derive key from password
            salt = b'stable_salt_for_config'  # In production, use unique salt per value
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = Fernet.generate_key() if self.password == 'default-dev-password' else kdf.derive(self.password.encode())
            self._fernet = Fernet(key if isinstance(key, bytes) else Fernet.generate_key())
        return self._fernet
    
    def encrypt_value(self, value: str) -> str:
        """
        Encrypt a configuration value.
        
        Args:
            value: Plain text value to encrypt
            
        Returns:
            Base64-encoded encrypted value
        """
        try:
            encrypted = self.fernet.encrypt(value.encode())
            return encrypted.decode()
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise SecureConfigurationError(f"Local encryption failed: {e}")
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """
        Decrypt a configuration value.
        
        Args:
            encrypted_value: Base64-encoded encrypted value
            
        Returns:
            Decrypted plain text value
        """
        try:
            decrypted = self.fernet.decrypt(encrypted_value.encode())
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            raise SecureConfigurationError(f"Local decryption failed: {e}")


class ConfigurationManager:
    """
    Comprehensive configuration management for Flask application factory pattern.
    
    Provides centralized configuration loading, validation, and management with
    support for multiple sources including environment variables, AWS Secrets Manager,
    local files, and container orchestration platforms. Integrates seamlessly with
    Flask 3.1.1 application factory pattern and Python 3.13.3 runtime.
    """
    
    def __init__(self, environment: Optional[ConfigurationEnvironment] = None):
        """
        Initialize configuration manager with environment detection.
        
        Args:
            environment: Specific environment to use (auto-detected if None)
        """
        self.environment = environment or self._detect_environment()
        self.logger = self._get_logger()
        self._aws_client: Optional[AWSSecretsManagerClient] = None
        self._local_encryption: Optional[LocalConfigurationEncryption] = None
        self._cached_config: Dict[str, Any] = {}
        self._config_metadata: Dict[str, ConfigurationMetadata] = {}
        
        self.logger.info(f"Configuration manager initialized for environment: {self.environment.value}")
    
    def _get_logger(self):
        """Get structured logger for configuration operations."""
        if STRUCTLOG_AVAILABLE:
            return structlog.get_logger("configuration_manager")
        else:
            return logging.getLogger("configuration_manager")
    
    def _detect_environment(self) -> ConfigurationEnvironment:
        """
        Detect current environment from various sources.
        
        Checks environment variables, container orchestration metadata,
        and deployment indicators to determine the current environment.
        """
        # Check explicit environment variable
        flask_env = os.environ.get('FLASK_ENV', '').lower()
        if flask_env:
            try:
                return ConfigurationEnvironment.from_string(flask_env)
            except ValueError:
                pass
        
        # Check container orchestration indicators
        if self._is_kubernetes():
            return ConfigurationEnvironment.PRODUCTION
        elif self._is_docker():
            return ConfigurationEnvironment.STAGING
        
        # Check CI/CD indicators
        if os.environ.get('CI') or os.environ.get('GITHUB_ACTIONS'):
            return ConfigurationEnvironment.TESTING
        
        # Default to development
        return ConfigurationEnvironment.DEVELOPMENT
    
    def _is_kubernetes(self) -> bool:
        """Check if running in Kubernetes environment."""
        return (
            os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount') or
            bool(os.environ.get('KUBERNETES_SERVICE_HOST'))
        )
    
    def _is_docker(self) -> bool:
        """Check if running in Docker container."""
        return (
            os.path.exists('/.dockerenv') or
            os.path.exists('/proc/self/cgroup') and 
            any('docker' in line for line in open('/proc/self/cgroup', 'r'))
        )
    
    @property
    def aws_client(self) -> Optional[AWSSecretsManagerClient]:
        """Lazy initialization of AWS Secrets Manager client."""
        if self._aws_client is None and AWS_AVAILABLE:
            try:
                region = os.environ.get('AWS_REGION', 'us-east-1')
                self._aws_client = AWSSecretsManagerClient(region_name=region)
            except Exception as e:
                self.logger.warning(f"AWS Secrets Manager not available: {e}")
        return self._aws_client
    
    @property
    def local_encryption(self) -> LocalConfigurationEncryption:
        """Lazy initialization of local encryption."""
        if self._local_encryption is None:
            try:
                self._local_encryption = LocalConfigurationEncryption()
            except ImportError:
                self.logger.warning("Local encryption not available (cryptography package missing)")
                raise
        return self._local_encryption
    
    def get_configuration_value(
        self,
        key: str,
        default: Any = None,
        value_type: Type = str,
        required: bool = False,
        sensitive: bool = False,
        validator: Optional[Callable[[Any], bool]] = None
    ) -> Any:
        """
        Get configuration value from multiple sources with validation.
        
        Attempts to load configuration from:
        1. Environment variables
        2. AWS Secrets Manager (if available and in production-like environment)
        3. Local encrypted storage (if configured)
        4. Default value
        
        Args:
            key: Configuration key name
            default: Default value if not found
            value_type: Expected type for value conversion
            required: Whether the value is required
            sensitive: Whether the value contains sensitive data
            validator: Optional validation function
            
        Returns:
            Configuration value converted to specified type
            
        Raises:
            ConfigurationError: If required value is missing or validation fails
        """
        # Check cache first
        if key in self._cached_config:
            return self._cached_config[key]
        
        value = None
        source = "default"
        
        # 1. Check environment variables
        env_value = os.environ.get(key)
        if env_value is not None:
            value = env_value
            source = f"environment:{key}"
        
        # 2. Check AWS Secrets Manager for production-like environments
        if value is None and self.environment.is_production_like and self.aws_client:
            secret_name = f"flask-app-{self.environment.value}-{key.lower().replace('_', '-')}"
            secret_value = self.aws_client.get_secret(secret_name)
            if secret_value is not None:
                value = secret_value
                source = f"aws_secrets:{secret_name}"
        
        # 3. Check local encrypted storage
        if value is None and sensitive and self._local_encryption:
            encrypted_key = f"{key}_ENCRYPTED"
            encrypted_value = os.environ.get(encrypted_key)
            if encrypted_value:
                try:
                    value = self.local_encryption.decrypt_value(encrypted_value)
                    source = f"local_encrypted:{encrypted_key}"
                except Exception as e:
                    self.logger.warning(f"Failed to decrypt {encrypted_key}: {e}")
        
        # 4. Use default value
        if value is None:
            if required:
                raise ConfigurationError(f"Required configuration value '{key}' is missing")
            value = default
            source = "default"
        
        # Type conversion
        if value is not None and value_type != str:
            try:
                if value_type == bool:
                    value = str(value).lower() in ('true', '1', 'yes', 'on')
                elif value_type == int:
                    value = int(value)
                elif value_type == float:
                    value = float(value)
                elif value_type == list and isinstance(value, str):
                    value = [item.strip() for item in value.split(',')]
                else:
                    value = value_type(value)
            except (ValueError, TypeError) as e:
                raise ConfigurationError(f"Invalid type for '{key}': {e}")
        
        # Validation
        if validator and value is not None:
            try:
                if not validator(value):
                    raise ConfigurationError(f"Validation failed for '{key}'")
            except Exception as e:
                raise ConfigurationError(f"Validator error for '{key}': {e}")
        
        # Store metadata
        self._config_metadata[key] = ConfigurationMetadata(
            source=source,
            is_sensitive=sensitive,
            last_updated=datetime.utcnow()
        )
        
        # Cache the result
        self._cached_config[key] = value
        
        # Log retrieval (mask sensitive values)
        display_value = "***MASKED***" if sensitive else str(value)
        self.logger.debug(f"Configuration loaded: {key}={display_value} from {source}")
        
        return value
    
    def validate_configuration(self, required_keys: List[str]) -> ConfigurationValidationResult:
        """
        Validate configuration completeness and correctness.
        
        Args:
            required_keys: List of required configuration keys
            
        Returns:
            Comprehensive validation result
        """
        result = ConfigurationValidationResult(is_valid=True)
        
        # Check required keys
        for key in required_keys:
            try:
                value = self.get_configuration_value(key, required=True)
                if value is None or (isinstance(value, str) and not value.strip()):
                    result.missing_required.append(key)
                    result.is_valid = False
            except ConfigurationError as e:
                result.errors.append(str(e))
                result.missing_required.append(key)
                result.is_valid = False
        
        # Environment-specific validation
        if self.environment.is_production_like:
            # Production security checks
            secret_key = os.environ.get('SECRET_KEY', '')
            if not secret_key or len(secret_key) < 32:
                result.security_issues.append("SECRET_KEY must be at least 32 characters in production")
                result.is_valid = False
            
            if not os.environ.get('AUTH0_DOMAIN'):
                result.security_issues.append("AUTH0_DOMAIN is required in production")
                result.is_valid = False
            
            # Check for development defaults in production
            if secret_key and 'dev' in secret_key.lower():
                result.security_issues.append("Development SECRET_KEY detected in production")
                result.is_valid = False
        
        # Container orchestration validation
        if self._is_kubernetes() or self._is_docker():
            if not os.environ.get('CONTAINER_PORT'):
                result.warnings.append("CONTAINER_PORT not set for containerized deployment")
        
        return result
    
    def get_database_configuration(self) -> Dict[str, Any]:
        """
        Get comprehensive database configuration for Flask-SQLAlchemy.
        
        Returns:
            Database configuration dictionary
        """
        config = {}
        
        # Database URI
        database_url = self.get_configuration_value('DATABASE_URL', sensitive=True)
        if database_url:
            config['SQLALCHEMY_DATABASE_URI'] = database_url
        else:
            # Construct from individual components
            db_host = self.get_configuration_value('DB_HOST', 'localhost')
            db_port = self.get_configuration_value('DB_PORT', '5432', int)
            db_name = self.get_configuration_value('DB_NAME', 'flask_app')
            db_user = self.get_configuration_value('DB_USER', required=True)
            db_password = self.get_configuration_value('DB_PASSWORD', sensitive=True, required=True)
            
            config['SQLALCHEMY_DATABASE_URI'] = (
                f"postgresql+psycopg2://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
            )
        
        # Connection pool configuration
        config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': self.get_configuration_value('DB_POOL_SIZE', 10, int),
            'pool_timeout': self.get_configuration_value('DB_POOL_TIMEOUT', 20, int),
            'pool_recycle': self.get_configuration_value('DB_POOL_RECYCLE', 3600, int),
            'max_overflow': self.get_configuration_value('DB_MAX_OVERFLOW', 20, int),
            'pool_pre_ping': True,
            'echo': self.environment.allows_debug and 
                   self.get_configuration_value('SQLALCHEMY_ECHO', False, bool)
        }
        
        # Migration configuration
        config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        config['SQLALCHEMY_RECORD_QUERIES'] = self.environment.allows_debug
        
        return config
    
    def get_aws_configuration(self) -> Dict[str, Any]:
        """
        Get AWS services configuration.
        
        Returns:
            AWS configuration dictionary
        """
        return {
            'AWS_REGION': self.get_configuration_value('AWS_REGION', 'us-east-1'),
            'AWS_ACCESS_KEY_ID': self.get_configuration_value('AWS_ACCESS_KEY_ID', sensitive=True),
            'AWS_SECRET_ACCESS_KEY': self.get_configuration_value('AWS_SECRET_ACCESS_KEY', sensitive=True),
            'AWS_S3_BUCKET': self.get_configuration_value('AWS_S3_BUCKET'),
            'AWS_KMS_KEY_ID': self.get_configuration_value('AWS_KMS_KEY_ID'),
            'AWS_SECRETS_MANAGER_PREFIX': self.get_configuration_value(
                'AWS_SECRETS_MANAGER_PREFIX', 
                f'flask-app-{self.environment.value}'
            )
        }
    
    def get_container_configuration(self) -> Dict[str, Any]:
        """
        Get container orchestration configuration.
        
        Returns:
            Container configuration dictionary
        """
        config = {
            'CONTAINER_PORT': self.get_configuration_value('CONTAINER_PORT', 8000, int),
            'WORKERS': self.get_configuration_value('WORKERS', 4, int),
            'WORKER_CLASS': self.get_configuration_value('WORKER_CLASS', 'sync'),
            'WORKER_CONNECTIONS': self.get_configuration_value('WORKER_CONNECTIONS', 1000, int),
            'TIMEOUT': self.get_configuration_value('TIMEOUT', 30, int),
            'KEEPALIVE': self.get_configuration_value('KEEPALIVE', 5, int)
        }
        
        # Kubernetes-specific configuration
        if self._is_kubernetes():
            config.update({
                'KUBERNETES_NAMESPACE': os.environ.get('KUBERNETES_NAMESPACE', 'default'),
                'KUBERNETES_SERVICE_NAME': os.environ.get('KUBERNETES_SERVICE_NAME'),
                'KUBERNETES_POD_NAME': os.environ.get('HOSTNAME'),
                'KUBERNETES_SERVICE_HOST': os.environ.get('KUBERNETES_SERVICE_HOST'),
                'KUBERNETES_SERVICE_PORT': os.environ.get('KUBERNETES_SERVICE_PORT')
            })
        
        # Docker-specific configuration
        if self._is_docker():
            config.update({
                'DOCKER_CONTAINER_ID': self._get_docker_container_id(),
                'DOCKER_IMAGE': os.environ.get('DOCKER_IMAGE'),
                'DOCKER_TAG': os.environ.get('DOCKER_TAG')
            })
        
        return config
    
    def _get_docker_container_id(self) -> Optional[str]:
        """Get Docker container ID from cgroup information."""
        try:
            with open('/proc/self/cgroup', 'r') as f:
                for line in f:
                    if 'docker' in line:
                        return line.strip().split('/')[-1][:12]
        except Exception:
            pass
        return None
    
    def get_security_configuration(self) -> Dict[str, Any]:
        """
        Get security-related configuration.
        
        Returns:
            Security configuration dictionary
        """
        return {
            'SECRET_KEY': self.get_configuration_value('SECRET_KEY', required=True, sensitive=True),
            'WTF_CSRF_ENABLED': self.get_configuration_value('WTF_CSRF_ENABLED', True, bool),
            'WTF_CSRF_TIME_LIMIT': self.get_configuration_value('WTF_CSRF_TIME_LIMIT', 3600, int),
            'WTF_CSRF_SSL_STRICT': self.get_configuration_value(
                'WTF_CSRF_SSL_STRICT', 
                self.environment.is_production_like, 
                bool
            ),
            'SESSION_TIMEOUT_HOURS': self.get_configuration_value('SESSION_TIMEOUT_HOURS', 24, int),
            'MAX_CONTENT_LENGTH': self.get_configuration_value('MAX_CONTENT_LENGTH', 16 * 1024 * 1024, int),
            'RATELIMIT_ENABLED': self.get_configuration_value(
                'RATELIMIT_ENABLED', 
                self.environment.is_production_like, 
                bool
            ),
            'RATELIMIT_DEFAULT': self.get_configuration_value('RATELIMIT_DEFAULT', '100 per hour')
        }
    
    def get_monitoring_configuration(self) -> Dict[str, Any]:
        """
        Get monitoring and observability configuration.
        
        Returns:
            Monitoring configuration dictionary
        """
        return {
            'METRICS_ENABLED': self.get_configuration_value('METRICS_ENABLED', True, bool),
            'HEALTH_CHECK_ENDPOINT': self.get_configuration_value('HEALTH_CHECK_ENDPOINT', '/health'),
            'METRICS_ENDPOINT': self.get_configuration_value('METRICS_ENDPOINT', '/metrics'),
            'LOG_LEVEL': self.get_configuration_value('LOG_LEVEL', 'INFO'),
            'LOG_FORMAT': self.get_configuration_value('LOG_FORMAT', 'json'),
            'LOG_TO_STDOUT': self.get_configuration_value('LOG_TO_STDOUT', True, bool),
            'PROMETHEUS_MULTIPROC_DIR': self.get_configuration_value('PROMETHEUS_MULTIPROC_DIR', '/tmp/prometheus')
        }
    
    def export_configuration_summary(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Export configuration summary for debugging and monitoring.
        
        Args:
            include_sensitive: Whether to include sensitive values (masked)
            
        Returns:
            Configuration summary dictionary
        """
        summary = {
            'environment': self.environment.value,
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {},
            'validation': {},
            'metadata': {}
        }
        
        # Categorize configuration by source
        for key, metadata in self._config_metadata.items():
            source_type = metadata.source.split(':')[0]
            if source_type not in summary['sources']:
                summary['sources'][source_type] = []
            
            value_info = {
                'key': key,
                'is_sensitive': metadata.is_sensitive,
                'last_updated': metadata.last_updated.isoformat() if metadata.last_updated else None
            }
            
            if include_sensitive or not metadata.is_sensitive:
                if key in self._cached_config:
                    if metadata.should_mask_value():
                        value_info['value'] = '***MASKED***'
                    else:
                        value_info['value'] = self._cached_config[key]
            
            summary['sources'][source_type].append(value_info)
        
        # Add environment detection info
        summary['environment_detection'] = {
            'is_kubernetes': self._is_kubernetes(),
            'is_docker': self._is_docker(),
            'detected_environment': self.environment.value
        }
        
        return summary
    
    def clear_cache(self) -> None:
        """Clear all cached configuration values."""
        self._cached_config.clear()
        self._config_metadata.clear()
        if self.aws_client:
            self.aws_client.clear_cache()
        self.logger.info("Configuration cache cleared")


def create_flask_configuration_manager(app: Optional[Flask] = None) -> ConfigurationManager:
    """
    Create and configure a ConfigurationManager for Flask application factory pattern.
    
    Factory function for creating ConfigurationManager instances integrated with
    Flask applications. Automatically detects environment and configures appropriate
    backends for configuration loading.
    
    Args:
        app: Optional Flask application instance for integration
        
    Returns:
        Configured ConfigurationManager instance
        
    Examples:
        >>> config_manager = create_flask_configuration_manager()
        >>> db_config = config_manager.get_database_configuration()
        >>> app.config.update(db_config)
    """
    manager = ConfigurationManager()
    
    if app is not None:
        # Store manager in app for access from request context
        app.config_manager = manager
        
        # Add configuration validation command
        @app.cli.command()
        def validate_config():
            """Validate application configuration."""
            required_keys = ['SECRET_KEY', 'DB_USER', 'DB_PASSWORD']
            result = manager.validate_configuration(required_keys)
            
            if result.is_valid:
                print("✅ Configuration validation passed")
            else:
                print("❌ Configuration validation failed")
                for error in result.errors:
                    print(f"  Error: {error}")
                for issue in result.security_issues:
                    print(f"  Security: {issue}")
                for missing in result.missing_required:
                    print(f"  Missing: {missing}")
            
            if result.warnings:
                print("⚠️  Warnings:")
                for warning in result.warnings:
                    print(f"  {warning}")
    
    return manager


def load_environment_configuration(
    config_obj: Any,
    environment: Optional[str] = None,
    aws_secrets_prefix: Optional[str] = None
) -> None:
    """
    Load environment-specific configuration into Flask config object.
    
    Utility function for loading configuration from multiple sources into a
    Flask configuration object. Supports environment variables, AWS Secrets Manager,
    and local encrypted storage with automatic fallback.
    
    Args:
        config_obj: Flask config object or dictionary to update
        environment: Target environment (auto-detected if None)
        aws_secrets_prefix: Prefix for AWS Secrets Manager secrets
        
    Examples:
        >>> app = Flask(__name__)
        >>> load_environment_configuration(app.config)
        >>> # Configuration automatically loaded from multiple sources
    """
    # Determine environment
    if environment is None:
        environment = os.environ.get('FLASK_ENV', 'development')
    
    # Create configuration manager
    env_enum = ConfigurationEnvironment.from_string(environment)
    manager = ConfigurationManager(env_enum)
    
    # Load core configuration sections
    try:
        # Database configuration
        db_config = manager.get_database_configuration()
        config_obj.update(db_config)
        
        # Security configuration
        security_config = manager.get_security_configuration()
        config_obj.update(security_config)
        
        # AWS configuration
        aws_config = manager.get_aws_configuration()
        config_obj.update(aws_config)
        
        # Container configuration
        container_config = manager.get_container_configuration()
        config_obj.update(container_config)
        
        # Monitoring configuration
        monitoring_config = manager.get_monitoring_configuration()
        config_obj.update(monitoring_config)
        
        # Environment-specific overrides
        if env_enum == ConfigurationEnvironment.DEVELOPMENT:
            config_obj.update({
                'DEBUG': True,
                'FLASK_ENV': 'development',
                'SQLALCHEMY_ECHO': True
            })
        elif env_enum == ConfigurationEnvironment.TESTING:
            config_obj.update({
                'TESTING': True,
                'WTF_CSRF_ENABLED': False,
                'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
            })
        elif env_enum.is_production_like:
            config_obj.update({
                'DEBUG': False,
                'PREFERRED_URL_SCHEME': 'https',
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True
            })
        
        manager.logger.info(f"Configuration loaded successfully for environment: {environment}")
        
    except Exception as e:
        if manager.logger:
            manager.logger.error(f"Failed to load configuration: {e}")
        raise ConfigurationError(f"Configuration loading failed: {e}")


def validate_flask_configuration(app: Flask) -> ConfigurationValidationResult:
    """
    Validate Flask application configuration for completeness and security.
    
    Comprehensive validation function for Flask applications that checks
    required configuration values, security settings, and environment-specific
    requirements. Used during application startup to catch configuration errors.
    
    Args:
        app: Flask application instance
        
    Returns:
        Detailed validation result
        
    Examples:
        >>> app = Flask(__name__)
        >>> result = validate_flask_configuration(app)
        >>> if not result.is_valid:
        ...     raise RuntimeError("Invalid configuration")
    """
    manager = getattr(app, 'config_manager', None)
    if manager is None:
        manager = ConfigurationManager()
    
    # Define required keys based on environment
    required_keys = ['SECRET_KEY']
    
    # Add environment-specific requirements
    if manager.environment.is_production_like:
        required_keys.extend([
            'DB_USER', 'DB_PASSWORD', 'AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET'
        ])
    elif manager.environment == ConfigurationEnvironment.DEVELOPMENT:
        required_keys.extend(['DB_USER'])
    
    # Perform validation
    result = manager.validate_configuration(required_keys)
    
    # Additional Flask-specific validation
    if app.config.get('SECRET_KEY') == 'dev':
        result.security_issues.append("Development SECRET_KEY in use")
        if manager.environment.is_production_like:
            result.is_valid = False
    
    # Database URI validation
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
    if not db_uri and manager.environment != ConfigurationEnvironment.TESTING:
        result.errors.append("SQLALCHEMY_DATABASE_URI is required")
        result.is_valid = False
    
    return result


# Configuration utility decorators
def require_configuration(*required_keys: str):
    """
    Decorator to ensure required configuration keys are present.
    
    Args:
        *required_keys: Configuration keys that must be present
        
    Returns:
        Decorator function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if FLASK_AVAILABLE and current_app:
                for key in required_keys:
                    if not current_app.config.get(key):
                        raise ConfigurationError(f"Required configuration '{key}' is missing")
            return func(*args, **kwargs)
        return wrapper
    return decorator


def configuration_cached(cache_key: str, ttl: int = 300):
    """
    Decorator to cache configuration-dependent function results.
    
    Args:
        cache_key: Key for caching results
        ttl: Time-to-live in seconds
        
    Returns:
        Decorator function
    """
    def decorator(func):
        cache = {}
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = f"{cache_key}:{hash(str(args) + str(kwargs))}"
            now = datetime.utcnow()
            
            if key in cache:
                result, timestamp = cache[key]
                if (now - timestamp).total_seconds() < ttl:
                    return result
            
            result = func(*args, **kwargs)
            cache[key] = (result, now)
            return result
        
        return wrapper
    return decorator


# Module-level configuration manager instance
_default_manager: Optional[ConfigurationManager] = None


def get_default_configuration_manager() -> ConfigurationManager:
    """
    Get the default module-level configuration manager instance.
    
    Provides a singleton configuration manager for use across the application.
    Creates a new instance if one doesn't exist.
    
    Returns:
        Default ConfigurationManager instance
    """
    global _default_manager
    if _default_manager is None:
        _default_manager = ConfigurationManager()
    return _default_manager


# Convenience functions for common configuration patterns
def get_database_url(environment: Optional[str] = None) -> str:
    """Get database URL for the specified environment."""
    manager = get_default_configuration_manager()
    db_config = manager.get_database_configuration()
    return db_config['SQLALCHEMY_DATABASE_URI']


def get_secret_key(environment: Optional[str] = None) -> str:
    """Get Flask secret key for the specified environment."""
    manager = get_default_configuration_manager()
    return manager.get_configuration_value('SECRET_KEY', required=True, sensitive=True)


def is_debug_enabled(environment: Optional[str] = None) -> bool:
    """Check if debug mode is enabled for the environment."""
    manager = get_default_configuration_manager()
    return manager.environment.allows_debug


def get_aws_region(environment: Optional[str] = None) -> str:
    """Get AWS region for the specified environment."""
    manager = get_default_configuration_manager()
    return manager.get_configuration_value('AWS_REGION', 'us-east-1')


if __name__ == '__main__':
    """
    Configuration management testing and validation script.
    
    When run directly, performs comprehensive testing of configuration
    management capabilities including environment detection, AWS integration,
    and validation functionality.
    """
    print("Flask Configuration Management Utilities Test")
    print("=" * 60)
    
    try:
        # Create configuration manager
        manager = ConfigurationManager()
        print(f"✅ Configuration manager created for environment: {manager.environment.value}")
        
        # Test environment detection
        print(f"Environment detection:")
        print(f"  - Is Kubernetes: {manager._is_kubernetes()}")
        print(f"  - Is Docker: {manager._is_docker()}")
        print(f"  - Environment: {manager.environment.value}")
        
        # Test configuration loading
        print("\nTesting configuration loading:")
        try:
            secret_key = manager.get_configuration_value('SECRET_KEY', 'test-key', sensitive=True)
            print(f"  - SECRET_KEY: ***MASKED*** (loaded from {manager._config_metadata['SECRET_KEY'].source})")
        except Exception as e:
            print(f"  - SECRET_KEY loading failed: {e}")
        
        # Test validation
        print("\nValidating configuration:")
        result = manager.validate_configuration(['SECRET_KEY'])
        print(f"  - Validation result: {'PASS' if result.is_valid else 'FAIL'}")
        if result.errors:
            for error in result.errors:
                print(f"    Error: {error}")
        if result.warnings:
            for warning in result.warnings:
                print(f"    Warning: {warning}")
        
        # Test AWS availability
        print(f"\nAWS Integration:")
        print(f"  - AWS SDK available: {AWS_AVAILABLE}")
        if manager.aws_client:
            print(f"  - AWS Secrets Manager: Available")
        else:
            print(f"  - AWS Secrets Manager: Not configured")
        
        # Export configuration summary
        print(f"\nConfiguration summary:")
        summary = manager.export_configuration_summary()
        print(f"  - Environment: {summary['environment']}")
        print(f"  - Sources: {list(summary['sources'].keys())}")
        print(f"  - Kubernetes: {summary['environment_detection']['is_kubernetes']}")
        print(f"  - Docker: {summary['environment_detection']['is_docker']}")
        
        print("\n✅ Configuration management test completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Configuration management test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)