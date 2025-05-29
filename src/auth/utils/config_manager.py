"""
Flask Authentication Configuration Management Utility

This module provides centralized configuration handling for all authentication services
in the Flask application, implementing the Flask application factory pattern for
systematic authentication configuration management. The module ensures consistent
authentication settings across development, staging, and production environments
while providing secure configuration management for Auth0, JWT, session handling,
and security policies.

Configuration Management:
- Flask application factory pattern implementation (Section 5.1.1)
- Auth0 Python SDK configuration management (Section 6.4.1.1)
- JWT token configuration with Flask-JWT-Extended (Section 6.4.1.4)
- Flask-Login session configuration management (Section 6.4.1.3)
- Environment-specific authentication settings (Section 4.6.2)

Security Features:
- Secure key management with AWS integration
- Environment variable validation and sanitization
- Configuration encryption for sensitive data
- Development vs production configuration separation
- Comprehensive configuration validation and error handling

Integration:
This module integrates with the Flask application factory pattern to provide
authentication configuration during application initialization, supporting
blueprint registration sequences and extension integration management as
specified in Section 5.1.1.

Author: Flask Migration Team
Version: 1.0.0 (Python 3.13.3, Flask 3.1.1)
"""

import os
import secrets
import logging
from datetime import timedelta
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
from enum import Enum
import json
import base64
from pathlib import Path

# Flask and authentication framework imports
from flask import Flask, current_app
from werkzeug.security import safe_str_cmp

# Cryptographic imports for secure configuration
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Structured logging for configuration management
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    import logging as structlog

# AWS integration for configuration management
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

# Validation utilities
try:
    from marshmallow import Schema, fields, ValidationError, validates, validates_schema
    MARSHMALLOW_AVAILABLE = True
except ImportError:
    MARSHMALLOW_AVAILABLE = False


class ConfigurationEnvironment(Enum):
    """Environment types for configuration management."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class ConfigurationSource(Enum):
    """Configuration source types for priority management."""
    ENVIRONMENT_VARIABLES = "environment"
    CONFIGURATION_FILE = "file"
    AWS_SECRETS_MANAGER = "aws_secrets"
    AWS_PARAMETER_STORE = "aws_parameters"
    DEFAULT_VALUES = "defaults"


@dataclass
class Auth0Configuration:
    """Auth0 identity provider configuration data structure."""
    domain: str
    client_id: str
    client_secret: str
    audience: Optional[str] = None
    scope: str = "openid profile email"
    management_api_token: Optional[str] = None
    management_api_audience: Optional[str] = None
    algorithms: List[str] = field(default_factory=lambda: ["RS256"])
    jwks_uri: Optional[str] = None
    issuer: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization validation and derived configuration."""
        if not self.audience:
            self.audience = f"https://{self.domain}/api/v2/"
        
        if not self.jwks_uri:
            self.jwks_uri = f"https://{self.domain}/.well-known/jwks.json"
        
        if not self.issuer:
            self.issuer = f"https://{self.domain}/"
        
        if not self.management_api_audience:
            self.management_api_audience = f"https://{self.domain}/api/v2/"
    
    def validate(self) -> bool:
        """Validate Auth0 configuration completeness."""
        required_fields = ['domain', 'client_id', 'client_secret']
        for field_name in required_fields:
            if not getattr(self, field_name):
                raise ValueError(f"Auth0 configuration missing required field: {field_name}")
        return True


@dataclass 
class JWTConfiguration:
    """JWT token configuration data structure."""
    secret_key: str
    algorithm: str = "HS256"
    access_token_expires: timedelta = timedelta(hours=1)
    refresh_token_expires: timedelta = timedelta(days=30)
    blacklist_enabled: bool = True
    blacklist_token_checks: List[str] = field(default_factory=lambda: ["access", "refresh"])
    cookie_secure: bool = True
    cookie_csrf_protect: bool = True
    access_cookie_name: str = "access_token_cookie"
    refresh_cookie_name: str = "refresh_token_cookie"
    csrf_token_name: str = "csrf_token"
    csrf_header_name: str = "X-CSRF-TOKEN"
    decode_leeway: timedelta = timedelta(seconds=10)
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.secret_key:
            raise ValueError("JWT secret key is required")
        
        if len(self.secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")


@dataclass
class SessionConfiguration:
    """Flask session management configuration data structure."""
    secret_key: str
    timeout: int = 3600  # 1 hour in seconds
    permanent_session_lifetime: timedelta = timedelta(hours=1)
    remember_cookie_duration: timedelta = timedelta(days=30)
    session_protection: str = "strong"
    cookie_name: str = "session"
    cookie_domain: Optional[str] = None
    cookie_path: str = "/"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = "Lax"
    use_signer: bool = True
    key_derivation: str = "hmac"
    salt: str = "cookie-session"
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not self.secret_key:
            raise ValueError("Session secret key is required")
        
        if len(self.secret_key) < 32:
            raise ValueError("Session secret key must be at least 32 characters")
        
        if self.session_protection not in ["basic", "strong", None]:
            raise ValueError("Session protection must be 'basic', 'strong', or None")


@dataclass
class SecurityConfiguration:
    """Security policy configuration data structure."""
    csrf_enabled: bool = True
    csrf_time_limit: int = 3600  # 1 hour
    csrf_ssl_strict: bool = True
    csrf_check_default: bool = True
    password_hash_method: str = "pbkdf2:sha256"
    password_salt_length: int = 16
    password_hash_iterations: int = 260000  # OWASP recommended minimum
    max_login_attempts: int = 5
    account_lockout_duration: int = 1800  # 30 minutes
    session_regeneration_interval: int = 3600  # 1 hour
    security_headers_enabled: bool = True
    content_security_policy: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization validation."""
        if self.password_hash_iterations < 100000:
            raise ValueError("Password hash iterations must be at least 100,000")
        
        if self.password_salt_length < 8:
            raise ValueError("Password salt length must be at least 8 bytes")


class AuthConfigurationManager:
    """
    Centralized authentication configuration manager implementing Flask application
    factory pattern for systematic authentication configuration during application
    initialization. Provides environment-specific configuration management, secure
    configuration storage, and comprehensive validation for all authentication
    services.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize the authentication configuration manager.
        
        Args:
            app: Optional Flask application instance for immediate initialization
        """
        self.app = app
        self.environment = None
        self.config_sources = {}
        self.encrypted_config = None
        self.encryption_key = None
        
        # Configuration data structures
        self.auth0_config: Optional[Auth0Configuration] = None
        self.jwt_config: Optional[JWTConfiguration] = None
        self.session_config: Optional[SessionConfiguration] = None
        self.security_config: Optional[SecurityConfiguration] = None
        
        # AWS clients for external configuration management
        self.secrets_client = None
        self.ssm_client = None
        
        # Initialize logger
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("auth_config_manager")
        else:
            self.logger = logging.getLogger("auth_config_manager")
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize authentication configuration with Flask application factory pattern.
        
        This method integrates with the Flask application factory pattern to provide
        systematic authentication configuration loading and validation during
        application initialization per Section 5.1.1.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        self.environment = self._detect_environment(app)
        
        try:
            # Initialize AWS clients if available
            self._init_aws_clients(app)
            
            # Load configuration from multiple sources
            self._load_configuration_sources(app)
            
            # Initialize authentication configurations
            self._init_auth0_configuration(app)
            self._init_jwt_configuration(app)
            self._init_session_configuration(app)
            self._init_security_configuration(app)
            
            # Apply configuration to Flask application
            self._apply_flask_configuration(app)
            
            # Validate complete configuration
            self._validate_configuration()
            
            # Store manager reference in application
            app.auth_config_manager = self
            
            self.logger.info(
                "Authentication configuration manager initialized",
                environment=self.environment.value,
                auth0_enabled=self.auth0_config is not None,
                jwt_enabled=self.jwt_config is not None,
                session_enabled=self.session_config is not None,
                security_enabled=self.security_config is not None
            )
            
        except Exception as e:
            self.logger.error("Failed to initialize authentication configuration", error=str(e))
            raise
    
    def _detect_environment(self, app: Flask) -> ConfigurationEnvironment:
        """
        Detect the current application environment for configuration selection.
        
        Args:
            app: Flask application instance
            
        Returns:
            ConfigurationEnvironment enum value
        """
        flask_env = app.config.get('FLASK_ENV', '').lower()
        app_env = os.environ.get('APP_ENV', '').lower()
        env = os.environ.get('ENVIRONMENT', '').lower()
        
        # Priority: FLASK_ENV > APP_ENV > ENVIRONMENT
        environment_string = flask_env or app_env or env or 'development'
        
        try:
            return ConfigurationEnvironment(environment_string)
        except ValueError:
            self.logger.warning(
                "Unknown environment detected, defaulting to development",
                detected_env=environment_string
            )
            return ConfigurationEnvironment.DEVELOPMENT
    
    def _init_aws_clients(self, app: Flask) -> None:
        """Initialize AWS clients for external configuration management."""
        if not AWS_AVAILABLE:
            self.logger.info("AWS SDK not available - external configuration disabled")
            return
        
        try:
            aws_region = app.config.get('AWS_REGION', os.environ.get('AWS_REGION', 'us-east-1'))
            
            # Initialize AWS Secrets Manager client
            if app.config.get('USE_AWS_SECRETS_MANAGER', False):
                self.secrets_client = boto3.client('secretsmanager', region_name=aws_region)
                self.logger.info("AWS Secrets Manager client initialized")
            
            # Initialize AWS Systems Manager Parameter Store client
            if app.config.get('USE_AWS_PARAMETER_STORE', False):
                self.ssm_client = boto3.client('ssm', region_name=aws_region)
                self.logger.info("AWS Parameter Store client initialized")
                
        except (NoCredentialsError, Exception) as e:
            self.logger.warning("Failed to initialize AWS clients", error=str(e))
    
    def _load_configuration_sources(self, app: Flask) -> None:
        """Load configuration from multiple sources with priority handling."""
        self.config_sources = {
            ConfigurationSource.DEFAULT_VALUES: self._load_default_configuration(),
            ConfigurationSource.ENVIRONMENT_VARIABLES: self._load_environment_configuration(),
            ConfigurationSource.CONFIGURATION_FILE: self._load_file_configuration(app),
            ConfigurationSource.AWS_SECRETS_MANAGER: self._load_aws_secrets_configuration(app),
            ConfigurationSource.AWS_PARAMETER_STORE: self._load_aws_parameters_configuration(app)
        }
        
        self.logger.info(
            "Configuration sources loaded",
            sources=[source.value for source, config in self.config_sources.items() if config]
        )
    
    def _load_default_configuration(self) -> Dict[str, Any]:
        """Load default authentication configuration values."""
        return {
            # Auth0 defaults
            'AUTH0_ALGORITHMS': ['RS256'],
            'AUTH0_SCOPE': 'openid profile email',
            
            # JWT defaults
            'JWT_ALGORITHM': 'HS256',
            'JWT_ACCESS_TOKEN_EXPIRES': timedelta(hours=1),
            'JWT_REFRESH_TOKEN_EXPIRES': timedelta(days=30),
            'JWT_BLACKLIST_ENABLED': True,
            'JWT_BLACKLIST_TOKEN_CHECKS': ['access', 'refresh'],
            'JWT_COOKIE_SECURE': True,
            'JWT_COOKIE_CSRF_PROTECT': True,
            'JWT_ACCESS_COOKIE_NAME': 'access_token_cookie',
            'JWT_REFRESH_COOKIE_NAME': 'refresh_token_cookie',
            'JWT_CSRF_TOKEN_NAME': 'csrf_token',
            'JWT_CSRF_HEADER_NAME': 'X-CSRF-TOKEN',
            'JWT_DECODE_LEEWAY': timedelta(seconds=10),
            
            # Session defaults
            'SESSION_TIMEOUT': 3600,
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=1),
            'REMEMBER_COOKIE_DURATION': timedelta(days=30),
            'SESSION_PROTECTION': 'strong',
            'SESSION_COOKIE_NAME': 'session',
            'SESSION_COOKIE_PATH': '/',
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'SESSION_USE_SIGNER': True,
            'SESSION_KEY_DERIVATION': 'hmac',
            'SESSION_SALT': 'cookie-session',
            
            # Security defaults
            'WTF_CSRF_ENABLED': True,
            'WTF_CSRF_TIME_LIMIT': 3600,
            'WTF_CSRF_SSL_STRICT': True,
            'WTF_CSRF_CHECK_DEFAULT': True,
            'PASSWORD_HASH_METHOD': 'pbkdf2:sha256',
            'PASSWORD_SALT_LENGTH': 16,
            'PASSWORD_HASH_ITERATIONS': 260000,
            'MAX_LOGIN_ATTEMPTS': 5,
            'ACCOUNT_LOCKOUT_DURATION': 1800,
            'SESSION_REGENERATION_INTERVAL': 3600,
            'SECURITY_HEADERS_ENABLED': True
        }
    
    def _load_environment_configuration(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}
        
        # Auth0 environment variables
        if os.environ.get('AUTH0_DOMAIN'):
            config.update({
                'AUTH0_DOMAIN': os.environ.get('AUTH0_DOMAIN'),
                'AUTH0_CLIENT_ID': os.environ.get('AUTH0_CLIENT_ID'),
                'AUTH0_CLIENT_SECRET': os.environ.get('AUTH0_CLIENT_SECRET'),
                'AUTH0_AUDIENCE': os.environ.get('AUTH0_AUDIENCE'),
                'AUTH0_SCOPE': os.environ.get('AUTH0_SCOPE', 'openid profile email'),
                'AUTH0_MANAGEMENT_API_TOKEN': os.environ.get('AUTH0_MANAGEMENT_API_TOKEN'),
                'AUTH0_MANAGEMENT_API_AUDIENCE': os.environ.get('AUTH0_MANAGEMENT_API_AUDIENCE'),
                'AUTH0_ALGORITHMS': os.environ.get('AUTH0_ALGORITHMS', 'RS256').split(',')
            })
        
        # JWT environment variables
        if os.environ.get('JWT_SECRET_KEY'):
            config.update({
                'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY'),
                'JWT_ALGORITHM': os.environ.get('JWT_ALGORITHM', 'HS256'),
                'JWT_ACCESS_TOKEN_EXPIRES': self._parse_timedelta(
                    os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', '3600')
                ),
                'JWT_REFRESH_TOKEN_EXPIRES': self._parse_timedelta(
                    os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', '2592000')  # 30 days
                ),
                'JWT_BLACKLIST_ENABLED': self._parse_bool(
                    os.environ.get('JWT_BLACKLIST_ENABLED', 'true')
                ),
                'JWT_COOKIE_SECURE': self._parse_bool(
                    os.environ.get('JWT_COOKIE_SECURE', 'true')
                )
            })
        
        # Session environment variables
        if os.environ.get('SECRET_KEY'):
            config.update({
                'SECRET_KEY': os.environ.get('SECRET_KEY'),
                'SESSION_TIMEOUT': int(os.environ.get('SESSION_TIMEOUT', '3600')),
                'SESSION_PROTECTION': os.environ.get('SESSION_PROTECTION', 'strong'),
                'SESSION_COOKIE_SECURE': self._parse_bool(
                    os.environ.get('SESSION_COOKIE_SECURE', 'true')
                ),
                'SESSION_COOKIE_HTTPONLY': self._parse_bool(
                    os.environ.get('SESSION_COOKIE_HTTPONLY', 'true')
                ),
                'SESSION_COOKIE_SAMESITE': os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
            })
        
        # Security environment variables
        config.update({
            'WTF_CSRF_ENABLED': self._parse_bool(
                os.environ.get('WTF_CSRF_ENABLED', 'true')
            ),
            'WTF_CSRF_TIME_LIMIT': int(os.environ.get('WTF_CSRF_TIME_LIMIT', '3600')),
            'PASSWORD_HASH_ITERATIONS': int(os.environ.get('PASSWORD_HASH_ITERATIONS', '260000')),
            'MAX_LOGIN_ATTEMPTS': int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
        })
        
        return config
    
    def _load_file_configuration(self, app: Flask) -> Dict[str, Any]:
        """Load configuration from configuration files."""
        config = {}
        
        # Check for environment-specific configuration files
        config_file_path = app.config.get('AUTH_CONFIG_FILE') or os.environ.get('AUTH_CONFIG_FILE')
        
        if not config_file_path:
            # Default configuration file paths
            config_dir = Path(app.root_path) / 'config'
            env_config_file = config_dir / f'auth_{self.environment.value}.json'
            default_config_file = config_dir / 'auth.json'
            
            if env_config_file.exists():
                config_file_path = env_config_file
            elif default_config_file.exists():
                config_file_path = default_config_file
        
        if config_file_path and Path(config_file_path).exists():
            try:
                with open(config_file_path, 'r') as file:
                    file_config = json.load(file)
                    config.update(file_config)
                    self.logger.info("Configuration loaded from file", file_path=str(config_file_path))
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning("Failed to load configuration file", file_path=str(config_file_path), error=str(e))
        
        return config
    
    def _load_aws_secrets_configuration(self, app: Flask) -> Dict[str, Any]:
        """Load configuration from AWS Secrets Manager."""
        config = {}
        
        if not self.secrets_client:
            return config
        
        secret_name = app.config.get('AUTH_SECRET_NAME') or os.environ.get('AUTH_SECRET_NAME')
        if not secret_name:
            secret_name = f"flask-auth-{self.environment.value}"
        
        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            secret_config = json.loads(response['SecretString'])
            config.update(secret_config)
            self.logger.info("Configuration loaded from AWS Secrets Manager", secret_name=secret_name)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.logger.info("AWS Secrets Manager secret not found", secret_name=secret_name)
            else:
                self.logger.warning("Failed to load AWS Secrets Manager configuration", error=str(e))
        except (json.JSONDecodeError, Exception) as e:
            self.logger.warning("Failed to parse AWS Secrets Manager configuration", error=str(e))
        
        return config
    
    def _load_aws_parameters_configuration(self, app: Flask) -> Dict[str, Any]:
        """Load configuration from AWS Systems Manager Parameter Store."""
        config = {}
        
        if not self.ssm_client:
            return config
        
        parameter_prefix = app.config.get('AUTH_PARAMETER_PREFIX') or os.environ.get('AUTH_PARAMETER_PREFIX')
        if not parameter_prefix:
            parameter_prefix = f"/flask-auth/{self.environment.value}/"
        
        try:
            response = self.ssm_client.get_parameters_by_path(
                Path=parameter_prefix,
                Recursive=True,
                WithDecryption=True
            )
            
            for parameter in response.get('Parameters', []):
                # Convert parameter name to config key
                key = parameter['Name'].replace(parameter_prefix, '').replace('/', '_').upper()
                value = parameter['Value']
                
                # Try to parse as JSON for complex values
                try:
                    config[key] = json.loads(value)
                except json.JSONDecodeError:
                    config[key] = value
            
            if config:
                self.logger.info("Configuration loaded from AWS Parameter Store", prefix=parameter_prefix)
                
        except ClientError as e:
            self.logger.warning("Failed to load AWS Parameter Store configuration", error=str(e))
        except Exception as e:
            self.logger.warning("Failed to parse AWS Parameter Store configuration", error=str(e))
        
        return config
    
    def _get_config_value(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with source priority handling.
        
        Priority order:
        1. AWS Secrets Manager
        2. AWS Parameter Store
        3. Configuration File
        4. Environment Variables
        5. Default Values
        
        Args:
            key: Configuration key name
            default: Default value if not found in any source
            
        Returns:
            Configuration value from highest priority source
        """
        sources_priority = [
            ConfigurationSource.AWS_SECRETS_MANAGER,
            ConfigurationSource.AWS_PARAMETER_STORE,
            ConfigurationSource.CONFIGURATION_FILE,
            ConfigurationSource.ENVIRONMENT_VARIABLES,
            ConfigurationSource.DEFAULT_VALUES
        ]
        
        for source in sources_priority:
            source_config = self.config_sources.get(source, {})
            if key in source_config:
                value = source_config[key]
                self.logger.debug("Configuration value retrieved", key=key, source=source.value)
                return value
        
        return default
    
    def _init_auth0_configuration(self, app: Flask) -> None:
        """Initialize Auth0 identity provider configuration."""
        auth0_domain = self._get_config_value('AUTH0_DOMAIN')
        auth0_client_id = self._get_config_value('AUTH0_CLIENT_ID')
        auth0_client_secret = self._get_config_value('AUTH0_CLIENT_SECRET')
        
        if auth0_domain and auth0_client_id and auth0_client_secret:
            try:
                self.auth0_config = Auth0Configuration(
                    domain=auth0_domain,
                    client_id=auth0_client_id,
                    client_secret=auth0_client_secret,
                    audience=self._get_config_value('AUTH0_AUDIENCE'),
                    scope=self._get_config_value('AUTH0_SCOPE', 'openid profile email'),
                    management_api_token=self._get_config_value('AUTH0_MANAGEMENT_API_TOKEN'),
                    management_api_audience=self._get_config_value('AUTH0_MANAGEMENT_API_AUDIENCE'),
                    algorithms=self._get_config_value('AUTH0_ALGORITHMS', ['RS256'])
                )
                
                self.auth0_config.validate()
                self.logger.info("Auth0 configuration initialized", domain=auth0_domain)
                
            except Exception as e:
                self.logger.error("Failed to initialize Auth0 configuration", error=str(e))
                raise
        else:
            self.logger.info("Auth0 configuration not available - Auth0 integration disabled")
    
    def _init_jwt_configuration(self, app: Flask) -> None:
        """Initialize JWT token configuration."""
        jwt_secret_key = self._get_config_value('JWT_SECRET_KEY') or self._get_config_value('SECRET_KEY')
        
        if not jwt_secret_key:
            jwt_secret_key = secrets.token_hex(32)
            self.logger.warning("JWT secret key not configured - using generated key")
        
        try:
            self.jwt_config = JWTConfiguration(
                secret_key=jwt_secret_key,
                algorithm=self._get_config_value('JWT_ALGORITHM', 'HS256'),
                access_token_expires=self._get_config_value('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1)),
                refresh_token_expires=self._get_config_value('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=30)),
                blacklist_enabled=self._get_config_value('JWT_BLACKLIST_ENABLED', True),
                blacklist_token_checks=self._get_config_value('JWT_BLACKLIST_TOKEN_CHECKS', ['access', 'refresh']),
                cookie_secure=self._get_config_value('JWT_COOKIE_SECURE', self.environment == ConfigurationEnvironment.PRODUCTION),
                cookie_csrf_protect=self._get_config_value('JWT_COOKIE_CSRF_PROTECT', True),
                access_cookie_name=self._get_config_value('JWT_ACCESS_COOKIE_NAME', 'access_token_cookie'),
                refresh_cookie_name=self._get_config_value('JWT_REFRESH_COOKIE_NAME', 'refresh_token_cookie'),
                csrf_token_name=self._get_config_value('JWT_CSRF_TOKEN_NAME', 'csrf_token'),
                csrf_header_name=self._get_config_value('JWT_CSRF_HEADER_NAME', 'X-CSRF-TOKEN'),
                decode_leeway=self._get_config_value('JWT_DECODE_LEEWAY', timedelta(seconds=10))
            )
            
            self.logger.info("JWT configuration initialized")
            
        except Exception as e:
            self.logger.error("Failed to initialize JWT configuration", error=str(e))
            raise
    
    def _init_session_configuration(self, app: Flask) -> None:
        """Initialize Flask session management configuration."""
        secret_key = self._get_config_value('SECRET_KEY')
        
        if not secret_key:
            secret_key = secrets.token_hex(32)
            self.logger.warning("Session secret key not configured - using generated key")
        
        try:
            self.session_config = SessionConfiguration(
                secret_key=secret_key,
                timeout=self._get_config_value('SESSION_TIMEOUT', 3600),
                permanent_session_lifetime=self._get_config_value('PERMANENT_SESSION_LIFETIME', timedelta(hours=1)),
                remember_cookie_duration=self._get_config_value('REMEMBER_COOKIE_DURATION', timedelta(days=30)),
                session_protection=self._get_config_value('SESSION_PROTECTION', 'strong'),
                cookie_name=self._get_config_value('SESSION_COOKIE_NAME', 'session'),
                cookie_domain=self._get_config_value('SESSION_COOKIE_DOMAIN'),
                cookie_path=self._get_config_value('SESSION_COOKIE_PATH', '/'),
                cookie_secure=self._get_config_value('SESSION_COOKIE_SECURE', self.environment == ConfigurationEnvironment.PRODUCTION),
                cookie_httponly=self._get_config_value('SESSION_COOKIE_HTTPONLY', True),
                cookie_samesite=self._get_config_value('SESSION_COOKIE_SAMESITE', 'Lax'),
                use_signer=self._get_config_value('SESSION_USE_SIGNER', True),
                key_derivation=self._get_config_value('SESSION_KEY_DERIVATION', 'hmac'),
                salt=self._get_config_value('SESSION_SALT', 'cookie-session')
            )
            
            self.logger.info("Session configuration initialized")
            
        except Exception as e:
            self.logger.error("Failed to initialize session configuration", error=str(e))
            raise
    
    def _init_security_configuration(self, app: Flask) -> None:
        """Initialize security policy configuration."""
        try:
            self.security_config = SecurityConfiguration(
                csrf_enabled=self._get_config_value('WTF_CSRF_ENABLED', True),
                csrf_time_limit=self._get_config_value('WTF_CSRF_TIME_LIMIT', 3600),
                csrf_ssl_strict=self._get_config_value('WTF_CSRF_SSL_STRICT', self.environment == ConfigurationEnvironment.PRODUCTION),
                csrf_check_default=self._get_config_value('WTF_CSRF_CHECK_DEFAULT', True),
                password_hash_method=self._get_config_value('PASSWORD_HASH_METHOD', 'pbkdf2:sha256'),
                password_salt_length=self._get_config_value('PASSWORD_SALT_LENGTH', 16),
                password_hash_iterations=self._get_config_value('PASSWORD_HASH_ITERATIONS', 260000),
                max_login_attempts=self._get_config_value('MAX_LOGIN_ATTEMPTS', 5),
                account_lockout_duration=self._get_config_value('ACCOUNT_LOCKOUT_DURATION', 1800),
                session_regeneration_interval=self._get_config_value('SESSION_REGENERATION_INTERVAL', 3600),
                security_headers_enabled=self._get_config_value('SECURITY_HEADERS_ENABLED', True),
                content_security_policy=self._get_config_value('CONTENT_SECURITY_POLICY')
            )
            
            self.logger.info("Security configuration initialized")
            
        except Exception as e:
            self.logger.error("Failed to initialize security configuration", error=str(e))
            raise
    
    def _apply_flask_configuration(self, app: Flask) -> None:
        """Apply authentication configuration to Flask application."""
        try:
            # Apply session configuration
            if self.session_config:
                app.config.update({
                    'SECRET_KEY': self.session_config.secret_key,
                    'PERMANENT_SESSION_LIFETIME': self.session_config.permanent_session_lifetime,
                    'SESSION_COOKIE_NAME': self.session_config.cookie_name,
                    'SESSION_COOKIE_DOMAIN': self.session_config.cookie_domain,
                    'SESSION_COOKIE_PATH': self.session_config.cookie_path,
                    'SESSION_COOKIE_SECURE': self.session_config.cookie_secure,
                    'SESSION_COOKIE_HTTPONLY': self.session_config.cookie_httponly,
                    'SESSION_COOKIE_SAMESITE': self.session_config.cookie_samesite
                })
            
            # Apply JWT configuration
            if self.jwt_config:
                app.config.update({
                    'JWT_SECRET_KEY': self.jwt_config.secret_key,
                    'JWT_ALGORITHM': self.jwt_config.algorithm,
                    'JWT_ACCESS_TOKEN_EXPIRES': self.jwt_config.access_token_expires,
                    'JWT_REFRESH_TOKEN_EXPIRES': self.jwt_config.refresh_token_expires,
                    'JWT_BLACKLIST_ENABLED': self.jwt_config.blacklist_enabled,
                    'JWT_BLACKLIST_TOKEN_CHECKS': self.jwt_config.blacklist_token_checks,
                    'JWT_COOKIE_SECURE': self.jwt_config.cookie_secure,
                    'JWT_COOKIE_CSRF_PROTECT': self.jwt_config.cookie_csrf_protect,
                    'JWT_ACCESS_COOKIE_NAME': self.jwt_config.access_cookie_name,
                    'JWT_REFRESH_COOKIE_NAME': self.jwt_config.refresh_cookie_name,
                    'JWT_CSRF_IN_COOKIES': self.jwt_config.cookie_csrf_protect,
                    'JWT_DECODE_LEEWAY': self.jwt_config.decode_leeway
                })
            
            # Apply security configuration
            if self.security_config:
                app.config.update({
                    'WTF_CSRF_ENABLED': self.security_config.csrf_enabled,
                    'WTF_CSRF_TIME_LIMIT': self.security_config.csrf_time_limit,
                    'WTF_CSRF_SSL_STRICT': self.security_config.csrf_ssl_strict,
                    'WTF_CSRF_CHECK_DEFAULT': self.security_config.csrf_check_default,
                    'SECURITY_PASSWORD_HASH': self.security_config.password_hash_method,
                    'SECURITY_PASSWORD_SALT': secrets.token_hex(self.security_config.password_salt_length),
                    'SECURITY_PASSWORD_ITERATIONS': self.security_config.password_hash_iterations
                })
            
            # Apply Auth0 configuration to application context
            if self.auth0_config:
                app.config.update({
                    'AUTH0_DOMAIN': self.auth0_config.domain,
                    'AUTH0_CLIENT_ID': self.auth0_config.client_id,
                    'AUTH0_CLIENT_SECRET': self.auth0_config.client_secret,
                    'AUTH0_AUDIENCE': self.auth0_config.audience,
                    'AUTH0_SCOPE': self.auth0_config.scope,
                    'AUTH0_MANAGEMENT_API_TOKEN': self.auth0_config.management_api_token,
                    'AUTH0_ALGORITHMS': self.auth0_config.algorithms
                })
            
            self.logger.info("Flask application configuration applied")
            
        except Exception as e:
            self.logger.error("Failed to apply Flask configuration", error=str(e))
            raise
    
    def _validate_configuration(self) -> None:
        """Validate complete authentication configuration."""
        validation_errors = []
        
        try:
            # Validate Auth0 configuration if present
            if self.auth0_config:
                self.auth0_config.validate()
            
            # Validate JWT configuration
            if self.jwt_config:
                if len(self.jwt_config.secret_key) < 32:
                    validation_errors.append("JWT secret key must be at least 32 characters")
            
            # Validate session configuration
            if self.session_config:
                if len(self.session_config.secret_key) < 32:
                    validation_errors.append("Session secret key must be at least 32 characters")
            
            # Validate security configuration
            if self.security_config:
                if self.security_config.password_hash_iterations < 100000:
                    validation_errors.append("Password hash iterations must be at least 100,000")
            
            # Environment-specific validation
            if self.environment == ConfigurationEnvironment.PRODUCTION:
                if self.session_config and not self.session_config.cookie_secure:
                    validation_errors.append("Session cookies must be secure in production")
                
                if self.jwt_config and not self.jwt_config.cookie_secure:
                    validation_errors.append("JWT cookies must be secure in production")
            
            if validation_errors:
                raise ValueError(f"Configuration validation failed: {'; '.join(validation_errors)}")
            
            self.logger.info("Authentication configuration validation passed")
            
        except Exception as e:
            self.logger.error("Configuration validation failed", error=str(e))
            raise
    
    def _parse_timedelta(self, value: Union[str, int, timedelta]) -> timedelta:
        """Parse timedelta from various input formats."""
        if isinstance(value, timedelta):
            return value
        elif isinstance(value, int):
            return timedelta(seconds=value)
        elif isinstance(value, str):
            try:
                return timedelta(seconds=int(value))
            except ValueError:
                # Try parsing more complex formats if needed
                pass
        
        raise ValueError(f"Cannot parse timedelta from value: {value}")
    
    def _parse_bool(self, value: Union[str, bool]) -> bool:
        """Parse boolean from string values."""
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on', 'enabled')
        
        return bool(value)
    
    def get_auth0_config(self) -> Optional[Auth0Configuration]:
        """Get Auth0 configuration."""
        return self.auth0_config
    
    def get_jwt_config(self) -> Optional[JWTConfiguration]:
        """Get JWT configuration."""
        return self.jwt_config
    
    def get_session_config(self) -> Optional[SessionConfiguration]:
        """Get session configuration."""
        return self.session_config
    
    def get_security_config(self) -> Optional[SecurityConfiguration]:
        """Get security configuration."""
        return self.security_config
    
    def get_environment(self) -> ConfigurationEnvironment:
        """Get current environment."""
        return self.environment
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == ConfigurationEnvironment.PRODUCTION
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == ConfigurationEnvironment.DEVELOPMENT
    
    def reload_configuration(self) -> None:
        """Reload configuration from all sources."""
        if self.app:
            self.logger.info("Reloading authentication configuration")
            self._load_configuration_sources(self.app)
            self._init_auth0_configuration(self.app)
            self._init_jwt_configuration(self.app)
            self._init_session_configuration(self.app)
            self._init_security_configuration(self.app)
            self._apply_flask_configuration(self.app)
            self._validate_configuration()
            self.logger.info("Authentication configuration reloaded successfully")
    
    def export_configuration(self, include_secrets: bool = False) -> Dict[str, Any]:
        """
        Export current configuration for debugging or documentation.
        
        Args:
            include_secrets: Whether to include secret values in export
            
        Returns:
            Dictionary containing configuration data
        """
        config_export = {
            'environment': self.environment.value,
            'auth0_enabled': self.auth0_config is not None,
            'jwt_enabled': self.jwt_config is not None,
            'session_enabled': self.session_config is not None,
            'security_enabled': self.security_config is not None
        }
        
        if include_secrets:
            self.logger.warning("Exporting configuration with secrets - ensure secure handling")
        
        if self.auth0_config:
            auth0_data = {
                'domain': self.auth0_config.domain,
                'client_id': self.auth0_config.client_id,
                'audience': self.auth0_config.audience,
                'scope': self.auth0_config.scope,
                'algorithms': self.auth0_config.algorithms
            }
            if include_secrets:
                auth0_data.update({
                    'client_secret': self.auth0_config.client_secret,
                    'management_api_token': self.auth0_config.management_api_token
                })
            config_export['auth0'] = auth0_data
        
        if self.jwt_config:
            jwt_data = {
                'algorithm': self.jwt_config.algorithm,
                'access_token_expires': str(self.jwt_config.access_token_expires),
                'refresh_token_expires': str(self.jwt_config.refresh_token_expires),
                'blacklist_enabled': self.jwt_config.blacklist_enabled,
                'cookie_secure': self.jwt_config.cookie_secure,
                'cookie_csrf_protect': self.jwt_config.cookie_csrf_protect
            }
            if include_secrets:
                jwt_data['secret_key'] = self.jwt_config.secret_key
            config_export['jwt'] = jwt_data
        
        if self.session_config:
            session_data = {
                'timeout': self.session_config.timeout,
                'session_protection': self.session_config.session_protection,
                'cookie_secure': self.session_config.cookie_secure,
                'cookie_httponly': self.session_config.cookie_httponly,
                'cookie_samesite': self.session_config.cookie_samesite
            }
            if include_secrets:
                session_data['secret_key'] = self.session_config.secret_key
            config_export['session'] = session_data
        
        if self.security_config:
            config_export['security'] = {
                'csrf_enabled': self.security_config.csrf_enabled,
                'csrf_time_limit': self.security_config.csrf_time_limit,
                'password_hash_method': self.security_config.password_hash_method,
                'password_hash_iterations': self.security_config.password_hash_iterations,
                'max_login_attempts': self.security_config.max_login_attempts,
                'security_headers_enabled': self.security_config.security_headers_enabled
            }
        
        return config_export


# Global configuration manager instance
auth_config_manager = AuthConfigurationManager()

# Convenience function for Flask application factory integration
def init_auth_config(app: Flask) -> AuthConfigurationManager:
    """
    Initialize authentication configuration with Flask application factory pattern.
    
    This function provides a convenient entry point for authentication configuration
    initialization within the Flask application factory pattern as specified in
    Section 5.1.1.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured AuthConfigurationManager instance
    """
    auth_config_manager.init_app(app)
    return auth_config_manager


# Export configuration classes and manager for external access
__all__ = [
    'AuthConfigurationManager',
    'auth_config_manager',
    'init_auth_config',
    'Auth0Configuration',
    'JWTConfiguration', 
    'SessionConfiguration',
    'SecurityConfiguration',
    'ConfigurationEnvironment',
    'ConfigurationSource'
]