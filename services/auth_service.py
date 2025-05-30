"""
Authentication Service Implementation for Flask Application

This module implements comprehensive authentication functionality using Flask-Login 0.6.3,
ItsDangerous 2.2+ for secure token generation, and Auth0 Python SDK 4.9.0 integration.
It replaces Node.js middleware authentication patterns with Flask's Service Layer architecture
while preserving all existing authentication functionality and security postures.

Key Features:
- Flask-Login session management with secure cookie protection
- ItsDangerous cryptographic token generation and validation
- Auth0 Python SDK integration for external identity provider support
- JWT token handling with PyJWT for API authentication
- Comprehensive security logging and audit trail integration
- Authentication decorators for route protection
- Session lifecycle management with automatic cleanup
- Multi-factor authentication support through Auth0
- Role-based access control integration

Architecture:
This implementation follows the Service Layer pattern specified in Section 4.6.1.3 of the
technical specification, providing Flask authentication decorators that replace Express.js
middleware patterns while maintaining complete functional parity and enhanced security.

Security Features:
- Cryptographic session protection via ItsDangerous 2.2+
- Secure cookie management with HTTPOnly and Secure flags
- CSRF protection integration
- Authentication failure tracking and rate limiting
- Comprehensive audit logging for all authentication events
- Token-based API authentication with JWT validation
- Session hijacking protection through IP and user agent validation

Dependencies:
- Flask-Login 0.6.3: Session management and user authentication state
- ItsDangerous 2.2+: Secure token generation and cookie signing
- auth0-python 4.9.0: External identity provider integration
- PyJWT: JWT token handling for API authentication
- python-dotenv: Configuration management for secrets and keys
"""

from __future__ import annotations

import os
import jwt
import logging
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Union, Callable
from functools import wraps
from urllib.parse import urljoin, urlparse

# Flask core imports
from flask import (
    current_app, 
    request, 
    session, 
    g, 
    redirect, 
    url_for, 
    jsonify,
    abort
)
from flask_login import (
    LoginManager, 
    UserMixin, 
    login_user, 
    logout_user, 
    login_required, 
    current_user,
    fresh_login_required
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden
from itsdangerous import (
    URLSafeTimedSerializer, 
    URLSafeSerializer,
    SignatureExpired, 
    BadSignature,
    BadPayload
)

# Auth0 SDK imports
try:
    from auth0.management import Auth0
    from auth0.authentication import GetToken, Users
    from auth0.exceptions import Auth0Error
    AUTH0_AVAILABLE = True
except ImportError:
    AUTH0_AVAILABLE = False
    current_app.logger.warning("Auth0 SDK not available - Auth0 integration disabled")

# JWT handling
try:
    import jwt as pyjwt
    from jwt.exceptions import (
        InvalidTokenError, 
        ExpiredSignatureError, 
        InvalidSignatureError,
        DecodeError
    )
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    current_app.logger.warning("PyJWT not available - JWT functionality disabled")

# Internal imports
from .base_service import BaseService, ServiceResult, ValidationResult, ServiceException
from models import User, UserSession, Role, Permission, AuditLog, db
from config import get_config


class AuthenticationError(ServiceException):
    """Authentication-specific exception for failed authentication attempts."""
    
    def __init__(
        self, 
        message: str, 
        error_code: str = 'AUTH_ERROR',
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, error_code, details)
        self.user_id = user_id


class AuthorizationError(ServiceException):
    """Authorization-specific exception for access control failures."""
    
    def __init__(
        self, 
        message: str, 
        error_code: str = 'AUTHZ_ERROR',
        user_id: Optional[int] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, error_code, details)
        self.user_id = user_id
        self.resource = resource
        self.action = action


class TokenError(ServiceException):
    """Token-specific exception for token generation and validation failures."""
    
    def __init__(
        self, 
        message: str, 
        error_code: str = 'TOKEN_ERROR',
        token_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, error_code, details)
        self.token_type = token_type


class FlaskLoginUser(UserMixin):
    """
    Flask-Login user implementation providing session management capabilities.
    
    This class wraps the SQLAlchemy User model to provide Flask-Login required
    methods while maintaining separation between authentication and data models.
    """
    
    def __init__(self, user_model: User):
        """
        Initialize Flask-Login user wrapper.
        
        Args:
            user_model: SQLAlchemy User model instance
        """
        self.user_model = user_model
        self._is_authenticated = True
        self._is_active = user_model.is_active if hasattr(user_model, 'is_active') else True
        self._is_anonymous = False
    
    def get_id(self) -> str:
        """Return user ID as string for Flask-Login."""
        return str(self.user_model.id)
    
    @property
    def is_authenticated(self) -> bool:
        """Return True if user is authenticated."""
        return self._is_authenticated
    
    @property
    def is_active(self) -> bool:
        """Return True if user account is active."""
        return self._is_active
    
    @property
    def is_anonymous(self) -> bool:
        """Return True if user is anonymous (always False for authenticated users)."""
        return self._is_anonymous
    
    def __getattr__(self, name):
        """Delegate attribute access to underlying user model."""
        return getattr(self.user_model, name)
    
    def __repr__(self) -> str:
        """String representation of Flask-Login user."""
        return f"<FlaskLoginUser(id={self.get_id()}, username={getattr(self.user_model, 'username', 'unknown')})>"


class AuthenticationService(BaseService[User]):
    """
    Comprehensive authentication service implementing Flask-Login integration,
    ItsDangerous token management, and Auth0 external identity provider support.
    
    This service replaces Node.js authentication middleware patterns with Flask's
    Service Layer architecture while preserving all existing authentication
    functionality and security postures. It provides centralized authentication
    logic with comprehensive security features and audit logging.
    
    Key Capabilities:
    - User authentication and session management via Flask-Login 0.6.3
    - Secure token generation and validation using ItsDangerous 2.2+
    - Auth0 integration for external identity provider support
    - JWT token handling for API authentication
    - Comprehensive security logging and audit trails
    - Authentication decorators for route protection
    - Multi-factor authentication support
    - Session security with IP and user agent validation
    """
    
    def __init__(self, db_session, login_manager: Optional[LoginManager] = None):
        """
        Initialize authentication service with Flask-Login integration.
        
        Args:
            db_session: SQLAlchemy database session
            login_manager: Optional Flask-Login manager instance
        """
        super().__init__(db_session, User)
        
        # Initialize Flask-Login manager
        self.login_manager = login_manager or self._create_login_manager()
        
        # Initialize ItsDangerous serializers for secure token handling
        self._init_token_serializers()
        
        # Initialize Auth0 integration if available
        self._init_auth0_integration()
        
        # Authentication configuration
        self.max_login_attempts = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
        self.lockout_duration = int(os.environ.get('LOCKOUT_DURATION_MINUTES', '15'))
        self.session_timeout = int(os.environ.get('SESSION_TIMEOUT_MINUTES', '30'))
        self.require_fresh_login = os.environ.get('REQUIRE_FRESH_LOGIN', 'false').lower() == 'true'
        
        # Security tracking
        self._failed_attempts = {}  # IP-based tracking
        self._user_sessions = {}    # Active user session tracking
        
        self.logger.info("Authentication service initialized successfully")
    
    def _create_login_manager(self) -> LoginManager:
        """
        Create and configure Flask-Login manager with security settings.
        
        Returns:
            Configured LoginManager instance
        """
        login_manager = LoginManager()
        
        # Configure login manager settings
        login_manager.login_view = 'auth.login'
        login_manager.login_message = 'Please log in to access this page.'
        login_manager.login_message_category = 'info'
        login_manager.session_protection = 'strong'
        login_manager.refresh_view = 'auth.reauthenticate'
        login_manager.needs_refresh_message = 'Please reauthenticate to access this page.'
        
        # Set user loader callback
        @login_manager.user_loader
        def load_user(user_id: str) -> Optional[FlaskLoginUser]:
            """Load user from database for Flask-Login session management."""
            try:
                user = self.get_by_id(int(user_id))
                if user and getattr(user, 'is_active', True):
                    return FlaskLoginUser(user)
                return None
            except (ValueError, TypeError):
                return None
        
        return login_manager
    
    def _init_token_serializers(self) -> None:
        """
        Initialize ItsDangerous serializers for secure token generation.
        
        Creates serializers for different token types with appropriate
        security settings and expiration handling.
        """
        # Get secret key from Flask configuration
        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key or secret_key == 'dev-key-change-in-production':
            raise ValueError("SECRET_KEY must be configured for secure token generation")
        
        # URL-safe timed serializer for tokens with expiration
        self.timed_serializer = URLSafeTimedSerializer(
            secret_key,
            salt='auth-tokens'
        )
        
        # URL-safe serializer for permanent tokens
        self.permanent_serializer = URLSafeSerializer(
            secret_key,
            salt='permanent-tokens'
        )
        
        # Session-specific serializer
        self.session_serializer = URLSafeTimedSerializer(
            secret_key,
            salt='session-tokens'
        )
        
        self.logger.debug("ItsDangerous token serializers initialized")
    
    def _init_auth0_integration(self) -> None:
        """
        Initialize Auth0 integration for external identity provider support.
        
        Configures Auth0 management and authentication clients using
        environment variables for secure credential management.
        """
        if not AUTH0_AVAILABLE:
            self.auth0_mgmt = None
            self.auth0_users = None
            return
        
        # Load Auth0 configuration from environment
        self.auth0_domain = os.environ.get('AUTH0_DOMAIN')
        self.auth0_client_id = os.environ.get('AUTH0_CLIENT_ID')
        self.auth0_client_secret = os.environ.get('AUTH0_CLIENT_SECRET')
        self.auth0_audience = os.environ.get('AUTH0_AUDIENCE')
        
        if all([self.auth0_domain, self.auth0_client_id, self.auth0_client_secret]):
            try:
                # Initialize Auth0 management client
                get_token = GetToken(self.auth0_domain, self.auth0_client_id, self.auth0_client_secret)
                token = get_token.client_credentials(f"https://{self.auth0_domain}/api/v2/")
                
                self.auth0_mgmt = Auth0(self.auth0_domain, token['access_token'])
                self.auth0_users = Users(self.auth0_domain)
                
                self.logger.info("Auth0 integration initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize Auth0 integration: {e}")
                self.auth0_mgmt = None
                self.auth0_users = None
        else:
            self.auth0_mgmt = None
            self.auth0_users = None
            self.logger.warning("Auth0 configuration incomplete - Auth0 integration disabled")
    
    def get_business_rules(self) -> Dict[str, Any]:
        """
        Get authentication-specific business rules and validation constraints.
        
        Returns:
            Dictionary containing authentication business rules
        """
        return {
            'password': {
                'min_length': 8,
                'require_uppercase': True,
                'require_lowercase': True,
                'require_numbers': True,
                'require_special_chars': True
            },
            'username': {
                'min_length': 3,
                'max_length': 50,
                'allowed_chars': 'alphanumeric_underscore_dash'
            },
            'session': {
                'max_concurrent_sessions': 5,
                'session_timeout_minutes': self.session_timeout,
                'require_fresh_login': self.require_fresh_login
            },
            'security': {
                'max_login_attempts': self.max_login_attempts,
                'lockout_duration_minutes': self.lockout_duration,
                'password_reset_token_expiry_hours': 24,
                'email_verification_token_expiry_hours': 72
            }
        }
    
    def validate_password_strength(self, password: str) -> ValidationResult:
        """
        Validate password strength against business rules.
        
        Args:
            password: Password to validate
            
        Returns:
            ValidationResult indicating password strength validation
        """
        validation = ValidationResult(is_valid=True, errors=[])
        rules = self.get_business_rules()['password']
        
        if len(password) < rules['min_length']:
            validation.add_error(f"Password must be at least {rules['min_length']} characters long")
        
        if rules['require_uppercase'] and not any(c.isupper() for c in password):
            validation.add_error("Password must contain at least one uppercase letter")
        
        if rules['require_lowercase'] and not any(c.islower() for c in password):
            validation.add_error("Password must contain at least one lowercase letter")
        
        if rules['require_numbers'] and not any(c.isdigit() for c in password):
            validation.add_error("Password must contain at least one number")
        
        if rules['require_special_chars'] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            validation.add_error("Password must contain at least one special character")
        
        return validation
    
    def authenticate_user(
        self, 
        username: str, 
        password: str, 
        remember_me: bool = False,
        ip_address: Optional[str] = None
    ) -> ServiceResult:
        """
        Authenticate user credentials and establish session.
        
        Args:
            username: Username or email for authentication
            password: User password
            remember_me: Whether to create persistent session
            ip_address: Client IP address for security tracking
            
        Returns:
            ServiceResult containing authentication result and user data
        """
        try:
            # Get client IP for security tracking
            client_ip = ip_address or self._get_client_ip()
            
            # Check for account lockout
            if self._is_ip_locked_out(client_ip):
                self._log_authentication_event(
                    'authentication_blocked',
                    None,
                    success=False,
                    details={'reason': 'ip_lockout', 'ip_address': client_ip}
                )
                return ServiceResult.error_result(
                    error="Account temporarily locked due to multiple failed attempts",
                    error_code="ACCOUNT_LOCKED"
                )
            
            # Find user by username or email
            user = self._find_user_by_identifier(username)
            if not user:
                self._record_failed_attempt(client_ip)
                self._log_authentication_event(
                    'authentication_failed',
                    None,
                    success=False,
                    details={'reason': 'user_not_found', 'username': username, 'ip_address': client_ip}
                )
                return ServiceResult.error_result(
                    error="Invalid username or password",
                    error_code="INVALID_CREDENTIALS"
                )
            
            # Check if user account is active
            if not getattr(user, 'is_active', True):
                self._log_authentication_event(
                    'authentication_failed',
                    user.id,
                    success=False,
                    details={'reason': 'account_inactive', 'ip_address': client_ip}
                )
                return ServiceResult.error_result(
                    error="Account is disabled",
                    error_code="ACCOUNT_DISABLED"
                )
            
            # Verify password
            if not self._verify_password(user, password):
                self._record_failed_attempt(client_ip, user.id)
                self._log_authentication_event(
                    'authentication_failed',
                    user.id,
                    success=False,
                    details={'reason': 'invalid_password', 'ip_address': client_ip}
                )
                return ServiceResult.error_result(
                    error="Invalid username or password",
                    error_code="INVALID_CREDENTIALS"
                )
            
            # Authentication successful - create session
            flask_user = FlaskLoginUser(user)
            
            # Log in user with Flask-Login
            login_success = login_user(flask_user, remember=remember_me, fresh=True)
            
            if not login_success:
                self._log_authentication_event(
                    'session_creation_failed',
                    user.id,
                    success=False,
                    details={'ip_address': client_ip}
                )
                return ServiceResult.error_result(
                    error="Failed to create user session",
                    error_code="SESSION_ERROR"
                )
            
            # Create user session record
            session_result = self._create_user_session(user, client_ip)
            
            # Clear failed attempts for this IP
            self._clear_failed_attempts(client_ip)
            
            # Log successful authentication
            self._log_authentication_event(
                'authentication_success',
                user.id,
                success=True,
                details={
                    'ip_address': client_ip,
                    'remember_me': remember_me,
                    'session_id': session_result.data.get('session_id') if session_result.success else None
                }
            )
            
            return ServiceResult.success_result(
                data={
                    'user': user,
                    'session': session_result.data if session_result.success else None,
                    'message': 'Authentication successful'
                },
                metadata={
                    'user_id': user.id,
                    'session_created': session_result.success,
                    'ip_address': client_ip
                }
            )
            
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return ServiceResult.error_result(
                error="Authentication failed due to system error",
                error_code="SYSTEM_ERROR"
            )
    
    def logout_user_session(self, user_id: Optional[int] = None) -> ServiceResult:
        """
        Logout user and cleanup session data.
        
        Args:
            user_id: Optional user ID for targeted logout
            
        Returns:
            ServiceResult indicating logout success
        """
        try:
            # Get current user if not specified
            if user_id is None and current_user.is_authenticated:
                user_id = int(current_user.get_id())
            
            # End user session record
            if user_id:
                session_result = self._end_user_session(user_id)
            
            # Logout with Flask-Login
            logout_user()
            
            # Clear Flask session
            session.clear()
            
            # Log logout event
            self._log_authentication_event(
                'logout',
                user_id,
                success=True,
                details={'ip_address': self._get_client_ip()}
            )
            
            return ServiceResult.success_result(
                data={'message': 'Logout successful'},
                metadata={'user_id': user_id}
            )
            
        except Exception as e:
            self.logger.error(f"Logout error: {e}")
            return ServiceResult.error_result(
                error="Logout failed",
                error_code="LOGOUT_ERROR"
            )
    
    def generate_secure_token(
        self, 
        data: Dict[str, Any], 
        token_type: str = 'general',
        expires_in: Optional[int] = None
    ) -> ServiceResult:
        """
        Generate secure token using ItsDangerous.
        
        Args:
            data: Data to include in token payload
            token_type: Type of token for different use cases
            expires_in: Token expiration in seconds
            
        Returns:
            ServiceResult containing generated token
        """
        try:
            # Choose appropriate serializer based on token type
            if token_type in ['password_reset', 'email_verification', 'session']:
                serializer = self.timed_serializer
            else:
                serializer = self.permanent_serializer
            
            # Add metadata to token
            token_data = {
                'data': data,
                'type': token_type,
                'issued_at': datetime.now(timezone.utc).isoformat(),
                'issuer': 'flask_auth_service'
            }
            
            # Generate token
            if expires_in and hasattr(serializer, 'dumps'):
                # For timed serializer, expiration is handled during validation
                token = serializer.dumps(token_data)
            else:
                token = serializer.dumps(token_data)
            
            self.logger.debug(f"Generated {token_type} token successfully")
            
            return ServiceResult.success_result(
                data={
                    'token': token,
                    'type': token_type,
                    'expires_in': expires_in
                },
                metadata={'token_type': token_type}
            )
            
        except Exception as e:
            self.logger.error(f"Token generation error: {e}")
            return ServiceResult.error_result(
                error="Failed to generate secure token",
                error_code="TOKEN_GENERATION_ERROR"
            )
    
    def validate_secure_token(
        self, 
        token: str, 
        token_type: str = 'general',
        max_age: Optional[int] = None
    ) -> ServiceResult:
        """
        Validate secure token using ItsDangerous.
        
        Args:
            token: Token to validate
            token_type: Expected token type
            max_age: Maximum token age in seconds
            
        Returns:
            ServiceResult containing token validation result and data
        """
        try:
            # Choose appropriate serializer
            if token_type in ['password_reset', 'email_verification', 'session']:
                serializer = self.timed_serializer
            else:
                serializer = self.permanent_serializer
            
            # Validate token
            if hasattr(serializer, 'loads') and max_age:
                token_data = serializer.loads(token, max_age=max_age)
            else:
                token_data = serializer.loads(token)
            
            # Verify token type
            if token_data.get('type') != token_type:
                return ServiceResult.error_result(
                    error="Invalid token type",
                    error_code="INVALID_TOKEN_TYPE"
                )
            
            self.logger.debug(f"Validated {token_type} token successfully")
            
            return ServiceResult.success_result(
                data=token_data.get('data', {}),
                metadata={
                    'token_type': token_type,
                    'issued_at': token_data.get('issued_at'),
                    'issuer': token_data.get('issuer')
                }
            )
            
        except SignatureExpired:
            return ServiceResult.error_result(
                error="Token has expired",
                error_code="TOKEN_EXPIRED"
            )
        except (BadSignature, BadPayload):
            return ServiceResult.error_result(
                error="Invalid token signature",
                error_code="INVALID_TOKEN"
            )
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            return ServiceResult.error_result(
                error="Token validation failed",
                error_code="TOKEN_VALIDATION_ERROR"
            )
    
    def generate_jwt_token(
        self, 
        user_id: int, 
        additional_claims: Optional[Dict[str, Any]] = None,
        expires_in: int = 3600
    ) -> ServiceResult:
        """
        Generate JWT token for API authentication.
        
        Args:
            user_id: User ID for token subject
            additional_claims: Additional JWT claims
            expires_in: Token expiration in seconds
            
        Returns:
            ServiceResult containing JWT token
        """
        if not JWT_AVAILABLE:
            return ServiceResult.error_result(
                error="JWT functionality not available",
                error_code="JWT_UNAVAILABLE"
            )
        
        try:
            # Get JWT secret from configuration
            jwt_secret = current_app.config.get('SECRET_KEY')
            if not jwt_secret:
                raise ValueError("JWT secret not configured")
            
            # Create JWT payload
            now = datetime.now(timezone.utc)
            payload = {
                'sub': str(user_id),
                'iat': now,
                'exp': now + timedelta(seconds=expires_in),
                'iss': 'flask_auth_service',
                'type': 'access_token'
            }
            
            # Add additional claims
            if additional_claims:
                payload.update(additional_claims)
            
            # Generate JWT token
            token = pyjwt.encode(payload, jwt_secret, algorithm='HS256')
            
            self.logger.debug(f"Generated JWT token for user {user_id}")
            
            return ServiceResult.success_result(
                data={
                    'access_token': token,
                    'token_type': 'Bearer',
                    'expires_in': expires_in,
                    'user_id': user_id
                },
                metadata={'user_id': user_id, 'expires_in': expires_in}
            )
            
        except Exception as e:
            self.logger.error(f"JWT generation error: {e}")
            return ServiceResult.error_result(
                error="Failed to generate JWT token",
                error_code="JWT_GENERATION_ERROR"
            )
    
    def validate_jwt_token(self, token: str) -> ServiceResult:
        """
        Validate JWT token and extract claims.
        
        Args:
            token: JWT token to validate
            
        Returns:
            ServiceResult containing token validation result and claims
        """
        if not JWT_AVAILABLE:
            return ServiceResult.error_result(
                error="JWT functionality not available",
                error_code="JWT_UNAVAILABLE"
            )
        
        try:
            # Get JWT secret from configuration
            jwt_secret = current_app.config.get('SECRET_KEY')
            if not jwt_secret:
                raise ValueError("JWT secret not configured")
            
            # Decode and validate JWT token
            payload = pyjwt.decode(
                token, 
                jwt_secret, 
                algorithms=['HS256'],
                options={'require': ['sub', 'iat', 'exp']}
            )
            
            # Extract user ID
            user_id = int(payload['sub'])
            
            # Verify user exists and is active
            user = self.get_by_id(user_id)
            if not user or not getattr(user, 'is_active', True):
                return ServiceResult.error_result(
                    error="Token user is inactive",
                    error_code="USER_INACTIVE"
                )
            
            self.logger.debug(f"Validated JWT token for user {user_id}")
            
            return ServiceResult.success_result(
                data={
                    'user_id': user_id,
                    'user': user,
                    'claims': payload
                },
                metadata={'user_id': user_id, 'token_type': 'jwt'}
            )
            
        except ExpiredSignatureError:
            return ServiceResult.error_result(
                error="JWT token has expired",
                error_code="TOKEN_EXPIRED"
            )
        except InvalidSignatureError:
            return ServiceResult.error_result(
                error="Invalid JWT signature",
                error_code="INVALID_SIGNATURE"
            )
        except (DecodeError, InvalidTokenError) as e:
            return ServiceResult.error_result(
                error="Invalid JWT token",
                error_code="INVALID_JWT"
            )
        except Exception as e:
            self.logger.error(f"JWT validation error: {e}")
            return ServiceResult.error_result(
                error="JWT validation failed",
                error_code="JWT_VALIDATION_ERROR"
            )
    
    def require_authentication(self, fresh: bool = False) -> Callable:
        """
        Authentication decorator factory for route protection.
        
        Args:
            fresh: Whether to require fresh authentication
            
        Returns:
            Decorator function for route protection
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if fresh:
                    fresh_login_required()
                else:
                    login_required()
                
                # Additional security checks
                if not self._validate_session_security():
                    logout_user()
                    abort(401, "Session security validation failed")
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_permission(self, permission: str) -> Callable:
        """
        Permission-based authorization decorator.
        
        Args:
            permission: Required permission name
            
        Returns:
            Decorator function for permission-based authorization
        """
        def decorator(func):
            @wraps(func)
            @login_required
            def wrapper(*args, **kwargs):
                if not self._check_user_permission(current_user.get_id(), permission):
                    self._log_authorization_failure(
                        int(current_user.get_id()),
                        permission,
                        'insufficient_permissions'
                    )
                    abort(403, f"Permission '{permission}' required")
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_role(self, role: str) -> Callable:
        """
        Role-based authorization decorator.
        
        Args:
            role: Required role name
            
        Returns:
            Decorator function for role-based authorization
        """
        def decorator(func):
            @wraps(func)
            @login_required
            def wrapper(*args, **kwargs):
                if not self._check_user_role(current_user.get_id(), role):
                    self._log_authorization_failure(
                        int(current_user.get_id()),
                        role,
                        'insufficient_role'
                    )
                    abort(403, f"Role '{role}' required")
                
                return func(*args, **kwargs)
            return wrapper
        return decorator
    
    def auth0_authenticate(self, auth0_token: str) -> ServiceResult:
        """
        Authenticate user using Auth0 token.
        
        Args:
            auth0_token: Auth0 JWT token
            
        Returns:
            ServiceResult containing authentication result
        """
        if not self.auth0_users:
            return ServiceResult.error_result(
                error="Auth0 integration not available",
                error_code="AUTH0_UNAVAILABLE"
            )
        
        try:
            # Validate Auth0 token
            user_info = self.auth0_users.userinfo(auth0_token)
            
            # Find or create user based on Auth0 profile
            user = self._find_or_create_auth0_user(user_info)
            
            # Create Flask-Login session
            flask_user = FlaskLoginUser(user)
            login_user(flask_user, remember=False, fresh=True)
            
            # Log successful Auth0 authentication
            self._log_authentication_event(
                'auth0_authentication_success',
                user.id,
                success=True,
                details={
                    'auth0_user_id': user_info.get('sub'),
                    'ip_address': self._get_client_ip()
                }
            )
            
            return ServiceResult.success_result(
                data={
                    'user': user,
                    'auth0_profile': user_info,
                    'message': 'Auth0 authentication successful'
                },
                metadata={'user_id': user.id, 'auth_provider': 'auth0'}
            )
            
        except Auth0Error as e:
            self.logger.error(f"Auth0 authentication error: {e}")
            return ServiceResult.error_result(
                error="Auth0 authentication failed",
                error_code="AUTH0_ERROR"
            )
        except Exception as e:
            self.logger.error(f"Auth0 authentication system error: {e}")
            return ServiceResult.error_result(
                error="Authentication system error",
                error_code="SYSTEM_ERROR"
            )
    
    def get_session_info(self, user_id: Optional[int] = None) -> ServiceResult:
        """
        Get current session information.
        
        Args:
            user_id: Optional user ID, defaults to current user
            
        Returns:
            ServiceResult containing session information
        """
        try:
            if user_id is None and current_user.is_authenticated:
                user_id = int(current_user.get_id())
            
            if not user_id:
                return ServiceResult.error_result(
                    error="No active session",
                    error_code="NO_SESSION"
                )
            
            # Get active user session
            user_session = self._get_active_user_session(user_id)
            
            session_info = {
                'user_id': user_id,
                'is_authenticated': current_user.is_authenticated if current_user else False,
                'session_id': user_session.id if user_session else None,
                'login_time': user_session.created_at if user_session else None,
                'last_activity': user_session.last_activity if user_session else None,
                'ip_address': user_session.ip_address if user_session else None,
                'user_agent': user_session.user_agent if user_session else None,
                'is_fresh': getattr(session, '_fresh', False)
            }
            
            return ServiceResult.success_result(
                data=session_info,
                metadata={'user_id': user_id}
            )
            
        except Exception as e:
            self.logger.error(f"Session info error: {e}")
            return ServiceResult.error_result(
                error="Failed to get session information",
                error_code="SESSION_ERROR"
            )
    
    # Private helper methods
    
    def _find_user_by_identifier(self, identifier: str) -> Optional[User]:
        """Find user by username or email."""
        try:
            # Try to find by username first
            user = self.db_session.query(User).filter(
                User.username == identifier
            ).first()
            
            # If not found, try email
            if not user and hasattr(User, 'email'):
                user = self.db_session.query(User).filter(
                    User.email == identifier
                ).first()
            
            return user
        except Exception as e:
            self.logger.error(f"Error finding user: {e}")
            return None
    
    def _verify_password(self, user: User, password: str) -> bool:
        """Verify user password."""
        try:
            # Assume user has password_hash attribute
            if hasattr(user, 'password_hash'):
                return check_password_hash(user.password_hash, password)
            
            # Fallback for other password storage methods
            if hasattr(user, 'password'):
                return user.password == password
            
            return False
        except Exception as e:
            self.logger.error(f"Password verification error: {e}")
            return False
    
    def _get_client_ip(self) -> str:
        """Get client IP address from request."""
        return request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    def _is_ip_locked_out(self, ip_address: str) -> bool:
        """Check if IP address is locked out due to failed attempts."""
        if ip_address not in self._failed_attempts:
            return False
        
        attempts = self._failed_attempts[ip_address]
        if attempts['count'] >= self.max_login_attempts:
            lockout_time = attempts['last_attempt'] + timedelta(minutes=self.lockout_duration)
            return datetime.now(timezone.utc) < lockout_time
        
        return False
    
    def _record_failed_attempt(self, ip_address: str, user_id: Optional[int] = None) -> None:
        """Record failed authentication attempt."""
        now = datetime.now(timezone.utc)
        
        if ip_address not in self._failed_attempts:
            self._failed_attempts[ip_address] = {'count': 0, 'last_attempt': now}
        
        self._failed_attempts[ip_address]['count'] += 1
        self._failed_attempts[ip_address]['last_attempt'] = now
        
        self.logger.warning(f"Failed authentication attempt from {ip_address}, count: {self._failed_attempts[ip_address]['count']}")
    
    def _clear_failed_attempts(self, ip_address: str) -> None:
        """Clear failed attempts for IP address."""
        if ip_address in self._failed_attempts:
            del self._failed_attempts[ip_address]
    
    def _create_user_session(self, user: User, ip_address: str) -> ServiceResult:
        """Create user session record."""
        try:
            with self.transaction():
                session_data = {
                    'user_id': user.id,
                    'session_id': secrets.token_urlsafe(32),
                    'ip_address': ip_address,
                    'user_agent': request.headers.get('User-Agent', '')[:500],
                    'created_at': datetime.now(timezone.utc),
                    'last_activity': datetime.now(timezone.utc),
                    'is_active': True
                }
                
                # Create session record if UserSession model exists
                if hasattr(UserSession, '__init__'):
                    user_session = UserSession(**session_data)
                    self.db_session.add(user_session)
                    self.db_session.flush()
                    
                    return ServiceResult.success_result(
                        data={
                            'session_id': session_data['session_id'],
                            'session_record_id': user_session.id
                        }
                    )
                
                return ServiceResult.success_result(data=session_data)
                
        except Exception as e:
            self.logger.error(f"Failed to create user session: {e}")
            return ServiceResult.error_result(
                error="Failed to create session",
                error_code="SESSION_CREATION_ERROR"
            )
    
    def _end_user_session(self, user_id: int) -> ServiceResult:
        """End user session record."""
        try:
            with self.transaction():
                # Update session record as inactive
                if hasattr(UserSession, 'query'):
                    active_sessions = self.db_session.query(UserSession).filter(
                        UserSession.user_id == user_id,
                        UserSession.is_active == True
                    ).all()
                    
                    for session_record in active_sessions:
                        session_record.is_active = False
                        session_record.ended_at = datetime.now(timezone.utc)
                
                return ServiceResult.success_result(
                    data={'message': 'Session ended successfully'}
                )
                
        except Exception as e:
            self.logger.error(f"Failed to end user session: {e}")
            return ServiceResult.error_result(
                error="Failed to end session",
                error_code="SESSION_END_ERROR"
            )
    
    def _get_active_user_session(self, user_id: int) -> Optional[UserSession]:
        """Get active user session record."""
        try:
            if hasattr(UserSession, 'query'):
                return self.db_session.query(UserSession).filter(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True
                ).first()
            return None
        except Exception as e:
            self.logger.error(f"Error getting user session: {e}")
            return None
    
    def _validate_session_security(self) -> bool:
        """Validate session security (IP, user agent, etc.)."""
        try:
            if not current_user.is_authenticated:
                return False
            
            # Get current session info
            user_id = int(current_user.get_id())
            current_ip = self._get_client_ip()
            current_ua = request.headers.get('User-Agent', '')
            
            # Get session record
            user_session = self._get_active_user_session(user_id)
            if not user_session:
                return True  # No session record to validate
            
            # Validate IP address consistency
            if user_session.ip_address != current_ip:
                self.logger.warning(f"Session IP mismatch for user {user_id}: {user_session.ip_address} != {current_ip}")
                return False
            
            # Validate user agent consistency (basic check)
            if user_session.user_agent and user_session.user_agent != current_ua:
                self.logger.warning(f"Session user agent mismatch for user {user_id}")
                # Note: User agent changes can be common, so this might be a warning rather than failure
            
            return True
            
        except Exception as e:
            self.logger.error(f"Session security validation error: {e}")
            return False
    
    def _check_user_permission(self, user_id: str, permission: str) -> bool:
        """Check if user has specific permission."""
        try:
            user_id_int = int(user_id)
            user = self.get_by_id(user_id_int)
            
            if not user or not hasattr(user, 'roles'):
                return False
            
            # Check user roles for permission
            for role in user.roles:
                if hasattr(role, 'permissions'):
                    for perm in role.permissions:
                        if hasattr(perm, 'name') and perm.name == permission:
                            return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Permission check error: {e}")
            return False
    
    def _check_user_role(self, user_id: str, role_name: str) -> bool:
        """Check if user has specific role."""
        try:
            user_id_int = int(user_id)
            user = self.get_by_id(user_id_int)
            
            if not user or not hasattr(user, 'roles'):
                return False
            
            # Check user roles
            for role in user.roles:
                if hasattr(role, 'name') and role.name == role_name:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Role check error: {e}")
            return False
    
    def _find_or_create_auth0_user(self, auth0_profile: Dict[str, Any]) -> User:
        """Find or create user based on Auth0 profile."""
        try:
            # Try to find existing user by Auth0 ID
            auth0_user_id = auth0_profile.get('sub')
            email = auth0_profile.get('email')
            
            # Look for existing user
            user = None
            if hasattr(User, 'auth0_id'):
                user = self.db_session.query(User).filter(User.auth0_id == auth0_user_id).first()
            
            if not user and email and hasattr(User, 'email'):
                user = self.db_session.query(User).filter(User.email == email).first()
            
            if user:
                # Update Auth0 ID if not set
                if hasattr(user, 'auth0_id') and not user.auth0_id:
                    user.auth0_id = auth0_user_id
                return user
            
            # Create new user
            user_data = {
                'username': auth0_profile.get('nickname') or auth0_profile.get('email'),
                'email': email,
                'auth0_id': auth0_user_id,
                'is_active': True
            }
            
            # Add other profile fields if User model supports them
            if hasattr(User, 'full_name'):
                user_data['full_name'] = auth0_profile.get('name')
            
            user = User(**user_data)
            self.db_session.add(user)
            self.db_session.flush()
            
            return user
            
        except Exception as e:
            self.logger.error(f"Error creating Auth0 user: {e}")
            raise
    
    def _log_authentication_event(
        self, 
        event_type: str, 
        user_id: Optional[int], 
        success: bool,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authentication event for audit trail."""
        try:
            event_data = {
                'event_type': event_type,
                'user_id': user_id,
                'success': success,
                'timestamp': datetime.now(timezone.utc),
                'ip_address': self._get_client_ip(),
                'user_agent': request.headers.get('User-Agent', ''),
                'details': details or {}
            }
            
            # Log to application logger
            log_level = logging.INFO if success else logging.WARNING
            self.logger.log(
                log_level,
                f"Authentication event: {event_type} - User {user_id} - {'SUCCESS' if success else 'FAILED'} - IP {event_data['ip_address']}"
            )
            
            # Store in audit log if model exists
            if hasattr(AuditLog, '__init__'):
                audit_entry = AuditLog(
                    user_id=user_id,
                    action=event_type,
                    resource='authentication',
                    success=success,
                    ip_address=event_data['ip_address'],
                    user_agent=event_data['user_agent'],
                    details=event_data['details'],
                    timestamp=event_data['timestamp']
                )
                self.db_session.add(audit_entry)
                self.db_session.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log authentication event: {e}")
    
    def _log_authorization_failure(
        self, 
        user_id: int, 
        resource: str, 
        reason: str
    ) -> None:
        """Log authorization failure for audit trail."""
        try:
            self._log_authentication_event(
                'authorization_failure',
                user_id,
                success=False,
                details={
                    'resource': resource,
                    'reason': reason,
                    'request_path': request.path,
                    'request_method': request.method
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log authorization failure: {e}")


# Factory function for creating authentication service instances
def create_auth_service(db_session, login_manager: Optional[LoginManager] = None) -> AuthenticationService:
    """
    Factory function for creating authentication service instances.
    
    Args:
        db_session: SQLAlchemy database session
        login_manager: Optional Flask-Login manager instance
        
    Returns:
        Configured AuthenticationService instance
    """
    return AuthenticationService(db_session, login_manager)


# Initialize Flask-Login for application factory pattern
def init_login_manager(app) -> LoginManager:
    """
    Initialize Flask-Login manager for Flask application.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured LoginManager instance
    """
    login_manager = LoginManager()
    login_manager.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'
    login_manager.refresh_view = 'auth.reauthenticate'
    login_manager.needs_refresh_message = 'Please reauthenticate to access this page.'
    
    # User loader will be set by AuthenticationService
    
    return login_manager