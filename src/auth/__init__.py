"""
Flask Authentication Module

This module provides comprehensive authentication and authorization services for the Flask application,
implementing the migration from Node.js middleware patterns to Flask decorator-based authentication
architecture. The module establishes the auth package namespace and provides centralized imports for
all Flask authentication components including session management, identity provider integration, and
security controls.

Key Components:
- Flask-Login session management with ItsDangerous secure cookie signing
- Auth0 Python SDK integration for external identity management
- JWT token handling with Flask-JWT-Extended for API authentication
- CSRF protection using Flask-WTF for form security
- Password security utilities with Werkzeug for secure hashing
- Security monitoring and incident response capabilities
- Authentication decorators replacing Node.js middleware patterns

Integration:
This module integrates with the Flask application factory pattern (Section 5.1.1) to provide
systematic authentication component registration and configuration management during application
initialization. All authentication services are designed to maintain functional parity with the
original Node.js implementation while leveraging Python 3.13.3 and Flask 3.1.1 capabilities.

Security Architecture:
Implements comprehensive security controls per Section 6.4 including multi-layered authentication,
authorization with role-based access control, secure session management, and real-time security
monitoring with automated incident response capabilities.

Author: Flask Migration Team
Version: 1.0.0 (Python 3.13.3, Flask 3.1.1)
"""

# Core Flask authentication and security imports
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, validate_csrf
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# Authentication service modules
from .session_manager import SessionManager, session_manager
from .auth0_integration import Auth0Integration, auth0_service
from .token_handler import TokenHandler, jwt_token_manager
from .decorators import require_auth, require_permission, require_role, csrf_exempt
from .password_utils import PasswordUtils, password_service
from .csrf_protection import CSRFProtectionService, csrf_service
from .security_monitor import SecurityMonitor, security_monitor

# Standard library imports for authentication
import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable
from functools import wraps

# Third-party imports for enhanced authentication
try:
    import structlog
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    
try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# Package version and metadata
__version__ = "1.0.0"
__author__ = "Flask Migration Team"
__description__ = "Flask Authentication Module for Node.js to Python Migration"
__python_version__ = "3.13.3"
__flask_version__ = "3.1.1"

# Authentication configuration constants
DEFAULT_SESSION_TIMEOUT = 3600  # 1 hour in seconds
DEFAULT_REMEMBER_ME_DURATION = 30  # 30 days for remember me functionality
DEFAULT_CSRF_TIME_LIMIT = 3600  # 1 hour for CSRF token validity
DEFAULT_JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
DEFAULT_JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

# Security monitoring configuration
SECURITY_EVENT_TYPES = [
    'authentication_success',
    'authentication_failure', 
    'authorization_denied',
    'session_created',
    'session_expired',
    'csrf_violation',
    'jwt_token_issued',
    'jwt_token_refresh',
    'password_change',
    'security_incident'
]

# Authentication error codes and messages
AUTH_ERROR_CODES = {
    'INVALID_CREDENTIALS': 'AUTH_001',
    'SESSION_EXPIRED': 'AUTH_002',
    'CSRF_TOKEN_MISSING': 'AUTH_003',
    'CSRF_TOKEN_INVALID': 'AUTH_004',
    'JWT_TOKEN_EXPIRED': 'AUTH_005',
    'JWT_TOKEN_INVALID': 'AUTH_006',
    'INSUFFICIENT_PERMISSIONS': 'AUTH_007',
    'USER_NOT_FOUND': 'AUTH_008',
    'ACCOUNT_LOCKED': 'AUTH_009',
    'TWO_FACTOR_REQUIRED': 'AUTH_010'
}

AUTH_ERROR_MESSAGES = {
    'AUTH_001': 'Invalid username or password',
    'AUTH_002': 'Your session has expired. Please log in again.',
    'AUTH_003': 'CSRF token is missing',
    'AUTH_004': 'CSRF token is invalid or expired',
    'AUTH_005': 'JWT token has expired',
    'AUTH_006': 'JWT token is invalid',
    'AUTH_007': 'Insufficient permissions to access this resource',
    'AUTH_008': 'User not found',
    'AUTH_009': 'Account is temporarily locked',
    'AUTH_010': 'Two-factor authentication required'
}


class AuthenticationManager:
    """
    Centralized authentication manager for Flask application factory pattern integration.
    
    This class orchestrates all authentication components and provides a unified interface
    for authentication service registration, configuration, and lifecycle management within
    the Flask application factory pattern as specified in Section 5.1.1.
    """
    
    def __init__(self):
        """Initialize the authentication manager with default configuration."""
        self.login_manager = None
        self.csrf_protect = None
        self.jwt_manager = None
        self.session_manager = None
        self.auth0_service = None
        self.token_handler = None
        self.password_utils = None
        self.security_monitor = None
        self.is_initialized = False
        self.config = {}
        
        # Initialize logger
        if STRUCTLOG_AVAILABLE:
            self.logger = structlog.get_logger("auth_manager")
        else:
            self.logger = logging.getLogger("auth_manager")
    
    def init_app(self, app) -> None:
        """
        Initialize authentication services with Flask application factory pattern.
        
        This method integrates with the Flask application factory pattern to provide
        systematic authentication component registration during application initialization.
        Per Section 5.1.1, this ensures organized blueprint registration and configuration
        management for all authentication services.
        
        Args:
            app: Flask application instance
        """
        if self.is_initialized:
            self.logger.warning("Authentication manager already initialized")
            return
        
        try:
            # Store configuration from Flask app
            self.config = self._extract_auth_config(app)
            
            # Initialize core Flask authentication components
            self._init_login_manager(app)
            self._init_csrf_protection(app)
            self._init_jwt_manager(app)
            
            # Initialize authentication service components
            self._init_session_manager(app)
            self._init_auth0_integration(app)
            self._init_token_handler(app)
            self._init_password_utils(app)
            self._init_security_monitor(app)
            
            # Register authentication error handlers
            self._register_error_handlers(app)
            
            # Setup authentication middleware
            self._setup_middleware(app)
            
            # Mark as initialized
            self.is_initialized = True
            app.auth_manager = self
            
            self.logger.info(
                "Authentication manager initialized successfully",
                python_version=__python_version__,
                flask_version=__flask_version__,
                components=[
                    "Flask-Login", "Flask-WTF CSRF", "Flask-JWT-Extended",
                    "Auth0 Integration", "Session Manager", "Security Monitor"
                ]
            )
            
        except Exception as e:
            self.logger.error("Failed to initialize authentication manager", error=str(e))
            raise
    
    def _extract_auth_config(self, app) -> Dict[str, Any]:
        """Extract authentication configuration from Flask application."""
        return {
            'SECRET_KEY': app.config.get('SECRET_KEY') or secrets.token_hex(32),
            'SESSION_TIMEOUT': app.config.get('SESSION_TIMEOUT', DEFAULT_SESSION_TIMEOUT),
            'REMEMBER_ME_DURATION': app.config.get('REMEMBER_ME_DURATION', DEFAULT_REMEMBER_ME_DURATION),
            'CSRF_TIME_LIMIT': app.config.get('WTF_CSRF_TIME_LIMIT', DEFAULT_CSRF_TIME_LIMIT),
            'JWT_SECRET_KEY': app.config.get('JWT_SECRET_KEY') or app.config.get('SECRET_KEY'),
            'JWT_ACCESS_TOKEN_EXPIRES': app.config.get('JWT_ACCESS_TOKEN_EXPIRES', DEFAULT_JWT_ACCESS_TOKEN_EXPIRES),
            'JWT_REFRESH_TOKEN_EXPIRES': app.config.get('JWT_REFRESH_TOKEN_EXPIRES', DEFAULT_JWT_REFRESH_TOKEN_EXPIRES),
            'AUTH0_DOMAIN': app.config.get('AUTH0_DOMAIN'),
            'AUTH0_CLIENT_ID': app.config.get('AUTH0_CLIENT_ID'),
            'AUTH0_CLIENT_SECRET': app.config.get('AUTH0_CLIENT_SECRET'),
            'AUTH0_MANAGEMENT_TOKEN': app.config.get('AUTH0_MANAGEMENT_TOKEN'),
            'SECURITY_MONITORING_ENABLED': app.config.get('SECURITY_MONITORING_ENABLED', True),
            'PROMETHEUS_ENABLED': app.config.get('PROMETHEUS_ENABLED', PROMETHEUS_AVAILABLE)
        }
    
    def _init_login_manager(self, app) -> None:
        """Initialize Flask-Login session management."""
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        
        # Configure Flask-Login settings
        self.login_manager.login_view = 'auth.login'
        self.login_manager.login_message = 'Please log in to access this page.'
        self.login_manager.login_message_category = 'info'
        self.login_manager.session_protection = 'strong'
        self.login_manager.remember_cookie_duration = timedelta(days=self.config['REMEMBER_ME_DURATION'])
        
        # Set user loader callback
        @self.login_manager.user_loader
        def load_user(user_id):
            """User loader callback for Flask-Login session restoration."""
            try:
                # Import here to avoid circular imports
                from ..models.user import User
                return User.query.get(int(user_id))
            except (ValueError, TypeError) as e:
                self.logger.warning("Invalid user ID in session", user_id=user_id, error=str(e))
                return None
            except Exception as e:
                self.logger.error("Error loading user from session", user_id=user_id, error=str(e))
                return None
        
        self.logger.info("Flask-Login manager initialized with secure session protection")
    
    def _init_csrf_protection(self, app) -> None:
        """Initialize Flask-WTF CSRF protection."""
        self.csrf_protect = CSRFProtect()
        self.csrf_protect.init_app(app)
        
        # Configure CSRF settings
        app.config.setdefault('WTF_CSRF_TIME_LIMIT', self.config['CSRF_TIME_LIMIT'])
        app.config.setdefault('WTF_CSRF_SSL_STRICT', True)
        app.config.setdefault('WTF_CSRF_CHECK_DEFAULT', True)
        
        self.logger.info("CSRF protection initialized with Flask-WTF")
    
    def _init_jwt_manager(self, app) -> None:
        """Initialize Flask-JWT-Extended for API authentication."""
        self.jwt_manager = JWTManager()
        self.jwt_manager.init_app(app)
        
        # Configure JWT settings
        app.config.setdefault('JWT_SECRET_KEY', self.config['JWT_SECRET_KEY'])
        app.config.setdefault('JWT_ACCESS_TOKEN_EXPIRES', self.config['JWT_ACCESS_TOKEN_EXPIRES'])
        app.config.setdefault('JWT_REFRESH_TOKEN_EXPIRES', self.config['JWT_REFRESH_TOKEN_EXPIRES'])
        app.config.setdefault('JWT_ALGORITHM', 'HS256')
        app.config.setdefault('JWT_BLACKLIST_ENABLED', True)
        app.config.setdefault('JWT_BLACKLIST_TOKEN_CHECKS', ['access', 'refresh'])
        
        self.logger.info("JWT manager initialized with Flask-JWT-Extended")
    
    def _init_session_manager(self, app) -> None:
        """Initialize custom session manager service."""
        from .session_manager import SessionManager
        self.session_manager = SessionManager(app)
        self.logger.info("Session manager service initialized")
    
    def _init_auth0_integration(self, app) -> None:
        """Initialize Auth0 identity provider integration."""
        if self.config.get('AUTH0_DOMAIN') and self.config.get('AUTH0_CLIENT_ID'):
            from .auth0_integration import Auth0Integration
            self.auth0_service = Auth0Integration(app)
            self.logger.info("Auth0 integration service initialized")
        else:
            self.logger.warning("Auth0 configuration missing - Auth0 integration disabled")
    
    def _init_token_handler(self, app) -> None:
        """Initialize JWT token handler service."""
        from .token_handler import TokenHandler
        self.token_handler = TokenHandler(app)
        self.logger.info("Token handler service initialized")
    
    def _init_password_utils(self, app) -> None:
        """Initialize password security utilities."""
        from .password_utils import PasswordUtils
        self.password_utils = PasswordUtils(app)
        self.logger.info("Password utilities service initialized")
    
    def _init_security_monitor(self, app) -> None:
        """Initialize security monitoring service."""
        if self.config.get('SECURITY_MONITORING_ENABLED'):
            from .security_monitor import SecurityMonitor
            self.security_monitor = SecurityMonitor(app)
            self.logger.info("Security monitoring service initialized")
        else:
            self.logger.info("Security monitoring disabled")
    
    def _register_error_handlers(self, app) -> None:
        """Register authentication-related error handlers."""
        
        @app.errorhandler(401)
        def handle_unauthorized(error):
            """Handle 401 Unauthorized errors."""
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    event_type='authentication_failure',
                    severity='warning',
                    details={'error_code': 'AUTH_002', 'endpoint': request.endpoint}
                )
            
            return {
                'error': 'Unauthorized',
                'code': 'AUTH_002',
                'message': AUTH_ERROR_MESSAGES['AUTH_002']
            }, 401
        
        @app.errorhandler(403)
        def handle_forbidden(error):
            """Handle 403 Forbidden errors."""
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    event_type='authorization_denied',
                    severity='warning',
                    details={'error_code': 'AUTH_007', 'endpoint': request.endpoint}
                )
            
            return {
                'error': 'Forbidden',
                'code': 'AUTH_007',
                'message': AUTH_ERROR_MESSAGES['AUTH_007']
            }, 403
        
        @app.errorhandler(400)
        def handle_csrf_error(error):
            """Handle CSRF token errors."""
            if 'CSRF' in str(error) or 'csrf' in str(error).lower():
                if self.security_monitor:
                    self.security_monitor.log_security_event(
                        event_type='csrf_violation',
                        severity='high',
                        details={'error_code': 'AUTH_004', 'endpoint': request.endpoint}
                    )
                
                return {
                    'error': 'CSRF Token Error',
                    'code': 'AUTH_004',
                    'message': AUTH_ERROR_MESSAGES['AUTH_004']
                }, 400
            
            return error
        
        self.logger.info("Authentication error handlers registered")
    
    def _setup_middleware(self, app) -> None:
        """Setup authentication middleware for request processing."""
        
        @app.before_request
        def setup_auth_context():
            """Setup authentication context for each request."""
            from flask import g, request
            
            # Initialize request context
            g.auth_manager = self
            g.is_authenticated = current_user.is_authenticated if current_user else False
            g.user_id = getattr(current_user, 'id', None) if current_user and current_user.is_authenticated else None
            
            # Log request with authentication context
            if self.security_monitor:
                self.security_monitor.log_request_context(
                    endpoint=request.endpoint,
                    method=request.method,
                    authenticated=g.is_authenticated,
                    user_id=g.user_id
                )
        
        self.logger.info("Authentication middleware configured")
    
    def get_current_user(self):
        """Get the current authenticated user."""
        return current_user if current_user.is_authenticated else None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Any]:
        """
        Authenticate user with username and password.
        
        Args:
            username: User's username or email
            password: User's password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        try:
            # Import here to avoid circular imports
            from ..models.user import User
            
            user = User.query.filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            if user and self.password_utils.verify_password(password, user.password_hash):
                if self.security_monitor:
                    self.security_monitor.log_security_event(
                        event_type='authentication_success',
                        severity='info',
                        details={'user_id': user.id, 'username': username}
                    )
                return user
            else:
                if self.security_monitor:
                    self.security_monitor.log_security_event(
                        event_type='authentication_failure',
                        severity='warning',
                        details={'username': username, 'reason': 'invalid_credentials'}
                    )
                return None
                
        except Exception as e:
            self.logger.error("Authentication error", error=str(e))
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    event_type='authentication_failure',
                    severity='error',
                    details={'username': username, 'error': str(e)}
                )
            return None
    
    def create_session(self, user, remember_me: bool = False) -> bool:
        """
        Create authenticated session for user.
        
        Args:
            user: User object to create session for
            remember_me: Whether to create persistent session
            
        Returns:
            True if session created successfully
        """
        try:
            login_user(user, remember=remember_me)
            
            if self.security_monitor:
                self.security_monitor.log_security_event(
                    event_type='session_created',
                    severity='info',
                    details={
                        'user_id': user.id,
                        'remember_me': remember_me,
                        'session_duration': 'persistent' if remember_me else 'temporary'
                    }
                )
            
            return True
            
        except Exception as e:
            self.logger.error("Session creation error", error=str(e))
            return False
    
    def destroy_session(self) -> bool:
        """
        Destroy current user session.
        
        Returns:
            True if session destroyed successfully
        """
        try:
            user_id = getattr(current_user, 'id', None) if current_user.is_authenticated else None
            logout_user()
            
            if self.security_monitor and user_id:
                self.security_monitor.log_security_event(
                    event_type='session_destroyed',
                    severity='info',
                    details={'user_id': user_id}
                )
            
            return True
            
        except Exception as e:
            self.logger.error("Session destruction error", error=str(e))
            return False


# Global authentication manager instance
auth_manager = AuthenticationManager()

# Convenience function for Flask application factory integration
def init_auth(app) -> AuthenticationManager:
    """
    Initialize authentication services with Flask application factory pattern.
    
    This function provides a convenient entry point for authentication initialization
    within the Flask application factory pattern as specified in Section 5.1.1.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured AuthenticationManager instance
    """
    auth_manager.init_app(app)
    return auth_manager

# Export all authentication components for centralized access
__all__ = [
    # Core authentication manager
    'AuthenticationManager',
    'auth_manager',
    'init_auth',
    
    # Flask authentication components
    'LoginManager',
    'UserMixin',
    'login_user',
    'logout_user', 
    'login_required',
    'current_user',
    'CSRFProtect',
    'validate_csrf',
    'JWTManager',
    'create_access_token',
    'jwt_required',
    'get_jwt_identity',
    'generate_password_hash',
    'check_password_hash',
    'URLSafeTimedSerializer',
    
    # Authentication service modules
    'SessionManager',
    'session_manager',
    'Auth0Integration', 
    'auth0_service',
    'TokenHandler',
    'jwt_token_manager',
    'PasswordUtils',
    'password_service',
    'CSRFProtectionService',
    'csrf_service',
    'SecurityMonitor',
    'security_monitor',
    
    # Authentication decorators
    'require_auth',
    'require_permission',
    'require_role',
    'csrf_exempt',
    
    # Configuration constants
    'AUTH_ERROR_CODES',
    'AUTH_ERROR_MESSAGES',
    'SECURITY_EVENT_TYPES',
    'DEFAULT_SESSION_TIMEOUT',
    'DEFAULT_REMEMBER_ME_DURATION',
    'DEFAULT_CSRF_TIME_LIMIT',
    
    # Package metadata
    '__version__',
    '__author__',
    '__description__',
    '__python_version__',
    '__flask_version__'
]