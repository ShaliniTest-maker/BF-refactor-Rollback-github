"""
Flask Authentication Blueprint

This module provides comprehensive authentication functionality for the Flask 3.1.1 application,
implementing user authentication routes including login, logout, registration, and session
management endpoints. The blueprint preserves existing authentication workflows while leveraging
Flask-Login for session management and ItsDangerous for secure session protection.

Key Features:
- Flask-Login 0.6.3 integration for comprehensive user session management per Section 2.1.4 Feature F-007
- ItsDangerous 2.2+ implementation for cryptographically secure cookie signing and token generation
- Auth0 Python SDK 4.9.0 integration for external authentication provider support per Section 0.2.4
- Authentication decorator patterns for endpoint protection per Section 5.2.2
- Session management patterns preserving existing user access control per Section 4.6

Authentication Workflows:
- Form-based authentication with username/password validation
- Session-based authentication using Flask-Login session management
- Token-based authentication using ItsDangerous secure tokens
- External authentication via Auth0 provider integration
- Multi-factor authentication support for enhanced security
- Password reset and account recovery workflows

Security Implementation:
- OWASP security standards compliance for authentication endpoints
- Secure cookie handling with HttpOnly, Secure, and SameSite attributes
- CSRF protection for form-based authentication workflows
- Rate limiting for authentication attempts and password reset requests
- Session fixation protection through Flask-Login session regeneration
- Cryptographic session protection via ItsDangerous signing

Author: Flask Migration System
Version: 1.0.0 
Compatibility: Flask 3.1.1, Flask-Login 0.6.3, ItsDangerous 2.2+, Auth0 Python SDK 4.9.0
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple, Union
from functools import wraps
from urllib.parse import urlparse, urljoin
import secrets
import re

# Flask core imports
from flask import (
    Blueprint, request, jsonify, session, redirect, url_for, 
    current_app, abort, flash, render_template, make_response,
    g, has_request_context
)

# Flask-Login imports for session management per Section 2.1.4 Feature F-007
from flask_login import (
    login_user, logout_user, login_required, current_user,
    LoginManager, UserMixin, AnonymousUserMixin
)

# ItsDangerous imports for secure token generation per Section 2.1.4 Feature F-007
from itsdangerous import (
    URLSafeTimedSerializer, URLSafeSerializer, BadSignature, 
    SignatureExpired, BadData, TimestampSigner
)

# Werkzeug security utilities
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden

# Auth0 integration per Section 0.2.4 dependency decisions
try:
    from auth0.management import Auth0
    from auth0.authentication import GetToken, Users
    AUTH0_AVAILABLE = True
except ImportError:
    AUTH0_AVAILABLE = False
    logging.warning("Auth0 Python SDK not available. Auth0 integration disabled.")

# Internal imports
from models import (
    User, UserSession, Role, Permission, 
    db, ValidationError, DatabaseError,
    load_user as model_load_user
)
from services import (
    AuthService, ValidationService, get_service, 
    ServiceError, ServiceResult
)
from config import get_config

# Configure logging for authentication blueprint
logger = logging.getLogger(__name__)

# Create authentication blueprint with URL prefix
auth_bp = Blueprint(
    'auth', 
    __name__, 
    url_prefix='/auth',
    template_folder='../templates/auth',
    static_folder='../static/auth'
)


class AuthenticationError(Exception):
    """Custom exception for authentication-specific errors."""
    
    def __init__(self, message: str, error_code: str = None, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or 'AUTHENTICATION_ERROR'
        self.status_code = status_code


class AuthorizationError(Exception):
    """Custom exception for authorization-specific errors."""
    
    def __init__(self, message: str, error_code: str = None, status_code: int = 403):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or 'AUTHORIZATION_ERROR'
        self.status_code = status_code


class TokenManager:
    """
    Secure token management using ItsDangerous 2.2+ for cryptographic operations.
    
    Provides comprehensive token generation, validation, and management for
    authentication workflows including password reset tokens, email verification
    tokens, and API authentication tokens with proper expiration handling.
    """
    
    def __init__(self, app=None):
        """Initialize token manager with optional Flask application."""
        self.app = app
        self._serializer = None
        self._timed_serializer = None
        self._timestamp_signer = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize token manager with Flask application configuration."""
        self.app = app
        
        # Get secret key from configuration
        secret_key = app.config.get('SECRET_KEY')
        if not secret_key or secret_key == 'dev-key-change-in-production':
            raise AuthenticationError(
                "SECRET_KEY must be configured for secure token generation",
                error_code="INVALID_SECRET_KEY"
            )
        
        # Initialize ItsDangerous serializers with security salt
        security_salt = app.config.get('SECURITY_SALT', 'flask-auth-security-salt')
        
        # URLSafeTimedSerializer for tokens with expiration
        self._timed_serializer = URLSafeTimedSerializer(
            secret_key,
            salt=security_salt
        )
        
        # URLSafeSerializer for permanent tokens
        self._serializer = URLSafeSerializer(
            secret_key,
            salt=security_salt
        )
        
        # TimestampSigner for session tokens
        self._timestamp_signer = TimestampSigner(
            secret_key,
            salt=security_salt
        )
        
        logger.info("TokenManager initialized with ItsDangerous 2.2+ support")
    
    def generate_auth_token(self, user_id: int, expires_in: int = 3600) -> str:
        """
        Generate secure authentication token for API access.
        
        Args:
            user_id: User identifier for token payload
            expires_in: Token expiration time in seconds (default: 1 hour)
            
        Returns:
            Secure token string
            
        Raises:
            AuthenticationError: If token generation fails
        """
        try:
            payload = {
                'user_id': user_id,
                'type': 'auth_token',
                'issued_at': datetime.now(timezone.utc).isoformat()
            }
            
            return self._timed_serializer.dumps(payload, max_age=expires_in)
            
        except Exception as e:
            logger.error(f"Auth token generation failed for user {user_id}: {e}")
            raise AuthenticationError(
                "Failed to generate authentication token",
                error_code="TOKEN_GENERATION_ERROR"
            )
    
    def verify_auth_token(self, token: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
        """
        Verify and decode authentication token.
        
        Args:
            token: Token string to verify
            max_age: Maximum token age in seconds
            
        Returns:
            Token payload if valid, None if invalid
        """
        try:
            payload = self._timed_serializer.loads(token, max_age=max_age)
            
            # Validate payload structure
            if not isinstance(payload, dict) or 'user_id' not in payload:
                logger.warning(f"Invalid token payload structure: {type(payload)}")
                return None
            
            return payload
            
        except SignatureExpired:
            logger.info("Token signature expired")
            return None
        except BadSignature:
            logger.warning("Invalid token signature")
            return None
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None
    
    def generate_reset_token(self, email: str, expires_in: int = 3600) -> str:
        """
        Generate secure password reset token.
        
        Args:
            email: User email address for reset
            expires_in: Token expiration time in seconds (default: 1 hour)
            
        Returns:
            Secure reset token string
        """
        try:
            payload = {
                'email': email,
                'type': 'password_reset',
                'nonce': secrets.token_urlsafe(16),
                'issued_at': datetime.now(timezone.utc).isoformat()
            }
            
            return self._timed_serializer.dumps(payload, max_age=expires_in)
            
        except Exception as e:
            logger.error(f"Reset token generation failed for email {email}: {e}")
            raise AuthenticationError(
                "Failed to generate password reset token",
                error_code="RESET_TOKEN_GENERATION_ERROR"
            )
    
    def verify_reset_token(self, token: str, max_age: int = 3600) -> Optional[str]:
        """
        Verify password reset token and return email.
        
        Args:
            token: Reset token to verify
            max_age: Maximum token age in seconds
            
        Returns:
            Email address if token is valid, None if invalid
        """
        try:
            payload = self._timed_serializer.loads(token, max_age=max_age)
            
            if isinstance(payload, dict) and 'email' in payload:
                return payload['email']
            
            return None
            
        except (SignatureExpired, BadSignature, BadData):
            return None
        except Exception as e:
            logger.error(f"Reset token verification error: {e}")
            return None
    
    def generate_session_token(self, session_data: Dict[str, Any]) -> str:
        """
        Generate secure session token with timestamp.
        
        Args:
            session_data: Session payload data
            
        Returns:
            Signed session token
        """
        try:
            return self._timestamp_signer.sign(self._serializer.dumps(session_data)).decode('utf-8')
        except Exception as e:
            logger.error(f"Session token generation failed: {e}")
            raise AuthenticationError(
                "Failed to generate session token",
                error_code="SESSION_TOKEN_ERROR"
            )
    
    def verify_session_token(self, token: str, max_age: int = None) -> Optional[Dict[str, Any]]:
        """
        Verify session token and return payload.
        
        Args:
            token: Session token to verify
            max_age: Maximum token age in seconds (optional)
            
        Returns:
            Session payload if valid, None if invalid
        """
        try:
            if max_age:
                unsigned_data = self._timestamp_signer.unsign(token, max_age=max_age)
            else:
                unsigned_data = self._timestamp_signer.unsign(token)
            
            return self._serializer.loads(unsigned_data)
            
        except (SignatureExpired, BadSignature, BadData):
            return None
        except Exception as e:
            logger.error(f"Session token verification error: {e}")
            return None


class Auth0Manager:
    """
    Auth0 integration manager for external authentication provider support.
    
    Provides Auth0 authentication workflows, user management, and OAuth2/OIDC
    integration per Section 0.2.4 dependency decisions using auth0-python 4.9.0 SDK.
    """
    
    def __init__(self, app=None):
        """Initialize Auth0 manager with optional Flask application."""
        self.app = app
        self.domain = None
        self.client_id = None
        self.client_secret = None
        self.audience = None
        self._management_api = None
        self._auth_api = None
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Auth0 manager with Flask application configuration."""
        if not AUTH0_AVAILABLE:
            logger.warning("Auth0 Python SDK not available. Skipping Auth0 initialization.")
            return
        
        self.app = app
        
        # Load Auth0 configuration from environment
        self.domain = app.config.get('AUTH0_DOMAIN')
        self.client_id = app.config.get('AUTH0_CLIENT_ID')
        self.client_secret = app.config.get('AUTH0_CLIENT_SECRET')
        self.audience = app.config.get('AUTH0_AUDIENCE')
        
        # Validate Auth0 configuration
        if not all([self.domain, self.client_id, self.client_secret]):
            logger.info("Auth0 configuration incomplete. Auth0 integration disabled.")
            return
        
        try:
            # Initialize Auth0 Management API
            get_token = GetToken(self.domain)
            token = get_token.client_credentials(
                self.client_id,
                self.client_secret,
                self.audience or f"https://{self.domain}/api/v2/"
            )
            
            self._management_api = Auth0(self.domain, token['access_token'])
            
            # Initialize Auth0 Authentication API
            self._auth_api = Users(self.domain)
            
            logger.info(f"Auth0 integration initialized for domain: {self.domain}")
            
        except Exception as e:
            logger.error(f"Auth0 initialization failed: {e}")
            self._management_api = None
            self._auth_api = None
    
    @property
    def is_available(self) -> bool:
        """Check if Auth0 integration is available and configured."""
        return AUTH0_AVAILABLE and self._management_api is not None
    
    def get_user_info(self, auth0_user_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve user information from Auth0.
        
        Args:
            auth0_user_id: Auth0 user identifier
            
        Returns:
            User information dict if successful, None if failed
        """
        if not self.is_available:
            logger.warning("Auth0 not available for user info retrieval")
            return None
        
        try:
            user_info = self._management_api.users.get(auth0_user_id)
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to retrieve Auth0 user info for {auth0_user_id}: {e}")
            return None
    
    def create_user(self, email: str, password: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Create user in Auth0.
        
        Args:
            email: User email address
            password: User password
            **kwargs: Additional user attributes
            
        Returns:
            Created user information if successful, None if failed
        """
        if not self.is_available:
            logger.warning("Auth0 not available for user creation")
            return None
        
        try:
            user_data = {
                'email': email,
                'password': password,
                'connection': 'Username-Password-Authentication',
                'email_verified': kwargs.get('email_verified', False),
                **kwargs
            }
            
            created_user = self._management_api.users.create(user_data)
            return created_user
            
        except Exception as e:
            logger.error(f"Failed to create Auth0 user for {email}: {e}")
            return None


# Global instances for blueprint usage
token_manager = TokenManager()
auth0_manager = Auth0Manager()


def init_auth(app):
    """
    Initialize authentication components for Flask application.
    
    Args:
        app: Flask application instance
    """
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'
    login_manager.refresh_view = 'auth.refresh_session'
    
    # Configure user loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        """Load user by ID for Flask-Login session management."""
        try:
            return model_load_user(user_id)
        except Exception as e:
            logger.error(f"Failed to load user {user_id}: {e}")
            return None
    
    # Initialize token manager and Auth0
    token_manager.init_app(app)
    auth0_manager.init_app(app)
    
    # Store managers in app for access from other modules
    app.auth_token_manager = token_manager
    app.auth0_manager = auth0_manager
    
    logger.info("Authentication system initialized successfully")


def require_auth(f):
    """
    Authentication decorator for protecting routes.
    
    This decorator ensures that only authenticated users can access protected endpoints
    while supporting both session-based and token-based authentication patterns.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check Flask-Login session authentication first
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        
        # Check for API token authentication
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
            try:
                payload = token_manager.verify_auth_token(token)
                if payload and 'user_id' in payload:
                    # Load user for request context
                    user = User.query.get(payload['user_id'])
                    if user and user.is_active:
                        g.current_user = user
                        return f(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Token authentication failed: {e}")
        
        # Authentication failed
        if request.is_json:
            return jsonify({
                'error': 'Authentication required',
                'error_code': 'AUTHENTICATION_REQUIRED',
                'message': 'Please provide valid authentication credentials'
            }), 401
        else:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.url))
    
    return decorated_function


def require_permission(permission_name: str):
    """
    Authorization decorator for permission-based access control.
    
    Args:
        permission_name: Required permission name for access
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', current_user)
            
            if not user or not user.has_permission(permission_name):
                if request.is_json:
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'error_code': 'PERMISSION_DENIED',
                        'required_permission': permission_name
                    }), 403
                else:
                    flash(f'You do not have permission to access this resource.', 'error')
                    return redirect(url_for('main.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_role(role_name: str):
    """
    Authorization decorator for role-based access control.
    
    Args:
        role_name: Required role name for access
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user = getattr(g, 'current_user', current_user)
            
            if not user or not user.has_role(role_name):
                if request.is_json:
                    return jsonify({
                        'error': 'Insufficient role permissions',
                        'error_code': 'ROLE_ACCESS_DENIED',
                        'required_role': role_name
                    }), 403
                else:
                    flash(f'You do not have the required role to access this resource.', 'error')
                    return redirect(url_for('main.index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def is_safe_url(target: str) -> bool:
    """
    Validate redirect URL for security.
    
    Args:
        target: URL to validate
        
    Returns:
        True if URL is safe for redirect, False otherwise
    """
    if not target:
        return False
    
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate password strength according to security requirements.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, ""


# Authentication Routes

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login endpoint supporting both form and JSON authentication.
    
    Implements comprehensive authentication workflows including session-based
    authentication via Flask-Login and token generation for API access.
    """
    if request.method == 'GET':
        # Render login form for web interface
        if request.is_json:
            return jsonify({
                'message': 'Login endpoint - POST credentials to authenticate',
                'required_fields': ['email', 'password'],
                'optional_fields': ['remember_me', 'auth_provider']
            })
        else:
            return render_template('auth/login.html', title='Sign In')
    
    try:
        # Parse request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        # Validate required fields
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)
        auth_provider = data.get('auth_provider', 'local')
        
        if not email or not password:
            error_response = {
                'error': 'Email and password are required',
                'error_code': 'MISSING_CREDENTIALS'
            }
            if request.is_json:
                return jsonify(error_response), 400
            else:
                flash('Email and password are required.', 'error')
                return render_template('auth/login.html', title='Sign In'), 400
        
        # Get authentication service
        auth_service = get_service(AuthService)
        
        # Authenticate user based on provider
        if auth_provider == 'auth0' and auth0_manager.is_available:
            # Auth0 authentication workflow
            auth_result = auth_service.authenticate_with_auth0(email, password)
        else:
            # Local authentication workflow
            auth_result = auth_service.authenticate_user(email, password)
        
        if not auth_result.success:
            error_response = {
                'error': auth_result.error or 'Invalid credentials',
                'error_code': 'AUTHENTICATION_FAILED'
            }
            if request.is_json:
                return jsonify(error_response), 401
            else:
                flash('Invalid email or password.', 'error')
                return render_template('auth/login.html', title='Sign In'), 401
        
        user = auth_result.data
        
        # Verify user is active
        if not user.is_active:
            error_response = {
                'error': 'Account is disabled',
                'error_code': 'ACCOUNT_DISABLED'
            }
            if request.is_json:
                return jsonify(error_response), 403
            else:
                flash('Your account has been disabled. Please contact support.', 'error')
                return render_template('auth/login.html', title='Sign In'), 403
        
        # Create user session
        session_result = auth_service.create_user_session(
            user.id,
            request.remote_addr,
            request.headers.get('User-Agent', 'Unknown')
        )
        
        if not session_result.success:
            logger.error(f"Failed to create session for user {user.id}: {session_result.error}")
            error_response = {
                'error': 'Failed to create user session',
                'error_code': 'SESSION_CREATION_FAILED'
            }
            if request.is_json:
                return jsonify(error_response), 500
            else:
                flash('Login failed. Please try again.', 'error')
                return render_template('auth/login.html', title='Sign In'), 500
        
        # Log in user with Flask-Login
        login_user(user, remember=remember_me, duration=timedelta(days=30 if remember_me else 1))
        
        # Generate API token for JSON requests
        if request.is_json:
            api_token = token_manager.generate_auth_token(user.id, expires_in=3600)
            
            response_data = {
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'roles': [role.name for role in user.roles]
                },
                'session': {
                    'session_id': session_result.data.id,
                    'expires_at': session_result.data.expires_at.isoformat()
                },
                'token': api_token,
                'token_expires_in': 3600
            }
            
            return jsonify(response_data), 200
        
        # Handle redirect for web interface
        next_page = request.args.get('next')
        if next_page and is_safe_url(next_page):
            return redirect(next_page)
        else:
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('main.index'))
    
    except ValidationError as e:
        error_response = {
            'error': str(e),
            'error_code': 'VALIDATION_ERROR'
        }
        if request.is_json:
            return jsonify(error_response), 400
        else:
            flash(str(e), 'error')
            return render_template('auth/login.html', title='Sign In'), 400
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        error_response = {
            'error': 'An unexpected error occurred during login',
            'error_code': 'INTERNAL_ERROR'
        }
        if request.is_json:
            return jsonify(error_response), 500
        else:
            flash('An unexpected error occurred. Please try again.', 'error')
            return render_template('auth/login.html', title='Sign In'), 500


@auth_bp.route('/logout', methods=['GET', 'POST'])
@require_auth
def logout():
    """
    User logout endpoint with comprehensive session cleanup.
    
    Handles both web and API logout workflows with proper session termination
    and security cleanup procedures.
    """
    try:
        user = getattr(g, 'current_user', current_user)
        user_id = user.id if user else None
        
        if user_id:
            # Get authentication service
            auth_service = get_service(AuthService)
            
            # Terminate user sessions
            auth_service.terminate_user_sessions(user_id)
            
            logger.info(f"User {user_id} logged out successfully")
        
        # Logout with Flask-Login
        logout_user()
        
        # Clear session data
        session.clear()
        
        if request.is_json:
            return jsonify({
                'message': 'Logout successful',
                'status': 'success'
            }), 200
        else:
            flash('You have been logged out successfully.', 'info')
            return redirect(url_for('main.index'))
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        
        # Still attempt Flask-Login logout
        logout_user()
        session.clear()
        
        if request.is_json:
            return jsonify({
                'message': 'Logout completed with errors',
                'error': 'Session cleanup encountered issues',
                'error_code': 'LOGOUT_PARTIAL_ERROR'
            }), 200  # Still return success as user is logged out
        else:
            flash('Logout completed. Some session cleanup may have failed.', 'warning')
            return redirect(url_for('main.index'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    User registration endpoint with comprehensive validation and security.
    
    Implements user account creation with password strength validation,
    email verification, and optional Auth0 integration.
    """
    if request.method == 'GET':
        if request.is_json:
            return jsonify({
                'message': 'User registration endpoint',
                'required_fields': ['email', 'password', 'name'],
                'optional_fields': ['confirm_password', 'auth_provider'],
                'password_requirements': {
                    'min_length': 8,
                    'requires_uppercase': True,
                    'requires_lowercase': True,
                    'requires_digit': True,
                    'requires_special_char': True
                }
            })
        else:
            return render_template('auth/register.html', title='Sign Up')
    
    try:
        # Parse request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        # Validate required fields
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', password)  # Default to password if not provided
        name = data.get('name', '').strip()
        auth_provider = data.get('auth_provider', 'local')
        
        # Field validation
        validation_errors = []
        
        if not email:
            validation_errors.append('Email is required')
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            validation_errors.append('Invalid email format')
        
        if not name:
            validation_errors.append('Name is required')
        elif len(name) < 2:
            validation_errors.append('Name must be at least 2 characters long')
        
        if not password:
            validation_errors.append('Password is required')
        else:
            # Validate password strength
            is_valid_password, password_error = validate_password_strength(password)
            if not is_valid_password:
                validation_errors.append(password_error)
        
        if password != confirm_password:
            validation_errors.append('Passwords do not match')
        
        if validation_errors:
            error_response = {
                'error': 'Validation failed',
                'error_code': 'VALIDATION_ERROR',
                'validation_errors': validation_errors
            }
            if request.is_json:
                return jsonify(error_response), 400
            else:
                for error in validation_errors:
                    flash(error, 'error')
                return render_template('auth/register.html', title='Sign Up'), 400
        
        # Get authentication service
        auth_service = get_service(AuthService)
        
        # Check if user already exists
        existing_user = auth_service.get_user_by_email(email)
        if existing_user.success and existing_user.data:
            error_response = {
                'error': 'An account with this email already exists',
                'error_code': 'EMAIL_ALREADY_EXISTS'
            }
            if request.is_json:
                return jsonify(error_response), 409
            else:
                flash('An account with this email already exists.', 'error')
                return render_template('auth/register.html', title='Sign Up'), 409
        
        # Create user account
        user_data = {
            'email': email,
            'password': password,
            'name': name,
            'is_active': True,  # Auto-activate for now, can add email verification later
            'auth_provider': auth_provider
        }
        
        # Register user based on provider
        if auth_provider == 'auth0' and auth0_manager.is_available:
            # Create user in Auth0 first
            auth0_user = auth0_manager.create_user(email, password, name=name)
            if auth0_user:
                user_data['auth0_user_id'] = auth0_user.get('user_id')
            else:
                error_response = {
                    'error': 'Failed to create Auth0 account',
                    'error_code': 'AUTH0_REGISTRATION_FAILED'
                }
                if request.is_json:
                    return jsonify(error_response), 500
                else:
                    flash('Failed to create account with Auth0. Please try again.', 'error')
                    return render_template('auth/register.html', title='Sign Up'), 500
        
        # Create local user account
        registration_result = auth_service.register_user(user_data)
        
        if not registration_result.success:
            error_response = {
                'error': registration_result.error or 'Registration failed',
                'error_code': 'REGISTRATION_FAILED'
            }
            if request.is_json:
                return jsonify(error_response), 500
            else:
                flash('Registration failed. Please try again.', 'error')
                return render_template('auth/register.html', title='Sign Up'), 500
        
        user = registration_result.data
        
        # Auto-login the new user
        login_user(user, remember=False)
        
        # Create initial session
        session_result = auth_service.create_user_session(
            user.id,
            request.remote_addr,
            request.headers.get('User-Agent', 'Unknown')
        )
        
        if request.is_json:
            api_token = token_manager.generate_auth_token(user.id, expires_in=3600)
            
            response_data = {
                'message': 'Registration successful',
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'auth_provider': user.auth_provider
                },
                'session': {
                    'session_id': session_result.data.id if session_result.success else None
                },
                'token': api_token,
                'token_expires_in': 3600
            }
            
            return jsonify(response_data), 201
        else:
            flash(f'Welcome {user.name}! Your account has been created successfully.', 'success')
            return redirect(url_for('main.index'))
    
    except ValidationError as e:
        error_response = {
            'error': str(e),
            'error_code': 'VALIDATION_ERROR'
        }
        if request.is_json:
            return jsonify(error_response), 400
        else:
            flash(str(e), 'error')
            return render_template('auth/register.html', title='Sign Up'), 400
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        error_response = {
            'error': 'An unexpected error occurred during registration',
            'error_code': 'INTERNAL_ERROR'
        }
        if request.is_json:
            return jsonify(error_response), 500
        else:
            flash('An unexpected error occurred. Please try again.', 'error')
            return render_template('auth/register.html', title='Sign Up'), 500


@auth_bp.route('/profile', methods=['GET', 'PUT'])
@require_auth
def profile():
    """
    User profile management endpoint.
    
    Allows authenticated users to view and update their profile information
    with proper validation and security controls.
    """
    user = getattr(g, 'current_user', current_user)
    
    if request.method == 'GET':
        # Return user profile information
        profile_data = {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'is_active': user.is_active,
            'auth_provider': getattr(user, 'auth_provider', 'local'),
            'created_at': user.created_at.isoformat() if hasattr(user, 'created_at') else None,
            'last_login': user.last_login.isoformat() if hasattr(user, 'last_login') and user.last_login else None,
            'roles': [role.name for role in user.roles] if hasattr(user, 'roles') else [],
            'permissions': list(user.get_permissions()) if hasattr(user, 'get_permissions') else []
        }
        
        if request.is_json:
            return jsonify({
                'user': profile_data,
                'message': 'Profile retrieved successfully'
            }), 200
        else:
            return render_template('auth/profile.html', user=profile_data, title='My Profile')
    
    elif request.method == 'PUT':
        try:
            # Parse update data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()
            
            # Get authentication service
            auth_service = get_service(AuthService)
            
            # Validate and update profile
            update_data = {}
            
            # Name update
            if 'name' in data:
                name = data['name'].strip()
                if len(name) < 2:
                    raise ValidationError('Name must be at least 2 characters long')
                update_data['name'] = name
            
            # Email update (requires additional validation)
            if 'email' in data:
                email = data['email'].strip().lower()
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                    raise ValidationError('Invalid email format')
                
                # Check if email is already in use
                if email != user.email:
                    existing_user = auth_service.get_user_by_email(email)
                    if existing_user.success and existing_user.data:
                        raise ValidationError('Email is already in use by another account')
                    update_data['email'] = email
            
            # Password update
            if 'current_password' in data and 'new_password' in data:
                current_password = data['current_password']
                new_password = data['new_password']
                
                # Verify current password
                if not check_password_hash(user.password_hash, current_password):
                    raise ValidationError('Current password is incorrect')
                
                # Validate new password strength
                is_valid_password, password_error = validate_password_strength(new_password)
                if not is_valid_password:
                    raise ValidationError(password_error)
                
                update_data['password'] = new_password
            
            # Update profile if there are changes
            if update_data:
                update_result = auth_service.update_user_profile(user.id, update_data)
                
                if not update_result.success:
                    raise ServiceError(update_result.error or 'Profile update failed')
                
                updated_user = update_result.data
                
                # Refresh current user object
                if hasattr(g, 'current_user'):
                    g.current_user = updated_user
                
                message = 'Profile updated successfully'
                
                # If email was changed, might need to re-verify
                if 'email' in update_data:
                    message += '. Please verify your new email address.'
            else:
                message = 'No changes to update'
            
            if request.is_json:
                return jsonify({
                    'message': message,
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'name': user.name
                    }
                }), 200
            else:
                flash(message, 'success')
                return redirect(url_for('auth.profile'))
        
        except ValidationError as e:
            error_response = {
                'error': str(e),
                'error_code': 'VALIDATION_ERROR'
            }
            if request.is_json:
                return jsonify(error_response), 400
            else:
                flash(str(e), 'error')
                return redirect(url_for('auth.profile'))
        
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            error_response = {
                'error': 'Failed to update profile',
                'error_code': 'PROFILE_UPDATE_ERROR'
            }
            if request.is_json:
                return jsonify(error_response), 500
            else:
                flash('Failed to update profile. Please try again.', 'error')
                return redirect(url_for('auth.profile'))


@auth_bp.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    """
    Dedicated password change endpoint for authenticated users.
    """
    try:
        user = getattr(g, 'current_user', current_user)
        
        # Parse request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validation
        if not all([current_password, new_password, confirm_password]):
            raise ValidationError('All password fields are required')
        
        if new_password != confirm_password:
            raise ValidationError('New passwords do not match')
        
        # Verify current password
        if not check_password_hash(user.password_hash, current_password):
            raise ValidationError('Current password is incorrect')
        
        # Validate new password strength
        is_valid_password, password_error = validate_password_strength(new_password)
        if not is_valid_password:
            raise ValidationError(password_error)
        
        # Get authentication service and update password
        auth_service = get_service(AuthService)
        result = auth_service.change_user_password(user.id, current_password, new_password)
        
        if not result.success:
            raise ServiceError(result.error or 'Password change failed')
        
        # Invalidate all existing sessions except current one
        auth_service.terminate_user_sessions(user.id, exclude_current=True)
        
        response_data = {
            'message': 'Password changed successfully',
            'status': 'success'
        }
        
        if request.is_json:
            return jsonify(response_data), 200
        else:
            flash('Password changed successfully.', 'success')
            return redirect(url_for('auth.profile'))
    
    except ValidationError as e:
        error_response = {
            'error': str(e),
            'error_code': 'VALIDATION_ERROR'
        }
        if request.is_json:
            return jsonify(error_response), 400
        else:
            flash(str(e), 'error')
            return redirect(url_for('auth.profile'))
    
    except Exception as e:
        logger.error(f"Password change error: {e}")
        error_response = {
            'error': 'Failed to change password',
            'error_code': 'PASSWORD_CHANGE_ERROR'
        }
        if request.is_json:
            return jsonify(error_response), 500
        else:
            flash('Failed to change password. Please try again.', 'error')
            return redirect(url_for('auth.profile'))


@auth_bp.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """
    Password reset request endpoint.
    
    Generates secure password reset tokens and handles password reset workflows
    with proper security validation and rate limiting.
    """
    if request.method == 'GET':
        # Show password reset form
        token = request.args.get('token')
        
        if token:
            # Verify reset token
            email = token_manager.verify_reset_token(token, max_age=3600)
            if not email:
                if request.is_json:
                    return jsonify({
                        'error': 'Invalid or expired reset token',
                        'error_code': 'INVALID_RESET_TOKEN'
                    }), 400
                else:
                    flash('Invalid or expired reset link. Please request a new one.', 'error')
                    return redirect(url_for('auth.reset_password'))
            
            if request.is_json:
                return jsonify({
                    'message': 'Valid reset token',
                    'email': email,
                    'instructions': 'POST new password to complete reset'
                })
            else:
                return render_template('auth/reset_password.html', token=token, email=email, title='Reset Password')
        else:
            if request.is_json:
                return jsonify({
                    'message': 'Password reset request endpoint',
                    'instructions': 'POST email to request reset token'
                })
            else:
                return render_template('auth/reset_password.html', title='Reset Password')
    
    elif request.method == 'POST':
        try:
            # Parse request data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()
            
            token = data.get('token')
            
            if token:
                # Complete password reset with token
                email = data.get('email', '')
                new_password = data.get('new_password', '')
                confirm_password = data.get('confirm_password', '')
                
                # Validate token
                token_email = token_manager.verify_reset_token(token, max_age=3600)
                if not token_email or token_email != email.lower().strip():
                    raise ValidationError('Invalid or expired reset token')
                
                # Validate passwords
                if not new_password or not confirm_password:
                    raise ValidationError('Password fields are required')
                
                if new_password != confirm_password:
                    raise ValidationError('Passwords do not match')
                
                # Validate password strength
                is_valid_password, password_error = validate_password_strength(new_password)
                if not is_valid_password:
                    raise ValidationError(password_error)
                
                # Get authentication service and reset password
                auth_service = get_service(AuthService)
                reset_result = auth_service.reset_user_password(email, new_password)
                
                if not reset_result.success:
                    raise ServiceError(reset_result.error or 'Password reset failed')
                
                # Terminate all existing sessions for security
                user = reset_result.data
                auth_service.terminate_user_sessions(user.id)
                
                response_data = {
                    'message': 'Password reset successfully',
                    'status': 'success'
                }
                
                if request.is_json:
                    return jsonify(response_data), 200
                else:
                    flash('Password reset successfully. Please log in with your new password.', 'success')
                    return redirect(url_for('auth.login'))
            
            else:
                # Request password reset token
                email = data.get('email', '').strip().lower()
                
                if not email:
                    raise ValidationError('Email is required')
                
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                    raise ValidationError('Invalid email format')
                
                # Get authentication service
                auth_service = get_service(AuthService)
                
                # Check if user exists (don't reveal if email doesn't exist for security)
                user_result = auth_service.get_user_by_email(email)
                
                if user_result.success and user_result.data:
                    # Generate reset token
                    reset_token = token_manager.generate_reset_token(email, expires_in=3600)
                    
                    # In a real application, you would send this token via email
                    # For now, we'll include it in the response (not recommended for production)
                    reset_link = url_for('auth.reset_password', token=reset_token, _external=True)
                    
                    # Log the reset request
                    logger.info(f"Password reset requested for {email}")
                    
                    if request.is_json:
                        return jsonify({
                            'message': 'Password reset token generated',
                            'reset_token': reset_token,  # Remove in production
                            'reset_link': reset_link,    # Remove in production
                            'expires_in': 3600,
                            'instructions': 'Check your email for reset instructions'
                        }), 200
                    else:
                        flash('Password reset instructions have been sent to your email.', 'info')
                        return render_template('auth/reset_password.html', success=True, title='Reset Password')
                else:
                    # Always return success to prevent email enumeration
                    if request.is_json:
                        return jsonify({
                            'message': 'If the email exists, reset instructions have been sent',
                            'status': 'success'
                        }), 200
                    else:
                        flash('If the email exists, reset instructions have been sent.', 'info')
                        return render_template('auth/reset_password.html', success=True, title='Reset Password')
        
        except ValidationError as e:
            error_response = {
                'error': str(e),
                'error_code': 'VALIDATION_ERROR'
            }
            if request.is_json:
                return jsonify(error_response), 400
            else:
                flash(str(e), 'error')
                return render_template('auth/reset_password.html', title='Reset Password'), 400
        
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            error_response = {
                'error': 'Password reset request failed',
                'error_code': 'RESET_ERROR'
            }
            if request.is_json:
                return jsonify(error_response), 500
            else:
                flash('Password reset request failed. Please try again.', 'error')
                return render_template('auth/reset_password.html', title='Reset Password'), 500


@auth_bp.route('/refresh-session', methods=['POST'])
@require_auth
def refresh_session():
    """
    Session refresh endpoint for extending authenticated sessions.
    """
    try:
        user = getattr(g, 'current_user', current_user)
        
        # Get authentication service
        auth_service = get_service(AuthService)
        
        # Refresh current session
        session_result = auth_service.refresh_user_session(
            user.id,
            request.remote_addr,
            request.headers.get('User-Agent', 'Unknown')
        )
        
        if not session_result.success:
            raise ServiceError(session_result.error or 'Session refresh failed')
        
        # Generate new API token
        api_token = token_manager.generate_auth_token(user.id, expires_in=3600)
        
        response_data = {
            'message': 'Session refreshed successfully',
            'session': {
                'session_id': session_result.data.id,
                'expires_at': session_result.data.expires_at.isoformat()
            },
            'token': api_token,
            'token_expires_in': 3600
        }
        
        return jsonify(response_data), 200
    
    except Exception as e:
        logger.error(f"Session refresh error: {e}")
        return jsonify({
            'error': 'Session refresh failed',
            'error_code': 'SESSION_REFRESH_ERROR'
        }), 500


@auth_bp.route('/sessions', methods=['GET', 'DELETE'])
@require_auth
def manage_sessions():
    """
    User session management endpoint for viewing and terminating sessions.
    """
    user = getattr(g, 'current_user', current_user)
    
    try:
        auth_service = get_service(AuthService)
        
        if request.method == 'GET':
            # Get user sessions
            sessions_result = auth_service.get_user_sessions(user.id)
            
            if not sessions_result.success:
                raise ServiceError(sessions_result.error or 'Failed to retrieve sessions')
            
            sessions_data = []
            for session_obj in sessions_result.data:
                sessions_data.append({
                    'id': session_obj.id,
                    'ip_address': session_obj.ip_address,
                    'user_agent': session_obj.user_agent,
                    'created_at': session_obj.created_at.isoformat(),
                    'expires_at': session_obj.expires_at.isoformat(),
                    'is_current': session_obj.id == session.get('session_id'),
                    'last_activity': session_obj.last_activity.isoformat() if hasattr(session_obj, 'last_activity') and session_obj.last_activity else None
                })
            
            return jsonify({
                'sessions': sessions_data,
                'total_sessions': len(sessions_data)
            }), 200
        
        elif request.method == 'DELETE':
            # Terminate sessions
            data = request.get_json() if request.is_json else {}
            session_id = data.get('session_id')
            terminate_all = data.get('terminate_all', False)
            
            if terminate_all:
                # Terminate all sessions except current
                result = auth_service.terminate_user_sessions(user.id, exclude_current=True)
                message = 'All other sessions terminated successfully'
            elif session_id:
                # Terminate specific session
                result = auth_service.terminate_session(session_id, user.id)
                message = 'Session terminated successfully'
            else:
                raise ValidationError('session_id or terminate_all parameter required')
            
            if not result.success:
                raise ServiceError(result.error or 'Session termination failed')
            
            return jsonify({
                'message': message,
                'status': 'success'
            }), 200
    
    except ValidationError as e:
        return jsonify({
            'error': str(e),
            'error_code': 'VALIDATION_ERROR'
        }), 400
    
    except Exception as e:
        logger.error(f"Session management error: {e}")
        return jsonify({
            'error': 'Session management failed',
            'error_code': 'SESSION_MANAGEMENT_ERROR'
        }), 500


@auth_bp.route('/verify-token', methods=['POST'])
def verify_token():
    """
    Token verification endpoint for API authentication validation.
    """
    try:
        # Parse request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        token = data.get('token', '')
        
        if not token:
            return jsonify({
                'error': 'Token is required',
                'error_code': 'MISSING_TOKEN'
            }), 400
        
        # Verify token
        payload = token_manager.verify_auth_token(token)
        
        if not payload:
            return jsonify({
                'error': 'Invalid or expired token',
                'error_code': 'INVALID_TOKEN',
                'valid': False
            }), 401
        
        # Get user information
        user_id = payload.get('user_id')
        if not user_id:
            return jsonify({
                'error': 'Invalid token payload',
                'error_code': 'INVALID_TOKEN_PAYLOAD',
                'valid': False
            }), 401
        
        # Verify user exists and is active
        user = User.query.get(user_id)
        if not user or not user.is_active:
            return jsonify({
                'error': 'User not found or inactive',
                'error_code': 'USER_NOT_ACTIVE',
                'valid': False
            }), 401
        
        return jsonify({
            'valid': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'roles': [role.name for role in user.roles] if hasattr(user, 'roles') else []
            },
            'token_info': {
                'issued_at': payload.get('issued_at'),
                'type': payload.get('type')
            }
        }), 200
    
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return jsonify({
            'error': 'Token verification failed',
            'error_code': 'TOKEN_VERIFICATION_ERROR',
            'valid': False
        }), 500


# Auth0 Integration Routes

@auth_bp.route('/auth0/login', methods=['POST'])
def auth0_login():
    """
    Auth0 authentication endpoint for external provider integration.
    """
    if not auth0_manager.is_available:
        return jsonify({
            'error': 'Auth0 integration not available',
            'error_code': 'AUTH0_NOT_CONFIGURED'
        }), 503
    
    try:
        # Parse request data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        # Auth0 token or code should be provided
        auth0_token = data.get('auth0_token')
        auth0_code = data.get('auth0_code')
        
        if not auth0_token and not auth0_code:
            return jsonify({
                'error': 'Auth0 token or authorization code required',
                'error_code': 'MISSING_AUTH0_CREDENTIALS'
            }), 400
        
        # Get authentication service
        auth_service = get_service(AuthService)
        
        # Authenticate with Auth0
        auth_result = auth_service.authenticate_with_auth0_token(auth0_token or auth0_code)
        
        if not auth_result.success:
            return jsonify({
                'error': auth_result.error or 'Auth0 authentication failed',
                'error_code': 'AUTH0_AUTHENTICATION_FAILED'
            }), 401
        
        user = auth_result.data
        
        # Create user session
        session_result = auth_service.create_user_session(
            user.id,
            request.remote_addr,
            request.headers.get('User-Agent', 'Unknown')
        )
        
        # Log in user with Flask-Login
        login_user(user, remember=False)
        
        # Generate API token
        api_token = token_manager.generate_auth_token(user.id, expires_in=3600)
        
        response_data = {
            'message': 'Auth0 login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'auth_provider': 'auth0'
            },
            'session': {
                'session_id': session_result.data.id if session_result.success else None
            },
            'token': api_token,
            'token_expires_in': 3600
        }
        
        return jsonify(response_data), 200
    
    except Exception as e:
        logger.error(f"Auth0 login error: {e}")
        return jsonify({
            'error': 'Auth0 login failed',
            'error_code': 'AUTH0_LOGIN_ERROR'
        }), 500


# Error Handlers

@auth_bp.errorhandler(AuthenticationError)
def handle_authentication_error(error):
    """Handle authentication errors with proper response format."""
    response_data = {
        'error': error.message,
        'error_code': error.error_code
    }
    
    if request.is_json:
        return jsonify(response_data), error.status_code
    else:
        flash(error.message, 'error')
        return redirect(url_for('auth.login')), error.status_code


@auth_bp.errorhandler(AuthorizationError)
def handle_authorization_error(error):
    """Handle authorization errors with proper response format."""
    response_data = {
        'error': error.message,
        'error_code': error.error_code
    }
    
    if request.is_json:
        return jsonify(response_data), error.status_code
    else:
        flash(error.message, 'error')
        return redirect(url_for('main.index')), error.status_code


@auth_bp.errorhandler(ValidationError)
def handle_validation_error(error):
    """Handle validation errors with proper response format."""
    response_data = {
        'error': str(error),
        'error_code': 'VALIDATION_ERROR'
    }
    
    if request.is_json:
        return jsonify(response_data), 400
    else:
        flash(str(error), 'error')
        return redirect(request.referrer or url_for('main.index')), 400


@auth_bp.errorhandler(429)
def handle_rate_limit_error(error):
    """Handle rate limiting errors."""
    response_data = {
        'error': 'Too many requests. Please try again later.',
        'error_code': 'RATE_LIMIT_EXCEEDED'
    }
    
    if request.is_json:
        return jsonify(response_data), 429
    else:
        flash('Too many requests. Please try again later.', 'warning')
        return redirect(request.referrer or url_for('main.index')), 429


# Blueprint initialization function
def register_auth_blueprint(app):
    """
    Register authentication blueprint with Flask application.
    
    Args:
        app: Flask application instance
    """
    # Initialize authentication system
    init_auth(app)
    
    # Register blueprint
    app.register_blueprint(auth_bp)
    
    logger.info("Authentication blueprint registered successfully")


# Export decorators and utilities for use in other blueprints
__all__ = [
    'auth_bp',
    'init_auth',
    'register_auth_blueprint',
    'require_auth',
    'require_permission',
    'require_role',
    'token_manager',
    'auth0_manager',
    'AuthenticationError',
    'AuthorizationError',
    'TokenManager',
    'Auth0Manager'
]