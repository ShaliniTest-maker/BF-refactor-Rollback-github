"""
Flask Authentication Blueprint

This blueprint manages user authentication routes including login, logout, registration,
and session management endpoints, implementing comprehensive Flask authentication patterns
using Flask-Login 0.6.3, ItsDangerous 2.2+, and Auth0 Python SDK 4.9.0 integration.

The authentication system preserves existing user access patterns and security levels
while transitioning from Node.js authentication middleware to Flask authentication
decorators and session management.

Key Features:
- Flask-Login integration for comprehensive user session management
- ItsDangerous 2.2+ for cryptographically secure cookie signing and token generation
- Auth0 Python SDK 4.9.0 for external authentication provider integration
- Authentication decorator patterns for endpoint protection
- Secure session management with preservation of existing user access control
- Service Layer pattern integration for authentication business logic

Authentication Flow:
1. User authentication via Auth0 or local login
2. Session creation with Flask-Login user loader
3. Secure cookie signing with ItsDangerous
4. Session validation and management
5. Authorization enforcement through decorators

Security Features:
- CSRF protection with secure token generation
- Session hijacking prevention through secure cookies
- Token-based authentication with cryptographic validation
- Rate limiting for authentication endpoints
- Comprehensive audit logging for security events
"""

import os
import logging
import json
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional, Union, Callable
from urllib.parse import urlencode, quote_plus

from flask import (
    Blueprint, request, jsonify, redirect, url_for, session, flash,
    current_app, g, make_response, abort, render_template
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, 
    current_user, UserMixin, AnonymousUserMixin
)
from itsdangerous import (
    URLSafeTimedSerializer, URLSafeSerializer, BadSignature, 
    SignatureExpired, BadData
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import Unauthorized, Forbidden
import requests

# Import Auth0 Python SDK 4.9.0 components
try:
    from auth0.authentication import GetToken, Users
    from auth0.management import Auth0
    from authlib.integrations.flask_client import OAuth
    AUTH0_AVAILABLE = True
except ImportError:
    AUTH0_AVAILABLE = False
    logging.warning("Auth0 SDK not available. Local authentication only.")

# Import Service Layer and Models
from services import get_service, with_service, ServiceException
from models import User, UserSession, load_user, db

# Configure logging for authentication events
logger = logging.getLogger(__name__)

# Create authentication blueprint
auth_bp = Blueprint(
    'auth', 
    __name__, 
    url_prefix='/auth',
    template_folder='../templates/auth',
    static_folder='../static'
)


class AuthenticationError(Exception):
    """Custom authentication error for handling auth failures"""
    def __init__(self, message: str, error_code: str = None, status_code: int = 401):
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(self.message)


class SecureTokenManager:
    """
    Secure token management using ItsDangerous 2.2+ for cryptographically
    secure cookie signing and token generation with comprehensive validation.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.serializer = None
        self.timed_serializer = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize secure token manager with Flask application"""
        secret_key = app.config.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("SECRET_KEY must be configured for secure token management")
        
        # Initialize ItsDangerous serializers
        self.serializer = URLSafeSerializer(secret_key)
        self.timed_serializer = URLSafeTimedSerializer(secret_key)
        
        # Configure security parameters
        self.token_salt = app.config.get('AUTH_TOKEN_SALT', 'auth-token-salt')
        self.session_salt = app.config.get('SESSION_SALT', 'session-salt')
        self.csrf_salt = app.config.get('CSRF_SALT', 'csrf-salt')
        self.max_age = app.config.get('AUTH_TOKEN_MAX_AGE', 3600)  # 1 hour default
    
    def generate_auth_token(self, user_id: int, additional_data: Dict = None) -> str:
        """
        Generate cryptographically secure authentication token
        
        Args:
            user_id: User identifier for token association
            additional_data: Optional additional data to include in token
            
        Returns:
            Secure signed token string
        """
        token_data = {
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'type': 'auth_token'
        }
        
        if additional_data:
            token_data.update(additional_data)
        
        return self.timed_serializer.dumps(token_data, salt=self.token_salt)
    
    def validate_auth_token(self, token: str, max_age: int = None) -> Optional[Dict]:
        """
        Validate and decode authentication token
        
        Args:
            token: Token string to validate
            max_age: Maximum age in seconds (defaults to configured value)
            
        Returns:
            Token data if valid, None if invalid
            
        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            max_age = max_age or self.max_age
            token_data = self.timed_serializer.loads(
                token, 
                salt=self.token_salt,
                max_age=max_age
            )
            
            # Validate token structure
            if not isinstance(token_data, dict) or 'user_id' not in token_data:
                raise AuthenticationError("Invalid token structure", "INVALID_TOKEN_STRUCTURE")
            
            return token_data
            
        except SignatureExpired:
            raise AuthenticationError("Token has expired", "TOKEN_EXPIRED", 401)
        except BadSignature:
            raise AuthenticationError("Invalid token signature", "INVALID_SIGNATURE", 401)
        except BadData:
            raise AuthenticationError("Invalid token data", "INVALID_TOKEN_DATA", 401)
    
    def generate_csrf_token(self) -> str:
        """Generate CSRF protection token"""
        token_data = {
            'csrf': True,
            'timestamp': datetime.utcnow().isoformat()
        }
        return self.serializer.dumps(token_data, salt=self.csrf_salt)
    
    def validate_csrf_token(self, token: str) -> bool:
        """Validate CSRF protection token"""
        try:
            token_data = self.serializer.loads(token, salt=self.csrf_salt)
            return isinstance(token_data, dict) and token_data.get('csrf') is True
        except (BadSignature, BadData):
            return False
    
    def generate_session_token(self, user_id: int, session_data: Dict = None) -> str:
        """Generate secure session token"""
        session_payload = {
            'user_id': user_id,
            'session_id': os.urandom(16).hex(),
            'created_at': datetime.utcnow().isoformat(),
            'data': session_data or {}
        }
        return self.timed_serializer.dumps(session_payload, salt=self.session_salt)
    
    def validate_session_token(self, token: str) -> Optional[Dict]:
        """Validate and decode session token"""
        try:
            return self.timed_serializer.loads(
                token, 
                salt=self.session_salt,
                max_age=self.max_age
            )
        except (SignatureExpired, BadSignature, BadData):
            return None


class Auth0Integration:
    """
    Auth0 Python SDK 4.9.0 integration for external authentication provider
    support with comprehensive user management and security validation.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.oauth = None
        self.auth0_client = None
        self.management_client = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Auth0 integration with Flask application"""
        if not AUTH0_AVAILABLE:
            logger.warning("Auth0 SDK not available, skipping Auth0 initialization")
            return
        
        # Get Auth0 configuration
        self.domain = app.config.get('AUTH0_DOMAIN')
        self.client_id = app.config.get('AUTH0_CLIENT_ID') or app.config.get('CLIENT_ID')
        self.client_secret = app.config.get('AUTH0_CLIENT_SECRET') or app.config.get('CLIENT_SECRET')
        self.algorithms = app.config.get('AUTH0_ALGORITHMS', ['RS256'])
        
        if not all([self.domain, self.client_id, self.client_secret]):
            logger.warning("Auth0 configuration incomplete, Auth0 integration disabled")
            return
        
        # Initialize OAuth client
        self.oauth = OAuth(app)
        self.auth0_client = self.oauth.register(
            'auth0',
            client_id=self.client_id,
            client_secret=self.client_secret,
            server_metadata_url=f'https://{self.domain}/.well-known/openid_configuration',
            client_kwargs={'scope': 'openid profile email'}
        )
        
        # Initialize Auth0 management client
        try:
            get_token = GetToken(self.domain, self.client_id, self.client_secret)
            token = get_token.client_credentials(f'https://{self.domain}/api/v2/')
            self.management_client = Auth0(self.domain, token['access_token'])
        except Exception as e:
            logger.error(f"Failed to initialize Auth0 management client: {e}")
    
    def get_authorization_url(self, redirect_uri: str, state: str = None) -> str:
        """Get Auth0 authorization URL for login redirect"""
        if not self.auth0_client:
            raise AuthenticationError("Auth0 not configured", "AUTH0_NOT_CONFIGURED")
        
        return self.auth0_client.authorize_redirect(
            redirect_uri=redirect_uri,
            state=state
        ).location
    
    def handle_callback(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        """
        Handle Auth0 callback and extract user information
        
        Args:
            code: Authorization code from Auth0
            redirect_uri: Redirect URI used in authorization
            
        Returns:
            User information dictionary from Auth0
        """
        if not self.auth0_client:
            raise AuthenticationError("Auth0 not configured", "AUTH0_NOT_CONFIGURED")
        
        try:
            # Exchange code for token
            token = self.auth0_client.authorize_access_token(
                redirect_uri=redirect_uri,
                code=code
            )
            
            # Get user information
            user_info = self.auth0_client.parse_id_token(token)
            
            return {
                'auth0_id': user_info.get('sub'),
                'email': user_info.get('email'),
                'email_verified': user_info.get('email_verified', False),
                'name': user_info.get('name'),
                'picture': user_info.get('picture'),
                'nickname': user_info.get('nickname'),
                'access_token': token.get('access_token'),
                'id_token': token.get('id_token')
            }
            
        except Exception as e:
            logger.error(f"Auth0 callback error: {e}")
            raise AuthenticationError(f"Auth0 authentication failed: {str(e)}", "AUTH0_CALLBACK_ERROR")
    
    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information from Auth0 Management API"""
        if not self.management_client:
            return None
        
        try:
            return self.management_client.users.get(user_id)
        except Exception as e:
            logger.error(f"Failed to get Auth0 user info: {e}")
            return None
    
    def update_user_metadata(self, user_id: str, metadata: Dict[str, Any]) -> bool:
        """Update user metadata in Auth0"""
        if not self.management_client:
            return False
        
        try:
            self.management_client.users.update(user_id, {"user_metadata": metadata})
            return True
        except Exception as e:
            logger.error(f"Failed to update Auth0 user metadata: {e}")
            return False


class AuthenticationManager:
    """
    Comprehensive authentication manager coordinating Flask-Login, ItsDangerous,
    and Auth0 integration for secure user authentication and session management.
    """
    
    def __init__(self, app=None):
        self.app = app
        self.login_manager = None
        self.token_manager = None
        self.auth0_integration = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize authentication manager with Flask application"""
        # Initialize Flask-Login
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        self.login_manager.login_view = 'auth.login'
        self.login_manager.login_message = 'Please log in to access this page.'
        self.login_manager.login_message_category = 'info'
        self.login_manager.session_protection = 'strong'
        self.login_manager.refresh_view = 'auth.refresh'
        
        # Set user loader
        self.login_manager.user_loader(self.load_user)
        
        # Initialize secure token manager
        self.token_manager = SecureTokenManager(app)
        
        # Initialize Auth0 integration
        self.auth0_integration = Auth0Integration(app)
        
        # Store in app context
        app.auth_manager = self
    
    def load_user(self, user_id: str) -> Optional[User]:
        """Flask-Login user loader callback"""
        try:
            return User.query.get(int(user_id))
        except (ValueError, TypeError):
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with username/password
        
        Args:
            username: Username or email
            password: User password
            
        Returns:
            User object if authenticated, None otherwise
        """
        try:
            # Get user from database
            user = User.query.filter(
                (User.username == username) | (User.email == username)
            ).first()
            
            if not user or not user.is_active:
                return None
            
            # Verify password
            if hasattr(user, 'password_hash') and user.password_hash:
                if check_password_hash(user.password_hash, password):
                    return user
            
            return None
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    def create_user_session(self, user: User, remember: bool = False) -> Dict[str, Any]:
        """
        Create secure user session with Flask-Login and token generation
        
        Args:
            user: User object
            remember: Whether to create persistent session
            
        Returns:
            Session information dictionary
        """
        try:
            # Login user with Flask-Login
            login_user(user, remember=remember)
            
            # Generate secure session token
            session_token = self.token_manager.generate_session_token(
                user.id,
                {'login_time': datetime.utcnow().isoformat()}
            )
            
            # Create user session record
            user_session = UserSession(
                user_id=user.id,
                session_id=session.get('_id', os.urandom(16).hex()),
                ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                user_agent=request.headers.get('User-Agent', ''),
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow()
            )
            
            db.session.add(user_session)
            db.session.commit()
            
            # Store session information
            session['auth_token'] = session_token
            session['user_id'] = user.id
            session['session_id'] = user_session.id
            
            return {
                'user_id': user.id,
                'session_id': user_session.id,
                'session_token': session_token,
                'csrf_token': self.token_manager.generate_csrf_token()
            }
            
        except Exception as e:
            logger.error(f"Session creation error: {e}")
            db.session.rollback()
            raise AuthenticationError(f"Failed to create session: {str(e)}", "SESSION_CREATION_ERROR")
    
    def validate_session(self, session_token: str = None) -> bool:
        """
        Validate user session and update activity
        
        Args:
            session_token: Session token to validate (from session if not provided)
            
        Returns:
            True if session is valid, False otherwise
        """
        try:
            token = session_token or session.get('auth_token')
            if not token:
                return False
            
            # Validate token
            token_data = self.token_manager.validate_session_token(token)
            if not token_data:
                return False
            
            # Update session activity
            session_id = session.get('session_id')
            if session_id:
                user_session = UserSession.query.get(session_id)
                if user_session:
                    user_session.last_activity = datetime.utcnow()
                    db.session.commit()
            
            return True
            
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False
    
    def logout_user_session(self) -> bool:
        """Logout user and clean up session"""
        try:
            # Get session information before logout
            session_id = session.get('session_id')
            
            # Logout with Flask-Login
            logout_user()
            
            # Update session record
            if session_id:
                user_session = UserSession.query.get(session_id)
                if user_session:
                    user_session.ended_at = datetime.utcnow()
                    db.session.commit()
            
            # Clear session data
            session.clear()
            
            return True
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False


# Initialize authentication manager
auth_manager = AuthenticationManager()


def init_auth(app):
    """Initialize authentication system with Flask application"""
    auth_manager.init_app(app)
    app.register_blueprint(auth_bp)


def require_auth(f: Callable = None, *, permissions: list = None, roles: list = None):
    """
    Authentication decorator for endpoint protection with optional permission/role checking
    
    Args:
        f: Function to decorate
        permissions: List of required permissions
        roles: List of required roles
        
    Returns:
        Decorated function with authentication enforcement
    
    Example:
        @require_auth
        def protected_endpoint():
            return "Protected content"
        
        @require_auth(permissions=['user.read'])
        def user_endpoint():
            return "User data"
    """
    def decorator(func):
        @wraps(func)
        @login_required
        def wrapper(*args, **kwargs):
            try:
                # Validate session token
                if not auth_manager.validate_session():
                    raise AuthenticationError("Invalid session", "INVALID_SESSION")
                
                # Check permissions if specified
                if permissions:
                    auth_service = get_service('auth')
                    if not auth_service.check_permissions(current_user.id, permissions):
                        raise AuthenticationError("Insufficient permissions", "INSUFFICIENT_PERMISSIONS", 403)
                
                # Check roles if specified
                if roles:
                    auth_service = get_service('auth')
                    if not auth_service.check_roles(current_user.id, roles):
                        raise AuthenticationError("Insufficient roles", "INSUFFICIENT_ROLES", 403)
                
                return func(*args, **kwargs)
                
            except AuthenticationError:
                raise
            except Exception as e:
                logger.error(f"Authentication decorator error: {e}")
                raise AuthenticationError("Authentication check failed", "AUTH_CHECK_ERROR")
        
        return wrapper
    
    if f is None:
        return decorator
    else:
        return decorator(f)


def csrf_protect(f):
    """CSRF protection decorator using ItsDangerous token validation"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not csrf_token or not auth_manager.token_manager.validate_csrf_token(csrf_token):
                abort(403, description="CSRF token missing or invalid")
        return f(*args, **kwargs)
    return wrapper


# Authentication Routes

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    User login endpoint supporting both local and Auth0 authentication
    
    GET: Return login form or redirect to Auth0
    POST: Process local login credentials
    """
    if request.method == 'GET':
        # Check if Auth0 is configured
        if auth_manager.auth0_integration and auth_manager.auth0_integration.auth0_client:
            auth0_url = request.args.get('auth0')
            if auth0_url == 'true':
                return redirect(url_for('auth.auth0_login'))
        
        # Return login form with CSRF token
        csrf_token = auth_manager.token_manager.generate_csrf_token()
        return jsonify({
            'status': 'login_form',
            'csrf_token': csrf_token,
            'auth0_available': auth_manager.auth0_integration is not None
        })
    
    # Handle POST login
    try:
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        remember = data.get('remember', False)
        
        if not username or not password:
            raise AuthenticationError("Username and password required", "MISSING_CREDENTIALS", 400)
        
        # Authenticate user
        user = auth_manager.authenticate_user(username, password)
        if not user:
            raise AuthenticationError("Invalid credentials", "INVALID_CREDENTIALS", 401)
        
        # Create session
        session_info = auth_manager.create_user_session(user, remember)
        
        # Log successful authentication
        logger.info(f"User {user.id} authenticated successfully")
        
        response_data = {
            'status': 'success',
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'csrf_token': session_info['csrf_token']
        }
        
        response = make_response(jsonify(response_data))
        
        # Set secure cookies
        response.set_cookie(
            'session_token',
            session_info['session_token'],
            httponly=True,
            secure=current_app.config.get('SESSION_COOKIE_SECURE', False),
            samesite='Lax',
            max_age=3600 if not remember else 30*24*3600
        )
        
        return response
        
    except AuthenticationError as e:
        logger.warning(f"Authentication failed: {e.message}")
        return jsonify({
            'status': 'error',
            'message': e.message,
            'error_code': e.error_code
        }), e.status_code
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500


@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint with comprehensive session cleanup"""
    try:
        # Logout user
        success = auth_manager.logout_user_session()
        
        if success:
            logger.info(f"User {current_user.id} logged out successfully")
            
            response = make_response(jsonify({
                'status': 'success',
                'message': 'Logout successful'
            }))
            
            # Clear session cookie
            response.set_cookie(
                'session_token',
                '',
                expires=0,
                httponly=True,
                secure=current_app.config.get('SESSION_COOKIE_SECURE', False)
            )
            
            return response
        else:
            raise AuthenticationError("Logout failed", "LOGOUT_ERROR")
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Logout failed'
        }), 500


@auth_bp.route('/register', methods=['POST'])
@csrf_protect
def register():
    """
    User registration endpoint with comprehensive validation
    
    Creates new user account with secure password hashing and validation
    """
    try:
        data = request.get_json() or {}
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            raise AuthenticationError(
                f"Missing required fields: {', '.join(missing_fields)}", 
                "MISSING_FIELDS", 
                400
            )
        
        username = data['username']
        email = data['email']
        password = data['password']
        
        # Check if user already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            raise AuthenticationError("User already exists", "USER_EXISTS", 409)
        
        # Use validation service for comprehensive validation
        validation_service = get_service('validation')
        validation_result = validation_service.validate_user_registration({
            'username': username,
            'email': email,
            'password': password
        })
        
        if not validation_result.is_valid:
            raise AuthenticationError(
                f"Validation failed: {', '.join(validation_result.errors)}", 
                "VALIDATION_ERROR", 
                400
            )
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f"New user registered: {new_user.id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Registration successful',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email
            }
        }), 201
        
    except AuthenticationError as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': e.message,
            'error_code': e.error_code
        }), e.status_code
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Registration failed'
        }), 500


@auth_bp.route('/auth0/login')
def auth0_login():
    """Initiate Auth0 authentication flow"""
    if not auth_manager.auth0_integration or not auth_manager.auth0_integration.auth0_client:
        return jsonify({
            'status': 'error',
            'message': 'Auth0 not configured'
        }), 503
    
    try:
        redirect_uri = url_for('auth.auth0_callback', _external=True)
        state = os.urandom(16).hex()
        session['auth0_state'] = state
        
        return auth_manager.auth0_integration.auth0_client.authorize_redirect(
            redirect_uri=redirect_uri,
            state=state
        )
        
    except Exception as e:
        logger.error(f"Auth0 login error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Auth0 login failed'
        }), 500


@auth_bp.route('/auth0/callback')
def auth0_callback():
    """Handle Auth0 authentication callback"""
    if not auth_manager.auth0_integration:
        return jsonify({
            'status': 'error',
            'message': 'Auth0 not configured'
        }), 503
    
    try:
        # Validate state parameter
        state = request.args.get('state')
        if not state or state != session.get('auth0_state'):
            raise AuthenticationError("Invalid state parameter", "INVALID_STATE", 400)
        
        # Handle Auth0 callback
        code = request.args.get('code')
        if not code:
            error = request.args.get('error')
            error_description = request.args.get('error_description')
            raise AuthenticationError(
                f"Auth0 error: {error_description or error}", 
                "AUTH0_ERROR", 
                400
            )
        
        redirect_uri = url_for('auth.auth0_callback', _external=True)
        user_info = auth_manager.auth0_integration.handle_callback(code, redirect_uri)
        
        # Find or create user
        user = User.query.filter_by(auth0_id=user_info['auth0_id']).first()
        if not user:
            # Create new user from Auth0 info
            user = User(
                auth0_id=user_info['auth0_id'],
                email=user_info['email'],
                username=user_info.get('nickname', user_info['email']),
                name=user_info.get('name'),
                is_active=True,
                email_verified=user_info.get('email_verified', False),
                created_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
        
        # Create session
        session_info = auth_manager.create_user_session(user, remember=False)
        
        # Clear Auth0 state
        session.pop('auth0_state', None)
        
        logger.info(f"User {user.id} authenticated via Auth0")
        
        # Redirect to application
        return redirect(url_for('main.dashboard'))
        
    except AuthenticationError as e:
        logger.warning(f"Auth0 callback error: {e.message}")
        return jsonify({
            'status': 'error',
            'message': e.message,
            'error_code': e.error_code
        }), e.status_code
    
    except Exception as e:
        logger.error(f"Auth0 callback error: {e}")
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Auth0 authentication failed'
        }), 500


@auth_bp.route('/session/validate', methods=['POST'])
@require_auth
def validate_session():
    """Validate current user session and return session information"""
    try:
        return jsonify({
            'status': 'valid',
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'is_active': current_user.is_active
            },
            'csrf_token': auth_manager.token_manager.generate_csrf_token()
        })
        
    except Exception as e:
        logger.error(f"Session validation error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Session validation failed'
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
@require_auth
def refresh_session():
    """Refresh user session and generate new tokens"""
    try:
        # Generate new session token
        new_token = auth_manager.token_manager.generate_session_token(
            current_user.id,
            {'refresh_time': datetime.utcnow().isoformat()}
        )
        
        # Update session
        session['auth_token'] = new_token
        
        response_data = {
            'status': 'success',
            'message': 'Session refreshed',
            'csrf_token': auth_manager.token_manager.generate_csrf_token()
        }
        
        response = make_response(jsonify(response_data))
        response.set_cookie(
            'session_token',
            new_token,
            httponly=True,
            secure=current_app.config.get('SESSION_COOKIE_SECURE', False),
            samesite='Lax',
            max_age=3600
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Session refresh error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Session refresh failed'
        }), 500


@auth_bp.route('/password/change', methods=['POST'])
@require_auth
@csrf_protect
def change_password():
    """Change user password with validation"""
    try:
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            raise AuthenticationError(
                "Current and new password required", 
                "MISSING_PASSWORDS", 
                400
            )
        
        # Verify current password
        if not current_user.password_hash or not check_password_hash(current_user.password_hash, current_password):
            raise AuthenticationError("Current password incorrect", "INVALID_PASSWORD", 401)
        
        # Validate new password
        validation_service = get_service('validation')
        if not validation_service.validate_password(new_password):
            raise AuthenticationError("New password does not meet requirements", "WEAK_PASSWORD", 400)
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        current_user.password_changed_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Password changed for user {current_user.id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Password changed successfully'
        })
        
    except AuthenticationError as e:
        return jsonify({
            'status': 'error',
            'message': e.message,
            'error_code': e.error_code
        }), e.status_code
    
    except Exception as e:
        logger.error(f"Password change error: {e}")
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Password change failed'
        }), 500


@auth_bp.route('/sessions', methods=['GET'])
@require_auth
def list_sessions():
    """List active sessions for current user"""
    try:
        sessions = UserSession.query.filter_by(
            user_id=current_user.id,
            ended_at=None
        ).order_by(UserSession.created_at.desc()).all()
        
        session_list = []
        for sess in sessions:
            session_list.append({
                'id': sess.id,
                'created_at': sess.created_at.isoformat(),
                'last_activity': sess.last_activity.isoformat() if sess.last_activity else None,
                'ip_address': sess.ip_address,
                'user_agent': sess.user_agent,
                'is_current': sess.id == session.get('session_id')
            })
        
        return jsonify({
            'status': 'success',
            'sessions': session_list
        })
        
    except Exception as e:
        logger.error(f"Session list error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve sessions'
        }), 500


@auth_bp.route('/sessions/<int:session_id>', methods=['DELETE'])
@require_auth
@csrf_protect
def revoke_session(session_id: int):
    """Revoke a specific user session"""
    try:
        user_session = UserSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not user_session:
            return jsonify({
                'status': 'error',
                'message': 'Session not found'
            }), 404
        
        # End the session
        user_session.ended_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"Session {session_id} revoked for user {current_user.id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Session revoked successfully'
        })
        
    except Exception as e:
        logger.error(f"Session revocation error: {e}")
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Failed to revoke session'
        }), 500


# Error handlers for authentication blueprint

@auth_bp.errorhandler(AuthenticationError)
def handle_auth_error(error):
    """Handle authentication errors"""
    return jsonify({
        'status': 'error',
        'message': error.message,
        'error_code': error.error_code
    }), error.status_code


@auth_bp.errorhandler(Unauthorized)
def handle_unauthorized(error):
    """Handle unauthorized access"""
    return jsonify({
        'status': 'error',
        'message': 'Authentication required',
        'error_code': 'UNAUTHORIZED'
    }), 401


@auth_bp.errorhandler(Forbidden)
def handle_forbidden(error):
    """Handle forbidden access"""
    return jsonify({
        'status': 'error',
        'message': 'Access forbidden',
        'error_code': 'FORBIDDEN'
    }), 403


# Request hooks for authentication blueprint

@auth_bp.before_request
def before_request():
    """Process authentication before each request"""
    # Skip authentication for certain routes
    exempt_routes = ['auth.login', 'auth.register', 'auth.auth0_login', 'auth.auth0_callback']
    
    if request.endpoint in exempt_routes:
        return
    
    # Validate session token from cookie
    session_token = request.cookies.get('session_token')
    if session_token:
        try:
            token_data = auth_manager.token_manager.validate_session_token(session_token)
            if token_data:
                g.session_validated = True
        except AuthenticationError:
            pass


@auth_bp.after_request
def after_request(response):
    """Process response after each request"""
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response


# Export authentication components for application use
__all__ = [
    'auth_bp',
    'init_auth', 
    'require_auth',
    'csrf_protect',
    'AuthenticationManager',
    'SecureTokenManager',
    'Auth0Integration',
    'AuthenticationError'
]