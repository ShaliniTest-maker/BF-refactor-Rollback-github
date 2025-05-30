"""
Authentication Service implementing Flask-Login session management, ItsDangerous secure token handling,
and user authentication workflows. This service replaces Node.js middleware authentication patterns
with Flask's Service Layer architecture while preserving all existing authentication functionality.

This service provides:
- Flask-Login 0.6.3 integration for user session management
- ItsDangerous 2.2+ cryptographic token generation and validation
- Express session & JWT logic mapping to Flask-Login patterns
- python-dotenv configuration loading for SECRET_KEY management
- Optional JWT integration with PyJWT or auth0-python SDK
- Authentication decorators replacing Express.js middleware patterns
- Service Layer pattern implementation with dependency injection
"""

import os
import jwt
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union, Tuple, List
from functools import wraps

from flask import Flask, current_app, request, session, jsonify, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

try:
    from auth0.v3.authentication import GetToken
    from auth0.v3.management import Auth0
    AUTH0_AVAILABLE = True
except ImportError:
    AUTH0_AVAILABLE = False

from services.base_service import BaseService
from models import User


class AuthenticationError(Exception):
    """Custom exception for authentication-related errors."""
    pass


class TokenError(Exception):
    """Custom exception for token-related errors."""
    pass


class SessionError(Exception):
    """Custom exception for session-related errors."""
    pass


class FlaskUser(UserMixin):
    """
    Flask-Login compatible user object that wraps the SQLAlchemy User model.
    Provides the required interface for Flask-Login session management.
    """
    
    def __init__(self, user_model: User):
        """
        Initialize FlaskUser with SQLAlchemy User model.
        
        Args:
            user_model: SQLAlchemy User model instance
        """
        self.user = user_model
        self.id = str(user_model.id)
    
    def get_id(self) -> str:
        """Return the user ID as required by Flask-Login."""
        return self.id
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated (Flask-Login interface)."""
        return True
    
    @property
    def is_active(self) -> bool:
        """Check if user account is active (Flask-Login interface)."""
        return getattr(self.user, 'is_active', True)
    
    @property
    def is_anonymous(self) -> bool:
        """Check if user is anonymous (Flask-Login interface)."""
        return False
    
    def get_roles(self) -> List[str]:
        """Get user roles for authorization."""
        return getattr(self.user, 'roles', [])
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.get_roles()


class AuthService(BaseService):
    """
    Authentication service implementing Flask-Login session management and ItsDangerous 
    secure token handling. Converts Node.js middleware authentication patterns to 
    Flask's Service Layer architecture.
    """
    
    def __init__(self, db_session: Session, app: Optional[Flask] = None):
        """
        Initialize AuthService with database session and optional Flask app.
        
        Args:
            db_session: SQLAlchemy database session
            app: Optional Flask application instance
        """
        super().__init__(db_session)
        self.app = app or current_app
        self.login_manager: Optional[LoginManager] = None
        self.serializer: Optional[URLSafeTimedSerializer] = None
        self._setup_login_manager()
        self._setup_serializer()
    
    def _setup_login_manager(self) -> None:
        """
        Configure Flask-Login manager with user loader and session protection.
        Implements Section 4.6.1.3 Flask-Login integration requirements.
        """
        try:
            self.login_manager = LoginManager()
            self.login_manager.init_app(self.app)
            
            # Configure session protection (equivalent to Express session security)
            self.login_manager.session_protection = "strong"
            self.login_manager.login_view = "auth.login"
            self.login_manager.login_message = "Please log in to access this page."
            self.login_manager.login_message_category = "info"
            
            # Register user loader callback
            @self.login_manager.user_loader
            def load_user(user_id: str) -> Optional[FlaskUser]:
                """
                User loader callback for Flask-Login.
                Replaces Node.js session user retrieval patterns.
                """
                return self._load_user_by_id(user_id)
            
            # Register request loader for token-based authentication
            @self.login_manager.request_loader
            def load_user_from_request(request) -> Optional[FlaskUser]:
                """
                Request loader callback for token-based authentication.
                Supports both API tokens and JWT tokens.
                """
                return self._load_user_from_request(request)
            
        except Exception as e:
            current_app.logger.error(f"Failed to setup LoginManager: {str(e)}")
            raise AuthenticationError(f"LoginManager setup failed: {str(e)}")
    
    def _setup_serializer(self) -> None:
        """
        Configure ItsDangerous serializer for secure token generation.
        Implements Section 4.6.1.3 ItsDangerous 2.2+ cryptographic requirements.
        """
        try:
            secret_key = self.app.config.get('SECRET_KEY')
            if not secret_key:
                raise AuthenticationError("SECRET_KEY not configured")
            
            # Initialize URLSafeTimedSerializer with enhanced security
            self.serializer = URLSafeTimedSerializer(
                secret_key=secret_key,
                salt='auth-service-salt'  # Additional salt for auth tokens
            )
            
        except Exception as e:
            current_app.logger.error(f"Failed to setup ItsDangerous serializer: {str(e)}")
            raise AuthenticationError(f"Token serializer setup failed: {str(e)}")
    
    def _load_user_by_id(self, user_id: str) -> Optional[FlaskUser]:
        """
        Load user by ID from database for Flask-Login.
        
        Args:
            user_id: User ID string
            
        Returns:
            FlaskUser instance or None if user not found
        """
        try:
            user = self.db_session.query(User).filter(User.id == int(user_id)).first()
            if user and getattr(user, 'is_active', True):
                return FlaskUser(user)
            return None
        except (ValueError, SQLAlchemyError) as e:
            current_app.logger.warning(f"Failed to load user {user_id}: {str(e)}")
            return None
    
    def _load_user_from_request(self, request) -> Optional[FlaskUser]:
        """
        Load user from request for token-based authentication.
        Supports API tokens, JWT tokens, and Authorization headers.
        
        Args:
            request: Flask request object
            
        Returns:
            FlaskUser instance or None if authentication fails
        """
        # Check Authorization header for Bearer token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            user = self._verify_jwt_token(token)
            if user:
                return user
        
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        if api_key:
            user = self._verify_api_key(api_key)
            if user:
                return user
        
        # Check for token in request parameters
        token = request.args.get('token') or request.form.get('token')
        if token:
            user = self._verify_secure_token(token)
            if user:
                return user
        
        return None
    
    def authenticate_user(self, email: str, password: str, remember: bool = False) -> Tuple[bool, Optional[FlaskUser], Optional[str]]:
        """
        Authenticate user with email and password using Flask-Login.
        Replaces Node.js passport authentication patterns.
        
        Args:
            email: User email address
            password: User password
            remember: Whether to remember user session
            
        Returns:
            Tuple of (success, user, error_message)
        """
        try:
            # Query user from database
            user = self.db_session.query(User).filter(User.email == email).first()
            
            if not user:
                current_app.logger.warning(f"Authentication attempt for non-existent user: {email}")
                return False, None, "Invalid email or password"
            
            # Check if user account is active
            if not getattr(user, 'is_active', True):
                current_app.logger.warning(f"Authentication attempt for inactive user: {email}")
                return False, None, "Account is deactivated"
            
            # Verify password hash
            if not self._verify_password(password, getattr(user, 'password_hash', '')):
                current_app.logger.warning(f"Failed password attempt for user: {email}")
                return False, None, "Invalid email or password"
            
            # Create FlaskUser wrapper and login
            flask_user = FlaskUser(user)
            login_success = login_user(flask_user, remember=remember)
            
            if login_success:
                # Update last login timestamp
                self._update_last_login(user)
                current_app.logger.info(f"Successful authentication for user: {email}")
                return True, flask_user, None
            else:
                current_app.logger.error(f"Flask-Login failed for user: {email}")
                return False, None, "Login failed"
        
        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error during authentication: {str(e)}")
            self.db_session.rollback()
            return False, None, "Authentication service unavailable"
        except Exception as e:
            current_app.logger.error(f"Unexpected error during authentication: {str(e)}")
            return False, None, "Authentication failed"
    
    def logout_user(self) -> bool:
        """
        Log out current user and clear session.
        
        Returns:
            True if logout successful, False otherwise
        """
        try:
            if current_user.is_authenticated:
                user_email = getattr(current_user.user, 'email', 'unknown')
                logout_user()
                current_app.logger.info(f"User logged out: {user_email}")
                return True
            return False
        except Exception as e:
            current_app.logger.error(f"Error during logout: {str(e)}")
            return False
    
    def generate_secure_token(self, user_id: int, purpose: str = 'auth', 
                            expires_in: int = 3600) -> str:
        """
        Generate secure token using ItsDangerous for various purposes.
        Implements Section 4.6.1.3 ItsDangerous token generation.
        
        Args:
            user_id: User ID
            purpose: Token purpose (auth, reset, verify, etc.)
            expires_in: Token expiration in seconds
            
        Returns:
            Secure token string
        """
        if not self.serializer:
            raise TokenError("Token serializer not initialized")
        
        try:
            payload = {
                'user_id': user_id,
                'purpose': purpose,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'nonce': secrets.token_hex(16)  # Prevent token reuse
            }
            
            token = self.serializer.dumps(payload)
            current_app.logger.debug(f"Generated {purpose} token for user {user_id}")
            return token
            
        except Exception as e:
            current_app.logger.error(f"Failed to generate token: {str(e)}")
            raise TokenError(f"Token generation failed: {str(e)}")
    
    def verify_secure_token(self, token: str, purpose: str = 'auth', 
                          max_age: int = 3600) -> Optional[Dict[str, Any]]:
        """
        Verify secure token using ItsDangerous.
        
        Args:
            token: Token to verify
            purpose: Expected token purpose
            max_age: Maximum token age in seconds
            
        Returns:
            Token payload if valid, None otherwise
        """
        if not self.serializer:
            raise TokenError("Token serializer not initialized")
        
        try:
            payload = self.serializer.loads(token, max_age=max_age)
            
            # Verify token purpose
            if payload.get('purpose') != purpose:
                current_app.logger.warning(f"Token purpose mismatch: expected {purpose}, got {payload.get('purpose')}")
                return None
            
            return payload
            
        except SignatureExpired:
            current_app.logger.warning("Token expired")
            return None
        except BadSignature:
            current_app.logger.warning("Invalid token signature")
            return None
        except Exception as e:
            current_app.logger.error(f"Token verification error: {str(e)}")
            return None
    
    def _verify_secure_token(self, token: str) -> Optional[FlaskUser]:
        """
        Verify secure token and return user if valid.
        
        Args:
            token: Token to verify
            
        Returns:
            FlaskUser instance or None
        """
        payload = self.verify_secure_token(token, purpose='auth')
        if payload and 'user_id' in payload:
            return self._load_user_by_id(str(payload['user_id']))
        return None
    
    def generate_jwt_token(self, user_id: int, expires_in: int = 3600) -> str:
        """
        Generate JWT token for API authentication.
        Implements optional JWT integration per Section 4.6.1.3.
        
        Args:
            user_id: User ID
            expires_in: Token expiration in seconds
            
        Returns:
            JWT token string
        """
        try:
            secret_key = self.app.config.get('SECRET_KEY')
            if not secret_key:
                raise TokenError("SECRET_KEY not configured for JWT")
            
            payload = {
                'user_id': user_id,
                'exp': datetime.now(timezone.utc) + timedelta(seconds=expires_in),
                'iat': datetime.now(timezone.utc),
                'iss': self.app.config.get('JWT_ISSUER', 'flask-auth-service'),
                'jti': secrets.token_hex(16)  # Unique token ID
            }
            
            token = jwt.encode(payload, secret_key, algorithm='HS256')
            current_app.logger.debug(f"Generated JWT token for user {user_id}")
            return token
            
        except Exception as e:
            current_app.logger.error(f"JWT generation error: {str(e)}")
            raise TokenError(f"JWT generation failed: {str(e)}")
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token and return payload.
        
        Args:
            token: JWT token to verify
            
        Returns:
            Token payload if valid, None otherwise
        """
        try:
            secret_key = self.app.config.get('SECRET_KEY')
            if not secret_key:
                raise TokenError("SECRET_KEY not configured for JWT")
            
            payload = jwt.decode(
                token, 
                secret_key, 
                algorithms=['HS256'],
                issuer=self.app.config.get('JWT_ISSUER', 'flask-auth-service')
            )
            
            return payload
            
        except jwt.ExpiredSignatureError:
            current_app.logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            current_app.logger.warning(f"Invalid JWT token: {str(e)}")
            return None
        except Exception as e:
            current_app.logger.error(f"JWT verification error: {str(e)}")
            return None
    
    def _verify_jwt_token(self, token: str) -> Optional[FlaskUser]:
        """
        Verify JWT token and return user if valid.
        
        Args:
            token: JWT token to verify
            
        Returns:
            FlaskUser instance or None
        """
        payload = self.verify_jwt_token(token)
        if payload and 'user_id' in payload:
            return self._load_user_by_id(str(payload['user_id']))
        return None
    
    def _verify_api_key(self, api_key: str) -> Optional[FlaskUser]:
        """
        Verify API key and return associated user.
        
        Args:
            api_key: API key to verify
            
        Returns:
            FlaskUser instance or None
        """
        try:
            # Hash the provided API key for secure comparison
            hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
            
            # Query user by API key hash
            user = self.db_session.query(User).filter(
                getattr(User, 'api_key_hash', None) == hashed_key
            ).first()
            
            if user and getattr(user, 'is_active', True):
                return FlaskUser(user)
            
            return None
            
        except (AttributeError, SQLAlchemyError) as e:
            current_app.logger.warning(f"API key verification error: {str(e)}")
            return None
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify password against hash using Werkzeug.
        
        Args:
            password: Plain text password
            password_hash: Stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            return check_password_hash(password_hash, password)
        except Exception as e:
            current_app.logger.error(f"Password verification error: {str(e)}")
            return False
    
    def hash_password(self, password: str) -> str:
        """
        Generate password hash using Werkzeug.
        
        Args:
            password: Plain text password
            
        Returns:
            Password hash
        """
        try:
            return generate_password_hash(password)
        except Exception as e:
            current_app.logger.error(f"Password hashing error: {str(e)}")
            raise AuthenticationError(f"Password hashing failed: {str(e)}")
    
    def _update_last_login(self, user: User) -> None:
        """
        Update user's last login timestamp.
        
        Args:
            user: User model instance
        """
        try:
            if hasattr(user, 'last_login'):
                user.last_login = datetime.now(timezone.utc)
                self.db_session.commit()
        except SQLAlchemyError as e:
            current_app.logger.warning(f"Failed to update last login: {str(e)}")
            self.db_session.rollback()
    
    def require_role(self, required_role: str):
        """
        Decorator to require specific role for route access.
        Replaces Node.js middleware role checking patterns.
        
        Args:
            required_role: Role name required for access
            
        Returns:
            Decorator function
        """
        def decorator(f):
            @wraps(f)
            @login_required
            def decorated_function(*args, **kwargs):
                if not current_user.is_authenticated:
                    return jsonify({'error': 'Authentication required'}), 401
                
                if not current_user.has_role(required_role):
                    current_app.logger.warning(
                        f"Access denied: User {getattr(current_user.user, 'email', 'unknown')} "
                        f"missing role {required_role}"
                    )
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def require_any_role(self, *roles: str):
        """
        Decorator to require any of the specified roles for route access.
        
        Args:
            roles: Role names, user must have at least one
            
        Returns:
            Decorator function
        """
        def decorator(f):
            @wraps(f)
            @login_required
            def decorated_function(*args, **kwargs):
                if not current_user.is_authenticated:
                    return jsonify({'error': 'Authentication required'}), 401
                
                user_roles = current_user.get_roles()
                if not any(role in user_roles for role in roles):
                    current_app.logger.warning(
                        f"Access denied: User {getattr(current_user.user, 'email', 'unknown')} "
                        f"missing required roles {roles}"
                    )
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def api_auth_required(self, f):
        """
        Decorator for API routes requiring authentication.
        Supports multiple authentication methods: session, JWT, API key.
        
        Args:
            f: Function to decorate
            
        Returns:
            Decorated function
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check session authentication first
            if current_user.is_authenticated:
                return f(*args, **kwargs)
            
            # Check token-based authentication
            user = self._load_user_from_request(request)
            if user:
                # Temporarily set user context for this request
                g.current_user = user
                return f(*args, **kwargs)
            
            # No valid authentication found
            return jsonify({'error': 'Authentication required'}), 401
        
        return decorated_function
    
    def get_current_user_id(self) -> Optional[int]:
        """
        Get current authenticated user ID.
        
        Returns:
            User ID if authenticated, None otherwise
        """
        if current_user.is_authenticated:
            return int(current_user.id)
        
        # Check for API authenticated user
        if hasattr(g, 'current_user') and g.current_user:
            return int(g.current_user.id)
        
        return None
    
    def is_authenticated(self) -> bool:
        """
        Check if current request is authenticated.
        
        Returns:
            True if authenticated, False otherwise
        """
        return (current_user.is_authenticated or 
                (hasattr(g, 'current_user') and g.current_user is not None))
    
    def setup_auth0_integration(self) -> Optional['Auth0']:
        """
        Setup Auth0 integration if credentials are available.
        Implements optional Auth0 integration per Section 4.6.1.3.
        
        Returns:
            Auth0 client instance or None if not configured
        """
        if not AUTH0_AVAILABLE:
            current_app.logger.warning("Auth0 Python SDK not available")
            return None
        
        try:
            domain = self.app.config.get('AUTH0_DOMAIN')
            client_id = self.app.config.get('AUTH0_CLIENT_ID')
            client_secret = self.app.config.get('AUTH0_CLIENT_SECRET')
            
            if not all([domain, client_id, client_secret]):
                current_app.logger.info("Auth0 configuration incomplete, skipping integration")
                return None
            
            # Setup Auth0 management client
            get_token = GetToken(domain)
            token = get_token.client_credentials(client_id, client_secret, f"https://{domain}/api/v2/")
            mgmt_api_token = token['access_token']
            
            auth0_client = Auth0(domain, mgmt_api_token)
            current_app.logger.info("Auth0 integration configured successfully")
            return auth0_client
            
        except Exception as e:
            current_app.logger.error(f"Auth0 setup error: {str(e)}")
            return None


def create_auth_service(db_session: Session, app: Optional[Flask] = None) -> AuthService:
    """
    Factory function to create AuthService instance.
    
    Args:
        db_session: SQLAlchemy database session
        app: Optional Flask application instance
        
    Returns:
        Configured AuthService instance
    """
    return AuthService(db_session, app)


# Authentication decorators for easy import and use
def login_required_api(f):
    """Convenience decorator for API routes requiring authentication."""
    def decorator(*args, **kwargs):
        from flask import current_app
        auth_service = current_app.auth_service
        return auth_service.api_auth_required(f)(*args, **kwargs)
    return decorator


def require_role_api(role: str):
    """Convenience decorator factory for role-based API access control."""
    def decorator(f):
        from flask import current_app
        auth_service = current_app.auth_service
        return auth_service.require_role(role)(f)
    return decorator