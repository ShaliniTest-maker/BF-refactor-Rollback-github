"""
Flask Authentication Blueprint

This module implements comprehensive Flask authentication decorators and session management,
converting Node.js authentication middleware to Flask's security architecture. It handles
user authentication flows, session management, and access control using ItsDangerous for
secure cookie protection.

Key Features:
- Flask-Login integration for session management
- ItsDangerous secure cookie signing and session protection
- Auth0 integration for external authentication
- CSRF protection using Flask-WTF
- Authentication decorators for route protection
- Password security utilities using Werkzeug
- Security monitoring and logging integration
- Comprehensive error handling and validation

This blueprint is critical for maintaining security posture during the Node.js to Flask
migration while providing enterprise-grade authentication capabilities.
"""

from functools import wraps
from typing import Dict, Any, Optional, Union, Callable
import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, session, current_app, redirect, url_for, flash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, 
    current_user, fresh_login_required
)
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_wtf.csrf import validate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, validators
from wtforms.validators import DataRequired, Email, Length

# Import authentication services and models
from src.auth.session_manager import SessionManager
from src.auth.auth0_integration import Auth0Integration
from src.auth.password_utils import PasswordUtils
from src.auth.csrf_protection import CSRFProtection
from src.auth.token_handler import TokenHandler
from src.auth.security_monitor import SecurityMonitor
from src.auth.decorators import require_auth, require_permission, require_role
from src.models.user import User
from src.models.session import UserSession
from src.services.user_service import UserService

# Create the authentication blueprint
auth_bp = Blueprint(
    'auth',
    __name__,
    url_prefix='/auth',
    static_folder='static',
    template_folder='templates'
)

# Initialize logger for authentication events
logger = logging.getLogger(__name__)

# Initialize authentication components
session_manager = SessionManager()
auth0_integration = Auth0Integration()
password_utils = PasswordUtils()
csrf_protection = CSRFProtection()
token_handler = TokenHandler()
security_monitor = SecurityMonitor()
user_service = UserService()

# Flask-Login configuration
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.refresh_view = 'auth.login'
login_manager.needs_refresh_message = 'To protect your account, please re-authenticate to access this page.'


class LoginForm(FlaskForm):
    """
    Login form with CSRF protection and validation.
    
    Implements Flask-WTF form validation with comprehensive field validation
    for secure user authentication while maintaining Node.js functionality parity.
    """
    username = StringField(
        'Username or Email',
        validators=[
            DataRequired(message='Username or email is required'),
            Length(min=3, max=254, message='Username must be between 3 and 254 characters')
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, message='Password must be at least 8 characters')
        ]
    )
    remember_me = BooleanField('Remember Me')


class RegisterForm(FlaskForm):
    """
    User registration form with comprehensive validation.
    
    Implements secure user registration with password strength validation,
    email verification, and CSRF protection.
    """
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(min=3, max=50, message='Username must be between 3 and 50 characters')
        ]
    )
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address'),
            Length(max=254, message='Email address too long')
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, message='Password must be at least 8 characters')
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Password confirmation is required'),
            validators.EqualTo('password', message='Passwords must match')
        ]
    )


class PasswordResetForm(FlaskForm):
    """
    Password reset form with security validation.
    
    Implements secure password reset functionality with token validation
    and comprehensive security monitoring.
    """
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Please enter a valid email address')
        ]
    )


class PasswordChangeForm(FlaskForm):
    """
    Password change form for authenticated users.
    
    Implements secure password change functionality with current password
    verification and new password validation.
    """
    current_password = PasswordField(
        'Current Password',
        validators=[
            DataRequired(message='Current password is required')
        ]
    )
    new_password = PasswordField(
        'New Password',
        validators=[
            DataRequired(message='New password is required'),
            Length(min=8, message='Password must be at least 8 characters')
        ]
    )
    confirm_password = PasswordField(
        'Confirm New Password',
        validators=[
            DataRequired(message='Password confirmation is required'),
            validators.EqualTo('new_password', message='Passwords must match')
        ]
    )


@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    """
    Flask-Login user loader function.
    
    Loads user from database using user ID for session management and
    authentication state restoration. This function is critical for
    Flask-Login session handling.
    
    Args:
        user_id: Unique user identifier
        
    Returns:
        User object if found, None otherwise
    """
    try:
        return user_service.get_user_by_id(int(user_id))
    except (ValueError, TypeError):
        logger.warning(f"Invalid user ID format in session: {user_id}")
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None


@auth_bp.before_request
def before_request() -> None:
    """
    Pre-request authentication processing.
    
    Implements Flask before_request handler to replace Express.js authentication
    middleware patterns. Handles session validation, CSRF protection, and
    security monitoring for all authentication-related requests.
    """
    # Log security events for monitoring
    security_monitor.log_request_event(
        request.endpoint,
        request.remote_addr,
        request.headers.get('User-Agent', 'Unknown'),
        current_user.get_id() if current_user.is_authenticated else None
    )
    
    # Validate session integrity
    if current_user.is_authenticated:
        session_valid = session_manager.validate_session(current_user.get_id())
        if not session_valid:
            logout_user()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))
    
    # Update session activity timestamp
    if current_user.is_authenticated:
        session_manager.update_session_activity(current_user.get_id())


@auth_bp.after_request
def after_request(response):
    """
    Post-request authentication processing.
    
    Implements Flask after_request handler for security monitoring,
    session cleanup, and audit logging.
    
    Args:
        response: Flask response object
        
    Returns:
        Modified Flask response object
    """
    # Log authentication events for security monitoring
    if hasattr(current_user, 'get_id') and current_user.is_authenticated:
        security_monitor.log_response_event(
            request.endpoint,
            response.status_code,
            current_user.get_id()
        )
    
    # Set security headers for enhanced protection
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    User authentication endpoint.
    
    Implements comprehensive user login functionality with Flask-Login integration,
    CSRF protection, security monitoring, and Auth0 fallback authentication.
    Maintains functional equivalence with Node.js authentication patterns.
    
    Returns:
        JSON response with authentication result and user data
    """
    # Redirect if user is already authenticated
    if current_user.is_authenticated:
        return jsonify({
            'success': True,
            'message': 'User already authenticated',
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email
            }
        }), 200
    
    if request.method == 'POST':
        try:
            # Validate CSRF token for POST requests
            csrf_protection.validate_csrf_token(request)
            
            # Parse request data
            data = request.get_json() or request.form
            username = data.get('username', '').strip()
            password = data.get('password', '')
            remember_me = bool(data.get('remember_me', False))
            
            # Validate input data
            form = LoginForm(data=data)
            if not form.validate():
                security_monitor.log_authentication_failure(
                    username,
                    'Form validation failed',
                    request.remote_addr
                )
                return jsonify({
                    'success': False,
                    'message': 'Invalid input data',
                    'errors': form.errors
                }), 400
            
            # Attempt user authentication
            user = user_service.authenticate_user(username, password)
            
            if user and user.is_active:
                # Create new session
                session_token = session_manager.create_session(
                    user.id,
                    remember_me=remember_me,
                    user_agent=request.headers.get('User-Agent', ''),
                    ip_address=request.remote_addr
                )
                
                # Log in user with Flask-Login
                login_success = login_user(user, remember=remember_me)
                
                if login_success:
                    # Log successful authentication
                    security_monitor.log_authentication_success(
                        user.username,
                        request.remote_addr,
                        session_token
                    )
                    
                    # Generate secure response with user data
                    response_data = {
                        'success': True,
                        'message': 'Authentication successful',
                        'user': {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email,
                            'roles': user.get_roles(),
                            'permissions': user.get_permissions()
                        },
                        'session_token': session_token,
                        'expires_at': session_manager.get_session_expiry(user.id).isoformat()
                    }
                    
                    return jsonify(response_data), 200
                else:
                    # Flask-Login failed
                    security_monitor.log_authentication_failure(
                        username,
                        'Flask-Login session creation failed',
                        request.remote_addr
                    )
                    return jsonify({
                        'success': False,
                        'message': 'Session creation failed'
                    }), 500
            else:
                # Authentication failed
                security_monitor.log_authentication_failure(
                    username,
                    'Invalid credentials',
                    request.remote_addr
                )
                return jsonify({
                    'success': False,
                    'message': 'Invalid username or password'
                }), 401
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            security_monitor.log_authentication_error(
                data.get('username', 'Unknown'),
                str(e),
                request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'Authentication service temporarily unavailable'
            }), 500
    
    # GET request - return login form or redirect info
    return jsonify({
        'csrf_token': csrf_protection.generate_csrf_token(),
        'auth0_login_url': auth0_integration.get_login_url(),
        'login_form_fields': {
            'username': 'required',
            'password': 'required',
            'remember_me': 'optional'
        }
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """
    User logout endpoint.
    
    Implements secure user logout with session cleanup, Flask-Login integration,
    and comprehensive security logging. Maintains session security throughout
    the logout process.
    
    Returns:
        JSON response confirming logout completion
    """
    try:
        # Validate CSRF token
        csrf_protection.validate_csrf_token(request)
        
        user_id = current_user.get_id()
        username = current_user.username
        
        # Cleanup user session
        session_manager.destroy_session(user_id)
        
        # Revoke any active tokens
        token_handler.revoke_user_tokens(user_id)
        
        # Log logout event
        security_monitor.log_logout_event(
            username,
            request.remote_addr,
            'User initiated logout'
        )
        
        # Logout user with Flask-Login
        logout_user()
        
        # Clear session data
        session.clear()
        
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        }), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        security_monitor.log_logout_error(
            current_user.username if current_user.is_authenticated else 'Unknown',
            str(e),
            request.remote_addr
        )
        return jsonify({
            'success': False,
            'message': 'Logout failed'
        }), 500


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    User registration endpoint.
    
    Implements secure user registration with comprehensive validation,
    password hashing, email verification, and security monitoring.
    Maintains functional equivalence with Node.js registration patterns.
    
    Returns:
        JSON response with registration result
    """
    try:
        # Validate CSRF token
        csrf_protection.validate_csrf_token(request)
        
        # Parse request data
        data = request.get_json() or request.form
        
        # Validate registration form
        form = RegisterForm(data=data)
        if not form.validate():
            return jsonify({
                'success': False,
                'message': 'Invalid registration data',
                'errors': form.errors
            }), 400
        
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Check if user already exists
        existing_user = user_service.get_user_by_username_or_email(username, email)
        if existing_user:
            security_monitor.log_registration_attempt(
                username,
                email,
                'User already exists',
                request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'Username or email already registered'
            }), 409
        
        # Validate password strength
        password_validation = password_utils.validate_password_strength(password)
        if not password_validation['is_valid']:
            return jsonify({
                'success': False,
                'message': 'Password does not meet security requirements',
                'password_requirements': password_validation['requirements']
            }), 400
        
        # Create new user account
        new_user = user_service.create_user(
            username=username,
            email=email,
            password=password
        )
        
        if new_user:
            # Log successful registration
            security_monitor.log_registration_success(
                username,
                email,
                request.remote_addr
            )
            
            # Generate email verification token if needed
            verification_token = token_handler.generate_email_verification_token(new_user.id)
            
            return jsonify({
                'success': True,
                'message': 'Registration successful',
                'user_id': new_user.id,
                'verification_required': True,
                'verification_token': verification_token
            }), 201
        else:
            return jsonify({
                'success': False,
                'message': 'Registration failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        security_monitor.log_registration_error(
            data.get('username', 'Unknown'),
            data.get('email', 'Unknown'),
            str(e),
            request.remote_addr
        )
        return jsonify({
            'success': False,
            'message': 'Registration service temporarily unavailable'
        }), 500


@auth_bp.route('/password-reset', methods=['POST'])
def password_reset():
    """
    Password reset request endpoint.
    
    Implements secure password reset functionality with email verification,
    token generation, and comprehensive security monitoring.
    
    Returns:
        JSON response with password reset status
    """
    try:
        # Validate CSRF token
        csrf_protection.validate_csrf_token(request)
        
        # Parse request data
        data = request.get_json() or request.form
        
        # Validate form data
        form = PasswordResetForm(data=data)
        if not form.validate():
            return jsonify({
                'success': False,
                'message': 'Invalid email address',
                'errors': form.errors
            }), 400
        
        email = data.get('email', '').strip().lower()
        
        # Find user by email
        user = user_service.get_user_by_email(email)
        
        if user:
            # Generate password reset token
            reset_token = token_handler.generate_password_reset_token(user.id)
            
            # Log password reset request
            security_monitor.log_password_reset_request(
                user.username,
                email,
                request.remote_addr
            )
            
            # In a real implementation, send email with reset token
            # For now, return the token (in production, this should be sent via email)
            return jsonify({
                'success': True,
                'message': 'Password reset instructions sent to your email',
                'reset_token': reset_token  # Remove this in production
            }), 200
        else:
            # Log failed reset attempt
            security_monitor.log_password_reset_failure(
                'Unknown',
                email,
                'User not found',
                request.remote_addr
            )
            
            # Return success message to prevent email enumeration
            return jsonify({
                'success': True,
                'message': 'Password reset instructions sent to your email'
            }), 200
            
    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Password reset service temporarily unavailable'
        }), 500


@auth_bp.route('/password-change', methods=['POST'])
@login_required
def password_change():
    """
    Password change endpoint for authenticated users.
    
    Implements secure password change functionality with current password
    verification and comprehensive security validation.
    
    Returns:
        JSON response with password change status
    """
    try:
        # Validate CSRF token
        csrf_protection.validate_csrf_token(request)
        
        # Parse request data
        data = request.get_json() or request.form
        
        # Validate form data
        form = PasswordChangeForm(data=data)
        if not form.validate():
            return jsonify({
                'success': False,
                'message': 'Invalid password change data',
                'errors': form.errors
            }), 400
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        # Verify current password
        if not user_service.verify_password(current_user.id, current_password):
            security_monitor.log_password_change_failure(
                current_user.username,
                'Invalid current password',
                request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            }), 401
        
        # Validate new password strength
        password_validation = password_utils.validate_password_strength(new_password)
        if not password_validation['is_valid']:
            return jsonify({
                'success': False,
                'message': 'New password does not meet security requirements',
                'password_requirements': password_validation['requirements']
            }), 400
        
        # Update password
        success = user_service.update_password(current_user.id, new_password)
        
        if success:
            # Log successful password change
            security_monitor.log_password_change_success(
                current_user.username,
                request.remote_addr
            )
            
            # Revoke all existing sessions except current
            session_manager.revoke_other_sessions(current_user.id)
            
            return jsonify({
                'success': True,
                'message': 'Password changed successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Password change failed'
            }), 500
            
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        security_monitor.log_password_change_error(
            current_user.username,
            str(e),
            request.remote_addr
        )
        return jsonify({
            'success': False,
            'message': 'Password change service temporarily unavailable'
        }), 500


@auth_bp.route('/verify-session', methods=['GET'])
@login_required
def verify_session():
    """
    Session verification endpoint.
    
    Implements session validation and user state verification for
    client applications requiring authentication status confirmation.
    
    Returns:
        JSON response with current user authentication status
    """
    try:
        # Validate current session
        session_valid = session_manager.validate_session(current_user.get_id())
        
        if session_valid:
            return jsonify({
                'success': True,
                'authenticated': True,
                'user': {
                    'id': current_user.id,
                    'username': current_user.username,
                    'email': current_user.email,
                    'roles': current_user.get_roles(),
                    'permissions': current_user.get_permissions()
                },
                'session_expires_at': session_manager.get_session_expiry(current_user.get_id()).isoformat()
            }), 200
        else:
            logout_user()
            return jsonify({
                'success': True,
                'authenticated': False,
                'message': 'Session expired'
            }), 200
            
    except Exception as e:
        logger.error(f"Session verification error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Session verification failed'
        }), 500


@auth_bp.route('/auth0/callback', methods=['GET', 'POST'])
def auth0_callback():
    """
    Auth0 authentication callback endpoint.
    
    Handles Auth0 authentication callback processing with token validation,
    user synchronization, and session creation.
    
    Returns:
        Redirect to application or JSON response with authentication result
    """
    try:
        # Process Auth0 callback
        auth_result = auth0_integration.handle_callback(request)
        
        if auth_result['success']:
            user_info = auth_result['user_info']
            
            # Synchronize user with local database
            user = user_service.sync_auth0_user(user_info)
            
            if user:
                # Create session and log in user
                session_token = session_manager.create_session(
                    user.id,
                    remember_me=False,
                    user_agent=request.headers.get('User-Agent', ''),
                    ip_address=request.remote_addr
                )
                
                login_user(user, remember=False)
                
                # Log successful Auth0 authentication
                security_monitor.log_auth0_authentication_success(
                    user.username,
                    user_info.get('sub'),
                    request.remote_addr
                )
                
                # Return success response
                return jsonify({
                    'success': True,
                    'message': 'Auth0 authentication successful',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email
                    }
                }), 200
            else:
                return jsonify({
                    'success': False,
                    'message': 'User synchronization failed'
                }), 500
        else:
            security_monitor.log_auth0_authentication_failure(
                'Unknown',
                auth_result.get('error', 'Unknown error'),
                request.remote_addr
            )
            return jsonify({
                'success': False,
                'message': 'Auth0 authentication failed',
                'error': auth_result.get('error')
            }), 401
            
    except Exception as e:
        logger.error(f"Auth0 callback error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Auth0 authentication service error'
        }), 500


# Export authentication decorators for use in other blueprints
__all__ = [
    'auth_bp',
    'login_manager',
    'require_auth',
    'require_permission', 
    'require_role',
    'LoginForm',
    'RegisterForm',
    'PasswordResetForm',
    'PasswordChangeForm'
]


def init_auth(app):
    """
    Initialize authentication blueprint with Flask application.
    
    Configures Flask-Login, registers authentication blueprint, and
    sets up authentication infrastructure for the Flask application.
    
    Args:
        app: Flask application instance
    """
    # Initialize Flask-Login with app
    login_manager.init_app(app)
    
    # Initialize authentication services
    session_manager.init_app(app)
    auth0_integration.init_app(app)
    csrf_protection.init_app(app)
    token_handler.init_app(app)
    security_monitor.init_app(app)
    
    # Register authentication blueprint
    app.register_blueprint(auth_bp)
    
    logger.info("Authentication blueprint initialized successfully")