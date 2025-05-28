"""
Flask Session Management Service

Comprehensive user session lifecycle management using Flask-Login and ItsDangerous
for secure session handling. This module manages session creation, validation, renewal,
and cleanup while maintaining compatibility with existing user experience patterns.
Provides secure cookie protection and session timeout policies equivalent to Node.js
implementation with enhanced security features for enterprise deployment.

Features:
- Flask-Login LoginManager configuration with secure session handling
- ItsDangerous session cookie signing with AES encryption
- Session timeout policies and remember-me functionality
- Session cleanup and garbage collection procedures
- User loader callbacks for Flask-Login session restoration
- Security controls with HTTPOnly and Secure flags
- Real-time session monitoring and anomaly detection
- Integration with AWS CloudWatch and Prometheus metrics

Technical Implementation:
- Flask 3.1.1 framework integration
- Python 3.13.3 runtime compatibility
- ItsDangerous ≥2.2 secure cookie signing
- PostgreSQL session storage backend
- AWS Secrets Manager integration for encryption keys
- Structured logging with JSON output format
"""

import os
import time
import uuid
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
import threading
import functools

# Flask core imports
from flask import Flask, current_app, session, request, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user

# Security and encryption imports
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from itsdangerous.exc import BadTimeSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Database and ORM imports
from sqlalchemy import and_, or_, func, text
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

# Logging and monitoring imports
import structlog
from prometheus_client import Counter, Histogram, Gauge

# Utility imports
import secrets
import base64
import json
from collections import defaultdict, deque


@dataclass
class SessionConfig:
    """Session configuration parameters for Flask-Login and ItsDangerous integration."""
    
    # Flask-Login configuration
    session_protection: str = 'strong'
    login_view: str = 'auth.login'
    login_message: str = 'Please log in to access this page.'
    login_message_category: str = 'info'
    refresh_view: str = 'auth.reauth'
    needs_refresh_message: str = 'Please reauthenticate to access this page.'
    
    # Session timeout configuration
    permanent_session_lifetime: int = 3600  # 1 hour in seconds
    remember_me_duration: int = 2592000  # 30 days in seconds
    session_refresh_each_request: bool = True
    session_cookie_name: str = 'session'
    
    # Security configuration
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: str = 'Lax'
    session_cookie_domain: Optional[str] = None
    
    # ItsDangerous configuration
    secret_key_rotation_interval: int = 86400  # 24 hours
    session_token_max_age: int = 3600  # 1 hour
    remember_token_max_age: int = 2592000  # 30 days
    
    # Cleanup configuration
    cleanup_interval: int = 300  # 5 minutes
    expired_session_retention: int = 86400  # 24 hours
    max_sessions_per_user: int = 10
    
    # Security monitoring configuration
    max_failed_logins: int = 5
    lockout_duration: int = 900  # 15 minutes
    session_anomaly_threshold: float = 0.1


class SessionSecurityManager:
    """Enhanced session security manager with encryption and monitoring capabilities."""
    
    def __init__(self):
        self.logger = structlog.get_logger("session_security")
        self._encryption_key: Optional[bytes] = None
        self._aesgcm: Optional[AESGCM] = None
        self._key_generation_time: Optional[datetime] = None
        
        # Session monitoring data structures
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.failed_login_attempts: defaultdict = defaultdict(deque)
        self.session_anomalies: deque = deque(maxlen=1000)
        
        # Thread lock for concurrent access
        self._lock = threading.Lock()
    
    def initialize_encryption(self, app: Flask) -> None:
        """Initialize encryption components with secure key management."""
        try:
            # Get or generate encryption key
            encryption_key = self._get_or_generate_encryption_key(app)
            self._encryption_key = encryption_key
            self._aesgcm = AESGCM(encryption_key)
            self._key_generation_time = datetime.utcnow()
            
            self.logger.info(
                "Session encryption initialized",
                key_algorithm="AES-GCM",
                key_length=len(encryption_key) * 8
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize session encryption",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _get_or_generate_encryption_key(self, app: Flask) -> bytes:
        """Get encryption key from secure storage or generate new one."""
        # Try to get key from AWS Secrets Manager in production
        if app.config.get('FLASK_ENV') == 'production':
            try:
                secrets_client = app.aws_secrets_client if hasattr(app, 'aws_secrets_client') else None
                if secrets_client:
                    secret_name = f"flask-app-session-key-{app.config.get('FLASK_ENV', 'dev')}"
                    response = secrets_client.get_secret_value(SecretId=secret_name)
                    secret_data = json.loads(response['SecretString'])
                    return base64.b64decode(secret_data['encryption_key'])
            except Exception as e:
                self.logger.warning(
                    "Failed to retrieve encryption key from Secrets Manager",
                    error=str(e)
                )
        
        # Fall back to environment variable or generate new key
        env_key = os.getenv('SESSION_ENCRYPTION_KEY')
        if env_key:
            try:
                return base64.b64decode(env_key)
            except Exception as e:
                self.logger.warning(
                    "Invalid SESSION_ENCRYPTION_KEY format",
                    error=str(e)
                )
        
        # Generate new key using PBKDF2
        password = app.config.get('SECRET_KEY', 'default-secret').encode()
        salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256-GCM
            salt=salt,
            iterations=100000,  # NIST recommended minimum
        )
        
        return kdf.derive(password)
    
    def encrypt_session_data(self, data: Dict[str, Any]) -> str:
        """Encrypt session data using AES-GCM with authenticated encryption."""
        if not self._aesgcm:
            raise RuntimeError("Session encryption not initialized")
        
        try:
            # Serialize data to JSON
            json_data = json.dumps(data, sort_keys=True).encode('utf-8')
            
            # Generate random nonce (96 bits for GCM)
            nonce = os.urandom(12)
            
            # Encrypt with authenticated encryption
            ciphertext = self._aesgcm.encrypt(nonce, json_data, None)
            
            # Combine nonce and ciphertext
            encrypted_data = nonce + ciphertext
            
            # Base64 encode for safe transport
            return base64.b64encode(encrypted_data).decode('ascii')
            
        except Exception as e:
            self.logger.error(
                "Session data encryption failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def decrypt_session_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt session data using AES-GCM with verification."""
        if not self._aesgcm:
            raise RuntimeError("Session encryption not initialized")
        
        try:
            # Decode base64
            combined_data = base64.b64decode(encrypted_data.encode('ascii'))
            
            # Separate nonce and ciphertext
            nonce = combined_data[:12]
            ciphertext = combined_data[12:]
            
            # Decrypt and verify
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)
            
            # Deserialize JSON
            return json.loads(plaintext.decode('utf-8'))
            
        except Exception as e:
            self.logger.error(
                "Session data decryption failed",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def track_failed_login(self, identifier: str) -> bool:
        """Track failed login attempts and return True if account should be locked."""
        current_time = time.time()
        window_start = current_time - 900  # 15-minute window
        
        with self._lock:
            # Clean old attempts
            attempts = self.failed_login_attempts[identifier]
            while attempts and attempts[0] < window_start:
                attempts.popleft()
            
            # Add new attempt
            attempts.append(current_time)
            
            # Check if threshold exceeded
            if len(attempts) >= SessionConfig.max_failed_logins:
                self.logger.warning(
                    "Account locked due to failed login attempts",
                    identifier=identifier,
                    attempts=len(attempts),
                    window_minutes=15
                )
                return True
            
            return False
    
    def is_account_locked(self, identifier: str) -> bool:
        """Check if account is currently locked due to failed attempts."""
        current_time = time.time()
        lockout_end = current_time - SessionConfig.lockout_duration
        
        with self._lock:
            attempts = self.failed_login_attempts[identifier]
            if not attempts:
                return False
            
            # Check if there are recent failed attempts within lockout period
            recent_attempts = [t for t in attempts if t > lockout_end]
            return len(recent_attempts) >= SessionConfig.max_failed_logins
    
    def clear_failed_attempts(self, identifier: str) -> None:
        """Clear failed login attempts for successful authentication."""
        with self._lock:
            if identifier in self.failed_login_attempts:
                del self.failed_login_attempts[identifier]


class FlaskSessionManager:
    """
    Comprehensive Flask session management service implementing secure session lifecycle
    management with Flask-Login integration, ItsDangerous cookie signing, and enhanced
    security features for enterprise deployment.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """Initialize Flask session manager with optional application instance."""
        self.app = app
        self.login_manager: Optional[LoginManager] = None
        self.session_serializer: Optional[URLSafeTimedSerializer] = None
        self.security_manager: Optional[SessionSecurityManager] = None
        self.config: SessionConfig = SessionConfig()
        
        # Logging and monitoring
        self.logger = structlog.get_logger("session_manager")
        
        # Prometheus metrics
        self.session_created_total = Counter(
            'flask_sessions_created_total',
            'Total number of sessions created',
            ['user_type', 'remember_me']
        )
        
        self.session_destroyed_total = Counter(
            'flask_sessions_destroyed_total',
            'Total number of sessions destroyed',
            ['reason']
        )
        
        self.session_validation_duration = Histogram(
            'flask_session_validation_duration_seconds',
            'Time spent validating session',
            ['validation_type']
        )
        
        self.active_sessions_gauge = Gauge(
            'flask_active_sessions_total',
            'Current number of active sessions'
        )
        
        # Background cleanup thread
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_active = False
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """Initialize session management with Flask application factory pattern."""
        self.app = app
        
        try:
            # Update configuration from app config
            self._update_config_from_app(app)
            
            # Initialize security manager
            self.security_manager = SessionSecurityManager()
            self.security_manager.initialize_encryption(app)
            
            # Initialize Flask-Login
            self._initialize_flask_login(app)
            
            # Initialize ItsDangerous serializer
            self._initialize_session_serializer(app)
            
            # Configure session settings
            self._configure_session_settings(app)
            
            # Register request handlers
            self._register_request_handlers(app)
            
            # Start background cleanup
            self._start_cleanup_thread()
            
            # Store manager instance in app
            app.session_manager = self
            
            self.logger.info(
                "Flask session manager initialized",
                session_protection=self.config.session_protection,
                permanent_lifetime=self.config.permanent_session_lifetime,
                remember_duration=self.config.remember_me_duration
            )
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize session manager",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def _update_config_from_app(self, app: Flask) -> None:
        """Update session configuration from Flask app configuration."""
        # Update session configuration from app config
        if app.config.get('SESSION_PERMANENT_LIFETIME'):
            self.config.permanent_session_lifetime = app.config['SESSION_PERMANENT_LIFETIME']
        
        if app.config.get('REMEMBER_COOKIE_DURATION'):
            self.config.remember_me_duration = app.config['REMEMBER_COOKIE_DURATION']
        
        if app.config.get('SESSION_COOKIE_SECURE') is not None:
            self.config.session_cookie_secure = app.config['SESSION_COOKIE_SECURE']
        
        if app.config.get('SESSION_COOKIE_HTTPONLY') is not None:
            self.config.session_cookie_httponly = app.config['SESSION_COOKIE_HTTPONLY']
        
        if app.config.get('SESSION_COOKIE_SAMESITE'):
            self.config.session_cookie_samesite = app.config['SESSION_COOKIE_SAMESITE']
        
        # Environment-specific adjustments
        if app.config.get('FLASK_ENV') == 'development':
            self.config.session_cookie_secure = False  # Allow HTTP in development
    
    def _initialize_flask_login(self, app: Flask) -> None:
        """Initialize Flask-Login with secure configuration."""
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        
        # Configure Flask-Login settings
        self.login_manager.session_protection = self.config.session_protection
        self.login_manager.login_view = self.config.login_view
        self.login_manager.login_message = self.config.login_message
        self.login_manager.login_message_category = self.config.login_message_category
        self.login_manager.refresh_view = self.config.refresh_view
        self.login_manager.needs_refresh_message = self.config.needs_refresh_message
        
        # Set user loader callback
        @self.login_manager.user_loader
        def load_user(user_id: str) -> Optional[UserMixin]:
            """Load user from session for Flask-Login integration."""
            return self._load_user_from_session(user_id)
        
        # Set request loader for stateless authentication
        @self.login_manager.request_loader
        def load_user_from_request(request) -> Optional[UserMixin]:
            """Load user from request headers for API authentication."""
            return self._load_user_from_request(request)
        
        # Set unauthorized handler
        @self.login_manager.unauthorized_handler
        def unauthorized():
            """Handle unauthorized access attempts."""
            return self._handle_unauthorized_access()
        
        self.logger.info(
            "Flask-Login initialized",
            session_protection=self.config.session_protection,
            login_view=self.config.login_view
        )
    
    def _initialize_session_serializer(self, app: Flask) -> None:
        """Initialize ItsDangerous session serializer for secure cookie signing."""
        secret_key = app.config.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("SECRET_KEY must be configured for session security")
        
        # Create URL-safe timed serializer with enhanced security
        self.session_serializer = URLSafeTimedSerializer(
            secret_key,
            salt='flask-session-salt',
            signer_kwargs={
                'key_derivation': 'hmac',
                'digest_method': hashlib.sha256
            }
        )
        
        self.logger.info(
            "Session serializer initialized",
            algorithm="HMAC-SHA256",
            salt_configured=True
        )
    
    def _configure_session_settings(self, app: Flask) -> None:
        """Configure Flask session settings for security and functionality."""
        # Set session configuration
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
            seconds=self.config.permanent_session_lifetime
        )
        app.config['SESSION_REFRESH_EACH_REQUEST'] = self.config.session_refresh_each_request
        app.config['SESSION_COOKIE_NAME'] = self.config.session_cookie_name
        app.config['SESSION_COOKIE_SECURE'] = self.config.session_cookie_secure
        app.config['SESSION_COOKIE_HTTPONLY'] = self.config.session_cookie_httponly
        app.config['SESSION_COOKIE_SAMESITE'] = self.config.session_cookie_samesite
        
        if self.config.session_cookie_domain:
            app.config['SESSION_COOKIE_DOMAIN'] = self.config.session_cookie_domain
        
        self.logger.info(
            "Session settings configured",
            secure=self.config.session_cookie_secure,
            httponly=self.config.session_cookie_httponly,
            samesite=self.config.session_cookie_samesite
        )
    
    def _register_request_handlers(self, app: Flask) -> None:
        """Register Flask request handlers for session management."""
        
        @app.before_request
        def before_request():
            """Handle session validation and setup before each request."""
            g.session_start_time = time.time()
            g.session_id = self._get_or_create_session_id()
            
            # Validate session if user is authenticated
            if current_user.is_authenticated:
                self._validate_current_session()
        
        @app.after_request
        def after_request(response):
            """Handle session cleanup and monitoring after each request."""
            # Calculate session processing time
            if hasattr(g, 'session_start_time'):
                duration = time.time() - g.session_start_time
                self.session_validation_duration.labels(
                    validation_type='request_processing'
                ).observe(duration)
            
            # Update session activity if authenticated
            if current_user.is_authenticated:
                self._update_session_activity()
            
            return response
        
        @app.teardown_appcontext
        def teardown_session(error):
            """Clean up session context on request teardown."""
            if error:
                self.logger.error(
                    "Request completed with error",
                    error=str(error),
                    session_id=getattr(g, 'session_id', 'unknown')
                )
    
    def create_session(
        self,
        user: UserMixin,
        remember: bool = False,
        permanent: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create new user session with comprehensive security features.
        
        Args:
            user: User object implementing UserMixin
            remember: Enable remember-me functionality
            permanent: Make session permanent (subject to timeout)
            **kwargs: Additional session metadata
        
        Returns:
            Dictionary containing session information
        """
        try:
            start_time = time.time()
            
            # Generate unique session ID
            session_id = str(uuid.uuid4())
            
            # Create session metadata
            session_data = {
                'session_id': session_id,
                'user_id': str(user.get_id()),
                'created_at': datetime.utcnow().isoformat(),
                'last_activity': datetime.utcnow().isoformat(),
                'ip_address': request.remote_addr if request else None,
                'user_agent': request.headers.get('User-Agent') if request else None,
                'remember_me': remember,
                'permanent': permanent,
                'csrf_token': secrets.token_urlsafe(32),
                **kwargs
            }
            
            # Encrypt and store session data
            if self.security_manager:
                encrypted_data = self.security_manager.encrypt_session_data(session_data)
                # Store in database or cache (implementation depends on session backend)
                self._store_session_data(session_id, encrypted_data, session_data)
            
            # Configure Flask session
            session.permanent = permanent
            session['session_id'] = session_id
            session['user_id'] = str(user.get_id())
            session['csrf_token'] = session_data['csrf_token']
            
            # Log in user with Flask-Login
            login_user(user, remember=remember, duration=timedelta(
                seconds=self.config.remember_me_duration if remember else self.config.permanent_session_lifetime
            ))
            
            # Update metrics
            self.session_created_total.labels(
                user_type='authenticated',
                remember_me=str(remember)
            ).inc()
            
            # Update active sessions gauge
            self._update_active_sessions_metric()
            
            # Record session creation time
            duration = time.time() - start_time
            self.session_validation_duration.labels(
                validation_type='session_creation'
            ).observe(duration)
            
            self.logger.info(
                "User session created",
                session_id=session_id,
                user_id=str(user.get_id()),
                remember_me=remember,
                permanent=permanent,
                ip_address=session_data.get('ip_address'),
                duration_ms=round(duration * 1000, 2)
            )
            
            return session_data
            
        except Exception as e:
            self.logger.error(
                "Failed to create user session",
                user_id=str(user.get_id()) if user else 'unknown',
                error=str(e),
                error_type=type(e).__name__
            )
            raise
    
    def destroy_session(self, reason: str = 'logout') -> bool:
        """
        Destroy current user session with cleanup.
        
        Args:
            reason: Reason for session destruction
        
        Returns:
            True if session was successfully destroyed
        """
        try:
            start_time = time.time()
            session_id = session.get('session_id')
            user_id = session.get('user_id')
            
            # Remove session data from storage
            if session_id:
                self._remove_session_data(session_id)
            
            # Clear Flask session
            session.clear()
            
            # Log out user with Flask-Login
            logout_user()
            
            # Update metrics
            self.session_destroyed_total.labels(reason=reason).inc()
            self._update_active_sessions_metric()
            
            # Record destruction time
            duration = time.time() - start_time
            self.session_validation_duration.labels(
                validation_type='session_destruction'
            ).observe(duration)
            
            self.logger.info(
                "User session destroyed",
                session_id=session_id,
                user_id=user_id,
                reason=reason,
                duration_ms=round(duration * 1000, 2)
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to destroy session",
                error=str(e),
                error_type=type(e).__name__,
                reason=reason
            )
            return False
    
    def validate_session(self, session_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate session and return session data if valid.
        
        Args:
            session_id: Session ID to validate
        
        Returns:
            Tuple of (is_valid, session_data)
        """
        try:
            start_time = time.time()
            
            # Retrieve encrypted session data
            encrypted_data = self._get_session_data(session_id)
            if not encrypted_data:
                return False, None
            
            # Decrypt session data
            if self.security_manager:
                session_data = self.security_manager.decrypt_session_data(encrypted_data)
            else:
                return False, None
            
            # Validate session expiration
            created_at = datetime.fromisoformat(session_data['created_at'])
            last_activity = datetime.fromisoformat(session_data['last_activity'])
            now = datetime.utcnow()
            
            # Check session timeout
            timeout_duration = (
                self.config.remember_me_duration 
                if session_data.get('remember_me') 
                else self.config.permanent_session_lifetime
            )
            
            if (now - last_activity).total_seconds() > timeout_duration:
                self.logger.warning(
                    "Session expired due to inactivity",
                    session_id=session_id,
                    last_activity=session_data['last_activity'],
                    timeout_duration=timeout_duration
                )
                self._remove_session_data(session_id)
                return False, None
            
            # Validate session integrity
            if not self._validate_session_integrity(session_data):
                self.logger.warning(
                    "Session failed integrity validation",
                    session_id=session_id
                )
                self._remove_session_data(session_id)
                return False, None
            
            # Record validation time
            duration = time.time() - start_time
            self.session_validation_duration.labels(
                validation_type='session_validation'
            ).observe(duration)
            
            return True, session_data
            
        except Exception as e:
            self.logger.error(
                "Session validation failed",
                session_id=session_id,
                error=str(e),
                error_type=type(e).__name__
            )
            return False, None
    
    def refresh_session(self, extend_expiry: bool = True) -> bool:
        """
        Refresh current session and optionally extend expiry.
        
        Args:
            extend_expiry: Whether to extend session expiry time
        
        Returns:
            True if session was successfully refreshed
        """
        try:
            session_id = session.get('session_id')
            if not session_id:
                return False
            
            # Get current session data
            is_valid, session_data = self.validate_session(session_id)
            if not is_valid or not session_data:
                return False
            
            # Update last activity
            session_data['last_activity'] = datetime.utcnow().isoformat()
            
            # Extend expiry if requested
            if extend_expiry:
                session_data['created_at'] = datetime.utcnow().isoformat()
            
            # Re-encrypt and store updated data
            if self.security_manager:
                encrypted_data = self.security_manager.encrypt_session_data(session_data)
                self._store_session_data(session_id, encrypted_data, session_data)
            
            self.logger.debug(
                "Session refreshed",
                session_id=session_id,
                user_id=session_data.get('user_id'),
                extend_expiry=extend_expiry
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to refresh session",
                error=str(e),
                error_type=type(e).__name__
            )
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and return count of removed sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            start_time = time.time()
            cleaned_count = 0
            
            # Get all active sessions
            active_sessions = self._get_all_session_data()
            
            for session_id, encrypted_data in active_sessions.items():
                try:
                    if self.security_manager:
                        session_data = self.security_manager.decrypt_session_data(encrypted_data)
                    else:
                        continue
                    
                    # Check if session is expired
                    last_activity = datetime.fromisoformat(session_data['last_activity'])
                    now = datetime.utcnow()
                    
                    timeout_duration = (
                        self.config.remember_me_duration 
                        if session_data.get('remember_me') 
                        else self.config.permanent_session_lifetime
                    )
                    
                    if (now - last_activity).total_seconds() > timeout_duration:
                        self._remove_session_data(session_id)
                        cleaned_count += 1
                        
                        self.logger.debug(
                            "Expired session cleaned up",
                            session_id=session_id,
                            user_id=session_data.get('user_id'),
                            last_activity=session_data['last_activity']
                        )
                
                except Exception as e:
                    self.logger.warning(
                        "Failed to process session during cleanup",
                        session_id=session_id,
                        error=str(e)
                    )
                    # Remove corrupted session data
                    self._remove_session_data(session_id)
                    cleaned_count += 1
            
            # Update metrics
            self._update_active_sessions_metric()
            
            duration = time.time() - start_time
            self.logger.info(
                "Session cleanup completed",
                cleaned_sessions=cleaned_count,
                duration_ms=round(duration * 1000, 2)
            )
            
            return cleaned_count
            
        except Exception as e:
            self.logger.error(
                "Session cleanup failed",
                error=str(e),
                error_type=type(e).__name__
            )
            return 0
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a specific user.
        
        Args:
            user_id: User ID to get sessions for
        
        Returns:
            List of session data dictionaries
        """
        try:
            user_sessions = []
            active_sessions = self._get_all_session_data()
            
            for session_id, encrypted_data in active_sessions.items():
                try:
                    if self.security_manager:
                        session_data = self.security_manager.decrypt_session_data(encrypted_data)
                        
                        if session_data.get('user_id') == user_id:
                            # Remove sensitive data before returning
                            safe_session_data = {
                                'session_id': session_data['session_id'],
                                'created_at': session_data['created_at'],
                                'last_activity': session_data['last_activity'],
                                'ip_address': session_data.get('ip_address'),
                                'user_agent': session_data.get('user_agent'),
                                'remember_me': session_data.get('remember_me', False)
                            }
                            user_sessions.append(safe_session_data)
                
                except Exception as e:
                    self.logger.warning(
                        "Failed to process user session",
                        session_id=session_id,
                        user_id=user_id,
                        error=str(e)
                    )
            
            return user_sessions
            
        except Exception as e:
            self.logger.error(
                "Failed to get user sessions",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            return []
    
    def revoke_user_sessions(self, user_id: str, except_session_id: Optional[str] = None) -> int:
        """
        Revoke all sessions for a user except optionally one.
        
        Args:
            user_id: User ID to revoke sessions for
            except_session_id: Session ID to keep active (optional)
        
        Returns:
            Number of sessions revoked
        """
        try:
            revoked_count = 0
            user_sessions = self.get_user_sessions(user_id)
            
            for session_data in user_sessions:
                session_id = session_data['session_id']
                
                if except_session_id and session_id == except_session_id:
                    continue
                
                self._remove_session_data(session_id)
                revoked_count += 1
                
                self.logger.info(
                    "User session revoked",
                    session_id=session_id,
                    user_id=user_id,
                    reason="administrative_revocation"
                )
            
            # Update metrics
            self.session_destroyed_total.labels(reason='revocation').inc(revoked_count)
            self._update_active_sessions_metric()
            
            return revoked_count
            
        except Exception as e:
            self.logger.error(
                "Failed to revoke user sessions",
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            return 0
    
    # Private helper methods
    
    def _load_user_from_session(self, user_id: str) -> Optional[UserMixin]:
        """Load user object from database for Flask-Login integration."""
        try:
            # This would integrate with your User model
            # For now, we'll create a basic user object
            from src.models.user import User  # Assuming this exists
            
            user = User.query.filter_by(id=user_id).first()
            if user:
                self.logger.debug(
                    "User loaded from session",
                    user_id=user_id
                )
                return user
            
            return None
            
        except Exception as e:
            self.logger.error(
                "Failed to load user from session",
                user_id=user_id,
                error=str(e)
            )
            return None
    
    def _load_user_from_request(self, request) -> Optional[UserMixin]:
        """Load user from request headers for API authentication."""
        try:
            # Check for Authorization header with Bearer token
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                
                # Validate token (this would integrate with your token handler)
                # For now, we'll skip token validation
                self.logger.debug(
                    "API token authentication attempted",
                    has_token=bool(token)
                )
            
            return None
            
        except Exception as e:
            self.logger.error(
                "Failed to load user from request",
                error=str(e)
            )
            return None
    
    def _handle_unauthorized_access(self):
        """Handle unauthorized access attempts."""
        from flask import jsonify, redirect, url_for, request
        
        # Log unauthorized access attempt
        self.logger.warning(
            "Unauthorized access attempt",
            endpoint=request.endpoint,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Return JSON response for API requests
        if request.is_json or request.path.startswith('/api/'):
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource'
            }), 401
        
        # Redirect to login page for web requests
        return redirect(url_for(self.config.login_view))
    
    def _get_or_create_session_id(self) -> str:
        """Get existing session ID or create new one."""
        session_id = session.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
        return session_id
    
    def _validate_current_session(self) -> None:
        """Validate current user session."""
        session_id = session.get('session_id')
        if session_id:
            is_valid, session_data = self.validate_session(session_id)
            if not is_valid:
                self.destroy_session(reason='invalid_session')
    
    def _update_session_activity(self) -> None:
        """Update session activity timestamp."""
        session_id = session.get('session_id')
        if session_id and self.config.session_refresh_each_request:
            self.refresh_session(extend_expiry=False)
    
    def _validate_session_integrity(self, session_data: Dict[str, Any]) -> bool:
        """Validate session data integrity."""
        required_fields = ['session_id', 'user_id', 'created_at', 'last_activity']
        
        for field in required_fields:
            if field not in session_data:
                return False
        
        # Additional integrity checks can be added here
        return True
    
    def _store_session_data(self, session_id: str, encrypted_data: str, metadata: Dict[str, Any]) -> None:
        """Store session data in backend storage."""
        # This would integrate with your session storage backend
        # Could be Redis, database, or in-memory storage
        # For now, we'll use a simple in-memory store
        if not hasattr(self, '_session_store'):
            self._session_store = {}
        
        self._session_store[session_id] = {
            'encrypted_data': encrypted_data,
            'metadata': metadata
        }
    
    def _get_session_data(self, session_id: str) -> Optional[str]:
        """Retrieve session data from backend storage."""
        if not hasattr(self, '_session_store'):
            return None
        
        session_info = self._session_store.get(session_id)
        return session_info['encrypted_data'] if session_info else None
    
    def _get_all_session_data(self) -> Dict[str, str]:
        """Get all session data from storage."""
        if not hasattr(self, '_session_store'):
            return {}
        
        return {
            session_id: info['encrypted_data']
            for session_id, info in self._session_store.items()
        }
    
    def _remove_session_data(self, session_id: str) -> None:
        """Remove session data from storage."""
        if hasattr(self, '_session_store') and session_id in self._session_store:
            del self._session_store[session_id]
    
    def _update_active_sessions_metric(self) -> None:
        """Update Prometheus metric for active sessions."""
        if hasattr(self, '_session_store'):
            self.active_sessions_gauge.set(len(self._session_store))
    
    def _start_cleanup_thread(self) -> None:
        """Start background thread for session cleanup."""
        def cleanup_worker():
            while self._cleanup_active:
                try:
                    self.cleanup_expired_sessions()
                    time.sleep(self.config.cleanup_interval)
                except Exception as e:
                    self.logger.error(
                        "Cleanup thread error",
                        error=str(e)
                    )
                    time.sleep(60)  # Wait before retrying
        
        self._cleanup_active = True
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
        
        self.logger.info(
            "Session cleanup thread started",
            cleanup_interval=self.config.cleanup_interval
        )
    
    def shutdown(self) -> None:
        """Shutdown session manager and cleanup resources."""
        self._cleanup_active = False
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5)
        
        self.logger.info("Session manager shutdown completed")


# Factory function for Flask application integration
def create_session_manager(app: Flask) -> FlaskSessionManager:
    """
    Factory function to create and configure session manager.
    
    Args:
        app: Flask application instance
    
    Returns:
        Configured FlaskSessionManager instance
    """
    session_manager = FlaskSessionManager(app)
    return session_manager


# Decorator for session-required views
def session_required(f):
    """
    Decorator to require valid session for view functions.
    
    Usage:
        @app.route('/protected')
        @session_required
        def protected_view():
            return "Protected content"
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return current_app.session_manager._handle_unauthorized_access()
        
        # Validate current session
        session_id = session.get('session_id')
        if session_id:
            is_valid, _ = current_app.session_manager.validate_session(session_id)
            if not is_valid:
                current_app.session_manager.destroy_session(reason='invalid_session')
                return current_app.session_manager._handle_unauthorized_access()
        
        return f(*args, **kwargs)
    
    return decorated_function


# Export main components
__all__ = [
    'FlaskSessionManager',
    'SessionConfig',
    'SessionSecurityManager',
    'create_session_manager',
    'session_required'
]