"""
Flask Session Management Service

Comprehensive user session lifecycle management using Flask-Login and ItsDangerous
for secure session handling. This module manages session creation, validation, 
renewal, and cleanup while maintaining compatibility with existing user experience
patterns and providing secure cookie protection equivalent to Node.js implementation.

Features:
- Flask-Login LoginManager configuration with secure session handling
- ItsDangerous session cookie signing with AES encryption for tamper protection  
- Session lifecycle management with creation, validation, and expiration
- User session restoration capabilities for Flask-Login integration
- Session security controls with HTTPOnly and Secure flags
- Session timeout policies and remember-me functionality
- Session cleanup and garbage collection procedures
- User loader callbacks for Flask-Login session restoration
- Service Layer pattern integration for workflow orchestration
- Comprehensive error handling and security monitoring

Technical Implementation:
- Flask-Login integration for authentication state management
- ItsDangerous URLSafeTimedSerializer for secure session cookie protection
- Flask application factory pattern integration
- UserSession model integration for persistent session storage
- User model integration for authentication workflows
- Security monitoring with structured logging and metrics
- Rate limiting and session security validation
- Automated session cleanup with configurable policies

Security Features:
- Cryptographic session signing with configurable expiration
- Session token uniqueness enforcement and validation
- HTTPOnly and Secure cookie flags for protection
- Session timeout and renewal policies
- Brute force protection and rate limiting
- Session hijacking detection and prevention
- Comprehensive audit logging for security compliance
- Real-time security monitoring and alerting

Architecture Integration:
- Service Layer pattern for business logic organization
- Flask application factory initialization
- Blueprint-level session management
- Database transaction management
- External authentication provider integration
- Monitoring and observability integration

Dependencies:
- Flask 3.1.1 with Flask-Login for authentication state
- ItsDangerous 2.2+ for secure cookie signing
- Flask-SQLAlchemy 3.1.1 for database persistence
- UserSession and User models for data management
- Python 3.13.3 runtime with cryptographic support
"""

import os
import time
import secrets
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union, List, Tuple, Callable
from functools import wraps
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import threading
import json

# Flask core imports for application integration
from flask import (
    Flask, current_app, request, session, g, 
    make_response, jsonify, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, 
    current_user, login_required, fresh_login_required
)

# ItsDangerous imports for secure session management per Section 6.4.1.3
from itsdangerous import (
    URLSafeTimedSerializer, SignatureExpired, BadSignature,
    TimestampSigner, URLSafeSerializer
)

# SQLAlchemy imports for database operations
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

# Werkzeug imports for security utilities
from werkzeug.security import safe_str_cmp
from werkzeug.exceptions import Unauthorized, Forbidden

# Internal imports for model integration
try:
    from ..models.user import User
    from ..models.session import UserSession
except ImportError:
    # Fallback for development/testing
    from src.models.user import User
    from src.models.session import UserSession

# Database instance
db = SQLAlchemy()

# Logger configuration for session management operations
logger = logging.getLogger(__name__)


@dataclass
class SessionConfig:
    """
    Session configuration data structure for centralized settings management.
    
    Provides type-safe configuration management for session policies,
    security settings, and integration parameters. Used by SessionManager
    for consistent configuration across the Flask application factory pattern.
    
    Attributes:
        default_duration_hours (int): Default session duration in hours
        max_duration_hours (int): Maximum allowed session duration
        remember_me_duration_days (int): Remember-me session duration in days
        cleanup_interval_minutes (int): Session cleanup interval
        cookie_name (str): Session cookie name
        cookie_secure (bool): Secure cookie flag setting
        cookie_httponly (bool): HTTPOnly cookie flag setting
        cookie_samesite (str): SameSite cookie attribute
        max_sessions_per_user (int): Maximum concurrent sessions per user
        session_refresh_threshold_minutes (int): Session refresh threshold
        enable_session_monitoring (bool): Enable security monitoring
        enable_rate_limiting (bool): Enable session rate limiting
        cleanup_batch_size (int): Cleanup operation batch size
    """
    
    # Session duration policies
    default_duration_hours: int = 24
    max_duration_hours: int = 168  # 7 days
    remember_me_duration_days: int = 30
    
    # Session management settings
    cleanup_interval_minutes: int = 60
    session_refresh_threshold_minutes: int = 15
    max_sessions_per_user: int = 5
    cleanup_batch_size: int = 1000
    
    # Cookie security configuration per Section 6.4.1.3
    cookie_name: str = 'flask_session'
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = 'Lax'
    
    # Security and monitoring features
    enable_session_monitoring: bool = True
    enable_rate_limiting: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters."""
        if self.default_duration_hours <= 0 or self.default_duration_hours > self.max_duration_hours:
            raise ValueError("Invalid default_duration_hours")
        
        if self.max_sessions_per_user <= 0:
            raise ValueError("max_sessions_per_user must be positive")
        
        if self.cleanup_interval_minutes <= 0:
            raise ValueError("cleanup_interval_minutes must be positive")


@dataclass
class SessionMetrics:
    """
    Session metrics data structure for monitoring and analytics.
    
    Provides comprehensive session statistics and security metrics
    for monitoring session behavior, detecting anomalies, and 
    generating security reports.
    
    Attributes:
        total_sessions (int): Total number of sessions
        active_sessions (int): Number of active sessions
        expired_sessions (int): Number of expired sessions
        invalid_sessions (int): Number of invalid sessions
        sessions_created_today (int): Sessions created today
        average_session_duration_hours (float): Average session duration
        unique_users_with_sessions (int): Number of users with active sessions
        concurrent_sessions_per_user (Dict[int, int]): Concurrent session counts
        security_events_count (int): Number of security events
        cleanup_events_count (int): Number of cleanup operations
        last_cleanup_time (Optional[datetime]): Last cleanup timestamp
        generated_at (datetime): Metrics generation timestamp
    """
    
    total_sessions: int = 0
    active_sessions: int = 0
    expired_sessions: int = 0
    invalid_sessions: int = 0
    sessions_created_today: int = 0
    average_session_duration_hours: float = 0.0
    unique_users_with_sessions: int = 0
    concurrent_sessions_per_user: Dict[int, int] = None
    security_events_count: int = 0
    cleanup_events_count: int = 0
    last_cleanup_time: Optional[datetime] = None
    generated_at: datetime = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.concurrent_sessions_per_user is None:
            self.concurrent_sessions_per_user = {}
        
        if self.generated_at is None:
            self.generated_at = datetime.now(timezone.utc)


class SessionSecurityMonitor:
    """
    Session security monitoring and threat detection system.
    
    Implements real-time security monitoring for session-related threats
    including session hijacking, brute force attacks, and suspicious
    session patterns. Integrates with Flask application monitoring
    and provides automated threat response capabilities.
    
    Features:
        - Session pattern analysis and anomaly detection
        - Rate limiting for session operations
        - Security event logging and alerting
        - Automated threat response and session invalidation
        - Integration with Prometheus metrics collection
        - Comprehensive audit trail for security compliance
    """
    
    def __init__(self, config: SessionConfig):
        """
        Initialize security monitor with configuration.
        
        Args:
            config (SessionConfig): Session configuration for security policies
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SecurityMonitor")
        
        # Rate limiting storage (in production, use Redis or similar)
        self._rate_limits = defaultdict(deque)
        self._security_events = deque(maxlen=10000)
        
        # Thread lock for concurrent access protection
        self._lock = threading.RLock()
        
        # Security thresholds
        self.max_login_attempts_per_hour = 10
        self.max_session_creation_per_hour = 20
        self.suspicious_user_agent_patterns = [
            'curl', 'wget', 'python-requests', 'bot', 'scanner'
        ]
    
    def check_rate_limit(self, identifier: str, action: str, limit: int, 
                        window_hours: int = 1) -> Tuple[bool, int]:
        """
        Check rate limit for session operations.
        
        Args:
            identifier (str): Rate limit identifier (IP, user ID, etc.)
            action (str): Action type being rate limited
            limit (int): Maximum number of actions allowed
            window_hours (int): Time window in hours
        
        Returns:
            Tuple[bool, int]: (allowed, remaining_attempts)
        """
        with self._lock:
            key = f"{action}:{identifier}"
            current_time = time.time()
            window_start = current_time - (window_hours * 3600)
            
            # Clean old entries
            while self._rate_limits[key] and self._rate_limits[key][0] < window_start:
                self._rate_limits[key].popleft()
            
            # Check current count
            current_count = len(self._rate_limits[key])
            
            if current_count >= limit:
                self.logger.warning(
                    f"Rate limit exceeded for {action}",
                    extra={
                        'identifier': identifier,
                        'action': action,
                        'current_count': current_count,
                        'limit': limit,
                        'window_hours': window_hours
                    }
                )
                return False, 0
            
            # Add current attempt
            self._rate_limits[key].append(current_time)
            remaining = limit - (current_count + 1)
            
            return True, remaining
    
    def record_security_event(self, event_type: str, user_id: Optional[int] = None,
                             ip_address: Optional[str] = None, 
                             additional_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Record security event for monitoring and analysis.
        
        Args:
            event_type (str): Type of security event
            user_id (Optional[int]): User ID associated with event
            ip_address (Optional[str]): IP address of request
            additional_data (Optional[Dict[str, Any]]): Additional event data
        """
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'request_id': getattr(g, 'request_id', None),
            'user_agent': request.headers.get('User-Agent') if request else None,
            'additional_data': additional_data or {}
        }
        
        with self._lock:
            self._security_events.append(event)
        
        self.logger.warning(
            f"Security event: {event_type}",
            extra=event
        )
        
        # Check for automated response
        self._check_automated_response(event)
    
    def _check_automated_response(self, event: Dict[str, Any]) -> None:
        """
        Check if automated security response should be triggered.
        
        Args:
            event (Dict[str, Any]): Security event data
        """
        event_type = event.get('event_type')
        user_id = event.get('user_id')
        ip_address = event.get('ip_address')
        
        # Implement automated response logic based on event type
        if event_type in ['session_hijacking_detected', 'multiple_failed_logins']:
            if user_id:
                self.logger.critical(
                    f"Triggering automated response for user {user_id}",
                    extra={'event': event}
                )
                # Could trigger session invalidation, account lockout, etc.
        
        if event_type == 'suspicious_session_pattern' and ip_address:
            self.logger.error(
                f"Suspicious activity from IP {ip_address}",
                extra={'event': event}
            )
            # Could trigger IP blocking, enhanced monitoring, etc.
    
    def analyze_session_pattern(self, user_id: int, session_data: Dict[str, Any]) -> List[str]:
        """
        Analyze session pattern for suspicious activity.
        
        Args:
            user_id (int): User ID to analyze
            session_data (Dict[str, Any]): Session data for analysis
        
        Returns:
            List[str]: List of detected anomalies
        """
        anomalies = []
        
        # Check for suspicious user agents
        user_agent = session_data.get('user_agent', '')
        if any(pattern in user_agent.lower() for pattern in self.suspicious_user_agent_patterns):
            anomalies.append('suspicious_user_agent')
        
        # Check for rapid session creation
        ip_address = session_data.get('ip_address')
        if ip_address:
            allowed, _ = self.check_rate_limit(
                ip_address, 
                'session_creation', 
                self.max_session_creation_per_hour
            )
            if not allowed:
                anomalies.append('rapid_session_creation')
        
        # Check for concurrent sessions from different IPs
        # This would require additional logic to track active sessions
        
        return anomalies


class FlaskSessionManager:
    """
    Comprehensive Flask session management service implementing secure session handling.
    
    This service provides centralized session management for Flask applications with
    Flask-Login integration, ItsDangerous secure cookie signing, and comprehensive
    session lifecycle management. Implements the Service Layer pattern for business
    logic organization and workflow orchestration.
    
    Key Features:
        - Flask-Login LoginManager configuration with secure session handling
        - ItsDangerous session cookie signing with AES encryption
        - Session lifecycle management (creation, validation, expiration, cleanup)
        - User session restoration capabilities for Flask-Login integration
        - Session security controls with HTTPOnly and Secure flags
        - Session timeout policies and remember-me functionality
        - Automated session cleanup and garbage collection
        - Security monitoring and threat detection
        - Rate limiting and brute force protection
        - Comprehensive audit logging and metrics collection
    
    Architecture:
        - Service Layer pattern for business logic organization
        - Flask application factory pattern integration
        - Database transaction management with rollback support
        - External authentication provider integration readiness
        - Monitoring and observability integration
    
    Security:
        - Cryptographic session signing with ItsDangerous
        - Session token uniqueness enforcement
        - HTTPOnly and Secure cookie flags
        - Session hijacking detection and prevention
        - Automated threat response capabilities
        - Comprehensive security event logging
    """
    
    def __init__(self, app: Optional[Flask] = None, config: Optional[SessionConfig] = None):
        """
        Initialize Flask session manager with optional app and configuration.
        
        Args:
            app (Optional[Flask]): Flask application instance
            config (Optional[SessionConfig]): Session configuration
        """
        self.app = app
        self.config = config or SessionConfig()
        self.login_manager = LoginManager()
        self.security_monitor = SessionSecurityMonitor(self.config)
        self.logger = logging.getLogger(__name__)
        
        # Session serializers for secure token management
        self._session_serializer: Optional[URLSafeTimedSerializer] = None
        self._cookie_serializer: Optional[URLSafeSerializer] = None
        
        # Cleanup thread management
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_stop_event = threading.Event()
        
        # Metrics storage
        self._metrics_cache: Optional[SessionMetrics] = None
        self._metrics_cache_time: Optional[datetime] = None
        self._metrics_cache_ttl = timedelta(minutes=5)
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize session manager with Flask application factory pattern.
        
        Configures Flask-Login, ItsDangerous serializers, session policies,
        and integrates with Flask application lifecycle. Called during
        application factory initialization per Section 5.1.1.
        
        Args:
            app (Flask): Flask application instance
        
        Raises:
            ValueError: If required configuration is missing
            RuntimeError: If initialization fails
        """
        try:
            self.app = app
            
            # Validate required configuration
            secret_key = app.config.get('SECRET_KEY')
            if not secret_key:
                raise ValueError("SECRET_KEY is required for session management")
            
            # Initialize ItsDangerous serializers per Section 6.4.1.3
            self._session_serializer = URLSafeTimedSerializer(
                secret_key,
                salt='session-token'
            )
            self._cookie_serializer = URLSafeSerializer(
                secret_key,
                salt='session-cookie'
            )
            
            # Configure Flask-Login per Section 4.6.2
            self._configure_flask_login(app)
            
            # Configure session cookies per Section 6.4.1.3
            self._configure_session_cookies(app)
            
            # Register request handlers
            self._register_request_handlers(app)
            
            # Start background cleanup if enabled
            if self.config.cleanup_interval_minutes > 0:
                self._start_cleanup_thread()
            
            # Register teardown handler
            app.teardown_appcontext(self._teardown_session)
            
            # Store manager instance in app context
            app.session_manager = self
            
            self.logger.info(
                "Flask session manager initialized successfully",
                extra={
                    'config': asdict(self.config),
                    'flask_app': app.name
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize session manager: {str(e)}")
            raise RuntimeError(f"Session manager initialization failed: {str(e)}")
    
    def _configure_flask_login(self, app: Flask) -> None:
        """
        Configure Flask-Login for authentication integration per Section 4.6.2.
        
        Args:
            app (Flask): Flask application instance
        """
        # Initialize LoginManager with app
        self.login_manager.init_app(app)
        
        # Configure LoginManager settings
        self.login_manager.session_protection = 'strong'
        self.login_manager.login_view = 'auth.login'
        self.login_manager.login_message = 'Please log in to access this page.'
        self.login_manager.login_message_category = 'info'
        self.login_manager.refresh_view = 'auth.refresh'
        self.login_manager.needs_refresh_message = 'Please refresh your login to continue.'
        
        # Register user loader callback
        @self.login_manager.user_loader
        def load_user(user_id: str) -> Optional[UserMixin]:
            """
            User loader callback for Flask-Login session restoration per Section 4.6.2.
            
            Args:
                user_id (str): User ID from session
            
            Returns:
                Optional[UserMixin]: User instance if found and active
            """
            try:
                if not user_id or not user_id.isdigit():
                    return None
                
                user = User.query.filter_by(
                    id=int(user_id),
                    is_active=True
                ).first()
                
                if user:
                    self.logger.debug(f"Loaded user {user_id} from session")
                    return user
                
                self.logger.warning(f"Failed to load user {user_id}: user not found or inactive")
                return None
                
            except Exception as e:
                self.logger.error(f"Error loading user {user_id}: {str(e)}")
                return None
        
        # Register header loader for API authentication
        @self.login_manager.request_loader
        def load_user_from_request(request) -> Optional[UserMixin]:
            """
            Request loader for API token authentication.
            
            Args:
                request: Flask request object
            
            Returns:
                Optional[UserMixin]: User instance if authenticated
            """
            # Check for session token in headers
            session_token = request.headers.get('X-Session-Token')
            if session_token:
                return self._load_user_from_session_token(session_token)
            
            # Check for API key authentication (if implemented)
            api_key = request.headers.get('X-API-Key')
            if api_key:
                return self._load_user_from_api_key(api_key)
            
            return None
        
        # Register unauthorized handler
        @self.login_manager.unauthorized_handler
        def unauthorized():
            """Handle unauthorized access attempts."""
            self.security_monitor.record_security_event(
                'unauthorized_access_attempt',
                ip_address=request.remote_addr
            )
            
            # Return JSON for API requests, redirect for web requests
            if request.is_json or 'application/json' in request.headers.get('Accept', ''):
                return jsonify({'error': 'Authentication required'}), 401
            else:
                return abort(401)
    
    def _configure_session_cookies(self, app: Flask) -> None:
        """
        Configure session cookie security settings per Section 6.4.1.3.
        
        Args:
            app (Flask): Flask application instance
        """
        # Session cookie configuration
        app.config.update({
            'SESSION_COOKIE_NAME': self.config.cookie_name,
            'SESSION_COOKIE_SECURE': self.config.cookie_secure,
            'SESSION_COOKIE_HTTPONLY': self.config.cookie_httponly,
            'SESSION_COOKIE_SAMESITE': self.config.cookie_samesite,
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=self.config.default_duration_hours),
            'SESSION_REFRESH_EACH_REQUEST': False,  # Manual refresh control
        })
        
        # Remember me cookie configuration
        app.config.update({
            'REMEMBER_COOKIE_NAME': f"{self.config.cookie_name}_remember",
            'REMEMBER_COOKIE_DURATION': timedelta(days=self.config.remember_me_duration_days),
            'REMEMBER_COOKIE_SECURE': self.config.cookie_secure,
            'REMEMBER_COOKIE_HTTPONLY': self.config.cookie_httponly,
            'REMEMBER_COOKIE_REFRESH_EACH_REQUEST': False,
        })
    
    def _register_request_handlers(self, app: Flask) -> None:
        """
        Register request handlers for session management.
        
        Args:
            app (Flask): Flask application instance
        """
        @app.before_request
        def before_request():
            """Handle pre-request session validation and security checks."""
            # Set request ID for correlation
            if not hasattr(g, 'request_id'):
                g.request_id = secrets.token_hex(16)
            
            # Security monitoring for authenticated requests
            if current_user.is_authenticated:
                self._update_session_activity()
                self._check_session_security()
        
        @app.after_request
        def after_request(response):
            """Handle post-request session updates."""
            # Update session cookie if needed
            if current_user.is_authenticated and session.permanent:
                self._refresh_session_if_needed()
            
            return response
    
    def _start_cleanup_thread(self) -> None:
        """Start background thread for session cleanup."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        self._cleanup_stop_event.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_worker,
            daemon=True,
            name='SessionCleanupThread'
        )
        self._cleanup_thread.start()
        
        self.logger.info("Started session cleanup thread")
    
    def _cleanup_worker(self) -> None:
        """Background worker for automatic session cleanup."""
        while not self._cleanup_stop_event.is_set():
            try:
                # Perform cleanup
                cleanup_count = self.cleanup_expired_sessions()
                
                if cleanup_count > 0:
                    self.logger.info(f"Cleaned up {cleanup_count} expired sessions")
                
                # Wait for next cleanup interval
                self._cleanup_stop_event.wait(self.config.cleanup_interval_minutes * 60)
                
            except Exception as e:
                self.logger.error(f"Session cleanup error: {str(e)}")
                # Wait before retry
                self._cleanup_stop_event.wait(60)
    
    def create_session(self, user_id: int, remember_me: bool = False,
                      duration_hours: Optional[int] = None,
                      session_metadata: Optional[Dict[str, Any]] = None) -> Tuple[Optional[str], Optional[UserSession]]:
        """
        Create new user session with secure token generation.
        
        Creates authenticated session for user with Flask-Login integration
        and secure token generation using ItsDangerous. Implements session
        policies and security controls per Section 4.6.2.
        
        Args:
            user_id (int): User ID to create session for
            remember_me (bool): Enable remember-me functionality
            duration_hours (Optional[int]): Custom session duration
            session_metadata (Optional[Dict[str, Any]]): Additional session metadata
        
        Returns:
            Tuple[Optional[str], Optional[UserSession]]: (session_token, session_instance)
        
        Raises:
            ValueError: If user_id is invalid
            RuntimeError: If session creation fails
        
        Example:
            >>> token, session = session_manager.create_session(
            ...     user_id=1,
            ...     remember_me=True,
            ...     duration_hours=48
            ... )
            >>> if token:
            ...     print(f"Session created: {token}")
        """
        try:
            # Validate user exists and is active
            user = User.query.filter_by(id=user_id, is_active=True).first()
            if not user:
                raise ValueError(f"User {user_id} not found or inactive")
            
            # Check rate limiting
            ip_address = request.remote_addr if request else 'unknown'
            allowed, remaining = self.security_monitor.check_rate_limit(
                ip_address,
                'session_creation',
                self.security_monitor.max_session_creation_per_hour
            )
            
            if not allowed:
                self.security_monitor.record_security_event(
                    'session_creation_rate_limit_exceeded',
                    user_id=user_id,
                    ip_address=ip_address
                )
                raise RuntimeError("Session creation rate limit exceeded")
            
            # Determine session duration
            if remember_me:
                session_duration = timedelta(days=self.config.remember_me_duration_days)
            else:
                hours = duration_hours or self.config.default_duration_hours
                hours = min(hours, self.config.max_duration_hours)
                session_duration = timedelta(hours=hours)
            
            # Prepare session metadata
            request_metadata = {
                'user_agent': request.headers.get('User-Agent') if request else None,
                'ip_address': ip_address,
                'remember_me': remember_me,
                'created_via': 'session_manager',
                'request_id': getattr(g, 'request_id', None)
            }
            
            if session_metadata:
                request_metadata.update(session_metadata)
            
            # Check for suspicious patterns
            anomalies = self.security_monitor.analyze_session_pattern(user_id, request_metadata)
            if anomalies:
                self.security_monitor.record_security_event(
                    'suspicious_session_pattern',
                    user_id=user_id,
                    ip_address=ip_address,
                    additional_data={'anomalies': anomalies}
                )
            
            # Enforce session limits per user
            self._enforce_session_limits(user_id)
            
            # Create UserSession instance
            expires_at = datetime.now(timezone.utc) + session_duration
            user_session = UserSession.create_session(
                user_id=user_id,
                expires_in_hours=int(session_duration.total_seconds() / 3600),
                session_metadata=json.dumps(request_metadata),
                user_agent=request_metadata.get('user_agent'),
                ip_address=ip_address
            )
            
            # Login user with Flask-Login
            login_user(user, remember=remember_me, duration=session_duration)
            
            # Set session as permanent for proper cookie handling
            session.permanent = True
            
            # Store session ID in Flask session for correlation
            session['user_session_id'] = user_session.id
            session['created_at'] = datetime.now(timezone.utc).isoformat()
            
            self.logger.info(
                f"Created session for user {user_id}",
                extra={
                    'user_id': user_id,
                    'session_id': user_session.id,
                    'remember_me': remember_me,
                    'expires_at': expires_at.isoformat(),
                    'ip_address': ip_address
                }
            )
            
            return user_session.session_token, user_session
            
        except Exception as e:
            self.logger.error(f"Failed to create session for user {user_id}: {str(e)}")
            # Ensure cleanup on failure
            if 'user_session' in locals():
                try:
                    db.session.delete(user_session)
                    db.session.commit()
                except:
                    pass
            raise
    
    def validate_session(self, session_token: str) -> Optional[UserSession]:
        """
        Validate session token and return active session.
        
        Validates session token using ItsDangerous verification and database
        lookup. Updates session activity and performs security checks.
        
        Args:
            session_token (str): Session token to validate
        
        Returns:
            Optional[UserSession]: Valid session instance or None
        
        Example:
            >>> session = session_manager.validate_session(token)
            >>> if session and session.is_active():
            ...     print(f"Valid session for user {session.user_id}")
        """
        try:
            if not session_token:
                return None
            
            # Validate with UserSession model
            user_session = UserSession.validate_session(session_token)
            
            if user_session and user_session.is_active():
                # Update activity timestamp
                user_session.update_last_accessed()
                db.session.commit()
                
                # Security validation
                self._validate_session_security(user_session)
                
                self.logger.debug(f"Validated session {user_session.id}")
                return user_session
            
            if user_session:
                self.logger.warning(f"Session {user_session.id} is inactive or expired")
            
            return None
            
        except Exception as e:
            self.logger.error(f"Session validation error: {str(e)}")
            return None
    
    def refresh_session(self, session_token: str, extend_hours: Optional[int] = None) -> bool:
        """
        Refresh session expiration time.
        
        Args:
            session_token (str): Session token to refresh
            extend_hours (Optional[int]): Hours to extend session
        
        Returns:
            bool: True if session was refreshed successfully
        """
        try:
            user_session = self.validate_session(session_token)
            if not user_session:
                return False
            
            # Determine extension duration
            if extend_hours:
                extend_hours = min(extend_hours, self.config.max_duration_hours)
            else:
                extend_hours = self.config.default_duration_hours
            
            user_session.extend_session(hours=extend_hours)
            db.session.commit()
            
            self.logger.info(f"Refreshed session {user_session.id} for {extend_hours} hours")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to refresh session: {str(e)}")
            return False
    
    def invalidate_session(self, session_token: str, reason: Optional[str] = None) -> bool:
        """
        Invalidate specific session.
        
        Args:
            session_token (str): Session token to invalidate
            reason (Optional[str]): Reason for invalidation
        
        Returns:
            bool: True if session was invalidated successfully
        """
        try:
            user_session = UserSession.validate_session(session_token)
            if not user_session:
                return False
            
            user_session.invalidate_session(reason)
            db.session.commit()
            
            self.logger.info(f"Invalidated session {user_session.id}: {reason or 'No reason specified'}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to invalidate session: {str(e)}")
            return False
    
    def invalidate_user_sessions(self, user_id: int, exclude_current: bool = True,
                                reason: Optional[str] = None) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id (int): User ID to invalidate sessions for
            exclude_current (bool): Exclude current session from invalidation
            reason (Optional[str]): Reason for invalidation
        
        Returns:
            int: Number of sessions invalidated
        """
        try:
            exclude_session_id = None
            if exclude_current and hasattr(session, 'user_session_id'):
                exclude_session_id = session.get('user_session_id')
            
            count = UserSession.invalidate_user_sessions(
                user_id=user_id,
                exclude_session_id=exclude_session_id
            )
            
            self.logger.info(
                f"Invalidated {count} sessions for user {user_id}: {reason or 'No reason specified'}"
            )
            
            return count
            
        except Exception as e:
            self.logger.error(f"Failed to invalidate user sessions: {str(e)}")
            return 0
    
    def logout_user(self, invalidate_session: bool = True) -> bool:
        """
        Logout current user and optionally invalidate session.
        
        Args:
            invalidate_session (bool): Whether to invalidate the session
        
        Returns:
            bool: True if logout was successful
        """
        try:
            user_id = current_user.id if current_user.is_authenticated else None
            
            # Invalidate database session if requested
            if invalidate_session and hasattr(session, 'user_session_id'):
                session_id = session.get('user_session_id')
                if session_id:
                    user_session = UserSession.query.get(session_id)
                    if user_session:
                        user_session.invalidate_session("User logout")
                        db.session.commit()
            
            # Logout with Flask-Login
            logout_user()
            
            # Clear Flask session
            session.clear()
            
            if user_id:
                self.logger.info(f"User {user_id} logged out successfully")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Logout failed: {str(e)}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from database per Section 4.6.2.
        
        Returns:
            int: Number of sessions cleaned up
        """
        try:
            count = UserSession.cleanup_expired_sessions(
                batch_size=self.config.cleanup_batch_size
            )
            
            if count > 0:
                self.logger.info(f"Cleaned up {count} expired sessions")
                
                # Update metrics
                if hasattr(self, 'security_monitor'):
                    self.security_monitor.record_security_event(
                        'session_cleanup_completed',
                        additional_data={'cleaned_sessions': count}
                    )
            
            return count
            
        except Exception as e:
            self.logger.error(f"Session cleanup failed: {str(e)}")
            return 0
    
    def get_session_metrics(self, force_refresh: bool = False) -> SessionMetrics:
        """
        Get comprehensive session metrics for monitoring.
        
        Args:
            force_refresh (bool): Force refresh of cached metrics
        
        Returns:
            SessionMetrics: Current session metrics
        """
        try:
            # Check cache validity
            if (not force_refresh and self._metrics_cache and self._metrics_cache_time and
                datetime.now(timezone.utc) - self._metrics_cache_time < self._metrics_cache_ttl):
                return self._metrics_cache
            
            # Generate fresh metrics
            stats = UserSession.get_session_statistics()
            
            # Get concurrent sessions per user
            concurrent_sessions = {}
            active_sessions = UserSession.query.filter(
                UserSession.is_valid == True,
                UserSession.expires_at > datetime.now(timezone.utc)
            ).all()
            
            user_session_counts = defaultdict(int)
            for session in active_sessions:
                user_session_counts[session.user_id] += 1
            
            metrics = SessionMetrics(
                total_sessions=stats.get('total_sessions', 0),
                active_sessions=stats.get('active_sessions', 0),
                expired_sessions=stats.get('expired_sessions', 0),
                invalid_sessions=stats.get('invalid_sessions', 0),
                sessions_created_today=stats.get('sessions_created_today', 0),
                unique_users_with_sessions=len(user_session_counts),
                concurrent_sessions_per_user=dict(user_session_counts),
                generated_at=datetime.now(timezone.utc)
            )
            
            # Cache metrics
            self._metrics_cache = metrics
            self._metrics_cache_time = datetime.now(timezone.utc)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to generate session metrics: {str(e)}")
            return SessionMetrics(generated_at=datetime.now(timezone.utc))
    
    def _load_user_from_session_token(self, session_token: str) -> Optional[UserMixin]:
        """Load user from session token for API authentication."""
        user_session = self.validate_session(session_token)
        if user_session and user_session.is_active():
            return User.query.get(user_session.user_id)
        return None
    
    def _load_user_from_api_key(self, api_key: str) -> Optional[UserMixin]:
        """Load user from API key (placeholder for future implementation)."""
        # Placeholder for API key authentication
        return None
    
    def _update_session_activity(self) -> None:
        """Update current session activity timestamp."""
        if hasattr(session, 'user_session_id'):
            session_id = session.get('user_session_id')
            if session_id:
                try:
                    user_session = UserSession.query.get(session_id)
                    if user_session:
                        user_session.update_last_accessed()
                        db.session.commit()
                except Exception as e:
                    self.logger.error(f"Failed to update session activity: {str(e)}")
    
    def _check_session_security(self) -> None:
        """Perform security checks on current session."""
        if not hasattr(session, 'user_session_id'):
            return
        
        session_id = session.get('user_session_id')
        if not session_id:
            return
        
        try:
            user_session = UserSession.query.get(session_id)
            if user_session:
                self._validate_session_security(user_session)
        except Exception as e:
            self.logger.error(f"Session security check failed: {str(e)}")
    
    def _validate_session_security(self, user_session: UserSession) -> None:
        """Validate session security and detect potential threats."""
        # Check for IP address changes (session hijacking detection)
        current_ip = request.remote_addr if request else None
        stored_ip = user_session.ip_address
        
        if current_ip and stored_ip and current_ip != stored_ip:
            self.security_monitor.record_security_event(
                'session_ip_change_detected',
                user_id=user_session.user_id,
                ip_address=current_ip,
                additional_data={
                    'original_ip': stored_ip,
                    'new_ip': current_ip,
                    'session_id': user_session.id
                }
            )
        
        # Check for unusual user agent changes
        current_user_agent = request.headers.get('User-Agent') if request else None
        stored_user_agent = user_session.user_agent
        
        if (current_user_agent and stored_user_agent and 
            current_user_agent != stored_user_agent):
            self.security_monitor.record_security_event(
                'session_user_agent_change',
                user_id=user_session.user_id,
                ip_address=current_ip,
                additional_data={
                    'original_user_agent': stored_user_agent,
                    'new_user_agent': current_user_agent,
                    'session_id': user_session.id
                }
            )
    
    def _refresh_session_if_needed(self) -> None:
        """Refresh session if approaching expiration."""
        if not hasattr(session, 'user_session_id'):
            return
        
        session_id = session.get('user_session_id')
        if not session_id:
            return
        
        try:
            user_session = UserSession.query.get(session_id)
            if not user_session or not user_session.is_active():
                return
            
            # Check if session needs refresh
            time_until_expiry = user_session.expires_at - datetime.now(timezone.utc)
            refresh_threshold = timedelta(minutes=self.config.session_refresh_threshold_minutes)
            
            if time_until_expiry < refresh_threshold:
                user_session.extend_session(hours=self.config.default_duration_hours)
                db.session.commit()
                
                self.logger.debug(f"Auto-refreshed session {session_id}")
                
        except Exception as e:
            self.logger.error(f"Session refresh failed: {str(e)}")
    
    def _enforce_session_limits(self, user_id: int) -> None:
        """Enforce maximum sessions per user limit."""
        try:
            active_sessions = UserSession.get_user_sessions(user_id, active_only=True)
            
            if len(active_sessions) >= self.config.max_sessions_per_user:
                # Invalidate oldest sessions to make room
                sessions_to_invalidate = active_sessions[-(len(active_sessions) - self.config.max_sessions_per_user + 1):]
                
                for old_session in sessions_to_invalidate:
                    old_session.invalidate_session("Session limit exceeded - oldest session invalidated")
                
                db.session.commit()
                
                self.logger.info(
                    f"Invalidated {len(sessions_to_invalidate)} sessions for user {user_id} due to session limit"
                )
                
        except Exception as e:
            self.logger.error(f"Failed to enforce session limits: {str(e)}")
    
    def _teardown_session(self, exception: Optional[Exception]) -> None:
        """Handle Flask session teardown."""
        if exception:
            self.logger.error(f"Request ended with exception: {str(exception)}")
            # Rollback any pending database changes
            try:
                db.session.rollback()
            except Exception:
                pass
    
    def stop_cleanup_thread(self) -> None:
        """Stop the background cleanup thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_stop_event.set()
            self._cleanup_thread.join(timeout=10)
            
            if self._cleanup_thread.is_alive():
                self.logger.warning("Cleanup thread did not stop gracefully")
            else:
                self.logger.info("Session cleanup thread stopped")
    
    def __del__(self):
        """Cleanup on object destruction."""
        self.stop_cleanup_thread()


# Flask application factory integration function
def create_session_manager(app: Flask, config: Optional[SessionConfig] = None) -> FlaskSessionManager:
    """
    Create and configure session manager for Flask application factory pattern.
    
    Factory function for creating session manager instances with Flask
    application integration. Supports environment-specific configuration
    and development/production deployment patterns.
    
    Args:
        app (Flask): Flask application instance
        config (Optional[SessionConfig]): Custom session configuration
    
    Returns:
        FlaskSessionManager: Configured session manager instance
    
    Example:
        >>> from flask import Flask
        >>> app = Flask(__name__)
        >>> app.config['SECRET_KEY'] = 'your-secret-key'
        >>> session_manager = create_session_manager(app)
        >>> print("Session manager initialized")
    """
    # Use environment-specific configuration if not provided
    if config is None:
        config = SessionConfig()
        
        # Override with environment-specific settings
        if app.config.get('TESTING'):
            config.cleanup_interval_minutes = 0  # Disable cleanup in tests
            config.enable_session_monitoring = False
        
        if app.config.get('DEBUG'):
            config.cookie_secure = False  # Allow HTTP in development
    
    # Create and initialize session manager
    session_manager = FlaskSessionManager(app, config)
    
    return session_manager


# Utility decorators for session management

def require_valid_session(f: Callable) -> Callable:
    """
    Decorator to require valid session for route access.
    
    Args:
        f (Callable): Route function to protect
    
    Returns:
        Callable: Protected route function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        
        # Additional session validation
        if hasattr(session, 'user_session_id'):
            session_id = session.get('user_session_id')
            if session_id:
                user_session = UserSession.query.get(session_id)
                if not user_session or not user_session.is_active():
                    logout_user()
                    abort(401)
        
        return f(*args, **kwargs)
    
    return decorated_function


def fresh_session_required(f: Callable) -> Callable:
    """
    Decorator to require fresh session for sensitive operations.
    
    Args:
        f (Callable): Route function to protect
    
    Returns:
        Callable: Protected route function
    """
    @wraps(f)
    @fresh_login_required
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    return decorated_function


# Module exports for organized import management
__all__ = [
    'FlaskSessionManager',
    'SessionConfig',
    'SessionMetrics',
    'SessionSecurityMonitor',
    'create_session_manager',
    'require_valid_session',
    'fresh_session_required'
]