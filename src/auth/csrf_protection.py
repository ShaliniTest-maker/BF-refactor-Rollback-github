"""
CSRF Protection Service

Comprehensive Cross-Site Request Forgery protection service implementing Flask-WTF
CSRFProtect for secure web forms and AJAX requests. This module provides token
generation, validation, exemption management, and security event logging while
maintaining compatibility with the Flask application factory pattern.

This implementation follows the Flask 3.1.1 architecture pattern from Section 5.1.1
and integrates with the authentication security framework from Section 4.6.2.
"""

import logging
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Set, Callable, Any
from urllib.parse import urlparse

import structlog
from flask import (
    Flask, 
    request, 
    session, 
    current_app, 
    g, 
    jsonify, 
    abort,
    render_template_string
)
from flask_wtf.csrf import CSRFProtect, validate_csrf, generate_csrf, CSRFError
from werkzeug.exceptions import BadRequest

# Configure structured logging for security events per Section 6.4.6.1
logger = structlog.get_logger("csrf_protection")


class CSRFViolationError(Exception):
    """Custom exception for CSRF validation violations with enhanced context."""
    
    def __init__(self, message: str, violation_type: str = "unknown", **kwargs):
        self.message = message
        self.violation_type = violation_type
        self.timestamp = datetime.utcnow()
        self.context = kwargs
        super().__init__(message)


class CSRFProtectionService:
    """
    Comprehensive CSRF protection service implementing Flask-WTF integration
    with enhanced security monitoring and exemption management capabilities.
    
    This service provides:
    - Automatic CSRF token validation on POST, PUT, PATCH, DELETE requests
    - Token generation for web forms and AJAX requests
    - API endpoint exemption management for alternative authentication
    - Frontend integration support for templates and JavaScript
    - Security event logging and monitoring integration
    - Proper error handling with user-friendly feedback
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize CSRF protection service with optional Flask application.
        
        Args:
            app: Flask application instance for immediate initialization
        """
        self.csrf = CSRFProtect()
        self.app = app
        self._exempt_routes: Set[str] = set()
        self._exempt_blueprints: Set[str] = set()
        self._api_endpoints: Set[str] = set()
        self._violation_count: Dict[str, int] = {}
        self._last_violation_time: Dict[str, datetime] = {}
        
        # CSRF configuration defaults per Section 4.6.2
        self._config_defaults = {
            'SECRET_KEY': None,  # Must be provided by application
            'WTF_CSRF_ENABLED': True,
            'WTF_CSRF_TIME_LIMIT': 3600,  # 1 hour token lifetime
            'WTF_CSRF_SSL_STRICT': True,   # Enforce HTTPS in production
            'WTF_CSRF_CHECK_DEFAULT': True,
            'WTF_CSRF_METHODS': ['POST', 'PUT', 'PATCH', 'DELETE'],
            'WTF_CSRF_FIELD_NAME': 'csrf_token',
            'WTF_CSRF_HEADERS': ['X-CSRFToken', 'X-CSRF-Token'],
            'CSRF_RATE_LIMIT_THRESHOLD': 10,  # Max violations per IP per hour
            'CSRF_MONITORING_ENABLED': True
        }
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask) -> None:
        """
        Initialize CSRF protection with Flask application factory pattern.
        
        Configures Flask-WTF CSRFProtect, sets up error handlers, and integrates
        with the application's security monitoring infrastructure per Section 5.1.1.
        
        Args:
            app: Flask application instance to configure
        """
        self.app = app
        
        # Apply configuration defaults
        for key, default_value in self._config_defaults.items():
            app.config.setdefault(key, default_value)
        
        # Validate required configuration
        if not app.config.get('SECRET_KEY'):
            raise ValueError(
                "SECRET_KEY must be configured for CSRF protection. "
                "This is required for secure token generation per Section 4.6.2."
            )
        
        # Initialize Flask-WTF CSRF protection
        self.csrf.init_app(app)
        
        # Register error handlers for CSRF violations per Section 4.6.3
        self._register_error_handlers(app)
        
        # Set up security monitoring integration per Section 6.4.6.1
        self._setup_security_monitoring(app)
        
        # Register template context processor for token access
        self._register_template_context(app)
        
        # Store service instance in application for access
        app.csrf_protection = self
        
        logger.info(
            "CSRF protection service initialized",
            app_name=app.name,
            csrf_enabled=app.config.get('WTF_CSRF_ENABLED'),
            time_limit=app.config.get('WTF_CSRF_TIME_LIMIT'),
            ssl_strict=app.config.get('WTF_CSRF_SSL_STRICT'),
            protected_methods=app.config.get('WTF_CSRF_METHODS')
        )
    
    def _register_error_handlers(self, app: Flask) -> None:
        """
        Register comprehensive CSRF error handlers for user-friendly feedback.
        
        Implements error handling per Section 4.6.3 with appropriate HTTP status
        codes and security event logging.
        
        Args:
            app: Flask application instance
        """
        @app.errorhandler(CSRFError)
        def handle_csrf_error(error):
            """Handle CSRF validation errors with comprehensive logging and response."""
            violation_info = self._analyze_csrf_violation(error)
            
            # Log security event per Section 6.4.6.1
            self._log_csrf_violation(violation_info)
            
            # Track violation for rate limiting
            self._track_violation(request.remote_addr)
            
            # Determine response format based on request type
            if request.is_json or 'application/json' in request.headers.get('Accept', ''):
                return jsonify({
                    'error': 'CSRF token validation failed',
                    'message': 'Invalid or missing CSRF token. Please refresh the page and try again.',
                    'code': 'CSRF_VALIDATION_ERROR',
                    'timestamp': datetime.utcnow().isoformat()
                }), 400
            else:
                # HTML response for form submissions
                return self._render_csrf_error_page(violation_info), 400
        
        @app.errorhandler(CSRFViolationError)
        def handle_custom_csrf_violation(error):
            """Handle custom CSRF violations with enhanced context."""
            self._log_csrf_violation({
                'violation_type': error.violation_type,
                'message': error.message,
                'context': error.context,
                'timestamp': error.timestamp
            })
            
            return jsonify({
                'error': 'CSRF security violation',
                'message': error.message,
                'violation_type': error.violation_type,
                'timestamp': error.timestamp.isoformat()
            }), 403
    
    def _setup_security_monitoring(self, app: Flask) -> None:
        """
        Configure security monitoring integration for CSRF events.
        
        Integrates with the security monitoring infrastructure per Section 6.4.6.1
        to provide real-time CSRF violation tracking and alerting.
        
        Args:
            app: Flask application instance
        """
        @app.before_request
        def track_csrf_context():
            """Track request context for CSRF monitoring."""
            if app.config.get('CSRF_MONITORING_ENABLED', True):
                g.csrf_start_time = time.time()
                g.csrf_request_id = secrets.token_hex(8)
                
                # Log request initiation for monitoring
                if request.method in app.config.get('WTF_CSRF_METHODS', []):
                    logger.debug(
                        "CSRF-protected request initiated",
                        request_id=g.csrf_request_id,
                        method=request.method,
                        endpoint=request.endpoint,
                        remote_addr=request.remote_addr,
                        user_agent=request.headers.get('User-Agent', '')[:100]
                    )
        
        @app.after_request
        def log_csrf_request_completion(response):
            """Log successful CSRF validation for monitoring."""
            if (hasattr(g, 'csrf_start_time') and 
                app.config.get('CSRF_MONITORING_ENABLED', True)):
                
                processing_time = time.time() - g.csrf_start_time
                
                if (request.method in app.config.get('WTF_CSRF_METHODS', []) and
                    response.status_code < 400):
                    
                    logger.info(
                        "CSRF validation successful",
                        request_id=getattr(g, 'csrf_request_id', 'unknown'),
                        method=request.method,
                        endpoint=request.endpoint,
                        status_code=response.status_code,
                        processing_time_ms=round(processing_time * 1000, 2)
                    )
            
            return response
    
    def _register_template_context(self, app: Flask) -> None:
        """
        Register template context processor for CSRF token access.
        
        Provides CSRF tokens to Jinja2 templates for form integration per Section 4.6.2.
        
        Args:
            app: Flask application instance
        """
        @app.context_processor
        def inject_csrf_token():
            """Inject CSRF token into template context."""
            return {
                'csrf_token': self.get_csrf_token,
                'csrf_meta_tag': self.get_csrf_meta_tag,
                'csrf_hidden_field': self.get_csrf_hidden_field
            }
    
    def get_csrf_token(self) -> str:
        """
        Generate CSRF token for current session.
        
        Returns:
            CSRF token string for use in forms and AJAX requests
        """
        try:
            return generate_csrf()
        except Exception as e:
            logger.error(
                "Failed to generate CSRF token",
                error=str(e),
                session_id=session.get('_id', 'unknown')
            )
            raise CSRFViolationError(
                "Unable to generate CSRF token",
                violation_type="token_generation_error",
                error=str(e)
            )
    
    def get_csrf_meta_tag(self) -> str:
        """
        Generate HTML meta tag for CSRF token.
        
        Provides easy integration with frontend JavaScript per Section 4.6.2.
        
        Returns:
            HTML meta tag containing CSRF token
        """
        token = self.get_csrf_token()
        return f'<meta name="csrf-token" content="{token}">'
    
    def get_csrf_hidden_field(self, field_name: Optional[str] = None) -> str:
        """
        Generate hidden HTML field for CSRF token.
        
        Args:
            field_name: Custom field name (defaults to WTF_CSRF_FIELD_NAME)
            
        Returns:
            HTML hidden input field containing CSRF token
        """
        field_name = field_name or current_app.config.get('WTF_CSRF_FIELD_NAME', 'csrf_token')
        token = self.get_csrf_token()
        return f'<input type="hidden" name="{field_name}" value="{token}">'
    
    def validate_csrf_token(self, token: Optional[str] = None) -> bool:
        """
        Validate CSRF token manually.
        
        Args:
            token: CSRF token to validate (if not provided, extracts from request)
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            validate_csrf(token)
            return True
        except CSRFError as e:
            logger.warning(
                "Manual CSRF token validation failed",
                token_provided=token is not None,
                error=str(e),
                remote_addr=request.remote_addr if request else 'unknown'
            )
            return False
    
    def exempt_route(self, route: str) -> None:
        """
        Exempt specific route from CSRF protection.
        
        Used for API endpoints with alternative authentication per Section 4.6.2.
        
        Args:
            route: Route pattern to exempt (e.g., '/api/v1/data')
        """
        self._exempt_routes.add(route)
        logger.info(
            "Route exempted from CSRF protection",
            route=route,
            exempt_routes_count=len(self._exempt_routes)
        )
    
    def exempt_blueprint(self, blueprint_name: str) -> None:
        """
        Exempt entire blueprint from CSRF protection.
        
        Used for API blueprints with alternative authentication per Section 4.6.2.
        
        Args:
            blueprint_name: Name of blueprint to exempt
        """
        self._exempt_blueprints.add(blueprint_name)
        logger.info(
            "Blueprint exempted from CSRF protection",
            blueprint=blueprint_name,
            exempt_blueprints_count=len(self._exempt_blueprints)
        )
    
    def register_api_endpoint(self, endpoint_pattern: str) -> None:
        """
        Register API endpoint pattern for automatic CSRF exemption.
        
        Args:
            endpoint_pattern: API endpoint pattern (e.g., '/api/*')
        """
        self._api_endpoints.add(endpoint_pattern)
        logger.info(
            "API endpoint registered for CSRF exemption",
            pattern=endpoint_pattern,
            api_endpoints_count=len(self._api_endpoints)
        )
    
    def is_exempt(self, endpoint: Optional[str] = None, blueprint: Optional[str] = None) -> bool:
        """
        Check if current request or specified endpoint is exempt from CSRF protection.
        
        Args:
            endpoint: Specific endpoint to check (defaults to current request)
            blueprint: Specific blueprint to check (defaults to current request)
            
        Returns:
            True if exempt, False otherwise
        """
        # Use current request context if not specified
        if endpoint is None:
            endpoint = request.endpoint if request else None
        if blueprint is None:
            blueprint = request.blueprint if request else None
        
        # Check blueprint exemption
        if blueprint and blueprint in self._exempt_blueprints:
            return True
        
        # Check specific route exemption
        if endpoint and endpoint in self._exempt_routes:
            return True
        
        # Check API endpoint patterns
        current_path = request.path if request else ''
        for pattern in self._api_endpoints:
            if pattern.endswith('*'):
                if current_path.startswith(pattern[:-1]):
                    return True
            elif current_path == pattern:
                return True
        
        return False
    
    def require_csrf_token(self, f: Callable) -> Callable:
        """
        Decorator to explicitly require CSRF token validation.
        
        Args:
            f: Function to decorate
            
        Returns:
            Decorated function with CSRF validation
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.validate_csrf_token():
                raise CSRFViolationError(
                    "CSRF token validation required for this endpoint",
                    violation_type="missing_token",
                    endpoint=request.endpoint,
                    method=request.method
                )
            return f(*args, **kwargs)
        return decorated_function
    
    def csrf_exempt(self, f: Callable) -> Callable:
        """
        Decorator to exempt specific view function from CSRF protection.
        
        Args:
            f: Function to exempt
            
        Returns:
            Decorated function exempt from CSRF validation
        """
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Mark request as CSRF exempt
            g.csrf_exempt = True
            return f(*args, **kwargs)
        return decorated_function
    
    def _analyze_csrf_violation(self, error: CSRFError) -> Dict[str, Any]:
        """
        Analyze CSRF violation for comprehensive logging and monitoring.
        
        Args:
            error: CSRFError instance
            
        Returns:
            Dictionary containing violation analysis
        """
        violation_info = {
            'timestamp': datetime.utcnow(),
            'error_message': str(error),
            'request_method': request.method,
            'request_path': request.path,
            'request_endpoint': request.endpoint,
            'request_blueprint': request.blueprint,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', '')[:200],
            'referer': request.headers.get('Referer', ''),
            'content_type': request.headers.get('Content-Type', ''),
            'has_json': request.is_json,
            'form_data_present': bool(request.form),
            'csrf_token_in_form': current_app.config.get('WTF_CSRF_FIELD_NAME') in request.form,
            'csrf_token_in_headers': any(
                header in request.headers 
                for header in current_app.config.get('WTF_CSRF_HEADERS', [])
            ),
            'session_id': session.get('_id', 'unknown'),
            'is_exempt': self.is_exempt()
        }
        
        # Analyze token presence and validity
        token_sources = []
        if violation_info['csrf_token_in_form']:
            token_sources.append('form')
        if violation_info['csrf_token_in_headers']:
            token_sources.append('headers')
        
        violation_info['token_sources'] = token_sources
        violation_info['violation_type'] = self._classify_violation(violation_info)
        
        return violation_info
    
    def _classify_violation(self, violation_info: Dict[str, Any]) -> str:
        """
        Classify CSRF violation type for targeted response.
        
        Args:
            violation_info: Violation analysis data
            
        Returns:
            Violation classification string
        """
        if violation_info['is_exempt']:
            return 'exempt_endpoint_violation'
        elif not violation_info['token_sources']:
            return 'missing_token'
        elif violation_info['csrf_token_in_form'] or violation_info['csrf_token_in_headers']:
            return 'invalid_token'
        else:
            return 'unknown_violation'
    
    def _log_csrf_violation(self, violation_info: Dict[str, Any]) -> None:
        """
        Log CSRF violation for security monitoring per Section 6.4.6.1.
        
        Args:
            violation_info: Violation analysis data
        """
        logger.warning(
            "CSRF violation detected",
            **violation_info,
            security_event=True,
            event_type="csrf_violation"
        )
        
        # Additional logging for security incident response per Section 6.4.6.2
        if violation_info.get('violation_type') in ['missing_token', 'invalid_token']:
            # Check for potential attack patterns
            recent_violations = self._get_recent_violations(violation_info['remote_addr'])
            if recent_violations >= current_app.config.get('CSRF_RATE_LIMIT_THRESHOLD', 10):
                logger.error(
                    "Potential CSRF attack detected - rate limit exceeded",
                    remote_addr=violation_info['remote_addr'],
                    violation_count=recent_violations,
                    time_window='1_hour',
                    security_incident=True,
                    incident_type="csrf_attack_pattern"
                )
    
    def _track_violation(self, remote_addr: str) -> None:
        """
        Track CSRF violations for rate limiting and attack detection.
        
        Args:
            remote_addr: Remote IP address
        """
        current_time = datetime.utcnow()
        
        # Clean old violation records (older than 1 hour)
        cutoff_time = current_time - timedelta(hours=1)
        to_remove = [
            addr for addr, timestamp in self._last_violation_time.items()
            if timestamp < cutoff_time
        ]
        for addr in to_remove:
            self._violation_count.pop(addr, None)
            self._last_violation_time.pop(addr, None)
        
        # Update violation count
        self._violation_count[remote_addr] = self._violation_count.get(remote_addr, 0) + 1
        self._last_violation_time[remote_addr] = current_time
    
    def _get_recent_violations(self, remote_addr: str) -> int:
        """
        Get count of recent CSRF violations for an IP address.
        
        Args:
            remote_addr: Remote IP address
            
        Returns:
            Number of violations in the last hour
        """
        return self._violation_count.get(remote_addr, 0)
    
    def _render_csrf_error_page(self, violation_info: Dict[str, Any]) -> str:
        """
        Render user-friendly CSRF error page per Section 4.6.3.
        
        Args:
            violation_info: Violation analysis data
            
        Returns:
            HTML error page content
        """
        error_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Error - CSRF Token Invalid</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .error-icon { color: #d32f2f; font-size: 48px; text-align: center; margin-bottom: 20px; }
                h1 { color: #d32f2f; text-align: center; margin-bottom: 20px; }
                p { line-height: 1.6; color: #555; }
                .actions { margin-top: 30px; text-align: center; }
                .btn { display: inline-block; padding: 10px 20px; background: #1976d2; color: white; text-decoration: none; border-radius: 3px; margin: 0 10px; }
                .btn:hover { background: #1565c0; }
                .details { margin-top: 30px; padding: 15px; background: #f9f9f9; border-radius: 3px; font-family: monospace; font-size: 12px; color: #666; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-icon">⚠️</div>
                <h1>Security Validation Failed</h1>
                <p>
                    Your request could not be processed due to a security token validation failure. 
                    This protection helps keep your data safe from unauthorized requests.
                </p>
                <p>
                    <strong>What happened?</strong><br>
                    The security token (CSRF token) associated with your request was missing, 
                    expired, or invalid. This can happen if:
                </p>
                <ul>
                    <li>Your session has been inactive for too long</li>
                    <li>You opened the page in multiple tabs</li>
                    <li>There was a network interruption</li>
                    <li>Your browser has security restrictions enabled</li>
                </ul>
                <p>
                    <strong>How to fix this:</strong><br>
                    Please refresh the page and try your action again. If the problem persists, 
                    try clearing your browser cache or contact support.
                </p>
                <div class="actions">
                    <a href="javascript:window.location.reload()" class="btn">Refresh Page</a>
                    <a href="javascript:history.back()" class="btn">Go Back</a>
                </div>
                {% if show_details %}
                <div class="details">
                    <strong>Technical Details:</strong><br>
                    Timestamp: {{ violation_info.timestamp }}<br>
                    Request ID: {{ violation_info.get('request_id', 'unknown') }}<br>
                    Violation Type: {{ violation_info.violation_type }}
                </div>
                {% endif %}
            </div>
        </body>
        </html>
        """
        
        show_details = current_app.config.get('DEBUG', False)
        return render_template_string(
            error_template,
            violation_info=violation_info,
            show_details=show_details
        )
    
    def get_protection_status(self) -> Dict[str, Any]:
        """
        Get current CSRF protection status and statistics.
        
        Returns:
            Dictionary containing protection status and metrics
        """
        return {
            'csrf_enabled': current_app.config.get('WTF_CSRF_ENABLED', False),
            'time_limit': current_app.config.get('WTF_CSRF_TIME_LIMIT'),
            'ssl_strict': current_app.config.get('WTF_CSRF_SSL_STRICT'),
            'protected_methods': current_app.config.get('WTF_CSRF_METHODS'),
            'exempt_routes_count': len(self._exempt_routes),
            'exempt_blueprints_count': len(self._exempt_blueprints),
            'api_endpoints_count': len(self._api_endpoints),
            'recent_violations': sum(self._violation_count.values()),
            'monitored_ips': len(self._violation_count),
            'monitoring_enabled': current_app.config.get('CSRF_MONITORING_ENABLED', True)
        }


# Global CSRF protection service instance
csrf_protection = CSRFProtectionService()


def init_csrf_protection(app: Flask) -> CSRFProtectionService:
    """
    Initialize CSRF protection service with Flask application factory pattern.
    
    This function provides a convenient way to set up CSRF protection during
    application factory initialization per Section 5.1.1.
    
    Args:
        app: Flask application instance
        
    Returns:
        Configured CSRFProtectionService instance
    """
    csrf_protection.init_app(app)
    
    # Configure common API exemptions per Section 4.6.2
    csrf_protection.register_api_endpoint('/api/v1/*')
    csrf_protection.register_api_endpoint('/api/v2/*')
    csrf_protection.exempt_blueprint('api')
    csrf_protection.exempt_blueprint('health')
    
    logger.info(
        "CSRF protection initialized with application factory",
        app_name=app.name,
        protection_status=csrf_protection.get_protection_status()
    )
    
    return csrf_protection


def get_csrf_token_for_ajax() -> str:
    """
    Convenience function to get CSRF token for AJAX requests.
    
    Designed for use in JavaScript contexts per Section 4.6.2.
    
    Returns:
        CSRF token string
    """
    return csrf_protection.get_csrf_token()


# Decorator exports for convenient use in blueprints
require_csrf = csrf_protection.require_csrf_token
csrf_exempt = csrf_protection.csrf_exempt