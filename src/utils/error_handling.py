"""
Error handling and exception management utilities for Flask application.

This module provides comprehensive error handling capabilities including:
- Flask error handlers for standardized responses
- Custom exception hierarchy for business logic errors
- Error logging integration with security monitoring
- Error recovery and resilience patterns
- API-compatible error response formatting

Technical Requirements:
- Flask 3.1.1 error handling framework per Section 5.4.3
- Custom exception hierarchy per Section 5.2.3
- Security monitoring integration per Section 6.4.6.1
- API compatibility during migration per Section 0.2.1
- Python 3.13.3 runtime compatibility

Integration Points:
- Flask application factory pattern for error handler registration
- src/utils/logging.py for structured logging
- src/utils/response.py for standardized response formatting
- src/auth/security_monitor.py for security event correlation
- Prometheus metrics for error rate monitoring
"""

import traceback
import sys
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, Type, Union, List, Tuple
from functools import wraps
from enum import Enum
import json

from flask import Flask, request, jsonify, g, current_app
from werkzeug.exceptions import HTTPException
import structlog

# Import application utilities
from src.utils.logging import get_logger, log_security_event
from src.utils.response import create_error_response, create_api_response


class ErrorSeverity(Enum):
    """Error severity levels for monitoring and alerting."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification and handling."""
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    BUSINESS_LOGIC = "business_logic"
    DATABASE = "database"
    EXTERNAL_SERVICE = "external_service"
    SYSTEM = "system"
    SECURITY = "security"
    MIGRATION = "migration"
    PYTHON_RUNTIME = "python_runtime"


# ==================== CUSTOM EXCEPTION HIERARCHY ====================

class BaseApplicationError(Exception):
    """
    Base exception class for all application-specific errors.
    
    Provides common error attributes and standardized error handling
    across the Flask application with security monitoring integration.
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = None,
        details: Dict[str, Any] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        user_message: str = None,
        status_code: int = 500,
        correlation_id: str = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.severity = severity
        self.category = category
        self.user_message = user_message or "An error occurred while processing your request"
        self.status_code = status_code
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        
        # Add request context if available
        if request:
            self.details.update({
                'request_method': request.method,
                'request_url': request.url,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'blueprint': getattr(g, 'blueprint_name', None),
                'endpoint': getattr(g, 'endpoint_name', None),
                'user_id': getattr(g, 'user_id', None)
            })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary format for logging and response."""
        return {
            'error_code': self.error_code,
            'message': self.message,
            'user_message': self.user_message,
            'severity': self.severity.value,
            'category': self.category.value,
            'status_code': self.status_code,
            'correlation_id': self.correlation_id,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'type': self.__class__.__name__
        }


class ValidationError(BaseApplicationError):
    """Raised when input validation fails."""
    
    def __init__(
        self,
        message: str,
        field_errors: Dict[str, List[str]] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.VALIDATION,
            status_code=400,
            user_message="Please check your input and try again",
            **kwargs
        )
        self.field_errors = field_errors or {}
        self.details['field_errors'] = self.field_errors


class AuthenticationError(BaseApplicationError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication required", **kwargs):
        super().__init__(
            message=message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHENTICATION,
            status_code=401,
            user_message="Please log in to access this resource",
            **kwargs
        )


class AuthorizationError(BaseApplicationError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(
            message=message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHORIZATION,
            status_code=403,
            user_message="You don't have permission to access this resource",
            **kwargs
        )


class BusinessLogicError(BaseApplicationError):
    """Raised when business logic validation fails."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message=message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.BUSINESS_LOGIC,
            status_code=422,
            user_message="Business rule validation failed",
            **kwargs
        )


class DatabaseError(BaseApplicationError):
    """Raised when database operations fail."""
    
    def __init__(
        self,
        message: str,
        operation: str = None,
        table: str = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.DATABASE,
            status_code=500,
            user_message="A database error occurred. Please try again later",
            **kwargs
        )
        if operation:
            self.details['database_operation'] = operation
        if table:
            self.details['table_name'] = table


class ExternalServiceError(BaseApplicationError):
    """Raised when external service calls fail."""
    
    def __init__(
        self,
        message: str,
        service_name: str = None,
        response_code: int = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.EXTERNAL_SERVICE,
            status_code=502,
            user_message="External service unavailable. Please try again later",
            **kwargs
        )
        if service_name:
            self.details['service_name'] = service_name
        if response_code:
            self.details['service_response_code'] = response_code


class SecurityError(BaseApplicationError):
    """Raised when security violations are detected."""
    
    def __init__(self, message: str, threat_type: str = None, **kwargs):
        super().__init__(
            message=message,
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.SECURITY,
            status_code=403,
            user_message="Security violation detected",
            **kwargs
        )
        if threat_type:
            self.details['threat_type'] = threat_type


class MigrationError(BaseApplicationError):
    """Raised during migration-specific operations."""
    
    def __init__(
        self,
        message: str,
        migration_step: str = None,
        rollback_available: bool = True,
        **kwargs
    ):
        super().__init__(
            message=message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.MIGRATION,
            status_code=500,
            user_message="Migration operation failed",
            **kwargs
        )
        if migration_step:
            self.details['migration_step'] = migration_step
        self.details['rollback_available'] = rollback_available


class PythonRuntimeError(BaseApplicationError):
    """Raised for Python runtime and Flask-specific errors."""
    
    def __init__(
        self,
        message: str,
        python_exception: Exception = None,
        traceback_info: str = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.PYTHON_RUNTIME,
            status_code=500,
            user_message="A system error occurred. Please try again later",
            **kwargs
        )
        if python_exception:
            self.details['python_exception_type'] = type(python_exception).__name__
            self.details['python_exception_message'] = str(python_exception)
        if traceback_info:
            self.details['traceback'] = traceback_info


# ==================== ERROR RECOVERY PATTERNS ====================

class CircuitBreakerError(ExternalServiceError):
    """Raised when circuit breaker is open."""
    
    def __init__(self, service_name: str, **kwargs):
        super().__init__(
            message=f"Circuit breaker open for service: {service_name}",
            service_name=service_name,
            user_message="Service temporarily unavailable. Please try again later",
            **kwargs
        )


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for error recovery.
    
    Provides resilience against cascading failures when external
    services are unavailable or responding slowly.
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Type[Exception] = Exception
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        
        self.logger = get_logger(f"circuit_breaker.{name}")
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt to reset."""
        if self.state == 'OPEN' and self.last_failure_time:
            time_since_failure = datetime.utcnow() - self.last_failure_time
            return time_since_failure.total_seconds() >= self.recovery_timeout
        return False
    
    def _on_success(self):
        """Handle successful operation."""
        self.failure_count = 0
        self.last_failure_time = None
        
        if self.state == 'HALF_OPEN':
            self.state = 'CLOSED'
            self.logger.info("Circuit breaker reset to CLOSED state", service=self.name)
    
    def _on_failure(self, exception: Exception):
        """Handle failed operation."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.failure_count >= self.failure_threshold:
            self.state = 'OPEN'
            self.logger.error(
                "Circuit breaker opened",
                service=self.name,
                failure_count=self.failure_count,
                exception_type=type(exception).__name__
            )
    
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == 'OPEN':
            if self._should_attempt_reset():
                self.state = 'HALF_OPEN'
                self.logger.info("Circuit breaker attempting reset", service=self.name)
            else:
                raise CircuitBreakerError(self.name)
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure(e)
            raise


# ==================== ERROR HANDLER REGISTRATION ====================

class FlaskErrorHandler:
    """
    Comprehensive Flask error handler management.
    
    Registers error handlers with Flask application factory pattern
    and provides consistent error response formatting across all
    blueprints and services.
    """
    
    def __init__(self, app: Flask = None):
        self.app = app
        self.logger = get_logger("error_handler")
        self.error_metrics = {}
        
        if app:
            self.init_app(app)
    
    def init_app(self, app: Flask):
        """Initialize error handlers with Flask application factory."""
        self.app = app
        
        # Register error handlers
        self._register_http_error_handlers(app)
        self._register_exception_handlers(app)
        self._register_before_request_handlers(app)
        self._register_after_request_handlers(app)
        
        self.logger.info("Flask error handlers registered successfully")
    
    def _register_http_error_handlers(self, app: Flask):
        """Register HTTP error handlers for standard status codes."""
        
        @app.errorhandler(400)
        def handle_bad_request(error):
            return self._handle_http_error(error, "Bad Request")
        
        @app.errorhandler(401)
        def handle_unauthorized(error):
            self._log_security_event("unauthorized_access", error)
            return self._handle_http_error(error, "Authentication required")
        
        @app.errorhandler(403)
        def handle_forbidden(error):
            self._log_security_event("forbidden_access", error)
            return self._handle_http_error(error, "Access denied")
        
        @app.errorhandler(404)
        def handle_not_found(error):
            return self._handle_http_error(error, "Resource not found")
        
        @app.errorhandler(405)
        def handle_method_not_allowed(error):
            return self._handle_http_error(error, "Method not allowed")
        
        @app.errorhandler(413)
        def handle_payload_too_large(error):
            return self._handle_http_error(error, "Request payload too large")
        
        @app.errorhandler(422)
        def handle_unprocessable_entity(error):
            return self._handle_http_error(error, "Unprocessable entity")
        
        @app.errorhandler(429)
        def handle_too_many_requests(error):
            self._log_security_event("rate_limit_exceeded", error)
            return self._handle_http_error(error, "Too many requests")
        
        @app.errorhandler(500)
        def handle_internal_server_error(error):
            return self._handle_http_error(error, "Internal server error")
        
        @app.errorhandler(502)
        def handle_bad_gateway(error):
            return self._handle_http_error(error, "External service unavailable")
        
        @app.errorhandler(503)
        def handle_service_unavailable(error):
            return self._handle_http_error(error, "Service temporarily unavailable")
    
    def _register_exception_handlers(self, app: Flask):
        """Register handlers for custom application exceptions."""
        
        @app.errorhandler(BaseApplicationError)
        def handle_application_error(error: BaseApplicationError):
            return self._handle_application_error(error)
        
        @app.errorhandler(ValidationError)
        def handle_validation_error(error: ValidationError):
            return self._handle_validation_error(error)
        
        @app.errorhandler(SecurityError)
        def handle_security_error(error: SecurityError):
            self._log_security_event("security_violation", error)
            return self._handle_application_error(error)
        
        @app.errorhandler(Exception)
        def handle_generic_exception(error: Exception):
            return self._handle_generic_exception(error)
    
    def _register_before_request_handlers(self, app: Flask):
        """Register before request handlers for error context setup."""
        
        @app.before_request
        def setup_error_context():
            """Setup error handling context for the request."""
            g.request_id = str(uuid.uuid4())
            g.start_time = datetime.utcnow()
            g.blueprint_name = request.blueprint
            g.endpoint_name = request.endpoint
    
    def _register_after_request_handlers(self, app: Flask):
        """Register after request handlers for error metrics collection."""
        
        @app.after_request
        def collect_error_metrics(response):
            """Collect error metrics and update monitoring data."""
            try:
                if response.status_code >= 400:
                    self._record_error_metric(response.status_code)
                    
                    # Log high-priority errors
                    if response.status_code >= 500:
                        self.logger.error(
                            "Server error response",
                            status_code=response.status_code,
                            request_id=getattr(g, 'request_id', None),
                            blueprint=getattr(g, 'blueprint_name', None),
                            endpoint=getattr(g, 'endpoint_name', None),
                            duration=self._calculate_request_duration()
                        )
                
                return response
            except Exception as e:
                self.logger.error("Error in after_request handler", error=str(e))
                return response
    
    def _handle_http_error(self, error: HTTPException, message: str) -> Tuple[Dict[str, Any], int]:
        """Handle standard HTTP errors with consistent formatting."""
        error_data = {
            'error': True,
            'error_code': f'HTTP_{error.code}',
            'message': message,
            'status_code': error.code,
            'correlation_id': getattr(g, 'request_id', str(uuid.uuid4())),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add description for some error codes
        if hasattr(error, 'description') and error.description:
            error_data['description'] = error.description
        
        self.logger.warning(
            f"HTTP error {error.code}",
            **error_data
        )
        
        return jsonify(error_data), error.code
    
    def _handle_application_error(self, error: BaseApplicationError) -> Tuple[Dict[str, Any], int]:
        """Handle custom application errors with full context."""
        error_dict = error.to_dict()
        
        # Log error with appropriate level based on severity
        log_level = self._get_log_level_for_severity(error.severity)
        self.logger.log(
            log_level,
            f"Application error: {error.error_code}",
            **error_dict
        )
        
        # Create API response
        response_data = {
            'error': True,
            'error_code': error.error_code,
            'message': error.user_message,
            'correlation_id': error.correlation_id,
            'timestamp': error.timestamp.isoformat()
        }
        
        # Add field errors for validation errors
        if isinstance(error, ValidationError) and error.field_errors:
            response_data['field_errors'] = error.field_errors
        
        # Add details for development environment
        if current_app.debug:
            response_data['debug_info'] = {
                'technical_message': error.message,
                'details': error.details,
                'category': error.category.value,
                'severity': error.severity.value
            }
        
        return jsonify(response_data), error.status_code
    
    def _handle_validation_error(self, error: ValidationError) -> Tuple[Dict[str, Any], int]:
        """Handle validation errors with field-level details."""
        response_data = {
            'error': True,
            'error_code': 'VALIDATION_ERROR',
            'message': error.user_message,
            'field_errors': error.field_errors,
            'correlation_id': error.correlation_id,
            'timestamp': error.timestamp.isoformat()
        }
        
        self.logger.warning(
            "Validation error",
            **error.to_dict()
        )
        
        return jsonify(response_data), error.status_code
    
    def _handle_generic_exception(self, error: Exception) -> Tuple[Dict[str, Any], int]:
        """Handle unexpected exceptions with security considerations."""
        # Generate correlation ID for tracking
        correlation_id = str(uuid.uuid4())
        
        # Get traceback information
        exc_info = sys.exc_info()
        traceback_str = ''.join(traceback.format_exception(*exc_info))
        
        # Create Python runtime error for proper categorization
        python_error = PythonRuntimeError(
            message=f"Unhandled {type(error).__name__}: {str(error)}",
            python_exception=error,
            traceback_info=traceback_str,
            correlation_id=correlation_id
        )
        
        # Log critical error
        self.logger.critical(
            "Unhandled exception",
            **python_error.to_dict()
        )
        
        # Check if this might be a security-related error
        self._check_for_security_implications(error, traceback_str)
        
        # Return generic error response (don't expose internal details)
        response_data = {
            'error': True,
            'error_code': 'INTERNAL_ERROR',
            'message': 'An unexpected error occurred. Please try again later.',
            'correlation_id': correlation_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Add debug info in development
        if current_app.debug:
            response_data['debug_info'] = {
                'exception_type': type(error).__name__,
                'exception_message': str(error),
                'traceback': traceback_str
            }
        
        return jsonify(response_data), 500
    
    def _log_security_event(self, event_type: str, error: Union[Exception, HTTPException]):
        """Log security-related events for monitoring."""
        try:
            event_data = {
                'event_type': event_type,
                'error_type': type(error).__name__,
                'status_code': getattr(error, 'code', None) or getattr(error, 'status_code', None),
                'request_method': request.method,
                'request_url': request.url,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'user_id': getattr(g, 'user_id', None),
                'session_id': getattr(g, 'session_id', None),
                'correlation_id': getattr(g, 'request_id', str(uuid.uuid4()))
            }
            
            # Use security monitoring integration if available
            try:
                log_security_event(event_type, 'warning', event_data)
            except ImportError:
                # Fallback to regular logging if security module not available
                self.logger.warning(f"Security event: {event_type}", **event_data)
        except Exception as e:
            self.logger.error("Failed to log security event", error=str(e))
    
    def _check_for_security_implications(self, error: Exception, traceback_str: str):
        """Check if exception might have security implications."""
        security_keywords = [
            'sql', 'injection', 'xss', 'csrf', 'authentication',
            'authorization', 'permission', 'access', 'token'
        ]
        
        error_text = f"{str(error)} {traceback_str}".lower()
        
        for keyword in security_keywords:
            if keyword in error_text:
                self._log_security_event("potential_security_exception", error)
                break
    
    def _record_error_metric(self, status_code: int):
        """Record error metrics for monitoring."""
        try:
            # Update error count metrics
            if status_code not in self.error_metrics:
                self.error_metrics[status_code] = 0
            self.error_metrics[status_code] += 1
            
            # Update Prometheus metrics if available
            if hasattr(current_app, 'prometheus_metrics'):
                current_app.prometheus_metrics.track_security_event(
                    event_type='http_error',
                    severity='medium' if 400 <= status_code < 500 else 'high',
                    details={'status_code': status_code}
                )
        except Exception as e:
            self.logger.error("Failed to record error metric", error=str(e))
    
    def _get_log_level_for_severity(self, severity: ErrorSeverity) -> str:
        """Get log level based on error severity."""
        severity_mapping = {
            ErrorSeverity.LOW: 'info',
            ErrorSeverity.MEDIUM: 'warning',
            ErrorSeverity.HIGH: 'error',
            ErrorSeverity.CRITICAL: 'critical'
        }
        return severity_mapping.get(severity, 'warning')
    
    def _calculate_request_duration(self) -> Optional[float]:
        """Calculate request duration in seconds."""
        try:
            start_time = getattr(g, 'start_time', None)
            if start_time:
                duration = (datetime.utcnow() - start_time).total_seconds()
                return round(duration, 3)
        except Exception:
            pass
        return None
    
    def get_error_metrics(self) -> Dict[str, Any]:
        """Get current error metrics for monitoring."""
        return {
            'error_counts': self.error_metrics.copy(),
            'total_errors': sum(self.error_metrics.values()),
            'timestamp': datetime.utcnow().isoformat()
        }


# ==================== ERROR HANDLER DECORATORS ====================

def handle_errors(
    fallback_response: Any = None,
    log_errors: bool = True,
    reraise_on: Tuple[Type[Exception], ...] = ()
):
    """
    Decorator for consistent error handling in Flask routes and services.
    
    Args:
        fallback_response: Response to return on error
        log_errors: Whether to log errors
        reraise_on: Exception types to re-raise instead of handling
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except reraise_on:
                raise
            except BaseApplicationError as e:
                if log_errors:
                    logger = get_logger(f"error_handler.{func.__name__}")
                    logger.error(f"Application error in {func.__name__}", **e.to_dict())
                raise
            except Exception as e:
                if log_errors:
                    logger = get_logger(f"error_handler.{func.__name__}")
                    logger.error(
                        f"Unexpected error in {func.__name__}",
                        error_type=type(e).__name__,
                        error_message=str(e),
                        traceback=traceback.format_exc()
                    )
                
                if fallback_response is not None:
                    return fallback_response
                
                # Convert to application error
                python_error = PythonRuntimeError(
                    message=f"Error in {func.__name__}: {str(e)}",
                    python_exception=e,
                    traceback_info=traceback.format_exc()
                )
                raise python_error
        
        return wrapper
    return decorator


def require_no_errors(error_message: str = "Operation failed"):
    """
    Decorator that converts any exception to BusinessLogicError.
    
    Useful for critical operations that should not fail silently.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BaseApplicationError:
                raise
            except Exception as e:
                raise BusinessLogicError(
                    message=f"{error_message}: {str(e)}",
                    details={
                        'function': func.__name__,
                        'original_error': str(e),
                        'original_error_type': type(e).__name__
                    }
                )
        return wrapper
    return decorator


# ==================== UTILITY FUNCTIONS ====================

def raise_for_status(response, service_name: str = "external_service"):
    """
    Raise ExternalServiceError for HTTP error status codes.
    
    Similar to requests.Response.raise_for_status() but with
    application-specific error handling.
    """
    if hasattr(response, 'status_code'):
        status_code = response.status_code
        if 400 <= status_code < 600:
            raise ExternalServiceError(
                message=f"HTTP {status_code} error from {service_name}",
                service_name=service_name,
                response_code=status_code,
                details={
                    'response_text': getattr(response, 'text', ''),
                    'response_headers': dict(getattr(response, 'headers', {}))
                }
            )


def safe_execute(
    func,
    *args,
    default_return=None,
    exception_types: Tuple[Type[Exception], ...] = (Exception,),
    log_exceptions: bool = True,
    **kwargs
):
    """
    Safely execute a function with error handling.
    
    Returns default_return on exception instead of raising.
    Useful for non-critical operations that should not fail the entire request.
    """
    try:
        return func(*args, **kwargs)
    except exception_types as e:
        if log_exceptions:
            logger = get_logger("safe_execute")
            logger.warning(
                f"Safe execution failed for {func.__name__}",
                error_type=type(e).__name__,
                error_message=str(e),
                args=str(args)[:200],
                kwargs=str(kwargs)[:200]
            )
        return default_return


def create_error_context(
    operation: str,
    user_id: str = None,
    additional_context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Create standardized error context for consistent error reporting.
    
    Args:
        operation: Name of the operation being performed
        user_id: ID of the user performing the operation
        additional_context: Additional context information
    
    Returns:
        Dictionary with standardized error context
    """
    context = {
        'operation': operation,
        'timestamp': datetime.utcnow().isoformat(),
        'correlation_id': str(uuid.uuid4()),
        'user_id': user_id,
        'request_id': getattr(g, 'request_id', None),
        'blueprint': getattr(g, 'blueprint_name', None),
        'endpoint': getattr(g, 'endpoint_name', None)
    }
    
    if additional_context:
        context.update(additional_context)
    
    return context


# ==================== MIGRATION-SPECIFIC ERROR HANDLING ====================

class DatabaseMigrationError(MigrationError):
    """Specific error for database migration failures."""
    
    def __init__(
        self,
        message: str,
        migration_version: str = None,
        affected_tables: List[str] = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            migration_step="database_migration",
            **kwargs
        )
        if migration_version:
            self.details['migration_version'] = migration_version
        if affected_tables:
            self.details['affected_tables'] = affected_tables


class ApiParityError(MigrationError):
    """Error when API response doesn't match Node.js implementation."""
    
    def __init__(
        self,
        message: str,
        endpoint: str = None,
        expected_response: Any = None,
        actual_response: Any = None,
        **kwargs
    ):
        super().__init__(
            message=message,
            migration_step="api_parity_validation",
            **kwargs
        )
        if endpoint:
            self.details['endpoint'] = endpoint
        if expected_response is not None:
            self.details['expected_response'] = str(expected_response)[:500]
        if actual_response is not None:
            self.details['actual_response'] = str(actual_response)[:500]


# ==================== MODULE INITIALIZATION ====================

# Global error handler instance
_error_handler = None


def init_error_handling(app: Flask) -> FlaskErrorHandler:
    """
    Initialize error handling for Flask application.
    
    This function should be called during Flask application factory
    initialization to register all error handlers and setup error
    monitoring integration.
    
    Args:
        app: Flask application instance
    
    Returns:
        FlaskErrorHandler instance
    """
    global _error_handler
    _error_handler = FlaskErrorHandler(app)
    
    # Store reference in app for access in other modules
    app.error_handler = _error_handler
    
    return _error_handler


def get_error_handler() -> Optional[FlaskErrorHandler]:
    """Get the global error handler instance."""
    return _error_handler


# ==================== EXPORTS ====================

__all__ = [
    # Exception classes
    'BaseApplicationError',
    'ValidationError',
    'AuthenticationError',
    'AuthorizationError',
    'BusinessLogicError',
    'DatabaseError',
    'ExternalServiceError',
    'SecurityError',
    'MigrationError',
    'PythonRuntimeError',
    'DatabaseMigrationError',
    'ApiParityError',
    
    # Error handling classes
    'FlaskErrorHandler',
    'CircuitBreaker',
    'CircuitBreakerError',
    
    # Enums
    'ErrorSeverity',
    'ErrorCategory',
    
    # Decorators
    'handle_errors',
    'require_no_errors',
    
    # Utility functions
    'raise_for_status',
    'safe_execute',
    'create_error_context',
    'init_error_handling',
    'get_error_handler'
]