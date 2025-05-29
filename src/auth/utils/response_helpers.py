"""
Authentication Response Formatting Utilities

This module provides comprehensive HTTP response generation utilities for authentication
endpoints, ensuring standardized response formats across all authentication operations
while maintaining compatibility with existing client applications during the Node.js
to Flask migration.

Features:
- Standardized authentication response formatting per Section 4.6.3
- Consistent error handling with appropriate status codes per Section 4.6.3  
- JSON response compatibility with existing client applications per Section 0.2.1
- Authentication workflow response standardization per Section 4.6.1
- CSRF token response integration for web security per Section 4.6.2

Author: Flask Migration Team
Version: 1.0.0
Flask Version: 3.1.1
Python Version: 3.13.3
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union, List
import json
import logging
from enum import Enum

from flask import jsonify, request, g, current_app, Response
from flask_wtf.csrf import generate_csrf
from werkzeug.http import HTTP_STATUS_CODES

# Configure module logger
logger = logging.getLogger(__name__)


class AuthResponseStatus(Enum):
    """Authentication response status enumeration for consistent status reporting."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class AuthErrorCode(Enum):
    """Standardized authentication error codes for client compatibility."""
    # Authentication Errors (1000-1099)
    INVALID_CREDENTIALS = "AUTH_1001"
    INVALID_TOKEN = "AUTH_1002"
    TOKEN_EXPIRED = "AUTH_1003"
    TOKEN_MISSING = "AUTH_1004"
    TOKEN_MALFORMED = "AUTH_1005"
    INVALID_REFRESH_TOKEN = "AUTH_1006"
    
    # Authorization Errors (1100-1199)
    INSUFFICIENT_PERMISSIONS = "AUTH_1101"
    ACCESS_DENIED = "AUTH_1102"
    ROLE_REQUIRED = "AUTH_1103"
    PERMISSION_REQUIRED = "AUTH_1104"
    
    # Session Errors (1200-1299)
    SESSION_EXPIRED = "AUTH_1201"
    SESSION_INVALID = "AUTH_1202"
    SESSION_NOT_FOUND = "AUTH_1203"
    CONCURRENT_SESSION_LIMIT = "AUTH_1204"
    
    # Validation Errors (1300-1399)
    INVALID_INPUT = "AUTH_1301"
    MISSING_REQUIRED_FIELD = "AUTH_1302"
    INVALID_EMAIL_FORMAT = "AUTH_1303"
    PASSWORD_TOO_WEAK = "AUTH_1304"
    CSRF_TOKEN_MISSING = "AUTH_1305"
    CSRF_TOKEN_INVALID = "AUTH_1306"
    
    # Rate Limiting Errors (1400-1499)
    RATE_LIMIT_EXCEEDED = "AUTH_1401"
    TOO_MANY_ATTEMPTS = "AUTH_1402"
    
    # Server Errors (1500-1599)
    INTERNAL_SERVER_ERROR = "AUTH_1501"
    SERVICE_UNAVAILABLE = "AUTH_1502"
    DATABASE_ERROR = "AUTH_1503"
    EXTERNAL_SERVICE_ERROR = "AUTH_1504"


# HTTP Status Code Mappings for Authentication Errors
AUTH_ERROR_STATUS_CODES = {
    AuthErrorCode.INVALID_CREDENTIALS: 401,
    AuthErrorCode.INVALID_TOKEN: 401,
    AuthErrorCode.TOKEN_EXPIRED: 401,
    AuthErrorCode.TOKEN_MISSING: 401,
    AuthErrorCode.TOKEN_MALFORMED: 401,
    AuthErrorCode.INVALID_REFRESH_TOKEN: 401,
    AuthErrorCode.INSUFFICIENT_PERMISSIONS: 403,
    AuthErrorCode.ACCESS_DENIED: 403,
    AuthErrorCode.ROLE_REQUIRED: 403,
    AuthErrorCode.PERMISSION_REQUIRED: 403,
    AuthErrorCode.SESSION_EXPIRED: 401,
    AuthErrorCode.SESSION_INVALID: 401,
    AuthErrorCode.SESSION_NOT_FOUND: 401,
    AuthErrorCode.CONCURRENT_SESSION_LIMIT: 429,
    AuthErrorCode.INVALID_INPUT: 400,
    AuthErrorCode.MISSING_REQUIRED_FIELD: 400,
    AuthErrorCode.INVALID_EMAIL_FORMAT: 400,
    AuthErrorCode.PASSWORD_TOO_WEAK: 400,
    AuthErrorCode.CSRF_TOKEN_MISSING: 400,
    AuthErrorCode.CSRF_TOKEN_INVALID: 400,
    AuthErrorCode.RATE_LIMIT_EXCEEDED: 429,
    AuthErrorCode.TOO_MANY_ATTEMPTS: 429,
    AuthErrorCode.INTERNAL_SERVER_ERROR: 500,
    AuthErrorCode.SERVICE_UNAVAILABLE: 503,
    AuthErrorCode.DATABASE_ERROR: 500,
    AuthErrorCode.EXTERNAL_SERVICE_ERROR: 502,
}


def _get_request_metadata() -> Dict[str, Any]:
    """
    Extract request metadata for response enrichment.
    
    Returns:
        Dict containing request metadata including timestamp, request ID, and client info
    """
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request_id": getattr(g, 'request_id', None),
        "endpoint": request.endpoint,
        "method": request.method,
        "user_agent": request.headers.get('User-Agent'),
        "ip_address": request.remote_addr,
        "blueprint": getattr(g, 'blueprint_name', request.blueprint)
    }


def _add_security_headers(response: Response) -> Response:
    """
    Add security headers to authentication responses.
    
    Args:
        response: Flask Response object to enhance with security headers
        
    Returns:
        Enhanced Response object with security headers
    """
    # Security headers for authentication endpoints
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response


def _add_csrf_token(response_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add CSRF token to response data for web security.
    
    Args:
        response_data: Response data dictionary to enhance with CSRF token
        
    Returns:
        Enhanced response data with CSRF token
    """
    try:
        csrf_token = generate_csrf()
        response_data["csrf_token"] = csrf_token
        logger.debug("CSRF token added to authentication response")
    except Exception as e:
        logger.warning(f"Failed to generate CSRF token: {str(e)}")
        # Don't fail the response for CSRF token generation issues
    
    return response_data


def create_auth_response(
    status: AuthResponseStatus,
    message: str,
    data: Optional[Dict[str, Any]] = None,
    status_code: int = 200,
    include_csrf: bool = True,
    additional_headers: Optional[Dict[str, str]] = None
) -> Response:
    """
    Create standardized authentication response with consistent formatting.
    
    Args:
        status: Response status from AuthResponseStatus enum
        message: Human-readable message describing the response
        data: Optional data payload to include in response
        status_code: HTTP status code for the response
        include_csrf: Whether to include CSRF token in response
        additional_headers: Optional additional headers to include
        
    Returns:
        Flask Response object with standardized authentication response format
    """
    # Build response data structure
    response_data = {
        "status": status.value,
        "message": message,
        "data": data or {},
        "meta": _get_request_metadata()
    }
    
    # Add CSRF token for web security if requested
    if include_csrf and status == AuthResponseStatus.SUCCESS:
        response_data = _add_csrf_token(response_data)
    
    # Create JSON response
    response = jsonify(response_data)
    response.status_code = status_code
    
    # Add security headers
    response = _add_security_headers(response)
    
    # Add any additional headers
    if additional_headers:
        for key, value in additional_headers.items():
            response.headers[key] = value
    
    # Log response creation for monitoring
    logger.info(
        "Authentication response created",
        extra={
            "status": status.value,
            "status_code": status_code,
            "endpoint": request.endpoint,
            "request_id": getattr(g, 'request_id', None)
        }
    )
    
    return response


def success_response(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    status_code: int = 200,
    include_csrf: bool = True,
    additional_headers: Optional[Dict[str, str]] = None
) -> Response:
    """
    Create standardized success response for authentication operations.
    
    Args:
        message: Success message to include in response
        data: Optional success data payload
        status_code: HTTP status code (default: 200)
        include_csrf: Whether to include CSRF token (default: True)
        additional_headers: Optional additional headers
        
    Returns:
        Flask Response object with standardized success format
    """
    return create_auth_response(
        status=AuthResponseStatus.SUCCESS,
        message=message,
        data=data,
        status_code=status_code,
        include_csrf=include_csrf,
        additional_headers=additional_headers
    )


def error_response(
    error_code: AuthErrorCode,
    message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    status_code: Optional[int] = None,
    additional_headers: Optional[Dict[str, str]] = None
) -> Response:
    """
    Create standardized error response for authentication failures.
    
    Args:
        error_code: Authentication error code from AuthErrorCode enum
        message: Optional custom error message (falls back to default)
        details: Optional error details for debugging
        status_code: Optional custom status code (falls back to mapped code)
        additional_headers: Optional additional headers
        
    Returns:
        Flask Response object with standardized error format
    """
    # Determine HTTP status code
    if status_code is None:
        status_code = AUTH_ERROR_STATUS_CODES.get(error_code, 500)
    
    # Generate default message if none provided
    if message is None:
        message = _get_default_error_message(error_code)
    
    # Build error data structure
    error_data = {
        "error_code": error_code.value,
        "error_type": _get_error_type(error_code),
        "details": details or {}
    }
    
    # Log error for monitoring and debugging
    logger.warning(
        "Authentication error response created",
        extra={
            "error_code": error_code.value,
            "status_code": status_code,
            "endpoint": request.endpoint,
            "request_id": getattr(g, 'request_id', None),
            "details": details
        }
    )
    
    return create_auth_response(
        status=AuthResponseStatus.ERROR,
        message=message,
        data=error_data,
        status_code=status_code,
        include_csrf=False,  # Don't include CSRF on error responses
        additional_headers=additional_headers
    )


def _get_default_error_message(error_code: AuthErrorCode) -> str:
    """
    Get default error message for authentication error codes.
    
    Args:
        error_code: Authentication error code
        
    Returns:
        Default error message string
    """
    error_messages = {
        AuthErrorCode.INVALID_CREDENTIALS: "Invalid username or password",
        AuthErrorCode.INVALID_TOKEN: "Authentication token is invalid",
        AuthErrorCode.TOKEN_EXPIRED: "Authentication token has expired",
        AuthErrorCode.TOKEN_MISSING: "Authentication token is required",
        AuthErrorCode.TOKEN_MALFORMED: "Authentication token format is invalid",
        AuthErrorCode.INVALID_REFRESH_TOKEN: "Refresh token is invalid or expired",
        AuthErrorCode.INSUFFICIENT_PERMISSIONS: "Insufficient permissions for this operation",
        AuthErrorCode.ACCESS_DENIED: "Access denied",
        AuthErrorCode.ROLE_REQUIRED: "Required role not assigned to user",
        AuthErrorCode.PERMISSION_REQUIRED: "Required permission not granted",
        AuthErrorCode.SESSION_EXPIRED: "User session has expired",
        AuthErrorCode.SESSION_INVALID: "User session is invalid",
        AuthErrorCode.SESSION_NOT_FOUND: "User session not found",
        AuthErrorCode.CONCURRENT_SESSION_LIMIT: "Maximum concurrent sessions exceeded",
        AuthErrorCode.INVALID_INPUT: "Invalid input provided",
        AuthErrorCode.MISSING_REQUIRED_FIELD: "Required field is missing",
        AuthErrorCode.INVALID_EMAIL_FORMAT: "Email address format is invalid",
        AuthErrorCode.PASSWORD_TOO_WEAK: "Password does not meet security requirements",
        AuthErrorCode.CSRF_TOKEN_MISSING: "CSRF token is required",
        AuthErrorCode.CSRF_TOKEN_INVALID: "CSRF token is invalid",
        AuthErrorCode.RATE_LIMIT_EXCEEDED: "Rate limit exceeded, please try again later",
        AuthErrorCode.TOO_MANY_ATTEMPTS: "Too many failed attempts, please try again later",
        AuthErrorCode.INTERNAL_SERVER_ERROR: "Internal server error occurred",
        AuthErrorCode.SERVICE_UNAVAILABLE: "Authentication service is temporarily unavailable",
        AuthErrorCode.DATABASE_ERROR: "Database error occurred",
        AuthErrorCode.EXTERNAL_SERVICE_ERROR: "External authentication service error"
    }
    
    return error_messages.get(error_code, "An authentication error occurred")


def _get_error_type(error_code: AuthErrorCode) -> str:
    """
    Get error type classification for error codes.
    
    Args:
        error_code: Authentication error code
        
    Returns:
        Error type classification string
    """
    if 1001 <= int(error_code.value.split('_')[1]) <= 1099:
        return "authentication_error"
    elif 1100 <= int(error_code.value.split('_')[1]) <= 1199:
        return "authorization_error"
    elif 1200 <= int(error_code.value.split('_')[1]) <= 1299:
        return "session_error"
    elif 1300 <= int(error_code.value.split('_')[1]) <= 1399:
        return "validation_error"
    elif 1400 <= int(error_code.value.split('_')[1]) <= 1499:
        return "rate_limit_error"
    elif 1500 <= int(error_code.value.split('_')[1]) <= 1599:
        return "server_error"
    else:
        return "unknown_error"


# Authentication Workflow-Specific Response Helpers

def login_success_response(
    user_data: Dict[str, Any],
    token_data: Optional[Dict[str, Any]] = None,
    session_data: Optional[Dict[str, Any]] = None
) -> Response:
    """
    Create standardized login success response.
    
    Args:
        user_data: User information to include in response
        token_data: Optional authentication token information
        session_data: Optional session information
        
    Returns:
        Flask Response object with login success format
    """
    response_data = {
        "user": user_data,
        "authentication": token_data or {},
        "session": session_data or {}
    }
    
    return success_response(
        message="Login successful",
        data=response_data,
        status_code=200,
        include_csrf=True
    )


def logout_success_response(message: str = "Logout successful") -> Response:
    """
    Create standardized logout success response.
    
    Args:
        message: Logout success message
        
    Returns:
        Flask Response object with logout success format
    """
    return success_response(
        message=message,
        data={"logged_out": True},
        status_code=200,
        include_csrf=False  # No CSRF needed after logout
    )


def token_refresh_success_response(
    token_data: Dict[str, Any],
    expires_in: Optional[int] = None
) -> Response:
    """
    Create standardized token refresh success response.
    
    Args:
        token_data: New token information
        expires_in: Token expiration time in seconds
        
    Returns:
        Flask Response object with token refresh success format
    """
    response_data = {
        "tokens": token_data,
        "expires_in": expires_in
    }
    
    if expires_in:
        response_data["expires_at"] = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat() + "Z"
    
    return success_response(
        message="Token refreshed successfully",
        data=response_data,
        status_code=200,
        include_csrf=True
    )


def registration_success_response(
    user_data: Dict[str, Any],
    requires_verification: bool = False
) -> Response:
    """
    Create standardized user registration success response.
    
    Args:
        user_data: Newly created user information
        requires_verification: Whether email verification is required
        
    Returns:
        Flask Response object with registration success format
    """
    response_data = {
        "user": user_data,
        "requires_verification": requires_verification
    }
    
    message = "Registration successful"
    if requires_verification:
        message += ". Please check your email for verification instructions."
    
    return success_response(
        message=message,
        data=response_data,
        status_code=201,  # Created
        include_csrf=True
    )


def password_reset_success_response(
    email: str,
    reset_token_sent: bool = True
) -> Response:
    """
    Create standardized password reset success response.
    
    Args:
        email: Email address where reset instructions were sent
        reset_token_sent: Whether reset token was successfully sent
        
    Returns:
        Flask Response object with password reset success format
    """
    response_data = {
        "email": email,
        "reset_instructions_sent": reset_token_sent
    }
    
    return success_response(
        message="Password reset instructions have been sent to your email",
        data=response_data,
        status_code=200,
        include_csrf=True
    )


def permission_check_response(
    has_permission: bool,
    required_permission: str,
    user_permissions: Optional[List[str]] = None
) -> Response:
    """
    Create standardized permission check response.
    
    Args:
        has_permission: Whether user has the required permission
        required_permission: The permission that was checked
        user_permissions: Optional list of user's current permissions
        
    Returns:
        Flask Response object with permission check result
    """
    if has_permission:
        response_data = {
            "permission": required_permission,
            "granted": True,
            "user_permissions": user_permissions or []
        }
        
        return success_response(
            message="Permission granted",
            data=response_data,
            status_code=200
        )
    else:
        return error_response(
            error_code=AuthErrorCode.PERMISSION_REQUIRED,
            details={
                "required_permission": required_permission,
                "user_permissions": user_permissions or []
            }
        )


def session_status_response(
    is_active: bool,
    session_data: Optional[Dict[str, Any]] = None,
    expires_at: Optional[datetime] = None
) -> Response:
    """
    Create standardized session status response.
    
    Args:
        is_active: Whether the session is currently active
        session_data: Optional session information
        expires_at: Optional session expiration time
        
    Returns:
        Flask Response object with session status information
    """
    response_data = {
        "active": is_active,
        "session": session_data or {},
        "expires_at": expires_at.isoformat() + "Z" if expires_at else None
    }
    
    if is_active:
        return success_response(
            message="Session is active",
            data=response_data,
            status_code=200
        )
    else:
        return error_response(
            error_code=AuthErrorCode.SESSION_EXPIRED,
            details=response_data
        )


def validation_error_response(
    validation_errors: Dict[str, List[str]],
    message: str = "Validation failed"
) -> Response:
    """
    Create standardized validation error response.
    
    Args:
        validation_errors: Dictionary of field names to error lists
        message: Overall validation error message
        
    Returns:
        Flask Response object with validation error details
    """
    return error_response(
        error_code=AuthErrorCode.INVALID_INPUT,
        message=message,
        details={
            "validation_errors": validation_errors,
            "error_count": sum(len(errors) for errors in validation_errors.values())
        }
    )


def rate_limit_error_response(
    limit: int,
    window_seconds: int,
    retry_after: Optional[int] = None
) -> Response:
    """
    Create standardized rate limit error response.
    
    Args:
        limit: Rate limit threshold that was exceeded
        window_seconds: Time window for the rate limit
        retry_after: Seconds to wait before retrying
        
    Returns:
        Flask Response object with rate limit error information
    """
    additional_headers = {}
    if retry_after:
        additional_headers['Retry-After'] = str(retry_after)
    
    return error_response(
        error_code=AuthErrorCode.RATE_LIMIT_EXCEEDED,
        details={
            "limit": limit,
            "window_seconds": window_seconds,
            "retry_after_seconds": retry_after
        },
        additional_headers=additional_headers
    )


# Utility Functions for Response Enhancement

def add_pagination_meta(
    response_data: Dict[str, Any],
    page: int,
    per_page: int,
    total: int,
    total_pages: int
) -> Dict[str, Any]:
    """
    Add pagination metadata to response data.
    
    Args:
        response_data: Existing response data to enhance
        page: Current page number
        per_page: Items per page
        total: Total number of items
        total_pages: Total number of pages
        
    Returns:
        Enhanced response data with pagination metadata
    """
    response_data["pagination"] = {
        "page": page,
        "per_page": per_page,
        "total": total,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "next_page": page + 1 if page < total_pages else None,
        "prev_page": page - 1 if page > 1 else None
    }
    
    return response_data


def sanitize_user_data(user_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize user data for safe inclusion in responses.
    
    Args:
        user_data: Raw user data dictionary
        
    Returns:
        Sanitized user data safe for client consumption
    """
    # Define safe fields that can be included in responses
    safe_fields = {
        'id', 'username', 'email', 'first_name', 'last_name', 
        'display_name', 'avatar_url', 'created_at', 'updated_at',
        'is_verified', 'is_active', 'last_login', 'roles', 'permissions'
    }
    
    # Remove sensitive fields and only include safe fields
    sanitized = {
        key: value for key, value in user_data.items() 
        if key in safe_fields
    }
    
    # Convert datetime objects to ISO format strings
    for key, value in sanitized.items():
        if isinstance(value, datetime):
            sanitized[key] = value.isoformat() + "Z"
    
    return sanitized


def get_client_info() -> Dict[str, Any]:
    """
    Extract client information from request for response metadata.
    
    Returns:
        Dictionary containing client information
    """
    return {
        "user_agent": request.headers.get('User-Agent'),
        "ip_address": request.remote_addr,
        "accept_language": request.headers.get('Accept-Language'),
        "referer": request.headers.get('Referer'),
        "origin": request.headers.get('Origin')
    }


# Response Status Code Utilities

def is_success_status(status_code: int) -> bool:
    """Check if status code indicates success (2xx)."""
    return 200 <= status_code < 300


def is_client_error_status(status_code: int) -> bool:
    """Check if status code indicates client error (4xx)."""
    return 400 <= status_code < 500


def is_server_error_status(status_code: int) -> bool:
    """Check if status code indicates server error (5xx)."""
    return 500 <= status_code < 600


def get_status_message(status_code: int) -> str:
    """Get HTTP status message for status code."""
    return HTTP_STATUS_CODES.get(status_code, "Unknown Status")


# Module Configuration and Initialization

def init_response_helpers(app):
    """
    Initialize response helpers with Flask application.
    
    Args:
        app: Flask application instance
    """
    # Configure logging for the module
    if not app.debug:
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s [%(name)s] %(message)s'
        )
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    # Store reference to app for access to configuration
    app.auth_response_helpers = {
        'success_response': success_response,
        'error_response': error_response,
        'login_success_response': login_success_response,
        'logout_success_response': logout_success_response,
        'token_refresh_success_response': token_refresh_success_response,
        'validation_error_response': validation_error_response,
        'rate_limit_error_response': rate_limit_error_response
    }
    
    logger.info("Authentication response helpers initialized successfully")


if __name__ == "__main__":
    # Module self-test functionality
    print("Authentication Response Helpers Module")
    print("=====================================")
    print(f"Available error codes: {len(AuthErrorCode)}")
    print(f"Available response statuses: {len(AuthResponseStatus)}")
    print("Module loaded successfully!")