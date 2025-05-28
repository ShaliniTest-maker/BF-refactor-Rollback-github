"""
Authentication response formatting utilities providing consistent HTTP response generation
for authentication endpoints, error handling, and status communication.

This module ensures standardized response formats across all authentication operations
while maintaining compatibility with existing client applications during the Node.js to Flask migration.

Key Features:
- Standardized authentication response formatting (Section 4.6.3)
- Consistent error handling with HTTP status codes (Section 4.6.3)
- JSON response compatibility with existing clients (Section 0.2.1)
- Authentication workflow response standardization (Section 4.6.1)
- CSRF token integration for web security (Section 4.6.2)
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, List
from http import HTTPStatus
import logging

from flask import jsonify, request, current_app, Response, session
from flask_wtf.csrf import generate_csrf, validate_csrf
from werkzeug.http import HTTP_STATUS_CODES

# Configure module logger
logger = logging.getLogger(__name__)


class ResponseFormat:
    """
    Standard response format structure for authentication endpoints.
    Ensures consistent response patterns across all authentication operations.
    """
    
    @staticmethod
    def success(
        data: Optional[Dict[str, Any]] = None,
        message: str = "Operation successful",
        status_code: int = HTTPStatus.OK,
        include_csrf: bool = False,
        additional_headers: Optional[Dict[str, str]] = None
    ) -> Response:
        """
        Generate standardized success response for authentication operations.
        
        Args:
            data: Response data payload
            message: Success message for client feedback
            status_code: HTTP status code (default: 200)
            include_csrf: Whether to include CSRF token in response
            additional_headers: Additional HTTP headers to include
            
        Returns:
            Flask Response object with standardized JSON format
        """
        response_payload = {
            "success": True,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status_code": status_code
        }
        
        if data is not None:
            response_payload["data"] = data
            
        # Include CSRF token if requested
        if include_csrf:
            try:
                csrf_token = generate_csrf()
                response_payload["csrf_token"] = csrf_token
                logger.debug("CSRF token included in authentication response")
            except Exception as e:
                logger.warning(f"Failed to generate CSRF token: {str(e)}")
        
        # Create JSON response
        response = jsonify(response_payload)
        response.status_code = status_code
        
        # Add additional headers if provided
        if additional_headers:
            for header_name, header_value in additional_headers.items():
                response.headers[header_name] = header_value
        
        # Set security headers for authentication responses
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        logger.info(f"Authentication success response generated: {message}")
        return response
    
    @staticmethod
    def error(
        message: str,
        status_code: int = HTTPStatus.BAD_REQUEST,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        include_csrf: bool = False
    ) -> Response:
        """
        Generate standardized error response for authentication operations.
        
        Args:
            message: Error message for client feedback
            status_code: HTTP status code
            error_code: Application-specific error code
            details: Additional error details
            include_csrf: Whether to include CSRF token in response
            
        Returns:
            Flask Response object with standardized error format
        """
        response_payload = {
            "success": False,
            "error": {
                "message": message,
                "status_code": status_code,
                "status_text": HTTP_STATUS_CODES.get(status_code, "Unknown Error")
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if error_code:
            response_payload["error"]["code"] = error_code
            
        if details:
            response_payload["error"]["details"] = details
            
        # Include CSRF token if requested (for forms that need re-submission)
        if include_csrf:
            try:
                csrf_token = generate_csrf()
                response_payload["csrf_token"] = csrf_token
                logger.debug("CSRF token included in authentication error response")
            except Exception as e:
                logger.warning(f"Failed to generate CSRF token for error response: {str(e)}")
        
        response = jsonify(response_payload)
        response.status_code = status_code
        
        # Set security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        logger.warning(f"Authentication error response generated: {message} (Status: {status_code})")
        return response


class AuthResponseHelper:
    """
    Specialized response helper for authentication workflows.
    Provides standardized responses for common authentication scenarios.
    """
    
    @staticmethod
    def login_success(
        user_data: Dict[str, Any],
        token_data: Optional[Dict[str, Any]] = None,
        session_info: Optional[Dict[str, Any]] = None,
        remember_me: bool = False
    ) -> Response:
        """
        Generate successful login response with user data and session information.
        
        Args:
            user_data: User profile information
            token_data: JWT token information (if using token-based auth)
            session_info: Session metadata
            remember_me: Whether remember-me functionality is enabled
            
        Returns:
            Standardized login success response
        """
        response_data = {
            "user": {
                "id": user_data.get("id"),
                "username": user_data.get("username"),
                "email": user_data.get("email"),
                "roles": user_data.get("roles", []),
                "permissions": user_data.get("permissions", []),
                "last_login": datetime.now(timezone.utc).isoformat(),
                "remember_me": remember_me
            }
        }
        
        if token_data:
            response_data["tokens"] = {
                "access_token": token_data.get("access_token"),
                "refresh_token": token_data.get("refresh_token"),
                "token_type": token_data.get("token_type", "Bearer"),
                "expires_in": token_data.get("expires_in"),
                "expires_at": token_data.get("expires_at")
            }
            
        if session_info:
            response_data["session"] = {
                "session_id": session_info.get("session_id"),
                "expires_at": session_info.get("expires_at"),
                "csrf_token": session_info.get("csrf_token")
            }
        
        additional_headers = {}
        if remember_me:
            additional_headers['Set-Cookie-SameSite'] = 'Strict'
            
        return ResponseFormat.success(
            data=response_data,
            message="Login successful",
            status_code=HTTPStatus.OK,
            include_csrf=True,
            additional_headers=additional_headers
        )
    
    @staticmethod
    def login_failed(
        reason: str = "Invalid credentials",
        attempt_count: Optional[int] = None,
        lockout_info: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Generate failed login response with security information.
        
        Args:
            reason: Specific reason for login failure
            attempt_count: Number of failed attempts
            lockout_info: Account lockout information if applicable
            
        Returns:
            Standardized login failure response
        """
        error_details = {"authentication_failed": True}
        
        if attempt_count is not None:
            error_details["failed_attempts"] = attempt_count
            
        if lockout_info:
            error_details["lockout"] = lockout_info
            
        return ResponseFormat.error(
            message=reason,
            status_code=HTTPStatus.UNAUTHORIZED,
            error_code="AUTH_LOGIN_FAILED",
            details=error_details,
            include_csrf=True
        )
    
    @staticmethod
    def logout_success(
        session_data: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Generate successful logout response.
        
        Args:
            session_data: Session information being terminated
            
        Returns:
            Standardized logout success response
        """
        response_data = {
            "logged_out": True,
            "session_terminated": True
        }
        
        if session_data:
            response_data["session_info"] = {
                "session_duration": session_data.get("duration"),
                "last_activity": session_data.get("last_activity")
            }
            
        return ResponseFormat.success(
            data=response_data,
            message="Logout successful",
            status_code=HTTPStatus.OK
        )
    
    @staticmethod
    def token_refresh_success(
        new_tokens: Dict[str, Any],
        user_info: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Generate successful token refresh response.
        
        Args:
            new_tokens: New JWT token information
            user_info: Updated user information
            
        Returns:
            Standardized token refresh response
        """
        response_data = {
            "tokens": {
                "access_token": new_tokens.get("access_token"),
                "refresh_token": new_tokens.get("refresh_token"),
                "token_type": new_tokens.get("token_type", "Bearer"),
                "expires_in": new_tokens.get("expires_in"),
                "expires_at": new_tokens.get("expires_at"),
                "refreshed_at": datetime.now(timezone.utc).isoformat()
            }
        }
        
        if user_info:
            response_data["user"] = user_info
            
        return ResponseFormat.success(
            data=response_data,
            message="Token refreshed successfully",
            status_code=HTTPStatus.OK
        )
    
    @staticmethod
    def unauthorized_access(
        resource: Optional[str] = None,
        required_permissions: Optional[List[str]] = None
    ) -> Response:
        """
        Generate unauthorized access response.
        
        Args:
            resource: Resource that was attempted to be accessed
            required_permissions: Permissions required for access
            
        Returns:
            Standardized unauthorized response
        """
        error_details = {"unauthorized_access": True}
        
        if resource:
            error_details["resource"] = resource
            
        if required_permissions:
            error_details["required_permissions"] = required_permissions
            
        return ResponseFormat.error(
            message="Unauthorized access attempt",
            status_code=HTTPStatus.UNAUTHORIZED,
            error_code="AUTH_UNAUTHORIZED",
            details=error_details
        )
    
    @staticmethod
    def forbidden_access(
        resource: Optional[str] = None,
        user_permissions: Optional[List[str]] = None
    ) -> Response:
        """
        Generate forbidden access response for insufficient permissions.
        
        Args:
            resource: Resource that was attempted to be accessed
            user_permissions: User's current permissions
            
        Returns:
            Standardized forbidden response
        """
        error_details = {"forbidden_access": True}
        
        if resource:
            error_details["resource"] = resource
            
        if user_permissions:
            error_details["user_permissions"] = user_permissions
            
        return ResponseFormat.error(
            message="Access forbidden - insufficient permissions",
            status_code=HTTPStatus.FORBIDDEN,
            error_code="AUTH_FORBIDDEN",
            details=error_details
        )


class CSRFResponseHelper:
    """
    CSRF token management utilities for authentication responses.
    Integrates with Flask-WTF for comprehensive CSRF protection.
    """
    
    @staticmethod
    def get_csrf_token() -> Optional[str]:
        """
        Generate or retrieve CSRF token for the current session.
        
        Returns:
            CSRF token string or None if generation fails
        """
        try:
            csrf_token = generate_csrf()
            logger.debug("CSRF token generated successfully")
            return csrf_token
        except Exception as e:
            logger.error(f"Failed to generate CSRF token: {str(e)}")
            return None
    
    @staticmethod
    def validate_csrf_token(token: str) -> bool:
        """
        Validate provided CSRF token against session.
        
        Args:
            token: CSRF token to validate
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            validate_csrf(token)
            logger.debug("CSRF token validation successful")
            return True
        except Exception as e:
            logger.warning(f"CSRF token validation failed: {str(e)}")
            return False
    
    @staticmethod
    def csrf_token_response() -> Response:
        """
        Generate response containing only CSRF token.
        Useful for AJAX requests that need fresh CSRF tokens.
        
        Returns:
            Response with CSRF token
        """
        csrf_token = CSRFResponseHelper.get_csrf_token()
        
        if csrf_token:
            return ResponseFormat.success(
                data={"csrf_token": csrf_token},
                message="CSRF token generated",
                status_code=HTTPStatus.OK
            )
        else:
            return ResponseFormat.error(
                message="Failed to generate CSRF token",
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                error_code="CSRF_GENERATION_FAILED"
            )
    
    @staticmethod
    def csrf_validation_failed() -> Response:
        """
        Generate response for CSRF validation failure.
        
        Returns:
            Standardized CSRF validation error response
        """
        return ResponseFormat.error(
            message="CSRF token validation failed",
            status_code=HTTPStatus.BAD_REQUEST,
            error_code="CSRF_VALIDATION_FAILED",
            details={
                "csrf_failed": True,
                "action_required": "Refresh page and retry"
            },
            include_csrf=True
        )


class ValidationResponseHelper:
    """
    Response utilities for authentication input validation errors.
    Provides consistent validation error formatting.
    """
    
    @staticmethod
    def validation_errors(
        errors: Dict[str, List[str]],
        message: str = "Validation errors occurred"
    ) -> Response:
        """
        Generate response for validation errors.
        
        Args:
            errors: Dictionary of field names to error messages
            message: General validation error message
            
        Returns:
            Standardized validation error response
        """
        return ResponseFormat.error(
            message=message,
            status_code=HTTPStatus.BAD_REQUEST,
            error_code="VALIDATION_FAILED",
            details={
                "validation_errors": errors,
                "fields_with_errors": list(errors.keys())
            },
            include_csrf=True
        )
    
    @staticmethod
    def password_validation_failed(
        requirements: List[str],
        failed_requirements: List[str]
    ) -> Response:
        """
        Generate response for password validation failure.
        
        Args:
            requirements: List of all password requirements
            failed_requirements: List of requirements that failed
            
        Returns:
            Password validation error response
        """
        return ResponseFormat.error(
            message="Password does not meet security requirements",
            status_code=HTTPStatus.BAD_REQUEST,
            error_code="PASSWORD_VALIDATION_FAILED",
            details={
                "password_requirements": requirements,
                "failed_requirements": failed_requirements
            },
            include_csrf=True
        )
    
    @staticmethod
    def email_validation_failed(email: str) -> Response:
        """
        Generate response for email validation failure.
        
        Args:
            email: Email address that failed validation
            
        Returns:
            Email validation error response
        """
        return ResponseFormat.error(
            message="Invalid email address format",
            status_code=HTTPStatus.BAD_REQUEST,
            error_code="EMAIL_VALIDATION_FAILED",
            details={
                "invalid_email": email,
                "expected_format": "user@domain.com"
            },
            include_csrf=True
        )


class SecurityResponseHelper:
    """
    Security-related response utilities for authentication endpoints.
    Handles security events and incident responses.
    """
    
    @staticmethod
    def rate_limit_exceeded(
        limit: int,
        window: int,
        retry_after: Optional[int] = None
    ) -> Response:
        """
        Generate response for rate limit exceeded.
        
        Args:
            limit: Rate limit threshold
            window: Time window in seconds
            retry_after: Seconds until retry is allowed
            
        Returns:
            Rate limit exceeded response
        """
        additional_headers = {}
        if retry_after:
            additional_headers['Retry-After'] = str(retry_after)
            
        return ResponseFormat.error(
            message="Rate limit exceeded",
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            error_code="RATE_LIMIT_EXCEEDED",
            details={
                "rate_limit": limit,
                "time_window": window,
                "retry_after": retry_after
            }
        )
    
    @staticmethod
    def account_locked(
        lockout_duration: Optional[int] = None,
        unlock_time: Optional[str] = None
    ) -> Response:
        """
        Generate response for locked account.
        
        Args:
            lockout_duration: Duration of lockout in seconds
            unlock_time: ISO timestamp when account will be unlocked
            
        Returns:
            Account locked response
        """
        details = {"account_locked": True}
        
        if lockout_duration:
            details["lockout_duration"] = lockout_duration
            
        if unlock_time:
            details["unlock_time"] = unlock_time
            
        return ResponseFormat.error(
            message="Account is temporarily locked due to security measures",
            status_code=HTTPStatus.FORBIDDEN,
            error_code="ACCOUNT_LOCKED",
            details=details
        )
    
    @staticmethod
    def suspicious_activity_detected(
        activity_type: str,
        action_taken: str
    ) -> Response:
        """
        Generate response for suspicious activity detection.
        
        Args:
            activity_type: Type of suspicious activity detected
            action_taken: Security action taken in response
            
        Returns:
            Suspicious activity response
        """
        return ResponseFormat.error(
            message="Suspicious activity detected",
            status_code=HTTPStatus.FORBIDDEN,
            error_code="SUSPICIOUS_ACTIVITY",
            details={
                "activity_type": activity_type,
                "action_taken": action_taken,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


def create_response_with_request_context(
    response_func,
    *args,
    request_id: Optional[str] = None,
    user_id: Optional[str] = None,
    **kwargs
) -> Response:
    """
    Create response with additional request context information.
    
    Args:
        response_func: Response function to call
        request_id: Unique request identifier
        user_id: User identifier for audit trails
        *args: Positional arguments for response function
        **kwargs: Keyword arguments for response function
        
    Returns:
        Response with enriched context information
    """
    response = response_func(*args, **kwargs)
    
    # Add request context to response headers for debugging and audit
    if request_id:
        response.headers['X-Request-ID'] = request_id
        
    if user_id:
        response.headers['X-User-ID'] = user_id
        
    # Add timestamp for response tracking
    response.headers['X-Response-Timestamp'] = datetime.now(timezone.utc).isoformat()
    
    return response


# Module-level utility functions for common authentication responses

def success_response(*args, **kwargs) -> Response:
    """Convenience function for success responses."""
    return ResponseFormat.success(*args, **kwargs)


def error_response(*args, **kwargs) -> Response:
    """Convenience function for error responses."""
    return ResponseFormat.error(*args, **kwargs)


def login_response(*args, **kwargs) -> Response:
    """Convenience function for login responses."""
    return AuthResponseHelper.login_success(*args, **kwargs)


def logout_response(*args, **kwargs) -> Response:
    """Convenience function for logout responses."""
    return AuthResponseHelper.logout_success(*args, **kwargs)


def unauthorized_response(*args, **kwargs) -> Response:
    """Convenience function for unauthorized responses."""
    return AuthResponseHelper.unauthorized_access(*args, **kwargs)


def forbidden_response(*args, **kwargs) -> Response:
    """Convenience function for forbidden responses."""
    return AuthResponseHelper.forbidden_access(*args, **kwargs)


def csrf_token_response() -> Response:
    """Convenience function for CSRF token responses."""
    return CSRFResponseHelper.csrf_token_response()


def validation_error_response(*args, **kwargs) -> Response:
    """Convenience function for validation error responses."""
    return ValidationResponseHelper.validation_errors(*args, **kwargs)