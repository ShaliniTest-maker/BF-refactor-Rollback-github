"""
HTTP Response Utilities for Flask Application

This module provides standardized response formatting, status code management, and API response 
helpers to ensure consistent response patterns across all Flask blueprints. It maintains 
compatibility with existing client applications while providing enhanced functionality for 
pagination, metadata inclusion, security headers, and CORS support.

Key Features:
- Standardized HTTP response formatting for API consistency (Section 4.3)
- API response structure compatibility with existing clients (Section 0.2.1) 
- Pagination and metadata response utilities (Section 2.2)
- Security header management and CORS support (Section 6.4.3.4)
- Response performance optimization for high-traffic endpoints (Section 5.4.5)

Usage:
    from src.utils.response import StandardResponse, PaginatedResponse, ErrorResponse
    
    # Standard success response
    return StandardResponse.success(data={'user_id': 123}, message='User created')
    
    # Paginated response
    return PaginatedResponse.create(
        data=users, 
        page=1, 
        per_page=10, 
        total=100
    )
    
    # Error response
    return ErrorResponse.bad_request(message='Invalid input', errors={'name': 'Required'})
"""

from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime, timezone
from enum import Enum
import json
import logging
from flask import Response, request, current_app, make_response, jsonify
from werkzeug.exceptions import HTTPException
import structlog

# Initialize structured logger
logger = structlog.get_logger(__name__)


class ResponseStatus(Enum):
    """Standardized response status codes and messages."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class HTTPStatusCode(Enum):
    """HTTP status codes with semantic meaning."""
    # Success codes
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    
    # Client error codes
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    
    # Server error codes
    INTERNAL_SERVER_ERROR = 500
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504


class SecurityHeaders:
    """Security header management for enhanced application security."""
    
    @staticmethod
    def get_default_security_headers() -> Dict[str, str]:
        """
        Get default security headers per Section 6.4.3.4.
        
        Returns:
            Dict of security headers to apply to all responses
        """
        return {
            # Prevent clickjacking attacks
            'X-Frame-Options': 'DENY',
            
            # Prevent content-type sniffing
            'X-Content-Type-Options': 'nosniff',
            
            # Enable XSS protection
            'X-XSS-Protection': '1; mode=block',
            
            # Strict transport security (HTTPS only)
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            
            # Content Security Policy
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
            
            # Referrer policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            # Permissions policy
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            
            # Cache control for sensitive data
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    
    @staticmethod
    def get_cors_headers(origin: Optional[str] = None) -> Dict[str, str]:
        """
        Get CORS headers for cross-origin requests per Section 6.4.3.4.
        
        Args:
            origin: The origin to allow, defaults to configured origins
            
        Returns:
            Dict of CORS headers
        """
        allowed_origins = current_app.config.get('CORS_ALLOWED_ORIGINS', ['*'])
        
        # Determine allowed origin
        if origin and origin in allowed_origins:
            allowed_origin = origin
        elif '*' in allowed_origins:
            allowed_origin = '*'
        else:
            allowed_origin = allowed_origins[0] if allowed_origins else None
        
        cors_headers = {}
        
        if allowed_origin:
            cors_headers.update({
                'Access-Control-Allow-Origin': allowed_origin,
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Max-Age': '3600'
            })
        
        return cors_headers


class ResponseMetadata:
    """Response metadata utilities for enhanced API responses."""
    
    @staticmethod
    def create_timestamp() -> str:
        """Create ISO 8601 UTC timestamp for response metadata."""
        return datetime.now(timezone.utc).isoformat()
    
    @staticmethod
    def get_request_metadata() -> Dict[str, Any]:
        """
        Extract request metadata for response tracking.
        
        Returns:
            Dictionary containing request metadata
        """
        metadata = {
            'timestamp': ResponseMetadata.create_timestamp(),
            'request_id': getattr(request, 'id', None),
            'method': request.method,
            'endpoint': request.endpoint,
            'path': request.path
        }
        
        # Add user context if available
        from flask import g
        if hasattr(g, 'user_id'):
            metadata['user_id'] = g.user_id
        
        if hasattr(g, 'session_id'):
            metadata['session_id'] = g.session_id
        
        return metadata
    
    @staticmethod
    def create_performance_metadata(execution_time: Optional[float] = None) -> Dict[str, Any]:
        """
        Create performance metadata for response optimization tracking.
        
        Args:
            execution_time: Request execution time in seconds
            
        Returns:
            Performance metadata dictionary
        """
        metadata = {
            'execution_time': execution_time,
            'server_time': ResponseMetadata.create_timestamp()
        }
        
        # Add performance metrics if available
        if hasattr(request, 'start_time'):
            execution_time = (datetime.now(timezone.utc) - request.start_time).total_seconds()
            metadata['calculated_execution_time'] = execution_time
        
        return metadata


class PaginationMeta:
    """Pagination metadata utilities per Section 2.2."""
    
    def __init__(self, page: int, per_page: int, total: int, total_pages: int):
        """
        Initialize pagination metadata.
        
        Args:
            page: Current page number (1-indexed)
            per_page: Number of items per page
            total: Total number of items
            total_pages: Total number of pages
        """
        self.page = page
        self.per_page = per_page
        self.total = total
        self.total_pages = total_pages
        self.has_next = page < total_pages
        self.has_prev = page > 1
        self.next_page = page + 1 if self.has_next else None
        self.prev_page = page - 1 if self.has_prev else None
    
    @classmethod
    def from_query_params(cls, total: int, page: Optional[int] = None, per_page: Optional[int] = None) -> 'PaginationMeta':
        """
        Create pagination metadata from query parameters.
        
        Args:
            total: Total number of items
            page: Page number from query params
            per_page: Items per page from query params
            
        Returns:
            PaginationMeta instance
        """
        # Default values and validation
        page = max(1, page or 1)
        per_page = min(max(1, per_page or 20), 100)  # Limit to 100 items per page
        total_pages = max(1, (total + per_page - 1) // per_page)
        
        # Ensure page doesn't exceed total pages
        page = min(page, total_pages)
        
        return cls(page=page, per_page=per_page, total=total, total_pages=total_pages)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pagination metadata to dictionary."""
        return {
            'page': self.page,
            'per_page': self.per_page,
            'total': self.total,
            'total_pages': self.total_pages,
            'has_next': self.has_next,
            'has_prev': self.has_prev,
            'next_page': self.next_page,
            'prev_page': self.prev_page
        }


class BaseResponse:
    """Base response class with standardized structure."""
    
    def __init__(
        self,
        status: ResponseStatus,
        status_code: HTTPStatusCode,
        message: Optional[str] = None,
        data: Any = None,
        errors: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        include_security_headers: bool = True,
        include_cors_headers: bool = True
    ):
        """
        Initialize base response.
        
        Args:
            status: Response status (success, error, warning, info)
            status_code: HTTP status code
            message: Human-readable message
            data: Response data payload
            errors: Error details if applicable
            metadata: Additional metadata
            include_security_headers: Whether to include security headers
            include_cors_headers: Whether to include CORS headers
        """
        self.status = status
        self.status_code = status_code
        self.message = message
        self.data = data
        self.errors = errors or {}
        self.metadata = metadata or {}
        self.include_security_headers = include_security_headers
        self.include_cors_headers = include_cors_headers
        
        # Always include request metadata
        self.metadata.update(ResponseMetadata.get_request_metadata())
        
        # Log response creation for monitoring
        logger.info(
            "Response created",
            status=status.value,
            status_code=status_code.value,
            endpoint=request.endpoint,
            has_data=data is not None,
            has_errors=bool(errors)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert response to dictionary format per Section 0.2.1.
        
        Returns:
            Standardized response dictionary
        """
        response_dict = {
            'status': self.status.value,
            'message': self.message,
            'metadata': self.metadata
        }
        
        # Include data if present
        if self.data is not None:
            response_dict['data'] = self.data
        
        # Include errors if present
        if self.errors:
            response_dict['errors'] = self.errors
        
        return response_dict
    
    def to_response(self) -> Response:
        """
        Convert to Flask Response object with appropriate headers.
        
        Returns:
            Flask Response object with headers
        """
        response_data = self.to_dict()
        
        # Create JSON response
        response = make_response(jsonify(response_data), self.status_code.value)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
        
        # Add security headers if enabled
        if self.include_security_headers:
            for header, value in SecurityHeaders.get_default_security_headers().items():
                response.headers[header] = value
        
        # Add CORS headers if enabled
        if self.include_cors_headers:
            origin = request.headers.get('Origin')
            for header, value in SecurityHeaders.get_cors_headers(origin).items():
                response.headers[header] = value
        
        return response


class StandardResponse(BaseResponse):
    """Standard API response for success cases."""
    
    @classmethod
    def success(
        cls,
        data: Any = None,
        message: str = "Operation completed successfully",
        status_code: HTTPStatusCode = HTTPStatusCode.OK,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Create successful response.
        
        Args:
            data: Response data
            message: Success message
            status_code: HTTP status code
            metadata: Additional metadata
            
        Returns:
            Flask Response object
        """
        response = cls(
            status=ResponseStatus.SUCCESS,
            status_code=status_code,
            message=message,
            data=data,
            metadata=metadata
        )
        return response.to_response()
    
    @classmethod
    def created(
        cls,
        data: Any = None,
        message: str = "Resource created successfully",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Response:
        """Create response for successful resource creation."""
        return cls.success(
            data=data,
            message=message,
            status_code=HTTPStatusCode.CREATED,
            metadata=metadata
        )
    
    @classmethod
    def no_content(cls, message: str = "Operation completed") -> Response:
        """Create response for successful operation with no content."""
        response = cls(
            status=ResponseStatus.SUCCESS,
            status_code=HTTPStatusCode.NO_CONTENT,
            message=message
        )
        return response.to_response()


class PaginatedResponse(BaseResponse):
    """Paginated response for data collections per Section 2.2."""
    
    def __init__(
        self,
        data: List[Any],
        pagination: PaginationMeta,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize paginated response.
        
        Args:
            data: List of data items for current page
            pagination: Pagination metadata
            message: Optional message
            metadata: Additional metadata
        """
        # Prepare response structure
        response_data = {
            'items': data,
            'pagination': pagination.to_dict()
        }
        
        # Add pagination metadata to response metadata
        if not metadata:
            metadata = {}
        metadata.update({
            'pagination_info': {
                'total_items': pagination.total,
                'current_page': pagination.page,
                'items_per_page': pagination.per_page
            }
        })
        
        super().__init__(
            status=ResponseStatus.SUCCESS,
            status_code=HTTPStatusCode.OK,
            message=message or f"Retrieved {len(data)} items (page {pagination.page} of {pagination.total_pages})",
            data=response_data,
            metadata=metadata
        )
    
    @classmethod
    def create(
        cls,
        data: List[Any],
        page: int,
        per_page: int,
        total: int,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Create paginated response from data and pagination parameters.
        
        Args:
            data: List of data items
            page: Current page number
            per_page: Items per page
            total: Total number of items
            message: Optional message
            metadata: Additional metadata
            
        Returns:
            Flask Response object
        """
        pagination = PaginationMeta.from_query_params(total=total, page=page, per_page=per_page)
        response = cls(data=data, pagination=pagination, message=message, metadata=metadata)
        return response.to_response()
    
    @classmethod
    def from_query_params(
        cls,
        data: List[Any],
        total: int,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Response:
        """
        Create paginated response using pagination parameters from request query string.
        
        Args:
            data: List of data items
            total: Total number of items
            message: Optional message
            metadata: Additional metadata
            
        Returns:
            Flask Response object
        """
        # Extract pagination parameters from request
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        return cls.create(
            data=data,
            page=page,
            per_page=per_page,
            total=total,
            message=message,
            metadata=metadata
        )


class ErrorResponse(BaseResponse):
    """Error response for handling various error scenarios."""
    
    def __init__(
        self,
        status_code: HTTPStatusCode,
        message: str,
        errors: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize error response.
        
        Args:
            status_code: HTTP status code
            message: Error message
            errors: Detailed error information
            error_code: Application-specific error code
            metadata: Additional metadata
        """
        if not metadata:
            metadata = {}
        
        # Add error-specific metadata
        metadata.update({
            'error_type': status_code.name.lower(),
            'error_code': error_code
        })
        
        super().__init__(
            status=ResponseStatus.ERROR,
            status_code=status_code,
            message=message,
            errors=errors,
            metadata=metadata
        )
        
        # Log error for monitoring
        logger.error(
            "Error response created",
            status_code=status_code.value,
            message=message,
            error_code=error_code,
            endpoint=request.endpoint,
            errors=errors
        )
    
    @classmethod
    def bad_request(
        cls,
        message: str = "Bad request",
        errors: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None
    ) -> Response:
        """Create bad request error response."""
        response = cls(
            status_code=HTTPStatusCode.BAD_REQUEST,
            message=message,
            errors=errors,
            error_code=error_code
        )
        return response.to_response()
    
    @classmethod
    def unauthorized(
        cls,
        message: str = "Authentication required",
        error_code: Optional[str] = None
    ) -> Response:
        """Create unauthorized error response."""
        response = cls(
            status_code=HTTPStatusCode.UNAUTHORIZED,
            message=message,
            error_code=error_code
        )
        return response.to_response()
    
    @classmethod
    def forbidden(
        cls,
        message: str = "Access forbidden",
        error_code: Optional[str] = None
    ) -> Response:
        """Create forbidden error response."""
        response = cls(
            status_code=HTTPStatusCode.FORBIDDEN,
            message=message,
            error_code=error_code
        )
        return response.to_response()
    
    @classmethod
    def not_found(
        cls,
        message: str = "Resource not found",
        error_code: Optional[str] = None
    ) -> Response:
        """Create not found error response."""
        response = cls(
            status_code=HTTPStatusCode.NOT_FOUND,
            message=message,
            error_code=error_code
        )
        return response.to_response()
    
    @classmethod
    def conflict(
        cls,
        message: str = "Resource conflict",
        errors: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None
    ) -> Response:
        """Create conflict error response."""
        response = cls(
            status_code=HTTPStatusCode.CONFLICT,
            message=message,
            errors=errors,
            error_code=error_code
        )
        return response.to_response()
    
    @classmethod
    def unprocessable_entity(
        cls,
        message: str = "Validation failed",
        errors: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None
    ) -> Response:
        """Create validation error response."""
        response = cls(
            status_code=HTTPStatusCode.UNPROCESSABLE_ENTITY,
            message=message,
            errors=errors,
            error_code=error_code
        )
        return response.to_response()
    
    @classmethod
    def too_many_requests(
        cls,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None
    ) -> Response:
        """Create rate limit error response."""
        metadata = {}
        if retry_after:
            metadata['retry_after'] = retry_after
        
        response = cls(
            status_code=HTTPStatusCode.TOO_MANY_REQUESTS,
            message=message,
            metadata=metadata
        )
        
        flask_response = response.to_response()
        if retry_after:
            flask_response.headers['Retry-After'] = str(retry_after)
        
        return flask_response
    
    @classmethod
    def internal_server_error(
        cls,
        message: str = "Internal server error",
        error_code: Optional[str] = None,
        include_debug_info: bool = False
    ) -> Response:
        """Create internal server error response."""
        metadata = {}
        
        # Include debug information in development
        if include_debug_info and current_app.debug:
            import traceback
            metadata['debug_info'] = {
                'traceback': traceback.format_exc()
            }
        
        response = cls(
            status_code=HTTPStatusCode.INTERNAL_SERVER_ERROR,
            message=message,
            error_code=error_code,
            metadata=metadata
        )
        return response.to_response()
    
    @classmethod
    def from_exception(cls, exception: Exception, include_debug_info: bool = False) -> Response:
        """
        Create error response from Python exception.
        
        Args:
            exception: Python exception
            include_debug_info: Whether to include debug information
            
        Returns:
            Flask Response object
        """
        if isinstance(exception, HTTPException):
            status_code = HTTPStatusCode(exception.code)
            message = exception.description or str(exception)
        else:
            status_code = HTTPStatusCode.INTERNAL_SERVER_ERROR
            message = "An unexpected error occurred"
        
        return cls.internal_server_error(
            message=message,
            error_code=type(exception).__name__,
            include_debug_info=include_debug_info
        )


class ResponseCache:
    """Response caching utilities for performance optimization per Section 5.4.5."""
    
    @staticmethod
    def set_cache_headers(
        response: Response,
        max_age: int = 300,
        private: bool = False,
        no_cache: bool = False,
        no_store: bool = False
    ) -> Response:
        """
        Set cache control headers for response optimization.
        
        Args:
            response: Flask Response object
            max_age: Cache duration in seconds
            private: Whether cache is private to user
            no_cache: Disable caching
            no_store: Prevent storage of response
            
        Returns:
            Response with cache headers
        """
        if no_store:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        elif no_cache:
            response.headers['Cache-Control'] = 'no-cache, must-revalidate'
        else:
            cache_directive = 'private' if private else 'public'
            response.headers['Cache-Control'] = f'{cache_directive}, max-age={max_age}'
        
        return response
    
    @staticmethod
    def set_etag(response: Response, data: Any) -> Response:
        """
        Set ETag header for response caching.
        
        Args:
            response: Flask Response object
            data: Data to generate ETag from
            
        Returns:
            Response with ETag header
        """
        import hashlib
        
        # Generate ETag from data
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        etag = hashlib.md5(data_str.encode()).hexdigest()
        response.headers['ETag'] = f'"{etag}"'
        
        return response


# Performance optimization utilities
class ResponseOptimizer:
    """Response optimization utilities per Section 5.4.5."""
    
    @staticmethod
    def compress_response(response: Response) -> Response:
        """
        Enable response compression for large payloads.
        
        Args:
            response: Flask Response object
            
        Returns:
            Response with compression enabled
        """
        # Flask-Compress should be used at application level
        # This is a placeholder for manual compression if needed
        content_length = response.content_length
        
        if content_length and content_length > 1024:  # Compress responses > 1KB
            response.headers['Vary'] = 'Accept-Encoding'
        
        return response
    
    @staticmethod
    def optimize_json_response(data: Any) -> str:
        """
        Optimize JSON serialization for performance.
        
        Args:
            data: Data to serialize
            
        Returns:
            Optimized JSON string
        """
        # Use separators to reduce size, ensure_ascii=False for Unicode support
        return json.dumps(
            data,
            separators=(',', ':'),
            ensure_ascii=False,
            default=str  # Handle datetime and other objects
        )


# Error handler integration utilities
def register_error_handlers(app):
    """
    Register standardized error handlers with Flask application.
    
    Args:
        app: Flask application instance
    """
    @app.errorhandler(400)
    def handle_bad_request(error):
        return ErrorResponse.bad_request(message=str(error))
    
    @app.errorhandler(401)
    def handle_unauthorized(error):
        return ErrorResponse.unauthorized()
    
    @app.errorhandler(403)
    def handle_forbidden(error):
        return ErrorResponse.forbidden()
    
    @app.errorhandler(404)
    def handle_not_found(error):
        return ErrorResponse.not_found()
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return ErrorResponse.bad_request(message="Method not allowed")
    
    @app.errorhandler(409)
    def handle_conflict(error):
        return ErrorResponse.conflict(message=str(error))
    
    @app.errorhandler(422)
    def handle_unprocessable_entity(error):
        return ErrorResponse.unprocessable_entity(message=str(error))
    
    @app.errorhandler(429)
    def handle_too_many_requests(error):
        return ErrorResponse.too_many_requests()
    
    @app.errorhandler(500)
    def handle_internal_server_error(error):
        return ErrorResponse.internal_server_error(
            include_debug_info=app.debug
        )
    
    @app.errorhandler(Exception)
    def handle_generic_exception(error):
        return ErrorResponse.from_exception(
            error,
            include_debug_info=app.debug
        )


# CORS preflight handler
def handle_preflight_request() -> Response:
    """
    Handle CORS preflight OPTIONS requests.
    
    Returns:
        Response for preflight request
    """
    response = make_response('', 200)
    
    # Add CORS headers
    origin = request.headers.get('Origin')
    for header, value in SecurityHeaders.get_cors_headers(origin).items():
        response.headers[header] = value
    
    return response


# Response middleware utilities
def add_response_middleware(app):
    """
    Add response middleware for consistent header management.
    
    Args:
        app: Flask application instance
    """
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        # Skip security headers for static files or if already present
        if not request.endpoint or request.endpoint == 'static':
            return response
        
        # Add security headers if not already present
        security_headers = SecurityHeaders.get_default_security_headers()
        for header, value in security_headers.items():
            if header not in response.headers:
                response.headers[header] = value
        
        return response
    
    @app.after_request
    def add_cors_headers(response):
        """Add CORS headers to all responses."""
        if request.method == 'OPTIONS':
            return response
        
        origin = request.headers.get('Origin')
        cors_headers = SecurityHeaders.get_cors_headers(origin)
        for header, value in cors_headers.items():
            if header not in response.headers:
                response.headers[header] = value
        
        return response


# Utility functions for common response patterns
def success_response(data: Any = None, message: str = "Success") -> Response:
    """Shorthand for creating success responses."""
    return StandardResponse.success(data=data, message=message)


def error_response(message: str, status_code: int = 400, errors: Optional[Dict] = None) -> Response:
    """Shorthand for creating error responses."""
    status_code_enum = HTTPStatusCode(status_code)
    
    if status_code_enum == HTTPStatusCode.BAD_REQUEST:
        return ErrorResponse.bad_request(message=message, errors=errors)
    elif status_code_enum == HTTPStatusCode.NOT_FOUND:
        return ErrorResponse.not_found(message=message)
    elif status_code_enum == HTTPStatusCode.UNAUTHORIZED:
        return ErrorResponse.unauthorized(message=message)
    elif status_code_enum == HTTPStatusCode.FORBIDDEN:
        return ErrorResponse.forbidden(message=message)
    else:
        return ErrorResponse.internal_server_error(message=message)


def paginated_response(data: List[Any], total: int, message: Optional[str] = None) -> Response:
    """Shorthand for creating paginated responses."""
    return PaginatedResponse.from_query_params(data=data, total=total, message=message)