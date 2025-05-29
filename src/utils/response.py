"""
Flask Response Utilities

HTTP response utilities providing standardized response formatting, status code management,
and API response helpers for Flask 3.1.1 applications running on Python 3.13.3 runtime.

This module ensures consistent response patterns across all Flask blueprints with support
for pagination, metadata inclusion, error response formatting, CORS headers, and security
headers while maintaining compatibility with existing client applications during the
Node.js to Flask migration.

Key Features:
- Standardized HTTP response formatting for API consistency per Section 4.3
- API response structure compatibility with existing clients per Section 0.2.1
- Pagination and metadata response utilities per Section 2.2
- Security header management and CORS support per Section 6.4.3.4
- Response performance optimization for high-traffic endpoints per Section 5.4.5

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime, timezone
import math
import time
from functools import wraps
from urllib.parse import urlencode, urlparse, parse_qs

from flask import (
    jsonify, 
    request, 
    current_app, 
    g,
    Response,
    make_response
)
from werkzeug.http import HTTP_STATUS_CODES
import structlog

# Initialize structured logger for response tracking
logger = structlog.get_logger("response_utils")

# Response format constants
DEFAULT_API_VERSION = "v1"
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 1000
MIN_PAGE_SIZE = 1

# HTTP Status Code Constants for consistency
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_NO_CONTENT = 204
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_METHOD_NOT_ALLOWED = 405
HTTP_CONFLICT = 409
HTTP_UNPROCESSABLE_ENTITY = 422
HTTP_TOO_MANY_REQUESTS = 429
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_SERVICE_UNAVAILABLE = 503

# Security Headers Configuration per Section 6.4.3.4
SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    'Referrer-Policy': 'strict-origin-when-cross-origin'
}

# CORS Configuration per Section 6.4.3.4
DEFAULT_CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',  # Configure appropriately for production
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, Accept, Origin',
    'Access-Control-Max-Age': '86400'  # 24 hours
}


class ResponseMetadata:
    """
    Response metadata container for consistent API response structure.
    
    Provides standardized metadata fields including request tracking,
    performance metrics, and API versioning information.
    """
    
    def __init__(
        self,
        request_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        api_version: str = DEFAULT_API_VERSION,
        execution_time_ms: Optional[float] = None,
        blueprint: Optional[str] = None,
        endpoint: Optional[str] = None
    ):
        self.request_id = request_id or getattr(g, 'request_id', None)
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.api_version = api_version
        self.execution_time_ms = execution_time_ms
        self.blueprint = blueprint or getattr(request, 'blueprint', None)
        self.endpoint = endpoint or getattr(request, 'endpoint', None)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary format for JSON serialization."""
        return {
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'api_version': self.api_version,
            'execution_time_ms': self.execution_time_ms,
            'blueprint': self.blueprint,
            'endpoint': self.endpoint
        }


class PaginationInfo:
    """
    Pagination information container for paginated API responses.
    
    Provides consistent pagination metadata including page information,
    total counts, and navigation links for data endpoints per Section 2.2.
    """
    
    def __init__(
        self,
        page: int,
        per_page: int,
        total: int,
        has_prev: bool = None,
        has_next: bool = None,
        prev_page: Optional[int] = None,
        next_page: Optional[int] = None
    ):
        self.page = max(1, page)
        self.per_page = min(max(MIN_PAGE_SIZE, per_page), MAX_PAGE_SIZE)
        self.total = max(0, total)
        self.pages = math.ceil(self.total / self.per_page) if self.per_page > 0 else 0
        
        # Calculate pagination flags
        self.has_prev = has_prev if has_prev is not None else (self.page > 1)
        self.has_next = has_next if has_next is not None else (self.page < self.pages)
        self.prev_page = prev_page if prev_page is not None else (self.page - 1 if self.has_prev else None)
        self.next_page = next_page if next_page is not None else (self.page + 1 if self.has_next else None)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert pagination info to dictionary format for JSON serialization."""
        return {
            'page': self.page,
            'per_page': self.per_page,
            'total': self.total,
            'pages': self.pages,
            'has_prev': self.has_prev,
            'has_next': self.has_next,
            'prev_page': self.prev_page,
            'next_page': self.next_page
        }
    
    def generate_links(self, base_url: str = None) -> Dict[str, Optional[str]]:
        """
        Generate pagination navigation links.
        
        Args:
            base_url: Base URL for generating navigation links
            
        Returns:
            Dictionary containing self, first, last, prev, next links
        """
        if not base_url:
            base_url = request.base_url
        
        # Parse existing query parameters
        parsed_url = urlparse(request.url)
        query_params = parse_qs(parsed_url.query)
        
        def build_page_url(page_num: int) -> str:
            """Build URL for specific page number."""
            page_params = query_params.copy()
            page_params['page'] = [str(page_num)]
            page_params['per_page'] = [str(self.per_page)]
            query_string = urlencode(page_params, doseq=True)
            return f"{base_url}?{query_string}"
        
        links = {
            'self': build_page_url(self.page),
            'first': build_page_url(1) if self.pages > 0 else None,
            'last': build_page_url(self.pages) if self.pages > 0 else None,
            'prev': build_page_url(self.prev_page) if self.has_prev else None,
            'next': build_page_url(self.next_page) if self.has_next else None
        }
        
        return links


def add_security_headers(response: Response) -> Response:
    """
    Add security headers to Flask response per Section 6.4.3.4.
    
    Implements security headers including HSTS, content type options,
    frame options, XSS protection, and CSP for enhanced security posture.
    
    Args:
        response: Flask Response object
        
    Returns:
        Response object with security headers added
    """
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    
    # Add additional security headers based on application configuration
    if current_app.config.get('SECURE_SSL_REDIRECT', False):
        response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    
    # Log security header application for monitoring
    logger.debug(
        "Security headers applied",
        headers=list(SECURITY_HEADERS.keys()),
        blueprint=getattr(request, 'blueprint', None),
        endpoint=getattr(request, 'endpoint', None)
    )
    
    return response


def add_cors_headers(
    response: Response, 
    origins: Union[str, List[str]] = None,
    methods: List[str] = None,
    headers: List[str] = None,
    credentials: bool = False
) -> Response:
    """
    Add CORS headers to Flask response per Section 6.4.3.4.
    
    Implements Cross-Origin Resource Sharing headers with configurable
    origins, methods, and headers for client compatibility.
    
    Args:
        response: Flask Response object
        origins: Allowed origins (string or list)
        methods: Allowed HTTP methods
        headers: Allowed headers
        credentials: Whether to allow credentials
        
    Returns:
        Response object with CORS headers added
    """
    # Determine allowed origin
    if origins is None:
        allowed_origin = DEFAULT_CORS_HEADERS['Access-Control-Allow-Origin']
    elif isinstance(origins, list):
        # Check if request origin is in allowed list
        request_origin = request.headers.get('Origin')
        if request_origin and request_origin in origins:
            allowed_origin = request_origin
        else:
            allowed_origin = origins[0] if origins else '*'
    else:
        allowed_origin = origins
    
    response.headers['Access-Control-Allow-Origin'] = allowed_origin
    
    # Set allowed methods
    if methods:
        response.headers['Access-Control-Allow-Methods'] = ', '.join(methods)
    else:
        response.headers['Access-Control-Allow-Methods'] = DEFAULT_CORS_HEADERS['Access-Control-Allow-Methods']
    
    # Set allowed headers
    if headers:
        response.headers['Access-Control-Allow-Headers'] = ', '.join(headers)
    else:
        response.headers['Access-Control-Allow-Headers'] = DEFAULT_CORS_HEADERS['Access-Control-Allow-Headers']
    
    # Set credentials flag
    if credentials:
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # Set max age
    response.headers['Access-Control-Max-Age'] = DEFAULT_CORS_HEADERS['Access-Control-Max-Age']
    
    # Log CORS header application for monitoring
    logger.debug(
        "CORS headers applied",
        origin=allowed_origin,
        methods=response.headers.get('Access-Control-Allow-Methods'),
        credentials=credentials
    )
    
    return response


def performance_headers(response: Response, cache_timeout: int = None) -> Response:
    """
    Add performance optimization headers per Section 5.4.5.
    
    Implements caching headers, ETag generation, and performance
    optimization headers for high-traffic endpoints.
    
    Args:
        response: Flask Response object
        cache_timeout: Cache timeout in seconds
        
    Returns:
        Response object with performance headers added
    """
    # Add cache control headers if cache timeout specified
    if cache_timeout is not None:
        response.cache_control.max_age = cache_timeout
        response.cache_control.public = True
    
    # Add performance monitoring headers
    if hasattr(g, 'start_time'):
        execution_time = (time.time() - g.start_time) * 1000  # Convert to milliseconds
        response.headers['X-Response-Time'] = f"{execution_time:.2f}ms"
    
    # Add server information for monitoring
    response.headers['X-Served-By'] = 'Flask-3.1.1'
    response.headers['X-Python-Version'] = '3.13.3'
    
    return response


def track_response_metrics(func):
    """
    Decorator for tracking response metrics per Section 5.4.5.
    
    Measures execution time and logs response metrics for
    performance monitoring and optimization.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        g.start_time = start_time
        
        try:
            result = func(*args, **kwargs)
            execution_time = (time.time() - start_time) * 1000
            
            # Log response metrics
            logger.info(
                "Response generated",
                execution_time_ms=execution_time,
                blueprint=getattr(request, 'blueprint', None),
                endpoint=getattr(request, 'endpoint', None),
                method=request.method,
                status_code=getattr(result, 'status_code', 'unknown')
            )
            
            return result
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            
            # Log error metrics
            logger.error(
                "Response generation failed",
                execution_time_ms=execution_time,
                blueprint=getattr(request, 'blueprint', None),
                endpoint=getattr(request, 'endpoint', None),
                error=str(e)
            )
            
            raise
    
    return wrapper


def success_response(
    data: Any = None,
    message: str = "Success",
    status_code: int = HTTP_OK,
    metadata: ResponseMetadata = None,
    headers: Dict[str, str] = None,
    enable_cors: bool = True,
    cache_timeout: int = None
) -> Response:
    """
    Generate standardized success response per Section 4.3.
    
    Creates consistent JSON response format for successful API operations
    with optional metadata, security headers, and CORS support.
    
    Args:
        data: Response data payload
        message: Success message
        status_code: HTTP status code
        metadata: Response metadata
        headers: Custom headers to add
        enable_cors: Whether to enable CORS headers
        cache_timeout: Cache timeout in seconds
        
    Returns:
        Flask Response object with JSON data
    """
    # Create metadata if not provided
    if metadata is None:
        metadata = ResponseMetadata()
        if hasattr(g, 'start_time'):
            metadata.execution_time_ms = (time.time() - g.start_time) * 1000
    
    # Build response structure
    response_data = {
        'success': True,
        'message': message,
        'data': data,
        'metadata': metadata.to_dict() if metadata else None
    }
    
    # Create Flask response with JSON content type
    response = make_response(jsonify(response_data), status_code)
    
    # Add security headers
    response = add_security_headers(response)
    
    # Add CORS headers if enabled
    if enable_cors:
        response = add_cors_headers(response)
    
    # Add performance headers
    response = performance_headers(response, cache_timeout)
    
    # Add custom headers if provided
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    
    # Log successful response
    logger.info(
        "Success response generated",
        status_code=status_code,
        message=message,
        has_data=data is not None,
        blueprint=getattr(request, 'blueprint', None),
        endpoint=getattr(request, 'endpoint', None)
    )
    
    return response


def error_response(
    message: str,
    status_code: int = HTTP_BAD_REQUEST,
    error_code: str = None,
    details: Any = None,
    metadata: ResponseMetadata = None,
    headers: Dict[str, str] = None,
    enable_cors: bool = True
) -> Response:
    """
    Generate standardized error response per Section 4.3.
    
    Creates consistent JSON error response format with proper HTTP status codes,
    error details, and debugging information while maintaining API compatibility.
    
    Args:
        message: Error message
        status_code: HTTP status code
        error_code: Application-specific error code
        details: Additional error details
        metadata: Response metadata
        headers: Custom headers to add
        enable_cors: Whether to enable CORS headers
        
    Returns:
        Flask Response object with JSON error data
    """
    # Create metadata if not provided
    if metadata is None:
        metadata = ResponseMetadata()
        if hasattr(g, 'start_time'):
            metadata.execution_time_ms = (time.time() - g.start_time) * 1000
    
    # Build error response structure
    response_data = {
        'success': False,
        'message': message,
        'error': {
            'code': error_code or status_code,
            'status': status_code,
            'description': HTTP_STATUS_CODES.get(status_code, 'Unknown Error'),
            'details': details
        },
        'metadata': metadata.to_dict() if metadata else None
    }
    
    # Create Flask response with JSON content type
    response = make_response(jsonify(response_data), status_code)
    
    # Add security headers
    response = add_security_headers(response)
    
    # Add CORS headers if enabled
    if enable_cors:
        response = add_cors_headers(response)
    
    # Add performance headers
    response = performance_headers(response)
    
    # Add custom headers if provided
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    
    # Log error response
    logger.warning(
        "Error response generated",
        status_code=status_code,
        message=message,
        error_code=error_code,
        blueprint=getattr(request, 'blueprint', None),
        endpoint=getattr(request, 'endpoint', None)
    )
    
    return response


def paginated_response(
    data: List[Any],
    pagination: PaginationInfo,
    message: str = "Data retrieved successfully",
    status_code: int = HTTP_OK,
    metadata: ResponseMetadata = None,
    headers: Dict[str, str] = None,
    enable_cors: bool = True,
    include_links: bool = True
) -> Response:
    """
    Generate paginated response for data endpoints per Section 2.2.
    
    Creates standardized paginated JSON response with pagination metadata,
    navigation links, and consistent structure for list operations.
    
    Args:
        data: List of data items for current page
        pagination: Pagination information
        message: Success message
        status_code: HTTP status code
        metadata: Response metadata
        headers: Custom headers to add
        enable_cors: Whether to enable CORS headers
        include_links: Whether to include navigation links
        
    Returns:
        Flask Response object with paginated JSON data
    """
    # Create metadata if not provided
    if metadata is None:
        metadata = ResponseMetadata()
        if hasattr(g, 'start_time'):
            metadata.execution_time_ms = (time.time() - g.start_time) * 1000
    
    # Build pagination metadata
    pagination_data = pagination.to_dict()
    
    # Add navigation links if requested
    if include_links:
        pagination_data['links'] = pagination.generate_links()
    
    # Build response structure
    response_data = {
        'success': True,
        'message': message,
        'data': data,
        'pagination': pagination_data,
        'metadata': metadata.to_dict() if metadata else None
    }
    
    # Create Flask response with JSON content type
    response = make_response(jsonify(response_data), status_code)
    
    # Add security headers
    response = add_security_headers(response)
    
    # Add CORS headers if enabled
    if enable_cors:
        response = add_cors_headers(response)
    
    # Add performance headers
    response = performance_headers(response)
    
    # Add pagination headers for API clients
    response.headers['X-Pagination-Page'] = str(pagination.page)
    response.headers['X-Pagination-Per-Page'] = str(pagination.per_page)
    response.headers['X-Pagination-Total'] = str(pagination.total)
    response.headers['X-Pagination-Pages'] = str(pagination.pages)
    
    # Add custom headers if provided
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    
    # Log paginated response
    logger.info(
        "Paginated response generated",
        status_code=status_code,
        page=pagination.page,
        per_page=pagination.per_page,
        total=pagination.total,
        items_count=len(data),
        blueprint=getattr(request, 'blueprint', None),
        endpoint=getattr(request, 'endpoint', None)
    )
    
    return response


def get_pagination_params() -> Tuple[int, int]:
    """
    Extract pagination parameters from request per Section 2.2.
    
    Parses page and per_page parameters from request args with
    validation and sensible defaults.
    
    Returns:
        Tuple of (page, per_page) with validated values
    """
    try:
        page = int(request.args.get('page', 1))
        page = max(1, page)  # Ensure page is at least 1
    except (ValueError, TypeError):
        page = 1
    
    try:
        per_page = int(request.args.get('per_page', DEFAULT_PAGE_SIZE))
        per_page = min(max(MIN_PAGE_SIZE, per_page), MAX_PAGE_SIZE)  # Clamp to valid range
    except (ValueError, TypeError):
        per_page = DEFAULT_PAGE_SIZE
    
    return page, per_page


def validate_json_response(data: Any) -> bool:
    """
    Validate data can be JSON serialized.
    
    Ensures response data is serializable to prevent runtime errors
    during response generation.
    
    Args:
        data: Data to validate
        
    Returns:
        True if data is JSON serializable, False otherwise
    """
    try:
        import json
        json.dumps(data, default=str)
        return True
    except (TypeError, ValueError):
        return False


def format_validation_errors(errors: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Format validation errors for consistent error responses.
    
    Converts form/schema validation errors into standardized format
    for API error responses per Section 4.3.
    
    Args:
        errors: Dictionary of field errors
        
    Returns:
        Formatted error details dictionary
    """
    formatted_errors = []
    
    for field, field_errors in errors.items():
        for error in field_errors:
            formatted_errors.append({
                'field': field,
                'message': error,
                'code': 'validation_error'
            })
    
    return {
        'validation_errors': formatted_errors,
        'error_count': len(formatted_errors)
    }


def health_check_response() -> Response:
    """
    Generate health check response for monitoring.
    
    Provides standardized health check endpoint response
    for application monitoring and load balancer health checks.
    
    Returns:
        Flask Response object with health status
    """
    health_data = {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'version': {
            'python': '3.13.3',
            'flask': '3.1.1',
            'api': DEFAULT_API_VERSION
        },
        'uptime_seconds': getattr(current_app, 'start_time', 0)
    }
    
    return success_response(
        data=health_data,
        message="Application is healthy",
        enable_cors=False,  # Health checks typically don't need CORS
        cache_timeout=0  # Don't cache health checks
    )


def options_response(
    allowed_methods: List[str] = None,
    max_age: int = 86400
) -> Response:
    """
    Generate OPTIONS response for CORS preflight requests.
    
    Handles CORS preflight requests with appropriate headers
    and allowed methods per Section 6.4.3.4.
    
    Args:
        allowed_methods: List of allowed HTTP methods
        max_age: Cache time for preflight response
        
    Returns:
        Flask Response object for OPTIONS request
    """
    if allowed_methods is None:
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    
    response = make_response('', 204)  # No Content
    
    # Add CORS headers
    response = add_cors_headers(
        response,
        methods=allowed_methods
    )
    
    # Set cache headers for preflight
    response.headers['Access-Control-Max-Age'] = str(max_age)
    
    # Log OPTIONS request
    logger.debug(
        "OPTIONS response generated",
        allowed_methods=allowed_methods,
        origin=request.headers.get('Origin'),
        blueprint=getattr(request, 'blueprint', None)
    )
    
    return response


# Response format validation decorator
def validate_response_format(func):
    """
    Decorator to validate response format consistency.
    
    Ensures all responses follow standardized format for
    API consistency and client compatibility.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        
        # Validate response is a Flask Response object
        if not isinstance(response, Response):
            logger.warning(
                "Invalid response type returned",
                response_type=type(response).__name__,
                endpoint=getattr(request, 'endpoint', None)
            )
        
        # Validate JSON content for API endpoints
        if response.content_type and 'application/json' in response.content_type:
            try:
                response.get_json()
            except Exception as e:
                logger.error(
                    "Invalid JSON response format",
                    error=str(e),
                    endpoint=getattr(request, 'endpoint', None)
                )
        
        return response
    
    return wrapper


# Export commonly used functions for easy import
__all__ = [
    'ResponseMetadata',
    'PaginationInfo',
    'success_response',
    'error_response',
    'paginated_response',
    'get_pagination_params',
    'add_security_headers',
    'add_cors_headers',
    'performance_headers',
    'track_response_metrics',
    'validate_json_response',
    'format_validation_errors',
    'health_check_response',
    'options_response',
    'validate_response_format',
    
    # HTTP Status Code Constants
    'HTTP_OK',
    'HTTP_CREATED',
    'HTTP_ACCEPTED',
    'HTTP_NO_CONTENT',
    'HTTP_BAD_REQUEST',
    'HTTP_UNAUTHORIZED',
    'HTTP_FORBIDDEN',
    'HTTP_NOT_FOUND',
    'HTTP_METHOD_NOT_ALLOWED',
    'HTTP_CONFLICT',
    'HTTP_UNPROCESSABLE_ENTITY',
    'HTTP_TOO_MANY_REQUESTS',
    'HTTP_INTERNAL_SERVER_ERROR',
    'HTTP_SERVICE_UNAVAILABLE'
]