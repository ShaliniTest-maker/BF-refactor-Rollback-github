"""
Data serialization and transformation utilities for Flask application.

This module provides comprehensive JSON handling, data format conversion, and API response
formatting utilities that maintain compatibility with existing client applications during
the Node.js to Flask migration. Includes support for datetime serialization, decimal handling,
secure data transformation, and consistent API response patterns.

Key Features:
- JSON serialization with Python datetime and decimal type support
- Data transformation utilities for API endpoint responses
- Secure serialization patterns preventing sensitive data exposure
- Consistent API response formatting for client compatibility
- Data pagination and filtering serialization helpers

Security Considerations:
- Field-level data filtering to prevent sensitive information leakage
- Configurable field exclusion patterns for data protection
- Sanitization of user-provided data before serialization
- Support for encrypted field handling with proper decryption controls

Usage:
    from src.utils.serialization import (
        serialize_json, create_api_response, create_paginated_response,
        sanitize_for_serialization, serialize_model_instance
    )
    
    # Basic JSON serialization with datetime support
    data = {'created_at': datetime.utcnow(), 'amount': Decimal('99.99')}
    json_str = serialize_json(data)
    
    # API response formatting
    response = create_api_response(data, message="Success", status_code=200)
    
    # Paginated response
    paginated = create_paginated_response(items, page=1, per_page=10, total=100)
"""

import json
import decimal
import datetime
from typing import Any, Dict, List, Optional, Union, Set, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import logging
from flask import jsonify, current_app, g
from werkzeug.exceptions import BadRequest
import re

# Import validation utilities for data sanitization
try:
    from src.utils.validation import sanitize_input, validate_field_type
except ImportError:
    # Fallback for testing or standalone usage
    def sanitize_input(value):
        return value
    
    def validate_field_type(value, expected_type):
        return isinstance(value, expected_type)


class SerializationError(Exception):
    """Custom exception for serialization-related errors."""
    pass


class DataClassification(Enum):
    """Data classification levels for security-aware serialization."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class PaginationMetadata:
    """Metadata structure for paginated responses."""
    page: int
    per_page: int
    total: int
    pages: int
    has_prev: bool
    has_next: bool
    prev_num: Optional[int] = None
    next_num: Optional[int] = None


@dataclass
class ApiResponse:
    """Standardized API response structure for client compatibility."""
    data: Any
    message: str
    status: str
    status_code: int
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None


class EnhancedJSONEncoder(json.JSONEncoder):
    """
    Enhanced JSON encoder with support for Python datetime, decimal, UUID, and other types.
    
    Provides comprehensive serialization support for common Python types while maintaining
    compatibility with existing API contracts during the Node.js to Flask migration.
    """
    
    def default(self, obj: Any) -> Any:
        """
        Convert Python objects to JSON-serializable formats.
        
        Args:
            obj: The object to serialize
            
        Returns:
            JSON-serializable representation of the object
            
        Raises:
            TypeError: If the object type is not serializable
        """
        try:
            # Handle datetime objects with ISO 8601 format
            if isinstance(obj, datetime.datetime):
                # Ensure timezone awareness for consistent serialization
                if obj.tzinfo is None:
                    # Assume UTC for naive datetime objects
                    obj = obj.replace(tzinfo=datetime.timezone.utc)
                return obj.isoformat()
            
            # Handle date objects
            elif isinstance(obj, datetime.date):
                return obj.isoformat()
            
            # Handle time objects
            elif isinstance(obj, datetime.time):
                return obj.isoformat()
            
            # Handle decimal objects for financial precision
            elif isinstance(obj, decimal.Decimal):
                # Convert to string to preserve precision
                return str(obj)
            
            # Handle UUID objects
            elif isinstance(obj, uuid.UUID):
                return str(obj)
            
            # Handle set objects
            elif isinstance(obj, set):
                return list(obj)
            
            # Handle Enum objects
            elif isinstance(obj, Enum):
                return obj.value
            
            # Handle bytes objects
            elif isinstance(obj, bytes):
                try:
                    return obj.decode('utf-8')
                except UnicodeDecodeError:
                    # Return base64 encoded string for binary data
                    import base64
                    return base64.b64encode(obj).decode('ascii')
            
            # Handle complex numbers
            elif isinstance(obj, complex):
                return {'real': obj.real, 'imag': obj.imag}
            
            # Handle dataclass objects
            elif hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            
            # Handle objects with to_dict method
            elif hasattr(obj, 'to_dict') and callable(obj.to_dict):
                return obj.to_dict()
            
            # Handle SQLAlchemy model instances
            elif hasattr(obj, '__table__'):
                return serialize_sqlalchemy_model(obj)
            
            # Fallback to default JSON encoder
            return super().default(obj)
            
        except Exception as e:
            current_app.logger.warning(
                f"Serialization warning for object type {type(obj).__name__}: {str(e)}"
            )
            # Return string representation as fallback
            return str(obj)


def serialize_json(
    data: Any, 
    ensure_ascii: bool = False, 
    indent: Optional[int] = None,
    sort_keys: bool = False,
    separators: Optional[tuple] = None
) -> str:
    """
    Enhanced JSON serialization with support for Python datetime and decimal types.
    
    Provides comprehensive JSON serialization capabilities for Flask API responses
    while maintaining compatibility with existing client applications.
    
    Args:
        data: The data to serialize to JSON
        ensure_ascii: Whether to escape non-ASCII characters
        indent: Number of spaces for pretty-printing (None for compact output)
        sort_keys: Whether to sort dictionary keys
        separators: Custom separators for compact output
        
    Returns:
        JSON string representation of the data
        
    Raises:
        SerializationError: If serialization fails
        
    Example:
        >>> from datetime import datetime
        >>> from decimal import Decimal
        >>> data = {
        ...     'timestamp': datetime.utcnow(),
        ...     'amount': Decimal('99.99'),
        ...     'user_id': uuid.uuid4()
        ... }
        >>> json_str = serialize_json(data)
    """
    try:
        # Use custom encoder for enhanced type support
        return json.dumps(
            data,
            cls=EnhancedJSONEncoder,
            ensure_ascii=ensure_ascii,
            indent=indent,
            sort_keys=sort_keys,
            separators=separators
        )
    except (TypeError, ValueError) as e:
        raise SerializationError(f"Failed to serialize data: {str(e)}") from e


def serialize_sqlalchemy_model(
    model_instance: Any, 
    exclude_fields: Optional[Set[str]] = None,
    include_relationships: bool = False,
    max_depth: int = 1
) -> Dict[str, Any]:
    """
    Serialize SQLAlchemy model instance to dictionary format.
    
    Converts Flask-SQLAlchemy model instances to dictionary representations
    suitable for JSON serialization while respecting field exclusions and
    security considerations.
    
    Args:
        model_instance: SQLAlchemy model instance to serialize
        exclude_fields: Set of field names to exclude from serialization
        include_relationships: Whether to include relationship fields
        max_depth: Maximum depth for relationship serialization
        
    Returns:
        Dictionary representation of the model instance
        
    Example:
        >>> user = User.query.get(1)
        >>> user_dict = serialize_sqlalchemy_model(
        ...     user, 
        ...     exclude_fields={'password_hash', 'secret_key'}
        ... )
    """
    if not hasattr(model_instance, '__table__'):
        raise SerializationError("Object is not a SQLAlchemy model instance")
    
    exclude_fields = exclude_fields or set()
    result = {}
    
    # Serialize column attributes
    for column in model_instance.__table__.columns:
        column_name = column.name
        
        # Skip excluded fields
        if column_name in exclude_fields:
            continue
            
        # Get attribute value
        try:
            value = getattr(model_instance, column_name)
            
            # Apply security filtering for sensitive fields
            if _is_sensitive_field(column_name):
                value = _filter_sensitive_data(value, column_name)
                
            result[column_name] = value
            
        except AttributeError:
            # Handle missing attributes gracefully
            continue
    
    # Include relationships if requested and within depth limit
    if include_relationships and max_depth > 0:
        for relationship in model_instance.__mapper__.relationships:
            rel_name = relationship.key
            
            # Skip excluded relationships
            if rel_name in exclude_fields:
                continue
                
            try:
                rel_value = getattr(model_instance, rel_name)
                
                if rel_value is not None:
                    if hasattr(rel_value, '__iter__') and not isinstance(rel_value, str):
                        # Handle collection relationships
                        result[rel_name] = [
                            serialize_sqlalchemy_model(
                                item, 
                                exclude_fields=exclude_fields,
                                include_relationships=False,
                                max_depth=max_depth - 1
                            )
                            for item in rel_value
                        ]
                    else:
                        # Handle single relationships
                        result[rel_name] = serialize_sqlalchemy_model(
                            rel_value,
                            exclude_fields=exclude_fields,
                            include_relationships=False,
                            max_depth=max_depth - 1
                        )
                        
            except AttributeError:
                # Handle missing relationship attributes gracefully
                continue
    
    return result


def sanitize_for_serialization(
    data: Any, 
    classification: DataClassification = DataClassification.PUBLIC,
    exclude_patterns: Optional[List[str]] = None
) -> Any:
    """
    Sanitize data for serialization based on security classification.
    
    Applies security-aware data sanitization to prevent sensitive information
    exposure during serialization while maintaining data utility for API responses.
    
    Args:
        data: Data to sanitize
        classification: Security classification level
        exclude_patterns: List of regex patterns for field exclusion
        
    Returns:
        Sanitized data safe for serialization
        
    Example:
        >>> user_data = {
        ...     'username': 'john_doe',
        ...     'email': 'john@example.com',
        ...     'password_hash': 'secret_hash',
        ...     'api_key': 'secret_key'
        ... }
        >>> sanitized = sanitize_for_serialization(
        ...     user_data, 
        ...     classification=DataClassification.PUBLIC
        ... )
        # Results in: {'username': 'john_doe', 'email': 'john@example.com'}
    """
    exclude_patterns = exclude_patterns or []
    
    # Define default exclusion patterns based on classification
    default_exclusions = _get_default_exclusions(classification)
    all_patterns = default_exclusions + exclude_patterns
    
    if isinstance(data, dict):
        return _sanitize_dict(data, all_patterns)
    elif isinstance(data, list):
        return [sanitize_for_serialization(item, classification, exclude_patterns) for item in data]
    else:
        return sanitize_input(data)


def create_api_response(
    data: Any = None,
    message: str = "Success",
    status_code: int = 200,
    metadata: Optional[Dict[str, Any]] = None,
    errors: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create standardized API response structure for client compatibility.
    
    Generates consistent API response format that maintains compatibility with
    existing client applications during the Node.js to Flask migration.
    
    Args:
        data: Response data payload
        message: Human-readable response message
        status_code: HTTP status code
        metadata: Additional response metadata
        errors: List of error messages (for error responses)
        
    Returns:
        Standardized API response dictionary
        
    Example:
        >>> response = create_api_response(
        ...     data={'user_id': 123, 'username': 'john_doe'},
        ...     message="User retrieved successfully",
        ...     status_code=200,
        ...     metadata={'request_id': 'req_12345'}
        ... )
    """
    # Determine status based on status code
    if status_code >= 200 and status_code < 300:
        status = "success"
    elif status_code >= 400 and status_code < 500:
        status = "error"
    elif status_code >= 500:
        status = "error"
    else:
        status = "unknown"
    
    # Generate timestamp in ISO format
    timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
    
    # Create response structure
    response = ApiResponse(
        data=data,
        message=message,
        status=status,
        status_code=status_code,
        timestamp=timestamp,
        metadata=metadata,
        errors=errors
    )
    
    # Convert to dictionary and serialize
    response_dict = asdict(response)
    
    # Remove None values for cleaner response
    return {k: v for k, v in response_dict.items() if v is not None}


def create_paginated_response(
    items: List[Any],
    page: int,
    per_page: int,
    total: int,
    endpoint: Optional[str] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Create paginated API response with comprehensive metadata.
    
    Generates standardized paginated response format supporting data pagination
    and filtering requirements while maintaining client compatibility.
    
    Args:
        items: List of items for current page
        page: Current page number (1-based)
        per_page: Number of items per page
        total: Total number of items across all pages
        endpoint: API endpoint for generating navigation links
        **kwargs: Additional query parameters for navigation links
        
    Returns:
        Paginated response dictionary with data and metadata
        
    Example:
        >>> users = User.query.paginate(page=1, per_page=10)
        >>> response = create_paginated_response(
        ...     items=[serialize_sqlalchemy_model(u) for u in users.items],
        ...     page=users.page,
        ...     per_page=users.per_page,
        ...     total=users.total,
        ...     endpoint='api.users'
        ... )
    """
    # Calculate pagination metadata
    pages = (total + per_page - 1) // per_page  # Ceiling division
    has_prev = page > 1
    has_next = page < pages
    prev_num = page - 1 if has_prev else None
    next_num = page + 1 if has_next else None
    
    # Create pagination metadata
    pagination_meta = PaginationMetadata(
        page=page,
        per_page=per_page,
        total=total,
        pages=pages,
        has_prev=has_prev,
        has_next=has_next,
        prev_num=prev_num,
        next_num=next_num
    )
    
    # Generate navigation links if endpoint provided
    links = {}
    if endpoint:
        from flask import url_for
        
        try:
            # Self link
            links['self'] = url_for(endpoint, page=page, per_page=per_page, **kwargs, _external=True)
            
            # First page link
            links['first'] = url_for(endpoint, page=1, per_page=per_page, **kwargs, _external=True)
            
            # Last page link
            links['last'] = url_for(endpoint, page=pages, per_page=per_page, **kwargs, _external=True)
            
            # Previous page link
            if has_prev:
                links['prev'] = url_for(endpoint, page=prev_num, per_page=per_page, **kwargs, _external=True)
            
            # Next page link
            if has_next:
                links['next'] = url_for(endpoint, page=next_num, per_page=per_page, **kwargs, _external=True)
                
        except Exception as e:
            # Handle URL generation errors gracefully
            current_app.logger.warning(f"Failed to generate pagination links: {str(e)}")
    
    # Create response metadata
    metadata = {
        'pagination': asdict(pagination_meta)
    }
    
    if links:
        metadata['links'] = links
    
    # Return standardized paginated response
    return create_api_response(
        data=items,
        message=f"Retrieved {len(items)} items (page {page} of {pages})",
        status_code=200,
        metadata=metadata
    )


def create_error_response(
    message: str,
    status_code: int = 400,
    errors: Optional[List[str]] = None,
    error_code: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create standardized error response for consistent error handling.
    
    Args:
        message: Primary error message
        status_code: HTTP status code
        errors: List of detailed error messages
        error_code: Application-specific error code
        
    Returns:
        Standardized error response dictionary
    """
    metadata = {}
    if error_code:
        metadata['error_code'] = error_code
    
    if hasattr(g, 'request_id'):
        metadata['request_id'] = g.request_id
    
    return create_api_response(
        data=None,
        message=message,
        status_code=status_code,
        metadata=metadata if metadata else None,
        errors=errors
    )


def serialize_query_result(
    query_result: Any,
    exclude_fields: Optional[Set[str]] = None,
    include_relationships: bool = False
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Serialize SQLAlchemy query results to JSON-compatible format.
    
    Args:
        query_result: SQLAlchemy query result (single instance or list)
        exclude_fields: Fields to exclude from serialization
        include_relationships: Whether to include relationship data
        
    Returns:
        Serialized query result(s)
    """
    if query_result is None:
        return None
    
    # Handle single instance
    if hasattr(query_result, '__table__'):
        return serialize_sqlalchemy_model(
            query_result,
            exclude_fields=exclude_fields,
            include_relationships=include_relationships
        )
    
    # Handle list/collection of instances
    if hasattr(query_result, '__iter__'):
        return [
            serialize_sqlalchemy_model(
                item,
                exclude_fields=exclude_fields,
                include_relationships=include_relationships
            )
            for item in query_result
            if hasattr(item, '__table__')
        ]
    
    # Handle other types
    return query_result


def format_decimal(value: decimal.Decimal, places: int = 2) -> str:
    """
    Format decimal value for consistent API representation.
    
    Args:
        value: Decimal value to format
        places: Number of decimal places
        
    Returns:
        Formatted decimal string
    """
    if not isinstance(value, decimal.Decimal):
        value = decimal.Decimal(str(value))
    
    # Quantize to specified decimal places
    quantized = value.quantize(decimal.Decimal(f'0.{"0" * places}'))
    return str(quantized)


def parse_filter_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse and validate filter parameters for API endpoints.
    
    Args:
        params: Raw query parameters from request
        
    Returns:
        Parsed and validated filter parameters
    """
    filters = {}
    
    for key, value in params.items():
        if key.startswith('filter_'):
            filter_name = key[7:]  # Remove 'filter_' prefix
            filters[filter_name] = sanitize_input(value)
    
    return filters


# Private helper functions

def _is_sensitive_field(field_name: str) -> bool:
    """Check if a field contains sensitive information."""
    sensitive_patterns = [
        r'.*password.*',
        r'.*secret.*',
        r'.*token.*',
        r'.*key.*',
        r'.*hash.*',
        r'.*salt.*',
        r'.*pin.*',
        r'.*ssn.*',
        r'.*social.*'
    ]
    
    field_lower = field_name.lower()
    return any(re.match(pattern, field_lower) for pattern in sensitive_patterns)


def _filter_sensitive_data(value: Any, field_name: str) -> Any:
    """Apply security filtering to sensitive field values."""
    if value is None:
        return None
    
    # For password-like fields, return masked value
    if 'password' in field_name.lower():
        return '***REDACTED***'
    
    # For other sensitive fields, return indication of presence
    return '***FILTERED***'


def _get_default_exclusions(classification: DataClassification) -> List[str]:
    """Get default field exclusion patterns based on data classification."""
    base_patterns = [
        r'.*password.*',
        r'.*secret.*',
        r'.*token.*',
        r'.*key.*'
    ]
    
    if classification == DataClassification.PUBLIC:
        return base_patterns + [
            r'.*hash.*',
            r'.*salt.*',
            r'.*internal.*',
            r'.*private.*',
            r'.*ssn.*',
            r'.*social.*'
        ]
    elif classification == DataClassification.INTERNAL:
        return base_patterns + [
            r'.*hash.*',
            r'.*salt.*'
        ]
    else:
        return base_patterns


def _sanitize_dict(data: Dict[str, Any], exclude_patterns: List[str]) -> Dict[str, Any]:
    """Sanitize dictionary by excluding fields matching patterns."""
    result = {}
    
    for key, value in data.items():
        # Check if key matches any exclusion pattern
        if any(re.match(pattern, key.lower()) for pattern in exclude_patterns):
            continue
        
        # Recursively sanitize nested structures
        if isinstance(value, dict):
            result[key] = _sanitize_dict(value, exclude_patterns)
        elif isinstance(value, list):
            result[key] = [
                _sanitize_dict(item, exclude_patterns) if isinstance(item, dict) else sanitize_input(item)
                for item in value
            ]
        else:
            result[key] = sanitize_input(value)
    
    return result


# Flask integration utilities

def jsonify_with_datetime(*args, **kwargs) -> 'Response':
    """
    Enhanced Flask jsonify with datetime support.
    
    Replacement for Flask's jsonify that uses the enhanced JSON encoder
    for consistent datetime and decimal serialization.
    """
    if args and kwargs:
        raise TypeError('jsonify() takes either args or kwargs, not both')
    
    if args:
        data = args[0] if len(args) == 1 else args
    else:
        data = kwargs
    
    # Use enhanced JSON encoder
    json_str = serialize_json(data)
    
    # Create Flask response
    from flask import current_app, Response
    response = Response(
        json_str,
        mimetype=current_app.config.get('JSONIFY_MIMETYPE', 'application/json')
    )
    
    return response


def register_serialization_handlers(app):
    """
    Register serialization handlers with Flask application.
    
    Args:
        app: Flask application instance
    """
    # Set default JSON encoder
    app.json_encoder = EnhancedJSONEncoder
    
    # Register error handlers for serialization errors
    @app.errorhandler(SerializationError)
    def handle_serialization_error(error):
        return create_error_response(
            message="Data serialization error",
            status_code=500,
            errors=[str(error)]
        ), 500


# Export main functions for external use
__all__ = [
    'serialize_json',
    'serialize_sqlalchemy_model',
    'sanitize_for_serialization',
    'create_api_response',
    'create_paginated_response',
    'create_error_response',
    'serialize_query_result',
    'format_decimal',
    'parse_filter_params',
    'jsonify_with_datetime',
    'register_serialization_handlers',
    'EnhancedJSONEncoder',
    'SerializationError',
    'DataClassification',
    'PaginationMetadata',
    'ApiResponse'
]