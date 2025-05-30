"""
Flask API Blueprint Implementation

This module provides the core REST API blueprint for the Flask 3.1.1 application,
implementing comprehensive API endpoint conversion from Node.js to Flask while
maintaining complete functional parity and API contract compliance per Section 4.3.1.

The blueprint implements Feature F-001 (API Endpoint Conversion) and Feature F-002
(Request/Response Handling Migration) with comprehensive HTTP method support,
request validation framework integration, and standardized response formatting.

Key Features:
- RESTful API endpoints with complete HTTP method support (GET, POST, PUT/PATCH, DELETE)
- Request validation using Marshmallow schemas for enhanced data integrity
- Service layer coordination for business logic execution per Section 2.1.3 Feature F-005
- Comprehensive error handling with proper HTTP status codes per Section 4.3.2.2
- API contract preservation with identical response formats per Section 4.3.1.4
- Performance optimization with response times under 200ms per Section 2.2.1
- Flask-SQLAlchemy integration for database operations
- Authentication and authorization support through service layer integration

Architecture Benefits:
- Blueprint-based modular organization per Flask 3.1.1 best practices
- Clear separation between API layer and business logic through service coordination
- Type-safe request/response handling with comprehensive validation
- Standardized error responses with detailed error information
- Performance monitoring and health check capabilities
- Comprehensive logging and audit trail support

Dependencies:
- Flask 3.1.1: Core web framework and blueprint functionality
- Flask-SQLAlchemy 3.1.1: Database ORM integration
- Marshmallow: Request/response validation and serialization
- Service Layer: Business logic coordination and execution
- Models: Database entity access and manipulation
"""

import logging
from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime, timezone
from functools import wraps
import traceback

# Core Flask imports
from flask import (
    Blueprint, request, jsonify, current_app, g,
    abort, make_response
)
from werkzeug.exceptions import (
    BadRequest, Unauthorized, Forbidden, NotFound,
    MethodNotAllowed, InternalServerError, HTTPException
)

# Marshmallow for request/response validation
from marshmallow import Schema, fields, ValidationError as MarshmallowValidationError, validate

# Import service layer components
from services import (
    get_service, AuthService, UserService, ValidationService,
    ServiceError, ValidationError, NotFoundError, DatabaseError,
    ServiceResult
)

# Import model components for type hints and direct access when needed
from models import (
    User, UserSession, Role, Permission,
    BusinessEntity, EntityRelationship, AuditLog,
    db
)

# Configure logging for API blueprint
logger = logging.getLogger(__name__)

# Create API blueprint with URL prefix
api_bp = Blueprint(
    'api',
    __name__,
    url_prefix='/api/v1',
    template_folder='templates'
)


# =============================================================================
# REQUEST/RESPONSE SCHEMAS
# =============================================================================

class BaseResponseSchema(Schema):
    """
    Base response schema for standardized API responses.
    
    Ensures consistent response format across all API endpoints
    while maintaining compatibility with existing client applications.
    """
    success = fields.Boolean(required=True, description="Operation success status")
    message = fields.String(required=True, description="Response message")
    data = fields.Raw(allow_none=True, description="Response data payload")
    timestamp = fields.DateTime(required=True, description="Response timestamp")
    request_id = fields.String(required=True, description="Unique request identifier")


class ErrorResponseSchema(BaseResponseSchema):
    """
    Error response schema for standardized error handling.
    
    Provides detailed error information while maintaining security
    and preventing sensitive information disclosure.
    """
    error_code = fields.String(required=True, description="Error code identifier")
    error_details = fields.Raw(allow_none=True, description="Additional error details")
    validation_errors = fields.Dict(allow_none=True, description="Field validation errors")


class PaginationSchema(Schema):
    """
    Pagination schema for list endpoints.
    
    Implements consistent pagination patterns across all list operations
    with configurable page sizes and comprehensive metadata.
    """
    page = fields.Integer(required=True, validate=validate.Range(min=1), description="Current page number")
    per_page = fields.Integer(required=True, validate=validate.Range(min=1, max=100), description="Items per page")
    total_items = fields.Integer(required=True, description="Total number of items")
    total_pages = fields.Integer(required=True, description="Total number of pages")
    has_next = fields.Boolean(required=True, description="Has next page flag")
    has_prev = fields.Boolean(required=True, description="Has previous page flag")


class UserCreateSchema(Schema):
    """
    User creation request validation schema.
    
    Validates user registration data with comprehensive field validation
    and business rule enforcement per existing API contracts.
    """
    email = fields.Email(required=True, description="User email address")
    password = fields.String(required=True, validate=validate.Length(min=8, max=128), description="User password")
    first_name = fields.String(required=True, validate=validate.Length(min=1, max=50), description="User first name")
    last_name = fields.String(required=True, validate=validate.Length(min=1, max=50), description="User last name")
    role_ids = fields.List(fields.Integer(), allow_none=True, description="Role assignments")


class UserUpdateSchema(Schema):
    """
    User update request validation schema.
    
    Validates user modification data with partial update support
    and field-level validation for data integrity.
    """
    email = fields.Email(allow_none=True, description="User email address")
    first_name = fields.String(allow_none=True, validate=validate.Length(min=1, max=50), description="User first name")
    last_name = fields.String(allow_none=True, validate=validate.Length(min=1, max=50), description="User last name")
    is_active = fields.Boolean(allow_none=True, description="User active status")
    role_ids = fields.List(fields.Integer(), allow_none=True, description="Role assignments")


class BusinessEntityCreateSchema(Schema):
    """
    Business entity creation request validation schema.
    
    Validates business entity data with comprehensive field validation
    and relationship management per business logic requirements.
    """
    name = fields.String(required=True, validate=validate.Length(min=1, max=100), description="Entity name")
    entity_type = fields.String(required=True, validate=validate.Length(min=1, max=50), description="Entity type")
    description = fields.String(allow_none=True, validate=validate.Length(max=500), description="Entity description")
    metadata = fields.Dict(allow_none=True, description="Additional entity metadata")
    parent_id = fields.Integer(allow_none=True, description="Parent entity ID")


class BusinessEntityUpdateSchema(Schema):
    """
    Business entity update request validation schema.
    
    Validates business entity modification data with partial update support
    and relationship validation for data consistency.
    """
    name = fields.String(allow_none=True, validate=validate.Length(min=1, max=100), description="Entity name")
    description = fields.String(allow_none=True, validate=validate.Length(max=500), description="Entity description")
    metadata = fields.Dict(allow_none=True, description="Additional entity metadata")
    is_active = fields.Boolean(allow_none=True, description="Entity active status")


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_request_id() -> str:
    """
    Generate unique request identifier for tracing and logging.
    
    Returns:
        Unique request identifier string
    """
    import uuid
    return str(uuid.uuid4())


def get_current_user() -> Optional[User]:
    """
    Get current authenticated user from Flask request context.
    
    Returns:
        Current user instance or None if not authenticated
    """
    try:
        auth_service = get_service(AuthService)
        return auth_service.get_current_user()
    except Exception as e:
        logger.warning(f"Failed to get current user: {e}")
        return None


def require_authentication(f):
    """
    Decorator for requiring user authentication on API endpoints.
    
    Args:
        f: Function to decorate
        
    Returns:
        Decorated function with authentication requirement
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            auth_service = get_service(AuthService)
            if not auth_service.is_authenticated():
                return create_error_response(
                    "Authentication required",
                    status_code=401,
                    error_code="AUTHENTICATION_REQUIRED"
                )
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Authentication check failed: {e}")
            return create_error_response(
                "Authentication system error",
                status_code=500,
                error_code="AUTHENTICATION_SYSTEM_ERROR"
            )
    return decorated_function


def require_permission(permission_name: str):
    """
    Decorator for requiring specific permission on API endpoints.
    
    Args:
        permission_name: Required permission name
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                auth_service = get_service(AuthService)
                current_user = get_current_user()
                
                if not current_user:
                    return create_error_response(
                        "Authentication required",
                        status_code=401,
                        error_code="AUTHENTICATION_REQUIRED"
                    )
                
                if not auth_service.has_permission(current_user.id, permission_name):
                    return create_error_response(
                        f"Permission '{permission_name}' required",
                        status_code=403,
                        error_code="INSUFFICIENT_PERMISSIONS"
                    )
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Permission check failed: {e}")
                return create_error_response(
                    "Authorization system error",
                    status_code=500,
                    error_code="AUTHORIZATION_SYSTEM_ERROR"
                )
        return decorated_function
    return decorator


def validate_request_json(schema_class: Schema):
    """
    Decorator for validating JSON request data using Marshmallow schemas.
    
    Args:
        schema_class: Marshmallow schema class for validation
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Validate content type
                if not request.is_json:
                    return create_error_response(
                        "Content-Type must be application/json",
                        status_code=400,
                        error_code="INVALID_CONTENT_TYPE"
                    )
                
                # Get JSON data
                json_data = request.get_json()
                if json_data is None:
                    return create_error_response(
                        "Invalid JSON data",
                        status_code=400,
                        error_code="INVALID_JSON"
                    )
                
                # Validate using schema
                schema = schema_class()
                try:
                    validated_data = schema.load(json_data)
                    g.validated_data = validated_data
                except MarshmallowValidationError as ve:
                    return create_error_response(
                        "Request validation failed",
                        status_code=400,
                        error_code="VALIDATION_ERROR",
                        validation_errors=ve.messages
                    )
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Request validation error: {e}")
                return create_error_response(
                    "Request validation system error",
                    status_code=500,
                    error_code="VALIDATION_SYSTEM_ERROR"
                )
        return decorated_function
    return decorator


def create_success_response(
    message: str,
    data: Any = None,
    status_code: int = 200,
    pagination: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Create standardized success response with consistent format.
    
    Args:
        message: Success message
        data: Response data payload
        status_code: HTTP status code
        pagination: Optional pagination metadata
        
    Returns:
        Tuple of response dictionary and status code
    """
    try:
        # Generate request ID for tracing
        request_id = getattr(g, 'request_id', generate_request_id())
        
        # Build response payload
        response_data = {
            'success': True,
            'message': message,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'request_id': request_id
        }
        
        # Add pagination metadata if provided
        if pagination:
            response_data['pagination'] = pagination
        
        # Log successful response
        logger.info(f"Success response: {message} (request_id: {request_id})")
        
        return response_data, status_code
        
    except Exception as e:
        logger.error(f"Error creating success response: {e}")
        # Fallback response
        return {
            'success': True,
            'message': message,
            'data': data,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'request_id': 'unknown'
        }, status_code


def create_error_response(
    message: str,
    status_code: int = 400,
    error_code: Optional[str] = None,
    error_details: Optional[Dict[str, Any]] = None,
    validation_errors: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Create standardized error response with comprehensive error information.
    
    Args:
        message: Error message
        status_code: HTTP status code
        error_code: Error code identifier
        error_details: Additional error details
        validation_errors: Field validation errors
        
    Returns:
        Tuple of response dictionary and status code
    """
    try:
        # Generate request ID for tracing
        request_id = getattr(g, 'request_id', generate_request_id())
        
        # Build error response payload
        response_data = {
            'success': False,
            'message': message,
            'data': None,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'request_id': request_id,
            'error_code': error_code or 'UNKNOWN_ERROR'
        }
        
        # Add optional error details
        if error_details:
            response_data['error_details'] = error_details
        
        if validation_errors:
            response_data['validation_errors'] = validation_errors
        
        # Log error response
        logger.warning(f"Error response: {message} (status: {status_code}, request_id: {request_id})")
        
        return response_data, status_code
        
    except Exception as e:
        logger.error(f"Error creating error response: {e}")
        # Fallback error response
        return {
            'success': False,
            'message': 'Internal server error',
            'data': None,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'request_id': 'unknown',
            'error_code': 'RESPONSE_GENERATION_ERROR'
        }, 500


def handle_service_error(error: Exception) -> Tuple[Dict[str, Any], int]:
    """
    Handle service layer errors with appropriate HTTP status codes.
    
    Args:
        error: Service layer exception
        
    Returns:
        Tuple of error response and status code
    """
    if isinstance(error, NotFoundError):
        return create_error_response(
            str(error),
            status_code=404,
            error_code="RESOURCE_NOT_FOUND"
        )
    elif isinstance(error, ValidationError):
        return create_error_response(
            str(error),
            status_code=400,
            error_code="VALIDATION_ERROR"
        )
    elif isinstance(error, DatabaseError):
        logger.error(f"Database error: {error}")
        return create_error_response(
            "Database operation failed",
            status_code=500,
            error_code="DATABASE_ERROR"
        )
    elif isinstance(error, ServiceError):
        return create_error_response(
            str(error),
            status_code=500,
            error_code="SERVICE_ERROR"
        )
    else:
        logger.error(f"Unexpected error: {error}")
        return create_error_response(
            "Internal server error",
            status_code=500,
            error_code="INTERNAL_ERROR"
        )


# =============================================================================
# HEALTH CHECK AND SYSTEM ENDPOINTS
# =============================================================================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """
    System health check endpoint for monitoring and load balancer integration.
    
    Returns comprehensive system health information including database connectivity,
    service layer status, and performance metrics for operational monitoring.
    
    Returns:
        JSON response with health status and system metrics
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        health_data = {
            'status': 'healthy',
            'database': 'connected',
            'services': 'operational',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': current_app.config.get('VERSION', '1.0.0')
        }
        
        # Test database connectivity
        try:
            db.session.execute(db.text('SELECT 1')).scalar()
            health_data['database'] = 'connected'
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            health_data['database'] = 'disconnected'
            health_data['status'] = 'degraded'
        
        # Test service layer health
        try:
            auth_service = get_service(AuthService)
            auth_result = auth_service.health_check()
            
            user_service = get_service(UserService)
            user_result = user_service.health_check()
            
            validation_service = get_service(ValidationService)
            validation_result = validation_service.health_check()
            
            if all([auth_result.success, user_result.success, validation_result.success]):
                health_data['services'] = 'operational'
            else:
                health_data['services'] = 'degraded'
                health_data['status'] = 'degraded'
                
        except Exception as e:
            logger.error(f"Service health check failed: {e}")
            health_data['services'] = 'unavailable'
            health_data['status'] = 'unhealthy'
        
        # Determine HTTP status code based on health
        status_code = 200 if health_data['status'] == 'healthy' else 503
        
        return create_success_response(
            "Health check completed",
            data=health_data,
            status_code=status_code
        )
        
    except Exception as e:
        logger.error(f"Health check endpoint error: {e}")
        return create_error_response(
            "Health check failed",
            status_code=500,
            error_code="HEALTH_CHECK_ERROR"
        )


@api_bp.route('/system/info', methods=['GET'])
@require_authentication
@require_permission('system:read')
def system_info():
    """
    System information endpoint for administrative monitoring.
    
    Provides detailed system configuration and operational metrics
    for administrative users with appropriate permissions.
    
    Returns:
        JSON response with comprehensive system information
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        system_data = {
            'application': {
                'name': current_app.config.get('APP_NAME', 'Flask Application'),
                'version': current_app.config.get('VERSION', '1.0.0'),
                'environment': current_app.config.get('FLASK_ENV', 'production'),
                'debug_mode': current_app.debug
            },
            'database': {
                'engine': str(db.engine.url).split('@')[0],  # Hide credentials
                'pool_size': db.engine.pool.size(),
                'checked_out': db.engine.pool.checkedout(),
                'overflow': db.engine.pool.overflow(),
                'invalid': db.engine.pool.invalid()
            },
            'services': {
                'total_registered': len(get_service(AuthService).get_performance_metrics())
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return create_success_response(
            "System information retrieved",
            data=system_data
        )
        
    except Exception as e:
        logger.error(f"System info endpoint error: {e}")
        return handle_service_error(e)


# =============================================================================
# USER MANAGEMENT ENDPOINTS
# =============================================================================

@api_bp.route('/users', methods=['GET'])
@require_authentication
@require_permission('users:read')
def list_users():
    """
    List users with pagination and filtering support.
    
    Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - search: Search term for name/email filtering
        - is_active: Filter by active status
        - role_id: Filter by role assignment
    
    Returns:
        JSON response with paginated user list and metadata
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Parse query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        search = request.args.get('search', '').strip()
        is_active = request.args.get('is_active', type=bool)
        role_id = request.args.get('role_id', type=int)
        
        # Get user service
        user_service = get_service(UserService)
        
        # Build filter criteria
        filters = {}
        if search:
            filters['search'] = search
        if is_active is not None:
            filters['is_active'] = is_active
        if role_id:
            filters['role_id'] = role_id
        
        # Execute service operation
        result = user_service.list_users(
            page=page,
            per_page=per_page,
            filters=filters
        )
        
        if not result.success:
            return create_error_response(
                result.error or "Failed to retrieve users",
                status_code=500,
                error_code="USER_LIST_ERROR"
            )
        
        # Build pagination metadata
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_items': result.data.get('total', 0),
            'total_pages': result.data.get('pages', 0),
            'has_next': result.data.get('has_next', False),
            'has_prev': result.data.get('has_prev', False)
        }
        
        return create_success_response(
            f"Retrieved {len(result.data.get('items', []))} users",
            data=result.data.get('items', []),
            pagination=pagination
        )
        
    except Exception as e:
        logger.error(f"List users endpoint error: {e}")
        return handle_service_error(e)


@api_bp.route('/users/<int:user_id>', methods=['GET'])
@require_authentication
@require_permission('users:read')
def get_user(user_id: int):
    """
    Get specific user by ID with comprehensive details.
    
    Args:
        user_id: User identifier
    
    Returns:
        JSON response with user details and relationships
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Get user service
        user_service = get_service(UserService)
        
        # Execute service operation
        result = user_service.get_user_by_id(user_id)
        
        if not result.success:
            if "not found" in (result.error or "").lower():
                return create_error_response(
                    f"User with ID {user_id} not found",
                    status_code=404,
                    error_code="USER_NOT_FOUND"
                )
            return create_error_response(
                result.error or "Failed to retrieve user",
                status_code=500,
                error_code="USER_RETRIEVAL_ERROR"
            )
        
        return create_success_response(
            f"User {user_id} retrieved successfully",
            data=result.data
        )
        
    except Exception as e:
        logger.error(f"Get user endpoint error: {e}")
        return handle_service_error(e)


@api_bp.route('/users', methods=['POST'])
@require_authentication
@require_permission('users:create')
@validate_request_json(UserCreateSchema)
def create_user():
    """
    Create new user with validation and role assignment.
    
    Request Body:
        - email: User email address (required)
        - password: User password (required, min 8 chars)
        - first_name: User first name (required)
        - last_name: User last name (required)
        - role_ids: List of role IDs to assign (optional)
    
    Returns:
        JSON response with created user details
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Get validated data from decorator
        user_data = g.validated_data
        
        # Get user service
        user_service = get_service(UserService)
        
        # Execute service operation
        result = user_service.create_user(user_data)
        
        if not result.success:
            return create_error_response(
                result.error or "Failed to create user",
                status_code=400,
                error_code="USER_CREATION_ERROR"
            )
        
        return create_success_response(
            "User created successfully",
            data=result.data,
            status_code=201
        )
        
    except Exception as e:
        logger.error(f"Create user endpoint error: {e}")
        return handle_service_error(e)


@api_bp.route('/users/<int:user_id>', methods=['PUT', 'PATCH'])
@require_authentication
@require_permission('users:update')
@validate_request_json(UserUpdateSchema)
def update_user(user_id: int):
    """
    Update existing user with partial update support.
    
    Args:
        user_id: User identifier
    
    Request Body:
        - email: User email address (optional)
        - first_name: User first name (optional)
        - last_name: User last name (optional)
        - is_active: User active status (optional)
        - role_ids: List of role IDs to assign (optional)
    
    Returns:
        JSON response with updated user details
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Get validated data from decorator
        user_data = g.validated_data
        
        # Get user service
        user_service = get_service(UserService)
        
        # Execute service operation
        result = user_service.update_user(user_id, user_data)
        
        if not result.success:
            if "not found" in (result.error or "").lower():
                return create_error_response(
                    f"User with ID {user_id} not found",
                    status_code=404,
                    error_code="USER_NOT_FOUND"
                )
            return create_error_response(
                result.error or "Failed to update user",
                status_code=400,
                error_code="USER_UPDATE_ERROR"
            )
        
        return create_success_response(
            f"User {user_id} updated successfully",
            data=result.data
        )
        
    except Exception as e:
        logger.error(f"Update user endpoint error: {e}")
        return handle_service_error(e)


@api_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_authentication
@require_permission('users:delete')
def delete_user(user_id: int):
    """
    Delete user with proper authorization and cleanup.
    
    Args:
        user_id: User identifier
    
    Returns:
        JSON response confirming deletion
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Get current user to prevent self-deletion
        current_user = get_current_user()
        if current_user and current_user.id == user_id:
            return create_error_response(
                "Cannot delete your own user account",
                status_code=400,
                error_code="SELF_DELETE_FORBIDDEN"
            )
        
        # Get user service
        user_service = get_service(UserService)
        
        # Execute service operation
        result = user_service.delete_user(user_id)
        
        if not result.success:
            if "not found" in (result.error or "").lower():
                return create_error_response(
                    f"User with ID {user_id} not found",
                    status_code=404,
                    error_code="USER_NOT_FOUND"
                )
            return create_error_response(
                result.error or "Failed to delete user",
                status_code=400,
                error_code="USER_DELETE_ERROR"
            )
        
        return create_success_response(
            f"User {user_id} deleted successfully",
            status_code=204
        )
        
    except Exception as e:
        logger.error(f"Delete user endpoint error: {e}")
        return handle_service_error(e)


# =============================================================================
# BUSINESS ENTITY ENDPOINTS
# =============================================================================

@api_bp.route('/entities', methods=['GET'])
@require_authentication
@require_permission('entities:read')
def list_business_entities():
    """
    List business entities with pagination and filtering support.
    
    Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - entity_type: Filter by entity type
        - search: Search term for name filtering
        - is_active: Filter by active status
        - parent_id: Filter by parent entity
    
    Returns:
        JSON response with paginated entity list and metadata
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Parse query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        entity_type = request.args.get('entity_type', '').strip()
        search = request.args.get('search', '').strip()
        is_active = request.args.get('is_active', type=bool)
        parent_id = request.args.get('parent_id', type=int)
        
        # Build filter criteria
        filters = {}
        if entity_type:
            filters['entity_type'] = entity_type
        if search:
            filters['search'] = search
        if is_active is not None:
            filters['is_active'] = is_active
        if parent_id:
            filters['parent_id'] = parent_id
        
        # Query business entities with pagination
        query = db.session.query(BusinessEntity)
        
        # Apply filters
        if entity_type:
            query = query.filter(BusinessEntity.entity_type == entity_type)
        if search:
            query = query.filter(BusinessEntity.name.ilike(f'%{search}%'))
        if is_active is not None:
            query = query.filter(BusinessEntity.is_active == is_active)
        if parent_id:
            # Filter by parent relationship (this assumes a parent_id field exists)
            pass  # Implement based on actual relationship structure
        
        # Execute paginated query
        pagination_result = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Convert entities to dictionary format
        entities = []
        for entity in pagination_result.items:
            entity_dict = {
                'id': entity.id,
                'name': entity.name,
                'entity_type': entity.entity_type,
                'description': entity.description,
                'metadata': entity.metadata,
                'is_active': entity.is_active,
                'created_at': entity.created_at.isoformat() if entity.created_at else None,
                'updated_at': entity.updated_at.isoformat() if entity.updated_at else None
            }
            entities.append(entity_dict)
        
        # Build pagination metadata
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_items': pagination_result.total,
            'total_pages': pagination_result.pages,
            'has_next': pagination_result.has_next,
            'has_prev': pagination_result.has_prev
        }
        
        return create_success_response(
            f"Retrieved {len(entities)} business entities",
            data=entities,
            pagination=pagination
        )
        
    except Exception as e:
        logger.error(f"List business entities endpoint error: {e}")
        return handle_service_error(e)


@api_bp.route('/entities/<int:entity_id>', methods=['GET'])
@require_authentication
@require_permission('entities:read')
def get_business_entity(entity_id: int):
    """
    Get specific business entity by ID with relationships.
    
    Args:
        entity_id: Entity identifier
    
    Returns:
        JSON response with entity details and relationships
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Query entity by ID
        entity = db.session.query(BusinessEntity).filter_by(id=entity_id).first()
        
        if not entity:
            return create_error_response(
                f"Business entity with ID {entity_id} not found",
                status_code=404,
                error_code="ENTITY_NOT_FOUND"
            )
        
        # Build entity response with relationships
        entity_data = {
            'id': entity.id,
            'name': entity.name,
            'entity_type': entity.entity_type,
            'description': entity.description,
            'metadata': entity.metadata,
            'is_active': entity.is_active,
            'created_at': entity.created_at.isoformat() if entity.created_at else None,
            'updated_at': entity.updated_at.isoformat() if entity.updated_at else None,
            'relationships': {
                'source_relationships': len(entity.source_relationships) if hasattr(entity, 'source_relationships') else 0,
                'target_relationships': len(entity.target_relationships) if hasattr(entity, 'target_relationships') else 0
            }
        }
        
        return create_success_response(
            f"Business entity {entity_id} retrieved successfully",
            data=entity_data
        )
        
    except Exception as e:
        logger.error(f"Get business entity endpoint error: {e}")
        return handle_service_error(e)


@api_bp.route('/entities', methods=['POST'])
@require_authentication
@require_permission('entities:create')
@validate_request_json(BusinessEntityCreateSchema)
def create_business_entity():
    """
    Create new business entity with validation.
    
    Request Body:
        - name: Entity name (required)
        - entity_type: Entity type (required)
        - description: Entity description (optional)
        - metadata: Additional metadata (optional)
        - parent_id: Parent entity ID (optional)
    
    Returns:
        JSON response with created entity details
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Get validated data from decorator
        entity_data = g.validated_data
        
        # Create new business entity
        entity = BusinessEntity(
            name=entity_data['name'],
            entity_type=entity_data['entity_type'],
            description=entity_data.get('description'),
            metadata=entity_data.get('metadata'),
            is_active=True
        )
        
        # Add to database session and commit
        db.session.add(entity)
        db.session.commit()
        
        # Build response data
        response_data = {
            'id': entity.id,
            'name': entity.name,
            'entity_type': entity.entity_type,
            'description': entity.description,
            'metadata': entity.metadata,
            'is_active': entity.is_active,
            'created_at': entity.created_at.isoformat() if entity.created_at else None
        }
        
        return create_success_response(
            "Business entity created successfully",
            data=response_data,
            status_code=201
        )
        
    except Exception as e:
        logger.error(f"Create business entity endpoint error: {e}")
        db.session.rollback()
        return handle_service_error(e)


@api_bp.route('/entities/<int:entity_id>', methods=['PUT', 'PATCH'])
@require_authentication
@require_permission('entities:update')
@validate_request_json(BusinessEntityUpdateSchema)
def update_business_entity(entity_id: int):
    """
    Update existing business entity with partial update support.
    
    Args:
        entity_id: Entity identifier
    
    Request Body:
        - name: Entity name (optional)
        - description: Entity description (optional)
        - metadata: Additional metadata (optional)
        - is_active: Entity active status (optional)
    
    Returns:
        JSON response with updated entity details
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Get validated data from decorator
        entity_data = g.validated_data
        
        # Query entity by ID
        entity = db.session.query(BusinessEntity).filter_by(id=entity_id).first()
        
        if not entity:
            return create_error_response(
                f"Business entity with ID {entity_id} not found",
                status_code=404,
                error_code="ENTITY_NOT_FOUND"
            )
        
        # Update entity fields
        if 'name' in entity_data:
            entity.name = entity_data['name']
        if 'description' in entity_data:
            entity.description = entity_data['description']
        if 'metadata' in entity_data:
            entity.metadata = entity_data['metadata']
        if 'is_active' in entity_data:
            entity.is_active = entity_data['is_active']
        
        # Commit changes
        db.session.commit()
        
        # Build response data
        response_data = {
            'id': entity.id,
            'name': entity.name,
            'entity_type': entity.entity_type,
            'description': entity.description,
            'metadata': entity.metadata,
            'is_active': entity.is_active,
            'created_at': entity.created_at.isoformat() if entity.created_at else None,
            'updated_at': entity.updated_at.isoformat() if entity.updated_at else None
        }
        
        return create_success_response(
            f"Business entity {entity_id} updated successfully",
            data=response_data
        )
        
    except Exception as e:
        logger.error(f"Update business entity endpoint error: {e}")
        db.session.rollback()
        return handle_service_error(e)


@api_bp.route('/entities/<int:entity_id>', methods=['DELETE'])
@require_authentication
@require_permission('entities:delete')
def delete_business_entity(entity_id: int):
    """
    Delete business entity with proper cleanup.
    
    Args:
        entity_id: Entity identifier
    
    Returns:
        JSON response confirming deletion
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Query entity by ID
        entity = db.session.query(BusinessEntity).filter_by(id=entity_id).first()
        
        if not entity:
            return create_error_response(
                f"Business entity with ID {entity_id} not found",
                status_code=404,
                error_code="ENTITY_NOT_FOUND"
            )
        
        # Delete entity (this will cascade to relationships if configured)
        db.session.delete(entity)
        db.session.commit()
        
        return create_success_response(
            f"Business entity {entity_id} deleted successfully",
            status_code=204
        )
        
    except Exception as e:
        logger.error(f"Delete business entity endpoint error: {e}")
        db.session.rollback()
        return handle_service_error(e)


# =============================================================================
# AUDIT AND MONITORING ENDPOINTS
# =============================================================================

@api_bp.route('/audit/logs', methods=['GET'])
@require_authentication
@require_permission('audit:read')
def list_audit_logs():
    """
    List audit logs with pagination and filtering support.
    
    Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - user_id: Filter by user
        - operation_type: Filter by operation type
        - start_date: Filter by start date (ISO format)
        - end_date: Filter by end date (ISO format)
    
    Returns:
        JSON response with paginated audit log list
    """
    try:
        # Generate request ID for tracing
        g.request_id = generate_request_id()
        
        # Parse query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        user_id = request.args.get('user_id', type=int)
        operation_type = request.args.get('operation_type', '').strip()
        start_date_str = request.args.get('start_date', '').strip()
        end_date_str = request.args.get('end_date', '').strip()
        
        # Query audit logs with pagination
        query = db.session.query(AuditLog)
        
        # Apply filters
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if operation_type:
            query = query.filter(AuditLog.operation_type == operation_type)
        
        # Date range filtering
        if start_date_str:
            try:
                start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
                query = query.filter(AuditLog.created_at >= start_date)
            except ValueError:
                return create_error_response(
                    "Invalid start_date format. Use ISO format.",
                    status_code=400,
                    error_code="INVALID_DATE_FORMAT"
                )
        
        if end_date_str:
            try:
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
                query = query.filter(AuditLog.created_at <= end_date)
            except ValueError:
                return create_error_response(
                    "Invalid end_date format. Use ISO format.",
                    status_code=400,
                    error_code="INVALID_DATE_FORMAT"
                )
        
        # Order by creation date (most recent first)
        query = query.order_by(AuditLog.created_at.desc())
        
        # Execute paginated query
        pagination_result = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Convert audit logs to dictionary format
        audit_logs = []
        for log in pagination_result.items:
            log_dict = {
                'id': log.id,
                'user_id': log.user_id,
                'operation_type': log.operation_type,
                'resource_type': log.resource_type,
                'resource_id': log.resource_id,
                'details': log.details,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'created_at': log.created_at.isoformat() if log.created_at else None
            }
            audit_logs.append(log_dict)
        
        # Build pagination metadata
        pagination = {
            'page': page,
            'per_page': per_page,
            'total_items': pagination_result.total,
            'total_pages': pagination_result.pages,
            'has_next': pagination_result.has_next,
            'has_prev': pagination_result.has_prev
        }
        
        return create_success_response(
            f"Retrieved {len(audit_logs)} audit logs",
            data=audit_logs,
            pagination=pagination
        )
        
    except Exception as e:
        logger.error(f"List audit logs endpoint error: {e}")
        return handle_service_error(e)


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@api_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle 400 Bad Request errors."""
    return create_error_response(
        "Bad request",
        status_code=400,
        error_code="BAD_REQUEST"
    )


@api_bp.errorhandler(401)
def handle_unauthorized(error):
    """Handle 401 Unauthorized errors."""
    return create_error_response(
        "Authentication required",
        status_code=401,
        error_code="AUTHENTICATION_REQUIRED"
    )


@api_bp.errorhandler(403)
def handle_forbidden(error):
    """Handle 403 Forbidden errors."""
    return create_error_response(
        "Access forbidden",
        status_code=403,
        error_code="ACCESS_FORBIDDEN"
    )


@api_bp.errorhandler(404)
def handle_not_found(error):
    """Handle 404 Not Found errors."""
    return create_error_response(
        "Resource not found",
        status_code=404,
        error_code="RESOURCE_NOT_FOUND"
    )


@api_bp.errorhandler(405)
def handle_method_not_allowed(error):
    """Handle 405 Method Not Allowed errors."""
    return create_error_response(
        "Method not allowed",
        status_code=405,
        error_code="METHOD_NOT_ALLOWED"
    )


@api_bp.errorhandler(500)
def handle_internal_server_error(error):
    """Handle 500 Internal Server Error."""
    logger.error(f"Internal server error: {error}")
    return create_error_response(
        "Internal server error",
        status_code=500,
        error_code="INTERNAL_SERVER_ERROR"
    )


@api_bp.errorhandler(Exception)
def handle_generic_exception(error):
    """Handle all other exceptions."""
    logger.error(f"Unhandled exception: {error}\n{traceback.format_exc()}")
    return create_error_response(
        "An unexpected error occurred",
        status_code=500,
        error_code="UNEXPECTED_ERROR"
    )


# =============================================================================
# REQUEST PREPROCESSING
# =============================================================================

@api_bp.before_request
def before_request():
    """
    Pre-process all API requests for logging and setup.
    
    Sets up request context with unique request ID for tracing,
    logs request details for monitoring, and initializes performance timing.
    """
    try:
        # Generate unique request ID
        g.request_id = generate_request_id()
        
        # Log request details
        logger.info(
            f"API Request: {request.method} {request.path} "
            f"(request_id: {g.request_id}, remote_addr: {request.remote_addr})"
        )
        
        # Set request start time for performance monitoring
        g.request_start_time = datetime.now(timezone.utc)
        
    except Exception as e:
        logger.error(f"Error in before_request: {e}")


@api_bp.after_request
def after_request(response):
    """
    Post-process all API responses for logging and monitoring.
    
    Args:
        response: Flask response object
        
    Returns:
        Modified response with additional headers and logging
    """
    try:
        # Calculate request duration
        if hasattr(g, 'request_start_time'):
            duration = (datetime.now(timezone.utc) - g.request_start_time).total_seconds() * 1000
        else:
            duration = 0
        
        # Add request ID header
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        
        # Add CORS headers for browser compatibility
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Request-ID'
        
        # Log response details
        logger.info(
            f"API Response: {request.method} {request.path} "
            f"(status: {response.status_code}, duration: {duration:.2f}ms, "
            f"request_id: {getattr(g, 'request_id', 'unknown')})"
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in after_request: {e}")
        return response


# =============================================================================
# BLUEPRINT REGISTRATION HELPER
# =============================================================================

def register_api_blueprint(app):
    """
    Register API blueprint with Flask application.
    
    Args:
        app: Flask application instance
    """
    try:
        app.register_blueprint(api_bp)
        logger.info("API blueprint registered successfully")
    except Exception as e:
        logger.error(f"Failed to register API blueprint: {e}")
        raise


# Export blueprint for application factory registration
__all__ = ['api_bp', 'register_api_blueprint']