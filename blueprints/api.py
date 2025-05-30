"""
Flask API Blueprint - RESTful API Endpoint Definitions

This blueprint implements the core REST API functionality for the Flask 3.1.1 application,
providing comprehensive HTTP method support (GET, POST, PUT/PATCH, DELETE) with enterprise-grade
request validation, response formatting, and error handling. The implementation preserves
complete API contract compatibility with existing client applications while leveraging Flask's
enhanced capabilities and Python's superior ecosystem.

Key Features:
- Complete RESTful API endpoint conversion from Node.js/Express.js patterns
- Flask-RESTX integration for automatic OpenAPI/Swagger documentation
- Marshmallow schema validation for robust request/response handling
- Service Layer pattern integration for business logic coordination
- Comprehensive error handling with standardized HTTP status codes
- Authentication decorator integration using Flask-Login patterns
- JSON response formatting with flask.jsonify() for API contract compliance

Architecture:
This blueprint follows Flask 3.1.1 blueprint patterns and integrates with the Service Layer
architecture for business logic orchestration. All endpoints maintain identical external API
contracts while transitioning from Express.js middleware patterns to Flask's request context
and decorator-based routing system.

API Coverage:
- User management endpoints (GET, POST, PUT, DELETE /api/users)
- Authentication endpoints (POST /api/auth/login, /api/auth/logout)
- Business entity operations (CRUD operations on primary business objects)
- Health and status monitoring endpoints
- Resource management with proper pagination and filtering
"""

from __future__ import annotations

import logging
from typing import (
    Dict, 
    Any, 
    Optional, 
    List, 
    Union,
    Tuple
)
from functools import wraps
from datetime import datetime, timezone

from flask import (
    Blueprint, 
    request, 
    jsonify, 
    current_app,
    g,
    abort,
    url_for,
    make_response
)
from flask_restx import (
    Api, 
    Resource, 
    Namespace,
    fields,
    marshal_with,
    expect,
    abort as restx_abort
)
from marshmallow import (
    Schema, 
    fields as ma_fields, 
    validate, 
    ValidationError,
    post_load,
    pre_dump
)
from werkzeug.exceptions import (
    BadRequest,
    NotFound, 
    Unauthorized,
    Forbidden,
    InternalServerError,
    UnprocessableEntity
)

# Import service layer dependencies for business logic coordination
from services import (
    get_service,
    with_service,
    service_transaction,
    ServiceException,
    ValidationException,
    DatabaseException
)

# Import model dependencies for data structure validation
from models import (
    User,
    BusinessEntity,
    AuditLog,
    db
)

# Configure logging for API operations
logger = logging.getLogger(__name__)

# Create Flask blueprint for API endpoints
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Initialize Flask-RESTX for automatic OpenAPI documentation
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'JWT token format: Bearer <token>'
    }
}

api = Api(
    api_bp,
    version='1.0',
    title='Flask Application API',
    description='RESTful API for Flask application with comprehensive endpoint coverage',
    doc='/docs/',
    authorizations=authorizations,
    security='Bearer',
    prefix='/api'
)

# Create API namespaces for organized endpoint management
auth_ns = api.namespace('auth', description='Authentication operations')
users_ns = api.namespace('users', description='User management operations') 
entities_ns = api.namespace('entities', description='Business entity operations')
admin_ns = api.namespace('admin', description='Administrative operations')


# =============================================================================
# MARSHMALLOW SCHEMAS FOR REQUEST/RESPONSE VALIDATION
# =============================================================================

class BaseResponseSchema(Schema):
    """Base response schema for API contract standardization."""
    
    success = ma_fields.Bool(required=True, description='Operation success status')
    message = ma_fields.Str(required=False, description='Human-readable message')
    timestamp = ma_fields.DateTime(
        required=True, 
        description='Response timestamp in ISO format'
    )
    request_id = ma_fields.Str(required=False, description='Unique request identifier')
    
    @pre_dump
    def add_timestamp(self, data, **kwargs):
        """Add timestamp to response data."""
        if isinstance(data, dict) and 'timestamp' not in data:
            data['timestamp'] = datetime.now(timezone.utc)
        return data


class ErrorResponseSchema(BaseResponseSchema):
    """Error response schema for standardized error handling."""
    
    error_code = ma_fields.Str(required=True, description='Machine-readable error code')
    error_details = ma_fields.Dict(
        required=False, 
        description='Additional error context'
    )


class PaginationSchema(Schema):
    """Pagination parameters schema for list endpoints."""
    
    page = ma_fields.Int(
        required=False, 
        default=1, 
        validate=validate.Range(min=1),
        description='Page number for pagination'
    )
    per_page = ma_fields.Int(
        required=False, 
        default=20, 
        validate=validate.Range(min=1, max=100),
        description='Items per page (max 100)'
    )
    sort_by = ma_fields.Str(
        required=False, 
        default='created_at',
        description='Field name for sorting'
    )
    sort_order = ma_fields.Str(
        required=False, 
        default='desc',
        validate=validate.OneOf(['asc', 'desc']),
        description='Sort order: asc or desc'
    )


class UserCreateSchema(Schema):
    """User creation request schema with comprehensive validation."""
    
    username = ma_fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50),
            validate.Regexp(r'^[a-zA-Z0-9_]+$', error='Username must contain only letters, numbers, and underscores')
        ],
        description='Unique username (3-50 characters, alphanumeric and underscore only)'
    )
    email = ma_fields.Email(
        required=True,
        validate=validate.Length(max=255),
        description='Valid email address'
    )
    password = ma_fields.Str(
        required=True,
        validate=[
            validate.Length(min=8, max=128),
            validate.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                error='Password must contain at least one lowercase letter, uppercase letter, number, and special character'
            )
        ],
        description='Strong password (8-128 characters with mixed case, numbers, and special characters)'
    )
    first_name = ma_fields.Str(
        required=True,
        validate=validate.Length(min=1, max=100),
        description='User first name'
    )
    last_name = ma_fields.Str(
        required=True,
        validate=validate.Length(min=1, max=100),
        description='User last name'
    )
    role = ma_fields.Str(
        required=False,
        default='user',
        validate=validate.OneOf(['user', 'admin', 'moderator']),
        description='User role assignment'
    )
    
    @post_load
    def validate_unique_fields(self, data, **kwargs):
        """Validate username and email uniqueness."""
        user_service = get_service('user')
        
        # Check username uniqueness
        if user_service.check_username_exists(data['username']):
            raise ValidationError('Username already exists', field_name='username')
        
        # Check email uniqueness  
        if user_service.check_email_exists(data['email']):
            raise ValidationError('Email already exists', field_name='email')
        
        return data


class UserUpdateSchema(Schema):
    """User update request schema with optional fields."""
    
    email = ma_fields.Email(
        required=False,
        validate=validate.Length(max=255),
        description='Updated email address'
    )
    first_name = ma_fields.Str(
        required=False,
        validate=validate.Length(min=1, max=100),
        description='Updated first name'
    )
    last_name = ma_fields.Str(
        required=False,
        validate=validate.Length(min=1, max=100),
        description='Updated last name'
    )
    is_active = ma_fields.Bool(
        required=False,
        description='User active status'
    )


class UserResponseSchema(BaseResponseSchema):
    """User response schema for API responses."""
    
    data = ma_fields.Nested('UserDataSchema', required=True)


class UserDataSchema(Schema):
    """User data schema for response serialization."""
    
    id = ma_fields.Int(required=True, description='User unique identifier')
    username = ma_fields.Str(required=True, description='Username')
    email = ma_fields.Str(required=True, description='Email address')
    first_name = ma_fields.Str(required=True, description='First name')
    last_name = ma_fields.Str(required=True, description='Last name')
    role = ma_fields.Str(required=True, description='User role')
    is_active = ma_fields.Bool(required=True, description='Active status')
    created_at = ma_fields.DateTime(required=True, description='Creation timestamp')
    updated_at = ma_fields.DateTime(required=True, description='Last update timestamp')


class AuthLoginSchema(Schema):
    """Authentication login request schema."""
    
    username = ma_fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50),
        description='Username or email'
    )
    password = ma_fields.Str(
        required=True,
        validate=validate.Length(min=1),
        description='User password'
    )
    remember_me = ma_fields.Bool(
        required=False,
        default=False,
        description='Extended session duration'
    )


class AuthResponseSchema(BaseResponseSchema):
    """Authentication response schema."""
    
    data = ma_fields.Nested('AuthDataSchema', required=True)


class AuthDataSchema(Schema):
    """Authentication data schema."""
    
    user_id = ma_fields.Int(required=True, description='Authenticated user ID')
    username = ma_fields.Str(required=True, description='Username')
    access_token = ma_fields.Str(required=True, description='JWT access token')
    token_type = ma_fields.Str(required=True, default='Bearer', description='Token type')
    expires_in = ma_fields.Int(required=True, description='Token expiration in seconds')


class BusinessEntityCreateSchema(Schema):
    """Business entity creation request schema."""
    
    name = ma_fields.Str(
        required=True,
        validate=validate.Length(min=1, max=255),
        description='Entity name'
    )
    entity_type = ma_fields.Str(
        required=True,
        validate=validate.OneOf(['company', 'project', 'department', 'team']),
        description='Entity type classification'
    )
    description = ma_fields.Str(
        required=False,
        validate=validate.Length(max=1000),
        description='Entity description'
    )
    metadata = ma_fields.Dict(
        required=False,
        description='Additional entity metadata'
    )


class BusinessEntityUpdateSchema(Schema):
    """Business entity update request schema."""
    
    name = ma_fields.Str(
        required=False,
        validate=validate.Length(min=1, max=255),
        description='Updated entity name'
    )
    description = ma_fields.Str(
        required=False,
        validate=validate.Length(max=1000),
        description='Updated entity description'
    )
    metadata = ma_fields.Dict(
        required=False,
        description='Updated entity metadata'
    )
    is_active = ma_fields.Bool(
        required=False,
        description='Entity active status'
    )


# =============================================================================
# FLASK-RESTX API MODELS FOR DOCUMENTATION
# =============================================================================

# Request models for OpenAPI documentation
user_create_model = api.model('UserCreate', {
    'username': fields.String(required=True, description='Unique username'),
    'email': fields.String(required=True, description='Valid email address'),
    'password': fields.String(required=True, description='Strong password'),
    'first_name': fields.String(required=True, description='First name'),
    'last_name': fields.String(required=True, description='Last name'),
    'role': fields.String(description='User role', default='user')
})

user_update_model = api.model('UserUpdate', {
    'email': fields.String(description='Updated email address'),
    'first_name': fields.String(description='Updated first name'),
    'last_name': fields.String(description='Updated last name'),
    'is_active': fields.Boolean(description='User active status')
})

auth_login_model = api.model('AuthLogin', {
    'username': fields.String(required=True, description='Username or email'),
    'password': fields.String(required=True, description='Password'),
    'remember_me': fields.Boolean(description='Extended session', default=False)
})

entity_create_model = api.model('EntityCreate', {
    'name': fields.String(required=True, description='Entity name'),
    'entity_type': fields.String(required=True, description='Entity type'),
    'description': fields.String(description='Entity description'),
    'metadata': fields.Raw(description='Entity metadata')
})

# Response models for OpenAPI documentation
user_response_model = api.model('UserResponse', {
    'success': fields.Boolean(required=True),
    'message': fields.String(),
    'timestamp': fields.DateTime(required=True),
    'data': fields.Nested(api.model('UserData', {
        'id': fields.Integer(required=True),
        'username': fields.String(required=True),
        'email': fields.String(required=True),
        'first_name': fields.String(required=True),
        'last_name': fields.String(required=True),
        'role': fields.String(required=True),
        'is_active': fields.Boolean(required=True),
        'created_at': fields.DateTime(required=True),
        'updated_at': fields.DateTime(required=True)
    }))
})

error_response_model = api.model('ErrorResponse', {
    'success': fields.Boolean(required=True, default=False),
    'message': fields.String(required=True),
    'error_code': fields.String(required=True),
    'error_details': fields.Raw(),
    'timestamp': fields.DateTime(required=True)
})


# =============================================================================
# UTILITY FUNCTIONS AND DECORATORS
# =============================================================================

def generate_request_id() -> str:
    """Generate unique request identifier for tracking."""
    import uuid
    return str(uuid.uuid4())


def validate_request_data(schema_class: Schema, location: str = 'json'):
    """
    Decorator for validating request data using Marshmallow schemas.
    
    Args:
        schema_class: Marshmallow schema class for validation
        location: Request data location ('json', 'args', 'form')
    
    Returns:
        Decorator function that validates and injects validated data
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Get request data based on location
                if location == 'json':
                    raw_data = request.get_json(force=True) or {}
                elif location == 'args':
                    raw_data = request.args.to_dict()
                elif location == 'form':
                    raw_data = request.form.to_dict()
                else:
                    raise ValidationError(f"Invalid data location: {location}")
                
                # Validate data using schema
                schema = schema_class()
                validated_data = schema.load(raw_data)
                
                # Inject validated data into request context
                g.validated_data = validated_data
                
                return func(*args, **kwargs)
                
            except ValidationError as e:
                logger.warning(f"Request validation failed: {e.messages}")
                return create_error_response(
                    message="Validation failed",
                    error_code="VALIDATION_ERROR", 
                    details=e.messages,
                    status_code=400
                )
            except Exception as e:
                logger.error(f"Request validation error: {str(e)}")
                return create_error_response(
                    message="Request processing failed",
                    error_code="REQUEST_ERROR",
                    status_code=400
                )
        
        return wrapper
    return decorator


def require_authentication(func):
    """
    Decorator for requiring user authentication on endpoints.
    
    Integrates with Flask-Login patterns and service layer authentication.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            # Get authentication service
            auth_service = get_service('auth')
            
            # Extract authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return create_error_response(
                    message="Authentication required",
                    error_code="AUTHENTICATION_REQUIRED",
                    status_code=401
                )
            
            # Extract and validate token
            token = auth_header.split(' ')[1]
            user_data = auth_service.validate_token(token)
            
            if not user_data:
                return create_error_response(
                    message="Invalid or expired token",
                    error_code="INVALID_TOKEN",
                    status_code=401
                )
            
            # Inject user data into request context
            g.current_user = user_data
            
            return func(*args, **kwargs)
            
        except ServiceException as e:
            logger.error(f"Authentication service error: {str(e)}")
            return create_error_response(
                message="Authentication failed",
                error_code="AUTHENTICATION_ERROR",
                status_code=401
            )
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return create_error_response(
                message="Authentication system error",
                error_code="AUTH_SYSTEM_ERROR",
                status_code=500
            )
    
    return wrapper


def require_admin(func):
    """Decorator for requiring admin role access."""
    @wraps(func)
    @require_authentication
    def wrapper(*args, **kwargs):
        current_user = getattr(g, 'current_user', None)
        
        if not current_user or current_user.get('role') != 'admin':
            return create_error_response(
                message="Administrative privileges required",
                error_code="INSUFFICIENT_PRIVILEGES", 
                status_code=403
            )
        
        return func(*args, **kwargs)
    
    return wrapper


def create_success_response(
    data: Any = None,
    message: str = "Operation successful", 
    status_code: int = 200,
    **kwargs
) -> Tuple[Dict[str, Any], int]:
    """
    Create standardized success response with API contract compliance.
    
    Args:
        data: Response data payload
        message: Human-readable success message
        status_code: HTTP status code
        **kwargs: Additional response fields
    
    Returns:
        Tuple of (response_dict, status_code)
    """
    response_data = {
        'success': True,
        'message': message,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'request_id': generate_request_id(),
        **kwargs
    }
    
    if data is not None:
        response_data['data'] = data
    
    return jsonify(response_data), status_code


def create_error_response(
    message: str,
    error_code: str,
    status_code: int = 400,
    details: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], int]:
    """
    Create standardized error response with comprehensive error details.
    
    Args:
        message: Human-readable error message
        error_code: Machine-readable error code
        status_code: HTTP status code
        details: Additional error context
    
    Returns:
        Tuple of (response_dict, status_code)
    """
    response_data = {
        'success': False,
        'message': message,
        'error_code': error_code,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'request_id': generate_request_id()
    }
    
    if details:
        response_data['error_details'] = details
    
    # Log error for monitoring
    logger.error(
        f"API Error: {error_code} - {message}",
        extra={
            'error_code': error_code,
            'status_code': status_code,
            'details': details,
            'request_id': response_data['request_id']
        }
    )
    
    return jsonify(response_data), status_code


def handle_service_exceptions(func):
    """
    Decorator for handling service layer exceptions with proper error responses.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
            
        except ValidationException as e:
            return create_error_response(
                message=str(e),
                error_code="VALIDATION_ERROR",
                status_code=400,
                details=getattr(e, 'details', None)
            )
        except DatabaseException as e:
            return create_error_response(
                message="Database operation failed",
                error_code="DATABASE_ERROR",
                status_code=500,
                details=getattr(e, 'details', None)
            )
        except ServiceException as e:
            return create_error_response(
                message=str(e),
                error_code=getattr(e, 'error_code', 'SERVICE_ERROR'),
                status_code=getattr(e, 'status_code', 500),
                details=getattr(e, 'details', None)
            )
        except Exception as e:
            logger.exception("Unexpected error in API endpoint")
            return create_error_response(
                message="Internal server error",
                error_code="INTERNAL_ERROR",
                status_code=500
            )
    
    return wrapper


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@auth_ns.route('/login')
class AuthLogin(Resource):
    """User authentication endpoint with JWT token generation."""
    
    @api.doc('authenticate_user')
    @api.expect(auth_login_model, validate=True)
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=400)
    @api.marshal_with(error_response_model, code=401)
    @validate_request_data(AuthLoginSchema)
    @handle_service_exceptions
    def post(self):
        """
        Authenticate user and generate access token.
        
        Validates user credentials and returns JWT access token for authenticated sessions.
        Supports both username and email for authentication with optional remember-me functionality.
        """
        validated_data = g.validated_data
        
        try:
            # Get authentication service
            auth_service = get_service('auth')
            
            # Authenticate user credentials
            auth_result = auth_service.authenticate_user(
                username=validated_data['username'],
                password=validated_data['password'],
                remember_me=validated_data.get('remember_me', False)
            )
            
            if not auth_result.success:
                return create_error_response(
                    message="Invalid credentials",
                    error_code="INVALID_CREDENTIALS",
                    status_code=401
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=auth_result.data['user_id'],
                action='LOGIN',
                details={'ip_address': request.remote_addr}
            )
            
            return create_success_response(
                data=auth_result.data,
                message="Authentication successful"
            )
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise ServiceException(
                message="Authentication system error",
                error_code="AUTH_SYSTEM_ERROR"
            )


@auth_ns.route('/logout')
class AuthLogout(Resource):
    """User logout endpoint with session termination."""
    
    @api.doc('logout_user')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @require_authentication
    @handle_service_exceptions
    def post(self):
        """
        Logout user and invalidate access token.
        
        Terminates user session and invalidates the current access token for security.
        """
        current_user = g.current_user
        
        try:
            # Get authentication service
            auth_service = get_service('auth')
            
            # Logout user and invalidate token
            logout_result = auth_service.logout_user(current_user['user_id'])
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='LOGOUT',
                details={'ip_address': request.remote_addr}
            )
            
            return create_success_response(
                message="Logout successful"
            )
            
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            raise ServiceException(
                message="Logout system error",
                error_code="LOGOUT_ERROR"
            )


@auth_ns.route('/refresh')
class AuthRefresh(Resource):
    """Token refresh endpoint for extending session duration."""
    
    @api.doc('refresh_token')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @require_authentication
    @handle_service_exceptions
    def post(self):
        """
        Refresh user access token.
        
        Generates new access token for authenticated user to extend session duration.
        """
        current_user = g.current_user
        
        try:
            # Get authentication service
            auth_service = get_service('auth')
            
            # Refresh access token
            refresh_result = auth_service.refresh_user_token(current_user['user_id'])
            
            if not refresh_result.success:
                return create_error_response(
                    message="Token refresh failed",
                    error_code="TOKEN_REFRESH_ERROR",
                    status_code=401
                )
            
            return create_success_response(
                data=refresh_result.data,
                message="Token refreshed successfully"
            )
            
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise ServiceException(
                message="Token refresh system error",
                error_code="TOKEN_REFRESH_SYSTEM_ERROR"
            )


# =============================================================================
# USER MANAGEMENT ENDPOINTS
# =============================================================================

@users_ns.route('')
class UsersList(Resource):
    """User list endpoint with pagination and filtering."""
    
    @api.doc('list_users')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=403)
    @validate_request_data(PaginationSchema, location='args')
    @require_authentication
    @handle_service_exceptions
    def get(self):
        """
        Retrieve paginated list of users.
        
        Returns paginated user list with filtering and sorting capabilities.
        Requires authentication and appropriate permissions.
        """
        pagination_params = g.validated_data
        current_user = g.current_user
        
        try:
            # Get user service
            user_service = get_service('user')
            
            # Retrieve users with pagination
            users_result = user_service.get_users_paginated(
                page=pagination_params['page'],
                per_page=pagination_params['per_page'],
                sort_by=pagination_params['sort_by'],
                sort_order=pagination_params['sort_order'],
                requester_id=current_user['user_id']
            )
            
            if not users_result.success:
                return create_error_response(
                    message="Failed to retrieve users",
                    error_code="USER_RETRIEVAL_ERROR",
                    status_code=500
                )
            
            return create_success_response(
                data=users_result.data,
                message="Users retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"User list retrieval failed: {str(e)}")
            raise ServiceException(
                message="User retrieval system error",
                error_code="USER_LIST_ERROR"
            )
    
    @api.doc('create_user')
    @api.expect(user_create_model, validate=True)
    @api.marshal_with(user_response_model, code=201)
    @api.marshal_with(error_response_model, code=400)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=403)
    @validate_request_data(UserCreateSchema)
    @require_admin
    @handle_service_exceptions
    def post(self):
        """
        Create new user account.
        
        Creates new user with comprehensive validation and security checks.
        Requires administrative privileges for execution.
        """
        validated_data = g.validated_data
        current_user = g.current_user
        
        try:
            # Get user service
            user_service = get_service('user')
            
            # Create new user
            create_result = user_service.create_user(
                user_data=validated_data,
                created_by=current_user['user_id']
            )
            
            if not create_result.success:
                return create_error_response(
                    message="User creation failed",
                    error_code="USER_CREATION_ERROR",
                    status_code=400,
                    details=create_result.errors
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='CREATE_USER',
                details={
                    'created_user_id': create_result.data['id'],
                    'username': create_result.data['username']
                }
            )
            
            return create_success_response(
                data=create_result.data,
                message="User created successfully",
                status_code=201
            )
            
        except Exception as e:
            logger.error(f"User creation failed: {str(e)}")
            raise ServiceException(
                message="User creation system error",
                error_code="USER_CREATION_SYSTEM_ERROR"
            )


@users_ns.route('/<int:user_id>')
class UsersDetail(Resource):
    """Individual user management endpoint."""
    
    @api.doc('get_user')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=404)
    @require_authentication
    @handle_service_exceptions
    def get(self, user_id: int):
        """
        Retrieve specific user details.
        
        Returns detailed user information with permission-based field filtering.
        """
        current_user = g.current_user
        
        try:
            # Get user service
            user_service = get_service('user')
            
            # Retrieve user details
            user_result = user_service.get_user_by_id(
                user_id=user_id,
                requester_id=current_user['user_id']
            )
            
            if not user_result.success:
                return create_error_response(
                    message="User not found",
                    error_code="USER_NOT_FOUND",
                    status_code=404
                )
            
            return create_success_response(
                data=user_result.data,
                message="User retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"User retrieval failed: {str(e)}")
            raise ServiceException(
                message="User retrieval system error",
                error_code="USER_RETRIEVAL_SYSTEM_ERROR"
            )
    
    @api.doc('update_user')
    @api.expect(user_update_model, validate=True)
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=400)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=404)
    @validate_request_data(UserUpdateSchema)
    @require_authentication
    @handle_service_exceptions
    def put(self, user_id: int):
        """
        Update user information.
        
        Updates user details with comprehensive validation and permission checks.
        Users can update their own information, admins can update any user.
        """
        validated_data = g.validated_data
        current_user = g.current_user
        
        try:
            # Get user service
            user_service = get_service('user')
            
            # Check permissions for update
            if user_id != current_user['user_id'] and current_user['role'] != 'admin':
                return create_error_response(
                    message="Insufficient privileges to update user",
                    error_code="INSUFFICIENT_PRIVILEGES",
                    status_code=403
                )
            
            # Update user information
            update_result = user_service.update_user(
                user_id=user_id,
                update_data=validated_data,
                updated_by=current_user['user_id']
            )
            
            if not update_result.success:
                return create_error_response(
                    message="User update failed",
                    error_code="USER_UPDATE_ERROR",
                    status_code=400,
                    details=update_result.errors
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='UPDATE_USER',
                details={
                    'updated_user_id': user_id,
                    'updated_fields': list(validated_data.keys())
                }
            )
            
            return create_success_response(
                data=update_result.data,
                message="User updated successfully"
            )
            
        except Exception as e:
            logger.error(f"User update failed: {str(e)}")
            raise ServiceException(
                message="User update system error",
                error_code="USER_UPDATE_SYSTEM_ERROR"
            )
    
    @api.doc('delete_user')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=403)
    @api.marshal_with(error_response_model, code=404)
    @require_admin
    @handle_service_exceptions
    def delete(self, user_id: int):
        """
        Delete user account.
        
        Permanently removes user account with comprehensive cleanup.
        Requires administrative privileges and cannot delete own account.
        """
        current_user = g.current_user
        
        try:
            # Prevent self-deletion
            if user_id == current_user['user_id']:
                return create_error_response(
                    message="Cannot delete own account",
                    error_code="SELF_DELETION_FORBIDDEN",
                    status_code=403
                )
            
            # Get user service
            user_service = get_service('user')
            
            # Delete user account
            delete_result = user_service.delete_user(
                user_id=user_id,
                deleted_by=current_user['user_id']
            )
            
            if not delete_result.success:
                return create_error_response(
                    message="User deletion failed",
                    error_code="USER_DELETION_ERROR",
                    status_code=400,
                    details=delete_result.errors
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='DELETE_USER',
                details={
                    'deleted_user_id': user_id,
                    'username': delete_result.data.get('username')
                }
            )
            
            return create_success_response(
                message="User deleted successfully"
            )
            
        except Exception as e:
            logger.error(f"User deletion failed: {str(e)}")
            raise ServiceException(
                message="User deletion system error",
                error_code="USER_DELETION_SYSTEM_ERROR"
            )


# =============================================================================
# BUSINESS ENTITY ENDPOINTS
# =============================================================================

@entities_ns.route('')
class EntitiesList(Resource):
    """Business entity list endpoint with CRUD operations."""
    
    @api.doc('list_entities')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @validate_request_data(PaginationSchema, location='args')
    @require_authentication
    @handle_service_exceptions
    def get(self):
        """
        Retrieve paginated list of business entities.
        
        Returns filtered and paginated business entity list with permission-based access.
        """
        pagination_params = g.validated_data
        current_user = g.current_user
        
        try:
            # Get entity service
            entity_service = get_service('entity')
            
            # Retrieve entities with pagination
            entities_result = entity_service.get_entities_paginated(
                page=pagination_params['page'],
                per_page=pagination_params['per_page'],
                sort_by=pagination_params['sort_by'],
                sort_order=pagination_params['sort_order'],
                requester_id=current_user['user_id']
            )
            
            if not entities_result.success:
                return create_error_response(
                    message="Failed to retrieve entities",
                    error_code="ENTITY_RETRIEVAL_ERROR",
                    status_code=500
                )
            
            return create_success_response(
                data=entities_result.data,
                message="Entities retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"Entity list retrieval failed: {str(e)}")
            raise ServiceException(
                message="Entity retrieval system error",
                error_code="ENTITY_LIST_ERROR"
            )
    
    @api.doc('create_entity')
    @api.expect(entity_create_model, validate=True)
    @api.marshal_with(user_response_model, code=201)
    @api.marshal_with(error_response_model, code=400)
    @api.marshal_with(error_response_model, code=401)
    @validate_request_data(BusinessEntityCreateSchema)
    @require_authentication
    @handle_service_exceptions
    def post(self):
        """
        Create new business entity.
        
        Creates business entity with comprehensive validation and permission checks.
        """
        validated_data = g.validated_data
        current_user = g.current_user
        
        try:
            # Get entity service
            entity_service = get_service('entity')
            
            # Create new entity
            create_result = entity_service.create_entity(
                entity_data=validated_data,
                created_by=current_user['user_id']
            )
            
            if not create_result.success:
                return create_error_response(
                    message="Entity creation failed",
                    error_code="ENTITY_CREATION_ERROR",
                    status_code=400,
                    details=create_result.errors
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='CREATE_ENTITY',
                details={
                    'entity_id': create_result.data['id'],
                    'entity_name': create_result.data['name'],
                    'entity_type': create_result.data['entity_type']
                }
            )
            
            return create_success_response(
                data=create_result.data,
                message="Entity created successfully",
                status_code=201
            )
            
        except Exception as e:
            logger.error(f"Entity creation failed: {str(e)}")
            raise ServiceException(
                message="Entity creation system error",
                error_code="ENTITY_CREATION_SYSTEM_ERROR"
            )


@entities_ns.route('/<int:entity_id>')
class EntitiesDetail(Resource):
    """Individual business entity management endpoint."""
    
    @api.doc('get_entity')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=404)
    @require_authentication
    @handle_service_exceptions
    def get(self, entity_id: int):
        """Retrieve specific business entity details."""
        current_user = g.current_user
        
        try:
            # Get entity service
            entity_service = get_service('entity')
            
            # Retrieve entity details
            entity_result = entity_service.get_entity_by_id(
                entity_id=entity_id,
                requester_id=current_user['user_id']
            )
            
            if not entity_result.success:
                return create_error_response(
                    message="Entity not found",
                    error_code="ENTITY_NOT_FOUND",
                    status_code=404
                )
            
            return create_success_response(
                data=entity_result.data,
                message="Entity retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"Entity retrieval failed: {str(e)}")
            raise ServiceException(
                message="Entity retrieval system error",
                error_code="ENTITY_RETRIEVAL_SYSTEM_ERROR"
            )
    
    @api.doc('update_entity')
    @api.expect(entity_create_model, validate=True)
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=400)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=404)
    @validate_request_data(BusinessEntityUpdateSchema)
    @require_authentication
    @handle_service_exceptions
    def put(self, entity_id: int):
        """Update business entity information."""
        validated_data = g.validated_data
        current_user = g.current_user
        
        try:
            # Get entity service
            entity_service = get_service('entity')
            
            # Update entity information
            update_result = entity_service.update_entity(
                entity_id=entity_id,
                update_data=validated_data,
                updated_by=current_user['user_id']
            )
            
            if not update_result.success:
                return create_error_response(
                    message="Entity update failed",
                    error_code="ENTITY_UPDATE_ERROR",
                    status_code=400,
                    details=update_result.errors
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='UPDATE_ENTITY',
                details={
                    'entity_id': entity_id,
                    'updated_fields': list(validated_data.keys())
                }
            )
            
            return create_success_response(
                data=update_result.data,
                message="Entity updated successfully"
            )
            
        except Exception as e:
            logger.error(f"Entity update failed: {str(e)}")
            raise ServiceException(
                message="Entity update system error",
                error_code="ENTITY_UPDATE_SYSTEM_ERROR"
            )
    
    @api.doc('delete_entity')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=404)
    @require_authentication
    @handle_service_exceptions
    def delete(self, entity_id: int):
        """Delete business entity."""
        current_user = g.current_user
        
        try:
            # Get entity service
            entity_service = get_service('entity')
            
            # Delete entity
            delete_result = entity_service.delete_entity(
                entity_id=entity_id,
                deleted_by=current_user['user_id']
            )
            
            if not delete_result.success:
                return create_error_response(
                    message="Entity deletion failed",
                    error_code="ENTITY_DELETION_ERROR",
                    status_code=400,
                    details=delete_result.errors
                )
            
            # Create audit log entry
            audit_service = get_service('audit')
            audit_service.log_user_action(
                user_id=current_user['user_id'],
                action='DELETE_ENTITY',
                details={
                    'entity_id': entity_id,
                    'entity_name': delete_result.data.get('name')
                }
            )
            
            return create_success_response(
                message="Entity deleted successfully"
            )
            
        except Exception as e:
            logger.error(f"Entity deletion failed: {str(e)}")
            raise ServiceException(
                message="Entity deletion system error",
                error_code="ENTITY_DELETION_SYSTEM_ERROR"
            )


# =============================================================================
# ADMINISTRATIVE ENDPOINTS
# =============================================================================

@admin_ns.route('/system/status')
class SystemStatus(Resource):
    """System status endpoint for administrative monitoring."""
    
    @api.doc('get_system_status')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=403)
    @require_admin
    @handle_service_exceptions
    def get(self):
        """
        Retrieve comprehensive system status information.
        
        Returns detailed system health, performance metrics, and operational status.
        Requires administrative privileges for access.
        """
        try:
            # Get system monitoring service
            system_service = get_service('system')
            
            # Retrieve comprehensive system status
            status_result = system_service.get_system_status()
            
            if not status_result.success:
                return create_error_response(
                    message="Failed to retrieve system status",
                    error_code="SYSTEM_STATUS_ERROR",
                    status_code=500
                )
            
            return create_success_response(
                data=status_result.data,
                message="System status retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"System status retrieval failed: {str(e)}")
            raise ServiceException(
                message="System status retrieval error",
                error_code="SYSTEM_STATUS_SYSTEM_ERROR"
            )


@admin_ns.route('/audit/logs')
class AuditLogs(Resource):
    """Audit log management endpoint."""
    
    @api.doc('get_audit_logs')
    @api.marshal_with(user_response_model, code=200)
    @api.marshal_with(error_response_model, code=401)
    @api.marshal_with(error_response_model, code=403)
    @validate_request_data(PaginationSchema, location='args')
    @require_admin
    @handle_service_exceptions
    def get(self):
        """
        Retrieve paginated audit log entries.
        
        Returns filtered audit trail with comprehensive search and filtering capabilities.
        """
        pagination_params = g.validated_data
        current_user = g.current_user
        
        try:
            # Get audit service
            audit_service = get_service('audit')
            
            # Retrieve audit logs with pagination
            logs_result = audit_service.get_audit_logs_paginated(
                page=pagination_params['page'],
                per_page=pagination_params['per_page'],
                sort_by=pagination_params['sort_by'],
                sort_order=pagination_params['sort_order'],
                requester_id=current_user['user_id']
            )
            
            if not logs_result.success:
                return create_error_response(
                    message="Failed to retrieve audit logs",
                    error_code="AUDIT_LOGS_ERROR",
                    status_code=500
                )
            
            return create_success_response(
                data=logs_result.data,
                message="Audit logs retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"Audit logs retrieval failed: {str(e)}")
            raise ServiceException(
                message="Audit logs retrieval error",
                error_code="AUDIT_LOGS_SYSTEM_ERROR"
            )


# =============================================================================
# ERROR HANDLERS
# =============================================================================

@api_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle 400 Bad Request errors."""
    return create_error_response(
        message="Bad request - invalid request format or parameters",
        error_code="BAD_REQUEST",
        status_code=400
    )


@api_bp.errorhandler(401)
def handle_unauthorized(error):
    """Handle 401 Unauthorized errors."""
    return create_error_response(
        message="Authentication required",
        error_code="UNAUTHORIZED",
        status_code=401
    )


@api_bp.errorhandler(403)
def handle_forbidden(error):
    """Handle 403 Forbidden errors."""
    return create_error_response(
        message="Insufficient privileges for requested operation",
        error_code="FORBIDDEN",
        status_code=403
    )


@api_bp.errorhandler(404)
def handle_not_found(error):
    """Handle 404 Not Found errors."""
    return create_error_response(
        message="Requested resource not found",
        error_code="NOT_FOUND",
        status_code=404
    )


@api_bp.errorhandler(422)
def handle_unprocessable_entity(error):
    """Handle 422 Unprocessable Entity errors."""
    return create_error_response(
        message="Request validation failed",
        error_code="VALIDATION_ERROR",
        status_code=422
    )


@api_bp.errorhandler(500)
def handle_internal_server_error(error):
    """Handle 500 Internal Server Error."""
    logger.exception("Internal server error in API blueprint")
    return create_error_response(
        message="Internal server error",
        error_code="INTERNAL_ERROR",
        status_code=500
    )


# =============================================================================
# REQUEST/RESPONSE HOOKS
# =============================================================================

@api_bp.before_request
def before_request():
    """
    Execute before each API request for logging and validation.
    """
    # Log API request for monitoring
    logger.info(
        f"API Request: {request.method} {request.path}",
        extra={
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'content_length': request.content_length
        }
    )
    
    # Initialize request context variables
    g.request_start_time = datetime.now(timezone.utc)


@api_bp.after_request
def after_request(response):
    """
    Execute after each API request for cleanup and logging.
    """
    # Calculate request processing time
    if hasattr(g, 'request_start_time'):
        processing_time = (
            datetime.now(timezone.utc) - g.request_start_time
        ).total_seconds() * 1000  # Convert to milliseconds
        
        # Log API response for monitoring
        logger.info(
            f"API Response: {response.status_code} - {processing_time:.2f}ms",
            extra={
                'status_code': response.status_code,
                'processing_time_ms': processing_time,
                'content_length': response.content_length
            }
        )
    
    # Add CORS headers for cross-origin requests
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response


@api_bp.teardown_request
def teardown_request(exception=None):
    """
    Clean up resources after request completion.
    """
    if exception:
        logger.error(f"Request teardown with exception: {str(exception)}")
        
        # Rollback database session on error
        try:
            db.session.rollback()
        except Exception as e:
            logger.error(f"Database rollback failed: {str(e)}")


# =============================================================================
# BLUEPRINT REGISTRATION FUNCTION
# =============================================================================

def register_api_blueprint(app):
    """
    Register API blueprint with Flask application.
    
    This function should be called from the Flask application factory to
    register the API blueprint with proper configuration and error handling.
    
    Args:
        app: Flask application instance
    """
    try:
        # Register the API blueprint
        app.register_blueprint(api_bp)
        
        logger.info("API blueprint registered successfully")
        
    except Exception as e:
        logger.error(f"Failed to register API blueprint: {str(e)}")
        raise


# Export blueprint for application registration
__all__ = ['api_bp', 'register_api_blueprint']


# Log successful module initialization
logger.info("Flask API blueprint module initialized successfully")