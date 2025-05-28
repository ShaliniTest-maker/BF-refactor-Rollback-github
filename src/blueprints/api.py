"""
Primary API endpoint blueprint implementing RESTful route definitions with Flask @blueprint.route decorators.

This module converts Express.js API handlers to Flask blueprint architecture, handling all core API 
endpoints with systematic request/response processing while maintaining identical API contracts from 
the Node.js implementation. Leverages Flask's modular blueprint organization with comprehensive 
schema validation and structured endpoint definitions.

Architecture Components:
- Flask blueprint with @blueprint.route decorators for organized route management
- Flask-RESTful Resource classes for standardized HTTP method handling  
- Marshmallow schema validation for robust request data validation
- Flask request context system for request parsing and response generation
- Before/after request handlers replacing Express middleware functionality
- Comprehensive error handling with standardized error responses

Features Implemented:
- F-001: API Endpoint Conversion - Complete Express.js to Flask route migration
- F-002: Request/Response Handling Migration - Flask request context implementation
- Identical API contract preservation for seamless client application compatibility
"""

from flask import Blueprint, request, jsonify, current_app
from flask_restful import Api, Resource
from marshmallow import Schema, fields, ValidationError, pre_load, post_dump
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized, Forbidden, InternalServerError
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

# Import service layer for business logic orchestration
from ..services.user_service import UserService
from ..services.business_entity_service import BusinessEntityService
from ..services.validation_service import ValidationService
from ..services.workflow_orchestrator import WorkflowOrchestrator

# Import models for data access and type hints
from ..models.user import User
from ..models.business_entity import BusinessEntity
from ..models.entity_relationship import EntityRelationship

# Import authentication decorators for security enforcement
from ..auth.decorators import require_auth, require_permission, require_role

# Configure logging for API request tracking
logger = logging.getLogger(__name__)

# Create API blueprint with URL prefix for organized route management
api_blueprint = Blueprint('api', __name__, url_prefix='/api/v1')
api = Api(api_blueprint)


# ============================================================================
# MARSHMALLOW SCHEMA DEFINITIONS
# ============================================================================

class UserSchema(Schema):
    """User entity schema for request/response validation and serialization."""
    
    id = fields.Integer(dump_only=True)
    username = fields.String(required=True, validate=lambda x: len(x) >= 3)
    email = fields.Email(required=True)
    password = fields.String(required=True, load_only=True, validate=lambda x: len(x) >= 8)
    is_active = fields.Boolean(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    
    @pre_load
    def validate_user_data(self, data, **kwargs):
        """Pre-processing validation for user data."""
        # Convert email to lowercase for consistency
        if 'email' in data:
            data['email'] = data['email'].lower().strip()
        return data
    
    @post_dump
    def format_timestamps(self, data, **kwargs):
        """Format timestamps for consistent API response."""
        if 'created_at' in data and data['created_at']:
            data['created_at'] = data['created_at'].isoformat()
        if 'updated_at' in data and data['updated_at']:
            data['updated_at'] = data['updated_at'].isoformat()
        return data


class BusinessEntitySchema(Schema):
    """Business entity schema for request/response validation and serialization."""
    
    id = fields.Integer(dump_only=True)
    name = fields.String(required=True, validate=lambda x: len(x) >= 2)
    description = fields.String(allow_none=True)
    status = fields.String(required=True, validate=lambda x: x in ['active', 'inactive', 'pending'])
    user_id = fields.Integer(required=True)
    metadata = fields.Raw(allow_none=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    
    @pre_load
    def validate_entity_data(self, data, **kwargs):
        """Pre-processing validation for business entity data."""
        # Ensure metadata is a valid dictionary if provided
        if 'metadata' in data and data['metadata'] is not None:
            if not isinstance(data['metadata'], dict):
                raise ValidationError('Metadata must be a valid JSON object')
        return data


class EntityRelationshipSchema(Schema):
    """Entity relationship schema for request/response validation and serialization."""
    
    id = fields.Integer(dump_only=True)
    source_entity_id = fields.Integer(required=True)
    target_entity_id = fields.Integer(required=True)
    relationship_type = fields.String(required=True)
    is_active = fields.Boolean(missing=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    
    @pre_load
    def validate_relationship_data(self, data, **kwargs):
        """Pre-processing validation for relationship data."""
        # Ensure source and target are different entities
        if data.get('source_entity_id') == data.get('target_entity_id'):
            raise ValidationError('Source and target entities cannot be the same')
        return data


# Initialize schema instances for reuse
user_schema = UserSchema()
users_schema = UserSchema(many=True)
business_entity_schema = BusinessEntitySchema()
business_entities_schema = BusinessEntitySchema(many=True)
entity_relationship_schema = EntityRelationshipSchema()
entity_relationships_schema = EntityRelationshipSchema(many=True)


# ============================================================================
# BLUEPRINT REQUEST/RESPONSE HANDLERS
# ============================================================================

@api_blueprint.before_request
def before_request_handler():
    """
    Before request handler replacing Express middleware functionality.
    
    Implements comprehensive request preprocessing including:
    - Request validation and sanitization
    - Content-type verification
    - Rate limiting preparation
    - Security headers validation
    """
    logger.info(f"API Request: {request.method} {request.path}")
    
    # Validate content-type for POST/PUT/PATCH requests
    if request.method in ['POST', 'PUT', 'PATCH']:
        if not request.is_json:
            logger.warning(f"Invalid content-type for {request.method} request")
            return jsonify({
                'error': 'Content-Type must be application/json',
                'status_code': 400,
                'timestamp': datetime.utcnow().isoformat()
            }), 400
    
    # Log request details for monitoring
    if hasattr(request, 'get_json') and request.is_json:
        logger.debug(f"Request data keys: {list(request.get_json().keys()) if request.get_json() else []}")


@api_blueprint.after_request
def after_request_handler(response):
    """
    After request handler for response processing and cleanup.
    
    Implements comprehensive response post-processing including:
    - Security headers addition
    - Response logging
    - Performance metrics collection
    - CORS headers management
    """
    logger.info(f"API Response: {response.status_code} for {request.method} {request.path}")
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Add CORS headers for API access
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    
    return response


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@api_blueprint.errorhandler(ValidationError)
def handle_validation_error(error):
    """Handle marshmallow validation errors with standardized response format."""
    logger.warning(f"Validation error: {error.messages}")
    return jsonify({
        'error': 'Validation failed',
        'details': error.messages,
        'status_code': 400,
        'timestamp': datetime.utcnow().isoformat()
    }), 400


@api_blueprint.errorhandler(BadRequest)
def handle_bad_request(error):
    """Handle bad request errors with standardized response format."""
    logger.warning(f"Bad request: {error.description}")
    return jsonify({
        'error': 'Bad request',
        'message': error.description,
        'status_code': 400,
        'timestamp': datetime.utcnow().isoformat()
    }), 400


@api_blueprint.errorhandler(NotFound)
def handle_not_found(error):
    """Handle not found errors with standardized response format."""
    logger.warning(f"Resource not found: {request.path}")
    return jsonify({
        'error': 'Resource not found',
        'message': 'The requested resource could not be found',
        'status_code': 404,
        'timestamp': datetime.utcnow().isoformat()
    }), 404


@api_blueprint.errorhandler(Unauthorized)
def handle_unauthorized(error):
    """Handle unauthorized access errors with standardized response format."""
    logger.warning(f"Unauthorized access attempt: {request.path}")
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required',
        'status_code': 401,
        'timestamp': datetime.utcnow().isoformat()
    }), 401


@api_blueprint.errorhandler(Forbidden)
def handle_forbidden(error):
    """Handle forbidden access errors with standardized response format."""
    logger.warning(f"Forbidden access attempt: {request.path}")
    return jsonify({
        'error': 'Forbidden',
        'message': 'Insufficient permissions',
        'status_code': 403,
        'timestamp': datetime.utcnow().isoformat()
    }), 403


@api_blueprint.errorhandler(InternalServerError)
def handle_internal_error(error):
    """Handle internal server errors with standardized response format."""
    logger.error(f"Internal server error: {error.description}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'status_code': 500,
        'timestamp': datetime.utcnow().isoformat()
    }), 500


# ============================================================================
# USER MANAGEMENT API ENDPOINTS
# ============================================================================

class UserListResource(Resource):
    """
    User collection resource implementing RESTful user management operations.
    
    Endpoints:
    - GET /api/v1/users - List all users with pagination
    - POST /api/v1/users - Create new user account
    """
    
    @require_auth
    @require_permission('users:read')
    def get(self):
        """
        Retrieve paginated list of users with filtering and sorting capabilities.
        
        Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - sort: Sort field (default: created_at)
        - order: Sort order (asc/desc, default: desc)
        - status: Filter by user status
        
        Returns:
            JSON response with user list and pagination metadata
        """
        try:
            # Extract query parameters with defaults
            page = request.args.get('page', 1, type=int)
            per_page = min(request.args.get('per_page', 20, type=int), 100)
            sort_field = request.args.get('sort', 'created_at')
            sort_order = request.args.get('order', 'desc')
            status_filter = request.args.get('status')
            
            # Initialize user service for business logic orchestration
            user_service = UserService()
            
            # Execute paginated user retrieval through service layer
            result = user_service.get_users_paginated(
                page=page,
                per_page=per_page,
                sort_field=sort_field,
                sort_order=sort_order,
                status_filter=status_filter
            )
            
            # Serialize users using marshmallow schema
            serialized_users = users_schema.dump(result['users'])
            
            return jsonify({
                'users': serialized_users,
                'pagination': {
                    'page': result['page'],
                    'per_page': result['per_page'],
                    'total': result['total'],
                    'pages': result['pages'],
                    'has_next': result['has_next'],
                    'has_prev': result['has_prev']
                },
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error retrieving users: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve users',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('users:create')
    def post(self):
        """
        Create new user account with comprehensive validation.
        
        Request Body:
        - username: Unique username (required, min 3 chars)
        - email: Valid email address (required, unique)
        - password: Strong password (required, min 8 chars)
        
        Returns:
            JSON response with created user data (excluding password)
        """
        try:
            # Validate and deserialize request data
            user_data = user_schema.load(request.get_json())
            
            # Initialize user service for business logic orchestration
            user_service = UserService()
            
            # Execute user creation through service layer
            new_user = user_service.create_user(user_data)
            
            # Serialize created user for response
            serialized_user = user_schema.dump(new_user)
            
            logger.info(f"Created new user: {new_user.username}")
            
            return jsonify({
                'user': serialized_user,
                'message': 'User created successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 201
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return jsonify({
                'error': 'Failed to create user',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


class UserResource(Resource):
    """
    Individual user resource implementing RESTful user operations.
    
    Endpoints:
    - GET /api/v1/users/<int:user_id> - Retrieve specific user
    - PUT /api/v1/users/<int:user_id> - Update user (full replacement)
    - PATCH /api/v1/users/<int:user_id> - Update user (partial)
    - DELETE /api/v1/users/<int:user_id> - Delete user account
    """
    
    @require_auth
    @require_permission('users:read')
    def get(self, user_id: int):
        """
        Retrieve specific user by ID with relationship data.
        
        Args:
            user_id: Unique user identifier
            
        Returns:
            JSON response with user data and associated entities
        """
        try:
            # Initialize user service for business logic orchestration
            user_service = UserService()
            
            # Retrieve user through service layer
            user = user_service.get_user_by_id(user_id)
            
            if not user:
                return jsonify({
                    'error': 'User not found',
                    'message': f'User with ID {user_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize user data
            serialized_user = user_schema.dump(user)
            
            # Include related business entities if requested
            include_entities = request.args.get('include_entities', 'false').lower() == 'true'
            if include_entities:
                business_entity_service = BusinessEntityService()
                entities = business_entity_service.get_entities_by_user_id(user_id)
                serialized_user['business_entities'] = business_entities_schema.dump(entities)
            
            return jsonify({
                'user': serialized_user,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error retrieving user {user_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve user',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('users:update')
    def put(self, user_id: int):
        """
        Update user with full data replacement.
        
        Args:
            user_id: Unique user identifier
            
        Request Body:
        - All user fields for complete replacement
        
        Returns:
            JSON response with updated user data
        """
        try:
            # Validate and deserialize request data
            user_data = user_schema.load(request.get_json())
            
            # Initialize user service for business logic orchestration
            user_service = UserService()
            
            # Execute user update through service layer
            updated_user = user_service.update_user(user_id, user_data, partial=False)
            
            if not updated_user:
                return jsonify({
                    'error': 'User not found',
                    'message': f'User with ID {user_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize updated user for response
            serialized_user = user_schema.dump(updated_user)
            
            logger.info(f"Updated user: {updated_user.username}")
            
            return jsonify({
                'user': serialized_user,
                'message': 'User updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to update user',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('users:update')
    def patch(self, user_id: int):
        """
        Update user with partial data modification.
        
        Args:
            user_id: Unique user identifier
            
        Request Body:
        - Partial user fields for selective update
        
        Returns:
            JSON response with updated user data
        """
        try:
            # Validate and deserialize partial request data
            user_data = user_schema.load(request.get_json(), partial=True)
            
            # Initialize user service for business logic orchestration
            user_service = UserService()
            
            # Execute partial user update through service layer
            updated_user = user_service.update_user(user_id, user_data, partial=True)
            
            if not updated_user:
                return jsonify({
                    'error': 'User not found',
                    'message': f'User with ID {user_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize updated user for response
            serialized_user = user_schema.dump(updated_user)
            
            logger.info(f"Partially updated user: {updated_user.username}")
            
            return jsonify({
                'user': serialized_user,
                'message': 'User updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error partially updating user {user_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to update user',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('users:delete')
    def delete(self, user_id: int):
        """
        Delete user account with cascade relationship handling.
        
        Args:
            user_id: Unique user identifier
            
        Returns:
            JSON response confirming deletion
        """
        try:
            # Initialize user service for business logic orchestration
            user_service = UserService()
            
            # Execute user deletion through service layer
            success = user_service.delete_user(user_id)
            
            if not success:
                return jsonify({
                    'error': 'User not found',
                    'message': f'User with ID {user_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            logger.info(f"Deleted user with ID: {user_id}")
            
            return jsonify({
                'message': 'User deleted successfully',
                'user_id': user_id,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to delete user',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


# ============================================================================
# BUSINESS ENTITY MANAGEMENT API ENDPOINTS
# ============================================================================

class BusinessEntityListResource(Resource):
    """
    Business entity collection resource implementing RESTful entity management operations.
    
    Endpoints:
    - GET /api/v1/entities - List all business entities with filtering
    - POST /api/v1/entities - Create new business entity
    """
    
    @require_auth
    @require_permission('entities:read')
    def get(self):
        """
        Retrieve paginated list of business entities with filtering capabilities.
        
        Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - user_id: Filter by entity owner
        - status: Filter by entity status
        - sort: Sort field (default: created_at)
        - order: Sort order (asc/desc, default: desc)
        
        Returns:
            JSON response with entity list and pagination metadata
        """
        try:
            # Extract query parameters with defaults
            page = request.args.get('page', 1, type=int)
            per_page = min(request.args.get('per_page', 20, type=int), 100)
            user_id_filter = request.args.get('user_id', type=int)
            status_filter = request.args.get('status')
            sort_field = request.args.get('sort', 'created_at')
            sort_order = request.args.get('order', 'desc')
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute paginated entity retrieval through service layer
            result = entity_service.get_entities_paginated(
                page=page,
                per_page=per_page,
                user_id_filter=user_id_filter,
                status_filter=status_filter,
                sort_field=sort_field,
                sort_order=sort_order
            )
            
            # Serialize entities using marshmallow schema
            serialized_entities = business_entities_schema.dump(result['entities'])
            
            return jsonify({
                'entities': serialized_entities,
                'pagination': {
                    'page': result['page'],
                    'per_page': result['per_page'],
                    'total': result['total'],
                    'pages': result['pages'],
                    'has_next': result['has_next'],
                    'has_prev': result['has_prev']
                },
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error retrieving business entities: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve business entities',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('entities:create')
    def post(self):
        """
        Create new business entity with ownership assignment.
        
        Request Body:
        - name: Entity name (required, min 2 chars)
        - description: Entity description (optional)
        - status: Entity status (required: active/inactive/pending)
        - user_id: Owner user ID (required)
        - metadata: Additional entity metadata (optional JSON object)
        
        Returns:
            JSON response with created entity data
        """
        try:
            # Validate and deserialize request data
            entity_data = business_entity_schema.load(request.get_json())
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute entity creation through service layer
            new_entity = entity_service.create_entity(entity_data)
            
            # Serialize created entity for response
            serialized_entity = business_entity_schema.dump(new_entity)
            
            logger.info(f"Created new business entity: {new_entity.name}")
            
            return jsonify({
                'entity': serialized_entity,
                'message': 'Business entity created successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 201
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error creating business entity: {str(e)}")
            return jsonify({
                'error': 'Failed to create business entity',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


class BusinessEntityResource(Resource):
    """
    Individual business entity resource implementing RESTful entity operations.
    
    Endpoints:
    - GET /api/v1/entities/<int:entity_id> - Retrieve specific entity
    - PUT /api/v1/entities/<int:entity_id> - Update entity (full replacement)
    - PATCH /api/v1/entities/<int:entity_id> - Update entity (partial)
    - DELETE /api/v1/entities/<int:entity_id> - Delete entity
    """
    
    @require_auth
    @require_permission('entities:read')
    def get(self, entity_id: int):
        """
        Retrieve specific business entity by ID with relationship data.
        
        Args:
            entity_id: Unique entity identifier
            
        Returns:
            JSON response with entity data and relationships
        """
        try:
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Retrieve entity through service layer
            entity = entity_service.get_entity_by_id(entity_id)
            
            if not entity:
                return jsonify({
                    'error': 'Business entity not found',
                    'message': f'Entity with ID {entity_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize entity data
            serialized_entity = business_entity_schema.dump(entity)
            
            # Include relationships if requested
            include_relationships = request.args.get('include_relationships', 'false').lower() == 'true'
            if include_relationships:
                relationships = entity_service.get_entity_relationships(entity_id)
                serialized_entity['relationships'] = entity_relationships_schema.dump(relationships)
            
            return jsonify({
                'entity': serialized_entity,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error retrieving business entity {entity_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve business entity',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('entities:update')
    def put(self, entity_id: int):
        """
        Update business entity with full data replacement.
        
        Args:
            entity_id: Unique entity identifier
            
        Request Body:
        - All entity fields for complete replacement
        
        Returns:
            JSON response with updated entity data
        """
        try:
            # Validate and deserialize request data
            entity_data = business_entity_schema.load(request.get_json())
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute entity update through service layer
            updated_entity = entity_service.update_entity(entity_id, entity_data, partial=False)
            
            if not updated_entity:
                return jsonify({
                    'error': 'Business entity not found',
                    'message': f'Entity with ID {entity_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize updated entity for response
            serialized_entity = business_entity_schema.dump(updated_entity)
            
            logger.info(f"Updated business entity: {updated_entity.name}")
            
            return jsonify({
                'entity': serialized_entity,
                'message': 'Business entity updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error updating business entity {entity_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to update business entity',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('entities:update') 
    def patch(self, entity_id: int):
        """
        Update business entity with partial data modification.
        
        Args:
            entity_id: Unique entity identifier
            
        Request Body:
        - Partial entity fields for selective update
        
        Returns:
            JSON response with updated entity data
        """
        try:
            # Validate and deserialize partial request data
            entity_data = business_entity_schema.load(request.get_json(), partial=True)
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute partial entity update through service layer
            updated_entity = entity_service.update_entity(entity_id, entity_data, partial=True)
            
            if not updated_entity:
                return jsonify({
                    'error': 'Business entity not found',
                    'message': f'Entity with ID {entity_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize updated entity for response
            serialized_entity = business_entity_schema.dump(updated_entity)
            
            logger.info(f"Partially updated business entity: {updated_entity.name}")
            
            return jsonify({
                'entity': serialized_entity,
                'message': 'Business entity updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error partially updating business entity {entity_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to update business entity',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('entities:delete')
    def delete(self, entity_id: int):
        """
        Delete business entity with cascade relationship handling.
        
        Args:
            entity_id: Unique entity identifier
            
        Returns:
            JSON response confirming deletion
        """
        try:
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute entity deletion through service layer
            success = entity_service.delete_entity(entity_id)
            
            if not success:
                return jsonify({
                    'error': 'Business entity not found',
                    'message': f'Entity with ID {entity_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            logger.info(f"Deleted business entity with ID: {entity_id}")
            
            return jsonify({
                'message': 'Business entity deleted successfully',
                'entity_id': entity_id,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error deleting business entity {entity_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to delete business entity',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


# ============================================================================
# ENTITY RELATIONSHIP MANAGEMENT API ENDPOINTS
# ============================================================================

class EntityRelationshipListResource(Resource):
    """
    Entity relationship collection resource implementing RESTful relationship management.
    
    Endpoints:
    - GET /api/v1/relationships - List entity relationships with filtering
    - POST /api/v1/relationships - Create new entity relationship
    """
    
    @require_auth
    @require_permission('relationships:read')
    def get(self):
        """
        Retrieve paginated list of entity relationships with filtering capabilities.
        
        Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - source_entity_id: Filter by source entity
        - target_entity_id: Filter by target entity
        - relationship_type: Filter by relationship type
        - is_active: Filter by active status
        - sort: Sort field (default: created_at)
        - order: Sort order (asc/desc, default: desc)
        
        Returns:
            JSON response with relationship list and pagination metadata
        """
        try:
            # Extract query parameters with defaults
            page = request.args.get('page', 1, type=int)
            per_page = min(request.args.get('per_page', 20, type=int), 100)
            source_entity_id = request.args.get('source_entity_id', type=int)
            target_entity_id = request.args.get('target_entity_id', type=int)
            relationship_type = request.args.get('relationship_type')
            is_active = request.args.get('is_active')
            sort_field = request.args.get('sort', 'created_at')
            sort_order = request.args.get('order', 'desc')
            
            # Convert is_active parameter to boolean if provided
            if is_active is not None:
                is_active = is_active.lower() in ['true', '1', 'yes']
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute paginated relationship retrieval through service layer
            result = entity_service.get_relationships_paginated(
                page=page,
                per_page=per_page,
                source_entity_id=source_entity_id,
                target_entity_id=target_entity_id,
                relationship_type=relationship_type,
                is_active=is_active,
                sort_field=sort_field,
                sort_order=sort_order
            )
            
            # Serialize relationships using marshmallow schema
            serialized_relationships = entity_relationships_schema.dump(result['relationships'])
            
            return jsonify({
                'relationships': serialized_relationships,
                'pagination': {
                    'page': result['page'],
                    'per_page': result['per_page'],
                    'total': result['total'],
                    'pages': result['pages'],
                    'has_next': result['has_next'],
                    'has_prev': result['has_prev']
                },
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error retrieving entity relationships: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve entity relationships',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('relationships:create')
    def post(self):
        """
        Create new entity relationship with validation.
        
        Request Body:
        - source_entity_id: Source entity ID (required)
        - target_entity_id: Target entity ID (required, must be different from source)
        - relationship_type: Type of relationship (required)
        - is_active: Active status (optional, default: true)
        
        Returns:
            JSON response with created relationship data
        """
        try:
            # Validate and deserialize request data
            relationship_data = entity_relationship_schema.load(request.get_json())
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute relationship creation through service layer
            new_relationship = entity_service.create_relationship(relationship_data)
            
            # Serialize created relationship for response
            serialized_relationship = entity_relationship_schema.dump(new_relationship)
            
            logger.info(f"Created new entity relationship: {new_relationship.relationship_type}")
            
            return jsonify({
                'relationship': serialized_relationship,
                'message': 'Entity relationship created successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 201
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error creating entity relationship: {str(e)}")
            return jsonify({
                'error': 'Failed to create entity relationship',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


class EntityRelationshipResource(Resource):
    """
    Individual entity relationship resource implementing RESTful relationship operations.
    
    Endpoints:
    - GET /api/v1/relationships/<int:relationship_id> - Retrieve specific relationship
    - PUT /api/v1/relationships/<int:relationship_id> - Update relationship (full)
    - PATCH /api/v1/relationships/<int:relationship_id> - Update relationship (partial)
    - DELETE /api/v1/relationships/<int:relationship_id> - Delete relationship
    """
    
    @require_auth
    @require_permission('relationships:read')
    def get(self, relationship_id: int):
        """
        Retrieve specific entity relationship by ID with entity data.
        
        Args:
            relationship_id: Unique relationship identifier
            
        Returns:
            JSON response with relationship data and related entities
        """
        try:
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Retrieve relationship through service layer
            relationship = entity_service.get_relationship_by_id(relationship_id)
            
            if not relationship:
                return jsonify({
                    'error': 'Entity relationship not found',
                    'message': f'Relationship with ID {relationship_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize relationship data
            serialized_relationship = entity_relationship_schema.dump(relationship)
            
            # Include entity details if requested
            include_entities = request.args.get('include_entities', 'false').lower() == 'true'
            if include_entities:
                source_entity = entity_service.get_entity_by_id(relationship.source_entity_id)
                target_entity = entity_service.get_entity_by_id(relationship.target_entity_id)
                
                if source_entity:
                    serialized_relationship['source_entity'] = business_entity_schema.dump(source_entity)
                if target_entity:
                    serialized_relationship['target_entity'] = business_entity_schema.dump(target_entity)
            
            return jsonify({
                'relationship': serialized_relationship,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error retrieving entity relationship {relationship_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to retrieve entity relationship',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('relationships:update')
    def put(self, relationship_id: int):
        """
        Update entity relationship with full data replacement.
        
        Args:
            relationship_id: Unique relationship identifier
            
        Request Body:
        - All relationship fields for complete replacement
        
        Returns:
            JSON response with updated relationship data
        """
        try:
            # Validate and deserialize request data
            relationship_data = entity_relationship_schema.load(request.get_json())
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute relationship update through service layer
            updated_relationship = entity_service.update_relationship(relationship_id, relationship_data, partial=False)
            
            if not updated_relationship:
                return jsonify({
                    'error': 'Entity relationship not found',
                    'message': f'Relationship with ID {relationship_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize updated relationship for response
            serialized_relationship = entity_relationship_schema.dump(updated_relationship)
            
            logger.info(f"Updated entity relationship: {updated_relationship.relationship_type}")
            
            return jsonify({
                'relationship': serialized_relationship,
                'message': 'Entity relationship updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error updating entity relationship {relationship_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to update entity relationship',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('relationships:update')
    def patch(self, relationship_id: int):
        """
        Update entity relationship with partial data modification.
        
        Args:
            relationship_id: Unique relationship identifier
            
        Request Body:
        - Partial relationship fields for selective update
        
        Returns:
            JSON response with updated relationship data
        """
        try:
            # Validate and deserialize partial request data
            relationship_data = entity_relationship_schema.load(request.get_json(), partial=True)
            
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute partial relationship update through service layer
            updated_relationship = entity_service.update_relationship(relationship_id, relationship_data, partial=True)
            
            if not updated_relationship:
                return jsonify({
                    'error': 'Entity relationship not found',
                    'message': f'Relationship with ID {relationship_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            # Serialize updated relationship for response
            serialized_relationship = entity_relationship_schema.dump(updated_relationship)
            
            logger.info(f"Partially updated entity relationship: {updated_relationship.relationship_type}")
            
            return jsonify({
                'relationship': serialized_relationship,
                'message': 'Entity relationship updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error partially updating entity relationship {relationship_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to update entity relationship',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500
    
    @require_auth
    @require_permission('relationships:delete')
    def delete(self, relationship_id: int):
        """
        Delete entity relationship.
        
        Args:
            relationship_id: Unique relationship identifier
            
        Returns:
            JSON response confirming deletion
        """
        try:
            # Initialize business entity service for orchestration
            entity_service = BusinessEntityService()
            
            # Execute relationship deletion through service layer
            success = entity_service.delete_relationship(relationship_id)
            
            if not success:
                return jsonify({
                    'error': 'Entity relationship not found',
                    'message': f'Relationship with ID {relationship_id} does not exist',
                    'status_code': 404,
                    'timestamp': datetime.utcnow().isoformat()
                }), 404
            
            logger.info(f"Deleted entity relationship with ID: {relationship_id}")
            
            return jsonify({
                'message': 'Entity relationship deleted successfully',
                'relationship_id': relationship_id,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Error deleting entity relationship {relationship_id}: {str(e)}")
            return jsonify({
                'error': 'Failed to delete entity relationship',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


# ============================================================================
# WORKFLOW AND ADVANCED OPERATIONS API ENDPOINTS
# ============================================================================

class WorkflowResource(Resource):
    """
    Workflow orchestration resource implementing complex business operations.
    
    Endpoints:
    - POST /api/v1/workflows/execute - Execute business workflow
    - GET /api/v1/workflows/status/<workflow_id> - Get workflow status
    """
    
    @require_auth
    @require_permission('workflows:execute')
    def post(self):
        """
        Execute complex business workflow through orchestrator.
        
        Request Body:
        - workflow_type: Type of workflow to execute (required)
        - parameters: Workflow-specific parameters (required)
        - async_execution: Whether to execute asynchronously (optional, default: false)
        
        Returns:
            JSON response with workflow execution result or status
        """
        try:
            request_data = request.get_json()
            
            if not request_data or 'workflow_type' not in request_data:
                return jsonify({
                    'error': 'Invalid request',
                    'message': 'workflow_type is required',
                    'status_code': 400,
                    'timestamp': datetime.utcnow().isoformat()
                }), 400
            
            workflow_type = request_data.get('workflow_type')
            parameters = request_data.get('parameters', {})
            async_execution = request_data.get('async_execution', False)
            
            # Initialize workflow orchestrator for complex operations
            orchestrator = WorkflowOrchestrator()
            
            # Execute workflow through orchestrator service layer
            if async_execution:
                # Start asynchronous workflow execution
                workflow_id = orchestrator.start_async_workflow(workflow_type, parameters)
                
                return jsonify({
                    'workflow_id': workflow_id,
                    'status': 'started',
                    'message': 'Workflow execution started',
                    'async': True,
                    'timestamp': datetime.utcnow().isoformat()
                }), 202
            else:
                # Execute synchronous workflow
                result = orchestrator.execute_workflow(workflow_type, parameters)
                
                return jsonify({
                    'result': result,
                    'status': 'completed',
                    'message': 'Workflow executed successfully',
                    'async': False,
                    'timestamp': datetime.utcnow().isoformat()
                }), 200
            
        except ValidationError as e:
            # Marshmallow validation errors handled by error handler
            raise e
            
        except Exception as e:
            logger.error(f"Error executing workflow: {str(e)}")
            return jsonify({
                'error': 'Failed to execute workflow',
                'message': str(e),
                'status_code': 500,
                'timestamp': datetime.utcnow().isoformat()
            }), 500


class HealthCheckResource(Resource):
    """
    Health check resource for system monitoring and status verification.
    
    Endpoints:
    - GET /api/v1/health - System health check
    - GET /api/v1/health/detailed - Detailed system status
    """
    
    def get(self):
        """
        Basic health check endpoint for load balancer and monitoring systems.
        
        Returns:
            JSON response with system health status
        """
        try:
            # Basic health check without authentication requirement
            return jsonify({
                'status': 'healthy',
                'service': 'flask-api',
                'version': '1.0.0',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 503


# ============================================================================
# FLASK-RESTFUL RESOURCE REGISTRATION
# ============================================================================

# User management endpoints
api.add_resource(UserListResource, '/users')
api.add_resource(UserResource, '/users/<int:user_id>')

# Business entity management endpoints
api.add_resource(BusinessEntityListResource, '/entities')
api.add_resource(BusinessEntityResource, '/entities/<int:entity_id>')

# Entity relationship management endpoints
api.add_resource(EntityRelationshipListResource, '/relationships')
api.add_resource(EntityRelationshipResource, '/relationships/<int:relationship_id>')

# Workflow and advanced operations endpoints
api.add_resource(WorkflowResource, '/workflows/execute')

# Health check and monitoring endpoints
api.add_resource(HealthCheckResource, '/health')


# ============================================================================
# ADDITIONAL BLUEPRINT ROUTES (NON-RESTFUL)
# ============================================================================

@api_blueprint.route('/status', methods=['GET'])
def api_status():
    """
    API status endpoint providing comprehensive system information.
    
    Returns:
        JSON response with detailed API status and metrics
    """
    try:
        # Collect system metrics and status information
        status_info = {
            'api_version': '1.0.0',
            'flask_version': '3.1.1',
            'status': 'operational',
            'uptime': 'calculated_at_runtime',  # Would be calculated in production
            'endpoints': {
                'users': '/api/v1/users',
                'entities': '/api/v1/entities', 
                'relationships': '/api/v1/relationships',
                'workflows': '/api/v1/workflows',
                'health': '/api/v1/health'
            },
            'features': {
                'authentication': 'enabled',
                'authorization': 'enabled',
                'validation': 'enabled',
                'pagination': 'enabled',
                'filtering': 'enabled',
                'relationships': 'enabled'
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(status_info), 200
        
    except Exception as e:
        logger.error(f"Error retrieving API status: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve API status',
            'message': str(e),
            'status_code': 500,
            'timestamp': datetime.utcnow().isoformat()
        }), 500


@api_blueprint.route('/schema/<schema_name>', methods=['GET'])
@require_auth
def get_schema_definition(schema_name: str):
    """
    Retrieve marshmallow schema definition for API documentation.
    
    Args:
        schema_name: Name of the schema to retrieve
        
    Returns:
        JSON response with schema definition
    """
    try:
        schemas = {
            'user': user_schema,
            'business_entity': business_entity_schema,
            'entity_relationship': entity_relationship_schema
        }
        
        if schema_name not in schemas:
            return jsonify({
                'error': 'Schema not found',
                'message': f'Schema "{schema_name}" does not exist',
                'available_schemas': list(schemas.keys()),
                'status_code': 404,
                'timestamp': datetime.utcnow().isoformat()
            }), 404
        
        schema = schemas[schema_name]
        
        # Extract schema field definitions
        schema_definition = {
            'schema_name': schema_name,
            'fields': {},
            'required_fields': [],
            'optional_fields': []
        }
        
        for field_name, field_obj in schema.fields.items():
            field_info = {
                'type': field_obj.__class__.__name__,
                'required': field_obj.required,
                'allow_none': field_obj.allow_none,
                'dump_only': field_obj.dump_only,
                'load_only': field_obj.load_only
            }
            
            schema_definition['fields'][field_name] = field_info
            
            if field_obj.required:
                schema_definition['required_fields'].append(field_name)
            else:
                schema_definition['optional_fields'].append(field_name)
        
        return jsonify({
            'schema': schema_definition,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving schema definition for {schema_name}: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve schema definition',
            'message': str(e),
            'status_code': 500,
            'timestamp': datetime.utcnow().isoformat()
        }), 500


# ============================================================================
# BLUEPRINT EXPORT
# ============================================================================

# Export the blueprint for registration in the Flask application factory
__all__ = ['api_blueprint']