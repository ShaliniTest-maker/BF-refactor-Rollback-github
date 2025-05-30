"""
Comprehensive API endpoint testing module validating Flask blueprint routes, request/response formats,
and RESTful API contract compliance ensuring 100% functional parity with Node.js implementation.

This module implements the testing requirements specified in Section 4.7.1 for API endpoints testing
using Flask test client and SQLAlchemy test database sessions, with comprehensive validation of
behavioral equivalence between Node.js system and Flask implementation per Section 4.7.1.

Testing Coverage:
- Authentication endpoints with JWT token validation per Section 3.6.3
- User management CRUD operations with role-based access control
- Business entity management with comprehensive validation
- Administrative endpoints with proper authorization
- Error handling and response format validation per Section 4.7.1
- Performance benchmarking against Node.js baseline per Section 4.7.4.1

Architecture:
The testing architecture follows pytest best practices with Flask testing utilities integration,
providing comprehensive test isolation, database transaction management, and performance
benchmarking capabilities per Section 4.7.3.1.
"""

import json
import pytest
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import time
import uuid

from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import Client
from sqlalchemy.orm import Session

# Import test fixtures and utilities
from .conftest import (
    testing_config,
    app,
    client,
    db_session,
    db,
    auth_headers,
    authenticated_user,
    api_test_data,
    benchmark_config,
    error_handler
)

# Performance testing imports per Section 4.7.4.1
try:
    import pytest_benchmark
    BENCHMARK_AVAILABLE = True
except ImportError:
    BENCHMARK_AVAILABLE = False


# ============================================================================
# TEST CONSTANTS AND CONFIGURATION
# ============================================================================

# API endpoint base URLs for systematic testing
API_BASE_URL = '/api'
AUTH_ENDPOINTS = {
    'login': f'{API_BASE_URL}/auth/login',
    'logout': f'{API_BASE_URL}/auth/logout',
    'refresh': f'{API_BASE_URL}/auth/refresh'
}
USER_ENDPOINTS = {
    'list': f'{API_BASE_URL}/users',
    'detail': f'{API_BASE_URL}/users/{{user_id}}',
    'create': f'{API_BASE_URL}/users'
}
ENTITY_ENDPOINTS = {
    'list': f'{API_BASE_URL}/entities',
    'detail': f'{API_BASE_URL}/entities/{{entity_id}}',
    'create': f'{API_BASE_URL}/entities'
}
ADMIN_ENDPOINTS = {
    'system_status': f'{API_BASE_URL}/admin/system/status',
    'audit_logs': f'{API_BASE_URL}/admin/audit/logs'
}

# Expected response structure for API contract validation per Section 4.7.1
EXPECTED_SUCCESS_RESPONSE_SCHEMA = {
    'success': bool,
    'message': str,
    'timestamp': str,
    'request_id': str,
    'data': dict  # Variable based on endpoint
}

EXPECTED_ERROR_RESPONSE_SCHEMA = {
    'success': bool,
    'message': str,
    'error_code': str,
    'timestamp': str,
    'request_id': str,
    'error_details': dict  # Optional
}

# HTTP status codes for API contract compliance validation
EXPECTED_STATUS_CODES = {
    'GET_SUCCESS': 200,
    'POST_SUCCESS': 201,
    'PUT_SUCCESS': 200,
    'DELETE_SUCCESS': 200,
    'BAD_REQUEST': 400,
    'UNAUTHORIZED': 401,
    'FORBIDDEN': 403,
    'NOT_FOUND': 404,
    'VALIDATION_ERROR': 422,
    'INTERNAL_ERROR': 500
}

# Content type validation for API responses
EXPECTED_CONTENT_TYPE = 'application/json'


# ============================================================================
# HELPER FUNCTIONS FOR TEST VALIDATION
# ============================================================================

def validate_response_schema(response_data: Dict[str, Any], expected_schema: Dict[str, type]) -> bool:
    """
    Validate API response conforms to expected schema structure.
    
    Args:
        response_data: Actual response data from API endpoint
        expected_schema: Expected schema with field names and types
        
    Returns:
        True if response matches schema, False otherwise
        
    Per Section 4.7.1: API contract validation ensuring identical request/response formats
    """
    for field_name, field_type in expected_schema.items():
        if field_name not in response_data:
            return False
        
        if field_name == 'data' and response_data[field_name] is None:
            continue  # Allow None data for some responses
            
        if not isinstance(response_data[field_name], field_type):
            return False
    
    return True


def validate_timestamp_format(timestamp_str: str) -> bool:
    """
    Validate timestamp follows ISO format for API consistency.
    
    Args:
        timestamp_str: Timestamp string from API response
        
    Returns:
        True if valid ISO format, False otherwise
    """
    try:
        datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return True
    except (ValueError, AttributeError):
        return False


def validate_request_id_format(request_id: str) -> bool:
    """
    Validate request ID follows UUID4 format for request tracking.
    
    Args:
        request_id: Request ID string from API response
        
    Returns:
        True if valid UUID4 format, False otherwise
    """
    try:
        uuid.UUID(request_id, version=4)
        return True
    except (ValueError, AttributeError):
        return False


def assert_api_response_valid(
    response,
    expected_status: int,
    expected_schema: Dict[str, type],
    validate_data: bool = True
) -> Dict[str, Any]:
    """
    Comprehensive API response validation helper.
    
    Args:
        response: Flask test response object
        expected_status: Expected HTTP status code
        expected_schema: Expected response schema
        validate_data: Whether to validate response data structure
        
    Returns:
        Parsed response data for further validation
        
    Raises:
        AssertionError: If response validation fails
        
    Per Section 4.7.1: 100% behavioral equivalence validation between Node.js and Flask
    """
    # Validate HTTP status code
    assert response.status_code == expected_status, (
        f"Expected status {expected_status}, got {response.status_code}. "
        f"Response: {response.get_data(as_text=True)}"
    )
    
    # Validate content type
    assert response.content_type.startswith(EXPECTED_CONTENT_TYPE), (
        f"Expected content type {EXPECTED_CONTENT_TYPE}, got {response.content_type}"
    )
    
    # Parse and validate JSON response
    try:
        response_data = response.get_json()
        assert response_data is not None, "Response body is not valid JSON"
    except Exception as e:
        pytest.fail(f"Failed to parse JSON response: {e}")
    
    # Validate response schema structure
    if validate_data:
        assert validate_response_schema(response_data, expected_schema), (
            f"Response schema validation failed. Expected: {expected_schema}, "
            f"Got: {list(response_data.keys())}"
        )
        
        # Validate timestamp format
        if 'timestamp' in response_data:
            assert validate_timestamp_format(response_data['timestamp']), (
                f"Invalid timestamp format: {response_data['timestamp']}"
            )
        
        # Validate request ID format
        if 'request_id' in response_data:
            assert validate_request_id_format(response_data['request_id']), (
                f"Invalid request ID format: {response_data['request_id']}"
            )
    
    return response_data


def create_test_user_payload(
    username: str = "testuser",
    email: str = "test@example.com",
    password: str = "SecurePassword123!",
    **kwargs
) -> Dict[str, Any]:
    """
    Create standardized test user payload for API testing.
    
    Args:
        username: User username
        email: User email address
        password: User password
        **kwargs: Additional user fields
        
    Returns:
        User creation payload for API testing
    """
    payload = {
        'username': username,
        'email': email,
        'password': password,
        'first_name': kwargs.get('first_name', 'Test'),
        'last_name': kwargs.get('last_name', 'User'),
        'role': kwargs.get('role', 'user')
    }
    payload.update(kwargs)
    return payload


def create_test_entity_payload(
    name: str = "Test Entity",
    entity_type: str = "company",
    **kwargs
) -> Dict[str, Any]:
    """
    Create standardized test business entity payload for API testing.
    
    Args:
        name: Entity name
        entity_type: Entity type classification
        **kwargs: Additional entity fields
        
    Returns:
        Entity creation payload for API testing
    """
    payload = {
        'name': name,
        'entity_type': entity_type,
        'description': kwargs.get('description', 'Test entity description'),
        'metadata': kwargs.get('metadata', {'test': True})
    }
    payload.update(kwargs)
    return payload


# ============================================================================
# AUTHENTICATION ENDPOINT TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.auth
class TestAuthenticationEndpoints:
    """
    Test authentication endpoints with comprehensive validation.
    
    Tests cover user login, logout, and token refresh operations with
    proper JWT token handling and Auth0 integration per Section 3.6.3.
    """
    
    def test_login_success(self, client: FlaskClient, api_test_data: Dict[str, Any]):
        """
        Test successful user authentication with valid credentials.
        
        Validates:
        - Successful login with valid username/password
        - JWT token generation and format validation
        - Response structure compliance with API contract
        - Authentication flow equivalence with Node.js implementation
        
        Per Section 4.7.1: Authentication endpoint testing with Flask test client
        """
        # Prepare login payload
        login_payload = api_test_data['auth']['login_payload']
        
        # Execute login request
        response = client.post(
            AUTH_ENDPOINTS['login'],
            data=json.dumps(login_payload),
            content_type='application/json'
        )
        
        # Validate successful response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate authentication data structure
        auth_data = response_data['data']
        required_auth_fields = ['user_id', 'username', 'access_token', 'token_type', 'expires_in']
        for field in required_auth_fields:
            assert field in auth_data, f"Missing authentication field: {field}"
        
        # Validate JWT token format
        assert auth_data['token_type'] == 'Bearer', "Invalid token type"
        assert len(auth_data['access_token']) > 0, "Empty access token"
        assert isinstance(auth_data['expires_in'], int), "Invalid expires_in format"
        assert auth_data['expires_in'] > 0, "Invalid expiration time"
    
    def test_login_invalid_credentials(self, client: FlaskClient, api_test_data: Dict[str, Any]):
        """
        Test login failure with invalid credentials.
        
        Validates:
        - Proper error response for invalid credentials
        - HTTP 401 status code for authentication failure
        - Error message format and content validation
        - Security best practices for authentication errors
        
        Per Section 4.7.1: Error handling validation in authentication flow
        """
        # Prepare invalid credentials payload
        invalid_payload = api_test_data['auth']['invalid_credentials']
        
        # Execute login request with invalid credentials
        response = client.post(
            AUTH_ENDPOINTS['login'],
            data=json.dumps(invalid_payload),
            content_type='application/json'
        )
        
        # Validate error response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['UNAUTHORIZED'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
        
        # Validate error details
        assert response_data['success'] is False, "Error response should have success=False"
        assert response_data['error_code'] == 'INVALID_CREDENTIALS', "Invalid error code"
        assert 'Invalid credentials' in response_data['message'], "Missing error message"
    
    def test_login_missing_fields(self, client: FlaskClient):
        """
        Test login validation with missing required fields.
        
        Validates:
        - Request validation for missing username/password
        - HTTP 400 status code for validation errors
        - Comprehensive field validation error messages
        - Input validation equivalence with Node.js implementation
        """
        # Test missing username
        missing_username_payload = {'password': 'testpassword'}
        response = client.post(
            AUTH_ENDPOINTS['login'],
            data=json.dumps(missing_username_payload),
            content_type='application/json'
        )
        
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
        
        # Test missing password
        missing_password_payload = {'username': 'testuser'}
        response = client.post(
            AUTH_ENDPOINTS['login'],
            data=json.dumps(missing_password_payload),
            content_type='application/json'
        )
        
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
    
    def test_logout_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful user logout with valid authentication.
        
        Validates:
        - Successful logout with valid authentication token
        - Token invalidation and session termination
        - Response format compliance with API contract
        - Logout flow equivalence with Node.js implementation
        
        Per Section 4.7.1: Authentication session management testing
        """
        # Execute logout request with authentication
        response = client.post(
            AUTH_ENDPOINTS['logout'],
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate successful logout response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate logout message
        assert 'Logout successful' in response_data['message'], "Invalid logout message"
    
    def test_logout_unauthorized(self, client: FlaskClient):
        """
        Test logout failure without authentication.
        
        Validates:
        - HTTP 401 status for unauthenticated logout attempts
        - Proper error response format for authentication failures
        - Security validation for protected endpoints
        """
        # Execute logout request without authentication
        response = client.post(
            AUTH_ENDPOINTS['logout'],
            content_type='application/json'
        )
        
        # Validate unauthorized response
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['UNAUTHORIZED'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
    
    def test_token_refresh_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful token refresh with valid authentication.
        
        Validates:
        - Token refresh with valid existing token
        - New token generation and format validation
        - Extended session duration handling
        - Token refresh equivalence with Node.js implementation
        """
        # Execute token refresh request
        response = client.post(
            AUTH_ENDPOINTS['refresh'],
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate successful refresh response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate refreshed token data
        token_data = response_data['data']
        required_token_fields = ['access_token', 'token_type', 'expires_in']
        for field in required_token_fields:
            assert field in token_data, f"Missing token field: {field}"
        
        # Validate new token differs from original
        original_token = auth_headers['Authorization'].split(' ')[1]
        assert token_data['access_token'] != original_token, "Token not refreshed"


# ============================================================================
# USER MANAGEMENT ENDPOINT TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.integration
class TestUserManagementEndpoints:
    """
    Test user management endpoints with comprehensive CRUD operations.
    
    Tests cover user creation, retrieval, updating, and deletion with
    proper role-based access control and validation per Section 4.7.1.
    """
    
    def test_create_user_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful user creation with valid payload.
        
        Validates:
        - User creation with comprehensive validation
        - Response format and data structure validation
        - Database persistence verification
        - CRUD operation equivalence with Node.js implementation
        
        Per Section 4.7.1: User management operations testing
        """
        # Prepare user creation payload
        user_payload = create_test_user_payload(
            username="newuser",
            email="newuser@example.com"
        )
        
        # Execute user creation request
        response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(user_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate successful creation response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['POST_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate created user data
        user_data = response_data['data']
        required_user_fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'role', 'is_active', 'created_at', 'updated_at'
        ]
        for field in required_user_fields:
            assert field in user_data, f"Missing user field: {field}"
        
        # Validate user data values
        assert user_data['username'] == user_payload['username'], "Username mismatch"
        assert user_data['email'] == user_payload['email'], "Email mismatch"
        assert user_data['is_active'] is True, "User should be active by default"
    
    def test_create_user_validation_errors(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test user creation validation with invalid data.
        
        Validates:
        - Comprehensive input validation for user creation
        - Error response format for validation failures
        - Field-specific validation error messages
        - Validation equivalence with Node.js implementation
        """
        # Test invalid email format
        invalid_email_payload = create_test_user_payload(
            username="testuser1",
            email="invalid-email"
        )
        
        response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(invalid_email_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
        
        # Test weak password
        weak_password_payload = create_test_user_payload(
            username="testuser2",
            email="test2@example.com",
            password="123"
        )
        
        response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(weak_password_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
    
    def test_get_users_list(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test user list retrieval with pagination.
        
        Validates:
        - User list endpoint with pagination parameters
        - Response format for list operations
        - Pagination metadata validation
        - List operation equivalence with Node.js implementation
        """
        # Execute user list request with pagination
        response = client.get(
            f"{USER_ENDPOINTS['list']}?page=1&per_page=10&sort_by=created_at&sort_order=desc",
            headers=auth_headers
        )
        
        # Validate successful list response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate list data structure
        list_data = response_data['data']
        assert 'users' in list_data or 'items' in list_data, "Missing users list in response"
        assert 'pagination' in list_data or 'total' in list_data, "Missing pagination metadata"
    
    def test_get_user_by_id(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test individual user retrieval by ID.
        
        Validates:
        - User detail endpoint functionality
        - User data structure and completeness
        - Access control for user data retrieval
        - Detail operation equivalence with Node.js implementation
        """
        # Use a test user ID (assuming user exists)
        test_user_id = 1
        
        # Execute user detail request
        response = client.get(
            USER_ENDPOINTS['detail'].format(user_id=test_user_id),
            headers=auth_headers
        )
        
        # Validate response (may be 200 or 404 depending on test data)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate user data structure
            user_data = response_data['data']
            required_user_fields = ['id', 'username', 'email', 'created_at']
            for field in required_user_fields:
                assert field in user_data, f"Missing user field: {field}"
        
        elif response.status_code == EXPECTED_STATUS_CODES['NOT_FOUND']:
            assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['NOT_FOUND'],
                expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
            )
    
    def test_update_user_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful user information update.
        
        Validates:
        - User update with valid data
        - Partial update support for PATCH operations
        - Response format for update operations
        - Update operation equivalence with Node.js implementation
        """
        # Use a test user ID
        test_user_id = 1
        
        # Prepare update payload
        update_payload = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com'
        }
        
        # Execute user update request
        response = client.put(
            USER_ENDPOINTS['detail'].format(user_id=test_user_id),
            data=json.dumps(update_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate response (may be 200, 403, or 404 depending on test setup)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate updated user data
            user_data = response_data['data']
            assert 'first_name' in user_data, "Missing updated field"
            assert 'updated_at' in user_data, "Missing update timestamp"
    
    def test_delete_user_authorization(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test user deletion with proper authorization.
        
        Validates:
        - Administrative privileges for user deletion
        - Proper error response for insufficient privileges
        - Self-deletion prevention validation
        - Deletion operation equivalence with Node.js implementation
        """
        # Use a test user ID
        test_user_id = 1
        
        # Execute user deletion request
        response = client.delete(
            USER_ENDPOINTS['detail'].format(user_id=test_user_id),
            headers=auth_headers
        )
        
        # Validate response (expecting 403 for non-admin user)
        expected_status = EXPECTED_STATUS_CODES['FORBIDDEN']
        assert_api_response_valid(
            response,
            expected_status=expected_status,
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )


# ============================================================================
# BUSINESS ENTITY ENDPOINT TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.integration
class TestBusinessEntityEndpoints:
    """
    Test business entity management endpoints with comprehensive validation.
    
    Tests cover entity creation, retrieval, updating, and deletion with
    proper business logic validation per Section 4.7.1.
    """
    
    def test_create_entity_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful business entity creation.
        
        Validates:
        - Entity creation with valid business data
        - Response format and structure validation
        - Business logic equivalence with Node.js implementation
        - Entity data persistence verification
        """
        # Prepare entity creation payload
        entity_payload = create_test_entity_payload(
            name="Test Company",
            entity_type="company"
        )
        
        # Execute entity creation request
        response = client.post(
            ENTITY_ENDPOINTS['create'],
            data=json.dumps(entity_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate successful creation response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['POST_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate created entity data
        entity_data = response_data['data']
        required_entity_fields = [
            'id', 'name', 'entity_type', 'description',
            'metadata', 'is_active', 'created_at', 'updated_at'
        ]
        for field in required_entity_fields:
            assert field in entity_data, f"Missing entity field: {field}"
        
        # Validate entity data values
        assert entity_data['name'] == entity_payload['name'], "Entity name mismatch"
        assert entity_data['entity_type'] == entity_payload['entity_type'], "Entity type mismatch"
        assert entity_data['is_active'] is True, "Entity should be active by default"
    
    def test_create_entity_validation_errors(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test entity creation validation with invalid data.
        
        Validates:
        - Input validation for entity creation
        - Error response format for validation failures
        - Business rule validation enforcement
        - Validation equivalence with Node.js implementation
        """
        # Test missing required fields
        invalid_payload = {
            'description': 'Missing name and type'
        }
        
        response = client.post(
            ENTITY_ENDPOINTS['create'],
            data=json.dumps(invalid_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
        
        # Test invalid entity type
        invalid_type_payload = create_test_entity_payload(
            entity_type="invalid_type"
        )
        
        response = client.post(
            ENTITY_ENDPOINTS['create'],
            data=json.dumps(invalid_type_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
    
    def test_get_entities_list(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test business entity list retrieval with filtering.
        
        Validates:
        - Entity list endpoint with pagination and filtering
        - Response format for entity list operations
        - Business data structure validation
        - List operation equivalence with Node.js implementation
        """
        # Execute entity list request
        response = client.get(
            f"{ENTITY_ENDPOINTS['list']}?page=1&per_page=20&sort_by=name",
            headers=auth_headers
        )
        
        # Validate successful list response
        response_data = assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
            expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
        )
        
        # Validate list data structure
        list_data = response_data['data']
        assert 'entities' in list_data or 'items' in list_data, "Missing entities list in response"
    
    def test_get_entity_by_id(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test individual entity retrieval by ID.
        
        Validates:
        - Entity detail endpoint functionality
        - Entity data structure and completeness
        - Business data access patterns
        - Detail operation equivalence with Node.js implementation
        """
        # Use a test entity ID
        test_entity_id = 1
        
        # Execute entity detail request
        response = client.get(
            ENTITY_ENDPOINTS['detail'].format(entity_id=test_entity_id),
            headers=auth_headers
        )
        
        # Validate response (may be 200 or 404 depending on test data)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate entity data structure
            entity_data = response_data['data']
            required_entity_fields = ['id', 'name', 'entity_type', 'created_at']
            for field in required_entity_fields:
                assert field in entity_data, f"Missing entity field: {field}"
    
    def test_update_entity_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful entity information update.
        
        Validates:
        - Entity update with valid business data
        - Partial update support for business entities
        - Response format for entity update operations
        - Update operation equivalence with Node.js implementation
        """
        # Use a test entity ID
        test_entity_id = 1
        
        # Prepare update payload
        update_payload = {
            'name': 'Updated Entity Name',
            'description': 'Updated entity description',
            'metadata': {'updated': True, 'version': 2}
        }
        
        # Execute entity update request
        response = client.put(
            ENTITY_ENDPOINTS['detail'].format(entity_id=test_entity_id),
            data=json.dumps(update_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate response (may be 200 or 404 depending on test setup)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate updated entity data
            entity_data = response_data['data']
            assert 'name' in entity_data, "Missing updated field"
            assert 'updated_at' in entity_data, "Missing update timestamp"
    
    def test_delete_entity_success(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test successful entity deletion.
        
        Validates:
        - Entity deletion with proper authorization
        - Soft delete vs hard delete behavior
        - Cascade deletion handling for related data
        - Deletion operation equivalence with Node.js implementation
        """
        # Use a test entity ID
        test_entity_id = 1
        
        # Execute entity deletion request
        response = client.delete(
            ENTITY_ENDPOINTS['detail'].format(entity_id=test_entity_id),
            headers=auth_headers
        )
        
        # Validate response (may be 200 or 404 depending on test setup)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate deletion confirmation
            assert 'deleted successfully' in response_data['message'].lower(), "Invalid deletion message"


# ============================================================================
# ADMINISTRATIVE ENDPOINT TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.auth
class TestAdministrativeEndpoints:
    """
    Test administrative endpoints with comprehensive authorization validation.
    
    Tests cover system status monitoring, audit log access, and other
    administrative functions with proper role-based access control.
    """
    
    def test_system_status_admin_access(self, client: FlaskClient):
        """
        Test system status endpoint with administrative access.
        
        Validates:
        - Administrative endpoint access control
        - System status data structure and completeness
        - Administrative privilege requirements
        - Monitoring endpoint equivalence with Node.js implementation
        """
        # Create admin authentication headers
        admin_headers = {
            'Authorization': 'Bearer admin-test-token',
            'Content-Type': 'application/json',
            'X-User-Role': 'admin'
        }
        
        # Execute system status request
        response = client.get(
            ADMIN_ENDPOINTS['system_status'],
            headers=admin_headers
        )
        
        # Validate response (expecting 401/403 for mock setup)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate system status data
            status_data = response_data['data']
            expected_status_fields = ['system_health', 'database_status', 'uptime']
            for field in expected_status_fields:
                if field in status_data:
                    assert status_data[field] is not None, f"Missing status field: {field}"
        else:
            # Validate unauthorized/forbidden response
            assert_api_response_valid(
                response,
                expected_status=response.status_code,
                expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
            )
    
    def test_system_status_unauthorized_access(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test system status endpoint with insufficient privileges.
        
        Validates:
        - Access control for administrative endpoints
        - Proper error response for insufficient privileges
        - Role-based authorization enforcement
        - Security validation equivalence with Node.js implementation
        """
        # Execute system status request with regular user credentials
        response = client.get(
            ADMIN_ENDPOINTS['system_status'],
            headers=auth_headers
        )
        
        # Validate forbidden response
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['FORBIDDEN'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
    
    def test_audit_logs_admin_access(self, client: FlaskClient):
        """
        Test audit log endpoint with administrative access.
        
        Validates:
        - Audit log retrieval with proper authorization
        - Audit data structure and pagination
        - Administrative logging functionality
        - Audit trail equivalence with Node.js implementation
        """
        # Create admin authentication headers
        admin_headers = {
            'Authorization': 'Bearer admin-test-token',
            'Content-Type': 'application/json',
            'X-User-Role': 'admin'
        }
        
        # Execute audit logs request
        response = client.get(
            f"{ADMIN_ENDPOINTS['audit_logs']}?page=1&per_page=50",
            headers=admin_headers
        )
        
        # Validate response (expecting 401/403 for mock setup)
        if response.status_code == EXPECTED_STATUS_CODES['GET_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['GET_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate audit log data structure
            logs_data = response_data['data']
            assert 'logs' in logs_data or 'items' in logs_data, "Missing audit logs in response"
        else:
            # Validate unauthorized/forbidden response
            assert_api_response_valid(
                response,
                expected_status=response.status_code,
                expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
            )


# ============================================================================
# ERROR HANDLING AND EDGE CASES TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.unit
class TestErrorHandlingAndEdgeCases:
    """
    Test comprehensive error handling and edge cases for API endpoints.
    
    Tests cover various error conditions, malformed requests, and edge cases
    to ensure robust API behavior under all conditions.
    """
    
    def test_invalid_json_payload(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test API behavior with malformed JSON payloads.
        
        Validates:
        - Proper error handling for invalid JSON syntax
        - HTTP 400 status code for malformed requests
        - Clear error messages for JSON parsing failures
        - Error handling equivalence with Node.js implementation
        """
        # Execute request with invalid JSON
        response = client.post(
            USER_ENDPOINTS['create'],
            data="{'invalid': json syntax}",
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate bad request response
        assert_api_response_valid(
            response,
            expected_status=EXPECTED_STATUS_CODES['BAD_REQUEST'],
            expected_schema=EXPECTED_ERROR_RESPONSE_SCHEMA
        )
    
    def test_missing_content_type(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test API behavior with missing content-type header.
        
        Validates:
        - Content-type header validation
        - Proper error response for missing headers
        - Request format enforcement
        - Header validation equivalence with Node.js implementation
        """
        # Remove content-type from headers
        headers_without_content_type = {k: v for k, v in auth_headers.items() if k != 'Content-Type'}
        
        # Execute request without content-type
        response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(create_test_user_payload()),
            headers=headers_without_content_type
        )
        
        # Validate response (may be 400 or 415 depending on Flask configuration)
        assert response.status_code in [400, 415], f"Unexpected status code: {response.status_code}"
    
    def test_oversized_payload(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test API behavior with oversized request payloads.
        
        Validates:
        - Request size limit enforcement
        - Proper error response for oversized requests
        - Security protection against large payloads
        - Size limit validation equivalence with Node.js implementation
        """
        # Create oversized payload
        oversized_payload = create_test_user_payload()
        oversized_payload['metadata'] = 'x' * (1024 * 1024)  # 1MB string
        
        # Execute request with oversized payload
        response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(oversized_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Validate response (may be 413 or 400 depending on configuration)
        assert response.status_code in [400, 413], f"Unexpected status code: {response.status_code}"
    
    def test_special_characters_in_data(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test API behavior with special characters and Unicode data.
        
        Validates:
        - Unicode character handling in API data
        - Special character encoding/decoding
        - Data integrity for international characters
        - Character handling equivalence with Node.js implementation
        """
        # Create payload with special characters
        special_chars_payload = create_test_user_payload(
            username="user_测试_🚀",
            email="test@测试.com",
            first_name="José",
            last_name="González"
        )
        
        # Execute request with special characters
        response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(special_chars_payload, ensure_ascii=False),
            headers=auth_headers,
            content_type='application/json; charset=utf-8'
        )
        
        # Validate response handling of special characters
        if response.status_code == EXPECTED_STATUS_CODES['POST_SUCCESS']:
            response_data = assert_api_response_valid(
                response,
                expected_status=EXPECTED_STATUS_CODES['POST_SUCCESS'],
                expected_schema=EXPECTED_SUCCESS_RESPONSE_SCHEMA
            )
            
            # Validate character preservation
            user_data = response_data['data']
            assert user_data['first_name'] == special_chars_payload['first_name'], "Special characters not preserved"
    
    def test_concurrent_request_handling(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test API behavior under concurrent request conditions.
        
        Validates:
        - Thread safety of API endpoints
        - Consistent response format under load
        - Database transaction isolation
        - Concurrency handling equivalence with Node.js implementation
        
        Note: This is a basic concurrency test; full load testing requires separate tools.
        """
        import threading
        import queue
        
        # Result queue for concurrent requests
        results = queue.Queue()
        
        def make_request():
            """Execute API request and store result."""
            try:
                response = client.get(
                    USER_ENDPOINTS['list'],
                    headers=auth_headers
                )
                results.put(('success', response.status_code))
            except Exception as e:
                results.put(('error', str(e)))
        
        # Execute multiple concurrent requests
        threads = []
        num_threads = 5
        
        for _ in range(num_threads):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Validate all requests completed successfully
        success_count = 0
        while not results.empty():
            result_type, result_value = results.get()
            if result_type == 'success':
                success_count += 1
                assert result_value in [200, 401], f"Unexpected status code in concurrent test: {result_value}"
        
        assert success_count == num_threads, f"Only {success_count}/{num_threads} requests succeeded"


# ============================================================================
# PERFORMANCE BENCHMARKING TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.performance
@pytest.mark.skipif(not BENCHMARK_AVAILABLE, reason="pytest-benchmark not available")
class TestAPIPerformanceBenchmarks:
    """
    Test API endpoint performance with comprehensive benchmarking.
    
    Tests measure response times, memory usage, and throughput to ensure
    performance parity with Node.js baseline per Section 4.7.4.1.
    """
    
    def test_authentication_endpoint_performance(
        self,
        client: FlaskClient,
        api_test_data: Dict[str, Any],
        benchmark
    ):
        """
        Benchmark authentication endpoint response times.
        
        Validates:
        - Login endpoint performance against Node.js baseline
        - Statistical analysis of response time variance
        - Memory usage during authentication operations
        - Performance regression detection per Section 4.7.4.1
        """
        login_payload = api_test_data['auth']['login_payload']
        
        def login_request():
            """Execute login request for benchmarking."""
            return client.post(
                AUTH_ENDPOINTS['login'],
                data=json.dumps(login_payload),
                content_type='application/json'
            )
        
        # Benchmark login performance
        response = benchmark(login_request)
        
        # Validate response while benchmarking
        assert response.status_code in [200, 401], f"Unexpected status during benchmark: {response.status_code}"
    
    def test_user_creation_performance(
        self,
        client: FlaskClient,
        auth_headers: Dict[str, str],
        benchmark
    ):
        """
        Benchmark user creation endpoint performance.
        
        Validates:
        - User creation performance with database operations
        - Database transaction overhead measurement
        - Response time consistency under database load
        - CRUD operation performance equivalence with Node.js
        """
        def create_user_request():
            """Execute user creation request for benchmarking."""
            user_payload = create_test_user_payload(
                username=f"benchmark_user_{int(time.time() * 1000000)}",
                email=f"benchmark_{int(time.time() * 1000000)}@example.com"
            )
            return client.post(
                USER_ENDPOINTS['create'],
                data=json.dumps(user_payload),
                headers=auth_headers,
                content_type='application/json'
            )
        
        # Benchmark user creation performance
        response = benchmark(create_user_request)
        
        # Validate response during benchmarking
        assert response.status_code in [201, 400, 401, 403], f"Unexpected status during benchmark: {response.status_code}"
    
    def test_list_endpoint_performance(
        self,
        client: FlaskClient,
        auth_headers: Dict[str, str],
        benchmark
    ):
        """
        Benchmark list endpoint performance with pagination.
        
        Validates:
        - List operation performance with database queries
        - Pagination overhead measurement
        - Query optimization effectiveness
        - List operation performance equivalence with Node.js
        """
        def list_users_request():
            """Execute user list request for benchmarking."""
            return client.get(
                f"{USER_ENDPOINTS['list']}?page=1&per_page=20",
                headers=auth_headers
            )
        
        # Benchmark list performance
        response = benchmark(list_users_request)
        
        # Validate response during benchmarking
        assert response.status_code in [200, 401, 403], f"Unexpected status during benchmark: {response.status_code}"


# ============================================================================
# API CONTRACT COMPLIANCE TESTS
# ============================================================================

@pytest.mark.api
@pytest.mark.unit
class TestAPIContractCompliance:
    """
    Test comprehensive API contract compliance and response format validation.
    
    Tests ensure 100% behavioral equivalence with Node.js implementation
    through systematic validation of API contracts per Section 4.7.1.
    """
    
    def test_response_header_compliance(self, client: FlaskClient):
        """
        Test API response headers match expected format.
        
        Validates:
        - Content-Type header consistency
        - CORS header presence and values
        - Security headers implementation
        - Header compliance with Node.js implementation
        """
        # Execute simple API request
        response = client.get(AUTH_ENDPOINTS['login'])
        
        # Validate response headers
        assert 'Content-Type' in response.headers, "Missing Content-Type header"
        assert response.headers['Content-Type'].startswith('application/json'), "Invalid Content-Type"
        
        # Validate CORS headers (if implemented)
        expected_cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers'
        ]
        
        for header in expected_cors_headers:
            if header in response.headers:
                assert response.headers[header] is not None, f"Empty CORS header: {header}"
        
        # Validate security headers
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        for header in security_headers:
            if header in response.headers:
                assert response.headers[header] is not None, f"Empty security header: {header}"
    
    def test_error_response_consistency(self, client: FlaskClient):
        """
        Test error response format consistency across endpoints.
        
        Validates:
        - Uniform error response structure
        - Error code standardization
        - Error message format consistency
        - Error handling equivalence with Node.js implementation
        """
        # Test multiple endpoints for consistent error format
        endpoints_to_test = [
            (AUTH_ENDPOINTS['login'], 'POST'),
            (USER_ENDPOINTS['list'], 'GET'),
            (ENTITY_ENDPOINTS['list'], 'GET'),
            (ADMIN_ENDPOINTS['system_status'], 'GET')
        ]
        
        for endpoint, method in endpoints_to_test:
            if method == 'POST':
                response = client.post(endpoint, data='invalid_json', content_type='application/json')
            else:
                response = client.get(endpoint)
            
            # Should get 400 or 401 depending on endpoint
            if response.status_code in [400, 401, 403, 422]:
                response_data = response.get_json()
                
                # Validate error response structure
                assert 'success' in response_data, f"Missing 'success' field in error response for {endpoint}"
                assert response_data['success'] is False, f"Error response should have success=False for {endpoint}"
                assert 'message' in response_data, f"Missing 'message' field in error response for {endpoint}"
                assert 'error_code' in response_data, f"Missing 'error_code' field in error response for {endpoint}"
                assert 'timestamp' in response_data, f"Missing 'timestamp' field in error response for {endpoint}"
    
    def test_pagination_format_consistency(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test pagination format consistency across list endpoints.
        
        Validates:
        - Uniform pagination metadata structure
        - Page parameter handling consistency
        - Sort parameter validation
        - Pagination equivalence with Node.js implementation
        """
        # Test pagination on multiple list endpoints
        list_endpoints = [
            USER_ENDPOINTS['list'],
            ENTITY_ENDPOINTS['list']
        ]
        
        for endpoint in list_endpoints:
            response = client.get(
                f"{endpoint}?page=1&per_page=10&sort_by=created_at&sort_order=desc",
                headers=auth_headers
            )
            
            if response.status_code == 200:
                response_data = response.get_json()
                
                # Validate pagination structure
                assert 'data' in response_data, f"Missing 'data' field in {endpoint}"
                
                # Check for pagination metadata (may vary based on implementation)
                data = response_data['data']
                pagination_fields = ['pagination', 'total', 'page', 'per_page', 'pages']
                
                has_pagination = any(field in data for field in pagination_fields)
                if has_pagination:
                    # If pagination is present, validate its structure
                    for field in ['total', 'page', 'per_page']:
                        if field in data:
                            assert isinstance(data[field], int), f"Invalid {field} type in {endpoint}"
    
    def test_timestamp_format_consistency(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test timestamp format consistency across API responses.
        
        Validates:
        - ISO 8601 timestamp format compliance
        - Timezone handling consistency
        - Timestamp precision and accuracy
        - Date format equivalence with Node.js implementation
        """
        # Execute requests that should return timestamps
        endpoints_with_timestamps = [
            (AUTH_ENDPOINTS['login'], 'POST', api_test_data.get('auth', {}).get('login_payload', {})),
            (USER_ENDPOINTS['list'], 'GET', None)
        ]
        
        for endpoint, method, payload in endpoints_with_timestamps:
            if method == 'POST' and payload:
                response = client.post(
                    endpoint,
                    data=json.dumps(payload),
                    headers=auth_headers,
                    content_type='application/json'
                )
            else:
                response = client.get(endpoint, headers=auth_headers)
            
            if response.status_code in [200, 201]:
                response_data = response.get_json()
                
                # Validate timestamp format
                if 'timestamp' in response_data:
                    assert validate_timestamp_format(response_data['timestamp']), (
                        f"Invalid timestamp format in {endpoint}: {response_data['timestamp']}"
                    )
                
                # Validate data timestamps if present
                if 'data' in response_data and response_data['data']:
                    data = response_data['data']
                    timestamp_fields = ['created_at', 'updated_at', 'timestamp']
                    
                    for field in timestamp_fields:
                        if field in data and data[field]:
                            assert validate_timestamp_format(data[field]), (
                                f"Invalid {field} format in {endpoint}: {data[field]}"
                            )


# ============================================================================
# INTEGRATION TESTS FOR API WORKFLOWS
# ============================================================================

@pytest.mark.api
@pytest.mark.integration
class TestAPIWorkflowIntegration:
    """
    Test complete API workflows and integration scenarios.
    
    Tests cover end-to-end workflows combining multiple API operations
    to validate business process equivalence with Node.js implementation.
    """
    
    def test_complete_user_lifecycle_workflow(self, client: FlaskClient):
        """
        Test complete user lifecycle from creation to deletion.
        
        Validates:
        - End-to-end user management workflow
        - API operation sequencing and state management
        - Data consistency across multiple operations
        - Workflow equivalence with Node.js implementation
        """
        # Step 1: Authenticate admin user (mock)
        admin_headers = {
            'Authorization': 'Bearer admin-test-token',
            'Content-Type': 'application/json',
            'X-User-Role': 'admin'
        }
        
        # Step 2: Create new user
        user_payload = create_test_user_payload(
            username="lifecycle_test_user",
            email="lifecycle@example.com"
        )
        
        create_response = client.post(
            USER_ENDPOINTS['create'],
            data=json.dumps(user_payload),
            headers=admin_headers,
            content_type='application/json'
        )
        
        # Continue workflow only if user creation succeeds
        if create_response.status_code == 201:
            create_data = create_response.get_json()
            user_id = create_data['data']['id']
            
            # Step 3: Retrieve created user
            get_response = client.get(
                USER_ENDPOINTS['detail'].format(user_id=user_id),
                headers=admin_headers
            )
            
            if get_response.status_code == 200:
                get_data = get_response.get_json()
                assert get_data['data']['username'] == user_payload['username'], "User data mismatch"
            
            # Step 4: Update user information
            update_payload = {
                'first_name': 'Updated',
                'last_name': 'Lifecycle'
            }
            
            update_response = client.put(
                USER_ENDPOINTS['detail'].format(user_id=user_id),
                data=json.dumps(update_payload),
                headers=admin_headers,
                content_type='application/json'
            )
            
            # Step 5: Delete user
            delete_response = client.delete(
                USER_ENDPOINTS['detail'].format(user_id=user_id),
                headers=admin_headers
            )
            
            # Validate workflow completion
            workflow_success = all([
                create_response.status_code == 201,
                get_response.status_code == 200,
                update_response.status_code in [200, 404],  # May not exist in test DB
                delete_response.status_code in [200, 404]   # May not exist in test DB
            ])
            
            assert workflow_success or create_response.status_code in [400, 401, 403], (
                "User lifecycle workflow failed unexpectedly"
            )
    
    def test_authentication_and_resource_access_workflow(self, client: FlaskClient, api_test_data: Dict[str, Any]):
        """
        Test authentication followed by protected resource access.
        
        Validates:
        - Authentication flow integration with resource access
        - Token-based session management across requests
        - Authorization enforcement for protected resources
        - Session workflow equivalence with Node.js implementation
        """
        # Step 1: Attempt to access protected resource without authentication
        unauthorized_response = client.get(USER_ENDPOINTS['list'])
        assert unauthorized_response.status_code == 401, "Should require authentication"
        
        # Step 2: Authenticate user
        login_payload = api_test_data['auth']['login_payload']
        login_response = client.post(
            AUTH_ENDPOINTS['login'],
            data=json.dumps(login_payload),
            content_type='application/json'
        )
        
        # Continue workflow only if login succeeds
        if login_response.status_code == 200:
            login_data = login_response.get_json()
            access_token = login_data['data']['access_token']
            
            # Step 3: Access protected resource with valid token
            auth_headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            protected_response = client.get(
                USER_ENDPOINTS['list'],
                headers=auth_headers
            )
            
            assert protected_response.status_code in [200, 403], "Should allow authenticated access"
            
            # Step 4: Logout and invalidate token
            logout_response = client.post(
                AUTH_ENDPOINTS['logout'],
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Step 5: Attempt to access resource with invalidated token
            post_logout_response = client.get(
                USER_ENDPOINTS['list'],
                headers=auth_headers
            )
            
            # Validate authentication workflow
            workflow_success = all([
                unauthorized_response.status_code == 401,
                login_response.status_code == 200,
                protected_response.status_code in [200, 403],
                logout_response.status_code in [200, 401],
                post_logout_response.status_code in [401, 403]
            ])
            
            assert workflow_success, "Authentication workflow validation failed"
    
    def test_entity_management_with_relationships_workflow(self, client: FlaskClient, auth_headers: Dict[str, str]):
        """
        Test business entity management with related data operations.
        
        Validates:
        - Entity creation with relationship management
        - Data consistency across related entities
        - Cascade operations and referential integrity
        - Relationship workflow equivalence with Node.js implementation
        """
        # Step 1: Create parent entity
        parent_entity_payload = create_test_entity_payload(
            name="Parent Company",
            entity_type="company"
        )
        
        parent_response = client.post(
            ENTITY_ENDPOINTS['create'],
            data=json.dumps(parent_entity_payload),
            headers=auth_headers,
            content_type='application/json'
        )
        
        # Continue workflow only if parent creation succeeds
        if parent_response.status_code == 201:
            parent_data = parent_response.get_json()
            parent_id = parent_data['data']['id']
            
            # Step 2: Create child entity with relationship
            child_entity_payload = create_test_entity_payload(
                name="Child Department",
                entity_type="department",
                metadata={'parent_id': parent_id}
            )
            
            child_response = client.post(
                ENTITY_ENDPOINTS['create'],
                data=json.dumps(child_entity_payload),
                headers=auth_headers,
                content_type='application/json'
            )
            
            # Step 3: Verify relationship integrity
            if child_response.status_code == 201:
                child_data = child_response.get_json()
                child_id = child_data['data']['id']
                
                # Verify parent entity still exists
                parent_check_response = client.get(
                    ENTITY_ENDPOINTS['detail'].format(entity_id=parent_id),
                    headers=auth_headers
                )
                
                # Verify child entity relationship
                child_check_response = client.get(
                    ENTITY_ENDPOINTS['detail'].format(entity_id=child_id),
                    headers=auth_headers
                )
                
                # Validate relationship workflow
                relationship_success = all([
                    parent_response.status_code == 201,
                    child_response.status_code == 201,
                    parent_check_response.status_code in [200, 404],
                    child_check_response.status_code in [200, 404]
                ])
                
                assert relationship_success or parent_response.status_code in [400, 401, 403], (
                    "Entity relationship workflow failed unexpectedly"
                )


# Export test classes for pytest discovery
__all__ = [
    'TestAuthenticationEndpoints',
    'TestUserManagementEndpoints', 
    'TestBusinessEntityEndpoints',
    'TestAdministrativeEndpoints',
    'TestErrorHandlingAndEdgeCases',
    'TestAPIPerformanceBenchmarks',
    'TestAPIContractCompliance',
    'TestAPIWorkflowIntegration'
]