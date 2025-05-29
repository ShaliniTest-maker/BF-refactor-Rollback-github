"""
API Error Handling Validation Test Suite for Flask Migration

This comprehensive test suite validates Flask @app.errorhandler decorators provide equivalent 
error handling to the original Node.js implementation, ensuring consistent error response formats, 
proper HTTP status codes, and comprehensive error scenario coverage across all Flask blueprints.

Key Testing Areas:
- Flask @app.errorhandler decorator testing replacing Express.js error middleware per Section 4.3.2
- Standardized error response format validation maintaining API consistency per Feature F-002
- Comprehensive error scenario testing including validation errors, authentication failures, 
  and server errors per Section 4.5.3
- HTTP status code accuracy testing ensuring proper error classification per Section 4.3.2
- Error logging and monitoring validation for production observability per Section 8.5
- Error handling equivalence testing against Node.js baseline behavior per Feature F-005

Technical Implementation:
- pytest-flask 1.3.0 fixtures for Flask application testing with request context management
- Flask-SQLAlchemy testing patterns with database transaction rollback for error isolation
- ItsDangerous session management for authentication error testing
- pytest-benchmark 5.1.0 for error handling performance validation
- Comparative testing framework for Node.js vs Flask error response parity

Migration Context:
Ensures complete functional parity during Node.js/Express.js to Python 3.13.3/Flask 3.1.1 
migration while maintaining zero functional regression and seamless transition for existing 
client applications requiring consistent error handling behavior.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from io import StringIO
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock

import pytest
from flask import Flask, request, g, session
from flask.testing import FlaskClient
from sqlalchemy.exc import IntegrityError, OperationalError, DatabaseError
from werkzeug.exceptions import HTTPException
from werkzeug.test import Client

# Import application modules for error testing
try:
    from src.models.user import User
    from src.models.business_entity import BusinessEntity
    from src.models.entity_relationship import EntityRelationship
    from src.services.validation_service import ValidationService
    from src.services.user_service import UserService
    from src.services.business_entity_service import BusinessEntityService
    from src.auth.decorators import require_auth, require_permission
    from src.auth.session_manager import SessionManager
    from src.auth.auth0_integration import Auth0Integration
except ImportError as e:
    # Graceful handling for missing modules during test setup
    pytest.skip(f"Application modules not available: {e}", allow_module_level=True)


# ================================================================================================
# PYTEST MARKERS FOR ERROR HANDLING TEST ORGANIZATION
# ================================================================================================

pytestmark = [
    pytest.mark.api,
    pytest.mark.integration,
    pytest.mark.blueprint
]


# ================================================================================================
# ERROR HANDLING TEST FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def error_handler_client(app: Flask, client: FlaskClient) -> FlaskClient:
    """
    Enhanced Flask test client for error handling validation.
    
    Provides a test client specifically configured for testing error handling
    scenarios with comprehensive error response capture and validation.
    
    Args:
        app: Flask application instance
        client: Base Flask test client
        
    Returns:
        FlaskClient: Error handling test client
    """
    # Configure application for error testing
    app.config.update({
        'TESTING': True,
        'PROPAGATE_EXCEPTIONS': False,  # Enable error handlers
        'DEBUG': False,  # Disable debug mode for production error handling
        'ERROR_404_HELP': False,  # Disable Werkzeug 404 help
        'SQLALCHEMY_ECHO': False  # Disable SQL logging during error tests
    })
    
    return client


@pytest.fixture(scope='function')
def log_capture() -> Tuple[StringIO, logging.Handler]:
    """
    Log capture fixture for error handling validation.
    
    Captures log messages during error scenarios for validation of
    error logging and monitoring integration.
    
    Returns:
        Tuple[StringIO, logging.Handler]: Log capture stream and handler
    """
    log_stream = StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.ERROR)
    
    # Configure formatter for structured log validation
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    
    # Add handler to Flask application logger
    flask_logger = logging.getLogger('flask.app')
    flask_logger.addHandler(handler)
    flask_logger.setLevel(logging.ERROR)
    
    return log_stream, handler


@pytest.fixture(scope='function')
def mock_validation_service() -> Mock:
    """
    Mock validation service for testing validation error scenarios.
    
    Provides controlled validation error generation for testing
    validation error handling patterns.
    
    Returns:
        Mock: Mock validation service instance
    """
    mock_service = Mock(spec=ValidationService)
    
    # Configure validation error responses
    mock_service.validate_user_data.side_effect = ValueError("Invalid user data")
    mock_service.validate_business_entity.side_effect = ValueError("Entity validation failed")
    mock_service.validate_entity_relationship.side_effect = ValueError("Relationship validation failed")
    
    return mock_service


@pytest.fixture(scope='function')
def mock_database_errors() -> Dict[str, Exception]:
    """
    Mock database error scenarios for error handling testing.
    
    Provides various database error types for testing database
    error handling and recovery patterns.
    
    Returns:
        Dict[str, Exception]: Database error scenarios
    """
    return {
        'integrity_error': IntegrityError(
            "UNIQUE constraint failed", None, None
        ),
        'operational_error': OperationalError(
            "Database connection failed", None, None
        ),
        'database_error': DatabaseError(
            "Database operation failed", None, None
        )
    }


@pytest.fixture(scope='function')
def expected_error_format() -> Dict[str, Any]:
    """
    Expected error response format for validation.
    
    Defines the standardized error response format that must be
    maintained for API consistency per Feature F-002.
    
    Returns:
        Dict[str, Any]: Expected error response structure
    """
    return {
        'error': {
            'code': 'string',  # Error code identifier
            'message': 'string',  # Human-readable error message
            'details': 'string or dict',  # Detailed error information
            'timestamp': 'string',  # ISO format timestamp
            'request_id': 'string',  # Unique request identifier
            'path': 'string'  # Request path that caused the error
        },
        'status': 'integer',  # HTTP status code
        'success': False  # Always false for error responses
    }


# ================================================================================================
# FLASK @APP.ERRORHANDLER DECORATOR TESTING PER SECTION 4.3.2
# ================================================================================================

class TestFlaskErrorHandlerDecorators:
    """
    Test suite for Flask @app.errorhandler decorator functionality.
    
    Validates that Flask error handlers provide equivalent functionality
    to Express.js error middleware while maintaining consistent error
    response formats and proper HTTP status code management.
    """
    
    @pytest.mark.auth
    def test_400_bad_request_handler(
        self, 
        error_handler_client: FlaskClient, 
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 400 Bad Request error handler implementation.
        
        Validates that Flask @app.errorhandler(400) provides standardized
        error responses for malformed requests with proper logging.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Simulate bad request with malformed JSON
        response = error_handler_client.post(
            '/api/users',
            data='{"invalid": json}',  # Malformed JSON
            content_type='application/json'
        )
        
        # Validate HTTP status code
        assert response.status_code == 400, "400 Bad Request handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert 'error' in error_data, "Error response must contain 'error' field"
        assert 'status' in error_data, "Error response must contain 'status' field"
        assert 'success' in error_data, "Error response must contain 'success' field"
        assert error_data['success'] is False, "Error response success must be False"
        assert error_data['status'] == 400, "Error status must match HTTP status code"
        
        # Validate error details structure
        error_info = error_data['error']
        assert 'code' in error_info, "Error must contain code"
        assert 'message' in error_info, "Error must contain message"
        assert 'timestamp' in error_info, "Error must contain timestamp"
        assert 'request_id' in error_info, "Error must contain request_id"
        assert 'path' in error_info, "Error must contain path"
        
        # Validate error content
        assert error_info['code'] == 'BAD_REQUEST', "Error code must be BAD_REQUEST"
        assert 'malformed' in error_info['message'].lower() or 'invalid' in error_info['message'].lower()
        assert error_info['path'] == '/api/users', "Error path must match request path"
        
        # Validate timestamp format (ISO 8601)
        try:
            datetime.fromisoformat(error_info['timestamp'].replace('Z', '+00:00'))
        except ValueError:
            pytest.fail("Error timestamp must be valid ISO 8601 format")
        
        # Validate request ID is UUID format
        try:
            uuid.UUID(error_info['request_id'])
        except ValueError:
            pytest.fail("Request ID must be valid UUID format")
        
        # Validate error logging
        log_content = log_stream.getvalue()
        assert '400' in log_content, "400 error must be logged"
        assert 'BAD_REQUEST' in log_content, "Error code must be logged"
    
    @pytest.mark.auth
    def test_401_unauthorized_handler(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 401 Unauthorized error handler for authentication failures.
        
        Validates Flask authentication error handling with proper
        response format and logging integration.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Attempt to access protected endpoint without authentication
        response = error_handler_client.get('/api/users/profile')
        
        # Validate HTTP status code
        assert response.status_code == 401, "401 Unauthorized handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert error_data['status'] == 401, "Error status must be 401"
        assert error_data['success'] is False, "Error response success must be False"
        
        # Validate authentication error details
        error_info = error_data['error']
        assert error_info['code'] == 'UNAUTHORIZED', "Error code must be UNAUTHORIZED"
        assert 'authentication' in error_info['message'].lower() or 'unauthorized' in error_info['message'].lower()
        
        # Validate WWW-Authenticate header presence
        assert 'WWW-Authenticate' in response.headers, "WWW-Authenticate header must be present"
        
        # Validate error logging for security monitoring
        log_content = log_stream.getvalue()
        assert '401' in log_content, "401 error must be logged for security monitoring"
    
    @pytest.mark.auth
    def test_403_forbidden_handler(
        self, 
        error_handler_client: FlaskClient,
        authenticated_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 403 Forbidden error handler for authorization failures.
        
        Validates Flask authorization error handling for insufficient
        permissions with proper response format.
        
        Args:
            error_handler_client: Flask test client for error testing
            authenticated_client: Authenticated test client
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Attempt to access admin endpoint with regular user
        response = authenticated_client.get('/api/admin/users')
        
        # Validate HTTP status code
        assert response.status_code == 403, "403 Forbidden handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert error_data['status'] == 403, "Error status must be 403"
        assert error_data['success'] is False, "Error response success must be False"
        
        # Validate authorization error details
        error_info = error_data['error']
        assert error_info['code'] == 'FORBIDDEN', "Error code must be FORBIDDEN"
        assert 'permission' in error_info['message'].lower() or 'forbidden' in error_info['message'].lower()
        
        # Validate error logging for security monitoring
        log_content = log_stream.getvalue()
        assert '403' in log_content, "403 error must be logged for security monitoring"
    
    @pytest.mark.api
    def test_404_not_found_handler(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 404 Not Found error handler for non-existent resources.
        
        Validates Flask 404 error handling with proper response
        format and resource identification.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Request non-existent endpoint
        response = error_handler_client.get('/api/non-existent-endpoint')
        
        # Validate HTTP status code
        assert response.status_code == 404, "404 Not Found handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert error_data['status'] == 404, "Error status must be 404"
        assert error_data['success'] is False, "Error response success must be False"
        
        # Validate not found error details
        error_info = error_data['error']
        assert error_info['code'] == 'NOT_FOUND', "Error code must be NOT_FOUND"
        assert 'not found' in error_info['message'].lower()
        assert error_info['path'] == '/api/non-existent-endpoint', "Error path must match request"
        
        # Validate error logging
        log_content = log_stream.getvalue()
        assert '404' in log_content, "404 error must be logged"
    
    @pytest.mark.database
    def test_409_conflict_handler(
        self, 
        error_handler_client: FlaskClient,
        mock_database_errors: Dict[str, Exception],
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 409 Conflict error handler for business rule violations.
        
        Validates Flask conflict error handling for database integrity
        constraints and business rule violations.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_database_errors: Mock database error scenarios
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Simulate conflict through duplicate entity creation
        user_data = {
            'username': 'existing_user',
            'email': 'existing@example.com',
            'password': 'password123'
        }
        
        # First request should succeed (or we mock it to simulate existing data)
        # Second request should trigger conflict
        with patch('src.services.user_service.UserService.create_user') as mock_create:
            mock_create.side_effect = mock_database_errors['integrity_error']
            
            response = error_handler_client.post(
                '/api/users',
                json=user_data,
                content_type='application/json'
            )
        
        # Validate HTTP status code
        assert response.status_code == 409, "409 Conflict handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert error_data['status'] == 409, "Error status must be 409"
        assert error_data['success'] is False, "Error response success must be False"
        
        # Validate conflict error details
        error_info = error_data['error']
        assert error_info['code'] == 'CONFLICT', "Error code must be CONFLICT"
        assert 'conflict' in error_info['message'].lower() or 'duplicate' in error_info['message'].lower()
        
        # Validate error logging
        log_content = log_stream.getvalue()
        assert '409' in log_content, "409 error must be logged"
    
    @pytest.mark.api
    def test_422_unprocessable_entity_handler(
        self, 
        error_handler_client: FlaskClient,
        mock_validation_service: Mock,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 422 Unprocessable Entity error handler for validation failures.
        
        Validates Flask validation error handling with detailed
        validation error information and proper response format.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_validation_service: Mock validation service
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Simulate validation failure
        invalid_user_data = {
            'username': '',  # Invalid: empty username
            'email': 'invalid-email',  # Invalid: malformed email
            'password': '123'  # Invalid: too short password
        }
        
        with patch('src.services.validation_service.ValidationService') as mock_validator:
            mock_validator.return_value = mock_validation_service
            
            response = error_handler_client.post(
                '/api/users',
                json=invalid_user_data,
                content_type='application/json'
            )
        
        # Validate HTTP status code
        assert response.status_code == 422, "422 Unprocessable Entity handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert error_data['status'] == 422, "Error status must be 422"
        assert error_data['success'] is False, "Error response success must be False"
        
        # Validate validation error details
        error_info = error_data['error']
        assert error_info['code'] == 'VALIDATION_ERROR', "Error code must be VALIDATION_ERROR"
        assert 'validation' in error_info['message'].lower()
        
        # Validate detailed validation errors
        if 'details' in error_info and isinstance(error_info['details'], dict):
            details = error_info['details']
            assert 'field_errors' in details, "Validation details must contain field errors"
        
        # Validate error logging
        log_content = log_stream.getvalue()
        assert '422' in log_content, "422 error must be logged"
    
    @pytest.mark.api
    def test_500_internal_server_error_handler(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test 500 Internal Server Error handler for application errors.
        
        Validates Flask internal error handling with proper error
        masking for security and comprehensive error logging.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Simulate internal server error
        with patch('src.services.user_service.UserService.get_user') as mock_get:
            mock_get.side_effect = Exception("Internal application error")
            
            response = error_handler_client.get('/api/users/1')
        
        # Validate HTTP status code
        assert response.status_code == 500, "500 Internal Server Error handler failed"
        
        # Validate error response format
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        assert error_data['status'] == 500, "Error status must be 500"
        assert error_data['success'] is False, "Error response success must be False"
        
        # Validate internal error details (should be masked for security)
        error_info = error_data['error']
        assert error_info['code'] == 'INTERNAL_SERVER_ERROR', "Error code must be INTERNAL_SERVER_ERROR"
        assert 'internal server error' in error_info['message'].lower()
        
        # Ensure sensitive error details are not exposed
        assert 'Internal application error' not in error_info['message'], "Internal error details must be masked"
        
        # Validate comprehensive error logging for debugging
        log_content = log_stream.getvalue()
        assert '500' in log_content, "500 error must be logged"
        assert 'Internal application error' in log_content, "Full error details must be logged for debugging"


# ================================================================================================
# STANDARDIZED ERROR RESPONSE FORMAT VALIDATION PER FEATURE F-002
# ================================================================================================

class TestStandardizedErrorResponseFormat:
    """
    Test suite for standardized error response format validation.
    
    Ensures consistent error response formats across all Flask blueprints
    maintaining API consistency per Feature F-002 requirements.
    """
    
    @pytest.mark.api
    def test_error_response_json_structure(
        self, 
        error_handler_client: FlaskClient,
        expected_error_format: Dict[str, Any]
    ) -> None:
        """
        Test standardized JSON error response structure.
        
        Validates that all error responses conform to the standardized
        JSON structure for client application compatibility.
        
        Args:
            error_handler_client: Flask test client for error testing
            expected_error_format: Expected error response format
        """
        # Test various error scenarios for consistent format
        error_scenarios = [
            ('/api/non-existent', 404),
            ('/api/users/profile', 401),  # Unauthorized access
        ]
        
        for endpoint, expected_status in error_scenarios:
            response = error_handler_client.get(endpoint)
            
            # Validate response is JSON
            assert response.is_json, f"Error response for {endpoint} must be JSON"
            
            error_data = response.get_json()
            assert error_data is not None, f"Error response for {endpoint} must be parseable JSON"
            
            # Validate top-level structure
            assert 'error' in error_data, f"Error response for {endpoint} must contain 'error' field"
            assert 'status' in error_data, f"Error response for {endpoint} must contain 'status' field"
            assert 'success' in error_data, f"Error response for {endpoint} must contain 'success' field"
            
            # Validate top-level values
            assert error_data['status'] == expected_status, f"Status must match HTTP status for {endpoint}"
            assert error_data['success'] is False, f"Success must be False for error responses"
            
            # Validate error object structure
            error_info = error_data['error']
            required_fields = ['code', 'message', 'timestamp', 'request_id', 'path']
            
            for field in required_fields:
                assert field in error_info, f"Error object must contain '{field}' field for {endpoint}"
                assert error_info[field] is not None, f"Error field '{field}' cannot be null for {endpoint}"
                assert error_info[field] != '', f"Error field '{field}' cannot be empty for {endpoint}"
    
    @pytest.mark.api
    def test_error_response_content_types(
        self, 
        error_handler_client: FlaskClient
    ) -> None:
        """
        Test error response content type consistency.
        
        Validates that error responses always return proper JSON
        content type regardless of request content type.
        
        Args:
            error_handler_client: Flask test client for error testing
        """
        # Test different request content types
        request_types = [
            'application/json',
            'text/html',
            'application/xml',
            'text/plain'
        ]
        
        for content_type in request_types:
            response = error_handler_client.get(
                '/api/non-existent-endpoint',
                headers={'Content-Type': content_type}
            )
            
            # All error responses should be JSON regardless of request type
            assert response.content_type.startswith('application/json'), \
                f"Error response must be JSON regardless of request content type {content_type}"
            
            # Validate JSON structure
            error_data = response.get_json()
            assert error_data is not None, "Error response must be valid JSON"
            assert 'error' in error_data, "Error response must follow standard format"
    
    @pytest.mark.api
    def test_error_response_headers(
        self, 
        error_handler_client: FlaskClient
    ) -> None:
        """
        Test standardized error response headers.
        
        Validates that error responses include proper headers for
        client error handling and caching policies.
        
        Args:
            error_handler_client: Flask test client for error testing
        """
        response = error_handler_client.get('/api/non-existent-endpoint')
        
        # Validate required headers
        assert 'Content-Type' in response.headers, "Error response must include Content-Type header"
        assert response.headers['Content-Type'].startswith('application/json'), \
            "Error response Content-Type must be application/json"
        
        # Validate security headers
        assert 'X-Content-Type-Options' in response.headers, \
            "Error response must include X-Content-Type-Options header"
        assert response.headers['X-Content-Type-Options'] == 'nosniff', \
            "X-Content-Type-Options must be 'nosniff'"
        
        # Validate caching headers for error responses
        assert 'Cache-Control' in response.headers, \
            "Error response must include Cache-Control header"
        assert 'no-cache' in response.headers['Cache-Control'], \
            "Error responses should not be cached"
    
    @pytest.mark.api
    def test_error_response_localization_ready(
        self, 
        error_handler_client: FlaskClient
    ) -> None:
        """
        Test error response localization readiness.
        
        Validates that error responses support future localization
        requirements with proper message structure.
        
        Args:
            error_handler_client: Flask test client for error testing
        """
        # Test with Accept-Language header
        response = error_handler_client.get(
            '/api/non-existent-endpoint',
            headers={'Accept-Language': 'en-US,en;q=0.9'}
        )
        
        error_data = response.get_json()
        error_info = error_data['error']
        
        # Validate message structure supports localization
        assert isinstance(error_info['message'], str), "Error message must be string for localization"
        assert len(error_info['message']) > 0, "Error message cannot be empty"
        
        # Validate error code structure supports localization
        assert isinstance(error_info['code'], str), "Error code must be string"
        assert error_info['code'].isupper(), "Error code should be uppercase for consistency"
        assert '_' in error_info['code'] or error_info['code'].isalpha(), \
            "Error code should follow standard naming convention"


# ================================================================================================
# COMPREHENSIVE ERROR SCENARIO TESTING PER SECTION 4.5.3
# ================================================================================================

class TestComprehensiveErrorScenarios:
    """
    Test suite for comprehensive error scenario coverage.
    
    Validates error handling across all application layers including
    validation errors, authentication failures, and server errors
    per Section 4.5.3 requirements.
    """
    
    @pytest.mark.database
    def test_database_connection_error_handling(
        self, 
        error_handler_client: FlaskClient,
        mock_database_errors: Dict[str, Exception],
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test database connection error handling scenarios.
        
        Validates proper error handling for database connectivity
        issues with appropriate error responses and logging.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_database_errors: Mock database error scenarios
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Simulate database connection failure
        with patch('src.models.user.User.query') as mock_query:
            mock_query.side_effect = mock_database_errors['operational_error']
            
            response = error_handler_client.get('/api/users')
        
        # Validate error response
        assert response.status_code == 503, "Database connection error should return 503 Service Unavailable"
        
        error_data = response.get_json()
        assert error_data is not None, "Database error response must be JSON"
        assert error_data['success'] is False, "Database error success must be False"
        
        error_info = error_data['error']
        assert error_info['code'] == 'SERVICE_UNAVAILABLE', "Database error code must be SERVICE_UNAVAILABLE"
        assert 'database' in error_info['message'].lower() or 'service unavailable' in error_info['message'].lower()
        
        # Validate comprehensive error logging for operations team
        log_content = log_stream.getvalue()
        assert '503' in log_content, "Database connection error must be logged"
        assert 'operational' in log_content.lower() or 'database' in log_content.lower()
    
    @pytest.mark.service
    def test_service_layer_error_handling(
        self, 
        error_handler_client: FlaskClient,
        mock_validation_service: Mock,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test service layer error handling scenarios.
        
        Validates proper error propagation from service layer
        to API response with appropriate error transformation.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_validation_service: Mock validation service
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Test validation service error propagation
        with patch('src.services.user_service.UserService.create_user') as mock_create:
            mock_create.side_effect = ValueError("Service validation failed")
            
            response = error_handler_client.post(
                '/api/users',
                json={'username': 'testuser', 'email': 'test@example.com'},
                content_type='application/json'
            )
        
        # Validate service error is properly handled
        assert response.status_code in [400, 422], "Service validation error should return 400 or 422"
        
        error_data = response.get_json()
        assert error_data is not None, "Service error response must be JSON"
        
        error_info = error_data['error']
        assert error_info['code'] in ['BAD_REQUEST', 'VALIDATION_ERROR'], \
            "Service error must map to appropriate error code"
        
        # Validate error logging
        log_content = log_stream.getvalue()
        assert 'Service validation failed' in log_content, "Service errors must be logged for debugging"
    
    @pytest.mark.auth
    def test_authentication_integration_error_handling(
        self, 
        error_handler_client: FlaskClient,
        mock_auth0_service: MagicMock,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test authentication integration error handling.
        
        Validates error handling for Auth0 integration failures
        and authentication service errors.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_auth0_service: Mock Auth0 service
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Simulate Auth0 service failure
        mock_auth0_service.validate_token.side_effect = Exception("Auth0 service unavailable")
        
        response = error_handler_client.post(
            '/api/auth/validate',
            headers={'Authorization': 'Bearer invalid-token'},
            json={}
        )
        
        # Validate authentication error handling
        assert response.status_code == 401, "Auth service failure should return 401 Unauthorized"
        
        error_data = response.get_json()
        assert error_data is not None, "Auth error response must be JSON"
        
        error_info = error_data['error']
        assert error_info['code'] == 'UNAUTHORIZED', "Auth error code must be UNAUTHORIZED"
        
        # Validate security logging
        log_content = log_stream.getvalue()
        assert '401' in log_content, "Authentication errors must be logged for security monitoring"
    
    @pytest.mark.blueprint
    def test_blueprint_specific_error_handling(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test blueprint-specific error handling scenarios.
        
        Validates that error handling works consistently across
        different Flask blueprints with proper error context.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for error logging validation
        """
        log_stream, handler = log_capture
        
        # Test different blueprint error scenarios
        blueprint_scenarios = [
            ('/api/users/non-existent', 'api_blueprint'),
            ('/auth/invalid-action', 'auth_blueprint'),
            ('/admin/restricted', 'admin_blueprint')
        ]
        
        for endpoint, blueprint_name in blueprint_scenarios:
            response = error_handler_client.get(endpoint)
            
            # Validate error response includes blueprint context
            error_data = response.get_json()
            if error_data and 'error' in error_data:
                error_info = error_data['error']
                
                # Validate path is correctly captured
                assert error_info['path'] == endpoint, \
                    f"Error path must match request path for blueprint {blueprint_name}"
                
                # Validate error structure is consistent across blueprints
                required_fields = ['code', 'message', 'timestamp', 'request_id']
                for field in required_fields:
                    assert field in error_info, \
                        f"Blueprint {blueprint_name} must include {field} in error response"
    
    @pytest.mark.performance
    def test_error_handling_performance_impact(
        self, 
        error_handler_client: FlaskClient,
        api_benchmark: Any
    ) -> None:
        """
        Test error handling performance impact.
        
        Validates that error handling does not significantly impact
        application performance compared to successful requests.
        
        Args:
            error_handler_client: Flask test client for error testing
            api_benchmark: Benchmark fixture for performance testing
        """
        # Benchmark error response time
        def generate_error():
            return error_handler_client.get('/api/non-existent-endpoint')
        
        # Benchmark successful response time (mock)
        def generate_success():
            with patch('src.services.user_service.UserService.get_users') as mock_get:
                mock_get.return_value = []
                return error_handler_client.get('/api/users')
        
        # Run benchmarks
        error_result = api_benchmark(generate_error)
        success_result = api_benchmark(generate_success)
        
        # Validate error handling performance
        # Error responses should not be significantly slower than successful responses
        performance_ratio = error_result.stats.mean / success_result.stats.mean
        assert performance_ratio < 2.0, \
            "Error handling should not be more than 2x slower than successful responses"


# ================================================================================================
# HTTP STATUS CODE ACCURACY TESTING PER SECTION 4.3.2
# ================================================================================================

class TestHTTPStatusCodeAccuracy:
    """
    Test suite for HTTP status code accuracy validation.
    
    Ensures proper error classification through accurate HTTP status
    codes per Section 4.3.2 requirements for client compatibility.
    """
    
    @pytest.mark.api
    def test_client_error_status_codes(
        self, 
        error_handler_client: FlaskClient
    ) -> None:
        """
        Test client error status code accuracy (4xx range).
        
        Validates that client errors return appropriate 4xx status
        codes with proper error classification.
        
        Args:
            error_handler_client: Flask test client for error testing
        """
        # Define client error scenarios and expected status codes
        client_error_scenarios = [
            {
                'description': 'Bad Request - Malformed JSON',
                'method': 'POST',
                'endpoint': '/api/users',
                'data': '{"invalid": json}',
                'content_type': 'application/json',
                'expected_status': 400
            },
            {
                'description': 'Unauthorized - No Authentication',
                'method': 'GET',
                'endpoint': '/api/users/profile',
                'expected_status': 401
            },
            {
                'description': 'Forbidden - Insufficient Permissions',
                'method': 'GET',
                'endpoint': '/api/admin/users',
                'expected_status': 403
            },
            {
                'description': 'Not Found - Non-existent Resource',
                'method': 'GET',
                'endpoint': '/api/users/999999',
                'expected_status': 404
            },
            {
                'description': 'Method Not Allowed - Invalid HTTP Method',
                'method': 'PATCH',
                'endpoint': '/api/health',  # Assuming health endpoint only supports GET
                'expected_status': 405
            },
            {
                'description': 'Conflict - Duplicate Resource',
                'method': 'POST',
                'endpoint': '/api/users',
                'json': {'username': 'duplicate', 'email': 'duplicate@example.com'},
                'expected_status': 409,
                'setup': 'duplicate_user'
            },
            {
                'description': 'Unprocessable Entity - Validation Error',
                'method': 'POST',
                'endpoint': '/api/users',
                'json': {'username': '', 'email': 'invalid-email'},
                'expected_status': 422
            }
        ]
        
        for scenario in client_error_scenarios:
            # Setup scenario if needed
            if scenario.get('setup') == 'duplicate_user':
                # Pre-create user to trigger conflict (or mock the scenario)
                with patch('src.services.user_service.UserService.create_user') as mock_create:
                    mock_create.side_effect = IntegrityError("UNIQUE constraint failed", None, None)
                    
                    response = getattr(error_handler_client, scenario['method'].lower())(
                        scenario['endpoint'],
                        **{k: v for k, v in scenario.items() if k in ['json', 'data', 'content_type']}
                    )
            else:
                # Execute test scenario
                response = getattr(error_handler_client, scenario['method'].lower())(
                    scenario['endpoint'],
                    **{k: v for k, v in scenario.items() if k in ['json', 'data', 'content_type']}
                )
            
            # Validate status code accuracy
            assert response.status_code == scenario['expected_status'], \
                f"{scenario['description']} must return status {scenario['expected_status']}, got {response.status_code}"
            
            # Validate error response format
            if response.is_json:
                error_data = response.get_json()
                assert error_data['status'] == scenario['expected_status'], \
                    f"Response body status must match HTTP status for {scenario['description']}"
    
    @pytest.mark.api
    def test_server_error_status_codes(
        self, 
        error_handler_client: FlaskClient,
        mock_database_errors: Dict[str, Exception]
    ) -> None:
        """
        Test server error status code accuracy (5xx range).
        
        Validates that server errors return appropriate 5xx status
        codes with proper error classification.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_database_errors: Mock database error scenarios
        """
        # Define server error scenarios and expected status codes
        server_error_scenarios = [
            {
                'description': 'Internal Server Error - Application Exception',
                'endpoint': '/api/users/1',
                'mock_exception': Exception("Internal application error"),
                'expected_status': 500
            },
            {
                'description': 'Bad Gateway - External Service Failure',
                'endpoint': '/api/auth/validate',
                'mock_exception': ConnectionError("Auth0 service unavailable"),
                'expected_status': 502
            },
            {
                'description': 'Service Unavailable - Database Connection Error',
                'endpoint': '/api/users',
                'mock_exception': mock_database_errors['operational_error'],
                'expected_status': 503
            },
            {
                'description': 'Gateway Timeout - Request Timeout',
                'endpoint': '/api/users/search',
                'mock_exception': TimeoutError("Request timeout"),
                'expected_status': 504
            }
        ]
        
        for scenario in server_error_scenarios:
            # Mock the appropriate service to raise the exception
            with patch('src.services.user_service.UserService.get_user') as mock_service:
                mock_service.side_effect = scenario['mock_exception']
                
                response = error_handler_client.get(scenario['endpoint'])
            
            # Validate status code accuracy
            assert response.status_code == scenario['expected_status'], \
                f"{scenario['description']} must return status {scenario['expected_status']}, got {response.status_code}"
            
            # Validate error response format
            if response.is_json:
                error_data = response.get_json()
                assert error_data['status'] == scenario['expected_status'], \
                    f"Response body status must match HTTP status for {scenario['description']}"
    
    @pytest.mark.api
    def test_status_code_consistency_across_endpoints(
        self, 
        error_handler_client: FlaskClient
    ) -> None:
        """
        Test status code consistency across different endpoints.
        
        Validates that similar error conditions return consistent
        status codes regardless of the endpoint.
        
        Args:
            error_handler_client: Flask test client for error testing
        """
        # Test consistent 404 responses across endpoints
        not_found_endpoints = [
            '/api/users/999999',
            '/api/business-entities/999999',
            '/api/entity-relationships/999999',
            '/api/non-existent-resource'
        ]
        
        for endpoint in not_found_endpoints:
            response = error_handler_client.get(endpoint)
            assert response.status_code == 404, \
                f"All non-existent resources must return 404, {endpoint} returned {response.status_code}"
        
        # Test consistent 401 responses for unauthenticated access
        protected_endpoints = [
            '/api/users/profile',
            '/api/users/settings',
            '/api/business-entities/create',
            '/api/admin/dashboard'
        ]
        
        for endpoint in protected_endpoints:
            response = error_handler_client.get(endpoint)
            assert response.status_code == 401, \
                f"All protected resources must return 401 when unauthenticated, {endpoint} returned {response.status_code}"


# ================================================================================================
# ERROR LOGGING AND MONITORING VALIDATION PER SECTION 8.5
# ================================================================================================

class TestErrorLoggingAndMonitoring:
    """
    Test suite for error logging and monitoring validation.
    
    Validates error logging integration for production observability
    per Section 8.5 infrastructure monitoring requirements.
    """
    
    @pytest.mark.monitoring
    def test_error_logging_format_and_structure(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test error logging format and structure for monitoring.
        
        Validates that error logs include all necessary information
        for production monitoring and debugging.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for log validation
        """
        log_stream, handler = log_capture
        
        # Generate various error scenarios
        error_scenarios = [
            {'endpoint': '/api/non-existent', 'expected_status': 404},
            {'endpoint': '/api/users/profile', 'expected_status': 401},
        ]
        
        for scenario in error_scenarios:
            # Clear previous logs
            log_stream.seek(0)
            log_stream.truncate(0)
            
            # Generate error
            response = error_handler_client.get(scenario['endpoint'])
            
            # Validate log content
            log_content = log_stream.getvalue()
            
            # Validate log contains essential information
            assert str(scenario['expected_status']) in log_content, \
                f"Error log must contain status code {scenario['expected_status']}"
            assert scenario['endpoint'] in log_content, \
                f"Error log must contain endpoint path {scenario['endpoint']}"
            
            # Validate log timestamp format
            log_lines = log_content.strip().split('\n')
            for line in log_lines:
                if line.strip():
                    # Each log line should start with timestamp
                    assert len(line.split(' - ')) >= 4, \
                        "Log line must contain timestamp, logger name, level, and message"
    
    @pytest.mark.monitoring
    def test_security_error_logging(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test security-related error logging for monitoring.
        
        Validates that security errors are properly logged for
        security monitoring and incident response.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for security log validation
        """
        log_stream, handler = log_capture
        
        # Add security logger for testing
        security_logger = logging.getLogger('security')
        security_handler = logging.StreamHandler(log_stream)
        security_handler.setLevel(logging.WARNING)
        security_logger.addHandler(security_handler)
        security_logger.setLevel(logging.WARNING)
        
        try:
            # Test unauthorized access attempt
            response = error_handler_client.get('/api/users/profile')
            assert response.status_code == 401
            
            # Test forbidden access attempt
            with patch('flask_login.current_user') as mock_user:
                mock_user.is_authenticated = True
                mock_user.has_permission.return_value = False
                
                response = error_handler_client.get('/api/admin/users')
                # Assuming this returns 403 when user lacks permissions
            
            # Validate security logging
            log_content = log_stream.getvalue()
            
            # Security events should be logged
            security_indicators = ['401', '403', 'unauthorized', 'forbidden']
            has_security_log = any(indicator in log_content.lower() for indicator in security_indicators)
            assert has_security_log, "Security-related errors must be logged for monitoring"
            
        finally:
            security_logger.removeHandler(security_handler)
    
    @pytest.mark.monitoring
    def test_performance_error_logging(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler],
        performance_monitor: Any
    ) -> None:
        """
        Test performance-related error logging.
        
        Validates that performance issues and timeouts are
        properly logged for performance monitoring.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for performance log validation
            performance_monitor: Performance monitoring fixture
        """
        log_stream, handler = log_capture
        
        # Start performance monitoring
        performance_monitor.start_monitoring()
        
        try:
            # Simulate slow operation leading to timeout
            with patch('src.services.user_service.UserService.get_users') as mock_get:
                mock_get.side_effect = TimeoutError("Database query timeout")
                
                response = error_handler_client.get('/api/users')
        
        finally:
            # Stop monitoring and get metrics
            metrics = performance_monitor.stop_monitoring()
        
        # Validate timeout error handling
        assert response.status_code == 504, "Timeout should return 504 Gateway Timeout"
        
        # Validate performance logging
        log_content = log_stream.getvalue()
        assert 'timeout' in log_content.lower() or '504' in log_content, \
            "Timeout errors must be logged for performance monitoring"
        
        # Validate performance metrics collection
        assert metrics['duration'] > 0, "Performance monitoring should capture duration"
    
    @pytest.mark.monitoring
    def test_error_correlation_and_tracing(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test error correlation and request tracing.
        
        Validates that errors include correlation IDs and request
        tracing information for distributed system debugging.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for correlation validation
        """
        log_stream, handler = log_capture
        
        # Generate error with custom request ID
        custom_request_id = str(uuid.uuid4())
        response = error_handler_client.get(
            '/api/non-existent-endpoint',
            headers={'X-Request-ID': custom_request_id}
        )
        
        # Validate error response includes correlation ID
        error_data = response.get_json()
        assert error_data is not None, "Error response must be JSON"
        
        error_info = error_data['error']
        request_id = error_info.get('request_id')
        
        # Validate request ID format and presence
        assert request_id is not None, "Error response must include request_id"
        try:
            uuid.UUID(request_id)
        except ValueError:
            pytest.fail("Request ID must be valid UUID format")
        
        # Validate log correlation
        log_content = log_stream.getvalue()
        if custom_request_id in response.headers.get('X-Request-ID', ''):
            # If custom request ID is honored, it should appear in logs
            assert custom_request_id in log_content or request_id in log_content, \
                "Request ID must appear in error logs for correlation"


# ================================================================================================
# ERROR HANDLING EQUIVALENCE TESTING PER FEATURE F-005
# ================================================================================================

class TestErrorHandlingEquivalence:
    """
    Test suite for error handling equivalence validation.
    
    Validates error handling equivalence against Node.js baseline
    behavior per Feature F-005 business logic preservation requirements.
    """
    
    @pytest.mark.comparative
    def test_error_response_format_equivalence(
        self, 
        error_handler_client: FlaskClient,
        comparative_test_runner: Any
    ) -> None:
        """
        Test error response format equivalence with Node.js baseline.
        
        Validates that Flask error responses match Node.js error
        response format for client application compatibility.
        
        Args:
            error_handler_client: Flask test client for error testing
            comparative_test_runner: Comparative testing runner
        """
        # Test various error scenarios for format equivalence
        error_endpoints = [
            '/api/non-existent-endpoint',
            '/api/users/999999',
            '/api/users/profile'  # Unauthorized access
        ]
        
        for endpoint in error_endpoints:
            # Generate Flask error response
            flask_response = error_handler_client.get(endpoint)
            
            # Compare with Node.js baseline using comparative runner
            comparison_result = comparative_test_runner.compare_responses(
                endpoint, flask_response, 'GET'
            )
            
            # Validate response format equivalence
            assert comparison_result['status_match'], \
                f"HTTP status must match Node.js baseline for {endpoint}"
            
            # Validate JSON structure equivalence
            if flask_response.is_json:
                flask_data = flask_response.get_json()
                
                # Key fields that must be equivalent
                required_fields = ['error', 'status', 'success']
                for field in required_fields:
                    assert field in flask_data, \
                        f"Flask response must include {field} field for equivalence with Node.js"
                
                # Error object structure equivalence
                if 'error' in flask_data:
                    error_info = flask_data['error']
                    error_required_fields = ['code', 'message']
                    for field in error_required_fields:
                        assert field in error_info, \
                            f"Flask error object must include {field} for Node.js equivalence"
    
    @pytest.mark.comparative
    def test_error_code_mapping_equivalence(
        self, 
        error_handler_client: FlaskClient,
        comparative_test_runner: Any
    ) -> None:
        """
        Test error code mapping equivalence with Node.js implementation.
        
        Validates that Flask error codes map correctly to Node.js
        error codes for consistent client error handling.
        
        Args:
            error_handler_client: Flask test client for error testing
            comparative_test_runner: Comparative testing runner
        """
        # Define expected error code mappings
        error_code_mappings = {
            400: 'BAD_REQUEST',
            401: 'UNAUTHORIZED',
            403: 'FORBIDDEN',
            404: 'NOT_FOUND',
            409: 'CONFLICT',
            422: 'VALIDATION_ERROR',
            500: 'INTERNAL_SERVER_ERROR',
            503: 'SERVICE_UNAVAILABLE'
        }
        
        for status_code, expected_code in error_code_mappings.items():
            # Generate appropriate error scenario for each status code
            if status_code == 400:
                response = error_handler_client.post(
                    '/api/users',
                    data='{"invalid": json}',
                    content_type='application/json'
                )
            elif status_code == 401:
                response = error_handler_client.get('/api/users/profile')
            elif status_code == 404:
                response = error_handler_client.get('/api/non-existent')
            else:
                # Mock other error scenarios
                continue
            
            # Validate error code equivalence
            if response.is_json and response.status_code == status_code:
                error_data = response.get_json()
                if 'error' in error_data and 'code' in error_data['error']:
                    assert error_data['error']['code'] == expected_code, \
                        f"Error code for status {status_code} must be {expected_code} for Node.js equivalence"
    
    @pytest.mark.comparative
    def test_error_behavior_equivalence(
        self, 
        error_handler_client: FlaskClient,
        comparative_test_runner: Any
    ) -> None:
        """
        Test error behavior equivalence with Node.js implementation.
        
        Validates that Flask error handling behavior matches Node.js
        behavior for business logic preservation.
        
        Args:
            error_handler_client: Flask test client for error testing
            comparative_test_runner: Comparative testing runner
        """
        # Test business logic error scenarios
        business_error_scenarios = [
            {
                'description': 'Validation Error Behavior',
                'endpoint': '/api/users',
                'method': 'POST',
                'data': {'username': '', 'email': 'invalid'},
                'expected_behavior': 'validation_error_with_details'
            },
            {
                'description': 'Authentication Error Behavior',
                'endpoint': '/api/users/profile',
                'method': 'GET',
                'expected_behavior': 'authentication_required'
            },
            {
                'description': 'Resource Not Found Behavior',
                'endpoint': '/api/users/999999',
                'method': 'GET',
                'expected_behavior': 'resource_not_found'
            }
        ]
        
        for scenario in business_error_scenarios:
            # Execute scenario
            if scenario['method'] == 'POST':
                response = error_handler_client.post(
                    scenario['endpoint'],
                    json=scenario.get('data', {}),
                    content_type='application/json'
                )
            else:
                response = error_handler_client.get(scenario['endpoint'])
            
            # Compare behavior with Node.js baseline
            comparison_result = comparative_test_runner.compare_responses(
                scenario['endpoint'], response, scenario['method']
            )
            
            # Validate behavioral equivalence
            assert comparison_result['status_match'], \
                f"Status code behavior must match Node.js for {scenario['description']}"
            
            # Additional validation based on expected behavior
            if scenario['expected_behavior'] == 'validation_error_with_details':
                error_data = response.get_json()
                if error_data and 'error' in error_data:
                    error_info = error_data['error']
                    # Validation errors should include details
                    assert 'details' in error_info or 'message' in error_info, \
                        "Validation errors must include detailed information for equivalence"
    
    @pytest.mark.comparative
    def test_error_handling_performance_equivalence(
        self, 
        error_handler_client: FlaskClient,
        api_benchmark: Any
    ) -> None:
        """
        Test error handling performance equivalence with Node.js baseline.
        
        Validates that Flask error handling performance meets or
        exceeds Node.js baseline performance requirements.
        
        Args:
            error_handler_client: Flask test client for error testing
            api_benchmark: Benchmark fixture for performance testing
        """
        # Benchmark common error scenarios
        def benchmark_404_error():
            return error_handler_client.get('/api/non-existent-endpoint')
        
        def benchmark_401_error():
            return error_handler_client.get('/api/users/profile')
        
        def benchmark_validation_error():
            return error_handler_client.post(
                '/api/users',
                json={'username': '', 'email': 'invalid'},
                content_type='application/json'
            )
        
        # Run benchmarks
        error_scenarios = [
            ('404_error', benchmark_404_error),
            ('401_error', benchmark_401_error),
            ('validation_error', benchmark_validation_error)
        ]
        
        for scenario_name, benchmark_func in error_scenarios:
            result = api_benchmark(benchmark_func)
            
            # Validate performance requirements
            # Error responses should complete within reasonable time
            assert result.stats.mean < 0.1, \
                f"Error handling for {scenario_name} must complete within 100ms on average"
            
            # Error handling should be consistent
            assert result.stats.stddev < result.stats.mean * 0.5, \
                f"Error handling for {scenario_name} must have consistent performance"


# ================================================================================================
# INTEGRATION TESTS FOR CROSS-CUTTING ERROR HANDLING CONCERNS
# ================================================================================================

class TestCrossCuttingErrorHandling:
    """
    Test suite for cross-cutting error handling concerns.
    
    Validates error handling integration across multiple application
    layers including blueprints, services, and middleware.
    """
    
    @pytest.mark.integration
    def test_end_to_end_error_flow(
        self, 
        error_handler_client: FlaskClient,
        mock_validation_service: Mock,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test end-to-end error flow across application layers.
        
        Validates that errors are properly handled and transformed
        as they flow through different application layers.
        
        Args:
            error_handler_client: Flask test client for error testing
            mock_validation_service: Mock validation service
            log_capture: Log capture for error flow validation
        """
        log_stream, handler = log_capture
        
        # Test error flow from service layer to API response
        with patch('src.services.validation_service.ValidationService') as mock_validator:
            # Configure service to raise validation error
            mock_validator.return_value.validate_user_data.side_effect = \
                ValueError("User validation failed in service layer")
            
            with patch('src.services.user_service.UserService.create_user') as mock_create:
                # Configure user service to propagate validation error
                mock_create.side_effect = ValueError("User validation failed in service layer")
                
                # Make request that triggers error flow
                response = error_handler_client.post(
                    '/api/users',
                    json={'username': 'testuser', 'email': 'test@example.com'},
                    content_type='application/json'
                )
        
        # Validate error is properly handled at API layer
        assert response.status_code in [400, 422], "Service errors must be handled at API layer"
        
        error_data = response.get_json()
        assert error_data is not None, "API error response must be JSON"
        assert error_data['success'] is False, "API error success must be False"
        
        # Validate error transformation
        error_info = error_data['error']
        assert 'validation' in error_info['message'].lower() or 'user' in error_info['message'].lower()
        
        # Validate error logging across layers
        log_content = log_stream.getvalue()
        assert 'validation failed' in log_content.lower(), "Service errors must be logged"
    
    @pytest.mark.integration
    def test_database_transaction_error_handling(
        self, 
        error_handler_client: FlaskClient,
        db_session: Any,
        mock_database_errors: Dict[str, Exception],
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test database transaction error handling.
        
        Validates that database transaction errors are properly
        handled with appropriate rollback and error responses.
        
        Args:
            error_handler_client: Flask test client for error testing
            db_session: Database session for transaction testing
            mock_database_errors: Mock database error scenarios
            log_capture: Log capture for transaction error validation
        """
        log_stream, handler = log_capture
        
        # Test transaction rollback on error
        with patch('src.models.user.User.save') as mock_save:
            mock_save.side_effect = mock_database_errors['integrity_error']
            
            response = error_handler_client.post(
                '/api/users',
                json={'username': 'testuser', 'email': 'test@example.com'},
                content_type='application/json'
            )
        
        # Validate transaction error handling
        assert response.status_code == 409, "Database integrity errors should return 409 Conflict"
        
        error_data = response.get_json()
        assert error_data is not None, "Transaction error response must be JSON"
        
        error_info = error_data['error']
        assert error_info['code'] == 'CONFLICT', "Transaction error code must be CONFLICT"
        
        # Validate transaction rollback logging
        log_content = log_stream.getvalue()
        assert 'integrity' in log_content.lower() or 'constraint' in log_content.lower(), \
            "Database integrity errors must be logged"
    
    @pytest.mark.integration
    def test_async_error_handling_compatibility(
        self, 
        error_handler_client: FlaskClient,
        log_capture: Tuple[StringIO, logging.Handler]
    ) -> None:
        """
        Test async error handling compatibility.
        
        Validates that error handling works correctly with any
        async operations or background tasks.
        
        Args:
            error_handler_client: Flask test client for error testing
            log_capture: Log capture for async error validation
        """
        log_stream, handler = log_capture
        
        # Test error handling in async context (if applicable)
        # For Flask, this might involve testing with async decorators or background tasks
        
        # Simulate async operation error
        async_error_response = error_handler_client.get('/api/async-operation')
        
        # Validate async error handling (implementation depends on async framework used)
        # This is a placeholder for async-specific error handling tests
        assert async_error_response.status_code in [404, 500, 501], \
            "Async operations must handle errors appropriately"
        
        if async_error_response.is_json:
            error_data = async_error_response.get_json()
            assert 'error' in error_data, "Async errors must follow standard error format"


# ================================================================================================
# PYTEST CONFIGURATION FOR ERROR HANDLING TESTS
# ================================================================================================

def pytest_configure(config):
    """
    Configure pytest for error handling tests.
    
    Sets up test environment and markers specific to error
    handling validation requirements.
    """
    # Register error handling specific markers
    config.addinivalue_line("markers", "error_handling: mark test as error handling validation")
    config.addinivalue_line("markers", "monitoring: mark test as monitoring validation")
    config.addinivalue_line("markers", "comparative: mark test as comparative validation")


def pytest_runtest_setup(item):
    """
    Setup hook for error handling tests.
    
    Performs pre-test setup specific to error handling validation.
    """
    # Ensure Flask application is in proper error handling mode
    if hasattr(item, 'keywords') and 'error_handling' in item.keywords:
        # Configure for error handling testing
        pass


def pytest_runtest_teardown(item):
    """
    Teardown hook for error handling tests.
    
    Performs post-test cleanup for error handling validation.
    """
    # Clear any error handling state
    if hasattr(item, 'keywords') and 'error_handling' in item.keywords:
        # Clean up error handling test state
        pass