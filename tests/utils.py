"""
Test utility functions module providing common testing helpers, assertion utilities, and test data manipulation functions for consistent testing patterns across the Flask test suite.

This module implements comprehensive testing utilities replacing Node.js test helper patterns with Python-based equivalents per Section 0.2.1. It provides Flask-specific testing assertions, response validation helpers, and test data manipulation utilities supporting Factory Boy and pytest fixtures per Section 4.7.3.2.

Key Features:
- Flask-specific assertion utilities for API endpoint testing
- Response validation helpers for JSON API contracts  
- Test data manipulation utilities integrating with Factory Boy
- Performance testing helpers for pytest-benchmark integration
- Database state management utilities for test isolation
- Authentication testing utilities for Auth0 mock integration
- Error condition testing helpers for comprehensive validation
- Comparative testing utilities for Node.js parity validation

Dependencies:
- pytest: Core testing framework with Flask integration
- Factory Boy: Test data generation via factories.py
- Flask: Application testing utilities
- pytest-benchmark: Performance testing integration
"""

import json
import re
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable, Tuple
from unittest.mock import Mock, patch, MagicMock
import difflib
import hashlib

import pytest
from flask import Flask, request, session, g
from flask.testing import FlaskClient
from werkzeug.test import TestResponse
from sqlalchemy.orm import Session
from sqlalchemy import text

# Import for performance benchmarking per Section 4.7.4.1
import psutil
import gc
import sys

# Import Factory Boy utilities
from tests.factories import (
    FACTORIES, get_factory, FactoryDataManager,
    UserFactory, RoleFactory, PermissionFactory
)


# ============================================================================
# Flask Response Assertion Utilities
# ============================================================================

class FlaskResponseAssertions:
    """
    Comprehensive Flask response assertion utilities for API endpoint testing.
    
    Provides Flask-specific assertion methods for validating HTTP responses, JSON data,
    status codes, and API contract compliance per Section 4.7.1 API endpoint validation.
    
    Features:
    - Status code validation with descriptive error messages
    - JSON response structure validation
    - Header assertion utilities
    - Content type validation
    - Error response format validation
    """
    
    @staticmethod
    def assert_status_code(response: TestResponse, expected_code: int, message: str = None) -> None:
        """
        Assert HTTP status code with enhanced error reporting.
        
        Args:
            response: Flask test response object
            expected_code: Expected HTTP status code
            message: Optional custom error message
            
        Raises:
            AssertionError: If status code doesn't match with detailed context
        """
        actual_code = response.status_code
        
        if actual_code != expected_code:
            error_msg = f"Expected status code {expected_code}, got {actual_code}"
            
            if message:
                error_msg = f"{message}: {error_msg}"
            
            # Add response data for debugging
            if response.is_json:
                try:
                    response_data = response.get_json()
                    error_msg += f"\nResponse data: {json.dumps(response_data, indent=2)}"
                except Exception:
                    error_msg += f"\nResponse text: {response.get_data(as_text=True)}"
            else:
                error_msg += f"\nResponse text: {response.get_data(as_text=True)[:500]}"
            
            raise AssertionError(error_msg)
    
    @staticmethod
    def assert_json_response(response: TestResponse, expected_structure: Dict = None) -> Dict[str, Any]:
        """
        Assert response is valid JSON and optionally validate structure.
        
        Args:
            response: Flask test response object
            expected_structure: Optional dictionary defining expected JSON structure
            
        Returns:
            Parsed JSON response data
            
        Raises:
            AssertionError: If response is not valid JSON or structure doesn't match
        """
        assert response.is_json, f"Response is not JSON. Content-Type: {response.content_type}"
        
        try:
            data = response.get_json()
        except Exception as e:
            raise AssertionError(f"Failed to parse JSON response: {e}")
        
        if expected_structure:
            FlaskResponseAssertions._validate_json_structure(data, expected_structure)
        
        return data
    
    @staticmethod
    def assert_json_contains(response: TestResponse, expected_fields: List[str]) -> Dict[str, Any]:
        """
        Assert JSON response contains all required fields.
        
        Args:
            response: Flask test response object
            expected_fields: List of field names that must be present
            
        Returns:
            Parsed JSON response data
            
        Raises:
            AssertionError: If any required fields are missing
        """
        data = FlaskResponseAssertions.assert_json_response(response)
        
        missing_fields = [field for field in expected_fields if field not in data]
        
        if missing_fields:
            raise AssertionError(
                f"Missing required fields: {missing_fields}\n"
                f"Available fields: {list(data.keys())}"
            )
        
        return data
    
    @staticmethod
    def assert_json_equals(response: TestResponse, expected_data: Dict[str, Any], ignore_fields: List[str] = None) -> None:
        """
        Assert JSON response equals expected data with optional field exclusions.
        
        Args:
            response: Flask test response object
            expected_data: Expected JSON data
            ignore_fields: Fields to ignore in comparison (e.g., timestamps, IDs)
            
        Raises:
            AssertionError: If JSON data doesn't match expected values
        """
        data = FlaskResponseAssertions.assert_json_response(response)
        
        if ignore_fields:
            data = {k: v for k, v in data.items() if k not in ignore_fields}
            expected_data = {k: v for k, v in expected_data.items() if k not in ignore_fields}
        
        if data != expected_data:
            diff = difflib.unified_diff(
                json.dumps(expected_data, indent=2, sort_keys=True).splitlines(),
                json.dumps(data, indent=2, sort_keys=True).splitlines(),
                fromfile='expected',
                tofile='actual',
                lineterm=''
            )
            raise AssertionError(f"JSON data mismatch:\n{''.join(diff)}")
    
    @staticmethod
    def assert_error_response(response: TestResponse, expected_error_code: str = None, expected_message: str = None) -> Dict[str, Any]:
        """
        Assert response is a properly formatted error with expected structure.
        
        Args:
            response: Flask test response object
            expected_error_code: Expected error code in response
            expected_message: Expected error message (can be partial match)
            
        Returns:
            Parsed error response data
            
        Raises:
            AssertionError: If error response format is invalid
        """
        assert response.status_code >= 400, f"Expected error status code (>=400), got {response.status_code}"
        
        data = FlaskResponseAssertions.assert_json_response(response)
        
        # Validate error response structure
        required_fields = ['error', 'message']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            raise AssertionError(f"Error response missing required fields: {missing_fields}")
        
        if expected_error_code and data.get('error') != expected_error_code:
            raise AssertionError(f"Expected error code '{expected_error_code}', got '{data.get('error')}'")
        
        if expected_message and expected_message not in data.get('message', ''):
            raise AssertionError(f"Expected message to contain '{expected_message}', got '{data.get('message')}'")
        
        return data
    
    @staticmethod
    def assert_pagination_response(response: TestResponse, expected_total: int = None) -> Dict[str, Any]:
        """
        Assert response contains proper pagination metadata.
        
        Args:
            response: Flask test response object
            expected_total: Expected total count of items
            
        Returns:
            Parsed pagination response data
            
        Raises:
            AssertionError: If pagination structure is invalid
        """
        data = FlaskResponseAssertions.assert_json_response(response)
        
        required_fields = ['data', 'pagination']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            raise AssertionError(f"Pagination response missing required fields: {missing_fields}")
        
        pagination = data['pagination']
        pagination_fields = ['page', 'per_page', 'total', 'pages']
        missing_pagination_fields = [field for field in pagination_fields if field not in pagination]
        
        if missing_pagination_fields:
            raise AssertionError(f"Pagination metadata missing fields: {missing_pagination_fields}")
        
        if expected_total is not None and pagination['total'] != expected_total:
            raise AssertionError(f"Expected total {expected_total}, got {pagination['total']}")
        
        return data
    
    @staticmethod
    def assert_content_type(response: TestResponse, expected_content_type: str) -> None:
        """
        Assert response has expected Content-Type header.
        
        Args:
            response: Flask test response object
            expected_content_type: Expected Content-Type value
            
        Raises:
            AssertionError: If Content-Type doesn't match
        """
        actual_content_type = response.content_type
        
        if expected_content_type not in actual_content_type:
            raise AssertionError(
                f"Expected Content-Type to contain '{expected_content_type}', "
                f"got '{actual_content_type}'"
            )
    
    @staticmethod
    def assert_headers_present(response: TestResponse, required_headers: List[str]) -> None:
        """
        Assert response contains all required headers.
        
        Args:
            response: Flask test response object
            required_headers: List of header names that must be present
            
        Raises:
            AssertionError: If any required headers are missing
        """
        missing_headers = [header for header in required_headers if header not in response.headers]
        
        if missing_headers:
            raise AssertionError(
                f"Missing required headers: {missing_headers}\n"
                f"Available headers: {list(response.headers.keys())}"
            )
    
    @staticmethod
    def _validate_json_structure(data: Any, expected_structure: Dict) -> None:
        """
        Recursively validate JSON structure against expected schema.
        
        Args:
            data: Actual JSON data
            expected_structure: Expected structure definition
            
        Raises:
            AssertionError: If structure doesn't match
        """
        if isinstance(expected_structure, dict):
            if not isinstance(data, dict):
                raise AssertionError(f"Expected dict, got {type(data)}")
            
            for key, expected_value in expected_structure.items():
                if key not in data:
                    raise AssertionError(f"Missing key: {key}")
                
                if isinstance(expected_value, type):
                    if not isinstance(data[key], expected_value):
                        raise AssertionError(f"Key '{key}': expected {expected_value}, got {type(data[key])}")
                elif isinstance(expected_value, dict):
                    FlaskResponseAssertions._validate_json_structure(data[key], expected_value)
                elif isinstance(expected_value, list) and expected_value:
                    if not isinstance(data[key], list):
                        raise AssertionError(f"Key '{key}': expected list, got {type(data[key])}")
                    if data[key] and expected_value:
                        FlaskResponseAssertions._validate_json_structure(data[key][0], expected_value[0])


# ============================================================================
# API Testing Utilities
# ============================================================================

class APITestHelpers:
    """
    Comprehensive API testing utilities for Flask endpoint validation.
    
    Provides high-level testing methods for common API testing patterns including
    CRUD operations, authentication flows, and error condition testing per
    Section 4.7.1 API endpoints testing.
    """
    
    def __init__(self, client: FlaskClient, response_assertions: FlaskResponseAssertions = None):
        """
        Initialize API test helpers with Flask test client.
        
        Args:
            client: Flask test client for making requests
            response_assertions: Optional custom response assertion utilities
        """
        self.client = client
        self.assertions = response_assertions or FlaskResponseAssertions()
    
    def get_json(self, url: str, headers: Dict[str, str] = None, expected_status: int = 200) -> Dict[str, Any]:
        """
        Perform GET request and return JSON response with validation.
        
        Args:
            url: Request URL
            headers: Optional request headers
            expected_status: Expected HTTP status code
            
        Returns:
            Parsed JSON response data
        """
        response = self.client.get(url, headers=headers)
        self.assertions.assert_status_code(response, expected_status)
        return self.assertions.assert_json_response(response)
    
    def post_json(self, url: str, data: Dict[str, Any], headers: Dict[str, str] = None, expected_status: int = 201) -> Dict[str, Any]:
        """
        Perform POST request with JSON data and return response.
        
        Args:
            url: Request URL
            data: JSON data to send
            headers: Optional request headers
            expected_status: Expected HTTP status code
            
        Returns:
            Parsed JSON response data
        """
        headers = headers or {}
        headers.setdefault('Content-Type', 'application/json')
        
        response = self.client.post(url, data=json.dumps(data), headers=headers)
        self.assertions.assert_status_code(response, expected_status)
        return self.assertions.assert_json_response(response)
    
    def put_json(self, url: str, data: Dict[str, Any], headers: Dict[str, str] = None, expected_status: int = 200) -> Dict[str, Any]:
        """
        Perform PUT request with JSON data and return response.
        
        Args:
            url: Request URL
            data: JSON data to send
            headers: Optional request headers
            expected_status: Expected HTTP status code
            
        Returns:
            Parsed JSON response data
        """
        headers = headers or {}
        headers.setdefault('Content-Type', 'application/json')
        
        response = self.client.put(url, data=json.dumps(data), headers=headers)
        self.assertions.assert_status_code(response, expected_status)
        return self.assertions.assert_json_response(response)
    
    def patch_json(self, url: str, data: Dict[str, Any], headers: Dict[str, str] = None, expected_status: int = 200) -> Dict[str, Any]:
        """
        Perform PATCH request with JSON data and return response.
        
        Args:
            url: Request URL
            data: JSON data to send
            headers: Optional request headers
            expected_status: Expected HTTP status code
            
        Returns:
            Parsed JSON response data
        """
        headers = headers or {}
        headers.setdefault('Content-Type', 'application/json')
        
        response = self.client.patch(url, data=json.dumps(data), headers=headers)
        self.assertions.assert_status_code(response, expected_status)
        return self.assertions.assert_json_response(response)
    
    def delete_json(self, url: str, headers: Dict[str, str] = None, expected_status: int = 204) -> Optional[Dict[str, Any]]:
        """
        Perform DELETE request and return response if JSON.
        
        Args:
            url: Request URL
            headers: Optional request headers
            expected_status: Expected HTTP status code
            
        Returns:
            Parsed JSON response data if present, None otherwise
        """
        response = self.client.delete(url, headers=headers)
        self.assertions.assert_status_code(response, expected_status)
        
        if response.is_json and response.get_data():
            return self.assertions.assert_json_response(response)
        
        return None
    
    def test_crud_operations(self, base_url: str, create_data: Dict[str, Any], 
                           update_data: Dict[str, Any], auth_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Test complete CRUD operations for a resource endpoint.
        
        Args:
            base_url: Base URL for the resource (e.g., '/api/users')
            create_data: Data for POST request
            update_data: Data for PUT/PATCH request
            auth_headers: Optional authentication headers
            
        Returns:
            Dictionary containing results of all CRUD operations
        """
        results = {}
        
        # CREATE
        created_item = self.post_json(base_url, create_data, auth_headers, expected_status=201)
        results['create'] = created_item
        
        item_id = created_item.get('id')
        assert item_id, "Created item must have an 'id' field"
        
        item_url = f"{base_url}/{item_id}"
        
        # READ (individual)
        retrieved_item = self.get_json(item_url, auth_headers, expected_status=200)
        results['read'] = retrieved_item
        
        # READ (list)
        items_list = self.get_json(base_url, auth_headers, expected_status=200)
        results['list'] = items_list
        
        # UPDATE
        updated_item = self.put_json(item_url, update_data, auth_headers, expected_status=200)
        results['update'] = updated_item
        
        # DELETE
        self.delete_json(item_url, auth_headers, expected_status=204)
        results['delete'] = True
        
        # Verify deletion
        response = self.client.get(item_url, headers=auth_headers)
        self.assertions.assert_status_code(response, 404)
        
        return results
    
    def test_error_conditions(self, url: str, test_cases: List[Dict[str, Any]], method: str = 'POST') -> List[Dict[str, Any]]:
        """
        Test various error conditions for an endpoint.
        
        Args:
            url: Endpoint URL to test
            test_cases: List of test case dictionaries with 'data', 'expected_status', 'expected_error'
            method: HTTP method to use
            
        Returns:
            List of test results
        """
        results = []
        
        for test_case in test_cases:
            data = test_case.get('data', {})
            expected_status = test_case.get('expected_status', 400)
            expected_error = test_case.get('expected_error')
            headers = test_case.get('headers', {'Content-Type': 'application/json'})
            
            if method.upper() == 'POST':
                response = self.client.post(url, data=json.dumps(data), headers=headers)
            elif method.upper() == 'PUT':
                response = self.client.put(url, data=json.dumps(data), headers=headers)
            elif method.upper() == 'PATCH':
                response = self.client.patch(url, data=json.dumps(data), headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            self.assertions.assert_status_code(response, expected_status)
            error_data = self.assertions.assert_error_response(response, expected_error_code=expected_error)
            
            results.append({
                'test_case': test_case,
                'response': error_data,
                'passed': True
            })
        
        return results


# ============================================================================
# Test Data Manipulation Utilities
# ============================================================================

class TestDataManager:
    """
    Test data manipulation utilities integrating with Factory Boy patterns.
    
    Provides high-level utilities for test data creation, modification, and cleanup
    supporting Factory Boy integration per Section 4.7.3.2 test data management.
    """
    
    def __init__(self, db_session: Session, factory_manager: FactoryDataManager = None):
        """
        Initialize test data manager with database session.
        
        Args:
            db_session: SQLAlchemy session for database operations
            factory_manager: Optional Factory Boy data manager
        """
        self.db_session = db_session
        self.factory_manager = factory_manager or FactoryDataManager()
        self._created_objects = []
    
    def create_test_user(self, **kwargs) -> Any:
        """
        Create test user with optional customizations.
        
        Args:
            **kwargs: User factory parameters
            
        Returns:
            Created user instance
        """
        user = UserFactory(**kwargs)
        self._created_objects.append(user)
        return user
    
    def create_authenticated_user(self, permissions: List[str] = None) -> Any:
        """
        Create user with authentication and specific permissions.
        
        Args:
            permissions: List of permission names to assign
            
        Returns:
            User with authentication and permissions configured
        """
        user = self.create_test_user(is_active=True, email_verified=True)
        
        if permissions:
            # Create role with specified permissions
            role = RoleFactory(name=f"test_role_{uuid.uuid4().hex[:8]}")
            
            for permission_name in permissions:
                # Parse permission name (e.g., 'users:read' -> resource='users', action='read')
                if ':' in permission_name:
                    resource, action = permission_name.split(':', 1)
                    permission = PermissionFactory(resource=resource, action=action)
                    role.permissions.append(permission)
            
            user.roles.append(role)
            self.db_session.commit()
        
        return user
    
    def create_test_dataset(self, dataset_config: Dict[str, Any]) -> Dict[str, List[Any]]:
        """
        Create comprehensive test dataset based on configuration.
        
        Args:
            dataset_config: Configuration dictionary defining what to create
                Example: {
                    'users': {'count': 5, 'factory_params': {}},
                    'roles': {'count': 3, 'factory_params': {'is_active': True}}
                }
        
        Returns:
            Dictionary mapping entity types to created instances
        """
        dataset = {}
        
        for entity_type, config in dataset_config.items():
            count = config.get('count', 1)
            factory_params = config.get('factory_params', {})
            
            factory = get_factory(entity_type)
            instances = factory.create_batch(count, **factory_params)
            dataset[entity_type] = instances
            self._created_objects.extend(instances)
        
        return dataset
    
    def create_related_objects(self, parent_object: Any, relationships: Dict[str, Dict]) -> Dict[str, List[Any]]:
        """
        Create related objects for a parent instance.
        
        Args:
            parent_object: Parent object to create relationships for
            relationships: Dictionary defining relationships to create
                Example: {
                    'sessions': {'count': 2, 'factory_params': {}},
                    'audit_logs': {'count': 5, 'factory_params': {'operation_type': 'UPDATE'}}
                }
        
        Returns:
            Dictionary mapping relationship names to created objects
        """
        related_objects = {}
        
        for relationship_name, config in relationships.items():
            count = config.get('count', 1)
            factory_params = config.get('factory_params', {})
            
            # Add parent relationship
            if hasattr(parent_object, 'id'):
                if 'user' in relationship_name:
                    factory_params['user'] = parent_object
                elif 'owner' in relationship_name:
                    factory_params['owner'] = parent_object
            
            factory = get_factory(relationship_name.rstrip('s'))  # Remove 's' from plural
            instances = factory.create_batch(count, **factory_params)
            related_objects[relationship_name] = instances
            self._created_objects.extend(instances)
        
        return related_objects
    
    def modify_object(self, obj: Any, changes: Dict[str, Any]) -> Any:
        """
        Modify object attributes and commit changes.
        
        Args:
            obj: Object to modify
            changes: Dictionary of attribute changes
            
        Returns:
            Modified object
        """
        for attr, value in changes.items():
            setattr(obj, attr, value)
        
        self.db_session.commit()
        return obj
    
    def cleanup_created_objects(self) -> None:
        """
        Clean up all objects created during test execution.
        """
        for obj in reversed(self._created_objects):
            try:
                self.db_session.delete(obj)
            except Exception:
                pass  # Object may already be deleted
        
        try:
            self.db_session.commit()
        except Exception:
            self.db_session.rollback()
        
        self._created_objects.clear()
    
    def snapshot_database_state(self) -> Dict[str, int]:
        """
        Create snapshot of current database state for comparison.
        
        Returns:
            Dictionary mapping table names to record counts
        """
        state = {}
        
        # Get all table names from metadata
        for table in self.db_session.get_bind().metadata.tables.values():
            try:
                count = self.db_session.execute(text(f"SELECT COUNT(*) FROM {table.name}")).scalar()
                state[table.name] = count
            except Exception:
                state[table.name] = 0
        
        return state
    
    def compare_database_states(self, before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
        """
        Compare two database state snapshots.
        
        Args:
            before: Database state before operation
            after: Database state after operation
            
        Returns:
            Dictionary showing changes in record counts
        """
        changes = {}
        
        all_tables = set(before.keys()) | set(after.keys())
        
        for table in all_tables:
            before_count = before.get(table, 0)
            after_count = after.get(table, 0)
            change = after_count - before_count
            
            if change != 0:
                changes[table] = change
        
        return changes


# ============================================================================
# Authentication Testing Utilities
# ============================================================================

class AuthTestHelpers:
    """
    Authentication testing utilities for Auth0 mock integration and session management.
    
    Provides utilities for testing authentication flows, session management,
    and authorization patterns per Section 3.6.3 authentication fixtures.
    """
    
    @staticmethod
    def create_mock_jwt_token(user_data: Dict[str, Any], expiry_hours: int = 1) -> str:
        """
        Create mock JWT token for testing authentication.
        
        Args:
            user_data: User data to include in token payload
            expiry_hours: Token expiry time in hours
            
        Returns:
            Mock JWT token string for testing
        """
        import base64
        
        header = {
            "typ": "JWT",
            "alg": "RS256",
            "kid": "test-key-id"
        }
        
        payload = {
            "iss": "https://test-domain.auth0.com/",
            "sub": user_data.get('id', 'test-user-id'),
            "aud": "test_audience",
            "iat": int(time.time()),
            "exp": int(time.time()) + (expiry_hours * 3600),
            "email": user_data.get('email', 'test@example.com'),
            "name": user_data.get('name', 'Test User'),
            "email_verified": user_data.get('email_verified', True)
        }
        
        # Encode components (simplified for testing)
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature = "mock-signature-for-testing"
        
        return f"{header_encoded}.{payload_encoded}.{signature}"
    
    @staticmethod
    def create_auth_headers(user_data: Dict[str, Any] = None, token: str = None) -> Dict[str, str]:
        """
        Create authentication headers for API testing.
        
        Args:
            user_data: User data for token generation
            token: Existing token to use
            
        Returns:
            Authentication headers dictionary
        """
        if token is None:
            user_data = user_data or {'id': 'test-user', 'email': 'test@example.com'}
            token = AuthTestHelpers.create_mock_jwt_token(user_data)
        
        return {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'X-User-ID': user_data.get('id', 'test-user') if user_data else 'test-user'
        }
    
    @staticmethod
    @contextmanager
    def mock_auth0_service(user_profile: Dict[str, Any] = None):
        """
        Context manager for mocking Auth0 service responses.
        
        Args:
            user_profile: User profile data to return from Auth0
            
        Yields:
            Mock Auth0 service context
        """
        default_profile = {
            'sub': 'test-user-id',
            'email': 'test@example.com',
            'name': 'Test User',
            'picture': 'https://example.com/avatar.jpg',
            'email_verified': True
        }
        
        profile = {**default_profile, **(user_profile or {})}
        
        with patch('auth0.authentication.Users') as mock_users:
            with patch('auth0.management.Auth0') as mock_management:
                # Configure mock responses
                mock_users.return_value.userinfo.return_value = profile
                mock_management.return_value.users.get.return_value = {
                    **profile,
                    'user_id': profile['sub'],
                    'app_metadata': {'roles': ['user']},
                    'user_metadata': {'preferences': {}}
                }
                
                yield {
                    'users': mock_users,
                    'management': mock_management,
                    'profile': profile
                }
    
    @staticmethod
    def assert_authenticated_request(response: TestResponse) -> None:
        """
        Assert that request was properly authenticated.
        
        Args:
            response: Flask test response
            
        Raises:
            AssertionError: If authentication assertion fails
        """
        if response.status_code == 401:
            raise AssertionError("Request was not authenticated (401 Unauthorized)")
        
        if response.status_code == 403:
            raise AssertionError("Request was not authorized (403 Forbidden)")
    
    @staticmethod
    def assert_unauthenticated_request(response: TestResponse) -> None:
        """
        Assert that unauthenticated request was properly rejected.
        
        Args:
            response: Flask test response
            
        Raises:
            AssertionError: If unauthenticated request was not rejected
        """
        if response.status_code not in [401, 403]:
            raise AssertionError(f"Expected 401 or 403 for unauthenticated request, got {response.status_code}")
    
    @staticmethod
    def test_endpoint_authentication(client: FlaskClient, endpoint: str, method: str = 'GET', 
                                   data: Dict[str, Any] = None) -> Dict[str, TestResponse]:
        """
        Test endpoint authentication requirements.
        
        Args:
            client: Flask test client
            endpoint: Endpoint URL to test
            method: HTTP method
            data: Optional request data
            
        Returns:
            Dictionary with authenticated and unauthenticated responses
        """
        results = {}
        
        # Test unauthenticated request
        if method.upper() == 'GET':
            results['unauthenticated'] = client.get(endpoint)
        elif method.upper() == 'POST':
            results['unauthenticated'] = client.post(
                endpoint, 
                data=json.dumps(data) if data else None,
                content_type='application/json'
            )
        elif method.upper() == 'PUT':
            results['unauthenticated'] = client.put(
                endpoint,
                data=json.dumps(data) if data else None,
                content_type='application/json'
            )
        elif method.upper() == 'DELETE':
            results['unauthenticated'] = client.delete(endpoint)
        
        # Test authenticated request
        auth_headers = AuthTestHelpers.create_auth_headers()
        
        if method.upper() == 'GET':
            results['authenticated'] = client.get(endpoint, headers=auth_headers)
        elif method.upper() == 'POST':
            results['authenticated'] = client.post(
                endpoint,
                data=json.dumps(data) if data else None,
                headers=auth_headers
            )
        elif method.upper() == 'PUT':
            results['authenticated'] = client.put(
                endpoint,
                data=json.dumps(data) if data else None,
                headers=auth_headers
            )
        elif method.upper() == 'DELETE':
            results['authenticated'] = client.delete(endpoint, headers=auth_headers)
        
        return results


# ============================================================================
# Performance Testing Utilities
# ============================================================================

class PerformanceTestHelpers:
    """
    Performance testing utilities for pytest-benchmark integration.
    
    Provides utilities for response time measurement, memory usage profiling,
    and SLA compliance validation per Section 4.7.4.1 performance benchmarking.
    """
    
    @staticmethod
    def measure_response_time(func: Callable, *args, **kwargs) -> Tuple[Any, float]:
        """
        Measure function execution time with high precision.
        
        Args:
            func: Function to measure
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function_result, execution_time_seconds)
        """
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        
        execution_time = end_time - start_time
        return result, execution_time
    
    @staticmethod
    def measure_memory_usage(func: Callable, *args, **kwargs) -> Tuple[Any, Dict[str, float]]:
        """
        Measure memory usage during function execution.
        
        Args:
            func: Function to measure
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function_result, memory_stats)
        """
        process = psutil.Process()
        
        # Force garbage collection for accurate measurement
        gc.collect()
        
        # Get initial memory usage
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Execute function
        result = func(*args, **kwargs)
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_stats = {
            'initial_mb': initial_memory,
            'final_mb': final_memory,
            'peak_mb': process.memory_info().peak_wss / 1024 / 1024 if hasattr(process.memory_info(), 'peak_wss') else final_memory,
            'delta_mb': final_memory - initial_memory
        }
        
        return result, memory_stats
    
    @staticmethod
    def benchmark_api_endpoint(client: FlaskClient, endpoint: str, method: str = 'GET',
                             data: Dict[str, Any] = None, headers: Dict[str, str] = None,
                             iterations: int = 10) -> Dict[str, Any]:
        """
        Benchmark API endpoint performance with statistical analysis.
        
        Args:
            client: Flask test client
            endpoint: Endpoint URL to benchmark
            method: HTTP method
            data: Optional request data
            headers: Optional request headers
            iterations: Number of iterations for statistical accuracy
            
        Returns:
            Performance statistics dictionary
        """
        response_times = []
        status_codes = []
        
        for i in range(iterations):
            start_time = time.perf_counter()
            
            if method.upper() == 'GET':
                response = client.get(endpoint, headers=headers)
            elif method.upper() == 'POST':
                response = client.post(
                    endpoint,
                    data=json.dumps(data) if data else None,
                    headers=headers
                )
            elif method.upper() == 'PUT':
                response = client.put(
                    endpoint,
                    data=json.dumps(data) if data else None,
                    headers=headers
                )
            elif method.upper() == 'DELETE':
                response = client.delete(endpoint, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            end_time = time.perf_counter()
            
            response_times.append(end_time - start_time)
            status_codes.append(response.status_code)
        
        # Calculate statistics
        avg_time = sum(response_times) / len(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        
        # Calculate percentiles
        sorted_times = sorted(response_times)
        p50 = sorted_times[len(sorted_times) // 2]
        p95 = sorted_times[int(len(sorted_times) * 0.95)]
        p99 = sorted_times[int(len(sorted_times) * 0.99)]
        
        return {
            'iterations': iterations,
            'avg_response_time': avg_time,
            'min_response_time': min_time,
            'max_response_time': max_time,
            'p50_response_time': p50,
            'p95_response_time': p95,
            'p99_response_time': p99,
            'status_codes': status_codes,
            'success_rate': status_codes.count(200) / len(status_codes) if status_codes else 0
        }
    
    @staticmethod
    def assert_performance_sla(stats: Dict[str, Any], max_avg_response_time: float = 0.2,
                             max_p95_response_time: float = 0.5, min_success_rate: float = 0.99) -> None:
        """
        Assert performance statistics meet SLA requirements.
        
        Args:
            stats: Performance statistics from benchmark
            max_avg_response_time: Maximum average response time in seconds
            max_p95_response_time: Maximum 95th percentile response time
            min_success_rate: Minimum success rate (0.0-1.0)
            
        Raises:
            AssertionError: If SLA requirements are not met
        """
        avg_time = stats['avg_response_time']
        p95_time = stats['p95_response_time']
        success_rate = stats['success_rate']
        
        if avg_time > max_avg_response_time:
            raise AssertionError(
                f"Average response time {avg_time:.3f}s exceeds SLA limit {max_avg_response_time:.3f}s"
            )
        
        if p95_time > max_p95_response_time:
            raise AssertionError(
                f"95th percentile response time {p95_time:.3f}s exceeds SLA limit {max_p95_response_time:.3f}s"
            )
        
        if success_rate < min_success_rate:
            raise AssertionError(
                f"Success rate {success_rate:.3f} is below SLA minimum {min_success_rate:.3f}"
            )


# ============================================================================
# Comparative Testing Utilities
# ============================================================================

class ComparativeTestHelpers:
    """
    Comparative testing utilities for Node.js to Flask parity validation.
    
    Provides utilities for comparing responses between systems and validating
    functional parity per Section 4.7.2 comparative testing process.
    """
    
    @staticmethod
    def compare_json_responses(response1: Dict[str, Any], response2: Dict[str, Any],
                             ignore_fields: List[str] = None, tolerance: float = 1e-6) -> Dict[str, Any]:
        """
        Compare two JSON responses with optional field exclusions and numeric tolerance.
        
        Args:
            response1: First response data
            response2: Second response data
            ignore_fields: Fields to ignore in comparison
            tolerance: Numeric comparison tolerance
            
        Returns:
            Comparison result dictionary
        """
        ignore_fields = ignore_fields or ['timestamp', 'created_at', 'updated_at', 'id']
        
        def normalize_response(data: Any, ignore_list: List[str]) -> Any:
            """Recursively normalize response data for comparison."""
            if isinstance(data, dict):
                return {k: normalize_response(v, ignore_list) 
                       for k, v in data.items() if k not in ignore_list}
            elif isinstance(data, list):
                return [normalize_response(item, ignore_list) for item in data]
            elif isinstance(data, float):
                return round(data, 10)  # Normalize float precision
            else:
                return data
        
        normalized1 = normalize_response(response1, ignore_fields)
        normalized2 = normalize_response(response2, ignore_fields)
        
        differences = []
        
        def find_differences(path: str, val1: Any, val2: Any) -> None:
            """Recursively find differences between values."""
            if type(val1) != type(val2):
                differences.append({
                    'path': path,
                    'type': 'type_mismatch',
                    'value1': val1,
                    'value2': val2
                })
            elif isinstance(val1, dict):
                all_keys = set(val1.keys()) | set(val2.keys())
                for key in all_keys:
                    new_path = f"{path}.{key}" if path else key
                    if key not in val1:
                        differences.append({
                            'path': new_path,
                            'type': 'missing_in_first',
                            'value2': val2[key]
                        })
                    elif key not in val2:
                        differences.append({
                            'path': new_path,
                            'type': 'missing_in_second',
                            'value1': val1[key]
                        })
                    else:
                        find_differences(new_path, val1[key], val2[key])
            elif isinstance(val1, list):
                if len(val1) != len(val2):
                    differences.append({
                        'path': path,
                        'type': 'length_mismatch',
                        'length1': len(val1),
                        'length2': len(val2)
                    })
                else:
                    for i, (item1, item2) in enumerate(zip(val1, val2)):
                        find_differences(f"{path}[{i}]", item1, item2)
            elif isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                if abs(val1 - val2) > tolerance:
                    differences.append({
                        'path': path,
                        'type': 'numeric_difference',
                        'value1': val1,
                        'value2': val2,
                        'difference': abs(val1 - val2)
                    })
            elif val1 != val2:
                differences.append({
                    'path': path,
                    'type': 'value_mismatch',
                    'value1': val1,
                    'value2': val2
                })
        
        find_differences('', normalized1, normalized2)
        
        return {
            'identical': len(differences) == 0,
            'differences': differences,
            'difference_count': len(differences),
            'normalized_data1': normalized1,
            'normalized_data2': normalized2
        }
    
    @staticmethod
    def generate_comparison_report(comparisons: List[Dict[str, Any]], endpoint: str) -> str:
        """
        Generate comprehensive comparison report for parity validation.
        
        Args:
            comparisons: List of comparison results
            endpoint: Endpoint being tested
            
        Returns:
            Formatted comparison report
        """
        total_comparisons = len(comparisons)
        identical_count = sum(1 for comp in comparisons if comp['identical'])
        success_rate = identical_count / total_comparisons if total_comparisons > 0 else 0
        
        report = f"""
Functional Parity Comparison Report
==================================
Endpoint: {endpoint}
Total Comparisons: {total_comparisons}
Identical Responses: {identical_count}
Success Rate: {success_rate:.2%}

"""
        
        if identical_count < total_comparisons:
            report += "Differences Found:\n"
            report += "-" * 20 + "\n"
            
            for i, comparison in enumerate(comparisons):
                if not comparison['identical']:
                    report += f"\nComparison {i+1}:\n"
                    for diff in comparison['differences']:
                        report += f"  Path: {diff['path']}\n"
                        report += f"  Type: {diff['type']}\n"
                        if 'value1' in diff:
                            report += f"  Value 1: {diff['value1']}\n"
                        if 'value2' in diff:
                            report += f"  Value 2: {diff['value2']}\n"
                        report += "\n"
        
        return report


# ============================================================================
# Database Testing Utilities
# ============================================================================

class DatabaseTestHelpers:
    """
    Database testing utilities for SQLAlchemy model validation and state management.
    
    Provides utilities for database state management, transaction testing,
    and model validation per Section 4.7.3.1 database testing setup.
    """
    
    def __init__(self, db_session: Session):
        """
        Initialize database test helpers.
        
        Args:
            db_session: SQLAlchemy session for database operations
        """
        self.db_session = db_session
    
    def assert_record_count(self, model_class: Any, expected_count: int, filter_kwargs: Dict[str, Any] = None) -> None:
        """
        Assert database table has expected number of records.
        
        Args:
            model_class: SQLAlchemy model class
            expected_count: Expected number of records
            filter_kwargs: Optional filter conditions
            
        Raises:
            AssertionError: If record count doesn't match
        """
        query = self.db_session.query(model_class)
        
        if filter_kwargs:
            query = query.filter_by(**filter_kwargs)
        
        actual_count = query.count()
        
        if actual_count != expected_count:
            raise AssertionError(
                f"Expected {expected_count} records in {model_class.__name__}, "
                f"got {actual_count}"
            )
    
    def assert_record_exists(self, model_class: Any, **filter_kwargs) -> Any:
        """
        Assert record exists in database and return it.
        
        Args:
            model_class: SQLAlchemy model class
            **filter_kwargs: Filter conditions
            
        Returns:
            Found record
            
        Raises:
            AssertionError: If record doesn't exist
        """
        record = self.db_session.query(model_class).filter_by(**filter_kwargs).first()
        
        if record is None:
            raise AssertionError(
                f"No record found in {model_class.__name__} with conditions: {filter_kwargs}"
            )
        
        return record
    
    def assert_record_not_exists(self, model_class: Any, **filter_kwargs) -> None:
        """
        Assert record does not exist in database.
        
        Args:
            model_class: SQLAlchemy model class
            **filter_kwargs: Filter conditions
            
        Raises:
            AssertionError: If record exists
        """
        record = self.db_session.query(model_class).filter_by(**filter_kwargs).first()
        
        if record is not None:
            raise AssertionError(
                f"Record found in {model_class.__name__} with conditions: {filter_kwargs} "
                f"when it should not exist"
            )
    
    @contextmanager
    def transaction_rollback(self):
        """
        Context manager for testing database operations with automatic rollback.
        
        Yields:
            Database session that will be rolled back after context
        """
        savepoint = self.db_session.begin_nested()
        
        try:
            yield self.db_session
        finally:
            savepoint.rollback()
    
    def validate_model_constraints(self, model_instance: Any, expected_violations: List[str] = None) -> List[str]:
        """
        Validate model instance against database constraints.
        
        Args:
            model_instance: Model instance to validate
            expected_violations: List of expected constraint violations
            
        Returns:
            List of constraint violations found
        """
        violations = []
        
        try:
            self.db_session.add(model_instance)
            self.db_session.flush()  # Trigger constraint checks without commit
        except Exception as e:
            violations.append(str(e))
        finally:
            self.db_session.rollback()
        
        if expected_violations:
            for expected in expected_violations:
                if not any(expected in violation for violation in violations):
                    raise AssertionError(f"Expected constraint violation '{expected}' not found")
        
        return violations


# ============================================================================
# Utility Functions and Helpers
# ============================================================================

def wait_for_condition(condition: Callable[[], bool], timeout: float = 5.0, 
                      interval: float = 0.1, error_message: str = None) -> bool:
    """
    Wait for a condition to become true with timeout.
    
    Args:
        condition: Function that returns True when condition is met
        timeout: Maximum time to wait in seconds
        interval: Check interval in seconds
        error_message: Custom error message if timeout occurs
        
    Returns:
        True if condition was met, False if timeout
        
    Raises:
        AssertionError: If condition is not met within timeout and error_message provided
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if condition():
            return True
        time.sleep(interval)
    
    if error_message:
        raise AssertionError(f"Condition not met within {timeout}s: {error_message}")
    
    return False


def generate_unique_string(prefix: str = "test", length: int = 8) -> str:
    """
    Generate unique string for test data.
    
    Args:
        prefix: String prefix
        length: Length of random suffix
        
    Returns:
        Unique string with prefix and random suffix
    """
    import random
    import string
    
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}_{suffix}"


def create_temporary_file(content: str = "", suffix: str = ".tmp") -> str:
    """
    Create temporary file for testing file operations.
    
    Args:
        content: File content
        suffix: File suffix
        
    Returns:
        Path to created temporary file
    """
    import tempfile
    
    fd, path = tempfile.mkstemp(suffix=suffix)
    
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
    except Exception:
        os.close(fd)
        raise
    
    return path


def normalize_json_for_comparison(data: Any) -> Any:
    """
    Normalize JSON data for consistent comparison between systems.
    
    Args:
        data: JSON data to normalize
        
    Returns:
        Normalized JSON data
    """
    if isinstance(data, dict):
        # Sort dictionary keys and normalize values
        return {k: normalize_json_for_comparison(v) for k, v in sorted(data.items())}
    elif isinstance(data, list):
        # Sort lists if they contain dictionaries with 'id' field
        if data and isinstance(data[0], dict) and 'id' in data[0]:
            return sorted([normalize_json_for_comparison(item) for item in data], 
                         key=lambda x: x.get('id', ''))
        else:
            return [normalize_json_for_comparison(item) for item in data]
    elif isinstance(data, float):
        # Round floats to avoid precision issues
        return round(data, 10)
    else:
        return data


def hash_response_content(response_data: Dict[str, Any], ignore_fields: List[str] = None) -> str:
    """
    Generate hash of response content for comparison caching.
    
    Args:
        response_data: Response data to hash
        ignore_fields: Fields to ignore when hashing
        
    Returns:
        SHA256 hash of normalized response content
    """
    ignore_fields = ignore_fields or ['timestamp', 'created_at', 'updated_at']
    
    # Remove ignored fields
    filtered_data = {k: v for k, v in response_data.items() if k not in ignore_fields}
    
    # Normalize and stringify
    normalized = normalize_json_for_comparison(filtered_data)
    content_string = json.dumps(normalized, sort_keys=True)
    
    # Generate hash
    return hashlib.sha256(content_string.encode()).hexdigest()


# ============================================================================
# Test Suite Utilities
# ============================================================================

class TestSuiteHelpers:
    """
    High-level test suite utilities for comprehensive testing workflows.
    
    Provides utilities for running complete test suites, generating reports,
    and managing test execution workflows per Section 4.7 testing strategy.
    """
    
    def __init__(self, client: FlaskClient, db_session: Session):
        """
        Initialize test suite helpers.
        
        Args:
            client: Flask test client
            db_session: Database session
        """
        self.client = client
        self.db_session = db_session
        self.api_helpers = APITestHelpers(client)
        self.auth_helpers = AuthTestHelpers()
        self.db_helpers = DatabaseTestHelpers(db_session)
        self.data_manager = TestDataManager(db_session)
        self.performance_helpers = PerformanceTestHelpers()
    
    def run_endpoint_test_suite(self, endpoint_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run comprehensive test suite for an API endpoint.
        
        Args:
            endpoint_config: Configuration for endpoint testing
                Example: {
                    'url': '/api/users',
                    'methods': ['GET', 'POST', 'PUT', 'DELETE'],
                    'auth_required': True,
                    'test_data': {...},
                    'performance_sla': {...}
                }
        
        Returns:
            Complete test results dictionary
        """
        results = {
            'endpoint': endpoint_config['url'],
            'auth_tests': {},
            'crud_tests': {},
            'error_tests': {},
            'performance_tests': {},
            'passed': True,
            'errors': []
        }
        
        try:
            # Authentication tests
            if endpoint_config.get('auth_required', False):
                for method in endpoint_config.get('methods', ['GET']):
                    auth_results = self.auth_helpers.test_endpoint_authentication(
                        self.client, endpoint_config['url'], method,
                        endpoint_config.get('test_data', {})
                    )
                    results['auth_tests'][method] = auth_results
            
            # CRUD operation tests
            if endpoint_config.get('test_data'):
                crud_results = self.api_helpers.test_crud_operations(
                    endpoint_config['url'],
                    endpoint_config['test_data'],
                    endpoint_config.get('update_data', {}),
                    self.auth_helpers.create_auth_headers() if endpoint_config.get('auth_required') else None
                )
                results['crud_tests'] = crud_results
            
            # Error condition tests
            if endpoint_config.get('error_test_cases'):
                error_results = self.api_helpers.test_error_conditions(
                    endpoint_config['url'],
                    endpoint_config['error_test_cases']
                )
                results['error_tests'] = error_results
            
            # Performance tests
            if endpoint_config.get('performance_sla'):
                perf_stats = self.performance_helpers.benchmark_api_endpoint(
                    self.client,
                    endpoint_config['url'],
                    headers=self.auth_helpers.create_auth_headers() if endpoint_config.get('auth_required') else None
                )
                results['performance_tests'] = perf_stats
                
                # Check SLA compliance
                sla_config = endpoint_config['performance_sla']
                self.performance_helpers.assert_performance_sla(
                    perf_stats,
                    sla_config.get('max_avg_response_time', 0.2),
                    sla_config.get('max_p95_response_time', 0.5),
                    sla_config.get('min_success_rate', 0.99)
                )
        
        except Exception as e:
            results['passed'] = False
            results['errors'].append(str(e))
        
        return results
    
    def generate_test_report(self, test_results: List[Dict[str, Any]]) -> str:
        """
        Generate comprehensive test report from results.
        
        Args:
            test_results: List of test result dictionaries
            
        Returns:
            Formatted test report string
        """
        total_tests = len(test_results)
        passed_tests = sum(1 for result in test_results if result.get('passed', False))
        success_rate = passed_tests / total_tests if total_tests > 0 else 0
        
        report = f"""
Flask Migration Test Suite Report
================================
Total Endpoints Tested: {total_tests}
Passed: {passed_tests}
Failed: {total_tests - passed_tests}
Success Rate: {success_rate:.2%}

Test Results Summary:
"""
        
        for result in test_results:
            status = "✅ PASS" if result.get('passed', False) else "❌ FAIL"
            report += f"\n{status} {result.get('endpoint', 'Unknown')}"
            
            if not result.get('passed', False):
                for error in result.get('errors', []):
                    report += f"\n  Error: {error}"
        
        return report


# Export all utility classes and functions for easy importing
__all__ = [
    'FlaskResponseAssertions',
    'APITestHelpers', 
    'TestDataManager',
    'AuthTestHelpers',
    'PerformanceTestHelpers',
    'ComparativeTestHelpers',
    'DatabaseTestHelpers',
    'TestSuiteHelpers',
    'wait_for_condition',
    'generate_unique_string',
    'create_temporary_file',
    'normalize_json_for_comparison',
    'hash_response_content'
]