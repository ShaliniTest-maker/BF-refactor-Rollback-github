"""
Test Utility Functions Module

This module provides comprehensive testing utilities for the Flask application,
including common testing helpers, assertion utilities, and test data manipulation
functions for consistent testing patterns across the pytest test suite.

Key Features:
- Flask-specific testing assertions and response validation helpers
- Factory Boy integration utilities for SQLAlchemy model testing
- Common testing patterns for API endpoint validation
- Database testing utilities with transaction management
- Performance testing helpers for SLA validation
- Authentication and authorization testing utilities
"""

import json
import pytest
from typing import Any, Dict, List, Optional, Union, Callable, Type
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from werkzeug.test import Client
from flask import Flask, Response
from flask.testing import FlaskClient
from sqlalchemy.orm import Session
from sqlalchemy import inspect
import factory


# =============================================================================
# Flask Response Validation Utilities
# =============================================================================

class ResponseAssertions:
    """
    Collection of Flask response assertion utilities providing consistent
    testing patterns for API endpoint validation and HTTP response verification.
    """

    @staticmethod
    def assert_status_code(response: Response, expected_status: int, message: Optional[str] = None) -> None:
        """
        Assert that response has expected status code with detailed error reporting.
        
        Args:
            response: Flask response object to validate
            expected_status: Expected HTTP status code
            message: Optional custom error message
            
        Raises:
            AssertionError: If status code doesn't match expected value
        """
        actual_status = response.status_code
        default_message = f"Expected HTTP status {expected_status} but got {actual_status}"
        error_message = message or default_message
        
        # Add response data for debugging if status is error
        if actual_status >= 400:
            try:
                response_data = response.get_json() or response.get_data(as_text=True)
                error_message += f"\nResponse data: {response_data}"
            except Exception:
                error_message += f"\nResponse data (raw): {response.get_data()}"
        
        assert actual_status == expected_status, error_message

    @staticmethod
    def assert_json_response(response: Response, expected_data: Dict[str, Any] = None, 
                           status_code: int = 200) -> Dict[str, Any]:
        """
        Assert response is valid JSON with expected status and optionally validate content.
        
        Args:
            response: Flask response object to validate
            expected_data: Optional dictionary to compare against response JSON
            status_code: Expected HTTP status code (default: 200)
            
        Returns:
            Dict containing the parsed JSON response data
            
        Raises:
            AssertionError: If response is not valid JSON or doesn't match expectations
        """
        ResponseAssertions.assert_status_code(response, status_code)
        
        # Validate content type
        content_type = response.headers.get('Content-Type', '')
        assert 'application/json' in content_type, f"Expected JSON response, got content-type: {content_type}"
        
        # Parse and validate JSON
        try:
            json_data = response.get_json()
            assert json_data is not None, "Response JSON is None or empty"
        except Exception as e:
            pytest.fail(f"Failed to parse JSON response: {e}\nResponse data: {response.get_data()}")
        
        # Validate expected data if provided
        if expected_data is not None:
            ResponseAssertions._assert_dict_contains(json_data, expected_data)
        
        return json_data

    @staticmethod
    def assert_redirect(response: Response, expected_location: str, status_code: int = 302) -> None:
        """
        Assert response is a redirect to expected location.
        
        Args:
            response: Flask response object to validate
            expected_location: Expected redirect URL or path
            status_code: Expected redirect status code (default: 302)
            
        Raises:
            AssertionError: If response is not a redirect or location doesn't match
        """
        valid_redirect_codes = [301, 302, 303, 305, 307, 308]
        assert response.status_code in valid_redirect_codes, \
            f"Expected redirect status code {valid_redirect_codes}, got {response.status_code}"
        
        if status_code:
            ResponseAssertions.assert_status_code(response, status_code)
        
        location = response.headers.get('Location', '')
        assert expected_location in location, \
            f"Expected redirect to contain '{expected_location}', got location: '{location}'"

    @staticmethod
    def assert_contains_text(response: Response, expected_text: str, case_sensitive: bool = True) -> None:
        """
        Assert response data contains expected text.
        
        Args:
            response: Flask response object to validate
            expected_text: Text that should be present in response
            case_sensitive: Whether to perform case-sensitive search (default: True)
            
        Raises:
            AssertionError: If expected text is not found in response
        """
        response_text = response.get_data(as_text=True)
        
        if case_sensitive:
            assert expected_text in response_text, \
                f"Expected text '{expected_text}' not found in response"
        else:
            assert expected_text.lower() in response_text.lower(), \
                f"Expected text '{expected_text}' not found in response (case-insensitive)"

    @staticmethod
    def assert_error_response(response: Response, expected_error: str = None, 
                            status_code: int = 400) -> Dict[str, Any]:
        """
        Assert response contains error information with expected format.
        
        Args:
            response: Flask response object to validate
            expected_error: Optional expected error message or code
            status_code: Expected error status code (default: 400)
            
        Returns:
            Dict containing the parsed error response data
            
        Raises:
            AssertionError: If response doesn't contain proper error format
        """
        json_data = ResponseAssertions.assert_json_response(response, status_code=status_code)
        
        # Validate error structure
        assert 'error' in json_data or 'message' in json_data, \
            f"Response should contain 'error' or 'message' field: {json_data}"
        
        if expected_error:
            error_content = json_data.get('error', json_data.get('message', ''))
            assert expected_error in str(error_content), \
                f"Expected error '{expected_error}' not found in response error: '{error_content}'"
        
        return json_data

    @staticmethod
    def _assert_dict_contains(actual: Dict[str, Any], expected: Dict[str, Any], path: str = "") -> None:
        """
        Recursively assert that actual dictionary contains all expected key-value pairs.
        
        Args:
            actual: Actual dictionary data
            expected: Expected dictionary data to verify
            path: Current path for error reporting (used in recursion)
            
        Raises:
            AssertionError: If expected data is not found in actual data
        """
        for key, expected_value in expected.items():
            current_path = f"{path}.{key}" if path else key
            
            assert key in actual, f"Missing key '{current_path}' in response data"
            
            actual_value = actual[key]
            
            if isinstance(expected_value, dict) and isinstance(actual_value, dict):
                ResponseAssertions._assert_dict_contains(actual_value, expected_value, current_path)
            elif isinstance(expected_value, list) and isinstance(actual_value, list):
                assert len(actual_value) == len(expected_value), \
                    f"List length mismatch at '{current_path}': expected {len(expected_value)}, got {len(actual_value)}"
                for i, (exp_item, act_item) in enumerate(zip(expected_value, actual_value)):
                    if isinstance(exp_item, dict):
                        ResponseAssertions._assert_dict_contains(act_item, exp_item, f"{current_path}[{i}]")
                    else:
                        assert act_item == exp_item, \
                            f"List item mismatch at '{current_path}[{i}]': expected {exp_item}, got {act_item}"
            else:
                assert actual_value == expected_value, \
                    f"Value mismatch at '{current_path}': expected {expected_value}, got {actual_value}"


# =============================================================================
# Authentication Testing Utilities
# =============================================================================

class AuthTestUtils:
    """
    Authentication testing utilities for managing test user sessions,
    authentication states, and authorization testing patterns.
    """

    @staticmethod
    def create_authenticated_request(client: FlaskClient, user_id: int = None, 
                                   auth_token: str = None) -> Callable:
        """
        Create a context manager for making authenticated requests.
        
        Args:
            client: Flask test client
            user_id: Optional user ID to authenticate as
            auth_token: Optional authentication token to use
            
        Returns:
            Context manager for authenticated requests
            
        Example:
            with AuthTestUtils.create_authenticated_request(client, user_id=1) as auth_client:
                response = auth_client.get('/protected-endpoint')
        """
        class AuthenticatedClient:
            def __init__(self, client, user_id, auth_token):
                self.client = client
                self.user_id = user_id
                self.auth_token = auth_token
                self.original_headers = {}

            def __enter__(self):
                # Set up authentication headers or session
                if self.auth_token:
                    self.client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {self.auth_token}'
                elif self.user_id:
                    # Simulate session-based authentication
                    with self.client.session_transaction() as sess:
                        sess['user_id'] = self.user_id
                        sess['_fresh'] = True
                return self.client

            def __exit__(self, exc_type, exc_val, exc_tb):
                # Clean up authentication
                if 'HTTP_AUTHORIZATION' in self.client.environ_base:
                    del self.client.environ_base['HTTP_AUTHORIZATION']
                with self.client.session_transaction() as sess:
                    sess.clear()

        return AuthenticatedClient(client, user_id, auth_token)

    @staticmethod
    def assert_requires_authentication(client: FlaskClient, endpoint: str, 
                                     method: str = 'GET', data: Dict = None) -> None:
        """
        Assert that an endpoint requires authentication by testing unauthenticated access.
        
        Args:
            client: Flask test client
            endpoint: URL endpoint to test
            method: HTTP method to use (default: 'GET')
            data: Optional request data for POST/PUT requests
            
        Raises:
            AssertionError: If endpoint doesn't require authentication
        """
        method = method.upper()
        client_method = getattr(client, method.lower())
        
        kwargs = {}
        if data and method in ['POST', 'PUT', 'PATCH']:
            kwargs['json'] = data
        
        response = client_method(endpoint, **kwargs)
        
        # Should redirect to login or return 401 Unauthorized
        assert response.status_code in [401, 403, 302], \
            f"Endpoint {endpoint} should require authentication, got status {response.status_code}"

    @staticmethod
    def assert_requires_permission(client: FlaskClient, endpoint: str, user_id: int,
                                 expected_status: int = 403, method: str = 'GET', 
                                 data: Dict = None) -> None:
        """
        Assert that an endpoint requires specific permissions by testing with unauthorized user.
        
        Args:
            client: Flask test client
            endpoint: URL endpoint to test
            user_id: User ID to authenticate as (should lack required permission)
            expected_status: Expected status code for unauthorized access (default: 403)
            method: HTTP method to use (default: 'GET')
            data: Optional request data for POST/PUT requests
            
        Raises:
            AssertionError: If endpoint doesn't enforce permissions properly
        """
        with AuthTestUtils.create_authenticated_request(client, user_id=user_id):
            method = method.upper()
            client_method = getattr(client, method.lower())
            
            kwargs = {}
            if data and method in ['POST', 'PUT', 'PATCH']:
                kwargs['json'] = data
            
            response = client_method(endpoint, **kwargs)
            ResponseAssertions.assert_status_code(response, expected_status,
                f"User {user_id} should not have permission to access {endpoint}")


# =============================================================================
# Database Testing Utilities
# =============================================================================

class DatabaseTestUtils:
    """
    Database testing utilities for managing test data, transaction isolation,
    and database state verification during testing.
    """

    @staticmethod
    def assert_record_exists(session: Session, model_class: Type, **filters) -> Any:
        """
        Assert that a database record exists with given filters.
        
        Args:
            session: SQLAlchemy session
            model_class: SQLAlchemy model class to query
            **filters: Field filters to apply to query
            
        Returns:
            The found database record
            
        Raises:
            AssertionError: If no record is found matching the filters
        """
        query = session.query(model_class)
        for field, value in filters.items():
            query = query.filter(getattr(model_class, field) == value)
        
        record = query.first()
        assert record is not None, \
            f"No {model_class.__name__} record found with filters: {filters}"
        
        return record

    @staticmethod
    def assert_record_count(session: Session, model_class: Type, expected_count: int, 
                          **filters) -> None:
        """
        Assert the count of records matching given filters.
        
        Args:
            session: SQLAlchemy session
            model_class: SQLAlchemy model class to query
            expected_count: Expected number of records
            **filters: Field filters to apply to query
            
        Raises:
            AssertionError: If record count doesn't match expected value
        """
        query = session.query(model_class)
        for field, value in filters.items():
            query = query.filter(getattr(model_class, field) == value)
        
        actual_count = query.count()
        assert actual_count == expected_count, \
            f"Expected {expected_count} {model_class.__name__} records with filters {filters}, found {actual_count}"

    @staticmethod
    def assert_record_not_exists(session: Session, model_class: Type, **filters) -> None:
        """
        Assert that no database record exists with given filters.
        
        Args:
            session: SQLAlchemy session
            model_class: SQLAlchemy model class to query
            **filters: Field filters to apply to query
            
        Raises:
            AssertionError: If a record is found matching the filters
        """
        query = session.query(model_class)
        for field, value in filters.items():
            query = query.filter(getattr(model_class, field) == value)
        
        record = query.first()
        assert record is None, \
            f"Expected no {model_class.__name__} record with filters {filters}, but found: {record}"

    @staticmethod
    def clean_database(session: Session, *model_classes: Type) -> None:
        """
        Clean database tables for specified model classes.
        
        Args:
            session: SQLAlchemy session
            *model_classes: Model classes to clean (if none provided, cleans all tables)
            
        Note:
            This method should only be used in test environments with proper isolation.
        """
        if not model_classes:
            # Clean all tables if no specific models provided
            meta = session.bind.engine.table_names()
            for table_name in reversed(meta):
                session.execute(f"DELETE FROM {table_name}")
        else:
            # Clean specific model tables
            for model_class in model_classes:
                session.query(model_class).delete()
        
        session.commit()

    @staticmethod
    def assert_field_updated(session: Session, model_instance: Any, field_name: str, 
                           expected_value: Any) -> None:
        """
        Assert that a model instance field has been updated to expected value.
        
        Args:
            session: SQLAlchemy session
            model_instance: Model instance to check
            field_name: Name of the field to verify
            expected_value: Expected field value
            
        Raises:
            AssertionError: If field value doesn't match expected value
        """
        # Refresh the instance to get latest data
        session.refresh(model_instance)
        
        actual_value = getattr(model_instance, field_name)
        assert actual_value == expected_value, \
            f"Expected {field_name} to be {expected_value}, got {actual_value}"

    @staticmethod
    def assert_audit_log_created(session: Session, table_name: str, operation_type: str,
                                record_id: int = None) -> Any:
        """
        Assert that an audit log entry was created for a database operation.
        
        Args:
            session: SQLAlchemy session
            table_name: Name of the table that was modified
            operation_type: Type of operation (INSERT, UPDATE, DELETE)
            record_id: Optional record ID that was affected
            
        Returns:
            The audit log record if found
            
        Raises:
            AssertionError: If no audit log is found
        """
        # Import here to avoid circular imports
        from models import AuditLog
        
        query = session.query(AuditLog).filter(
            AuditLog.table_name == table_name,
            AuditLog.operation_type == operation_type.upper()
        )
        
        if record_id is not None:
            query = query.filter(AuditLog.record_id == str(record_id))
        
        audit_record = query.first()
        assert audit_record is not None, \
            f"No audit log found for {operation_type} operation on {table_name}"
        
        return audit_record


# =============================================================================
# Factory Boy Integration Utilities
# =============================================================================

class FactoryUtils:
    """
    Factory Boy integration utilities for enhanced test data generation,
    relationship management, and SQLAlchemy session coordination.
    """

    @staticmethod
    def setup_factory_session(session: Session, *factory_classes: Type[factory.Factory]) -> None:
        """
        Configure Factory Boy factories to use the provided SQLAlchemy session.
        
        Args:
            session: SQLAlchemy session for database operations
            *factory_classes: Factory classes to configure
            
        Note:
            This ensures all factory-generated objects use the same database session
            as the test, enabling proper transaction isolation.
        """
        for factory_class in factory_classes:
            if hasattr(factory_class._meta, 'sqlalchemy_session'):
                factory_class._meta.sqlalchemy_session = session

    @staticmethod
    def create_batch_with_relationship(factory_class: Type[factory.Factory], size: int,
                                     relationship_field: str, related_object: Any,
                                     **kwargs) -> List[Any]:
        """
        Create a batch of objects with a shared relationship.
        
        Args:
            factory_class: Factory class to use for object creation
            size: Number of objects to create
            relationship_field: Name of the relationship field
            related_object: Object to relate all created objects to
            **kwargs: Additional factory parameters
            
        Returns:
            List of created objects with the specified relationship
        """
        kwargs[relationship_field] = related_object
        return factory_class.create_batch(size, **kwargs)

    @staticmethod
    def build_object_tree(factory_class: Type[factory.Factory], depth: int = 2,
                         child_count: int = 3, **kwargs) -> Any:
        """
        Build a tree of related objects for testing hierarchical structures.
        
        Args:
            factory_class: Factory class for creating objects
            depth: Depth of the tree structure
            child_count: Number of children per level
            **kwargs: Additional factory parameters
            
        Returns:
            Root object with nested children structure
        """
        root = factory_class.create(**kwargs)
        
        if depth > 1:
            children = []
            for _ in range(child_count):
                child = FactoryUtils.build_object_tree(
                    factory_class, depth - 1, child_count, parent=root, **kwargs
                )
                children.append(child)
            
            # Attach children if the model supports it
            if hasattr(root, 'children'):
                root.children = children
        
        return root

    @staticmethod
    def assert_factory_creates_valid_object(factory_class: Type[factory.Factory],
                                          session: Session = None, **kwargs) -> Any:
        """
        Assert that a factory creates a valid object with all required fields.
        
        Args:
            factory_class: Factory class to test
            session: Optional SQLAlchemy session for validation
            **kwargs: Additional factory parameters
            
        Returns:
            Created object if validation passes
            
        Raises:
            AssertionError: If factory doesn't create a valid object
        """
        if session:
            FactoryUtils.setup_factory_session(session, factory_class)
        
        obj = factory_class.create(**kwargs)
        
        # Validate object was created
        assert obj is not None, f"Factory {factory_class.__name__} returned None"
        
        # Validate required fields if model has them
        if hasattr(obj.__class__, '__table__'):
            for column in obj.__class__.__table__.columns:
                if not column.nullable and not column.default and not column.server_default:
                    value = getattr(obj, column.name)
                    assert value is not None, \
                        f"Required field {column.name} is None in {factory_class.__name__}"
        
        return obj

    @staticmethod
    def create_related_objects(primary_factory: Type[factory.Factory],
                             related_factories: Dict[str, Type[factory.Factory]],
                             **kwargs) -> Dict[str, Any]:
        """
        Create a primary object with all its related objects.
        
        Args:
            primary_factory: Factory for the main object
            related_factories: Dict mapping relationship names to factory classes
            **kwargs: Additional parameters for the primary factory
            
        Returns:
            Dict containing the primary object and all related objects
        """
        result = {}
        
        # Create related objects first
        for relation_name, related_factory in related_factories.items():
            result[relation_name] = related_factory.create()
            kwargs[relation_name] = result[relation_name]
        
        # Create primary object with relationships
        result['primary'] = primary_factory.create(**kwargs)
        
        return result


# =============================================================================
# Performance Testing Utilities
# =============================================================================

class PerformanceTestUtils:
    """
    Performance testing utilities for response time validation,
    memory usage monitoring, and SLA compliance testing.
    """

    @staticmethod
    def assert_response_time(response_time: float, max_allowed_ms: float) -> None:
        """
        Assert that response time is within acceptable limits.
        
        Args:
            response_time: Actual response time in seconds
            max_allowed_ms: Maximum allowed response time in milliseconds
            
        Raises:
            AssertionError: If response time exceeds the limit
        """
        response_time_ms = response_time * 1000
        assert response_time_ms <= max_allowed_ms, \
            f"Response time {response_time_ms:.2f}ms exceeds limit of {max_allowed_ms}ms"

    @staticmethod
    def benchmark_endpoint(client: FlaskClient, endpoint: str, method: str = 'GET',
                         data: Dict = None, iterations: int = 10) -> Dict[str, float]:
        """
        Benchmark an endpoint with multiple iterations and return performance metrics.
        
        Args:
            client: Flask test client
            endpoint: URL endpoint to benchmark
            method: HTTP method to use (default: 'GET')
            data: Optional request data
            iterations: Number of iterations to run (default: 10)
            
        Returns:
            Dict containing performance metrics (avg, min, max response times)
        """
        import time
        
        response_times = []
        method = method.upper()
        client_method = getattr(client, method.lower())
        
        kwargs = {}
        if data and method in ['POST', 'PUT', 'PATCH']:
            kwargs['json'] = data
        
        for _ in range(iterations):
            start_time = time.time()
            response = client_method(endpoint, **kwargs)
            end_time = time.time()
            
            # Ensure request was successful for valid benchmark
            assert response.status_code < 400, \
                f"Benchmark failed: {endpoint} returned status {response.status_code}"
            
            response_times.append(end_time - start_time)
        
        return {
            'avg_time_ms': (sum(response_times) / len(response_times)) * 1000,
            'min_time_ms': min(response_times) * 1000,
            'max_time_ms': max(response_times) * 1000,
            'total_requests': iterations
        }

    @staticmethod
    def assert_concurrent_performance(client: FlaskClient, endpoint: str,
                                    concurrent_users: int = 5, 
                                    requests_per_user: int = 10,
                                    max_avg_response_ms: float = 200) -> Dict[str, Any]:
        """
        Test endpoint performance under concurrent load.
        
        Args:
            client: Flask test client
            endpoint: URL endpoint to test
            concurrent_users: Number of concurrent virtual users
            requests_per_user: Number of requests each user makes
            max_avg_response_ms: Maximum allowed average response time
            
        Returns:
            Dict containing concurrent performance metrics
            
        Raises:
            AssertionError: If performance doesn't meet SLA requirements
        """
        import threading
        import time
        from queue import Queue
        
        results_queue = Queue()
        
        def user_simulation():
            """Simulate a single user making multiple requests."""
            user_times = []
            for _ in range(requests_per_user):
                start_time = time.time()
                response = client.get(endpoint)
                end_time = time.time()
                
                if response.status_code < 400:
                    user_times.append(end_time - start_time)
            
            results_queue.put(user_times)
        
        # Start concurrent users
        threads = []
        start_time = time.time()
        
        for _ in range(concurrent_users):
            thread = threading.Thread(target=user_simulation)
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        # Collect results
        all_response_times = []
        while not results_queue.empty():
            user_times = results_queue.get()
            all_response_times.extend(user_times)
        
        if not all_response_times:
            pytest.fail("No successful responses recorded during concurrent test")
        
        # Calculate metrics
        avg_response_time = (sum(all_response_times) / len(all_response_times)) * 1000
        total_requests = len(all_response_times)
        requests_per_second = total_requests / total_time
        
        # Assert SLA compliance
        PerformanceTestUtils.assert_response_time(
            sum(all_response_times) / len(all_response_times), 
            max_avg_response_ms
        )
        
        return {
            'avg_response_time_ms': avg_response_time,
            'total_requests': total_requests,
            'total_time_seconds': total_time,
            'requests_per_second': requests_per_second,
            'concurrent_users': concurrent_users,
            'success_rate': (total_requests / (concurrent_users * requests_per_user)) * 100
        }


# =============================================================================
# Test Data Manipulation Utilities
# =============================================================================

class TestDataUtils:
    """
    Utilities for test data creation, manipulation, and validation
    supporting complex test scenarios and data consistency checks.
    """

    @staticmethod
    def create_test_user_with_roles(session: Session, username: str = "testuser",
                                  email: str = "test@example.com",
                                  roles: List[str] = None) -> Any:
        """
        Create a test user with specified roles for authorization testing.
        
        Args:
            session: SQLAlchemy session
            username: Username for the test user
            email: Email address for the test user
            roles: List of role names to assign to the user
            
        Returns:
            Created user object with assigned roles
        """
        # Import here to avoid circular imports
        from models import User, Role
        
        # Create user
        user = User(username=username, email=email)
        session.add(user)
        session.flush()  # Get user ID before adding roles
        
        # Add roles if specified
        if roles:
            for role_name in roles:
                role = session.query(Role).filter(Role.name == role_name).first()
                if not role:
                    role = Role(name=role_name, description=f"Test role: {role_name}")
                    session.add(role)
                    session.flush()
                
                user.roles.append(role)
        
        session.commit()
        return user

    @staticmethod
    def create_hierarchical_test_data(session: Session, model_class: Type,
                                    levels: int = 3, items_per_level: int = 2,
                                    **base_kwargs) -> List[Any]:
        """
        Create hierarchical test data for testing tree structures.
        
        Args:
            session: SQLAlchemy session
            model_class: Model class to create hierarchy for
            levels: Number of hierarchy levels
            items_per_level: Number of items at each level
            **base_kwargs: Base parameters for object creation
            
        Returns:
            List of all created objects (flat list)
        """
        all_objects = []
        current_level = [None]  # Start with root level (parent = None)
        
        for level in range(levels):
            next_level = []
            
            for parent in current_level:
                for i in range(items_per_level):
                    kwargs = base_kwargs.copy()
                    kwargs['name'] = f"Level_{level}_Item_{i}"
                    
                    if parent:
                        kwargs['parent_id'] = parent.id
                    
                    obj = model_class(**kwargs)
                    session.add(obj)
                    next_level.append(obj)
                    all_objects.append(obj)
            
            session.flush()  # Ensure IDs are available for next level
            current_level = next_level
        
        session.commit()
        return all_objects

    @staticmethod
    def assert_data_integrity(session: Session, model_class: Type,
                            integrity_checks: Dict[str, Callable]) -> None:
        """
        Assert data integrity constraints for a model class.
        
        Args:
            session: SQLAlchemy session
            model_class: Model class to check
            integrity_checks: Dict mapping check names to validation functions
            
        Example:
            integrity_checks = {
                'unique_emails': lambda objs: len(set(obj.email for obj in objs)) == len(objs),
                'valid_status': lambda objs: all(obj.status in ['active', 'inactive'] for obj in objs)
            }
        """
        all_objects = session.query(model_class).all()
        
        for check_name, check_function in integrity_checks.items():
            try:
                result = check_function(all_objects)
                assert result, f"Data integrity check '{check_name}' failed for {model_class.__name__}"
            except Exception as e:
                pytest.fail(f"Data integrity check '{check_name}' raised exception: {e}")

    @staticmethod
    def generate_test_data_variations(base_data: Dict[str, Any],
                                    variations: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
        """
        Generate multiple test data variations for parametrized testing.
        
        Args:
            base_data: Base data dictionary
            variations: Dict mapping field names to lists of variation values
            
        Returns:
            List of data dictionaries with all combinations of variations
            
        Example:
            base_data = {'name': 'Test', 'active': True}
            variations = {'age': [18, 25, 65], 'status': ['new', 'active']}
            # Returns 6 combinations (3 ages × 2 statuses)
        """
        import itertools
        
        if not variations:
            return [base_data]
        
        variation_keys = list(variations.keys())
        variation_values = [variations[key] for key in variation_keys]
        
        result = []
        for combination in itertools.product(*variation_values):
            data = base_data.copy()
            for key, value in zip(variation_keys, combination):
                data[key] = value
            result.append(data)
        
        return result

    @staticmethod
    def validate_test_data_cleanup(session: Session, *model_classes: Type) -> None:
        """
        Validate that test data has been properly cleaned up after test execution.
        
        Args:
            session: SQLAlchemy session
            *model_classes: Model classes to check for remaining test data
            
        Raises:
            AssertionError: If test data remains in the database
        """
        for model_class in model_classes:
            count = session.query(model_class).count()
            assert count == 0, \
                f"Test cleanup failed: {count} {model_class.__name__} records remain in database"


# =============================================================================
# Mock and Stub Utilities
# =============================================================================

class MockUtils:
    """
    Mock and stub utilities for isolating tests from external dependencies
    and creating controlled test environments.
    """

    @staticmethod
    def create_mock_service(service_class: Type, method_behaviors: Dict[str, Any] = None) -> Mock:
        """
        Create a mock service object with specified method behaviors.
        
        Args:
            service_class: Service class to mock
            method_behaviors: Dict mapping method names to return values or side effects
            
        Returns:
            Mock object configured with specified behaviors
        """
        mock_service = Mock(spec=service_class)
        
        if method_behaviors:
            for method_name, behavior in method_behaviors.items():
                mock_method = getattr(mock_service, method_name)
                
                if callable(behavior):
                    mock_method.side_effect = behavior
                else:
                    mock_method.return_value = behavior
        
        return mock_service

    @staticmethod
    def patch_service(service_path: str, method_behaviors: Dict[str, Any] = None):
        """
        Context manager for patching a service with mock behaviors.
        
        Args:
            service_path: Import path to the service to patch
            method_behaviors: Dict mapping method names to return values or side effects
            
        Returns:
            Context manager for the patched service
        """
        def configure_mock(mock_obj):
            if method_behaviors:
                for method_name, behavior in method_behaviors.items():
                    mock_method = getattr(mock_obj.return_value, method_name)
                    
                    if callable(behavior):
                        mock_method.side_effect = behavior
                    else:
                        mock_method.return_value = behavior
            
            return mock_obj
        
        return patch(service_path, side_effect=configure_mock)

    @staticmethod
    def create_mock_request_context(app: Flask, path: str = '/', method: str = 'GET',
                                  data: Dict = None, headers: Dict = None) -> Any:
        """
        Create a mock Flask request context for testing without actual HTTP requests.
        
        Args:
            app: Flask application instance
            path: Request path (default: '/')
            method: HTTP method (default: 'GET')
            data: Request data dictionary
            headers: Request headers dictionary
            
        Returns:
            Request context manager
        """
        with app.test_request_context(path, method=method, json=data, headers=headers) as ctx:
            return ctx


# =============================================================================
# Export commonly used utilities for easy import
# =============================================================================

# Create convenience aliases for the most commonly used utilities
assert_status_code = ResponseAssertions.assert_status_code
assert_json_response = ResponseAssertions.assert_json_response
assert_error_response = ResponseAssertions.assert_error_response
assert_redirect = ResponseAssertions.assert_redirect

assert_record_exists = DatabaseTestUtils.assert_record_exists
assert_record_count = DatabaseTestUtils.assert_record_count
setup_factory_session = FactoryUtils.setup_factory_session

create_authenticated_request = AuthTestUtils.create_authenticated_request
assert_requires_authentication = AuthTestUtils.assert_requires_authentication

benchmark_endpoint = PerformanceTestUtils.benchmark_endpoint
assert_response_time = PerformanceTestUtils.assert_response_time

create_mock_service = MockUtils.create_mock_service


# Module-level docstring for pytest register_assert_rewrite
pytest.register_assert_rewrite(__name__)

__all__ = [
    # Main utility classes
    'ResponseAssertions', 'AuthTestUtils', 'DatabaseTestUtils', 
    'FactoryUtils', 'PerformanceTestUtils', 'TestDataUtils', 'MockUtils',
    
    # Convenience functions
    'assert_status_code', 'assert_json_response', 'assert_error_response', 'assert_redirect',
    'assert_record_exists', 'assert_record_count', 'setup_factory_session',
    'create_authenticated_request', 'assert_requires_authentication',
    'benchmark_endpoint', 'assert_response_time', 'create_mock_service'
]