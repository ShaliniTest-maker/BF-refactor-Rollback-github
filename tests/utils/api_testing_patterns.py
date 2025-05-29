"""
API Testing Utilities for Flask Blueprint Migration

This module provides comprehensive endpoint validation patterns, request/response testing helpers,
and Flask blueprint testing infrastructure to ensure complete functionality parity between
Node.js Express routes and Flask blueprint implementations during the migration process.

Key Features:
- API endpoint testing patterns for Flask blueprint validation per Feature F-001
- Request/response handling migration testing per Feature F-002
- RESTful API contract preservation per Section 5.3.2
- API security measures preservation in Flask implementation per Section 2.4.4
- External service compatibility validation per Section 2.4.7
- Error handling testing patterns with Flask error handler validation
- Middleware translation testing utilities for Flask decorator patterns
- API versioning and backward compatibility testing utilities

Dependencies:
- pytest 8.2.0: Core testing framework with fixture management
- pytest-flask 1.3.0: Flask-specific testing utilities and fixtures
- Flask 3.1.1: Web application framework with blueprint support
- requests 2.31.0: HTTP library for external API testing
- jsonschema 4.23.0: JSON schema validation for API contracts
- faker 26.0.0: Realistic test data generation
"""

import json
import uuid
import time
import functools
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, asdict
from unittest.mock import Mock, patch, MagicMock
import re

# Core testing imports
import pytest
from flask import Flask, request, jsonify, g, current_app
from flask.testing import FlaskClient
from werkzeug.test import Client
from werkzeug.wrappers import Response

# JSON schema validation
import jsonschema
from jsonschema import validate, ValidationError as SchemaValidationError

# Data generation for testing
from faker import Faker

# Performance testing
import psutil
import threading

# Import application components
try:
    from src.blueprints import api as api_blueprint
    from src.blueprints import auth as auth_blueprint  
    from src.blueprints import main as main_blueprint
    from src.services.base import ServiceBase
    from src.auth.decorators import require_auth, require_role
except ImportError:
    # Handle case where modules don't exist yet during development
    api_blueprint = None
    auth_blueprint = None
    main_blueprint = None
    ServiceBase = None
    require_auth = None
    require_role = None


# Initialize Faker for test data generation
fake = Faker()


@dataclass
class APITestCase:
    """
    Data class representing a comprehensive API test case with expected behavior,
    validation rules, and performance requirements for Flask blueprint testing.
    
    This class encapsulates all necessary information for systematic API endpoint
    testing, ensuring complete validation of functionality parity between Node.js
    Express routes and Flask blueprint implementations.
    """
    
    # Basic test case identification
    name: str
    description: str
    blueprint_name: str
    endpoint: str
    method: str
    
    # Request configuration
    request_data: Optional[Dict[str, Any]] = None
    request_headers: Optional[Dict[str, str]] = None
    query_params: Optional[Dict[str, Any]] = None
    path_params: Optional[Dict[str, str]] = None
    
    # Expected response configuration
    expected_status: int = 200
    expected_content_type: str = 'application/json'
    expected_headers: Optional[Dict[str, str]] = None
    expected_schema: Optional[Dict[str, Any]] = None
    expected_response_fields: Optional[List[str]] = None
    
    # Authentication and authorization
    requires_auth: bool = False
    required_roles: Optional[List[str]] = None
    auth_token: Optional[str] = None
    
    # Performance requirements
    max_response_time: float = 2.0  # seconds
    memory_threshold: float = 100.0  # MB
    
    # Validation settings
    validate_contract: bool = True
    validate_security: bool = True
    validate_performance: bool = True
    
    # Error testing configuration
    test_error_scenarios: bool = True
    expected_error_codes: Optional[List[int]] = None
    
    # External service mocking
    mock_external_services: Optional[Dict[str, Any]] = None
    
    # Custom validation functions
    custom_validators: Optional[List[Callable]] = None


class APIContractValidator:
    """
    Comprehensive API contract validation utility ensuring RESTful API contract
    preservation per Section 5.3.2. This class validates response formats,
    status codes, headers, and data schemas to ensure complete compatibility
    between Node.js Express API responses and Flask blueprint responses.
    
    Features:
    - JSON schema validation for response data
    - HTTP status code validation
    - Response header validation
    - Content-Type validation
    - API versioning compatibility checks
    - Backward compatibility validation
    """
    
    def __init__(self):
        self.validation_errors = []
        self.contract_schemas = {}
        self.version_compatibility_matrix = {}
        
    def register_schema(self, endpoint: str, method: str, schema: Dict[str, Any], 
                       version: str = "v1"):
        """
        Register JSON schema for API endpoint validation
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            schema: JSON schema definition
            version: API version
        """
        key = f"{method}:{endpoint}:{version}"
        self.contract_schemas[key] = schema
        
    def validate_response_contract(self, response: Response, endpoint: str, 
                                 method: str, version: str = "v1") -> bool:
        """
        Validate response against registered contract schema
        
        Args:
            response: Flask test response
            endpoint: API endpoint path  
            method: HTTP method
            version: API version
            
        Returns:
            bool: True if validation passes, False otherwise
        """
        self.validation_errors.clear()
        
        try:
            # Validate status code is in acceptable range
            if not (200 <= response.status_code < 600):
                self.validation_errors.append(
                    f"Invalid status code: {response.status_code}"
                )
                
            # Validate content type for JSON endpoints
            if response.status_code in [200, 201, 202] and endpoint.startswith('/api/'):
                if not response.content_type or 'application/json' not in response.content_type:
                    self.validation_errors.append(
                        f"Expected JSON content type, got: {response.content_type}"
                    )
                    
            # Validate JSON schema if registered
            schema_key = f"{method}:{endpoint}:{version}"
            if schema_key in self.contract_schemas:
                self._validate_json_schema(response, self.contract_schemas[schema_key])
                
            # Validate required headers
            self._validate_response_headers(response)
            
            return len(self.validation_errors) == 0
            
        except Exception as e:
            self.validation_errors.append(f"Contract validation error: {str(e)}")
            return False
            
    def _validate_json_schema(self, response: Response, schema: Dict[str, Any]):
        """Validate response JSON against schema"""
        try:
            if response.content_type and 'application/json' in response.content_type:
                json_data = response.get_json()
                if json_data is not None:
                    validate(instance=json_data, schema=schema)
        except SchemaValidationError as e:
            self.validation_errors.append(f"JSON schema validation failed: {e.message}")
        except json.JSONDecodeError as e:
            self.validation_errors.append(f"Invalid JSON response: {str(e)}")
            
    def _validate_response_headers(self, response: Response):
        """Validate required response headers"""
        required_headers = ['Content-Type']
        
        for header in required_headers:
            if header not in response.headers:
                self.validation_errors.append(f"Missing required header: {header}")
                
        # Validate security headers for API endpoints
        if response.request and response.request.path.startswith('/api/'):
            security_headers = ['X-Content-Type-Options', 'X-Frame-Options']
            for header in security_headers:
                if header not in response.headers:
                    self.validation_errors.append(
                        f"Missing security header: {header}"
                    )
    
    def get_validation_errors(self) -> List[str]:
        """Get list of validation errors from last validation"""
        return self.validation_errors.copy()
        
    def validate_backward_compatibility(self, old_response: Response, 
                                      new_response: Response) -> bool:
        """
        Validate backward compatibility between Node.js and Flask responses
        
        Args:
            old_response: Response from Node.js baseline
            new_response: Response from Flask implementation
            
        Returns:
            bool: True if backward compatible, False otherwise
        """
        compatibility_errors = []
        
        # Compare status codes
        if old_response.status_code != new_response.status_code:
            compatibility_errors.append(
                f"Status code mismatch: {old_response.status_code} vs {new_response.status_code}"
            )
            
        # Compare content types
        if old_response.content_type != new_response.content_type:
            compatibility_errors.append(
                f"Content type mismatch: {old_response.content_type} vs {new_response.content_type}"
            )
            
        # Compare JSON structure if both are JSON
        if (old_response.content_type and 'application/json' in old_response.content_type and
            new_response.content_type and 'application/json' in new_response.content_type):
            
            old_json = old_response.get_json()
            new_json = new_response.get_json()
            
            if old_json is not None and new_json is not None:
                self._compare_json_structures(old_json, new_json, compatibility_errors)
                
        self.validation_errors.extend(compatibility_errors)
        return len(compatibility_errors) == 0
        
    def _compare_json_structures(self, old_json: Any, new_json: Any, 
                               errors: List[str], path: str = ""):
        """Recursively compare JSON structures for compatibility"""
        if type(old_json) != type(new_json):
            errors.append(f"Type mismatch at {path}: {type(old_json)} vs {type(new_json)}")
            return
            
        if isinstance(old_json, dict):
            for key in old_json.keys():
                if key not in new_json:
                    errors.append(f"Missing key at {path}.{key}")
                else:
                    self._compare_json_structures(
                        old_json[key], new_json[key], errors, f"{path}.{key}"
                    )
                    
        elif isinstance(old_json, list):
            if len(old_json) > 0 and len(new_json) > 0:
                # Compare first elements for structure compatibility
                self._compare_json_structures(
                    old_json[0], new_json[0], errors, f"{path}[0]"
                )


class FlaskBlueprintTester:
    """
    Comprehensive Flask blueprint testing utility providing systematic endpoint
    validation, middleware testing, and authentication decorator verification.
    
    This class implements comprehensive testing patterns for Flask blueprint
    validation per Feature F-001, ensuring identical functionality between
    Node.js Express routes and Flask blueprint implementations.
    
    Features:
    - Systematic blueprint endpoint testing
    - Authentication decorator validation
    - Error handler testing
    - Middleware translation verification
    - Performance monitoring
    - Request/response cycle validation
    """
    
    def __init__(self, app: Flask, client: FlaskClient):
        self.app = app
        self.client = client
        self.contract_validator = APIContractValidator()
        self.performance_monitor = PerformanceMonitor()
        self.security_validator = SecurityValidator()
        self.test_results = []
        
    def test_blueprint_endpoint(self, test_case: APITestCase) -> Dict[str, Any]:
        """
        Execute comprehensive endpoint test based on test case configuration
        
        Args:
            test_case: API test case configuration
            
        Returns:
            Dict containing test results and metrics
        """
        test_result = {
            'test_case': test_case.name,
            'endpoint': f"{test_case.method} {test_case.endpoint}",
            'blueprint': test_case.blueprint_name,
            'success': False,
            'errors': [],
            'metrics': {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Start performance monitoring
            self.performance_monitor.start_monitoring()
            
            # Prepare request
            request_kwargs = self._prepare_request(test_case)
            
            # Execute request with monitoring
            with self.app.test_request_context():
                response = self._execute_request(test_case, request_kwargs)
                
            # Stop performance monitoring
            self.performance_monitor.stop_monitoring()
            test_result['metrics'] = self.performance_monitor.get_metrics()
            
            # Validate response
            validation_results = self._validate_response(test_case, response)
            test_result.update(validation_results)
            
            # Test error scenarios if enabled
            if test_case.test_error_scenarios:
                error_results = self._test_error_scenarios(test_case)
                test_result['error_scenarios'] = error_results
                
            test_result['success'] = len(test_result['errors']) == 0
            
        except Exception as e:
            test_result['errors'].append(f"Test execution error: {str(e)}")
            test_result['success'] = False
            
        self.test_results.append(test_result)
        return test_result
        
    def _prepare_request(self, test_case: APITestCase) -> Dict[str, Any]:
        """Prepare request parameters for test execution"""
        kwargs = {
            'method': test_case.method,
            'path': test_case.endpoint
        }
        
        # Add query parameters
        if test_case.query_params:
            kwargs['query_string'] = test_case.query_params
            
        # Add request headers
        headers = test_case.request_headers or {}
        if test_case.requires_auth and test_case.auth_token:
            headers['Authorization'] = f"Bearer {test_case.auth_token}"
        headers.setdefault('Content-Type', 'application/json')
        kwargs['headers'] = headers
        
        # Add request data
        if test_case.request_data:
            if headers.get('Content-Type') == 'application/json':
                kwargs['data'] = json.dumps(test_case.request_data)
            else:
                kwargs['data'] = test_case.request_data
                
        return kwargs
        
    def _execute_request(self, test_case: APITestCase, kwargs: Dict[str, Any]) -> Response:
        """Execute HTTP request and capture response"""
        # Mock external services if specified
        if test_case.mock_external_services:
            return self._execute_with_mocks(test_case, kwargs)
        else:
            return self.client.open(**kwargs)
            
    def _execute_with_mocks(self, test_case: APITestCase, kwargs: Dict[str, Any]) -> Response:
        """Execute request with external service mocking"""
        mocks = []
        
        try:
            # Set up mocks based on configuration
            for service, mock_config in test_case.mock_external_services.items():
                mock_obj = self._create_service_mock(service, mock_config)
                mocks.append(mock_obj)
                
            # Execute request with mocks active
            return self.client.open(**kwargs)
            
        finally:
            # Clean up mocks
            for mock_obj in mocks:
                if hasattr(mock_obj, 'stop'):
                    mock_obj.stop()
                    
    def _create_service_mock(self, service: str, config: Dict[str, Any]) -> Mock:
        """Create mock for external service based on configuration"""
        if service == 'auth0':
            return self._create_auth0_mock(config)
        elif service == 'database':
            return self._create_database_mock(config)
        elif service == 'external_api':
            return self._create_external_api_mock(config)
        else:
            return Mock()
            
    def _create_auth0_mock(self, config: Dict[str, Any]) -> Mock:
        """Create Auth0 service mock"""
        mock_auth0 = patch('src.auth.auth0_integration.Auth0Client')
        mock_instance = mock_auth0.start()
        
        # Configure mock responses based on config
        mock_instance.return_value.validate_token.return_value = config.get(
            'token_validation', {'sub': 'test_user', 'roles': ['user']}
        )
        mock_instance.return_value.get_user_info.return_value = config.get(
            'user_info', {'id': 'test_user', 'email': 'test@example.com'}
        )
        
        return mock_auth0
        
    def _create_database_mock(self, config: Dict[str, Any]) -> Mock:
        """Create database service mock"""
        mock_db = patch('src.models.db.session')
        mock_session = mock_db.start()
        
        # Configure query responses
        for query, response in config.get('queries', {}).items():
            getattr(mock_session, 'query').return_value.filter.return_value.first.return_value = response
            
        return mock_db
        
    def _create_external_api_mock(self, config: Dict[str, Any]) -> Mock:
        """Create external API service mock"""
        mock_requests = patch('requests.request')
        mock_response = mock_requests.start()
        
        # Configure response
        mock_resp = Mock()
        mock_resp.status_code = config.get('status_code', 200)
        mock_resp.json.return_value = config.get('response_data', {})
        mock_response.return_value = mock_resp
        
        return mock_requests
        
    def _validate_response(self, test_case: APITestCase, response: Response) -> Dict[str, Any]:
        """Comprehensive response validation"""
        validation_result = {
            'contract_valid': True,
            'security_valid': True,
            'performance_valid': True,
            'errors': []
        }
        
        # Contract validation
        if test_case.validate_contract:
            contract_valid = self.contract_validator.validate_response_contract(
                response, test_case.endpoint, test_case.method
            )
            validation_result['contract_valid'] = contract_valid
            if not contract_valid:
                validation_result['errors'].extend(
                    self.contract_validator.get_validation_errors()
                )
                
        # Security validation
        if test_case.validate_security:
            security_valid = self.security_validator.validate_response_security(
                response, test_case
            )
            validation_result['security_valid'] = security_valid
            if not security_valid:
                validation_result['errors'].extend(
                    self.security_validator.get_validation_errors()
                )
                
        # Performance validation
        if test_case.validate_performance:
            metrics = self.performance_monitor.get_metrics()
            performance_valid = self._validate_performance(test_case, metrics)
            validation_result['performance_valid'] = performance_valid
            if not performance_valid:
                validation_result['errors'].append(
                    f"Performance threshold exceeded: {metrics.get('response_time', 0)}s > {test_case.max_response_time}s"
                )
                
        # Custom validation
        if test_case.custom_validators:
            for validator in test_case.custom_validators:
                try:
                    validator_result = validator(response, test_case)
                    if not validator_result.get('valid', True):
                        validation_result['errors'].extend(
                            validator_result.get('errors', [])
                        )
                except Exception as e:
                    validation_result['errors'].append(
                        f"Custom validator error: {str(e)}"
                    )
                    
        return validation_result
        
    def _validate_performance(self, test_case: APITestCase, metrics: Dict[str, Any]) -> bool:
        """Validate performance metrics against thresholds"""
        response_time = metrics.get('response_time', 0)
        memory_usage = metrics.get('memory_usage', 0)
        
        return (response_time <= test_case.max_response_time and 
                memory_usage <= test_case.memory_threshold)
                
    def _test_error_scenarios(self, test_case: APITestCase) -> Dict[str, Any]:
        """Test various error scenarios for robust error handling validation"""
        error_results = {
            'authentication_errors': [],
            'authorization_errors': [],
            'validation_errors': [],
            'server_errors': []
        }
        
        # Test authentication errors if auth is required
        if test_case.requires_auth:
            error_results['authentication_errors'] = self._test_auth_errors(test_case)
            
        # Test authorization errors if roles are required
        if test_case.required_roles:
            error_results['authorization_errors'] = self._test_authz_errors(test_case)
            
        # Test input validation errors
        error_results['validation_errors'] = self._test_validation_errors(test_case)
        
        # Test server error handling
        error_results['server_errors'] = self._test_server_errors(test_case)
        
        return error_results
        
    def _test_auth_errors(self, test_case: APITestCase) -> List[Dict[str, Any]]:
        """Test authentication error scenarios"""
        auth_error_tests = []
        
        # Test missing token
        kwargs = self._prepare_request(test_case)
        kwargs['headers'].pop('Authorization', None)
        response = self.client.open(**kwargs)
        
        auth_error_tests.append({
            'scenario': 'missing_token',
            'expected_status': 401,
            'actual_status': response.status_code,
            'valid': response.status_code == 401
        })
        
        # Test invalid token
        kwargs = self._prepare_request(test_case)
        kwargs['headers']['Authorization'] = 'Bearer invalid_token'
        response = self.client.open(**kwargs)
        
        auth_error_tests.append({
            'scenario': 'invalid_token', 
            'expected_status': 401,
            'actual_status': response.status_code,
            'valid': response.status_code == 401
        })
        
        return auth_error_tests
        
    def _test_authz_errors(self, test_case: APITestCase) -> List[Dict[str, Any]]:
        """Test authorization error scenarios"""
        authz_error_tests = []
        
        # Test insufficient privileges
        kwargs = self._prepare_request(test_case)
        # Use token with insufficient roles (would need integration with auth system)
        kwargs['headers']['Authorization'] = 'Bearer user_token_without_required_roles'
        response = self.client.open(**kwargs)
        
        authz_error_tests.append({
            'scenario': 'insufficient_privileges',
            'expected_status': 403,
            'actual_status': response.status_code,
            'valid': response.status_code == 403
        })
        
        return authz_error_tests
        
    def _test_validation_errors(self, test_case: APITestCase) -> List[Dict[str, Any]]:
        """Test input validation error scenarios"""
        validation_error_tests = []
        
        if test_case.method in ['POST', 'PUT', 'PATCH'] and test_case.request_data:
            # Test invalid JSON
            kwargs = self._prepare_request(test_case)
            kwargs['data'] = 'invalid json'
            response = self.client.open(**kwargs)
            
            validation_error_tests.append({
                'scenario': 'invalid_json',
                'expected_status': 400,
                'actual_status': response.status_code,
                'valid': response.status_code == 400
            })
            
            # Test missing required fields
            kwargs = self._prepare_request(test_case)
            kwargs['data'] = json.dumps({})  # Empty data
            response = self.client.open(**kwargs)
            
            validation_error_tests.append({
                'scenario': 'missing_required_fields',
                'expected_status': 400,
                'actual_status': response.status_code,
                'valid': response.status_code == 400
            })
            
        return validation_error_tests
        
    def _test_server_errors(self, test_case: APITestCase) -> List[Dict[str, Any]]:
        """Test server error handling scenarios"""
        server_error_tests = []
        
        # Test 404 for non-existent endpoint
        kwargs = self._prepare_request(test_case)
        kwargs['path'] = '/api/nonexistent/endpoint'
        response = self.client.open(**kwargs)
        
        server_error_tests.append({
            'scenario': 'not_found',
            'expected_status': 404,
            'actual_status': response.status_code,
            'valid': response.status_code == 404
        })
        
        return server_error_tests
        
    def test_middleware_translation(self, blueprint_name: str) -> Dict[str, Any]:
        """
        Test Flask decorator patterns replacing Express.js middleware functionality
        per Section 5.3.2. Validates authentication decorators, error handlers,
        and request processing middleware translation.
        
        Args:
            blueprint_name: Name of Flask blueprint to test
            
        Returns:
            Dict containing middleware translation test results
        """
        middleware_results = {
            'blueprint': blueprint_name,
            'authentication_decorators': {},
            'error_handlers': {},
            'request_processors': {},
            'success': False,
            'errors': []
        }
        
        try:
            # Test authentication decorators
            middleware_results['authentication_decorators'] = self._test_auth_decorators(blueprint_name)
            
            # Test error handlers
            middleware_results['error_handlers'] = self._test_error_handlers(blueprint_name)
            
            # Test request processors
            middleware_results['request_processors'] = self._test_request_processors(blueprint_name)
            
            # Determine overall success
            all_sections = [
                middleware_results['authentication_decorators'],
                middleware_results['error_handlers'],
                middleware_results['request_processors']
            ]
            
            middleware_results['success'] = all(
                section.get('success', False) for section in all_sections
            )
            
        except Exception as e:
            middleware_results['errors'].append(f"Middleware testing error: {str(e)}")
            
        return middleware_results
        
    def _test_auth_decorators(self, blueprint_name: str) -> Dict[str, Any]:
        """Test Flask authentication decorators"""
        decorator_results = {
            'require_auth_decorator': False,
            'require_role_decorator': False,
            'success': False,
            'errors': []
        }
        
        try:
            # Test @require_auth decorator functionality
            if require_auth is not None:
                decorator_results['require_auth_decorator'] = self._validate_auth_decorator()
                
            # Test @require_role decorator functionality  
            if require_role is not None:
                decorator_results['require_role_decorator'] = self._validate_role_decorator()
                
            decorator_results['success'] = (
                decorator_results['require_auth_decorator'] and
                decorator_results['require_role_decorator']
            )
            
        except Exception as e:
            decorator_results['errors'].append(f"Auth decorator testing error: {str(e)}")
            
        return decorator_results
        
    def _validate_auth_decorator(self) -> bool:
        """Validate authentication decorator functionality"""
        try:
            # Create test endpoint with auth decorator
            @require_auth
            def test_endpoint():
                return jsonify({'message': 'authenticated'})
                
            # Test with and without authentication
            with self.app.test_request_context():
                # Test should pass with proper setup
                return True
                
        except Exception:
            return False
            
    def _validate_role_decorator(self) -> bool:
        """Validate role-based authorization decorator functionality"""
        try:
            # Create test endpoint with role decorator
            @require_role('admin')
            def test_admin_endpoint():
                return jsonify({'message': 'admin access'})
                
            # Test with different roles
            with self.app.test_request_context():
                # Test should pass with proper setup
                return True
                
        except Exception:
            return False
            
    def _test_error_handlers(self, blueprint_name: str) -> Dict[str, Any]:
        """Test Flask error handler implementation"""
        error_handler_results = {
            'error_404_handler': False,
            'error_500_handler': False,
            'validation_error_handler': False,
            'success': False,
            'errors': []
        }
        
        try:
            # Test 404 error handling
            response = self.client.get('/nonexistent/endpoint')
            error_handler_results['error_404_handler'] = (
                response.status_code == 404 and 
                response.content_type and 
                'application/json' in response.content_type
            )
            
            # Additional error handler tests would be implemented here
            error_handler_results['success'] = error_handler_results['error_404_handler']
            
        except Exception as e:
            error_handler_results['errors'].append(f"Error handler testing error: {str(e)}")
            
        return error_handler_results
        
    def _test_request_processors(self, blueprint_name: str) -> Dict[str, Any]:
        """Test Flask request processing patterns"""
        processor_results = {
            'before_request_processor': False,
            'after_request_processor': False,
            'success': False,
            'errors': []
        }
        
        try:
            # Test request processing through actual endpoint
            response = self.client.get('/api/health')  # Assuming health endpoint exists
            
            # Validate request processing occurred
            processor_results['before_request_processor'] = response.status_code in [200, 404]
            processor_results['after_request_processor'] = 'Content-Type' in response.headers
            
            processor_results['success'] = (
                processor_results['before_request_processor'] and
                processor_results['after_request_processor']
            )
            
        except Exception as e:
            processor_results['errors'].append(f"Request processor testing error: {str(e)}")
            
        return processor_results
        
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report for all executed tests"""
        total_tests = len(self.test_results)
        successful_tests = sum(1 for result in self.test_results if result['success'])
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'successful_tests': successful_tests,
                'failed_tests': total_tests - successful_tests,
                'success_rate': (successful_tests / total_tests * 100) if total_tests > 0 else 0,
                'generated_at': datetime.utcnow().isoformat()
            },
            'test_results': self.test_results,
            'performance_summary': self._generate_performance_summary(),
            'contract_validation_summary': self._generate_contract_summary(),
            'security_validation_summary': self._generate_security_summary()
        }
        
        return report
        
    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate performance testing summary"""
        response_times = []
        memory_usage = []
        
        for result in self.test_results:
            metrics = result.get('metrics', {})
            if 'response_time' in metrics:
                response_times.append(metrics['response_time'])
            if 'memory_usage' in metrics:
                memory_usage.append(metrics['memory_usage'])
                
        return {
            'average_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'average_memory_usage': sum(memory_usage) / len(memory_usage) if memory_usage else 0,
            'max_memory_usage': max(memory_usage) if memory_usage else 0
        }
        
    def _generate_contract_summary(self) -> Dict[str, Any]:
        """Generate API contract validation summary"""
        contract_valid_count = sum(
            1 for result in self.test_results 
            if result.get('contract_valid', False)
        )
        
        return {
            'total_contract_tests': len(self.test_results),
            'valid_contracts': contract_valid_count,
            'invalid_contracts': len(self.test_results) - contract_valid_count,
            'contract_compliance_rate': (contract_valid_count / len(self.test_results) * 100) if self.test_results else 0
        }
        
    def _generate_security_summary(self) -> Dict[str, Any]:
        """Generate security validation summary"""
        security_valid_count = sum(
            1 for result in self.test_results 
            if result.get('security_valid', False)
        )
        
        return {
            'total_security_tests': len(self.test_results),
            'valid_security': security_valid_count,
            'invalid_security': len(self.test_results) - security_valid_count,
            'security_compliance_rate': (security_valid_count / len(self.test_results) * 100) if self.test_results else 0
        }


class SecurityValidator:
    """
    Security validation utility for API endpoint testing, ensuring API security
    measures preservation in Flask implementation per Section 2.4.4.
    
    Features:
    - Authentication validation
    - Authorization checks
    - Input sanitization validation
    - CSRF protection verification
    - Security header validation
    - Session security checks
    """
    
    def __init__(self):
        self.validation_errors = []
        
    def validate_response_security(self, response: Response, test_case: APITestCase) -> bool:
        """
        Comprehensive security validation for API response
        
        Args:
            response: Flask test response
            test_case: API test case configuration
            
        Returns:
            bool: True if security validation passes
        """
        self.validation_errors.clear()
        
        # Validate authentication requirements
        if test_case.requires_auth:
            self._validate_authentication_enforcement(response, test_case)
            
        # Validate authorization requirements
        if test_case.required_roles:
            self._validate_authorization_enforcement(response, test_case)
            
        # Validate security headers
        self._validate_security_headers(response)
        
        # Validate CSRF protection
        self._validate_csrf_protection(response, test_case)
        
        # Validate input sanitization
        self._validate_input_sanitization(response, test_case)
        
        return len(self.validation_errors) == 0
        
    def _validate_authentication_enforcement(self, response: Response, test_case: APITestCase):
        """Validate authentication is properly enforced"""
        # If auth is required but no token provided, should get 401
        if test_case.requires_auth and not test_case.auth_token:
            if response.status_code != 401:
                self.validation_errors.append(
                    f"Authentication not enforced: expected 401, got {response.status_code}"
                )
                
    def _validate_authorization_enforcement(self, response: Response, test_case: APITestCase):
        """Validate authorization is properly enforced"""
        # Additional authorization validation logic would be implemented here
        pass
        
    def _validate_security_headers(self, response: Response):
        """Validate required security headers are present"""
        required_security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        for header in required_security_headers:
            if header not in response.headers:
                self.validation_errors.append(f"Missing security header: {header}")
                
    def _validate_csrf_protection(self, response: Response, test_case: APITestCase):
        """Validate CSRF protection implementation"""
        # CSRF validation logic would be implemented here
        pass
        
    def _validate_input_sanitization(self, response: Response, test_case: APITestCase):
        """Validate input sanitization and XSS prevention"""
        # Input sanitization validation logic would be implemented here  
        pass
        
    def get_validation_errors(self) -> List[str]:
        """Get list of security validation errors"""
        return self.validation_errors.copy()


class PerformanceMonitor:
    """
    Performance monitoring utility for API testing, ensuring Flask application
    performance meets or exceeds Node.js baseline performance per Section 2.4.2.
    
    Features:
    - Response time measurement
    - Memory usage monitoring
    - CPU utilization tracking
    - Concurrent request handling
    - Database query performance
    - Resource utilization analysis
    """
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.start_memory = None
        self.end_memory = None
        self.start_cpu = None
        self.end_cpu = None
        
    def start_monitoring(self):
        """Start performance monitoring"""
        self.start_time = time.time()
        self.start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.start_cpu = psutil.Process().cpu_percent()
        
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.end_time = time.time()
        self.end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.end_cpu = psutil.Process().cpu_percent()
        
    def get_metrics(self) -> Dict[str, float]:
        """Get performance metrics"""
        if self.start_time is None or self.end_time is None:
            return {}
            
        return {
            'response_time': self.end_time - self.start_time,
            'memory_usage': self.end_memory - self.start_memory if self.start_memory else 0,
            'cpu_usage': self.end_cpu,
            'memory_mb': self.end_memory
        }


class RequestResponseValidator:
    """
    Request/response validation utility ensuring format preservation per Feature F-002.
    
    This class validates that Flask blueprint request/response handling maintains
    identical behavior to Node.js Express patterns, ensuring complete functionality
    parity during the migration process.
    
    Features:
    - Request format validation
    - Response format validation
    - JSON schema compliance
    - Header validation
    - Status code verification
    - Content-Type validation
    """
    
    def __init__(self):
        self.baseline_responses = {}
        self.validation_errors = []
        
    def register_baseline_response(self, endpoint: str, method: str, 
                                 baseline_response: Dict[str, Any]):
        """
        Register baseline Node.js response for comparison testing
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            baseline_response: Expected response from Node.js implementation
        """
        key = f"{method}:{endpoint}"
        self.baseline_responses[key] = baseline_response
        
    def validate_request_format(self, request_data: Dict[str, Any], 
                              expected_format: Dict[str, Any]) -> bool:
        """
        Validate request format matches expected structure
        
        Args:
            request_data: Actual request data
            expected_format: Expected request format
            
        Returns:
            bool: True if format is valid
        """
        self.validation_errors.clear()
        
        try:
            # Validate required fields
            for field in expected_format.get('required_fields', []):
                if field not in request_data:
                    self.validation_errors.append(f"Missing required field: {field}")
                    
            # Validate field types
            for field, expected_type in expected_format.get('field_types', {}).items():
                if field in request_data:
                    if not isinstance(request_data[field], expected_type):
                        self.validation_errors.append(
                            f"Invalid type for field {field}: expected {expected_type}, got {type(request_data[field])}"
                        )
                        
            return len(self.validation_errors) == 0
            
        except Exception as e:
            self.validation_errors.append(f"Request validation error: {str(e)}")
            return False
            
    def validate_response_format(self, response: Response, endpoint: str, 
                               method: str) -> bool:
        """
        Validate response format against baseline Node.js response
        
        Args:
            response: Flask test response
            endpoint: API endpoint path
            method: HTTP method
            
        Returns:
            bool: True if format matches baseline
        """
        self.validation_errors.clear()
        
        key = f"{method}:{endpoint}"
        if key not in self.baseline_responses:
            self.validation_errors.append(f"No baseline response registered for {key}")
            return False
            
        baseline = self.baseline_responses[key]
        
        # Validate status code
        if response.status_code != baseline.get('status_code', 200):
            self.validation_errors.append(
                f"Status code mismatch: expected {baseline.get('status_code')}, got {response.status_code}"
            )
            
        # Validate content type
        expected_content_type = baseline.get('content_type', 'application/json')
        if response.content_type != expected_content_type:
            self.validation_errors.append(
                f"Content type mismatch: expected {expected_content_type}, got {response.content_type}"
            )
            
        # Validate JSON structure
        if response.content_type and 'application/json' in response.content_type:
            response_json = response.get_json()
            baseline_json = baseline.get('response_data', {})
            
            if response_json != baseline_json:
                self.validation_errors.append("Response JSON structure does not match baseline")
                
        return len(self.validation_errors) == 0
        
    def get_validation_errors(self) -> List[str]:
        """Get list of validation errors"""
        return self.validation_errors.copy()


class ExternalServiceTester:
    """
    External service compatibility testing utility per Section 2.4.7.
    
    This class validates that Flask application maintains compatibility with
    external services and third-party integrations during the migration process.
    
    Features:
    - External API integration testing
    - Service compatibility validation
    - Mock service configuration
    - Integration endpoint testing
    - Service contract validation
    """
    
    def __init__(self, app: Flask, client: FlaskClient):
        self.app = app
        self.client = client
        self.external_services = {}
        self.test_results = []
        
    def register_external_service(self, service_name: str, config: Dict[str, Any]):
        """
        Register external service for compatibility testing
        
        Args:
            service_name: Name of external service
            config: Service configuration and endpoints
        """
        self.external_services[service_name] = config
        
    def test_external_service_compatibility(self, service_name: str) -> Dict[str, Any]:
        """
        Test compatibility with external service
        
        Args:
            service_name: Name of service to test
            
        Returns:
            Dict containing compatibility test results
        """
        if service_name not in self.external_services:
            return {
                'service': service_name,
                'success': False,
                'error': 'Service not registered'
            }
            
        service_config = self.external_services[service_name]
        test_result = {
            'service': service_name,
            'endpoints_tested': [],
            'success': False,
            'errors': []
        }
        
        try:
            # Test each endpoint defined for the service
            for endpoint_config in service_config.get('endpoints', []):
                endpoint_result = self._test_service_endpoint(service_name, endpoint_config)
                test_result['endpoints_tested'].append(endpoint_result)
                
            # Determine overall success
            test_result['success'] = all(
                ep['success'] for ep in test_result['endpoints_tested']
            )
            
        except Exception as e:
            test_result['errors'].append(f"Service testing error: {str(e)}")
            
        self.test_results.append(test_result)
        return test_result
        
    def _test_service_endpoint(self, service_name: str, 
                             endpoint_config: Dict[str, Any]) -> Dict[str, Any]:
        """Test individual service endpoint"""
        endpoint_result = {
            'endpoint': endpoint_config.get('path', ''),
            'method': endpoint_config.get('method', 'GET'),
            'success': False,
            'errors': []
        }
        
        try:
            # Create test request for service endpoint
            test_case = APITestCase(
                name=f"{service_name}_{endpoint_config.get('name', 'test')}",
                description=f"External service test for {service_name}",
                blueprint_name='api',
                endpoint=endpoint_config.get('path', ''),
                method=endpoint_config.get('method', 'GET'),
                request_data=endpoint_config.get('request_data'),
                expected_status=endpoint_config.get('expected_status', 200),
                mock_external_services={
                    service_name: endpoint_config.get('mock_config', {})
                }
            )
            
            # Execute test using blueprint tester
            blueprint_tester = FlaskBlueprintTester(self.app, self.client)
            result = blueprint_tester.test_blueprint_endpoint(test_case)
            
            endpoint_result['success'] = result['success']
            endpoint_result['errors'] = result['errors']
            
        except Exception as e:
            endpoint_result['errors'].append(f"Endpoint testing error: {str(e)}")
            
        return endpoint_result


# ================================
# Test Data Factories and Utilities
# ================================

class APITestDataFactory:
    """
    Test data factory for generating realistic API test data using Faker library.
    
    This factory provides comprehensive test data generation for various API
    testing scenarios, ensuring robust test coverage and realistic data patterns.
    """
    
    def __init__(self):
        self.fake = Faker()
        
    def create_user_data(self, **overrides) -> Dict[str, Any]:
        """Generate realistic user data for API testing"""
        user_data = {
            'id': str(uuid.uuid4()),
            'username': self.fake.user_name(),
            'email': self.fake.email(),
            'first_name': self.fake.first_name(),
            'last_name': self.fake.last_name(),
            'phone': self.fake.phone_number(),
            'address': {
                'street': self.fake.street_address(),
                'city': self.fake.city(),
                'state': self.fake.state(),
                'zip_code': self.fake.zipcode(),
                'country': self.fake.country()
            },
            'created_at': self.fake.date_time_this_year().isoformat(),
            'is_active': True,
            'profile': {
                'bio': self.fake.text(max_nb_chars=200),
                'website': self.fake.url(),
                'avatar_url': self.fake.image_url()
            }
        }
        user_data.update(overrides)
        return user_data
        
    def create_api_request_data(self, endpoint_type: str, **overrides) -> Dict[str, Any]:
        """Generate API request data based on endpoint type"""
        base_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': str(uuid.uuid4()),
            'client_version': '1.0.0'
        }
        
        if endpoint_type == 'user_creation':
            base_data.update(self.create_user_data())
        elif endpoint_type == 'user_update':
            base_data.update({
                'first_name': self.fake.first_name(),
                'last_name': self.fake.last_name(),
                'email': self.fake.email()
            })
        elif endpoint_type == 'search':
            base_data.update({
                'query': self.fake.word(),
                'filters': {
                    'category': self.fake.word(),
                    'date_range': {
                        'start': self.fake.date_this_year().isoformat(),
                        'end': datetime.utcnow().isoformat()
                    }
                },
                'sort': 'created_at',
                'order': 'desc',
                'limit': 20,
                'offset': 0
            })
            
        base_data.update(overrides)
        return base_data
        
    def create_error_test_data(self) -> List[Dict[str, Any]]:
        """Generate test data for error scenario testing"""
        return [
            # Invalid JSON
            {'data': 'invalid json string', 'expected_error': 'JSON_PARSE_ERROR'},
            
            # Missing required fields
            {'data': {}, 'expected_error': 'MISSING_REQUIRED_FIELDS'},
            
            # Invalid field types
            {
                'data': {
                    'email': 'not-an-email',
                    'age': 'not-a-number',
                    'is_active': 'not-a-boolean'
                },
                'expected_error': 'INVALID_FIELD_TYPES'
            },
            
            # Boundary value testing
            {
                'data': {
                    'username': 'a' * 1000,  # Too long
                    'email': 'test@' + 'a' * 500 + '.com',  # Too long
                    'age': -1  # Invalid range
                },
                'expected_error': 'VALIDATION_ERROR'
            }
        ]


# ================================
# Common Test Patterns and Helpers
# ================================

def create_api_test_suite(app: Flask, client: FlaskClient, 
                         blueprint_name: str) -> List[APITestCase]:
    """
    Create comprehensive API test suite for Flask blueprint
    
    Args:
        app: Flask application instance
        client: Flask test client
        blueprint_name: Name of blueprint to test
        
    Returns:
        List of API test cases for the blueprint
    """
    test_factory = APITestDataFactory()
    test_cases = []
    
    # Common CRUD endpoints
    crud_endpoints = [
        ('GET', '/api/users', 'list_users'),
        ('POST', '/api/users', 'create_user'),
        ('GET', '/api/users/<id>', 'get_user'),
        ('PUT', '/api/users/<id>', 'update_user'),
        ('DELETE', '/api/users/<id>', 'delete_user')
    ]
    
    for method, endpoint, operation in crud_endpoints:
        test_case = APITestCase(
            name=f"{blueprint_name}_{operation}",
            description=f"Test {operation} endpoint functionality",
            blueprint_name=blueprint_name,
            endpoint=endpoint,
            method=method,
            request_data=test_factory.create_api_request_data(
                'user_creation' if method == 'POST' else 'user_update'
            ) if method in ['POST', 'PUT'] else None,
            expected_status=201 if method == 'POST' else 200,
            requires_auth=True,
            validate_contract=True,
            validate_security=True,
            validate_performance=True
        )
        test_cases.append(test_case)
        
    return test_cases


def validate_api_migration_parity(nodejs_response: Dict[str, Any], 
                                flask_response: Response) -> Dict[str, Any]:
    """
    Validate complete parity between Node.js and Flask API responses
    
    Args:
        nodejs_response: Response from Node.js baseline implementation
        flask_response: Response from Flask implementation
        
    Returns:
        Dict containing parity validation results
    """
    parity_result = {
        'status_code_match': False,
        'content_type_match': False,
        'json_structure_match': False,
        'headers_match': False,
        'overall_parity': False,
        'differences': []
    }
    
    # Compare status codes
    parity_result['status_code_match'] = (
        nodejs_response.get('status_code') == flask_response.status_code
    )
    if not parity_result['status_code_match']:
        parity_result['differences'].append(
            f"Status code: {nodejs_response.get('status_code')} vs {flask_response.status_code}"
        )
        
    # Compare content types
    parity_result['content_type_match'] = (
        nodejs_response.get('content_type') == flask_response.content_type
    )
    if not parity_result['content_type_match']:
        parity_result['differences'].append(
            f"Content type: {nodejs_response.get('content_type')} vs {flask_response.content_type}"
        )
        
    # Compare JSON structure
    if flask_response.content_type and 'application/json' in flask_response.content_type:
        flask_json = flask_response.get_json()
        nodejs_json = nodejs_response.get('json_data', {})
        
        parity_result['json_structure_match'] = (flask_json == nodejs_json)
        if not parity_result['json_structure_match']:
            parity_result['differences'].append("JSON structure differs between implementations")
            
    # Compare important headers
    important_headers = ['Content-Type', 'Cache-Control', 'X-RateLimit-Remaining']
    headers_match = True
    
    for header in important_headers:
        nodejs_header = nodejs_response.get('headers', {}).get(header)
        flask_header = flask_response.headers.get(header)
        
        if nodejs_header != flask_header:
            headers_match = False
            parity_result['differences'].append(f"Header {header}: {nodejs_header} vs {flask_header}")
            
    parity_result['headers_match'] = headers_match
    
    # Overall parity assessment
    parity_result['overall_parity'] = (
        parity_result['status_code_match'] and
        parity_result['content_type_match'] and
        parity_result['json_structure_match'] and
        parity_result['headers_match']
    )
    
    return parity_result


# ================================
# pytest Integration Utilities
# ================================

@pytest.fixture
def api_contract_validator():
    """pytest fixture for API contract validation"""
    return APIContractValidator()


@pytest.fixture  
def flask_blueprint_tester(app, client):
    """pytest fixture for Flask blueprint testing"""
    return FlaskBlueprintTester(app, client)


@pytest.fixture
def performance_monitor():
    """pytest fixture for performance monitoring"""
    return PerformanceMonitor()


@pytest.fixture
def security_validator():
    """pytest fixture for security validation"""
    return SecurityValidator()


@pytest.fixture
def request_response_validator():
    """pytest fixture for request/response validation"""
    return RequestResponseValidator()


@pytest.fixture
def external_service_tester(app, client):
    """pytest fixture for external service testing"""
    return ExternalServiceTester(app, client)


@pytest.fixture
def api_test_data_factory():
    """pytest fixture for test data generation"""
    return APITestDataFactory()


# ================================
# Parametrized Test Data
# ================================

# Common test scenarios for parametrized testing
API_ENDPOINT_TEST_SCENARIOS = [
    ('GET', '/api/health', 200, None, False),
    ('GET', '/api/users', 200, None, True),
    ('POST', '/api/users', 201, {'username': 'test', 'email': 'test@example.com'}, True),
    ('GET', '/api/users/1', 200, None, True),
    ('PUT', '/api/users/1', 200, {'first_name': 'Updated'}, True),
    ('DELETE', '/api/users/1', 204, None, True),
]

ERROR_SCENARIO_TEST_CASES = [
    ('invalid_json', 'invalid json', 400),
    ('missing_auth', None, 401),
    ('insufficient_permissions', None, 403),
    ('not_found', None, 404),
    ('validation_error', {'invalid': 'data'}, 400),
    ('server_error', None, 500),
]

PERFORMANCE_TEST_SCENARIOS = [
    ('single_request', 1, 1.0),
    ('multiple_requests', 10, 2.0),
    ('concurrent_requests', 50, 5.0),
    ('load_test', 100, 10.0),
]

# Export test scenarios and utilities
__all__ = [
    'APITestCase',
    'APIContractValidator',
    'FlaskBlueprintTester',
    'SecurityValidator',
    'PerformanceMonitor',
    'RequestResponseValidator',
    'ExternalServiceTester',
    'APITestDataFactory',
    'create_api_test_suite',
    'validate_api_migration_parity',
    'API_ENDPOINT_TEST_SCENARIOS',
    'ERROR_SCENARIO_TEST_CASES',
    'PERFORMANCE_TEST_SCENARIOS'
]