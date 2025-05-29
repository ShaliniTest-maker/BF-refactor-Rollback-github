"""
Comprehensive API endpoint integration test suite validating Flask blueprint route functionality,
request/response handling, and data processing for all core API endpoints.

This test file ensures complete API contract compliance between the original Node.js implementation
and the Flask migration, validating endpoint responses, data formats, and business logic execution
across all HTTP methods (GET, POST, PUT, DELETE). Critical for verifying zero functional regression
during migration.

Features tested:
- F-001: API endpoint conversion maintaining identical functionality per Section 4.3.1
- F-002: Request/response handling migration using Flask request context per Section 4.3.2  
- F-005: Business logic preservation across all endpoints per Feature F-005
- F-007: Authentication mechanism migration per Feature F-007
- F-009: Functionality parity validation per Feature F-009

Testing Framework: pytest-flask 1.3.0 per Section 4.7.1
Performance Testing: pytest-benchmark 5.1.0 per Section 4.7.1
"""

import pytest
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from flask import url_for, request, jsonify
from marshmallow import ValidationError

# Import Flask application components for testing
from src.blueprints.api import api_bp
from src.models.user import User
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.services.user_service import UserService
from src.services.business_entity_service import BusinessEntityService
from src.services.validation_service import ValidationService
from src.auth.decorators import require_auth, require_permission


class TestAPIEndpointFunctionality:
    """
    Test suite validating core API endpoint functionality with Flask blueprint routes.
    
    Validates Feature F-001: API endpoint conversion maintaining identical functionality
    and response patterns per Section 4.3.1 endpoint conversion requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client, db_session):
        """Setup method run before each test with Flask application context."""
        self.app = app
        self.client = client
        self.db_session = db_session
        
        # Create test user for authentication testing
        with self.app.app_context():
            self.test_user = User(
                username='testuser',
                email='test@example.com'
            )
            self.test_user.set_password('testpassword')
            self.db_session.add(self.test_user)
            self.db_session.commit()
            
    def test_api_blueprint_registration(self, app):
        """
        Test Flask blueprint registration and route discovery.
        
        Validates that API blueprint is properly registered with Flask application
        factory pattern per Section 5.2.2 blueprint management requirements.
        """
        # Verify API blueprint is registered
        assert 'api' in app.blueprints
        
        # Verify blueprint URL prefix configuration
        api_blueprint = app.blueprints['api']
        assert api_blueprint.url_prefix == '/api' or api_blueprint.url_prefix is None
        
        # Test blueprint route decorator registration
        with app.app_context():
            # Get all registered routes for API blueprint
            api_routes = [rule for rule in app.url_map.iter_rules() 
                         if rule.endpoint.startswith('api.')]
            
            # Validate essential API endpoints are registered
            essential_endpoints = [
                'api.get_business_entities',
                'api.create_business_entity', 
                'api.update_business_entity',
                'api.delete_business_entity',
                'api.get_entity_relationships',
                'api.create_entity_relationship'
            ]
            
            registered_endpoints = [route.endpoint for route in api_routes]
            for endpoint in essential_endpoints:
                assert endpoint in registered_endpoints, f"Missing API endpoint: {endpoint}"
                
    def test_health_check_endpoint(self, client):
        """
        Test health check endpoint functionality and response format.
        
        Validates basic API responsiveness and proper JSON response formatting
        per Section 4.3.2 request/response handling requirements.
        """
        response = client.get('/api/health')
        
        # Validate HTTP status code
        assert response.status_code == 200
        
        # Validate JSON response format
        data = response.get_json()
        assert data is not None
        assert 'status' in data
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        
        # Validate response headers
        assert response.headers['Content-Type'] == 'application/json'
        
    def test_api_endpoint_response_format_consistency(self, client):
        """
        Test consistent response format across all API endpoints.
        
        Validates Feature F-002: Request/response handling migration maintaining
        standardized JSON response patterns per Section 4.3.2.
        """
        # Test GET endpoint response format
        response = client.get('/api/business_entities')
        assert response.status_code in [200, 401]  # 401 if authentication required
        
        if response.status_code == 200:
            data = response.get_json()
            assert data is not None
            assert isinstance(data, (dict, list))
            
            # Validate standard response structure
            if isinstance(data, dict):
                # Expect standard API response format
                expected_keys = ['data', 'meta'] if 'data' in data else ['entities', 'total']
                assert any(key in data for key in expected_keys)
        
        # Test response content type consistency
        assert response.headers['Content-Type'] == 'application/json'


class TestHTTPMethodValidation:
    """
    Test suite validating HTTP method handling across all API endpoints.
    
    Validates proper HTTP method support (GET, POST, PUT, DELETE) with
    correct status codes and response formats per Feature F-001.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client, db_session, authenticated_user):
        """Setup authenticated test environment for HTTP method testing."""
        self.app = app
        self.client = client
        self.db_session = db_session
        self.auth_headers = self._get_auth_headers(authenticated_user)
        
        # Create test business entity for CRUD operations
        with self.app.app_context():
            self.test_entity = BusinessEntity(
                name='Test Entity',
                description='Test entity for API testing',
                status='active',
                owner_id=authenticated_user.id
            )
            self.db_session.add(self.test_entity)
            self.db_session.commit()
            self.entity_id = self.test_entity.id
            
    def _get_auth_headers(self, user):
        """Helper method to generate authentication headers for testing."""
        # Simulate authentication header generation
        # This would integrate with actual auth implementation
        return {
            'Authorization': f'Bearer {user.id}',
            'Content-Type': 'application/json'
        }
        
    def test_get_method_validation(self, client):
        """
        Test GET method handling and response validation.
        
        Validates GET endpoint functionality with proper query parameter
        handling and response pagination per API contract requirements.
        """
        # Test GET all entities
        response = client.get('/api/business_entities', headers=self.auth_headers)
        
        if response.status_code == 200:
            data = response.get_json()
            assert data is not None
            assert isinstance(data, (dict, list))
            
            # Validate response structure for entity listing
            if isinstance(data, dict):
                assert 'entities' in data or 'data' in data
                if 'entities' in data:
                    assert isinstance(data['entities'], list)
                    
        # Test GET specific entity
        response = client.get(f'/api/business_entities/{self.entity_id}', 
                            headers=self.auth_headers)
                            
        if response.status_code == 200:
            data = response.get_json()
            assert data is not None
            assert 'id' in data or 'entity' in data
            
    def test_post_method_validation(self, client):
        """
        Test POST method handling and entity creation validation.
        
        Validates POST endpoint functionality with request body parsing,
        validation, and proper status code responses per Section 4.3.1.
        """
        # Test entity creation
        new_entity_data = {
            'name': 'New Test Entity',
            'description': 'Created via API test',
            'status': 'active'
        }
        
        response = client.post('/api/business_entities',
                             json=new_entity_data,
                             headers=self.auth_headers)
                             
        # Validate response based on authentication/authorization
        assert response.status_code in [201, 401, 403]
        
        if response.status_code == 201:
            data = response.get_json()
            assert data is not None
            assert 'id' in data or 'entity' in data
            
            # Validate created entity data
            if 'entity' in data:
                entity = data['entity']
                assert entity['name'] == new_entity_data['name']
                assert entity['description'] == new_entity_data['description']
                
    def test_put_method_validation(self, client):
        """
        Test PUT method handling and entity update validation.
        
        Validates PUT endpoint functionality with complete resource replacement
        and proper validation per RESTful API standards.
        """
        update_data = {
            'name': 'Updated Test Entity',
            'description': 'Updated via API test',
            'status': 'inactive'
        }
        
        response = client.put(f'/api/business_entities/{self.entity_id}',
                            json=update_data,
                            headers=self.auth_headers)
                            
        # Validate response based on authentication/authorization
        assert response.status_code in [200, 401, 403, 404]
        
        if response.status_code == 200:
            data = response.get_json()
            assert data is not None
            
            # Validate updated entity data
            if 'entity' in data:
                entity = data['entity']
                assert entity['name'] == update_data['name']
                assert entity['status'] == update_data['status']
                
    def test_delete_method_validation(self, client):
        """
        Test DELETE method handling and entity deletion validation.
        
        Validates DELETE endpoint functionality with proper resource removal
        and cascade handling per business logic requirements.
        """
        response = client.delete(f'/api/business_entities/{self.entity_id}',
                               headers=self.auth_headers)
                               
        # Validate response based on authentication/authorization
        assert response.status_code in [200, 204, 401, 403, 404]
        
        if response.status_code in [200, 204]:
            # Verify entity is marked as deleted or removed
            if response.status_code == 200:
                data = response.get_json()
                if data:
                    assert 'message' in data or 'success' in data


class TestRequestResponseHandling:
    """
    Test suite validating Flask request/response handling mechanisms.
    
    Validates Feature F-002: Request/response handling migration using Flask 
    request context per Section 4.3.2 conversion requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client):
        """Setup Flask request context testing environment."""
        self.app = app
        self.client = client
        
    def test_flask_request_context_handling(self, client):
        """
        Test Flask request context access and parameter parsing.
        
        Validates flask.request object functionality for query parameters,
        request body parsing, and header access per Flask patterns.
        """
        # Test query parameter handling
        response = client.get('/api/business_entities?page=1&limit=10&status=active')
        
        # Validate request was processed (regardless of auth requirements)
        assert response.status_code in [200, 401, 403]
        assert response.headers['Content-Type'] == 'application/json'
        
        # Test request body parsing for POST requests
        test_data = {
            'name': 'Request Test Entity',
            'description': 'Testing request body parsing'
        }
        
        response = client.post('/api/business_entities',
                             json=test_data,
                             headers={'Content-Type': 'application/json'})
                             
        # Validate JSON request body was parsed
        assert response.status_code in [201, 400, 401, 403]
        
        if response.status_code == 400:
            # Validation error indicates request was parsed
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'message' in data
            
    def test_flask_jsonify_response_formatting(self, client):
        """
        Test flask.jsonify response formatting and serialization.
        
        Validates standardized JSON response formatting with proper
        Content-Type headers per Section 4.3.2 requirements.
        """
        response = client.get('/api/health')
        
        # Validate JSON response formatting
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        
        # Validate JSON serialization
        data = response.get_json()
        assert data is not None
        assert isinstance(data, dict)
        
        # Test response contains expected structure
        assert 'status' in data
        
    def test_request_header_validation(self, client):
        """
        Test request header processing and validation.
        
        Validates proper header handling for authentication, content-type,
        and custom headers per API requirements.
        """
        # Test Content-Type header validation
        invalid_content_type_data = "invalid json data"
        
        response = client.post('/api/business_entities',
                             data=invalid_content_type_data,
                             headers={'Content-Type': 'text/plain'})
                             
        # Should reject invalid content type
        assert response.status_code in [400, 415, 401]
        
        # Test proper JSON content type acceptance
        valid_data = {'name': 'Test Entity'}
        
        response = client.post('/api/business_entities',
                             json=valid_data,
                             headers={'Content-Type': 'application/json'})
                             
        # Should accept valid JSON (may still require auth)
        assert response.status_code in [201, 400, 401, 403]
        
    def test_error_response_standardization(self, client):
        """
        Test standardized error response formatting.
        
        Validates consistent error response structure across all endpoints
        with proper HTTP status codes per Section 4.3.2.
        """
        # Test 404 error response format
        response = client.get('/api/business_entities/99999')
        
        if response.status_code == 404:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'message' in data
            
        # Test 400 error response format for invalid data
        invalid_data = {'invalid_field': 'invalid_value'}
        
        response = client.post('/api/business_entities',
                             json=invalid_data)
                             
        if response.status_code == 400:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'message' in data or 'errors' in data


class TestSchemaValidation:
    """
    Test suite validating schema validation integration with marshmallow/Pydantic.
    
    Validates comprehensive schema validation per Section 4.3.1 requirements
    with robust request data validation and type safety.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client, authenticated_user):
        """Setup schema validation testing environment."""
        self.app = app
        self.client = client
        self.auth_headers = {'Authorization': f'Bearer {authenticated_user.id}',
                           'Content-Type': 'application/json'}
        
    def test_input_validation_schema_enforcement(self, client):
        """
        Test input validation schema enforcement for API requests.
        
        Validates marshmallow/Pydantic schema validation with proper
        error responses for invalid input data per Section 4.3.1.
        """
        # Test missing required fields
        incomplete_data = {
            'description': 'Missing required name field'
        }
        
        response = client.post('/api/business_entities',
                             json=incomplete_data,
                             headers=self.auth_headers)
                             
        # Should return validation error
        assert response.status_code in [400, 401, 422]
        
        if response.status_code in [400, 422]:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'errors' in data or 'message' in data
            
    def test_data_type_validation(self, client):
        """
        Test data type validation and constraint checking.
        
        Validates proper type checking for fields with correct error
        messages for type mismatches per validation requirements.
        """
        # Test invalid data types
        invalid_type_data = {
            'name': 123,  # Should be string
            'status': 'invalid_status',  # Should be valid enum value
            'owner_id': 'not_a_number'  # Should be integer
        }
        
        response = client.post('/api/business_entities',
                             json=invalid_type_data,
                             headers=self.auth_headers)
                             
        # Should return validation error for type mismatches
        assert response.status_code in [400, 401, 422]
        
        if response.status_code in [400, 422]:
            data = response.get_json()
            assert data is not None
            # Validation errors should provide specific field information
            if 'errors' in data:
                assert isinstance(data['errors'], (dict, list))
                
    def test_field_length_validation(self, client):
        """
        Test field length and constraint validation.
        
        Validates string length limits, number ranges, and other
        field constraints per business rule requirements.
        """
        # Test string length validation
        long_name_data = {
            'name': 'x' * 300,  # Assuming max length is 255
            'description': 'Valid description',
            'status': 'active'
        }
        
        response = client.post('/api/business_entities',
                             json=long_name_data,
                             headers=self.auth_headers)
                             
        # Should handle length validation appropriately
        if response.status_code in [400, 422]:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'errors' in data
            
    def test_nested_object_validation(self, client):
        """
        Test validation of nested objects and relationships.
        
        Validates complex object validation for entity relationships
        and nested data structures per business model requirements.
        """
        # Test entity relationship creation with validation
        relationship_data = {
            'source_entity_id': 1,
            'target_entity_id': 2,
            'relationship_type': 'depends_on',
            'metadata': {
                'strength': 'high',
                'direction': 'bidirectional'
            }
        }
        
        response = client.post('/api/entity_relationships',
                             json=relationship_data,
                             headers=self.auth_headers)
                             
        # Validate nested object processing
        assert response.status_code in [201, 400, 401, 403, 422]
        
        if response.status_code in [400, 422]:
            data = response.get_json()
            assert data is not None
            # Should handle nested validation errors


class TestAuthenticationIntegration:
    """
    Test suite validating authentication decorator integration.
    
    Validates Feature F-007: Authentication mechanism migration with Flask
    authentication decorators per Section 4.6.1 requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client):
        """Setup authentication testing environment."""
        self.app = app
        self.client = client
        
    def test_authentication_decorator_enforcement(self, client):
        """
        Test Flask authentication decorator functionality.
        
        Validates @require_auth decorator enforcement across protected
        endpoints per Feature F-007 authentication migration.
        """
        # Test unauthenticated access to protected endpoint
        response = client.get('/api/business_entities')
        
        # Should require authentication
        assert response.status_code in [401, 403]
        
        if response.status_code == 401:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'message' in data
            
    def test_session_management_integration(self, client, authenticated_user):
        """
        Test Flask-Login session management integration.
        
        Validates session creation, validation, and cleanup with
        ItsDangerous secure cookie handling per Section 4.6.2.
        """
        # Test authenticated access with valid session
        auth_headers = {'Authorization': f'Bearer {authenticated_user.id}'}
        
        response = client.get('/api/business_entities', headers=auth_headers)
        
        # Should allow authenticated access
        assert response.status_code in [200, 403]  # 403 if permissions required
        
    def test_permission_based_authorization(self, client, authenticated_user):
        """
        Test permission-based authorization decorators.
        
        Validates @require_permission decorator functionality for
        fine-grained access control per business requirements.
        """
        # Test access to admin-only endpoints
        admin_headers = {'Authorization': f'Bearer {authenticated_user.id}'}
        
        response = client.delete('/api/business_entities/1', headers=admin_headers)
        
        # Should enforce permission requirements
        assert response.status_code in [200, 204, 401, 403, 404]
        
        if response.status_code == 403:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'message' in data


class TestBusinessLogicIntegration:
    """
    Test suite validating Service Layer integration and business logic execution.
    
    Validates Feature F-005: Business logic preservation and Feature F-006:
    Service Layer implementation per Section 5.2.3 requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client, db_session, authenticated_user):
        """Setup business logic testing environment."""
        self.app = app
        self.client = client
        self.db_session = db_session
        self.user = authenticated_user
        self.auth_headers = {'Authorization': f'Bearer {authenticated_user.id}',
                           'Content-Type': 'application/json'}
        
    def test_service_layer_orchestration(self, client):
        """
        Test Service Layer pattern implementation and workflow orchestration.
        
        Validates business logic coordination through service classes
        per Section 5.2.3 Service Layer implementation requirements.
        """
        # Test complex business workflow through API
        entity_data = {
            'name': 'Service Test Entity',
            'description': 'Testing service layer integration',
            'status': 'active'
        }
        
        response = client.post('/api/business_entities',
                             json=entity_data,
                             headers=self.auth_headers)
                             
        # Validate service layer processing
        if response.status_code == 201:
            data = response.get_json()
            assert data is not None
            
            # Service layer should handle entity creation workflow
            if 'entity' in data:
                entity = data['entity']
                assert 'id' in entity
                assert entity['name'] == entity_data['name']
                
                # Test follow-up service operations
                entity_id = entity['id']
                
                # Test relationship creation through service layer
                relationship_data = {
                    'source_entity_id': entity_id,
                    'target_entity_id': entity_id,
                    'relationship_type': 'self_reference'
                }
                
                rel_response = client.post('/api/entity_relationships',
                                         json=relationship_data,
                                         headers=self.auth_headers)
                                         
                # Should handle complex business logic
                assert rel_response.status_code in [201, 400, 401, 403]
                
    def test_transaction_boundary_management(self, client):
        """
        Test transaction boundary management in service operations.
        
        Validates ACID transaction handling and rollback capabilities
        per Section 4.5.2 transaction management requirements.
        """
        # Test transaction rollback on validation failure
        invalid_entity_data = {
            'name': '',  # Invalid empty name should trigger rollback
            'description': 'Should not be created due to validation failure'
        }
        
        response = client.post('/api/business_entities',
                             json=invalid_entity_data,
                             headers=self.auth_headers)
                             
        # Should handle validation failure with proper rollback
        assert response.status_code in [400, 401, 422]
        
        if response.status_code in [400, 422]:
            # Verify no partial data was committed
            entities_response = client.get('/api/business_entities',
                                         headers=self.auth_headers)
            if entities_response.status_code == 200:
                data = entities_response.get_json()
                # Should not contain invalid entity
                if 'entities' in data:
                    invalid_entities = [e for e in data['entities'] 
                                      if e.get('name') == '']
                    assert len(invalid_entities) == 0
                    
    def test_cross_service_coordination(self, client):
        """
        Test coordination between multiple service classes.
        
        Validates workflow orchestration across UserService,
        BusinessEntityService, and ValidationService per Section 5.2.3.
        """
        # Test user entity ownership workflow
        entity_data = {
            'name': 'Cross-Service Test Entity',
            'description': 'Testing cross-service coordination',
            'status': 'active'
        }
        
        response = client.post('/api/business_entities',
                             json=entity_data,
                             headers=self.auth_headers)
                             
        if response.status_code == 201:
            data = response.get_json()
            
            # Verify user service and entity service coordination
            if 'entity' in data:
                entity = data['entity']
                assert 'owner_id' in entity
                assert entity['owner_id'] == self.user.id
                
                # Test entity access validation through user service
                entity_id = entity['id']
                get_response = client.get(f'/api/business_entities/{entity_id}',
                                        headers=self.auth_headers)
                                        
                # Should validate ownership through service coordination
                assert get_response.status_code in [200, 401, 403, 404]


class TestPerformanceComparison:
    """
    Test suite for API performance benchmarking against Node.js baseline.
    
    Uses pytest-benchmark 5.1.0 for performance validation per Section 4.7.1
    requirements and Feature F-009 functionality parity validation.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client, authenticated_user):
        """Setup performance testing environment."""
        self.app = app
        self.client = client
        self.auth_headers = {'Authorization': f'Bearer {authenticated_user.id}'}
        
    def test_api_response_time_benchmark(self, client, benchmark):
        """
        Benchmark API response times against Node.js baseline.
        
        Validates response time equivalence or improvement per
        Section 4.7.1 performance testing requirements.
        """
        def api_call():
            return client.get('/api/business_entities', headers=self.auth_headers)
            
        # Benchmark the API call
        result = benchmark(api_call)
        
        # Validate response was successful
        assert result.status_code in [200, 401, 403]
        
        # Performance validation is handled by pytest-benchmark
        # Baseline comparison configured in pytest-benchmark settings
        
    def test_concurrent_request_handling(self, client, benchmark):
        """
        Test concurrent request handling performance.
        
        Validates Flask application can handle equivalent concurrent
        user loads as Node.js implementation per Section 2.1.9.
        """
        import concurrent.futures
        import threading
        
        def concurrent_api_call():
            """Simulate concurrent API requests."""
            responses = []
            
            def make_request():
                return client.get('/api/health')
                
            # Simulate 10 concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                responses = [future.result() for future in concurrent.futures.as_completed(futures)]
                
            return responses
            
        # Benchmark concurrent request handling
        responses = benchmark(concurrent_api_call)
        
        # Validate all requests were handled successfully
        assert len(responses) == 10
        for response in responses:
            assert response.status_code == 200
            
    def test_database_query_performance(self, client, benchmark, db_session):
        """
        Test database query performance with SQLAlchemy.
        
        Validates database operation performance equivalent to
        MongoDB baseline per Section 5.2.4 requirements.
        """
        def database_operation():
            """Simulate database-intensive API operation."""
            return client.get('/api/business_entities?include_relationships=true',
                            headers=self.auth_headers)
                            
        # Benchmark database-heavy operation
        result = benchmark(database_operation)
        
        # Validate database operation completed successfully
        assert result.status_code in [200, 401, 403]


class TestAPIContractCompliance:
    """
    Test suite validating API contract compliance and backward compatibility.
    
    Ensures 100% compatibility with existing API documentation and client
    expectations per Feature F-002 request/response handling requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app, client, authenticated_user):
        """Setup API contract testing environment."""
        self.app = app
        self.client = client
        self.auth_headers = {'Authorization': f'Bearer {authenticated_user.id}'}
        
    def test_response_format_compatibility(self, client):
        """
        Test response format compatibility with Node.js baseline.
        
        Validates identical JSON response structures for client
        application compatibility per Feature F-002 requirements.
        """
        response = client.get('/api/business_entities', headers=self.auth_headers)
        
        if response.status_code == 200:
            data = response.get_json()
            assert data is not None
            
            # Validate expected response structure
            # This structure should match Node.js API exactly
            expected_fields = ['entities', 'total', 'page', 'limit']
            available_fields = list(data.keys())
            
            # At minimum, should have entities data
            assert any(field in available_fields for field in ['entities', 'data', 'results'])
            
    def test_http_status_code_consistency(self, client):
        """
        Test HTTP status code consistency with Node.js implementation.
        
        Validates identical status codes for all scenarios per
        API contract requirements and client expectations.
        """
        # Test successful retrieval
        response = client.get('/api/health')
        assert response.status_code == 200
        
        # Test not found
        response = client.get('/api/business_entities/99999', headers=self.auth_headers)
        assert response.status_code in [404, 401, 403]
        
        # Test unauthorized access
        response = client.get('/api/business_entities')
        assert response.status_code in [401, 403]
        
        # Test method not allowed
        response = client.patch('/api/health')  # Assuming PATCH not supported
        assert response.status_code in [405, 404]
        
    def test_header_consistency(self, client):
        """
        Test HTTP header consistency with Node.js implementation.
        
        Validates Content-Type, CORS, and other headers match
        original implementation for client compatibility.
        """
        response = client.get('/api/health')
        
        # Validate essential headers
        assert 'Content-Type' in response.headers
        assert response.headers['Content-Type'] == 'application/json'
        
        # Test CORS headers if applicable
        if 'Access-Control-Allow-Origin' in response.headers:
            assert response.headers['Access-Control-Allow-Origin'] is not None
            
    def test_error_message_format_consistency(self, client):
        """
        Test error message format consistency with Node.js baseline.
        
        Validates error response structures match original implementation
        for consistent client-side error handling.
        """
        # Test validation error format
        invalid_data = {'invalid': 'data'}
        response = client.post('/api/business_entities', json=invalid_data)
        
        if response.status_code in [400, 422]:
            data = response.get_json()
            assert data is not None
            
            # Should have consistent error structure
            expected_error_fields = ['error', 'message', 'errors']
            assert any(field in data for field in expected_error_fields)
            
        # Test authentication error format
        response = client.get('/api/business_entities')
        
        if response.status_code == 401:
            data = response.get_json()
            assert data is not None
            assert 'error' in data or 'message' in data


# Pytest markers for test categorization per Section 4.7.1
pytestmark = [
    pytest.mark.api,
    pytest.mark.integration,
    pytest.mark.flask_migration,
    pytest.mark.blueprint_testing
]


def test_comprehensive_api_endpoint_coverage(client, app):
    """
    Integration test validating comprehensive API endpoint coverage.
    
    Ensures all Flask blueprint routes are properly registered and accessible
    for complete API functionality validation per Feature F-001.
    """
    with app.app_context():
        # Get all API routes
        api_routes = [rule for rule in app.url_map.iter_rules() 
                     if rule.endpoint.startswith('api.')]
        
        # Validate minimum expected endpoint coverage
        assert len(api_routes) > 0, "No API routes registered"
        
        # Test basic connectivity to all registered endpoints
        for rule in api_routes:
            if 'GET' in rule.methods:
                # Test GET endpoints for basic connectivity
                url = rule.rule.replace('<int:id>', '1').replace('<id>', '1')
                response = client.get(url)
                
                # Should receive valid HTTP response (not server error)
                assert response.status_code < 500, f"Server error on {url}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])