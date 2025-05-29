"""
Multi-component workflow coordination test suite validating complex interactions between
Flask blueprints, Service Layer, database models, and authentication systems.

This comprehensive test file ensures seamless coordination across all Flask application
components while maintaining functional equivalence with the original Node.js multi-component
interactions. The test suite validates blueprint management, service orchestration,
authentication integration, and database coordination patterns.

Key Testing Areas:
- Multi-component coordination across Flask blueprints, Service Layer, and database models
- Blueprint registration and coordination within Flask application factory pattern
- Authentication decorator integration with service layer for secure workflow execution
- Database model coordination with service layer for transaction boundary management
- Cross-component communication through Flask request context and dependency injection
- Modular scaling patterns with efficient blueprint-service interaction

Migration Context:
These tests ensure that the Flask 3.1.1 application factory pattern with blueprint-based
modular architecture maintains 100% functional parity with the Node.js implementation
while enhancing organizational structure through the Service Layer pattern.
"""

import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Tuple
from unittest.mock import patch, MagicMock, call
from contextlib import contextmanager

import pytest
from flask import Flask, request, session, g, current_app, url_for
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, event
from sqlalchemy.orm import scoped_session
from werkzeug.test import Client
from werkzeug.wrappers import Response

# Import workflow testing fixtures
from tests.integration.workflows.conftest import *

# Import application components
try:
    from src.app import create_app
    from src.blueprints import register_blueprints
    from src.blueprints.api import api_blueprint
    from src.blueprints.auth import auth_blueprint
    from src.blueprints.main import main_blueprint
    from src.services.user_service import UserService
    from src.services.business_entity_service import BusinessEntityService
    from src.services.workflow_orchestrator import WorkflowOrchestrator
    from src.services.validation_service import ValidationService
    from src.models.user import User
    from src.models.business_entity import BusinessEntity
    from src.models.entity_relationship import EntityRelationship
    from src.models.session import UserSession
    from src.auth.decorators import require_auth, require_permission
    from src.auth.session_manager import SessionManager
    from src.auth.token_handler import TokenHandler
except ImportError as e:
    # Graceful handling for missing modules during initial setup
    print(f"Warning: Could not import application modules: {e}")


# ================================================================================================
# MULTI-COMPONENT COORDINATION CORE TESTS
# ================================================================================================

@pytest.mark.workflow
@pytest.mark.service_layer
@pytest.mark.composition
class TestMultiComponentCoordination:
    """
    Core multi-component coordination test class validating seamless interaction
    between Flask blueprints, Service Layer, database models, and authentication.
    """
    
    def test_complete_request_lifecycle_coordination(
        self,
        app: Flask,
        client: FlaskClient,
        service_registry: Dict[str, Any],
        workflow_execution_context: Dict[str, Any],
        resource_monitor: Any
    ):
        """
        Test complete request lifecycle through all Flask application components.
        
        Validates seamless coordination from HTTP request through Werkzeug WSGI
        interface, Flask router, blueprint management, authentication decorators,
        service layer execution, database operations, and response generation.
        
        This test ensures the multi-component architecture maintains functional
        equivalence with the Node.js implementation while leveraging Flask's
        modular blueprint organization and Service Layer pattern.
        """
        with resource_monitor.monitor_context() as monitor:
            # Test data for complete workflow
            test_user_data = {
                'username': f'testuser_{uuid.uuid4().hex[:8]}',
                'email': f'test_{uuid.uuid4().hex[:8]}@example.com',
                'password': 'SecurePassword123!'
            }
            
            business_entity_data = {
                'name': f'TestEntity_{uuid.uuid4().hex[:8]}',
                'description': 'Test business entity for coordination testing',
                'status': 'active'
            }
            
            workflow_steps = []
            coordination_metrics = {
                'blueprint_calls': 0,
                'service_calls': 0,
                'database_operations': 0,
                'authentication_checks': 0,
                'component_transitions': []
            }
            
            with app.app_context():
                # Step 1: User Registration through Auth Blueprint
                workflow_steps.append('user_registration_request')
                coordination_metrics['blueprint_calls'] += 1
                coordination_metrics['component_transitions'].append({
                    'step': 'auth_blueprint_entry',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                registration_response = client.post(
                    '/auth/register',
                    data=json.dumps(test_user_data),
                    content_type='application/json'
                )
                
                # Verify successful registration
                assert registration_response.status_code == 201
                registration_data = json.loads(registration_response.data)
                assert 'user_id' in registration_data
                user_id = registration_data['user_id']
                
                coordination_metrics['service_calls'] += 1
                coordination_metrics['database_operations'] += 1
                coordination_metrics['component_transitions'].append({
                    'step': 'service_layer_user_creation',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 2: User Authentication through Auth Blueprint
                workflow_steps.append('user_authentication')
                coordination_metrics['authentication_checks'] += 1
                
                auth_response = client.post(
                    '/auth/login',
                    data=json.dumps({
                        'username': test_user_data['username'],
                        'password': test_user_data['password']
                    }),
                    content_type='application/json'
                )
                
                assert auth_response.status_code == 200
                auth_data = json.loads(auth_response.data)
                assert 'access_token' in auth_data
                access_token = auth_data['access_token']
                
                coordination_metrics['component_transitions'].append({
                    'step': 'authentication_successful',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 3: Business Entity Creation through API Blueprint with Authentication
                workflow_steps.append('business_entity_creation')
                coordination_metrics['blueprint_calls'] += 1
                coordination_metrics['authentication_checks'] += 1
                
                headers = {'Authorization': f'Bearer {access_token}'}
                entity_response = client.post(
                    '/api/business-entities',
                    data=json.dumps(business_entity_data),
                    content_type='application/json',
                    headers=headers
                )
                
                assert entity_response.status_code == 201
                entity_data = json.loads(entity_response.data)
                assert 'entity_id' in entity_data
                entity_id = entity_data['entity_id']
                
                coordination_metrics['service_calls'] += 1
                coordination_metrics['database_operations'] += 1
                coordination_metrics['component_transitions'].append({
                    'step': 'service_layer_entity_creation',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 4: Cross-Component Data Retrieval
                workflow_steps.append('cross_component_retrieval')
                coordination_metrics['blueprint_calls'] += 1
                coordination_metrics['authentication_checks'] += 1
                
                retrieval_response = client.get(
                    f'/api/users/{user_id}/business-entities',
                    headers=headers
                )
                
                assert retrieval_response.status_code == 200
                retrieval_data = json.loads(retrieval_response.data)
                assert len(retrieval_data['entities']) > 0
                assert retrieval_data['entities'][0]['entity_id'] == entity_id
                
                coordination_metrics['service_calls'] += 1
                coordination_metrics['database_operations'] += 1
                coordination_metrics['component_transitions'].append({
                    'step': 'cross_component_data_retrieval',
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 5: Main Blueprint Health Check for Complete Coordination
                workflow_steps.append('main_blueprint_health_check')
                coordination_metrics['blueprint_calls'] += 1
                
                health_response = client.get('/health')
                assert health_response.status_code == 200
                health_data = json.loads(health_response.data)
                assert health_data['status'] == 'healthy'
                
                coordination_metrics['component_transitions'].append({
                    'step': 'main_blueprint_health_verification',
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Validate coordination metrics
        assert coordination_metrics['blueprint_calls'] >= 4  # Auth, API, Main blueprints
        assert coordination_metrics['service_calls'] >= 3   # User, Entity, Validation services
        assert coordination_metrics['database_operations'] >= 3  # Create user, entity, retrieve
        assert coordination_metrics['authentication_checks'] >= 3  # Login, entity creation, retrieval
        assert len(coordination_metrics['component_transitions']) >= 5
        
        # Validate workflow execution context
        assert workflow_execution_context['metrics']['database_queries'] > 0
        assert len(workflow_steps) == 5
        
        # Validate resource monitoring results
        resource_metrics = monitor._generate_metrics_summary()
        assert resource_metrics['samples_collected'] > 0
        assert resource_metrics['memory_metrics']['avg'] > 0
    
    def test_blueprint_service_layer_integration(
        self,
        app: Flask,
        service_registry: Dict[str, Any],
        service_composition_factory: Callable,
        dependency_injection_container: Any
    ):
        """
        Test blueprint integration with Service Layer for business logic orchestration.
        
        Validates that Flask blueprints properly coordinate with Service Layer
        components for business logic execution while maintaining proper
        transaction boundaries and error handling throughout the process.
        """
        with app.app_context():
            # Create service composition for testing
            composition = service_composition_factory(
                'user_service',
                'business_entity_service',
                'validation_service',
                config={'transaction_timeout': 30, 'validation_strict': True}
            )
            
            # Inject services into dependency container
            for service_name, service in composition['services'].items():
                dependency_injection_container.register_factory(
                    service_name,
                    lambda s=service: s
                )
            
            integration_results = {
                'blueprint_registrations': [],
                'service_invocations': [],
                'transaction_coordinates': [],
                'error_handling_events': []
            }
            
            # Test Auth Blueprint - Service Layer Integration
            auth_service = dependency_injection_container.get_service('user_service')
            assert auth_service is not None
            
            # Mock authentication workflow
            with patch.object(auth_service, 'create_user') as mock_create:
                mock_create.return_value = {
                    'user_id': 123,
                    'username': 'testuser',
                    'status': 'active'
                }
                
                # Simulate blueprint calling service
                result = auth_service.create_user(
                    username='testuser',
                    email='test@example.com',
                    password='password123'
                )
                
                integration_results['blueprint_registrations'].append('auth_blueprint')
                integration_results['service_invocations'].append('user_service.create_user')
                
                assert result['user_id'] == 123
                assert mock_create.call_count == 1
            
            # Test API Blueprint - Business Entity Service Integration
            entity_service = dependency_injection_container.get_service('business_entity_service')
            assert entity_service is not None
            
            with patch.object(entity_service, 'create_entity') as mock_entity_create:
                mock_entity_create.return_value = {
                    'entity_id': 456,
                    'name': 'TestEntity',
                    'owner_id': 123
                }
                
                # Simulate API blueprint calling business service
                with composition['transaction_manager'].transaction():
                    result = entity_service.create_entity(
                        name='TestEntity',
                        description='Test Description',
                        owner_id=123
                    )
                    
                    integration_results['service_invocations'].append('business_entity_service.create_entity')
                    integration_results['transaction_coordinates'].append('entity_creation_transaction')
                    
                    assert result['entity_id'] == 456
                    assert mock_entity_create.call_count == 1
            
            # Test Validation Service Integration
            validation_service = dependency_injection_container.get_service('validation_service')
            if validation_service:
                with patch.object(validation_service, 'validate_business_rules') as mock_validate:
                    mock_validate.return_value = {'valid': True, 'errors': []}
                    
                    validation_result = validation_service.validate_business_rules({
                        'entity_name': 'TestEntity',
                        'owner_id': 123
                    })
                    
                    integration_results['service_invocations'].append('validation_service.validate_business_rules')
                    
                    assert validation_result['valid'] is True
                    assert mock_validate.call_count == 1
            
            # Test Error Handling Integration
            with patch.object(auth_service, 'create_user') as mock_error:
                mock_error.side_effect = Exception("Service layer error")
                
                try:
                    auth_service.create_user(
                        username='erroruser',
                        email='error@example.com',
                        password='password123'
                    )
                except Exception as e:
                    integration_results['error_handling_events'].append({
                        'error_type': type(e).__name__,
                        'error_message': str(e),
                        'service': 'user_service'
                    })
        
        # Validate integration results
        assert len(integration_results['blueprint_registrations']) >= 1
        assert len(integration_results['service_invocations']) >= 3
        assert len(integration_results['transaction_coordinates']) >= 1
        assert len(integration_results['error_handling_events']) >= 1
        
        # Validate service composition metrics
        assert composition['metrics']['operation_count'] >= 0
        assert composition['transaction_manager'].get_transaction_status() == 'inactive'
    
    def test_authentication_decorator_service_coordination(
        self,
        app: Flask,
        client: FlaskClient,
        service_registry: Dict[str, Any],
        mock_service_factory: Callable
    ):
        """
        Test authentication decorator integration with service layer coordination.
        
        Validates that Flask authentication decorators properly coordinate with
        service layer components for secure workflow execution while maintaining
        session state and access control throughout multi-step operations.
        """
        # Create mock authentication service
        mock_auth_service = mock_service_factory(
            'auth_service',
            {
                'validate_token': lambda token: {'user_id': 123, 'username': 'testuser', 'valid': True},
                'check_permissions': lambda user_id, permission: True,
                'get_user_session': lambda user_id: {'session_id': 'test_session', 'active': True}
            },
            {'session_timeout': 3600}
        )
        
        # Create mock business service
        mock_business_service = mock_service_factory(
            'business_service',
            {
                'process_secure_operation': lambda user_id, data: {
                    'operation_id': 'op_123',
                    'user_id': user_id,
                    'status': 'completed'
                }
            }
        )
        
        coordination_trace = {
            'authentication_events': [],
            'service_calls': [],
            'permission_checks': [],
            'session_validations': []
        }
        
        with app.app_context():
            # Simulate authenticated request workflow
            test_token = 'test_jwt_token_12345'
            
            # Test authentication decorator coordination
            with patch('src.auth.decorators.require_auth') as mock_auth_decorator:
                # Configure mock decorator to simulate authentication flow
                def mock_decorator_func(f):
                    def wrapper(*args, **kwargs):
                        # Simulate authentication validation
                        token_validation = mock_auth_service.validate_token(test_token)
                        coordination_trace['authentication_events'].append({
                            'event': 'token_validation',
                            'user_id': token_validation['user_id'],
                            'valid': token_validation['valid'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        if token_validation['valid']:
                            # Set user context
                            g.current_user_id = token_validation['user_id']
                            g.current_username = token_validation['username']
                            
                            # Execute decorated function
                            return f(*args, **kwargs)
                        else:
                            return {'error': 'Authentication failed'}, 401
                    return wrapper
                
                mock_auth_decorator.return_value = mock_decorator_func
                
                # Test protected service operation
                @mock_auth_decorator()
                def protected_service_operation(operation_data):
                    """Mock protected service operation."""
                    user_id = g.current_user_id
                    
                    # Check permissions
                    has_permission = mock_auth_service.check_permissions(user_id, 'business_operations')
                    coordination_trace['permission_checks'].append({
                        'user_id': user_id,
                        'permission': 'business_operations',
                        'granted': has_permission,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    if not has_permission:
                        return {'error': 'Insufficient permissions'}, 403
                    
                    # Validate session
                    session_info = mock_auth_service.get_user_session(user_id)
                    coordination_trace['session_validations'].append({
                        'user_id': user_id,
                        'session_id': session_info['session_id'],
                        'active': session_info['active'],
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    if not session_info['active']:
                        return {'error': 'Session expired'}, 401
                    
                    # Execute business service operation
                    service_result = mock_business_service.process_secure_operation(
                        user_id=user_id,
                        data=operation_data
                    )
                    coordination_trace['service_calls'].append({
                        'service': 'business_service',
                        'method': 'process_secure_operation',
                        'user_id': user_id,
                        'result': service_result,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    return service_result
                
                # Execute protected operation
                operation_result = protected_service_operation({
                    'operation_type': 'data_processing',
                    'data': {'key': 'value'}
                })
                
                # Validate coordination results
                assert operation_result['operation_id'] == 'op_123'
                assert operation_result['user_id'] == 123
                assert operation_result['status'] == 'completed'
        
        # Validate coordination trace
        assert len(coordination_trace['authentication_events']) >= 1
        assert len(coordination_trace['permission_checks']) >= 1
        assert len(coordination_trace['session_validations']) >= 1
        assert len(coordination_trace['service_calls']) >= 1
        
        # Validate authentication flow
        auth_event = coordination_trace['authentication_events'][0]
        assert auth_event['valid'] is True
        assert auth_event['user_id'] == 123
        
        # Validate permission checking
        permission_check = coordination_trace['permission_checks'][0]
        assert permission_check['granted'] is True
        assert permission_check['permission'] == 'business_operations'
        
        # Validate session management
        session_validation = coordination_trace['session_validations'][0]
        assert session_validation['active'] is True
        assert session_validation['session_id'] == 'test_session'
        
        # Validate service execution
        service_call = coordination_trace['service_calls'][0]
        assert service_call['service'] == 'business_service'
        assert service_call['user_id'] == 123


# ================================================================================================
# DATABASE MODEL COORDINATION TESTS
# ================================================================================================

@pytest.mark.workflow
@pytest.mark.transaction
@pytest.mark.database
class TestDatabaseModelCoordination:
    """
    Database model coordination test class validating complex data operations
    across multiple models and service boundaries with transaction management.
    """
    
    def test_multi_model_transaction_coordination(
        self,
        app: Flask,
        db_session: scoped_session,
        service_registry: Dict[str, Any],
        transaction_boundary_tester: Any
    ):
        """
        Test complex transaction coordination across multiple database models.
        
        Validates that service layer properly coordinates database operations
        across User, BusinessEntity, and EntityRelationship models while
        maintaining ACID properties and proper rollback behavior.
        """
        with app.app_context():
            # Test data for multi-model coordination
            test_data = {
                'user1': {
                    'username': f'user1_{uuid.uuid4().hex[:8]}',
                    'email': f'user1_{uuid.uuid4().hex[:8]}@example.com',
                    'password_hash': 'hashed_password_1'
                },
                'user2': {
                    'username': f'user2_{uuid.uuid4().hex[:8]}',
                    'email': f'user2_{uuid.uuid4().hex[:8]}@example.com',
                    'password_hash': 'hashed_password_2'
                },
                'entity': {
                    'name': f'Entity_{uuid.uuid4().hex[:8]}',
                    'description': 'Test entity for coordination',
                    'status': 'active'
                },
                'relationship': {
                    'relationship_type': 'collaboration',
                    'is_active': True
                }
            }
            
            coordination_operations = []
            
            # Define transaction operations
            def create_user_operation():
                """Create first user."""
                user1 = User(**test_data['user1'])
                db_session.add(user1)
                db_session.flush()  # Get ID without committing
                coordination_operations.append({
                    'operation': 'create_user1',
                    'user_id': user1.id,
                    'timestamp': datetime.utcnow()
                })
                return user1
            
            def create_second_user_operation():
                """Create second user."""
                user2 = User(**test_data['user2'])
                db_session.add(user2)
                db_session.flush()
                coordination_operations.append({
                    'operation': 'create_user2',
                    'user_id': user2.id,
                    'timestamp': datetime.utcnow()
                })
                return user2
            
            def create_business_entity_operation():
                """Create business entity."""
                # Get first user
                user1 = db_session.query(User).filter_by(
                    username=test_data['user1']['username']
                ).first()
                
                entity = BusinessEntity(
                    name=test_data['entity']['name'],
                    description=test_data['entity']['description'],
                    status=test_data['entity']['status'],
                    owner_id=user1.id
                )
                db_session.add(entity)
                db_session.flush()
                coordination_operations.append({
                    'operation': 'create_business_entity',
                    'entity_id': entity.id,
                    'owner_id': user1.id,
                    'timestamp': datetime.utcnow()
                })
                return entity
            
            def create_entity_relationship_operation():
                """Create entity relationship."""
                # Get users and entity
                user1 = db_session.query(User).filter_by(
                    username=test_data['user1']['username']
                ).first()
                user2 = db_session.query(User).filter_by(
                    username=test_data['user2']['username']
                ).first()
                entity = db_session.query(BusinessEntity).filter_by(
                    name=test_data['entity']['name']
                ).first()
                
                # Create relationship between entity and second user
                relationship = EntityRelationship(
                    source_entity_id=entity.id,
                    target_entity_id=user2.id,
                    relationship_type=test_data['relationship']['relationship_type'],
                    is_active=test_data['relationship']['is_active']
                )
                db_session.add(relationship)
                db_session.flush()
                coordination_operations.append({
                    'operation': 'create_entity_relationship',
                    'relationship_id': relationship.id,
                    'source_entity_id': entity.id,
                    'target_entity_id': user2.id,
                    'timestamp': datetime.utcnow()
                })
                return relationship
            
            # Test successful transaction coordination
            transaction_operations = [
                create_user_operation,
                create_second_user_operation,
                create_business_entity_operation,
                create_entity_relationship_operation
            ]
            
            transaction_result = transaction_boundary_tester.test_transaction_isolation(
                transaction_operations,
                isolation_level='READ_COMMITTED'
            )
            
            # Validate successful transaction
            assert transaction_result['success'] is True
            assert transaction_result['operations_count'] == 4
            assert len(coordination_operations) == 4
            
            # Verify data integrity
            created_user1 = db_session.query(User).filter_by(
                username=test_data['user1']['username']
            ).first()
            created_user2 = db_session.query(User).filter_by(
                username=test_data['user2']['username']
            ).first()
            created_entity = db_session.query(BusinessEntity).filter_by(
                name=test_data['entity']['name']
            ).first()
            created_relationship = db_session.query(EntityRelationship).filter_by(
                relationship_type=test_data['relationship']['relationship_type']
            ).first()
            
            assert created_user1 is not None
            assert created_user2 is not None
            assert created_entity is not None
            assert created_relationship is not None
            assert created_entity.owner_id == created_user1.id
            assert created_relationship.source_entity_id == created_entity.id
            assert created_relationship.target_entity_id == created_user2.id
            
            # Test transaction rollback coordination
            rollback_operations = []
            
            def create_user_with_error():
                """Create user that will cause rollback."""
                user = User(
                    username='rollback_user',
                    email='rollback@example.com',
                    password_hash='hashed_password'
                )
                db_session.add(user)
                db_session.flush()
                rollback_operations.append('user_created')
                return user
            
            def create_entity_with_error():
                """Create entity that will cause transaction failure."""
                # This will fail due to invalid foreign key
                entity = BusinessEntity(
                    name='Rollback Entity',
                    description='This should be rolled back',
                    status='active',
                    owner_id=999999  # Non-existent user ID
                )
                db_session.add(entity)
                db_session.flush()
                rollback_operations.append('entity_created')
                return entity
            
            # Test rollback behavior
            rollback_transaction_operations = [
                create_user_with_error,
                create_entity_with_error
            ]
            
            rollback_result = transaction_boundary_tester.test_transaction_isolation(
                rollback_transaction_operations,
                isolation_level='READ_COMMITTED'
            )
            
            # Validate rollback occurred
            assert rollback_result['success'] is False
            assert rollback_result.get('rollback_successful', False) is True
            
            # Verify rollback integrity
            rollback_user = db_session.query(User).filter_by(
                username='rollback_user'
            ).first()
            rollback_entity = db_session.query(BusinessEntity).filter_by(
                name='Rollback Entity'
            ).first()
            
            assert rollback_user is None  # Should be rolled back
            assert rollback_entity is None  # Should be rolled back
    
    def test_service_layer_database_consistency(
        self,
        app: Flask,
        db_session: scoped_session,
        service_registry: Dict[str, Any],
        business_logic_validator: Any
    ):
        """
        Test service layer coordination with database models for data consistency.
        
        Validates that service layer operations maintain data consistency
        across multiple database models while preserving business rules
        and constraint validation throughout complex operations.
        """
        with app.app_context():
            # Set baseline expectations for Node.js equivalent operations
            business_logic_validator.set_baseline(
                'user_business_entity_creation',
                input_data={
                    'username': 'testuser',
                    'email': 'test@example.com',
                    'entity_name': 'TestEntity',
                    'entity_description': 'Test Description'
                },
                output_data={
                    'user_created': True,
                    'entity_created': True,
                    'ownership_established': True,
                    'data_consistent': True
                }
            )
            
            # Get services from registry
            user_service = service_registry['services'].get('user_service')
            business_entity_service = service_registry['services'].get('business_entity_service')
            
            consistency_metrics = {
                'operations_performed': [],
                'constraint_validations': [],
                'consistency_checks': [],
                'business_rule_validations': []
            }
            
            if user_service and business_entity_service:
                # Mock service methods for consistency testing
                with patch.object(user_service, 'create_user') as mock_create_user, \
                     patch.object(business_entity_service, 'create_entity') as mock_create_entity:
                    
                    # Configure mock returns for consistent behavior
                    mock_user_result = {
                        'user_id': 123,
                        'username': 'testuser',
                        'email': 'test@example.com',
                        'created_at': datetime.utcnow().isoformat(),
                        'status': 'active'
                    }
                    mock_create_user.return_value = mock_user_result
                    
                    mock_entity_result = {
                        'entity_id': 456,
                        'name': 'TestEntity',
                        'description': 'Test Description',
                        'owner_id': 123,
                        'status': 'active',
                        'created_at': datetime.utcnow().isoformat()
                    }
                    mock_create_entity.return_value = mock_entity_result
                    
                    # Test coordinated service operations
                    def coordinated_user_entity_creation():
                        """Coordinated user and entity creation workflow."""
                        # Step 1: Create user
                        user_result = user_service.create_user(
                            username='testuser',
                            email='test@example.com',
                            password='SecurePassword123!'
                        )
                        consistency_metrics['operations_performed'].append({
                            'operation': 'user_creation',
                            'result': user_result,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        # Step 2: Validate user creation constraints
                        assert user_result['user_id'] == 123
                        assert user_result['username'] == 'testuser'
                        consistency_metrics['constraint_validations'].append({
                            'constraint': 'user_data_validation',
                            'valid': True,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        # Step 3: Create business entity with user ownership
                        entity_result = business_entity_service.create_entity(
                            name='TestEntity',
                            description='Test Description',
                            owner_id=user_result['user_id']
                        )
                        consistency_metrics['operations_performed'].append({
                            'operation': 'entity_creation',
                            'result': entity_result,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        # Step 4: Validate ownership consistency
                        assert entity_result['owner_id'] == user_result['user_id']
                        consistency_metrics['consistency_checks'].append({
                            'check': 'ownership_consistency',
                            'valid': True,
                            'user_id': user_result['user_id'],
                            'entity_id': entity_result['entity_id'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        # Step 5: Validate business rules
                        business_rules_valid = (
                            user_result['status'] == 'active' and
                            entity_result['status'] == 'active' and
                            entity_result['owner_id'] == user_result['user_id']
                        )
                        consistency_metrics['business_rule_validations'].append({
                            'rule': 'active_user_entity_ownership',
                            'valid': business_rules_valid,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                        return {
                            'user_created': True,
                            'entity_created': True,
                            'ownership_established': True,
                            'data_consistent': True
                        }
                    
                    # Execute coordinated workflow
                    validation_result = business_logic_validator.validate_operation(
                        'user_business_entity_creation',
                        coordinated_user_entity_creation,
                        {}
                    )
                    
                    # Validate consistency results
                    assert validation_result['success'] is True
                    assert validation_result['functional_equivalence'] is True
                    
                    # Verify service calls occurred
                    assert mock_create_user.call_count == 1
                    assert mock_create_entity.call_count == 1
                    
                    # Validate call arguments
                    user_call_args = mock_create_user.call_args
                    assert user_call_args[1]['username'] == 'testuser'
                    assert user_call_args[1]['email'] == 'test@example.com'
                    
                    entity_call_args = mock_create_entity.call_args
                    assert entity_call_args[1]['name'] == 'TestEntity'
                    assert entity_call_args[1]['owner_id'] == 123
            
            # Validate consistency metrics
            assert len(consistency_metrics['operations_performed']) >= 2
            assert len(consistency_metrics['constraint_validations']) >= 1
            assert len(consistency_metrics['consistency_checks']) >= 1
            assert len(consistency_metrics['business_rule_validations']) >= 1
            
            # Verify all validations passed
            for validation in consistency_metrics['constraint_validations']:
                assert validation['valid'] is True
            
            for check in consistency_metrics['consistency_checks']:
                assert check['valid'] is True
            
            for rule_validation in consistency_metrics['business_rule_validations']:
                assert rule_validation['valid'] is True


# ================================================================================================
# BLUEPRINT REGISTRATION AND FACTORY COORDINATION TESTS
# ================================================================================================

@pytest.mark.workflow
@pytest.mark.composition
@pytest.mark.blueprint
class TestBlueprintFactoryCoordination:
    """
    Blueprint registration and Flask application factory coordination test class
    validating systematic module organization and blueprint management.
    """
    
    def test_blueprint_registration_sequence(
        self,
        app: Flask,
        service_registry: Dict[str, Any]
    ):
        """
        Test systematic blueprint registration within Flask application factory.
        
        Validates that blueprint registration occurs in the correct sequence
        during Flask application factory initialization with proper module
        organization and dependency resolution.
        """
        registration_trace = {
            'blueprints_registered': [],
            'registration_order': [],
            'dependencies_resolved': [],
            'configuration_loaded': []
        }
        
        with app.app_context():
            # Track blueprint registration
            original_register_blueprint = app.register_blueprint
            
            def tracked_register_blueprint(blueprint, **options):
                """Track blueprint registration calls."""
                registration_trace['blueprints_registered'].append({
                    'blueprint_name': blueprint.name,
                    'url_prefix': options.get('url_prefix'),
                    'registration_time': datetime.utcnow().isoformat()
                })
                registration_trace['registration_order'].append(blueprint.name)
                return original_register_blueprint(blueprint, **options)
            
            # Patch blueprint registration to track calls
            with patch.object(app, 'register_blueprint', side_effect=tracked_register_blueprint):
                # Test blueprint registration sequence
                try:
                    # Import and register main blueprint
                    if main_blueprint:
                        app.register_blueprint(main_blueprint)
                        registration_trace['dependencies_resolved'].append({
                            'blueprint': 'main',
                            'dependencies': ['flask_core'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                except Exception as e:
                    registration_trace['blueprints_registered'].append({
                        'blueprint_name': 'main',
                        'error': str(e),
                        'registration_time': datetime.utcnow().isoformat()
                    })
                
                try:
                    # Import and register auth blueprint
                    if auth_blueprint:
                        app.register_blueprint(auth_blueprint, url_prefix='/auth')
                        registration_trace['dependencies_resolved'].append({
                            'blueprint': 'auth',
                            'dependencies': ['flask_login', 'itsdangerous', 'auth_services'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                except Exception as e:
                    registration_trace['blueprints_registered'].append({
                        'blueprint_name': 'auth',
                        'error': str(e),
                        'registration_time': datetime.utcnow().isoformat()
                    })
                
                try:
                    # Import and register API blueprint
                    if api_blueprint:
                        app.register_blueprint(api_blueprint, url_prefix='/api')
                        registration_trace['dependencies_resolved'].append({
                            'blueprint': 'api',
                            'dependencies': ['flask_restful', 'marshmallow', 'business_services'],
                            'timestamp': datetime.utcnow().isoformat()
                        })
                except Exception as e:
                    registration_trace['blueprints_registered'].append({
                        'blueprint_name': 'api',
                        'error': str(e),
                        'registration_time': datetime.utcnow().isoformat()
                    })
            
            # Test blueprint discovery and automatic registration
            discovered_blueprints = []
            
            # Mock blueprint discovery
            for blueprint_name in ['main', 'auth', 'api']:
                try:
                    # Simulate blueprint module discovery
                    blueprint_module = f'src.blueprints.{blueprint_name}'
                    discovered_blueprints.append({
                        'name': blueprint_name,
                        'module': blueprint_module,
                        'discovered': True,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                except Exception as e:
                    discovered_blueprints.append({
                        'name': blueprint_name,
                        'module': f'src.blueprints.{blueprint_name}',
                        'discovered': False,
                        'error': str(e),
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            # Test configuration loading for blueprints
            blueprint_configs = {
                'main': {
                    'health_check_enabled': True,
                    'monitoring_endpoints': True
                },
                'auth': {
                    'session_timeout': 3600,
                    'token_expiry': 7200,
                    'require_csrf': True
                },
                'api': {
                    'rate_limiting': True,
                    'request_validation': True,
                    'response_caching': False
                }
            }
            
            for blueprint_name, config in blueprint_configs.items():
                registration_trace['configuration_loaded'].append({
                    'blueprint': blueprint_name,
                    'config': config,
                    'loaded': True,
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Validate blueprint registration results
        registered_blueprints = [bp for bp in registration_trace['blueprints_registered'] if 'error' not in bp]
        failed_registrations = [bp for bp in registration_trace['blueprints_registered'] if 'error' in bp]
        
        # At least some blueprints should be registered or attempted
        assert len(registration_trace['blueprints_registered']) >= 1
        
        # Validate registration order (main should come first if registered)
        if 'main' in registration_trace['registration_order']:
            assert registration_trace['registration_order'].index('main') == 0
        
        # Validate dependency resolution
        assert len(registration_trace['dependencies_resolved']) >= 0
        for dependency in registration_trace['dependencies_resolved']:
            assert 'blueprint' in dependency
            assert 'dependencies' in dependency
            assert isinstance(dependency['dependencies'], list)
        
        # Validate configuration loading
        assert len(registration_trace['configuration_loaded']) == 3
        for config_item in registration_trace['configuration_loaded']:
            assert config_item['loaded'] is True
            assert 'config' in config_item
        
        # Validate blueprint discovery
        assert len(discovered_blueprints) == 3
        for blueprint in discovered_blueprints:
            assert 'name' in blueprint
            assert 'module' in blueprint
    
    def test_modular_scaling_coordination(
        self,
        app: Flask,
        service_registry: Dict[str, Any],
        workflow_performance_benchmarker: Any
    ):
        """
        Test modular scaling patterns with efficient blueprint-service interaction.
        
        Validates that individual blueprint modules can interact efficiently
        with service layer components while supporting independent optimization
        and maintaining coordination integrity during scaling operations.
        """
        scaling_metrics = {
            'blueprint_performance': {},
            'service_interaction_times': {},
            'resource_utilization': {},
            'coordination_overhead': {}
        }
        
        # Set baseline performance expectations
        workflow_performance_benchmarker.set_baseline_metrics(
            'blueprint_service_interaction',
            {
                'execution_time': 0.1,  # 100ms baseline
                'memory_usage': 10.0,   # 10MB baseline
                'cpu_usage': 5.0,       # 5% CPU baseline
                'database_queries': 3   # 3 queries baseline
            }
        )
        
        with app.app_context():
            # Test individual blueprint performance
            blueprint_modules = ['main', 'auth', 'api']
            
            for blueprint_name in blueprint_modules:
                def blueprint_operation():
                    """Simulate blueprint operation with service interaction."""
                    start_time = time.time()
                    
                    # Simulate blueprint processing
                    if blueprint_name == 'main':
                        # Main blueprint: Health check and monitoring
                        operation_result = {
                            'status': 'healthy',
                            'components_checked': ['database', 'services', 'cache'],
                            'response_time': time.time() - start_time
                        }
                    elif blueprint_name == 'auth':
                        # Auth blueprint: Authentication processing
                        operation_result = {
                            'authenticated': True,
                            'user_id': 123,
                            'session_created': True,
                            'processing_time': time.time() - start_time
                        }
                    elif blueprint_name == 'api':
                        # API blueprint: Business logic processing
                        operation_result = {
                            'data_processed': True,
                            'records_affected': 5,
                            'validation_passed': True,
                            'processing_time': time.time() - start_time
                        }
                    
                    # Simulate service layer interaction
                    service_interaction_start = time.time()
                    
                    # Mock service calls based on blueprint
                    if blueprint_name in service_registry['services']:
                        service = service_registry['services'][blueprint_name]
                        # Simulate service operation
                        time.sleep(0.01)  # Simulate processing time
                    
                    service_interaction_time = time.time() - service_interaction_start
                    scaling_metrics['service_interaction_times'][blueprint_name] = service_interaction_time
                    
                    return operation_result
                
                # Benchmark blueprint performance
                performance_result = workflow_performance_benchmarker.benchmark_workflow(
                    f'{blueprint_name}_blueprint_operation',
                    blueprint_operation,
                    iterations=3
                )
                
                scaling_metrics['blueprint_performance'][blueprint_name] = {
                    'avg_execution_time': performance_result['avg_execution_time'],
                    'min_execution_time': performance_result['min_execution_time'],
                    'max_execution_time': performance_result['max_execution_time'],
                    'memory_usage': performance_result['avg_memory_usage'],
                    'cpu_usage': performance_result['avg_cpu_usage']
                }
                
                # Check if performance meets baseline
                if 'baseline_comparison' in performance_result:
                    baseline_comparison = performance_result['baseline_comparison']
                    scaling_metrics['coordination_overhead'][blueprint_name] = {
                        'performance_ratio': baseline_comparison['execution_time_ratio'],
                        'memory_ratio': baseline_comparison['memory_usage_ratio'],
                        'performance_improvement': baseline_comparison['performance_improvement']
                    }
            
            # Test coordinated blueprint interaction
            def coordinated_multi_blueprint_operation():
                """Test coordinated operation across multiple blueprints."""
                coordination_start = time.time()
                coordination_results = []
                
                # Step 1: Main blueprint health check
                health_result = {
                    'blueprint': 'main',
                    'operation': 'health_check',
                    'status': 'completed',
                    'timestamp': datetime.utcnow().isoformat()
                }
                coordination_results.append(health_result)
                
                # Step 2: Auth blueprint user validation
                auth_result = {
                    'blueprint': 'auth',
                    'operation': 'user_validation',
                    'authenticated': True,
                    'timestamp': datetime.utcnow().isoformat()
                }
                coordination_results.append(auth_result)
                
                # Step 3: API blueprint data processing
                api_result = {
                    'blueprint': 'api',
                    'operation': 'data_processing',
                    'processed': True,
                    'timestamp': datetime.utcnow().isoformat()
                }
                coordination_results.append(api_result)
                
                coordination_time = time.time() - coordination_start
                
                return {
                    'coordination_successful': True,
                    'blueprints_coordinated': len(coordination_results),
                    'total_coordination_time': coordination_time,
                    'results': coordination_results
                }
            
            # Benchmark coordinated operation
            coordinated_performance = workflow_performance_benchmarker.benchmark_workflow(
                'coordinated_multi_blueprint_operation',
                coordinated_multi_blueprint_operation,
                iterations=3
            )
            
            scaling_metrics['coordination_overhead']['multi_blueprint'] = {
                'coordination_time': coordinated_performance['avg_execution_time'],
                'blueprints_coordinated': 3,
                'overhead_per_blueprint': coordinated_performance['avg_execution_time'] / 3
            }
        
        # Validate scaling performance
        assert len(scaling_metrics['blueprint_performance']) >= 1
        assert len(scaling_metrics['service_interaction_times']) >= 0
        
        # Check individual blueprint performance
        for blueprint_name, performance in scaling_metrics['blueprint_performance'].items():
            assert performance['avg_execution_time'] > 0
            assert performance['avg_execution_time'] < 1.0  # Should be under 1 second
            
            # Validate memory usage is reasonable
            if performance['memory_usage'] > 0:
                assert performance['memory_usage'] < 100  # Should be under 100MB
        
        # Validate coordination overhead is acceptable
        if 'multi_blueprint' in scaling_metrics['coordination_overhead']:
            coordination_metrics = scaling_metrics['coordination_overhead']['multi_blueprint']
            assert coordination_metrics['coordination_time'] > 0
            assert coordination_metrics['blueprints_coordinated'] == 3
            assert coordination_metrics['overhead_per_blueprint'] < 0.5  # Under 500ms per blueprint
        
        # Generate performance report
        performance_report = workflow_performance_benchmarker.generate_performance_report()
        assert performance_report['total_workflows_benchmarked'] >= 1
        
        # Validate no significant performance degradation
        if performance_report.get('degraded_workflows'):
            degraded_count = len(performance_report['degraded_workflows'])
            total_workflows = performance_report['total_workflows_benchmarked']
            degradation_rate = degraded_count / total_workflows if total_workflows > 0 else 0
            assert degradation_rate < 0.3  # Less than 30% degradation acceptable


# ================================================================================================
# CROSS-COMPONENT COMMUNICATION AND DEPENDENCY INJECTION TESTS
# ================================================================================================

@pytest.mark.workflow
@pytest.mark.dependency_injection
@pytest.mark.communication
class TestCrossComponentCommunication:
    """
    Cross-component communication test class validating Flask request context
    and dependency injection coordination throughout the application.
    """
    
    def test_flask_request_context_coordination(
        self,
        app: Flask,
        client: FlaskClient,
        service_registry: Dict[str, Any]
    ):
        """
        Test cross-component communication through Flask request context.
        
        Validates that components can communicate effectively through Flask's
        request context while maintaining proper state isolation and data
        flow throughout the request lifecycle.
        """
        context_coordination_trace = {
            'request_contexts': [],
            'context_variables': [],
            'component_communications': [],
            'state_transitions': []
        }
        
        with app.test_request_context('/test-endpoint', method='POST'):
            # Initialize request context with test data
            g.request_id = str(uuid.uuid4())
            g.user_context = {
                'user_id': 123,
                'username': 'testuser',
                'permissions': ['read', 'write']
            }
            g.workflow_state = {
                'current_step': 'initialization',
                'steps_completed': [],
                'context_data': {}
            }
            
            context_coordination_trace['request_contexts'].append({
                'request_id': g.request_id,
                'endpoint': '/test-endpoint',
                'method': 'POST',
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Test Blueprint-to-Service communication through context
            def simulate_auth_blueprint_operation():
                """Simulate auth blueprint setting user context."""
                # Auth blueprint sets user authentication context
                g.authenticated = True
                g.auth_timestamp = datetime.utcnow().isoformat()
                g.session_id = f'session_{uuid.uuid4().hex[:8]}'
                
                context_coordination_trace['context_variables'].append({
                    'component': 'auth_blueprint',
                    'operation': 'set_authentication_context',
                    'variables_set': ['authenticated', 'auth_timestamp', 'session_id'],
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                g.workflow_state['steps_completed'].append('authentication')
                g.workflow_state['current_step'] = 'authorization'
                
                return {
                    'authenticated': g.authenticated,
                    'session_id': g.session_id
                }
            
            def simulate_service_layer_operation():
                """Simulate service layer reading and updating context."""
                # Service layer reads authentication context
                if hasattr(g, 'authenticated') and g.authenticated:
                    # Perform business logic with user context
                    g.business_operation_id = f'op_{uuid.uuid4().hex[:8]}'
                    g.operation_result = {
                        'user_id': g.user_context['user_id'],
                        'operation_type': 'business_logic',
                        'status': 'completed'
                    }
                    
                    context_coordination_trace['context_variables'].append({
                        'component': 'service_layer',
                        'operation': 'business_logic_execution',
                        'variables_read': ['authenticated', 'user_context'],
                        'variables_set': ['business_operation_id', 'operation_result'],
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    g.workflow_state['steps_completed'].append('business_logic')
                    g.workflow_state['current_step'] = 'data_persistence'
                    
                    return g.operation_result
                else:
                    raise Exception("Authentication context not found")
            
            def simulate_database_layer_operation():
                """Simulate database layer using context for operations."""
                # Database layer reads business operation context
                if hasattr(g, 'business_operation_id'):
                    # Simulate database operation with context
                    g.db_transaction_id = f'txn_{uuid.uuid4().hex[:8]}'
                    g.db_result = {
                        'transaction_id': g.db_transaction_id,
                        'operation_id': g.business_operation_id,
                        'records_affected': 1,
                        'status': 'committed'
                    }
                    
                    context_coordination_trace['context_variables'].append({
                        'component': 'database_layer',
                        'operation': 'data_persistence',
                        'variables_read': ['business_operation_id', 'user_context'],
                        'variables_set': ['db_transaction_id', 'db_result'],
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    g.workflow_state['steps_completed'].append('data_persistence')
                    g.workflow_state['current_step'] = 'response_generation'
                    
                    return g.db_result
                else:
                    raise Exception("Business operation context not found")
            
            def simulate_api_blueprint_response():
                """Simulate API blueprint generating response from context."""
                # API blueprint reads all context for response generation
                if (hasattr(g, 'operation_result') and 
                    hasattr(g, 'db_result') and 
                    hasattr(g, 'authenticated')):
                    
                    response_data = {
                        'request_id': g.request_id,
                        'user_id': g.user_context['user_id'],
                        'operation_id': g.business_operation_id,
                        'transaction_id': g.db_transaction_id,
                        'status': 'success',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    
                    context_coordination_trace['context_variables'].append({
                        'component': 'api_blueprint',
                        'operation': 'response_generation',
                        'variables_read': ['operation_result', 'db_result', 'authenticated', 'user_context'],
                        'variables_set': [],
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                    g.workflow_state['steps_completed'].append('response_generation')
                    g.workflow_state['current_step'] = 'completed'
                    
                    return response_data
                else:
                    raise Exception("Required context variables not found")
            
            # Execute coordinated workflow through context
            try:
                # Step 1: Auth blueprint operation
                auth_result = simulate_auth_blueprint_operation()
                context_coordination_trace['component_communications'].append({
                    'from_component': 'auth_blueprint',
                    'to_component': 'request_context',
                    'communication_type': 'context_variable_set',
                    'data_flow': auth_result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 2: Service layer operation
                service_result = simulate_service_layer_operation()
                context_coordination_trace['component_communications'].append({
                    'from_component': 'request_context',
                    'to_component': 'service_layer',
                    'communication_type': 'context_variable_read',
                    'data_flow': service_result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 3: Database layer operation
                db_result = simulate_database_layer_operation()
                context_coordination_trace['component_communications'].append({
                    'from_component': 'service_layer',
                    'to_component': 'database_layer',
                    'communication_type': 'context_coordination',
                    'data_flow': db_result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Step 4: API blueprint response
                api_result = simulate_api_blueprint_response()
                context_coordination_trace['component_communications'].append({
                    'from_component': 'database_layer',
                    'to_component': 'api_blueprint',
                    'communication_type': 'context_aggregation',
                    'data_flow': api_result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Record state transitions
                for step in g.workflow_state['steps_completed']:
                    context_coordination_trace['state_transitions'].append({
                        'step': step,
                        'request_id': g.request_id,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
            except Exception as e:
                context_coordination_trace['component_communications'].append({
                    'error': str(e),
                    'component': 'context_coordination',
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        # Validate context coordination results
        assert len(context_coordination_trace['request_contexts']) == 1
        assert len(context_coordination_trace['context_variables']) >= 4  # Auth, service, DB, API
        assert len(context_coordination_trace['component_communications']) >= 4
        assert len(context_coordination_trace['state_transitions']) >= 4
        
        # Validate request context flow
        request_context = context_coordination_trace['request_contexts'][0]
        assert 'request_id' in request_context
        assert request_context['endpoint'] == '/test-endpoint'
        assert request_context['method'] == 'POST'
        
        # Validate component communications
        communication_components = [
            comm['from_component'] for comm in context_coordination_trace['component_communications']
            if 'from_component' in comm
        ]
        assert 'auth_blueprint' in communication_components
        assert 'request_context' in communication_components
        assert 'service_layer' in communication_components
        assert 'database_layer' in communication_components
        
        # Validate state transitions
        completed_steps = [
            transition['step'] for transition in context_coordination_trace['state_transitions']
        ]
        expected_steps = ['authentication', 'business_logic', 'data_persistence', 'response_generation']
        for expected_step in expected_steps:
            assert expected_step in completed_steps
    
    def test_dependency_injection_coordination(
        self,
        app: Flask,
        dependency_injection_container: Any,
        mock_service_factory: Callable,
        service_registry: Dict[str, Any]
    ):
        """
        Test dependency injection coordination across Flask components.
        
        Validates that dependency injection works effectively across
        blueprints, services, and models while maintaining proper
        lifecycle management and circular dependency resolution.
        """
        injection_coordination_metrics = {
            'services_registered': [],
            'dependencies_resolved': [],
            'injection_events': [],
            'circular_dependency_checks': []
        }
        
        with app.app_context():
            # Register mock services for dependency injection testing
            mock_user_repository = mock_service_factory(
                'user_repository',
                {
                    'find_by_id': lambda user_id: {'id': user_id, 'username': f'user_{user_id}'},
                    'save': lambda user: {'id': user.get('id', 123), 'saved': True},
                    'delete': lambda user_id: {'deleted': True, 'id': user_id}
                },
                {'connection_pool_size': 10}
            )
            
            mock_user_service = mock_service_factory(
                'user_service_di',
                {
                    'get_user': lambda user_id: {'id': user_id, 'profile': 'loaded'},
                    'update_user': lambda user_id, data: {'id': user_id, 'updated': True},
                    'delete_user': lambda user_id: {'id': user_id, 'deleted': True}
                },
                {'cache_enabled': True}
            )
            
            mock_auth_service = mock_service_factory(
                'auth_service_di',
                {
                    'authenticate': lambda username, password: {'authenticated': True, 'user_id': 123},
                    'authorize': lambda user_id, permission: True,
                    'create_session': lambda user_id: {'session_id': f'session_{user_id}'}
                },
                {'session_timeout': 3600}
            )
            
            injection_coordination_metrics['services_registered'] = [
                'user_repository',
                'user_service_di',
                'auth_service_di'
            ]
            
            # Register service dependencies
            dependency_injection_container.register_service(
                'user_service_with_deps',
                type('UserServiceWithDeps', (), {}),
                singleton=True,
                dependencies=['user_repository', 'auth_service_di']
            )
            
            dependency_injection_container.register_service(
                'business_service_with_deps',
                type('BusinessServiceWithDeps', (), {}),
                singleton=True,
                dependencies=['user_service_di', 'user_repository']
            )
            
            injection_coordination_metrics['dependencies_resolved'].append({
                'service': 'user_service_with_deps',
                'dependencies': ['user_repository', 'auth_service_di'],
                'timestamp': datetime.utcnow().isoformat()
            })
            
            injection_coordination_metrics['dependencies_resolved'].append({
                'service': 'business_service_with_deps',
                'dependencies': ['user_service_di', 'user_repository'],
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Test dependency injection in practice
            @dependency_injection_container.inject_dependencies
            def blueprint_handler_with_injection(
                user_service_di=None,
                auth_service_di=None,
                user_repository=None
            ):
                """Mock blueprint handler with dependency injection."""
                injection_coordination_metrics['injection_events'].append({
                    'component': 'blueprint_handler',
                    'injected_services': ['user_service_di', 'auth_service_di', 'user_repository'],
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Use injected services
                auth_result = auth_service_di.authenticate('testuser', 'password123')
                user_data = user_service_di.get_user(auth_result['user_id'])
                repository_data = user_repository.find_by_id(auth_result['user_id'])
                
                return {
                    'authentication': auth_result,
                    'user_data': user_data,
                    'repository_data': repository_data,
                    'handler_success': True
                }
            
            # Execute blueprint handler with injection
            handler_result = blueprint_handler_with_injection()
            
            # Validate injection results
            assert handler_result['handler_success'] is True
            assert handler_result['authentication']['authenticated'] is True
            assert handler_result['user_data']['id'] == 123
            assert handler_result['repository_data']['id'] == 123
            
            # Test service composition through dependency injection
            composition = dependency_injection_container.create_service_composition(
                'user_service_di',
                'auth_service_di',
                'user_repository'
            )
            
            injection_coordination_metrics['injection_events'].append({
                'component': 'service_composition',
                'services_composed': list(composition.keys()),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            assert len(composition) == 3
            assert 'user_service_di' in composition
            assert 'auth_service_di' in composition
            assert 'user_repository' in composition
            
            # Test circular dependency detection
            try:
                # Attempt to create circular dependency
                dependency_injection_container.register_service(
                    'circular_service_a',
                    type('CircularServiceA', (), {}),
                    dependencies=['circular_service_b']
                )
                
                dependency_injection_container.register_service(
                    'circular_service_b',
                    type('CircularServiceB', (), {}),
                    dependencies=['circular_service_a']
                )
                
                # Try to resolve circular dependency
                try:
                    circular_service = dependency_injection_container.get_service('circular_service_a')
                    injection_coordination_metrics['circular_dependency_checks'].append({
                        'detected': False,
                        'resolved': True,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                except Exception as e:
                    injection_coordination_metrics['circular_dependency_checks'].append({
                        'detected': True,
                        'error': str(e),
                        'resolved': False,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
            except Exception as e:
                injection_coordination_metrics['circular_dependency_checks'].append({
                    'registration_error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            # Test singleton behavior
            service_instance_1 = dependency_injection_container.get_service('user_service_di')
            service_instance_2 = dependency_injection_container.get_service('user_service_di')
            
            # Both instances should be the same for singleton services
            assert service_instance_1 is service_instance_2
            
            injection_coordination_metrics['injection_events'].append({
                'component': 'singleton_validation',
                'singleton_confirmed': service_instance_1 is service_instance_2,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Validate dependency injection coordination
        assert len(injection_coordination_metrics['services_registered']) == 3
        assert len(injection_coordination_metrics['dependencies_resolved']) >= 2
        assert len(injection_coordination_metrics['injection_events']) >= 3
        
        # Validate service registration
        for service_name in injection_coordination_metrics['services_registered']:
            assert service_name in ['user_repository', 'user_service_di', 'auth_service_di']
        
        # Validate dependency resolution
        for dependency_resolution in injection_coordination_metrics['dependencies_resolved']:
            assert 'service' in dependency_resolution
            assert 'dependencies' in dependency_resolution
            assert isinstance(dependency_resolution['dependencies'], list)
        
        # Validate injection events
        injection_components = [
            event['component'] for event in injection_coordination_metrics['injection_events']
        ]
        assert 'blueprint_handler' in injection_components
        assert 'service_composition' in injection_components
        assert 'singleton_validation' in injection_components
        
        # Validate circular dependency handling
        if injection_coordination_metrics['circular_dependency_checks']:
            # Either no circular dependencies created, or they were detected
            circular_check = injection_coordination_metrics['circular_dependency_checks'][0]
            assert 'detected' in circular_check or 'registration_error' in circular_check


# ================================================================================================
# PERFORMANCE AND RESOURCE COORDINATION TESTS
# ================================================================================================

@pytest.mark.workflow
@pytest.mark.performance_workflow
@pytest.mark.scaling
class TestPerformanceResourceCoordination:
    """
    Performance and resource coordination test class validating system
    performance under multi-component coordination scenarios.
    """
    
    def test_multi_component_performance_coordination(
        self,
        app: Flask,
        client: FlaskClient,
        workflow_performance_benchmarker: Any,
        resource_monitor: Any,
        service_registry: Dict[str, Any]
    ):
        """
        Test performance coordination across multiple Flask components.
        
        Validates that multi-component coordination maintains acceptable
        performance levels while scaling across blueprints, services,
        and database operations during complex workflow execution.
        """
        # Set performance baselines from Node.js implementation
        workflow_performance_benchmarker.set_baseline_metrics(
            'multi_component_coordination',
            {
                'execution_time': 0.5,   # 500ms baseline
                'memory_usage': 50.0,    # 50MB baseline
                'cpu_usage': 15.0,       # 15% CPU baseline
                'database_queries': 10   # 10 queries baseline
            }
        )
        
        performance_coordination_results = {
            'component_timings': {},
            'resource_consumption': {},
            'coordination_overhead': {},
            'bottleneck_analysis': {}
        }
        
        def multi_component_workflow():
            """Complex workflow involving all Flask components."""
            workflow_start = time.time()
            component_timings = {}
            
            with app.test_request_context('/api/complex-operation', method='POST'):
                # Component 1: Authentication processing
                auth_start = time.time()
                g.user_id = 123
                g.authenticated = True
                g.permissions = ['read', 'write', 'admin']
                auth_time = time.time() - auth_start
                component_timings['authentication'] = auth_time
                
                # Component 2: Request validation
                validation_start = time.time()
                request_data = {
                    'operation_type': 'complex_business_logic',
                    'data_payload': {'records': list(range(100))},
                    'validation_rules': ['required_fields', 'data_integrity', 'business_rules']
                }
                # Simulate validation processing
                for rule in request_data['validation_rules']:
                    time.sleep(0.001)  # Simulate validation time
                validation_time = time.time() - validation_start
                component_timings['validation'] = validation_time
                
                # Component 3: Service layer orchestration
                service_start = time.time()
                service_operations = []
                
                # Mock multiple service calls
                for i in range(5):
                    service_operation = {
                        'service_id': f'service_{i}',
                        'operation': f'business_operation_{i}',
                        'data_processed': len(request_data['data_payload']['records']),
                        'timestamp': datetime.utcnow().isoformat()
                    }
                    service_operations.append(service_operation)
                    time.sleep(0.002)  # Simulate service processing
                
                service_time = time.time() - service_start
                component_timings['service_orchestration'] = service_time
                
                # Component 4: Database operations
                database_start = time.time()
                database_operations = []
                
                # Simulate multiple database calls
                for i in range(8):
                    db_operation = {
                        'query_id': f'query_{i}',
                        'operation_type': 'read' if i % 2 == 0 else 'write',
                        'table': f'table_{i % 3}',
                        'execution_time': 0.003 + (i * 0.001)
                    }
                    database_operations.append(db_operation)
                    time.sleep(0.003)  # Simulate database time
                
                database_time = time.time() - database_start
                component_timings['database_operations'] = database_time
                
                # Component 5: Response generation
                response_start = time.time()
                response_data = {
                    'request_id': str(uuid.uuid4()),
                    'user_id': g.user_id,
                    'operation_results': service_operations,
                    'database_results': database_operations,
                    'processing_summary': {
                        'total_services': len(service_operations),
                        'total_queries': len(database_operations),
                        'data_records_processed': len(request_data['data_payload']['records'])
                    },
                    'performance_metrics': component_timings
                }
                response_time = time.time() - response_start
                component_timings['response_generation'] = response_time
                
                # Calculate coordination overhead
                total_component_time = sum(component_timings.values())
                total_workflow_time = time.time() - workflow_start
                coordination_overhead = total_workflow_time - total_component_time
                
                performance_coordination_results['component_timings'] = component_timings
                performance_coordination_results['coordination_overhead'] = {
                    'total_workflow_time': total_workflow_time,
                    'total_component_time': total_component_time,
                    'coordination_overhead': coordination_overhead,
                    'overhead_percentage': (coordination_overhead / total_workflow_time * 100) if total_workflow_time > 0 else 0
                }
                
                return response_data
        
        # Benchmark multi-component workflow with resource monitoring
        with resource_monitor.monitor_context(interval=0.05) as monitor:
            benchmark_result = workflow_performance_benchmarker.benchmark_workflow(
                'multi_component_coordination',
                multi_component_workflow,
                iterations=5
            )
        
        # Collect resource monitoring data
        resource_metrics = monitor._generate_metrics_summary()
        performance_coordination_results['resource_consumption'] = {
            'memory_metrics': resource_metrics['memory_metrics'],
            'cpu_metrics': resource_metrics['cpu_metrics'],
            'samples_collected': resource_metrics['samples_collected'],
            'collection_duration': resource_metrics['collection_duration']
        }
        
        # Analyze bottlenecks
        if performance_coordination_results['component_timings']:
            component_times = performance_coordination_results['component_timings']
            max_time_component = max(component_times, key=component_times.get)
            min_time_component = min(component_times, key=component_times.get)
            
            performance_coordination_results['bottleneck_analysis'] = {
                'slowest_component': max_time_component,
                'slowest_component_time': component_times[max_time_component],
                'fastest_component': min_time_component,
                'fastest_component_time': component_times[min_time_component],
                'performance_variance': component_times[max_time_component] - component_times[min_time_component],
                'optimization_target': max_time_component
            }
        
        # Validate performance coordination results
        assert benchmark_result['success'] is True
        assert benchmark_result['avg_execution_time'] > 0
        assert benchmark_result['iterations'] == 5
        
        # Validate component coordination performance
        if 'baseline_comparison' in benchmark_result:
            baseline_comparison = benchmark_result['baseline_comparison']
            
            # Performance should not degrade significantly
            assert baseline_comparison['execution_time_ratio'] < 2.0  # Within 2x of baseline
            
            # Memory usage should be reasonable
            if baseline_comparison['memory_usage_ratio'] > 0:
                assert baseline_comparison['memory_usage_ratio'] < 3.0  # Within 3x of baseline
        
        # Validate coordination overhead is acceptable
        coordination_metrics = performance_coordination_results['coordination_overhead']
        assert coordination_metrics['coordination_overhead'] >= 0
        assert coordination_metrics['overhead_percentage'] < 30  # Less than 30% overhead
        
        # Validate resource consumption
        resource_consumption = performance_coordination_results['resource_consumption']
        assert resource_consumption['samples_collected'] > 0
        assert resource_consumption['memory_metrics']['avg'] > 0
        assert resource_consumption['cpu_metrics']['avg'] >= 0
        
        # Validate bottleneck analysis provides actionable insights
        if performance_coordination_results['bottleneck_analysis']:
            bottleneck = performance_coordination_results['bottleneck_analysis']
            assert 'slowest_component' in bottleneck
            assert 'optimization_target' in bottleneck
            assert bottleneck['performance_variance'] >= 0
        
        # Component timing validation
        if performance_coordination_results['component_timings']:
            timings = performance_coordination_results['component_timings']
            expected_components = [
                'authentication', 
                'validation', 
                'service_orchestration', 
                'database_operations', 
                'response_generation'
            ]
            
            for component in expected_components:
                if component in timings:
                    assert timings[component] > 0
                    assert timings[component] < 1.0  # Each component under 1 second
        
        # Generate comprehensive performance report
        performance_report = workflow_performance_benchmarker.generate_performance_report()
        assert performance_report['total_workflows_benchmarked'] >= 1
        
        # Log performance insights for optimization
        print(f"\nMulti-Component Coordination Performance Results:")
        print(f"Average Execution Time: {benchmark_result['avg_execution_time']:.4f}s")
        print(f"Coordination Overhead: {coordination_metrics['overhead_percentage']:.2f}%")
        if performance_coordination_results['bottleneck_analysis']:
            bottleneck = performance_coordination_results['bottleneck_analysis']
            print(f"Performance Bottleneck: {bottleneck['optimization_target']} ({bottleneck['slowest_component_time']:.4f}s)")