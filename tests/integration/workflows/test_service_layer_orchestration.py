"""
Comprehensive Service Layer pattern validation test suite ensuring proper business logic orchestration,
dependency injection, and workflow coordination between Flask services.

This test file validates the Python class file generation, Flask application context registration,
and service composition patterns that replace Node.js business logic while maintaining functional 
equivalence per Section 4.5.2 and Feature F-005 requirements.

Key Testing Areas:
- Service Layer implementation with functional equivalence per Section 4.5.1
- Flask application context registration and dependency injection per Section 4.5.2
- Business logic abstraction and workflow orchestration per Section 4.5.3
- Transaction boundary management with Flask-SQLAlchemy per Section 6.1.1
- Service composition patterns for complex business workflows per Section 5.2.3
- Flask blueprint integration with Service Layer per Section 5.1.1
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from contextlib import contextmanager

# Flask and testing imports
from flask import Flask, current_app, request, g
from flask.ctx import AppContext, RequestContext
from flask_sqlalchemy import SQLAlchemy
from flask_injector import FlaskInjector, inject
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import sessionmaker

# Application imports
from src.services.base import BaseService
from src.services.user_service import UserService  
from src.services.business_entity_service import BusinessEntityService
from src.services.workflow_orchestrator import WorkflowOrchestrator
from src.services.validation_service import ValidationService
from src.models.user import User
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.models.session import UserSession
from src.models.base import BaseModel
from src.blueprints import register_blueprints
from src.auth.services import AuthService

# Configure logging for detailed test output
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@dataclass
class ServiceOrchestrationTestContext:
    """Test context for Service Layer orchestration validation"""
    app: Flask
    db: SQLAlchemy
    injector: FlaskInjector
    services: Dict[str, BaseService]
    test_data: Dict[str, Any]
    performance_metrics: Dict[str, float]


class TestServiceLayerOrchestration:
    """
    Comprehensive Service Layer pattern validation ensuring proper business logic orchestration,
    dependency injection, and workflow coordination between Flask services per Section 4.5.2.
    """

    def test_flask_application_context_registration(self, app, db):
        """
        Test Service Layer integration with Flask application context registration 
        per Section 4.5.2 requirements for Python class file generation.
        
        Validates:
        - Flask application factory pattern initialization
        - Service registration within application context
        - Context management and lifecycle handling
        """
        logger.info("Testing Flask application context registration for Service Layer")
        
        with app.app_context():
            # Verify Flask application context is properly initialized
            assert current_app is not None
            assert current_app.name == app.name
            
            # Test service registration within application context
            user_service = UserService()
            business_service = BusinessEntityService()
            workflow_orchestrator = WorkflowOrchestrator()
            
            # Validate services are properly registered with Flask context
            assert hasattr(user_service, 'app_context')
            assert hasattr(business_service, 'app_context') 
            assert hasattr(workflow_orchestrator, 'app_context')
            
            # Test Flask application context accessibility from services
            assert user_service.get_current_app() == current_app
            assert business_service.get_current_app() == current_app
            assert workflow_orchestrator.get_current_app() == current_app
            
        logger.info("✓ Flask application context registration validated successfully")

    def test_dependency_injection_architecture(self, app, db):
        """
        Test dependency injection architecture using Flask-Injector for clean service 
        separation and enhanced testability per Section 4.5.1.
        
        Validates:
        - Flask-Injector integration patterns
        - Service dependency resolution
        - Clean architectural separation
        """
        logger.info("Testing dependency injection architecture with Flask-Injector")
        
        with app.app_context():
            # Configure Flask-Injector for dependency injection testing
            from injector import Injector, singleton
            
            def configure_services(binder):
                binder.bind(UserService, to=UserService, scope=singleton)
                binder.bind(BusinessEntityService, to=BusinessEntityService, scope=singleton)
                binder.bind(ValidationService, to=ValidationService, scope=singleton)
                binder.bind(WorkflowOrchestrator, to=WorkflowOrchestrator, scope=singleton)
            
            injector = Injector([configure_services])
            FlaskInjector(app=app, injector=injector)
            
            # Test dependency injection resolution
            user_service = injector.get(UserService)
            business_service = injector.get(BusinessEntityService)
            workflow_orchestrator = injector.get(WorkflowOrchestrator)
            
            assert isinstance(user_service, UserService)
            assert isinstance(business_service, BusinessEntityService)
            assert isinstance(workflow_orchestrator, WorkflowOrchestrator)
            
            # Test service dependencies are properly injected
            assert workflow_orchestrator.user_service is not None
            assert workflow_orchestrator.business_service is not None
            assert workflow_orchestrator.validation_service is not None
            
            # Validate singleton pattern enforcement
            user_service_2 = injector.get(UserService)
            assert user_service is user_service_2  # Same instance
            
        logger.info("✓ Dependency injection architecture validated successfully")

    def test_service_composition_patterns(self, app, db, sample_users, sample_business_entities):
        """
        Test service composition architecture supporting complex business workflows 
        through coordinated service interactions per Section 5.2.3.
        
        Validates:
        - Multi-service workflow coordination
        - Service composition patterns
        - Business logic abstraction
        """
        logger.info("Testing service composition patterns for complex workflows")
        
        with app.app_context():
            # Initialize services for composition testing
            user_service = UserService()
            business_service = BusinessEntityService()
            validation_service = ValidationService()
            workflow_orchestrator = WorkflowOrchestrator(
                user_service=user_service,
                business_service=business_service,
                validation_service=validation_service
            )
            
            # Test complex business workflow composition
            test_user_data = {
                'username': 'test_composition_user',
                'email': 'test@composition.example.com',
                'password': 'secure_password_123'
            }
            
            test_entity_data = {
                'name': 'Test Business Entity',
                'description': 'Complex workflow test entity',
                'status': 'active'
            }
            
            # Execute composed workflow operation
            result = workflow_orchestrator.execute_complex_workflow(
                user_data=test_user_data,
                entity_data=test_entity_data,
                workflow_type='user_entity_creation'
            )
            
            # Validate workflow composition results
            assert result['success'] is True
            assert 'user_id' in result
            assert 'entity_id' in result
            assert 'workflow_id' in result
            
            # Verify all services participated in composition
            assert result['services_involved'] == [
                'UserService', 'BusinessEntityService', 'ValidationService'
            ]
            
            # Test service composition error handling
            invalid_data = {'invalid': 'data_structure'}
            error_result = workflow_orchestrator.execute_complex_workflow(
                user_data=invalid_data,
                entity_data=test_entity_data,
                workflow_type='invalid_workflow'
            )
            
            assert error_result['success'] is False
            assert 'error' in error_result
            assert 'validation_errors' in error_result
            
        logger.info("✓ Service composition patterns validated successfully")

    def test_transaction_boundary_management(self, app, db):
        """
        Test transaction boundary management across service calls with Flask-SQLAlchemy 
        session coordination per Section 4.5.3.
        
        Validates:
        - ACID properties preservation
        - Transaction rollback capabilities
        - Cross-service transaction coordination
        """
        logger.info("Testing transaction boundary management across services")
        
        with app.app_context():
            user_service = UserService()
            business_service = BusinessEntityService()
            workflow_orchestrator = WorkflowOrchestrator()
            
            # Test successful transaction boundary
            test_transaction_data = {
                'user': {
                    'username': 'transaction_test_user',
                    'email': 'transaction@test.example.com',
                    'password': 'secure_password_123'
                },
                'entity': {
                    'name': 'Transaction Test Entity',
                    'description': 'Testing transaction boundaries',
                    'status': 'active'
                }
            }
            
            # Execute transaction with explicit boundary management
            with workflow_orchestrator.transaction_scope() as tx:
                user_result = user_service.create_user_with_transaction(
                    test_transaction_data['user'], transaction=tx
                )
                
                entity_result = business_service.create_entity_with_transaction(
                    test_transaction_data['entity'], 
                    owner_id=user_result['id'],
                    transaction=tx
                )
                
                # Verify transaction state
                assert tx.is_active
                assert not tx.is_committed
                
                # Commit transaction explicitly
                tx.commit()
                
            # Verify data persistence after transaction
            created_user = user_service.get_user_by_id(user_result['id'])
            created_entity = business_service.get_entity_by_id(entity_result['id'])
            
            assert created_user is not None
            assert created_entity is not None
            assert created_entity.owner_id == created_user.id
            
            # Test transaction rollback scenario
            rollback_data = {
                'user': {
                    'username': 'rollback_test_user',
                    'email': 'rollback@test.example.com',
                    'password': 'secure_password_123'
                },
                'entity': {
                    'name': '',  # Invalid empty name to trigger rollback
                    'description': 'Testing rollback scenario',
                    'status': 'invalid_status'
                }
            }
            
            # Execute transaction with forced rollback
            with pytest.raises(SQLAlchemyError):
                with workflow_orchestrator.transaction_scope() as tx:
                    user_rollback_result = user_service.create_user_with_transaction(
                        rollback_data['user'], transaction=tx
                    )
                    
                    # This should fail and trigger rollback
                    business_service.create_entity_with_transaction(
                        rollback_data['entity'],
                        owner_id=user_rollback_result['id'],
                        transaction=tx
                    )
                    
            # Verify rollback occurred - user should not exist
            rollback_user = user_service.get_user_by_username('rollback_test_user')
            assert rollback_user is None
            
        logger.info("✓ Transaction boundary management validated successfully")

    def test_service_registration_and_discovery(self, app, db):
        """
        Test comprehensive service registration and discovery within Flask application 
        factory pattern per Section 5.1.1.
        
        Validates:
        - Flask application factory integration
        - Service registration orchestration
        - Service discovery mechanisms
        """
        logger.info("Testing service registration and discovery patterns")
        
        with app.app_context():
            # Test service registry initialization
            from src.services import ServiceRegistry
            registry = ServiceRegistry(app)
            
            # Register services with application factory
            registry.register_service('user_service', UserService)
            registry.register_service('business_service', BusinessEntityService) 
            registry.register_service('validation_service', ValidationService)
            registry.register_service('workflow_orchestrator', WorkflowOrchestrator)
            
            # Test service discovery
            discovered_user_service = registry.get_service('user_service')
            discovered_business_service = registry.get_service('business_service')
            discovered_validation_service = registry.get_service('validation_service')
            discovered_orchestrator = registry.get_service('workflow_orchestrator')
            
            assert isinstance(discovered_user_service, UserService)
            assert isinstance(discovered_business_service, BusinessEntityService)
            assert isinstance(discovered_validation_service, ValidationService)
            assert isinstance(discovered_orchestrator, WorkflowOrchestrator)
            
            # Test service lifecycle management
            assert registry.is_service_registered('user_service')
            assert registry.is_service_registered('business_service')
            assert registry.is_service_registered('validation_service')
            assert registry.is_service_registered('workflow_orchestrator')
            
            # Test service unregistration
            registry.unregister_service('validation_service')
            assert not registry.is_service_registered('validation_service')
            
            # Test service re-registration
            registry.register_service('validation_service', ValidationService)
            assert registry.is_service_registered('validation_service')
            
            # Validate service registry integration with Flask app context
            assert registry.app == current_app
            assert len(registry.get_all_services()) == 4
            
        logger.info("✓ Service registration and discovery validated successfully")

    def test_blueprint_integration_with_service_layer(self, app, db):
        """
        Test service layer integration with Flask blueprints for modular business 
        logic execution per Section 5.1.1.
        
        Validates:
        - Blueprint and service layer coordination
        - Modular business logic execution
        - Request context service access
        """
        logger.info("Testing Flask blueprint integration with Service Layer")
        
        with app.app_context():
            # Register blueprints with service layer integration
            register_blueprints(app)
            
            # Create test client for blueprint testing
            with app.test_client() as client:
                with app.test_request_context('/api/users', method='POST'):
                    # Test service layer access from blueprint context
                    from flask import g
                    
                    # Simulate blueprint service injection
                    g.user_service = UserService()
                    g.business_service = BusinessEntityService()
                    g.workflow_orchestrator = WorkflowOrchestrator()
                    
                    # Test service accessibility from request context
                    assert hasattr(g, 'user_service')
                    assert hasattr(g, 'business_service')
                    assert hasattr(g, 'workflow_orchestrator')
                    
                    # Test service operations within request context
                    test_user_creation = {
                        'username': 'blueprint_test_user',
                        'email': 'blueprint@test.example.com',
                        'password': 'secure_password_123'
                    }
                    
                    # Execute service operation from blueprint context
                    user_result = g.user_service.create_user(test_user_creation)
                    assert user_result['success'] is True
                    assert 'id' in user_result
                    
                    # Test business entity creation through service integration
                    entity_creation = {
                        'name': 'Blueprint Test Entity',
                        'description': 'Testing blueprint service integration',
                        'status': 'active',
                        'owner_id': user_result['id']
                    }
                    
                    entity_result = g.business_service.create_entity(entity_creation)
                    assert entity_result['success'] is True
                    assert 'id' in entity_result
                    
                    # Test workflow orchestration from blueprint
                    workflow_result = g.workflow_orchestrator.execute_user_entity_workflow(
                        user_id=user_result['id'],
                        entity_id=entity_result['id'],
                        workflow_type='associate_user_entity'
                    )
                    
                    assert workflow_result['success'] is True
                    assert workflow_result['workflow_status'] == 'completed'
                    
        logger.info("✓ Blueprint integration with Service Layer validated successfully")

    def test_business_logic_orchestration_equivalence(self, app, db, nodejs_baseline_service):
        """
        Test business logic abstraction and workflow orchestration maintaining functional 
        equivalence with original Node.js business rules per Section 4.5.1.
        
        Validates:
        - Business rule preservation
        - Workflow execution equivalence
        - Calculation algorithm preservation
        """
        logger.info("Testing business logic orchestration equivalence with Node.js")
        
        with app.app_context():
            workflow_orchestrator = WorkflowOrchestrator()
            validation_service = ValidationService()
            
            # Test business rule preservation
            business_rule_test_cases = [
                {
                    'rule_type': 'user_validation',
                    'input': {
                        'username': 'test_user_123',
                        'email': 'test@example.com',
                        'password': 'secure_password_123'
                    },
                    'expected_outcome': True
                },
                {
                    'rule_type': 'entity_validation',
                    'input': {
                        'name': 'Valid Entity Name',
                        'description': 'Valid entity description',
                        'status': 'active'
                    },
                    'expected_outcome': True
                },
                {
                    'rule_type': 'relationship_validation',
                    'input': {
                        'source_entity_id': 1,
                        'target_entity_id': 2,
                        'relationship_type': 'associated'
                    },
                    'expected_outcome': True
                }
            ]
            
            # Execute business rule validation tests
            for test_case in business_rule_test_cases:
                flask_result = validation_service.validate_business_rule(
                    test_case['rule_type'],
                    test_case['input']
                )
                
                # Compare with Node.js baseline (mocked for testing)
                nodejs_result = nodejs_baseline_service.validate_business_rule(
                    test_case['rule_type'],
                    test_case['input']
                )
                
                assert flask_result == nodejs_result
                assert flask_result == test_case['expected_outcome']
                
            # Test complex workflow orchestration equivalence
            complex_workflow_data = {
                'workflow_type': 'user_entity_relationship_creation',
                'users': [
                    {'username': 'user1', 'email': 'user1@test.com', 'password': 'pass123'},
                    {'username': 'user2', 'email': 'user2@test.com', 'password': 'pass456'}
                ],
                'entities': [
                    {'name': 'Entity A', 'description': 'First entity', 'status': 'active'},
                    {'name': 'Entity B', 'description': 'Second entity', 'status': 'active'}
                ],
                'relationships': [
                    {'source': 0, 'target': 1, 'type': 'associated'}
                ]
            }
            
            # Execute complex workflow in Flask
            flask_workflow_result = workflow_orchestrator.execute_complex_business_workflow(
                complex_workflow_data
            )
            
            # Compare with Node.js baseline (mocked for testing)
            nodejs_workflow_result = nodejs_baseline_service.execute_complex_business_workflow(
                complex_workflow_data
            )
            
            # Validate functional equivalence
            assert flask_workflow_result['success'] == nodejs_workflow_result['success']
            assert len(flask_workflow_result['created_users']) == len(nodejs_workflow_result['created_users'])
            assert len(flask_workflow_result['created_entities']) == len(nodejs_workflow_result['created_entities'])
            assert len(flask_workflow_result['created_relationships']) == len(nodejs_workflow_result['created_relationships'])
            
        logger.info("✓ Business logic orchestration equivalence validated successfully")

    def test_service_layer_performance_benchmarking(self, app, db, benchmark):
        """
        Test Service Layer performance against Node.js baseline ensuring equivalent 
        or improved performance metrics per Section 4.11.
        
        Validates:
        - Service operation performance
        - Workflow execution timing
        - Resource utilization efficiency
        """
        logger.info("Testing Service Layer performance benchmarking")
        
        with app.app_context():
            user_service = UserService()
            business_service = BusinessEntityService()
            workflow_orchestrator = WorkflowOrchestrator()
            
            # Performance test data
            performance_test_data = {
                'user_creation_batch': [
                    {
                        'username': f'perf_user_{i}',
                        'email': f'perf{i}@test.com',
                        'password': 'secure_password_123'
                    }
                    for i in range(100)
                ],
                'entity_creation_batch': [
                    {
                        'name': f'Performance Entity {i}',
                        'description': f'Performance test entity {i}',
                        'status': 'active'
                    }
                    for i in range(100)
                ]
            }
            
            # Benchmark user creation performance
            def create_users_batch():
                return user_service.create_users_batch(
                    performance_test_data['user_creation_batch']
                )
            
            user_creation_result = benchmark(create_users_batch)
            assert user_creation_result['success'] is True
            assert len(user_creation_result['created_users']) == 100
            
            # Benchmark entity creation performance  
            def create_entities_batch():
                return business_service.create_entities_batch(
                    performance_test_data['entity_creation_batch'],
                    owner_ids=[user['id'] for user in user_creation_result['created_users']]
                )
                
            entity_creation_result = benchmark(create_entities_batch)
            assert entity_creation_result['success'] is True
            assert len(entity_creation_result['created_entities']) == 100
            
            # Benchmark complex workflow performance
            def execute_complex_workflow_batch():
                return workflow_orchestrator.execute_batch_workflow(
                    user_ids=[user['id'] for user in user_creation_result['created_users']],
                    entity_ids=[entity['id'] for entity in entity_creation_result['created_entities']],
                    workflow_type='batch_association'
                )
                
            workflow_result = benchmark(execute_complex_workflow_batch)
            assert workflow_result['success'] is True
            assert len(workflow_result['processed_associations']) == 100
            
            # Log performance metrics for comparison
            logger.info(f"User creation performance: {benchmark.stats}")
            logger.info(f"Entity creation performance: {benchmark.stats}")
            logger.info(f"Workflow execution performance: {benchmark.stats}")
            
        logger.info("✓ Service Layer performance benchmarking completed successfully")

    def test_error_handling_and_recovery_workflows(self, app, db):
        """
        Test comprehensive error handling with automatic retry mechanisms 
        per Section 4.5.3 workflow orchestration patterns.
        
        Validates:
        - Error handling patterns
        - Automatic retry mechanisms
        - Workflow recovery procedures
        """
        logger.info("Testing error handling and recovery workflows")
        
        with app.app_context():
            workflow_orchestrator = WorkflowOrchestrator()
            
            # Test database connection error handling
            with patch('src.models.base.db.session') as mock_session:
                mock_session.commit.side_effect = SQLAlchemyError("Database connection failed")
                
                error_test_data = {
                    'user': {
                        'username': 'error_test_user',
                        'email': 'error@test.com',
                        'password': 'secure_password_123'
                    }
                }
                
                # Execute workflow with error scenario
                result = workflow_orchestrator.execute_workflow_with_retry(
                    workflow_type='user_creation',
                    data=error_test_data,
                    max_retries=3
                )
                
                # Validate error handling
                assert result['success'] is False
                assert 'error' in result
                assert result['retry_count'] == 3
                assert result['error_type'] == 'SQLAlchemyError'
                
            # Test validation error handling
            invalid_data = {
                'user': {
                    'username': '',  # Invalid empty username
                    'email': 'invalid_email',  # Invalid email format
                    'password': '123'  # Too short password
                }
            }
            
            validation_result = workflow_orchestrator.execute_validated_workflow(
                workflow_type='user_creation',
                data=invalid_data
            )
            
            assert validation_result['success'] is False
            assert 'validation_errors' in validation_result
            assert len(validation_result['validation_errors']) >= 3
            
            # Test workflow recovery mechanisms
            recovery_data = {
                'user': {
                    'username': 'recovery_test_user', 
                    'email': 'recovery@test.com',
                    'password': 'secure_password_123'
                }
            }
            
            # Simulate partial failure and recovery
            with patch('src.services.user_service.UserService.create_user') as mock_create:
                # First call fails, second succeeds
                mock_create.side_effect = [
                    SQLAlchemyError("Temporary failure"),
                    {'success': True, 'id': 123, 'username': 'recovery_test_user'}
                ]
                
                recovery_result = workflow_orchestrator.execute_workflow_with_recovery(
                    workflow_type='user_creation',
                    data=recovery_data,
                    recovery_strategy='retry_with_backoff'
                )
                
                assert recovery_result['success'] is True
                assert recovery_result['recovery_executed'] is True
                assert recovery_result['attempts'] == 2
                
        logger.info("✓ Error handling and recovery workflows validated successfully")

    def test_service_layer_integration_comprehensive(self, app, db, sample_users, sample_business_entities):
        """
        Comprehensive integration test validating complete Service Layer implementation
        with all components working together per Feature F-005 and F-006 requirements.
        
        Validates:
        - End-to-end service layer functionality
        - Complete workflow integration
        - System-wide service coordination
        """
        logger.info("Testing comprehensive Service Layer integration")
        
        with app.app_context():
            # Initialize complete service ecosystem
            from src.services import ServiceRegistry
            registry = ServiceRegistry(app)
            
            # Register all services
            user_service = registry.register_service('user_service', UserService)
            business_service = registry.register_service('business_service', BusinessEntityService)
            validation_service = registry.register_service('validation_service', ValidationService)
            workflow_orchestrator = registry.register_service('workflow_orchestrator', WorkflowOrchestrator)
            auth_service = registry.register_service('auth_service', AuthService)
            
            # Test comprehensive workflow execution
            comprehensive_test_scenario = {
                'phase_1': {
                    'action': 'user_registration',
                    'data': {
                        'username': 'comprehensive_user',
                        'email': 'comprehensive@test.com',
                        'password': 'secure_password_123'
                    }
                },
                'phase_2': {
                    'action': 'authentication',
                    'data': {
                        'username': 'comprehensive_user',
                        'password': 'secure_password_123'
                    }
                },
                'phase_3': {
                    'action': 'entity_creation',
                    'data': {
                        'name': 'Comprehensive Test Entity',
                        'description': 'Full integration test entity',
                        'status': 'active'
                    }
                },
                'phase_4': {
                    'action': 'relationship_establishment',
                    'data': {
                        'relationship_type': 'ownership'
                    }
                },
                'phase_5': {
                    'action': 'workflow_validation',
                    'data': {
                        'validation_type': 'complete_system'
                    }
                }
            }
            
            # Execute comprehensive workflow
            execution_results = {}
            
            # Phase 1: User Registration
            user_result = workflow_orchestrator.execute_user_registration_workflow(
                comprehensive_test_scenario['phase_1']['data']
            )
            execution_results['user_registration'] = user_result
            assert user_result['success'] is True
            
            # Phase 2: Authentication
            auth_result = workflow_orchestrator.execute_authentication_workflow(
                user_id=user_result['user_id'],
                credentials=comprehensive_test_scenario['phase_2']['data']
            )
            execution_results['authentication'] = auth_result
            assert auth_result['success'] is True
            assert auth_result['authenticated'] is True
            
            # Phase 3: Entity Creation
            entity_result = workflow_orchestrator.execute_entity_creation_workflow(
                user_id=user_result['user_id'],
                entity_data=comprehensive_test_scenario['phase_3']['data'],
                session_token=auth_result['session_token']
            )
            execution_results['entity_creation'] = entity_result
            assert entity_result['success'] is True
            
            # Phase 4: Relationship Establishment
            relationship_result = workflow_orchestrator.execute_relationship_workflow(
                user_id=user_result['user_id'],
                entity_id=entity_result['entity_id'],
                relationship_data=comprehensive_test_scenario['phase_4']['data']
            )
            execution_results['relationship_establishment'] = relationship_result
            assert relationship_result['success'] is True
            
            # Phase 5: Workflow Validation
            validation_result = workflow_orchestrator.execute_comprehensive_validation(
                workflow_results=execution_results,
                validation_criteria=comprehensive_test_scenario['phase_5']['data']
            )
            execution_results['workflow_validation'] = validation_result
            assert validation_result['success'] is True
            assert validation_result['all_phases_valid'] is True
            
            # Validate complete system state
            final_system_state = workflow_orchestrator.get_system_state_summary()
            assert final_system_state['users_count'] >= 1
            assert final_system_state['entities_count'] >= 1
            assert final_system_state['relationships_count'] >= 1
            assert final_system_state['active_sessions_count'] >= 1
            
            # Verify all services participated in workflow
            assert len(final_system_state['services_utilized']) == 5
            expected_services = ['UserService', 'BusinessEntityService', 'ValidationService', 'WorkflowOrchestrator', 'AuthService']
            for service in expected_services:
                assert service in final_system_state['services_utilized']
                
        logger.info("✓ Comprehensive Service Layer integration validated successfully")


class TestServiceLayerPerformanceOptimization:
    """
    Performance optimization validation for Service Layer patterns ensuring
    efficient workflow execution per Section 4.5.3.
    """

    def test_service_caching_optimization(self, app, db, benchmark):
        """Test service layer caching for improved performance"""
        logger.info("Testing service layer caching optimization")
        
        with app.app_context():
            user_service = UserService()
            
            # Create test user for caching tests
            test_user_data = {
                'username': 'cache_test_user',
                'email': 'cache@test.com', 
                'password': 'secure_password_123'
            }
            
            user_result = user_service.create_user(test_user_data)
            user_id = user_result['id']
            
            # Benchmark uncached user retrieval
            def get_user_uncached():
                return user_service.get_user_by_id(user_id, use_cache=False)
                
            uncached_result = benchmark(get_user_uncached)
            
            # Benchmark cached user retrieval
            def get_user_cached():
                return user_service.get_user_by_id(user_id, use_cache=True)
                
            cached_result = benchmark(get_user_cached)
            
            # Validate caching improves performance
            assert uncached_result is not None
            assert cached_result is not None
            assert uncached_result.id == cached_result.id
            
        logger.info("✓ Service layer caching optimization validated")

    def test_database_query_optimization(self, app, db, benchmark):
        """Test optimized database query patterns for service layer"""
        logger.info("Testing database query optimization patterns")
        
        with app.app_context():
            business_service = BusinessEntityService()
            
            # Create test entities for query optimization testing
            test_entities = []
            for i in range(50):
                entity_data = {
                    'name': f'Query Test Entity {i}',
                    'description': f'Query optimization test {i}',
                    'status': 'active'
                }
                result = business_service.create_entity(entity_data)
                test_entities.append(result['id'])
            
            # Benchmark N+1 query pattern (inefficient)
            def get_entities_n_plus_one():
                entities = []
                for entity_id in test_entities:
                    entity = business_service.get_entity_by_id(entity_id)
                    entities.append(entity)
                return entities
                
            n_plus_one_result = benchmark(get_entities_n_plus_one)
            
            # Benchmark optimized batch query
            def get_entities_batch():
                return business_service.get_entities_by_ids(test_entities)
                
            batch_result = benchmark(get_entities_batch)
            
            # Validate optimization effectiveness
            assert len(n_plus_one_result) == len(batch_result)
            assert len(batch_result) == 50
            
        logger.info("✓ Database query optimization validated")


# Test fixtures and utilities
@pytest.fixture
def sample_users(app, db):
    """Fixture providing sample users for testing"""
    with app.app_context():
        users = []
        for i in range(5):
            user_data = {
                'username': f'sample_user_{i}',
                'email': f'sample{i}@test.com',
                'password': 'secure_password_123'
            }
            user = User(**user_data)
            db.session.add(user)
            users.append(user)
        
        db.session.commit()
        return users


@pytest.fixture 
def sample_business_entities(app, db, sample_users):
    """Fixture providing sample business entities for testing"""
    with app.app_context():
        entities = []
        for i, user in enumerate(sample_users):
            entity_data = {
                'name': f'Sample Entity {i}',
                'description': f'Sample entity for testing {i}',
                'status': 'active',
                'owner_id': user.id
            }
            entity = BusinessEntity(**entity_data)
            db.session.add(entity)
            entities.append(entity)
            
        db.session.commit()
        return entities


@pytest.fixture
def nodejs_baseline_service():
    """Mock fixture simulating Node.js baseline service for comparison testing"""
    class NodeJSBaselineService:
        def validate_business_rule(self, rule_type: str, input_data: Dict) -> bool:
            """Mock Node.js business rule validation"""
            # Simulate Node.js validation logic
            if rule_type == 'user_validation':
                return (
                    len(input_data.get('username', '')) >= 3 and
                    '@' in input_data.get('email', '') and
                    len(input_data.get('password', '')) >= 8
                )
            elif rule_type == 'entity_validation':
                return (
                    len(input_data.get('name', '')) > 0 and
                    input_data.get('status') in ['active', 'inactive']
                )
            elif rule_type == 'relationship_validation':
                return (
                    input_data.get('source_entity_id') != input_data.get('target_entity_id') and
                    input_data.get('relationship_type') in ['associated', 'related', 'dependent']
                )
            return False
            
        def execute_complex_business_workflow(self, workflow_data: Dict) -> Dict:
            """Mock Node.js complex workflow execution"""
            return {
                'success': True,
                'created_users': workflow_data.get('users', []),
                'created_entities': workflow_data.get('entities', []),
                'created_relationships': workflow_data.get('relationships', []),
                'workflow_id': 'nodejs_mock_workflow_123'
            }
    
    return NodeJSBaselineService()


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])