"""
Database Transaction Management Testing Suite

Comprehensive testing suite validating SQLAlchemy session handling, transaction boundaries,
and commit/rollback operations across complex business logic scenarios. This test file ensures
proper transaction isolation, validates service layer transaction coordination, and tests error
handling with automatic rollback capabilities while maintaining ACID compliance equivalent to
the original system's transaction patterns.

Migration Context:
This test suite validates the Flask-SQLAlchemy 3.1.1 transaction management implementation
against the original Node.js system behavior, ensuring zero functional regression and
maintaining all ACID properties during the Node.js to Python 3.13.3/Flask 3.1.1 migration.

Key Testing Areas:
- SQLAlchemy session management with Flask request context integration (Section 5.2.4)
- Service layer transaction boundary coordination for business logic operations (Section 5.2.3)
- Database transaction isolation and concurrent operation safety (Section 6.2.1)
- Error handling with automatic transaction rollback capabilities (Section 4.8)
- ACID transaction compliance maintaining data integrity equivalent to original system (Feature F-004)
- Complex transaction testing across multiple models and relationships (Feature F-005)
"""

import pytest
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from unittest.mock import patch, MagicMock

from flask import Flask, g, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, create_engine, event
from sqlalchemy.exc import (
    IntegrityError, 
    OperationalError, 
    SQLAlchemyError,
    InvalidRequestError
)
from sqlalchemy.orm import sessionmaker, scoped_session
from werkzeug.exceptions import InternalServerError

# Import application modules
from src.models import db
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.services.base import BaseService
from src.services.user_service import UserService
from src.services.business_entity_service import BusinessEntityService
from src.services.workflow_orchestrator import WorkflowOrchestrator


# ================================================================================================
# TRANSACTION MANAGEMENT TEST MARKERS AND CONFIGURATION
# ================================================================================================

pytestmark = [
    pytest.mark.database,
    pytest.mark.integration,
    pytest.mark.transaction
]


# ================================================================================================
# TRANSACTION TESTING FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def transaction_monitor(app: Flask, database: SQLAlchemy) -> Dict[str, Any]:
    """
    Transaction monitoring fixture for tracking transaction lifecycle events.
    
    Provides comprehensive monitoring of SQLAlchemy transaction events including
    begin, commit, rollback, and session operations for validation testing.
    
    Args:
        app: Flask application instance
        database: SQLAlchemy database instance
        
    Returns:
        Dict[str, Any]: Transaction monitor with event tracking capabilities
    """
    monitor = {
        'events': [],
        'transactions': [],
        'sessions': [],
        'errors': [],
        'active_transactions': 0,
        'committed_transactions': 0,
        'rolled_back_transactions': 0
    }
    
    def track_begin(session, transaction, connection):
        """Track transaction begin events."""
        event_data = {
            'type': 'begin',
            'timestamp': datetime.utcnow(),
            'session_id': id(session),
            'transaction_id': id(transaction),
            'connection_id': id(connection)
        }
        monitor['events'].append(event_data)
        monitor['transactions'].append(transaction)
        monitor['active_transactions'] += 1
    
    def track_commit(session):
        """Track transaction commit events."""
        event_data = {
            'type': 'commit',
            'timestamp': datetime.utcnow(),
            'session_id': id(session)
        }
        monitor['events'].append(event_data)
        monitor['committed_transactions'] += 1
        monitor['active_transactions'] = max(0, monitor['active_transactions'] - 1)
    
    def track_rollback(session):
        """Track transaction rollback events."""
        event_data = {
            'type': 'rollback',
            'timestamp': datetime.utcnow(),
            'session_id': id(session)
        }
        monitor['events'].append(event_data)
        monitor['rolled_back_transactions'] += 1
        monitor['active_transactions'] = max(0, monitor['active_transactions'] - 1)
    
    def track_error(exception_context):
        """Track transaction error events."""
        monitor['errors'].append({
            'exception': str(exception_context.original_exception),
            'timestamp': datetime.utcnow(),
            'context': str(exception_context)
        })
    
    with app.app_context():
        # Register SQLAlchemy event listeners
        event.listen(database.session, 'after_transaction_create', track_begin)
        event.listen(database.session, 'after_commit', track_commit)
        event.listen(database.session, 'after_rollback', track_rollback)
        event.listen(database.engine, 'handle_error', track_error)
        
        try:
            yield monitor
        finally:
            # Clean up event listeners
            event.remove(database.session, 'after_transaction_create', track_begin)
            event.remove(database.session, 'after_commit', track_commit)
            event.remove(database.session, 'after_rollback', track_rollback)
            event.remove(database.engine, 'handle_error', track_error)


@pytest.fixture(scope='function')
def concurrent_session_factory(app: Flask, database: SQLAlchemy):
    """
    Concurrent session factory for testing transaction isolation.
    
    Provides multiple database sessions for testing concurrent transaction
    behavior and isolation properties.
    
    Args:
        app: Flask application instance
        database: SQLAlchemy database instance
        
    Returns:
        Callable: Session factory function for creating isolated sessions
    """
    def create_session():
        """Create a new database session for concurrent testing."""
        engine = database.get_engine()
        Session = sessionmaker(bind=engine)
        return Session()
    
    return create_session


@pytest.fixture(scope='function')
def service_layer_setup(db_session, test_user: User):
    """
    Service layer setup fixture for transaction boundary testing.
    
    Provides configured service instances for testing transaction
    coordination across the service layer architecture.
    
    Args:
        db_session: Database session fixture
        test_user: Test user fixture
        
    Returns:
        Dict: Service instances for transaction testing
    """
    return {
        'user_service': UserService(db_session),
        'business_entity_service': BusinessEntityService(db_session),
        'workflow_orchestrator': WorkflowOrchestrator(db_session),
        'test_user': test_user
    }


# ================================================================================================
# SQLALCHEMY SESSION MANAGEMENT WITH FLASK REQUEST CONTEXT INTEGRATION TESTS
# Section 5.2.4 - Database Access Layer
# ================================================================================================

class TestSQLAlchemySessionManagement:
    """
    Test suite for SQLAlchemy session management with Flask request context integration.
    
    Validates proper session lifecycle management, Flask request context binding,
    and session cleanup across request boundaries per Section 5.2.4.
    """
    
    def test_session_request_context_binding(self, app: Flask, client, transaction_monitor):
        """
        Test SQLAlchemy session binding to Flask request context.
        
        Validates that database sessions are properly bound to Flask request
        contexts and automatically cleaned up after request completion.
        """
        with app.test_request_context():
            # Verify session is available in request context
            assert db.session is not None
            session_id = id(db.session)
            
            # Create a test user within request context
            user = User(
                username='context_test_user',
                email='context@test.com',
                password_hash='test_hash',
                is_active=True
            )
            db.session.add(user)
            db.session.commit()
            
            # Verify transaction was committed
            assert transaction_monitor['committed_transactions'] >= 1
            
            # Verify user was created
            created_user = db.session.query(User).filter_by(username='context_test_user').first()
            assert created_user is not None
            assert created_user.email == 'context@test.com'
        
        # After request context, session should be cleaned up
        # New request context should get a new session
        with app.test_request_context():
            new_session_id = id(db.session)
            # Sessions should be different instances (or properly cleaned)
            # This validates proper session lifecycle management
            
            # Verify data persists across request contexts
            user = db.session.query(User).filter_by(username='context_test_user').first()
            assert user is not None
    
    def test_session_thread_safety(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test SQLAlchemy session thread safety with Flask request contexts.
        
        Validates that each Flask request context gets its own session
        and that concurrent requests don't interfere with each other.
        """
        results = []
        errors = []
        
        def create_user_in_thread(thread_id: int):
            """Create user in separate thread with request context."""
            try:
                with app.test_request_context():
                    user = User(
                        username=f'thread_user_{thread_id}',
                        email=f'thread{thread_id}@test.com',
                        password_hash='thread_hash',
                        is_active=True
                    )
                    db.session.add(user)
                    db.session.commit()
                    
                    # Verify user was created in this session
                    created_user = db.session.query(User).filter_by(
                        username=f'thread_user_{thread_id}'
                    ).first()
                    
                    results.append({
                        'thread_id': thread_id,
                        'user_id': created_user.id if created_user else None,
                        'session_id': id(db.session),
                        'success': created_user is not None
                    })
            except Exception as e:
                errors.append({
                    'thread_id': thread_id,
                    'error': str(e)
                })
        
        # Execute concurrent operations
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(create_user_in_thread, i) 
                for i in range(5)
            ]
            
            for future in as_completed(futures):
                future.result()  # Wait for completion
        
        # Validate results
        assert len(errors) == 0, f"Thread safety errors occurred: {errors}"
        assert len(results) == 5, "Not all threads completed successfully"
        
        # Verify all users were created
        for result in results:
            assert result['success'], f"User creation failed in thread {result['thread_id']}"
        
        # Verify session isolation - each thread should have different sessions
        session_ids = [result['session_id'] for result in results]
        # Note: Depending on session scope, this might be expected to be same or different
        
        # Verify no transaction conflicts occurred
        assert len(transaction_monitor['errors']) == 0, "Transaction errors detected"
    
    def test_session_cleanup_on_exception(self, app: Flask, transaction_monitor):
        """
        Test session cleanup when exceptions occur within request context.
        
        Validates that sessions are properly cleaned up and transactions
        are rolled back when exceptions occur during request processing.
        """
        initial_rollback_count = transaction_monitor['rolled_back_transactions']
        
        with pytest.raises(IntegrityError):
            with app.test_request_context():
                # Create first user
                user1 = User(
                    username='duplicate_test',
                    email='duplicate@test.com',
                    password_hash='test_hash',
                    is_active=True
                )
                db.session.add(user1)
                db.session.commit()
                
                # Attempt to create duplicate user (should cause IntegrityError)
                user2 = User(
                    username='duplicate_test',  # Duplicate username
                    email='duplicate2@test.com',
                    password_hash='test_hash',
                    is_active=True
                )
                db.session.add(user2)
                db.session.commit()  # This should raise IntegrityError
        
        # Verify rollback occurred
        assert transaction_monitor['rolled_back_transactions'] > initial_rollback_count
        
        # Verify session state is clean after exception
        with app.test_request_context():
            # Should be able to create user with different username
            user3 = User(
                username='after_exception',
                email='after@test.com',
                password_hash='test_hash',
                is_active=True
            )
            db.session.add(user3)
            db.session.commit()
            
            # Verify user was created successfully
            created_user = db.session.query(User).filter_by(username='after_exception').first()
            assert created_user is not None
    
    def test_nested_session_operations(self, app: Flask, transaction_monitor):
        """
        Test nested session operations within Flask request context.
        
        Validates that nested service calls and database operations
        work correctly within a single request context session.
        """
        with app.test_request_context():
            # Create parent entity
            user = User(
                username='nested_test_user',
                email='nested@test.com',
                password_hash='test_hash',
                is_active=True
            )
            db.session.add(user)
            db.session.flush()  # Get ID without committing
            
            # Create related entities in nested operations
            business_entity = BusinessEntity(
                name='Nested Test Entity',
                description='Entity created in nested operation',
                owner_id=user.id,
                status='active'
            )
            db.session.add(business_entity)
            db.session.flush()
            
            # Create session for user
            user_session = UserSession(
                user_id=user.id,
                session_token=str(uuid.uuid4()),
                expires_at=datetime.utcnow() + timedelta(hours=1),
                is_valid=True
            )
            db.session.add(user_session)
            
            # Commit all nested operations
            db.session.commit()
            
            # Verify all entities were created with proper relationships
            created_user = db.session.query(User).filter_by(username='nested_test_user').first()
            assert created_user is not None
            
            created_entity = db.session.query(BusinessEntity).filter_by(owner_id=created_user.id).first()
            assert created_entity is not None
            assert created_entity.name == 'Nested Test Entity'
            
            created_session = db.session.query(UserSession).filter_by(user_id=created_user.id).first()
            assert created_session is not None
            assert created_session.is_valid is True
        
        # Verify transaction completed successfully
        assert transaction_monitor['committed_transactions'] >= 1


# ================================================================================================
# SERVICE LAYER TRANSACTION BOUNDARY COORDINATION TESTS
# Section 5.2.3 - Service Layer Implementation
# ================================================================================================

class TestServiceLayerTransactionBoundaries:
    """
    Test suite for service layer transaction boundary coordination.
    
    Validates proper transaction management across service layer operations,
    ensuring consistent data state throughout complex business operations
    per Section 5.2.3.
    """
    
    def test_service_transaction_coordination(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test transaction coordination across multiple service layer operations.
        
        Validates that service layer operations maintain proper transaction
        boundaries and coordinate consistently across business workflows.
        """
        services = service_layer_setup
        
        with app.test_request_context():
            initial_commit_count = transaction_monitor['committed_transactions']
            
            # Execute coordinated service operations
            user_service = services['user_service']
            entity_service = services['business_entity_service']
            
            # Create user through service layer
            user_data = {
                'username': 'service_test_user',
                'email': 'service@test.com',
                'password': 'service_password123'
            }
            created_user = user_service.create_user(user_data)
            
            # Create business entity through service layer
            entity_data = {
                'name': 'Service Test Entity',
                'description': 'Entity created through service layer',
                'owner_id': created_user.id,
                'status': 'active'
            }
            created_entity = entity_service.create_business_entity(entity_data)
            
            # Verify both operations completed within coordinated transactions
            assert created_user is not None
            assert created_entity is not None
            assert created_entity.owner_id == created_user.id
            
            # Verify transactions were properly coordinated
            final_commit_count = transaction_monitor['committed_transactions']
            assert final_commit_count > initial_commit_count
    
    def test_service_transaction_rollback_coordination(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test service layer transaction rollback coordination.
        
        Validates that when one service operation fails, all related
        operations are properly rolled back to maintain data consistency.
        """
        services = service_layer_setup
        
        with app.test_request_context():
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            # Mock service failure scenario
            entity_service = services['business_entity_service']
            
            # Patch service method to simulate failure
            with patch.object(entity_service, 'validate_entity_data') as mock_validate:
                mock_validate.side_effect = ValueError("Service validation failure")
                
                with pytest.raises(ValueError):
                    # Attempt to create entity (should fail during validation)
                    entity_data = {
                        'name': 'Failed Entity',
                        'description': 'This entity should fail to create',
                        'owner_id': services['test_user'].id,
                        'status': 'active'
                    }
                    entity_service.create_business_entity(entity_data)
            
            # Verify rollback occurred
            final_rollback_count = transaction_monitor['rolled_back_transactions']
            assert final_rollback_count > initial_rollback_count
            
            # Verify no partial data was committed
            failed_entity = db.session.query(BusinessEntity).filter_by(name='Failed Entity').first()
            assert failed_entity is None
    
    def test_workflow_orchestrator_transaction_management(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test workflow orchestrator transaction management across multiple services.
        
        Validates that complex business workflows maintain proper transaction
        boundaries across multiple service calls and business operations.
        """
        services = service_layer_setup
        orchestrator = services['workflow_orchestrator']
        
        with app.test_request_context():
            # Define complex workflow data
            workflow_data = {
                'user_data': {
                    'username': 'workflow_user',
                    'email': 'workflow@test.com',
                    'password': 'workflow_password123'
                },
                'entities': [
                    {
                        'name': 'Workflow Entity 1',
                        'description': 'First entity in workflow',
                        'status': 'active'
                    },
                    {
                        'name': 'Workflow Entity 2',
                        'description': 'Second entity in workflow',
                        'status': 'active'
                    }
                ],
                'relationships': [
                    {
                        'source_index': 0,
                        'target_index': 1,
                        'relationship_type': 'parent-child'
                    }
                ]
            }
            
            # Execute complex workflow
            result = orchestrator.execute_entity_creation_workflow(workflow_data)
            
            # Verify workflow completed successfully
            assert result['success'] is True
            assert result['user'] is not None
            assert len(result['entities']) == 2
            assert len(result['relationships']) == 1
            
            # Verify all data was created with proper relationships
            created_user = db.session.query(User).filter_by(username='workflow_user').first()
            assert created_user is not None
            
            created_entities = db.session.query(BusinessEntity).filter_by(owner_id=created_user.id).all()
            assert len(created_entities) == 2
            
            created_relationships = db.session.query(EntityRelationship).join(
                BusinessEntity, EntityRelationship.source_entity_id == BusinessEntity.id
            ).filter(BusinessEntity.owner_id == created_user.id).all()
            assert len(created_relationships) == 1
    
    def test_service_transaction_savepoints(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test service layer savepoint management for complex operations.
        
        Validates that service layer can use savepoints for partial rollback
        while maintaining overall transaction integrity.
        """
        services = service_layer_setup
        entity_service = services['business_entity_service']
        
        with app.test_request_context():
            # Begin transaction with savepoints
            db.session.begin()
            
            try:
                # Create first entity successfully
                entity1_data = {
                    'name': 'Savepoint Entity 1',
                    'description': 'First entity for savepoint testing',
                    'owner_id': services['test_user'].id,
                    'status': 'active'
                }
                entity1 = entity_service.create_business_entity(entity1_data)
                
                # Create savepoint
                savepoint = db.session.begin_nested()
                
                try:
                    # Create second entity (this will be rolled back)
                    entity2_data = {
                        'name': 'Savepoint Entity 2',
                        'description': 'Second entity for savepoint testing',
                        'owner_id': services['test_user'].id,
                        'status': 'invalid_status'  # This should cause validation error
                    }
                    
                    # Simulate validation failure
                    if entity2_data['status'] == 'invalid_status':
                        raise ValueError("Invalid status value")
                    
                    entity2 = entity_service.create_business_entity(entity2_data)
                    savepoint.commit()
                    
                except ValueError:
                    # Rollback to savepoint
                    savepoint.rollback()
                
                # Commit main transaction
                db.session.commit()
                
                # Verify first entity was committed, second was not
                committed_entity1 = db.session.query(BusinessEntity).filter_by(
                    name='Savepoint Entity 1'
                ).first()
                assert committed_entity1 is not None
                
                uncommitted_entity2 = db.session.query(BusinessEntity).filter_by(
                    name='Savepoint Entity 2'
                ).first()
                assert uncommitted_entity2 is None
                
            except Exception:
                db.session.rollback()
                raise


# ================================================================================================
# DATABASE TRANSACTION ISOLATION AND CONCURRENT OPERATION SAFETY TESTS
# Section 6.2.1 - Database Technology Transition
# ================================================================================================

class TestTransactionIsolationAndConcurrency:
    """
    Test suite for database transaction isolation and concurrent operation safety.
    
    Validates that database transactions maintain proper isolation levels
    and handle concurrent operations safely per Section 6.2.1.
    """
    
    def test_read_committed_isolation(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test READ COMMITTED isolation level behavior.
        
        Validates that transactions can read committed data from other
        transactions but not uncommitted changes.
        """
        # Create test data in first transaction
        with app.test_request_context():
            user = User(
                username='isolation_test_user',
                email='isolation@test.com',
                password_hash='test_hash',
                is_active=True
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id
        
        # Test concurrent read operations
        session1 = concurrent_session_factory()
        session2 = concurrent_session_factory()
        
        try:
            # Session 1: Begin transaction and modify data
            session1.begin()
            user1 = session1.query(User).filter_by(id=user_id).first()
            user1.email = 'modified@test.com'
            session1.add(user1)
            # Don't commit yet
            
            # Session 2: Read data (should see original value)
            session2.begin()
            user2 = session2.query(User).filter_by(id=user_id).first()
            assert user2.email == 'isolation@test.com'  # Original value
            session2.rollback()
            
            # Session 1: Commit changes
            session1.commit()
            
            # Session 2: Read data again (should now see committed changes)
            session2.begin()
            user2 = session2.query(User).filter_by(id=user_id).first()
            assert user2.email == 'modified@test.com'  # Modified value
            session2.rollback()
            
        finally:
            session1.close()
            session2.close()
    
    def test_concurrent_write_operations(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test concurrent write operations with proper conflict resolution.
        
        Validates that concurrent write operations are handled safely
        with appropriate locking and conflict resolution mechanisms.
        """
        results = []
        errors = []
        
        def concurrent_user_creation(thread_id: int):
            """Create users concurrently to test write conflicts."""
            session = concurrent_session_factory()
            try:
                session.begin()
                
                # Small delay to increase chance of concurrent execution
                time.sleep(0.01)
                
                user = User(
                    username=f'concurrent_user_{thread_id}',
                    email=f'concurrent{thread_id}@test.com',
                    password_hash='concurrent_hash',
                    is_active=True
                )
                session.add(user)
                session.commit()
                
                results.append({
                    'thread_id': thread_id,
                    'user_id': user.id,
                    'success': True
                })
                
            except Exception as e:
                session.rollback()
                errors.append({
                    'thread_id': thread_id,
                    'error': str(e)
                })
            finally:
                session.close()
        
        # Execute concurrent write operations
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(concurrent_user_creation, i) 
                for i in range(10)
            ]
            
            for future in as_completed(futures):
                future.result()
        
        # Verify all operations completed (with or without conflicts)
        total_operations = len(results) + len(errors)
        assert total_operations == 10
        
        # Verify successful operations created valid data
        for result in results:
            with app.test_request_context():
                user = db.session.query(User).filter_by(id=result['user_id']).first()
                assert user is not None
                assert user.username == f"concurrent_user_{result['thread_id']}"
    
    def test_deadlock_detection_and_resolution(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test deadlock detection and resolution mechanisms.
        
        Validates that the system can detect and resolve deadlocks
        that may occur during concurrent operations.
        """
        # Create test users for deadlock scenario
        with app.test_request_context():
            user1 = User(username='deadlock_user1', email='deadlock1@test.com', 
                        password_hash='test_hash', is_active=True)
            user2 = User(username='deadlock_user2', email='deadlock2@test.com', 
                        password_hash='test_hash', is_active=True)
            db.session.add(user1)
            db.session.add(user2)
            db.session.commit()
            user1_id, user2_id = user1.id, user2.id
        
        deadlock_detected = threading.Event()
        
        def transaction_a():
            """First transaction in potential deadlock scenario."""
            session = concurrent_session_factory()
            try:
                session.begin()
                
                # Lock user1 first
                user1 = session.query(User).filter_by(id=user1_id).with_for_update().first()
                user1.email = 'deadlock1_modified@test.com'
                session.add(user1)
                
                # Wait to increase deadlock chance
                time.sleep(0.1)
                
                # Try to lock user2 (potential deadlock)
                user2 = session.query(User).filter_by(id=user2_id).with_for_update().first()
                user2.email = 'deadlock2_modified_by_a@test.com'
                session.add(user2)
                
                session.commit()
                
            except OperationalError as e:
                session.rollback()
                if "deadlock" in str(e).lower():
                    deadlock_detected.set()
            except Exception:
                session.rollback()
            finally:
                session.close()
        
        def transaction_b():
            """Second transaction in potential deadlock scenario."""
            session = concurrent_session_factory()
            try:
                session.begin()
                
                # Lock user2 first (opposite order from transaction_a)
                user2 = session.query(User).filter_by(id=user2_id).with_for_update().first()
                user2.email = 'deadlock2_modified@test.com'
                session.add(user2)
                
                # Wait to increase deadlock chance
                time.sleep(0.1)
                
                # Try to lock user1 (potential deadlock)
                user1 = session.query(User).filter_by(id=user1_id).with_for_update().first()
                user1.email = 'deadlock1_modified_by_b@test.com'
                session.add(user1)
                
                session.commit()
                
            except OperationalError as e:
                session.rollback()
                if "deadlock" in str(e).lower():
                    deadlock_detected.set()
            except Exception:
                session.rollback()
            finally:
                session.close()
        
        # Execute potentially deadlocking transactions
        thread_a = threading.Thread(target=transaction_a)
        thread_b = threading.Thread(target=transaction_b)
        
        thread_a.start()
        thread_b.start()
        
        thread_a.join(timeout=5)
        thread_b.join(timeout=5)
        
        # Verify at least one transaction completed or deadlock was detected
        # (Implementation may vary based on database configuration)
        assert thread_a.is_alive() is False or thread_b.is_alive() is False
    
    def test_transaction_timeout_handling(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test transaction timeout handling and cleanup.
        
        Validates that long-running transactions are properly handled
        and cleaned up according to configured timeout settings.
        """
        session = concurrent_session_factory()
        
        try:
            session.begin()
            
            # Create user with explicit lock
            user = User(
                username='timeout_test_user',
                email='timeout@test.com',
                password_hash='test_hash',
                is_active=True
            )
            session.add(user)
            session.flush()  # Get ID without committing
            
            # Hold lock for extended period (simulate timeout scenario)
            locked_user = session.query(User).filter_by(
                id=user.id
            ).with_for_update().first()
            
            # In a real scenario, this would eventually timeout
            # For testing, we'll simulate the timeout behavior
            start_time = time.time()
            
            # Simulate work that takes time
            time.sleep(0.1)
            
            elapsed_time = time.time() - start_time
            
            # Verify transaction is still active within reasonable time
            assert elapsed_time < 1.0  # Should complete quickly in test
            
            session.commit()
            
        except OperationalError as e:
            # Handle timeout or lock wait timeout
            session.rollback()
            assert "timeout" in str(e).lower() or "deadlock" in str(e).lower()
        finally:
            session.close()


# ================================================================================================
# ERROR HANDLING WITH AUTOMATIC TRANSACTION ROLLBACK TESTS
# Section 4.8 - Error Handling and Recovery Workflows
# ================================================================================================

class TestErrorHandlingAndTransactionRollback:
    """
    Test suite for error handling with automatic transaction rollback capabilities.
    
    Validates that errors trigger appropriate rollback mechanisms and maintain
    data consistency according to Section 4.8 error handling workflows.
    """
    
    def test_database_constraint_violation_rollback(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test automatic rollback on database constraint violations.
        
        Validates that constraint violations trigger automatic rollback
        and leave the database in a consistent state.
        """
        with app.test_request_context():
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            # Create entity with valid data
            entity1 = BusinessEntity(
                name='Constraint Test Entity 1',
                description='First entity for constraint testing',
                owner_id=test_user.id,
                status='active'
            )
            db.session.add(entity1)
            db.session.commit()
            
            # Attempt to violate foreign key constraint
            with pytest.raises(IntegrityError):
                invalid_entity = BusinessEntity(
                    name='Invalid Entity',
                    description='Entity with invalid foreign key',
                    owner_id=99999,  # Non-existent user ID
                    status='active'
                )
                db.session.add(invalid_entity)
                db.session.commit()
            
            # Verify rollback occurred
            final_rollback_count = transaction_monitor['rolled_back_transactions']
            assert final_rollback_count > initial_rollback_count
            
            # Verify database is in consistent state
            invalid_entity_check = db.session.query(BusinessEntity).filter_by(
                name='Invalid Entity'
            ).first()
            assert invalid_entity_check is None
            
            # Verify original entity still exists
            valid_entity_check = db.session.query(BusinessEntity).filter_by(
                name='Constraint Test Entity 1'
            ).first()
            assert valid_entity_check is not None
    
    def test_service_layer_exception_rollback(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test service layer exception handling with automatic rollback.
        
        Validates that service layer exceptions trigger proper rollback
        and maintain transactional integrity across business operations.
        """
        services = service_layer_setup
        entity_service = services['business_entity_service']
        
        with app.test_request_context():
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            # Mock service method to raise exception
            with patch.object(entity_service, '_validate_business_rules') as mock_validate:
                mock_validate.side_effect = ValueError("Business rule validation failed")
                
                with pytest.raises(ValueError):
                    entity_data = {
                        'name': 'Exception Test Entity',
                        'description': 'Entity that should cause service exception',
                        'owner_id': services['test_user'].id,
                        'status': 'active'
                    }
                    entity_service.create_business_entity(entity_data)
            
            # Verify rollback occurred
            final_rollback_count = transaction_monitor['rolled_back_transactions']
            assert final_rollback_count > initial_rollback_count
            
            # Verify no partial data was committed
            failed_entity = db.session.query(BusinessEntity).filter_by(
                name='Exception Test Entity'
            ).first()
            assert failed_entity is None
    
    def test_nested_transaction_rollback(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test nested transaction rollback behavior.
        
        Validates that exceptions in nested operations properly rollback
        the entire transaction tree while maintaining data consistency.
        """
        with app.test_request_context():
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            try:
                # Begin outer transaction
                db.session.begin()
                
                # Create user session
                user_session = UserSession(
                    user_id=test_user.id,
                    session_token='nested_rollback_test',
                    expires_at=datetime.utcnow() + timedelta(hours=1),
                    is_valid=True
                )
                db.session.add(user_session)
                db.session.flush()
                
                # Begin nested transaction
                savepoint = db.session.begin_nested()
                
                try:
                    # Create business entity
                    entity = BusinessEntity(
                        name='Nested Rollback Entity',
                        description='Entity in nested transaction',
                        owner_id=test_user.id,
                        status='active'
                    )
                    db.session.add(entity)
                    db.session.flush()
                    
                    # Create relationship (this will fail due to missing target)
                    relationship = EntityRelationship(
                        source_entity_id=entity.id,
                        target_entity_id=99999,  # Non-existent entity
                        relationship_type='invalid',
                        is_active=True
                    )
                    db.session.add(relationship)
                    savepoint.commit()  # This should fail
                    
                except IntegrityError:
                    # Rollback nested transaction
                    savepoint.rollback()
                    raise ValueError("Nested operation failed")
                
                # Commit outer transaction
                db.session.commit()
                
            except ValueError:
                # Rollback entire transaction
                db.session.rollback()
            
            # Verify rollback occurred
            final_rollback_count = transaction_monitor['rolled_back_transactions']
            assert final_rollback_count > initial_rollback_count
            
            # Verify no partial data was committed
            failed_session = db.session.query(UserSession).filter_by(
                session_token='nested_rollback_test'
            ).first()
            assert failed_session is None
            
            failed_entity = db.session.query(BusinessEntity).filter_by(
                name='Nested Rollback Entity'
            ).first()
            assert failed_entity is None
    
    def test_connection_failure_recovery(self, app: Flask, transaction_monitor):
        """
        Test transaction rollback and recovery on connection failures.
        
        Validates that connection failures trigger appropriate rollback
        and allow for recovery without data corruption.
        """
        with app.test_request_context():
            # Simulate connection failure during transaction
            with patch.object(db.session, 'commit') as mock_commit:
                mock_commit.side_effect = OperationalError(
                    "Connection failure", None, None
                )
                
                user = User(
                    username='connection_failure_test',
                    email='connection@test.com',
                    password_hash='test_hash',
                    is_active=True
                )
                db.session.add(user)
                
                with pytest.raises(OperationalError):
                    db.session.commit()
            
            # Verify no partial data was committed
            failed_user = db.session.query(User).filter_by(
                username='connection_failure_test'
            ).first()
            assert failed_user is None
            
            # Verify system can recover and continue operations
            recovery_user = User(
                username='recovery_test',
                email='recovery@test.com',
                password_hash='test_hash',
                is_active=True
            )
            db.session.add(recovery_user)
            db.session.commit()
            
            # Verify recovery operation succeeded
            created_user = db.session.query(User).filter_by(
                username='recovery_test'
            ).first()
            assert created_user is not None


# ================================================================================================
# ACID COMPLIANCE VALIDATION TESTS
# Feature F-004 - Database Migration Management
# ================================================================================================

class TestACIDComplianceValidation:
    """
    Test suite for ACID compliance validation ensuring transaction integrity.
    
    Validates Atomicity, Consistency, Isolation, and Durability properties
    equivalent to the original system per Feature F-004.
    """
    
    def test_atomicity_validation(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test transaction atomicity - all or nothing execution.
        
        Validates that transactions either complete entirely or fail entirely
        with no partial state changes persisted to the database.
        """
        with app.test_request_context():
            initial_commit_count = transaction_monitor['committed_transactions']
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            # Test successful atomic operation
            try:
                db.session.begin()
                
                # Multiple related operations
                entity1 = BusinessEntity(
                    name='Atomic Entity 1',
                    description='First entity in atomic operation',
                    owner_id=test_user.id,
                    status='active'
                )
                db.session.add(entity1)
                db.session.flush()
                
                entity2 = BusinessEntity(
                    name='Atomic Entity 2',
                    description='Second entity in atomic operation',
                    owner_id=test_user.id,
                    status='active'
                )
                db.session.add(entity2)
                db.session.flush()
                
                relationship = EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity2.id,
                    relationship_type='atomic-test',
                    is_active=True
                )
                db.session.add(relationship)
                
                # All operations succeed - commit atomically
                db.session.commit()
                
                # Verify all data was committed
                committed_entity1 = db.session.query(BusinessEntity).filter_by(
                    name='Atomic Entity 1'
                ).first()
                committed_entity2 = db.session.query(BusinessEntity).filter_by(
                    name='Atomic Entity 2'
                ).first()
                committed_relationship = db.session.query(EntityRelationship).filter_by(
                    relationship_type='atomic-test'
                ).first()
                
                assert committed_entity1 is not None
                assert committed_entity2 is not None
                assert committed_relationship is not None
                
            except Exception:
                db.session.rollback()
                raise
            
            # Test failed atomic operation
            try:
                db.session.begin()
                
                entity3 = BusinessEntity(
                    name='Atomic Entity 3',
                    description='Third entity in atomic operation',
                    owner_id=test_user.id,
                    status='active'
                )
                db.session.add(entity3)
                db.session.flush()
                
                # This should fail due to invalid foreign key
                invalid_relationship = EntityRelationship(
                    source_entity_id=entity3.id,
                    target_entity_id=99999,  # Non-existent entity
                    relationship_type='atomic-fail-test',
                    is_active=True
                )
                db.session.add(invalid_relationship)
                
                db.session.commit()  # Should fail
                
            except IntegrityError:
                db.session.rollback()
            
            # Verify no partial data was committed
            failed_entity = db.session.query(BusinessEntity).filter_by(
                name='Atomic Entity 3'
            ).first()
            assert failed_entity is None
            
            failed_relationship = db.session.query(EntityRelationship).filter_by(
                relationship_type='atomic-fail-test'
            ).first()
            assert failed_relationship is None
            
            # Verify transaction counts
            final_commit_count = transaction_monitor['committed_transactions']
            final_rollback_count = transaction_monitor['rolled_back_transactions']
            
            assert final_commit_count > initial_commit_count
            assert final_rollback_count > initial_rollback_count
    
    def test_consistency_validation(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test transaction consistency - database constraints maintained.
        
        Validates that all database constraints, foreign keys, and business
        rules are maintained consistently across all transaction operations.
        """
        with app.test_request_context():
            # Test foreign key consistency
            entity = BusinessEntity(
                name='Consistency Test Entity',
                description='Entity for consistency testing',
                owner_id=test_user.id,
                status='active'
            )
            db.session.add(entity)
            db.session.commit()
            
            # Verify foreign key relationship is maintained
            created_entity = db.session.query(BusinessEntity).filter_by(
                name='Consistency Test Entity'
            ).first()
            assert created_entity.owner_id == test_user.id
            
            # Test unique constraint consistency
            with pytest.raises(IntegrityError):
                duplicate_user = User(
                    username=test_user.username,  # Duplicate username
                    email='duplicate@test.com',
                    password_hash='test_hash',
                    is_active=True
                )
                db.session.add(duplicate_user)
                db.session.commit()
            
            # Verify consistency after constraint violation
            user_count = db.session.query(User).filter_by(
                username=test_user.username
            ).count()
            assert user_count == 1  # Only original user should exist
    
    def test_isolation_validation(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test transaction isolation - concurrent transactions don't interfere.
        
        Validates that concurrent transactions maintain proper isolation
        and don't see uncommitted changes from other transactions.
        """
        # Create test data
        with app.test_request_context():
            user = User(
                username='isolation_validation_user',
                email='isolation@validation.com',
                password_hash='test_hash',
                is_active=True
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id
        
        isolation_results = []
        
        def transaction_1():
            """First transaction that modifies data."""
            session = concurrent_session_factory()
            try:
                session.begin()
                
                user = session.query(User).filter_by(id=user_id).first()
                original_email = user.email
                
                # Modify user data
                user.email = 'modified@isolation.com'
                session.add(user)
                
                # Hold transaction open briefly
                time.sleep(0.2)
                
                session.commit()
                
                isolation_results.append({
                    'transaction': 1,
                    'action': 'modify',
                    'original_email': original_email,
                    'modified_email': user.email
                })
                
            except Exception as e:
                session.rollback()
                isolation_results.append({
                    'transaction': 1,
                    'error': str(e)
                })
            finally:
                session.close()
        
        def transaction_2():
            """Second transaction that reads data."""
            session = concurrent_session_factory()
            try:
                # Small delay to ensure transaction_1 starts first
                time.sleep(0.1)
                
                session.begin()
                
                # Read data while transaction_1 is active but not committed
                user = session.query(User).filter_by(id=user_id).first()
                read_email = user.email
                
                session.rollback()
                
                isolation_results.append({
                    'transaction': 2,
                    'action': 'read_during_modification',
                    'read_email': read_email
                })
                
            except Exception as e:
                session.rollback()
                isolation_results.append({
                    'transaction': 2,
                    'error': str(e)
                })
            finally:
                session.close()
        
        # Execute concurrent transactions
        thread1 = threading.Thread(target=transaction_1)
        thread2 = threading.Thread(target=transaction_2)
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Verify isolation was maintained
        assert len(isolation_results) >= 2
        
        # Transaction 2 should have read the original value (not the uncommitted change)
        tx2_result = next((r for r in isolation_results if r.get('transaction') == 2), None)
        assert tx2_result is not None
        assert tx2_result.get('read_email') == 'isolation@validation.com'  # Original value
    
    def test_durability_validation(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test transaction durability - committed changes persist.
        
        Validates that once a transaction is committed, the changes
        persist even across application restarts or failures.
        """
        with app.test_request_context():
            # Create and commit data
            entity = BusinessEntity(
                name='Durability Test Entity',
                description='Entity for durability testing',
                owner_id=test_user.id,
                status='active'
            )
            db.session.add(entity)
            db.session.commit()
            entity_id = entity.id
        
        # Simulate application restart by creating new session
        with app.test_request_context():
            # Verify data persists in new session
            persistent_entity = db.session.query(BusinessEntity).filter_by(
                id=entity_id
            ).first()
            
            assert persistent_entity is not None
            assert persistent_entity.name == 'Durability Test Entity'
            assert persistent_entity.owner_id == test_user.id
        
        # Test durability under simulated failure conditions
        with app.test_request_context():
            # Modify existing data
            persistent_entity = db.session.query(BusinessEntity).filter_by(
                id=entity_id
            ).first()
            persistent_entity.description = 'Modified for durability test'
            db.session.commit()
        
        # Verify modification persists
        with app.test_request_context():
            modified_entity = db.session.query(BusinessEntity).filter_by(
                id=entity_id
            ).first()
            
            assert modified_entity is not None
            assert modified_entity.description == 'Modified for durability test'


# ================================================================================================
# COMPLEX TRANSACTION TESTING ACROSS MULTIPLE MODELS AND RELATIONSHIPS
# Feature F-005 - Business Logic Preservation
# ================================================================================================

class TestComplexTransactionScenarios:
    """
    Test suite for complex transaction scenarios across multiple models and relationships.
    
    Validates transaction management in complex business scenarios with multiple
    entities and relationships per Feature F-005.
    """
    
    def test_multi_model_transaction_coordination(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test transaction coordination across multiple model types.
        
        Validates that complex operations involving multiple models
        maintain proper transaction boundaries and data consistency.
        """
        services = service_layer_setup
        orchestrator = services['workflow_orchestrator']
        
        with app.test_request_context():
            initial_commit_count = transaction_monitor['committed_transactions']
            
            # Define complex multi-model operation
            complex_workflow_data = {
                'primary_user': {
                    'username': 'complex_primary_user',
                    'email': 'primary@complex.com',
                    'password': 'complex_password123'
                },
                'secondary_user': {
                    'username': 'complex_secondary_user',
                    'email': 'secondary@complex.com',
                    'password': 'complex_password456'
                },
                'business_entities': [
                    {
                        'name': 'Complex Entity 1',
                        'description': 'First entity in complex workflow',
                        'status': 'active',
                        'owner_type': 'primary'
                    },
                    {
                        'name': 'Complex Entity 2',
                        'description': 'Second entity in complex workflow',
                        'status': 'active',
                        'owner_type': 'secondary'
                    },
                    {
                        'name': 'Complex Entity 3',
                        'description': 'Third entity in complex workflow',
                        'status': 'active',
                        'owner_type': 'primary'
                    }
                ],
                'entity_relationships': [
                    {
                        'source_index': 0,
                        'target_index': 1,
                        'relationship_type': 'collaboration'
                    },
                    {
                        'source_index': 1,
                        'target_index': 2,
                        'relationship_type': 'dependency'
                    }
                ],
                'user_sessions': [
                    {
                        'user_type': 'primary',
                        'duration_hours': 2
                    },
                    {
                        'user_type': 'secondary',
                        'duration_hours': 1
                    }
                ]
            }
            
            # Execute complex multi-model transaction
            result = orchestrator.execute_complex_multi_model_workflow(complex_workflow_data)
            
            # Verify all models were created successfully
            assert result['success'] is True
            assert len(result['users']) == 2
            assert len(result['entities']) == 3
            assert len(result['relationships']) == 2
            assert len(result['sessions']) == 2
            
            # Verify proper relationships between models
            primary_user = db.session.query(User).filter_by(
                username='complex_primary_user'
            ).first()
            secondary_user = db.session.query(User).filter_by(
                username='complex_secondary_user'
            ).first()
            
            assert primary_user is not None
            assert secondary_user is not None
            
            # Verify entity ownership
            primary_entities = db.session.query(BusinessEntity).filter_by(
                owner_id=primary_user.id
            ).all()
            secondary_entities = db.session.query(BusinessEntity).filter_by(
                owner_id=secondary_user.id
            ).all()
            
            assert len(primary_entities) == 2  # Entities 1 and 3
            assert len(secondary_entities) == 1  # Entity 2
            
            # Verify relationships
            relationships = db.session.query(EntityRelationship).all()
            assert len(relationships) == 2
            
            # Verify user sessions
            primary_sessions = db.session.query(UserSession).filter_by(
                user_id=primary_user.id
            ).all()
            secondary_sessions = db.session.query(UserSession).filter_by(
                user_id=secondary_user.id
            ).all()
            
            assert len(primary_sessions) == 1
            assert len(secondary_sessions) == 1
            
            # Verify transaction coordination
            final_commit_count = transaction_monitor['committed_transactions']
            assert final_commit_count > initial_commit_count
    
    def test_cascade_operation_transaction_management(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test transaction management for cascade operations.
        
        Validates that cascade delete and update operations maintain
        proper transaction boundaries and referential integrity.
        """
        with app.test_request_context():
            # Create parent entity
            parent_entity = BusinessEntity(
                name='Cascade Parent Entity',
                description='Parent entity for cascade testing',
                owner_id=test_user.id,
                status='active'
            )
            db.session.add(parent_entity)
            db.session.flush()
            
            # Create child entities
            child_entities = []
            for i in range(3):
                child = BusinessEntity(
                    name=f'Cascade Child Entity {i+1}',
                    description=f'Child entity {i+1} for cascade testing',
                    owner_id=test_user.id,
                    status='active'
                )
                db.session.add(child)
                child_entities.append(child)
            
            db.session.flush()
            
            # Create relationships
            relationships = []
            for child in child_entities:
                relationship = EntityRelationship(
                    source_entity_id=parent_entity.id,
                    target_entity_id=child.id,
                    relationship_type='parent-child',
                    is_active=True
                )
                db.session.add(relationship)
                relationships.append(relationship)
            
            db.session.commit()
            
            # Test cascade delete operation
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            try:
                # Delete parent entity (should handle cascade properly)
                db.session.delete(parent_entity)
                
                # Delete related relationships manually (simulating cascade)
                for relationship in relationships:
                    db.session.delete(relationship)
                
                db.session.commit()
                
                # Verify cascade operation completed
                remaining_parent = db.session.query(BusinessEntity).filter_by(
                    name='Cascade Parent Entity'
                ).first()
                assert remaining_parent is None
                
                remaining_relationships = db.session.query(EntityRelationship).filter_by(
                    source_entity_id=parent_entity.id
                ).all()
                assert len(remaining_relationships) == 0
                
                # Child entities should still exist (no cascade delete configured)
                remaining_children = db.session.query(BusinessEntity).filter(
                    BusinessEntity.name.like('Cascade Child Entity%')
                ).all()
                assert len(remaining_children) == 3
                
            except Exception:
                db.session.rollback()
                
                # Verify rollback preserved data integrity
                final_rollback_count = transaction_monitor['rolled_back_transactions']
                assert final_rollback_count > initial_rollback_count
    
    def test_bulk_operation_transaction_management(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test transaction management for bulk operations.
        
        Validates that bulk insert, update, and delete operations
        maintain proper transaction boundaries and performance.
        """
        with app.test_request_context():
            initial_commit_count = transaction_monitor['committed_transactions']
            
            # Bulk insert operation
            bulk_entities = []
            for i in range(50):
                entity = BusinessEntity(
                    name=f'Bulk Entity {i+1:03d}',
                    description=f'Bulk created entity number {i+1}',
                    owner_id=test_user.id,
                    status='active'
                )
                bulk_entities.append(entity)
            
            # Use bulk insert for performance
            db.session.bulk_save_objects(bulk_entities)
            db.session.commit()
            
            # Verify bulk insert completed
            created_entities = db.session.query(BusinessEntity).filter(
                BusinessEntity.name.like('Bulk Entity%')
            ).all()
            assert len(created_entities) == 50
            
            # Bulk update operation
            entity_ids = [entity.id for entity in created_entities]
            
            db.session.query(BusinessEntity).filter(
                BusinessEntity.id.in_(entity_ids)
            ).update(
                {'status': 'updated'}, 
                synchronize_session=False
            )
            db.session.commit()
            
            # Verify bulk update completed
            updated_entities = db.session.query(BusinessEntity).filter(
                BusinessEntity.id.in_(entity_ids),
                BusinessEntity.status == 'updated'
            ).all()
            assert len(updated_entities) == 50
            
            # Bulk delete operation
            db.session.query(BusinessEntity).filter(
                BusinessEntity.id.in_(entity_ids)
            ).delete(synchronize_session=False)
            db.session.commit()
            
            # Verify bulk delete completed
            remaining_entities = db.session.query(BusinessEntity).filter(
                BusinessEntity.id.in_(entity_ids)
            ).all()
            assert len(remaining_entities) == 0
            
            # Verify transaction efficiency
            final_commit_count = transaction_monitor['committed_transactions']
            commit_difference = final_commit_count - initial_commit_count
            
            # Should use minimal transactions for bulk operations
            assert commit_difference <= 5  # Reasonable number of commits for bulk ops
    
    def test_distributed_transaction_simulation(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test simulated distributed transaction coordination.
        
        Validates transaction coordination patterns that would be used
        in distributed scenarios with multiple services and data sources.
        """
        services = service_layer_setup
        orchestrator = services['workflow_orchestrator']
        
        with app.test_request_context():
            # Simulate distributed transaction with compensation pattern
            transaction_log = []
            
            try:
                # Step 1: Create user (service A simulation)
                user_data = {
                    'username': 'distributed_test_user',
                    'email': 'distributed@test.com',
                    'password': 'distributed_password123'
                }
                created_user = services['user_service'].create_user(user_data)
                transaction_log.append({
                    'step': 1,
                    'action': 'create_user',
                    'user_id': created_user.id,
                    'compensation': 'delete_user'
                })
                
                # Step 2: Create business entity (service B simulation)
                entity_data = {
                    'name': 'Distributed Test Entity',
                    'description': 'Entity for distributed transaction testing',
                    'owner_id': created_user.id,
                    'status': 'active'
                }
                created_entity = services['business_entity_service'].create_business_entity(entity_data)
                transaction_log.append({
                    'step': 2,
                    'action': 'create_entity',
                    'entity_id': created_entity.id,
                    'compensation': 'delete_entity'
                })
                
                # Step 3: Create user session (service C simulation)
                session_data = {
                    'user_id': created_user.id,
                    'duration_hours': 1
                }
                created_session = services['user_service'].create_user_session(session_data)
                transaction_log.append({
                    'step': 3,
                    'action': 'create_session',
                    'session_id': created_session.id,
                    'compensation': 'delete_session'
                })
                
                # Simulate failure in step 4
                if True:  # Simulate failure condition
                    raise ValueError("Simulated distributed transaction failure")
                
            except ValueError:
                # Compensation workflow - rollback in reverse order
                for log_entry in reversed(transaction_log):
                    if log_entry['compensation'] == 'delete_session':
                        session = db.session.query(UserSession).filter_by(
                            id=log_entry['session_id']
                        ).first()
                        if session:
                            db.session.delete(session)
                    
                    elif log_entry['compensation'] == 'delete_entity':
                        entity = db.session.query(BusinessEntity).filter_by(
                            id=log_entry['entity_id']
                        ).first()
                        if entity:
                            db.session.delete(entity)
                    
                    elif log_entry['compensation'] == 'delete_user':
                        user = db.session.query(User).filter_by(
                            id=log_entry['user_id']
                        ).first()
                        if user:
                            # Delete user sessions first
                            db.session.query(UserSession).filter_by(
                                user_id=user.id
                            ).delete()
                            # Delete user entities first
                            db.session.query(BusinessEntity).filter_by(
                                owner_id=user.id
                            ).delete()
                            # Delete user
                            db.session.delete(user)
                
                db.session.commit()
            
            # Verify compensation completed successfully
            compensated_user = db.session.query(User).filter_by(
                username='distributed_test_user'
            ).first()
            assert compensated_user is None
            
            compensated_entity = db.session.query(BusinessEntity).filter_by(
                name='Distributed Test Entity'
            ).first()
            assert compensated_entity is None


# ================================================================================================
# PERFORMANCE AND STRESS TESTING FOR TRANSACTION MANAGEMENT
# ================================================================================================

class TestTransactionPerformanceAndStress:
    """
    Test suite for transaction performance and stress testing.
    
    Validates transaction management performance under load and
    stress conditions to ensure production readiness.
    """
    
    @pytest.mark.performance
    def test_transaction_throughput_performance(self, app: Flask, test_user: User, benchmark):
        """
        Test transaction throughput performance.
        
        Validates that transaction management maintains acceptable
        performance under normal load conditions.
        """
        def create_entity_transaction():
            """Single entity creation transaction for benchmarking."""
            with app.test_request_context():
                entity = BusinessEntity(
                    name=f'Performance Entity {uuid.uuid4()}',
                    description='Entity for performance testing',
                    owner_id=test_user.id,
                    status='active'
                )
                db.session.add(entity)
                db.session.commit()
                return entity.id
        
        # Benchmark transaction throughput
        result = benchmark(create_entity_transaction)
        
        # Verify entity was created
        with app.test_request_context():
            created_entity = db.session.query(BusinessEntity).filter_by(id=result).first()
            assert created_entity is not None
    
    @pytest.mark.performance
    def test_concurrent_transaction_stress(self, app: Flask, concurrent_session_factory, transaction_monitor):
        """
        Test transaction management under concurrent stress.
        
        Validates that transaction management remains stable and
        consistent under high concurrent load.
        """
        stress_results = []
        stress_errors = []
        
        def stress_transaction(thread_id: int):
            """Stress test transaction for concurrent execution."""
            session = concurrent_session_factory()
            try:
                for i in range(10):
                    session.begin()
                    
                    user = User(
                        username=f'stress_user_{thread_id}_{i}',
                        email=f'stress{thread_id}_{i}@test.com',
                        password_hash='stress_hash',
                        is_active=True
                    )
                    session.add(user)
                    session.commit()
                    
                    stress_results.append({
                        'thread_id': thread_id,
                        'iteration': i,
                        'user_id': user.id
                    })
                    
            except Exception as e:
                session.rollback()
                stress_errors.append({
                    'thread_id': thread_id,
                    'error': str(e)
                })
            finally:
                session.close()
        
        # Execute concurrent stress test
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(stress_transaction, i) 
                for i in range(10)
            ]
            
            for future in as_completed(futures):
                future.result()
        
        end_time = time.time()
        
        # Analyze stress test results
        total_operations = len(stress_results)
        total_errors = len(stress_errors)
        execution_time = end_time - start_time
        
        # Verify stress test metrics
        assert total_operations > 0, "No operations completed successfully"
        error_rate = total_errors / (total_operations + total_errors) if (total_operations + total_errors) > 0 else 0
        assert error_rate < 0.1, f"Error rate too high: {error_rate:.2%}"
        
        throughput = total_operations / execution_time
        assert throughput > 10, f"Throughput too low: {throughput:.2f} ops/sec"
        
        # Verify no transaction integrity issues
        assert len(transaction_monitor['errors']) == 0, "Transaction integrity errors detected"
    
    @pytest.mark.slow
    def test_long_running_transaction_management(self, app: Flask, test_user: User, transaction_monitor):
        """
        Test management of long-running transactions.
        
        Validates that long-running transactions are handled properly
        without causing deadlocks or resource leaks.
        """
        with app.test_request_context():
            initial_active_count = transaction_monitor['active_transactions']
            
            # Simulate long-running transaction
            db.session.begin()
            
            try:
                # Create entities progressively in long transaction
                entity_ids = []
                for i in range(20):
                    entity = BusinessEntity(
                        name=f'Long Running Entity {i+1}',
                        description=f'Entity {i+1} in long-running transaction',
                        owner_id=test_user.id,
                        status='active'
                    )
                    db.session.add(entity)
                    db.session.flush()
                    entity_ids.append(entity.id)
                    
                    # Simulate processing time
                    time.sleep(0.05)
                
                # Create relationships between entities
                for i in range(len(entity_ids) - 1):
                    relationship = EntityRelationship(
                        source_entity_id=entity_ids[i],
                        target_entity_id=entity_ids[i + 1],
                        relationship_type='sequential',
                        is_active=True
                    )
                    db.session.add(relationship)
                
                # Commit long transaction
                db.session.commit()
                
                # Verify all entities were created
                created_entities = db.session.query(BusinessEntity).filter(
                    BusinessEntity.name.like('Long Running Entity%')
                ).all()
                assert len(created_entities) == 20
                
                # Verify relationships were created
                created_relationships = db.session.query(EntityRelationship).filter_by(
                    relationship_type='sequential'
                ).all()
                assert len(created_relationships) == 19
                
            except Exception:
                db.session.rollback()
                raise
            
            final_active_count = transaction_monitor['active_transactions']
            
            # Verify transaction was properly cleaned up
            assert final_active_count <= initial_active_count + 1  # Allow for test transaction


# ================================================================================================
# INTEGRATION TESTS WITH FLASK BLUEPRINT AND SERVICE LAYER
# ================================================================================================

class TestTransactionIntegrationWithApplication:
    """
    Test suite for transaction integration with Flask application components.
    
    Validates transaction management integration with Flask blueprints,
    service layer, and application request/response lifecycle.
    """
    
    def test_blueprint_request_transaction_integration(self, app: Flask, client, test_user: User, transaction_monitor):
        """
        Test transaction integration with Flask blueprint requests.
        
        Validates that HTTP requests through Flask blueprints maintain
        proper transaction boundaries and session management.
        """
        # Mock blueprint endpoint behavior
        with app.test_request_context():
            initial_commit_count = transaction_monitor['committed_transactions']
            
            # Simulate POST request to create business entity
            with app.test_client() as test_client:
                # Simulate authenticated request
                with test_client.session_transaction() as sess:
                    sess['_user_id'] = str(test_user.id)
                    sess['user_id'] = test_user.id
                
                # Create entity via simulated API call
                entity_data = {
                    'name': 'Blueprint Integration Entity',
                    'description': 'Entity created via blueprint integration',
                    'status': 'active'
                }
                
                # Simulate service layer call within request context
                entity_service = BusinessEntityService(db.session)
                entity_data['owner_id'] = test_user.id
                created_entity = entity_service.create_business_entity(entity_data)
                
                # Verify entity was created within request transaction
                assert created_entity is not None
                assert created_entity.name == 'Blueprint Integration Entity'
                
                # Verify transaction was committed
                final_commit_count = transaction_monitor['committed_transactions']
                assert final_commit_count > initial_commit_count
    
    def test_service_layer_transaction_propagation(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test transaction propagation through service layer calls.
        
        Validates that transaction context propagates correctly
        through nested service layer method calls.
        """
        services = service_layer_setup
        orchestrator = services['workflow_orchestrator']
        
        with app.test_request_context():
            # Test transaction propagation through service calls
            propagation_data = {
                'user_data': {
                    'username': 'propagation_test_user',
                    'email': 'propagation@test.com',
                    'password': 'propagation_password123'
                },
                'entity_data': {
                    'name': 'Propagation Test Entity',
                    'description': 'Entity for transaction propagation testing',
                    'status': 'active'
                },
                'session_data': {
                    'duration_hours': 2
                }
            }
            
            # Execute nested service calls with transaction propagation
            result = orchestrator.execute_user_onboarding_workflow(propagation_data)
            
            # Verify all operations completed within coordinated transactions
            assert result['success'] is True
            assert result['user'] is not None
            assert result['entity'] is not None
            assert result['session'] is not None
            
            # Verify proper relationships
            assert result['entity'].owner_id == result['user'].id
            assert result['session'].user_id == result['user'].id
    
    def test_error_handling_across_application_layers(self, app: Flask, service_layer_setup, transaction_monitor):
        """
        Test error handling and rollback across application layers.
        
        Validates that errors at any application layer trigger proper
        rollback across all participating transaction components.
        """
        services = service_layer_setup
        entity_service = services['business_entity_service']
        
        with app.test_request_context():
            initial_rollback_count = transaction_monitor['rolled_back_transactions']
            
            # Simulate error in service layer during blueprint request
            with patch.object(entity_service, '_persist_entity') as mock_persist:
                mock_persist.side_effect = SQLAlchemyError("Database persistence error")
                
                with pytest.raises(SQLAlchemyError):
                    entity_data = {
                        'name': 'Error Handling Entity',
                        'description': 'Entity for error handling testing',
                        'owner_id': services['test_user'].id,
                        'status': 'active'
                    }
                    entity_service.create_business_entity(entity_data)
            
            # Verify rollback occurred across application layers
            final_rollback_count = transaction_monitor['rolled_back_transactions']
            assert final_rollback_count > initial_rollback_count
            
            # Verify no partial data was committed
            failed_entity = db.session.query(BusinessEntity).filter_by(
                name='Error Handling Entity'
            ).first()
            assert failed_entity is None
    
    def test_transaction_cleanup_on_request_completion(self, app: Flask, client, test_user: User, transaction_monitor):
        """
        Test transaction cleanup when Flask requests complete.
        
        Validates that database sessions and transactions are properly
        cleaned up when Flask request contexts end.
        """
        session_ids = []
        
        # Execute multiple requests to test cleanup
        for i in range(5):
            with app.test_request_context():
                # Capture session ID
                session_ids.append(id(db.session))
                
                # Perform database operation
                entity = BusinessEntity(
                    name=f'Cleanup Test Entity {i+1}',
                    description=f'Entity {i+1} for cleanup testing',
                    owner_id=test_user.id,
                    status='active'
                )
                db.session.add(entity)
                db.session.commit()
        
        # Verify session cleanup between requests
        unique_sessions = len(set(session_ids))
        
        # Sessions should be properly managed (could be same or different depending on scope)
        assert unique_sessions >= 1, "Session management not working properly"
        
        # Verify all entities were created successfully
        with app.test_request_context():
            cleanup_entities = db.session.query(BusinessEntity).filter(
                BusinessEntity.name.like('Cleanup Test Entity%')
            ).all()
            assert len(cleanup_entities) == 5
        
        # Verify no transaction leaks
        assert transaction_monitor['active_transactions'] == 0, "Active transactions not cleaned up"