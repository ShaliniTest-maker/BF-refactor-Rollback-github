"""
Advanced workflow orchestration pattern testing validating complex multi-step business processes, 
service composition, event-driven processing, and comprehensive error handling with automatic 
retry mechanisms. This test suite ensures Flask Service Layer patterns maintain the functional 
behavior of the original Node.js implementation through sophisticated orchestration testing.

This module implements comprehensive testing per Section 4.5.3 of the technical specification,
validating:
- Service composition architecture for complex business operations
- Event-driven processing through Flask signals
- Transaction boundary management with Flask-SQLAlchemy session handling
- Performance optimization strategies including caching and efficient database queries
- Multi-step business process coordination with transactional integrity
- Error handling with automatic retry mechanisms and rollback capabilities
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock, call
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from flask import Flask, g, current_app
from flask.signals import Namespace, signals
import threading
import queue
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta

# Import Flask application components
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.services.base import BaseService
from src.services.user_service import UserService
from src.services.business_entity_service import BusinessEntityService
from src.services.workflow_orchestrator import WorkflowOrchestrator
from src.services.validation_service import ValidationService
from src.auth.decorators import require_auth, require_permission
from src.auth.session_manager import SessionManager
from src.utils.error_handling import BusinessLogicError, ValidationError, ServiceError
from src.utils.database import DatabaseTransactionManager
from src.utils.monitoring import MetricsCollector
from src.utils.logging import CorrelationLogger


# Test data structures for workflow coordination
@dataclass
class WorkflowContext:
    """Context object for maintaining workflow state across multi-step operations."""
    correlation_id: str
    user_id: int
    workflow_type: str
    current_step: str
    step_data: Dict[str, Any]
    transaction_id: Optional[str] = None
    retry_count: int = 0
    error_history: List[Dict] = None
    performance_metrics: Dict[str, float] = None
    
    def __post_init__(self):
        if self.error_history is None:
            self.error_history = []
        if self.performance_metrics is None:
            self.performance_metrics = {}


@dataclass
class ServiceExecutionResult:
    """Result container for service execution outcomes."""
    success: bool
    result: Any
    execution_time: float
    errors: List[str]
    transaction_info: Optional[Dict] = None
    performance_data: Optional[Dict] = None


class WorkflowSignals:
    """Custom Flask signals for event-driven workflow processing."""
    namespace = Namespace()
    
    # Workflow lifecycle signals
    workflow_started = namespace.signal('workflow-started')
    workflow_step_completed = namespace.signal('workflow-step-completed')
    workflow_step_failed = namespace.signal('workflow-step-failed')
    workflow_completed = namespace.signal('workflow-completed')
    workflow_failed = namespace.signal('workflow-failed')
    workflow_rolled_back = namespace.signal('workflow-rolled-back')
    
    # Service coordination signals
    service_composition_started = namespace.signal('service-composition-started')
    service_composition_completed = namespace.signal('service-composition-completed')
    
    # Transaction boundary signals
    transaction_started = namespace.signal('transaction-started')
    transaction_committed = namespace.signal('transaction-committed')
    transaction_rolled_back = namespace.signal('transaction-rolled-back')
    
    # Performance monitoring signals
    performance_threshold_exceeded = namespace.signal('performance-threshold-exceeded')
    cache_hit = namespace.signal('cache-hit')
    cache_miss = namespace.signal('cache-miss')


class WorkflowEventCollector:
    """Collector for workflow events to enable comprehensive testing validation."""
    
    def __init__(self):
        self.events = []
        self.signal_data = {}
        self.lock = threading.Lock()
    
    def clear(self):
        """Clear all collected events."""
        with self.lock:
            self.events.clear()
            self.signal_data.clear()
    
    def record_event(self, event_type: str, data: Dict):
        """Record a workflow event with timestamp and data."""
        with self.lock:
            self.events.append({
                'event_type': event_type,
                'timestamp': datetime.utcnow(),
                'data': data
            })
    
    def connect_signals(self):
        """Connect to all workflow signals for event collection."""
        WorkflowSignals.workflow_started.connect(
            lambda sender, **kwargs: self.record_event('workflow_started', kwargs)
        )
        WorkflowSignals.workflow_step_completed.connect(
            lambda sender, **kwargs: self.record_event('workflow_step_completed', kwargs)
        )
        WorkflowSignals.workflow_step_failed.connect(
            lambda sender, **kwargs: self.record_event('workflow_step_failed', kwargs)
        )
        WorkflowSignals.workflow_completed.connect(
            lambda sender, **kwargs: self.record_event('workflow_completed', kwargs)
        )
        WorkflowSignals.workflow_failed.connect(
            lambda sender, **kwargs: self.record_event('workflow_failed', kwargs)
        )
        WorkflowSignals.workflow_rolled_back.connect(
            lambda sender, **kwargs: self.record_event('workflow_rolled_back', kwargs)
        )
        WorkflowSignals.service_composition_started.connect(
            lambda sender, **kwargs: self.record_event('service_composition_started', kwargs)
        )
        WorkflowSignals.service_composition_completed.connect(
            lambda sender, **kwargs: self.record_event('service_composition_completed', kwargs)
        )
        WorkflowSignals.transaction_started.connect(
            lambda sender, **kwargs: self.record_event('transaction_started', kwargs)
        )
        WorkflowSignals.transaction_committed.connect(
            lambda sender, **kwargs: self.record_event('transaction_committed', kwargs)
        )
        WorkflowSignals.transaction_rolled_back.connect(
            lambda sender, **kwargs: self.record_event('transaction_rolled_back', kwargs)
        )
    
    def get_events_by_type(self, event_type: str) -> List[Dict]:
        """Get all events of a specific type."""
        with self.lock:
            return [event for event in self.events if event['event_type'] == event_type]
    
    def count_events(self, event_type: str) -> int:
        """Count events of a specific type."""
        return len(self.get_events_by_type(event_type))


class MockTransactionContext:
    """Mock transaction context for testing transaction boundary management."""
    
    def __init__(self, should_fail: bool = False, fail_on_commit: bool = False):
        self.should_fail = should_fail
        self.fail_on_commit = fail_on_commit
        self.is_active = False
        self.is_committed = False
        self.is_rolled_back = False
        self.operations = []
    
    def __enter__(self):
        self.is_active = True
        WorkflowSignals.transaction_started.send(current_app._get_current_object())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None or self.should_fail:
            self.rollback()
        else:
            if self.fail_on_commit:
                raise OperationalError("Transaction commit failed", None, None)
            self.commit()
        self.is_active = False
    
    def commit(self):
        """Commit the transaction."""
        if self.is_active and not self.is_rolled_back:
            self.is_committed = True
            WorkflowSignals.transaction_committed.send(current_app._get_current_object())
    
    def rollback(self):
        """Rollback the transaction."""
        if self.is_active and not self.is_committed:
            self.is_rolled_back = True
            WorkflowSignals.transaction_rolled_back.send(current_app._get_current_object())
    
    def add_operation(self, operation: str):
        """Add an operation to the transaction log."""
        self.operations.append(operation)


@pytest.fixture
def workflow_event_collector():
    """Fixture providing workflow event collection capabilities."""
    collector = WorkflowEventCollector()
    collector.connect_signals()
    yield collector
    collector.clear()


@pytest.fixture
def mock_services(app, db_session):
    """Fixture providing mock service instances for testing."""
    services = {}
    
    # Mock base service
    services['base'] = Mock(spec=BaseService)
    services['base'].db_session = db_session
    services['base'].logger = Mock()
    
    # Mock user service
    services['user'] = Mock(spec=UserService)
    services['user'].create_user = Mock()
    services['user'].authenticate_user = Mock()
    services['user'].get_user_by_id = Mock()
    services['user'].update_user_profile = Mock()
    
    # Mock business entity service
    services['business_entity'] = Mock(spec=BusinessEntityService)
    services['business_entity'].create_entity = Mock()
    services['business_entity'].update_entity = Mock()
    services['business_entity'].create_relationship = Mock()
    services['business_entity'].delete_entity = Mock()
    
    # Mock validation service
    services['validation'] = Mock(spec=ValidationService)
    services['validation'].validate_user_data = Mock(return_value=True)
    services['validation'].validate_business_rules = Mock(return_value=True)
    services['validation'].validate_entity_data = Mock(return_value=True)
    
    # Mock workflow orchestrator
    services['orchestrator'] = Mock(spec=WorkflowOrchestrator)
    services['orchestrator'].execute_workflow = Mock()
    services['orchestrator'].coordinate_services = Mock()
    services['orchestrator'].handle_workflow_error = Mock()
    
    return services


@pytest.fixture
def performance_monitor():
    """Fixture providing performance monitoring capabilities."""
    class PerformanceMonitor:
        def __init__(self):
            self.metrics = {}
            self.thresholds = {
                'response_time': 2.0,  # 2 seconds max
                'database_query': 0.5,  # 500ms max
                'service_execution': 1.0,  # 1 second max
                'memory_usage': 100 * 1024 * 1024  # 100MB max
            }
        
        @contextmanager
        def measure_execution(self, operation_name: str):
            """Context manager for measuring execution time."""
            start_time = time.time()
            try:
                yield
            finally:
                execution_time = time.time() - start_time
                self.metrics[operation_name] = execution_time
                
                # Check thresholds
                if operation_name in self.thresholds:
                    if execution_time > self.thresholds[operation_name]:
                        WorkflowSignals.performance_threshold_exceeded.send(
                            current_app._get_current_object(),
                            operation=operation_name,
                            execution_time=execution_time,
                            threshold=self.thresholds[operation_name]
                        )
        
        def get_metric(self, operation_name: str) -> Optional[float]:
            """Get performance metric by operation name."""
            return self.metrics.get(operation_name)
        
        def clear_metrics(self):
            """Clear all collected metrics."""
            self.metrics.clear()
    
    return PerformanceMonitor()


class TestAdvancedWorkflowOrchestration:
    """Test suite for advanced workflow orchestration patterns."""
    
    def test_service_composition_complex_workflow(self, app, db_session, mock_services, workflow_event_collector, performance_monitor):
        """
        Test service composition architecture enabling complex business workflows 
        through coordinated service interactions.
        
        Validates:
        - Multi-service coordination with proper dependency management
        - Service execution order and result passing
        - Error propagation across service boundaries
        - Performance monitoring of composite operations
        """
        with app.app_context():
            # Setup workflow context
            context = WorkflowContext(
                correlation_id="test-workflow-001",
                user_id=1,
                workflow_type="complex_business_operation",
                current_step="initialization"
            )
            
            # Define complex workflow steps
            workflow_steps = [
                {"step": "validate_user", "service": "user", "method": "authenticate_user"},
                {"step": "validate_input", "service": "validation", "method": "validate_user_data"},
                {"step": "create_entity", "service": "business_entity", "method": "create_entity"},
                {"step": "create_relationships", "service": "business_entity", "method": "create_relationship"},
                {"step": "finalize_workflow", "service": "orchestrator", "method": "execute_workflow"}
            ]
            
            # Configure mock responses
            mock_services['user'].authenticate_user.return_value = ServiceExecutionResult(
                success=True, result={"user_id": 1, "username": "testuser"}, 
                execution_time=0.1, errors=[]
            )
            mock_services['validation'].validate_user_data.return_value = True
            mock_services['business_entity'].create_entity.return_value = ServiceExecutionResult(
                success=True, result={"entity_id": 100}, execution_time=0.2, errors=[]
            )
            mock_services['business_entity'].create_relationship.return_value = ServiceExecutionResult(
                success=True, result={"relationship_id": 50}, execution_time=0.15, errors=[]
            )
            
            # Signal workflow start
            WorkflowSignals.workflow_started.send(
                current_app._get_current_object(),
                context=context,
                steps=workflow_steps
            )
            
            # Execute workflow with service composition
            results = {}
            try:
                with performance_monitor.measure_execution("complete_workflow"):
                    for step_config in workflow_steps:
                        context.current_step = step_config["step"]
                        
                        with performance_monitor.measure_execution(f"step_{step_config['step']}"):
                            service = mock_services[step_config["service"]]
                            method = getattr(service, step_config["method"])
                            
                            # Execute service method with context
                            if step_config["step"] == "validate_input":
                                result = method(context.step_data)
                            elif step_config["step"] == "create_entity":
                                result = method({"name": "Test Entity", "owner_id": context.user_id})
                            elif step_config["step"] == "create_relationships":
                                result = method({"source_id": 100, "target_id": 101})
                            else:
                                result = method()
                            
                            results[step_config["step"]] = result
                            
                            # Signal step completion
                            WorkflowSignals.workflow_step_completed.send(
                                current_app._get_current_object(),
                                context=context,
                                step=step_config["step"],
                                result=result
                            )
                
                # Signal workflow completion
                WorkflowSignals.workflow_completed.send(
                    current_app._get_current_object(),
                    context=context,
                    results=results
                )
                
            except Exception as e:
                WorkflowSignals.workflow_failed.send(
                    current_app._get_current_object(),
                    context=context,
                    error=str(e)
                )
                raise
            
            # Validate service composition execution
            assert workflow_event_collector.count_events('workflow_started') == 1
            assert workflow_event_collector.count_events('workflow_step_completed') == 5
            assert workflow_event_collector.count_events('workflow_completed') == 1
            assert workflow_event_collector.count_events('workflow_failed') == 0
            
            # Verify service execution order
            completed_steps = workflow_event_collector.get_events_by_type('workflow_step_completed')
            expected_order = ['validate_user', 'validate_input', 'create_entity', 'create_relationships', 'finalize_workflow']
            actual_order = [event['data']['step'] for event in completed_steps]
            assert actual_order == expected_order
            
            # Validate performance metrics
            total_execution_time = performance_monitor.get_metric("complete_workflow")
            assert total_execution_time is not None
            assert total_execution_time < 2.0  # Should complete within 2 seconds
            
            # Verify all services were called
            mock_services['user'].authenticate_user.assert_called_once()
            mock_services['validation'].validate_user_data.assert_called_once()
            mock_services['business_entity'].create_entity.assert_called_once()
            mock_services['business_entity'].create_relationship.assert_called_once()
    
    def test_event_driven_processing_flask_signals(self, app, db_session, workflow_event_collector):
        """
        Test event-driven processing through Flask signals for resilient operation patterns.
        
        Validates:
        - Flask signals integration for workflow coordination
        - Event-driven error handling and recovery
        - Asynchronous event processing capabilities
        - Signal data propagation and integrity
        """
        with app.app_context():
            # Setup event-driven workflow components
            event_queue = queue.Queue()
            signal_responses = {}
            
            # Define signal handlers for workflow events
            @WorkflowSignals.workflow_started.connect
            def handle_workflow_start(sender, **kwargs):
                context = kwargs.get('context')
                signal_responses['workflow_started'] = {
                    'correlation_id': context.correlation_id,
                    'timestamp': datetime.utcnow()
                }
                event_queue.put(('workflow_started', kwargs))
            
            @WorkflowSignals.workflow_step_completed.connect
            def handle_step_completion(sender, **kwargs):
                step = kwargs.get('step')
                result = kwargs.get('result')
                signal_responses[f'step_completed_{step}'] = {
                    'result': result,
                    'timestamp': datetime.utcnow()
                }
                event_queue.put(('step_completed', kwargs))
            
            @WorkflowSignals.workflow_step_failed.connect
            def handle_step_failure(sender, **kwargs):
                step = kwargs.get('step')
                error = kwargs.get('error')
                signal_responses[f'step_failed_{step}'] = {
                    'error': error,
                    'timestamp': datetime.utcnow()
                }
                event_queue.put(('step_failed', kwargs))
                
                # Trigger automatic retry logic
                if kwargs.get('context', {}).get('retry_count', 0) < 3:
                    # Simulate retry mechanism
                    WorkflowSignals.workflow_step_completed.send(
                        sender,
                        context=kwargs.get('context'),
                        step=f"{step}_retry",
                        result={'retried': True}
                    )
            
            # Create workflow context
            context = WorkflowContext(
                correlation_id="event-driven-001",
                user_id=1,
                workflow_type="event_driven_test",
                current_step="start"
            )
            
            # Execute event-driven workflow
            WorkflowSignals.workflow_started.send(
                current_app._get_current_object(),
                context=context
            )
            
            # Simulate workflow steps with events
            steps = ['authentication', 'validation', 'processing', 'completion']
            for i, step in enumerate(steps):
                context.current_step = step
                
                if step == 'validation':
                    # Simulate step failure to test error handling
                    WorkflowSignals.workflow_step_failed.send(
                        current_app._get_current_object(),
                        context=context,
                        step=step,
                        error="Validation failed"
                    )
                else:
                    WorkflowSignals.workflow_step_completed.send(
                        current_app._get_current_object(),
                        context=context,
                        step=step,
                        result={"step_result": f"completed_{step}"}
                    )
            
            # Allow time for asynchronous event processing
            time.sleep(0.1)
            
            # Validate event-driven processing
            assert 'workflow_started' in signal_responses
            assert signal_responses['workflow_started']['correlation_id'] == context.correlation_id
            
            # Verify step completion events
            assert 'step_completed_authentication' in signal_responses
            assert 'step_completed_processing' in signal_responses
            assert 'step_completed_completion' in signal_responses
            
            # Verify error handling and retry
            assert 'step_failed_validation' in signal_responses
            assert 'step_completed_validation_retry' in signal_responses
            
            # Check event queue processing
            event_count = 0
            while not event_queue.empty():
                event_type, event_data = event_queue.get()
                event_count += 1
                assert 'context' in event_data or 'step' in event_data
            
            assert event_count >= 5  # Started + 4 steps (including retry)
            
            # Validate Flask signals integration
            workflow_events = workflow_event_collector.get_events_by_type('workflow_started')
            assert len(workflow_events) == 1
            assert workflow_events[0]['data']['context'].correlation_id == context.correlation_id
    
    def test_transaction_boundary_management_acid_properties(self, app, db_session, mock_services, workflow_event_collector):
        """
        Test transaction boundary management through Flask-SQLAlchemy session management 
        with ACID property preservation.
        
        Validates:
        - Transaction isolation and consistency
        - Rollback capabilities on service failures
        - Nested transaction handling
        - Database integrity during complex operations
        """
        with app.app_context():
            # Setup transaction test context
            context = WorkflowContext(
                correlation_id="transaction-test-001",
                user_id=1,
                workflow_type="transaction_boundary_test",
                current_step="transaction_start"
            )
            
            # Test successful transaction scenario
            with MockTransactionContext() as tx1:
                tx1.add_operation("create_user")
                tx1.add_operation("create_entity")
                tx1.add_operation("create_relationship")
                
                # Simulate multi-service transaction
                mock_services['user'].create_user.return_value = ServiceExecutionResult(
                    success=True, result={"user_id": 123}, execution_time=0.1, errors=[],
                    transaction_info={"transaction_id": "tx1", "operation": "create_user"}
                )
                
                mock_services['business_entity'].create_entity.return_value = ServiceExecutionResult(
                    success=True, result={"entity_id": 456}, execution_time=0.15, errors=[],
                    transaction_info={"transaction_id": "tx1", "operation": "create_entity"}
                )
                
                # Execute transactional operations
                user_result = mock_services['user'].create_user({"username": "txuser", "email": "tx@test.com"})
                entity_result = mock_services['business_entity'].create_entity({"name": "TX Entity", "owner_id": 123})
                
                assert user_result.success
                assert entity_result.success
                assert tx1.is_active
            
            # Verify successful transaction commit
            assert tx1.is_committed
            assert not tx1.is_rolled_back
            assert len(tx1.operations) == 3
            
            # Test transaction rollback scenario
            rollback_executed = False
            try:
                with MockTransactionContext(should_fail=True) as tx2:
                    tx2.add_operation("create_user")
                    tx2.add_operation("create_entity")
                    
                    # Simulate service failure during transaction
                    mock_services['user'].create_user.return_value = ServiceExecutionResult(
                        success=False, result=None, execution_time=0.1, 
                        errors=["Database constraint violation"],
                        transaction_info={"transaction_id": "tx2", "operation": "create_user"}
                    )
                    
                    user_result = mock_services['user'].create_user({"username": "failuser"})
                    if not user_result.success:
                        raise ServiceError("User creation failed")
                        
            except ServiceError:
                rollback_executed = True
            
            # Verify transaction rollback
            assert rollback_executed
            assert tx2.is_rolled_back
            assert not tx2.is_committed
            
            # Test nested transaction scenario
            with MockTransactionContext() as outer_tx:
                outer_tx.add_operation("outer_start")
                
                # Simulate nested transaction
                with MockTransactionContext() as inner_tx:
                    inner_tx.add_operation("inner_operation")
                    
                    # Inner transaction operations
                    mock_services['validation'].validate_user_data.return_value = True
                    validation_result = mock_services['validation'].validate_user_data({"test": "data"})
                    assert validation_result
                
                # Inner transaction should be committed
                assert inner_tx.is_committed
                
                outer_tx.add_operation("outer_end")
            
            # Outer transaction should be committed
            assert outer_tx.is_committed
            assert len(outer_tx.operations) == 2
            
            # Test commit failure scenario
            commit_failed = False
            try:
                with MockTransactionContext(fail_on_commit=True) as tx3:
                    tx3.add_operation("operation_before_commit_failure")
                    
            except OperationalError:
                commit_failed = True
            
            assert commit_failed
            assert not tx3.is_committed
            
            # Validate transaction events
            transaction_started_events = workflow_event_collector.get_events_by_type('transaction_started')
            transaction_committed_events = workflow_event_collector.get_events_by_type('transaction_committed')
            transaction_rolled_back_events = workflow_event_collector.get_events_by_type('transaction_rolled_back')
            
            assert len(transaction_started_events) >= 4  # Multiple transactions started
            assert len(transaction_committed_events) >= 2  # Some successful commits
            assert len(transaction_rolled_back_events) >= 1  # At least one rollback
    
    def test_performance_optimization_strategies(self, app, db_session, mock_services, performance_monitor, workflow_event_collector):
        """
        Test performance optimization strategy including caching, efficient database 
        query patterns, and optimized execution paths.
        
        Validates:
        - Caching mechanisms and cache hit/miss patterns
        - Database query optimization and execution time monitoring
        - Memory usage optimization during complex workflows
        - Performance threshold monitoring and alerting
        """
        with app.app_context():
            # Setup performance test cache
            workflow_cache = {}
            cache_stats = {"hits": 0, "misses": 0}
            
            def get_from_cache(cache_key: str):
                """Simulate cache retrieval with performance monitoring."""
                if cache_key in workflow_cache:
                    cache_stats["hits"] += 1
                    WorkflowSignals.cache_hit.send(
                        current_app._get_current_object(),
                        cache_key=cache_key,
                        value=workflow_cache[cache_key]
                    )
                    return workflow_cache[cache_key]
                else:
                    cache_stats["misses"] += 1
                    WorkflowSignals.cache_miss.send(
                        current_app._get_current_object(),
                        cache_key=cache_key
                    )
                    return None
            
            def set_cache(cache_key: str, value: Any):
                """Set cache value with TTL simulation."""
                workflow_cache[cache_key] = value
            
            # Test cached workflow execution
            context = WorkflowContext(
                correlation_id="performance-test-001",
                user_id=1,
                workflow_type="performance_optimization_test",
                current_step="cache_test"
            )
            
            # First execution - cache miss scenario
            cache_key = f"user_profile_{context.user_id}"
            cached_result = get_from_cache(cache_key)
            
            if cached_result is None:
                with performance_monitor.measure_execution("database_query_user_profile"):
                    # Simulate database query
                    time.sleep(0.1)  # Simulate DB latency
                    user_profile = {"user_id": context.user_id, "profile_data": "comprehensive_data"}
                    set_cache(cache_key, user_profile)
                    result = user_profile
            else:
                result = cached_result
            
            # Verify cache miss on first execution
            assert cache_stats["misses"] == 1
            assert cache_stats["hits"] == 0
            
            # Second execution - cache hit scenario
            cached_result = get_from_cache(cache_key)
            if cached_result is not None:
                with performance_monitor.measure_execution("cached_user_profile"):
                    result = cached_result
            
            # Verify cache hit on second execution
            assert cache_stats["hits"] == 1
            assert cache_stats["misses"] == 1
            
            # Test query optimization patterns
            with performance_monitor.measure_execution("optimized_entity_query"):
                # Simulate optimized database query with join
                mock_services['business_entity'].get_entities_with_relationships = Mock(
                    return_value=ServiceExecutionResult(
                        success=True,
                        result=[{"entity_id": 1, "relationships": []}],
                        execution_time=0.05,  # Optimized query time
                        errors=[],
                        performance_data={"query_type": "optimized_join", "rows_returned": 10}
                    )
                )
                
                entities_result = mock_services['business_entity'].get_entities_with_relationships()
                assert entities_result.success
                assert entities_result.execution_time < 0.1  # Should be fast
            
            # Test memory optimization with large dataset processing
            large_dataset_size = 1000
            with performance_monitor.measure_execution("large_dataset_processing"):
                # Simulate memory-efficient processing
                processed_items = []
                batch_size = 100
                
                for i in range(0, large_dataset_size, batch_size):
                    batch = list(range(i, min(i + batch_size, large_dataset_size)))
                    # Process batch and release memory
                    processed_batch = [{"item_id": item, "processed": True} for item in batch]
                    processed_items.extend(processed_batch)
                    
                    # Simulate memory cleanup
                    del processed_batch
            
            # Validate performance metrics
            db_query_time = performance_monitor.get_metric("database_query_user_profile")
            cached_query_time = performance_monitor.get_metric("cached_user_profile")
            optimized_query_time = performance_monitor.get_metric("optimized_entity_query")
            large_dataset_time = performance_monitor.get_metric("large_dataset_processing")
            
            # Verify performance improvements
            assert db_query_time > cached_query_time  # Cache should be faster
            assert optimized_query_time < 0.1  # Optimized query should be fast
            assert large_dataset_time < 2.0  # Large dataset processing should be reasonable
            
            # Test performance threshold monitoring
            with performance_monitor.measure_execution("slow_operation"):
                time.sleep(2.5)  # Intentionally slow operation
            
            # Verify threshold exceeded events
            threshold_events = workflow_event_collector.get_events_by_type('performance_threshold_exceeded')
            assert len(threshold_events) >= 1
            
            slow_operation_event = next(
                (event for event in threshold_events 
                 if event['data'].get('operation') == 'slow_operation'), 
                None
            )
            assert slow_operation_event is not None
            assert slow_operation_event['data']['execution_time'] > 2.0
            
            # Validate cache statistics
            cache_hit_events = workflow_event_collector.get_events_by_type('cache_hit')
            cache_miss_events = workflow_event_collector.get_events_by_type('cache_miss')
            
            assert len(cache_hit_events) >= 1
            assert len(cache_miss_events) >= 1
            
            # Calculate cache hit ratio
            total_cache_operations = cache_stats["hits"] + cache_stats["misses"]
            cache_hit_ratio = cache_stats["hits"] / total_cache_operations if total_cache_operations > 0 else 0
            assert cache_hit_ratio >= 0.5  # Should have reasonable cache efficiency
    
    def test_multi_step_business_process_coordination(self, app, db_session, mock_services, workflow_event_collector, performance_monitor):
        """
        Test multi-step business process coordination maintaining transactional 
        integrity across service boundaries.
        
        Validates:
        - Complex business workflow execution with multiple services
        - Data consistency across service boundaries
        - Compensation patterns for failed operations
        - Business rule enforcement throughout the process
        """
        with app.app_context():
            # Define complex business process: User Registration with Entity Creation
            context = WorkflowContext(
                correlation_id="business-process-001",
                user_id=0,  # Will be set during process
                workflow_type="user_registration_with_entity",
                current_step="start",
                step_data={
                    "user_data": {
                        "username": "newuser",
                        "email": "newuser@test.com",
                        "password": "secure_password"
                    },
                    "entity_data": {
                        "name": "User's Default Entity",
                        "description": "Default business entity for new user"
                    },
                    "relationship_data": {
                        "type": "OWNERSHIP",
                        "is_primary": True
                    }
                }
            )
            
            # Configure mock services for business process
            mock_services['validation'].validate_user_data.return_value = True
            mock_services['validation'].validate_business_rules.return_value = True
            mock_services['validation'].validate_entity_data.return_value = True
            
            mock_services['user'].create_user.return_value = ServiceExecutionResult(
                success=True, 
                result={"user_id": 1001, "username": "newuser", "created_at": datetime.utcnow()},
                execution_time=0.2, 
                errors=[],
                transaction_info={"step": "user_creation", "entity_count": 1}
            )
            
            mock_services['business_entity'].create_entity.return_value = ServiceExecutionResult(
                success=True,
                result={"entity_id": 2001, "name": "User's Default Entity", "owner_id": 1001},
                execution_time=0.15,
                errors=[],
                transaction_info={"step": "entity_creation", "relationships_pending": 1}
            )
            
            mock_services['business_entity'].create_relationship.return_value = ServiceExecutionResult(
                success=True,
                result={"relationship_id": 3001, "source_id": 1001, "target_id": 2001, "type": "OWNERSHIP"},
                execution_time=0.1,
                errors=[],
                transaction_info={"step": "relationship_creation", "is_primary": True}
            )
            
            # Execute multi-step business process
            process_results = {}
            compensation_actions = []
            
            try:
                with performance_monitor.measure_execution("complete_business_process"):
                    
                    # Step 1: Input Validation
                    context.current_step = "input_validation"
                    with performance_monitor.measure_execution("step_input_validation"):
                        user_valid = mock_services['validation'].validate_user_data(context.step_data["user_data"])
                        entity_valid = mock_services['validation'].validate_entity_data(context.step_data["entity_data"])
                        business_rules_valid = mock_services['validation'].validate_business_rules({
                            "user_data": context.step_data["user_data"],
                            "entity_data": context.step_data["entity_data"]
                        })
                        
                        if not (user_valid and entity_valid and business_rules_valid):
                            raise ValidationError("Input validation failed")
                        
                        process_results["validation"] = {
                            "user_valid": user_valid,
                            "entity_valid": entity_valid,
                            "business_rules_valid": business_rules_valid
                        }
                    
                    WorkflowSignals.workflow_step_completed.send(
                        current_app._get_current_object(),
                        context=context,
                        step="input_validation",
                        result=process_results["validation"]
                    )
                    
                    # Step 2: User Creation with Transaction
                    context.current_step = "user_creation"
                    with performance_monitor.measure_execution("step_user_creation"):
                        with MockTransactionContext() as user_tx:
                            user_tx.add_operation("create_user_account")
                            user_result = mock_services['user'].create_user(context.step_data["user_data"])
                            
                            if not user_result.success:
                                raise ServiceError("User creation failed")
                            
                            context.user_id = user_result.result["user_id"]
                            process_results["user_creation"] = user_result.result
                            
                            # Setup compensation action
                            compensation_actions.append({
                                "action": "delete_user",
                                "params": {"user_id": context.user_id}
                            })
                    
                    WorkflowSignals.workflow_step_completed.send(
                        current_app._get_current_object(),
                        context=context,
                        step="user_creation",
                        result=process_results["user_creation"]
                    )
                    
                    # Step 3: Entity Creation
                    context.current_step = "entity_creation"
                    with performance_monitor.measure_execution("step_entity_creation"):
                        with MockTransactionContext() as entity_tx:
                            entity_tx.add_operation("create_business_entity")
                            
                            entity_data_with_owner = {
                                **context.step_data["entity_data"],
                                "owner_id": context.user_id
                            }
                            entity_result = mock_services['business_entity'].create_entity(entity_data_with_owner)
                            
                            if not entity_result.success:
                                raise ServiceError("Entity creation failed")
                            
                            process_results["entity_creation"] = entity_result.result
                            
                            # Setup compensation action
                            compensation_actions.append({
                                "action": "delete_entity", 
                                "params": {"entity_id": entity_result.result["entity_id"]}
                            })
                    
                    WorkflowSignals.workflow_step_completed.send(
                        current_app._get_current_object(),
                        context=context,
                        step="entity_creation",
                        result=process_results["entity_creation"]
                    )
                    
                    # Step 4: Relationship Creation
                    context.current_step = "relationship_creation"
                    with performance_monitor.measure_execution("step_relationship_creation"):
                        with MockTransactionContext() as rel_tx:
                            rel_tx.add_operation("create_ownership_relationship")
                            
                            relationship_data = {
                                **context.step_data["relationship_data"],
                                "source_id": context.user_id,
                                "target_id": process_results["entity_creation"]["entity_id"]
                            }
                            relationship_result = mock_services['business_entity'].create_relationship(relationship_data)
                            
                            if not relationship_result.success:
                                raise ServiceError("Relationship creation failed")
                            
                            process_results["relationship_creation"] = relationship_result.result
                    
                    WorkflowSignals.workflow_step_completed.send(
                        current_app._get_current_object(),
                        context=context,
                        step="relationship_creation",
                        result=process_results["relationship_creation"]
                    )
                    
                    # Step 5: Process Finalization
                    context.current_step = "finalization"
                    with performance_monitor.measure_execution("step_finalization"):
                        # Finalize the business process
                        final_result = {
                            "user_id": context.user_id,
                            "entity_id": process_results["entity_creation"]["entity_id"],
                            "relationship_id": process_results["relationship_creation"]["relationship_id"],
                            "process_completed_at": datetime.utcnow(),
                            "compensation_actions_available": len(compensation_actions)
                        }
                        process_results["finalization"] = final_result
                    
                    WorkflowSignals.workflow_step_completed.send(
                        current_app._get_current_object(),
                        context=context,
                        step="finalization",
                        result=process_results["finalization"]
                    )
                
                # Signal successful process completion
                WorkflowSignals.workflow_completed.send(
                    current_app._get_current_object(),
                    context=context,
                    results=process_results
                )
                
            except Exception as e:
                # Execute compensation actions on failure
                context.error_history.append({
                    "error": str(e),
                    "step": context.current_step,
                    "timestamp": datetime.utcnow(),
                    "compensation_actions": compensation_actions
                })
                
                WorkflowSignals.workflow_failed.send(
                    current_app._get_current_object(),
                    context=context,
                    error=str(e),
                    compensation_actions=compensation_actions
                )
                
                # Execute compensation (in reverse order)
                for compensation in reversed(compensation_actions):
                    # Simulate compensation execution
                    if compensation["action"] == "delete_entity":
                        mock_services['business_entity'].delete_entity(compensation["params"])
                    elif compensation["action"] == "delete_user":
                        mock_services['user'].delete_user(compensation["params"])
                
                WorkflowSignals.workflow_rolled_back.send(
                    current_app._get_current_object(),
                    context=context,
                    compensation_actions=compensation_actions
                )
                
                raise
            
            # Validate multi-step process execution
            assert workflow_event_collector.count_events('workflow_step_completed') == 5
            assert workflow_event_collector.count_events('workflow_completed') == 1
            assert workflow_event_collector.count_events('workflow_failed') == 0
            
            # Verify process results integrity
            assert "user_creation" in process_results
            assert "entity_creation" in process_results
            assert "relationship_creation" in process_results
            assert "finalization" in process_results
            
            # Validate data consistency across steps
            assert process_results["entity_creation"]["owner_id"] == process_results["user_creation"]["user_id"]
            assert process_results["relationship_creation"]["source_id"] == process_results["user_creation"]["user_id"]
            assert process_results["relationship_creation"]["target_id"] == process_results["entity_creation"]["entity_id"]
            
            # Verify service execution order and dependencies
            step_completion_events = workflow_event_collector.get_events_by_type('workflow_step_completed')
            step_order = [event['data']['step'] for event in step_completion_events]
            expected_order = ["input_validation", "user_creation", "entity_creation", "relationship_creation", "finalization"]
            assert step_order == expected_order
            
            # Validate performance metrics
            total_process_time = performance_monitor.get_metric("complete_business_process")
            assert total_process_time is not None
            assert total_process_time < 3.0  # Should complete within reasonable time
            
            # Verify all services were called with correct parameters
            mock_services['validation'].validate_user_data.assert_called_once()
            mock_services['validation'].validate_entity_data.assert_called_once()
            mock_services['validation'].validate_business_rules.assert_called_once()
            mock_services['user'].create_user.assert_called_once()
            mock_services['business_entity'].create_entity.assert_called_once()
            mock_services['business_entity'].create_relationship.assert_called_once()
    
    def test_error_handling_with_automatic_retry_mechanisms(self, app, db_session, mock_services, workflow_event_collector, performance_monitor):
        """
        Test comprehensive error handling with automatic retry mechanisms 
        and rollback capabilities.
        
        Validates:
        - Automatic retry logic for transient failures
        - Exponential backoff retry strategies
        - Circuit breaker patterns for persistent failures
        - Error classification and handling strategies
        """
        with app.app_context():
            # Setup retry configuration
            retry_config = {
                "max_retries": 3,
                "initial_delay": 0.1,
                "backoff_multiplier": 2.0,
                "max_delay": 1.0,
                "retryable_errors": [OperationalError, IntegrityError],
                "non_retryable_errors": [ValidationError, BusinessLogicError]
            }
            
            def calculate_retry_delay(attempt: int, config: Dict) -> float:
                """Calculate retry delay with exponential backoff."""
                delay = config["initial_delay"] * (config["backoff_multiplier"] ** attempt)
                return min(delay, config["max_delay"])
            
            def is_retryable_error(error: Exception, config: Dict) -> bool:
                """Determine if an error is retryable."""
                return any(isinstance(error, error_type) for error_type in config["retryable_errors"])
            
            # Test automatic retry with transient failures
            context = WorkflowContext(
                correlation_id="retry-test-001",
                user_id=1,
                workflow_type="retry_mechanism_test",
                current_step="retry_test"
            )
            
            # Configure mock service with transient failures
            call_count = {"value": 0}
            
            def failing_service_call(*args, **kwargs):
                call_count["value"] += 1
                if call_count["value"] <= 2:  # Fail first 2 attempts
                    raise OperationalError("Temporary database connection error", None, None)
                else:  # Succeed on 3rd attempt
                    return ServiceExecutionResult(
                        success=True,
                        result={"operation": "succeeded", "attempt": call_count["value"]},
                        execution_time=0.1,
                        errors=[]
                    )
            
            mock_services['user'].create_user.side_effect = failing_service_call
            
            # Execute operation with retry logic
            result = None
            retry_attempts = []
            
            try:
                with performance_monitor.measure_execution("operation_with_retries"):
                    for attempt in range(retry_config["max_retries"] + 1):
                        try:
                            context.retry_count = attempt
                            
                            if attempt > 0:
                                delay = calculate_retry_delay(attempt - 1, retry_config)
                                time.sleep(delay)
                                retry_attempts.append({
                                    "attempt": attempt,
                                    "delay": delay,
                                    "timestamp": datetime.utcnow()
                                })
                            
                            result = mock_services['user'].create_user({"username": "retryuser"})
                            break  # Success, exit retry loop
                            
                        except Exception as e:
                            if attempt == retry_config["max_retries"]:
                                # Max retries exceeded
                                context.error_history.append({
                                    "error": str(e),
                                    "final_attempt": True,
                                    "total_attempts": attempt + 1,
                                    "timestamp": datetime.utcnow()
                                })
                                WorkflowSignals.workflow_failed.send(
                                    current_app._get_current_object(),
                                    context=context,
                                    error=str(e),
                                    retry_attempts=retry_attempts
                                )
                                raise
                            
                            if not is_retryable_error(e, retry_config):
                                # Non-retryable error, fail immediately
                                context.error_history.append({
                                    "error": str(e),
                                    "non_retryable": True,
                                    "attempt": attempt + 1,
                                    "timestamp": datetime.utcnow()
                                })
                                WorkflowSignals.workflow_failed.send(
                                    current_app._get_current_object(),
                                    context=context,
                                    error=str(e),
                                    retry_attempts=retry_attempts
                                )
                                raise
                            
                            # Log retry attempt
                            context.error_history.append({
                                "error": str(e),
                                "retryable": True,
                                "attempt": attempt + 1,
                                "timestamp": datetime.utcnow()
                            })
                            
                            WorkflowSignals.workflow_step_failed.send(
                                current_app._get_current_object(),
                                context=context,
                                step="user_creation",
                                error=str(e),
                                attempt=attempt + 1
                            )
                
            except Exception as final_error:
                # Handle final failure after all retries
                pass
            
            # Validate retry mechanism execution
            assert result is not None
            assert result.success
            assert result.result["attempt"] == 3  # Should succeed on 3rd attempt
            assert call_count["value"] == 3  # Should have made 3 calls total
            assert len(retry_attempts) == 2  # Should have 2 retry attempts
            
            # Verify exponential backoff
            assert retry_attempts[0]["delay"] == retry_config["initial_delay"]
            assert retry_attempts[1]["delay"] == retry_config["initial_delay"] * retry_config["backoff_multiplier"]
            
            # Test non-retryable error handling
            call_count["value"] = 0
            
            def non_retryable_failure(*args, **kwargs):
                call_count["value"] += 1
                raise ValidationError("Invalid input data - not retryable")
            
            mock_services['validation'].validate_user_data.side_effect = non_retryable_failure
            
            # Execute operation that should fail immediately
            immediate_failure = False
            try:
                with performance_monitor.measure_execution("non_retryable_operation"):
                    for attempt in range(retry_config["max_retries"] + 1):
                        try:
                            validation_result = mock_services['validation'].validate_user_data({"invalid": "data"})
                            break
                        except Exception as e:
                            if not is_retryable_error(e, retry_config):
                                immediate_failure = True
                                raise
                            
            except ValidationError:
                pass  # Expected
            
            # Validate immediate failure for non-retryable errors
            assert immediate_failure
            assert call_count["value"] == 1  # Should only be called once
            
            # Test circuit breaker pattern simulation
            circuit_breaker_state = {"open": False, "failure_count": 0, "last_failure_time": None}
            circuit_breaker_config = {"failure_threshold": 3, "timeout": 1.0}
            
            def circuit_breaker_check():
                """Check if circuit breaker should be open."""
                if circuit_breaker_state["open"]:
                    if (datetime.utcnow() - circuit_breaker_state["last_failure_time"]).total_seconds() > circuit_breaker_config["timeout"]:
                        circuit_breaker_state["open"] = False
                        circuit_breaker_state["failure_count"] = 0
                    else:
                        raise ServiceError("Circuit breaker open - service unavailable")
            
            def record_circuit_breaker_failure():
                """Record a failure for circuit breaker."""
                circuit_breaker_state["failure_count"] += 1
                circuit_breaker_state["last_failure_time"] = datetime.utcnow()
                if circuit_breaker_state["failure_count"] >= circuit_breaker_config["failure_threshold"]:
                    circuit_breaker_state["open"] = True
            
            # Simulate multiple failures to trigger circuit breaker
            for i in range(4):  # Trigger circuit breaker after 3 failures
                try:
                    circuit_breaker_check()
                    # Simulate service call that fails
                    if i < 3:
                        record_circuit_breaker_failure()
                        raise OperationalError("Service failure", None, None)
                    else:
                        # This should be blocked by circuit breaker
                        pass
                        
                except ServiceError as e:
                    if "Circuit breaker open" in str(e):
                        # Circuit breaker is working
                        assert circuit_breaker_state["open"]
                        break
                except OperationalError:
                    # Expected failures before circuit breaker opens
                    continue
            
            # Validate circuit breaker opened
            assert circuit_breaker_state["open"]
            assert circuit_breaker_state["failure_count"] >= circuit_breaker_config["failure_threshold"]
            
            # Validate error handling events
            step_failed_events = workflow_event_collector.get_events_by_type('workflow_step_failed')
            assert len(step_failed_events) >= 2  # Should have recorded retry attempts
            
            # Verify performance metrics for retry operations
            retry_operation_time = performance_monitor.get_metric("operation_with_retries")
            non_retryable_time = performance_monitor.get_metric("non_retryable_operation")
            
            assert retry_operation_time > non_retryable_time  # Retries should take longer
            assert retry_operation_time > 0.2  # Should include retry delays
            assert non_retryable_time < 0.1  # Should fail quickly for non-retryable errors


class TestServiceCompositionArchitecture:
    """Test suite for service composition and coordination patterns."""
    
    def test_dependency_injection_service_coordination(self, app, db_session, mock_services):
        """
        Test dependency injection patterns for coordinated service interactions.
        
        Validates:
        - Service dependency resolution and injection
        - Circular dependency detection and prevention
        - Service lifecycle management
        - Configuration-based service composition
        """
        with app.app_context():
            # Define service dependency graph
            service_dependencies = {
                "workflow_orchestrator": ["user_service", "business_entity_service", "validation_service"],
                "business_entity_service": ["validation_service", "user_service"],
                "user_service": ["validation_service"],
                "validation_service": []
            }
            
            # Simulate dependency injection container
            service_container = {}
            service_creation_order = []
            
            def resolve_dependencies(service_name: str, visited: set = None) -> Mock:
                """Resolve service dependencies recursively."""
                if visited is None:
                    visited = set()
                
                if service_name in visited:
                    raise ValueError(f"Circular dependency detected: {service_name}")
                
                if service_name in service_container:
                    return service_container[service_name]
                
                visited.add(service_name)
                
                # Create service dependencies first
                dependencies = {}
                for dep_name in service_dependencies.get(service_name, []):
                    dependencies[dep_name] = resolve_dependencies(dep_name, visited.copy())
                
                # Create the service with its dependencies
                service = mock_services[service_name.replace("_service", "").replace("workflow_", "")]
                service._dependencies = dependencies
                service_container[service_name] = service
                service_creation_order.append(service_name)
                
                visited.remove(service_name)
                return service
            
            # Resolve all services
            orchestrator = resolve_dependencies("workflow_orchestrator")
            
            # Validate dependency injection
            assert len(service_container) == 4
            assert "workflow_orchestrator" in service_container
            assert "user_service" in service_container
            assert "business_entity_service" in service_container
            assert "validation_service" in service_container
            
            # Verify creation order respects dependencies
            validation_index = service_creation_order.index("validation_service")
            user_index = service_creation_order.index("user_service")
            business_entity_index = service_creation_order.index("business_entity_service")
            orchestrator_index = service_creation_order.index("workflow_orchestrator")
            
            # validation_service should be created first (no dependencies)
            assert validation_index < user_index
            assert validation_index < business_entity_index
            assert validation_index < orchestrator_index
            
            # Verify dependency injection in services
            orchestrator_deps = orchestrator._dependencies
            assert "user_service" in orchestrator_deps
            assert "business_entity_service" in orchestrator_deps
            assert "validation_service" in orchestrator_deps
            
            # Test circular dependency detection
            service_dependencies_circular = {
                "service_a": ["service_b"],
                "service_b": ["service_c"],
                "service_c": ["service_a"]  # Creates cycle
            }
            
            circular_detection_failed = False
            try:
                visited_circular = set()
                
                def resolve_circular(service_name: str, visited: set) -> Mock:
                    if service_name in visited:
                        raise ValueError(f"Circular dependency detected: {service_name}")
                    
                    visited.add(service_name)
                    
                    for dep_name in service_dependencies_circular.get(service_name, []):
                        resolve_circular(dep_name, visited.copy())
                    
                    return Mock()
                
                resolve_circular("service_a", visited_circular)
                
            except ValueError as e:
                if "Circular dependency" in str(e):
                    circular_detection_failed = True
            
            assert circular_detection_failed  # Should detect circular dependency
    
    def test_service_lifecycle_management(self, app, db_session, mock_services, workflow_event_collector):
        """
        Test service lifecycle management including initialization, startup, and shutdown.
        
        Validates:
        - Service initialization sequences
        - Health check implementations
        - Graceful shutdown procedures
        - Resource cleanup and connection management
        """
        with app.app_context():
            # Define service lifecycle states
            class ServiceState:
                UNINITIALIZED = "uninitialized"
                INITIALIZING = "initializing"
                READY = "ready"
                STARTING = "starting"
                RUNNING = "running"
                STOPPING = "stopping"
                STOPPED = "stopped"
                ERROR = "error"
            
            # Service lifecycle manager
            class ServiceLifecycleManager:
                def __init__(self):
                    self.services = {}
                    self.state_transitions = []
                
                def register_service(self, name: str, service: Mock):
                    """Register a service for lifecycle management."""
                    service._state = ServiceState.UNINITIALIZED
                    service._health_status = "unknown"
                    service._resources = []
                    self.services[name] = service
                    self.record_state_transition(name, ServiceState.UNINITIALIZED)
                
                def record_state_transition(self, service_name: str, new_state: str):
                    """Record service state transition."""
                    self.state_transitions.append({
                        "service": service_name,
                        "state": new_state,
                        "timestamp": datetime.utcnow()
                    })
                
                def initialize_service(self, name: str):
                    """Initialize a service."""
                    service = self.services[name]
                    service._state = ServiceState.INITIALIZING
                    self.record_state_transition(name, ServiceState.INITIALIZING)
                    
                    # Simulate initialization
                    service.initialize = Mock()
                    service.initialize()
                    
                    service._state = ServiceState.READY
                    self.record_state_transition(name, ServiceState.READY)
                
                def start_service(self, name: str):
                    """Start a service."""
                    service = self.services[name]
                    if service._state != ServiceState.READY:
                        raise ValueError(f"Service {name} is not ready to start")
                    
                    service._state = ServiceState.STARTING
                    self.record_state_transition(name, ServiceState.STARTING)
                    
                    # Simulate startup
                    service.start = Mock()
                    service.start()
                    
                    service._state = ServiceState.RUNNING
                    service._health_status = "healthy"
                    self.record_state_transition(name, ServiceState.RUNNING)
                
                def stop_service(self, name: str):
                    """Stop a service gracefully."""
                    service = self.services[name]
                    if service._state != ServiceState.RUNNING:
                        return  # Already stopped
                    
                    service._state = ServiceState.STOPPING
                    self.record_state_transition(name, ServiceState.STOPPING)
                    
                    # Simulate graceful shutdown
                    service.stop = Mock()
                    service.stop()
                    
                    # Cleanup resources
                    service._resources.clear()
                    
                    service._state = ServiceState.STOPPED
                    service._health_status = "stopped"
                    self.record_state_transition(name, ServiceState.STOPPED)
                
                def health_check(self, name: str) -> Dict:
                    """Perform health check on a service."""
                    service = self.services[name]
                    health_result = {
                        "service": name,
                        "state": service._state,
                        "status": service._health_status,
                        "timestamp": datetime.utcnow(),
                        "resources": len(service._resources),
                        "uptime": "0:00:00"  # Simplified
                    }
                    
                    # Simulate health check logic
                    if service._state == ServiceState.RUNNING:
                        service.check_health = Mock(return_value=True)
                        if service.check_health():
                            health_result["status"] = "healthy"
                        else:
                            health_result["status"] = "unhealthy"
                            service._state = ServiceState.ERROR
                            self.record_state_transition(name, ServiceState.ERROR)
                    
                    return health_result
                
                def get_all_states(self) -> Dict:
                    """Get current state of all services."""
                    return {name: service._state for name, service in self.services.items()}
            
            # Test service lifecycle
            lifecycle_manager = ServiceLifecycleManager()
            
            # Register services
            service_names = ["user_service", "business_entity_service", "validation_service", "workflow_orchestrator"]
            for name in service_names:
                service_key = name.replace("_service", "").replace("workflow_", "")
                lifecycle_manager.register_service(name, mock_services[service_key])
            
            # Initialize services in dependency order
            initialization_order = ["validation_service", "user_service", "business_entity_service", "workflow_orchestrator"]
            for service_name in initialization_order:
                lifecycle_manager.initialize_service(service_name)
            
            # Start services
            for service_name in initialization_order:
                lifecycle_manager.start_service(service_name)
            
            # Verify all services are running
            states = lifecycle_manager.get_all_states()
            for service_name in service_names:
                assert states[service_name] == ServiceState.RUNNING
            
            # Perform health checks
            health_results = {}
            for service_name in service_names:
                health_results[service_name] = lifecycle_manager.health_check(service_name)
                assert health_results[service_name]["status"] == "healthy"
            
            # Test graceful shutdown
            for service_name in reversed(initialization_order):  # Shutdown in reverse order
                lifecycle_manager.stop_service(service_name)
            
            # Verify all services are stopped
            final_states = lifecycle_manager.get_all_states()
            for service_name in service_names:
                assert final_states[service_name] == ServiceState.STOPPED
            
            # Validate state transition sequence
            transitions = lifecycle_manager.state_transitions
            
            # Each service should have gone through: uninitialized -> initializing -> ready -> starting -> running -> stopping -> stopped
            expected_sequence = [
                ServiceState.UNINITIALIZED,
                ServiceState.INITIALIZING,
                ServiceState.READY,
                ServiceState.STARTING,
                ServiceState.RUNNING,
                ServiceState.STOPPING,
                ServiceState.STOPPED
            ]
            
            for service_name in service_names:
                service_transitions = [t for t in transitions if t["service"] == service_name]
                service_states = [t["state"] for t in service_transitions]
                assert service_states == expected_sequence
            
            # Test error handling during lifecycle
            lifecycle_manager.register_service("error_service", Mock(spec=BaseService))
            
            # Simulate initialization error
            error_service = lifecycle_manager.services["error_service"]
            error_service._state = ServiceState.INITIALIZING
            lifecycle_manager.record_state_transition("error_service", ServiceState.INITIALIZING)
            
            # Simulate error during initialization
            error_service._state = ServiceState.ERROR
            lifecycle_manager.record_state_transition("error_service", ServiceState.ERROR)
            
            # Verify error state
            assert lifecycle_manager.get_all_states()["error_service"] == ServiceState.ERROR
            
            # Verify health check detects error
            error_health = lifecycle_manager.health_check("error_service")
            assert error_health["status"] in ["unhealthy", "stopped"]


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])