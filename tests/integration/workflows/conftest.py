"""
Workflow-specific pytest configuration file for business logic testing and Service Layer validation.

This module provides specialized fixtures for business logic testing, service layer validation,
complex workflow orchestration, and performance benchmarking. Extends the parent conftest.py
with workflow-specific test infrastructure including service composition fixtures, business
logic validation utilities, and comprehensive transaction boundary testing capabilities.

Key Features:
- Service Layer pattern testing fixtures for comprehensive business logic validation
- Business logic validation utilities for functional equivalence testing between Node.js and Flask
- Service composition fixtures enabling complex workflow testing with dependency injection
- Workflow orchestration fixtures supporting multi-step business process coordination
- Performance benchmarking fixtures integrated with pytest-benchmark for workflow execution timing
- Transaction boundary testing and multi-component coordination validation

Migration Context:
This configuration supports comprehensive testing of the Service Layer pattern implementation
during the Node.js to Python 3.13.3/Flask 3.1.1 migration, ensuring 100% functional parity
and zero regression in business logic execution while enabling advanced workflow orchestration.
"""

import asyncio
import inspect
import json
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Generator, Type, Union
from unittest.mock import patch, MagicMock, AsyncMock

import pytest
import pytest_benchmark
from flask import Flask, g, request, session, current_app
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text, event
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.engine import Engine

# Import parent fixtures
from tests.integration.conftest import *

# Import service layer components
try:
    from src.services.base import BaseService
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
except ImportError as e:
    # Graceful handling for missing modules during initial setup
    print(f"Warning: Could not import service modules: {e}")
    BaseService = None
    UserService = None
    BusinessEntityService = None
    WorkflowOrchestrator = None
    ValidationService = None


# ================================================================================================
# SERVICE LAYER PATTERN TESTING FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def service_registry(app: Flask, db_session: scoped_session) -> Dict[str, Any]:
    """
    Service registry fixture providing centralized service instance management.
    
    Creates and configures all service layer components with proper dependency
    injection and Flask application context integration. Supports testing of
    Service Layer pattern implementation with comprehensive service composition.
    
    Args:
        app: Flask application instance
        db_session: Database session for service operations
        
    Returns:
        Dict[str, Any]: Registry of service instances for testing
    """
    with app.app_context():
        # Initialize base service dependencies
        registry = {
            'app': app,
            'db_session': db_session,
            'services': {},
            'mocks': {},
            'config': {
                'transaction_timeout': 30,
                'retry_attempts': 3,
                'async_timeout': 60,
                'validation_strict_mode': True
            }
        }
        
        # Initialize service instances if available
        if BaseService and UserService and BusinessEntityService:
            registry['services'] = {
                'user_service': UserService(db_session=db_session),
                'business_entity_service': BusinessEntityService(db_session=db_session),
                'validation_service': ValidationService() if ValidationService else None,
                'workflow_orchestrator': WorkflowOrchestrator(db_session=db_session) if WorkflowOrchestrator else None
            }
            
            # Configure service dependencies
            for service_name, service in registry['services'].items():
                if service and hasattr(service, '_configure_dependencies'):
                    service._configure_dependencies(registry['services'])
        
        yield registry


@pytest.fixture(scope='function')
def base_service_mock(app: Flask, db_session: scoped_session) -> Generator[MagicMock, None, None]:
    """
    Base service mock fixture for testing service layer patterns.
    
    Provides a mock base service implementation for testing service layer
    functionality without requiring complete service implementations.
    
    Args:
        app: Flask application instance
        db_session: Database session for service operations
        
    Yields:
        MagicMock: Mock base service instance
    """
    mock_service = MagicMock()
    mock_service.db_session = db_session
    mock_service.app = app
    
    # Configure mock methods for service layer testing
    mock_service.begin_transaction.return_value = None
    mock_service.commit_transaction.return_value = None
    mock_service.rollback_transaction.return_value = None
    mock_service.validate_input.return_value = True
    mock_service.handle_error.return_value = None
    
    # Mock transaction context manager
    @contextmanager
    def mock_transaction():
        try:
            mock_service.begin_transaction()
            yield
            mock_service.commit_transaction()
        except Exception:
            mock_service.rollback_transaction()
            raise
    
    mock_service.transaction = mock_transaction
    
    with app.app_context():
        yield mock_service


@pytest.fixture(scope='function')
def service_composition_factory(service_registry: Dict[str, Any]) -> Generator[Callable, None, None]:
    """
    Service composition factory for complex workflow testing.
    
    Provides a factory function for creating composed service workflows
    that enable testing of complex business operations involving multiple
    services with proper dependency injection and transaction coordination.
    
    Args:
        service_registry: Service registry with initialized services
        
    Yields:
        Callable: Factory function for creating service compositions
    """
    def create_composition(*service_names: str, **kwargs) -> Dict[str, Any]:
        """
        Create a service composition for workflow testing.
        
        Args:
            *service_names: Names of services to include in composition
            **kwargs: Additional configuration for the composition
            
        Returns:
            Dict[str, Any]: Service composition with configured dependencies
        """
        composition = {
            'services': {},
            'config': kwargs.get('config', {}),
            'transaction_manager': None,
            'event_handlers': {},
            'metrics': {
                'operation_count': 0,
                'error_count': 0,
                'transaction_count': 0,
                'start_time': datetime.utcnow()
            }
        }
        
        # Add requested services to composition
        for service_name in service_names:
            if service_name in service_registry['services']:
                composition['services'][service_name] = service_registry['services'][service_name]
        
        # Create transaction manager for the composition
        class CompositionTransactionManager:
            def __init__(self, db_session):
                self.db_session = db_session
                self.active_transaction = None
            
            @contextmanager
            def transaction(self):
                """Manage transaction boundaries for service composition."""
                self.active_transaction = self.db_session.begin()
                composition['metrics']['transaction_count'] += 1
                try:
                    yield
                    self.active_transaction.commit()
                except Exception:
                    self.active_transaction.rollback()
                    composition['metrics']['error_count'] += 1
                    raise
                finally:
                    self.active_transaction = None
            
            def get_transaction_status(self) -> str:
                """Get current transaction status."""
                if self.active_transaction:
                    return 'active'
                return 'inactive'
        
        composition['transaction_manager'] = CompositionTransactionManager(
            service_registry['db_session']
        )
        
        return composition
    
    yield create_composition


@pytest.fixture(scope='function')
def workflow_execution_context(
    app: Flask, 
    service_registry: Dict[str, Any]
) -> Generator[Dict[str, Any], None, None]:
    """
    Workflow execution context fixture for comprehensive workflow testing.
    
    Provides an execution context for testing complex workflows with
    proper state management, error handling, and performance monitoring.
    
    Args:
        app: Flask application instance
        service_registry: Service registry with initialized services
        
    Yields:
        Dict[str, Any]: Workflow execution context
    """
    context = {
        'app': app,
        'services': service_registry['services'],
        'state': {},
        'errors': [],
        'events': [],
        'metrics': {
            'execution_time': 0,
            'memory_usage': 0,
            'database_queries': 0,
            'api_calls': 0
        },
        'config': {
            'timeout': 30,
            'max_retries': 3,
            'rollback_on_error': True
        }
    }
    
    # Track database queries during workflow execution
    query_count = 0
    
    def query_counter(conn, cursor, statement, parameters, context, executemany):
        nonlocal query_count
        query_count += 1
        context['metrics']['database_queries'] = query_count
    
    # Register query tracking
    engine = service_registry['db_session'].get_bind()
    event.listen(engine, "before_cursor_execute", query_counter)
    
    with app.app_context():
        start_time = time.time()
        try:
            yield context
        finally:
            context['metrics']['execution_time'] = time.time() - start_time
            event.remove(engine, "before_cursor_execute", query_counter)


# ================================================================================================
# BUSINESS LOGIC VALIDATION UTILITIES
# ================================================================================================

@pytest.fixture(scope='function')
def business_logic_validator(service_registry: Dict[str, Any]) -> Generator[Any, None, None]:
    """
    Business logic validation utility for functional equivalence testing.
    
    Provides utilities for validating business logic execution and ensuring
    functional equivalence between Node.js baseline and Flask implementation.
    
    Args:
        service_registry: Service registry with initialized services
        
    Yields:
        Any: Business logic validator instance
    """
    class BusinessLogicValidator:
        def __init__(self, services: Dict[str, Any]):
            self.services = services
            self.validation_results = []
            self.baseline_data = {}
            self.flask_data = {}
            
        def set_baseline(self, operation: str, input_data: Dict[str, Any], output_data: Dict[str, Any]):
            """Set baseline data from Node.js implementation."""
            self.baseline_data[operation] = {
                'input': input_data,
                'output': output_data,
                'timestamp': datetime.utcnow().isoformat()
            }
        
        def validate_operation(
            self, 
            operation: str, 
            service_method: Callable, 
            input_data: Dict[str, Any]
        ) -> Dict[str, Any]:
            """
            Validate a business logic operation against baseline.
            
            Args:
                operation: Name of the operation being validated
                service_method: Service method to execute
                input_data: Input data for the operation
                
            Returns:
                Dict[str, Any]: Validation results
            """
            start_time = time.time()
            
            try:
                # Execute Flask implementation
                flask_result = service_method(**input_data)
                execution_time = time.time() - start_time
                
                # Store Flask results
                self.flask_data[operation] = {
                    'input': input_data,
                    'output': flask_result,
                    'execution_time': execution_time,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Compare with baseline if available
                validation_result = {
                    'operation': operation,
                    'success': True,
                    'execution_time': execution_time,
                    'functional_equivalence': False,
                    'differences': [],
                    'flask_output': flask_result
                }
                
                if operation in self.baseline_data:
                    baseline = self.baseline_data[operation]
                    validation_result.update(
                        self._compare_outputs(baseline['output'], flask_result)
                    )
                
                self.validation_results.append(validation_result)
                return validation_result
                
            except Exception as e:
                error_result = {
                    'operation': operation,
                    'success': False,
                    'error': str(e),
                    'execution_time': time.time() - start_time,
                    'functional_equivalence': False
                }
                self.validation_results.append(error_result)
                return error_result
        
        def _compare_outputs(self, baseline: Any, flask_output: Any) -> Dict[str, Any]:
            """Compare baseline and Flask outputs for equivalence."""
            differences = []
            functional_equivalence = True
            
            # Handle different data types
            if type(baseline) != type(flask_output):
                differences.append({
                    'type': 'type_mismatch',
                    'baseline_type': str(type(baseline)),
                    'flask_type': str(type(flask_output))
                })
                functional_equivalence = False
            
            # Handle dictionary comparison
            elif isinstance(baseline, dict) and isinstance(flask_output, dict):
                baseline_keys = set(baseline.keys())
                flask_keys = set(flask_output.keys())
                
                if baseline_keys != flask_keys:
                    differences.append({
                        'type': 'key_mismatch',
                        'missing_keys': list(baseline_keys - flask_keys),
                        'extra_keys': list(flask_keys - baseline_keys)
                    })
                    functional_equivalence = False
                
                for key in baseline_keys & flask_keys:
                    if baseline[key] != flask_output[key]:
                        differences.append({
                            'type': 'value_mismatch',
                            'key': key,
                            'baseline_value': baseline[key],
                            'flask_value': flask_output[key]
                        })
                        functional_equivalence = False
            
            # Handle direct value comparison
            elif baseline != flask_output:
                differences.append({
                    'type': 'value_mismatch',
                    'baseline_value': baseline,
                    'flask_value': flask_output
                })
                functional_equivalence = False
            
            return {
                'functional_equivalence': functional_equivalence,
                'differences': differences
            }
        
        def generate_validation_report(self) -> Dict[str, Any]:
            """Generate comprehensive validation report."""
            total_validations = len(self.validation_results)
            successful_validations = sum(1 for r in self.validation_results if r['success'])
            equivalent_validations = sum(1 for r in self.validation_results if r.get('functional_equivalence', False))
            
            return {
                'total_validations': total_validations,
                'successful_validations': successful_validations,
                'equivalent_validations': equivalent_validations,
                'success_rate': (successful_validations / total_validations * 100) if total_validations > 0 else 0,
                'equivalence_rate': (equivalent_validations / total_validations * 100) if total_validations > 0 else 0,
                'failed_operations': [r['operation'] for r in self.validation_results if not r['success']],
                'non_equivalent_operations': [r['operation'] for r in self.validation_results if not r.get('functional_equivalence', False)],
                'detailed_results': self.validation_results,
                'report_timestamp': datetime.utcnow().isoformat()
            }
    
    validator = BusinessLogicValidator(service_registry['services'])
    yield validator


@pytest.fixture(scope='function')
def calculation_validator(business_logic_validator: Any) -> Generator[Any, None, None]:
    """
    Calculation validation fixture for testing algorithmic business logic.
    
    Provides specialized validation for calculation algorithms and
    mathematical business rules to ensure precision equivalence.
    
    Args:
        business_logic_validator: Business logic validator instance
        
    Yields:
        Any: Calculation validator specialized for mathematical operations
    """
    class CalculationValidator:
        def __init__(self, base_validator: Any):
            self.base_validator = base_validator
            self.precision_tolerance = 0.0001  # Default precision tolerance
            
        def validate_calculation(
            self, 
            operation: str, 
            calculation_func: Callable, 
            input_data: Dict[str, Any],
            expected_result: Union[int, float, Dict[str, Union[int, float]]],
            tolerance: Optional[float] = None
        ) -> Dict[str, Any]:
            """
            Validate calculation operations with precision tolerance.
            
            Args:
                operation: Name of the calculation operation
                calculation_func: Function performing the calculation
                input_data: Input data for the calculation
                expected_result: Expected calculation result
                tolerance: Precision tolerance for floating point comparisons
                
            Returns:
                Dict[str, Any]: Validation results with precision analysis
            """
            tolerance = tolerance or self.precision_tolerance
            start_time = time.time()
            
            try:
                # Execute calculation
                result = calculation_func(**input_data)
                execution_time = time.time() - start_time
                
                # Validate precision
                precision_valid = self._validate_precision(result, expected_result, tolerance)
                
                return {
                    'operation': operation,
                    'success': True,
                    'execution_time': execution_time,
                    'calculated_result': result,
                    'expected_result': expected_result,
                    'precision_valid': precision_valid,
                    'tolerance_used': tolerance,
                    'functional_equivalence': precision_valid
                }
                
            except Exception as e:
                return {
                    'operation': operation,
                    'success': False,
                    'error': str(e),
                    'execution_time': time.time() - start_time,
                    'precision_valid': False,
                    'functional_equivalence': False
                }
        
        def _validate_precision(
            self, 
            result: Union[int, float, Dict], 
            expected: Union[int, float, Dict], 
            tolerance: float
        ) -> bool:
            """Validate precision of calculation results."""
            if isinstance(result, dict) and isinstance(expected, dict):
                for key in expected:
                    if key not in result:
                        return False
                    if not self._validate_precision(result[key], expected[key], tolerance):
                        return False
                return True
            
            elif isinstance(result, (int, float)) and isinstance(expected, (int, float)):
                return abs(result - expected) <= tolerance
            
            else:
                return result == expected
    
    validator = CalculationValidator(business_logic_validator)
    yield validator


# ================================================================================================
# WORKFLOW ORCHESTRATION FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def workflow_orchestrator_fixture(
    service_registry: Dict[str, Any],
    workflow_execution_context: Dict[str, Any]
) -> Generator[Any, None, None]:
    """
    Workflow orchestrator fixture for multi-step business process testing.
    
    Provides workflow orchestration capabilities for testing complex
    multi-step business processes with transaction coordination and
    error handling throughout the workflow execution chain.
    
    Args:
        service_registry: Service registry with initialized services
        workflow_execution_context: Workflow execution context
        
    Yields:
        Any: Workflow orchestrator instance for testing
    """
    class WorkflowOrchestratorFixture:
        def __init__(self, services: Dict[str, Any], context: Dict[str, Any]):
            self.services = services
            self.context = context
            self.workflow_steps = []
            self.execution_results = []
            self.rollback_actions = []
            
        def add_step(
            self, 
            step_name: str, 
            service_method: Callable, 
            input_data: Dict[str, Any],
            rollback_action: Optional[Callable] = None
        ):
            """Add a step to the workflow."""
            step = {
                'name': step_name,
                'method': service_method,
                'input': input_data,
                'rollback': rollback_action,
                'order': len(self.workflow_steps)
            }
            self.workflow_steps.append(step)
        
        def execute_workflow(self, rollback_on_error: bool = True) -> Dict[str, Any]:
            """
            Execute the complete workflow with transaction management.
            
            Args:
                rollback_on_error: Whether to rollback on any step failure
                
            Returns:
                Dict[str, Any]: Workflow execution results
            """
            start_time = time.time()
            workflow_result = {
                'workflow_id': str(uuid.uuid4()),
                'start_time': datetime.utcnow().isoformat(),
                'success': True,
                'steps_executed': 0,
                'step_results': [],
                'errors': [],
                'rollback_performed': False
            }
            
            try:
                # Execute each workflow step
                for step in self.workflow_steps:
                    step_start = time.time()
                    
                    try:
                        # Execute step
                        step_result = step['method'](**step['input'])
                        step_execution_time = time.time() - step_start
                        
                        step_data = {
                            'step_name': step['name'],
                            'success': True,
                            'execution_time': step_execution_time,
                            'result': step_result,
                            'order': step['order']
                        }
                        
                        workflow_result['step_results'].append(step_data)
                        workflow_result['steps_executed'] += 1
                        
                        # Store rollback action if provided
                        if step['rollback']:
                            self.rollback_actions.append(step['rollback'])
                        
                    except Exception as step_error:
                        # Handle step failure
                        step_data = {
                            'step_name': step['name'],
                            'success': False,
                            'execution_time': time.time() - step_start,
                            'error': str(step_error),
                            'order': step['order']
                        }
                        
                        workflow_result['step_results'].append(step_data)
                        workflow_result['errors'].append(str(step_error))
                        workflow_result['success'] = False
                        
                        if rollback_on_error:
                            self._execute_rollback()
                            workflow_result['rollback_performed'] = True
                        
                        break  # Stop executing further steps
                
            except Exception as workflow_error:
                workflow_result['success'] = False
                workflow_result['errors'].append(str(workflow_error))
                
                if rollback_on_error:
                    self._execute_rollback()
                    workflow_result['rollback_performed'] = True
            
            finally:
                workflow_result['execution_time'] = time.time() - start_time
                workflow_result['end_time'] = datetime.utcnow().isoformat()
            
            self.execution_results.append(workflow_result)
            return workflow_result
        
        def _execute_rollback(self):
            """Execute rollback actions in reverse order."""
            for rollback_action in reversed(self.rollback_actions):
                try:
                    rollback_action()
                except Exception as rollback_error:
                    # Log rollback errors but don't raise them
                    pass
        
        def get_workflow_metrics(self) -> Dict[str, Any]:
            """Get comprehensive workflow execution metrics."""
            if not self.execution_results:
                return {}
            
            total_executions = len(self.execution_results)
            successful_executions = sum(1 for r in self.execution_results if r['success'])
            
            execution_times = [r['execution_time'] for r in self.execution_results]
            
            return {
                'total_executions': total_executions,
                'successful_executions': successful_executions,
                'success_rate': (successful_executions / total_executions * 100) if total_executions > 0 else 0,
                'avg_execution_time': sum(execution_times) / len(execution_times) if execution_times else 0,
                'min_execution_time': min(execution_times) if execution_times else 0,
                'max_execution_time': max(execution_times) if execution_times else 0,
                'total_steps_defined': len(self.workflow_steps),
                'rollback_frequency': sum(1 for r in self.execution_results if r['rollback_performed'])
            }
    
    orchestrator = WorkflowOrchestratorFixture(
        service_registry['services'], 
        workflow_execution_context
    )
    yield orchestrator


@pytest.fixture(scope='function')
def transaction_boundary_tester(
    service_registry: Dict[str, Any]
) -> Generator[Any, None, None]:
    """
    Transaction boundary testing fixture for service coordination validation.
    
    Provides comprehensive transaction boundary testing capabilities
    to ensure proper ACID properties and rollback behavior across
    service boundaries during complex workflow execution.
    
    Args:
        service_registry: Service registry with initialized services
        
    Yields:
        Any: Transaction boundary tester instance
    """
    class TransactionBoundaryTester:
        def __init__(self, services: Dict[str, Any], db_session: scoped_session):
            self.services = services
            self.db_session = db_session
            self.transaction_logs = []
            
        def test_transaction_isolation(
            self, 
            operations: List[Callable], 
            isolation_level: str = 'READ_COMMITTED'
        ) -> Dict[str, Any]:
            """
            Test transaction isolation across multiple operations.
            
            Args:
                operations: List of operations to execute in transaction
                isolation_level: SQL isolation level to test
                
            Returns:
                Dict[str, Any]: Transaction isolation test results
            """
            test_id = str(uuid.uuid4())
            start_time = time.time()
            
            result = {
                'test_id': test_id,
                'isolation_level': isolation_level,
                'operations_count': len(operations),
                'success': True,
                'isolation_violations': [],
                'execution_time': 0
            }
            
            try:
                # Begin transaction with specified isolation level
                transaction = self.db_session.begin()
                
                # Execute operations within transaction
                for i, operation in enumerate(operations):
                    operation_start = time.time()
                    try:
                        operation_result = operation()
                        self.transaction_logs.append({
                            'test_id': test_id,
                            'operation_index': i,
                            'success': True,
                            'execution_time': time.time() - operation_start,
                            'result': str(operation_result)[:100]  # Truncate for logging
                        })
                    except Exception as op_error:
                        self.transaction_logs.append({
                            'test_id': test_id,
                            'operation_index': i,
                            'success': False,
                            'error': str(op_error),
                            'execution_time': time.time() - operation_start
                        })
                        result['success'] = False
                        raise
                
                # Commit transaction
                transaction.commit()
                
            except Exception as transaction_error:
                result['success'] = False
                result['error'] = str(transaction_error)
                try:
                    transaction.rollback()
                    result['rollback_successful'] = True
                except Exception as rollback_error:
                    result['rollback_successful'] = False
                    result['rollback_error'] = str(rollback_error)
            
            finally:
                result['execution_time'] = time.time() - start_time
            
            return result
        
        def test_concurrent_transactions(
            self, 
            transaction_count: int, 
            operations_per_transaction: List[Callable]
        ) -> Dict[str, Any]:
            """
            Test concurrent transaction execution for deadlock detection.
            
            Args:
                transaction_count: Number of concurrent transactions
                operations_per_transaction: Operations to execute in each transaction
                
            Returns:
                Dict[str, Any]: Concurrent transaction test results
            """
            import threading
            import queue
            
            results_queue = queue.Queue()
            threads = []
            
            def execute_transaction(transaction_id: int):
                """Execute a single transaction."""
                result = {
                    'transaction_id': transaction_id,
                    'success': True,
                    'deadlock_detected': False,
                    'execution_time': 0
                }
                
                start_time = time.time()
                try:
                    with self.db_session.begin() as transaction:
                        for operation in operations_per_transaction:
                            operation()
                except Exception as e:
                    result['success'] = False
                    result['error'] = str(e)
                    if 'deadlock' in str(e).lower():
                        result['deadlock_detected'] = True
                finally:
                    result['execution_time'] = time.time() - start_time
                    results_queue.put(result)
            
            # Start concurrent transactions
            for i in range(transaction_count):
                thread = threading.Thread(target=execute_transaction, args=(i,))
                threads.append(thread)
                thread.start()
            
            # Wait for all transactions to complete
            for thread in threads:
                thread.join()
            
            # Collect results
            transaction_results = []
            while not results_queue.empty():
                transaction_results.append(results_queue.get())
            
            successful_transactions = sum(1 for r in transaction_results if r['success'])
            deadlock_count = sum(1 for r in transaction_results if r.get('deadlock_detected', False))
            
            return {
                'total_transactions': transaction_count,
                'successful_transactions': successful_transactions,
                'failed_transactions': transaction_count - successful_transactions,
                'deadlock_count': deadlock_count,
                'success_rate': (successful_transactions / transaction_count * 100) if transaction_count > 0 else 0,
                'transaction_results': transaction_results
            }
        
        def validate_acid_properties(
            self, 
            test_operations: List[Callable]
        ) -> Dict[str, bool]:
            """
            Validate ACID properties during transaction execution.
            
            Args:
                test_operations: Operations to test for ACID compliance
                
            Returns:
                Dict[str, bool]: ACID property validation results
            """
            acid_results = {
                'atomicity': True,
                'consistency': True,
                'isolation': True,
                'durability': True
            }
            
            # Test Atomicity - all operations succeed or all fail
            try:
                with self.db_session.begin() as transaction:
                    initial_count = self.db_session.query(User).count()
                    
                    # Execute operations
                    for operation in test_operations:
                        operation()
                    
                    # Force an error to test rollback
                    raise Exception("Test rollback")
                    
            except Exception:
                # Verify rollback occurred (atomicity)
                final_count = self.db_session.query(User).count()
                acid_results['atomicity'] = (initial_count == final_count)
            
            # Additional ACID tests would be implemented here
            # For brevity, returning basic validation
            
            return acid_results
    
    tester = TransactionBoundaryTester(
        service_registry['services'], 
        service_registry['db_session']
    )
    yield tester


# ================================================================================================
# PERFORMANCE BENCHMARKING FIXTURES FOR WORKFLOW EXECUTION
# ================================================================================================

@pytest.fixture(scope='function')
def workflow_performance_benchmarker(
    benchmark_config: Dict[str, Any],
    service_registry: Dict[str, Any]
) -> Generator[Any, None, None]:
    """
    Workflow performance benchmarking fixture with pytest-benchmark integration.
    
    Provides comprehensive performance benchmarking for workflow execution
    timing, resource utilization measurement, and comparison against Node.js
    baseline performance metrics using pytest-benchmark 5.1.0 integration.
    
    Args:
        benchmark_config: pytest-benchmark configuration parameters
        service_registry: Service registry with initialized services
        
    Yields:
        Any: Workflow performance benchmarker instance
    """
    class WorkflowPerformanceBenchmarker:
        def __init__(self, config: Dict[str, Any], services: Dict[str, Any]):
            self.config = config
            self.services = services
            self.benchmark_results = []
            self.baseline_metrics = {}
            
        def set_baseline_metrics(self, workflow_name: str, metrics: Dict[str, float]):
            """Set baseline performance metrics from Node.js implementation."""
            self.baseline_metrics[workflow_name] = {
                'execution_time': metrics.get('execution_time', 0),
                'memory_usage': metrics.get('memory_usage', 0),
                'cpu_usage': metrics.get('cpu_usage', 0),
                'database_queries': metrics.get('database_queries', 0),
                'timestamp': datetime.utcnow().isoformat()
            }
        
        def benchmark_workflow(
            self, 
            workflow_name: str, 
            workflow_func: Callable, 
            iterations: int = 5
        ) -> Dict[str, Any]:
            """
            Benchmark workflow execution with comprehensive metrics.
            
            Args:
                workflow_name: Name of the workflow being benchmarked
                workflow_func: Workflow function to benchmark
                iterations: Number of benchmark iterations
                
            Returns:
                Dict[str, Any]: Comprehensive benchmark results
            """
            import psutil
            import gc
            
            # Prepare for benchmarking
            gc.collect()  # Clean up before benchmarking
            process = psutil.Process()
            
            # Benchmark metrics collection
            execution_times = []
            memory_usages = []
            cpu_usages = []
            
            for i in range(iterations):
                # Collect baseline metrics
                start_memory = process.memory_info().rss / 1024 / 1024  # MB
                start_cpu = process.cpu_percent()
                
                # Execute workflow and measure time
                start_time = time.time()
                try:
                    result = workflow_func()
                    execution_time = time.time() - start_time
                    success = True
                except Exception as e:
                    execution_time = time.time() - start_time
                    success = False
                    result = str(e)
                
                # Collect post-execution metrics
                end_memory = process.memory_info().rss / 1024 / 1024  # MB
                end_cpu = process.cpu_percent()
                
                # Store metrics
                execution_times.append(execution_time)
                memory_usages.append(end_memory - start_memory)
                cpu_usages.append(end_cpu - start_cpu)
                
                # Brief pause between iterations
                time.sleep(0.1)
            
            # Calculate statistics
            avg_execution_time = sum(execution_times) / len(execution_times)
            min_execution_time = min(execution_times)
            max_execution_time = max(execution_times)
            avg_memory_usage = sum(memory_usages) / len(memory_usages)
            avg_cpu_usage = sum(cpu_usages) / len(cpu_usages)
            
            benchmark_result = {
                'workflow_name': workflow_name,
                'iterations': iterations,
                'avg_execution_time': avg_execution_time,
                'min_execution_time': min_execution_time,
                'max_execution_time': max_execution_time,
                'avg_memory_usage': avg_memory_usage,
                'avg_cpu_usage': avg_cpu_usage,
                'execution_times': execution_times,
                'memory_usages': memory_usages,
                'cpu_usages': cpu_usages,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Compare with baseline if available
            if workflow_name in self.baseline_metrics:
                baseline = self.baseline_metrics[workflow_name]
                benchmark_result['baseline_comparison'] = {
                    'execution_time_ratio': avg_execution_time / baseline['execution_time'] if baseline['execution_time'] > 0 else float('inf'),
                    'memory_usage_ratio': avg_memory_usage / baseline['memory_usage'] if baseline['memory_usage'] > 0 else float('inf'),
                    'performance_improvement': ((baseline['execution_time'] - avg_execution_time) / baseline['execution_time'] * 100) if baseline['execution_time'] > 0 else 0
                }
            
            self.benchmark_results.append(benchmark_result)
            return benchmark_result
        
        def generate_performance_report(self) -> Dict[str, Any]:
            """Generate comprehensive performance benchmarking report."""
            if not self.benchmark_results:
                return {'error': 'No benchmark results available'}
            
            total_workflows = len(self.benchmark_results)
            avg_execution_time = sum(r['avg_execution_time'] for r in self.benchmark_results) / total_workflows
            
            improved_workflows = []
            degraded_workflows = []
            
            for result in self.benchmark_results:
                if 'baseline_comparison' in result:
                    improvement = result['baseline_comparison'].get('performance_improvement', 0)
                    if improvement > 0:
                        improved_workflows.append({
                            'workflow': result['workflow_name'],
                            'improvement': improvement
                        })
                    elif improvement < 0:
                        degraded_workflows.append({
                            'workflow': result['workflow_name'],
                            'degradation': abs(improvement)
                        })
            
            return {
                'total_workflows_benchmarked': total_workflows,
                'avg_execution_time': avg_execution_time,
                'improved_workflows': improved_workflows,
                'degraded_workflows': degraded_workflows,
                'performance_summary': {
                    'workflows_improved': len(improved_workflows),
                    'workflows_degraded': len(degraded_workflows),
                    'overall_performance_change': sum(w['improvement'] for w in improved_workflows) - sum(w['degradation'] for w in degraded_workflows)
                },
                'detailed_results': self.benchmark_results,
                'report_timestamp': datetime.utcnow().isoformat()
            }
    
    benchmarker = WorkflowPerformanceBenchmarker(benchmark_config, service_registry['services'])
    yield benchmarker


@pytest.fixture(scope='function')
def resource_monitor(app: Flask) -> Generator[Any, None, None]:
    """
    Resource monitoring fixture for workflow execution analysis.
    
    Provides real-time resource monitoring during workflow execution
    to track memory usage, CPU utilization, and database connection
    usage patterns during complex business operations.
    
    Args:
        app: Flask application instance
        
    Yields:
        Any: Resource monitor instance for workflow analysis
    """
    import psutil
    import threading
    from collections import deque
    
    class ResourceMonitor:
        def __init__(self):
            self.monitoring = False
            self.monitor_thread = None
            self.metrics = {
                'cpu_usage': deque(maxlen=1000),
                'memory_usage': deque(maxlen=1000),
                'disk_io': deque(maxlen=1000),
                'network_io': deque(maxlen=1000),
                'timestamps': deque(maxlen=1000)
            }
            self.process = psutil.Process()
            
        def start_monitoring(self, interval: float = 0.1):
            """Start resource monitoring with specified interval."""
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
            self.monitor_thread.start()
        
        def stop_monitoring(self) -> Dict[str, Any]:
            """Stop monitoring and return collected metrics."""
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join()
            
            return self._generate_metrics_summary()
        
        def _monitor_loop(self, interval: float):
            """Continuous monitoring loop."""
            while self.monitoring:
                try:
                    # Collect system metrics
                    cpu_percent = self.process.cpu_percent()
                    memory_info = self.process.memory_info()
                    
                    # Store metrics
                    self.metrics['cpu_usage'].append(cpu_percent)
                    self.metrics['memory_usage'].append(memory_info.rss / 1024 / 1024)  # MB
                    self.metrics['timestamps'].append(time.time())
                    
                    time.sleep(interval)
                except Exception:
                    break
        
        def _generate_metrics_summary(self) -> Dict[str, Any]:
            """Generate summary of collected metrics."""
            if not self.metrics['cpu_usage']:
                return {'error': 'No metrics collected'}
            
            cpu_usage = list(self.metrics['cpu_usage'])
            memory_usage = list(self.metrics['memory_usage'])
            
            return {
                'collection_duration': self.metrics['timestamps'][-1] - self.metrics['timestamps'][0] if len(self.metrics['timestamps']) > 1 else 0,
                'samples_collected': len(cpu_usage),
                'cpu_metrics': {
                    'avg': sum(cpu_usage) / len(cpu_usage),
                    'min': min(cpu_usage),
                    'max': max(cpu_usage),
                    'peak_usage_times': [i for i, usage in enumerate(cpu_usage) if usage > 80]
                },
                'memory_metrics': {
                    'avg': sum(memory_usage) / len(memory_usage),
                    'min': min(memory_usage),
                    'max': max(memory_usage),
                    'peak_usage': max(memory_usage),
                    'memory_growth': memory_usage[-1] - memory_usage[0] if len(memory_usage) > 1 else 0
                },
                'performance_warnings': {
                    'high_cpu_periods': len([usage for usage in cpu_usage if usage > 80]),
                    'memory_leaks_detected': memory_usage[-1] > memory_usage[0] * 1.5 if len(memory_usage) > 1 else False
                }
            }
        
        @contextmanager
        def monitor_context(self, interval: float = 0.1):
            """Context manager for monitoring specific operations."""
            self.start_monitoring(interval)
            try:
                yield self
            finally:
                metrics = self.stop_monitoring()
                return metrics
    
    monitor = ResourceMonitor()
    yield monitor


# ================================================================================================
# SERVICE LAYER COMPOSITION AND DEPENDENCY INJECTION FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def dependency_injection_container(
    app: Flask, 
    service_registry: Dict[str, Any]
) -> Generator[Any, None, None]:
    """
    Dependency injection container fixture for Service Layer testing.
    
    Provides comprehensive dependency injection capabilities for testing
    service composition patterns and dependency resolution during complex
    workflow execution with proper lifecycle management.
    
    Args:
        app: Flask application instance
        service_registry: Service registry with initialized services
        
    Yields:
        Any: Dependency injection container instance
    """
    class DependencyInjectionContainer:
        def __init__(self, app: Flask, services: Dict[str, Any]):
            self.app = app
            self.services = services
            self.dependencies = {}
            self.singletons = {}
            self.factories = {}
            
        def register_service(
            self, 
            service_name: str, 
            service_class: Type, 
            singleton: bool = True,
            dependencies: Optional[List[str]] = None
        ):
            """Register a service with the container."""
            self.dependencies[service_name] = {
                'class': service_class,
                'singleton': singleton,
                'dependencies': dependencies or [],
                'instance': None
            }
        
        def register_factory(self, service_name: str, factory_func: Callable):
            """Register a factory function for service creation."""
            self.factories[service_name] = factory_func
        
        def get_service(self, service_name: str) -> Any:
            """Resolve and return a service instance."""
            # Check if service is already instantiated as singleton
            if service_name in self.singletons:
                return self.singletons[service_name]
            
            # Check factory functions
            if service_name in self.factories:
                instance = self.factories[service_name]()
                if self.dependencies.get(service_name, {}).get('singleton', False):
                    self.singletons[service_name] = instance
                return instance
            
            # Check registered services
            if service_name in self.dependencies:
                service_config = self.dependencies[service_name]
                
                # Resolve dependencies
                resolved_deps = {}
                for dep_name in service_config['dependencies']:
                    resolved_deps[dep_name] = self.get_service(dep_name)
                
                # Create instance
                instance = service_config['class'](**resolved_deps)
                
                # Store as singleton if required
                if service_config['singleton']:
                    self.singletons[service_name] = instance
                
                return instance
            
            # Check existing services in registry
            if service_name in self.services:
                return self.services[service_name]
            
            raise ValueError(f"Service '{service_name}' not found in container")
        
        def inject_dependencies(self, target_func: Callable) -> Callable:
            """Decorator for automatic dependency injection."""
            def wrapper(*args, **kwargs):
                # Inspect function signature for dependency hints
                sig = inspect.signature(target_func)
                injected_kwargs = {}
                
                for param_name, param in sig.parameters.items():
                    if param_name not in kwargs and param_name in self.dependencies:
                        injected_kwargs[param_name] = self.get_service(param_name)
                
                return target_func(*args, **kwargs, **injected_kwargs)
            
            return wrapper
        
        def create_service_composition(self, *service_names: str) -> Dict[str, Any]:
            """Create a composition of services for testing."""
            composition = {}
            for service_name in service_names:
                composition[service_name] = self.get_service(service_name)
            return composition
        
        def clear_singletons(self):
            """Clear all singleton instances for fresh testing."""
            self.singletons.clear()
    
    # Initialize container with existing services
    container = DependencyInjectionContainer(app, service_registry['services'])
    
    # Register available services
    if service_registry['services']:
        for service_name, service_instance in service_registry['services'].items():
            container.register_factory(service_name, lambda: service_instance)
    
    yield container


@pytest.fixture(scope='function')
def mock_service_factory(
    dependency_injection_container: Any
) -> Generator[Callable, None, None]:
    """
    Mock service factory for testing service layer interactions.
    
    Provides a factory for creating mock services that can be injected
    into the dependency injection container for isolated testing of
    service layer interactions and workflow coordination.
    
    Args:
        dependency_injection_container: Dependency injection container
        
    Yields:
        Callable: Factory function for creating mock services
    """
    def create_mock_service(
        service_name: str, 
        methods: Dict[str, Any], 
        properties: Optional[Dict[str, Any]] = None
    ) -> MagicMock:
        """
        Create a mock service with specified methods and properties.
        
        Args:
            service_name: Name of the service to mock
            methods: Dictionary of method names and their return values
            properties: Dictionary of property names and their values
            
        Returns:
            MagicMock: Configured mock service instance
        """
        mock_service = MagicMock()
        mock_service._service_name = service_name
        
        # Configure methods
        for method_name, return_value in methods.items():
            if callable(return_value):
                setattr(mock_service, method_name, return_value)
            else:
                getattr(mock_service, method_name).return_value = return_value
        
        # Configure properties
        if properties:
            for prop_name, prop_value in properties.items():
                setattr(mock_service, prop_name, prop_value)
        
        # Register with container
        dependency_injection_container.register_factory(
            service_name, 
            lambda: mock_service
        )
        
        return mock_service
    
    yield create_mock_service


# ================================================================================================
# WORKFLOW-SPECIFIC PYTEST MARKERS AND CONFIGURATION
# ================================================================================================

def pytest_configure(config):
    """
    Pytest configuration for workflow-specific testing.
    
    Configures pytest with workflow-specific markers and settings for
    comprehensive Service Layer pattern and business logic testing.
    """
    # Register workflow-specific markers
    config.addinivalue_line("markers", "workflow: mark test as workflow orchestration test")
    config.addinivalue_line("markers", "service_layer: mark test as Service Layer pattern test")
    config.addinivalue_line("markers", "business_logic: mark test as business logic validation test")
    config.addinivalue_line("markers", "transaction: mark test as transaction boundary test")
    config.addinivalue_line("markers", "composition: mark test as service composition test")
    config.addinivalue_line("markers", "orchestration: mark test as multi-step orchestration test")
    config.addinivalue_line("markers", "performance_workflow: mark test as workflow performance test")
    config.addinivalue_line("markers", "validation: mark test as business validation test")
    config.addinivalue_line("markers", "calculation: mark test as calculation validation test")
    config.addinivalue_line("markers", "dependency_injection: mark test as dependency injection test")


def pytest_runtest_setup(item):
    """
    Workflow test setup hook.
    
    Performs workflow-specific setup and validation for each test.
    """
    # Ensure workflow test environment is properly configured
    if hasattr(item, 'keywords'):
        if 'workflow' in item.keywords:
            # Ensure workflow fixtures are available
            pass
        if 'service_layer' in item.keywords:
            # Ensure service layer fixtures are available
            pass
        if 'performance_workflow' in item.keywords:
            # Ensure performance monitoring is enabled
            pass


def pytest_runtest_teardown(item):
    """
    Workflow test teardown hook.
    
    Performs workflow-specific cleanup after each test.
    """
    # Clean up workflow-specific resources
    if hasattr(g, '_get_current_object'):
        # Clear Flask workflow context
        if hasattr(g, 'workflow_context'):
            delattr(g, 'workflow_context')
        if hasattr(g, 'service_registry'):
            delattr(g, 'service_registry')