"""
Workflow Orchestration Service

This service implements comprehensive workflow orchestration patterns for complex business 
process coordination across multiple services and entities. Provides advanced service 
composition architecture, transaction boundary management, and event-driven processing 
capabilities while maintaining functional equivalence with the original Node.js implementation.

Key Features:
- Advanced workflow orchestration patterns per Section 4.5.3
- Service composition architecture for complex business operations per Section 5.2.3
- Transaction boundary management with ACID properties preservation per Section 4.5.2
- Event-driven processing through Flask signals per Section 4.5.3
- Workflow retry mechanisms for resilient operation per Section 4.5.3
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union
import functools
import asyncio
from concurrent.futures import ThreadPoolExecutor

from flask import current_app, g
from flask.signals import Namespace
from blinker import signal
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from werkzeug.exceptions import BadRequest, InternalServerError

# Import database models
from ..models import User, BusinessEntity, EntityRelationship
from ..models.base import db

# Configure logging for workflow orchestration
logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """Enumeration of workflow execution statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class WorkflowStepStatus(Enum):
    """Enumeration of individual workflow step statuses."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


class TransactionIsolationLevel(Enum):
    """Database transaction isolation levels for workflow execution."""
    READ_UNCOMMITTED = "READ_UNCOMMITTED"
    READ_COMMITTED = "READ_COMMITTED"
    REPEATABLE_READ = "REPEATABLE_READ"
    SERIALIZABLE = "SERIALIZABLE"


@dataclass
class WorkflowStep:
    """
    Individual workflow step configuration with execution metadata.
    
    Implements step-level configuration for service composition patterns
    enabling complex business workflow coordination with retry logic
    and transaction boundary management.
    """
    step_id: str
    service_method: Callable
    input_data: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    retry_attempts: int = 3
    retry_delay: float = 1.0
    timeout_seconds: int = 300
    rollback_method: Optional[Callable] = None
    conditional_execution: Optional[Callable[[Dict[str, Any]], bool]] = None
    priority: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Runtime execution state
    status: WorkflowStepStatus = WorkflowStepStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    error_message: Optional[str] = None
    result_data: Optional[Any] = None
    attempt_count: int = 0


@dataclass
class WorkflowDefinition:
    """
    Complete workflow definition with steps, configuration, and metadata.
    
    Orchestrates multi-step business workflows through service composition 
    patterns with comprehensive transaction management and event coordination.
    """
    workflow_id: str
    name: str
    description: str
    steps: List[WorkflowStep]
    max_execution_time: int = 3600  # 1 hour default
    transaction_isolation: TransactionIsolationLevel = TransactionIsolationLevel.READ_COMMITTED
    enable_parallel_execution: bool = False
    rollback_on_failure: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Runtime execution state
    status: WorkflowStatus = WorkflowStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    current_step: Optional[str] = None
    error_message: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowResult:
    """
    Comprehensive workflow execution result with detailed step information.
    
    Provides complete execution metadata for workflow analysis, debugging,
    and business process optimization with transaction boundary preservation.
    """
    workflow_id: str
    status: WorkflowStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    execution_time: Optional[float] = None
    steps_executed: int = 0
    steps_successful: int = 0
    steps_failed: int = 0
    final_result: Optional[Any] = None
    error_details: Optional[Dict[str, Any]] = None
    step_results: Dict[str, Any] = field(default_factory=dict)
    transaction_rollback_performed: bool = False
    retry_attempts_total: int = 0


class WorkflowOrchestratorError(Exception):
    """Base exception for workflow orchestration errors."""
    pass


class WorkflowTimeoutError(WorkflowOrchestratorError):
    """Exception raised when workflow execution exceeds timeout limits."""
    pass


class WorkflowStepFailedError(WorkflowOrchestratorError):
    """Exception raised when a critical workflow step fails."""
    pass


class TransactionBoundaryError(WorkflowOrchestratorError):
    """Exception raised when transaction boundary management fails."""
    pass


class ServiceCompositionError(WorkflowOrchestratorError):
    """Exception raised when service composition encounters errors."""
    pass


# Flask signals namespace for workflow events
workflow_signals = Namespace()

# Workflow lifecycle signals for event-driven processing
workflow_started = workflow_signals.signal('workflow-started')
workflow_completed = workflow_signals.signal('workflow-completed')
workflow_failed = workflow_signals.signal('workflow-failed')
workflow_step_started = workflow_signals.signal('workflow-step-started')
workflow_step_completed = workflow_signals.signal('workflow-step-completed')
workflow_step_failed = workflow_signals.signal('workflow-step-failed')
workflow_step_retrying = workflow_signals.signal('workflow-step-retrying')
transaction_started = workflow_signals.signal('transaction-started')
transaction_committed = workflow_signals.signal('transaction-committed')
transaction_rolled_back = workflow_signals.signal('transaction-rolled-back')


class WorkflowOrchestrator:
    """
    Advanced workflow orchestration service implementing complex business process
    coordination across multiple services and entities.
    
    This service provides comprehensive workflow orchestration capabilities including:
    - Service composition patterns for multi-step business operations
    - Transaction boundary management with ACID properties preservation
    - Event-driven processing through Flask signals integration
    - Comprehensive retry mechanisms with exponential backoff
    - Parallel and sequential workflow execution patterns
    - Integration with Flask-SQLAlchemy session management
    - Cross-cutting business concern coordination
    
    Features:
    - Advanced workflow orchestration patterns per Section 4.5.3
    - Service composition architecture per Section 5.2.3
    - Transaction boundary management per Section 4.5.2
    - Event-driven processing per Section 4.5.3
    - Workflow retry mechanisms per Section 4.5.3
    """
    
    def __init__(self, app=None):
        """
        Initialize workflow orchestrator with Flask application context.
        
        Args:
            app: Flask application instance for context integration
        """
        self.app = app
        self._active_workflows: Dict[str, WorkflowDefinition] = {}
        self._workflow_history: Dict[str, WorkflowResult] = {}
        self._service_registry: Dict[str, Any] = {}
        self._executor = ThreadPoolExecutor(max_workers=10)
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize workflow orchestrator with Flask application factory pattern.
        
        Integrates workflow orchestration service with Flask application context,
        registers signal handlers, and configures transaction management.
        
        Args:
            app: Flask application instance
        """
        self.app = app
        app.workflow_orchestrator = self
        
        # Register default signal handlers for workflow lifecycle events
        self._register_default_signal_handlers()
        
        # Configure database session management for transaction boundaries
        app.teardown_appcontext(self._close_database_sessions)
        
        logger.info("Workflow orchestrator initialized with Flask application")
    
    def _register_default_signal_handlers(self):
        """
        Register default signal handlers for workflow lifecycle events.
        
        Implements event-driven processing capabilities through Flask signals
        integration enabling workflow monitoring and cross-cutting concerns.
        """
        @workflow_started.connect
        def on_workflow_started(sender, workflow_id, workflow_name, **kwargs):
            logger.info(f"Workflow started: {workflow_id} ({workflow_name})")
        
        @workflow_completed.connect
        def on_workflow_completed(sender, workflow_id, result, **kwargs):
            logger.info(f"Workflow completed: {workflow_id} with status {result.status}")
        
        @workflow_failed.connect
        def on_workflow_failed(sender, workflow_id, error, **kwargs):
            logger.error(f"Workflow failed: {workflow_id} - {error}")
        
        @transaction_rolled_back.connect
        def on_transaction_rollback(sender, workflow_id, error, **kwargs):
            logger.warning(f"Transaction rolled back for workflow: {workflow_id} - {error}")
    
    def _close_database_sessions(self, exception):
        """
        Clean up database sessions during application context teardown.
        
        Ensures proper transaction boundary management and resource cleanup
        for workflow orchestration database operations.
        """
        if hasattr(g, 'workflow_session'):
            try:
                if exception:
                    g.workflow_session.rollback()
                else:
                    g.workflow_session.commit()
            except Exception as e:
                logger.error(f"Error closing workflow database session: {e}")
                g.workflow_session.rollback()
            finally:
                g.workflow_session.close()
                delattr(g, 'workflow_session')
    
    def register_service(self, service_name: str, service_instance: Any):
        """
        Register service instance for workflow composition patterns.
        
        Enables service composition architecture by registering service instances
        for use in workflow step execution and business logic coordination.
        
        Args:
            service_name: Unique identifier for the service
            service_instance: Service instance for workflow integration
        """
        self._service_registry[service_name] = service_instance
        logger.debug(f"Registered service: {service_name}")
    
    def get_service(self, service_name: str) -> Any:
        """
        Retrieve registered service instance for workflow execution.
        
        Args:
            service_name: Service identifier
            
        Returns:
            Service instance for workflow integration
            
        Raises:
            ServiceCompositionError: If service is not registered
        """
        if service_name not in self._service_registry:
            raise ServiceCompositionError(f"Service not registered: {service_name}")
        
        return self._service_registry[service_name]
    
    def create_workflow_definition(
        self,
        workflow_id: str,
        name: str,
        description: str,
        steps: List[WorkflowStep],
        **kwargs
    ) -> WorkflowDefinition:
        """
        Create comprehensive workflow definition for business process orchestration.
        
        Implements workflow definition creation with service composition patterns,
        transaction configuration, and execution metadata management.
        
        Args:
            workflow_id: Unique workflow identifier
            name: Human-readable workflow name
            description: Workflow description and purpose
            steps: List of workflow steps for execution
            **kwargs: Additional workflow configuration options
            
        Returns:
            Complete workflow definition ready for execution
        """
        # Validate workflow step dependencies
        self._validate_workflow_dependencies(steps)
        
        # Sort steps by priority and dependencies
        sorted_steps = self._sort_workflow_steps(steps)
        
        workflow_definition = WorkflowDefinition(
            workflow_id=workflow_id,
            name=name,
            description=description,
            steps=sorted_steps,
            **kwargs
        )
        
        logger.debug(f"Created workflow definition: {workflow_id} with {len(steps)} steps")
        return workflow_definition
    
    def _validate_workflow_dependencies(self, steps: List[WorkflowStep]):
        """
        Validate workflow step dependencies for execution consistency.
        
        Ensures all step dependencies are satisfied and circular dependencies
        are detected before workflow execution begins.
        
        Args:
            steps: List of workflow steps to validate
            
        Raises:
            WorkflowOrchestratorError: If dependencies are invalid
        """
        step_ids = {step.step_id for step in steps}
        
        for step in steps:
            for dependency in step.dependencies:
                if dependency not in step_ids:
                    raise WorkflowOrchestratorError(
                        f"Step {step.step_id} depends on non-existent step: {dependency}"
                    )
        
        # Check for circular dependencies using topological sort
        try:
            self._topological_sort(steps)
        except ValueError as e:
            raise WorkflowOrchestratorError(f"Circular dependency detected: {e}")
    
    def _sort_workflow_steps(self, steps: List[WorkflowStep]) -> List[WorkflowStep]:
        """
        Sort workflow steps by dependencies and priority for execution order.
        
        Implements topological sorting for dependency resolution and
        priority-based ordering for optimal workflow execution.
        
        Args:
            steps: Unsorted list of workflow steps
            
        Returns:
            Sorted list of workflow steps ready for execution
        """
        # Perform topological sort for dependency ordering
        sorted_by_deps = self._topological_sort(steps)
        
        # Secondary sort by priority within dependency groups
        return sorted(sorted_by_deps, key=lambda x: (-x.priority, x.step_id))
    
    def _topological_sort(self, steps: List[WorkflowStep]) -> List[WorkflowStep]:
        """
        Perform topological sort for workflow step dependency resolution.
        
        Args:
            steps: List of workflow steps with dependencies
            
        Returns:
            Topologically sorted list of workflow steps
            
        Raises:
            ValueError: If circular dependencies are detected
        """
        # Build adjacency list and in-degree count
        step_map = {step.step_id: step for step in steps}
        in_degree = {step.step_id: 0 for step in steps}
        adj_list = {step.step_id: [] for step in steps}
        
        for step in steps:
            for dependency in step.dependencies:
                adj_list[dependency].append(step.step_id)
                in_degree[step.step_id] += 1
        
        # Kahn's algorithm for topological sorting
        queue = [step_id for step_id, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            current = queue.pop(0)
            result.append(step_map[current])
            
            for neighbor in adj_list[current]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        if len(result) != len(steps):
            raise ValueError("Circular dependency detected in workflow steps")
        
        return result
    
    def execute_workflow(
        self,
        workflow_definition: WorkflowDefinition,
        context: Optional[Dict[str, Any]] = None
    ) -> WorkflowResult:
        """
        Execute complete workflow with comprehensive orchestration and monitoring.
        
        Implements advanced workflow orchestration patterns with transaction
        boundary management, event-driven processing, and retry mechanisms
        for resilient business process execution.
        
        Args:
            workflow_definition: Complete workflow definition for execution
            context: Additional context data for workflow execution
            
        Returns:
            Comprehensive workflow execution result with detailed metadata
            
        Raises:
            WorkflowOrchestratorError: If workflow execution encounters errors
        """
        workflow_id = workflow_definition.workflow_id
        context = context or {}
        
        # Initialize workflow execution state
        workflow_definition.context.update(context)
        workflow_definition.status = WorkflowStatus.RUNNING
        workflow_definition.started_at = datetime.utcnow()
        
        # Store active workflow for monitoring
        self._active_workflows[workflow_id] = workflow_definition
        
        # Emit workflow started signal
        workflow_started.send(
            current_app._get_current_object(),
            workflow_id=workflow_id,
            workflow_name=workflow_definition.name,
            context=context
        )
        
        try:
            # Execute workflow with transaction boundary management
            result = self._execute_workflow_with_transaction(workflow_definition)
            
            # Update workflow completion state
            workflow_definition.status = WorkflowStatus.COMPLETED
            workflow_definition.completed_at = datetime.utcnow()
            workflow_definition.execution_time = (
                workflow_definition.completed_at - workflow_definition.started_at
            ).total_seconds()
            
            # Emit workflow completed signal
            workflow_completed.send(
                current_app._get_current_object(),
                workflow_id=workflow_id,
                result=result
            )
            
            logger.info(f"Workflow {workflow_id} completed successfully in {workflow_definition.execution_time:.2f}s")
            return result
            
        except Exception as e:
            # Handle workflow execution failure
            workflow_definition.status = WorkflowStatus.FAILED
            workflow_definition.completed_at = datetime.utcnow()
            workflow_definition.error_message = str(e)
            
            # Emit workflow failed signal
            workflow_failed.send(
                current_app._get_current_object(),
                workflow_id=workflow_id,
                error=str(e)
            )
            
            logger.error(f"Workflow {workflow_id} failed: {e}")
            
            # Create failure result
            result = WorkflowResult(
                workflow_id=workflow_id,
                status=WorkflowStatus.FAILED,
                started_at=workflow_definition.started_at,
                completed_at=workflow_definition.completed_at,
                error_details={'error': str(e), 'type': type(e).__name__}
            )
            
            # Store in workflow history
            self._workflow_history[workflow_id] = result
            
            raise WorkflowOrchestratorError(f"Workflow execution failed: {e}") from e
        
        finally:
            # Clean up active workflow tracking
            if workflow_id in self._active_workflows:
                del self._active_workflows[workflow_id]
    
    def _execute_workflow_with_transaction(
        self,
        workflow_definition: WorkflowDefinition
    ) -> WorkflowResult:
        """
        Execute workflow within transaction boundary for ACID properties preservation.
        
        Implements comprehensive transaction boundary management with isolation
        level control, rollback capabilities, and session coordination for
        multi-step business workflow execution.
        
        Args:
            workflow_definition: Workflow definition for transaction execution
            
        Returns:
            Complete workflow execution result with transaction metadata
        """
        session = self._get_workflow_session(workflow_definition.transaction_isolation)
        
        try:
            # Emit transaction started signal
            transaction_started.send(
                current_app._get_current_object(),
                workflow_id=workflow_definition.workflow_id,
                isolation_level=workflow_definition.transaction_isolation.value
            )
            
            # Execute workflow steps within transaction
            if workflow_definition.enable_parallel_execution:
                result = self._execute_workflow_parallel(workflow_definition, session)
            else:
                result = self._execute_workflow_sequential(workflow_definition, session)
            
            # Commit transaction for successful workflow execution
            session.commit()
            
            # Emit transaction committed signal
            transaction_committed.send(
                current_app._get_current_object(),
                workflow_id=workflow_definition.workflow_id
            )
            
            # Store successful result in workflow history
            self._workflow_history[workflow_definition.workflow_id] = result
            
            return result
            
        except Exception as e:
            # Rollback transaction on workflow failure
            session.rollback()
            
            # Emit transaction rollback signal
            transaction_rolled_back.send(
                current_app._get_current_object(),
                workflow_id=workflow_definition.workflow_id,
                error=str(e)
            )
            
            # Perform workflow-level rollback if enabled
            if workflow_definition.rollback_on_failure:
                self._perform_workflow_rollback(workflow_definition, session)
            
            raise TransactionBoundaryError(f"Transaction failed for workflow {workflow_definition.workflow_id}: {e}") from e
        
        finally:
            session.close()
    
    def _get_workflow_session(self, isolation_level: TransactionIsolationLevel) -> Session:
        """
        Get database session with specified transaction isolation level.
        
        Creates and configures database session for workflow execution with
        appropriate isolation level for transaction boundary management.
        
        Args:
            isolation_level: Database transaction isolation level
            
        Returns:
            Configured database session for workflow execution
        """
        session = db.session
        
        # Configure transaction isolation level
        if isolation_level != TransactionIsolationLevel.READ_COMMITTED:
            session.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation_level.value}")
        
        # Store session in Flask application context
        g.workflow_session = session
        
        return session
    
    def _execute_workflow_sequential(
        self,
        workflow_definition: WorkflowDefinition,
        session: Session
    ) -> WorkflowResult:
        """
        Execute workflow steps in sequential order with dependency resolution.
        
        Implements sequential workflow execution with comprehensive step
        monitoring, retry mechanisms, and error handling for business
        process coordination.
        
        Args:
            workflow_definition: Workflow definition for sequential execution
            session: Database session for transaction management
            
        Returns:
            Complete workflow execution result with step-level details
        """
        result = WorkflowResult(
            workflow_id=workflow_definition.workflow_id,
            status=WorkflowStatus.RUNNING,
            started_at=workflow_definition.started_at
        )
        
        for step in workflow_definition.steps:
            # Check workflow timeout before executing each step
            if self._is_workflow_timeout(workflow_definition):
                raise WorkflowTimeoutError(f"Workflow {workflow_definition.workflow_id} exceeded maximum execution time")
            
            # Check step conditional execution
            if step.conditional_execution and not step.conditional_execution(workflow_definition.context):
                step.status = WorkflowStepStatus.SKIPPED
                logger.debug(f"Skipped step {step.step_id} due to conditional execution")
                continue
            
            # Execute workflow step with retry mechanism
            step_result = self._execute_workflow_step_with_retry(step, workflow_definition, session)
            
            # Update workflow context with step result
            workflow_definition.context[f"step_{step.step_id}_result"] = step_result
            result.step_results[step.step_id] = step_result
            
            # Update execution statistics
            result.steps_executed += 1
            if step.status == WorkflowStepStatus.COMPLETED:
                result.steps_successful += 1
            elif step.status == WorkflowStepStatus.FAILED:
                result.steps_failed += 1
                
                # Handle critical step failure
                if not step.rollback_method:
                    raise WorkflowStepFailedError(f"Critical step {step.step_id} failed: {step.error_message}")
        
        # Finalize workflow execution result
        result.status = WorkflowStatus.COMPLETED
        result.completed_at = datetime.utcnow()
        result.execution_time = (result.completed_at - result.started_at).total_seconds()
        result.final_result = workflow_definition.context
        
        return result
    
    def _execute_workflow_parallel(
        self,
        workflow_definition: WorkflowDefinition,
        session: Session
    ) -> WorkflowResult:
        """
        Execute workflow steps in parallel where dependencies allow.
        
        Implements parallel workflow execution with dependency graph resolution,
        concurrent step execution, and synchronized result collection for
        enhanced workflow performance.
        
        Args:
            workflow_definition: Workflow definition for parallel execution
            session: Database session for transaction management
            
        Returns:
            Complete workflow execution result with parallel execution metadata
        """
        result = WorkflowResult(
            workflow_id=workflow_definition.workflow_id,
            status=WorkflowStatus.RUNNING,
            started_at=workflow_definition.started_at
        )
        
        # Build dependency graph for parallel execution
        dependency_graph = self._build_dependency_graph(workflow_definition.steps)
        completed_steps = set()
        step_futures = {}
        
        while len(completed_steps) < len(workflow_definition.steps):
            # Find steps ready for execution (dependencies satisfied)
            ready_steps = [
                step for step in workflow_definition.steps
                if (step.step_id not in completed_steps and
                    all(dep in completed_steps for dep in step.dependencies))
            ]
            
            # Submit ready steps for parallel execution
            for step in ready_steps:
                if step.step_id not in step_futures:
                    future = self._executor.submit(
                        self._execute_workflow_step_with_retry,
                        step,
                        workflow_definition,
                        session
                    )
                    step_futures[step.step_id] = future
            
            # Wait for at least one step to complete
            completed_future = next(iter(step_futures.values()))
            completed_future.result()  # This will block until completion
            
            # Process completed steps
            for step_id, future in list(step_futures.items()):
                if future.done():
                    try:
                        step_result = future.result()
                        workflow_definition.context[f"step_{step_id}_result"] = step_result
                        result.step_results[step_id] = step_result
                        result.steps_executed += 1
                        result.steps_successful += 1
                        completed_steps.add(step_id)
                    except Exception as e:
                        result.steps_failed += 1
                        logger.error(f"Parallel step {step_id} failed: {e}")
                        # Handle critical failure in parallel execution
                        raise WorkflowStepFailedError(f"Parallel step {step_id} failed: {e}")
                    finally:
                        del step_futures[step_id]
        
        # Finalize parallel workflow execution result
        result.status = WorkflowStatus.COMPLETED
        result.completed_at = datetime.utcnow()
        result.execution_time = (result.completed_at - result.started_at).total_seconds()
        result.final_result = workflow_definition.context
        
        return result
    
    def _build_dependency_graph(self, steps: List[WorkflowStep]) -> Dict[str, List[str]]:
        """
        Build dependency graph for parallel workflow execution.
        
        Args:
            steps: List of workflow steps with dependencies
            
        Returns:
            Dependency graph mapping step IDs to dependent step IDs
        """
        graph = {}
        for step in steps:
            graph[step.step_id] = step.dependencies.copy()
        return graph
    
    def _execute_workflow_step_with_retry(
        self,
        step: WorkflowStep,
        workflow_definition: WorkflowDefinition,
        session: Session
    ) -> Any:
        """
        Execute individual workflow step with comprehensive retry mechanism.
        
        Implements robust workflow step execution with exponential backoff retry,
        error handling, and signal emission for step-level monitoring and
        event-driven processing coordination.
        
        Args:
            step: Workflow step for execution
            workflow_definition: Parent workflow definition for context
            session: Database session for transaction management
            
        Returns:
            Step execution result data
            
        Raises:
            WorkflowStepFailedError: If step fails after all retry attempts
        """
        workflow_definition.current_step = step.step_id
        step.status = WorkflowStepStatus.RUNNING
        step.started_at = datetime.utcnow()
        
        # Emit step started signal
        workflow_step_started.send(
            current_app._get_current_object(),
            workflow_id=workflow_definition.workflow_id,
            step_id=step.step_id,
            step=step
        )
        
        last_exception = None
        
        for attempt in range(step.retry_attempts + 1):
            step.attempt_count = attempt + 1
            
            try:
                # Execute step with timeout handling
                step_result = self._execute_step_with_timeout(step, workflow_definition, session)
                
                # Update step completion state
                step.status = WorkflowStepStatus.COMPLETED
                step.completed_at = datetime.utcnow()
                step.execution_time = (step.completed_at - step.started_at).total_seconds()
                step.result_data = step_result
                
                # Emit step completed signal
                workflow_step_completed.send(
                    current_app._get_current_object(),
                    workflow_id=workflow_definition.workflow_id,
                    step_id=step.step_id,
                    result=step_result
                )
                
                logger.debug(f"Step {step.step_id} completed in attempt {attempt + 1}")
                return step_result
                
            except Exception as e:
                last_exception = e
                step.error_message = str(e)
                
                # Check if we should retry
                if attempt < step.retry_attempts:
                    step.status = WorkflowStepStatus.RETRYING
                    
                    # Emit step retrying signal
                    workflow_step_retrying.send(
                        current_app._get_current_object(),
                        workflow_id=workflow_definition.workflow_id,
                        step_id=step.step_id,
                        attempt=attempt + 1,
                        error=str(e)
                    )
                    
                    # Calculate exponential backoff delay
                    delay = step.retry_delay * (2 ** attempt)
                    logger.warning(f"Step {step.step_id} failed (attempt {attempt + 1}), retrying in {delay}s: {e}")
                    time.sleep(delay)
                else:
                    # Final failure after all retry attempts
                    step.status = WorkflowStepStatus.FAILED
                    step.completed_at = datetime.utcnow()
                    step.execution_time = (step.completed_at - step.started_at).total_seconds()
                    
                    # Emit step failed signal
                    workflow_step_failed.send(
                        current_app._get_current_object(),
                        workflow_id=workflow_definition.workflow_id,
                        step_id=step.step_id,
                        error=str(e),
                        attempts=step.retry_attempts + 1
                    )
                    
                    logger.error(f"Step {step.step_id} failed after {step.retry_attempts + 1} attempts: {e}")
                    break
        
        # Perform step rollback if available
        if step.rollback_method:
            try:
                logger.info(f"Performing rollback for failed step: {step.step_id}")
                step.rollback_method(workflow_definition.context)
            except Exception as rollback_error:
                logger.error(f"Rollback failed for step {step.step_id}: {rollback_error}")
        
        raise WorkflowStepFailedError(f"Step {step.step_id} failed after {step.retry_attempts + 1} attempts: {last_exception}")
    
    def _execute_step_with_timeout(
        self,
        step: WorkflowStep,
        workflow_definition: WorkflowDefinition,
        session: Session
    ) -> Any:
        """
        Execute workflow step with timeout handling.
        
        Args:
            step: Workflow step for execution
            workflow_definition: Parent workflow definition
            session: Database session for transaction management
            
        Returns:
            Step execution result
            
        Raises:
            TimeoutError: If step execution exceeds timeout
        """
        import signal
        import functools
        
        def timeout_handler(signum, frame):
            raise TimeoutError(f"Step {step.step_id} timed out after {step.timeout_seconds} seconds")
        
        # Set up timeout handling
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(step.timeout_seconds)
        
        try:
            # Prepare step input data with workflow context
            step_input = {
                **step.input_data,
                'workflow_context': workflow_definition.context,
                'session': session
            }
            
            # Execute step method with prepared input
            return step.service_method(**step_input)
            
        finally:
            # Clean up timeout handling
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    
    def _is_workflow_timeout(self, workflow_definition: WorkflowDefinition) -> bool:
        """
        Check if workflow has exceeded maximum execution time.
        
        Args:
            workflow_definition: Workflow definition to check
            
        Returns:
            True if workflow has timed out, False otherwise
        """
        if not workflow_definition.started_at:
            return False
        
        elapsed_time = (datetime.utcnow() - workflow_definition.started_at).total_seconds()
        return elapsed_time > workflow_definition.max_execution_time
    
    def _perform_workflow_rollback(
        self,
        workflow_definition: WorkflowDefinition,
        session: Session
    ):
        """
        Perform comprehensive workflow rollback for completed steps.
        
        Executes rollback operations for all completed workflow steps in
        reverse order to maintain business logic consistency and data integrity.
        
        Args:
            workflow_definition: Workflow definition for rollback
            session: Database session for rollback operations
        """
        logger.info(f"Performing workflow rollback for: {workflow_definition.workflow_id}")
        
        # Get completed steps in reverse order
        completed_steps = [
            step for step in reversed(workflow_definition.steps)
            if step.status == WorkflowStepStatus.COMPLETED and step.rollback_method
        ]
        
        for step in completed_steps:
            try:
                logger.debug(f"Rolling back step: {step.step_id}")
                step.rollback_method(workflow_definition.context)
            except Exception as rollback_error:
                logger.error(f"Rollback failed for step {step.step_id}: {rollback_error}")
                # Continue with remaining rollbacks despite individual failures
    
    def get_workflow_status(self, workflow_id: str) -> Optional[WorkflowResult]:
        """
        Get current status and result for specified workflow.
        
        Args:
            workflow_id: Workflow identifier for status query
            
        Returns:
            Workflow result with current status, or None if not found
        """
        # Check active workflows first
        if workflow_id in self._active_workflows:
            workflow = self._active_workflows[workflow_id]
            return WorkflowResult(
                workflow_id=workflow_id,
                status=workflow.status,
                started_at=workflow.started_at,
                completed_at=workflow.completed_at,
                execution_time=workflow.execution_time,
                steps_executed=len([s for s in workflow.steps if s.status != WorkflowStepStatus.PENDING]),
                steps_successful=len([s for s in workflow.steps if s.status == WorkflowStepStatus.COMPLETED]),
                steps_failed=len([s for s in workflow.steps if s.status == WorkflowStepStatus.FAILED])
            )
        
        # Check workflow history
        return self._workflow_history.get(workflow_id)
    
    def cancel_workflow(self, workflow_id: str) -> bool:
        """
        Cancel active workflow execution.
        
        Args:
            workflow_id: Workflow identifier for cancellation
            
        Returns:
            True if workflow was cancelled, False if not found or already completed
        """
        if workflow_id not in self._active_workflows:
            return False
        
        workflow = self._active_workflows[workflow_id]
        workflow.status = WorkflowStatus.CANCELLED
        workflow.completed_at = datetime.utcnow()
        
        logger.info(f"Cancelled workflow: {workflow_id}")
        return True
    
    def get_active_workflows(self) -> List[str]:
        """
        Get list of currently active workflow IDs.
        
        Returns:
            List of active workflow identifiers
        """
        return list(self._active_workflows.keys())
    
    def cleanup_completed_workflows(self, max_age_hours: int = 24):
        """
        Clean up completed workflows from memory to prevent memory leaks.
        
        Args:
            max_age_hours: Maximum age in hours for completed workflows to retain
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        # Clean up workflow history
        expired_workflows = [
            workflow_id for workflow_id, result in self._workflow_history.items()
            if result.completed_at and result.completed_at < cutoff_time
        ]
        
        for workflow_id in expired_workflows:
            del self._workflow_history[workflow_id]
        
        logger.debug(f"Cleaned up {len(expired_workflows)} expired workflows")


# Utility functions for common workflow patterns

def create_service_step(
    step_id: str,
    service_name: str,
    method_name: str,
    input_data: Dict[str, Any] = None,
    **kwargs
) -> WorkflowStep:
    """
    Create workflow step for service method execution.
    
    Utility function for creating workflow steps that call service methods
    with automatic service resolution and method binding.
    
    Args:
        step_id: Unique step identifier
        service_name: Registered service name
        method_name: Service method name to call
        input_data: Input data for method execution
        **kwargs: Additional step configuration
        
    Returns:
        Configured workflow step for service method execution
    """
    def service_method_wrapper(**step_input):
        # Get workflow orchestrator from Flask app context
        orchestrator = current_app.workflow_orchestrator
        service = orchestrator.get_service(service_name)
        method = getattr(service, method_name)
        
        # Remove workflow-specific keys from input
        clean_input = {k: v for k, v in step_input.items() 
                      if k not in ['workflow_context', 'session']}
        
        return method(**clean_input)
    
    return WorkflowStep(
        step_id=step_id,
        service_method=service_method_wrapper,
        input_data=input_data or {},
        **kwargs
    )


def create_validation_step(
    step_id: str,
    validation_rules: List[Callable],
    input_data: Dict[str, Any] = None,
    **kwargs
) -> WorkflowStep:
    """
    Create workflow step for data validation.
    
    Args:
        step_id: Unique step identifier
        validation_rules: List of validation functions
        input_data: Input data for validation
        **kwargs: Additional step configuration
        
    Returns:
        Configured workflow step for validation execution
    """
    def validation_method(**step_input):
        data = {**input_data, **step_input} if input_data else step_input
        
        for validation_rule in validation_rules:
            if not validation_rule(data):
                raise ValueError(f"Validation failed for rule: {validation_rule.__name__}")
        
        return True
    
    return WorkflowStep(
        step_id=step_id,
        service_method=validation_method,
        input_data=input_data or {},
        **kwargs
    )


def create_conditional_step(
    step_id: str,
    condition: Callable[[Dict[str, Any]], bool],
    true_step: WorkflowStep,
    false_step: Optional[WorkflowStep] = None,
    **kwargs
) -> WorkflowStep:
    """
    Create conditional workflow step for branching logic.
    
    Args:
        step_id: Unique step identifier
        condition: Condition function for branching
        true_step: Step to execute if condition is True
        false_step: Optional step to execute if condition is False
        **kwargs: Additional step configuration
        
    Returns:
        Configured conditional workflow step
    """
    def conditional_method(**step_input):
        workflow_context = step_input.get('workflow_context', {})
        
        if condition(workflow_context):
            return true_step.service_method(**step_input)
        elif false_step:
            return false_step.service_method(**step_input)
        else:
            return None
    
    return WorkflowStep(
        step_id=step_id,
        service_method=conditional_method,
        conditional_execution=condition,
        **kwargs
    )