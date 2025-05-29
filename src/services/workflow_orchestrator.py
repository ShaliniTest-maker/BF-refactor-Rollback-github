"""
Workflow Orchestration Service for Flask Application

This module implements the advanced workflow orchestration patterns as specified in
Section 4.5.3, providing comprehensive business process coordination across multiple
services and entities. The service manages multi-step business workflows, service
composition patterns, and cross-cutting business concerns while maintaining
transaction consistency throughout complex operations.

Key Features:
- Advanced workflow orchestration patterns for business process coordination
- Service composition architecture enabling multi-step business workflows
- Transaction boundary management with ACID properties preservation
- Event-driven processing capabilities through Flask signals
- Workflow retry mechanisms for resilient operation
- Business logic coordination maintaining functional equivalence with Node.js

Architecture Integration:
- Integrates with the Service Layer pattern per Section 5.2.3
- Coordinates with Flask blueprints for HTTP endpoint integration
- Manages complex business operations across service boundaries
- Provides workflow state management and error recovery
"""

import logging
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum, auto
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar, Union

from flask import current_app, g
from flask.signals import Namespace
from flask_sqlalchemy import SQLAlchemy
from injector import inject, singleton
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from .base import BaseService, ServiceError, TransactionError, ValidationError
from .business_entity_service import BusinessEntityService
from .user_service import UserService
from .validation_service import ValidationService

# Type variables for workflow operations
T = TypeVar("T")
WorkflowResult = TypeVar("WorkflowResult")

# Flask signals namespace for workflow events
workflow_signals = Namespace()

# Workflow event signals
workflow_started = workflow_signals.signal("workflow-started")
workflow_completed = workflow_signals.signal("workflow-completed")
workflow_failed = workflow_signals.signal("workflow-failed")
workflow_step_completed = workflow_signals.signal("workflow-step-completed")
workflow_step_failed = workflow_signals.signal("workflow-step-failed")
workflow_rolled_back = workflow_signals.signal("workflow-rolled-back")

# Logger configuration for workflow orchestration
logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """Enumeration of workflow execution statuses."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    ROLLED_BACK = auto()


class WorkflowStepStatus(Enum):
    """Enumeration of individual workflow step statuses."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()
    RETRYING = auto()


class WorkflowPriority(Enum):
    """Enumeration of workflow execution priorities."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class WorkflowContext:
    """
    Context object containing workflow execution state and metadata.
    
    Provides comprehensive state management for workflow execution including
    step tracking, error handling, and recovery information.
    """
    workflow_id: str
    workflow_type: str
    status: WorkflowStatus
    priority: WorkflowPriority
    user_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]
    retry_count: int
    max_retries: int
    context_data: Dict[str, Any]
    step_results: Dict[str, Any]
    rollback_steps: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert workflow context to dictionary representation."""
        return {
            **asdict(self),
            "status": self.status.name,
            "priority": self.priority.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


@dataclass
class WorkflowStep:
    """
    Definition of an individual workflow step with execution logic.
    
    Encapsulates step-specific configuration including execution function,
    validation rules, rollback logic, and error handling policies.
    """
    step_id: str
    step_name: str
    step_function: Callable[[WorkflowContext], Any]
    rollback_function: Optional[Callable[[WorkflowContext], None]]
    validation_function: Optional[Callable[[WorkflowContext], bool]]
    required_services: List[str]
    retry_policy: Dict[str, Any]
    timeout_seconds: Optional[int]
    critical: bool
    depends_on: List[str]
    
    def __post_init__(self):
        """Initialize default retry policy if not provided."""
        if not self.retry_policy:
            self.retry_policy = {
                "max_retries": 3,
                "delay": 1.0,
                "backoff_factor": 2.0,
                "retry_on_exceptions": [OperationalError, SQLAlchemyError]
            }


class WorkflowError(ServiceError):
    """
    Exception raised for workflow execution errors.
    
    Extends ServiceError with workflow-specific error context including
    workflow ID, step information, and recovery guidance.
    """
    
    def __init__(self, message: str, workflow_id: str = None, 
                 step_id: str = None, original_error: Exception = None,
                 context: WorkflowContext = None):
        self.workflow_id = workflow_id
        self.step_id = step_id
        self.context = context
        super().__init__(message, original_error)


def workflow_step(step_id: str, step_name: str = None, rollback_function: Callable = None,
                 validation_function: Callable = None, required_services: List[str] = None,
                 retry_policy: Dict[str, Any] = None, timeout_seconds: int = None,
                 critical: bool = True, depends_on: List[str] = None):
    """
    Decorator for defining workflow steps with comprehensive configuration.
    
    Provides declarative workflow step definition with automatic registration,
    dependency management, and error handling integration.
    
    Args:
        step_id: Unique identifier for the workflow step
        step_name: Human-readable name for the step
        rollback_function: Function to execute for rollback operations
        validation_function: Function to validate step preconditions
        required_services: List of service names required for execution
        retry_policy: Retry configuration for step execution
        timeout_seconds: Maximum execution time for the step
        critical: Whether step failure should fail the entire workflow
        depends_on: List of step IDs that must complete before this step
    
    Returns:
        Decorated function registered as a workflow step
    """
    
    def decorator(func: Callable[[WorkflowContext], Any]) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        
        # Store step metadata on the function
        wrapper._workflow_step = WorkflowStep(
            step_id=step_id,
            step_name=step_name or step_id,
            step_function=wrapper,
            rollback_function=rollback_function,
            validation_function=validation_function,
            required_services=required_services or [],
            retry_policy=retry_policy or {},
            timeout_seconds=timeout_seconds,
            critical=critical,
            depends_on=depends_on or []
        )
        
        return wrapper
    
    return decorator


@singleton
class WorkflowOrchestrator(BaseService):
    """
    Advanced workflow orchestration service implementing complex business process
    coordination across multiple services and entities.
    
    This service provides comprehensive workflow management capabilities including:
    - Multi-step business workflow execution with dependency management
    - Service composition patterns for complex business operations
    - Transaction boundary management with ACID properties preservation
    - Event-driven processing through Flask signals
    - Automatic retry mechanisms for resilient operation
    - Workflow state persistence and recovery capabilities
    - Business logic coordination maintaining functional equivalence
    
    The orchestrator integrates with all business services through the Service
    Layer pattern and provides centralized coordination for complex business
    processes that span multiple domains and entities.
    """
    
    @inject
    def __init__(self, db: SQLAlchemy):
        """
        Initialize workflow orchestrator with database and service dependencies.
        
        Args:
            db: Flask-SQLAlchemy database instance for transaction management
        """
        super().__init__(db)
        
        # Service composition for complex business operations
        self._user_service: Optional[UserService] = None
        self._business_entity_service: Optional[BusinessEntityService] = None
        self._validation_service: Optional[ValidationService] = None
        
        # Workflow execution state management
        self._active_workflows: Dict[str, WorkflowContext] = {}
        self._workflow_definitions: Dict[str, List[WorkflowStep]] = {}
        self._workflow_locks: Dict[str, bool] = {}
        
        # Event-driven processing configuration
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._register_signal_handlers()
        
        # Performance monitoring
        self._workflow_metrics: Dict[str, Dict[str, Any]] = {}
        
        self.logger.info("Initialized WorkflowOrchestrator service")
    
    @property
    def user_service(self) -> UserService:
        """Get user service instance through service composition."""
        if self._user_service is None:
            self._user_service = self.compose_service(UserService)
        return self._user_service
    
    @property
    def business_entity_service(self) -> BusinessEntityService:
        """Get business entity service instance through service composition."""
        if self._business_entity_service is None:
            self._business_entity_service = self.compose_service(BusinessEntityService)
        return self._business_entity_service
    
    @property
    def validation_service(self) -> ValidationService:
        """Get validation service instance through service composition."""
        if self._validation_service is None:
            self._validation_service = self.compose_service(ValidationService)
        return self._validation_service
    
    def validate_business_rules(self, data: Dict[str, Any]) -> bool:
        """
        Validate workflow orchestration business rules.
        
        Implements workflow-specific business rule validation including
        workflow definition validation, step dependency checking, and
        resource availability verification.
        
        Args:
            data: Workflow data to validate
        
        Returns:
            True if validation passes
        
        Raises:
            ValidationError: When workflow business rules are violated
        """
        required_fields = ["workflow_type", "context_data"]
        validated_data = self.validate_input(data, required_fields)
        
        workflow_type = validated_data["workflow_type"]
        
        # Validate workflow type is registered
        if workflow_type not in self._workflow_definitions:
            raise ValidationError(f"Unknown workflow type: {workflow_type}")
        
        # Validate context data structure
        context_data = validated_data["context_data"]
        if not isinstance(context_data, dict):
            raise ValidationError("Workflow context_data must be a dictionary")
        
        # Validate workflow-specific business rules through composed services
        if "user_id" in context_data:
            # Validate user exists and is active
            user_validation_data = {"user_id": context_data["user_id"]}
            if not self.user_service.validate_business_rules(user_validation_data):
                raise ValidationError("Invalid user for workflow execution")
        
        if "entity_id" in context_data:
            # Validate business entity exists and is accessible
            entity_validation_data = {"entity_id": context_data["entity_id"]}
            if not self.business_entity_service.validate_business_rules(entity_validation_data):
                raise ValidationError("Invalid business entity for workflow execution")
        
        self.logger.debug(f"Validated workflow business rules for type: {workflow_type}")
        return True
    
    def register_workflow_definition(self, workflow_type: str, 
                                   steps: List[WorkflowStep]) -> None:
        """
        Register a workflow definition with step configuration.
        
        Provides workflow registration capabilities for complex business processes
        with comprehensive step validation and dependency checking.
        
        Args:
            workflow_type: Unique identifier for the workflow type
            steps: List of workflow steps in execution order
        
        Raises:
            ValidationError: When workflow definition is invalid
        """
        if not workflow_type:
            raise ValidationError("Workflow type cannot be empty")
        
        if not steps:
            raise ValidationError("Workflow must have at least one step")
        
        # Validate step dependencies
        step_ids = {step.step_id for step in steps}
        for step in steps:
            for dependency in step.depends_on:
                if dependency not in step_ids:
                    raise ValidationError(
                        f"Step {step.step_id} depends on unknown step: {dependency}"
                    )
        
        # Check for circular dependencies
        self._validate_no_circular_dependencies(steps)
        
        self._workflow_definitions[workflow_type] = steps
        self.logger.info(f"Registered workflow definition: {workflow_type} with {len(steps)} steps")
    
    def _validate_no_circular_dependencies(self, steps: List[WorkflowStep]) -> None:
        """
        Validate that workflow steps have no circular dependencies.
        
        Args:
            steps: List of workflow steps to validate
        
        Raises:
            ValidationError: When circular dependencies are detected
        """
        step_dependencies = {step.step_id: step.depends_on for step in steps}
        
        def has_circular_dependency(step_id: str, visited: set, recursion_stack: set) -> bool:
            visited.add(step_id)
            recursion_stack.add(step_id)
            
            for dependency in step_dependencies.get(step_id, []):
                if dependency not in visited:
                    if has_circular_dependency(dependency, visited, recursion_stack):
                        return True
                elif dependency in recursion_stack:
                    return True
            
            recursion_stack.remove(step_id)
            return False
        
        visited = set()
        for step in steps:
            if step.step_id not in visited:
                if has_circular_dependency(step.step_id, visited, set()):
                    raise ValidationError(f"Circular dependency detected in workflow steps")
    
    def execute_workflow(self, workflow_type: str, context_data: Dict[str, Any],
                        priority: WorkflowPriority = WorkflowPriority.NORMAL,
                        max_retries: int = 3) -> WorkflowContext:
        """
        Execute a complete workflow with comprehensive orchestration.
        
        Implements advanced workflow orchestration patterns with transaction
        boundary management, event-driven processing, and error recovery.
        
        Args:
            workflow_type: Type of workflow to execute
            context_data: Initial context data for workflow execution
            priority: Execution priority for resource allocation
            max_retries: Maximum retry attempts for the entire workflow
        
        Returns:
            WorkflowContext with execution results and status
        
        Raises:
            WorkflowError: When workflow execution fails
        """
        # Validate workflow execution request
        validation_data = {
            "workflow_type": workflow_type,
            "context_data": context_data
        }
        self.validate_business_rules(validation_data)
        
        # Create workflow context
        workflow_id = str(uuid.uuid4())
        workflow_context = WorkflowContext(
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            status=WorkflowStatus.PENDING,
            priority=priority,
            user_id=self.get_current_user_id(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            completed_at=None,
            error_message=None,
            retry_count=0,
            max_retries=max_retries,
            context_data=context_data.copy(),
            step_results={},
            rollback_steps=[]
        )
        
        # Register active workflow
        self._active_workflows[workflow_id] = workflow_context
        
        try:
            # Emit workflow started signal
            workflow_started.send(
                current_app._get_current_object(),
                workflow_context=workflow_context
            )
            
            # Execute workflow with transaction boundary management
            with self.transaction_boundary():
                self._execute_workflow_steps(workflow_context)
                
                # Mark workflow as completed
                workflow_context.status = WorkflowStatus.COMPLETED
                workflow_context.completed_at = datetime.utcnow()
                workflow_context.updated_at = datetime.utcnow()
                
                # Emit workflow completed signal
                workflow_completed.send(
                    current_app._get_current_object(),
                    workflow_context=workflow_context
                )
                
                self.logger.info(f"Workflow {workflow_id} completed successfully")
                
        except Exception as e:
            # Handle workflow failure with rollback
            self._handle_workflow_failure(workflow_context, e)
            raise WorkflowError(
                f"Workflow execution failed: {str(e)}",
                workflow_id=workflow_id,
                original_error=e,
                context=workflow_context
            )
        
        finally:
            # Clean up active workflow registration
            self._active_workflows.pop(workflow_id, None)
        
        return workflow_context
    
    def _execute_workflow_steps(self, workflow_context: WorkflowContext) -> None:
        """
        Execute individual workflow steps with dependency management.
        
        Implements step-by-step execution with dependency resolution,
        error handling, and progress tracking.
        
        Args:
            workflow_context: Workflow execution context
        
        Raises:
            WorkflowError: When step execution fails
        """
        workflow_context.status = WorkflowStatus.RUNNING
        steps = self._workflow_definitions[workflow_context.workflow_type]
        
        # Build execution order based on dependencies
        execution_order = self._resolve_step_dependencies(steps)
        
        for step in execution_order:
            try:
                # Check if step should be executed
                if not self._should_execute_step(step, workflow_context):
                    workflow_context.step_results[step.step_id] = {
                        "status": WorkflowStepStatus.SKIPPED.name,
                        "result": None,
                        "executed_at": datetime.utcnow().isoformat()
                    }
                    continue
                
                # Execute step with retry mechanism
                step_result = self._execute_step_with_retry(step, workflow_context)
                
                # Store step result
                workflow_context.step_results[step.step_id] = {
                    "status": WorkflowStepStatus.COMPLETED.name,
                    "result": step_result,
                    "executed_at": datetime.utcnow().isoformat()
                }
                
                # Add to rollback steps if rollback function exists
                if step.rollback_function:
                    workflow_context.rollback_steps.append(step.step_id)
                
                # Emit step completed signal
                workflow_step_completed.send(
                    current_app._get_current_object(),
                    workflow_context=workflow_context,
                    step=step,
                    result=step_result
                )
                
                self.logger.debug(f"Completed step {step.step_id} in workflow {workflow_context.workflow_id}")
                
            except Exception as e:
                # Handle step failure
                workflow_context.step_results[step.step_id] = {
                    "status": WorkflowStepStatus.FAILED.name,
                    "error": str(e),
                    "executed_at": datetime.utcnow().isoformat()
                }
                
                # Emit step failed signal
                workflow_step_failed.send(
                    current_app._get_current_object(),
                    workflow_context=workflow_context,
                    step=step,
                    error=e
                )
                
                self.logger.error(f"Step {step.step_id} failed in workflow {workflow_context.workflow_id}: {e}")
                
                # Check if step is critical
                if step.critical:
                    raise WorkflowError(
                        f"Critical step {step.step_id} failed: {str(e)}",
                        workflow_id=workflow_context.workflow_id,
                        step_id=step.step_id,
                        original_error=e,
                        context=workflow_context
                    )
                
                # Continue with non-critical step failure
                self.logger.warning(f"Non-critical step {step.step_id} failed, continuing workflow")
    
    def _resolve_step_dependencies(self, steps: List[WorkflowStep]) -> List[WorkflowStep]:
        """
        Resolve step execution order based on dependencies.
        
        Implements topological sorting for dependency resolution.
        
        Args:
            steps: List of workflow steps
        
        Returns:
            List of steps in execution order
        """
        step_map = {step.step_id: step for step in steps}
        in_degree = {step.step_id: len(step.depends_on) for step in steps}
        queue = [step_id for step_id, degree in in_degree.items() if degree == 0]
        execution_order = []
        
        while queue:
            current_step_id = queue.pop(0)
            current_step = step_map[current_step_id]
            execution_order.append(current_step)
            
            # Update in-degree for dependent steps
            for step in steps:
                if current_step_id in step.depends_on:
                    in_degree[step.step_id] -= 1
                    if in_degree[step.step_id] == 0:
                        queue.append(step.step_id)
        
        return execution_order
    
    def _should_execute_step(self, step: WorkflowStep, 
                           workflow_context: WorkflowContext) -> bool:
        """
        Determine if a workflow step should be executed.
        
        Evaluates step preconditions and validation functions.
        
        Args:
            step: Workflow step to evaluate
            workflow_context: Current workflow context
        
        Returns:
            True if step should be executed
        """
        # Check validation function if provided
        if step.validation_function:
            try:
                return step.validation_function(workflow_context)
            except Exception as e:
                self.logger.warning(f"Step validation failed for {step.step_id}: {e}")
                return False
        
        return True
    
    def _execute_step_with_retry(self, step: WorkflowStep, 
                               workflow_context: WorkflowContext) -> Any:
        """
        Execute a workflow step with retry mechanism.
        
        Implements step-specific retry policies with exponential backoff.
        
        Args:
            step: Workflow step to execute
            workflow_context: Current workflow context
        
        Returns:
            Step execution result
        
        Raises:
            WorkflowError: When step execution fails after all retries
        """
        retry_policy = step.retry_policy
        max_retries = retry_policy.get("max_retries", 3)
        delay = retry_policy.get("delay", 1.0)
        backoff_factor = retry_policy.get("backoff_factor", 2.0)
        retry_exceptions = tuple(retry_policy.get("retry_on_exceptions", [OperationalError]))
        
        last_exception = None
        current_delay = delay
        
        for attempt in range(max_retries + 1):
            try:
                # Execute step function with context
                return step.step_function(workflow_context)
                
            except retry_exceptions as e:
                last_exception = e
                if attempt == max_retries:
                    self.logger.error(
                        f"Step {step.step_id} failed after {max_retries} retries: {e}"
                    )
                    break
                
                self.logger.warning(
                    f"Retry attempt {attempt + 1}/{max_retries} for step {step.step_id}: {e}"
                )
                time.sleep(current_delay)
                current_delay *= backoff_factor
                
            except Exception as e:
                # Don't retry on non-retryable exceptions
                self.logger.error(f"Non-retryable error in step {step.step_id}: {e}")
                raise WorkflowError(
                    f"Step execution failed: {str(e)}",
                    workflow_id=workflow_context.workflow_id,
                    step_id=step.step_id,
                    original_error=e,
                    context=workflow_context
                )
        
        # If we get here, all retries failed
        raise WorkflowError(
            f"Step {step.step_id} failed after {max_retries} retries",
            workflow_id=workflow_context.workflow_id,
            step_id=step.step_id,
            original_error=last_exception,
            context=workflow_context
        )
    
    def _handle_workflow_failure(self, workflow_context: WorkflowContext, 
                               error: Exception) -> None:
        """
        Handle workflow failure with rollback operations.
        
        Implements comprehensive error handling with automatic rollback
        of completed steps and state recovery.
        
        Args:
            workflow_context: Failed workflow context
            error: Exception that caused the failure
        """
        workflow_context.status = WorkflowStatus.FAILED
        workflow_context.error_message = str(error)
        workflow_context.updated_at = datetime.utcnow()
        
        # Attempt to rollback completed steps
        if workflow_context.rollback_steps:
            self.logger.info(f"Rolling back {len(workflow_context.rollback_steps)} steps")
            
            try:
                self._execute_rollback_steps(workflow_context)
                workflow_context.status = WorkflowStatus.ROLLED_BACK
                
                # Emit rollback signal
                workflow_rolled_back.send(
                    current_app._get_current_object(),
                    workflow_context=workflow_context
                )
                
            except Exception as rollback_error:
                self.logger.error(f"Rollback failed: {rollback_error}")
                workflow_context.error_message += f"; Rollback failed: {str(rollback_error)}"
        
        # Emit workflow failed signal
        workflow_failed.send(
            current_app._get_current_object(),
            workflow_context=workflow_context,
            error=error
        )
        
        self.logger.error(f"Workflow {workflow_context.workflow_id} failed: {error}")
    
    def _execute_rollback_steps(self, workflow_context: WorkflowContext) -> None:
        """
        Execute rollback operations for completed workflow steps.
        
        Implements reverse-order rollback execution with error handling.
        
        Args:
            workflow_context: Workflow context with rollback information
        """
        steps = self._workflow_definitions[workflow_context.workflow_type]
        step_map = {step.step_id: step for step in steps}
        
        # Execute rollback in reverse order
        for step_id in reversed(workflow_context.rollback_steps):
            step = step_map.get(step_id)
            if step and step.rollback_function:
                try:
                    step.rollback_function(workflow_context)
                    self.logger.debug(f"Rolled back step {step_id}")
                except Exception as e:
                    self.logger.error(f"Rollback failed for step {step_id}: {e}")
                    # Continue with other rollback operations
    
    def _register_signal_handlers(self) -> None:
        """
        Register Flask signal handlers for workflow events.
        
        Implements event-driven processing capabilities through Flask signals
        for workflow monitoring and integration.
        """
        @workflow_started.connect
        def handle_workflow_started(sender, workflow_context):
            self.logger.info(f"Workflow started: {workflow_context.workflow_id}")
            self._update_workflow_metrics(workflow_context, "started")
        
        @workflow_completed.connect
        def handle_workflow_completed(sender, workflow_context):
            self.logger.info(f"Workflow completed: {workflow_context.workflow_id}")
            self._update_workflow_metrics(workflow_context, "completed")
        
        @workflow_failed.connect
        def handle_workflow_failed(sender, workflow_context, error):
            self.logger.error(f"Workflow failed: {workflow_context.workflow_id}")
            self._update_workflow_metrics(workflow_context, "failed")
        
        @workflow_step_completed.connect
        def handle_step_completed(sender, workflow_context, step, result):
            self.logger.debug(f"Step completed: {step.step_id}")
            self._update_step_metrics(workflow_context, step, "completed")
        
        @workflow_step_failed.connect
        def handle_step_failed(sender, workflow_context, step, error):
            self.logger.warning(f"Step failed: {step.step_id}")
            self._update_step_metrics(workflow_context, step, "failed")
    
    def _update_workflow_metrics(self, workflow_context: WorkflowContext, 
                               event_type: str) -> None:
        """
        Update workflow execution metrics for monitoring and analysis.
        
        Args:
            workflow_context: Workflow context
            event_type: Type of workflow event
        """
        workflow_type = workflow_context.workflow_type
        
        if workflow_type not in self._workflow_metrics:
            self._workflow_metrics[workflow_type] = {
                "total_executions": 0,
                "successful_executions": 0,
                "failed_executions": 0,
                "average_duration": 0.0,
                "last_execution": None
            }
        
        metrics = self._workflow_metrics[workflow_type]
        
        if event_type == "started":
            metrics["total_executions"] += 1
            metrics["last_execution"] = datetime.utcnow().isoformat()
        elif event_type == "completed":
            metrics["successful_executions"] += 1
            if workflow_context.created_at and workflow_context.completed_at:
                duration = (workflow_context.completed_at - workflow_context.created_at).total_seconds()
                current_avg = metrics["average_duration"]
                total_successful = metrics["successful_executions"]
                metrics["average_duration"] = ((current_avg * (total_successful - 1)) + duration) / total_successful
        elif event_type == "failed":
            metrics["failed_executions"] += 1
    
    def _update_step_metrics(self, workflow_context: WorkflowContext, 
                           step: WorkflowStep, event_type: str) -> None:
        """
        Update step execution metrics for performance analysis.
        
        Args:
            workflow_context: Workflow context
            step: Workflow step
            event_type: Type of step event
        """
        # Implementation for step-level metrics tracking
        pass
    
    def get_workflow_status(self, workflow_id: str) -> Optional[WorkflowContext]:
        """
        Get current status of a workflow execution.
        
        Args:
            workflow_id: Unique workflow identifier
        
        Returns:
            WorkflowContext if found, None otherwise
        """
        return self._active_workflows.get(workflow_id)
    
    def get_workflow_metrics(self) -> Dict[str, Dict[str, Any]]:
        """
        Get workflow execution metrics for monitoring.
        
        Returns:
            Dictionary of workflow metrics by workflow type
        """
        return self._workflow_metrics.copy()
    
    def cancel_workflow(self, workflow_id: str) -> bool:
        """
        Cancel an active workflow execution.
        
        Args:
            workflow_id: Unique workflow identifier
        
        Returns:
            True if workflow was cancelled successfully
        """
        workflow_context = self._active_workflows.get(workflow_id)
        if not workflow_context:
            return False
        
        if workflow_context.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]:
            return False
        
        workflow_context.status = WorkflowStatus.CANCELLED
        workflow_context.updated_at = datetime.utcnow()
        
        self.logger.info(f"Cancelled workflow: {workflow_id}")
        return True
    
    # Workflow step implementations for common business processes
    
    @workflow_step(
        step_id="validate_user_access",
        step_name="Validate User Access Rights",
        critical=True,
        required_services=["user_service", "validation_service"]
    )
    def validate_user_access_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to validate user access rights for business operations.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Validation result with user access information
        """
        user_id = workflow_context.context_data.get("user_id")
        if not user_id:
            raise ValidationError("User ID required for access validation")
        
        # Validate user through composed user service
        user_validation_result = self.user_service.validate_user_access(
            user_id, workflow_context.context_data
        )
        
        # Additional validation through validation service
        validation_result = self.validation_service.validate_user_permissions(
            user_id, workflow_context.context_data
        )
        
        return {
            "user_validation": user_validation_result,
            "permission_validation": validation_result,
            "access_granted": user_validation_result and validation_result
        }
    
    @workflow_step(
        step_id="create_business_entity",
        step_name="Create Business Entity",
        rollback_function=lambda ctx: ctx.step_results.get("create_business_entity", {}).get("entity_id"),
        critical=True,
        depends_on=["validate_user_access"],
        required_services=["business_entity_service", "validation_service"]
    )
    def create_business_entity_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to create business entity with comprehensive validation.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Created entity information
        """
        entity_data = workflow_context.context_data.get("entity_data")
        if not entity_data:
            raise ValidationError("Entity data required for creation")
        
        # Validate entity data through validation service
        validation_result = self.validation_service.validate_entity_creation(entity_data)
        if not validation_result:
            raise ValidationError("Entity data validation failed")
        
        # Create entity through business entity service
        created_entity = self.business_entity_service.create_entity(
            entity_data, workflow_context.user_id
        )
        
        return {
            "entity_id": created_entity.id,
            "entity_data": created_entity.to_dict(),
            "validation_result": validation_result
        }
    
    def rollback_business_entity_creation(self, workflow_context: WorkflowContext) -> None:
        """
        Rollback function for business entity creation step.
        
        Args:
            workflow_context: Workflow context with rollback information
        """
        step_result = workflow_context.step_results.get("create_business_entity")
        if step_result and "entity_id" in step_result:
            entity_id = step_result["entity_id"]
            try:
                self.business_entity_service.delete_entity(entity_id)
                self.logger.info(f"Rolled back entity creation: {entity_id}")
            except Exception as e:
                self.logger.error(f"Failed to rollback entity creation {entity_id}: {e}")
    
    @workflow_step(
        step_id="establish_entity_relationships",
        step_name="Establish Entity Relationships",
        rollback_function=lambda ctx: None,  # Will implement rollback separately
        critical=False,
        depends_on=["create_business_entity"],
        required_services=["business_entity_service", "validation_service"]
    )
    def establish_entity_relationships_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to establish business entity relationships.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Relationship establishment results
        """
        entity_id = workflow_context.step_results.get("create_business_entity", {}).get("entity_id")
        if not entity_id:
            raise ValidationError("Entity ID required for relationship establishment")
        
        relationship_data = workflow_context.context_data.get("relationships", [])
        established_relationships = []
        
        for relationship in relationship_data:
            try:
                # Validate relationship data
                validation_result = self.validation_service.validate_relationship_data(relationship)
                if not validation_result:
                    continue
                
                # Create relationship through business entity service
                created_relationship = self.business_entity_service.create_relationship(
                    entity_id, relationship
                )
                established_relationships.append({
                    "relationship_id": created_relationship.id,
                    "relationship_type": created_relationship.relationship_type,
                    "target_entity_id": created_relationship.target_entity_id
                })
                
            except Exception as e:
                self.logger.warning(f"Failed to establish relationship: {e}")
                continue
        
        return {
            "established_relationships": established_relationships,
            "total_relationships": len(established_relationships),
            "requested_relationships": len(relationship_data)
        }
    
    @workflow_step(
        step_id="validate_business_constraints",
        step_name="Validate Business Constraints",
        critical=True,
        depends_on=["create_business_entity"],
        required_services=["validation_service", "business_entity_service"]
    )
    def validate_business_constraints_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to validate complex business constraints.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Business constraint validation results
        """
        entity_id = workflow_context.step_results.get("create_business_entity", {}).get("entity_id")
        if not entity_id:
            raise ValidationError("Entity ID required for constraint validation")
        
        # Comprehensive business constraint validation
        constraint_checks = {
            "entity_data_integrity": False,
            "relationship_constraints": False,
            "business_rules_compliance": False,
            "cross_entity_constraints": False
        }
        
        try:
            # Validate entity data integrity
            entity_validation = self.validation_service.validate_entity_integrity(entity_id)
            constraint_checks["entity_data_integrity"] = entity_validation
            
            # Validate relationship constraints
            relationship_validation = self.validation_service.validate_relationship_constraints(entity_id)
            constraint_checks["relationship_constraints"] = relationship_validation
            
            # Validate business rules compliance
            business_rules_validation = self.validation_service.validate_business_rules_compliance(
                entity_id, workflow_context.context_data
            )
            constraint_checks["business_rules_compliance"] = business_rules_validation
            
            # Validate cross-entity constraints
            cross_entity_validation = self.business_entity_service.validate_cross_entity_constraints(
                entity_id, workflow_context.context_data
            )
            constraint_checks["cross_entity_constraints"] = cross_entity_validation
            
        except Exception as e:
            self.logger.error(f"Business constraint validation failed: {e}")
            raise ValidationError(f"Business constraint validation error: {str(e)}")
        
        # Check if all constraints pass
        all_constraints_valid = all(constraint_checks.values())
        
        if not all_constraints_valid:
            failed_constraints = [
                constraint for constraint, valid in constraint_checks.items() 
                if not valid
            ]
            raise ValidationError(
                f"Business constraint validation failed: {', '.join(failed_constraints)}"
            )
        
        return {
            "constraint_checks": constraint_checks,
            "all_constraints_valid": all_constraints_valid,
            "validation_timestamp": datetime.utcnow().isoformat()
        }
    
    @workflow_step(
        step_id="finalize_workflow_operations",
        step_name="Finalize Workflow Operations",
        critical=True,
        depends_on=["validate_business_constraints", "establish_entity_relationships"],
        required_services=["business_entity_service", "user_service"]
    )
    def finalize_workflow_operations_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to finalize all workflow operations.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Finalization results and summary
        """
        entity_id = workflow_context.step_results.get("create_business_entity", {}).get("entity_id")
        if not entity_id:
            raise ValidationError("Entity ID required for workflow finalization")
        
        # Finalize entity status
        finalization_result = self.business_entity_service.finalize_entity_creation(
            entity_id, workflow_context.context_data
        )
        
        # Update user activity tracking
        if workflow_context.user_id:
            self.user_service.update_user_activity(
                workflow_context.user_id,
                {
                    "activity_type": "workflow_completion",
                    "workflow_id": workflow_context.workflow_id,
                    "workflow_type": workflow_context.workflow_type,
                    "entity_id": entity_id
                }
            )
        
        # Generate workflow summary
        workflow_summary = {
            "workflow_id": workflow_context.workflow_id,
            "workflow_type": workflow_context.workflow_type,
            "entity_id": entity_id,
            "total_steps_executed": len(workflow_context.step_results),
            "successful_steps": len([
                result for result in workflow_context.step_results.values()
                if result.get("status") == WorkflowStepStatus.COMPLETED.name
            ]),
            "execution_duration": (
                datetime.utcnow() - workflow_context.created_at
            ).total_seconds(),
            "finalization_result": finalization_result
        }
        
        return workflow_summary
    
    # High-level workflow definitions for common business processes
    
    def register_default_workflows(self) -> None:
        """
        Register default workflow definitions for common business processes.
        
        Provides out-of-the-box workflow definitions for standard business
        operations with comprehensive step coordination and error handling.
        """
        # Business entity creation workflow
        entity_creation_steps = [
            self.validate_user_access_step._workflow_step,
            self.create_business_entity_step._workflow_step,
            self.establish_entity_relationships_step._workflow_step,
            self.validate_business_constraints_step._workflow_step,
            self.finalize_workflow_operations_step._workflow_step
        ]
        
        # Update rollback function references for proper workflow context
        entity_creation_steps[1].rollback_function = self.rollback_business_entity_creation
        
        self.register_workflow_definition("entity_creation", entity_creation_steps)
        
        # User registration workflow
        user_registration_steps = [
            self.validate_user_registration_step._workflow_step,
            self.create_user_account_step._workflow_step,
            self.setup_user_profile_step._workflow_step,
            self.send_welcome_notification_step._workflow_step
        ]
        
        self.register_workflow_definition("user_registration", user_registration_steps)
        
        # Complex business operation workflow
        complex_operation_steps = [
            self.validate_user_access_step._workflow_step,
            self.validate_operation_prerequisites_step._workflow_step,
            self.execute_business_logic_step._workflow_step,
            self.update_related_entities_step._workflow_step,
            self.generate_operation_report_step._workflow_step
        ]
        
        self.register_workflow_definition("complex_business_operation", complex_operation_steps)
        
        self.logger.info("Registered default workflow definitions")
    
    # Additional workflow step implementations
    
    @workflow_step(
        step_id="validate_user_registration",
        step_name="Validate User Registration Data",
        critical=True,
        required_services=["validation_service"]
    )
    def validate_user_registration_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to validate user registration data.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            User registration validation results
        """
        user_data = workflow_context.context_data.get("user_data")
        if not user_data:
            raise ValidationError("User data required for registration validation")
        
        # Comprehensive user registration validation
        validation_result = self.validation_service.validate_user_registration(user_data)
        
        if not validation_result.get("valid", False):
            validation_errors = validation_result.get("errors", [])
            raise ValidationError(f"User registration validation failed: {', '.join(validation_errors)}")
        
        return validation_result
    
    @workflow_step(
        step_id="create_user_account",
        step_name="Create User Account",
        rollback_function=lambda ctx: None,  # Will implement rollback separately
        critical=True,
        depends_on=["validate_user_registration"],
        required_services=["user_service"]
    )
    def create_user_account_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to create user account.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Created user account information
        """
        user_data = workflow_context.context_data.get("user_data")
        
        # Create user through user service
        created_user = self.user_service.create_user(user_data)
        
        return {
            "user_id": created_user.id,
            "username": created_user.username,
            "email": created_user.email,
            "created_at": created_user.created_at.isoformat()
        }
    
    @workflow_step(
        step_id="setup_user_profile",
        step_name="Setup User Profile",
        critical=False,
        depends_on=["create_user_account"],
        required_services=["user_service"]
    )
    def setup_user_profile_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to setup user profile.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            User profile setup results
        """
        user_id = workflow_context.step_results.get("create_user_account", {}).get("user_id")
        profile_data = workflow_context.context_data.get("profile_data", {})
        
        if user_id and profile_data:
            profile_result = self.user_service.setup_user_profile(user_id, profile_data)
            return {"profile_setup": profile_result}
        
        return {"profile_setup": "skipped"}
    
    @workflow_step(
        step_id="send_welcome_notification",
        step_name="Send Welcome Notification",
        critical=False,
        depends_on=["create_user_account"],
        required_services=["user_service"]
    )
    def send_welcome_notification_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to send welcome notification.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Notification sending results
        """
        user_id = workflow_context.step_results.get("create_user_account", {}).get("user_id")
        
        if user_id:
            notification_result = self.user_service.send_welcome_notification(user_id)
            return {"notification_sent": notification_result}
        
        return {"notification_sent": False}
    
    @workflow_step(
        step_id="validate_operation_prerequisites",
        step_name="Validate Operation Prerequisites",
        critical=True,
        depends_on=["validate_user_access"],
        required_services=["validation_service", "business_entity_service"]
    )
    def validate_operation_prerequisites_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to validate complex operation prerequisites.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Prerequisites validation results
        """
        operation_data = workflow_context.context_data.get("operation_data")
        if not operation_data:
            raise ValidationError("Operation data required for prerequisite validation")
        
        # Validate operation prerequisites
        prerequisite_checks = self.validation_service.validate_operation_prerequisites(
            operation_data, workflow_context.user_id
        )
        
        if not prerequisite_checks.get("all_prerequisites_met", False):
            failed_prerequisites = prerequisite_checks.get("failed_prerequisites", [])
            raise ValidationError(
                f"Operation prerequisites not met: {', '.join(failed_prerequisites)}"
            )
        
        return prerequisite_checks
    
    @workflow_step(
        step_id="execute_business_logic",
        step_name="Execute Core Business Logic",
        critical=True,
        depends_on=["validate_operation_prerequisites"],
        required_services=["business_entity_service", "validation_service"]
    )
    def execute_business_logic_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to execute core business logic operations.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Business logic execution results
        """
        operation_data = workflow_context.context_data.get("operation_data")
        operation_type = operation_data.get("operation_type")
        
        # Execute business logic based on operation type
        if operation_type == "entity_update":
            result = self.business_entity_service.execute_entity_update(
                operation_data, workflow_context.user_id
            )
        elif operation_type == "relationship_management":
            result = self.business_entity_service.execute_relationship_management(
                operation_data, workflow_context.user_id
            )
        elif operation_type == "data_processing":
            result = self.business_entity_service.execute_data_processing(
                operation_data, workflow_context.user_id
            )
        else:
            raise ValidationError(f"Unknown operation type: {operation_type}")
        
        return {
            "operation_type": operation_type,
            "execution_result": result,
            "execution_timestamp": datetime.utcnow().isoformat()
        }
    
    @workflow_step(
        step_id="update_related_entities",
        step_name="Update Related Entities",
        critical=False,
        depends_on=["execute_business_logic"],
        required_services=["business_entity_service"]
    )
    def update_related_entities_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to update entities related to the main operation.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Related entity update results
        """
        operation_result = workflow_context.step_results.get("execute_business_logic", {})
        
        if "affected_entities" in operation_result.get("execution_result", {}):
            affected_entities = operation_result["execution_result"]["affected_entities"]
            
            update_results = []
            for entity_id in affected_entities:
                try:
                    update_result = self.business_entity_service.update_related_entity(
                        entity_id, workflow_context.context_data
                    )
                    update_results.append({
                        "entity_id": entity_id,
                        "update_result": update_result
                    })
                except Exception as e:
                    self.logger.warning(f"Failed to update related entity {entity_id}: {e}")
                    update_results.append({
                        "entity_id": entity_id,
                        "update_result": None,
                        "error": str(e)
                    })
            
            return {
                "updated_entities": update_results,
                "total_updates": len(update_results)
            }
        
        return {"updated_entities": [], "total_updates": 0}
    
    @workflow_step(
        step_id="generate_operation_report",
        step_name="Generate Operation Report",
        critical=False,
        depends_on=["execute_business_logic", "update_related_entities"],
        required_services=["business_entity_service"]
    )
    def generate_operation_report_step(self, workflow_context: WorkflowContext) -> Dict[str, Any]:
        """
        Workflow step to generate comprehensive operation report.
        
        Args:
            workflow_context: Current workflow execution context
        
        Returns:
            Generated operation report
        """
        # Generate comprehensive operation report
        report_data = {
            "workflow_summary": {
                "workflow_id": workflow_context.workflow_id,
                "workflow_type": workflow_context.workflow_type,
                "execution_start": workflow_context.created_at.isoformat(),
                "user_id": workflow_context.user_id
            },
            "operation_details": workflow_context.step_results.get("execute_business_logic", {}),
            "related_entity_updates": workflow_context.step_results.get("update_related_entities", {}),
            "execution_metrics": {
                "total_steps": len(workflow_context.step_results),
                "successful_steps": len([
                    result for result in workflow_context.step_results.values()
                    if result.get("status") == WorkflowStepStatus.COMPLETED.name
                ]),
                "failed_steps": len([
                    result for result in workflow_context.step_results.values()
                    if result.get("status") == WorkflowStepStatus.FAILED.name
                ])
            }
        }
        
        # Generate report through business entity service
        report_result = self.business_entity_service.generate_operation_report(report_data)
        
        return {
            "report_generated": True,
            "report_id": report_result.get("report_id"),
            "report_data": report_data
        }
    
    # Utility methods for workflow management
    
    def get_active_workflows(self) -> List[Dict[str, Any]]:
        """
        Get list of currently active workflows.
        
        Returns:
            List of active workflow contexts
        """
        return [
            workflow_context.to_dict()
            for workflow_context in self._active_workflows.values()
        ]
    
    def get_workflow_definition(self, workflow_type: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get workflow definition for a specific workflow type.
        
        Args:
            workflow_type: Type of workflow
        
        Returns:
            List of workflow step definitions if found
        """
        if workflow_type in self._workflow_definitions:
            steps = self._workflow_definitions[workflow_type]
            return [
                {
                    "step_id": step.step_id,
                    "step_name": step.step_name,
                    "required_services": step.required_services,
                    "critical": step.critical,
                    "depends_on": step.depends_on,
                    "timeout_seconds": step.timeout_seconds
                }
                for step in steps
            ]
        return None
    
    def cleanup_completed_workflows(self, max_age_hours: int = 24) -> int:
        """
        Clean up completed workflow contexts to free memory.
        
        Args:
            max_age_hours: Maximum age in hours for completed workflows
        
        Returns:
            Number of workflows cleaned up
        """
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(hours=max_age_hours)
        
        workflows_to_remove = []
        for workflow_id, workflow_context in self._active_workflows.items():
            if (workflow_context.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED] and
                workflow_context.updated_at < cutoff_time):
                workflows_to_remove.append(workflow_id)
        
        for workflow_id in workflows_to_remove:
            del self._active_workflows[workflow_id]
        
        self.logger.info(f"Cleaned up {len(workflows_to_remove)} completed workflows")
        return len(workflows_to_remove)