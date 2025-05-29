"""
Business Logic Workflow Comparison Test Suite

This module implements comprehensive business logic workflow comparison testing ensuring
identical execution patterns and state management between Node.js and Flask implementations.
Validates workflow orchestration through the Service Layer pattern, verifies business rule
compliance, and ensures equivalent transaction handling during migration per Section 4.7.2.

The test suite provides:
- Comprehensive business logic verification ensuring identical workflow outcomes
- Service Layer pattern validation comparing workflow orchestration between systems
- Database transaction handling comparison with state management verification
- Business rule compliance testing with automated validation checkpoints
- Error handling consistency validation between Node.js and Flask implementations
- Automated workflow state comparison with real-time discrepancy detection

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
Testing Framework: pytest-flask 1.3.0, pytest-benchmark 5.1.0, tox 4.26.0
"""

import pytest
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
from contextlib import contextmanager
import asyncio
from dataclasses import dataclass, asdict
from copy import deepcopy

# Flask application testing framework
from flask import Flask, request, g
from flask.testing import FlaskClient

# Service Layer imports for workflow orchestration testing
from src.services.workflow_orchestrator import WorkflowOrchestrator
from src.services.business_entity_service import BusinessEntityService
from src.services.user_service import UserService
from src.services.validation_service import ValidationService
from src.services.base import BaseService

# Model imports for database state verification
from src.models.user import User
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.models.session import UserSession

# Authentication imports for session state testing
from src.auth.models import AuthUser
from src.auth.services import AuthenticationService
from src.auth.utils import TokenManager

# Database and transaction management
from src.models import db
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

# Performance benchmarking
import time
import psutil
import gc
from memory_profiler import profile

# Configuration for multi-environment testing
import os
from contextlib import suppress

# Logging configuration for detailed test reporting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class WorkflowResult:
    """
    Data class for workflow execution results comparison.
    
    Enables structured comparison between Node.js and Flask workflow outcomes
    with comprehensive state tracking and validation metrics.
    """
    execution_id: str
    system_type: str  # 'nodejs' or 'flask'
    workflow_name: str
    start_time: datetime
    end_time: datetime
    execution_time_ms: float
    success: bool
    final_state: Dict[str, Any]
    error_messages: List[str]
    database_changes: Dict[str, Any]
    validation_results: Dict[str, bool]
    memory_usage_mb: float
    cpu_usage_percent: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert workflow result to dictionary for comparison analysis."""
        return asdict(self)


@dataclass
class BusinessRuleResult:
    """
    Data class for business rule validation results.
    
    Tracks business rule compliance across different systems with detailed
    validation metrics and error tracking.
    """
    rule_name: str
    system_type: str
    input_data: Dict[str, Any]
    expected_outcome: Any
    actual_outcome: Any
    validation_passed: bool
    validation_errors: List[str]
    execution_time_ms: float
    
    def matches(self, other: 'BusinessRuleResult') -> bool:
        """Compare business rule results for equivalence."""
        return (
            self.expected_outcome == other.expected_outcome and
            self.actual_outcome == other.actual_outcome and
            self.validation_passed == other.validation_passed
        )


class NodeJSSystemMock:
    """
    Mock implementation of Node.js system for comparative testing.
    
    Simulates Node.js baseline behavior for workflow comparison validation.
    Provides consistent baseline responses for migration validation testing.
    """
    
    def __init__(self):
        """Initialize Node.js system mock with baseline configurations."""
        self.logger = logging.getLogger(f"{__name__}.NodeJSSystemMock")
        self.session_data = {}
        self.entity_data = {}
        self.user_data = {}
        self.workflow_history = []
        self.transaction_log = []
        
    def execute_user_registration_workflow(self, user_data: Dict[str, Any]) -> WorkflowResult:
        """
        Mock Node.js user registration workflow execution.
        
        Returns baseline workflow result for comparison with Flask implementation.
        """
        start_time = datetime.utcnow()
        execution_id = f"nodejs_user_reg_{int(time.time() * 1000)}"
        
        try:
            # Simulate Node.js validation logic
            if not user_data.get('email') or '@' not in user_data['email']:
                raise ValueError("Invalid email format")
            
            if not user_data.get('username') or len(user_data['username']) < 3:
                raise ValueError("Username must be at least 3 characters")
            
            # Simulate database operations
            user_id = f"user_{len(self.user_data) + 1}"
            self.user_data[user_id] = {
                'id': user_id,
                'username': user_data['username'],
                'email': user_data['email'],
                'created_at': start_time.isoformat(),
                'status': 'active'
            }
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds() * 1000
            
            return WorkflowResult(
                execution_id=execution_id,
                system_type='nodejs',
                workflow_name='user_registration',
                start_time=start_time,
                end_time=end_time,
                execution_time_ms=execution_time,
                success=True,
                final_state={'user_id': user_id, 'status': 'registered'},
                error_messages=[],
                database_changes={'users_created': 1},
                validation_results={'email_valid': True, 'username_valid': True},
                memory_usage_mb=45.2,  # Simulated Node.js memory usage
                cpu_usage_percent=12.5
            )
            
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds() * 1000
            
            return WorkflowResult(
                execution_id=execution_id,
                system_type='nodejs',
                workflow_name='user_registration',
                start_time=start_time,
                end_time=end_time,
                execution_time_ms=execution_time,
                success=False,
                final_state={},
                error_messages=[str(e)],
                database_changes={},
                validation_results={'email_valid': False, 'username_valid': False},
                memory_usage_mb=42.1,
                cpu_usage_percent=8.3
            )
    
    def execute_business_entity_workflow(self, entity_data: Dict[str, Any], user_id: str) -> WorkflowResult:
        """
        Mock Node.js business entity creation workflow execution.
        
        Simulates complex business entity workflow with relationship management.
        """
        start_time = datetime.utcnow()
        execution_id = f"nodejs_entity_{int(time.time() * 1000)}"
        
        try:
            # Simulate business validation rules
            if not entity_data.get('name') or len(entity_data['name']) < 2:
                raise ValueError("Entity name must be at least 2 characters")
            
            if user_id not in self.user_data:
                raise ValueError("Invalid user ID")
            
            # Simulate entity creation with relationships
            entity_id = f"entity_{len(self.entity_data) + 1}"
            self.entity_data[entity_id] = {
                'id': entity_id,
                'name': entity_data['name'],
                'description': entity_data.get('description', ''),
                'owner_id': user_id,
                'status': 'active',
                'created_at': start_time.isoformat(),
                'relationships': []
            }
            
            # Simulate relationship creation if parent_entity provided
            if entity_data.get('parent_entity_id'):
                parent_id = entity_data['parent_entity_id']
                if parent_id in self.entity_data:
                    relationship_id = f"rel_{len(self.entity_data)}"
                    self.entity_data[entity_id]['relationships'].append({
                        'id': relationship_id,
                        'source_entity_id': parent_id,
                        'target_entity_id': entity_id,
                        'relationship_type': 'parent_child',
                        'is_active': True
                    })
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds() * 1000
            
            return WorkflowResult(
                execution_id=execution_id,
                system_type='nodejs',
                workflow_name='business_entity_creation',
                start_time=start_time,
                end_time=end_time,
                execution_time_ms=execution_time,
                success=True,
                final_state={
                    'entity_id': entity_id,
                    'relationships_created': len(self.entity_data[entity_id]['relationships']),
                    'status': 'created'
                },
                error_messages=[],
                database_changes={
                    'entities_created': 1,
                    'relationships_created': len(self.entity_data[entity_id]['relationships'])
                },
                validation_results={
                    'name_valid': True,
                    'owner_valid': True,
                    'relationships_valid': True
                },
                memory_usage_mb=52.7,
                cpu_usage_percent=18.2
            )
            
        except Exception as e:
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds() * 1000
            
            return WorkflowResult(
                execution_id=execution_id,
                system_type='nodejs',
                workflow_name='business_entity_creation',
                start_time=start_time,
                end_time=end_time,
                execution_time_ms=execution_time,
                success=False,
                final_state={},
                error_messages=[str(e)],
                database_changes={},
                validation_results={'name_valid': False, 'owner_valid': False},
                memory_usage_mb=48.3,
                cpu_usage_percent=15.1
            )
    
    def validate_business_rule(self, rule_name: str, input_data: Dict[str, Any]) -> BusinessRuleResult:
        """
        Mock Node.js business rule validation execution.
        
        Simulates business rule processing for comparative validation.
        """
        start_time = time.time()
        
        try:
            if rule_name == "email_uniqueness":
                # Simulate email uniqueness validation
                email = input_data.get('email')
                existing_emails = [user['email'] for user in self.user_data.values()]
                is_unique = email not in existing_emails
                
                return BusinessRuleResult(
                    rule_name=rule_name,
                    system_type='nodejs',
                    input_data=input_data,
                    expected_outcome=True,
                    actual_outcome=is_unique,
                    validation_passed=is_unique,
                    validation_errors=[] if is_unique else ["Email already exists"],
                    execution_time_ms=(time.time() - start_time) * 1000
                )
                
            elif rule_name == "entity_ownership":
                # Simulate entity ownership validation
                user_id = input_data.get('user_id')
                entity_id = input_data.get('entity_id')
                
                if entity_id in self.entity_data:
                    owner_id = self.entity_data[entity_id]['owner_id']
                    is_owner = owner_id == user_id
                else:
                    is_owner = False
                
                return BusinessRuleResult(
                    rule_name=rule_name,
                    system_type='nodejs',
                    input_data=input_data,
                    expected_outcome=True,
                    actual_outcome=is_owner,
                    validation_passed=is_owner,
                    validation_errors=[] if is_owner else ["User is not entity owner"],
                    execution_time_ms=(time.time() - start_time) * 1000
                )
                
            else:
                raise ValueError(f"Unknown business rule: {rule_name}")
                
        except Exception as e:
            return BusinessRuleResult(
                rule_name=rule_name,
                system_type='nodejs',
                input_data=input_data,
                expected_outcome=None,
                actual_outcome=None,
                validation_passed=False,
                validation_errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000
            )


class FlaskWorkflowExecutor:
    """
    Flask workflow execution utility for comparative testing.
    
    Orchestrates Flask service layer workflow execution with comprehensive
    state tracking and performance monitoring for comparison validation.
    """
    
    def __init__(self, app: Flask, db_session: SQLAlchemy):
        """Initialize Flask workflow executor with application context."""
        self.app = app
        self.db = db_session
        self.logger = logging.getLogger(f"{__name__}.FlaskWorkflowExecutor")
        
        # Initialize service layer components
        self.workflow_orchestrator = WorkflowOrchestrator()
        self.business_entity_service = BusinessEntityService()
        self.user_service = UserService()
        self.validation_service = ValidationService()
        self.auth_service = AuthenticationService()
    
    @contextmanager
    def workflow_context(self, execution_id: str):
        """
        Context manager for Flask workflow execution with transaction management.
        
        Provides consistent transaction boundaries and resource cleanup for
        workflow testing with comprehensive error handling and state tracking.
        """
        try:
            # Start database transaction
            self.db.session.begin()
            
            # Track workflow execution start
            workflow_start = datetime.utcnow()
            self.logger.info(f"Starting Flask workflow execution: {execution_id}")
            
            # Capture initial memory state
            process = psutil.Process()
            initial_memory = process.memory_info().rss / 1024 / 1024  # MB
            initial_cpu = process.cpu_percent()
            
            yield {
                'execution_id': execution_id,
                'start_time': workflow_start,
                'initial_memory_mb': initial_memory,
                'initial_cpu_percent': initial_cpu
            }
            
        except Exception as e:
            # Rollback transaction on error
            self.db.session.rollback()
            self.logger.error(f"Flask workflow execution failed: {execution_id}, Error: {str(e)}")
            raise
        finally:
            # Ensure transaction cleanup
            if self.db.session.is_active:
                self.db.session.commit()
            
            # Final resource measurement
            process = psutil.Process()
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            final_cpu = process.cpu_percent()
            
            self.logger.info(f"Completed Flask workflow execution: {execution_id}")
            self.logger.info(f"Memory usage: {final_memory:.2f} MB, CPU: {final_cpu:.1f}%")
    
    def execute_user_registration_workflow(self, user_data: Dict[str, Any]) -> WorkflowResult:
        """
        Execute Flask user registration workflow with comprehensive tracking.
        
        Implements Service Layer pattern workflow orchestration for user
        registration with validation, database operations, and state management.
        """
        execution_id = f"flask_user_reg_{int(time.time() * 1000)}"
        
        with self.workflow_context(execution_id) as context:
            start_time = context['start_time']
            
            try:
                # Service Layer workflow orchestration
                with self.app.app_context():
                    # Step 1: Input validation through validation service
                    validation_result = self.validation_service.validate_user_data(user_data)
                    if not validation_result.is_valid:
                        raise ValueError(f"Validation failed: {validation_result.errors}")
                    
                    # Step 2: Business rule validation
                    email_unique = self.user_service.is_email_unique(user_data['email'])
                    username_unique = self.user_service.is_username_unique(user_data['username'])
                    
                    if not email_unique:
                        raise ValueError("Email already exists")
                    if not username_unique:
                        raise ValueError("Username already exists")
                    
                    # Step 3: User creation through service layer
                    user = self.user_service.create_user(
                        username=user_data['username'],
                        email=user_data['email'],
                        password=user_data.get('password', 'default_password')
                    )
                    
                    # Step 4: Session creation for authentication
                    session = self.auth_service.create_user_session(user.id)
                    
                    # Step 5: Workflow completion and state capture
                    end_time = datetime.utcnow()
                    execution_time = (end_time - start_time).total_seconds() * 1000
                    
                    # Resource usage measurement
                    process = psutil.Process()
                    final_memory = process.memory_info().rss / 1024 / 1024
                    final_cpu = process.cpu_percent()
                    
                    return WorkflowResult(
                        execution_id=execution_id,
                        system_type='flask',
                        workflow_name='user_registration',
                        start_time=start_time,
                        end_time=end_time,
                        execution_time_ms=execution_time,
                        success=True,
                        final_state={
                            'user_id': user.id,
                            'session_id': session.id,
                            'status': 'registered'
                        },
                        error_messages=[],
                        database_changes={
                            'users_created': 1,
                            'sessions_created': 1
                        },
                        validation_results={
                            'email_valid': True,
                            'username_valid': True,
                            'email_unique': True,
                            'username_unique': True
                        },
                        memory_usage_mb=final_memory,
                        cpu_usage_percent=final_cpu
                    )
                    
            except Exception as e:
                end_time = datetime.utcnow()
                execution_time = (end_time - start_time).total_seconds() * 1000
                
                # Resource usage measurement for error case
                process = psutil.Process()
                final_memory = process.memory_info().rss / 1024 / 1024
                final_cpu = process.cpu_percent()
                
                return WorkflowResult(
                    execution_id=execution_id,
                    system_type='flask',
                    workflow_name='user_registration',
                    start_time=start_time,
                    end_time=end_time,
                    execution_time_ms=execution_time,
                    success=False,
                    final_state={},
                    error_messages=[str(e)],
                    database_changes={},
                    validation_results={
                        'email_valid': False,
                        'username_valid': False
                    },
                    memory_usage_mb=final_memory,
                    cpu_usage_percent=final_cpu
                )
    
    def execute_business_entity_workflow(self, entity_data: Dict[str, Any], user_id: int) -> WorkflowResult:
        """
        Execute Flask business entity creation workflow with relationship management.
        
        Implements complex Service Layer workflow orchestration for business entity
        creation with comprehensive validation and relationship handling.
        """
        execution_id = f"flask_entity_{int(time.time() * 1000)}"
        
        with self.workflow_context(execution_id) as context:
            start_time = context['start_time']
            
            try:
                with self.app.app_context():
                    # Step 1: Entity data validation
                    validation_result = self.validation_service.validate_entity_data(entity_data)
                    if not validation_result.is_valid:
                        raise ValueError(f"Entity validation failed: {validation_result.errors}")
                    
                    # Step 2: User ownership validation
                    user = self.user_service.get_user_by_id(user_id)
                    if not user:
                        raise ValueError("Invalid user ID")
                    
                    # Step 3: Business entity creation through service layer
                    entity = self.business_entity_service.create_entity(
                        name=entity_data['name'],
                        description=entity_data.get('description', ''),
                        owner_id=user_id
                    )
                    
                    # Step 4: Relationship management if parent entity specified
                    relationships_created = 0
                    if entity_data.get('parent_entity_id'):
                        parent_entity_id = entity_data['parent_entity_id']
                        parent_entity = self.business_entity_service.get_entity_by_id(parent_entity_id)
                        
                        if parent_entity:
                            relationship = self.business_entity_service.create_entity_relationship(
                                source_entity_id=parent_entity_id,
                                target_entity_id=entity.id,
                                relationship_type='parent_child'
                            )
                            relationships_created = 1
                    
                    # Step 5: Workflow orchestration completion
                    workflow_state = self.workflow_orchestrator.complete_entity_workflow(
                        entity_id=entity.id,
                        relationships_count=relationships_created
                    )
                    
                    end_time = datetime.utcnow()
                    execution_time = (end_time - start_time).total_seconds() * 1000
                    
                    # Resource usage measurement
                    process = psutil.Process()
                    final_memory = process.memory_info().rss / 1024 / 1024
                    final_cpu = process.cpu_percent()
                    
                    return WorkflowResult(
                        execution_id=execution_id,
                        system_type='flask',
                        workflow_name='business_entity_creation',
                        start_time=start_time,
                        end_time=end_time,
                        execution_time_ms=execution_time,
                        success=True,
                        final_state={
                            'entity_id': entity.id,
                            'relationships_created': relationships_created,
                            'workflow_status': workflow_state.status,
                            'status': 'created'
                        },
                        error_messages=[],
                        database_changes={
                            'entities_created': 1,
                            'relationships_created': relationships_created
                        },
                        validation_results={
                            'name_valid': True,
                            'owner_valid': True,
                            'relationships_valid': True,
                            'workflow_completed': True
                        },
                        memory_usage_mb=final_memory,
                        cpu_usage_percent=final_cpu
                    )
                    
            except Exception as e:
                end_time = datetime.utcnow()
                execution_time = (end_time - start_time).total_seconds() * 1000
                
                process = psutil.Process()
                final_memory = process.memory_info().rss / 1024 / 1024
                final_cpu = process.cpu_percent()
                
                return WorkflowResult(
                    execution_id=execution_id,
                    system_type='flask',
                    workflow_name='business_entity_creation',
                    start_time=start_time,
                    end_time=end_time,
                    execution_time_ms=execution_time,
                    success=False,
                    final_state={},
                    error_messages=[str(e)],
                    database_changes={},
                    validation_results={
                        'name_valid': False,
                        'owner_valid': False,
                        'workflow_completed': False
                    },
                    memory_usage_mb=final_memory,
                    cpu_usage_percent=final_cpu
                )
    
    def validate_business_rule(self, rule_name: str, input_data: Dict[str, Any]) -> BusinessRuleResult:
        """
        Execute Flask business rule validation with Service Layer pattern.
        
        Implements business rule validation through Service Layer orchestration
        with comprehensive error handling and performance tracking.
        """
        start_time = time.time()
        
        try:
            with self.app.app_context():
                if rule_name == "email_uniqueness":
                    email = input_data.get('email')
                    is_unique = self.user_service.is_email_unique(email)
                    
                    return BusinessRuleResult(
                        rule_name=rule_name,
                        system_type='flask',
                        input_data=input_data,
                        expected_outcome=True,
                        actual_outcome=is_unique,
                        validation_passed=is_unique,
                        validation_errors=[] if is_unique else ["Email already exists"],
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
                    
                elif rule_name == "entity_ownership":
                    user_id = input_data.get('user_id')
                    entity_id = input_data.get('entity_id')
                    
                    is_owner = self.business_entity_service.verify_entity_ownership(
                        entity_id=entity_id,
                        user_id=user_id
                    )
                    
                    return BusinessRuleResult(
                        rule_name=rule_name,
                        system_type='flask',
                        input_data=input_data,
                        expected_outcome=True,
                        actual_outcome=is_owner,
                        validation_passed=is_owner,
                        validation_errors=[] if is_owner else ["User is not entity owner"],
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
                    
                else:
                    raise ValueError(f"Unknown business rule: {rule_name}")
                    
        except Exception as e:
            return BusinessRuleResult(
                rule_name=rule_name,
                system_type='flask',
                input_data=input_data,
                expected_outcome=None,
                actual_outcome=None,
                validation_passed=False,
                validation_errors=[str(e)],
                execution_time_ms=(time.time() - start_time) * 1000
            )


class WorkflowComparator:
    """
    Comprehensive workflow comparison utility for migration validation.
    
    Provides detailed analysis of workflow execution differences between
    Node.js and Flask implementations with automated discrepancy detection
    and comprehensive reporting capabilities.
    """
    
    def __init__(self):
        """Initialize workflow comparator with analysis configurations."""
        self.logger = logging.getLogger(f"{__name__}.WorkflowComparator")
        self.tolerance_ms = 100  # Performance tolerance in milliseconds
        self.memory_tolerance_percent = 10  # Memory usage tolerance percentage
        
    def compare_workflow_results(self, nodejs_result: WorkflowResult, flask_result: WorkflowResult) -> Dict[str, Any]:
        """
        Comprehensive comparison of workflow execution results.
        
        Analyzes workflow outcomes, performance metrics, database changes,
        and validation results to identify migration parity compliance.
        """
        comparison = {
            'workflow_name': nodejs_result.workflow_name,
            'execution_comparison': {
                'nodejs_execution_id': nodejs_result.execution_id,
                'flask_execution_id': flask_result.execution_id,
                'success_match': nodejs_result.success == flask_result.success,
                'nodejs_success': nodejs_result.success,
                'flask_success': flask_result.success
            },
            'performance_analysis': self._analyze_performance(nodejs_result, flask_result),
            'state_comparison': self._compare_final_states(nodejs_result, flask_result),
            'database_changes_comparison': self._compare_database_changes(nodejs_result, flask_result),
            'validation_results_comparison': self._compare_validation_results(nodejs_result, flask_result),
            'error_handling_comparison': self._compare_error_handling(nodejs_result, flask_result),
            'overall_parity': True,  # Will be set based on analysis
            'discrepancies': [],
            'recommendations': []
        }
        
        # Determine overall parity and collect discrepancies
        self._assess_overall_parity(comparison, nodejs_result, flask_result)
        
        return comparison
    
    def _analyze_performance(self, nodejs_result: WorkflowResult, flask_result: WorkflowResult) -> Dict[str, Any]:
        """Analyze performance metrics between Node.js and Flask implementations."""
        performance_analysis = {
            'execution_time': {
                'nodejs_ms': nodejs_result.execution_time_ms,
                'flask_ms': flask_result.execution_time_ms,
                'difference_ms': flask_result.execution_time_ms - nodejs_result.execution_time_ms,
                'within_tolerance': abs(flask_result.execution_time_ms - nodejs_result.execution_time_ms) <= self.tolerance_ms,
                'flask_faster': flask_result.execution_time_ms < nodejs_result.execution_time_ms
            },
            'memory_usage': {
                'nodejs_mb': nodejs_result.memory_usage_mb,
                'flask_mb': flask_result.memory_usage_mb,
                'difference_mb': flask_result.memory_usage_mb - nodejs_result.memory_usage_mb,
                'difference_percent': ((flask_result.memory_usage_mb - nodejs_result.memory_usage_mb) / nodejs_result.memory_usage_mb) * 100,
                'within_tolerance': abs(((flask_result.memory_usage_mb - nodejs_result.memory_usage_mb) / nodejs_result.memory_usage_mb) * 100) <= self.memory_tolerance_percent,
                'flask_more_efficient': flask_result.memory_usage_mb < nodejs_result.memory_usage_mb
            },
            'cpu_usage': {
                'nodejs_percent': nodejs_result.cpu_usage_percent,
                'flask_percent': flask_result.cpu_usage_percent,
                'difference_percent': flask_result.cpu_usage_percent - nodejs_result.cpu_usage_percent
            }
        }
        
        return performance_analysis
    
    def _compare_final_states(self, nodejs_result: WorkflowResult, flask_result: WorkflowResult) -> Dict[str, Any]:
        """Compare final workflow states for functional equivalence."""
        nodejs_state = nodejs_result.final_state
        flask_state = flask_result.final_state
        
        # Extract comparable state elements
        comparable_keys = set(nodejs_state.keys()) & set(flask_state.keys())
        nodejs_only_keys = set(nodejs_state.keys()) - set(flask_state.keys())
        flask_only_keys = set(flask_state.keys()) - set(nodejs_state.keys())
        
        state_matches = {}
        for key in comparable_keys:
            # Handle different ID formats (string vs int)
            nodejs_val = str(nodejs_state[key]) if key.endswith('_id') else nodejs_state[key]
            flask_val = str(flask_state[key]) if key.endswith('_id') else flask_state[key]
            state_matches[key] = nodejs_val == flask_val
        
        return {
            'comparable_keys': list(comparable_keys),
            'nodejs_only_keys': list(nodejs_only_keys),
            'flask_only_keys': list(flask_only_keys),
            'state_matches': state_matches,
            'all_comparable_match': all(state_matches.values()) if state_matches else True,
            'nodejs_final_state': nodejs_state,
            'flask_final_state': flask_state
        }
    
    def _compare_database_changes(self, nodejs_result: WorkflowResult, flask_result: WorkflowResult) -> Dict[str, Any]:
        """Compare database modification patterns between implementations."""
        nodejs_changes = nodejs_result.database_changes
        flask_changes = flask_result.database_changes
        
        change_comparison = {}
        all_change_keys = set(nodejs_changes.keys()) | set(flask_changes.keys())
        
        for key in all_change_keys:
            nodejs_value = nodejs_changes.get(key, 0)
            flask_value = flask_changes.get(key, 0)
            change_comparison[key] = {
                'nodejs_count': nodejs_value,
                'flask_count': flask_value,
                'match': nodejs_value == flask_value
            }
        
        return {
            'change_comparison': change_comparison,
            'all_changes_match': all(comp['match'] for comp in change_comparison.values()),
            'nodejs_total_changes': sum(nodejs_changes.values()),
            'flask_total_changes': sum(flask_changes.values())
        }
    
    def _compare_validation_results(self, nodejs_result: WorkflowResult, flask_result: WorkflowResult) -> Dict[str, Any]:
        """Compare validation patterns and business rule compliance."""
        nodejs_validations = nodejs_result.validation_results
        flask_validations = flask_result.validation_results
        
        validation_comparison = {}
        all_validation_keys = set(nodejs_validations.keys()) | set(flask_validations.keys())
        
        for key in all_validation_keys:
            nodejs_value = nodejs_validations.get(key, None)
            flask_value = flask_validations.get(key, None)
            validation_comparison[key] = {
                'nodejs_result': nodejs_value,
                'flask_result': flask_value,
                'match': nodejs_value == flask_value
            }
        
        return {
            'validation_comparison': validation_comparison,
            'all_validations_match': all(comp['match'] for comp in validation_comparison.values()),
            'validation_coverage': {
                'nodejs_validations': len(nodejs_validations),
                'flask_validations': len(flask_validations),
                'common_validations': len(set(nodejs_validations.keys()) & set(flask_validations.keys()))
            }
        }
    
    def _compare_error_handling(self, nodejs_result: WorkflowResult, flask_result: WorkflowResult) -> Dict[str, Any]:
        """Compare error handling patterns and consistency."""
        return {
            'error_consistency': {
                'nodejs_errors': nodejs_result.error_messages,
                'flask_errors': flask_result.error_messages,
                'error_count_match': len(nodejs_result.error_messages) == len(flask_result.error_messages),
                'both_success': nodejs_result.success and flask_result.success,
                'both_failure': not nodejs_result.success and not flask_result.success,
                'error_handling_consistent': (nodejs_result.success == flask_result.success)
            }
        }
    
    def _assess_overall_parity(self, comparison: Dict[str, Any], nodejs_result: WorkflowResult, flask_result: WorkflowResult):
        """Assess overall migration parity and identify discrepancies."""
        discrepancies = []
        recommendations = []
        
        # Check execution success parity
        if not comparison['execution_comparison']['success_match']:
            discrepancies.append("Execution success outcomes differ between systems")
            recommendations.append("Review error handling logic in Flask implementation")
        
        # Check performance within tolerance
        perf = comparison['performance_analysis']
        if not perf['execution_time']['within_tolerance']:
            discrepancies.append(f"Execution time difference exceeds tolerance: {perf['execution_time']['difference_ms']:.2f}ms")
            recommendations.append("Optimize Flask performance or adjust tolerance thresholds")
        
        if not perf['memory_usage']['within_tolerance']:
            discrepancies.append(f"Memory usage difference exceeds tolerance: {perf['memory_usage']['difference_percent']:.1f}%")
            recommendations.append("Investigate Flask memory usage patterns and optimization opportunities")
        
        # Check state comparison
        state_comp = comparison['state_comparison']
        if not state_comp['all_comparable_match']:
            discrepancies.append("Final workflow states do not match between systems")
            recommendations.append("Review state management logic in Service Layer implementation")
        
        # Check database changes
        db_comp = comparison['database_changes_comparison']
        if not db_comp['all_changes_match']:
            discrepancies.append("Database modification patterns differ between systems")
            recommendations.append("Verify Flask-SQLAlchemy transaction handling and database operations")
        
        # Check validation results
        val_comp = comparison['validation_results_comparison']
        if not val_comp['all_validations_match']:
            discrepancies.append("Business rule validation results differ between systems")
            recommendations.append("Review validation service implementation and business rule logic")
        
        # Set overall parity status
        comparison['overall_parity'] = len(discrepancies) == 0
        comparison['discrepancies'] = discrepancies
        comparison['recommendations'] = recommendations
        
        # Log analysis results
        if comparison['overall_parity']:
            self.logger.info(f"Workflow parity PASSED for {nodejs_result.workflow_name}")
        else:
            self.logger.warning(f"Workflow parity FAILED for {nodejs_result.workflow_name}: {len(discrepancies)} discrepancies found")
            for disc in discrepancies:
                self.logger.warning(f"  - {disc}")
    
    def compare_business_rules(self, nodejs_result: BusinessRuleResult, flask_result: BusinessRuleResult) -> Dict[str, Any]:
        """
        Compare business rule validation results between implementations.
        
        Provides detailed analysis of business rule compliance and validation
        consistency for migration validation.
        """
        comparison = {
            'rule_name': nodejs_result.rule_name,
            'input_data_match': nodejs_result.input_data == flask_result.input_data,
            'outcome_match': nodejs_result.actual_outcome == flask_result.actual_outcome,
            'validation_match': nodejs_result.validation_passed == flask_result.validation_passed,
            'execution_time_comparison': {
                'nodejs_ms': nodejs_result.execution_time_ms,
                'flask_ms': flask_result.execution_time_ms,
                'difference_ms': flask_result.execution_time_ms - nodejs_result.execution_time_ms,
                'flask_faster': flask_result.execution_time_ms < nodejs_result.execution_time_ms
            },
            'error_comparison': {
                'nodejs_errors': nodejs_result.validation_errors,
                'flask_errors': flask_result.validation_errors,
                'error_consistency': set(nodejs_result.validation_errors) == set(flask_result.validation_errors)
            },
            'overall_rule_parity': True,
            'discrepancies': []
        }
        
        # Assess rule parity
        discrepancies = []
        if not comparison['outcome_match']:
            discrepancies.append(f"Rule outcomes differ: Node.js={nodejs_result.actual_outcome}, Flask={flask_result.actual_outcome}")
        
        if not comparison['validation_match']:
            discrepancies.append(f"Validation results differ: Node.js={nodejs_result.validation_passed}, Flask={flask_result.validation_passed}")
        
        if not comparison['error_comparison']['error_consistency']:
            discrepancies.append("Error messages differ between implementations")
        
        comparison['overall_rule_parity'] = len(discrepancies) == 0
        comparison['discrepancies'] = discrepancies
        
        return comparison


# Test Fixtures and Test Cases


@pytest.fixture
def nodejs_system():
    """Fixture providing Node.js system mock for comparative testing."""
    return NodeJSSystemMock()


@pytest.fixture
def flask_workflow_executor(app, db):
    """Fixture providing Flask workflow executor for comparative testing."""
    return FlaskWorkflowExecutor(app, db)


@pytest.fixture
def workflow_comparator():
    """Fixture providing workflow comparison utility."""
    return WorkflowComparator()


@pytest.fixture
def sample_user_data():
    """Fixture providing sample user data for workflow testing."""
    return {
        'username': 'testuser123',
        'email': 'test@example.com',
        'password': 'SecurePassword123!',
        'first_name': 'Test',
        'last_name': 'User'
    }


@pytest.fixture
def sample_entity_data():
    """Fixture providing sample business entity data for workflow testing."""
    return {
        'name': 'Test Business Entity',
        'description': 'A test business entity for workflow validation',
        'category': 'Testing',
        'metadata': {
            'department': 'QA',
            'priority': 'high'
        }
    }


# Comprehensive Business Logic Workflow Tests


class TestUserRegistrationWorkflow:
    """
    Test suite for user registration workflow comparison.
    
    Validates Service Layer pattern implementation for user registration
    with comprehensive state management and business rule verification.
    """
    
    def test_successful_user_registration_workflow_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator, 
        sample_user_data
    ):
        """
        Test successful user registration workflow parity between systems.
        
        Validates identical workflow execution patterns, database state changes,
        and business rule compliance for successful user registration scenarios.
        """
        # Execute workflow on both systems
        nodejs_result = nodejs_system.execute_user_registration_workflow(sample_user_data)
        flask_result = flask_workflow_executor.execute_user_registration_workflow(sample_user_data)
        
        # Perform comprehensive comparison
        comparison = workflow_comparator.compare_workflow_results(nodejs_result, flask_result)
        
        # Assert overall parity
        assert comparison['overall_parity'], f"User registration workflow parity failed: {comparison['discrepancies']}"
        
        # Assert specific workflow elements
        assert comparison['execution_comparison']['success_match'], "Execution success outcomes must match"
        assert comparison['state_comparison']['all_comparable_match'], "Final states must match"
        assert comparison['database_changes_comparison']['all_changes_match'], "Database changes must match"
        assert comparison['validation_results_comparison']['all_validations_match'], "Validation results must match"
        
        # Assert performance within tolerance
        perf = comparison['performance_analysis']
        assert perf['execution_time']['within_tolerance'], f"Execution time exceeds tolerance: {perf['execution_time']['difference_ms']}ms"
        assert perf['memory_usage']['within_tolerance'], f"Memory usage exceeds tolerance: {perf['memory_usage']['difference_percent']}%"
        
        # Log successful comparison
        logger.info("User registration workflow parity validation PASSED")
        logger.info(f"Performance comparison: Node.js={nodejs_result.execution_time_ms:.2f}ms, Flask={flask_result.execution_time_ms:.2f}ms")
    
    def test_user_registration_validation_error_workflow_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test user registration validation error handling parity.
        
        Validates consistent error handling patterns and validation responses
        when user registration workflows encounter validation failures.
        """
        # Test data with validation errors
        invalid_user_data = {
            'username': 'ab',  # Too short
            'email': 'invalid-email',  # Invalid format
            'password': '123'  # Too weak
        }
        
        # Execute workflow on both systems
        nodejs_result = nodejs_system.execute_user_registration_workflow(invalid_user_data)
        flask_result = flask_workflow_executor.execute_user_registration_workflow(invalid_user_data)
        
        # Perform comprehensive comparison
        comparison = workflow_comparator.compare_workflow_results(nodejs_result, flask_result)
        
        # Assert error handling consistency
        assert comparison['execution_comparison']['success_match'], "Error handling outcomes must match"
        assert not nodejs_result.success and not flask_result.success, "Both systems should fail validation"
        assert comparison['error_handling_comparison']['error_consistency']['error_handling_consistent'], "Error handling must be consistent"
        
        # Assert no unintended database changes
        assert comparison['database_changes_comparison']['nodejs_total_changes'] == 0, "No database changes should occur on validation failure"
        assert comparison['database_changes_comparison']['flask_total_changes'] == 0, "No database changes should occur on validation failure"
        
        logger.info("User registration validation error workflow parity validation PASSED")
    
    @pytest.mark.benchmark
    def test_user_registration_workflow_performance_benchmarking(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator, 
        sample_user_data,
        benchmark
    ):
        """
        Benchmark user registration workflow performance against Node.js baseline.
        
        Validates Flask implementation meets or exceeds Node.js performance
        characteristics with detailed performance profiling and analysis.
        """
        def execute_flask_workflow():
            return flask_workflow_executor.execute_user_registration_workflow(sample_user_data)
        
        # Benchmark Flask implementation
        flask_result = benchmark(execute_flask_workflow)
        
        # Execute Node.js baseline for comparison
        nodejs_result = nodejs_system.execute_user_registration_workflow(sample_user_data)
        
        # Performance analysis
        comparison = workflow_comparator.compare_workflow_results(nodejs_result, flask_result)
        perf = comparison['performance_analysis']
        
        # Assert performance requirements
        assert perf['execution_time']['within_tolerance'], f"Flask execution time must be within tolerance: {perf['execution_time']['difference_ms']}ms"
        
        # Log performance metrics
        logger.info(f"Performance benchmark results:")
        logger.info(f"  Node.js baseline: {nodejs_result.execution_time_ms:.2f}ms, {nodejs_result.memory_usage_mb:.2f}MB")
        logger.info(f"  Flask implementation: {flask_result.execution_time_ms:.2f}ms, {flask_result.memory_usage_mb:.2f}MB")
        logger.info(f"  Performance improvement: {perf['execution_time']['flask_faster']}")


class TestBusinessEntityWorkflow:
    """
    Test suite for business entity workflow comparison.
    
    Validates Service Layer pattern implementation for complex business entity
    workflows with relationship management and transaction handling.
    """
    
    def test_business_entity_creation_workflow_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator, 
        sample_entity_data
    ):
        """
        Test business entity creation workflow parity between systems.
        
        Validates complex Service Layer workflow orchestration for business
        entity creation with comprehensive relationship management validation.
        """
        # First create a user for entity ownership
        user_data = {
            'username': 'entityowner',
            'email': 'owner@example.com',
            'password': 'SecurePassword123!'
        }
        
        # Create user on both systems
        nodejs_user_result = nodejs_system.execute_user_registration_workflow(user_data)
        flask_user_result = flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        assert nodejs_user_result.success and flask_user_result.success, "User creation must succeed"
        
        # Extract user IDs
        nodejs_user_id = nodejs_user_result.final_state['user_id']
        flask_user_id = flask_user_result.final_state['user_id']
        
        # Execute entity creation workflow
        nodejs_result = nodejs_system.execute_business_entity_workflow(sample_entity_data, nodejs_user_id)
        flask_result = flask_workflow_executor.execute_business_entity_workflow(sample_entity_data, int(flask_user_id))
        
        # Perform comprehensive comparison
        comparison = workflow_comparator.compare_workflow_results(nodejs_result, flask_result)
        
        # Assert overall parity
        assert comparison['overall_parity'], f"Business entity workflow parity failed: {comparison['discrepancies']}"
        
        # Assert workflow success
        assert comparison['execution_comparison']['success_match'], "Execution success outcomes must match"
        assert nodejs_result.success and flask_result.success, "Both workflows should succeed"
        
        # Assert database changes consistency
        assert comparison['database_changes_comparison']['all_changes_match'], "Database changes must match"
        
        # Assert entity creation validation
        assert comparison['validation_results_comparison']['all_validations_match'], "Validation results must match"
        
        logger.info("Business entity creation workflow parity validation PASSED")
    
    def test_business_entity_relationship_workflow_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator, 
        sample_entity_data
    ):
        """
        Test business entity relationship creation workflow parity.
        
        Validates complex relationship management workflows with parent-child
        entity associations and referential integrity preservation.
        """
        # Create user and parent entity first
        user_data = {'username': 'relowner', 'email': 'rel@example.com', 'password': 'SecurePassword123!'}
        
        nodejs_user_result = nodejs_system.execute_user_registration_workflow(user_data)
        flask_user_result = flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        nodejs_user_id = nodejs_user_result.final_state['user_id']
        flask_user_id = flask_user_result.final_state['user_id']
        
        # Create parent entity
        parent_entity_data = {'name': 'Parent Entity', 'description': 'Parent for relationship testing'}
        
        nodejs_parent_result = nodejs_system.execute_business_entity_workflow(parent_entity_data, nodejs_user_id)
        flask_parent_result = flask_workflow_executor.execute_business_entity_workflow(parent_entity_data, int(flask_user_id))
        
        nodejs_parent_id = nodejs_parent_result.final_state['entity_id']
        flask_parent_id = flask_parent_result.final_state['entity_id']
        
        # Create child entity with relationship
        child_entity_data = {
            'name': 'Child Entity',
            'description': 'Child entity for relationship testing',
            'parent_entity_id': nodejs_parent_id  # For Node.js
        }
        flask_child_entity_data = {
            'name': 'Child Entity',
            'description': 'Child entity for relationship testing',
            'parent_entity_id': int(flask_parent_id)  # For Flask
        }
        
        nodejs_result = nodejs_system.execute_business_entity_workflow(child_entity_data, nodejs_user_id)
        flask_result = flask_workflow_executor.execute_business_entity_workflow(flask_child_entity_data, int(flask_user_id))
        
        # Perform comprehensive comparison
        comparison = workflow_comparator.compare_workflow_results(nodejs_result, flask_result)
        
        # Assert relationship creation parity
        assert comparison['overall_parity'], f"Entity relationship workflow parity failed: {comparison['discrepancies']}"
        
        # Assert relationship count consistency
        nodejs_relationships = nodejs_result.final_state.get('relationships_created', 0)
        flask_relationships = flask_result.final_state.get('relationships_created', 0)
        assert nodejs_relationships == flask_relationships, "Relationship creation counts must match"
        
        # Assert database changes include relationships
        db_changes = comparison['database_changes_comparison']
        assert db_changes['change_comparison'].get('relationships_created', {}).get('match', False), "Relationship database changes must match"
        
        logger.info("Business entity relationship workflow parity validation PASSED")
    
    def test_business_entity_validation_error_workflow_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test business entity validation error handling parity.
        
        Validates consistent error handling for invalid business entity data
        and ownership validation failures.
        """
        # Invalid entity data
        invalid_entity_data = {
            'name': 'A',  # Too short
            'description': 'Invalid entity for testing'
        }
        
        # Invalid user ID
        invalid_user_id = 'nonexistent_user'
        
        # Execute workflow on both systems
        nodejs_result = nodejs_system.execute_business_entity_workflow(invalid_entity_data, invalid_user_id)
        flask_result = flask_workflow_executor.execute_business_entity_workflow(invalid_entity_data, 99999)
        
        # Perform comprehensive comparison
        comparison = workflow_comparator.compare_workflow_results(nodejs_result, flask_result)
        
        # Assert error handling consistency
        assert comparison['execution_comparison']['success_match'], "Error handling outcomes must match"
        assert not nodejs_result.success and not flask_result.success, "Both systems should fail validation"
        
        # Assert no unintended database changes
        assert comparison['database_changes_comparison']['nodejs_total_changes'] == 0
        assert comparison['database_changes_comparison']['flask_total_changes'] == 0
        
        logger.info("Business entity validation error workflow parity validation PASSED")


class TestBusinessRuleValidation:
    """
    Test suite for business rule validation comparison.
    
    Validates consistent business rule enforcement and validation logic
    between Node.js and Flask implementations with comprehensive rule coverage.
    """
    
    def test_email_uniqueness_business_rule_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test email uniqueness business rule validation parity.
        
        Validates consistent email uniqueness enforcement across both systems
        with comprehensive validation logic comparison.
        """
        # Test unique email
        unique_email_data = {'email': 'unique@example.com'}
        
        nodejs_result = nodejs_system.validate_business_rule('email_uniqueness', unique_email_data)
        flask_result = flask_workflow_executor.validate_business_rule('email_uniqueness', unique_email_data)
        
        comparison = workflow_comparator.compare_business_rules(nodejs_result, flask_result)
        
        assert comparison['overall_rule_parity'], f"Email uniqueness rule parity failed: {comparison['discrepancies']}"
        assert comparison['outcome_match'], "Rule outcomes must match"
        assert comparison['validation_match'], "Validation results must match"
        
        # Test duplicate email after creating user
        user_data = {
            'username': 'testuser',
            'email': 'duplicate@example.com',
            'password': 'SecurePassword123!'
        }
        
        # Create user with email
        nodejs_system.execute_user_registration_workflow(user_data)
        flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        # Test duplicate email validation
        duplicate_email_data = {'email': 'duplicate@example.com'}
        
        nodejs_duplicate_result = nodejs_system.validate_business_rule('email_uniqueness', duplicate_email_data)
        flask_duplicate_result = flask_workflow_executor.validate_business_rule('email_uniqueness', duplicate_email_data)
        
        duplicate_comparison = workflow_comparator.compare_business_rules(nodejs_duplicate_result, flask_duplicate_result)
        
        assert duplicate_comparison['overall_rule_parity'], "Duplicate email rule parity failed"
        assert not nodejs_duplicate_result.validation_passed and not flask_duplicate_result.validation_passed, "Both should reject duplicate email"
        
        logger.info("Email uniqueness business rule parity validation PASSED")
    
    def test_entity_ownership_business_rule_parity(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test entity ownership business rule validation parity.
        
        Validates consistent entity ownership verification across both systems
        with comprehensive access control validation.
        """
        # Create user and entity for ownership testing
        user_data = {'username': 'owner', 'email': 'owner@example.com', 'password': 'SecurePassword123!'}
        entity_data = {'name': 'Owned Entity', 'description': 'Entity for ownership testing'}
        
        # Create user and entity on both systems
        nodejs_user_result = nodejs_system.execute_user_registration_workflow(user_data)
        flask_user_result = flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        nodejs_user_id = nodejs_user_result.final_state['user_id']
        flask_user_id = flask_user_result.final_state['user_id']
        
        nodejs_entity_result = nodejs_system.execute_business_entity_workflow(entity_data, nodejs_user_id)
        flask_entity_result = flask_workflow_executor.execute_business_entity_workflow(entity_data, int(flask_user_id))
        
        nodejs_entity_id = nodejs_entity_result.final_state['entity_id']
        flask_entity_id = flask_entity_result.final_state['entity_id']
        
        # Test valid ownership
        valid_ownership_data = {'user_id': nodejs_user_id, 'entity_id': nodejs_entity_id}
        flask_ownership_data = {'user_id': int(flask_user_id), 'entity_id': int(flask_entity_id)}
        
        nodejs_ownership_result = nodejs_system.validate_business_rule('entity_ownership', valid_ownership_data)
        flask_ownership_result = flask_workflow_executor.validate_business_rule('entity_ownership', flask_ownership_data)
        
        comparison = workflow_comparator.compare_business_rules(nodejs_ownership_result, flask_ownership_result)
        
        assert comparison['overall_rule_parity'], f"Entity ownership rule parity failed: {comparison['discrepancies']}"
        assert nodejs_ownership_result.validation_passed and flask_ownership_result.validation_passed, "Valid ownership should pass"
        
        # Test invalid ownership
        invalid_ownership_data = {'user_id': 'invalid_user', 'entity_id': nodejs_entity_id}
        flask_invalid_data = {'user_id': 99999, 'entity_id': int(flask_entity_id)}
        
        nodejs_invalid_result = nodejs_system.validate_business_rule('entity_ownership', invalid_ownership_data)
        flask_invalid_result = flask_workflow_executor.validate_business_rule('entity_ownership', flask_invalid_data)
        
        invalid_comparison = workflow_comparator.compare_business_rules(nodejs_invalid_result, flask_invalid_result)
        
        assert invalid_comparison['overall_rule_parity'], "Invalid ownership rule parity failed"
        assert not nodejs_invalid_result.validation_passed and not flask_invalid_result.validation_passed, "Invalid ownership should fail"
        
        logger.info("Entity ownership business rule parity validation PASSED")


class TestWorkflowStateManagement:
    """
    Test suite for workflow state management comparison.
    
    Validates transaction handling, state persistence, and rollback behavior
    consistency between Node.js and Flask implementations.
    """
    
    def test_transaction_rollback_state_consistency(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test transaction rollback behavior consistency.
        
        Validates that failed workflows maintain consistent state and
        proper transaction rollback across both systems.
        """
        # Test data that will cause rollback
        user_data = {'username': 'rollbackuser', 'email': 'rollback@example.com', 'password': 'SecurePassword123!'}
        
        # Create user first
        nodejs_user_result = nodejs_system.execute_user_registration_workflow(user_data)
        flask_user_result = flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        assert nodejs_user_result.success and flask_user_result.success
        
        # Attempt to create duplicate user (should rollback)
        duplicate_result_nodejs = nodejs_system.execute_user_registration_workflow(user_data)
        duplicate_result_flask = flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        # Compare rollback behavior
        comparison = workflow_comparator.compare_workflow_results(duplicate_result_nodejs, duplicate_result_flask)
        
        # Assert rollback consistency
        assert comparison['execution_comparison']['success_match'], "Rollback behavior must be consistent"
        assert not duplicate_result_nodejs.success and not duplicate_result_flask.success, "Both should fail due to duplication"
        
        # Assert no database changes occurred during rollback
        assert comparison['database_changes_comparison']['nodejs_total_changes'] == 0
        assert comparison['database_changes_comparison']['flask_total_changes'] == 0
        
        logger.info("Transaction rollback state consistency validation PASSED")
    
    def test_concurrent_workflow_state_isolation(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test concurrent workflow state isolation.
        
        Validates that concurrent workflow executions maintain proper
        state isolation and transaction boundaries.
        """
        # Simulate concurrent user registrations
        user_data_1 = {'username': 'concurrent1', 'email': 'concurrent1@example.com', 'password': 'SecurePassword123!'}
        user_data_2 = {'username': 'concurrent2', 'email': 'concurrent2@example.com', 'password': 'SecurePassword123!'}
        
        # Execute concurrent workflows
        nodejs_result_1 = nodejs_system.execute_user_registration_workflow(user_data_1)
        flask_result_1 = flask_workflow_executor.execute_user_registration_workflow(user_data_1)
        
        nodejs_result_2 = nodejs_system.execute_user_registration_workflow(user_data_2)
        flask_result_2 = flask_workflow_executor.execute_user_registration_workflow(user_data_2)
        
        # Compare workflow isolation
        comparison_1 = workflow_comparator.compare_workflow_results(nodejs_result_1, flask_result_1)
        comparison_2 = workflow_comparator.compare_workflow_results(nodejs_result_2, flask_result_2)
        
        # Assert both workflows succeeded independently
        assert comparison_1['overall_parity'] and comparison_2['overall_parity'], "Concurrent workflows must maintain parity"
        assert nodejs_result_1.success and flask_result_1.success, "First workflow should succeed"
        assert nodejs_result_2.success and flask_result_2.success, "Second workflow should succeed"
        
        # Assert state isolation (different user IDs)
        nodejs_user_1_id = nodejs_result_1.final_state['user_id']
        nodejs_user_2_id = nodejs_result_2.final_state['user_id']
        flask_user_1_id = flask_result_1.final_state['user_id']
        flask_user_2_id = flask_result_2.final_state['user_id']
        
        assert nodejs_user_1_id != nodejs_user_2_id, "Node.js users should have different IDs"
        assert flask_user_1_id != flask_user_2_id, "Flask users should have different IDs"
        
        logger.info("Concurrent workflow state isolation validation PASSED")


class TestPerformanceComparison:
    """
    Test suite for performance comparison and benchmarking.
    
    Validates Flask implementation performance against Node.js baseline
    with comprehensive performance profiling and optimization validation.
    """
    
    @pytest.mark.benchmark
    def test_workflow_performance_benchmarking(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator, 
        benchmark
    ):
        """
        Comprehensive workflow performance benchmarking.
        
        Validates Flask implementation meets or exceeds Node.js performance
        requirements with detailed performance profiling.
        """
        # Benchmark data
        user_data = {'username': 'perftest', 'email': 'perf@example.com', 'password': 'SecurePassword123!'}
        entity_data = {'name': 'Performance Test Entity', 'description': 'Entity for performance testing'}
        
        # Benchmark Flask user registration
        def flask_user_workflow():
            return flask_workflow_executor.execute_user_registration_workflow(user_data)
        
        flask_user_result = benchmark(flask_user_workflow)
        
        # Compare with Node.js baseline
        nodejs_user_result = nodejs_system.execute_user_registration_workflow(user_data)
        
        user_comparison = workflow_comparator.compare_workflow_results(nodejs_user_result, flask_user_result)
        user_perf = user_comparison['performance_analysis']
        
        # Performance assertions
        assert user_perf['execution_time']['within_tolerance'], f"User workflow performance outside tolerance: {user_perf['execution_time']['difference_ms']}ms"
        
        # Extract user IDs for entity workflow
        flask_user_id = flask_user_result.final_state['user_id']
        nodejs_user_id = nodejs_user_result.final_state['user_id']
        
        # Benchmark Flask entity creation
        def flask_entity_workflow():
            return flask_workflow_executor.execute_business_entity_workflow(entity_data, int(flask_user_id))
        
        flask_entity_result = benchmark(flask_entity_workflow)
        
        # Compare with Node.js baseline
        nodejs_entity_result = nodejs_system.execute_business_entity_workflow(entity_data, nodejs_user_id)
        
        entity_comparison = workflow_comparator.compare_workflow_results(nodejs_entity_result, flask_entity_result)
        entity_perf = entity_comparison['performance_analysis']
        
        # Performance assertions
        assert entity_perf['execution_time']['within_tolerance'], f"Entity workflow performance outside tolerance: {entity_perf['execution_time']['difference_ms']}ms"
        
        # Log performance results
        logger.info("Workflow performance benchmarking PASSED")
        logger.info(f"User workflow - Node.js: {nodejs_user_result.execution_time_ms:.2f}ms, Flask: {flask_user_result.execution_time_ms:.2f}ms")
        logger.info(f"Entity workflow - Node.js: {nodejs_entity_result.execution_time_ms:.2f}ms, Flask: {flask_entity_result.execution_time_ms:.2f}ms")
    
    def test_memory_usage_comparison(
        self, 
        nodejs_system, 
        flask_workflow_executor, 
        workflow_comparator
    ):
        """
        Test memory usage comparison between implementations.
        
        Validates Flask implementation memory efficiency meets or exceeds
        Node.js baseline with detailed memory profiling.
        """
        # Memory profiling test data
        test_data_sets = [
            {'username': f'memtest{i}', 'email': f'memtest{i}@example.com', 'password': 'SecurePassword123!'}
            for i in range(10)
        ]
        
        nodejs_memory_usage = []
        flask_memory_usage = []
        
        # Execute multiple workflows to measure memory patterns
        for user_data in test_data_sets:
            nodejs_result = nodejs_system.execute_user_registration_workflow(user_data)
            flask_result = flask_workflow_executor.execute_user_registration_workflow(user_data)
            
            nodejs_memory_usage.append(nodejs_result.memory_usage_mb)
            flask_memory_usage.append(flask_result.memory_usage_mb)
        
        # Calculate memory statistics
        nodejs_avg_memory = sum(nodejs_memory_usage) / len(nodejs_memory_usage)
        flask_avg_memory = sum(flask_memory_usage) / len(flask_memory_usage)
        
        memory_difference_percent = ((flask_avg_memory - nodejs_avg_memory) / nodejs_avg_memory) * 100
        
        # Assert memory efficiency
        assert abs(memory_difference_percent) <= 10, f"Memory usage difference exceeds tolerance: {memory_difference_percent:.1f}%"
        
        logger.info(f"Memory usage comparison PASSED")
        logger.info(f"Average memory usage - Node.js: {nodejs_avg_memory:.2f}MB, Flask: {flask_avg_memory:.2f}MB")
        logger.info(f"Memory difference: {memory_difference_percent:.1f}%")


# Integration Test Execution


if __name__ == "__main__":
    """
    Main execution block for standalone test execution.
    
    Enables running comparative workflow tests independently with
    comprehensive logging and reporting capabilities.
    """
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--benchmark-only",
        "--benchmark-sort=mean",
        "--benchmark-json=benchmark_results.json"
    ])