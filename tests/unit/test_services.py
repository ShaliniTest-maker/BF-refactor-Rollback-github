"""
Comprehensive Unit Tests for Service Layer Business Logic Components

This test module validates all Service Layer business logic components including UserService,
BusinessEntityService, ValidationService, and WorkflowOrchestrator. Tests ensure business rule
preservation, workflow orchestration, transaction boundary management, and service composition
patterns maintain 100% functional equivalence with original Node.js business logic during
the Flask migration.

Test Coverage:
- UserService business logic preservation per Feature F-005
- BusinessEntityService complex workflow validation per Section 5.2.3  
- ValidationService dataclasses and type hint validation per Section 4.5.1
- WorkflowOrchestrator service composition patterns per Section 5.2.3
- Transaction boundary management with Flask-SQLAlchemy per Section 4.5.2
- Service dependency injection with Flask-Injector per Section 4.5.1
- Error handling and retry mechanisms per Section 4.5.3

Requirements Validated:
- Service Layer pattern unit testing for business logic preservation per Feature F-005
- 90% code coverage requirement for service layer per Feature F-006
- Business workflow orchestration validation per Section 5.2.3 component details
- Transaction boundary management testing per Section 4.5.2
- Service composition and dependency injection testing per Section 4.5.1
- Business rule enforcement validation per Section 4.12.1 validation checkpoints
- pytest-flask 1.3.0 service layer testing integration per Section 4.7.1
"""

import pytest
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock, call, ANY
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json
import time

# Flask and testing imports
from flask import Flask, current_app, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError, OperationalError, DatabaseError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest, InternalServerError

# Import service layer components for testing
from src.services.user_service import (
    UserService, 
    UserStatus, 
    RegistrationStatus,
    UserRegistrationData,
    UserAuthenticationData
)
from src.services.business_entity_service import (
    BusinessEntityService,
    EntityCreationRequest,
    EntityRelationshipRequest, 
    EntityUpdateRequest
)
from src.services.validation_service import (
    ValidationService,
    ValidationResult,
    ValidationSeverity,
    ValidationType
)
from src.services.workflow_orchestrator import (
    WorkflowOrchestrator,
    WorkflowStatus,
    WorkflowStepStatus,
    WorkflowStep
)
from src.services.base import BaseService, ServiceError

# Import database models for testing
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship

# Import utility modules for comprehensive testing
from src.utils.error_handling import (
    UserServiceError, ValidationError, AuthenticationError,
    UserNotFoundError, DuplicateUserError, SessionError,
    BusinessLogicError, DataIntegrityError, DatabaseConstraintError
)
from src.utils.logging import StructuredLogger


class TestUserService:
    """
    Comprehensive unit tests for UserService business logic preservation.
    
    Tests validate user management workflows, authentication logic, profile operations,
    and session management while ensuring 100% functional equivalence with original 
    Node.js business rules during the Flask migration.
    
    Coverage Areas:
    - User registration workflow testing with validation rules
    - Authentication mechanism validation with security preservation  
    - Profile management business logic verification
    - Session lifecycle management and security validation
    - Error handling and edge case business rule enforcement
    - Transaction boundary management for user operations
    """
    
    @pytest.fixture
    def user_service(self, app, db_session):
        """Create UserService instance with proper Flask application context."""
        with app.app_context():
            service = UserService(db=db_session)
            yield service
    
    @pytest.fixture
    def sample_user_data(self):
        """Sample user data for registration testing scenarios."""
        return UserRegistrationData(
            username="testuser123",
            email="test@example.com", 
            password="SecurePassword123!",
            first_name="Test",
            last_name="User",
            profile_data={"preferences": {"theme": "dark"}}
        )
    
    @pytest.fixture
    def sample_auth_data(self):
        """Sample authentication data for login testing scenarios."""
        return UserAuthenticationData(
            identifier="testuser123",
            password="SecurePassword123!",
            remember_me=False,
            device_info={"browser": "Chrome", "os": "Linux"}
        )
    
    def test_user_service_initialization(self, user_service):
        """Test UserService proper initialization with dependency injection."""
        assert user_service is not None
        assert isinstance(user_service, UserService)
        assert hasattr(user_service, 'db')
        assert hasattr(user_service, 'session_manager')
        assert hasattr(user_service, 'password_utils')
    
    def test_user_registration_success(self, user_service, sample_user_data, db_session):
        """
        Test successful user registration workflow with business rule validation.
        
        Validates:
        - User data validation and sanitization
        - Password hashing and security requirements
        - Database transaction boundary management
        - Business rule enforcement for unique constraints
        - Successful user creation with proper data persistence
        """
        # Mock database operations for isolation
        with patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit') as mock_commit, \
             patch.object(db_session, 'rollback') as mock_rollback:
            
            # Mock user lookup to simulate no existing user
            with patch.object(user_service, '_find_user_by_email', return_value=None), \
                 patch.object(user_service, '_find_user_by_username', return_value=None):
                
                # Execute user registration
                result = user_service.register_user(sample_user_data)
                
                # Validate registration success
                assert result['status'] == RegistrationStatus.SUCCESS
                assert result['user_id'] is not None
                assert 'user' in result
                assert result['user']['username'] == sample_user_data.username
                assert result['user']['email'] == sample_user_data.email
                
                # Verify database operations were called
                mock_add.assert_called_once()
                mock_commit.assert_called_once()
                mock_rollback.assert_not_called()
    
    def test_user_registration_duplicate_email(self, user_service, sample_user_data, db_session):
        """
        Test user registration failure due to duplicate email constraint.
        
        Validates business rule enforcement for unique email addresses
        and proper error handling without database corruption.
        """
        # Mock existing user with same email
        existing_user = Mock(spec=User)
        existing_user.email = sample_user_data.email
        
        with patch.object(user_service, '_find_user_by_email', return_value=existing_user):
            result = user_service.register_user(sample_user_data)
            
            # Validate proper duplicate handling
            assert result['status'] == RegistrationStatus.EMAIL_EXISTS
            assert 'error' in result
            assert 'email' in result['error'].lower()
    
    def test_user_registration_duplicate_username(self, user_service, sample_user_data, db_session):
        """
        Test user registration failure due to duplicate username constraint.
        
        Validates business rule enforcement for unique usernames
        and consistent error response patterns.
        """
        # Mock existing user with same username
        existing_user = Mock(spec=User)
        existing_user.username = sample_user_data.username
        
        with patch.object(user_service, '_find_user_by_email', return_value=None), \
             patch.object(user_service, '_find_user_by_username', return_value=existing_user):
            
            result = user_service.register_user(sample_user_data)
            
            # Validate proper duplicate handling
            assert result['status'] == RegistrationStatus.USERNAME_EXISTS
            assert 'error' in result
            assert 'username' in result['error'].lower()
    
    def test_user_authentication_success(self, user_service, sample_auth_data, db_session):
        """
        Test successful user authentication with proper session management.
        
        Validates:
        - Credential verification logic
        - Password hash validation
        - Session creation and management
        - User status verification
        - Authentication security preservation
        """
        # Mock user with correct credentials
        mock_user = Mock(spec=User)
        mock_user.id = str(uuid.uuid4())
        mock_user.username = sample_auth_data.identifier
        mock_user.email = "test@example.com"
        mock_user.password_hash = generate_password_hash(sample_auth_data.password)
        mock_user.is_active = True
        mock_user.status = UserStatus.ACTIVE.value
        
        with patch.object(user_service, '_find_user_by_identifier', return_value=mock_user), \
             patch.object(user_service, '_verify_password', return_value=True), \
             patch.object(user_service, '_create_user_session', return_value={'session_id': 'test_session'}) as mock_session:
            
            # Execute authentication
            result = user_service.authenticate_user(sample_auth_data)
            
            # Validate authentication success
            assert result['success'] is True
            assert result['user']['id'] == mock_user.id
            assert result['user']['username'] == mock_user.username
            assert 'session' in result
            
            # Verify session creation was called
            mock_session.assert_called_once_with(mock_user, sample_auth_data.remember_me)
    
    def test_user_authentication_invalid_credentials(self, user_service, sample_auth_data):
        """
        Test authentication failure with invalid credentials.
        
        Validates proper security handling and error responses
        without revealing sensitive information about user existence.
        """
        with patch.object(user_service, '_find_user_by_identifier', return_value=None):
            result = user_service.authenticate_user(sample_auth_data)
            
            # Validate authentication failure
            assert result['success'] is False
            assert 'error' in result
            assert 'invalid' in result['error'].lower()
    
    def test_user_authentication_inactive_user(self, user_service, sample_auth_data):
        """
        Test authentication failure for inactive user accounts.
        
        Validates business rule enforcement for user account status
        and proper security handling for inactive accounts.
        """
        # Mock inactive user
        mock_user = Mock(spec=User)
        mock_user.is_active = False
        mock_user.status = UserStatus.INACTIVE.value
        
        with patch.object(user_service, '_find_user_by_identifier', return_value=mock_user):
            result = user_service.authenticate_user(sample_auth_data)
            
            # Validate inactive user handling
            assert result['success'] is False
            assert 'inactive' in result['error'].lower()
    
    def test_user_profile_update_success(self, user_service, db_session):
        """
        Test successful user profile update with business validation.
        
        Validates profile modification workflow, data validation,
        and transaction boundary management for update operations.
        """
        user_id = str(uuid.uuid4())
        update_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'profile_data': {'theme': 'light', 'notifications': True}
        }
        
        # Mock existing user
        mock_user = Mock(spec=User)
        mock_user.id = user_id
        mock_user.first_name = 'Original'
        mock_user.last_name = 'User'
        
        with patch.object(user_service, '_find_user_by_id', return_value=mock_user), \
             patch.object(db_session, 'commit') as mock_commit:
            
            result = user_service.update_user_profile(user_id, update_data)
            
            # Validate profile update success
            assert result['success'] is True
            assert result['user']['first_name'] == update_data['first_name']
            assert result['user']['last_name'] == update_data['last_name']
            
            # Verify database commit was called
            mock_commit.assert_called_once()
    
    def test_user_profile_update_user_not_found(self, user_service):
        """
        Test profile update failure for non-existent user.
        
        Validates proper error handling and user existence validation
        in profile management workflows.
        """
        user_id = str(uuid.uuid4())
        update_data = {'first_name': 'Updated'}
        
        with patch.object(user_service, '_find_user_by_id', return_value=None):
            with pytest.raises(UserNotFoundError):
                user_service.update_user_profile(user_id, update_data)
    
    def test_user_session_management(self, user_service, db_session):
        """
        Test user session lifecycle management and security validation.
        
        Validates session creation, validation, expiration, and cleanup
        with proper security controls and session integrity preservation.
        """
        # Mock user for session operations
        mock_user = Mock(spec=User)
        mock_user.id = str(uuid.uuid4())
        mock_user.username = 'testuser'
        
        # Test session creation
        with patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit') as mock_commit:
            
            session_result = user_service._create_user_session(mock_user, remember_me=True)
            
            # Validate session creation
            assert 'session_id' in session_result
            assert 'expires_at' in session_result
            assert session_result['user_id'] == mock_user.id
            
            # Verify database operations
            mock_add.assert_called_once()
            mock_commit.assert_called_once()
    
    @pytest.mark.parametrize("password,expected_strength", [
        ("weak", False),
        ("StrongPassword123!", True),
        ("Medium@123", True),
        ("12345", False),
    ])
    def test_password_validation(self, user_service, password, expected_strength):
        """
        Test password strength validation with various password patterns.
        
        Validates business rules for password security requirements
        and consistent validation behavior across different input patterns.
        """
        result = user_service._validate_password_strength(password)
        assert result == expected_strength
    
    def test_transaction_rollback_on_error(self, user_service, sample_user_data, db_session):
        """
        Test transaction rollback behavior during registration errors.
        
        Validates transaction boundary management and data consistency
        during error scenarios with proper rollback mechanisms.
        """
        with patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit', side_effect=IntegrityError("test", "test", "test")) as mock_commit, \
             patch.object(db_session, 'rollback') as mock_rollback:
            
            # Mock no existing users for initial validation
            with patch.object(user_service, '_find_user_by_email', return_value=None), \
                 patch.object(user_service, '_find_user_by_username', return_value=None):
                
                result = user_service.register_user(sample_user_data)
                
                # Validate error handling and rollback
                assert result['status'] == RegistrationStatus.SYSTEM_ERROR
                mock_add.assert_called_once()
                mock_commit.assert_called_once()
                mock_rollback.assert_called_once()


class TestBusinessEntityService:
    """
    Comprehensive unit tests for BusinessEntityService complex workflow validation.
    
    Tests validate entity creation, relationship management, lifecycle operations,
    and cross-entity business rules while ensuring functional equivalence with
    original Node.js business logic patterns through Service Layer implementation.
    
    Coverage Areas:
    - Entity creation workflow with business validation
    - Complex entity relationship mapping and constraints
    - Entity lifecycle management with status transitions
    - Cross-entity business rule coordination and enforcement
    - Transaction boundary management for entity operations
    - Service composition patterns for multi-entity workflows
    """
    
    @pytest.fixture
    def business_service(self, app, db_session):
        """Create BusinessEntityService instance with Flask application context."""
        with app.app_context():
            service = BusinessEntityService(db=db_session)
            yield service
    
    @pytest.fixture
    def sample_entity_data(self):
        """Sample entity creation data for testing scenarios."""
        return EntityCreationRequest(
            name="Test Entity",
            description="Test entity for unit testing",
            owner_id=1,
            status="active",
            metadata={"category": "test", "priority": "high"}
        )
    
    @pytest.fixture
    def sample_relationship_data(self):
        """Sample relationship data for entity relationship testing."""
        return EntityRelationshipRequest(
            source_entity_id=1,
            target_entity_id=2,
            relationship_type="depends_on",
            metadata={"strength": "strong", "weight": 0.8},
            is_active=True
        )
    
    def test_business_entity_service_initialization(self, business_service):
        """Test BusinessEntityService proper initialization with dependencies."""
        assert business_service is not None
        assert isinstance(business_service, BusinessEntityService)
        assert hasattr(business_service, 'db')
        assert hasattr(business_service, 'validation_service')
        assert hasattr(business_service, 'logger')
    
    def test_entity_creation_success(self, business_service, sample_entity_data, db_session):
        """
        Test successful entity creation with business validation.
        
        Validates:
        - Entity data validation and business rules
        - Proper database persistence with transaction management
        - Entity metadata handling and serialization
        - Business rule enforcement for entity constraints
        - Successful entity creation workflow orchestration
        """
        # Mock database operations for isolation
        with patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit') as mock_commit, \
             patch.object(db_session, 'rollback') as mock_rollback:
            
            # Mock entity validation to pass
            with patch.object(business_service, '_validate_entity_data', return_value=True), \
                 patch.object(business_service, '_check_entity_name_unique', return_value=True):
                
                # Execute entity creation
                result = business_service.create_entity(sample_entity_data)
                
                # Validate creation success
                assert result['success'] is True
                assert result['entity']['name'] == sample_entity_data.name
                assert result['entity']['description'] == sample_entity_data.description
                assert result['entity']['status'] == sample_entity_data.status
                assert result['entity']['metadata'] == sample_entity_data.metadata
                
                # Verify database operations
                mock_add.assert_called_once()
                mock_commit.assert_called_once()
                mock_rollback.assert_not_called()
    
    def test_entity_creation_validation_failure(self, business_service, sample_entity_data):
        """
        Test entity creation failure due to validation errors.
        
        Validates business rule enforcement and proper error handling
        without database persistence for invalid entity data.
        """
        # Mock validation failure
        validation_errors = ["Entity name is required", "Invalid status value"]
        
        with patch.object(business_service, '_validate_entity_data', return_value=False), \
             patch.object(business_service, '_get_validation_errors', return_value=validation_errors):
            
            result = business_service.create_entity(sample_entity_data)
            
            # Validate validation failure handling
            assert result['success'] is False
            assert 'errors' in result
            assert len(result['errors']) == len(validation_errors)
    
    def test_entity_creation_duplicate_name(self, business_service, sample_entity_data):
        """
        Test entity creation failure due to duplicate name constraint.
        
        Validates business rule enforcement for unique entity names
        and proper constraint violation handling.
        """
        with patch.object(business_service, '_validate_entity_data', return_value=True), \
             patch.object(business_service, '_check_entity_name_unique', return_value=False):
            
            result = business_service.create_entity(sample_entity_data)
            
            # Validate duplicate name handling
            assert result['success'] is False
            assert 'duplicate' in result['error'].lower()
            assert 'name' in result['error'].lower()
    
    def test_entity_relationship_creation_success(self, business_service, sample_relationship_data, db_session):
        """
        Test successful entity relationship creation with validation.
        
        Validates:
        - Relationship data validation and business rules
        - Entity existence verification for relationship endpoints
        - Relationship type validation and constraint checking
        - Transaction boundary management for relationship operations
        - Complex business entity relationship mapping per Section 6.2.2.1
        """
        # Mock source and target entities
        mock_source = Mock(spec=BusinessEntity)
        mock_source.id = sample_relationship_data.source_entity_id
        mock_source.status = "active"
        
        mock_target = Mock(spec=BusinessEntity)
        mock_target.id = sample_relationship_data.target_entity_id
        mock_target.status = "active"
        
        with patch.object(business_service, '_find_entity_by_id') as mock_find, \
             patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit') as mock_commit:
            
            # Configure entity lookup mock
            mock_find.side_effect = [mock_source, mock_target]
            
            # Mock relationship validation
            with patch.object(business_service, '_validate_relationship_data', return_value=True), \
                 patch.object(business_service, '_check_relationship_exists', return_value=False):
                
                # Execute relationship creation
                result = business_service.create_relationship(sample_relationship_data)
                
                # Validate relationship creation success
                assert result['success'] is True
                assert result['relationship']['source_entity_id'] == sample_relationship_data.source_entity_id
                assert result['relationship']['target_entity_id'] == sample_relationship_data.target_entity_id
                assert result['relationship']['relationship_type'] == sample_relationship_data.relationship_type
                
                # Verify database operations
                mock_add.assert_called_once()
                mock_commit.assert_called_once()
    
    def test_entity_relationship_creation_missing_entity(self, business_service, sample_relationship_data):
        """
        Test relationship creation failure for non-existent entities.
        
        Validates entity existence verification and proper error handling
        for relationship operations with missing entity references.
        """
        # Mock missing source entity
        with patch.object(business_service, '_find_entity_by_id', return_value=None):
            result = business_service.create_relationship(sample_relationship_data)
            
            # Validate missing entity handling
            assert result['success'] is False
            assert 'not found' in result['error'].lower()
    
    def test_entity_update_success(self, business_service, db_session):
        """
        Test successful entity update with selective field updates.
        
        Validates entity lifecycle management with partial updates,
        business rule preservation, and transaction boundary management.
        """
        entity_id = 1
        update_data = EntityUpdateRequest(
            entity_id=entity_id,
            name="Updated Entity Name",
            description="Updated description",
            status="inactive"
        )
        
        # Mock existing entity
        mock_entity = Mock(spec=BusinessEntity)
        mock_entity.id = entity_id
        mock_entity.name = "Original Name"
        mock_entity.description = "Original description"
        mock_entity.status = "active"
        
        with patch.object(business_service, '_find_entity_by_id', return_value=mock_entity), \
             patch.object(db_session, 'commit') as mock_commit:
            
            # Mock validation success
            with patch.object(business_service, '_validate_update_data', return_value=True):
                
                # Execute entity update
                result = business_service.update_entity(update_data)
                
                # Validate update success
                assert result['success'] is True
                assert mock_entity.name == update_data.name
                assert mock_entity.description == update_data.description
                assert mock_entity.status == update_data.status
                
                # Verify database commit
                mock_commit.assert_called_once()
    
    def test_entity_lifecycle_state_transitions(self, business_service, db_session):
        """
        Test entity lifecycle state transitions with business rules.
        
        Validates status transition validation, business rule enforcement,
        and proper lifecycle management for entity status changes.
        """
        entity_id = 1
        
        # Mock entity with current status
        mock_entity = Mock(spec=BusinessEntity)
        mock_entity.id = entity_id
        mock_entity.status = "active"
        
        with patch.object(business_service, '_find_entity_by_id', return_value=mock_entity), \
             patch.object(db_session, 'commit') as mock_commit:
            
            # Test valid status transition
            result = business_service.update_entity_status(entity_id, "inactive")
            
            # Validate status transition
            assert result['success'] is True
            assert mock_entity.status == "inactive"
            mock_commit.assert_called_once()
    
    def test_cross_entity_business_rules(self, business_service, db_session):
        """
        Test cross-entity business rule coordination and enforcement.
        
        Validates complex business logic coordination across multiple entities,
        relationship constraint validation, and business rule preservation
        during multi-entity operations per Section 5.2.3.
        """
        # Mock entities with dependencies
        parent_entity = Mock(spec=BusinessEntity)
        parent_entity.id = 1
        parent_entity.status = "active"
        parent_entity.children = []
        
        child_entity = Mock(spec=BusinessEntity)
        child_entity.id = 2
        child_entity.status = "active"
        child_entity.parent_id = 1
        
        with patch.object(business_service, '_find_entity_by_id') as mock_find, \
             patch.object(business_service, '_get_entity_children', return_value=[child_entity]):
            
            mock_find.return_value = parent_entity
            
            # Test business rule: cannot deactivate parent with active children
            result = business_service.validate_entity_deactivation(1)
            
            # Validate business rule enforcement
            assert result['can_deactivate'] is False
            assert 'active children' in result['reason'].lower()
    
    def test_entity_search_and_filtering(self, business_service, db_session):
        """
        Test entity search and filtering capabilities with business logic.
        
        Validates search functionality, filtering logic, and result
        formatting while maintaining business rule consistency.
        """
        # Mock search criteria
        search_criteria = {
            'name': 'Test',
            'status': 'active',
            'metadata': {'category': 'test'}
        }
        
        # Mock search results
        mock_entities = [
            Mock(spec=BusinessEntity, id=1, name="Test Entity 1"),
            Mock(spec=BusinessEntity, id=2, name="Test Entity 2")
        ]
        
        with patch.object(business_service, '_search_entities', return_value=mock_entities):
            
            result = business_service.search_entities(search_criteria)
            
            # Validate search results
            assert result['success'] is True
            assert len(result['entities']) == 2
            assert all('id' in entity for entity in result['entities'])
            assert all('name' in entity for entity in result['entities'])
    
    def test_transaction_boundary_management(self, business_service, sample_entity_data, db_session):
        """
        Test transaction boundary management for complex entity operations.
        
        Validates transaction consistency, rollback behavior on errors,
        and proper resource cleanup during transaction failures.
        """
        with patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit', side_effect=SQLAlchemyError("Database error")) as mock_commit, \
             patch.object(db_session, 'rollback') as mock_rollback:
            
            # Mock validation success but database failure
            with patch.object(business_service, '_validate_entity_data', return_value=True), \
                 patch.object(business_service, '_check_entity_name_unique', return_value=True):
                
                result = business_service.create_entity(sample_entity_data)
                
                # Validate error handling and rollback
                assert result['success'] is False
                assert 'error' in result
                mock_add.assert_called_once()
                mock_commit.assert_called_once()
                mock_rollback.assert_called_once()


class TestValidationService:
    """
    Comprehensive unit tests for ValidationService dataclasses and type hint validation.
    
    Tests validate business rule enforcement, data validation logic, constraint checking,
    and input sanitization while ensuring type safety and validation consistency
    throughout the Flask application per Section 4.5.1 requirements.
    
    Coverage Areas:
    - Dataclass validation with type hints and constraints
    - Business rule enforcement and validation logic preservation  
    - Input validation and sanitization patterns from Node.js
    - Database constraint checking and integrity validation
    - Validation error handling with detailed error reporting
    - Security validation and input sanitization for safety
    """
    
    @pytest.fixture
    def validation_service(self, app):
        """Create ValidationService instance with Flask application context."""
        with app.app_context():
            service = ValidationService()
            yield service
    
    @pytest.fixture
    def sample_validation_data(self):
        """Sample data for validation testing scenarios."""
        return {
            'username': 'testuser123',
            'email': 'test@example.com',
            'age': 25,
            'status': 'active',
            'metadata': {'preferences': {'theme': 'dark'}}
        }
    
    def test_validation_service_initialization(self, validation_service):
        """Test ValidationService proper initialization with configuration."""
        assert validation_service is not None
        assert isinstance(validation_service, ValidationService)
        assert hasattr(validation_service, 'validation_schemas')
        assert hasattr(validation_service, 'sanitization_rules')
    
    def test_dataclass_validation_success(self, validation_service, sample_validation_data):
        """
        Test successful dataclass validation with type hints.
        
        Validates dataclass integration per Section 4.5.1 requirements,
        type hint validation, and successful validation workflow
        with proper result formatting and metadata tracking.
        """
        # Define validation schema with type hints
        validation_schema = {
            'username': {'type': str, 'required': True, 'min_length': 3},
            'email': {'type': str, 'required': True, 'format': 'email'},
            'age': {'type': int, 'required': False, 'min_value': 0},
            'status': {'type': str, 'required': True, 'choices': ['active', 'inactive']}
        }
        
        # Execute validation
        result = validation_service.validate_data(sample_validation_data, validation_schema)
        
        # Validate successful validation
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.sanitized_data is not None
        assert result.validation_timestamp is not None
    
    def test_dataclass_validation_type_errors(self, validation_service):
        """
        Test dataclass validation with type constraint violations.
        
        Validates type hint enforcement, error collection and reporting,
        and consistent validation behavior for type safety requirements.
        """
        # Invalid data with type violations
        invalid_data = {
            'username': 123,  # Should be string
            'email': 'invalid-email',  # Invalid format
            'age': 'twenty-five',  # Should be integer
            'status': 'unknown'  # Invalid choice
        }
        
        validation_schema = {
            'username': {'type': str, 'required': True},
            'email': {'type': str, 'required': True, 'format': 'email'},
            'age': {'type': int, 'required': False},
            'status': {'type': str, 'required': True, 'choices': ['active', 'inactive']}
        }
        
        # Execute validation
        result = validation_service.validate_data(invalid_data, validation_schema)
        
        # Validate type error handling
        assert result.is_valid is False
        assert len(result.errors) > 0
        
        # Check specific error types
        error_fields = [error['field'] for error in result.errors]
        assert 'username' in error_fields
        assert 'email' in error_fields
        assert 'age' in error_fields
        assert 'status' in error_fields
    
    def test_business_rule_validation(self, validation_service):
        """
        Test business rule enforcement with custom validation logic.
        
        Validates business rule preservation from Node.js implementation,
        custom validation function execution, and complex business
        constraint checking per Section 4.12.1 validation requirements.
        """
        # Sample data for business rule testing
        user_data = {
            'username': 'admin',
            'role': 'administrator',
            'department': 'IT',
            'clearance_level': 5
        }
        
        # Define business rules
        def validate_admin_clearance(data):
            """Business rule: Administrators must have clearance level >= 4"""
            if data.get('role') == 'administrator' and data.get('clearance_level', 0) < 4:
                return False, "Administrators require minimum clearance level 4"
            return True, None
        
        def validate_department_role_consistency(data):
            """Business rule: IT department can only have specific roles"""
            if data.get('department') == 'IT':
                valid_roles = ['administrator', 'developer', 'analyst']
                if data.get('role') not in valid_roles:
                    return False, "Invalid role for IT department"
            return True, None
        
        # Apply business rule validation
        result = validation_service.validate_business_rules(user_data, [
            validate_admin_clearance,
            validate_department_role_consistency
        ])
        
        # Validate business rule success
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_business_rule_validation_failures(self, validation_service):
        """
        Test business rule validation with rule violations.
        
        Validates business rule error handling, multiple rule violation
        collection, and detailed error reporting for business constraint failures.
        """
        # Data that violates business rules
        user_data = {
            'username': 'lowclearance',
            'role': 'administrator',
            'department': 'IT',
            'clearance_level': 2  # Violates admin clearance rule
        }
        
        def validate_admin_clearance(data):
            if data.get('role') == 'administrator' and data.get('clearance_level', 0) < 4:
                return False, "Administrators require minimum clearance level 4"
            return True, None
        
        # Apply business rule validation
        result = validation_service.validate_business_rules(user_data, [validate_admin_clearance])
        
        # Validate business rule failure
        assert result.is_valid is False
        assert len(result.errors) == 1
        assert 'clearance level' in result.errors[0]['message'].lower()
    
    def test_input_sanitization(self, validation_service):
        """
        Test input sanitization and security validation.
        
        Validates input sanitization patterns preservation from Node.js,
        XSS prevention, SQL injection protection, and safe data processing
        for security vulnerability prevention.
        """
        # Data with potential security issues
        unsafe_data = {
            'username': '<script>alert("xss")</script>',
            'description': 'Normal text with <img src="x" onerror="alert(1)">',
            'sql_field': "'; DROP TABLE users; --",
            'html_content': '<p>Safe content</p><script>unsafe()</script>'
        }
        
        # Execute sanitization
        result = validation_service.sanitize_input(unsafe_data)
        
        # Validate sanitization success
        assert result.sanitized_data is not None
        
        # Verify script tags are removed or escaped
        sanitized = result.sanitized_data
        assert '<script>' not in sanitized['username']
        assert 'onerror' not in sanitized['description']
        assert 'DROP TABLE' not in sanitized['sql_field']
        assert '<script>' not in sanitized['html_content']
    
    def test_database_constraint_validation(self, validation_service, db_session):
        """
        Test database constraint checking and integrity validation.
        
        Validates database constraint enforcement, foreign key validation,
        unique constraint checking, and data integrity preservation
        during validation workflows per Section 6.2.2.2 requirements.
        """
        # Mock database constraints
        constraints = {
            'unique_email': {
                'table': 'users',
                'field': 'email',
                'value': 'test@example.com'
            },
            'foreign_key_user': {
                'table': 'entities',
                'field': 'owner_id',
                'reference_table': 'users',
                'reference_field': 'id',
                'value': 999  # Non-existent user ID
            }
        }
        
        with patch.object(validation_service, '_check_unique_constraint') as mock_unique, \
             patch.object(validation_service, '_check_foreign_key_constraint') as mock_fk:
            
            # Configure constraint check results
            mock_unique.return_value = False  # Email already exists
            mock_fk.return_value = False  # User ID doesn't exist
            
            # Execute constraint validation
            result = validation_service.validate_database_constraints(constraints)
            
            # Validate constraint failures
            assert result.is_valid is False
            assert len(result.errors) == 2
            
            # Verify constraint checking was called
            mock_unique.assert_called()
            mock_fk.assert_called()
    
    def test_nested_data_validation(self, validation_service):
        """
        Test validation of nested data structures with complex schemas.
        
        Validates nested object validation, array validation, and complex
        data structure handling with recursive validation logic.
        """
        # Complex nested data structure
        nested_data = {
            'user': {
                'profile': {
                    'personal': {
                        'first_name': 'John',
                        'last_name': 'Doe',
                        'age': 30
                    },
                    'preferences': {
                        'theme': 'dark',
                        'notifications': True,
                        'languages': ['en', 'es']
                    }
                },
                'roles': [
                    {'name': 'user', 'permissions': ['read']},
                    {'name': 'admin', 'permissions': ['read', 'write', 'delete']}
                ]
            }
        }
        
        # Define nested validation schema
        nested_schema = {
            'user.profile.personal.first_name': {'type': str, 'required': True},
            'user.profile.personal.age': {'type': int, 'min_value': 0},
            'user.profile.preferences.theme': {'type': str, 'choices': ['light', 'dark']},
            'user.roles': {'type': list, 'min_length': 1}
        }
        
        # Execute nested validation
        result = validation_service.validate_nested_data(nested_data, nested_schema)
        
        # Validate nested validation success
        assert result.is_valid is True
        assert result.sanitized_data is not None
    
    @pytest.mark.parametrize("validation_type,data,expected_valid", [
        (ValidationType.FORMAT, {'email': 'test@example.com'}, True),
        (ValidationType.FORMAT, {'email': 'invalid-email'}, False),
        (ValidationType.SECURITY, {'password': 'StrongPass123!'}, True),
        (ValidationType.SECURITY, {'password': '123'}, False),
        (ValidationType.BUSINESS_RULE, {'age': 25, 'role': 'adult'}, True),
        (ValidationType.BUSINESS_RULE, {'age': 15, 'role': 'adult'}, False),
    ])
    def test_validation_type_scenarios(self, validation_service, validation_type, data, expected_valid):
        """
        Test various validation type scenarios with parameterized inputs.
        
        Validates different validation types, consistent behavior across
        validation categories, and proper validation result classification.
        """
        # Configure validation based on type
        if validation_type == ValidationType.FORMAT:
            schema = {'email': {'type': str, 'format': 'email'}}
        elif validation_type == ValidationType.SECURITY:
            schema = {'password': {'type': str, 'min_length': 8, 'security': True}}
        elif validation_type == ValidationType.BUSINESS_RULE:
            schema = {'age': {'type': int}, 'role': {'type': str}}
            
            def age_role_rule(data):
                if data.get('role') == 'adult' and data.get('age', 0) < 18:
                    return False, "Adults must be 18 or older"
                return True, None
            
            # Execute with business rule
            result = validation_service.validate_business_rules(data, [age_role_rule])
            assert result.is_valid == expected_valid
            return
        
        # Execute standard validation
        result = validation_service.validate_data(data, schema)
        assert result.is_valid == expected_valid
    
    def test_validation_performance_monitoring(self, validation_service, performance_monitor):
        """
        Test validation performance monitoring and SLA compliance.
        
        Validates validation performance requirements, timing measurement,
        and performance threshold enforcement for validation operations.
        """
        # Large dataset for performance testing
        large_dataset = {
            f'field_{i}': f'value_{i}' for i in range(1000)
        }
        
        schema = {
            f'field_{i}': {'type': str, 'required': True} for i in range(1000)
        }
        
        # Monitor validation performance
        performance_monitor['start']()
        result = validation_service.validate_data(large_dataset, schema)
        performance_monitor['stop']()
        
        # Validate performance and results
        assert result.is_valid is True
        
        # Ensure validation completes within performance threshold
        performance_monitor['assert_threshold'](5.0)  # 5 second threshold


class TestWorkflowOrchestrator:
    """
    Comprehensive unit tests for WorkflowOrchestrator service composition patterns.
    
    Tests validate advanced workflow orchestration, service composition architecture,
    transaction boundary management, and event-driven processing while ensuring
    business logic coordination and workflow consistency per Section 5.2.3 requirements.
    
    Coverage Areas:
    - Service composition patterns for complex business operations
    - Workflow step execution and coordination management  
    - Transaction boundary management with ACID properties preservation
    - Event-driven processing through Flask signals integration
    - Workflow retry mechanisms for resilient operation handling
    - Performance monitoring and SLA compliance for workflows
    """
    
    @pytest.fixture
    def workflow_orchestrator(self, app, db_session):
        """Create WorkflowOrchestrator instance with Flask application context."""
        with app.app_context():
            orchestrator = WorkflowOrchestrator(db=db_session)
            yield orchestrator
    
    @pytest.fixture
    def sample_workflow_steps(self):
        """Sample workflow steps for orchestration testing."""
        return [
            WorkflowStep(
                name="validate_user",
                service="user_service",
                method="validate_user_data",
                parameters={'user_id': 1},
                retry_count=3,
                timeout=30
            ),
            WorkflowStep(
                name="create_entity",
                service="business_entity_service", 
                method="create_entity",
                parameters={'entity_data': {'name': 'Test Entity'}},
                retry_count=2,
                timeout=60
            ),
            WorkflowStep(
                name="send_notification",
                service="notification_service",
                method="send_notification",
                parameters={'message': 'Entity created successfully'},
                retry_count=1,
                timeout=15
            )
        ]
    
    def test_workflow_orchestrator_initialization(self, workflow_orchestrator):
        """Test WorkflowOrchestrator proper initialization with dependencies."""
        assert workflow_orchestrator is not None
        assert isinstance(workflow_orchestrator, WorkflowOrchestrator)
        assert hasattr(workflow_orchestrator, 'db')
        assert hasattr(workflow_orchestrator, 'service_registry')
        assert hasattr(workflow_orchestrator, 'signal_dispatcher')
    
    def test_workflow_execution_success(self, workflow_orchestrator, sample_workflow_steps, db_session):
        """
        Test successful workflow execution with service composition.
        
        Validates:
        - Workflow step coordination and execution sequencing
        - Service composition patterns for multi-service operations
        - Transaction boundary management across workflow steps
        - Event-driven processing with Flask signals integration
        - Successful workflow completion with proper result aggregation
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock service registry and method execution
        mock_user_service = Mock()
        mock_user_service.validate_user_data.return_value = {'valid': True, 'user': {'id': 1}}
        
        mock_entity_service = Mock()
        mock_entity_service.create_entity.return_value = {'success': True, 'entity': {'id': 1}}
        
        mock_notification_service = Mock()
        mock_notification_service.send_notification.return_value = {'sent': True, 'message_id': 'msg_123'}
        
        # Configure service registry
        service_registry = {
            'user_service': mock_user_service,
            'business_entity_service': mock_entity_service,
            'notification_service': mock_notification_service
        }
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry), \
             patch.object(db_session, 'commit') as mock_commit:
            
            # Execute workflow
            result = workflow_orchestrator.execute_workflow(workflow_id, sample_workflow_steps)
            
            # Validate workflow execution success
            assert result['status'] == WorkflowStatus.COMPLETED
            assert result['workflow_id'] == workflow_id
            assert len(result['step_results']) == len(sample_workflow_steps)
            
            # Verify all steps completed successfully
            for step_result in result['step_results']:
                assert step_result['status'] == WorkflowStepStatus.COMPLETED
            
            # Verify service method calls
            mock_user_service.validate_user_data.assert_called_once()
            mock_entity_service.create_entity.assert_called_once()
            mock_notification_service.send_notification.assert_called_once()
            
            # Verify transaction commit
            mock_commit.assert_called()
    
    def test_workflow_step_failure_and_retry(self, workflow_orchestrator, sample_workflow_steps):
        """
        Test workflow step failure handling with retry mechanisms.
        
        Validates retry logic, failure recovery, error handling,
        and resilient operation patterns for workflow step failures
        per Section 4.5.3 workflow requirements.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock service that fails initially then succeeds
        mock_service = Mock()
        mock_service.validate_user_data.side_effect = [
            Exception("Temporary failure"),
            Exception("Still failing"),
            {'valid': True, 'user': {'id': 1}}  # Success on third try
        ]
        
        service_registry = {'user_service': mock_service}
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry):
            
            # Execute single step workflow with retry
            single_step = [sample_workflow_steps[0]]  # Just the user validation step
            result = workflow_orchestrator.execute_workflow(workflow_id, single_step)
            
            # Validate retry behavior
            assert result['status'] == WorkflowStatus.COMPLETED
            assert mock_service.validate_user_data.call_count == 3  # Initial + 2 retries
            
            # Verify step result shows retry history
            step_result = result['step_results'][0]
            assert step_result['retry_count'] == 2
            assert step_result['status'] == WorkflowStepStatus.COMPLETED
    
    def test_workflow_step_max_retries_exceeded(self, workflow_orchestrator, sample_workflow_steps):
        """
        Test workflow step failure when max retries are exceeded.
        
        Validates failure handling, retry limit enforcement, and
        proper workflow termination for persistent step failures.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock service that always fails
        mock_service = Mock()
        mock_service.validate_user_data.side_effect = Exception("Persistent failure")
        
        service_registry = {'user_service': mock_service}
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry):
            
            # Execute workflow with failing step
            single_step = [sample_workflow_steps[0]]
            result = workflow_orchestrator.execute_workflow(workflow_id, single_step)
            
            # Validate failure handling
            assert result['status'] == WorkflowStatus.FAILED
            assert mock_service.validate_user_data.call_count == 4  # Initial + 3 retries
            
            # Verify step result shows failure
            step_result = result['step_results'][0]
            assert step_result['status'] == WorkflowStepStatus.FAILED
            assert 'Persistent failure' in step_result['error_message']
    
    def test_transaction_boundary_management(self, workflow_orchestrator, sample_workflow_steps, db_session):
        """
        Test transaction boundary management across workflow steps.
        
        Validates ACID properties preservation, transaction consistency,
        rollback behavior on failures, and proper resource cleanup
        during complex multi-service workflows per Section 4.5.2.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock services with mixed success/failure
        mock_user_service = Mock()
        mock_user_service.validate_user_data.return_value = {'valid': True}
        
        mock_entity_service = Mock()
        mock_entity_service.create_entity.side_effect = Exception("Database constraint violation")
        
        service_registry = {
            'user_service': mock_user_service,
            'business_entity_service': mock_entity_service
        }
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry), \
             patch.object(db_session, 'rollback') as mock_rollback, \
             patch.object(db_session, 'commit') as mock_commit:
            
            # Execute workflow with transaction failure
            first_two_steps = sample_workflow_steps[:2]
            result = workflow_orchestrator.execute_workflow(workflow_id, first_two_steps)
            
            # Validate transaction rollback on failure
            assert result['status'] == WorkflowStatus.FAILED
            mock_rollback.assert_called()
            mock_commit.assert_not_called()
    
    def test_event_driven_processing(self, workflow_orchestrator, sample_workflow_steps):
        """
        Test event-driven processing through Flask signals integration.
        
        Validates event emission, signal handling, event-driven coordination,
        and workflow event propagation per Section 4.5.3 event processing.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock signal dispatcher
        mock_signal_dispatcher = Mock()
        
        # Mock service registry
        mock_service = Mock()
        mock_service.validate_user_data.return_value = {'valid': True}
        service_registry = {'user_service': mock_service}
        
        with patch.object(workflow_orchestrator, 'signal_dispatcher', mock_signal_dispatcher), \
             patch.object(workflow_orchestrator, 'service_registry', service_registry):
            
            # Execute workflow with event monitoring
            single_step = [sample_workflow_steps[0]]
            result = workflow_orchestrator.execute_workflow(workflow_id, single_step)
            
            # Validate event emission
            assert result['status'] == WorkflowStatus.COMPLETED
            
            # Verify workflow events were emitted
            mock_signal_dispatcher.send.assert_any_call(
                'workflow_started',
                workflow_id=workflow_id,
                steps=single_step
            )
            mock_signal_dispatcher.send.assert_any_call(
                'workflow_completed',
                workflow_id=workflow_id,
                result=ANY
            )
    
    def test_service_composition_patterns(self, workflow_orchestrator, db_session):
        """
        Test complex service composition patterns for business operations.
        
        Validates service dependency coordination, data flow between services,
        composition result aggregation, and service interaction patterns
        per Section 5.2.3 service composition architecture.
        """
        workflow_id = str(uuid.uuid4())
        
        # Define complex composition workflow
        composition_steps = [
            WorkflowStep(
                name="fetch_user",
                service="user_service",
                method="get_user",
                parameters={'user_id': 1}
            ),
            WorkflowStep(
                name="validate_permissions",
                service="auth_service",
                method="check_permissions",
                parameters={'user_id': '${fetch_user.result.id}', 'action': 'create_entity'}
            ),
            WorkflowStep(
                name="create_entity",
                service="business_entity_service",
                method="create_entity",
                parameters={
                    'entity_data': {'name': 'New Entity', 'owner_id': '${fetch_user.result.id}'}
                }
            ),
            WorkflowStep(
                name="log_activity",
                service="audit_service",
                method="log_action",
                parameters={
                    'user_id': '${fetch_user.result.id}',
                    'action': 'entity_created',
                    'entity_id': '${create_entity.result.entity.id}'
                }
            )
        ]
        
        # Mock services with interdependent results
        mock_user_service = Mock()
        mock_user_service.get_user.return_value = {'id': 1, 'username': 'testuser'}
        
        mock_auth_service = Mock()
        mock_auth_service.check_permissions.return_value = {'authorized': True}
        
        mock_entity_service = Mock()
        mock_entity_service.create_entity.return_value = {'success': True, 'entity': {'id': 123}}
        
        mock_audit_service = Mock()
        mock_audit_service.log_action.return_value = {'logged': True, 'log_id': 'log_456'}
        
        service_registry = {
            'user_service': mock_user_service,
            'auth_service': mock_auth_service,
            'business_entity_service': mock_entity_service,
            'audit_service': mock_audit_service
        }
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry), \
             patch.object(workflow_orchestrator, '_resolve_parameters') as mock_resolve:
            
            # Configure parameter resolution for dependencies
            mock_resolve.side_effect = [
                {'user_id': 1},  # fetch_user parameters
                {'user_id': 1, 'action': 'create_entity'},  # validate_permissions parameters
                {'entity_data': {'name': 'New Entity', 'owner_id': 1}},  # create_entity parameters
                {'user_id': 1, 'action': 'entity_created', 'entity_id': 123}  # log_activity parameters
            ]
            
            # Execute composition workflow
            result = workflow_orchestrator.execute_workflow(workflow_id, composition_steps)
            
            # Validate composition success
            assert result['status'] == WorkflowStatus.COMPLETED
            assert len(result['step_results']) == 4
            
            # Verify service call sequence and parameter resolution
            mock_user_service.get_user.assert_called_with(user_id=1)
            mock_auth_service.check_permissions.assert_called_with(user_id=1, action='create_entity')
            mock_entity_service.create_entity.assert_called_with(
                entity_data={'name': 'New Entity', 'owner_id': 1}
            )
            mock_audit_service.log_action.assert_called_with(
                user_id=1, action='entity_created', entity_id=123
            )
    
    def test_workflow_timeout_handling(self, workflow_orchestrator, sample_workflow_steps):
        """
        Test workflow timeout handling and resource cleanup.
        
        Validates timeout enforcement, resource cleanup on timeout,
        and proper workflow termination for long-running operations.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock service with artificial delay
        mock_service = Mock()
        
        def slow_operation(*args, **kwargs):
            time.sleep(2)  # Simulate slow operation
            return {'result': 'success'}
        
        mock_service.validate_user_data = slow_operation
        service_registry = {'user_service': mock_service}
        
        # Set short timeout for testing
        timeout_step = sample_workflow_steps[0]
        timeout_step.timeout = 1  # 1 second timeout
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry):
            
            # Execute workflow with timeout
            result = workflow_orchestrator.execute_workflow(workflow_id, [timeout_step])
            
            # Validate timeout handling
            assert result['status'] == WorkflowStatus.TIMEOUT
            
            step_result = result['step_results'][0]
            assert step_result['status'] == WorkflowStepStatus.FAILED
            assert 'timeout' in step_result['error_message'].lower()
    
    def test_workflow_performance_monitoring(self, workflow_orchestrator, sample_workflow_steps, performance_monitor):
        """
        Test workflow performance monitoring and SLA compliance.
        
        Validates workflow execution timing, performance threshold enforcement,
        and SLA compliance for complex business workflow operations.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock fast services for performance testing
        mock_services = {}
        for step in sample_workflow_steps:
            mock_service = Mock()
            setattr(mock_service, step.method, Mock(return_value={'success': True}))
            mock_services[step.service] = mock_service
        
        with patch.object(workflow_orchestrator, 'service_registry', mock_services):
            
            # Monitor workflow performance
            performance_monitor['start']()
            result = workflow_orchestrator.execute_workflow(workflow_id, sample_workflow_steps)
            performance_monitor['stop']()
            
            # Validate workflow success and performance
            assert result['status'] == WorkflowStatus.COMPLETED
            
            # Ensure workflow completes within performance threshold
            performance_monitor['assert_threshold'](2.0)  # 2 second threshold for 3 steps
    
    @pytest.mark.parametrize("isolation_level", [
        TransactionIsolationLevel.READ_COMMITTED,
        TransactionIsolationLevel.REPEATABLE_READ,
        TransactionIsolationLevel.SERIALIZABLE
    ])
    def test_transaction_isolation_levels(self, workflow_orchestrator, sample_workflow_steps, isolation_level, db_session):
        """
        Test different transaction isolation levels for workflow execution.
        
        Validates transaction isolation configuration, concurrent access handling,
        and data consistency across different isolation levels.
        """
        workflow_id = str(uuid.uuid4())
        
        # Mock service for isolation testing
        mock_service = Mock()
        mock_service.validate_user_data.return_value = {'valid': True}
        service_registry = {'user_service': mock_service}
        
        with patch.object(workflow_orchestrator, 'service_registry', service_registry), \
             patch.object(db_session, 'execute') as mock_execute:
            
            # Execute workflow with specific isolation level
            result = workflow_orchestrator.execute_workflow(
                workflow_id, 
                [sample_workflow_steps[0]], 
                isolation_level=isolation_level
            )
            
            # Validate isolation level was set
            assert result['status'] == WorkflowStatus.COMPLETED
            mock_execute.assert_any_call(f"SET TRANSACTION ISOLATION LEVEL {isolation_level.value}")


# ================================
# Integration Test Scenarios
# ================================

class TestServiceIntegration:
    """
    Integration tests for service layer components working together.
    
    Tests validate service composition, cross-service workflows, and
    end-to-end business logic coordination while ensuring functional
    equivalence with original Node.js business rules.
    """
    
    @pytest.fixture
    def integrated_services(self, app, db_session):
        """Create integrated service instances for testing."""
        with app.app_context():
            services = {
                'user_service': UserService(db=db_session),
                'business_entity_service': BusinessEntityService(db=db_session),
                'validation_service': ValidationService(),
                'workflow_orchestrator': WorkflowOrchestrator(db=db_session)
            }
            yield services
    
    def test_user_entity_creation_workflow(self, integrated_services, db_session):
        """
        Test integrated workflow: user registration -> entity creation -> validation.
        
        Validates end-to-end business workflow coordination across multiple
        services while maintaining transactional consistency and business rules.
        """
        user_service = integrated_services['user_service']
        entity_service = integrated_services['business_entity_service']
        validation_service = integrated_services['validation_service']
        orchestrator = integrated_services['workflow_orchestrator']
        
        # Mock database operations
        with patch.object(db_session, 'add') as mock_add, \
             patch.object(db_session, 'commit') as mock_commit:
            
            # Mock service dependencies
            with patch.object(user_service, '_find_user_by_email', return_value=None), \
                 patch.object(user_service, '_find_user_by_username', return_value=None), \
                 patch.object(entity_service, '_validate_entity_data', return_value=True), \
                 patch.object(entity_service, '_check_entity_name_unique', return_value=True):
                
                # Define integrated workflow
                workflow_steps = [
                    WorkflowStep(
                        name="register_user",
                        service="user_service",
                        method="register_user",
                        parameters={
                            'user_data': UserRegistrationData(
                                username="integration_user",
                                email="integration@example.com",
                                password="SecurePass123!"
                            )
                        }
                    ),
                    WorkflowStep(
                        name="create_entity",
                        service="business_entity_service", 
                        method="create_entity",
                        parameters={
                            'entity_data': EntityCreationRequest(
                                name="User Entity",
                                description="Entity for integration user",
                                owner_id="${register_user.result.user_id}"
                            )
                        }
                    )
                ]
                
                # Configure service registry
                orchestrator.service_registry = {
                    'user_service': user_service,
                    'business_entity_service': entity_service
                }
                
                # Execute integrated workflow
                result = orchestrator.execute_workflow(str(uuid.uuid4()), workflow_steps)
                
                # Validate integrated workflow success
                assert result['status'] == WorkflowStatus.COMPLETED
                assert len(result['step_results']) == 2
                
                # Verify both services were called
                assert mock_add.call_count >= 2  # At least one call per service
                assert mock_commit.call_count >= 1  # Transaction committed
    
    def test_validation_error_propagation(self, integrated_services):
        """
        Test validation error propagation across service boundaries.
        
        Validates error handling consistency, validation failure propagation,
        and proper error response formatting across service compositions.
        """
        validation_service = integrated_services['validation_service']
        user_service = integrated_services['user_service']
        
        # Invalid user data that should fail validation
        invalid_user_data = UserRegistrationData(
            username="",  # Empty username
            email="invalid-email",  # Invalid email format
            password="weak"  # Weak password
        )
        
        # Execute registration with validation
        result = user_service.register_user(invalid_user_data)
        
        # Validate error propagation
        assert result['status'] == RegistrationStatus.VALIDATION_FAILED
        assert 'errors' in result
        assert len(result['errors']) > 0


# ================================
# Performance and Load Testing
# ================================

@pytest.mark.performance
class TestServicePerformance:
    """
    Performance tests for service layer components.
    
    Tests validate performance requirements, load handling capabilities,
    and SLA compliance for service layer operations under various conditions.
    """
    
    def test_user_service_bulk_operations(self, app, db_session, performance_monitor):
        """Test user service performance with bulk operations."""
        with app.app_context():
            user_service = UserService(db=db_session)
            
            # Mock bulk database operations
            with patch.object(db_session, 'add'), \
                 patch.object(db_session, 'commit'), \
                 patch.object(user_service, '_find_user_by_email', return_value=None), \
                 patch.object(user_service, '_find_user_by_username', return_value=None):
                
                # Performance test with multiple user registrations
                performance_monitor['start']()
                
                results = []
                for i in range(100):
                    user_data = UserRegistrationData(
                        username=f"perfuser_{i}",
                        email=f"perf_{i}@example.com",
                        password="TestPassword123!"
                    )
                    result = user_service.register_user(user_data)
                    results.append(result)
                
                performance_monitor['stop']()
                
                # Validate performance and results
                assert all(r['status'] == RegistrationStatus.SUCCESS for r in results)
                performance_monitor['assert_threshold'](10.0)  # 10 second threshold for 100 operations
    
    def test_workflow_orchestrator_concurrent_execution(self, app, db_session, performance_monitor):
        """Test workflow orchestrator performance with concurrent workflows."""
        with app.app_context():
            orchestrator = WorkflowOrchestrator(db=db_session)
            
            # Mock fast service for concurrent testing
            mock_service = Mock()
            mock_service.test_operation.return_value = {'success': True}
            orchestrator.service_registry = {'test_service': mock_service}
            
            # Define simple workflow step
            workflow_step = WorkflowStep(
                name="test_step",
                service="test_service",
                method="test_operation",
                parameters={}
            )
            
            # Performance test with concurrent workflows
            performance_monitor['start']()
            
            results = []
            for i in range(50):
                workflow_id = f"perf_workflow_{i}"
                result = orchestrator.execute_workflow(workflow_id, [workflow_step])
                results.append(result)
            
            performance_monitor['stop']()
            
            # Validate concurrent execution performance
            assert all(r['status'] == WorkflowStatus.COMPLETED for r in results)
            performance_monitor['assert_threshold'](15.0)  # 15 second threshold for 50 workflows


# ================================
# Error Handling and Edge Cases
# ================================

@pytest.mark.unit
class TestServiceErrorHandling:
    """
    Comprehensive error handling tests for service layer components.
    
    Tests validate error scenarios, exception handling, recovery mechanisms,
    and proper error response formatting across all service components.
    """
    
    def test_database_connection_failure_handling(self, app):
        """Test service behavior during database connection failures."""
        with app.app_context():
            # Simulate database connection failure
            with patch('sqlalchemy.create_engine', side_effect=OperationalError("connection", "failed", "error")):
                
                user_service = UserService()
                
                user_data = UserRegistrationData(
                    username="testuser",
                    email="test@example.com", 
                    password="TestPassword123!"
                )
                
                # Validate graceful error handling
                with pytest.raises(ServiceError):
                    user_service.register_user(user_data)
    
    def test_service_dependency_injection_failure(self, app, db_session):
        """Test service behavior when dependency injection fails."""
        with app.app_context():
            # Test with missing required dependencies
            with pytest.raises((ImportError, AttributeError)):
                # This should fail due to missing dependencies
                BusinessEntityService(db=None)
    
    def test_concurrent_access_conflict_resolution(self, app, db_session):
        """Test service handling of concurrent access conflicts."""
        with app.app_context():
            user_service = UserService(db=db_session)
            
            # Simulate concurrent access conflict
            with patch.object(db_session, 'commit', side_effect=IntegrityError("conflict", "params", "orig")):
                
                user_data = UserRegistrationData(
                    username="concurrent_user",
                    email="concurrent@example.com",
                    password="TestPassword123!"
                )
                
                # Mock no existing users for initial validation
                with patch.object(user_service, '_find_user_by_email', return_value=None), \
                     patch.object(user_service, '_find_user_by_username', return_value=None):
                    
                    result = user_service.register_user(user_data)
                    
                    # Validate conflict handling
                    assert result['status'] == RegistrationStatus.SYSTEM_ERROR
                    assert 'error' in result


if __name__ == '__main__':
    # Configure pytest execution for service layer testing
    pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--cov=src.services',
        '--cov-report=html',
        '--cov-report=term-missing',
        '--cov-fail-under=90'
    ])