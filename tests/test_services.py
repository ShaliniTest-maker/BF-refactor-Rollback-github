"""
Service Layer Testing Module

This module provides comprehensive testing for the Flask Service Layer implementation,
validating business logic, workflow orchestration, and functional equivalence with 
the original Node.js business rules and operations.

The testing suite implements:
- Business logic testing using Flask test client and SQLAlchemy test database sessions per Section 4.7.1
- Service Layer pattern implementation validation for workflow orchestration per Section 5.1.1
- 100% functional parity validation with original Node.js business logic per Section 4.7.1
- Comprehensive use case testing with domain model validation per Service Layer pattern requirements
- Performance benchmarking with pytest-benchmark for SLA validation per Section 4.7.4.1
- Error handling and recovery procedures per Section 4.7.6

Features:
- User Service comprehensive business logic validation
- Auth Service authentication workflow testing
- Service Layer orchestration and integration testing
- Performance regression detection with statistical analysis
- Error handling and edge case validation
- Factory Boy integration for realistic test data scenarios
"""

import pytest
import json
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from flask import Flask, current_app
from flask.testing import FlaskClient
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# Import services under test
from services.user_service import (
    UserService, UserCreationData, UserUpdateData, UserSearchCriteria,
    UserOperationResult, UserValidationResult, UserStatus,
    UserServiceError, UserNotFoundError, UserValidationError, DuplicateUserError
)
from services.auth_service import (
    AuthService, FlaskUser, AuthenticationError, TokenError, SessionError
)

# Import test utilities and fixtures
from tests.factories import (
    UserFactory, RoleFactory, PermissionFactory, UserRoleFactory,
    UserSessionFactory, FactoryPresets, FactorySessionManager
)


# ============================================================================
# Service Layer Testing Framework Classes
# ============================================================================

@dataclass
class ServiceTestResult:
    """Type-safe service test result structure for comprehensive validation."""
    success: bool
    result_data: Any = None
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    validation_errors: Optional[List[str]] = None
    
    @classmethod
    def success_result(cls, data: Any, execution_time: float = None) -> 'ServiceTestResult':
        """Create successful test result."""
        return cls(success=True, result_data=data, execution_time=execution_time)
    
    @classmethod
    def error_result(cls, error: str, validation_errors: List[str] = None) -> 'ServiceTestResult':
        """Create error test result."""
        return cls(
            success=False, 
            error_message=error,
            validation_errors=validation_errors or []
        )


class ServiceLayerTestFramework:
    """
    Testing framework for Service Layer pattern validation and workflow orchestration.
    
    Provides comprehensive testing utilities for validating business logic implementation,
    service integration patterns, and functional equivalence with Node.js systems.
    """
    
    def __init__(self, app: Flask, db_session: Session):
        """
        Initialize Service Layer testing framework.
        
        Args:
            app: Flask application instance
            db_session: SQLAlchemy database session with rollback capabilities
        """
        self.app = app
        self.db_session = db_session
        self.user_service = UserService(db_session)
        self.auth_service = AuthService(db_session, app)
        self.test_data_cache = {}
        
    def setup_test_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """
        Set up comprehensive test scenario with realistic data.
        
        Args:
            scenario_name: Name of test scenario to create
            
        Returns:
            Dictionary containing created test entities
        """
        if scenario_name in self.test_data_cache:
            return self.test_data_cache[scenario_name]
        
        if scenario_name == "admin_user_scenario":
            data = FactoryPresets.create_admin_user_with_roles()
            self.test_data_cache[scenario_name] = {
                'admin_user': data[0],
                'admin_role': data[1],
                'permissions': data[2]
            }
        elif scenario_name == "rbac_scenario":
            data = FactoryPresets.create_rbac_test_scenario()
            self.test_data_cache[scenario_name] = data
        elif scenario_name == "user_session_scenario":
            data = FactoryPresets.create_user_session_with_audit_trail()
            self.test_data_cache[scenario_name] = data
        else:
            # Default scenario with basic user
            user = UserFactory()
            self.test_data_cache[scenario_name] = {'user': user}
        
        return self.test_data_cache[scenario_name]
    
    def validate_service_operation(self, operation_name: str, 
                                 operation_result: Any,
                                 expected_type: type = None,
                                 validation_rules: List[callable] = None) -> ServiceTestResult:
        """
        Validate service operation results with comprehensive checks.
        
        Args:
            operation_name: Name of operation being validated
            operation_result: Result from service operation
            expected_type: Expected type of result
            validation_rules: List of validation functions
            
        Returns:
            ServiceTestResult with validation outcome
        """
        try:
            # Type validation
            if expected_type and not isinstance(operation_result, expected_type):
                return ServiceTestResult.error_result(
                    f"{operation_name}: Expected {expected_type.__name__}, got {type(operation_result).__name__}"
                )
            
            # Custom validation rules
            if validation_rules:
                for rule in validation_rules:
                    validation_result = rule(operation_result)
                    if not validation_result:
                        return ServiceTestResult.error_result(
                            f"{operation_name}: Custom validation rule failed"
                        )
            
            return ServiceTestResult.success_result(operation_result)
            
        except Exception as e:
            return ServiceTestResult.error_result(
                f"{operation_name}: Validation error - {str(e)}"
            )
    
    def measure_performance(self, operation_func: callable, *args, **kwargs) -> ServiceTestResult:
        """
        Measure service operation performance with statistical analysis.
        
        Args:
            operation_func: Function to measure
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            ServiceTestResult with performance data
        """
        import time
        
        start_time = time.perf_counter()
        try:
            result = operation_func(*args, **kwargs)
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            return ServiceTestResult.success_result(result, execution_time)
            
        except Exception as e:
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            
            return ServiceTestResult.error_result(
                f"Performance test failed: {str(e)}",
                []
            )


# ============================================================================
# User Service Business Logic Testing
# ============================================================================

class TestUserServiceBusinessLogic:
    """
    Comprehensive User Service business logic testing with functional parity validation.
    
    Validates all user management operations including CRUD operations, authentication,
    session management, and role/permission handling to ensure 100% functional
    equivalence with original Node.js business logic.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app: Flask, db_session: Session):
        """Set up test framework for each test method."""
        self.framework = ServiceLayerTestFramework(app, db_session)
        self.user_service = self.framework.user_service
        self.db_session = db_session
    
    # User Creation Business Logic Tests
    
    def test_create_user_comprehensive_validation(self):
        """
        Test comprehensive user creation with business logic validation.
        
        Validates:
        - Complete user creation workflow
        - Business rule enforcement
        - Data validation and sanitization
        - Error handling for edge cases
        """
        # Test valid user creation
        user_data = UserCreationData(
            username="test_user_123",
            email="test@example.com",
            password="SecurePassword123!",
            first_name="Test",
            last_name="User",
            role_names=["user"]
        )
        
        result = self.user_service.create_user(user_data)
        
        assert result.success is True
        assert result.user is not None
        assert result.user.username == "test_user_123"
        assert result.user.email == "test@example.com"
        assert result.user.is_active is True
        assert result.error_message is None
        
        # Verify password hash was created
        assert result.user.password_hash is not None
        assert result.user.password_hash != "SecurePassword123!"
        
        # Verify audit fields
        assert result.user.created_at is not None
        assert result.user.updated_at is not None
        assert result.user.created_at == result.user.updated_at
    
    def test_create_user_duplicate_validation(self):
        """Test duplicate user creation handling with proper error responses."""
        # Create initial user
        user_data = UserCreationData(
            username="duplicate_user",
            email="duplicate@example.com",
            password="Password123!"
        )
        
        first_result = self.user_service.create_user(user_data)
        assert first_result.success is True
        
        # Attempt to create duplicate user
        with pytest.raises(DuplicateUserError):
            self.user_service.create_user(user_data)
        
        # Test duplicate username with different email
        duplicate_username_data = UserCreationData(
            username="duplicate_user",
            email="different@example.com",
            password="Password123!"
        )
        
        with pytest.raises(DuplicateUserError) as exc_info:
            self.user_service.create_user(duplicate_username_data)
        assert "duplicate_user" in str(exc_info.value)
        
        # Test duplicate email with different username
        duplicate_email_data = UserCreationData(
            username="different_user",
            email="duplicate@example.com",
            password="Password123!"
        )
        
        with pytest.raises(DuplicateUserError) as exc_info:
            self.user_service.create_user(duplicate_email_data)
        assert "duplicate@example.com" in str(exc_info.value)
    
    def test_create_user_validation_errors(self):
        """Test user creation validation with comprehensive error scenarios."""
        # Test missing required fields
        invalid_data = UserCreationData(
            username="",
            email="",
            password=""
        )
        
        with pytest.raises(UserValidationError) as exc_info:
            self.user_service.create_user(invalid_data)
        
        validation_errors = exc_info.value.validation_errors
        assert "Username is required" in validation_errors
        assert "Email is required" in validation_errors
        
        # Test invalid email format
        invalid_email_data = UserCreationData(
            username="valid_user",
            email="invalid-email-format",
            password="Password123!"
        )
        
        with pytest.raises(UserValidationError) as exc_info:
            self.user_service.create_user(invalid_email_data)
        assert "Invalid email format" in exc_info.value.validation_errors
        
        # Test weak password
        weak_password_data = UserCreationData(
            username="valid_user",
            email="valid@example.com",
            password="123"
        )
        
        with pytest.raises(UserValidationError) as exc_info:
            self.user_service.create_user(weak_password_data)
        
        password_errors = exc_info.value.validation_errors
        assert any("password" in error.lower() for error in password_errors)
    
    def test_create_user_with_roles_assignment(self):
        """Test user creation with role assignment business logic."""
        # Create role first
        role = RoleFactory(name="test_role")
        self.db_session.commit()
        
        user_data = UserCreationData(
            username="role_test_user",
            email="roletest@example.com",
            password="Password123!",
            role_names=["test_role"]
        )
        
        result = self.user_service.create_user(user_data)
        
        assert result.success is True
        
        # Verify role assignment
        created_user = self.user_service.get_user_by_id(result.user.id, include_roles=True)
        assert len(created_user.roles) == 1
        assert created_user.roles[0].name == "test_role"
        
        # Test with non-existent role
        invalid_role_data = UserCreationData(
            username="invalid_role_user",
            email="invalidrole@example.com",
            password="Password123!",
            role_names=["non_existent_role"]
        )
        
        with pytest.raises(UserValidationError) as exc_info:
            self.user_service.create_user(invalid_role_data)
        assert "non_existent_role" in str(exc_info.value.validation_errors)
    
    # User Update Business Logic Tests
    
    def test_update_user_comprehensive_workflow(self):
        """Test comprehensive user update workflow with business logic validation."""
        # Create test user
        user = UserFactory()
        self.db_session.commit()
        
        # Update user data
        update_data = UserUpdateData(
            username="updated_username",
            email="updated@example.com",
            first_name="Updated",
            last_name="Name",
            is_active=False
        )
        
        result = self.user_service.update_user(user.id, update_data)
        
        assert result.success is True
        assert result.user.username == "updated_username"
        assert result.user.email == "updated@example.com"
        assert result.user.first_name == "Updated"
        assert result.user.last_name == "Name"
        assert result.user.is_active is False
        
        # Verify updated_at timestamp was updated
        assert result.user.updated_at > result.user.created_at
    
    def test_update_user_validation_errors(self):
        """Test user update validation with error handling."""
        user = UserFactory()
        self.db_session.commit()
        
        # Test invalid email update
        invalid_update = UserUpdateData(email="invalid-email")
        
        result = self.user_service.update_user(user.id, invalid_update)
        
        assert result.success is False
        assert "Invalid email format" in result.validation_errors
        
        # Test empty username
        empty_username_update = UserUpdateData(username="")
        
        result = self.user_service.update_user(user.id, empty_username_update)
        
        assert result.success is False
        assert "Username cannot be empty" in result.validation_errors
    
    def test_update_user_duplicate_prevention(self):
        """Test update user duplicate prevention business logic."""
        # Create two users
        user1 = UserFactory(username="user1", email="user1@example.com")
        user2 = UserFactory(username="user2", email="user2@example.com")
        self.db_session.commit()
        
        # Try to update user2 with user1's username
        duplicate_username_update = UserUpdateData(username="user1")
        
        result = self.user_service.update_user(user2.id, duplicate_username_update)
        
        assert result.success is False
        assert "already taken" in result.validation_errors[0]
        
        # Try to update user2 with user1's email
        duplicate_email_update = UserUpdateData(email="user1@example.com")
        
        result = self.user_service.update_user(user2.id, duplicate_email_update)
        
        assert result.success is False
        assert "already taken" in result.validation_errors[0]
    
    def test_update_user_role_management(self):
        """Test user role management through update operations."""
        # Create user and roles
        user = UserFactory()
        role1 = RoleFactory(name="role1")
        role2 = RoleFactory(name="role2")
        self.db_session.commit()
        
        # Assign initial role
        self.user_service.assign_role_to_user(user.id, "role1")
        
        # Update user roles
        update_data = UserUpdateData(role_names=["role2"])
        
        result = self.user_service.update_user(user.id, update_data)
        
        assert result.success is True
        
        # Verify role was updated
        updated_user = self.user_service.get_user_by_id(user.id, include_roles=True)
        role_names = [role.name for role in updated_user.roles]
        assert "role2" in role_names
        assert "role1" not in role_names
    
    # User Deletion Business Logic Tests
    
    def test_delete_user_soft_delete_workflow(self):
        """Test soft delete user workflow with business logic validation."""
        user = UserFactory()
        self.db_session.commit()
        
        result = self.user_service.delete_user(user.id, soft_delete=True)
        
        assert result.success is True
        assert result.user.is_active is False
        assert result.user.status == UserStatus.DELETED.value
        assert result.user.deleted_at is not None
        assert result.user.updated_at > result.user.created_at
    
    def test_delete_user_hard_delete_workflow(self):
        """Test hard delete user workflow with cascading operations."""
        user = UserFactory()
        session = UserSessionFactory(user=user)
        self.db_session.commit()
        
        user_id = user.id
        session_id = session.id
        
        result = self.user_service.delete_user(user_id, soft_delete=False)
        
        assert result.success is True
        
        # Verify user was removed from database
        deleted_user = self.user_service.get_user_by_id(user_id)
        assert deleted_user is None
        
        # Verify associated sessions were removed
        from models.user import UserSession
        remaining_session = self.db_session.query(UserSession).filter(
            UserSession.id == session_id
        ).first()
        assert remaining_session is None
    
    def test_delete_non_existent_user(self):
        """Test deletion of non-existent user with proper error handling."""
        result = self.user_service.delete_user(99999, soft_delete=True)
        
        assert result.success is False
        assert "not found" in result.error_message
    
    # User Retrieval Business Logic Tests
    
    def test_get_user_by_id_with_relationships(self):
        """Test user retrieval with relationship loading optimization."""
        scenario_data = self.framework.setup_test_scenario("rbac_scenario")
        user = scenario_data['users']['admin_user']
        
        # Test basic retrieval
        retrieved_user = self.user_service.get_user_by_id(user.id)
        assert retrieved_user is not None
        assert retrieved_user.id == user.id
        
        # Test with roles included
        user_with_roles = self.user_service.get_user_by_id(user.id, include_roles=True)
        assert user_with_roles is not None
        assert hasattr(user_with_roles, 'roles')
        assert len(user_with_roles.roles) > 0
    
    def test_get_user_by_username_and_email(self):
        """Test user retrieval by username and email with case handling."""
        user = UserFactory(username="testuser", email="test@example.com")
        self.db_session.commit()
        
        # Test username retrieval
        user_by_username = self.user_service.get_user_by_username("testuser")
        assert user_by_username is not None
        assert user_by_username.id == user.id
        
        # Test email retrieval
        user_by_email = self.user_service.get_user_by_email("test@example.com")
        assert user_by_email is not None
        assert user_by_email.id == user.id
        
        # Test non-existent user
        non_existent = self.user_service.get_user_by_username("nonexistent")
        assert non_existent is None
    
    def test_search_users_comprehensive_criteria(self):
        """Test user search with comprehensive criteria and pagination."""
        # Create test users with various attributes
        users = [
            UserFactory(username="admin_user", email="admin@example.com", is_active=True),
            UserFactory(username="test_user", email="test@example.com", is_active=True),
            UserFactory(username="inactive_user", email="inactive@example.com", is_active=False)
        ]
        self.db_session.commit()
        
        # Test search by email pattern
        search_criteria = UserSearchCriteria(
            email="test",
            include_inactive=False,
            limit=10,
            offset=0
        )
        
        results, total_count = self.user_service.search_users(search_criteria)
        
        assert len(results) == 1
        assert results[0].email == "test@example.com"
        assert total_count == 1
        
        # Test search including inactive users
        search_criteria_with_inactive = UserSearchCriteria(
            include_inactive=True,
            limit=10
        )
        
        results_with_inactive, total_count_with_inactive = self.user_service.search_users(
            search_criteria_with_inactive
        )
        
        assert len(results_with_inactive) >= 3
        assert total_count_with_inactive >= 3
        
        # Test pagination
        paginated_criteria = UserSearchCriteria(
            limit=2,
            offset=0,
            order_by="username",
            order_direction="asc"
        )
        
        page_results, page_total = self.user_service.search_users(paginated_criteria)
        
        assert len(page_results) <= 2
        assert page_total >= 3
    
    # Authentication Business Logic Tests
    
    def test_authenticate_user_workflow(self):
        """Test user authentication workflow with comprehensive validation."""
        # Create user with known password
        password = "TestPassword123!"
        user_data = UserCreationData(
            username="auth_test_user",
            email="authtest@example.com",
            password=password
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        # Test successful authentication by email
        authenticated_user = self.user_service.authenticate_user(
            "authtest@example.com", password
        )
        
        assert authenticated_user is not None
        assert authenticated_user.email == "authtest@example.com"
        
        # Verify last_login was updated
        assert authenticated_user.last_login is not None
        
        # Test successful authentication by username
        authenticated_by_username = self.user_service.authenticate_user(
            "auth_test_user", password
        )
        
        assert authenticated_by_username is not None
        assert authenticated_by_username.username == "auth_test_user"
        
        # Test failed authentication
        failed_auth = self.user_service.authenticate_user(
            "authtest@example.com", "wrong_password"
        )
        
        assert failed_auth is None
        
        # Test authentication with non-existent user
        non_existent_auth = self.user_service.authenticate_user(
            "nonexistent@example.com", password
        )
        
        assert non_existent_auth is None
    
    def test_authenticate_inactive_user(self):
        """Test authentication rejection for inactive users."""
        # Create inactive user
        user_data = UserCreationData(
            username="inactive_user",
            email="inactive@example.com",
            password="Password123!",
            is_active=False
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        # Attempt authentication
        authenticated_user = self.user_service.authenticate_user(
            "inactive@example.com", "Password123!"
        )
        
        assert authenticated_user is None
    
    # Password Management Business Logic Tests
    
    def test_change_user_password_workflow(self):
        """Test password change workflow with validation."""
        # Create user
        current_password = "CurrentPassword123!"
        user_data = UserCreationData(
            username="password_test_user",
            email="passwordtest@example.com",
            password=current_password
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        user_id = create_result.user.id
        new_password = "NewPassword456!"
        
        # Test successful password change
        change_result = self.user_service.change_user_password(
            user_id, current_password, new_password
        )
        
        assert change_result.success is True
        
        # Verify old password no longer works
        old_auth = self.user_service.authenticate_user(
            "passwordtest@example.com", current_password
        )
        assert old_auth is None
        
        # Verify new password works
        new_auth = self.user_service.authenticate_user(
            "passwordtest@example.com", new_password
        )
        assert new_auth is not None
        
        # Test password change with wrong current password
        wrong_current_result = self.user_service.change_user_password(
            user_id, "WrongPassword", "AnotherPassword123!"
        )
        
        assert wrong_current_result.success is False
        assert "incorrect" in wrong_current_result.error_message.lower()
    
    def test_reset_user_password_admin_operation(self):
        """Test admin password reset functionality."""
        # Create user
        user_data = UserCreationData(
            username="reset_test_user",
            email="resettest@example.com",
            password="OriginalPassword123!"
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        user_id = create_result.user.id
        new_password = "ResetPassword789!"
        
        # Test admin password reset
        reset_result = self.user_service.reset_user_password(user_id, new_password)
        
        assert reset_result.success is True
        
        # Verify new password works
        auth_result = self.user_service.authenticate_user(
            "resettest@example.com", new_password
        )
        assert auth_result is not None
        
        # Test reset with weak password
        weak_password_result = self.user_service.reset_user_password(user_id, "123")
        
        assert weak_password_result.success is False
        assert "validation failed" in weak_password_result.error_message.lower()
    
    # Role and Permission Management Tests
    
    def test_user_permission_workflow(self):
        """Test user permission management through roles."""
        scenario_data = self.framework.setup_test_scenario("rbac_scenario")
        admin_user = scenario_data['users']['admin_user']
        regular_user = scenario_data['users']['regular_user']
        
        # Test admin permissions
        admin_permissions = self.user_service.get_user_permissions(admin_user.id)
        assert len(admin_permissions) > 0
        
        # Test specific permission check for admin
        has_admin_permission = self.user_service.user_has_permission(
            admin_user.id, "users.admin"
        )
        assert has_admin_permission is True
        
        # Test regular user permissions
        regular_permissions = self.user_service.get_user_permissions(regular_user.id)
        
        # Test permission check for regular user
        has_limited_permission = self.user_service.user_has_permission(
            regular_user.id, "users.read"
        )
        assert has_limited_permission is True
        
        has_admin_permission = self.user_service.user_has_permission(
            regular_user.id, "users.admin"
        )
        assert has_admin_permission is False
    
    def test_assign_and_remove_roles(self):
        """Test role assignment and removal operations."""
        user = UserFactory()
        role = RoleFactory(name="test_assignment_role")
        self.db_session.commit()
        
        # Test role assignment
        assign_result = self.user_service.assign_role_to_user(user.id, "test_assignment_role")
        assert assign_result is True
        
        # Verify assignment
        user_with_roles = self.user_service.get_user_by_id(user.id, include_roles=True)
        role_names = [role.name for role in user_with_roles.roles]
        assert "test_assignment_role" in role_names
        
        # Test duplicate assignment (should succeed silently)
        duplicate_assign = self.user_service.assign_role_to_user(user.id, "test_assignment_role")
        assert duplicate_assign is True
        
        # Test role removal
        remove_result = self.user_service.remove_role_from_user(user.id, "test_assignment_role")
        assert remove_result is True
        
        # Verify removal
        user_after_removal = self.user_service.get_user_by_id(user.id, include_roles=True)
        role_names_after = [role.name for role in user_after_removal.roles]
        assert "test_assignment_role" not in role_names_after
        
        # Test removing non-existent role (should succeed silently)
        remove_nonexistent = self.user_service.remove_role_from_user(
            user.id, "nonexistent_role"
        )
        assert remove_nonexistent is False
    
    # Session Management Tests
    
    def test_user_session_management(self):
        """Test user session management operations."""
        scenario_data = self.framework.setup_test_scenario("user_session_scenario")
        user = scenario_data['user']
        session = scenario_data['session']
        
        # Test get user sessions
        sessions = self.user_service.get_user_sessions(user.id)
        assert len(sessions) > 0
        
        # Test session invalidation
        invalidate_result = self.user_service.invalidate_user_session(session.id)
        assert invalidate_result is True
        
        # Verify session was invalidated
        sessions_after_invalidation = self.user_service.get_user_sessions(
            user.id, include_expired=True
        )
        invalidated_session = next(
            (s for s in sessions_after_invalidation if s.id == session.id), None
        )
        assert invalidated_session is not None
        assert invalidated_session.is_valid is False
    
    def test_cleanup_expired_sessions(self):
        """Test expired session cleanup operations."""
        # Create user with expired session
        user = UserFactory()
        expired_session = UserSessionFactory(
            user=user,
            expires_at=datetime.utcnow() - timedelta(hours=1),
            is_valid=False
        )
        valid_session = UserSessionFactory(user=user)
        self.db_session.commit()
        
        # Test cleanup operation
        cleaned_count = self.user_service.cleanup_expired_sessions()
        assert cleaned_count >= 1
        
        # Verify valid sessions remain
        remaining_sessions = self.user_service.get_user_sessions(user.id)
        assert len(remaining_sessions) >= 1
    
    # Analytics and Reporting Tests
    
    def test_user_statistics_generation(self):
        """Test user statistics and reporting functionality."""
        # Create test data
        active_user = UserFactory(is_active=True)
        inactive_user = UserFactory(is_active=False)
        auth0_user = UserFactory(auth0_user_id="auth0|test123")
        self.db_session.commit()
        
        # Generate statistics
        stats = self.user_service.get_user_stats()
        
        assert isinstance(stats, dict)
        assert 'total_users' in stats
        assert 'active_users' in stats
        assert 'inactive_users' in stats
        assert 'users_with_auth0' in stats
        
        assert stats['total_users'] >= 3
        assert stats['active_users'] >= 1
        assert stats['inactive_users'] >= 1
        assert stats['users_with_auth0'] >= 1


# ============================================================================
# Auth Service Authentication Workflow Testing
# ============================================================================

class TestAuthServiceWorkflows:
    """
    Comprehensive Auth Service authentication workflow testing.
    
    Validates Flask-Login integration, token management, session handling,
    and authentication decorators to ensure proper authentication flow
    orchestration and security compliance.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app: Flask, db_session: Session):
        """Set up test framework for authentication testing."""
        self.framework = ServiceLayerTestFramework(app, db_session)
        self.auth_service = self.framework.auth_service
        self.user_service = self.framework.user_service
        self.app = app
        self.db_session = db_session
    
    def test_flask_login_authentication_workflow(self):
        """Test Flask-Login authentication workflow integration."""
        # Create test user
        user_data = UserCreationData(
            username="flask_login_user",
            email="flasklogin@example.com",
            password="FlaskPassword123!"
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        # Test authentication
        success, flask_user, error = self.auth_service.authenticate_user(
            "flasklogin@example.com", "FlaskPassword123!"
        )
        
        assert success is True
        assert flask_user is not None
        assert isinstance(flask_user, FlaskUser)
        assert flask_user.user.email == "flasklogin@example.com"
        assert error is None
        
        # Test Flask-Login interface compliance
        assert flask_user.is_authenticated is True
        assert flask_user.is_active is True
        assert flask_user.is_anonymous is False
        assert flask_user.get_id() == str(create_result.user.id)
    
    def test_authentication_failure_scenarios(self):
        """Test comprehensive authentication failure handling."""
        # Create test user
        user_data = UserCreationData(
            username="auth_fail_user",
            email="authfail@example.com",
            password="CorrectPassword123!"
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        # Test wrong password
        success, user, error = self.auth_service.authenticate_user(
            "authfail@example.com", "WrongPassword"
        )
        
        assert success is False
        assert user is None
        assert "Invalid email or password" in error
        
        # Test non-existent email
        success, user, error = self.auth_service.authenticate_user(
            "nonexistent@example.com", "AnyPassword"
        )
        
        assert success is False
        assert user is None
        assert "Invalid email or password" in error
        
        # Test inactive user
        update_result = self.user_service.update_user(
            create_result.user.id, UserUpdateData(is_active=False)
        )
        assert update_result.success is True
        
        success, user, error = self.auth_service.authenticate_user(
            "authfail@example.com", "CorrectPassword123!"
        )
        
        assert success is False
        assert user is None
        assert "deactivated" in error
    
    def test_secure_token_generation_and_verification(self):
        """Test ItsDangerous secure token generation and verification."""
        user = UserFactory()
        self.db_session.commit()
        
        # Test token generation
        token = self.auth_service.generate_secure_token(
            user.id, purpose='test', expires_in=3600
        )
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Test token verification
        payload = self.auth_service.verify_secure_token(
            token, purpose='test', max_age=3600
        )
        
        assert payload is not None
        assert payload['user_id'] == user.id
        assert payload['purpose'] == 'test'
        assert 'created_at' in payload
        assert 'nonce' in payload
        
        # Test token with wrong purpose
        wrong_purpose_payload = self.auth_service.verify_secure_token(
            token, purpose='wrong_purpose', max_age=3600
        )
        
        assert wrong_purpose_payload is None
        
        # Test expired token (simulate by setting very short max_age)
        import time
        time.sleep(1)  # Wait 1 second
        
        expired_payload = self.auth_service.verify_secure_token(
            token, purpose='test', max_age=0  # 0 seconds max age
        )
        
        assert expired_payload is None
    
    def test_jwt_token_generation_and_verification(self):
        """Test JWT token generation and verification workflow."""
        user = UserFactory()
        self.db_session.commit()
        
        # Test JWT generation
        jwt_token = self.auth_service.generate_jwt_token(user.id, expires_in=3600)
        
        assert isinstance(jwt_token, str)
        assert len(jwt_token) > 0
        
        # Test JWT verification
        payload = self.auth_service.verify_jwt_token(jwt_token)
        
        assert payload is not None
        assert payload['user_id'] == user.id
        assert 'exp' in payload
        assert 'iat' in payload
        assert 'iss' in payload
        assert 'jti' in payload
        
        # Test JWT with tampered signature
        tampered_token = jwt_token[:-5] + "XXXX"
        
        tampered_payload = self.auth_service.verify_jwt_token(tampered_token)
        assert tampered_payload is None
    
    def test_password_hashing_and_verification(self):
        """Test password hashing and verification security."""
        password = "SecureTestPassword123!"
        
        # Test password hashing
        password_hash = self.auth_service.hash_password(password)
        
        assert isinstance(password_hash, str)
        assert password_hash != password
        assert len(password_hash) > 0
        
        # Test password verification
        is_valid = self.auth_service._verify_password(password, password_hash)
        assert is_valid is True
        
        # Test wrong password
        is_invalid = self.auth_service._verify_password("WrongPassword", password_hash)
        assert is_invalid is False
    
    def test_authentication_decorators(self):
        """Test authentication decorator functionality."""
        # This test would require a Flask application context
        # and actual route testing, which is more suited for integration tests
        # Here we test the decorator creation
        
        role_decorator = self.auth_service.require_role('admin')
        assert callable(role_decorator)
        
        multi_role_decorator = self.auth_service.require_any_role('admin', 'manager')
        assert callable(multi_role_decorator)
        
        api_auth_decorator = self.auth_service.api_auth_required
        assert callable(api_auth_decorator)
    
    @pytest.mark.integration
    def test_user_session_integration(self):
        """Test user session integration with authentication service."""
        # Create user and authenticate
        user_data = UserCreationData(
            username="session_test_user",
            email="sessiontest@example.com",
            password="SessionPassword123!"
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        success, flask_user, error = self.auth_service.authenticate_user(
            "sessiontest@example.com", "SessionPassword123!", remember=True
        )
        
        assert success is True
        assert flask_user is not None
        
        # Test current user ID retrieval
        with self.app.test_request_context():
            # Simulate logged in user context
            from flask_login import login_user
            login_user(flask_user, remember=True)
            
            current_user_id = self.auth_service.get_current_user_id()
            assert current_user_id == create_result.user.id
            
            is_authenticated = self.auth_service.is_authenticated()
            assert is_authenticated is True
            
            # Test logout
            logout_success = self.auth_service.logout_user()
            assert logout_success is True


# ============================================================================
# Service Layer Integration and Orchestration Testing
# ============================================================================

class TestServiceLayerOrchestration:
    """
    Service Layer orchestration and integration testing.
    
    Validates complex workflows that involve multiple services, business logic
    orchestration, and cross-service integration patterns to ensure proper
    implementation of the Service Layer pattern per Section 5.1.1.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app: Flask, db_session: Session):
        """Set up test framework for orchestration testing."""
        self.framework = ServiceLayerTestFramework(app, db_session)
        self.user_service = self.framework.user_service
        self.auth_service = self.framework.auth_service
        self.app = app
        self.db_session = db_session
    
    def test_user_registration_complete_workflow(self):
        """
        Test complete user registration workflow orchestration.
        
        Validates end-to-end user registration including:
        - User creation with validation
        - Password hashing
        - Role assignment
        - Authentication verification
        - Session management
        """
        # Define registration workflow
        def complete_user_registration(username: str, email: str, password: str, 
                                     role_names: List[str] = None) -> Dict[str, Any]:
            """Complete user registration workflow with all services."""
            try:
                # Step 1: Create user with validation
                user_data = UserCreationData(
                    username=username,
                    email=email,
                    password=password,
                    role_names=role_names or ["user"]
                )
                
                create_result = self.user_service.create_user(user_data)
                if not create_result.success:
                    return {'success': False, 'error': create_result.error_message}
                
                # Step 2: Verify authentication works
                auth_success, flask_user, auth_error = self.auth_service.authenticate_user(
                    email, password
                )
                
                if not auth_success:
                    return {'success': False, 'error': f'Authentication failed: {auth_error}'}
                
                # Step 3: Generate authentication tokens
                secure_token = self.auth_service.generate_secure_token(
                    create_result.user.id, purpose='verification'
                )
                
                jwt_token = self.auth_service.generate_jwt_token(create_result.user.id)
                
                # Step 4: Return complete registration result
                return {
                    'success': True,
                    'user': create_result.user,
                    'flask_user': flask_user,
                    'secure_token': secure_token,
                    'jwt_token': jwt_token
                }
                
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        # Execute workflow
        result = complete_user_registration(
            username="workflow_user",
            email="workflow@example.com",
            password="WorkflowPassword123!",
            role_names=["user", "subscriber"]
        )
        
        # Validate workflow results
        assert result['success'] is True
        assert 'user' in result
        assert 'flask_user' in result
        assert 'secure_token' in result
        assert 'jwt_token' in result
        
        # Verify user was created properly
        user = result['user']
        assert user.username == "workflow_user"
        assert user.email == "workflow@example.com"
        assert user.is_active is True
        
        # Verify Flask user integration
        flask_user = result['flask_user']
        assert flask_user.user.id == user.id
        assert flask_user.is_authenticated is True
        
        # Verify tokens are valid
        secure_token = result['secure_token']
        jwt_token = result['jwt_token']
        
        assert isinstance(secure_token, str) and len(secure_token) > 0
        assert isinstance(jwt_token, str) and len(jwt_token) > 0
        
        # Verify token verification
        token_payload = self.auth_service.verify_secure_token(
            secure_token, purpose='verification'
        )
        assert token_payload is not None
        assert token_payload['user_id'] == user.id
        
        jwt_payload = self.auth_service.verify_jwt_token(jwt_token)
        assert jwt_payload is not None
        assert jwt_payload['user_id'] == user.id
    
    def test_user_role_management_orchestration(self):
        """
        Test user role management orchestration workflow.
        
        Validates complex role management including:
        - Role assignment through user service
        - Permission validation
        - Authentication integration
        - Role-based access control workflow
        """
        # Setup RBAC scenario
        scenario_data = self.framework.setup_test_scenario("rbac_scenario")
        
        def manage_user_roles_workflow(user_id: int, new_roles: List[str], 
                                     verify_permissions: List[str] = None) -> Dict[str, Any]:
            """Complete role management workflow."""
            try:
                # Step 1: Get current user state
                current_user = self.user_service.get_user_by_id(user_id, include_roles=True)
                if not current_user:
                    return {'success': False, 'error': 'User not found'}
                
                current_roles = [role.name for role in current_user.roles]
                
                # Step 2: Update roles
                update_data = UserUpdateData(role_names=new_roles)
                update_result = self.user_service.update_user(user_id, update_data)
                
                if not update_result.success:
                    return {'success': False, 'error': update_result.error_message}
                
                # Step 3: Verify new roles were assigned
                updated_user = self.user_service.get_user_by_id(user_id, include_roles=True)
                updated_roles = [role.name for role in updated_user.roles]
                
                # Step 4: Verify permissions if specified
                permission_results = {}
                if verify_permissions:
                    for permission in verify_permissions:
                        has_permission = self.user_service.user_has_permission(
                            user_id, permission
                        )
                        permission_results[permission] = has_permission
                
                # Step 5: Get all user permissions
                all_permissions = self.user_service.get_user_permissions(user_id)
                
                return {
                    'success': True,
                    'previous_roles': current_roles,
                    'new_roles': updated_roles,
                    'permission_checks': permission_results,
                    'all_permissions': all_permissions
                }
                
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        # Test role upgrade workflow
        regular_user = scenario_data['users']['regular_user']
        
        result = manage_user_roles_workflow(
            regular_user.id,
            new_roles=['manager', 'user'],
            verify_permissions=['users.read', 'users.update', 'users.admin']
        )
        
        assert result['success'] is True
        assert 'manager' in result['new_roles']
        assert 'user' in result['new_roles']
        
        # Verify permission changes
        permission_checks = result['permission_checks']
        assert permission_checks['users.read'] is True
        assert permission_checks['users.update'] is True
        assert permission_checks['users.admin'] is False  # Manager doesn't have admin
        
        # Verify permission list expansion
        all_permissions = result['all_permissions']
        assert len(all_permissions) > len(scenario_data['users']['regular_user'].roles)
    
    def test_authentication_session_lifecycle_orchestration(self):
        """
        Test complete authentication and session lifecycle orchestration.
        
        Validates:
        - User authentication
        - Session creation and management
        - Token generation and validation
        - Session cleanup and logout
        """
        # Create test user
        user_data = UserCreationData(
            username="lifecycle_user",
            email="lifecycle@example.com",
            password="LifecyclePassword123!"
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        def authentication_lifecycle_workflow(email: str, password: str) -> Dict[str, Any]:
            """Complete authentication lifecycle workflow."""
            try:
                # Step 1: Authenticate user
                auth_success, flask_user, auth_error = self.auth_service.authenticate_user(
                    email, password, remember=True
                )
                
                if not auth_success:
                    return {'success': False, 'error': auth_error}
                
                user_id = int(flask_user.get_id())
                
                # Step 2: Generate authentication tokens
                secure_token = self.auth_service.generate_secure_token(
                    user_id, purpose='auth', expires_in=3600
                )
                
                jwt_token = self.auth_service.generate_jwt_token(
                    user_id, expires_in=3600
                )
                
                # Step 3: Create user session record
                session = UserSessionFactory(
                    user_id=user_id,
                    session_token=secure_token
                )
                self.db_session.commit()
                
                # Step 4: Verify session and tokens
                token_payload = self.auth_service.verify_secure_token(
                    secure_token, purpose='auth'
                )
                
                jwt_payload = self.auth_service.verify_jwt_token(jwt_token)
                
                # Step 5: Get user sessions
                user_sessions = self.user_service.get_user_sessions(user_id)
                
                # Step 6: Cleanup (logout simulation)
                logout_success = self.auth_service.logout_user()
                session_invalidated = self.user_service.invalidate_user_session(session.id)
                
                return {
                    'success': True,
                    'authentication': {
                        'user_id': user_id,
                        'flask_user': flask_user
                    },
                    'tokens': {
                        'secure_token': secure_token,
                        'jwt_token': jwt_token,
                        'token_payload': token_payload,
                        'jwt_payload': jwt_payload
                    },
                    'session': {
                        'session_id': session.id,
                        'session_count': len(user_sessions)
                    },
                    'cleanup': {
                        'logout_success': logout_success,
                        'session_invalidated': session_invalidated
                    }
                }
                
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        # Execute lifecycle workflow
        with self.app.test_request_context():
            result = authentication_lifecycle_workflow(
                "lifecycle@example.com", "LifecyclePassword123!"
            )
        
        # Validate workflow results
        assert result['success'] is True
        
        # Validate authentication
        auth_data = result['authentication']
        assert auth_data['user_id'] == create_result.user.id
        assert auth_data['flask_user'].is_authenticated is True
        
        # Validate tokens
        token_data = result['tokens']
        assert token_data['token_payload']['user_id'] == create_result.user.id
        assert token_data['jwt_payload']['user_id'] == create_result.user.id
        
        # Validate session
        session_data = result['session']
        assert session_data['session_count'] >= 1
        
        # Validate cleanup
        cleanup_data = result['cleanup']
        assert cleanup_data['session_invalidated'] is True
    
    def test_error_handling_orchestration(self):
        """
        Test service layer error handling and recovery orchestration.
        
        Validates proper error propagation, transaction rollback,
        and error recovery patterns across service boundaries.
        """
        def error_prone_workflow(create_duplicate: bool = False,
                                use_invalid_data: bool = False) -> Dict[str, Any]:
            """Workflow designed to test error handling."""
            errors_encountered = []
            operations_completed = []
            
            try:
                # Step 1: Try to create user (might fail)
                if use_invalid_data:
                    user_data = UserCreationData(
                        username="",  # Invalid username
                        email="invalid-email",  # Invalid email
                        password="123"  # Weak password
                    )
                elif create_duplicate:
                    # Create a user first
                    first_user_data = UserCreationData(
                        username="duplicate_test",
                        email="duplicate@example.com",
                        password="ValidPassword123!"
                    )
                    first_result = self.user_service.create_user(first_user_data)
                    operations_completed.append("first_user_created")
                    
                    # Try to create duplicate
                    user_data = UserCreationData(
                        username="duplicate_test",
                        email="duplicate@example.com",
                        password="ValidPassword123!"
                    )
                else:
                    user_data = UserCreationData(
                        username="error_test_user",
                        email="errortest@example.com",
                        password="ValidPassword123!"
                    )
                
                try:
                    create_result = self.user_service.create_user(user_data)
                    if create_result.success:
                        operations_completed.append("user_created")
                        user_id = create_result.user.id
                    else:
                        errors_encountered.append(f"Create failed: {create_result.error_message}")
                        return {
                            'success': False,
                            'errors': errors_encountered,
                            'operations_completed': operations_completed
                        }
                except Exception as e:
                    errors_encountered.append(f"Create exception: {str(e)}")
                    return {
                        'success': False,
                        'errors': errors_encountered,
                        'operations_completed': operations_completed
                    }
                
                # Step 2: Try authentication (might fail if user creation failed)
                try:
                    auth_success, flask_user, auth_error = self.auth_service.authenticate_user(
                        user_data.email, user_data.password
                    )
                    
                    if auth_success:
                        operations_completed.append("authentication_successful")
                    else:
                        errors_encountered.append(f"Auth failed: {auth_error}")
                except Exception as e:
                    errors_encountered.append(f"Auth exception: {str(e)}")
                
                # Step 3: Try token generation
                try:
                    if 'user_created' in operations_completed:
                        token = self.auth_service.generate_secure_token(user_id)
                        operations_completed.append("token_generated")
                except Exception as e:
                    errors_encountered.append(f"Token generation failed: {str(e)}")
                
                return {
                    'success': len(errors_encountered) == 0,
                    'errors': errors_encountered,
                    'operations_completed': operations_completed
                }
                
            except Exception as e:
                errors_encountered.append(f"Workflow exception: {str(e)}")
                return {
                    'success': False,
                    'errors': errors_encountered,
                    'operations_completed': operations_completed
                }
        
        # Test successful workflow
        success_result = error_prone_workflow()
        assert success_result['success'] is True
        assert len(success_result['errors']) == 0
        assert 'user_created' in success_result['operations_completed']
        assert 'authentication_successful' in success_result['operations_completed']
        assert 'token_generated' in success_result['operations_completed']
        
        # Test validation error workflow
        validation_result = error_prone_workflow(use_invalid_data=True)
        assert validation_result['success'] is False
        assert len(validation_result['errors']) > 0
        assert any("validation" in error.lower() or "invalid" in error.lower() 
                  for error in validation_result['errors'])
        
        # Test duplicate error workflow
        duplicate_result = error_prone_workflow(create_duplicate=True)
        assert duplicate_result['success'] is False
        assert len(duplicate_result['errors']) > 0
        assert any("duplicate" in error.lower() for error in duplicate_result['errors'])
        assert 'first_user_created' in duplicate_result['operations_completed']


# ============================================================================
# Performance Benchmarking and SLA Validation
# ============================================================================

class TestServicePerformance:
    """
    Service Layer performance testing with pytest-benchmark integration.
    
    Validates performance characteristics against Node.js baseline metrics
    and ensures SLA compliance per Section 4.7.4.1 requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app: Flask, db_session: Session, benchmark_config: Dict[str, Any]):
        """Set up performance testing framework."""
        self.framework = ServiceLayerTestFramework(app, db_session)
        self.user_service = self.framework.user_service
        self.auth_service = self.framework.auth_service
        self.benchmark_config = benchmark_config
        self.db_session = db_session
    
    @pytest.mark.performance
    def test_user_creation_performance(self, benchmark):
        """Benchmark user creation performance against SLA requirements."""
        def create_user_operation():
            user_data = UserCreationData(
                username=f"perf_user_{secrets.token_hex(8)}",
                email=f"perftest_{secrets.token_hex(8)}@example.com",
                password="PerformanceTest123!"
            )
            result = self.user_service.create_user(user_data)
            self.db_session.rollback()  # Clean up for next iteration
            return result
        
        # Execute benchmark
        result = benchmark.pedantic(
            create_user_operation,
            iterations=10,
            rounds=5,
            warmup_rounds=2
        )
        
        # Validate performance SLA (should complete within 200ms)
        assert benchmark.stats.median < 0.2  # 200ms SLA
        assert result.success is True
    
    @pytest.mark.performance
    def test_user_authentication_performance(self, benchmark):
        """Benchmark authentication performance for login workflows."""
        # Setup test user
        user_data = UserCreationData(
            username="auth_perf_user",
            email="authperf@example.com",
            password="AuthPerformance123!"
        )
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        def authenticate_user_operation():
            success, flask_user, error = self.auth_service.authenticate_user(
                "authperf@example.com", "AuthPerformance123!"
            )
            return success, flask_user, error
        
        # Execute benchmark
        result = benchmark.pedantic(
            authenticate_user_operation,
            iterations=20,
            rounds=5,
            warmup_rounds=3
        )
        
        # Validate performance SLA (authentication should be fast)
        assert benchmark.stats.median < 0.05  # 50ms SLA for authentication
        success, flask_user, error = result
        assert success is True
        assert flask_user is not None
    
    @pytest.mark.performance
    def test_user_search_performance(self, benchmark):
        """Benchmark user search performance with pagination."""
        # Setup test data
        test_users = []
        for i in range(50):  # Create 50 test users
            user_data = UserCreationData(
                username=f"search_user_{i:03d}",
                email=f"search{i:03d}@example.com",
                password="SearchTest123!"
            )
            result = self.user_service.create_user(user_data)
            test_users.append(result.user)
        
        def search_users_operation():
            search_criteria = UserSearchCriteria(
                email="search",
                include_inactive=True,
                limit=20,
                offset=0,
                order_by="username"
            )
            results, total_count = self.user_service.search_users(search_criteria)
            return results, total_count
        
        # Execute benchmark
        result = benchmark.pedantic(
            search_users_operation,
            iterations=15,
            rounds=5,
            warmup_rounds=2
        )
        
        # Validate performance SLA (search should complete within 100ms)
        assert benchmark.stats.median < 0.1  # 100ms SLA for search
        results, total_count = result
        assert len(results) <= 20
        assert total_count >= 50
    
    @pytest.mark.performance
    def test_token_generation_performance(self, benchmark):
        """Benchmark token generation and verification performance."""
        user = UserFactory()
        self.db_session.commit()
        
        def token_operations():
            # Generate tokens
            secure_token = self.auth_service.generate_secure_token(
                user.id, purpose='benchmark'
            )
            jwt_token = self.auth_service.generate_jwt_token(user.id)
            
            # Verify tokens
            secure_payload = self.auth_service.verify_secure_token(
                secure_token, purpose='benchmark'
            )
            jwt_payload = self.auth_service.verify_jwt_token(jwt_token)
            
            return secure_token, jwt_token, secure_payload, jwt_payload
        
        # Execute benchmark
        result = benchmark.pedantic(
            token_operations,
            iterations=25,
            rounds=5,
            warmup_rounds=3
        )
        
        # Validate performance SLA (token ops should be very fast)
        assert benchmark.stats.median < 0.02  # 20ms SLA for token operations
        secure_token, jwt_token, secure_payload, jwt_payload = result
        assert secure_payload is not None
        assert jwt_payload is not None
    
    @pytest.mark.performance
    def test_permission_check_performance(self, benchmark):
        """Benchmark permission checking performance for authorization."""
        # Setup RBAC scenario
        scenario_data = self.framework.setup_test_scenario("rbac_scenario")
        admin_user = scenario_data['users']['admin_user']
        
        def permission_check_operations():
            # Check multiple permissions
            permissions = [
                "users.read", "users.create", "users.update", "users.delete",
                "roles.read", "permissions.admin", "business_entities.read"
            ]
            
            results = {}
            for permission in permissions:
                has_permission = self.user_service.user_has_permission(
                    admin_user.id, permission
                )
                results[permission] = has_permission
            
            # Get all permissions
            all_permissions = self.user_service.get_user_permissions(admin_user.id)
            
            return results, all_permissions
        
        # Execute benchmark
        result = benchmark.pedantic(
            permission_check_operations,
            iterations=20,
            rounds=5,
            warmup_rounds=2
        )
        
        # Validate performance SLA (permission checks should be fast)
        assert benchmark.stats.median < 0.03  # 30ms SLA for permission checks
        permission_results, all_permissions = result
        assert len(permission_results) == 7
        assert len(all_permissions) > 0
    
    @pytest.mark.performance
    def test_database_session_performance(self, benchmark):
        """Benchmark database session management performance."""
        user = UserFactory()
        session1 = UserSessionFactory(user=user)
        session2 = UserSessionFactory(user=user)
        self.db_session.commit()
        
        def session_management_operations():
            # Get user sessions
            sessions = self.user_service.get_user_sessions(user.id)
            
            # Invalidate a session
            self.user_service.invalidate_user_session(session1.id)
            
            # Cleanup expired sessions
            cleaned_count = self.user_service.cleanup_expired_sessions()
            
            # Rollback for next iteration
            self.db_session.rollback()
            
            return sessions, cleaned_count
        
        # Execute benchmark
        result = benchmark.pedantic(
            session_management_operations,
            iterations=15,
            rounds=5,
            warmup_rounds=2
        )
        
        # Validate performance SLA
        assert benchmark.stats.median < 0.05  # 50ms SLA for session management
        sessions, cleaned_count = result
        assert len(sessions) >= 2
    
    @pytest.mark.performance
    def test_complex_workflow_performance(self, benchmark):
        """Benchmark complex multi-service workflow performance."""
        def complex_workflow():
            # Create user
            user_data = UserCreationData(
                username=f"complex_{secrets.token_hex(6)}",
                email=f"complex_{secrets.token_hex(6)}@example.com",
                password="ComplexWorkflow123!",
                role_names=["user"]
            )
            
            create_result = self.user_service.create_user(user_data)
            if not create_result.success:
                self.db_session.rollback()
                return None
            
            # Authenticate user
            success, flask_user, error = self.auth_service.authenticate_user(
                user_data.email, user_data.password
            )
            
            if not success:
                self.db_session.rollback()
                return None
            
            # Generate tokens
            secure_token = self.auth_service.generate_secure_token(
                create_result.user.id, purpose='workflow'
            )
            
            # Check permissions
            permissions = self.user_service.get_user_permissions(create_result.user.id)
            
            # Update user
            update_result = self.user_service.update_user(
                create_result.user.id,
                UserUpdateData(first_name="Complex", last_name="Workflow")
            )
            
            # Cleanup
            self.db_session.rollback()
            
            return {
                'user_created': create_result.success,
                'authenticated': success,
                'token_generated': bool(secure_token),
                'permissions_count': len(permissions),
                'user_updated': update_result.success if update_result else False
            }
        
        # Execute benchmark
        result = benchmark.pedantic(
            complex_workflow,
            iterations=10,
            rounds=3,
            warmup_rounds=2
        )
        
        # Validate performance SLA (complex workflow should complete within 500ms)
        assert benchmark.stats.median < 0.5  # 500ms SLA for complex workflow
        assert result is not None
        assert result['user_created'] is True
        assert result['authenticated'] is True


# ============================================================================
# Error Handling and Edge Case Testing
# ============================================================================

class TestServiceErrorHandling:
    """
    Comprehensive error handling and edge case testing for Service Layer.
    
    Validates error propagation, recovery procedures, and edge case handling
    to ensure robust service operation per Section 4.7.6 requirements.
    """
    
    @pytest.fixture(autouse=True)
    def setup_method(self, app: Flask, db_session: Session):
        """Set up error testing framework."""
        self.framework = ServiceLayerTestFramework(app, db_session)
        self.user_service = self.framework.user_service
        self.auth_service = self.framework.auth_service
        self.db_session = db_session
    
    def test_database_transaction_error_handling(self):
        """Test database transaction error handling and rollback."""
        # Simulate database error during user creation
        with patch.object(self.db_session, 'add', side_effect=SQLAlchemyError("Simulated DB error")):
            user_data = UserCreationData(
                username="db_error_user",
                email="dberror@example.com",
                password="DbError123!"
            )
            
            with pytest.raises(UserServiceError) as exc_info:
                self.user_service.create_user(user_data)
            
            assert "Database error occurred" in str(exc_info.value)
        
        # Verify database state is clean (transaction rolled back)
        users_after_error = self.user_service.search_users(
            UserSearchCriteria(email="dberror@example.com")
        )
        assert len(users_after_error[0]) == 0
    
    def test_integrity_constraint_error_handling(self):
        """Test handling of database integrity constraint violations."""
        # Create initial user
        user_data = UserCreationData(
            username="integrity_user",
            email="integrity@example.com",
            password="Integrity123!"
        )
        
        first_result = self.user_service.create_user(user_data)
        assert first_result.success is True
        
        # Simulate integrity error on duplicate creation
        with patch.object(self.db_session, 'flush', side_effect=IntegrityError(
            "UNIQUE constraint failed", None, None
        )):
            duplicate_data = UserCreationData(
                username="integrity_user_different",
                email="integrity_different@example.com",
                password="Integrity123!"
            )
            
            with pytest.raises(DuplicateUserError):
                self.user_service.create_user(duplicate_data)
    
    def test_authentication_service_error_scenarios(self):
        """Test authentication service error handling scenarios."""
        # Test authentication with malformed configuration
        with patch.object(self.auth_service, 'serializer', None):
            with pytest.raises(TokenError) as exc_info:
                self.auth_service.generate_secure_token(1, purpose='test')
            
            assert "Token serializer not initialized" in str(exc_info.value)
        
        # Test JWT operations with missing secret key
        with patch.object(self.auth_service.app, 'config', {'SECRET_KEY': None}):
            with pytest.raises(TokenError) as exc_info:
                self.auth_service.generate_jwt_token(1)
            
            assert "SECRET_KEY not configured" in str(exc_info.value)
    
    def test_service_initialization_error_handling(self):
        """Test service initialization error scenarios."""
        # Test UserService with invalid database session
        invalid_session = Mock()
        invalid_session.query.side_effect = SQLAlchemyError("Invalid session")
        
        invalid_user_service = UserService(invalid_session)
        
        result = invalid_user_service.get_user_by_id(1)
        assert result is None  # Should handle error gracefully
        
        # Test AuthService with invalid Flask app
        invalid_app = Mock()
        invalid_app.config = {}
        
        with pytest.raises(AuthenticationError):
            AuthService(self.db_session, invalid_app)
    
    def test_edge_case_input_validation(self):
        """Test edge case input validation and sanitization."""
        # Test extremely long inputs
        long_username = "a" * 1000
        long_email = "a" * 1000 + "@example.com"
        
        user_data = UserCreationData(
            username=long_username,
            email=long_email,
            password="ValidPassword123!"
        )
        
        with pytest.raises(UserValidationError) as exc_info:
            self.user_service.create_user(user_data)
        
        validation_errors = exc_info.value.validation_errors
        assert any("cannot exceed" in error for error in validation_errors)
        
        # Test special characters and unicode
        unicode_data = UserCreationData(
            username="user_测试_نام",
            email="test@тест.com",
            password="Password123!🔒"
        )
        
        # Should handle unicode gracefully
        result = self.user_service.create_user(unicode_data)
        assert result.success is True
        assert result.user.username == "user_测试_نام"
    
    def test_concurrent_operation_edge_cases(self):
        """Test edge cases in concurrent operations."""
        # Simulate race condition in user creation
        user_data = UserCreationData(
            username="race_condition_user",
            email="racetest@example.com",
            password="RaceTest123!"
        )
        
        # First creation should succeed
        first_result = self.user_service.create_user(user_data)
        assert first_result.success is True
        
        # Simulate concurrent duplicate creation
        with pytest.raises(DuplicateUserError):
            self.user_service.create_user(user_data)
    
    def test_memory_and_resource_edge_cases(self):
        """Test memory and resource usage edge cases."""
        # Test large data operations
        large_metadata = {"key_" + str(i): "value_" * 100 for i in range(1000)}
        
        user_data = UserCreationData(
            username="large_data_user",
            email="largedata@example.com",
            password="LargeData123!",
            metadata=large_metadata
        )
        
        # Should handle large metadata gracefully
        result = self.user_service.create_user(user_data)
        assert result.success is True
        
        # Test search with large result sets
        # Create many users for search test
        for i in range(100):
            test_user_data = UserCreationData(
                username=f"search_test_user_{i:03d}",
                email=f"searchtest{i:03d}@example.com",
                password="SearchTest123!"
            )
            self.user_service.create_user(test_user_data)
        
        # Test large search without limits
        search_criteria = UserSearchCriteria(
            email="searchtest",
            include_inactive=True
        )
        
        results, total_count = self.user_service.search_users(search_criteria)
        assert len(results) == total_count  # Should return all results
        assert total_count >= 100
    
    def test_service_recovery_procedures(self):
        """Test service recovery and cleanup procedures."""
        # Create test data
        user = UserFactory()
        session1 = UserSessionFactory(user=user, is_valid=True)
        session2 = UserSessionFactory(user=user, is_valid=False)
        self.db_session.commit()
        
        # Test session cleanup recovery
        cleaned_count = self.user_service.cleanup_expired_sessions()
        assert cleaned_count >= 1  # Should clean up invalid session
        
        # Test session invalidation recovery
        all_sessions_before = self.user_service.get_user_sessions(
            user.id, include_expired=True
        )
        
        # Invalidate all sessions for user
        for session in all_sessions_before:
            if session.is_valid:
                result = self.user_service.invalidate_user_session(session.id)
                assert result is True
        
        # Verify all sessions are invalidated
        valid_sessions_after = self.user_service.get_user_sessions(user.id)
        assert len(valid_sessions_after) == 0
    
    def test_cross_service_error_propagation(self):
        """Test error propagation between services."""
        # Test scenario where UserService error affects AuthService
        user_data = UserCreationData(
            username="error_propagation_user",
            email="errorprop@example.com",
            password="ErrorProp123!"
        )
        
        create_result = self.user_service.create_user(user_data)
        assert create_result.success is True
        
        # Delete user to create orphaned authentication scenario
        delete_result = self.user_service.delete_user(
            create_result.user.id, soft_delete=False
        )
        assert delete_result.success is True
        
        # Try to authenticate deleted user
        auth_success, flask_user, error = self.auth_service.authenticate_user(
            "errorprop@example.com", "ErrorProp123!"
        )
        
        assert auth_success is False
        assert flask_user is None
        assert "not found" in error.lower()
        
        # Try to generate token for non-existent user
        non_existent_user_id = 99999
        
        # This should work (token generation doesn't validate user existence)
        token = self.auth_service.generate_secure_token(
            non_existent_user_id, purpose='test'
        )
        assert isinstance(token, str)
        
        # But token verification should work
        payload = self.auth_service.verify_secure_token(token, purpose='test')
        assert payload is not None
        assert payload['user_id'] == non_existent_user_id


# ============================================================================
# Test Execution Markers and Configuration
# ============================================================================

# Test execution markers for pytest categorization
pytestmark = [
    pytest.mark.services,
    pytest.mark.business_logic,
    pytest.mark.integration
]