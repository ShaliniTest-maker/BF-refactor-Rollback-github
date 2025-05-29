"""
Comprehensive Unit Tests for Service Layer Business Logic Components

This module provides complete unit test coverage for all Service Layer business logic
components including UserService, BusinessEntityService, ValidationService, and
WorkflowOrchestrator. These tests validate business rule preservation, workflow
orchestration, transaction boundary management, and service composition patterns to
ensure 100% functional equivalence with original Node.js business logic during the
Flask migration.

Test Coverage:
- UserService: User management workflows, authentication, registration, profile management
- BusinessEntityService: Entity creation, relationship management, lifecycle operations
- ValidationService: Data validation, business rule enforcement, constraint checking
- WorkflowOrchestrator: Service composition patterns, workflow orchestration
- BaseService: Transaction boundary management, retry mechanisms, error handling

Technical Requirements:
- pytest-flask 1.3.0 service layer testing integration per Section 4.7.1
- 90% code coverage requirement for service layer per Feature F-006
- Business workflow orchestration validation per Section 5.2.3 component details
- Transaction boundary management testing per Section 4.5.2
- Service composition and dependency injection testing per Section 4.5.1
- Business rule enforcement validation per Section 4.12.1 validation checkpoints

Architecture Integration:
- Flask application context fixtures for isolated testing environments
- Database transaction rollback capabilities for clean test state management
- Mock object integration for external dependency testing
- Service Layer pattern validation for workflow orchestration
- Dependency injection testing with Flask-Injector integration
"""

import pytest
import uuid
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import Mock, MagicMock, patch, call
from typing import Dict, Any, List, Optional

# Flask and Flask extensions
from flask import Flask, g, current_app, request_started, request_finished
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import BadRequest, InternalServerError
from injector import Injector

# SQLAlchemy exceptions for testing error handling
from sqlalchemy.exc import (
    IntegrityError, 
    SQLAlchemyError, 
    OperationalError, 
    DatabaseError
)

# Import services to test
from src.services.base import (
    BaseService, 
    ServiceError, 
    ValidationError, 
    TransactionError, 
    ConcurrencyError,
    retry_on_failure,
    require_app_context
)
from src.services.user_service import (
    UserService, 
    UserRegistrationError, 
    UserAuthenticationError, 
    UserProfileError, 
    UserSessionError
)
from src.services.business_entity_service import (
    BusinessEntityService,
    EntityCreationError,
    EntityRelationshipError,
    EntityLifecycleError
)
from src.services.validation_service import (
    ValidationService,
    ValidationResult,
    ValidationSeverity,
    ValidationType
)
from src.services.workflow_orchestrator import (
    WorkflowOrchestrator,
    WorkflowExecutionError,
    ServiceCompositionError,
    WorkflowStepError
)

# Import models for testing
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.models.base import BaseModel


class TestBaseService:
    """
    Unit tests for BaseService abstract class validating Service Layer pattern
    implementation, transaction boundary management, and service composition.
    
    Tests the foundational service layer architecture as specified in Section 5.2.3
    with comprehensive validation of transaction management, error handling, retry
    mechanisms, and Flask application context integration.
    """
    
    @pytest.fixture
    def mock_service(self, app, db):
        """
        Create a concrete implementation of BaseService for testing.
        
        Args:
            app: Flask application fixture
            db: SQLAlchemy database fixture
        
        Returns:
            ConcreteTestService: Test implementation of BaseService
        """
        class ConcreteTestService(BaseService):
            def validate_business_rules(self, data: Dict[str, Any]) -> bool:
                """Test implementation of abstract business rule validation."""
                return True
        
        with app.app_context():
            service = ConcreteTestService(db=db)
            return service
    
    def test_base_service_initialization(self, mock_service, app, db):
        """
        Test BaseService initialization with Flask-SQLAlchemy integration.
        
        Validates service initialization requirements per Section 5.2.3 including
        database session access, logging configuration, and Flask application
        context integration.
        """
        # Test service initialization
        assert mock_service.db == db
        assert hasattr(mock_service, 'session')
        assert hasattr(mock_service, 'logger')
        assert hasattr(mock_service, '_session_cache')
        assert hasattr(mock_service, '_composition_services')
        
        # Test session property access
        assert mock_service.session == db.session
        
        # Test logger configuration
        assert mock_service.logger.name == mock_service.__class__.__module__
    
    def test_transaction_boundary_success(self, mock_service, app, db):
        """
        Test successful transaction boundary management.
        
        Validates transaction boundary control as specified in Section 4.5.2
        with proper commit behavior and session management.
        """
        with app.app_context():
            # Create test data within transaction boundary
            with mock_service.transaction_boundary() as session:
                user = User(
                    username='test_user',
                    email='test@example.com',
                    password='TestPassword123!'
                )
                session.add(user)
                # Transaction should commit automatically
            
            # Verify data was committed
            saved_user = User.query.filter_by(username='test_user').first()
            assert saved_user is not None
            assert saved_user.email == 'test@example.com'
    
    def test_transaction_boundary_rollback(self, mock_service, app, db):
        """
        Test transaction boundary rollback on exception.
        
        Validates automatic rollback behavior when exceptions occur within
        transaction boundaries as specified in Section 4.5.2.
        """
        with app.app_context():
            with pytest.raises(TransactionError):
                with mock_service.transaction_boundary() as session:
                    user = User(
                        username='rollback_user',
                        email='rollback@example.com',
                        password='TestPassword123!'
                    )
                    session.add(user)
                    # Force an exception to trigger rollback
                    raise Exception("Test exception for rollback")
            
            # Verify data was not committed
            rollback_user = User.query.filter_by(username='rollback_user').first()
            assert rollback_user is None
    
    def test_nested_transaction_boundary(self, mock_service, app, db):
        """
        Test nested transaction boundary with savepoint management.
        
        Validates nested transaction support with savepoint creation and
        rollback capabilities for complex business operations.
        """
        with app.app_context():
            with mock_service.transaction_boundary() as outer_session:
                # Create outer transaction data
                user1 = User(
                    username='outer_user',
                    email='outer@example.com',
                    password='TestPassword123!'
                )
                outer_session.add(user1)
                
                # Test nested transaction with rollback
                with pytest.raises(TransactionError):
                    with mock_service.transaction_boundary(nested=True) as inner_session:
                        user2 = User(
                            username='inner_user',
                            email='inner@example.com',
                            password='TestPassword123!'
                        )
                        inner_session.add(user2)
                        # Force rollback of nested transaction only
                        raise Exception("Nested transaction rollback")
                
                # Outer transaction should still be valid
                outer_session.flush()
            
            # Verify outer transaction committed, inner rolled back
            outer_user = User.query.filter_by(username='outer_user').first()
            inner_user = User.query.filter_by(username='inner_user').first()
            assert outer_user is not None
            assert inner_user is None
    
    def test_retry_mechanism_success(self, mock_service, app):
        """
        Test retry mechanism with successful operation.
        
        Validates retry decorator behavior with successful operations
        as specified in Section 4.5.3 for resilient operation support.
        """
        call_count = 0
        
        def successful_operation():
            nonlocal call_count
            call_count += 1
            return "success"
        
        with app.app_context():
            result = mock_service.execute_with_retry(successful_operation, "test operation")
            
            assert result == "success"
            assert call_count == 1
    
    def test_retry_mechanism_with_failures(self, mock_service, app):
        """
        Test retry mechanism with multiple failures before success.
        
        Validates retry logic with exponential backoff and eventual success
        for operations that fail initially but succeed on retry.
        """
        call_count = 0
        
        def failing_then_success_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OperationalError("Temporary failure", None, None)
            return "eventual_success"
        
        with app.app_context():
            with patch('time.sleep'):  # Mock sleep to speed up test
                result = mock_service.execute_with_retry(
                    failing_then_success_operation,
                    "retry test operation"
                )
                
                assert result == "eventual_success"
                assert call_count == 3
    
    def test_retry_mechanism_max_retries_exceeded(self, mock_service, app):
        """
        Test retry mechanism when max retries are exceeded.
        
        Validates that ServiceError is raised when operations continue
        to fail beyond the maximum retry limit.
        """
        call_count = 0
        
        def always_failing_operation():
            nonlocal call_count
            call_count += 1
            raise OperationalError("Persistent failure", None, None)
        
        with app.app_context():
            with patch('time.sleep'):  # Mock sleep to speed up test
                with pytest.raises(ServiceError) as exc_info:
                    mock_service.execute_with_retry(
                        always_failing_operation,
                        "max retries test"
                    )
                
                assert "Operation failed after" in str(exc_info.value)
                assert exc_info.value.retry_count == 3
                assert call_count == 4  # Initial attempt + 3 retries
    
    def test_input_validation_success(self, mock_service, app):
        """
        Test successful input validation with required fields.
        
        Validates input validation functionality with proper data sanitization
        and required field checking.
        """
        with app.app_context():
            input_data = {
                'username': 'test_user',
                'email': 'test@example.com',
                'password': 'TestPassword123!',
                'optional_field': 'optional_value',
                'empty_field': '',
                'none_field': None
            }
            
            required_fields = ['username', 'email', 'password']
            validated_data = mock_service.validate_input(input_data, required_fields)
            
            # Check required fields preserved
            assert validated_data['username'] == 'test_user'
            assert validated_data['email'] == 'test@example.com'
            assert validated_data['password'] == 'TestPassword123!'
            
            # Check optional field preserved
            assert validated_data['optional_field'] == 'optional_value'
            
            # Check empty and None fields removed
            assert 'empty_field' not in validated_data
            assert 'none_field' not in validated_data
    
    def test_input_validation_missing_required_fields(self, mock_service, app):
        """
        Test input validation with missing required fields.
        
        Validates that ValidationError is raised when required fields
        are missing from input data.
        """
        with app.app_context():
            input_data = {
                'username': 'test_user',
                # Missing email and password
            }
            
            required_fields = ['username', 'email', 'password']
            
            with pytest.raises(ValidationError) as exc_info:
                mock_service.validate_input(input_data, required_fields)
            
            assert "Required fields missing" in str(exc_info.value)
            assert "email" in str(exc_info.value)
            assert "password" in str(exc_info.value)
    
    def test_service_composition(self, mock_service, app):
        """
        Test service composition functionality for complex workflows.
        
        Validates service composition patterns as specified in Section 5.2.3
        enabling coordination of multiple services for complex business operations.
        """
        with app.app_context():
            # Mock another service for composition
            class MockComposedService(BaseService):
                def validate_business_rules(self, data: Dict[str, Any]) -> bool:
                    return True
                
                def composed_operation(self):
                    return "composed_result"
            
            # Register the service with the injector
            injector = current_app.injector
            injector.binder.bind(MockComposedService, MockComposedService(db=mock_service.db))
            
            # Test service composition
            composed_service = mock_service.compose_service(MockComposedService)
            
            assert isinstance(composed_service, MockComposedService)
            assert composed_service.composed_operation() == "composed_result"
            
            # Test caching of composed service
            composed_service_2 = mock_service.compose_service(MockComposedService)
            assert composed_service is composed_service_2
    
    def test_integrity_error_handling(self, mock_service, app):
        """
        Test database integrity error handling with proper error translation.
        
        Validates that database integrity constraints are properly translated
        to ValidationError exceptions with meaningful messages.
        """
        with app.app_context():
            # Test unique constraint violation
            unique_error = IntegrityError(
                "duplicate key value violates unique constraint",
                "DETAIL: Key (username)=(test_user) already exists.",
                "23505"
            )
            
            with pytest.raises(ValidationError) as exc_info:
                mock_service.handle_integrity_error(unique_error, "user creation")
            
            assert "Duplicate value" in str(exc_info.value)
            
            # Test foreign key constraint violation
            fk_error = IntegrityError(
                "insert or update on table violates foreign key constraint",
                "DETAIL: Key (user_id)=(999) is not present in table users.",
                "23503"
            )
            
            with pytest.raises(ValidationError) as exc_info:
                mock_service.handle_integrity_error(fk_error, "entity creation")
            
            assert "Referenced entity does not exist" in str(exc_info.value)
            
            # Test not null constraint violation
            null_error = IntegrityError(
                "null value in column violates not-null constraint",
                "DETAIL: Failing row contains (null).",
                "23502"
            )
            
            with pytest.raises(ValidationError) as exc_info:
                mock_service.handle_integrity_error(null_error, "data insertion")
            
            assert "Required field" in str(exc_info.value)
    
    def test_caching_functionality(self, mock_service, app):
        """
        Test service-level caching for performance optimization.
        
        Validates caching functionality with TTL support and cache invalidation
        for improved service performance.
        """
        with app.app_context():
            # Test cache storage and retrieval
            cache_key = "test_key"
            cache_value = {"data": "test_value", "timestamp": time.time()}
            
            mock_service.cache_result(cache_key, cache_value, ttl=60)
            retrieved_value = mock_service.get_cached_result(cache_key)
            
            assert retrieved_value == cache_value
            
            # Test cache expiration
            mock_service.cache_result("expired_key", "expired_value", ttl=0)
            time.sleep(0.1)  # Wait for expiration
            expired_value = mock_service.get_cached_result("expired_key")
            
            assert expired_value is None
            
            # Test cache clearing
            mock_service.clear_cache()
            cleared_value = mock_service.get_cached_result(cache_key)
            
            assert cleared_value is None
    
    def test_current_user_context(self, mock_service, app):
        """
        Test current user context access for authentication integration.
        
        Validates Flask-Login integration and user context management
        within service operations.
        """
        with app.app_context():
            # Test without user context
            user_id = mock_service.get_current_user_id()
            assert user_id is None
            
            # Test with user context in Flask g
            g.user_id = 123
            user_id = mock_service.get_current_user_id()
            assert user_id == 123
            
            # Test with current_user object
            mock_user = Mock()
            mock_user.id = 456
            g.current_user = mock_user
            
            user_id = mock_service.get_current_user_id()
            assert user_id == 456
    
    def test_logging_functionality(self, mock_service, app):
        """
        Test service operation logging with data sanitization.
        
        Validates consistent logging across service operations with
        sensitive data filtering for security compliance.
        """
        with app.app_context():
            with patch.object(mock_service.logger, 'info') as mock_logger:
                # Test logging without sensitive data
                operation_data = {
                    'username': 'test_user',
                    'email': 'test@example.com',
                    'action': 'user_creation'
                }
                
                mock_service.log_service_operation(
                    "User registration",
                    operation_data,
                    level="info"
                )
                
                mock_logger.assert_called_once()
                log_call = mock_logger.call_args[0][0]
                assert "User registration" in log_call
                assert "test_user" in log_call
                
                # Test logging with sensitive data filtering
                mock_logger.reset_mock()
                sensitive_data = {
                    'username': 'test_user',
                    'password': 'secret_password',
                    'token': 'secret_token',
                    'api_key': 'secret_key'
                }
                
                mock_service.log_service_operation(
                    "Authentication attempt",
                    sensitive_data,
                    level="warning"
                )
                
                log_call = mock_logger.call_args[0][0]
                assert "password" not in log_call
                assert "token" not in log_call
                assert "api_key" not in log_call
                assert "test_user" in log_call


class TestUserService:
    """
    Unit tests for UserService business logic preservation and functionality.
    
    Tests comprehensive user management workflows including registration,
    authentication, profile management, and user entity operations to ensure
    100% functional equivalence with original Node.js business logic as
    specified in Feature F-005 and F-006.
    """
    
    @pytest.fixture
    def user_service(self, app, db):
        """
        Create UserService instance for testing.
        
        Args:
            app: Flask application fixture
            db: SQLAlchemy database fixture
        
        Returns:
            UserService: Configured user service instance
        """
        with app.app_context():
            return UserService(db=db)
    
    @pytest.fixture
    def valid_user_data(self):
        """
        Provide valid user registration data for testing.
        
        Returns:
            Dict[str, Any]: Valid user data meeting all business rules
        """
        return {
            'username': 'test_user_001',
            'email': 'testuser001@example.com',
            'password': 'TestPassword123!',
            'is_active': True
        }
    
    @pytest.fixture
    def mock_validation_service(self):
        """
        Create mock ValidationService for testing service composition.
        
        Returns:
            Mock: Mocked validation service with configured responses
        """
        mock_service = Mock()
        mock_service.validate_user_data.return_value = ValidationResult(is_valid=True)
        mock_service.validate_business_rules.return_value = True
        return mock_service
    
    def test_user_service_initialization(self, user_service, app):
        """
        Test UserService initialization with proper configuration.
        
        Validates service initialization per Section 5.2.3 including
        password policy configuration, session settings, and validation
        service composition.
        """
        with app.app_context():
            # Test base service initialization
            assert hasattr(user_service, 'db')
            assert hasattr(user_service, 'session')
            assert hasattr(user_service, 'logger')
            
            # Test user-specific configuration
            assert hasattr(user_service, '_password_policy')
            assert hasattr(user_service, '_default_session_hours')
            assert hasattr(user_service, '_remember_me_hours')
            
            # Test password policy configuration
            policy = user_service._password_policy
            assert policy['min_length'] == 8
            assert policy['require_uppercase'] is True
            assert policy['require_lowercase'] is True
            assert policy['require_digit'] is True
            assert policy['require_special'] is True
            assert policy['max_length'] == 128
            
            # Test session configuration
            assert user_service._default_session_hours == 24
            assert user_service._remember_me_hours == 168
    
    def test_user_business_rules_validation_success(self, user_service, app, valid_user_data):
        """
        Test successful user business rules validation.
        
        Validates business rule implementation per Section 4.12.1 including
        username validation, email format checking, and password policy
        enforcement.
        """
        with app.app_context():
            # Test complete user data validation
            result = user_service.validate_business_rules(valid_user_data)
            assert result is True
            
            # Test individual field validation
            username_data = {'username': 'valid_user123'}
            assert user_service.validate_business_rules(username_data) is True
            
            email_data = {'email': 'valid@example.com'}
            assert user_service.validate_business_rules(email_data) is True
            
            password_data = {'password': 'ValidPassword123!'}
            assert user_service.validate_business_rules(password_data) is True
    
    def test_user_business_rules_validation_failures(self, user_service, app):
        """
        Test user business rules validation failures.
        
        Validates proper error handling for invalid user data that violates
        business rules and security policies.
        """
        with app.app_context():
            # Test invalid username
            with pytest.raises(ValidationError) as exc_info:
                user_service.validate_business_rules({'username': 'a'})  # Too short
            assert "Username does not meet business requirements" in str(exc_info.value)
            
            with pytest.raises(ValidationError):
                user_service.validate_business_rules({'username': 'invalid@username'})  # Invalid chars
            
            # Test invalid email
            with pytest.raises(ValidationError) as exc_info:
                user_service.validate_business_rules({'email': 'invalid_email'})
            assert "Email format does not meet business requirements" in str(exc_info.value)
            
            with pytest.raises(ValidationError):
                user_service.validate_business_rules({'email': 'test@'})  # Incomplete email
            
            # Test invalid password
            with pytest.raises(ValidationError) as exc_info:
                user_service.validate_business_rules({'password': 'weak'})
            assert "Password does not meet security policy requirements" in str(exc_info.value)
            
            with pytest.raises(ValidationError):
                user_service.validate_business_rules({'password': 'NoDigits!'})  # Missing digit
            
            with pytest.raises(ValidationError):
                user_service.validate_business_rules({'password': 'noupper123!'})  # Missing uppercase
            
            with pytest.raises(ValidationError):
                user_service.validate_business_rules({'password': 'NOLOWER123!'})  # Missing lowercase
            
            with pytest.raises(ValidationError):
                user_service.validate_business_rules({'password': 'NoSpecial123'})  # Missing special char
    
    def test_username_validation_rules(self, user_service, app):
        """
        Test specific username validation rules implementation.
        
        Validates username business rules including length requirements,
        character restrictions, and format validation.
        """
        with app.app_context():
            # Test valid usernames
            assert user_service._validate_username('user123') is True
            assert user_service._validate_username('test_user') is True
            assert user_service._validate_username('user-name') is True
            assert user_service._validate_username('a' * 80) is True  # Max length
            
            # Test invalid usernames
            assert user_service._validate_username('ab') is False  # Too short
            assert user_service._validate_username('a' * 81) is False  # Too long
            assert user_service._validate_username('user@name') is False  # Invalid char
            assert user_service._validate_username('user name') is False  # Space
            assert user_service._validate_username('_username') is False  # Start with underscore
            assert user_service._validate_username('-username') is False  # Start with hyphen
            assert user_service._validate_username('') is False  # Empty
            assert user_service._validate_username(None) is False  # None
            assert user_service._validate_username(123) is False  # Non-string
    
    def test_email_validation_rules(self, user_service, app):
        """
        Test specific email validation rules implementation.
        
        Validates email format business rules including basic format checking,
        length requirements, and domain validation.
        """
        with app.app_context():
            # Test valid emails
            assert user_service._validate_email_format('test@example.com') is True
            assert user_service._validate_email_format('user.name@domain.co.uk') is True
            assert user_service._validate_email_format('user+tag@example.org') is True
            assert user_service._validate_email_format('a@b.co') is True  # Min valid
            
            # Test invalid emails
            assert user_service._validate_email_format('') is False  # Empty
            assert user_service._validate_email_format('invalid') is False  # No @
            assert user_service._validate_email_format('@example.com') is False  # No local part
            assert user_service._validate_email_format('test@') is False  # No domain
            assert user_service._validate_email_format('test@domain') is False  # No TLD
            assert user_service._validate_email_format('test..test@domain.com') is False  # Double dot
            assert user_service._validate_email_format('a@b.c') is False  # TLD too short
            assert user_service._validate_email_format('a' * 115 + '@example.com') is False  # Too long
            assert user_service._validate_email_format(None) is False  # None
            assert user_service._validate_email_format(123) is False  # Non-string
    
    def test_password_policy_validation(self, user_service, app):
        """
        Test comprehensive password policy validation.
        
        Validates password security policy enforcement including length,
        character requirements, and complexity rules.
        """
        with app.app_context():
            # Test valid passwords
            assert user_service._validate_password_policy('TestPass123!') is True
            assert user_service._validate_password_policy('Abc123@#$') is True
            assert user_service._validate_password_policy('P@ssw0rd') is True  # Min length
            assert user_service._validate_password_policy('A' * 126 + '1!') is True  # Max length
            
            # Test length violations
            assert user_service._validate_password_policy('Short1!') is False  # Too short
            assert user_service._validate_password_policy('A' * 127 + '1!') is False  # Too long
            
            # Test character requirement violations
            assert user_service._validate_password_policy('testpass123!') is False  # No uppercase
            assert user_service._validate_password_policy('TESTPASS123!') is False  # No lowercase
            assert user_service._validate_password_policy('TestPass!') is False  # No digit
            assert user_service._validate_password_policy('TestPass123') is False  # No special
            
            # Test edge cases
            assert user_service._validate_password_policy('') is False  # Empty
            assert user_service._validate_password_policy(None) is False  # None
            assert user_service._validate_password_policy(123) is False  # Non-string
    
    def test_user_registration_success(self, user_service, app, db, valid_user_data):
        """
        Test successful user registration workflow.
        
        Validates complete user registration process including validation,
        database persistence, and proper user instance creation as specified
        in Feature F-005 business logic preservation.
        """
        with app.app_context():
            # Test basic user registration
            user = user_service.register_user(valid_user_data)
            
            # Verify user instance
            assert isinstance(user, User)
            assert user.id is not None
            assert user.username == valid_user_data['username'].lower()
            assert user.email == valid_user_data['email'].lower()
            assert user.is_active == valid_user_data['is_active']
            
            # Verify password hashing
            assert user.password_hash != valid_user_data['password']
            assert check_password_hash(user.password_hash, valid_user_data['password'])
            
            # Verify database persistence
            saved_user = User.query.filter_by(username=user.username).first()
            assert saved_user is not None
            assert saved_user.id == user.id
    
    def test_user_registration_with_auto_login(self, user_service, app, db, valid_user_data):
        """
        Test user registration with automatic login functionality.
        
        Validates user registration with auto-login feature including session
        creation and Flask-Login integration.
        """
        with app.app_context():
            # Mock request context for session creation
            request_context = {
                'user_agent': 'Mozilla/5.0 Test Browser',
                'ip_address': '192.168.1.1'
            }
            
            with patch('flask_login.login_user') as mock_login:
                user = user_service.register_user(
                    valid_user_data,
                    auto_login=True,
                    request_context=request_context
                )
                
                # Verify auto-login was called
                mock_login.assert_called_once_with(user)
                
                # Verify user creation
                assert user is not None
                assert user.username == valid_user_data['username'].lower()
    
    def test_user_registration_duplicate_username(self, user_service, app, db, valid_user_data):
        """
        Test user registration with duplicate username handling.
        
        Validates proper error handling when attempting to register a user
        with an existing username, ensuring database constraint enforcement.
        """
        with app.app_context():
            # Create first user
            user1 = user_service.register_user(valid_user_data)
            assert user1 is not None
            
            # Attempt to create second user with same username
            duplicate_data = valid_user_data.copy()
            duplicate_data['email'] = 'different@example.com'
            
            with pytest.raises(UserRegistrationError) as exc_info:
                user_service.register_user(duplicate_data)
            
            assert "User already exists" in str(exc_info.value)
    
    def test_user_registration_duplicate_email(self, user_service, app, db, valid_user_data):
        """
        Test user registration with duplicate email handling.
        
        Validates proper error handling when attempting to register a user
        with an existing email address.
        """
        with app.app_context():
            # Create first user
            user1 = user_service.register_user(valid_user_data)
            assert user1 is not None
            
            # Attempt to create second user with same email
            duplicate_data = valid_user_data.copy()
            duplicate_data['username'] = 'different_user'
            
            with pytest.raises(UserRegistrationError) as exc_info:
                user_service.register_user(duplicate_data)
            
            assert "User already exists" in str(exc_info.value)
    
    def test_user_registration_validation_error(self, user_service, app, db):
        """
        Test user registration with validation errors.
        
        Validates proper error handling when registration data fails
        business rule validation.
        """
        with app.app_context():
            # Test missing required fields
            invalid_data = {'username': 'test_user'}  # Missing email and password
            
            with pytest.raises(ValidationError) as exc_info:
                user_service.register_user(invalid_data)
            
            assert "Required fields missing" in str(exc_info.value)
            
            # Test invalid business rules
            invalid_data = {
                'username': 'a',  # Too short
                'email': 'invalid_email',  # Invalid format
                'password': 'weak'  # Weak password
            }
            
            with pytest.raises(ValidationError):
                user_service.register_user(invalid_data)
    
    def test_user_authentication_success(self, user_service, app, db, valid_user_data):
        """
        Test successful user authentication workflow.
        
        Validates user authentication process including credential verification,
        session creation, and Flask-Login integration as specified in Feature F-007.
        """
        with app.app_context():
            # Create user for authentication testing
            user = user_service.register_user(valid_user_data)
            
            # Test authentication with username
            authenticated_user = user_service.authenticate_user(
                valid_user_data['username'],
                valid_user_data['password']
            )
            
            assert authenticated_user is not None
            assert authenticated_user.id == user.id
            assert authenticated_user.username == user.username
            
            # Test authentication with email
            authenticated_user_email = user_service.authenticate_user(
                valid_user_data['email'],
                valid_user_data['password']
            )
            
            assert authenticated_user_email is not None
            assert authenticated_user_email.id == user.id
    
    def test_user_authentication_invalid_credentials(self, user_service, app, db, valid_user_data):
        """
        Test user authentication with invalid credentials.
        
        Validates proper handling of authentication failures including
        invalid usernames, passwords, and non-existent users.
        """
        with app.app_context():
            # Create user for testing
            user = user_service.register_user(valid_user_data)
            
            # Test invalid password
            result = user_service.authenticate_user(
                valid_user_data['username'],
                'wrong_password'
            )
            assert result is None
            
            # Test non-existent user
            result = user_service.authenticate_user(
                'non_existent_user',
                valid_user_data['password']
            )
            assert result is None
            
            # Test invalid email
            result = user_service.authenticate_user(
                'nonexistent@example.com',
                valid_user_data['password']
            )
            assert result is None
    
    def test_user_authentication_with_remember_me(self, user_service, app, db, valid_user_data):
        """
        Test user authentication with remember-me functionality.
        
        Validates extended session creation for remember-me login functionality
        with proper session duration management.
        """
        with app.app_context():
            # Create user for testing
            user = user_service.register_user(valid_user_data)
            
            request_context = {
                'user_agent': 'Mozilla/5.0 Test Browser',
                'ip_address': '192.168.1.1'
            }
            
            # Test authentication with remember_me
            with patch.object(user_service, '_create_user_session_internal') as mock_session:
                mock_session.return_value = 'test_session_token'
                
                authenticated_user = user_service.authenticate_user(
                    valid_user_data['username'],
                    valid_user_data['password'],
                    remember_me=True,
                    request_context=request_context
                )
                
                assert authenticated_user is not None
                # Verify session creation was called with remember_me context
                mock_session.assert_called_once()
    
    def test_user_authentication_inactive_user(self, user_service, app, db, valid_user_data):
        """
        Test authentication for inactive user accounts.
        
        Validates that inactive users cannot authenticate even with valid
        credentials, ensuring proper account status enforcement.
        """
        with app.app_context():
            # Create inactive user
            valid_user_data['is_active'] = False
            user = user_service.register_user(valid_user_data)
            
            # Manually set user as inactive in database
            user.is_active = False
            db.session.commit()
            
            # Test authentication for inactive user
            result = user_service.authenticate_user(
                valid_user_data['username'],
                valid_user_data['password']
            )
            
            # Should return None for inactive user
            assert result is None
    
    @patch('src.services.user_service.ValidationService')
    def test_user_service_composition(self, mock_validation_class, user_service, app):
        """
        Test UserService composition with ValidationService.
        
        Validates service composition patterns as specified in Section 5.2.3
        for complex business workflow coordination.
        """
        with app.app_context():
            # Configure mock validation service
            mock_validation_instance = Mock()
            mock_validation_instance.validate_user_data.return_value = ValidationResult(is_valid=True)
            user_service._validation_service = mock_validation_instance
            
            # Test validation service access
            validation_service = user_service.validation_service
            assert validation_service == mock_validation_instance
            
            # Test validation service caching
            validation_service_2 = user_service.validation_service
            assert validation_service is validation_service_2
    
    def test_user_service_transaction_boundary_integration(self, user_service, app, db, valid_user_data):
        """
        Test UserService integration with transaction boundary management.
        
        Validates proper transaction handling within user service operations
        including commit and rollback scenarios.
        """
        with app.app_context():
            # Test successful transaction
            with user_service.transaction_boundary():
                user = User(
                    username=valid_user_data['username'],
                    email=valid_user_data['email'],
                    password=valid_user_data['password']
                )
                user_service.session.add(user)
                user_service.session.flush()
                user_id = user.id
            
            # Verify transaction committed
            saved_user = User.query.get(user_id)
            assert saved_user is not None
            
            # Test transaction rollback
            with pytest.raises(TransactionError):
                with user_service.transaction_boundary():
                    user2 = User(
                        username='rollback_user',
                        email='rollback@example.com',
                        password='TestPassword123!'
                    )
                    user_service.session.add(user2)
                    user_service.session.flush()
                    # Force exception to trigger rollback
                    raise Exception("Test rollback")
            
            # Verify rollback occurred
            rollback_user = User.query.filter_by(username='rollback_user').first()
            assert rollback_user is None
    
    def test_user_service_error_handling(self, user_service, app, db):
        """
        Test comprehensive error handling in UserService operations.
        
        Validates proper error translation and handling across all user
        service operations including database errors and validation failures.
        """
        with app.app_context():
            # Test database error handling
            with patch.object(user_service.session, 'add', side_effect=SQLAlchemyError("Database error")):
                with pytest.raises(UserRegistrationError) as exc_info:
                    user_service.register_user({
                        'username': 'test_user',
                        'email': 'test@example.com',
                        'password': 'TestPassword123!'
                    })
                
                assert "User registration failed" in str(exc_info.value)
                assert exc_info.value.original_error is not None
            
            # Test validation error propagation
            with pytest.raises(ValidationError):
                user_service.register_user({
                    'username': 'a',  # Invalid username
                    'email': 'test@example.com',
                    'password': 'TestPassword123!'
                })


class TestBusinessEntityService:
    """
    Unit tests for BusinessEntityService complex workflow validation.
    
    Tests business entity management workflows including entity creation,
    relationship management, lifecycle operations, and cross-entity business
    rules to ensure functional equivalence with Node.js implementation as
    specified in Section 5.2.3.
    """
    
    @pytest.fixture
    def business_entity_service(self, app, db):
        """
        Create BusinessEntityService instance for testing.
        
        Args:
            app: Flask application fixture
            db: SQLAlchemy database fixture
        
        Returns:
            BusinessEntityService: Configured business entity service instance
        """
        with app.app_context():
            return BusinessEntityService(db=db)
    
    @pytest.fixture
    def test_user(self, app, db):
        """
        Create test user for entity ownership testing.
        
        Returns:
            User: Test user instance
        """
        with app.app_context():
            user = User(
                username='entity_owner',
                email='owner@example.com',
                password='TestPassword123!'
            )
            db.session.add(user)
            db.session.commit()
            return user
    
    @pytest.fixture
    def valid_entity_data(self, test_user):
        """
        Provide valid business entity data for testing.
        
        Args:
            test_user: Test user fixture for ownership
        
        Returns:
            Dict[str, Any]: Valid entity data meeting business rules
        """
        return {
            'name': 'Test Business Entity',
            'description': 'A test business entity for unit testing',
            'status': 'active',
            'owner_id': test_user.id,
            'metadata': {
                'category': 'test',
                'priority': 'high',
                'tags': ['testing', 'business']
            }
        }
    
    def test_business_entity_service_initialization(self, business_entity_service, app):
        """
        Test BusinessEntityService initialization and configuration.
        
        Validates service initialization per Section 5.2.3 including
        proper inheritance from BaseService and entity-specific configuration.
        """
        with app.app_context():
            # Test base service initialization
            assert hasattr(business_entity_service, 'db')
            assert hasattr(business_entity_service, 'session')
            assert hasattr(business_entity_service, 'logger')
            
            # Test business entity specific attributes
            assert hasattr(business_entity_service, '_entity_status_values')
            assert hasattr(business_entity_service, '_relationship_types')
            
            # Test entity status configuration
            status_values = business_entity_service._entity_status_values
            assert 'active' in status_values
            assert 'inactive' in status_values
            assert 'pending' in status_values
            assert 'archived' in status_values
    
    def test_entity_business_rules_validation(self, business_entity_service, app, valid_entity_data):
        """
        Test business entity validation rules implementation.
        
        Validates entity-specific business rules including name validation,
        description requirements, status validation, and ownership rules.
        """
        with app.app_context():
            # Test valid entity data
            result = business_entity_service.validate_business_rules(valid_entity_data)
            assert result is True
            
            # Test invalid entity name
            invalid_data = valid_entity_data.copy()
            invalid_data['name'] = ''  # Empty name
            
            with pytest.raises(ValidationError) as exc_info:
                business_entity_service.validate_business_rules(invalid_data)
            assert "Entity name is required" in str(exc_info.value)
            
            # Test invalid status
            invalid_data = valid_entity_data.copy()
            invalid_data['status'] = 'invalid_status'
            
            with pytest.raises(ValidationError) as exc_info:
                business_entity_service.validate_business_rules(invalid_data)
            assert "Invalid entity status" in str(exc_info.value)
            
            # Test missing owner
            invalid_data = valid_entity_data.copy()
            del invalid_data['owner_id']
            
            with pytest.raises(ValidationError) as exc_info:
                business_entity_service.validate_business_rules(invalid_data)
            assert "Entity owner is required" in str(exc_info.value)
    
    def test_create_business_entity_success(self, business_entity_service, app, db, valid_entity_data):
        """
        Test successful business entity creation workflow.
        
        Validates complete entity creation process including validation,
        database persistence, and proper entity instance creation.
        """
        with app.app_context():
            # Create business entity
            entity = business_entity_service.create_entity(valid_entity_data)
            
            # Verify entity instance
            assert isinstance(entity, BusinessEntity)
            assert entity.id is not None
            assert entity.name == valid_entity_data['name']
            assert entity.description == valid_entity_data['description']
            assert entity.status == valid_entity_data['status']
            assert entity.owner_id == valid_entity_data['owner_id']
            
            # Verify timestamps
            assert entity.created_at is not None
            assert entity.updated_at is not None
            
            # Verify database persistence
            saved_entity = BusinessEntity.query.filter_by(name=entity.name).first()
            assert saved_entity is not None
            assert saved_entity.id == entity.id
    
    def test_create_business_entity_with_metadata(self, business_entity_service, app, db, valid_entity_data):
        """
        Test business entity creation with metadata handling.
        
        Validates metadata serialization and storage for entity attributes
        that require flexible schema support.
        """
        with app.app_context():
            # Create entity with metadata
            entity = business_entity_service.create_entity(valid_entity_data)
            
            # Verify metadata storage
            assert entity.metadata is not None
            assert entity.metadata['category'] == 'test'
            assert entity.metadata['priority'] == 'high'
            assert 'testing' in entity.metadata['tags']
            assert 'business' in entity.metadata['tags']
    
    def test_update_business_entity_success(self, business_entity_service, app, db, valid_entity_data):
        """
        Test successful business entity update workflow.
        
        Validates entity update process including partial updates,
        validation, and proper change tracking.
        """
        with app.app_context():
            # Create entity first
            entity = business_entity_service.create_entity(valid_entity_data)
            original_updated_at = entity.updated_at
            
            # Update entity
            update_data = {
                'description': 'Updated description for testing',
                'status': 'inactive',
                'metadata': {
                    'category': 'updated_test',
                    'priority': 'medium'
                }
            }
            
            # Wait briefly to ensure timestamp difference
            time.sleep(0.1)
            
            updated_entity = business_entity_service.update_entity(entity.id, update_data)
            
            # Verify updates
            assert updated_entity.id == entity.id
            assert updated_entity.description == update_data['description']
            assert updated_entity.status == update_data['status']
            assert updated_entity.metadata['category'] == 'updated_test'
            assert updated_entity.metadata['priority'] == 'medium'
            
            # Verify timestamp update
            assert updated_entity.updated_at > original_updated_at
            
            # Verify unchanged fields
            assert updated_entity.name == entity.name
            assert updated_entity.owner_id == entity.owner_id
    
    def test_entity_relationship_creation(self, business_entity_service, app, db, test_user):
        """
        Test entity relationship creation and management.
        
        Validates complex business entity relationship workflows including
        relationship creation, type validation, and bidirectional associations.
        """
        with app.app_context():
            # Create source and target entities
            source_data = {
                'name': 'Source Entity',
                'description': 'Source entity for relationship testing',
                'status': 'active',
                'owner_id': test_user.id
            }
            target_data = {
                'name': 'Target Entity',
                'description': 'Target entity for relationship testing',
                'status': 'active',
                'owner_id': test_user.id
            }
            
            source_entity = business_entity_service.create_entity(source_data)
            target_entity = business_entity_service.create_entity(target_data)
            
            # Create relationship
            relationship_data = {
                'source_entity_id': source_entity.id,
                'target_entity_id': target_entity.id,
                'relationship_type': 'dependency',
                'metadata': {
                    'strength': 'strong',
                    'direction': 'unidirectional'
                }
            }
            
            relationship = business_entity_service.create_relationship(relationship_data)
            
            # Verify relationship
            assert isinstance(relationship, EntityRelationship)
            assert relationship.id is not None
            assert relationship.source_entity_id == source_entity.id
            assert relationship.target_entity_id == target_entity.id
            assert relationship.relationship_type == 'dependency'
            assert relationship.is_active is True
            
            # Verify metadata
            assert relationship.metadata['strength'] == 'strong'
            assert relationship.metadata['direction'] == 'unidirectional'
    
    def test_entity_lifecycle_management(self, business_entity_service, app, db, valid_entity_data):
        """
        Test entity lifecycle management including activation, deactivation, and archival.
        
        Validates entity state transitions and lifecycle business rules
        enforcement throughout entity lifetime.
        """
        with app.app_context():
            # Create entity
            entity = business_entity_service.create_entity(valid_entity_data)
            assert entity.status == 'active'
            
            # Deactivate entity
            deactivated_entity = business_entity_service.deactivate_entity(entity.id)
            assert deactivated_entity.status == 'inactive'
            
            # Reactivate entity
            reactivated_entity = business_entity_service.activate_entity(entity.id)
            assert reactivated_entity.status == 'active'
            
            # Archive entity
            archived_entity = business_entity_service.archive_entity(entity.id)
            assert archived_entity.status == 'archived'
            
            # Test that archived entities cannot be activated
            with pytest.raises(EntityLifecycleError) as exc_info:
                business_entity_service.activate_entity(entity.id)
            assert "Cannot activate archived entity" in str(exc_info.value)
    
    def test_entity_ownership_validation(self, business_entity_service, app, db):
        """
        Test entity ownership validation and access control.
        
        Validates that entities can only be modified by their owners or
        authorized users according to business rules.
        """
        with app.app_context():
            # Create two users
            owner = User(
                username='entity_owner',
                email='owner@example.com',
                password='TestPassword123!'
            )
            other_user = User(
                username='other_user',
                email='other@example.com',
                password='TestPassword123!'
            )
            db.session.add_all([owner, other_user])
            db.session.commit()
            
            # Create entity with owner
            entity_data = {
                'name': 'Owned Entity',
                'description': 'Entity with ownership validation',
                'status': 'active',
                'owner_id': owner.id
            }
            
            entity = business_entity_service.create_entity(entity_data)
            
            # Test ownership validation in updates
            with patch.object(business_entity_service, 'get_current_user_id', return_value=other_user.id):
                with pytest.raises(ValidationError) as exc_info:
                    business_entity_service.update_entity(entity.id, {'description': 'Unauthorized update'})
                assert "Not authorized to modify entity" in str(exc_info.value)
            
            # Test owner can update
            with patch.object(business_entity_service, 'get_current_user_id', return_value=owner.id):
                updated_entity = business_entity_service.update_entity(
                    entity.id, 
                    {'description': 'Authorized update'}
                )
                assert updated_entity.description == 'Authorized update'
    
    def test_entity_search_and_filtering(self, business_entity_service, app, db, test_user):
        """
        Test entity search and filtering capabilities.
        
        Validates entity query operations including search by name,
        status filtering, and owner-based filtering.
        """
        with app.app_context():
            # Create multiple entities with different attributes
            entities_data = [
                {
                    'name': 'Alpha Entity',
                    'description': 'First test entity',
                    'status': 'active',
                    'owner_id': test_user.id
                },
                {
                    'name': 'Beta Entity',
                    'description': 'Second test entity',
                    'status': 'inactive',
                    'owner_id': test_user.id
                },
                {
                    'name': 'Gamma Entity',
                    'description': 'Third test entity',
                    'status': 'active',
                    'owner_id': test_user.id
                }
            ]
            
            created_entities = []
            for data in entities_data:
                entity = business_entity_service.create_entity(data)
                created_entities.append(entity)
            
            # Test search by name
            search_results = business_entity_service.search_entities(name_filter='Alpha')
            assert len(search_results) == 1
            assert search_results[0].name == 'Alpha Entity'
            
            # Test filter by status
            active_entities = business_entity_service.search_entities(status_filter='active')
            assert len(active_entities) == 2
            
            inactive_entities = business_entity_service.search_entities(status_filter='inactive')
            assert len(inactive_entities) == 1
            assert inactive_entities[0].name == 'Beta Entity'
            
            # Test filter by owner
            owner_entities = business_entity_service.search_entities(owner_id=test_user.id)
            assert len(owner_entities) == 3
    
    def test_entity_transaction_boundary_management(self, business_entity_service, app, db, valid_entity_data):
        """
        Test transaction boundary management in entity operations.
        
        Validates that entity operations properly handle transaction boundaries
        including commit and rollback scenarios for data consistency.
        """
        with app.app_context():
            # Test successful transaction
            with business_entity_service.transaction_boundary():
                entity = BusinessEntity(
                    name=valid_entity_data['name'],
                    description=valid_entity_data['description'],
                    status=valid_entity_data['status'],
                    owner_id=valid_entity_data['owner_id']
                )
                business_entity_service.session.add(entity)
                business_entity_service.session.flush()
                entity_id = entity.id
            
            # Verify transaction committed
            saved_entity = BusinessEntity.query.get(entity_id)
            assert saved_entity is not None
            
            # Test transaction rollback
            with pytest.raises(TransactionError):
                with business_entity_service.transaction_boundary():
                    entity2 = BusinessEntity(
                        name='Rollback Entity',
                        description='Entity for rollback testing',
                        status='active',
                        owner_id=valid_entity_data['owner_id']
                    )
                    business_entity_service.session.add(entity2)
                    business_entity_service.session.flush()
                    # Force exception to trigger rollback
                    raise Exception("Test rollback")
            
            # Verify rollback occurred
            rollback_entity = BusinessEntity.query.filter_by(name='Rollback Entity').first()
            assert rollback_entity is None
    
    def test_entity_service_composition(self, business_entity_service, app):
        """
        Test BusinessEntityService composition with other services.
        
        Validates service composition patterns for complex business workflows
        requiring coordination between multiple services.
        """
        with app.app_context():
            # Test validation service composition
            validation_service = business_entity_service.compose_service(ValidationService)
            assert validation_service is not None
            
            # Test service caching
            validation_service_2 = business_entity_service.compose_service(ValidationService)
            assert validation_service is validation_service_2
    
    def test_entity_error_handling(self, business_entity_service, app, db):
        """
        Test comprehensive error handling in entity operations.
        
        Validates proper error translation and handling across all entity
        service operations including database errors and validation failures.
        """
        with app.app_context():
            # Test database error handling
            with patch.object(business_entity_service.session, 'add', side_effect=SQLAlchemyError("Database error")):
                with pytest.raises(EntityCreationError) as exc_info:
                    business_entity_service.create_entity({
                        'name': 'Test Entity',
                        'description': 'Test description',
                        'status': 'active',
                        'owner_id': 1
                    })
                
                assert "Entity creation failed" in str(exc_info.value)
                assert exc_info.value.original_error is not None
            
            # Test validation error propagation
            with pytest.raises(ValidationError):
                business_entity_service.create_entity({
                    'name': '',  # Invalid name
                    'description': 'Test description',
                    'status': 'active',
                    'owner_id': 1
                })


class TestValidationService:
    """
    Unit tests for ValidationService dataclasses and type hint validation.
    
    Tests comprehensive data validation, business rule enforcement, and constraint
    checking using Python dataclasses and type hints as specified in Section 4.5.1
    and Section 4.12.1 validation rules implementation.
    """
    
    @pytest.fixture
    def validation_service(self, app, db):
        """
        Create ValidationService instance for testing.
        
        Args:
            app: Flask application fixture
            db: SQLAlchemy database fixture
        
        Returns:
            ValidationService: Configured validation service instance
        """
        with app.app_context():
            return ValidationService(db=db)
    
    @pytest.fixture
    def sample_validation_data(self):
        """
        Provide sample data for validation testing.
        
        Returns:
            Dict[str, Any]: Sample data with various data types
        """
        return {
            'string_field': 'test_value',
            'integer_field': 42,
            'float_field': 3.14,
            'boolean_field': True,
            'email_field': 'test@example.com',
            'date_field': '2023-12-01',
            'optional_field': None,
            'list_field': ['item1', 'item2', 'item3'],
            'dict_field': {'nested_key': 'nested_value'}
        }
    
    def test_validation_service_initialization(self, validation_service, app):
        """
        Test ValidationService initialization and configuration.
        
        Validates service initialization per Section 4.5.1 including
        validation rules setup, type hint configuration, and dataclass
        validation infrastructure.
        """
        with app.app_context():
            # Test base service initialization
            assert hasattr(validation_service, 'db')
            assert hasattr(validation_service, 'session')
            assert hasattr(validation_service, 'logger')
            
            # Test validation-specific attributes
            assert hasattr(validation_service, '_validation_rules')
            assert hasattr(validation_service, '_type_validators')
            assert hasattr(validation_service, '_sanitizers')
            
            # Test validation configuration
            assert hasattr(validation_service, '_email_pattern')
            assert hasattr(validation_service, '_phone_pattern')
            assert hasattr(validation_service, '_url_pattern')
    
    def test_validation_result_dataclass(self, validation_service, app):
        """
        Test ValidationResult dataclass functionality.
        
        Validates dataclass implementation per Section 4.5.1 including
        proper field definitions, type hints, and default values.
        """
        with app.app_context():
            # Test default ValidationResult creation
            result = ValidationResult()
            
            assert result.is_valid is True
            assert result.errors == []
            assert result.warnings == []
            assert result.field_errors == {}
            assert result.sanitized_data == {}
            assert result.validation_type is None
            assert result.severity is None
            assert result.metadata == {}
            
            # Test ValidationResult with data
            result_with_data = ValidationResult(
                is_valid=False,
                errors=['Test error'],
                warnings=['Test warning'],
                field_errors={'field1': 'Field error'},
                sanitized_data={'clean': 'data'},
                validation_type=ValidationType.BUSINESS_RULE,
                severity=ValidationSeverity.ERROR,
                metadata={'context': 'test'}
            )
            
            assert result_with_data.is_valid is False
            assert result_with_data.errors == ['Test error']
            assert result_with_data.warnings == ['Test warning']
            assert result_with_data.field_errors == {'field1': 'Field error'}
            assert result_with_data.sanitized_data == {'clean': 'data'}
            assert result_with_data.validation_type == ValidationType.BUSINESS_RULE
            assert result_with_data.severity == ValidationSeverity.ERROR
            assert result_with_data.metadata == {'context': 'test'}
    
    def test_data_type_validation(self, validation_service, app, sample_validation_data):
        """
        Test data type validation with type hints.
        
        Validates type checking functionality using Python type hints
        for robust data validation as specified in Section 4.5.1.
        """
        with app.app_context():
            # Test string validation
            string_result = validation_service.validate_data_type(
                sample_validation_data['string_field'],
                str,
                'string_field'
            )
            assert string_result.is_valid is True
            
            # Test integer validation
            integer_result = validation_service.validate_data_type(
                sample_validation_data['integer_field'],
                int,
                'integer_field'
            )
            assert integer_result.is_valid is True
            
            # Test float validation
            float_result = validation_service.validate_data_type(
                sample_validation_data['float_field'],
                float,
                'float_field'
            )
            assert float_result.is_valid is True
            
            # Test boolean validation
            boolean_result = validation_service.validate_data_type(
                sample_validation_data['boolean_field'],
                bool,
                'boolean_field'
            )
            assert boolean_result.is_valid is True
            
            # Test type mismatch
            type_mismatch_result = validation_service.validate_data_type(
                sample_validation_data['string_field'],
                int,
                'string_field'
            )
            assert type_mismatch_result.is_valid is False
            assert 'Type mismatch' in type_mismatch_result.field_errors['string_field']
    
    def test_business_rule_validation(self, validation_service, app):
        """
        Test business rule validation implementation.
        
        Validates business rule enforcement per Section 4.12.1 including
        custom validation rules and constraint checking.
        """
        with app.app_context():
            # Test email validation business rule
            valid_email_result = validation_service.validate_email('test@example.com')
            assert valid_email_result.is_valid is True
            
            invalid_email_result = validation_service.validate_email('invalid-email')
            assert invalid_email_result.is_valid is False
            assert 'Invalid email format' in invalid_email_result.errors
            
            # Test phone number validation business rule
            valid_phone_result = validation_service.validate_phone('+1-555-123-4567')
            assert valid_phone_result.is_valid is True
            
            invalid_phone_result = validation_service.validate_phone('invalid-phone')
            assert invalid_phone_result.is_valid is False
            assert 'Invalid phone format' in invalid_phone_result.errors
            
            # Test URL validation business rule
            valid_url_result = validation_service.validate_url('https://example.com')
            assert valid_url_result.is_valid is True
            
            invalid_url_result = validation_service.validate_url('not-a-url')
            assert invalid_url_result.is_valid is False
            assert 'Invalid URL format' in invalid_url_result.errors
    
    def test_constraint_validation(self, validation_service, app):
        """
        Test constraint validation implementation.
        
        Validates constraint checking including length constraints,
        range constraints, and pattern constraints.
        """
        with app.app_context():
            # Test string length constraints
            valid_length_result = validation_service.validate_string_length(
                'test_string',
                min_length=5,
                max_length=20,
                field_name='test_field'
            )
            assert valid_length_result.is_valid is True
            
            too_short_result = validation_service.validate_string_length(
                'abc',
                min_length=5,
                max_length=20,
                field_name='test_field'
            )
            assert too_short_result.is_valid is False
            assert 'too short' in too_short_result.field_errors['test_field']
            
            too_long_result = validation_service.validate_string_length(
                'a' * 25,
                min_length=5,
                max_length=20,
                field_name='test_field'
            )
            assert too_long_result.is_valid is False
            assert 'too long' in too_long_result.field_errors['test_field']
            
            # Test numeric range constraints
            valid_range_result = validation_service.validate_numeric_range(
                15,
                min_value=10,
                max_value=20,
                field_name='number_field'
            )
            assert valid_range_result.is_valid is True
            
            below_range_result = validation_service.validate_numeric_range(
                5,
                min_value=10,
                max_value=20,
                field_name='number_field'
            )
            assert below_range_result.is_valid is False
            assert 'below minimum' in below_range_result.field_errors['number_field']
            
            above_range_result = validation_service.validate_numeric_range(
                25,
                min_value=10,
                max_value=20,
                field_name='number_field'
            )
            assert above_range_result.is_valid is False
            assert 'above maximum' in above_range_result.field_errors['number_field']
    
    def test_data_sanitization(self, validation_service, app):
        """
        Test data sanitization functionality.
        
        Validates input sanitization patterns preservation per Section 2.1.9
        including XSS prevention, SQL injection prevention, and data cleaning.
        """
        with app.app_context():
            # Test HTML sanitization
            html_input = '<script>alert("xss")</script><p>Safe content</p>'
            sanitized_html = validation_service.sanitize_html(html_input)
            
            assert '<script>' not in sanitized_html
            assert 'alert' not in sanitized_html
            assert '<p>Safe content</p>' in sanitized_html
            
            # Test string trimming and normalization
            messy_string = '  \t\n  Test String  \t\n  '
            sanitized_string = validation_service.sanitize_string(messy_string)
            
            assert sanitized_string == 'Test String'
            
            # Test SQL injection prevention
            sql_input = "'; DROP TABLE users; --"
            sanitized_sql = validation_service.sanitize_sql_input(sql_input)
            
            assert 'DROP TABLE' not in sanitized_sql
            assert '--' not in sanitized_sql
            
            # Test email sanitization
            email_input = '  TEST@EXAMPLE.COM  '
            sanitized_email = validation_service.sanitize_email(email_input)
            
            assert sanitized_email == 'test@example.com'
    
    def test_comprehensive_validation_workflow(self, validation_service, app):
        """
        Test comprehensive validation workflow with multiple validation types.
        
        Validates end-to-end validation process combining type validation,
        business rules, constraints, and sanitization.
        """
        with app.app_context():
            # Define comprehensive validation schema
            validation_schema = {
                'username': {
                    'type': str,
                    'min_length': 3,
                    'max_length': 50,
                    'pattern': r'^[a-zA-Z0-9_]+$',
                    'required': True
                },
                'email': {
                    'type': str,
                    'format': 'email',
                    'required': True
                },
                'age': {
                    'type': int,
                    'min_value': 18,
                    'max_value': 120,
                    'required': True
                },
                'website': {
                    'type': str,
                    'format': 'url',
                    'required': False
                }
            }
            
            # Test valid data
            valid_data = {
                'username': 'john_doe123',
                'email': 'john@example.com',
                'age': 25,
                'website': 'https://johndoe.com'
            }
            
            result = validation_service.validate_comprehensive(valid_data, validation_schema)
            
            assert result.is_valid is True
            assert len(result.errors) == 0
            assert len(result.field_errors) == 0
            
            # Test invalid data
            invalid_data = {
                'username': 'ab',  # Too short
                'email': 'invalid-email',  # Invalid format
                'age': 15,  # Below minimum
                'website': 'not-a-url'  # Invalid format
            }
            
            result = validation_service.validate_comprehensive(invalid_data, validation_schema)
            
            assert result.is_valid is False
            assert len(result.errors) > 0
            assert 'username' in result.field_errors
            assert 'email' in result.field_errors
            assert 'age' in result.field_errors
            assert 'website' in result.field_errors
    
    def test_validation_service_business_rules(self, validation_service, app, sample_validation_data):
        """
        Test ValidationService business rules implementation.
        
        Validates implementation of abstract business rules method
        with validation-specific business logic.
        """
        with app.app_context():
            # Test valid business rules
            result = validation_service.validate_business_rules(sample_validation_data)
            assert result is True
            
            # Test invalid business rules
            invalid_data = {
                'string_field': '',  # Empty string
                'integer_field': -1,  # Negative number
                'email_field': 'invalid'  # Invalid email
            }
            
            with pytest.raises(ValidationError):
                validation_service.validate_business_rules(invalid_data)
    
    def test_validation_error_handling(self, validation_service, app):
        """
        Test validation error handling and error message generation.
        
        Validates consistent error handling per Section 4.5.3 with
        proper error categorization and message formatting.
        """
        with app.app_context():
            # Test validation error creation
            error_result = ValidationResult(
                is_valid=False,
                errors=['General validation error'],
                field_errors={'field1': 'Field-specific error'},
                severity=ValidationSeverity.ERROR,
                validation_type=ValidationType.BUSINESS_RULE
            )
            
            assert error_result.is_valid is False
            assert 'General validation error' in error_result.errors
            assert error_result.field_errors['field1'] == 'Field-specific error'
            assert error_result.severity == ValidationSeverity.ERROR
            
            # Test multiple error aggregation
            errors = ['Error 1', 'Error 2', 'Error 3']
            field_errors = {
                'field1': 'Field 1 error',
                'field2': 'Field 2 error'
            }
            
            multi_error_result = ValidationResult(
                is_valid=False,
                errors=errors,
                field_errors=field_errors
            )
            
            assert len(multi_error_result.errors) == 3
            assert len(multi_error_result.field_errors) == 2
    
    def test_validation_service_composition(self, validation_service, app):
        """
        Test ValidationService composition with other services.
        
        Validates service composition patterns for complex validation workflows
        requiring coordination between validation and other business services.
        """
        with app.app_context():
            # Test user service composition for user validation
            user_service = validation_service.compose_service(UserService)
            assert user_service is not None
            
            # Test service caching
            user_service_2 = validation_service.compose_service(UserService)
            assert user_service is user_service_2


class TestWorkflowOrchestrator:
    """
    Unit tests for WorkflowOrchestrator service composition patterns.
    
    Tests advanced workflow orchestration patterns, service composition,
    transaction boundary management, and complex business process coordination
    as specified in Section 4.5.3 and Section 5.2.3.
    """
    
    @pytest.fixture
    def workflow_orchestrator(self, app, db):
        """
        Create WorkflowOrchestrator instance for testing.
        
        Args:
            app: Flask application fixture
            db: SQLAlchemy database fixture
        
        Returns:
            WorkflowOrchestrator: Configured workflow orchestrator instance
        """
        with app.app_context():
            return WorkflowOrchestrator(db=db)
    
    @pytest.fixture
    def mock_services(self, app, db):
        """
        Create mock services for workflow composition testing.
        
        Returns:
            Dict[str, Mock]: Dictionary of mock service instances
        """
        with app.app_context():
            mock_user_service = Mock(spec=UserService)
            mock_entity_service = Mock(spec=BusinessEntityService)
            mock_validation_service = Mock(spec=ValidationService)
            
            return {
                'user_service': mock_user_service,
                'entity_service': mock_entity_service,
                'validation_service': mock_validation_service
            }
    
    def test_workflow_orchestrator_initialization(self, workflow_orchestrator, app):
        """
        Test WorkflowOrchestrator initialization and configuration.
        
        Validates orchestrator initialization per Section 5.2.3 including
        workflow step configuration, service composition setup, and
        event-driven processing infrastructure.
        """
        with app.app_context():
            # Test base service initialization
            assert hasattr(workflow_orchestrator, 'db')
            assert hasattr(workflow_orchestrator, 'session')
            assert hasattr(workflow_orchestrator, 'logger')
            
            # Test workflow-specific attributes
            assert hasattr(workflow_orchestrator, '_workflow_steps')
            assert hasattr(workflow_orchestrator, '_workflow_state')
            assert hasattr(workflow_orchestrator, '_service_registry')
            assert hasattr(workflow_orchestrator, '_retry_policies')
            
            # Test workflow configuration
            assert hasattr(workflow_orchestrator, '_default_timeout')
            assert hasattr(workflow_orchestrator, '_max_concurrent_workflows')
            assert workflow_orchestrator._default_timeout == 300  # 5 minutes
            assert workflow_orchestrator._max_concurrent_workflows == 10
    
    def test_service_composition_registration(self, workflow_orchestrator, app, mock_services):
        """
        Test service composition registration for workflow coordination.
        
        Validates service registration and discovery mechanisms for complex
        business workflow orchestration.
        """
        with app.app_context():
            # Register services with orchestrator
            workflow_orchestrator.register_service('user_service', mock_services['user_service'])
            workflow_orchestrator.register_service('entity_service', mock_services['entity_service'])
            workflow_orchestrator.register_service('validation_service', mock_services['validation_service'])
            
            # Test service retrieval
            retrieved_user_service = workflow_orchestrator.get_service('user_service')
            assert retrieved_user_service == mock_services['user_service']
            
            retrieved_entity_service = workflow_orchestrator.get_service('entity_service')
            assert retrieved_entity_service == mock_services['entity_service']
            
            # Test service listing
            registered_services = workflow_orchestrator.list_registered_services()
            assert 'user_service' in registered_services
            assert 'entity_service' in registered_services
            assert 'validation_service' in registered_services
            assert len(registered_services) == 3
    
    def test_workflow_step_definition(self, workflow_orchestrator, app):
        """
        Test workflow step definition and configuration.
        
        Validates workflow step creation, ordering, and dependency management
        for complex business process orchestration.
        """
        with app.app_context():
            # Define workflow steps
            workflow_steps = [
                {
                    'step_id': 'validate_input',
                    'service': 'validation_service',
                    'method': 'validate_user_data',
                    'timeout': 30,
                    'retry_policy': {'max_retries': 3, 'delay': 1}
                },
                {
                    'step_id': 'create_user',
                    'service': 'user_service',
                    'method': 'register_user',
                    'timeout': 60,
                    'depends_on': ['validate_input'],
                    'retry_policy': {'max_retries': 2, 'delay': 2}
                },
                {
                    'step_id': 'create_entity',
                    'service': 'entity_service',
                    'method': 'create_entity',
                    'timeout': 45,
                    'depends_on': ['create_user'],
                    'retry_policy': {'max_retries': 1, 'delay': 3}
                }
            ]
            
            # Register workflow
            workflow_id = workflow_orchestrator.define_workflow('user_onboarding', workflow_steps)
            
            assert workflow_id is not None
            assert workflow_id in workflow_orchestrator._workflow_steps
            
            # Verify workflow steps
            registered_steps = workflow_orchestrator._workflow_steps[workflow_id]
            assert len(registered_steps) == 3
            assert registered_steps[0]['step_id'] == 'validate_input'
            assert registered_steps[1]['step_id'] == 'create_user'
            assert registered_steps[2]['step_id'] == 'create_entity'
            
            # Verify dependencies
            assert 'depends_on' not in registered_steps[0]
            assert registered_steps[1]['depends_on'] == ['validate_input']
            assert registered_steps[2]['depends_on'] == ['create_user']
    
    def test_workflow_execution_success(self, workflow_orchestrator, app, mock_services):
        """
        Test successful workflow execution with service composition.
        
        Validates end-to-end workflow execution including step coordination,
        data passing between steps, and success handling.
        """
        with app.app_context():
            # Configure mock services
            mock_services['validation_service'].validate_user_data.return_value = ValidationResult(
                is_valid=True,
                sanitized_data={'username': 'test_user', 'email': 'test@example.com'}
            )
            mock_user = Mock()
            mock_user.id = 123
            mock_user.username = 'test_user'
            mock_services['user_service'].register_user.return_value = mock_user
            
            mock_entity = Mock()
            mock_entity.id = 456
            mock_entity.name = 'Test Entity'
            mock_services['entity_service'].create_entity.return_value = mock_entity
            
            # Register services
            for service_name, service_instance in mock_services.items():
                workflow_orchestrator.register_service(service_name, service_instance)
            
            # Define and execute workflow
            workflow_steps = [
                {
                    'step_id': 'validate_input',
                    'service': 'validation_service',
                    'method': 'validate_user_data',
                    'input_mapping': {'data': 'workflow_input'}
                },
                {
                    'step_id': 'create_user',
                    'service': 'user_service',
                    'method': 'register_user',
                    'input_mapping': {'user_data': 'validate_input.sanitized_data'},
                    'depends_on': ['validate_input']
                },
                {
                    'step_id': 'create_entity',
                    'service': 'entity_service',
                    'method': 'create_entity',
                    'input_mapping': {
                        'entity_data': {
                            'name': 'User Entity',
                            'owner_id': 'create_user.id'
                        }
                    },
                    'depends_on': ['create_user']
                }
            ]
            
            workflow_id = workflow_orchestrator.define_workflow('user_onboarding', workflow_steps)
            
            # Execute workflow
            workflow_input = {
                'username': 'test_user',
                'email': 'test@example.com',
                'password': 'TestPassword123!'
            }
            
            result = workflow_orchestrator.execute_workflow(workflow_id, workflow_input)
            
            # Verify execution result
            assert result.is_success is True
            assert result.workflow_id == workflow_id
            assert len(result.step_results) == 3
            assert 'validate_input' in result.step_results
            assert 'create_user' in result.step_results
            assert 'create_entity' in result.step_results
            
            # Verify service method calls
            mock_services['validation_service'].validate_user_data.assert_called_once()
            mock_services['user_service'].register_user.assert_called_once()
            mock_services['entity_service'].create_entity.assert_called_once()
    
    def test_workflow_execution_step_failure(self, workflow_orchestrator, app, mock_services):
        """
        Test workflow execution with step failure and error handling.
        
        Validates error handling, rollback mechanisms, and failure recovery
        when individual workflow steps fail during execution.
        """
        with app.app_context():
            # Configure mock services with failure
            mock_services['validation_service'].validate_user_data.return_value = ValidationResult(
                is_valid=True,
                sanitized_data={'username': 'test_user', 'email': 'test@example.com'}
            )
            
            # User service will fail
            mock_services['user_service'].register_user.side_effect = UserRegistrationError(
                "Registration failed"
            )
            
            # Register services
            for service_name, service_instance in mock_services.items():
                workflow_orchestrator.register_service(service_name, service_instance)
            
            # Define workflow with rollback steps
            workflow_steps = [
                {
                    'step_id': 'validate_input',
                    'service': 'validation_service',
                    'method': 'validate_user_data'
                },
                {
                    'step_id': 'create_user',
                    'service': 'user_service',
                    'method': 'register_user',
                    'depends_on': ['validate_input'],
                    'rollback_method': 'cleanup_user_registration'
                }
            ]
            
            workflow_id = workflow_orchestrator.define_workflow('failing_workflow', workflow_steps)
            
            # Execute workflow
            workflow_input = {'username': 'test_user', 'email': 'test@example.com'}
            
            result = workflow_orchestrator.execute_workflow(workflow_id, workflow_input)
            
            # Verify execution failure
            assert result.is_success is False
            assert result.error is not None
            assert "Registration failed" in str(result.error)
            assert 'validate_input' in result.step_results  # Should have succeeded
            assert 'create_user' not in result.step_results or result.step_results['create_user'].is_error
    
    def test_workflow_step_retry_mechanism(self, workflow_orchestrator, app, mock_services):
        """
        Test workflow step retry mechanisms for resilient execution.
        
        Validates retry logic implementation per Section 4.5.3 including
        exponential backoff and maximum retry limits.
        """
        with app.app_context():
            # Configure mock service with intermittent failures
            call_count = 0
            
            def failing_then_success(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise ServiceError("Temporary failure")
                return ValidationResult(is_valid=True, sanitized_data={'validated': True})
            
            mock_services['validation_service'].validate_user_data.side_effect = failing_then_success
            
            # Register services
            workflow_orchestrator.register_service('validation_service', mock_services['validation_service'])
            
            # Define workflow with retry policy
            workflow_steps = [
                {
                    'step_id': 'validate_input',
                    'service': 'validation_service',
                    'method': 'validate_user_data',
                    'retry_policy': {
                        'max_retries': 3,
                        'delay': 0.1,
                        'backoff_factor': 2.0
                    }
                }
            ]
            
            workflow_id = workflow_orchestrator.define_workflow('retry_workflow', workflow_steps)
            
            # Execute workflow
            with patch('time.sleep'):  # Mock sleep to speed up test
                result = workflow_orchestrator.execute_workflow(workflow_id, {'data': 'test'})
            
            # Verify retry success
            assert result.is_success is True
            assert call_count == 3  # Should have retried twice before success
            assert mock_services['validation_service'].validate_user_data.call_count == 3
    
    def test_workflow_transaction_boundary_management(self, workflow_orchestrator, app, db):
        """
        Test workflow transaction boundary management across multiple services.
        
        Validates that workflow orchestration properly manages transaction
        boundaries across service boundaries for data consistency.
        """
        with app.app_context():
            # Test successful workflow transaction
            with workflow_orchestrator.workflow_transaction_boundary() as transaction_context:
                # Simulate multiple service operations within workflow
                user = User(
                    username='workflow_user',
                    email='workflow@example.com',
                    password='TestPassword123!'
                )
                transaction_context.session.add(user)
                transaction_context.session.flush()
                
                entity = BusinessEntity(
                    name='Workflow Entity',
                    description='Entity created in workflow',
                    status='active',
                    owner_id=user.id
                )
                transaction_context.session.add(entity)
                transaction_context.session.flush()
                
                # Store IDs for verification
                user_id = user.id
                entity_id = entity.id
            
            # Verify all operations committed
            saved_user = User.query.get(user_id)
            saved_entity = BusinessEntity.query.get(entity_id)
            assert saved_user is not None
            assert saved_entity is not None
            assert saved_entity.owner_id == saved_user.id
            
            # Test workflow transaction rollback
            with pytest.raises(WorkflowExecutionError):
                with workflow_orchestrator.workflow_transaction_boundary() as transaction_context:
                    user2 = User(
                        username='rollback_user',
                        email='rollback@example.com',
                        password='TestPassword123!'
                    )
                    transaction_context.session.add(user2)
                    transaction_context.session.flush()
                    
                    # Force rollback
                    raise WorkflowExecutionError("Workflow failed")
            
            # Verify rollback occurred
            rollback_user = User.query.filter_by(username='rollback_user').first()
            assert rollback_user is None
    
    def test_workflow_state_management(self, workflow_orchestrator, app):
        """
        Test workflow state management and persistence.
        
        Validates workflow state tracking, step progress monitoring,
        and state persistence for long-running workflows.
        """
        with app.app_context():
            # Define multi-step workflow
            workflow_steps = [
                {'step_id': 'step1', 'service': 'test_service', 'method': 'method1'},
                {'step_id': 'step2', 'service': 'test_service', 'method': 'method2', 'depends_on': ['step1']},
                {'step_id': 'step3', 'service': 'test_service', 'method': 'method3', 'depends_on': ['step2']}
            ]
            
            workflow_id = workflow_orchestrator.define_workflow('state_test_workflow', workflow_steps)
            
            # Initialize workflow state
            execution_id = workflow_orchestrator.initialize_workflow_state(workflow_id, {'input': 'data'})
            
            # Verify initial state
            state = workflow_orchestrator.get_workflow_state(execution_id)
            assert state.workflow_id == workflow_id
            assert state.status == 'initialized'
            assert state.current_step is None
            assert state.completed_steps == []
            assert state.failed_steps == []
            
            # Update state as workflow progresses
            workflow_orchestrator.update_workflow_state(execution_id, 'running', current_step='step1')
            state = workflow_orchestrator.get_workflow_state(execution_id)
            assert state.status == 'running'
            assert state.current_step == 'step1'
            
            # Mark step as completed
            workflow_orchestrator.mark_step_completed(execution_id, 'step1', {'result': 'step1_result'})
            state = workflow_orchestrator.get_workflow_state(execution_id)
            assert 'step1' in state.completed_steps
            assert state.step_results['step1']['result'] == 'step1_result'
            
            # Mark step as failed
            workflow_orchestrator.mark_step_failed(execution_id, 'step2', 'Step 2 failed')
            state = workflow_orchestrator.get_workflow_state(execution_id)
            assert 'step2' in state.failed_steps
            assert state.step_errors['step2'] == 'Step 2 failed'
    
    def test_workflow_orchestrator_business_rules(self, workflow_orchestrator, app):
        """
        Test WorkflowOrchestrator business rules implementation.
        
        Validates implementation of abstract business rules method
        with workflow-specific business logic validation.
        """
        with app.app_context():
            # Test valid workflow data
            valid_data = {
                'workflow_id': 'test_workflow',
                'execution_context': {'user_id': 123},
                'input_data': {'valid': True}
            }
            
            result = workflow_orchestrator.validate_business_rules(valid_data)
            assert result is True
            
            # Test invalid workflow data
            invalid_data = {
                'workflow_id': '',  # Empty workflow ID
                'execution_context': {},  # Missing user context
                'input_data': None  # Invalid input
            }
            
            with pytest.raises(ValidationError):
                workflow_orchestrator.validate_business_rules(invalid_data)
    
    def test_workflow_orchestrator_service_composition(self, workflow_orchestrator, app):
        """
        Test WorkflowOrchestrator composition with other services.
        
        Validates service composition patterns for complex workflow coordination
        requiring integration with all other service layer components.
        """
        with app.app_context():
            # Test user service composition
            user_service = workflow_orchestrator.compose_service(UserService)
            assert user_service is not None
            
            # Test business entity service composition
            entity_service = workflow_orchestrator.compose_service(BusinessEntityService)
            assert entity_service is not None
            
            # Test validation service composition
            validation_service = workflow_orchestrator.compose_service(ValidationService)
            assert validation_service is not None
            
            # Test service caching
            user_service_2 = workflow_orchestrator.compose_service(UserService)
            assert user_service is user_service_2
    
    def test_concurrent_workflow_execution(self, workflow_orchestrator, app, mock_services):
        """
        Test concurrent workflow execution with proper isolation.
        
        Validates that multiple workflows can execute concurrently without
        interference and with proper resource management.
        """
        with app.app_context():
            # Configure mock services
            mock_services['validation_service'].validate_user_data.return_value = ValidationResult(
                is_valid=True,
                sanitized_data={'validated': True}
            )
            
            # Register services
            workflow_orchestrator.register_service('validation_service', mock_services['validation_service'])
            
            # Define simple workflow
            workflow_steps = [
                {
                    'step_id': 'validate',
                    'service': 'validation_service',
                    'method': 'validate_user_data'
                }
            ]
            
            workflow_id = workflow_orchestrator.define_workflow('concurrent_test', workflow_steps)
            
            # Execute multiple workflows concurrently
            import threading
            results = []
            
            def execute_workflow(input_data):
                result = workflow_orchestrator.execute_workflow(workflow_id, input_data)
                results.append(result)
            
            threads = []
            for i in range(5):
                thread = threading.Thread(
                    target=execute_workflow,
                    args=({'data': f'test_{i}'},)
                )
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Verify all workflows completed successfully
            assert len(results) == 5
            for result in results:
                assert result.is_success is True
            
            # Verify service was called for each workflow
            assert mock_services['validation_service'].validate_user_data.call_count == 5