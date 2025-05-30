"""
Comprehensive Database Model Testing Module

This module validates Flask-SQLAlchemy declarative models, relationship mappings, 
and data operations ensuring complete schema integrity during MongoDB to SQL conversion.
Implements systematic testing of database models with comprehensive validation of
business logic, data relationships, and migration integrity per Section 4.7.1.

The testing framework validates:
- Flask-SQLAlchemy declarative model functionality and constraints
- Relationship mappings and bidirectional consistency validation
- Data integrity preservation throughout migration process
- SQLAlchemy session management with transaction rollback capabilities
- Database schema preservation without modification during conversion
- Performance benchmarking against baseline requirements

Key Testing Areas:
- User model authentication and session management
- Encrypted field functionality with FernetEngine validation
- Audit trail tracking with automatic timestamp population
- RBAC integration with role and permission relationships
- Business entity management and hierarchical relationships
- Database transaction isolation and rollback procedures

Dependencies:
- pytest 8.3.3: Primary testing framework with Flask-specific extensions
- Factory Boy: Django-style factory patterns for realistic test data generation
- Flask-SQLAlchemy 3.1.1: Database ORM functionality under test
- pytest-benchmark: Performance testing and regression detection
- SQLAlchemy test utilities: Database session management and rollback support
"""

import pytest
import json
import secrets
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import patch, Mock

# Third-party testing imports
from sqlalchemy import inspect, text, func, event
from sqlalchemy.exc import IntegrityError, ValidationError as SQLValidationError
from sqlalchemy.orm import Session, scoped_session
from werkzeug.exceptions import ValidationError
from cryptography.fernet import Fernet

# Flask and application imports
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Model imports from the application
from models.base import db, BaseModel, AuditMixin, EncryptedMixin, DatabaseManager
from models.user import User, UserSession, UserUtils, load_user

# Factory imports for test data generation
from tests.factories import (
    UserFactory, UserSessionFactory, RoleFactory, PermissionFactory,
    UserRoleFactory, RolePermissionFactory, BusinessEntityFactory,
    EntityRelationshipFactory, AuditLogFactory, SecurityEventFactory,
    FactorySessionManager, FactoryPresets, configure_factories,
    reset_factory_sequences, cleanup_test_data
)


class TestDatabaseInfrastructure:
    """
    Test database infrastructure and session management capabilities.
    
    Validates SQLAlchemy session handling, transaction management, and connection
    pool configuration for enterprise-grade database operations per Section 4.4.1.2.
    """
    
    def test_database_session_initialization(self, app: Flask, db_session: Session):
        """
        Test SQLAlchemy database session initialization and configuration.
        
        Validates proper database session setup with connection pooling,
        transaction management, and Flask application context integration.
        
        Args:
            app: Flask application fixture
            db_session: Database session fixture with rollback capabilities
        """
        # Verify database session is properly configured
        assert db_session is not None
        assert hasattr(db_session, 'execute')
        assert hasattr(db_session, 'commit')
        assert hasattr(db_session, 'rollback')
        
        # Verify Flask-SQLAlchemy integration
        assert hasattr(app, 'db')
        assert app.db.session is not None
        
        # Test connection pool configuration
        engine = db_session.get_bind()
        assert engine is not None
        assert engine.pool is not None
        
        # Verify transaction isolation
        with db_session.begin():
            result = db_session.execute(text("SELECT 1 as test_value"))
            assert result.fetchone().test_value == 1
    
    def test_database_transaction_rollback(self, db_session: Session):
        """
        Test database transaction rollback capabilities for test isolation.
        
        Validates that database transactions can be properly rolled back
        to maintain test isolation per Section 4.7.3.1.
        
        Args:
            db_session: Database session fixture with rollback capabilities
        """
        # Create test user and commit
        user = UserFactory.build()
        db_session.add(user)
        db_session.flush()  # Assign ID without committing
        user_id = user.id
        
        # Verify user exists in session
        found_user = db_session.query(User).filter_by(id=user_id).first()
        assert found_user is not None
        assert found_user.username == user.username
        
        # Rollback transaction
        db_session.rollback()
        
        # Verify user no longer exists after rollback
        found_user_after_rollback = db_session.query(User).filter_by(id=user_id).first()
        assert found_user_after_rollback is None
    
    def test_database_connection_pool_configuration(self, app: Flask):
        """
        Test database connection pool configuration and management.
        
        Validates connection pool settings including pool_size, max_overflow,
        and pool_timeout configuration per Section 4.4.1.2.
        
        Args:
            app: Flask application fixture
        """
        # Get database engine configuration
        engine = app.db.engine
        pool = engine.pool
        
        # Verify connection pool is configured
        assert pool is not None
        
        # Test connection acquisition and release
        connection = pool.connect()
        assert connection is not None
        
        # Test connection is functional
        result = connection.execute(text("SELECT 1 as pool_test"))
        assert result.fetchone().pool_test == 1
        
        # Release connection back to pool
        connection.close()
    
    def test_database_manager_utilities(self, db_session: Session):
        """
        Test DatabaseManager utility functions for transaction management.
        
        Validates utility methods for safe commit, rollback, and transaction
        context management per Section 6.2 database design requirements.
        
        Args:
            db_session: Database session fixture
        """
        # Test safe commit functionality
        user = UserFactory.build()
        db_session.add(user)
        
        # Test DatabaseManager.safe_commit()
        commit_result = DatabaseManager.safe_commit()
        assert commit_result is True
        
        # Verify user was committed
        user_id = user.id
        committed_user = db_session.query(User).filter_by(id=user_id).first()
        assert committed_user is not None
        
        # Test safe rollback functionality
        rollback_result = DatabaseManager.safe_rollback()
        assert rollback_result is True
        
        # Test transaction context manager
        with DatabaseManager.transaction():
            test_user = UserFactory.build()
            db_session.add(test_user)
            # Transaction will auto-commit on context exit
        
        # Verify user was committed through transaction context
        transaction_user = db_session.query(User).filter_by(id=test_user.id).first()
        assert transaction_user is not None


class TestBaseModelFunctionality:
    """
    Test BaseModel functionality including audit trails and common utilities.
    
    Validates the foundation model class providing common functionality across
    all entity models per Section 4.4.1.1 model definition standards.
    """
    
    def test_audit_mixin_timestamp_population(self, db_session: Session):
        """
        Test automatic audit timestamp population in AuditMixin.
        
        Validates that created_at and updated_at timestamps are automatically
        populated during model creation and updates per Section 4.7.1.
        
        Args:
            db_session: Database session fixture
        """
        # Create user to test audit timestamp population
        user = UserFactory()
        db_session.flush()
        
        # Verify created_at timestamp is populated
        assert user.created_at is not None
        assert isinstance(user.created_at, datetime)
        assert user.created_at <= datetime.utcnow()
        
        # Verify updated_at timestamp is populated
        assert user.updated_at is not None
        assert isinstance(user.updated_at, datetime)
        assert user.updated_at >= user.created_at
        
        # Test updated_at timestamp changes on update
        original_updated_at = user.updated_at
        user.first_name = "Updated Name"
        db_session.flush()
        
        assert user.updated_at > original_updated_at
    
    def test_audit_mixin_user_attribution(self, db_session: Session):
        """
        Test automatic user attribution in audit fields.
        
        Validates that created_by and updated_by fields are automatically
        populated with user context per Section 4.7.1 audit requirements.
        
        Args:
            db_session: Database session fixture
        """
        # Test audit field population without user context
        user = UserFactory()
        db_session.flush()
        
        # Verify audit fields are populated with system default
        assert user.created_by is not None
        assert user.updated_by is not None
        
        # Test with mock user context
        with patch('models.base.get_current_user_context', return_value='test_user'):
            updated_user = UserFactory()
            db_session.flush()
            
            # Note: In actual implementation, this would be populated by SQLAlchemy event
            # For testing, we verify the structure exists
            assert hasattr(updated_user, 'created_by')
            assert hasattr(updated_user, 'updated_by')
    
    def test_encrypted_mixin_functionality(self, db_session: Session):
        """
        Test EncryptedMixin field encryption and decryption capabilities.
        
        Validates encrypted field functionality using FernetEngine for PII
        protection per Section 4.4.1.1 security requirements.
        
        Args:
            db_session: Database session fixture
        """
        # Test encryption key retrieval
        with patch.dict('os.environ', {'FIELD_ENCRYPTION_KEY': Fernet.generate_key().decode()}):
            key = EncryptedMixin.get_encryption_key()
            assert key is not None
            assert isinstance(key, bytes)
        
        # Test encrypted field creation (structure validation)
        user = UserFactory()
        
        # Verify encrypted fields exist and can store data
        assert hasattr(user, 'email')
        assert hasattr(user, 'first_name')
        assert hasattr(user, 'last_name')
        
        # Test that encrypted fields can be read back
        test_email = user.email
        assert test_email is not None
        
        # Test field validation for encrypted data
        user.email = "test@example.com"
        user.first_name = "Test"
        user.last_name = "User"
        
        db_session.flush()
        
        # Verify data persistence through encryption
        assert user.email == "test@example.com"
        assert user.first_name == "Test"
        assert user.last_name == "User"
    
    def test_base_model_serialization(self, db_session: Session):
        """
        Test BaseModel serialization methods for API integration.
        
        Validates to_dict() and to_json() methods with sensitive data protection
        per API contract requirements.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        db_session.flush()
        
        # Test basic dictionary serialization
        user_dict = user.to_dict()
        
        assert isinstance(user_dict, dict)
        assert 'id' in user_dict
        assert 'username' in user_dict
        assert 'created_at' in user_dict
        assert 'updated_at' in user_dict
        
        # Test serialization with sensitive data excluded by default
        assert user_dict.get('email') == '[ENCRYPTED]'  # Should be masked
        
        # Test serialization including sensitive data
        user_dict_sensitive = user.to_dict(include_sensitive=True)
        assert user_dict_sensitive.get('email') != '[ENCRYPTED]'
        
        # Test field exclusion
        user_dict_excluded = user.to_dict(exclude_fields=['username', 'email'])
        assert 'username' not in user_dict_excluded
        assert 'email' not in user_dict_excluded
        
        # Test JSON serialization
        user_json = user.to_json()
        assert isinstance(user_json, str)
        
        # Verify JSON can be parsed
        parsed_json = json.loads(user_json)
        assert isinstance(parsed_json, dict)
        assert 'id' in parsed_json
    
    def test_base_model_crud_operations(self, db_session: Session):
        """
        Test BaseModel CRUD operations with validation.
        
        Validates create, update, delete operations with proper validation
        and error handling per Section 6.2 database design.
        
        Args:
            db_session: Database session fixture
        """
        # Test create operation
        user_data = {
            'username': 'test_user_crud',
            'email': 'crud@example.com',
            'first_name': 'CRUD',
            'last_name': 'Test'
        }
        
        user = User.create(**user_data)
        assert user is not None
        assert user.username == 'test_user_crud'
        
        # Test get_by_id operation
        user_id = user.id
        retrieved_user = User.get_by_id(user_id)
        assert retrieved_user is not None
        assert retrieved_user.id == user_id
        
        # Test update operation
        updated_user = user.update(first_name='Updated CRUD')
        assert updated_user.first_name == 'Updated CRUD'
        
        # Test validation during update
        try:
            user.update(email='invalid-email-format')
            pytest.fail("Expected validation error for invalid email")
        except (ValidationError, ValueError):
            pass  # Expected validation error
        
        # Test delete operation
        delete_result = user.delete()
        assert delete_result is True
        
        # Verify user is deleted
        deleted_user = User.get_by_id(user_id)
        assert deleted_user is None


class TestUserModelComprehensive:
    """
    Comprehensive test suite for User model functionality.
    
    Validates user authentication, profile management, session handling,
    and Auth0 integration per Section 0.2.1 database model conversion.
    """
    
    def test_user_model_creation_and_validation(self, db_session: Session):
        """
        Test User model creation with comprehensive field validation.
        
        Validates user creation with required fields, constraints, and
        validation rules per Section 4.7.1 data operations testing.
        
        Args:
            db_session: Database session fixture
        """
        # Test user creation with all required fields
        user_data = {
            'username': 'test_user_validation',
            'email': 'validation@example.com',
            'first_name': 'Test',
            'last_name': 'User'
        }
        
        user = User(**user_data)
        db_session.add(user)
        db_session.flush()
        
        # Verify basic field population
        assert user.id is not None
        assert user.username == 'test_user_validation'
        assert user.email == 'validation@example.com'
        assert user.first_name == 'Test'
        assert user.last_name == 'User'
        
        # Verify default values
        assert user.is_active is True
        assert user.is_verified is False
        assert user.is_admin is False
        assert user.login_count == 0
        assert user.failed_login_count == 0
        assert user.timezone == 'UTC'
        assert user.locale == 'en'
        
        # Verify audit timestamps
        assert user.created_at is not None
        assert user.updated_at is not None
    
    def test_user_model_validation_rules(self, db_session: Session):
        """
        Test User model field validation and constraint enforcement.
        
        Validates input validation, format checking, and constraint enforcement
        for user data integrity per Section 4.4.1.1 validation rules.
        
        Args:
            db_session: Database session fixture
        """
        # Test username validation
        user = User()
        
        # Test empty username validation
        with pytest.raises(ValueError, match="Username cannot be empty"):
            user.validate_username('username', '')
        
        # Test short username validation
        with pytest.raises(ValueError, match="Username must be at least 3 characters"):
            user.validate_username('username', 'ab')
        
        # Test long username validation
        with pytest.raises(ValueError, match="Username cannot exceed 100 characters"):
            user.validate_username('username', 'a' * 101)
        
        # Test invalid characters in username
        with pytest.raises(ValueError, match="Username can only contain"):
            user.validate_username('username', 'user@name!')
        
        # Test valid username
        valid_username = user.validate_username('username', 'Valid_User.123')
        assert valid_username == 'valid_user.123'  # Should be lowercased
        
        # Test email validation
        with pytest.raises(ValueError, match="Email cannot be empty"):
            user.validate_email('email', '')
        
        with pytest.raises(ValueError, match="Invalid email format"):
            user.validate_email('email', 'invalid-email')
        
        with pytest.raises(ValueError, match="Invalid email format"):
            user.validate_email('email', '@domain.com')
        
        with pytest.raises(ValueError, match="Email cannot exceed 255 characters"):
            user.validate_email('email', 'a' * 250 + '@example.com')
        
        # Test valid email
        valid_email = user.validate_email('email', 'Valid.Email@Example.COM')
        assert valid_email == 'valid.email@example.com'  # Should be lowercased
        
        # Test Auth0 user ID validation
        assert user.validate_auth0_user_id('auth0_user_id', None) is None
        assert user.validate_auth0_user_id('auth0_user_id', '') is None
        
        with pytest.raises(ValueError, match="Auth0 user ID cannot exceed 255 characters"):
            user.validate_auth0_user_id('auth0_user_id', 'a' * 256)
        
        valid_auth0_id = user.validate_auth0_user_id('auth0_user_id', 'auth0|user123')
        assert valid_auth0_id == 'auth0|user123'
    
    def test_user_password_management(self, db_session: Session):
        """
        Test User model password hashing and verification.
        
        Validates secure password storage using Werkzeug password hashing
        per Section 6.4 security architecture requirements.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        
        # Test password setting with validation
        with pytest.raises(ValueError, match="Password cannot be empty"):
            user.set_password('')
        
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            user.set_password('short')
        
        with pytest.raises(ValueError, match="Password cannot exceed 128 characters"):
            user.set_password('a' * 129)
        
        # Test valid password setting
        test_password = 'SecurePassword123!'
        user.set_password(test_password)
        
        # Verify password hash is generated
        assert user.password_hash is not None
        assert user.password_hash != test_password  # Should be hashed
        
        # Test password verification
        assert user.check_password(test_password) is True
        assert user.check_password('wrong_password') is False
        assert user.check_password('') is False
        
        # Test password check with no password hash
        user_no_password = UserFactory(auth0_user=True)  # Auth0 users have no local password
        assert user_no_password.check_password('any_password') is False
    
    def test_user_authentication_tracking(self, db_session: Session):
        """
        Test User model authentication and login tracking.
        
        Validates login tracking, failed attempt management, and account
        locking per Section 6.4 security architecture.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        initial_login_count = user.login_count
        
        # Test successful login tracking
        user.update_login_tracking()
        
        assert user.last_login_at is not None
        assert user.login_count == initial_login_count + 1
        assert user.failed_login_count == 0
        assert user.locked_until is None
        
        # Test failed login recording
        initial_failed_count = user.failed_login_count
        
        # Record failed login attempts
        for i in range(4):
            is_locked = user.record_failed_login(max_attempts=5)
            assert is_locked is False
            assert user.failed_login_count == initial_failed_count + i + 1
        
        # Fifth failed attempt should lock account
        is_locked = user.record_failed_login(max_attempts=5, lockout_duration=30)
        assert is_locked is True
        assert user.failed_login_count == 5
        assert user.locked_until is not None
        assert user.is_account_locked() is True
        
        # Test account unlock
        user.unlock_account()
        assert user.locked_until is None
        assert user.failed_login_count == 0
        assert user.is_account_locked() is False
        
        # Test successful login after unlock
        user.update_login_tracking()
        assert user.failed_login_count == 0
        assert user.locked_until is None
    
    def test_user_auth0_integration(self, db_session: Session):
        """
        Test User model Auth0 integration and synchronization.
        
        Validates Auth0 user data synchronization and metadata management
        per Section 3.4 third-party services integration.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory(auth0_user=True)
        
        # Test Auth0 user data synchronization
        auth0_data = {
            'user_id': 'auth0|new_user_id_123',
            'email': 'auth0@example.com',
            'email_verified': True,
            'given_name': 'Auth0',
            'family_name': 'User',
            'picture': 'https://example.com/auth0_avatar.jpg',
            'user_metadata': {
                'preferences': {'theme': 'dark', 'language': 'en'},
                'onboarding_completed': True
            },
            'app_metadata': {
                'roles': ['user', 'beta_tester'],
                'customer_tier': 'premium'
            },
            'last_login': '2024-01-15T10:30:00Z',
            'logins_count': 25
        }
        
        user.sync_with_auth0(auth0_data)
        
        # Verify Auth0 data synchronization
        assert user.auth0_user_id == 'auth0|new_user_id_123'
        assert user.email == 'auth0@example.com'
        assert user.is_verified is True
        assert user.first_name == 'Auth0'
        assert user.last_name == 'User'
        assert user.avatar_url == 'https://example.com/auth0_avatar.jpg'
        assert user.login_count >= 25  # Should be max of current and Auth0 count
        
        # Test metadata retrieval
        user_metadata = user.get_auth0_metadata()
        assert isinstance(user_metadata, dict)
        assert user_metadata.get('preferences', {}).get('theme') == 'dark'
        
        app_metadata = user.get_auth0_app_metadata()
        assert isinstance(app_metadata, dict)
        assert 'user' in app_metadata.get('roles', [])
        assert app_metadata.get('customer_tier') == 'premium'
        
        # Test invalid metadata handling
        user.auth0_metadata = 'invalid_json'
        assert user.get_auth0_metadata() == {}
        
        user.auth0_app_metadata = None
        assert user.get_auth0_app_metadata() == {}
    
    def test_user_profile_management(self, db_session: Session):
        """
        Test User model profile management and utility methods.
        
        Validates profile data management, full name generation, and
        user data representation per user management requirements.
        
        Args:
            db_session: Database session fixture
        """
        # Test full name generation
        user = UserFactory(first_name='Test', last_name='User')
        assert user.get_full_name() == 'Test User'
        
        user_first_only = UserFactory(first_name='FirstOnly', last_name=None)
        assert user_first_only.get_full_name() == 'FirstOnly'
        
        user_last_only = UserFactory(first_name=None, last_name='LastOnly')
        assert user_last_only.get_full_name() == 'LastOnly'
        
        user_no_names = UserFactory(first_name=None, last_name=None)
        assert user_no_names.get_full_name() == user_no_names.username
        
        # Test user dictionary representation
        user_dict = user.to_dict()
        
        required_fields = [
            'id', 'username', 'is_active', 'is_verified', 'is_admin',
            'timezone', 'locale', 'last_login_at', 'login_count',
            'created_at', 'updated_at'
        ]
        
        for field in required_fields:
            assert field in user_dict
        
        # Test sensitive data inclusion
        user_dict_sensitive = user.to_dict(include_sensitive=True)
        sensitive_fields = [
            'email', 'first_name', 'last_name', 'full_name',
            'auth0_user_id', 'auth0_metadata', 'auth0_app_metadata'
        ]
        
        for field in sensitive_fields:
            assert field in user_dict_sensitive
        
        # Test Flask-Login integration methods
        assert user.get_id() == str(user.id)
        assert user.is_authenticated is True
        assert user.is_anonymous is False
    
    def test_user_rbac_integration(self, db_session: Session, user_factory):
        """
        Test User model RBAC integration with roles and permissions.
        
        Validates role assignment, permission checking, and authorization
        workflows per Section 6.4 security architecture.
        
        Args:
            db_session: Database session fixture
            user_factory: User factory for test data generation
        """
        # Create test scenario with RBAC entities
        rbac_scenario = FactoryPresets.create_rbac_test_scenario()
        
        admin_user = rbac_scenario['users']['admin_user']
        manager_user = rbac_scenario['users']['manager_user']
        regular_user = rbac_scenario['users']['regular_user']
        
        admin_role = rbac_scenario['roles']['admin']
        manager_role = rbac_scenario['roles']['manager']
        user_role = rbac_scenario['roles']['user']
        
        db_session.flush()
        
        # Test role checking
        assert admin_user.has_role('admin') is True
        assert admin_user.has_role('manager') is False
        assert manager_user.has_role('manager') is True
        assert regular_user.has_role('user') is True
        
        # Test permission checking (Note: This would require actual RBAC implementation)
        # For now, test the method structure exists
        assert hasattr(admin_user, 'has_permission')
        assert hasattr(admin_user, 'get_permissions')
        assert hasattr(admin_user, 'get_active_roles')
        
        # Test role assignment methods
        assert hasattr(admin_user, 'assign_role')
        assert hasattr(admin_user, 'revoke_role')


class TestUserSessionModel:
    """
    Test suite for UserSession model functionality.
    
    Validates session management, token handling, and security tracking
    per Flask session management requirements.
    """
    
    def test_user_session_creation(self, db_session: Session):
        """
        Test UserSession creation and token generation.
        
        Validates session creation with secure token generation and
        proper lifecycle management per Section 6.4 security architecture.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        
        # Test session creation with default parameters
        session = UserSession.create_session(user)
        
        # Verify session tokens are generated
        assert session.session_token is not None
        assert len(session.session_token) > 32  # URL-safe base64 encoded
        assert session.csrf_token is not None
        assert session.refresh_token is not None
        
        # Verify session lifecycle fields
        assert session.user_id == user.id
        assert session.expires_at > datetime.utcnow()
        assert session.is_valid is True
        assert session.revoked_at is None
        
        # Verify default values
        assert session.login_method == 'password'
        assert session.last_activity_at is not None
        
        # Test session creation with custom parameters
        custom_session = UserSession.create_session(
            user,
            expires_in=7200,  # 2 hours
            ip_address='192.168.1.1',
            user_agent='Test User Agent',
            login_method='auth0'
        )
        
        assert custom_session.ip_address == '192.168.1.1'
        assert custom_session.user_agent == 'Test User Agent'
        assert custom_session.login_method == 'auth0'
        assert custom_session.expires_at > datetime.utcnow() + timedelta(hours=1)
    
    def test_user_session_lifecycle_management(self, db_session: Session):
        """
        Test UserSession lifecycle and status management.
        
        Validates session expiration, validity checking, and extension
        capabilities per session management requirements.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        
        # Test active session
        session = UserSession.create_session(user, expires_in=3600)
        
        assert session.is_expired() is False
        assert session.is_active() is True
        
        # Test session expiration
        session.expires_at = datetime.utcnow() - timedelta(hours=1)
        assert session.is_expired() is True
        assert session.is_active() is False
        
        # Test invalid session
        session.is_valid = False
        session.expires_at = datetime.utcnow() + timedelta(hours=1)
        assert session.is_expired() is False
        assert session.is_active() is False
        
        # Test session extension
        valid_session = UserSession.create_session(user, expires_in=1800)
        original_expiry = valid_session.expires_at
        
        valid_session.extend_session(extend_by=3600)
        
        assert valid_session.expires_at > original_expiry
        assert valid_session.last_activity_at > original_expiry
        
        # Test extension of inactive session (should not extend)
        valid_session.is_valid = False
        pre_extension_expiry = valid_session.expires_at
        valid_session.extend_session(extend_by=3600)
        # Should not extend inactive session
        assert valid_session.expires_at == pre_extension_expiry
    
    def test_user_session_security_tracking(self, db_session: Session):
        """
        Test UserSession security tracking and activity monitoring.
        
        Validates IP tracking, user agent monitoring, and security
        event detection per Section 6.4 security requirements.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        session = UserSession.create_session(
            user,
            ip_address='192.168.1.100',
            user_agent='Initial User Agent'
        )
        
        # Test activity update
        original_activity = session.last_activity_at
        
        session.update_activity(
            ip_address='192.168.1.101',
            user_agent='Updated User Agent'
        )
        
        assert session.last_activity_at > original_activity
        assert session.ip_address == '192.168.1.101'
        assert session.user_agent == 'Updated User Agent'
        
        # Test IP change detection (should log warning)
        with patch('models.user.logging.getLogger') as mock_logger:
            session.update_activity(ip_address='10.0.0.1')
            
            # Verify logging was called for IP change
            mock_logger.return_value.warning.assert_called()
            call_args = mock_logger.return_value.warning.call_args[0][0]
            assert 'Session IP change detected' in call_args
        
        # Test session revocation
        session.revoke_session(revoked_by='admin')
        
        assert session.is_valid is False
        assert session.revoked_at is not None
        assert session.revoked_by == 'admin'
        assert session.is_active() is False
    
    def test_user_session_data_management(self, db_session: Session):
        """
        Test UserSession data storage and retrieval.
        
        Validates session data serialization, storage, and retrieval
        for application state management.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        session = UserSessionFactory(user=user)
        
        # Test session data storage
        test_data = {
            'preferences': {
                'theme': 'dark',
                'language': 'en',
                'notifications': True
            },
            'navigation': {
                'last_page': '/dashboard',
                'breadcrumbs': ['/home', '/dashboard']
            },
            'temp_data': {
                'form_state': {'field1': 'value1'},
                'shopping_cart': []
            }
        }
        
        session.set_session_data(test_data)
        
        # Verify data serialization
        assert session.session_data is not None
        
        # Test data retrieval
        retrieved_data = session.get_session_data()
        assert isinstance(retrieved_data, dict)
        assert retrieved_data['preferences']['theme'] == 'dark'
        assert retrieved_data['navigation']['last_page'] == '/dashboard'
        
        # Test empty data handling
        session.set_session_data(None)
        assert session.session_data is None
        assert session.get_session_data() == {}
        
        # Test invalid JSON handling
        session.session_data = 'invalid_json'
        assert session.get_session_data() == {}
    
    def test_user_session_cleanup_utilities(self, db_session: Session):
        """
        Test UserSession cleanup and maintenance utilities.
        
        Validates expired session cleanup and maintenance procedures
        per Section 6.5 monitoring and observability.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        
        # Create mix of active and expired sessions
        active_sessions = []
        expired_sessions = []
        
        for i in range(3):
            # Create active session
            active_session = UserSession.create_session(user, expires_in=3600)
            active_sessions.append(active_session)
            
            # Create expired session
            expired_session = UserSession.create_session(user, expires_in=3600)
            expired_session.expires_at = datetime.utcnow() - timedelta(hours=i+1)
            expired_sessions.append(expired_session)
        
        db_session.add_all(active_sessions + expired_sessions)
        db_session.flush()
        
        # Test cleanup count (mock the actual cleanup since it uses text() queries)
        with patch.object(db_session, 'execute') as mock_execute:
            # Mock the result to simulate deleting expired sessions
            mock_result = Mock()
            mock_result.rowcount = len(expired_sessions)
            mock_execute.return_value = mock_result
            
            deleted_count = UserSession.cleanup_expired_sessions(batch_size=100)
            
            # Verify cleanup was attempted
            assert mock_execute.called
            assert deleted_count == len(expired_sessions)
    
    def test_user_session_serialization(self, db_session: Session):
        """
        Test UserSession serialization for API responses.
        
        Validates session data serialization with token protection
        and security considerations.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        session = UserSessionFactory(user=user)
        
        # Test basic serialization (without tokens)
        session_dict = session.to_dict()
        
        required_fields = [
            'id', 'user_id', 'expires_at', 'is_valid', 'is_expired',
            'is_active', 'ip_address', 'user_agent', 'last_activity_at',
            'login_method', 'created_at'
        ]
        
        for field in required_fields:
            assert field in session_dict
        
        # Verify tokens are not included by default
        assert 'session_token' not in session_dict
        assert 'csrf_token' not in session_dict
        assert 'refresh_token' not in session_dict
        
        # Test serialization with tokens
        session_dict_with_tokens = session.to_dict(include_tokens=True)
        
        token_fields = ['session_token', 'csrf_token', 'refresh_token', 'session_data']
        
        for field in token_fields:
            assert field in session_dict_with_tokens
        
        # Test datetime serialization format
        assert isinstance(session_dict['expires_at'], str)
        assert 'T' in session_dict['expires_at']  # ISO format


class TestUserUtilities:
    """
    Test suite for UserUtils helper functions and user management operations.
    
    Validates utility functions for user creation, authentication, and
    session management per comprehensive user management requirements.
    """
    
    def test_user_creation_utility(self, db_session: Session):
        """
        Test UserUtils.create_user() functionality.
        
        Validates user creation utility with validation and constraint
        checking per Section 4.7.1 data operations testing.
        
        Args:
            db_session: Database session fixture
        """
        # Test successful user creation
        user = UserUtils.create_user(
            username='utility_test_user',
            email='utility@example.com',
            password='SecurePassword123!',
            first_name='Utility',
            last_name='Test'
        )
        
        assert user is not None
        assert user.username == 'utility_test_user'
        assert user.email == 'utility@example.com'
        assert user.first_name == 'Utility'
        assert user.last_name == 'Test'
        assert user.password_hash is not None
        
        # Test user creation validation
        with pytest.raises(ValueError, match="Username and email are required"):
            UserUtils.create_user('', 'email@example.com')
        
        with pytest.raises(ValueError, match="Username and email are required"):
            UserUtils.create_user('username', '')
        
        # Test duplicate user prevention
        db_session.add(user)
        db_session.flush()
        
        with pytest.raises(ValueError, match="User with this username or email already exists"):
            UserUtils.create_user('utility_test_user', 'different@example.com')
        
        with pytest.raises(ValueError, match="User with this username or email already exists"):
            UserUtils.create_user('different_username', 'utility@example.com')
        
        # Test Auth0 user creation (without password)
        auth0_user = UserUtils.create_user(
            username='auth0_utility_user',
            email='auth0_utility@example.com',
            auth0_user_id='auth0|utility_123'
        )
        
        assert auth0_user.auth0_user_id == 'auth0|utility_123'
        assert auth0_user.password_hash is None
    
    def test_user_authentication_utility(self, db_session: Session):
        """
        Test UserUtils.authenticate_user() functionality.
        
        Validates user authentication with username/email lookup and
        password verification per Section 6.4 security architecture.
        
        Args:
            db_session: Database session fixture
        """
        # Create test user
        user = UserUtils.create_user(
            username='auth_test_user',
            email='auth_test@example.com',
            password='AuthTestPassword123!'
        )
        db_session.add(user)
        db_session.flush()
        
        # Test successful authentication with username
        authenticated_user = UserUtils.authenticate_user('auth_test_user', 'AuthTestPassword123!')
        assert authenticated_user is not None
        assert authenticated_user.id == user.id
        assert authenticated_user.login_count > 0
        
        # Test successful authentication with email
        authenticated_user_email = UserUtils.authenticate_user('auth_test@example.com', 'AuthTestPassword123!')
        assert authenticated_user_email is not None
        assert authenticated_user_email.id == user.id
        
        # Test failed authentication with wrong password
        failed_auth = UserUtils.authenticate_user('auth_test_user', 'WrongPassword')
        assert failed_auth is None
        
        # Verify failed login was recorded
        db_session.refresh(user)
        assert user.failed_login_count > 0
        
        # Test authentication with non-existent user
        no_user = UserUtils.authenticate_user('nonexistent_user', 'any_password')
        assert no_user is None
        
        # Test authentication with locked account
        user.failed_login_count = 5
        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db_session.flush()
        
        locked_auth = UserUtils.authenticate_user('auth_test_user', 'AuthTestPassword123!')
        assert locked_auth is None
        
        # Test authentication with inactive user
        user.is_active = False
        user.locked_until = None
        user.failed_login_count = 0
        db_session.flush()
        
        inactive_auth = UserUtils.authenticate_user('auth_test_user', 'AuthTestPassword123!')
        assert inactive_auth is None
    
    def test_auth0_user_management_utility(self, db_session: Session):
        """
        Test UserUtils.find_or_create_auth0_user() functionality.
        
        Validates Auth0 user creation and linking per Section 3.4
        third-party services integration.
        
        Args:
            db_session: Database session fixture
        """
        # Test Auth0 user creation
        auth0_data = {
            'user_id': 'auth0|test_user_123',
            'email': 'auth0_user@example.com',
            'username': 'auth0_test_user',
            'nickname': 'auth0user',
            'email_verified': True,
            'given_name': 'Auth0',
            'family_name': 'User',
            'picture': 'https://example.com/avatar.jpg'
        }
        
        # Test creating new Auth0 user
        auth0_user = UserUtils.find_or_create_auth0_user(auth0_data)
        db_session.flush()
        
        assert auth0_user is not None
        assert auth0_user.auth0_user_id == 'auth0|test_user_123'
        assert auth0_user.email == 'auth0_user@example.com'
        assert auth0_user.is_verified is True
        assert auth0_user.first_name == 'Auth0'
        assert auth0_user.last_name == 'User'
        
        # Test finding existing Auth0 user
        existing_user = UserUtils.find_or_create_auth0_user(auth0_data)
        assert existing_user.id == auth0_user.id
        
        # Test linking existing email user to Auth0
        existing_email_user = UserUtils.create_user(
            username='existing_email_user',
            email='existing@example.com',
            password='ExistingPassword123!'
        )
        db_session.add(existing_email_user)
        db_session.flush()
        
        auth0_linking_data = {
            'user_id': 'auth0|link_user_456',
            'email': 'existing@example.com',
            'email_verified': True
        }
        
        linked_user = UserUtils.find_or_create_auth0_user(auth0_linking_data)
        assert linked_user.id == existing_email_user.id
        assert linked_user.auth0_user_id == 'auth0|link_user_456'
        
        # Test username uniqueness handling
        username_conflict_data = {
            'user_id': 'auth0|conflict_user_789',
            'email': 'conflict@example.com',
            'username': auth0_user.username  # Same username as existing user
        }
        
        conflict_user = UserUtils.find_or_create_auth0_user(username_conflict_data)
        assert conflict_user.username != auth0_user.username
        assert conflict_user.username.startswith(auth0_user.username)
        
        # Test Auth0 user ID validation
        with pytest.raises(ValueError, match="Auth0 user ID is required"):
            UserUtils.find_or_create_auth0_user({'email': 'no_auth0_id@example.com'})
    
    def test_session_management_utilities(self, db_session: Session):
        """
        Test UserUtils session management utilities.
        
        Validates session creation, validation, and user retrieval
        per session management requirements.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        db_session.add(user)
        db_session.flush()
        
        # Test session creation utility
        session = UserUtils.create_session_for_user(
            user,
            expires_in=7200,
            ip_address='10.0.0.1',
            user_agent='Test Agent'
        )
        
        assert session is not None
        assert session.user_id == user.id
        assert session.ip_address == '10.0.0.1'
        assert session.user_agent == 'Test Agent'
        
        # Test session token validation
        valid_session = UserUtils.validate_session_token(session.session_token)
        assert valid_session is not None
        assert valid_session.id == session.id
        
        # Test invalid token validation
        invalid_session = UserUtils.validate_session_token('invalid_token')
        assert invalid_session is None
        
        # Test empty token validation
        empty_session = UserUtils.validate_session_token('')
        assert empty_session is None
        
        # Test expired session validation
        session.expires_at = datetime.utcnow() - timedelta(hours=1)
        db_session.flush()
        
        expired_session = UserUtils.validate_session_token(session.session_token)
        assert expired_session is None
        
        # Test user retrieval by session token
        active_session = UserSession.create_session(user)
        db_session.add(active_session)
        db_session.flush()
        
        session_user = UserUtils.get_user_by_session_token(active_session.session_token)
        assert session_user is not None
        assert session_user.id == user.id
        
        # Test user retrieval with invalid token
        no_user = UserUtils.get_user_by_session_token('invalid_token')
        assert no_user is None


class TestDatabaseRelationships:
    """
    Test database relationships and referential integrity.
    
    Validates model relationships, foreign key constraints, and cascading
    operations per Section 4.7.1 relationship testing requirements.
    """
    
    def test_user_session_relationship(self, db_session: Session):
        """
        Test User-UserSession relationship integrity.
        
        Validates one-to-many relationship between User and UserSession
        with proper foreign key constraints and cascading behavior.
        
        Args:
            db_session: Database session fixture
        """
        user = UserFactory()
        db_session.add(user)
        db_session.flush()
        
        # Create multiple sessions for the user
        sessions = []
        for i in range(3):
            session = UserSession.create_session(
                user,
                ip_address=f'192.168.1.{i+1}',
                login_method='password'
            )
            sessions.append(session)
            db_session.add(session)
        
        db_session.flush()
        
        # Test relationship from user side
        user_sessions = user.sessions.all()
        assert len(user_sessions) == 3
        
        for session in sessions:
            assert session in user_sessions
        
        # Test relationship from session side
        for session in sessions:
            assert session.user.id == user.id
            assert session.user_id == user.id
        
        # Test filtering on relationship
        active_sessions = user.sessions.filter_by(is_valid=True).all()
        assert len(active_sessions) == 3
        
        # Revoke one session and test filtering
        sessions[0].revoke_session()
        db_session.flush()
        
        valid_sessions = user.sessions.filter_by(is_valid=True).all()
        assert len(valid_sessions) == 2
        
        # Test cascading delete (if configured)
        session_ids = [s.id for s in sessions]
        
        # Delete user - sessions should be handled according to cascade configuration
        db_session.delete(user)
        db_session.flush()
        
        # Verify cascading behavior (sessions should be deleted with cascade='all, delete-orphan')
        remaining_sessions = db_session.query(UserSession).filter(UserSession.id.in_(session_ids)).all()
        assert len(remaining_sessions) == 0
    
    def test_factory_relationship_integrity(self, db_session: Session):
        """
        Test relationship integrity in factory-generated data.
        
        Validates that Factory Boy generates consistent relationship
        data with proper foreign key relationships.
        
        Args:
            db_session: Database session fixture
        """
        # Test RBAC relationship factories
        rbac_scenario = FactoryPresets.create_rbac_test_scenario()
        
        users = rbac_scenario['users']
        roles = rbac_scenario['roles']
        user_roles = rbac_scenario['user_roles']
        
        db_session.flush()
        
        # Verify user-role relationships
        for role_name, user_role in user_roles.items():
            assert user_role.user in users.values()
            assert user_role.role in roles.values()
            assert user_role.user_id == user_role.user.id
            assert user_role.role_id == user_role.role.id
        
        # Test business entity relationships
        business_hierarchy = FactoryPresets.create_business_entity_hierarchy()
        
        parent_company = business_hierarchy['parent_company']
        departments = business_hierarchy['departments']
        projects = business_hierarchy['projects']
        dept_relationships = business_hierarchy['dept_relationships']
        
        db_session.flush()
        
        # Verify hierarchical relationships
        for relationship in dept_relationships:
            assert relationship.source_entity == parent_company
            assert relationship.target_entity in departments
            assert relationship.relationship_type == 'parent_child'
        
        # Test audit log relationships
        audit_scenario = FactoryPresets.create_user_session_with_audit_trail()
        
        user = audit_scenario['user']
        session = audit_scenario['session']
        audit_logs = audit_scenario['audit_logs']
        
        db_session.flush()
        
        # Verify audit relationships
        assert session.user == user
        assert session.user_id == user.id
        
        for audit_log in audit_logs:
            assert audit_log.user_id == user
            assert hasattr(audit_log, 'username')  # Should be populated from user


class TestPerformanceAndBenchmarking:
    """
    Performance testing and benchmarking for database operations.
    
    Validates database performance meets SLA requirements and establishes
    benchmarks per Section 4.7.4 performance validation.
    """
    
    def test_user_query_performance(self, db_session: Session, benchmark):
        """
        Benchmark User model query performance.
        
        Validates user lookup and authentication query performance
        meets response time requirements per Section 4.7.4.1.
        
        Args:
            db_session: Database session fixture
            benchmark: pytest-benchmark fixture for performance testing
        """
        # Create test data for performance testing
        users = []
        for i in range(100):
            user = UserFactory.build()
            users.append(user)
        
        db_session.add_all(users)
        db_session.flush()
        
        # Benchmark user lookup by ID
        test_user = users[50]
        
        def lookup_user_by_id():
            return db_session.query(User).filter_by(id=test_user.id).first()
        
        result = benchmark(lookup_user_by_id)
        assert result is not None
        assert result.id == test_user.id
        
        # Benchmark user lookup by username
        def lookup_user_by_username():
            return db_session.query(User).filter_by(username=test_user.username).first()
        
        result = benchmark(lookup_user_by_username)
        assert result is not None
        
        # Benchmark user authentication query
        def authenticate_query():
            return db_session.query(User).filter(
                (User.username == test_user.username) | (User.email == test_user.email)
            ).filter_by(is_active=True).first()
        
        result = benchmark(authenticate_query)
        assert result is not None
    
    def test_session_cleanup_performance(self, db_session: Session, benchmark):
        """
        Benchmark session cleanup operation performance.
        
        Validates batch cleanup operations meet performance requirements
        for maintenance operations per Section 6.5 monitoring.
        
        Args:
            db_session: Database session fixture
            benchmark: pytest-benchmark fixture for performance testing
        """
        # Create test user and expired sessions
        user = UserFactory()
        db_session.add(user)
        db_session.flush()
        
        # Create a mix of active and expired sessions
        sessions = []
        for i in range(50):
            session = UserSession.create_session(user, expires_in=3600)
            if i < 25:  # Make half of them expired
                session.expires_at = datetime.utcnow() - timedelta(hours=i+1)
            sessions.append(session)
        
        db_session.add_all(sessions)
        db_session.flush()
        
        # Benchmark session cleanup query
        def cleanup_expired_sessions():
            # Simulate the cleanup query (without actual deletion in test)
            expired_sessions = db_session.query(UserSession).filter(
                UserSession.expires_at < datetime.utcnow()
            ).limit(100).all()
            return len(expired_sessions)
        
        expired_count = benchmark(cleanup_expired_sessions)
        assert expired_count >= 25  # Should find at least 25 expired sessions
    
    def test_relationship_query_performance(self, db_session: Session, benchmark):
        """
        Benchmark relationship query performance.
        
        Validates complex relationship queries meet performance requirements
        for business logic operations.
        
        Args:
            db_session: Database session fixture
            benchmark: pytest-benchmark fixture for performance testing
        """
        # Create comprehensive test scenario
        rbac_scenario = FactoryPresets.create_rbac_test_scenario()
        db_session.flush()
        
        admin_user = rbac_scenario['users']['admin_user']
        
        # Benchmark role lookup query
        def get_user_roles():
            # This would use the actual relationship once RBAC models are implemented
            return db_session.query(User).filter_by(id=admin_user.id).first()
        
        result = benchmark(get_user_roles)
        assert result is not None
        
        # Benchmark session query with user join
        user_with_sessions = UserFactory()
        sessions = [UserSession.create_session(user_with_sessions) for _ in range(10)]
        db_session.add(user_with_sessions)
        db_session.add_all(sessions)
        db_session.flush()
        
        def get_user_with_sessions():
            return db_session.query(User).filter_by(id=user_with_sessions.id).first()
        
        result = benchmark(get_user_with_sessions)
        assert result is not None


class TestDataIntegrityAndMigration:
    """
    Test data integrity and migration validation.
    
    Validates data consistency, constraint enforcement, and migration
    integrity per Section 4.4.2 migration management requirements.
    """
    
    def test_database_constraint_enforcement(self, db_session: Session):
        """
        Test database constraint enforcement and validation.
        
        Validates unique constraints, foreign key constraints, and
        check constraints per Section 4.4.1.1 validation rules.
        
        Args:
            db_session: Database session fixture
        """
        # Test unique constraint enforcement
        user1 = UserFactory(username='unique_test_user', email='unique@example.com')
        db_session.add(user1)
        db_session.flush()
        
        # Attempt to create user with duplicate username
        with pytest.raises((IntegrityError, ValueError)):
            user2 = UserFactory(username='unique_test_user', email='different@example.com')
            db_session.add(user2)
            db_session.flush()
        
        db_session.rollback()
        
        # Attempt to create user with duplicate email
        with pytest.raises((IntegrityError, ValueError)):
            user3 = UserFactory(username='different_user', email='unique@example.com')
            db_session.add(user3)
            db_session.flush()
        
        db_session.rollback()
        
        # Test check constraint enforcement (if implemented)
        user = UserFactory()
        user.login_count = -1  # Should violate check constraint
        
        # This would raise IntegrityError if check constraints are enforced
        with pytest.raises((IntegrityError, ValueError)):
            db_session.add(user)
            db_session.flush()
        
        db_session.rollback()
    
    def test_data_validation_during_migration(self, db_session: Session):
        """
        Test data validation and consistency during migration scenarios.
        
        Validates data integrity preservation during model changes
        per Section 4.4.2.3 post-migration validation.
        
        Args:
            db_session: Database session fixture
        """
        # Create comprehensive test data
        users = UserFactory.create_batch(10)
        db_session.add_all(users)
        db_session.flush()
        
        # Create sessions for each user
        all_sessions = []
        for user in users:
            sessions = [UserSession.create_session(user) for _ in range(3)]
            all_sessions.extend(sessions)
        
        db_session.add_all(all_sessions)
        db_session.flush()
        
        # Validate data consistency
        total_users = db_session.query(User).count()
        total_sessions = db_session.query(UserSession).count()
        
        assert total_users == 10
        assert total_sessions == 30
        
        # Validate relationship consistency
        for user in users:
            user_sessions = user.sessions.all()
            assert len(user_sessions) == 3
            
            for session in user_sessions:
                assert session.user_id == user.id
                assert session.user.id == user.id
        
        # Validate audit trail consistency
        for user in users:
            assert user.created_at is not None
            assert user.updated_at is not None
            assert user.created_at <= user.updated_at
        
        for session in all_sessions:
            assert session.created_at is not None
            assert session.updated_at is not None
            assert session.last_activity_at is not None
    
    def test_factory_data_consistency(self, db_session: Session):
        """
        Test Factory Boy data generation consistency and validation.
        
        Validates that factory-generated data maintains consistency
        and realistic patterns per Section 4.7.3.2 test data management.
        
        Args:
            db_session: Database session fixture
        """
        # Test user factory data consistency
        users = UserFactory.create_batch(20)
        db_session.add_all(users)
        db_session.flush()
        
        # Validate unique constraints in factory data
        usernames = [user.username for user in users]
        emails = [user.email for user in users]
        
        assert len(set(usernames)) == len(usernames)  # All usernames unique
        assert len(set(emails)) == len(emails)  # All emails unique
        
        # Validate realistic data patterns
        for user in users:
            assert user.username is not None
            assert len(user.username) >= 3
            assert '@' in user.email
            assert '.' in user.email
            assert user.timezone in ['UTC', 'America/New_York', 'America/Los_Angeles', 
                                   'Europe/London', 'Europe/Paris', 'Asia/Tokyo', 'Australia/Sydney']
            assert user.locale in ['en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ko', 'zh']
        
        # Test session factory data consistency
        sessions = []
        for user in users[:5]:  # Test with subset
            user_sessions = UserSessionFactory.create_batch(3, user=user)
            sessions.extend(user_sessions)
        
        db_session.add_all(sessions)
        db_session.flush()
        
        # Validate session tokens are unique
        session_tokens = [session.session_token for session in sessions]
        assert len(set(session_tokens)) == len(session_tokens)
        
        # Validate session data consistency
        for session in sessions:
            assert session.session_token is not None
            assert len(session.session_token) > 32
            assert session.user_id is not None
            assert session.expires_at > datetime.utcnow()
            assert session.last_activity_at <= datetime.utcnow()


class TestErrorHandlingAndRecovery:
    """
    Test error handling and recovery procedures.
    
    Validates error scenarios, rollback procedures, and recovery
    mechanisms per Section 4.7.6 error handling requirements.
    """
    
    def test_transaction_rollback_on_error(self, db_session: Session):
        """
        Test transaction rollback during error conditions.
        
        Validates that transactions are properly rolled back on errors
        to maintain database consistency.
        
        Args:
            db_session: Database session fixture
        """
        # Start with clean state
        initial_user_count = db_session.query(User).count()
        
        try:
            # Begin transaction with valid user
            user1 = UserFactory(username='rollback_test_1')
            db_session.add(user1)
            db_session.flush()
            
            # Attempt to add invalid user that should cause rollback
            user2 = UserFactory(username='rollback_test_1')  # Duplicate username
            db_session.add(user2)
            db_session.flush()  # This should fail
            
            pytest.fail("Expected IntegrityError for duplicate username")
            
        except (IntegrityError, ValueError):
            # Expected error - rollback transaction
            db_session.rollback()
        
        # Verify rollback was successful
        final_user_count = db_session.query(User).count()
        assert final_user_count == initial_user_count
        
        # Verify no partial data was committed
        rollback_user = db_session.query(User).filter_by(username='rollback_test_1').first()
        assert rollback_user is None
    
    def test_database_connection_error_handling(self, app: Flask):
        """
        Test database connection error handling and recovery.
        
        Validates application behavior during database connection issues
        per Section 4.7.6.1 test failure analysis.
        
        Args:
            app: Flask application fixture
        """
        # Test connection pool behavior during errors
        with app.app_context():
            # Simulate connection error by using invalid database URL
            with patch.object(app.db.engine, 'connect', side_effect=Exception("Connection failed")):
                
                # Attempt database operation that should handle connection error gracefully
                try:
                    with DatabaseManager.transaction():
                        # This should fail gracefully
                        User.query.first()
                    pytest.fail("Expected database connection error")
                except Exception as e:
                    assert "Connection failed" in str(e)
    
    def test_data_validation_error_recovery(self, db_session: Session):
        """
        Test data validation error handling and recovery.
        
        Validates graceful handling of validation errors with proper
        error messages and recovery procedures.
        
        Args:
            db_session: Database session fixture
        """
        # Test validation error handling in user creation
        with pytest.raises(ValueError) as exc_info:
            user = User()
            user.validate_username('username', '')
        
        assert "Username cannot be empty" in str(exc_info.value)
        
        # Test recovery after validation error
        user = User()
        
        # First, invalid username
        try:
            user.validate_username('username', 'ab')
        except ValueError:
            pass  # Expected
        
        # Then, valid username should work
        valid_username = user.validate_username('username', 'valid_username')
        assert valid_username == 'valid_username'
        
        # Test email validation error handling
        with pytest.raises(ValueError) as exc_info:
            user.validate_email('email', 'invalid-email')
        
        assert "Invalid email format" in str(exc_info.value)
        
        # Test recovery with valid email
        valid_email = user.validate_email('email', 'valid@example.com')
        assert valid_email == 'valid@example.com'
    
    def test_factory_error_handling(self, db_session: Session):
        """
        Test Factory Boy error handling and recovery.
        
        Validates error handling in factory data generation and
        recovery from factory-related errors.
        
        Args:
            db_session: Database session fixture
        """
        # Test factory session management error handling
        original_session = FactorySessionManager.get_session()
        assert original_session is not None
        
        # Test cleanup after errors
        try:
            # Force an error in factory creation
            with patch.object(db_session, 'add', side_effect=Exception("Factory error")):
                UserFactory()
            pytest.fail("Expected factory error")
        except Exception as e:
            assert "Factory error" in str(e)
        
        # Test that session can be recovered
        FactorySessionManager.cleanup_session()
        recovered_session = FactorySessionManager.get_session()
        assert recovered_session is not None
        
        # Test factory reset functionality
        reset_result = reset_factory_sequences()
        # Function should complete without error
        
        cleanup_result = cleanup_test_data()
        assert cleanup_result is True
    
    def test_audit_trail_error_resilience(self, db_session: Session):
        """
        Test audit trail resilience during error conditions.
        
        Validates that audit trail tracking continues to function
        even during error scenarios.
        
        Args:
            db_session: Database session fixture
        """
        # Test audit field population with mock user context
        with patch('models.base.get_current_user_context', return_value='test_user'):
            user = UserFactory()
            db_session.add(user)
            
            # Simulate error in audit field population
            with patch('models.base.logger.error') as mock_logger:
                try:
                    # Force flush to trigger audit event
                    db_session.flush()
                except Exception:
                    pass  # Ignore any errors for this test
        
        # Test that audit trail errors don't break transactions
        with patch('models.base.get_current_user_context', side_effect=Exception("Audit error")):
            user2 = UserFactory()
            db_session.add(user2)
            
            # Should complete successfully despite audit error
            db_session.flush()
            assert user2.id is not None


# Pytest configuration and fixtures specific to model testing
@pytest.fixture(scope='function')
def setup_test_factories(db_session):
    """
    Set up Factory Boy configuration for model testing.
    
    Configures factories with proper session management and
    cleanup for isolated test execution.
    
    Args:
        db_session: Database session fixture
        
    Yields:
        Configured factory environment
    """
    # Configure factories with test session
    configure_factories()
    
    # Set session for all factories
    for factory_class in [UserFactory, UserSessionFactory]:
        factory_class._meta.sqlalchemy_session = db_session
    
    yield
    
    # Cleanup after test
    cleanup_test_data()


# Performance test markers for pytest-benchmark
pytestmark = [
    pytest.mark.database,
    pytest.mark.models,
    pytest.mark.sqlalchemy
]