"""
Comprehensive Unit Tests for Flask-SQLAlchemy Models

This module provides comprehensive unit testing for all Flask-SQLAlchemy models including
User, UserSession, BusinessEntity, EntityRelationship, and base model functionality.
These tests validate model field constraints, relationships, validation rules, and
database operations to ensure complete functional parity with original Node.js data
layer during the Flask migration process.

Key Testing Areas:
- BaseModel functionality with timestamp and primary key validation
- User model with Flask-Login UserMixin integration and authentication testing  
- UserSession model with ItsDangerous token validation and security testing
- BusinessEntity and EntityRelationship models with complex relationship validation
- Database constraint enforcement and validation rule preservation
- Model relationship integrity testing with foreign key constraints and cascade behavior
- Business logic validation to ensure constraint preservation per Feature F-003

Technical Specification References:
- Feature F-003: Database Model Conversion from MongoDB schemas
- Feature F-007: Authentication Mechanism Migration with Flask-Login integration
- Feature F-009: Functionality Parity Validation with 90% code coverage requirement
- Section 4.7.1: Testing and Validation Workflow with pytest-flask 1.3.0
- Section 6.2.2.1: Entity Relationships and Data Models
- Section 6.2.2.2: Database constraint and validation rule preservation

Dependencies:
- pytest-flask 1.3.0: Flask application testing fixtures and database isolation
- Flask-SQLAlchemy 3.1.1: Database ORM functionality and model testing
- Flask-Login: User authentication testing with UserMixin integration
- ItsDangerous: Secure session token validation testing
- Werkzeug: Password hashing and security utilities testing
"""

import pytest
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, Mock
from typing import Dict, Any, List, Optional

# Flask and extension imports for testing
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from itsdangerous import URLSafeTimedSerializer

# Import models for testing
from src.models.base import BaseModel, db
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship

# Import testing utilities and fixtures
from tests.conftest import MockUser


class TestBaseModel:
    """
    Comprehensive test suite for BaseModel functionality including timestamp management,
    primary key patterns, and common utility methods. These tests ensure the foundation
    for all model inheritance follows Flask-SQLAlchemy best practices.
    
    Testing coverage includes:
    - Auto-incrementing primary key validation per Section 6.2.2.2
    - Automatic timestamp population and management (created_at, updated_at)
    - Common utility methods (to_dict, save, delete, create, etc.)
    - Table name generation from class names using snake_case conversion
    - PostgreSQL-optimized field patterns and constraints
    """
    
    def test_base_model_abstract_table(self, app: Flask, db_session):
        """
        Test that BaseModel is properly configured as abstract base class.
        
        Validates that BaseModel cannot be instantiated directly and serves
        only as inheritance base for concrete model implementations.
        """
        with app.app_context():
            # BaseModel should be abstract and not create a table
            assert BaseModel.__abstract__ is True
            assert not hasattr(BaseModel, '__table__')
    
    def test_primary_key_configuration(self, app: Flask, db_session):
        """
        Test auto-incrementing primary key configuration per Section 6.2.2.2.
        
        Validates that all models inherit proper primary key patterns with
        auto-incrementing integers for optimal PostgreSQL join performance.
        """
        with app.app_context():
            # Create test user to validate primary key behavior
            user = User(
                username='test_pk_user',
                email='pk_test@example.com',
                password='TestPassword123!'
            )
            
            # Primary key should be None before saving
            assert user.id is None
            
            # Save and verify auto-increment behavior
            user.save()
            assert user.id is not None
            assert isinstance(user.id, int)
            assert user.id > 0
            
            # Create second user to verify increment
            user2 = User(
                username='test_pk_user2',
                email='pk_test2@example.com',
                password='TestPassword123!'
            )
            user2.save()
            
            assert user2.id > user.id
    
    def test_timestamp_auto_population(self, app: Flask, db_session):
        """
        Test automatic timestamp population per database design requirements.
        
        Validates that created_at and updated_at fields are automatically
        populated with UTC timestamps during model creation and updates.
        """
        with app.app_context():
            # Record time before creation
            before_creation = datetime.now(timezone.utc)
            
            # Create user and verify timestamp population
            user = User(
                username='timestamp_test',
                email='timestamp@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            after_creation = datetime.now(timezone.utc)
            
            # Verify created_at timestamp
            assert user.created_at is not None
            assert isinstance(user.created_at, datetime)
            assert before_creation <= user.created_at <= after_creation
            assert user.created_at.tzinfo is not None  # UTC timezone
            
            # Verify updated_at timestamp
            assert user.updated_at is not None
            assert isinstance(user.updated_at, datetime)
            assert before_creation <= user.updated_at <= after_creation
            
            # Test timestamp update on modification
            original_updated_at = user.updated_at
            import time
            time.sleep(0.01)  # Small delay to ensure timestamp difference
            
            user.first_name = 'Updated'
            user.save()
            
            assert user.updated_at > original_updated_at
            assert user.created_at != user.updated_at  # Should be different after update
    
    def test_model_string_representation(self, app: Flask, db_session):
        """
        Test model string representation for debugging and logging.
        
        Validates that models provide consistent and informative string
        representations for enterprise-grade debugging patterns.
        """
        with app.app_context():
            user = User(
                username='repr_test',
                email='repr@example.com', 
                password='TestPassword123!'
            )
            user.save()
            
            # Test __repr__ method
            repr_str = repr(user)
            assert '<User(' in repr_str
            assert f'id={user.id}' in repr_str
            assert 'username=\'repr_test\'' in repr_str
            assert 'email=\'repr@example.com\'' in repr_str
            
            # Test __str__ method for display names
            str_repr = str(user)
            assert 'repr_test' in str_repr
    
    def test_to_dict_serialization(self, app: Flask, db_session):
        """
        Test model-to-dictionary serialization for API responses.
        
        Validates consistent serialization methods across all models with
        proper datetime formatting and optional field inclusion control.
        """
        with app.app_context():
            user = User(
                username='dict_test',
                email='dict@example.com',
                password='TestPassword123!',
                first_name='Dict',
                last_name='Test'
            )
            user.save()
            
            # Test basic to_dict functionality
            user_dict = user.to_dict()
            
            # Verify required fields
            assert 'id' in user_dict
            assert 'username' in user_dict
            assert 'email' in user_dict
            assert 'first_name' in user_dict
            assert 'last_name' in user_dict
            assert 'is_active' in user_dict
            assert 'created_at' in user_dict
            assert 'updated_at' in user_dict
            
            # Verify data types and values
            assert user_dict['id'] == user.id
            assert user_dict['username'] == 'dict_test'
            assert user_dict['email'] == 'dict@example.com'
            assert user_dict['is_active'] is True
            
            # Verify datetime serialization
            assert isinstance(user_dict['created_at'], str)
            assert isinstance(user_dict['updated_at'], str)
            
            # Test timestamp exclusion
            base_dict = user.to_dict(include_timestamps=False)
            assert 'created_at' not in base_dict
            assert 'updated_at' not in base_dict
    
    def test_update_from_dict_functionality(self, app: Flask, db_session):
        """
        Test model update from dictionary data with field validation.
        
        Validates safe model updating with automatic timestamp updates
        and field access control for security.
        """
        with app.app_context():
            user = User(
                username='update_test',
                email='update@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            original_updated_at = user.updated_at
            original_created_at = user.created_at
            
            # Test basic field updates
            update_data = {
                'first_name': 'Updated',
                'last_name': 'User',
                'is_active': False
            }
            
            import time
            time.sleep(0.01)  # Ensure timestamp difference
            user.update_from_dict(update_data)
            
            # Verify field updates
            assert user.first_name == 'Updated'
            assert user.last_name == 'User'
            assert user.is_active is False
            
            # Verify timestamp behavior
            assert user.updated_at > original_updated_at
            assert user.created_at == original_created_at  # Should not change
            
            # Test restricted field updates
            restricted_data = {
                'id': 999,  # Should be ignored
                'created_at': datetime.now(timezone.utc),  # Should be ignored
                'first_name': 'Allowed'
            }
            
            user.update_from_dict(restricted_data)
            assert user.id != 999  # ID should not change
            assert user.created_at == original_created_at  # Should not change
            assert user.first_name == 'Allowed'  # Should be updated
            
            # Test allowed fields restriction
            allowed_fields = {'last_name'}
            user.update_from_dict({'first_name': 'Blocked', 'last_name': 'Allowed'}, allowed_fields)
            assert user.first_name == 'Allowed'  # Should not change
            assert user.last_name == 'Allowed'  # Should change
    
    def test_model_save_and_delete_methods(self, app: Flask, db_session):
        """
        Test model persistence methods with transaction control.
        
        Validates save and delete operations with optional commit control
        and proper transaction boundary management.
        """
        with app.app_context():
            user = User(
                username='persist_test',
                email='persist@example.com',
                password='TestPassword123!'
            )
            
            # Test save without commit
            user.save(commit=False)
            assert user.id is not None  # Should have ID from session
            
            # Verify not committed to database
            db_user = User.query.filter_by(username='persist_test').first()
            assert db_user is None  # Should not exist in committed state
            
            # Commit and verify persistence
            db.session.commit()
            db_user = User.query.filter_by(username='persist_test').first()
            assert db_user is not None
            assert db_user.username == 'persist_test'
            
            # Test delete without commit
            user.delete(commit=False)
            db_user = User.query.filter_by(username='persist_test').first()
            assert db_user is not None  # Should still exist before commit
            
            # Commit deletion
            db.session.commit()
            db_user = User.query.filter_by(username='persist_test').first()
            assert db_user is None  # Should be deleted
    
    def test_model_class_methods(self, app: Flask, db_session):
        """
        Test model class methods for instance creation and retrieval.
        
        Validates create, get_by_id, and exists class methods for
        consistent model access patterns across the application.
        """
        with app.app_context():
            # Test create class method
            user = User.create(
                username='class_test',
                email='class@example.com',
                password='TestPassword123!'
            )
            
            assert user.id is not None
            assert user.username == 'class_test'
            
            # Test get_by_id class method
            retrieved_user = User.get_by_id(user.id)
            assert retrieved_user is not None
            assert retrieved_user.id == user.id
            assert retrieved_user.username == 'class_test'
            
            # Test get_by_id with non-existent ID
            non_existent = User.get_by_id(99999)
            assert non_existent is None
            
            # Test exists class method
            assert User.exists(user.id) is True
            assert User.exists(99999) is False
    
    def test_table_name_generation(self, app: Flask, db_session):
        """
        Test automatic table name generation from class names.
        
        Validates snake_case conversion from CamelCase class names
        following PostgreSQL naming conventions.
        """
        with app.app_context():
            # Test various model table names
            assert User.__tablename__ == 'users'
            assert UserSession.__tablename__ == 'user_sessions'
            assert BusinessEntity.__tablename__ == 'business_entities'
            assert EntityRelationship.__tablename__ == 'entity_relationships'


class TestUserModel:
    """
    Comprehensive test suite for User model with Flask-Login UserMixin integration,
    authentication functionality, and security features. These tests ensure complete
    functional parity with original Node.js user authentication patterns.
    
    Testing coverage includes:
    - Flask-Login UserMixin integration per Feature F-007
    - Werkzeug password hashing and verification per Section 4.6.1
    - User validation rules (username, email format validation)
    - Account security features (account locking, password reset, email verification)
    - User relationship mapping to UserSession and BusinessEntity models
    - Authentication tracking and security monitoring
    """
    
    def test_user_creation_with_validation(self, app: Flask, db_session):
        """
        Test user creation with comprehensive field validation.
        
        Validates username and email format validation, password requirements,
        and proper model initialization with security defaults.
        """
        with app.app_context():
            # Test successful user creation
            user = User(
                username='valid_user',
                email='valid@example.com',
                password='SecurePassword123!',
                first_name='Valid',
                last_name='User'
            )
            user.save()
            
            assert user.id is not None
            assert user.username == 'valid_user'
            assert user.email == 'valid@example.com'
            assert user.first_name == 'Valid'
            assert user.last_name == 'User'
            assert user.is_active is True
            assert user.is_verified is False  # Default value
            assert user.is_admin is False  # Default value
            assert user.failed_login_attempts == 0
            assert user.password_hash is not None
            assert user.password_hash != 'SecurePassword123!'  # Should be hashed
    
    def test_username_validation(self, app: Flask, db_session):
        """
        Test username validation rules per business requirements.
        
        Validates username format, length constraints, character restrictions,
        and reserved username prevention.
        """
        with app.app_context():
            # Test valid usernames
            valid_usernames = [
                'validuser',
                'valid_user',
                'valid-user',
                'valid.user',
                'user123',
                'a1b2c3'
            ]
            
            for username in valid_usernames:
                try:
                    user = User(
                        username=username,
                        email=f'{username}@example.com',
                        password='TestPassword123!'
                    )
                    user.save()
                    assert user.username == username.lower()  # Should be normalized
                    user.delete()  # Cleanup
                except Exception as e:
                    pytest.fail(f"Valid username '{username}' should not raise exception: {e}")
            
            # Test invalid usernames
            invalid_usernames = [
                '',  # Empty
                'ab',  # Too short
                'a' * 81,  # Too long
                'user@name',  # Invalid character
                'user name',  # Space
                '.username',  # Starts with period
                'username.',  # Ends with period
                'user..name',  # Consecutive periods
                'admin',  # Reserved
                'root',  # Reserved
                'user#name',  # Invalid character
            ]
            
            for username in invalid_usernames:
                with pytest.raises(ValueError):
                    User(
                        username=username,
                        email='test@example.com',
                        password='TestPassword123!'
                    )
    
    def test_email_validation(self, app: Flask, db_session):
        """
        Test email address validation per security requirements.
        
        Validates email format, length constraints, domain validation,
        and email normalization patterns.
        """
        with app.app_context():
            # Test valid email addresses
            valid_emails = [
                'user@example.com',
                'user.name@example.com',
                'user+tag@example.com',
                'user123@example123.com',
                'user@subdomain.example.com',
                'test.email+tag@domain.co.uk'
            ]
            
            for email in valid_emails:
                try:
                    user = User(
                        username=f'user{hash(email) % 1000}',
                        email=email,
                        password='TestPassword123!'
                    )
                    user.save()
                    assert user.email == email.lower()  # Should be normalized
                    user.delete()  # Cleanup
                except Exception as e:
                    pytest.fail(f"Valid email '{email}' should not raise exception: {e}")
            
            # Test invalid email addresses
            invalid_emails = [
                '',  # Empty
                'invalid',  # No @
                '@example.com',  # No local part
                'user@',  # No domain
                'user@.com',  # Invalid domain
                'user.@example.com',  # Ends with period
                '.user@example.com',  # Starts with period
                'user..name@example.com',  # Consecutive periods
                'a' * 65 + '@example.com',  # Local part too long
                'user@' + 'a' * 250 + '.com',  # Domain too long
                'user@example',  # No TLD
            ]
            
            for email in invalid_emails:
                with pytest.raises(ValueError):
                    User(
                        username='testuser',
                        email=email,
                        password='TestPassword123!'
                    )
    
    def test_password_hashing_and_verification(self, app: Flask, db_session):
        """
        Test password hashing with Werkzeug security utilities per Section 4.6.1.
        
        Validates PBKDF2-SHA256 password hashing, verification, and password
        strength requirements for authentication security.
        """
        with app.app_context():
            password = 'SecurePassword123!'
            user = User(
                username='password_test',
                email='password@example.com',
                password=password
            )
            user.save()
            
            # Verify password is hashed
            assert user.password_hash is not None
            assert user.password_hash != password
            assert user.password_hash.startswith('pbkdf2:sha256:')
            
            # Test password verification
            assert user.check_password(password) is True
            assert user.check_password('WrongPassword') is False
            assert user.check_password('') is False
            
            # Test password change
            new_password = 'NewSecurePassword456!'
            user.set_password(new_password)
            
            assert user.check_password(password) is False  # Old password invalid
            assert user.check_password(new_password) is True  # New password valid
            
            # Test password strength requirements
            weak_passwords = [
                '',  # Empty
                'short',  # Too short
                'a' * 130,  # Too long
                'password',  # Too simple
                'PASSWORD',  # No variety
                '12345678',  # Only numbers
                'abcdefgh',  # Only lowercase
                'ABCDEFGH',  # Only uppercase
                'Password1',  # Only 2 types
                'password123',  # Common weak password
            ]
            
            for weak_password in weak_passwords:
                with pytest.raises(ValueError):
                    user.set_password(weak_password)
    
    def test_flask_login_usermixin_integration(self, app: Flask, db_session):
        """
        Test Flask-Login UserMixin integration per Feature F-007.
        
        Validates UserMixin properties and methods for Flask-Login
        authentication decorator compatibility.
        """
        with app.app_context():
            user = User(
                username='login_test',
                email='login@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Test UserMixin properties
            assert user.is_authenticated is True
            assert user.is_anonymous is False
            assert user.is_active is True  # From model field
            assert user.get_id() == str(user.id)
            
            # Test with inactive user
            inactive_user = User(
                username='inactive_test',
                email='inactive@example.com',
                password='TestPassword123!',
                is_active=False
            )
            inactive_user.save()
            
            assert inactive_user.is_authenticated is True  # Still authenticated if loaded
            assert inactive_user.is_active is False  # But account is inactive
    
    def test_user_authentication_tracking(self, app: Flask, db_session):
        """
        Test user authentication with security tracking and monitoring.
        
        Validates authentication attempt tracking, account locking,
        and security monitoring per authentication requirements.
        """
        with app.app_context():
            user = User(
                username='auth_test',
                email='auth@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Test successful authentication
            assert user.authenticate('TestPassword123!', '192.168.1.1') is True
            assert user.failed_login_attempts == 0
            assert user.last_login_at is not None
            assert user.last_login_ip == '192.168.1.1'
            
            # Test failed authentication
            original_attempts = user.failed_login_attempts
            assert user.authenticate('WrongPassword', '192.168.1.1') is False
            assert user.failed_login_attempts == original_attempts + 1
            
            # Test account locking after failed attempts
            with patch.object(current_app, 'config', {'MAX_FAILED_LOGIN_ATTEMPTS': 3}):
                user.failed_login_attempts = 2
                user.save()
                
                # One more failure should lock account
                assert user.authenticate('WrongPassword', '192.168.1.1') is False
                assert user.failed_login_attempts == 3
                assert user.is_account_locked is True
                
                # Should reject even correct password when locked
                assert user.authenticate('TestPassword123!', '192.168.1.1') is False
                
                # Test account unlock
                user.reset_failed_login_attempts()
                assert user.failed_login_attempts == 0
                assert user.is_account_locked is False
                
                # Should work after unlock
                assert user.authenticate('TestPassword123!', '192.168.1.1') is True
    
    def test_password_reset_functionality(self, app: Flask, db_session):
        """
        Test password reset token generation and validation.
        
        Validates secure password reset workflows with token expiration
        and proper security token management.
        """
        with app.app_context():
            user = User(
                username='reset_test',
                email='reset@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Test token generation
            token = user.generate_password_reset_token()
            assert token is not None
            assert len(token) >= 32  # Secure token length
            assert user.password_reset_token == token
            assert user.password_reset_expires is not None
            
            # Test token validation
            assert user.verify_password_reset_token(token) is True
            assert user.verify_password_reset_token('invalid_token') is False
            assert user.verify_password_reset_token('') is False
            
            # Test token expiration
            user.password_reset_expires = datetime.now(timezone.utc) - timedelta(hours=1)
            user.save()
            assert user.verify_password_reset_token(token) is False
            
            # Test token clearing
            user.generate_password_reset_token()  # Generate new token
            assert user.password_reset_token is not None
            
            user.clear_password_reset_token()
            assert user.password_reset_token is None
            assert user.password_reset_expires is None
    
    def test_email_verification_functionality(self, app: Flask, db_session):
        """
        Test email verification token generation and validation.
        
        Validates email verification workflows with secure token management
        and account verification status tracking.
        """
        with app.app_context():
            user = User(
                username='verify_test',
                email='verify@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Should have verification token by default
            assert user.email_verification_token is not None
            assert user.email_verification_expires is not None
            assert user.is_verified is False
            
            # Test token validation
            token = user.email_verification_token
            assert user.verify_email_verification_token(token) is True
            assert user.verify_email_verification_token('invalid') is False
            
            # Test email verification completion
            user.complete_email_verification()
            assert user.is_verified is True
            assert user.email_verification_token is None
            assert user.email_verification_expires is None
            
            # Test token regeneration
            user.is_verified = False
            new_token = user.generate_email_verification_token()
            assert new_token is not None
            assert new_token != token  # Should be different
            assert user.verify_email_verification_token(new_token) is True
    
    def test_user_account_management(self, app: Flask, db_session):
        """
        Test user account activation and deactivation functionality.
        
        Validates account lifecycle management with session invalidation
        and proper state transitions.
        """
        with app.app_context():
            user = User(
                username='account_test',
                email='account@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            assert user.is_active is True
            
            # Test account deactivation
            user.deactivate_account()
            assert user.is_active is False
            
            # Test account reactivation
            user.failed_login_attempts = 5  # Set failed attempts
            user.activate_account()
            assert user.is_active is True
            assert user.failed_login_attempts == 0  # Should reset
    
    def test_user_display_properties(self, app: Flask, db_session):
        """
        Test user display properties and name handling.
        
        Validates full name composition, display name generation,
        and avatar URL generation for UI components.
        """
        with app.app_context():
            # Test with both names
            user1 = User(
                username='display_test1',
                email='display1@example.com',
                password='TestPassword123!',
                first_name='John',
                last_name='Doe'
            )
            user1.save()
            
            assert user1.full_name == 'John Doe'
            assert user1.display_name == 'John Doe'
            
            # Test with only first name
            user2 = User(
                username='display_test2',
                email='display2@example.com',
                password='TestPassword123!',
                first_name='Jane'
            )
            user2.save()
            
            assert user2.full_name == 'Jane'
            assert user2.display_name == 'Jane'
            
            # Test with no names
            user3 = User(
                username='display_test3',
                email='display3@example.com',
                password='TestPassword123!'
            )
            user3.save()
            
            assert user3.full_name == 'display_test3'
            assert user3.display_name == 'display_test3'
            
            # Test avatar URL generation
            avatar_url = user1.get_avatar_url()
            assert 'gravatar.com/avatar' in avatar_url
            assert avatar_url.endswith('?s=80&d=identicon')
            
            # Test custom avatar size
            custom_avatar = user1.get_avatar_url(size=120, default='mp')
            assert '?s=120&d=mp' in custom_avatar
    
    def test_user_class_methods(self, app: Flask, db_session):
        """
        Test User model class methods for user lookup and management.
        
        Validates user finder methods, admin user queries, and
        utility methods for user management operations.
        """
        with app.app_context():
            # Create test users
            admin_user = User.create_user(
                username='admin_test',
                email='admin_test@example.com',
                password='TestPassword123!',
                is_admin=True,
                auto_verify=True
            )
            
            regular_user = User.create_user(
                username='regular_test',
                email='regular_test@example.com',
                password='TestPassword123!'
            )
            
            # Test find_by_username
            found_user = User.find_by_username('admin_test')
            assert found_user is not None
            assert found_user.id == admin_user.id
            
            # Test case insensitive search
            found_user = User.find_by_username('ADMIN_TEST')
            assert found_user is not None
            assert found_user.id == admin_user.id
            
            # Test find_by_email
            found_user = User.find_by_email('regular_test@example.com')
            assert found_user is not None
            assert found_user.id == regular_user.id
            
            # Test find_by_username_or_email
            found_user = User.find_by_username_or_email('admin_test')
            assert found_user.id == admin_user.id
            
            found_user = User.find_by_username_or_email('regular_test@example.com')
            assert found_user.id == regular_user.id
            
            # Test get_admin_users
            admin_users = User.get_admin_users()
            assert len(admin_users) == 1
            assert admin_users[0].id == admin_user.id
            
            # Test create_user with duplicate username
            with pytest.raises(ValueError):
                User.create_user(
                    username='admin_test',  # Duplicate
                    email='new@example.com',
                    password='TestPassword123!'
                )
            
            # Test create_user with duplicate email
            with pytest.raises(ValueError):
                User.create_user(
                    username='new_user',
                    email='admin_test@example.com',  # Duplicate
                    password='TestPassword123!'
                )
    
    def test_user_token_cleanup(self, app: Flask, db_session):
        """
        Test expired token cleanup functionality.
        
        Validates automatic cleanup of expired password reset and
        email verification tokens for security maintenance.
        """
        with app.app_context():
            # Create users with expired tokens
            user1 = User(
                username='cleanup_test1',
                email='cleanup1@example.com',
                password='TestPassword123!'
            )
            user1.save()
            
            user2 = User(
                username='cleanup_test2',
                email='cleanup2@example.com',
                password='TestPassword123!'
            )
            user2.save()
            
            # Set expired tokens
            user1.generate_password_reset_token()
            user1.password_reset_expires = datetime.now(timezone.utc) - timedelta(hours=1)
            user1.save()
            
            user2.generate_email_verification_token()
            user2.email_verification_expires = datetime.now(timezone.utc) - timedelta(hours=1)
            user2.save()
            
            # Verify tokens exist
            assert user1.password_reset_token is not None
            assert user2.email_verification_token is not None
            
            # Run cleanup
            cleanup_count = User.cleanup_expired_tokens()
            assert cleanup_count == 2
            
            # Verify tokens cleaned up
            db.session.refresh(user1)
            db.session.refresh(user2)
            assert user1.password_reset_token is None
            assert user2.email_verification_token is None


class TestUserSessionModel:
    """
    Comprehensive test suite for UserSession model with ItsDangerous integration,
    session management, and security features. These tests ensure Flask-Login
    compatibility and secure session token handling.
    
    Testing coverage includes:
    - ItsDangerous secure session token validation per Section 4.6.2
    - Foreign key relationship with User model per Section 6.2.2.1
    - Session expiration and validation patterns per Flask-Login requirements
    - Session security tracking and fingerprinting
    - Session cleanup and invalidation functionality
    """
    
    def test_user_session_creation(self, app: Flask, db_session):
        """
        Test UserSession creation with secure token generation.
        
        Validates session token creation, ItsDangerous integration,
        and proper foreign key relationships with User model.
        """
        with app.app_context():
            # Create user for session testing
            user = User(
                username='session_test',
                email='session@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create user session
            session = UserSession(
                user_id=user.id,
                ip_address='192.168.1.1',
                user_agent='Test Browser',
                remember_me=False
            )
            session.save()
            
            assert session.id is not None
            assert session.user_id == user.id
            assert session.session_token is not None
            assert len(session.session_token) >= 32  # Secure token length
            assert session.signed_token is not None
            assert session.expires_at is not None
            assert session.is_valid is True
            assert session.ip_address == '192.168.1.1'
            assert session.user_agent == 'Test Browser'
            assert session.remember_me is False
            assert session.last_activity is not None
    
    def test_session_token_uniqueness(self, app: Flask, db_session):
        """
        Test session token uniqueness constraints.
        
        Validates that session tokens are unique across all sessions
        and cannot be duplicated in the database.
        """
        with app.app_context():
            user = User(
                username='token_test',
                email='token@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create first session
            session1 = UserSession(user_id=user.id)
            session1.save()
            
            # Create second session 
            session2 = UserSession(user_id=user.id)
            session2.save()
            
            # Tokens should be different
            assert session1.session_token != session2.session_token
            assert session1.signed_token != session2.signed_token
            
            # Verify uniqueness in database
            all_tokens = db.session.query(UserSession.session_token).all()
            token_values = [token[0] for token in all_tokens]
            assert len(token_values) == len(set(token_values))  # All unique
    
    def test_session_expiration_handling(self, app: Flask, db_session):
        """
        Test session expiration validation and cleanup.
        
        Validates session timeout handling, expired session detection,
        and automatic session cleanup functionality.
        """
        with app.app_context():
            user = User(
                username='expiry_test',
                email='expiry@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create session with custom expiration
            session = UserSession(user_id=user.id)
            session.save()
            
            # Test active session
            assert session.is_expired() is False
            assert session.is_active_session() is True
            
            # Test expired session
            session.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
            session.save()
            
            assert session.is_expired() is True
            assert session.is_active_session() is False
            
            # Test session with remember_me flag (longer expiration)
            remember_session = UserSession(
                user_id=user.id,
                remember_me=True
            )
            remember_session.save()
            
            # Remember sessions should have longer expiration
            regular_session = UserSession(
                user_id=user.id,
                remember_me=False
            )
            regular_session.save()
            
            assert remember_session.expires_at > regular_session.expires_at
    
    def test_session_activity_tracking(self, app: Flask, db_session):
        """
        Test session activity tracking and timeout management.
        
        Validates last activity updates, session timeout detection,
        and activity-based session lifecycle management.
        """
        with app.app_context():
            user = User(
                username='activity_test',
                email='activity@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            session = UserSession(user_id=user.id)
            session.save()
            
            original_activity = session.last_activity
            
            # Test activity update
            import time
            time.sleep(0.01)  # Small delay
            session.update_activity()
            
            assert session.last_activity > original_activity
            
            # Test session timeout check
            assert session.is_session_timeout() is False
            
            # Set old activity time
            session.last_activity = datetime.now(timezone.utc) - timedelta(hours=2)
            session.save()
            
            with patch.object(current_app, 'config', {'SESSION_TIMEOUT_HOURS': 1}):
                assert session.is_session_timeout() is True
    
    def test_session_security_features(self, app: Flask, db_session):
        """
        Test session security features and fingerprinting.
        
        Validates IP address tracking, user agent fingerprinting,
        and session security validation for fraud detection.
        """
        with app.app_context():
            user = User(
                username='security_test',
                email='security@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            session = UserSession(
                user_id=user.id,
                ip_address='192.168.1.100',
                user_agent='Mozilla/5.0 Test Browser'
            )
            session.save()
            
            # Test security validation
            assert session.validate_security_context('192.168.1.100', 'Mozilla/5.0 Test Browser') is True
            assert session.validate_security_context('192.168.1.200', 'Mozilla/5.0 Test Browser') is False
            assert session.validate_security_context('192.168.1.100', 'Different Browser') is False
            
            # Test loose security validation (IP only)
            assert session.validate_ip_address('192.168.1.100') is True
            assert session.validate_ip_address('192.168.1.200') is False
            
            # Test session fingerprint generation
            fingerprint = session.generate_fingerprint()
            assert fingerprint is not None
            assert isinstance(fingerprint, str)
            assert len(fingerprint) > 0
    
    def test_session_invalidation(self, app: Flask, db_session):
        """
        Test session invalidation and cleanup functionality.
        
        Validates individual session invalidation, bulk user session cleanup,
        and proper session state management for security.
        """
        with app.app_context():
            user = User(
                username='invalidate_test',
                email='invalidate@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create multiple sessions
            session1 = UserSession(user_id=user.id)
            session1.save()
            
            session2 = UserSession(user_id=user.id)
            session2.save()
            
            session3 = UserSession(user_id=user.id)
            session3.save()
            
            # Test individual session invalidation
            session1.invalidate()
            assert session1.is_valid is False
            assert session1.is_active_session() is False
            
            # Test bulk user session invalidation
            active_count = UserSession.invalidate_user_sessions(user.id, exclude_session_id=session2.id)
            assert active_count == 1  # session3 should be invalidated
            
            db.session.refresh(session2)
            db.session.refresh(session3)
            assert session2.is_valid is True  # Excluded
            assert session3.is_valid is False  # Invalidated
    
    def test_session_relationship_with_user(self, app: Flask, db_session):
        """
        Test UserSession relationship with User model.
        
        Validates foreign key constraints, relationship loading,
        and cascade behavior per Section 6.2.2.1.
        """
        with app.app_context():
            user = User(
                username='relationship_test',
                email='relationship@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create sessions
            session1 = UserSession(user_id=user.id)
            session1.save()
            
            session2 = UserSession(user_id=user.id)
            session2.save()
            
            # Test relationship loading
            assert session1.user is not None
            assert session1.user.id == user.id
            assert session1.user.username == 'relationship_test'
            
            # Test reverse relationship
            user_sessions = user.sessions.all()
            assert len(user_sessions) == 2
            assert session1 in user_sessions
            assert session2 in user_sessions
            
            # Test session count
            assert user.get_active_session_count() == 2
            
            # Test cascade deletion
            user.delete()
            
            # Sessions should be deleted due to cascade
            remaining_sessions = UserSession.query.filter_by(user_id=user.id).all()
            assert len(remaining_sessions) == 0
    
    def test_session_class_methods(self, app: Flask, db_session):
        """
        Test UserSession class methods for session management.
        
        Validates session finder methods, cleanup utilities,
        and bulk session management operations.
        """
        with app.app_context():
            user1 = User(
                username='session_class_test1',
                email='session1@example.com',
                password='TestPassword123!'
            )
            user1.save()
            
            user2 = User(
                username='session_class_test2',
                email='session2@example.com',
                password='TestPassword123!'
            )
            user2.save()
            
            # Create sessions
            session1 = UserSession(user_id=user1.id)
            session1.save()
            
            session2 = UserSession(user_id=user1.id)
            session2.save()
            
            session3 = UserSession(user_id=user2.id)
            session3.save()
            
            # Test find_by_token
            found_session = UserSession.find_by_token(session1.session_token)
            assert found_session is not None
            assert found_session.id == session1.id
            
            # Test find_by_user
            user1_sessions = UserSession.find_by_user(user1.id)
            assert len(user1_sessions) == 2
            
            user1_active_sessions = UserSession.find_by_user(user1.id, active_only=True)
            assert len(user1_active_sessions) == 2
            
            # Invalidate one session and test active filter
            session1.invalidate()
            user1_active_sessions = UserSession.find_by_user(user1.id, active_only=True)
            assert len(user1_active_sessions) == 1
            
            # Test cleanup expired sessions
            session2.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
            session2.save()
            
            cleanup_count = UserSession.cleanup_expired_sessions()
            assert cleanup_count == 1
            
            remaining_sessions = UserSession.find_by_user(user1.id, active_only=True)
            assert len(remaining_sessions) == 0


class TestBusinessEntityModel:
    """
    Comprehensive test suite for BusinessEntity model with user ownership
    relationships and business metadata management. These tests ensure
    proper business logic preservation and entity management functionality.
    
    Testing coverage includes:
    - Business entity metadata fields and validation
    - Foreign key relationship with User model for ownership
    - Status management and business workflow support
    - Entity relationship foundations per ER diagram requirements
    """
    
    def test_business_entity_creation(self, app: Flask, db_session):
        """
        Test BusinessEntity creation with user ownership.
        
        Validates business entity initialization with proper user relationships,
        metadata field handling, and status management.
        """
        with app.app_context():
            # Create owner user
            owner = User(
                username='entity_owner',
                email='owner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create business entity
            entity = BusinessEntity(
                name='Test Business',
                description='A test business entity',
                owner_id=owner.id,
                status='active'
            )
            entity.save()
            
            assert entity.id is not None
            assert entity.name == 'Test Business'
            assert entity.description == 'A test business entity'
            assert entity.owner_id == owner.id
            assert entity.status == 'active'
            assert entity.created_at is not None
            assert entity.updated_at is not None
    
    def test_business_entity_user_relationship(self, app: Flask, db_session):
        """
        Test BusinessEntity relationship with User model.
        
        Validates foreign key constraints, relationship loading,
        and ownership patterns for business entity access control.
        """
        with app.app_context():
            owner = User(
                username='business_owner',
                email='business@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create multiple entities
            entity1 = BusinessEntity(
                name='Business One',
                description='First business',
                owner_id=owner.id
            )
            entity1.save()
            
            entity2 = BusinessEntity(
                name='Business Two',
                description='Second business',
                owner_id=owner.id
            )
            entity2.save()
            
            # Test forward relationship
            assert entity1.owner is not None
            assert entity1.owner.id == owner.id
            assert entity1.owner.username == 'business_owner'
            
            # Test reverse relationship
            owner_entities = owner.business_entities.all()
            assert len(owner_entities) == 2
            assert entity1 in owner_entities
            assert entity2 in owner_entities
            
            # Test entity count method
            assert owner.get_business_entity_count() == 2
    
    def test_business_entity_validation(self, app: Flask, db_session):
        """
        Test BusinessEntity field validation and constraints.
        
        Validates business name requirements, description handling,
        and status field validation for business workflow support.
        """
        with app.app_context():
            owner = User(
                username='validation_owner',
                email='validation@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Test successful creation with valid data
            valid_entity = BusinessEntity(
                name='Valid Business Name',
                description='A valid description',
                owner_id=owner.id,
                status='active'
            )
            valid_entity.save()
            assert valid_entity.id is not None
            
            # Test name validation
            with pytest.raises(ValueError):
                BusinessEntity(
                    name='',  # Empty name
                    owner_id=owner.id
                )
            
            with pytest.raises(ValueError):
                BusinessEntity(
                    name='a' * 256,  # Too long
                    owner_id=owner.id
                )
            
            # Test status validation
            invalid_statuses = ['invalid_status', '', None]
            for status in invalid_statuses:
                entity = BusinessEntity(
                    name='Test Entity',
                    owner_id=owner.id,
                    status=status
                )
                if status is None:
                    # Should use default
                    entity.save()
                    assert entity.status == 'draft'  # Default status
                    entity.delete()
                else:
                    with pytest.raises(ValueError):
                        entity.validate_status()
    
    def test_business_entity_status_management(self, app: Flask, db_session):
        """
        Test business entity status lifecycle management.
        
        Validates status transitions, workflow support, and proper
        business state management for entity lifecycle.
        """
        with app.app_context():
            owner = User(
                username='status_owner',
                email='status@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            entity = BusinessEntity(
                name='Status Test Entity',
                owner_id=owner.id,
                status='draft'
            )
            entity.save()
            
            # Test status transitions
            assert entity.status == 'draft'
            assert entity.is_active() is False
            
            entity.activate()
            assert entity.status == 'active'
            assert entity.is_active() is True
            
            entity.deactivate()
            assert entity.status == 'inactive'
            assert entity.is_active() is False
            
            entity.archive()
            assert entity.status == 'archived'
            assert entity.is_archived() is True
            
            # Test status history tracking
            assert entity.updated_at is not None
    
    def test_business_entity_relationship_foundations(self, app: Flask, db_session):
        """
        Test BusinessEntity foundations for EntityRelationship model.
        
        Validates that BusinessEntity properly supports relationship
        mappings and provides foundation for complex business workflows.
        """
        with app.app_context():
            owner = User(
                username='relationship_owner',
                email='relowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create entities for relationship testing
            source_entity = BusinessEntity(
                name='Source Entity',
                description='Source for relationships',
                owner_id=owner.id,
                status='active'
            )
            source_entity.save()
            
            target_entity = BusinessEntity(
                name='Target Entity',
                description='Target for relationships',
                owner_id=owner.id,
                status='active'
            )
            target_entity.save()
            
            # Test that entities can serve as relationship endpoints
            assert source_entity.can_create_relationships() is True
            assert target_entity.can_accept_relationships() is True
            
            # Test entity metadata for relationships
            source_dict = source_entity.to_dict()
            assert 'id' in source_dict
            assert 'name' in source_dict
            assert 'status' in source_dict
            assert 'owner_id' in source_dict
    
    def test_business_entity_class_methods(self, app: Flask, db_session):
        """
        Test BusinessEntity class methods for entity management.
        
        Validates entity finder methods, status filtering,
        and bulk entity management operations.
        """
        with app.app_context():
            owner1 = User(
                username='entity_owner1',
                email='owner1@example.com',
                password='TestPassword123!'
            )
            owner1.save()
            
            owner2 = User(
                username='entity_owner2',
                email='owner2@example.com',
                password='TestPassword123!'
            )
            owner2.save()
            
            # Create entities with different statuses
            active_entity = BusinessEntity(
                name='Active Entity',
                owner_id=owner1.id,
                status='active'
            )
            active_entity.save()
            
            inactive_entity = BusinessEntity(
                name='Inactive Entity',
                owner_id=owner1.id,
                status='inactive'
            )
            inactive_entity.save()
            
            archived_entity = BusinessEntity(
                name='Archived Entity',
                owner_id=owner2.id,
                status='archived'
            )
            archived_entity.save()
            
            # Test find_by_owner
            owner1_entities = BusinessEntity.find_by_owner(owner1.id)
            assert len(owner1_entities) == 2
            
            # Test find_by_status
            active_entities = BusinessEntity.find_by_status('active')
            assert len(active_entities) == 1
            assert active_entities[0].id == active_entity.id
            
            # Test find_active_entities
            active_entities = BusinessEntity.find_active_entities()
            assert len(active_entities) == 1
            
            # Test search by name
            search_results = BusinessEntity.search_by_name('Active')
            assert len(search_results) == 1
            assert search_results[0].id == active_entity.id


class TestEntityRelationshipModel:
    """
    Comprehensive test suite for EntityRelationship model with complex business
    entity associations, relationship type categorization, and temporal management.
    These tests ensure sophisticated business logic workflows through many-to-many
    entity relationships with proper referential integrity.
    
    Testing coverage includes:
    - Complex business entity relationship mapping per Section 6.2.2.1
    - Dual foreign key relationships for source and target entities
    - Relationship type categorization and validation
    - Temporal state management and lifecycle tracking
    - Composite indexing and performance optimization
    """
    
    def test_entity_relationship_creation(self, app: Flask, db_session):
        """
        Test EntityRelationship creation with dual foreign keys.
        
        Validates relationship creation between business entities with
        proper foreign key constraints and metadata management.
        """
        with app.app_context():
            # Create owner and entities
            owner = User(
                username='rel_owner',
                email='relowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            source_entity = BusinessEntity(
                name='Source Entity',
                owner_id=owner.id,
                status='active'
            )
            source_entity.save()
            
            target_entity = BusinessEntity(
                name='Target Entity',
                owner_id=owner.id,
                status='active'
            )
            target_entity.save()
            
            # Create relationship
            relationship = EntityRelationship(
                source_entity_id=source_entity.id,
                target_entity_id=target_entity.id,
                relationship_type='parent_child',
                is_active=True
            )
            relationship.save()
            
            assert relationship.id is not None
            assert relationship.source_entity_id == source_entity.id
            assert relationship.target_entity_id == target_entity.id
            assert relationship.relationship_type == 'parent_child'
            assert relationship.is_active is True
            assert relationship.created_at is not None
    
    def test_entity_relationship_foreign_keys(self, app: Flask, db_session):
        """
        Test EntityRelationship foreign key relationships.
        
        Validates source and target entity relationships with proper
        constraint enforcement and relationship loading.
        """
        with app.app_context():
            owner = User(
                username='fk_owner',
                email='fkowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            entity1 = BusinessEntity(
                name='Entity One',
                owner_id=owner.id
            )
            entity1.save()
            
            entity2 = BusinessEntity(
                name='Entity Two',
                owner_id=owner.id
            )
            entity2.save()
            
            relationship = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='partnership'
            )
            relationship.save()
            
            # Test forward relationships
            assert relationship.source_entity is not None
            assert relationship.source_entity.id == entity1.id
            assert relationship.source_entity.name == 'Entity One'
            
            assert relationship.target_entity is not None
            assert relationship.target_entity.id == entity2.id
            assert relationship.target_entity.name == 'Entity Two'
            
            # Test reverse relationships
            source_relationships = entity1.source_relationships.all()
            assert len(source_relationships) == 1
            assert source_relationships[0].id == relationship.id
            
            target_relationships = entity2.target_relationships.all()
            assert len(target_relationships) == 1
            assert target_relationships[0].id == relationship.id
    
    def test_relationship_type_validation(self, app: Flask, db_session):
        """
        Test relationship type categorization and validation.
        
        Validates relationship type constraints, business rule enforcement,
        and proper categorization for workflow support.
        """
        with app.app_context():
            owner = User(
                username='type_owner',
                email='typeowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            entity1 = BusinessEntity(name='Entity 1', owner_id=owner.id)
            entity1.save()
            
            entity2 = BusinessEntity(name='Entity 2', owner_id=owner.id)
            entity2.save()
            
            # Test valid relationship types
            valid_types = [
                'parent_child',
                'partnership',
                'supplier_customer',
                'subsidiary',
                'collaboration',
                'dependency'
            ]
            
            for rel_type in valid_types:
                relationship = EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity2.id,
                    relationship_type=rel_type
                )
                relationship.save()
                assert relationship.relationship_type == rel_type
                relationship.delete()  # Cleanup
            
            # Test invalid relationship type
            with pytest.raises(ValueError):
                EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity2.id,
                    relationship_type='invalid_type'
                )
    
    def test_relationship_temporal_management(self, app: Flask, db_session):
        """
        Test relationship temporal state management and lifecycle.
        
        Validates relationship activation, deactivation, and temporal
        tracking for business workflow and lifecycle management.
        """
        with app.app_context():
            owner = User(
                username='temporal_owner',
                email='temporalowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            entity1 = BusinessEntity(name='Temporal Entity 1', owner_id=owner.id)
            entity1.save()
            
            entity2 = BusinessEntity(name='Temporal Entity 2', owner_id=owner.id)
            entity2.save()
            
            relationship = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='partnership',
                is_active=True
            )
            relationship.save()
            
            # Test active state
            assert relationship.is_active is True
            assert relationship.is_relationship_active() is True
            
            # Test deactivation
            relationship.deactivate()
            assert relationship.is_active is False
            assert relationship.is_relationship_active() is False
            
            # Test reactivation
            relationship.activate()
            assert relationship.is_active is True
            assert relationship.is_relationship_active() is True
            
            # Test temporal tracking
            original_updated = relationship.updated_at
            import time
            time.sleep(0.01)
            relationship.deactivate()
            assert relationship.updated_at > original_updated
    
    def test_relationship_business_logic_validation(self, app: Flask, db_session):
        """
        Test relationship business logic and constraint validation.
        
        Validates business rules, self-relationship prevention,
        and duplicate relationship detection for data integrity.
        """
        with app.app_context():
            owner = User(
                username='logic_owner',
                email='logicowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            entity1 = BusinessEntity(name='Logic Entity 1', owner_id=owner.id)
            entity1.save()
            
            entity2 = BusinessEntity(name='Logic Entity 2', owner_id=owner.id)
            entity2.save()
            
            # Test self-relationship prevention
            with pytest.raises(ValueError):
                EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity1.id,  # Same entity
                    relationship_type='partnership'
                )
            
            # Create valid relationship
            relationship1 = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='partnership'
            )
            relationship1.save()
            
            # Test duplicate relationship detection
            with pytest.raises(ValueError):
                EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity2.id,
                    relationship_type='partnership'  # Same relationship
                )
            
            # Test reverse relationship (should be allowed)
            relationship2 = EntityRelationship(
                source_entity_id=entity2.id,
                target_entity_id=entity1.id,
                relationship_type='partnership'
            )
            relationship2.save()
            assert relationship2.id is not None
    
    def test_relationship_cascade_behavior(self, app: Flask, db_session):
        """
        Test EntityRelationship cascade behavior with entity deletion.
        
        Validates proper cascade deletion and referential integrity
        when business entities are deleted.
        """
        with app.app_context():
            owner = User(
                username='cascade_owner',
                email='cascadeowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            entity1 = BusinessEntity(name='Cascade Entity 1', owner_id=owner.id)
            entity1.save()
            
            entity2 = BusinessEntity(name='Cascade Entity 2', owner_id=owner.id)
            entity2.save()
            
            entity3 = BusinessEntity(name='Cascade Entity 3', owner_id=owner.id)
            entity3.save()
            
            # Create relationships
            rel1 = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='partnership'
            )
            rel1.save()
            
            rel2 = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity3.id,
                relationship_type='supplier_customer'
            )
            rel2.save()
            
            # Verify relationships exist
            assert EntityRelationship.query.filter_by(source_entity_id=entity1.id).count() == 2
            
            # Delete source entity
            entity1.delete()
            
            # Relationships should be deleted due to cascade
            remaining_rels = EntityRelationship.query.filter_by(source_entity_id=entity1.id).all()
            assert len(remaining_rels) == 0
    
    def test_relationship_query_methods(self, app: Flask, db_session):
        """
        Test EntityRelationship query and finder methods.
        
        Validates relationship lookup methods, filtering capabilities,
        and complex query patterns for business workflow support.
        """
        with app.app_context():
            owner = User(
                username='query_owner',
                email='queryowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create entities
            entities = []
            for i in range(4):
                entity = BusinessEntity(
                    name=f'Query Entity {i+1}',
                    owner_id=owner.id
                )
                entity.save()
                entities.append(entity)
            
            # Create various relationships
            relationships = [
                EntityRelationship(
                    source_entity_id=entities[0].id,
                    target_entity_id=entities[1].id,
                    relationship_type='partnership',
                    is_active=True
                ),
                EntityRelationship(
                    source_entity_id=entities[0].id,
                    target_entity_id=entities[2].id,
                    relationship_type='supplier_customer',
                    is_active=True
                ),
                EntityRelationship(
                    source_entity_id=entities[1].id,
                    target_entity_id=entities[3].id,
                    relationship_type='partnership',
                    is_active=False
                )
            ]
            
            for rel in relationships:
                rel.save()
            
            # Test find_by_source_entity
            source_rels = EntityRelationship.find_by_source_entity(entities[0].id)
            assert len(source_rels) == 2
            
            # Test find_by_target_entity
            target_rels = EntityRelationship.find_by_target_entity(entities[1].id)
            assert len(target_rels) == 1
            
            # Test find_by_type
            partnership_rels = EntityRelationship.find_by_type('partnership')
            assert len(partnership_rels) == 2
            
            # Test find_active_relationships
            active_rels = EntityRelationship.find_active_relationships()
            assert len(active_rels) == 2
            
            # Test find_relationships_between
            between_rels = EntityRelationship.find_relationships_between(
                entities[0].id, entities[1].id
            )
            assert len(between_rels) == 1
            
            # Test get_entity_relationship_count
            entity0_count = EntityRelationship.get_entity_relationship_count(entities[0].id)
            assert entity0_count == 2  # As source
    
    def test_relationship_performance_indexing(self, app: Flask, db_session):
        """
        Test EntityRelationship composite indexing for performance.
        
        Validates that composite indexes are properly configured
        for efficient relationship queries and business logic performance.
        """
        with app.app_context():
            # This test validates that indexes exist and queries are efficient
            # In a real scenario, you would use EXPLAIN ANALYZE on queries
            
            owner = User(
                username='perf_owner',
                email='perfowner@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create entities for performance testing
            entities = []
            for i in range(10):
                entity = BusinessEntity(
                    name=f'Performance Entity {i+1}',
                    owner_id=owner.id
                )
                entity.save()
                entities.append(entity)
            
            # Create many relationships for performance testing
            for i in range(len(entities)):
                for j in range(i+1, len(entities)):
                    if i != j:  # Avoid self-relationships
                        relationship = EntityRelationship(
                            source_entity_id=entities[i].id,
                            target_entity_id=entities[j].id,
                            relationship_type='partnership',
                            is_active=(i + j) % 2 == 0  # Mix of active/inactive
                        )
                        relationship.save()
            
            # Test query performance with indexed fields
            # These queries should use indexes for efficiency
            
            # Query by source entity (should use source_entity_id index)
            source_rels = EntityRelationship.query.filter_by(
                source_entity_id=entities[0].id
            ).all()
            assert len(source_rels) > 0
            
            # Query by relationship type and active status (should use composite index)
            active_partnerships = EntityRelationship.query.filter_by(
                relationship_type='partnership',
                is_active=True
            ).all()
            assert len(active_partnerships) > 0
            
            # Query by active status (should use is_active index)
            all_active = EntityRelationship.query.filter_by(is_active=True).all()
            assert len(all_active) > 0


class TestModelRelationshipsAndConstraints:
    """
    Integration tests for model relationships, database constraints, and
    referential integrity across all models. These tests ensure proper
    foreign key behavior, cascade operations, and constraint enforcement.
    
    Testing coverage includes:
    - Cross-model relationship integrity testing
    - Database constraint enforcement validation
    - Cascade behavior testing for data consistency
    - Unique constraint validation across models
    - Complex query patterns across related models
    """
    
    def test_user_session_cascade_behavior(self, app: Flask, db_session):
        """
        Test User to UserSession cascade deletion behavior.
        
        Validates that user deletion properly cascades to sessions
        and maintains referential integrity.
        """
        with app.app_context():
            user = User(
                username='cascade_user',
                email='cascade@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create multiple sessions
            sessions = []
            for i in range(3):
                session = UserSession(
                    user_id=user.id,
                    ip_address=f'192.168.1.{i+1}'
                )
                session.save()
                sessions.append(session)
            
            session_ids = [s.id for s in sessions]
            
            # Verify sessions exist
            assert UserSession.query.filter_by(user_id=user.id).count() == 3
            
            # Delete user
            user.delete()
            
            # Sessions should be deleted
            for session_id in session_ids:
                assert UserSession.query.get(session_id) is None
    
    def test_user_business_entity_cascade_behavior(self, app: Flask, db_session):
        """
        Test User to BusinessEntity cascade deletion behavior.
        
        Validates that user deletion properly cascades to business entities
        and maintains data integrity.
        """
        with app.app_context():
            user = User(
                username='entity_owner',
                email='entityowner@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Create business entities
            entities = []
            for i in range(2):
                entity = BusinessEntity(
                    name=f'Test Entity {i+1}',
                    owner_id=user.id
                )
                entity.save()
                entities.append(entity)
            
            entity_ids = [e.id for e in entities]
            
            # Verify entities exist
            assert BusinessEntity.query.filter_by(owner_id=user.id).count() == 2
            
            # Delete user
            user.delete()
            
            # Entities should be deleted
            for entity_id in entity_ids:
                assert BusinessEntity.query.get(entity_id) is None
    
    def test_business_entity_relationship_cascade(self, app: Flask, db_session):
        """
        Test BusinessEntity to EntityRelationship cascade behavior.
        
        Validates that entity deletion properly cascades to relationships
        and maintains referential integrity across the relationship graph.
        """
        with app.app_context():
            owner = User(
                username='rel_cascade_owner',
                email='relcascade@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create entities
            entity1 = BusinessEntity(name='Entity 1', owner_id=owner.id)
            entity1.save()
            
            entity2 = BusinessEntity(name='Entity 2', owner_id=owner.id)
            entity2.save()
            
            entity3 = BusinessEntity(name='Entity 3', owner_id=owner.id)
            entity3.save()
            
            # Create relationships
            rel1 = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='partnership'
            )
            rel1.save()
            
            rel2 = EntityRelationship(
                source_entity_id=entity2.id,
                target_entity_id=entity3.id,
                relationship_type='supplier_customer'
            )
            rel2.save()
            
            rel3 = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity3.id,
                relationship_type='collaboration'
            )
            rel3.save()
            
            relationship_ids = [rel1.id, rel2.id, rel3.id]
            
            # Delete entity1
            entity1.delete()
            
            # Relationships involving entity1 should be deleted
            assert EntityRelationship.query.get(rel1.id) is None  # entity1 -> entity2
            assert EntityRelationship.query.get(rel3.id) is None  # entity1 -> entity3
            assert EntityRelationship.query.get(rel2.id) is not None  # entity2 -> entity3 (should remain)
    
    def test_unique_constraint_enforcement(self, app: Flask, db_session):
        """
        Test unique constraint enforcement across all models.
        
        Validates that unique constraints are properly enforced
        for usernames, emails, session tokens, and other unique fields.
        """
        with app.app_context():
            # Test User unique constraints
            user1 = User(
                username='unique_test',
                email='unique@example.com',
                password='TestPassword123!'
            )
            user1.save()
            
            # Duplicate username should fail
            with pytest.raises(Exception):  # Could be IntegrityError or similar
                user2 = User(
                    username='unique_test',  # Duplicate
                    email='different@example.com',
                    password='TestPassword123!'
                )
                user2.save()
                db.session.commit()
            
            db.session.rollback()  # Reset after error
            
            # Duplicate email should fail
            with pytest.raises(Exception):
                user3 = User(
                    username='different_user',
                    email='unique@example.com',  # Duplicate
                    password='TestPassword123!'
                )
                user3.save()
                db.session.commit()
            
            db.session.rollback()  # Reset after error
            
            # Test UserSession unique token constraint
            session1 = UserSession(user_id=user1.id)
            session1.save()
            
            # Manually setting same token should fail
            with pytest.raises(Exception):
                session2 = UserSession(user_id=user1.id)
                session2.session_token = session1.session_token  # Duplicate token
                session2.save()
                db.session.commit()
    
    def test_foreign_key_constraint_enforcement(self, app: Flask, db_session):
        """
        Test foreign key constraint enforcement across models.
        
        Validates that foreign key relationships are properly enforced
        and prevent orphaned records.
        """
        with app.app_context():
            # Test UserSession foreign key constraint
            with pytest.raises(Exception):  # Foreign key violation
                invalid_session = UserSession(
                    user_id=99999,  # Non-existent user
                    ip_address='192.168.1.1'
                )
                invalid_session.save()
                db.session.commit()
            
            db.session.rollback()  # Reset after error
            
            # Test BusinessEntity foreign key constraint
            with pytest.raises(Exception):
                invalid_entity = BusinessEntity(
                    name='Invalid Entity',
                    owner_id=99999  # Non-existent user
                )
                invalid_entity.save()
                db.session.commit()
            
            db.session.rollback()  # Reset after error
            
            # Test EntityRelationship foreign key constraints
            user = User(
                username='fk_test_user',
                email='fktest@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            entity = BusinessEntity(
                name='FK Test Entity',
                owner_id=user.id
            )
            entity.save()
            
            # Invalid source entity
            with pytest.raises(Exception):
                invalid_rel1 = EntityRelationship(
                    source_entity_id=99999,  # Non-existent
                    target_entity_id=entity.id,
                    relationship_type='partnership'
                )
                invalid_rel1.save()
                db.session.commit()
            
            db.session.rollback()
            
            # Invalid target entity
            with pytest.raises(Exception):
                invalid_rel2 = EntityRelationship(
                    source_entity_id=entity.id,
                    target_entity_id=99999,  # Non-existent
                    relationship_type='partnership'
                )
                invalid_rel2.save()
                db.session.commit()
    
    def test_complex_cross_model_queries(self, app: Flask, db_session):
        """
        Test complex queries across multiple related models.
        
        Validates that relationships enable efficient cross-model
        queries for business logic and reporting requirements.
        """
        with app.app_context():
            # Create test data structure
            owner = User(
                username='complex_owner',
                email='complex@example.com',
                password='TestPassword123!'
            )
            owner.save()
            
            # Create multiple sessions
            for i in range(3):
                session = UserSession(
                    user_id=owner.id,
                    ip_address=f'192.168.1.{i+10}'
                )
                session.save()
            
            # Create business entities
            entities = []
            for i in range(4):
                entity = BusinessEntity(
                    name=f'Complex Entity {i+1}',
                    owner_id=owner.id,
                    status='active' if i % 2 == 0 else 'inactive'
                )
                entity.save()
                entities.append(entity)
            
            # Create relationships
            for i in range(len(entities) - 1):
                relationship = EntityRelationship(
                    source_entity_id=entities[i].id,
                    target_entity_id=entities[i+1].id,
                    relationship_type='partnership',
                    is_active=True
                )
                relationship.save()
            
            # Test: Find all active business entities for users with active sessions
            from sqlalchemy import and_
            
            query = db.session.query(BusinessEntity).join(User).join(UserSession).filter(
                and_(
                    BusinessEntity.status == 'active',
                    UserSession.is_valid == True,
                    User.is_active == True
                )
            ).distinct()
            
            results = query.all()
            assert len(results) > 0
            
            # Test: Find all relationships involving entities owned by specific user
            relationship_query = db.session.query(EntityRelationship).join(
                BusinessEntity, EntityRelationship.source_entity_id == BusinessEntity.id
            ).filter(BusinessEntity.owner_id == owner.id)
            
            rel_results = relationship_query.all()
            assert len(rel_results) > 0
            
            # Test: Count entities by owner with relationship counts
            entity_counts = db.session.query(
                User.username,
                db.func.count(BusinessEntity.id).label('entity_count'),
                db.func.count(EntityRelationship.id).label('relationship_count')
            ).join(BusinessEntity).outerjoin(
                EntityRelationship, BusinessEntity.id == EntityRelationship.source_entity_id
            ).group_by(User.id, User.username).all()
            
            assert len(entity_counts) > 0
            for username, entity_count, rel_count in entity_counts:
                assert entity_count > 0
    
    def test_database_constraint_validation_coverage(self, app: Flask, db_session):
        """
        Test comprehensive database constraint validation coverage.
        
        Validates that all defined database constraints are properly
        enforced and provide appropriate validation feedback.
        """
        with app.app_context():
            # Test User model constraints
            user = User(
                username='constraint_test',
                email='constraint@example.com',
                password='TestPassword123!'
            )
            user.save()
            
            # Test username length constraints
            with pytest.raises(ValueError):
                User._validate_username('ab')  # Too short
            
            with pytest.raises(ValueError):
                User._validate_username('a' * 81)  # Too long
            
            # Test email length constraints
            with pytest.raises(ValueError):
                User._validate_email('a@b.c')  # Too short
            
            with pytest.raises(ValueError):
                User._validate_email('a' * 116 + '@b.com')  # Too long
            
            # Test failed login attempts constraint (should be non-negative)
            user.failed_login_attempts = -1
            with pytest.raises(Exception):
                user.save()
                db.session.commit()
            
            db.session.rollback()
            
            # Test BusinessEntity name constraints
            with pytest.raises(ValueError):
                BusinessEntity(
                    name='',  # Empty name
                    owner_id=user.id
                )
            
            # Test EntityRelationship constraints
            entity1 = BusinessEntity(name='Entity 1', owner_id=user.id)
            entity1.save()
            
            # Self-relationship should be prevented
            with pytest.raises(ValueError):
                EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity1.id,  # Same entity
                    relationship_type='partnership'
                )


# Pytest marks for test categorization per conftest.py markers
pytestmark = [
    pytest.mark.unit,
    pytest.mark.database,
    pytest.mark.models
]


if __name__ == '__main__':
    # Allow running tests directly with python -m pytest tests/unit/test_models.py
    pytest.main([__file__, '-v', '--tb=short'])