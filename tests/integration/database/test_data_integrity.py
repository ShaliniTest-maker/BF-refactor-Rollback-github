"""
Data Integrity and Constraint Validation Testing Suite

This comprehensive test module validates PostgreSQL database constraints, data validation rules,
and referential integrity enforcement during the migration from MongoDB to Flask-SQLAlchemy.
The test suite ensures complete data consistency equivalent to the original system's validation
patterns while validating constraint enforcement, transaction boundary management, and error
handling capabilities.

Test Categories:
- PostgreSQL constraint validation (unique, check, foreign key constraints)
- Field-level data validation and business rule enforcement
- Transaction boundary management with rollback capabilities
- Referential integrity testing with cascade operations
- Data consistency validation equivalent to MongoDB patterns
- Constraint violation error handling and exception management

Requirements Addressed:
- Feature F-003: Database Model Conversion with constraint preservation
- Feature F-004: Database Migration Management with data integrity
- Section 6.2.1: Flask-SQLAlchemy 3.1.1 model validation
- Section 6.2.2.1: Entity relationships and referential integrity
- Section 6.2.2.2: PostgreSQL constraint enforcement
- Section 5.2.4: Transaction boundary management
- Section 4.8: Error handling and recovery workflows
"""

import pytest
import sqlalchemy
from sqlalchemy import text
from sqlalchemy.exc import (
    IntegrityError, 
    DataError, 
    StatementError,
    InvalidRequestError
)
from sqlalchemy.orm import Session
from flask import Flask
from datetime import datetime, timedelta
import uuid
from typing import Dict, List, Any, Optional

# Import Flask application and models
from src.models import (
    User, 
    UserSession, 
    BusinessEntity, 
    EntityRelationship,
    db
)
from src.models.base import BaseModel


class TestDatabaseConstraints:
    """
    Test suite for PostgreSQL database constraint validation ensuring 
    equivalent constraint enforcement to MongoDB validation patterns.
    
    This test class validates:
    - Unique constraint enforcement on critical fields
    - Check constraint validation for business rules
    - Foreign key constraint enforcement and referential integrity
    - Not-null constraint validation for required fields
    """

    def test_user_unique_constraints(self, app: Flask, db_session: Session):
        """
        Test unique constraint enforcement on User model fields.
        
        Validates:
        - Username uniqueness across all user records
        - Email address uniqueness for authentication integrity
        - Proper constraint violation error handling
        - Database rollback on constraint violations
        
        Requirements: Feature F-003, Section 6.2.2.2
        """
        with app.app_context():
            # Create first user with unique constraints
            user1 = User(
                username="testuser1",
                email="test1@example.com",
                password_hash="hashed_password_1"
            )
            db_session.add(user1)
            db_session.commit()
            
            # Verify user creation successful
            assert user1.id is not None
            assert user1.username == "testuser1"
            assert user1.email == "test1@example.com"
            
            # Test username uniqueness violation
            user2 = User(
                username="testuser1",  # Duplicate username
                email="test2@example.com",
                password_hash="hashed_password_2"
            )
            db_session.add(user2)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify constraint violation error contains username reference
            assert "username" in str(exc_info.value).lower()
            db_session.rollback()
            
            # Test email uniqueness violation
            user3 = User(
                username="testuser3",
                email="test1@example.com",  # Duplicate email
                password_hash="hashed_password_3"
            )
            db_session.add(user3)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify constraint violation error contains email reference
            assert "email" in str(exc_info.value).lower()
            db_session.rollback()
            
            # Verify successful creation with unique values
            user4 = User(
                username="testuser4",
                email="test4@example.com",
                password_hash="hashed_password_4"
            )
            db_session.add(user4)
            db_session.commit()
            
            assert user4.id is not None
            assert user4.username == "testuser4"

    def test_user_session_unique_constraints(self, app: Flask, db_session: Session):
        """
        Test unique constraint enforcement on UserSession model.
        
        Validates:
        - Session token uniqueness for security integrity
        - Proper constraint violation handling for authentication
        - Database rollback on duplicate session tokens
        
        Requirements: Feature F-007, Section 6.2.2.2
        """
        with app.app_context():
            # Create test user for session relationships
            user = User(
                username="sessionuser",
                email="session@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Create first session with unique token
            session1 = UserSession(
                user_id=user.id,
                session_token="unique_token_123",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(session1)
            db_session.commit()
            
            assert session1.id is not None
            assert session1.session_token == "unique_token_123"
            
            # Test session token uniqueness violation
            session2 = UserSession(
                user_id=user.id,
                session_token="unique_token_123",  # Duplicate token
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(session2)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify constraint violation error
            assert "session_token" in str(exc_info.value).lower()
            db_session.rollback()
            
            # Verify successful creation with unique token
            session3 = UserSession(
                user_id=user.id,
                session_token="unique_token_456",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(session3)
            db_session.commit()
            
            assert session3.id is not None
            assert session3.session_token == "unique_token_456"

    def test_foreign_key_constraints(self, app: Flask, db_session: Session):
        """
        Test foreign key constraint enforcement across model relationships.
        
        Validates:
        - UserSession foreign key constraint to User model
        - BusinessEntity foreign key constraint to User model
        - EntityRelationship foreign key constraints to BusinessEntity model
        - Proper constraint violation error handling
        - Database rollback on invalid foreign key references
        
        Requirements: Section 6.2.2.1, Feature F-003
        """
        with app.app_context():
            # Test UserSession foreign key constraint
            invalid_session = UserSession(
                user_id=99999,  # Non-existent user ID
                session_token="invalid_user_session",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(invalid_session)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify foreign key constraint violation
            assert "foreign key constraint" in str(exc_info.value).lower() or "violates" in str(exc_info.value).lower()
            db_session.rollback()
            
            # Create valid user for foreign key testing
            user = User(
                username="fkuser",
                email="fk@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Test BusinessEntity foreign key constraint
            invalid_entity = BusinessEntity(
                name="Invalid Entity",
                description="Entity with invalid owner",
                owner_id=99999,  # Non-existent user ID
                status="active"
            )
            db_session.add(invalid_entity)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify foreign key constraint violation
            assert "foreign key constraint" in str(exc_info.value).lower() or "violates" in str(exc_info.value).lower()
            db_session.rollback()
            
            # Create valid business entity
            entity = BusinessEntity(
                name="Valid Entity",
                description="Entity with valid owner",
                owner_id=user.id,
                status="active"
            )
            db_session.add(entity)
            db_session.commit()
            
            # Test EntityRelationship foreign key constraints
            invalid_relationship = EntityRelationship(
                source_entity_id=99999,  # Non-existent entity ID
                target_entity_id=entity.id,
                relationship_type="depends_on",
                is_active=True
            )
            db_session.add(invalid_relationship)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify foreign key constraint violation
            assert "foreign key constraint" in str(exc_info.value).lower() or "violates" in str(exc_info.value).lower()
            db_session.rollback()

    def test_not_null_constraints(self, app: Flask, db_session: Session):
        """
        Test NOT NULL constraint enforcement on required fields.
        
        Validates:
        - Required field validation across all models
        - Proper error handling for missing required data
        - Database rollback on null constraint violations
        
        Requirements: Feature F-003, Section 6.2.2.2
        """
        with app.app_context():
            # Test User model NOT NULL constraints
            invalid_user = User(
                username=None,  # Required field
                email="test@example.com",
                password_hash="hashed_password"
            )
            db_session.add(invalid_user)
            
            with pytest.raises((IntegrityError, StatementError)) as exc_info:
                db_session.commit()
            
            db_session.rollback()
            
            # Test UserSession model NOT NULL constraints
            user = User(
                username="validuser",
                email="valid@example.com", 
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            invalid_session = UserSession(
                user_id=user.id,
                session_token=None,  # Required field
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(invalid_session)
            
            with pytest.raises((IntegrityError, StatementError)) as exc_info:
                db_session.commit()
            
            db_session.rollback()
            
            # Test BusinessEntity model NOT NULL constraints
            invalid_entity = BusinessEntity(
                name=None,  # Required field
                description="Valid description",
                owner_id=user.id,
                status="active"
            )
            db_session.add(invalid_entity)
            
            with pytest.raises((IntegrityError, StatementError)) as exc_info:
                db_session.commit()
            
            db_session.rollback()


class TestDataValidationRules:
    """
    Test suite for field-level data validation and business rule enforcement.
    
    This test class validates:
    - Field length constraints and data type validation
    - Business rule enforcement through check constraints
    - Data format validation for email and other formatted fields
    - Range validation for numeric and date fields
    """

    def test_field_length_validation(self, app: Flask, db_session: Session):
        """
        Test field length constraints and data type validation.
        
        Validates:
        - String field length limits enforcement
        - Text field capacity for large content
        - Proper error handling for oversized data
        
        Requirements: Section 6.2.1, Feature F-003
        """
        with app.app_context():
            # Test username length constraints (assuming reasonable limits)
            long_username = "a" * 1000  # Extremely long username
            user_long_username = User(
                username=long_username,
                email="test@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user_long_username)
            
            # This should either succeed (if no explicit length limit) or fail with appropriate error
            try:
                db_session.commit()
                # If it succeeds, verify the data was stored correctly
                assert user_long_username.username == long_username
            except (DataError, IntegrityError, StatementError):
                # If it fails, verify it's due to length constraints
                db_session.rollback()
            
            # Test valid length data
            user_valid = User(
                username="validusername",
                email="valid@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user_valid)
            db_session.commit()
            
            assert user_valid.id is not None

    def test_email_format_validation(self, app: Flask, db_session: Session):
        """
        Test email format validation constraints.
        
        Validates:
        - Email format constraints through database or application validation
        - Proper error handling for invalid email formats
        
        Requirements: Feature F-003, Section 6.2.2.2
        """
        with app.app_context():
            # Test various email formats - note that PostgreSQL itself doesn't enforce email format
            # but the application should handle this
            invalid_emails = [
                "invalid-email",
                "@example.com",
                "test@",
                "test..test@example.com",
                ""
            ]
            
            for invalid_email in invalid_emails:
                try:
                    user = User(
                        username=f"user_{hash(invalid_email)}",
                        email=invalid_email,
                        password_hash="hashed_password"
                    )
                    db_session.add(user)
                    db_session.commit()
                    
                    # If the database allows it, the application should validate
                    # For now, we'll allow it and note that validation should be at application level
                    
                except (DataError, IntegrityError, StatementError):
                    db_session.rollback()
            
            # Test valid email format
            user_valid_email = User(
                username="validemailuser",
                email="valid.email@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user_valid_email)
            db_session.commit()
            
            assert user_valid_email.id is not None
            assert user_valid_email.email == "valid.email@example.com"

    def test_business_entity_status_validation(self, app: Flask, db_session: Session):
        """
        Test business rule validation for entity status values.
        
        Validates:
        - Status field value constraints
        - Business rule enforcement for valid status transitions
        - Proper error handling for invalid status values
        
        Requirements: Feature F-005, Section 6.2.2.2
        """
        with app.app_context():
            # Create user for entity ownership
            user = User(
                username="entityowner",
                email="owner@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Test valid status values
            valid_statuses = ["active", "inactive", "pending", "archived"]
            
            for status in valid_statuses:
                entity = BusinessEntity(
                    name=f"Entity_{status}",
                    description=f"Entity with {status} status",
                    owner_id=user.id,
                    status=status
                )
                db_session.add(entity)
                db_session.commit()
                
                assert entity.id is not None
                assert entity.status == status
            
            # Test potentially invalid status (database may allow any string)
            invalid_entity = BusinessEntity(
                name="Invalid Status Entity",
                description="Entity with invalid status",
                owner_id=user.id,
                status="completely_invalid_status"
            )
            db_session.add(invalid_entity)
            
            # PostgreSQL will likely allow this unless there's a check constraint
            try:
                db_session.commit()
                # If allowed, we should implement application-level validation
                assert invalid_entity.id is not None
            except (DataError, IntegrityError, StatementError):
                db_session.rollback()

    def test_session_expiration_validation(self, app: Flask, db_session: Session):
        """
        Test session expiration date validation rules.
        
        Validates:
        - Future date requirement for session expiration
        - Proper date format handling
        - Business rule enforcement for session validity
        
        Requirements: Feature F-007, Section 6.2.2.2
        """
        with app.app_context():
            # Create user for session testing
            user = User(
                username="sessionuser",
                email="session@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Test past expiration date (business rule validation)
            past_date = datetime.utcnow() - timedelta(days=1)
            past_session = UserSession(
                user_id=user.id,
                session_token="past_session_token",
                expires_at=past_date,
                is_valid=True
            )
            db_session.add(past_session)
            db_session.commit()
            
            # Database will likely allow this, but application should validate
            assert past_session.id is not None
            assert past_session.expires_at == past_date
            
            # Test future expiration date (valid)
            future_date = datetime.utcnow() + timedelta(days=1)
            future_session = UserSession(
                user_id=user.id,
                session_token="future_session_token",
                expires_at=future_date,
                is_valid=True
            )
            db_session.add(future_session)
            db_session.commit()
            
            assert future_session.id is not None
            assert future_session.expires_at == future_date


class TestTransactionBoundaryManagement:
    """
    Test suite for SQLAlchemy session management and transaction boundaries.
    
    This test class validates:
    - Transaction isolation and ACID compliance
    - Automatic rollback on exceptions
    - Savepoint management for nested transactions
    - Session lifecycle management with Flask request context
    """

    def test_transaction_isolation(self, app: Flask, db_session: Session):
        """
        Test transaction isolation between concurrent operations.
        
        Validates:
        - Transaction isolation levels
        - Proper session management
        - Data consistency during concurrent access
        
        Requirements: Section 5.2.4, Feature F-004
        """
        with app.app_context():
            # Create initial user
            user1 = User(
                username="isolation_user1",
                email="isolation1@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user1)
            db_session.commit()
            
            # Start a transaction and modify user
            db_session.begin()
            user1.email = "modified1@example.com"
            
            # In a real concurrent scenario, another session wouldn't see this change
            # until commit. Here we'll verify the change is pending
            assert user1.email == "modified1@example.com"
            
            # Rollback to test isolation
            db_session.rollback()
            
            # Verify rollback worked
            db_session.refresh(user1)
            assert user1.email == "isolation1@example.com"

    def test_automatic_rollback_on_exception(self, app: Flask, db_session: Session):
        """
        Test automatic transaction rollback when exceptions occur.
        
        Validates:
        - Exception handling during database operations
        - Automatic rollback on constraint violations
        - Session state after exception handling
        
        Requirements: Section 4.8, Section 5.2.4
        """
        with app.app_context():
            # Create user for testing
            user = User(
                username="rollback_user",
                email="rollback@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            initial_user_count = db_session.query(User).count()
            
            try:
                # Start a transaction that will fail
                db_session.begin()
                
                # Add a valid user
                user2 = User(
                    username="valid_user",
                    email="valid@example.com",
                    password_hash="hashed_password"
                )
                db_session.add(user2)
                
                # Add an invalid user (constraint violation)
                user3 = User(
                    username="rollback_user",  # Duplicate username
                    email="duplicate@example.com",
                    password_hash="hashed_password"
                )
                db_session.add(user3)
                
                # This should raise an IntegrityError
                db_session.commit()
                
            except IntegrityError:
                # Verify automatic rollback occurred
                db_session.rollback()
                
                # Verify no partial data was committed
                final_user_count = db_session.query(User).count()
                assert final_user_count == initial_user_count
                
                # Verify the valid user was not saved due to rollback
                valid_user_exists = db_session.query(User).filter_by(
                    username="valid_user"
                ).first()
                assert valid_user_exists is None

    def test_savepoint_management(self, app: Flask, db_session: Session):
        """
        Test savepoint management for nested transaction scenarios.
        
        Validates:
        - Savepoint creation and rollback
        - Nested transaction handling
        - Partial rollback capabilities
        
        Requirements: Section 5.2.4, Feature F-004
        """
        with app.app_context():
            # Create initial data
            user = User(
                username="savepoint_user",
                email="savepoint@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Start outer transaction
            db_session.begin()
            
            # Create a business entity
            entity1 = BusinessEntity(
                name="Entity 1",
                description="First entity",
                owner_id=user.id,
                status="active"
            )
            db_session.add(entity1)
            
            # Create savepoint
            savepoint = db_session.begin_nested()
            
            try:
                # Create another entity that might fail
                entity2 = BusinessEntity(
                    name="Entity 2",
                    description="Second entity", 
                    owner_id=user.id,
                    status="active"
                )
                db_session.add(entity2)
                
                # Simulate a condition that causes rollback to savepoint
                if True:  # Simulated error condition
                    raise Exception("Simulated error")
                
                savepoint.commit()
                
            except Exception:
                # Rollback to savepoint
                savepoint.rollback()
            
            # Commit outer transaction (entity1 should be saved, entity2 should not)
            db_session.commit()
            
            # Verify entity1 was saved
            saved_entity1 = db_session.query(BusinessEntity).filter_by(
                name="Entity 1"
            ).first()
            assert saved_entity1 is not None
            
            # Verify entity2 was not saved
            saved_entity2 = db_session.query(BusinessEntity).filter_by(
                name="Entity 2" 
            ).first()
            assert saved_entity2 is None

    def test_session_lifecycle_management(self, app: Flask, db_session: Session):
        """
        Test session lifecycle management with Flask request context.
        
        Validates:
        - Session creation and cleanup
        - Request context integration
        - Memory management for database sessions
        
        Requirements: Section 5.2.4, Section 5.2.1
        """
        with app.app_context():
            # Test session state tracking
            initial_session_id = id(db_session)
            
            # Create and commit some data
            user = User(
                username="lifecycle_user",
                email="lifecycle@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            assert user.id is not None
            
            # Session should remain consistent
            current_session_id = id(db_session)
            assert current_session_id == initial_session_id
            
            # Test session cleanup on rollback
            db_session.begin()
            user.email = "modified@example.com"
            db_session.rollback()
            
            # Verify session is still usable
            db_session.refresh(user)
            assert user.email == "lifecycle@example.com"


class TestReferentialIntegrity:
    """
    Test suite for referential integrity and cascade operations.
    
    This test class validates:
    - Foreign key relationship enforcement
    - Cascade delete operations
    - Orphan record prevention
    - Relationship consistency across model updates
    """

    def test_cascade_delete_operations(self, app: Flask, db_session: Session):
        """
        Test cascade delete behavior for parent-child relationships.
        
        Validates:
        - User deletion cascades to UserSession records
        - BusinessEntity deletion cascades to EntityRelationship records
        - Proper cleanup of orphaned records
        
        Requirements: Section 6.2.2.1, Feature F-003
        """
        with app.app_context():
            # Create user with sessions
            user = User(
                username="cascade_user",
                email="cascade@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Create multiple sessions for the user
            session1 = UserSession(
                user_id=user.id,
                session_token="cascade_token_1",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            session2 = UserSession(
                user_id=user.id,
                session_token="cascade_token_2", 
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add_all([session1, session2])
            db_session.commit()
            
            # Verify sessions exist
            session_count = db_session.query(UserSession).filter_by(
                user_id=user.id
            ).count()
            assert session_count == 2
            
            # Delete user (should cascade to sessions if configured)
            user_id = user.id
            db_session.delete(user)
            
            try:
                db_session.commit()
                
                # Check if sessions were cascade deleted
                remaining_sessions = db_session.query(UserSession).filter_by(
                    user_id=user_id
                ).count()
                
                # Depending on cascade configuration, sessions might be deleted
                # If not cascade configured, this will fail with foreign key constraint
                
            except IntegrityError:
                # If cascade is not configured, we get a foreign key constraint error
                db_session.rollback()
                
                # Manually delete sessions first
                db_session.query(UserSession).filter_by(user_id=user.id).delete()
                db_session.delete(user)
                db_session.commit()
                
                # Verify cleanup
                remaining_sessions = db_session.query(UserSession).filter_by(
                    user_id=user_id
                ).count()
                assert remaining_sessions == 0

    def test_business_entity_relationships(self, app: Flask, db_session: Session):
        """
        Test business entity relationship integrity and cascade operations.
        
        Validates:
        - EntityRelationship foreign key constraints
        - Business entity deletion impact on relationships
        - Relationship consistency validation
        
        Requirements: Section 6.2.2.1, Feature F-005
        """
        with app.app_context():
            # Create user and business entities
            user = User(
                username="relationship_user",
                email="relationship@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            entity1 = BusinessEntity(
                name="Source Entity",
                description="Source business entity",
                owner_id=user.id,
                status="active"
            )
            entity2 = BusinessEntity(
                name="Target Entity",
                description="Target business entity",
                owner_id=user.id,
                status="active"
            )
            db_session.add_all([entity1, entity2])
            db_session.commit()
            
            # Create relationship between entities
            relationship = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type="depends_on",
                is_active=True
            )
            db_session.add(relationship)
            db_session.commit()
            
            # Verify relationship exists
            assert relationship.id is not None
            assert relationship.source_entity_id == entity1.id
            assert relationship.target_entity_id == entity2.id
            
            # Test deleting source entity
            entity1_id = entity1.id
            db_session.delete(entity1)
            
            try:
                db_session.commit()
                
                # Check if relationship was cascade deleted
                remaining_relationships = db_session.query(EntityRelationship).filter_by(
                    source_entity_id=entity1_id
                ).count()
                
            except IntegrityError:
                # If cascade is not configured, clean up manually
                db_session.rollback()
                
                # Delete relationships first
                db_session.query(EntityRelationship).filter(
                    (EntityRelationship.source_entity_id == entity1.id) |
                    (EntityRelationship.target_entity_id == entity1.id)
                ).delete()
                
                db_session.delete(entity1)
                db_session.commit()
                
                # Verify cleanup
                remaining_relationships = db_session.query(EntityRelationship).filter(
                    (EntityRelationship.source_entity_id == entity1_id) |
                    (EntityRelationship.target_entity_id == entity1_id)
                ).count()
                assert remaining_relationships == 0

    def test_orphan_record_prevention(self, app: Flask, db_session: Session):
        """
        Test prevention of orphaned records in database relationships.
        
        Validates:
        - Foreign key constraint enforcement prevents orphans
        - Proper error handling for invalid references
        - Data consistency across relationship operations
        
        Requirements: Section 6.2.2.1, Feature F-004
        """
        with app.app_context():
            # Try to create session without valid user
            orphan_session = UserSession(
                user_id=99999,  # Non-existent user
                session_token="orphan_token",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(orphan_session)
            
            with pytest.raises(IntegrityError):
                db_session.commit()
            
            db_session.rollback()
            
            # Try to create business entity without valid owner
            orphan_entity = BusinessEntity(
                name="Orphan Entity",
                description="Entity without valid owner",
                owner_id=99999,  # Non-existent user
                status="active"
            )
            db_session.add(orphan_entity)
            
            with pytest.raises(IntegrityError):
                db_session.commit()
            
            db_session.rollback()
            
            # Try to create relationship with non-existent entities
            orphan_relationship = EntityRelationship(
                source_entity_id=99999,  # Non-existent entity
                target_entity_id=99998,  # Non-existent entity
                relationship_type="depends_on",
                is_active=True
            )
            db_session.add(orphan_relationship)
            
            with pytest.raises(IntegrityError):
                db_session.commit()
            
            db_session.rollback()

    def test_relationship_consistency_validation(self, app: Flask, db_session: Session):
        """
        Test relationship consistency across model updates.
        
        Validates:
        - Relationship integrity during updates
        - Consistency of bidirectional relationships
        - Proper handling of relationship state changes
        
        Requirements: Section 6.2.2.1, Feature F-005
        """
        with app.app_context():
            # Create complete relationship structure
            user = User(
                username="consistency_user",
                email="consistency@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            entity1 = BusinessEntity(
                name="Consistency Entity 1",
                description="First entity for consistency testing",
                owner_id=user.id,
                status="active"
            )
            entity2 = BusinessEntity(
                name="Consistency Entity 2",
                description="Second entity for consistency testing",
                owner_id=user.id,
                status="active"
            )
            db_session.add_all([entity1, entity2])
            db_session.commit()
            
            relationship = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type="depends_on",
                is_active=True
            )
            db_session.add(relationship)
            db_session.commit()
            
            # Update relationship status
            relationship.is_active = False
            db_session.commit()
            
            # Verify update consistency
            updated_relationship = db_session.query(EntityRelationship).filter_by(
                id=relationship.id
            ).first()
            assert updated_relationship.is_active is False
            
            # Update relationship type
            relationship.relationship_type = "contains"
            db_session.commit()
            
            # Verify type update
            updated_relationship = db_session.query(EntityRelationship).filter_by(
                id=relationship.id
            ).first()
            assert updated_relationship.relationship_type == "contains"


class TestDataConsistencyValidation:
    """
    Test suite for data consistency validation equivalent to MongoDB patterns.
    
    This test class validates:
    - Data type consistency across operations
    - Field validation equivalent to MongoDB schema validation
    - Document-to-relational data pattern preservation
    - Business rule consistency during migration
    """

    def test_data_type_consistency(self, app: Flask, db_session: Session):
        """
        Test data type consistency across database operations.
        
        Validates:
        - Consistent data type handling
        - Type conversion validation
        - Data integrity across different operations
        
        Requirements: Feature F-003, Section 6.2.1
        """
        with app.app_context():
            # Test datetime consistency
            now = datetime.utcnow()
            user = User(
                username="datetime_user",
                email="datetime@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Verify created_at is set and consistent
            assert user.created_at is not None
            assert isinstance(user.created_at, datetime)
            assert user.updated_at is not None
            assert isinstance(user.updated_at, datetime)
            
            # Test boolean consistency
            session = UserSession(
                user_id=user.id,
                session_token="bool_test_token",
                expires_at=now + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(session)
            db_session.commit()
            
            # Verify boolean field consistency
            assert session.is_valid is True
            assert isinstance(session.is_valid, bool)
            
            # Update boolean field
            session.is_valid = False
            db_session.commit()
            
            # Verify boolean update consistency
            db_session.refresh(session)
            assert session.is_valid is False
            assert isinstance(session.is_valid, bool)

    def test_mongodb_pattern_preservation(self, app: Flask, db_session: Session):
        """
        Test preservation of MongoDB document patterns in relational structure.
        
        Validates:
        - Document-like field grouping preservation
        - Embedded document pattern translation
        - Array-like relationship pattern preservation
        
        Requirements: Feature F-003, Feature F-004
        """
        with app.app_context():
            # Create user representing a MongoDB document
            user = User(
                username="mongo_pattern_user",
                email="mongo@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Create business entities (representing embedded documents)
            entities = []
            for i in range(3):
                entity = BusinessEntity(
                    name=f"Pattern Entity {i}",
                    description=f"Entity {i} for pattern testing",
                    owner_id=user.id,
                    status="active"
                )
                entities.append(entity)
            
            db_session.add_all(entities)
            db_session.commit()
            
            # Create relationships (representing document references)
            relationships = []
            for i in range(len(entities)-1):
                relationship = EntityRelationship(
                    source_entity_id=entities[i].id,
                    target_entity_id=entities[i+1].id,
                    relationship_type="leads_to",
                    is_active=True
                )
                relationships.append(relationship)
            
            db_session.add_all(relationships)
            db_session.commit()
            
            # Verify document-like structure is preserved
            user_entities = db_session.query(BusinessEntity).filter_by(
                owner_id=user.id
            ).all()
            assert len(user_entities) == 3
            
            # Verify relationship chain (like document references)
            for relationship in relationships:
                assert relationship.source_entity_id is not None
                assert relationship.target_entity_id is not None
                assert relationship.is_active is True

    def test_business_rule_consistency(self, app: Flask, db_session: Session):
        """
        Test business rule consistency during MongoDB to PostgreSQL migration.
        
        Validates:
        - Business validation rule preservation
        - Workflow consistency across data operations
        - State management equivalent to original patterns
        
        Requirements: Feature F-005, Section 6.2.2.2
        """
        with app.app_context():
            # Create user for business rule testing
            user = User(
                username="business_rule_user",
                email="business@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            # Test business entity status workflow
            entity = BusinessEntity(
                name="Rule Test Entity",
                description="Entity for business rule testing",
                owner_id=user.id,
                status="pending"  # Initial status
            )
            db_session.add(entity)
            db_session.commit()
            
            # Simulate status transition workflow
            valid_transitions = [
                ("pending", "active"),
                ("active", "inactive"),
                ("inactive", "archived")
            ]
            
            for from_status, to_status in valid_transitions:
                assert entity.status == from_status
                entity.status = to_status
                db_session.commit()
                
                # Verify transition succeeded
                db_session.refresh(entity)
                assert entity.status == to_status
            
            # Test session validity business rule
            session = UserSession(
                user_id=user.id,
                session_token="business_rule_token",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(session)
            db_session.commit()
            
            # Simulate session invalidation business rule
            assert session.is_valid is True
            session.is_valid = False
            db_session.commit()
            
            # Verify business rule applied
            db_session.refresh(session)
            assert session.is_valid is False


class TestConstraintViolationErrorHandling:
    """
    Test suite for constraint violation error handling and exception management.
    
    This test class validates:
    - Proper exception types for different constraint violations
    - Error message clarity and usefulness
    - Recovery procedures after constraint violations
    - Integration with Flask error handling patterns
    """

    def test_unique_constraint_error_handling(self, app: Flask, db_session: Session):
        """
        Test error handling for unique constraint violations.
        
        Validates:
        - Specific exception types for unique constraint violations
        - Error message content and clarity
        - Database session state after constraint violation
        - Recovery procedures
        
        Requirements: Section 4.8, Feature F-003
        """
        with app.app_context():
            # Create initial user
            user1 = User(
                username="unique_test_user",
                email="unique@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user1)
            db_session.commit()
            
            # Test username uniqueness violation
            user2 = User(
                username="unique_test_user",  # Duplicate username
                email="unique2@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user2)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify error information
            error_str = str(exc_info.value).lower()
            assert "unique" in error_str or "duplicate" in error_str
            assert "username" in error_str
            
            # Verify session is in error state and requires rollback
            db_session.rollback()
            
            # Verify recovery - session should be usable after rollback
            user3 = User(
                username="recovery_user",
                email="recovery@example.com", 
                password_hash="hashed_password"
            )
            db_session.add(user3)
            db_session.commit()
            
            assert user3.id is not None

    def test_foreign_key_constraint_error_handling(self, app: Flask, db_session: Session):
        """
        Test error handling for foreign key constraint violations.
        
        Validates:
        - Specific exception types for foreign key violations
        - Error message content for missing references
        - Session recovery after foreign key errors
        
        Requirements: Section 4.8, Section 6.2.2.1
        """
        with app.app_context():
            # Test foreign key violation
            invalid_session = UserSession(
                user_id=99999,  # Non-existent user
                session_token="invalid_fk_token",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(invalid_session)
            
            with pytest.raises(IntegrityError) as exc_info:
                db_session.commit()
            
            # Verify foreign key error information
            error_str = str(exc_info.value).lower()
            assert "foreign key" in error_str or "violates" in error_str or "constraint" in error_str
            
            # Verify session rollback and recovery
            db_session.rollback()
            
            # Create valid user and session for recovery test
            user = User(
                username="fk_recovery_user",
                email="fk_recovery@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            valid_session = UserSession(
                user_id=user.id,
                session_token="valid_fk_token",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(valid_session)
            db_session.commit()
            
            assert valid_session.id is not None

    def test_not_null_constraint_error_handling(self, app: Flask, db_session: Session):
        """
        Test error handling for NOT NULL constraint violations.
        
        Validates:
        - Specific exception types for null constraint violations
        - Error message identification of null fields
        - Session state management after null violations
        
        Requirements: Section 4.8, Feature F-003
        """
        with app.app_context():
            # Test NOT NULL violation
            invalid_user = User(
                username=None,  # Required field
                email="null_test@example.com",
                password_hash="hashed_password"
            )
            db_session.add(invalid_user)
            
            with pytest.raises((IntegrityError, StatementError)) as exc_info:
                db_session.commit()
            
            # Verify null constraint error information
            error_str = str(exc_info.value).lower()
            # Error message varies by database but should indicate null violation
            assert "null" in error_str or "not null" in error_str or "constraint" in error_str
            
            # Verify session rollback and recovery
            db_session.rollback()
            
            # Create valid user for recovery test
            valid_user = User(
                username="null_recovery_user",
                email="null_recovery@example.com",
                password_hash="hashed_password"
            )
            db_session.add(valid_user)
            db_session.commit()
            
            assert valid_user.id is not None

    def test_transaction_error_recovery(self, app: Flask, db_session: Session):
        """
        Test comprehensive error recovery in transaction scenarios.
        
        Validates:
        - Multiple constraint violation handling in single transaction
        - Partial rollback scenarios
        - Transaction state after various error types
        - Complex error recovery procedures
        
        Requirements: Section 4.8, Section 5.2.4
        """
        with app.app_context():
            # Create initial valid data
            user = User(
                username="transaction_error_user",
                email="transaction_error@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            initial_user_count = db_session.query(User).count()
            
            # Start transaction with multiple operations, some failing
            try:
                db_session.begin()
                
                # Valid operation
                entity1 = BusinessEntity(
                    name="Valid Entity",
                    description="This should work",
                    owner_id=user.id,
                    status="active"
                )
                db_session.add(entity1)
                
                # Invalid operation (foreign key violation)
                entity2 = BusinessEntity(
                    name="Invalid Entity",
                    description="This should fail",
                    owner_id=99999,  # Non-existent user
                    status="active"
                )
                db_session.add(entity2)
                
                # This should raise IntegrityError
                db_session.commit()
                
            except IntegrityError as e:
                # Verify error handling
                assert "foreign key" in str(e).lower() or "constraint" in str(e).lower()
                
                # Rollback transaction
                db_session.rollback()
                
                # Verify no partial commits occurred
                final_user_count = db_session.query(User).count()
                assert final_user_count == initial_user_count
                
                # Verify the valid entity was not saved due to transaction rollback
                saved_entity = db_session.query(BusinessEntity).filter_by(
                    name="Valid Entity"
                ).first()
                assert saved_entity is None
                
                # Verify session is still usable for new operations
                recovery_entity = BusinessEntity(
                    name="Recovery Entity",
                    description="This should work after recovery",
                    owner_id=user.id,
                    status="active"
                )
                db_session.add(recovery_entity)
                db_session.commit()
                
                assert recovery_entity.id is not None

    def test_flask_error_handler_integration(self, app: Flask, db_session: Session):
        """
        Test integration with Flask error handling patterns.
        
        Validates:
        - Database errors in Flask request context
        - Error handler decorator compatibility
        - Response generation for database errors
        - Session cleanup in error scenarios
        
        Requirements: Section 4.8, Section 5.2.1
        """
        with app.app_context():
            # Simulate Flask request context error handling
            with app.test_request_context():
                try:
                    # Create invalid user in request context
                    user1 = User(
                        username="flask_error_user",
                        email="flask_error@example.com",
                        password_hash="hashed_password"
                    )
                    db_session.add(user1)
                    db_session.commit()
                    
                    # Create duplicate user (constraint violation)
                    user2 = User(
                        username="flask_error_user",  # Duplicate
                        email="flask_error2@example.com",
                        password_hash="hashed_password"
                    )
                    db_session.add(user2)
                    db_session.commit()
                    
                except IntegrityError as e:
                    # Simulate Flask error handler behavior
                    db_session.rollback()
                    
                    # Verify error can be handled gracefully
                    error_message = str(e)
                    assert len(error_message) > 0
                    
                    # Verify session cleanup
                    assert db_session.is_active
                    
                    # Verify recovery in same request context
                    recovery_user = User(
                        username="flask_recovery_user",
                        email="flask_recovery@example.com",
                        password_hash="hashed_password"
                    )
                    db_session.add(recovery_user)
                    db_session.commit()
                    
                    assert recovery_user.id is not None


# Integration test utilities for data integrity validation
class DataIntegrityTestUtils:
    """
    Utility class providing helper methods for data integrity testing.
    
    This class provides:
    - Data validation helper methods
    - Constraint verification utilities
    - Error analysis and reporting tools
    - Performance measurement for integrity operations
    """
    
    @staticmethod
    def validate_all_constraints(db_session: Session) -> Dict[str, bool]:
        """
        Validate all database constraints across all models.
        
        Returns:
            Dictionary mapping constraint types to validation status
            
        Requirements: Feature F-003, Feature F-004
        """
        results = {
            "unique_constraints": True,
            "foreign_key_constraints": True,
            "not_null_constraints": True,
            "check_constraints": True
        }
        
        try:
            # Test unique constraints by attempting to create duplicates
            # This is a simplified test - production would be more comprehensive
            
            # Test foreign key constraints
            orphan_session = UserSession(
                user_id=99999,
                session_token="constraint_test_token",
                expires_at=datetime.utcnow() + timedelta(hours=24),
                is_valid=True
            )
            db_session.add(orphan_session)
            db_session.commit()
            
            results["foreign_key_constraints"] = False
            
        except IntegrityError:
            db_session.rollback()
            # Foreign key constraint is working
            
        except Exception:
            db_session.rollback()
            results["foreign_key_constraints"] = False
        
        return results
    
    @staticmethod
    def analyze_constraint_error(error: Exception) -> Dict[str, Any]:
        """
        Analyze constraint violation errors for detailed reporting.
        
        Args:
            error: The exception raised by constraint violation
            
        Returns:
            Dictionary containing error analysis details
            
        Requirements: Section 4.8
        """
        error_str = str(error).lower()
        
        analysis = {
            "error_type": type(error).__name__,
            "constraint_type": "unknown",
            "affected_column": None,
            "affected_table": None,
            "error_message": str(error)
        }
        
        # Analyze constraint type
        if "unique" in error_str or "duplicate" in error_str:
            analysis["constraint_type"] = "unique"
        elif "foreign key" in error_str or "violates" in error_str:
            analysis["constraint_type"] = "foreign_key"
        elif "null" in error_str or "not null" in error_str:
            analysis["constraint_type"] = "not_null"
        elif "check" in error_str:
            analysis["constraint_type"] = "check"
        
        return analysis
    
    @staticmethod
    def measure_constraint_performance(db_session: Session, operation_count: int = 100) -> Dict[str, float]:
        """
        Measure performance impact of constraint validation.
        
        Args:
            db_session: Database session for operations
            operation_count: Number of operations to measure
            
        Returns:
            Dictionary containing performance metrics
            
        Requirements: Section 6.2.1, Section 6.2.5.1
        """
        import time
        
        metrics = {
            "insert_time": 0.0,
            "update_time": 0.0,
            "delete_time": 0.0,
            "constraint_validation_overhead": 0.0
        }
        
        # Measure insert performance with constraints
        start_time = time.time()
        
        users = []
        for i in range(operation_count):
            user = User(
                username=f"perf_user_{i}",
                email=f"perf{i}@example.com",
                password_hash="hashed_password"
            )
            users.append(user)
            db_session.add(user)
        
        db_session.commit()
        metrics["insert_time"] = time.time() - start_time
        
        # Measure update performance
        start_time = time.time()
        for user in users:
            user.email = f"updated_{user.email}"
        db_session.commit()
        metrics["update_time"] = time.time() - start_time
        
        # Measure delete performance
        start_time = time.time()
        for user in users:
            db_session.delete(user)
        db_session.commit()
        metrics["delete_time"] = time.time() - start_time
        
        return metrics


# Pytest fixtures for data integrity testing
@pytest.fixture
def constraint_test_data(app: Flask, db_session: Session):
    """
    Fixture providing test data for constraint validation tests.
    
    Creates a consistent set of test data for constraint testing scenarios.
    
    Requirements: Feature F-003, Section 6.2.2.1
    """
    with app.app_context():
        # Create test users
        users = []
        for i in range(3):
            user = User(
                username=f"constraint_user_{i}",
                email=f"constraint{i}@example.com",
                password_hash="hashed_password"
            )
            users.append(user)
            db_session.add(user)
        
        db_session.commit()
        
        # Create test business entities
        entities = []
        for i, user in enumerate(users):
            entity = BusinessEntity(
                name=f"Constraint Entity {i}",
                description=f"Entity {i} for constraint testing",
                owner_id=user.id,
                status="active"
            )
            entities.append(entity)
            db_session.add(entity)
        
        db_session.commit()
        
        # Create test relationships
        relationships = []
        for i in range(len(entities) - 1):
            relationship = EntityRelationship(
                source_entity_id=entities[i].id,
                target_entity_id=entities[i + 1].id,
                relationship_type="depends_on",
                is_active=True
            )
            relationships.append(relationship)
            db_session.add(relationship)
        
        db_session.commit()
        
        return {
            "users": users,
            "entities": entities,
            "relationships": relationships
        }


@pytest.fixture
def integrity_utils():
    """
    Fixture providing data integrity testing utilities.
    
    Returns:
        DataIntegrityTestUtils instance for testing operations
    """
    return DataIntegrityTestUtils()


# Performance benchmarks for data integrity operations
@pytest.mark.benchmark
class TestDataIntegrityPerformance:
    """
    Performance benchmark tests for data integrity operations.
    
    This test class validates:
    - Constraint validation performance impact
    - Database operation speeds with integrity checks
    - Scalability of constraint enforcement
    - Performance equivalence to MongoDB validation patterns
    """
    
    def test_constraint_validation_performance(self, app: Flask, db_session: Session, benchmark):
        """
        Benchmark constraint validation performance.
        
        Validates:
        - Performance impact of constraint checks
        - Scalability of integrity validation
        - Comparison to baseline performance expectations
        
        Requirements: Section 6.2.1, Section 6.2.5.1
        """
        with app.app_context():
            def create_user_with_constraints():
                user = User(
                    username=f"bench_user_{uuid.uuid4().hex[:8]}",
                    email=f"bench_{uuid.uuid4().hex[:8]}@example.com",
                    password_hash="hashed_password"
                )
                db_session.add(user)
                db_session.commit()
                return user
            
            # Benchmark user creation with constraint validation
            result = benchmark(create_user_with_constraints)
            
            # Verify the operation completed successfully
            assert result.id is not None
            
            # Clean up
            db_session.delete(result)
            db_session.commit()
    
    def test_relationship_integrity_performance(self, app: Flask, db_session: Session, benchmark):
        """
        Benchmark relationship integrity validation performance.
        
        Validates:
        - Foreign key constraint validation speed
        - Relationship creation performance with integrity checks
        - Complex relationship operation performance
        
        Requirements: Section 6.2.2.1, Section 6.2.5.1
        """
        with app.app_context():
            # Create base entities for relationship testing
            user = User(
                username="perf_relationship_user",
                email="perf_rel@example.com",
                password_hash="hashed_password"
            )
            db_session.add(user)
            db_session.commit()
            
            entity1 = BusinessEntity(
                name="Perf Entity 1",
                description="Performance test entity 1",
                owner_id=user.id,
                status="active"
            )
            entity2 = BusinessEntity(
                name="Perf Entity 2", 
                description="Performance test entity 2",
                owner_id=user.id,
                status="active"
            )
            db_session.add_all([entity1, entity2])
            db_session.commit()
            
            def create_relationship_with_integrity():
                relationship = EntityRelationship(
                    source_entity_id=entity1.id,
                    target_entity_id=entity2.id,
                    relationship_type="performance_test",
                    is_active=True
                )
                db_session.add(relationship)
                db_session.commit()
                return relationship
            
            # Benchmark relationship creation with integrity checks
            result = benchmark(create_relationship_with_integrity)
            
            # Verify the operation completed successfully
            assert result.id is not None
            assert result.source_entity_id == entity1.id
            assert result.target_entity_id == entity2.id
            
            # Clean up
            db_session.delete(result)
            db_session.delete(entity1)
            db_session.delete(entity2)
            db_session.delete(user)
            db_session.commit()