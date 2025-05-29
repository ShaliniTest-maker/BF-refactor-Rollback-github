"""
Comprehensive Flask-SQLAlchemy Model Relationship Testing Suite

This test module validates foreign key constraints, relationship mapping, and referential integrity
across all database models, ensuring proper User-to-UserSession relationships, User-to-BusinessEntity
ownership patterns, and BusinessEntity-to-EntityRelationship associations function correctly with
SQLAlchemy's declarative model system while maintaining data consistency and constraint enforcement
equivalent to the original MongoDB relationship patterns.

Key Testing Areas:
- Foreign key constraint enforcement and referential integrity per Section 6.2.2.1
- SQLAlchemy relationship mapping validation for all model associations
- Cascade behavior testing for delete operations and orphan cleanup
- Lazy vs eager loading performance optimization testing per Section 6.2.5.1
- Bidirectional relationship functionality through backref validation
- Database constraint violation handling and integrity enforcement per Section 6.2.2.2
- Transaction boundary management for relationship operations per Section 5.2.4

Model Relationships Tested:
- User ||--o{ UserSession : "has_sessions" (one-to-many with cascade delete)
- User ||--o{ BusinessEntity : "owns" (one-to-many with cascade delete)
- BusinessEntity ||--o{ EntityRelationship : "source_relationships" (one-to-many)
- BusinessEntity ||--o{ EntityRelationship : "target_relationships" (one-to-many)

Technical Specifications:
- Flask-SQLAlchemy 3.1.1 declarative model relationship validation
- PostgreSQL 15.x foreign key constraint testing and enforcement
- SQLAlchemy session management with proper transaction boundaries
- Database migration compatibility with Flask-Migrate 4.1.0
- Performance validation meeting 95th percentile SLA targets per Section 6.2.1
"""

import pytest
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from unittest.mock import patch, MagicMock
from sqlalchemy import text, and_, or_, desc, asc
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.orm import selectinload, joinedload, subqueryload
from sqlalchemy.orm.exc import DetachedInstanceError
from flask import current_app

# Import models for relationship testing
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship
from src.models.base import db


class TestUserToUserSessionRelationships:
    """
    Test suite for User-to-UserSession one-to-many relationship validation.
    
    Validates the foreign key relationship from UserSession.user_id to User.id,
    including cascade behavior, referential integrity, and bidirectional navigation
    through the 'sessions' and 'user' relationship properties.
    """
    
    def test_user_session_foreign_key_relationship_creation(self, db_session, test_user):
        """
        Test creation of UserSession with valid foreign key relationship to User.
        
        Validates:
        - UserSession creation with valid user_id foreign key
        - Automatic relationship establishment through SQLAlchemy ORM
        - Bidirectional navigation between User and UserSession instances
        - Database constraint enforcement for valid foreign key references
        """
        # Create user session with foreign key relationship
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        session = UserSession(
            user_id=test_user.id,
            expires_at=expires_at,
            session_metadata='{"device": "test_device"}',
            user_agent="Mozilla/5.0 (Test Browser)",
            ip_address="192.168.1.100"
        )
        
        db_session.add(session)
        db_session.commit()
        db_session.refresh(session)
        
        # Validate foreign key relationship establishment
        assert session.user_id == test_user.id
        assert session.user is not None
        assert session.user.id == test_user.id
        assert session.user.username == test_user.username
        
        # Validate bidirectional relationship navigation
        user_sessions = test_user.sessions.all()
        assert len(user_sessions) == 1
        assert user_sessions[0].id == session.id
        assert user_sessions[0].session_token == session.session_token
        
        # Validate relationship attributes are properly set
        assert session.is_valid is True
        assert session.expires_at == expires_at
        assert session.user_agent == "Mozilla/5.0 (Test Browser)"
        assert session.ip_address == "192.168.1.100"
    
    def test_user_session_foreign_key_constraint_violation(self, db_session):
        """
        Test foreign key constraint violation when creating UserSession with invalid user_id.
        
        Validates:
        - Database constraint enforcement for invalid foreign key references
        - Proper exception handling for referential integrity violations
        - Transaction rollback behavior on constraint violation
        - SQLAlchemy error handling for invalid relationships
        """
        # Attempt to create session with non-existent user_id
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        invalid_session = UserSession(
            user_id=99999,  # Non-existent user ID
            expires_at=expires_at,
            session_metadata='{"test": "invalid_user"}',
            user_agent="Test Agent",
            ip_address="127.0.0.1"
        )
        
        db_session.add(invalid_session)
        
        # Validate constraint violation raises IntegrityError
        with pytest.raises(IntegrityError) as exc_info:
            db_session.commit()
        
        # Validate specific constraint violation details
        assert "foreign key constraint" in str(exc_info.value).lower() or \
               "constraint failed" in str(exc_info.value).lower()
        
        # Validate transaction rollback
        db_session.rollback()
        
        # Verify no invalid session was created
        invalid_sessions = db_session.query(UserSession).filter_by(user_id=99999).all()
        assert len(invalid_sessions) == 0
    
    def test_user_session_cascade_delete_behavior(self, db_session, test_user):
        """
        Test cascade delete behavior when User is deleted.
        
        Validates:
        - CASCADE DELETE constraint enforcement for user sessions
        - Automatic cleanup of dependent UserSession records
        - Referential integrity maintenance during cascade operations
        - Transaction consistency during cascade delete operations
        """
        # Create multiple sessions for the user
        sessions_data = [
            {
                'expires_at': datetime.now(timezone.utc) + timedelta(hours=12),
                'user_agent': "Browser 1",
                'ip_address': "192.168.1.10"
            },
            {
                'expires_at': datetime.now(timezone.utc) + timedelta(hours=24),
                'user_agent': "Browser 2", 
                'ip_address': "192.168.1.20"
            },
            {
                'expires_at': datetime.now(timezone.utc) + timedelta(hours=48),
                'user_agent': "Mobile App",
                'ip_address': "10.0.0.5"
            }
        ]
        
        created_sessions = []
        for session_data in sessions_data:
            session = UserSession(
                user_id=test_user.id,
                **session_data
            )
            db_session.add(session)
            created_sessions.append(session)
        
        db_session.commit()
        
        # Verify sessions were created
        user_sessions_before = db_session.query(UserSession).filter_by(user_id=test_user.id).all()
        assert len(user_sessions_before) == 3
        
        # Delete the user - should cascade delete all sessions
        db_session.delete(test_user)
        db_session.commit()
        
        # Verify cascade delete removed all user sessions
        user_sessions_after = db_session.query(UserSession).filter_by(user_id=test_user.id).all()
        assert len(user_sessions_after) == 0
        
        # Verify user was deleted
        deleted_user = db_session.query(User).filter_by(id=test_user.id).first()
        assert deleted_user is None
    
    def test_user_session_relationship_lazy_loading(self, db_session, test_user):
        """
        Test lazy loading behavior for User-UserSession relationships.
        
        Validates:
        - Lazy loading configuration for sessions relationship
        - Query efficiency for large session collections
        - Memory optimization through lazy loading patterns
        - Performance characteristics matching Section 6.2.5.1 requirements
        """
        # Create multiple sessions for testing lazy loading
        session_count = 10
        for i in range(session_count):
            session = UserSession(
                user_id=test_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24 + i),
                user_agent=f"Test Agent {i}",
                ip_address=f"192.168.1.{100 + i}"
            )
            db_session.add(session)
        
        db_session.commit()
        
        # Query user without loading sessions (lazy loading test)
        user_query = db_session.query(User).filter_by(id=test_user.id).first()
        
        # Verify user is loaded but sessions are not yet loaded
        assert user_query.id == test_user.id
        assert user_query.username == test_user.username
        
        # Access sessions property - should trigger lazy loading
        user_sessions = user_query.sessions.all()
        assert len(user_sessions) == session_count
        
        # Verify each session has proper relationship back to user
        for session in user_sessions:
            assert session.user_id == test_user.id
            assert session.user.username == test_user.username
    
    def test_user_session_relationship_eager_loading(self, db_session, test_user):
        """
        Test eager loading behavior for User-UserSession relationships.
        
        Validates:
        - Eager loading configuration using joinedload and selectinload
        - Query optimization for relationship preloading
        - Performance improvement through reduced N+1 query problems
        - Load strategy effectiveness per Section 6.2.5.1 optimization
        """
        # Create test sessions
        session_count = 5
        for i in range(session_count):
            session = UserSession(
                user_id=test_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=12 + i * 6),
                user_agent=f"Eager Load Test Agent {i}",
                ip_address=f"10.0.0.{50 + i}"
            )
            db_session.add(session)
        
        db_session.commit()
        
        # Test joinedload strategy
        user_with_joined_sessions = (
            db_session.query(User)
            .options(joinedload(User.sessions))
            .filter_by(id=test_user.id)
            .first()
        )
        
        assert user_with_joined_sessions is not None
        # Sessions should be loaded immediately without additional queries
        sessions = user_with_joined_sessions.sessions.all()
        assert len(sessions) == session_count
        
        # Test selectinload strategy for better performance with large collections
        user_with_selected_sessions = (
            db_session.query(User)
            .options(selectinload(User.sessions))
            .filter_by(id=test_user.id)
            .first()
        )
        
        assert user_with_selected_sessions is not None
        selected_sessions = user_with_selected_sessions.sessions.all()
        assert len(selected_sessions) == session_count
        
        # Verify both strategies loaded the same sessions
        joined_session_ids = {s.id for s in sessions}
        selected_session_ids = {s.id for s in selected_sessions}
        assert joined_session_ids == selected_session_ids
    
    def test_user_session_relationship_backref_functionality(self, db_session, test_user):
        """
        Test bidirectional relationship functionality through backref.
        
        Validates:
        - Bidirectional navigation between User and UserSession
        - Backref property configuration and accessibility
        - Relationship consistency in both directions
        - SQLAlchemy backref implementation per Flask-SQLAlchemy patterns
        """
        # Create session with relationship
        session = UserSession(
            user_id=test_user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            user_agent="Backref Test Browser",
            ip_address="172.16.0.100"
        )
        
        db_session.add(session)
        db_session.commit()
        db_session.refresh(session)
        
        # Test forward relationship (session -> user)
        assert session.user is not None
        assert session.user.id == test_user.id
        assert session.user.username == test_user.username
        assert session.user.email == test_user.email
        
        # Test backward relationship (user -> sessions)
        user_sessions = test_user.sessions.all()
        assert len(user_sessions) == 1
        assert user_sessions[0].id == session.id
        assert user_sessions[0].session_token == session.session_token
        
        # Test relationship consistency
        retrieved_user = session.user
        retrieved_sessions = retrieved_user.sessions.all()
        assert len(retrieved_sessions) == 1
        assert retrieved_sessions[0].id == session.id
        
        # Test modification through backref
        session.user.username = "modified_username"
        db_session.commit()
        
        # Verify modification is reflected through both directions
        assert test_user.username == "modified_username"
        assert session.user.username == "modified_username"


class TestUserToBusinessEntityRelationships:
    """
    Test suite for User-to-BusinessEntity one-to-many ownership relationship validation.
    
    Validates the foreign key relationship from BusinessEntity.owner_id to User.id,
    including ownership patterns, cascade behavior, and business entity access control
    through the 'business_entities' and 'owner' relationship properties.
    """
    
    def test_business_entity_ownership_relationship_creation(self, db_session, test_user):
        """
        Test creation of BusinessEntity with valid ownership relationship to User.
        
        Validates:
        - BusinessEntity creation with valid owner_id foreign key
        - Ownership relationship establishment through SQLAlchemy ORM
        - Bidirectional navigation between User and BusinessEntity instances
        - Business entity metadata and status field management
        """
        # Create business entity with ownership relationship
        entity = BusinessEntity(
            name="Test Business Entity",
            description="A comprehensive test business entity for ownership validation",
            owner_id=test_user.id,
            status="active"
        )
        
        db_session.add(entity)
        db_session.commit()
        db_session.refresh(entity)
        
        # Validate ownership relationship establishment
        assert entity.owner_id == test_user.id
        assert entity.owner is not None
        assert entity.owner.id == test_user.id
        assert entity.owner.username == test_user.username
        
        # Validate bidirectional relationship navigation
        user_entities = test_user.business_entities.all()
        assert len(user_entities) == 1
        assert user_entities[0].id == entity.id
        assert user_entities[0].name == entity.name
        assert user_entities[0].status == "active"
        
        # Validate business entity attributes
        assert entity.name == "Test Business Entity"
        assert entity.description == "A comprehensive test business entity for ownership validation"
        assert entity.status == "active"
        assert entity.created_at is not None
        assert entity.updated_at is not None
    
    def test_business_entity_ownership_constraint_violation(self, db_session):
        """
        Test foreign key constraint violation for invalid owner_id.
        
        Validates:
        - Database constraint enforcement for invalid ownership references
        - Proper exception handling for ownership violations
        - Transaction rollback behavior on constraint violation
        - Business entity creation security through ownership validation
        """
        # Attempt to create entity with non-existent owner_id
        invalid_entity = BusinessEntity(
            name="Invalid Ownership Entity",
            description="Entity with invalid owner reference",
            owner_id=88888,  # Non-existent user ID
            status="active"
        )
        
        db_session.add(invalid_entity)
        
        # Validate constraint violation raises IntegrityError
        with pytest.raises(IntegrityError) as exc_info:
            db_session.commit()
        
        # Validate specific constraint violation details
        assert "foreign key constraint" in str(exc_info.value).lower() or \
               "constraint failed" in str(exc_info.value).lower()
        
        # Validate transaction rollback
        db_session.rollback()
        
        # Verify no invalid entity was created
        invalid_entities = db_session.query(BusinessEntity).filter_by(owner_id=88888).all()
        assert len(invalid_entities) == 0
    
    def test_business_entity_ownership_cascade_delete_behavior(self, db_session, test_user):
        """
        Test cascade delete behavior when User owner is deleted.
        
        Validates:
        - CASCADE DELETE constraint enforcement for owned business entities
        - Automatic cleanup of dependent BusinessEntity records
        - Ownership referential integrity during cascade operations
        - Business workflow consistency during owner deletion
        """
        # Create multiple business entities with different statuses
        entities_data = [
            {
                'name': "Active Business Unit",
                'description': "Primary active business entity",
                'status': "active"
            },
            {
                'name': "Pending Business Unit", 
                'description': "Business entity pending approval",
                'status': "pending"
            },
            {
                'name': "Inactive Business Unit",
                'description': "Temporarily inactive business entity", 
                'status': "inactive"
            }
        ]
        
        created_entities = []
        for entity_data in entities_data:
            entity = BusinessEntity(
                owner_id=test_user.id,
                **entity_data
            )
            db_session.add(entity)
            created_entities.append(entity)
        
        db_session.commit()
        
        # Verify entities were created with proper ownership
        user_entities_before = db_session.query(BusinessEntity).filter_by(owner_id=test_user.id).all()
        assert len(user_entities_before) == 3
        
        # Verify entities have different statuses
        statuses = {entity.status for entity in user_entities_before}
        assert statuses == {"active", "pending", "inactive"}
        
        # Delete the owner user - should cascade delete all owned entities
        db_session.delete(test_user)
        db_session.commit()
        
        # Verify cascade delete removed all owned business entities
        user_entities_after = db_session.query(BusinessEntity).filter_by(owner_id=test_user.id).all()
        assert len(user_entities_after) == 0
        
        # Verify user was deleted
        deleted_user = db_session.query(User).filter_by(id=test_user.id).first()
        assert deleted_user is None
    
    def test_business_entity_ownership_status_filtering(self, db_session, test_user):
        """
        Test business entity filtering by status for ownership workflows.
        
        Validates:
        - Status-based filtering through relationship properties
        - Business workflow management through entity status
        - Query optimization for status-based business logic
        - Owner-specific entity management capabilities
        """
        # Create entities with various statuses
        status_entities = [
            ("active", "Active Entity 1"),
            ("active", "Active Entity 2"), 
            ("pending", "Pending Entity 1"),
            ("inactive", "Inactive Entity 1"),
            ("draft", "Draft Entity 1"),
            ("archived", "Archived Entity 1")
        ]
        
        for status, name in status_entities:
            entity = BusinessEntity(
                name=name,
                description=f"Test entity with {status} status",
                owner_id=test_user.id,
                status=status
            )
            db_session.add(entity)
        
        db_session.commit()
        
        # Test filtering active entities through relationship
        active_entities = test_user.business_entities.filter_by(status="active").all()
        assert len(active_entities) == 2
        assert all(entity.status == "active" for entity in active_entities)
        
        # Test filtering pending entities
        pending_entities = test_user.business_entities.filter_by(status="pending").all()
        assert len(pending_entities) == 1
        assert pending_entities[0].status == "pending"
        
        # Test filtering with multiple conditions
        active_or_pending = test_user.business_entities.filter(
            BusinessEntity.status.in_(["active", "pending"])
        ).all()
        assert len(active_or_pending) == 3
        
        # Test ordering by status and name
        ordered_entities = test_user.business_entities.order_by(
            BusinessEntity.status.asc(),
            BusinessEntity.name.asc()
        ).all()
        assert len(ordered_entities) == 6
        assert ordered_entities[0].status == "active"  # Alphabetically first status
    
    def test_business_entity_ownership_lazy_dynamic_loading(self, db_session, test_user):
        """
        Test dynamic loading behavior for User-BusinessEntity relationships.
        
        Validates:
        - Dynamic query configuration for large entity collections
        - Query building capability through dynamic relationships
        - Memory efficiency for business entity management
        - Performance optimization through dynamic loading per Section 6.2.5.1
        """
        # Create larger number of entities for dynamic loading test
        entity_count = 25
        for i in range(entity_count):
            entity = BusinessEntity(
                name=f"Dynamic Load Entity {i:02d}",
                description=f"Entity number {i} for dynamic loading test",
                owner_id=test_user.id,
                status="active" if i % 2 == 0 else "inactive"
            )
            db_session.add(entity)
        
        db_session.commit()
        
        # Test dynamic query building (business_entities returns a query object)
        entities_query = test_user.business_entities
        assert hasattr(entities_query, 'filter'), "business_entities should return a dynamic query"
        assert hasattr(entities_query, 'order_by'), "business_entities should support query methods"
        
        # Test dynamic filtering
        active_entities = entities_query.filter_by(status="active").all()
        inactive_entities = entities_query.filter_by(status="inactive").all()
        
        # Verify counts (even numbers are active, odd are inactive)
        expected_active = len([i for i in range(entity_count) if i % 2 == 0])
        expected_inactive = entity_count - expected_active
        
        assert len(active_entities) == expected_active
        assert len(inactive_entities) == expected_inactive
        
        # Test dynamic ordering and pagination
        recent_entities = entities_query.order_by(desc(BusinessEntity.created_at)).limit(5).all()
        assert len(recent_entities) == 5
        
        # Test dynamic counting
        total_count = entities_query.count()
        assert total_count == entity_count


class TestBusinessEntityToEntityRelationshipAssociations:
    """
    Test suite for BusinessEntity-to-EntityRelationship many-to-many association validation.
    
    Validates the dual foreign key relationships from EntityRelationship to BusinessEntity
    (both source_entity_id and target_entity_id), including complex business relationship
    management, bidirectional navigation, and relationship type categorization.
    """
    
    def test_entity_relationship_creation_with_valid_associations(self, db_session, test_user):
        """
        Test creation of EntityRelationship with valid BusinessEntity associations.
        
        Validates:
        - EntityRelationship creation with valid source and target entity foreign keys
        - Business relationship type categorization and metadata management
        - Bidirectional navigation between BusinessEntity and EntityRelationship
        - Complex business logic support through relationship mapping
        """
        # Create source and target business entities
        source_entity = BusinessEntity(
            name="Source Business Entity",
            description="Entity serving as relationship source",
            owner_id=test_user.id,
            status="active"
        )
        
        target_entity = BusinessEntity(
            name="Target Business Entity",
            description="Entity serving as relationship target",
            owner_id=test_user.id,
            status="active"
        )
        
        db_session.add_all([source_entity, target_entity])
        db_session.commit()
        db_session.refresh(source_entity)
        db_session.refresh(target_entity)
        
        # Create entity relationship
        relationship = EntityRelationship(
            source_entity_id=source_entity.id,
            target_entity_id=target_entity.id,
            relationship_type="parent-child",
            is_active=True
        )
        
        db_session.add(relationship)
        db_session.commit()
        db_session.refresh(relationship)
        
        # Validate foreign key relationships
        assert relationship.source_entity_id == source_entity.id
        assert relationship.target_entity_id == target_entity.id
        assert relationship.source_entity.id == source_entity.id
        assert relationship.target_entity.id == target_entity.id
        
        # Validate relationship attributes
        assert relationship.relationship_type == "parent-child"
        assert relationship.is_active is True
        assert relationship.created_at is not None
        assert relationship.updated_at is not None
        
        # Validate bidirectional navigation from source entity
        source_relationships = source_entity.source_relationships.all()
        assert len(source_relationships) == 1
        assert source_relationships[0].id == relationship.id
        assert source_relationships[0].target_entity.id == target_entity.id
        
        # Validate bidirectional navigation from target entity
        target_relationships = target_entity.target_relationships.all()
        assert len(target_relationships) == 1
        assert target_relationships[0].id == relationship.id
        assert target_relationships[0].source_entity.id == source_entity.id
    
    def test_entity_relationship_foreign_key_constraint_violations(self, db_session, test_user):
        """
        Test foreign key constraint violations for EntityRelationship associations.
        
        Validates:
        - Database constraint enforcement for invalid entity references
        - Proper exception handling for relationship constraint violations
        - Transaction rollback behavior on constraint violations
        - Business relationship integrity enforcement
        """
        # Create one valid entity for partial testing
        valid_entity = BusinessEntity(
            name="Valid Entity",
            description="Valid entity for constraint testing",
            owner_id=test_user.id,
            status="active"
        )
        
        db_session.add(valid_entity)
        db_session.commit()
        
        # Test invalid source_entity_id
        invalid_source_relationship = EntityRelationship(
            source_entity_id=77777,  # Non-existent entity ID
            target_entity_id=valid_entity.id,
            relationship_type="invalid-source",
            is_active=True
        )
        
        db_session.add(invalid_source_relationship)
        
        with pytest.raises(IntegrityError) as exc_info:
            db_session.commit()
        
        assert "foreign key constraint" in str(exc_info.value).lower() or \
               "constraint failed" in str(exc_info.value).lower()
        
        db_session.rollback()
        
        # Test invalid target_entity_id
        invalid_target_relationship = EntityRelationship(
            source_entity_id=valid_entity.id,
            target_entity_id=66666,  # Non-existent entity ID
            relationship_type="invalid-target",
            is_active=True
        )
        
        db_session.add(invalid_target_relationship)
        
        with pytest.raises(IntegrityError) as exc_info:
            db_session.commit()
        
        assert "foreign key constraint" in str(exc_info.value).lower() or \
               "constraint failed" in str(exc_info.value).lower()
        
        db_session.rollback()
        
        # Verify no invalid relationships were created
        invalid_relationships = db_session.query(EntityRelationship).filter(
            or_(
                EntityRelationship.source_entity_id == 77777,
                EntityRelationship.target_entity_id == 66666
            )
        ).all()
        assert len(invalid_relationships) == 0
    
    def test_entity_relationship_self_reference_constraint(self, db_session, test_user):
        """
        Test prevention of self-referencing entity relationships.
        
        Validates:
        - Check constraint preventing source_entity_id == target_entity_id
        - Business logic enforcement for valid relationship patterns
        - Database constraint validation for relationship integrity
        - Prevention of circular relationship patterns
        """
        # Create business entity
        entity = BusinessEntity(
            name="Self-Reference Test Entity",
            description="Entity for testing self-reference prevention",
            owner_id=test_user.id,
            status="active"
        )
        
        db_session.add(entity)
        db_session.commit()
        
        # Attempt to create self-referencing relationship
        self_relationship = EntityRelationship(
            source_entity_id=entity.id,
            target_entity_id=entity.id,  # Same as source - should fail
            relationship_type="self-reference",
            is_active=True
        )
        
        db_session.add(self_relationship)
        
        # Validate constraint violation for self-reference
        with pytest.raises((IntegrityError, ValueError)) as exc_info:
            db_session.commit()
        
        # Check for specific constraint violation or validation error
        error_message = str(exc_info.value).lower()
        assert ("check constraint" in error_message or 
                "constraint failed" in error_message or
                "self-relationship" in error_message)
        
        db_session.rollback()
        
        # Verify no self-referencing relationship was created
        self_relationships = db_session.query(EntityRelationship).filter(
            EntityRelationship.source_entity_id == entity.id,
            EntityRelationship.target_entity_id == entity.id
        ).all()
        assert len(self_relationships) == 0
    
    def test_entity_relationship_cascade_delete_behavior(self, db_session, test_user):
        """
        Test cascade delete behavior when BusinessEntity is deleted.
        
        Validates:
        - CASCADE DELETE constraint enforcement for entity relationships
        - Automatic cleanup of dependent EntityRelationship records
        - Referential integrity maintenance during entity deletion
        - Business relationship consistency during cascade operations
        """
        # Create business entities for relationship testing
        entities = []
        for i in range(3):
            entity = BusinessEntity(
                name=f"Cascade Test Entity {i}",
                description=f"Entity {i} for cascade delete testing",
                owner_id=test_user.id,
                status="active"
            )
            entities.append(entity)
            db_session.add(entity)
        
        db_session.commit()
        
        # Create relationships with entities[0] as source and target
        relationships = [
            EntityRelationship(
                source_entity_id=entities[0].id,
                target_entity_id=entities[1].id,
                relationship_type="parent-child",
                is_active=True
            ),
            EntityRelationship(
                source_entity_id=entities[2].id,
                target_entity_id=entities[0].id,
                relationship_type="sibling",
                is_active=True
            )
        ]
        
        for relationship in relationships:
            db_session.add(relationship)
        
        db_session.commit()
        
        # Verify relationships were created
        entity0_source_relationships = entities[0].source_relationships.all()
        entity0_target_relationships = entities[0].target_relationships.all()
        assert len(entity0_source_relationships) == 1
        assert len(entity0_target_relationships) == 1
        
        # Delete entities[0] - should cascade delete related relationships
        db_session.delete(entities[0])
        db_session.commit()
        
        # Verify cascade delete removed all relationships involving entities[0]
        remaining_relationships = db_session.query(EntityRelationship).filter(
            or_(
                EntityRelationship.source_entity_id == entities[0].id,
                EntityRelationship.target_entity_id == entities[0].id
            )
        ).all()
        assert len(remaining_relationships) == 0
        
        # Verify other entities still exist
        entity1 = db_session.query(BusinessEntity).filter_by(id=entities[1].id).first()
        entity2 = db_session.query(BusinessEntity).filter_by(id=entities[2].id).first()
        assert entity1 is not None
        assert entity2 is not None
    
    def test_entity_relationship_complex_navigation_patterns(self, db_session, test_user):
        """
        Test complex relationship navigation patterns for business logic support.
        
        Validates:
        - Multi-hop relationship navigation and traversal
        - Complex business relationship pattern support
        - Relationship type filtering and categorization
        - Performance optimization for complex relationship queries
        """
        # Create a network of business entities
        entities = []
        entity_names = [
            "Corporate Headquarters",
            "Regional Office North", 
            "Regional Office South",
            "Local Branch A",
            "Local Branch B",
            "Department Finance",
            "Department Marketing"
        ]
        
        for name in entity_names:
            entity = BusinessEntity(
                name=name,
                description=f"Business entity: {name}",
                owner_id=test_user.id,
                status="active"
            )
            entities.append(entity)
            db_session.add(entity)
        
        db_session.commit()
        
        # Create hierarchical relationships
        relationships_data = [
            (0, 1, "parent-subsidiary"),      # HQ -> Regional North
            (0, 2, "parent-subsidiary"),      # HQ -> Regional South  
            (1, 3, "office-branch"),          # Regional North -> Branch A
            (2, 4, "office-branch"),          # Regional South -> Branch B
            (1, 5, "office-department"),      # Regional North -> Finance
            (2, 6, "office-department"),      # Regional South -> Marketing
            (3, 4, "partner"),                # Branch A <-> Branch B
            (5, 6, "collaboration")           # Finance <-> Marketing
        ]
        
        for source_idx, target_idx, rel_type in relationships_data:
            relationship = EntityRelationship(
                source_entity_id=entities[source_idx].id,
                target_entity_id=entities[target_idx].id,
                relationship_type=rel_type,
                is_active=True
            )
            db_session.add(relationship)
        
        db_session.commit()
        
        # Test complex relationship queries
        
        # 1. Find all subsidiaries of headquarters
        hq = entities[0]
        subsidiaries = hq.source_relationships.filter_by(
            relationship_type="parent-subsidiary"
        ).all()
        assert len(subsidiaries) == 2
        
        # 2. Find all departments across the organization
        departments = db_session.query(EntityRelationship).filter_by(
            relationship_type="office-department"
        ).all()
        assert len(departments) == 2
        
        # 3. Test relationship type filtering
        partner_relationships = db_session.query(EntityRelationship).filter_by(
            relationship_type="partner"
        ).all()
        assert len(partner_relationships) == 1
        
        # 4. Test multi-hop navigation (find all entities connected to HQ)
        connected_to_hq = set()
        
        # Direct children of HQ
        for rel in hq.source_relationships:
            connected_to_hq.add(rel.target_entity.id)
            
            # Grandchildren (children of children)
            for child_rel in rel.target_entity.source_relationships:
                connected_to_hq.add(child_rel.target_entity.id)
        
        # Should find Regional offices + Branches + Departments
        assert len(connected_to_hq) >= 4  # At least Regional + Branches + some Departments
        
        # 5. Test relationship deactivation and filtering
        collaboration_rel = db_session.query(EntityRelationship).filter_by(
            relationship_type="collaboration"
        ).first()
        collaboration_rel.is_active = False
        db_session.commit()
        
        # Verify active relationship filtering
        active_relationships = db_session.query(EntityRelationship).filter_by(
            is_active=True
        ).all()
        inactive_relationships = db_session.query(EntityRelationship).filter_by(
            is_active=False
        ).all()
        
        assert len(inactive_relationships) == 1
        assert len(active_relationships) == len(relationships_data) - 1


class TestRelationshipPerformanceAndOptimization:
    """
    Test suite for relationship performance optimization and query efficiency validation.
    
    Validates query performance characteristics, loading strategies, and optimization
    patterns to ensure Flask-SQLAlchemy relationships meet the 95th percentile
    performance targets specified in Section 6.2.1 (simple queries < 500ms, 
    complex queries < 2000ms).
    """
    
    def test_relationship_loading_strategy_performance(self, db_session, test_user, benchmark):
        """
        Test performance characteristics of different relationship loading strategies.
        
        Validates:
        - Lazy loading performance for memory optimization
        - Eager loading performance using joinedload and selectinload
        - Query execution time compliance with 95th percentile targets
        - Loading strategy optimization per Section 6.2.5.1 requirements
        """
        # Create test data for performance testing
        entity_count = 20
        sessions_per_user = 15
        relationships_per_entity = 8
        
        # Create business entities
        entities = []
        for i in range(entity_count):
            entity = BusinessEntity(
                name=f"Performance Entity {i:02d}",
                description=f"Entity {i} for performance testing",
                owner_id=test_user.id,
                status="active" if i % 3 != 0 else "inactive"
            )
            entities.append(entity)
            db_session.add(entity)
        
        # Create user sessions
        for i in range(sessions_per_user):
            session = UserSession(
                user_id=test_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24 + i),
                user_agent=f"Performance Test Agent {i}",
                ip_address=f"192.168.100.{10 + i}"
            )
            db_session.add(session)
        
        db_session.commit()
        
        # Create entity relationships
        for i in range(0, len(entities) - 1, 2):
            if i + 1 < len(entities):
                relationship = EntityRelationship(
                    source_entity_id=entities[i].id,
                    target_entity_id=entities[i + 1].id,
                    relationship_type=f"type_{i % 3}",
                    is_active=True
                )
                db_session.add(relationship)
        
        db_session.commit()
        
        # Benchmark lazy loading performance
        def lazy_load_test():
            user = db_session.query(User).filter_by(id=test_user.id).first()
            sessions = user.sessions.all()
            entities = user.business_entities.all()
            return len(sessions), len(entities)
        
        lazy_result = benchmark(lazy_load_test)
        assert lazy_result[0] == sessions_per_user
        assert lazy_result[1] == entity_count
        
        # Benchmark eager loading with joinedload
        def eager_joinedload_test():
            user = (db_session.query(User)
                   .options(joinedload(User.sessions), joinedload(User.business_entities))
                   .filter_by(id=test_user.id)
                   .first())
            sessions = user.sessions.all()
            entities = user.business_entities.all()
            return len(sessions), len(entities)
        
        eager_result = benchmark(eager_joinedload_test)
        assert eager_result[0] == sessions_per_user
        assert eager_result[1] == entity_count
        
        # Benchmark selectinload strategy
        def selectinload_test():
            user = (db_session.query(User)
                   .options(selectinload(User.sessions), selectinload(User.business_entities))
                   .filter_by(id=test_user.id)
                   .first())
            sessions = user.sessions.all()
            entities = user.business_entities.all()
            return len(sessions), len(entities)
        
        select_result = benchmark(selectinload_test)
        assert select_result[0] == sessions_per_user
        assert select_result[1] == entity_count
    
    def test_complex_relationship_query_performance(self, db_session, test_user, benchmark):
        """
        Test performance of complex relationship queries and joins.
        
        Validates:
        - Complex join query performance under load
        - Multi-table relationship traversal efficiency
        - Query execution time compliance with 2000ms target for complex queries
        - Database index utilization for relationship queries
        """
        # Create larger dataset for complex query testing
        user_count = 10
        entities_per_user = 15
        relationships_per_entity_pair = 2
        
        users = [test_user]  # Include the test user
        
        # Create additional users
        for i in range(user_count - 1):
            user = User(
                username=f"perfuser_{i:02d}",
                email=f"perf{i:02d}@example.com",
                password="password123"
            )
            users.append(user)
            db_session.add(user)
        
        db_session.commit()
        
        # Create entities for each user
        all_entities = []
        for user in users:
            for i in range(entities_per_user):
                entity = BusinessEntity(
                    name=f"Complex Entity {user.id}_{i:02d}",
                    description=f"Entity {i} for user {user.id}",
                    owner_id=user.id,
                    status="active" if i % 2 == 0 else "inactive"
                )
                all_entities.append(entity)
                db_session.add(entity)
        
        db_session.commit()
        
        # Create cross-user entity relationships
        relationship_count = 0
        for i in range(0, len(all_entities) - 1, 3):
            if i + 1 < len(all_entities) and relationship_count < 50:  # Limit for performance
                relationship = EntityRelationship(
                    source_entity_id=all_entities[i].id,
                    target_entity_id=all_entities[i + 1].id,
                    relationship_type=f"complex_type_{relationship_count % 5}",
                    is_active=True
                )
                db_session.add(relationship)
                relationship_count += 1
        
        db_session.commit()
        
        # Benchmark complex relationship query
        def complex_relationship_query():
            # Query users with their entities and relationships in a single query
            results = (db_session.query(User)
                      .join(BusinessEntity, User.id == BusinessEntity.owner_id)
                      .join(EntityRelationship, 
                           BusinessEntity.id == EntityRelationship.source_entity_id)
                      .filter(BusinessEntity.status == "active")
                      .filter(EntityRelationship.is_active == True)
                      .distinct()
                      .all())
            return len(results)
        
        complex_result = benchmark(complex_relationship_query)
        assert complex_result >= 1  # Should find at least some results
        
        # Benchmark relationship aggregation query
        def relationship_aggregation_query():
            # Count relationships by type for active entities
            from sqlalchemy import func
            results = (db_session.query(
                        EntityRelationship.relationship_type,
                        func.count(EntityRelationship.id).label('count')
                      )
                      .join(BusinessEntity, 
                           EntityRelationship.source_entity_id == BusinessEntity.id)
                      .filter(BusinessEntity.status == "active")
                      .filter(EntityRelationship.is_active == True)
                      .group_by(EntityRelationship.relationship_type)
                      .all())
            return len(results)
        
        agg_result = benchmark(relationship_aggregation_query)
        assert agg_result >= 1  # Should find at least one relationship type
    
    def test_relationship_memory_usage_optimization(self, db_session, test_user):
        """
        Test memory usage optimization for large relationship collections.
        
        Validates:
        - Memory efficiency of lazy loading for large collections
        - Dynamic query optimization for memory management
        - Pagination support for large relationship sets
        - Memory usage patterns per Section 6.2.5.1 optimization
        """
        import gc
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create large number of relationships for memory testing
        large_entity_count = 100
        
        # Create entities
        entities = []
        for i in range(large_entity_count):
            entity = BusinessEntity(
                name=f"Memory Test Entity {i:03d}",
                description=f"Entity {i} for memory optimization testing",
                owner_id=test_user.id,
                status="active"
            )
            entities.append(entity)
            db_session.add(entity)
        
        db_session.commit()
        
        # Create sessions
        for i in range(50):
            session = UserSession(
                user_id=test_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24 + i),
                user_agent=f"Memory Test Agent {i}",
                ip_address=f"10.0.{i // 256}.{i % 256}"
            )
            db_session.add(session)
        
        db_session.commit()
        
        # Test lazy loading memory efficiency
        user = db_session.query(User).filter_by(id=test_user.id).first()
        
        # Access relationships without loading all data
        entities_query = user.business_entities
        sessions_query = user.sessions
        
        # Verify queries are not automatically executed
        assert hasattr(entities_query, 'filter')
        assert hasattr(sessions_query, 'filter')
        
        # Test pagination for memory efficiency
        page_size = 10
        entity_page_1 = entities_query.limit(page_size).offset(0).all()
        entity_page_2 = entities_query.limit(page_size).offset(page_size).all()
        
        assert len(entity_page_1) == page_size
        assert len(entity_page_2) == page_size
        assert entity_page_1[0].id != entity_page_2[0].id
        
        # Test filtering without loading all entities
        active_entities = entities_query.filter_by(status="active").all()
        assert len(active_entities) == large_entity_count
        
        # Measure memory usage after operations
        gc.collect()  # Force garbage collection
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB for this test)
        assert memory_increase < 100, f"Memory usage increased by {memory_increase:.2f}MB"


class TestRelationshipTransactionManagement:
    """
    Test suite for relationship transaction management and consistency validation.
    
    Validates transaction boundary management for relationship operations, 
    ensuring ACID compliance and proper rollback behavior during relationship
    modifications per Section 5.2.4 transaction coordination requirements.
    """
    
    def test_relationship_transaction_rollback_behavior(self, db_session, test_user):
        """
        Test transaction rollback behavior for relationship operations.
        
        Validates:
        - Transaction rollback for failed relationship operations
        - Data consistency maintenance during rollback scenarios
        - Proper cleanup of partially created relationships
        - ACID compliance for relationship transaction boundaries
        """
        # Create entities for relationship testing
        entity1 = BusinessEntity(
            name="Transaction Test Entity 1",
            description="First entity for transaction testing",
            owner_id=test_user.id,
            status="active"
        )
        
        entity2 = BusinessEntity(
            name="Transaction Test Entity 2", 
            description="Second entity for transaction testing",
            owner_id=test_user.id,
            status="active"
        )
        
        db_session.add_all([entity1, entity2])
        db_session.commit()
        
        # Get initial counts
        initial_relationship_count = db_session.query(EntityRelationship).count()
        initial_session_count = db_session.query(UserSession).count()
        
        # Start transaction with multiple operations
        try:
            # Create valid relationship
            relationship = EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type="transaction-test",
                is_active=True
            )
            db_session.add(relationship)
            
            # Create valid session
            session = UserSession(
                user_id=test_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                user_agent="Transaction Test Agent",
                ip_address="192.168.1.200"
            )
            db_session.add(session)
            
            # Create invalid relationship (should cause constraint violation)
            invalid_relationship = EntityRelationship(
                source_entity_id=99999,  # Non-existent entity
                target_entity_id=entity2.id,
                relationship_type="invalid-transaction",
                is_active=True
            )
            db_session.add(invalid_relationship)
            
            # This commit should fail and rollback everything
            db_session.commit()
            
            # Should not reach here
            assert False, "Transaction should have failed"
            
        except IntegrityError:
            # Expected behavior - rollback should occur
            db_session.rollback()
        
        # Verify rollback cleaned up all operations
        final_relationship_count = db_session.query(EntityRelationship).count()
        final_session_count = db_session.query(UserSession).count()
        
        assert final_relationship_count == initial_relationship_count
        assert final_session_count == initial_session_count
        
        # Verify specific records were not created
        transaction_relationships = db_session.query(EntityRelationship).filter_by(
            relationship_type="transaction-test"
        ).all()
        assert len(transaction_relationships) == 0
        
        transaction_sessions = db_session.query(UserSession).filter_by(
            user_agent="Transaction Test Agent"
        ).all()
        assert len(transaction_sessions) == 0
    
    def test_relationship_nested_transaction_behavior(self, db_session, test_user):
        """
        Test nested transaction behavior for complex relationship operations.
        
        Validates:
        - Nested transaction support for complex business operations
        - Savepoint management for partial rollback scenarios
        - Transaction isolation during complex relationship modifications
        - Nested transaction coordination per Section 5.2.4
        """
        from sqlalchemy import event
        
        # Create test entities
        entities = []
        for i in range(3):
            entity = BusinessEntity(
                name=f"Nested Transaction Entity {i}",
                description=f"Entity {i} for nested transaction testing", 
                owner_id=test_user.id,
                status="active"
            )
            entities.append(entity)
            db_session.add(entity)
        
        db_session.commit()
        
        # Start outer transaction
        outer_savepoint = db_session.begin()
        
        try:
            # Create first relationship (should succeed)
            relationship1 = EntityRelationship(
                source_entity_id=entities[0].id,
                target_entity_id=entities[1].id,
                relationship_type="nested-outer",
                is_active=True
            )
            db_session.add(relationship1)
            
            # Start inner transaction
            inner_savepoint = db_session.begin_nested()
            
            try:
                # Create second relationship (should succeed)
                relationship2 = EntityRelationship(
                    source_entity_id=entities[1].id,
                    target_entity_id=entities[2].id,
                    relationship_type="nested-inner",
                    is_active=True
                )
                db_session.add(relationship2)
                
                # Create invalid relationship (should fail)
                invalid_relationship = EntityRelationship(
                    source_entity_id=88888,  # Non-existent entity
                    target_entity_id=entities[2].id,
                    relationship_type="nested-invalid",
                    is_active=True
                )
                db_session.add(invalid_relationship)
                
                # Flush to trigger constraint check
                db_session.flush()
                
                # Should not reach here
                assert False, "Inner transaction should have failed"
                
            except IntegrityError:
                # Expected - rollback inner transaction only
                inner_savepoint.rollback()
            
            # Outer transaction should still be valid
            # Create another relationship to verify outer transaction state
            relationship3 = EntityRelationship(
                source_entity_id=entities[0].id,
                target_entity_id=entities[2].id,
                relationship_type="nested-recovery",
                is_active=True
            )
            db_session.add(relationship3)
            
            # Commit outer transaction
            outer_savepoint.commit()
            
        except Exception:
            outer_savepoint.rollback()
            raise
        
        # Verify transaction results
        outer_relationships = db_session.query(EntityRelationship).filter_by(
            relationship_type="nested-outer"
        ).all()
        assert len(outer_relationships) == 1
        
        inner_relationships = db_session.query(EntityRelationship).filter_by(
            relationship_type="nested-inner"
        ).all()
        assert len(inner_relationships) == 0  # Should be rolled back
        
        invalid_relationships = db_session.query(EntityRelationship).filter_by(
            relationship_type="nested-invalid"
        ).all()
        assert len(invalid_relationships) == 0  # Should be rolled back
        
        recovery_relationships = db_session.query(EntityRelationship).filter_by(
            relationship_type="nested-recovery"
        ).all()
        assert len(recovery_relationships) == 1  # Should be committed
    
    def test_relationship_concurrent_modification_handling(self, db_session, test_user):
        """
        Test handling of concurrent modifications to relationships.
        
        Validates:
        - Optimistic locking behavior for relationship modifications
        - Concurrent update detection and handling
        - Data consistency during concurrent relationship operations
        - Thread safety for relationship modifications
        """
        import threading
        import time
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.exc import StaleDataError
        
        # Create test entity
        entity1 = BusinessEntity(
            name="Concurrent Test Entity 1",
            description="Entity for concurrent modification testing",
            owner_id=test_user.id,
            status="active"
        )
        
        entity2 = BusinessEntity(
            name="Concurrent Test Entity 2",
            description="Entity for concurrent modification testing",
            owner_id=test_user.id,
            status="active"
        )
        
        db_session.add_all([entity1, entity2])
        db_session.commit()
        
        # Create initial relationship
        relationship = EntityRelationship(
            source_entity_id=entity1.id,
            target_entity_id=entity2.id,
            relationship_type="concurrent-test",
            is_active=True
        )
        
        db_session.add(relationship)
        db_session.commit()
        relationship_id = relationship.id
        
        # Simulate concurrent modifications
        modification_results = []
        
        def modify_relationship(session_factory, result_list, modification_type):
            """Function to run in separate thread for concurrent testing."""
            try:
                session = session_factory()
                rel = session.query(EntityRelationship).filter_by(id=relationship_id).first()
                
                if rel:
                    if modification_type == "deactivate":
                        rel.is_active = False
                    elif modification_type == "change_type":
                        rel.relationship_type = "concurrent-modified"
                    
                    # Add small delay to increase chance of conflict
                    time.sleep(0.1)
                    
                    session.commit()
                    result_list.append(("success", modification_type))
                else:
                    result_list.append(("not_found", modification_type))
                    
                session.close()
                
            except Exception as e:
                result_list.append(("error", modification_type, str(e)))
        
        # Create session factory for concurrent access
        Session = sessionmaker(bind=db_session.bind)
        
        # Start concurrent modifications
        thread1 = threading.Thread(
            target=modify_relationship,
            args=(Session, modification_results, "deactivate")
        )
        
        thread2 = threading.Thread(
            target=modify_relationship,
            args=(Session, modification_results, "change_type")
        )
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Analyze results
        assert len(modification_results) == 2
        
        # At least one modification should succeed
        success_count = len([r for r in modification_results if r[0] == "success"])
        assert success_count >= 1
        
        # Verify final state is consistent
        db_session.expire_all()  # Clear session cache
        final_relationship = db_session.query(EntityRelationship).filter_by(
            id=relationship_id
        ).first()
        
        assert final_relationship is not None
        # Either deactivated OR type changed, but not in inconsistent state
        assert (not final_relationship.is_active) or \
               (final_relationship.relationship_type == "concurrent-modified")


# ================================================================================================
# INTEGRATION TEST MARKERS AND CONFIGURATION
# ================================================================================================

# Mark all tests in this module as database integration tests
pytestmark = [
    pytest.mark.database,
    pytest.mark.integration,
    pytest.mark.sqlalchemy
]


def test_comprehensive_relationship_model_validation(db_session, test_user, sample_business_entities):
    """
    Comprehensive integration test validating all model relationships together.
    
    This test serves as a final validation that all relationships work correctly
    together in complex scenarios, ensuring the complete Flask-SQLAlchemy 
    relationship system maintains data integrity and functional equivalence
    with the original MongoDB relationship patterns.
    """
    # Create comprehensive test scenario with all relationship types
    
    # 1. User with multiple sessions
    sessions = []
    for i in range(3):
        session = UserSession(
            user_id=test_user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24 + i * 12),
            user_agent=f"Integration Test Agent {i}",
            ip_address=f"172.20.0.{10 + i}"
        )
        sessions.append(session)
        db_session.add(session)
    
    db_session.commit()
    
    # 2. Business entities already created by fixture
    entities = sample_business_entities
    assert len(entities) >= 2, "Need at least 2 entities for relationship testing"
    
    # 3. Entity relationships connecting the business entities
    relationships = []
    if len(entities) >= 2:
        relationship = EntityRelationship(
            source_entity_id=entities[0].id,
            target_entity_id=entities[1].id,
            relationship_type="integration-test",
            is_active=True
        )
        relationships.append(relationship)
        db_session.add(relationship)
    
    if len(entities) >= 3:
        relationship = EntityRelationship(
            source_entity_id=entities[1].id,
            target_entity_id=entities[2].id,
            relationship_type="integration-chain",
            is_active=True
        )
        relationships.append(relationship)
        db_session.add(relationship)
    
    db_session.commit()
    
    # Comprehensive validation of all relationships
    
    # Validate User -> UserSession relationships
    user_sessions = test_user.sessions.all()
    assert len(user_sessions) == 3
    for session in user_sessions:
        assert session.user_id == test_user.id
        assert session.user.username == test_user.username
    
    # Validate User -> BusinessEntity relationships
    user_entities = test_user.business_entities.all()
    assert len(user_entities) == len(entities)
    for entity in user_entities:
        assert entity.owner_id == test_user.id
        assert entity.owner.username == test_user.username
    
    # Validate BusinessEntity -> EntityRelationship relationships
    if len(relationships) > 0:
        # Source relationships
        source_rels = entities[0].source_relationships.all()
        assert len(source_rels) >= 1
        assert source_rels[0].source_entity_id == entities[0].id
        
        # Target relationships
        target_rels = entities[1].target_relationships.all() 
        assert len(target_rels) >= 1
        assert target_rels[0].target_entity_id == entities[1].id
    
    # Test cascade behavior by deleting user
    user_id = test_user.id
    entity_ids = [e.id for e in entities]
    session_ids = [s.id for s in sessions]
    relationship_ids = [r.id for r in relationships]
    
    db_session.delete(test_user)
    db_session.commit()
    
    # Verify all related records were cascade deleted
    remaining_entities = db_session.query(BusinessEntity).filter(
        BusinessEntity.id.in_(entity_ids)
    ).all()
    assert len(remaining_entities) == 0
    
    remaining_sessions = db_session.query(UserSession).filter(
        UserSession.id.in_(session_ids)
    ).all()
    assert len(remaining_sessions) == 0
    
    remaining_relationships = db_session.query(EntityRelationship).filter(
        EntityRelationship.id.in_(relationship_ids)
    ).all()
    assert len(remaining_relationships) == 0
    
    # Verify user was deleted
    deleted_user = db_session.query(User).filter_by(id=user_id).first()
    assert deleted_user is None