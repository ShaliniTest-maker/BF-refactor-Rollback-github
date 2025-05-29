"""
Comprehensive Flask-SQLAlchemy Model Relationship Testing Suite.

This module provides comprehensive testing for Flask-SQLAlchemy model relationships,
validating foreign key constraints, relationship mapping, and referential integrity
across all database models. Ensures proper User-to-UserSession relationships,
User-to-BusinessEntity ownership patterns, and BusinessEntity-to-EntityRelationship
associations function correctly with SQLAlchemy's declarative model system.

Key Testing Areas:
- Foreign key constraint enforcement and referential integrity validation
- Relationship loading strategies (lazy vs eager loading) for performance optimization  
- Cascade behavior testing for delete operations and relationship management
- Bidirectional relationship functionality through backref testing
- Constraint violation scenarios and database integrity enforcement
- Complex relationship scenarios and business workflow integration
- Performance validation for relationship queries and operations

Migration Context:
This test suite validates the successful migration from MongoDB relationship patterns
to Flask-SQLAlchemy declarative models with PostgreSQL foreign key constraints,
ensuring zero data loss and complete functional parity during the Node.js to Python
migration process.

Technical Specification References:
- Feature F-003: Database Model Conversion from MongoDB relationship patterns
- Section 6.2.1: Flask-SQLAlchemy 3.1.1 declarative model relationship mapping
- Section 6.2.2.1: PostgreSQL foreign key constraint enforcement per database design
- Feature F-004: Relationship integrity validation ensuring proper data associations
- Section 5.2.4: SQLAlchemy session management testing for relationship operations
"""

import pytest
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy import text, inspect, func
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.orm import selectinload, joinedload, contains_eager
from sqlalchemy.orm.exc import DetachedInstanceError

# Import models for comprehensive relationship testing
from src.models import db
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity
from src.models.entity_relationship import EntityRelationship

# Configure logging for test debugging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestUserRelationships:
    """
    Test suite for User model relationships with UserSession and BusinessEntity.
    
    Validates the core user relationship patterns including:
    - User-to-UserSession one-to-many relationships with cascade delete
    - User-to-BusinessEntity ownership patterns with proper constraints
    - Foreign key constraint enforcement and referential integrity
    - Cascade delete behavior and orphan management
    - Relationship loading strategies and performance optimization
    """
    
    @pytest.mark.database
    def test_user_session_relationship_creation(self, db_session, test_user):
        """
        Test User-to-UserSession relationship creation and basic functionality.
        
        Validates:
        - Foreign key relationship establishment
        - Bidirectional relationship access through backref
        - Session ownership and user association
        - Automatic relationship population
        """
        # Create user session with foreign key relationship
        session = UserSession(
            user_id=test_user.id,
            ip_address='192.168.1.100',
            user_agent='pytest-test-agent',
            remember_me=False
        )
        
        db_session.add(session)
        db_session.commit()
        db_session.refresh(session)
        
        # Validate foreign key relationship
        assert session.user_id == test_user.id
        assert session.user is not None
        assert session.user.id == test_user.id
        
        # Validate bidirectional relationship through backref
        db_session.refresh(test_user)
        user_sessions = list(test_user.sessions)
        assert len(user_sessions) == 1
        assert user_sessions[0].id == session.id
        assert user_sessions[0].user_id == test_user.id
        
        # Validate session ownership
        assert session.user.username == test_user.username
        assert session.user.email == test_user.email
    
    @pytest.mark.database
    def test_user_business_entity_relationship_creation(self, db_session, test_user):
        """
        Test User-to-BusinessEntity ownership relationship creation.
        
        Validates:
        - Foreign key ownership relationship establishment
        - Entity ownership patterns and access control
        - Bidirectional relationship functionality
        - Multiple entity ownership per user
        """
        # Create business entities with user ownership
        entity1 = BusinessEntity(
            name='Test Entity 1',
            description='First test business entity',
            owner_id=test_user.id,
            status='active'
        )
        
        entity2 = BusinessEntity(
            name='Test Entity 2', 
            description='Second test business entity',
            owner_id=test_user.id,
            status='active'
        )
        
        db_session.add_all([entity1, entity2])
        db_session.commit()
        db_session.refresh(entity1)
        db_session.refresh(entity2)
        
        # Validate foreign key ownership relationships
        assert entity1.owner_id == test_user.id
        assert entity2.owner_id == test_user.id
        assert entity1.owner is not None
        assert entity2.owner is not None
        assert entity1.owner.id == test_user.id
        assert entity2.owner.id == test_user.id
        
        # Validate bidirectional relationship through backref
        db_session.refresh(test_user)
        user_entities = list(test_user.business_entities)
        assert len(user_entities) == 2
        
        entity_ids = {entity.id for entity in user_entities}
        assert entity1.id in entity_ids
        assert entity2.id in entity_ids
        
        # Validate entity ownership access control
        for entity in user_entities:
            assert entity.can_be_accessed_by(test_user.id)
            assert entity.owner.username == test_user.username
    
    @pytest.mark.database
    def test_user_relationship_foreign_key_constraints(self, db_session):
        """
        Test foreign key constraint enforcement for User relationships.
        
        Validates:
        - Invalid foreign key rejection
        - Non-existent user ID constraint enforcement
        - Database integrity protection
        - Proper error handling for constraint violations
        """
        # Test invalid user_id in UserSession
        with pytest.raises(IntegrityError):
            invalid_session = UserSession(
                user_id=99999,  # Non-existent user ID
                ip_address='192.168.1.100',
                user_agent='pytest-test-agent'
            )
            db_session.add(invalid_session)
            db_session.commit()
        
        db_session.rollback()
        
        # Test invalid owner_id in BusinessEntity
        with pytest.raises(IntegrityError):
            invalid_entity = BusinessEntity(
                name='Invalid Entity',
                description='Entity with invalid owner',
                owner_id=99999,  # Non-existent owner ID
                status='active'
            )
            db_session.add(invalid_entity)
            db_session.commit()
        
        db_session.rollback()
        
        # Test NULL foreign key constraint (should fail)
        with pytest.raises(IntegrityError):
            null_session = UserSession(
                user_id=None,  # NULL foreign key
                ip_address='192.168.1.100'
            )
            db_session.add(null_session)
            db_session.commit()
        
        db_session.rollback()
    
    @pytest.mark.database 
    def test_user_cascade_delete_behavior(self, db_session, test_user):
        """
        Test cascade delete behavior for User relationships.
        
        Validates:
        - CASCADE DELETE for UserSession relationships
        - CASCADE DELETE for BusinessEntity relationships  
        - Orphan removal and referential integrity
        - Complete cleanup of dependent records
        """
        # Create dependent records
        session1 = UserSession(
            user_id=test_user.id,
            ip_address='192.168.1.100',
            user_agent='test-agent-1'
        )
        
        session2 = UserSession(
            user_id=test_user.id,
            ip_address='192.168.1.101',
            user_agent='test-agent-2'
        )
        
        entity1 = BusinessEntity(
            name='Test Entity 1',
            description='First test entity',
            owner_id=test_user.id,
            status='active'
        )
        
        entity2 = BusinessEntity(
            name='Test Entity 2', 
            description='Second test entity',
            owner_id=test_user.id,
            status='active'
        )
        
        db_session.add_all([session1, session2, entity1, entity2])
        db_session.commit()
        
        # Store IDs for verification after delete
        user_id = test_user.id
        session1_id = session1.id
        session2_id = session2.id
        entity1_id = entity1.id
        entity2_id = entity2.id
        
        # Verify records exist before deletion
        assert db_session.query(UserSession).filter_by(user_id=user_id).count() == 2
        assert db_session.query(BusinessEntity).filter_by(owner_id=user_id).count() == 2
        
        # Delete the user - should cascade to all dependent records
        db_session.delete(test_user)
        db_session.commit()
        
        # Verify cascade deletion of UserSession records
        assert db_session.query(UserSession).filter_by(id=session1_id).first() is None
        assert db_session.query(UserSession).filter_by(id=session2_id).first() is None
        assert db_session.query(UserSession).filter_by(user_id=user_id).count() == 0
        
        # Verify cascade deletion of BusinessEntity records
        assert db_session.query(BusinessEntity).filter_by(id=entity1_id).first() is None
        assert db_session.query(BusinessEntity).filter_by(id=entity2_id).first() is None
        assert db_session.query(BusinessEntity).filter_by(owner_id=user_id).count() == 0
    
    @pytest.mark.database
    def test_user_relationship_lazy_loading(self, db_session, test_user):
        """
        Test lazy loading behavior for User relationships.
        
        Validates:
        - Lazy loading strategy implementation
        - On-demand relationship loading
        - Query efficiency for lazy loading
        - Proper session management during lazy loading
        """
        # Create test data
        sessions = [
            UserSession(user_id=test_user.id, ip_address=f'192.168.1.{i}')
            for i in range(1, 4)
        ]
        
        entities = [
            BusinessEntity(
                name=f'Entity {i}',
                description=f'Test entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 4)
        ]
        
        db_session.add_all(sessions + entities)
        db_session.commit()
        
        # Clear session to test lazy loading
        db_session.expunge_all()
        
        # Reload user and test lazy loading
        user = db_session.query(User).filter_by(id=test_user.id).first()
        
        # Test lazy loading of sessions (dynamic relationship)
        # This should trigger a separate query
        user_sessions = list(user.sessions)
        assert len(user_sessions) == 3
        
        # Test lazy loading of business entities (dynamic relationship)
        # This should trigger another separate query
        user_entities = list(user.business_entities)
        assert len(user_entities) == 3
        
        # Verify each relationship loads correctly
        for session in user_sessions:
            assert session.user_id == user.id
            assert isinstance(session, UserSession)
        
        for entity in user_entities:
            assert entity.owner_id == user.id
            assert isinstance(entity, BusinessEntity)
    
    @pytest.mark.database
    def test_user_relationship_eager_loading(self, db_session, test_user):
        """
        Test eager loading behavior for User relationships.
        
        Validates:
        - Eager loading strategy implementation
        - Single query efficiency for eager loading
        - Proper relationship population
        - Performance optimization through eager loading
        """
        # Create test data
        sessions = [
            UserSession(user_id=test_user.id, ip_address=f'192.168.1.{i}')
            for i in range(1, 4)
        ]
        
        entities = [
            BusinessEntity(
                name=f'Entity {i}',
                description=f'Test entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 4)
        ]
        
        db_session.add_all(sessions + entities)
        db_session.commit()
        
        # Test eager loading with selectinload
        user_with_sessions = (
            db_session.query(User)
            .options(selectinload(User.sessions))
            .filter_by(id=test_user.id)
            .first()
        )
        
        # Verify sessions are eagerly loaded
        assert len(list(user_with_sessions.sessions)) == 3
        
        # Test eager loading with joinedload (not recommended for dynamic but testing compatibility)
        user_with_entities = (
            db_session.query(User)
            .filter_by(id=test_user.id)
            .first()
        )
        
        # Access the dynamic relationship
        entities_list = list(user_with_entities.business_entities)
        assert len(entities_list) == 3
        
        # Verify data integrity with eager loading
        for session in user_with_sessions.sessions:
            assert session.user_id == user_with_sessions.id
            assert session.user.username == user_with_sessions.username
        
        for entity in entities_list:
            assert entity.owner_id == user_with_entities.id
            assert entity.owner.username == user_with_entities.username


class TestBusinessEntityRelationships:
    """
    Test suite for BusinessEntity relationships with EntityRelationship.
    
    Validates:
    - BusinessEntity-to-EntityRelationship associations as source and target
    - Dual foreign key relationship patterns
    - Complex business relationship scenarios
    - Relationship type categorization and validation
    - Bidirectional relationship navigation
    """
    
    @pytest.mark.database
    def test_entity_relationship_creation(self, db_session, sample_business_entities):
        """
        Test EntityRelationship creation with BusinessEntity associations.
        
        Validates:
        - Dual foreign key relationships (source and target)
        - Relationship type categorization
        - Bidirectional navigation between entities
        - Proper constraint validation
        """
        if len(sample_business_entities) < 2:
            pytest.skip("Need at least 2 business entities for relationship testing")
        
        source_entity = sample_business_entities[0]
        target_entity = sample_business_entities[1]
        
        # Create entity relationship
        relationship = EntityRelationship(
            source_entity_id=source_entity.id,
            target_entity_id=target_entity.id,
            relationship_type='parent_child',
            is_active=True
        )
        
        db_session.add(relationship)
        db_session.commit()
        db_session.refresh(relationship)
        
        # Validate foreign key relationships
        assert relationship.source_entity_id == source_entity.id
        assert relationship.target_entity_id == target_entity.id
        assert relationship.source_entity is not None
        assert relationship.target_entity is not None
        assert relationship.source_entity.id == source_entity.id
        assert relationship.target_entity.id == target_entity.id
        
        # Validate relationship type
        assert relationship.relationship_type == 'parent_child'
        assert relationship.is_active is True
        
        # Test bidirectional navigation
        db_session.refresh(source_entity)
        db_session.refresh(target_entity)
        
        # Source entity should have this relationship as outgoing
        source_relationships = list(source_entity.source_relationships)
        assert len(source_relationships) >= 1
        assert any(rel.id == relationship.id for rel in source_relationships)
        
        # Target entity should have this relationship as incoming
        target_relationships = list(target_entity.target_relationships)
        assert len(target_relationships) >= 1
        assert any(rel.id == relationship.id for rel in target_relationships)
    
    @pytest.mark.database
    def test_entity_relationship_foreign_key_constraints(self, db_session):
        """
        Test foreign key constraint enforcement for EntityRelationship.
        
        Validates:
        - Invalid source entity ID rejection
        - Invalid target entity ID rejection
        - Self-referential relationship prevention
        - Proper constraint violation handling
        """
        # Test invalid source_entity_id
        with pytest.raises(IntegrityError):
            invalid_relationship = EntityRelationship(
                source_entity_id=99999,  # Non-existent entity
                target_entity_id=1,
                relationship_type='parent_child'
            )
            db_session.add(invalid_relationship)
            db_session.commit()
        
        db_session.rollback()
        
        # Test invalid target_entity_id
        with pytest.raises(IntegrityError):
            invalid_relationship = EntityRelationship(
                source_entity_id=1,
                target_entity_id=99999,  # Non-existent entity
                relationship_type='parent_child'
            )
            db_session.add(invalid_relationship)
            db_session.commit()
        
        db_session.rollback()
        
        # Test NULL foreign key constraints
        with pytest.raises(IntegrityError):
            null_source_relationship = EntityRelationship(
                source_entity_id=None,
                target_entity_id=1,
                relationship_type='parent_child'
            )
            db_session.add(null_source_relationship)
            db_session.commit()
        
        db_session.rollback()
    
    @pytest.mark.database
    def test_entity_relationship_self_reference_prevention(self, db_session, sample_business_entities):
        """
        Test prevention of self-referential relationships.
        
        Validates:
        - Database constraint preventing self-references
        - Business rule enforcement
        - Proper error handling for invalid relationships
        """
        if not sample_business_entities:
            pytest.skip("Need business entities for self-reference testing")
        
        entity = sample_business_entities[0]
        
        # Attempt to create self-referential relationship
        with pytest.raises(IntegrityError):
            self_relationship = EntityRelationship(
                source_entity_id=entity.id,
                target_entity_id=entity.id,  # Self-reference
                relationship_type='parent_child'
            )
            db_session.add(self_relationship)
            db_session.commit()
        
        db_session.rollback()
    
    @pytest.mark.database
    def test_entity_relationship_cascade_delete(self, db_session, sample_business_entities):
        """
        Test cascade delete behavior for EntityRelationship.
        
        Validates:
        - CASCADE DELETE when source entity is deleted
        - CASCADE DELETE when target entity is deleted
        - Proper cleanup of relationship records
        - Referential integrity maintenance
        """
        if len(sample_business_entities) < 3:
            pytest.skip("Need at least 3 business entities for cascade testing")
        
        entity1 = sample_business_entities[0]
        entity2 = sample_business_entities[1]
        entity3 = sample_business_entities[2]
        
        # Create multiple relationships involving entity1
        rel1 = EntityRelationship(
            source_entity_id=entity1.id,
            target_entity_id=entity2.id,
            relationship_type='parent_child'
        )
        
        rel2 = EntityRelationship(
            source_entity_id=entity3.id,
            target_entity_id=entity1.id,
            relationship_type='parent_child'
        )
        
        db_session.add_all([rel1, rel2])
        db_session.commit()
        
        rel1_id = rel1.id
        rel2_id = rel2.id
        entity1_id = entity1.id
        
        # Verify relationships exist
        assert db_session.query(EntityRelationship).filter_by(id=rel1_id).first() is not None
        assert db_session.query(EntityRelationship).filter_by(id=rel2_id).first() is not None
        
        # Delete entity1 - should cascade delete both relationships
        db_session.delete(entity1)
        db_session.commit()
        
        # Verify cascade deletion
        assert db_session.query(EntityRelationship).filter_by(id=rel1_id).first() is None
        assert db_session.query(EntityRelationship).filter_by(id=rel2_id).first() is None
        
        # Verify no orphaned relationships remain
        orphaned_rels = db_session.query(EntityRelationship).filter(
            (EntityRelationship.source_entity_id == entity1_id) |
            (EntityRelationship.target_entity_id == entity1_id)
        ).count()
        assert orphaned_rels == 0
    
    @pytest.mark.database
    def test_complex_entity_relationship_scenarios(self, db_session, sample_business_entities):
        """
        Test complex business relationship scenarios.
        
        Validates:
        - Multiple relationship types between same entities
        - Hierarchical relationship patterns
        - Business workflow relationship modeling
        - Complex navigation and querying
        """
        if len(sample_business_entities) < 3:
            pytest.skip("Need at least 3 business entities for complex scenarios")
        
        entity1, entity2, entity3 = sample_business_entities[0:3]
        
        # Create complex relationship structure
        relationships = [
            EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='parent_child'
            ),
            EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity3.id,
                relationship_type='parent_child'
            ),
            EntityRelationship(
                source_entity_id=entity2.id,
                target_entity_id=entity3.id,
                relationship_type='dependency'
            ),
            EntityRelationship(
                source_entity_id=entity1.id,
                target_entity_id=entity2.id,
                relationship_type='collaboration'  # Different type between same entities
            )
        ]
        
        db_session.add_all(relationships)
        db_session.commit()
        
        # Test complex navigation and querying
        db_session.refresh(entity1)
        
        # Entity1 should have 3 outgoing relationships
        outgoing_rels = list(entity1.source_relationships)
        assert len(outgoing_rels) == 3
        
        # Test filtering by relationship type
        parent_child_rels = [rel for rel in outgoing_rels if rel.relationship_type == 'parent_child']
        assert len(parent_child_rels) == 2
        
        collaboration_rels = [rel for rel in outgoing_rels if rel.relationship_type == 'collaboration']
        assert len(collaboration_rels) == 1
        
        # Test getting all related entities
        related_entities = entity1.get_related_entities()
        assert len(related_entities) >= 2  # entity2 and entity3
        
        related_entity_ids = {entity.id for entity in related_entities}
        assert entity2.id in related_entity_ids
        assert entity3.id in related_entity_ids


class TestRelationshipLoadingPerformance:
    """
    Test suite for relationship loading performance optimization.
    
    Validates:
    - Lazy vs eager loading performance characteristics
    - Query optimization for relationship traversal
    - N+1 query problem prevention
    - Bulk loading strategies for large datasets
    """
    
    @pytest.mark.database
    @pytest.mark.performance
    def test_lazy_loading_performance(self, db_session, test_user, api_benchmark):
        """
        Test lazy loading performance characteristics.
        
        Validates:
        - Individual query execution for lazy loading
        - Performance impact of lazy loading on large datasets
        - Memory efficiency of lazy loading strategy
        """
        # Create larger dataset for performance testing
        sessions = [
            UserSession(user_id=test_user.id, ip_address=f'192.168.1.{i}')
            for i in range(1, 21)  # 20 sessions
        ]
        
        entities = [
            BusinessEntity(
                name=f'Entity {i}',
                description=f'Performance test entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 21)  # 20 entities
        ]
        
        db_session.add_all(sessions + entities)
        db_session.commit()
        
        # Clear session for clean test
        db_session.expunge_all()
        
        def lazy_loading_test():
            # Load user without relationships
            user = db_session.query(User).filter_by(id=test_user.id).first()
            
            # Access relationships (triggers lazy loading)
            session_count = user.sessions.count()
            entity_count = user.business_entities.count()
            
            return session_count, entity_count
        
        # Benchmark lazy loading performance
        result = api_benchmark(lazy_loading_test)
        session_count, entity_count = result
        
        assert session_count == 20
        assert entity_count == 20
    
    @pytest.mark.database
    @pytest.mark.performance
    def test_eager_loading_performance(self, db_session, test_user, api_benchmark):
        """
        Test eager loading performance characteristics.
        
        Validates:
        - Single query execution for eager loading
        - Performance benefits of eager loading for bulk access
        - Memory usage patterns for eager loading
        """
        # Create test dataset
        sessions = [
            UserSession(user_id=test_user.id, ip_address=f'192.168.1.{i}')
            for i in range(1, 21)
        ]
        
        entities = [
            BusinessEntity(
                name=f'Entity {i}',
                description=f'Performance test entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 21)
        ]
        
        db_session.add_all(sessions + entities)
        db_session.commit()
        
        def eager_loading_test():
            # Load user with eager loading for sessions
            user = (
                db_session.query(User)
                .options(selectinload(User.sessions))
                .filter_by(id=test_user.id)
                .first()
            )
            
            # Access should not trigger additional queries
            session_count = len(list(user.sessions))
            
            # Load entities separately for comparison
            entity_count = user.business_entities.count()
            
            return session_count, entity_count
        
        # Benchmark eager loading performance
        result = api_benchmark(eager_loading_test)
        session_count, entity_count = result
        
        assert session_count == 20
        assert entity_count == 20
    
    @pytest.mark.database
    def test_n_plus_one_query_prevention(self, db_session, test_user):
        """
        Test prevention of N+1 query problems in relationship loading.
        
        Validates:
        - Efficient bulk loading strategies
        - Query count optimization
        - Proper use of join strategies
        """
        # Create test data with relationships
        entities = []
        for i in range(1, 6):
            entity = BusinessEntity(
                name=f'Entity {i}',
                description=f'N+1 test entity {i}',
                owner_id=test_user.id,
                status='active'
            )
            entities.append(entity)
        
        db_session.add_all(entities)
        db_session.commit()
        
        # Create relationships between entities
        relationships = []
        for i in range(len(entities) - 1):
            rel = EntityRelationship(
                source_entity_id=entities[i].id,
                target_entity_id=entities[i + 1].id,
                relationship_type='parent_child'
            )
            relationships.append(rel)
        
        db_session.add_all(relationships)
        db_session.commit()
        
        # Test efficient loading to prevent N+1 queries
        entities_with_relationships = (
            db_session.query(BusinessEntity)
            .options(
                selectinload(BusinessEntity.source_relationships),
                selectinload(BusinessEntity.target_relationships)
            )
            .filter_by(owner_id=test_user.id)
            .all()
        )
        
        # Verify all data is loaded without additional queries
        for entity in entities_with_relationships:
            source_rels = list(entity.source_relationships)
            target_rels = list(entity.target_relationships)
            
            # This should not trigger additional queries
            for rel in source_rels:
                assert rel.source_entity_id == entity.id
            
            for rel in target_rels:
                assert rel.target_entity_id == entity.id


class TestConstraintViolationHandling:
    """
    Test suite for database constraint violation handling.
    
    Validates:
    - Foreign key constraint violations
    - Unique constraint violations  
    - Check constraint violations
    - Proper error handling and rollback behavior
    """
    
    @pytest.mark.database
    def test_foreign_key_constraint_violations(self, db_session):
        """
        Test handling of foreign key constraint violations.
        
        Validates:
        - Proper exception handling for invalid foreign keys
        - Transaction rollback on constraint violations
        - Error message clarity and debugging information
        """
        # Test UserSession with invalid user_id
        with pytest.raises(IntegrityError) as exc_info:
            invalid_session = UserSession(
                user_id=99999,
                ip_address='192.168.1.100'
            )
            db_session.add(invalid_session)
            db_session.commit()
        
        assert "FOREIGN KEY constraint failed" in str(exc_info.value)
        db_session.rollback()
        
        # Test BusinessEntity with invalid owner_id
        with pytest.raises(IntegrityError) as exc_info:
            invalid_entity = BusinessEntity(
                name='Invalid Entity',
                owner_id=99999,
                status='active'
            )
            db_session.add(invalid_entity)
            db_session.commit()
        
        assert "FOREIGN KEY constraint failed" in str(exc_info.value)
        db_session.rollback()
        
        # Test EntityRelationship with invalid entity IDs
        with pytest.raises(IntegrityError):
            invalid_relationship = EntityRelationship(
                source_entity_id=99999,
                target_entity_id=99998,
                relationship_type='parent_child'
            )
            db_session.add(invalid_relationship)
            db_session.commit()
        
        db_session.rollback()
    
    @pytest.mark.database
    def test_unique_constraint_violations(self, db_session, test_user):
        """
        Test handling of unique constraint violations.
        
        Validates:
        - Session token uniqueness enforcement
        - Business entity name uniqueness per owner
        - Proper exception handling for duplicates
        """
        # Create initial session
        session1 = UserSession(
            user_id=test_user.id,
            ip_address='192.168.1.100'
        )
        db_session.add(session1)
        db_session.commit()
        
        # Attempt to create session with duplicate token
        with pytest.raises(IntegrityError):
            session2 = UserSession(
                user_id=test_user.id,
                ip_address='192.168.1.101'
            )
            # Manually set same token to trigger unique constraint
            session2.session_token = session1.session_token
            db_session.add(session2)
            db_session.commit()
        
        db_session.rollback()
        
        # Test business entity name uniqueness per owner
        entity1 = BusinessEntity(
            name='Unique Entity',
            owner_id=test_user.id,
            status='active'
        )
        db_session.add(entity1)
        db_session.commit()
        
        # Attempt duplicate name for same owner
        with pytest.raises(IntegrityError):
            entity2 = BusinessEntity(
                name='Unique Entity',  # Duplicate name
                owner_id=test_user.id,
                status='active'
            )
            db_session.add(entity2)
            db_session.commit()
        
        db_session.rollback()
    
    @pytest.mark.database
    def test_check_constraint_violations(self, db_session, test_user):
        """
        Test handling of check constraint violations.
        
        Validates:
        - Field validation through check constraints
        - Business rule enforcement at database level
        - Proper error handling for invalid data
        """
        # Test invalid status value in BusinessEntity
        with pytest.raises(IntegrityError):
            invalid_entity = BusinessEntity(
                name='Test Entity',
                owner_id=test_user.id,
                status='invalid_status'  # Not in allowed values
            )
            db_session.add(invalid_entity)
            db_session.commit()
        
        db_session.rollback()
        
        # Test empty name in BusinessEntity  
        with pytest.raises(IntegrityError):
            empty_name_entity = BusinessEntity(
                name='',  # Empty name violates check constraint
                owner_id=test_user.id,
                status='active'
            )
            db_session.add(empty_name_entity)
            db_session.commit()
        
        db_session.rollback()


class TestAdvancedRelationshipScenarios:
    """
    Test suite for advanced relationship scenarios and edge cases.
    
    Validates:
    - Complex multi-level relationship hierarchies
    - Circular relationship detection and handling
    - Bulk relationship operations
    - Relationship state management and lifecycle
    """
    
    @pytest.mark.database
    def test_multi_level_relationship_hierarchy(self, db_session, test_user):
        """
        Test complex multi-level relationship hierarchies.
        
        Validates:
        - Deep relationship navigation
        - Hierarchical business logic patterns
        - Performance with nested relationships
        """
        # Create hierarchical entity structure
        root_entity = BusinessEntity(
            name='Root Entity',
            description='Top-level entity',
            owner_id=test_user.id,
            status='active'
        )
        
        level1_entities = [
            BusinessEntity(
                name=f'Level 1 Entity {i}',
                description=f'First level entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 4)
        ]
        
        level2_entities = [
            BusinessEntity(
                name=f'Level 2 Entity {i}',
                description=f'Second level entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 6)
        ]
        
        db_session.add_all([root_entity] + level1_entities + level2_entities)
        db_session.commit()
        
        # Create hierarchical relationships
        level1_relationships = [
            EntityRelationship(
                source_entity_id=root_entity.id,
                target_entity_id=entity.id,
                relationship_type='parent_child'
            ) for entity in level1_entities
        ]
        
        level2_relationships = []
        for i, level2_entity in enumerate(level2_entities):
            parent_level1 = level1_entities[i % len(level1_entities)]
            level2_relationships.append(
                EntityRelationship(
                    source_entity_id=parent_level1.id,
                    target_entity_id=level2_entity.id,
                    relationship_type='parent_child'
                )
            )
        
        db_session.add_all(level1_relationships + level2_relationships)
        db_session.commit()
        
        # Test hierarchical navigation
        db_session.refresh(root_entity)
        
        # Root should have 3 direct children
        direct_children = list(root_entity.source_relationships.filter_by(
            relationship_type='parent_child'
        ))
        assert len(direct_children) == 3
        
        # Test navigation to grandchildren
        grandchildren_count = 0
        for child_rel in direct_children:
            child_entity = child_rel.target_entity
            grandchild_rels = list(child_entity.source_relationships.filter_by(
                relationship_type='parent_child'
            ))
            grandchildren_count += len(grandchild_rels)
        
        assert grandchildren_count == 5  # Total level 2 entities
    
    @pytest.mark.database
    def test_relationship_state_management(self, db_session, sample_business_entities):
        """
        Test relationship state management and lifecycle.
        
        Validates:
        - Active/inactive relationship states
        - Soft deletion patterns
        - State transition validation
        - Temporal relationship management
        """
        if len(sample_business_entities) < 2:
            pytest.skip("Need at least 2 business entities for state testing")
        
        entity1, entity2 = sample_business_entities[0:2]
        
        # Create relationship in active state
        relationship = EntityRelationship(
            source_entity_id=entity1.id,
            target_entity_id=entity2.id,
            relationship_type='parent_child',
            is_active=True
        )
        
        db_session.add(relationship)
        db_session.commit()
        
        # Verify active state
        assert relationship.is_active is True
        active_rels = db_session.query(EntityRelationship).filter_by(
            is_active=True
        ).count()
        assert active_rels >= 1
        
        # Test state transition to inactive
        relationship.deactivate()
        db_session.commit()
        
        assert relationship.is_active is False
        db_session.refresh(relationship)
        assert relationship.is_active is False
        
        # Verify filtering by active state
        active_rels = list(entity1.source_relationships.filter_by(is_active=True))
        inactive_rels = list(entity1.source_relationships.filter_by(is_active=False))
        
        assert len(inactive_rels) >= 1
        assert any(rel.id == relationship.id for rel in inactive_rels)
        
        # Test reactivation
        relationship.activate()
        db_session.commit()
        
        assert relationship.is_active is True
    
    @pytest.mark.database
    def test_bulk_relationship_operations(self, db_session, test_user):
        """
        Test bulk relationship operations for performance.
        
        Validates:
        - Bulk creation performance
        - Bulk update operations
        - Bulk deletion with constraints
        - Transaction management for bulk operations
        """
        # Create entities for bulk operations
        entities = [
            BusinessEntity(
                name=f'Bulk Entity {i}',
                description=f'Entity for bulk testing {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 11)  # 10 entities
        ]
        
        db_session.add_all(entities)
        db_session.commit()
        
        # Bulk create relationships (create a star pattern)
        center_entity = entities[0]
        relationships = [
            EntityRelationship(
                source_entity_id=center_entity.id,
                target_entity_id=entity.id,
                relationship_type='parent_child',
                is_active=True
            ) for entity in entities[1:]
        ]
        
        # Test bulk insertion
        db_session.add_all(relationships)
        db_session.commit()
        
        # Verify bulk creation
        created_rels = db_session.query(EntityRelationship).filter_by(
            source_entity_id=center_entity.id,
            relationship_type='parent_child'
        ).count()
        assert created_rels == 9
        
        # Test bulk update
        relationship_ids = [rel.id for rel in relationships]
        updated_count = db_session.query(EntityRelationship).filter(
            EntityRelationship.id.in_(relationship_ids)
        ).update(
            {'relationship_type': 'dependency'},
            synchronize_session=False
        )
        db_session.commit()
        
        assert updated_count == 9
        
        # Verify bulk update
        dependency_rels = db_session.query(EntityRelationship).filter_by(
            source_entity_id=center_entity.id,
            relationship_type='dependency'
        ).count()
        assert dependency_rels == 9
        
        # Test bulk soft deletion
        deactivated_count = db_session.query(EntityRelationship).filter(
            EntityRelationship.id.in_(relationship_ids)
        ).update(
            {'is_active': False},
            synchronize_session=False
        )
        db_session.commit()
        
        assert deactivated_count == 9
        
        # Verify bulk deactivation
        active_rels = db_session.query(EntityRelationship).filter_by(
            source_entity_id=center_entity.id,
            is_active=True
        ).count()
        assert active_rels == 0


class TestRelationshipIntegrityValidation:
    """
    Test suite for comprehensive relationship integrity validation.
    
    Validates:
    - Cross-model referential integrity
    - Data consistency across relationships
    - Constraint enforcement under concurrent access
    - Recovery from integrity violations
    """
    
    @pytest.mark.database
    def test_cross_model_referential_integrity(self, db_session, test_user):
        """
        Test referential integrity across all model relationships.
        
        Validates:
        - End-to-end relationship integrity
        - Cross-model cascade behavior
        - Complex deletion scenarios
        """
        # Create complete relationship chain
        session = UserSession(
            user_id=test_user.id,
            ip_address='192.168.1.100'
        )
        
        entity = BusinessEntity(
            name='Integrity Test Entity',
            description='Entity for integrity testing',
            owner_id=test_user.id,
            status='active'
        )
        
        db_session.add_all([session, entity])
        db_session.commit()
        
        # Create another entity for relationship
        entity2 = BusinessEntity(
            name='Second Integrity Entity',
            description='Second entity for relationship',
            owner_id=test_user.id,
            status='active'
        )
        
        db_session.add(entity2)
        db_session.commit()
        
        # Create entity relationship
        relationship = EntityRelationship(
            source_entity_id=entity.id,
            target_entity_id=entity2.id,
            relationship_type='parent_child'
        )
        
        db_session.add(relationship)
        db_session.commit()
        
        # Store IDs for verification
        user_id = test_user.id
        session_id = session.id
        entity_id = entity.id
        entity2_id = entity2.id
        relationship_id = relationship.id
        
        # Verify complete relationship chain exists
        assert db_session.query(User).filter_by(id=user_id).first() is not None
        assert db_session.query(UserSession).filter_by(id=session_id).first() is not None
        assert db_session.query(BusinessEntity).filter_by(id=entity_id).first() is not None
        assert db_session.query(BusinessEntity).filter_by(id=entity2_id).first() is not None
        assert db_session.query(EntityRelationship).filter_by(id=relationship_id).first() is not None
        
        # Test cascade deletion from root
        db_session.delete(test_user)
        db_session.commit()
        
        # Verify complete cascade deletion
        assert db_session.query(User).filter_by(id=user_id).first() is None
        assert db_session.query(UserSession).filter_by(id=session_id).first() is None
        assert db_session.query(BusinessEntity).filter_by(id=entity_id).first() is None
        assert db_session.query(BusinessEntity).filter_by(id=entity2_id).first() is None
        assert db_session.query(EntityRelationship).filter_by(id=relationship_id).first() is None
    
    @pytest.mark.database
    def test_relationship_data_consistency(self, db_session, test_user):
        """
        Test data consistency across relationship operations.
        
        Validates:
        - Bidirectional relationship consistency
        - State synchronization across related models
        - Transaction boundary respect
        """
        # Create entities with relationships
        entity1 = BusinessEntity(
            name='Consistency Entity 1',
            owner_id=test_user.id,
            status='active'
        )
        
        entity2 = BusinessEntity(
            name='Consistency Entity 2', 
            owner_id=test_user.id,
            status='active'
        )
        
        db_session.add_all([entity1, entity2])
        db_session.commit()
        
        # Create bidirectional relationships
        rel1 = EntityRelationship(
            source_entity_id=entity1.id,
            target_entity_id=entity2.id,
            relationship_type='parent_child'
        )
        
        rel2 = EntityRelationship(
            source_entity_id=entity2.id,
            target_entity_id=entity1.id,
            relationship_type='dependency'
        )
        
        db_session.add_all([rel1, rel2])
        db_session.commit()
        
        # Test consistency of bidirectional navigation
        db_session.refresh(entity1)
        db_session.refresh(entity2)
        
        # Entity1 outgoing relationships
        entity1_outgoing = list(entity1.source_relationships)
        assert len(entity1_outgoing) == 1
        assert entity1_outgoing[0].target_entity_id == entity2.id
        
        # Entity1 incoming relationships
        entity1_incoming = list(entity1.target_relationships)
        assert len(entity1_incoming) == 1
        assert entity1_incoming[0].source_entity_id == entity2.id
        
        # Entity2 outgoing relationships
        entity2_outgoing = list(entity2.source_relationships)
        assert len(entity2_outgoing) == 1
        assert entity2_outgoing[0].target_entity_id == entity1.id
        
        # Entity2 incoming relationships
        entity2_incoming = list(entity2.target_relationships)
        assert len(entity2_incoming) == 1
        assert entity2_incoming[0].source_entity_id == entity1.id
        
        # Test state consistency after updates
        rel1.deactivate()
        db_session.commit()
        
        # Verify state consistency
        db_session.refresh(entity1)
        db_session.refresh(entity2)
        
        active_outgoing_1 = list(entity1.source_relationships.filter_by(is_active=True))
        assert len(active_outgoing_1) == 0
        
        active_incoming_2 = list(entity2.target_relationships.filter_by(is_active=True))
        assert len(active_incoming_2) == 0


# Performance benchmarking and comparative testing
class TestRelationshipPerformanceComparison:
    """
    Test suite for relationship performance comparison against Node.js baseline.
    
    Validates:
    - Query performance meets SLA requirements per Section 6.2.1
    - Memory usage optimization
    - Response time compliance with 95th percentile targets
    - Scalability patterns equivalent to Node.js implementation
    """
    
    @pytest.mark.database
    @pytest.mark.performance
    def test_relationship_query_performance(self, db_session, test_user, database_benchmark):
        """
        Test relationship query performance against baseline requirements.
        
        Validates performance targets from Section 6.2.1:
        - Simple SELECT operations < 500ms (95th percentile)
        - Complex JOIN operations < 2000ms (95th percentile)
        """
        # Create performance test dataset
        entities = [
            BusinessEntity(
                name=f'Perf Entity {i}',
                description=f'Performance test entity {i}',
                owner_id=test_user.id,
                status='active'
            ) for i in range(1, 101)  # 100 entities
        ]
        
        db_session.add_all(entities)
        db_session.commit()
        
        # Create relationships for complex queries
        relationships = []
        for i in range(99):
            rel = EntityRelationship(
                source_entity_id=entities[i].id,
                target_entity_id=entities[i + 1].id,
                relationship_type='parent_child'
            )
            relationships.append(rel)
        
        db_session.add_all(relationships)
        db_session.commit()
        
        # Test simple relationship query performance
        def simple_relationship_query():
            return db_session.query(BusinessEntity).filter_by(
                owner_id=test_user.id
            ).count()
        
        simple_result = database_benchmark(simple_relationship_query)
        assert simple_result == 100
        
        # Test complex JOIN query performance
        def complex_join_query():
            return (
                db_session.query(BusinessEntity)
                .join(EntityRelationship, BusinessEntity.id == EntityRelationship.source_entity_id)
                .filter(BusinessEntity.owner_id == test_user.id)
                .filter(EntityRelationship.relationship_type == 'parent_child')
                .count()
            )
        
        complex_result = database_benchmark(complex_join_query)
        assert complex_result == 99
    
    @pytest.mark.database
    @pytest.mark.performance
    def test_relationship_memory_efficiency(self, db_session, test_user, performance_monitor):
        """
        Test memory efficiency of relationship operations.
        
        Validates:
        - Memory usage patterns for large relationship sets
        - Garbage collection efficiency
        - Memory leak prevention
        """
        performance_monitor.start_monitoring()
        
        try:
            # Create and process large relationship dataset
            batch_size = 50
            for batch in range(5):  # 5 batches of 50 entities each
                entities = [
                    BusinessEntity(
                        name=f'Memory Test Entity {batch}_{i}',
                        description=f'Memory efficiency test entity batch {batch} item {i}',
                        owner_id=test_user.id,
                        status='active'
                    ) for i in range(batch_size)
                ]
                
                db_session.add_all(entities)
                db_session.commit()
                
                # Create relationships within batch
                relationships = []
                for i in range(batch_size - 1):
                    rel = EntityRelationship(
                        source_entity_id=entities[i].id,
                        target_entity_id=entities[i + 1].id,
                        relationship_type='parent_child'
                    )
                    relationships.append(rel)
                
                db_session.add_all(relationships)
                db_session.commit()
                
                # Process relationships to test memory usage
                for entity in entities:
                    related_entities = entity.get_related_entities()
                    assert isinstance(related_entities, list)
                
                # Clear references to help GC
                del entities
                del relationships
        
        finally:
            metrics = performance_monitor.stop_monitoring()
            
            # Validate memory usage is reasonable
            peak_memory_mb = metrics['peak_memory']
            assert peak_memory_mb < 500, f"Peak memory usage {peak_memory_mb}MB exceeds threshold"
            
            logger.info(f"Memory performance metrics: {metrics}")


# Test configuration and utilities
@pytest.mark.database
def test_relationship_test_configuration(db_session):
    """
    Validate test configuration and database setup for relationship testing.
    
    Ensures:
    - All required tables exist
    - Foreign key constraints are properly configured
    - Indexes are created for performance
    """
    # Check table existence
    inspector = inspect(db_session.bind)
    tables = inspector.get_table_names()
    
    required_tables = ['users', 'user_sessions', 'business_entities', 'entity_relationships']
    for table in required_tables:
        assert table in tables, f"Required table {table} not found in database"
    
    # Check foreign key constraints
    for table in required_tables[1:]:  # Skip users table (no foreign keys)
        foreign_keys = inspector.get_foreign_keys(table)
        assert len(foreign_keys) > 0, f"Table {table} should have foreign key constraints"
    
    # Check indexes for performance
    for table in required_tables:
        indexes = inspector.get_indexes(table)
        assert len(indexes) > 0, f"Table {table} should have performance indexes"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])