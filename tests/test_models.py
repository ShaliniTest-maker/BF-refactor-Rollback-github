"""
Database model testing module validating Flask-SQLAlchemy declarative models, relationship mappings, and data operations ensuring complete schema integrity during MongoDB to SQL conversion.

This comprehensive testing module implements Pytest 8.3.3 with Flask testing utilities for validating Flask-SQLAlchemy 3.1.1 model functionality, relationship mappings, and data operations per Section 4.7.1. It ensures 100% functional parity with the original Node.js/Mongoose implementation while maintaining complete data integrity throughout the MongoDB to PostgreSQL migration process.

Test Coverage Areas:
- Model field validation and constraint enforcement
- Relationship mapping and foreign key integrity
- CRUD operations with transaction rollback testing
- Encrypted field functionality and data protection
- Audit trail capture and user context tracking
- RBAC system integration and permission management
- Business entity relationship modeling
- Session management and authentication flows
- Data integrity validation and migration testing
- Performance benchmarking against baseline metrics

Dependencies:
- pytest: Primary testing framework with Flask integration
- Factory Boy: Test data generation with realistic patterns
- SQLAlchemy: Database session management and rollback capabilities
- Flask-SQLAlchemy: ORM functionality and model testing
"""

import pytest
import uuid
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional
import tempfile
import os

# SQLAlchemy and Flask testing imports
from sqlalchemy import text, func, and_, or_, distinct
from sqlalchemy.exc import IntegrityError, DataError, StatementError
from sqlalchemy.orm import sessionmaker, scoped_session
from flask import Flask, g
from flask_sqlalchemy import SQLAlchemy

# Import all model classes for comprehensive testing
from models.base import BaseModel, AuditMixin, EncryptedMixin
from models.user import User, UserSession
from models.rbac import Role, Permission
from models.business import BusinessEntity, EntityRelationship  
from models.audit import AuditLog, SecurityEvent

# Import Factory Boy test data generators
from tests.factories import (
    UserFactory, RoleFactory, PermissionFactory, BusinessEntityFactory,
    EntityRelationshipFactory, UserSessionFactory, AuditLogFactory,
    SecurityEventFactory, FactoryDataManager
)

# Performance and monitoring imports for baseline validation
import time
import psutil
import threading
from contextlib import contextmanager
from collections import defaultdict


class ModelTestBase:
    """
    Base test class providing common functionality for all model testing operations.
    
    Implements comprehensive testing infrastructure including database session management,
    transaction rollback capabilities, performance monitoring, and data integrity validation
    patterns per Section 4.7.3.1 testing infrastructure requirements.
    
    Features:
    - Automatic test database session management with rollback
    - Performance benchmarking against Node.js baseline metrics
    - Data integrity validation and constraint testing
    - Relationship mapping verification and foreign key testing
    - Factory Boy integration for realistic test data generation
    - Thread-safe session handling for concurrent test execution
    """
    
    @pytest.fixture(autouse=True)
    def setup_test_session(self, db_session, app_context):
        """
        Automatically configure test database session with rollback capabilities.
        
        Provides isolated test execution environment with automatic cleanup and
        rollback procedures ensuring test independence and data consistency per
        Section 4.7.3.1 database testing setup requirements.
        
        Args:
            db_session: SQLAlchemy test session with rollback capabilities
            app_context: Flask application context for model operations
        """
        self.db = db_session
        self.app = app_context
        
        # Configure Factory Boy to use test session
        for factory_class in [UserFactory, RoleFactory, PermissionFactory, 
                             BusinessEntityFactory, EntityRelationshipFactory,
                             UserSessionFactory, AuditLogFactory, SecurityEventFactory]:
            factory_class._meta.sqlalchemy_session = db_session
        
        # Setup performance monitoring
        self.performance_metrics = defaultdict(list)
        self.start_time = time.time()
        
        yield
        
        # Cleanup and rollback after each test
        db_session.rollback()
        db_session.close()
    
    def assert_model_fields(self, model_instance, expected_fields: Dict[str, Any]):
        """
        Validate model field values against expected data with comprehensive type checking.
        
        Args:
            model_instance: SQLAlchemy model instance to validate
            expected_fields: Dictionary of field names and expected values
        """
        for field_name, expected_value in expected_fields.items():
            actual_value = getattr(model_instance, field_name, None)
            
            # Handle different field types appropriately
            if isinstance(expected_value, datetime) and actual_value:
                # Allow small time differences for auto-generated timestamps
                time_diff = abs((actual_value - expected_value).total_seconds())
                assert time_diff < 5, f"Timestamp field {field_name} difference too large: {time_diff}s"
            elif expected_value is None:
                assert actual_value is None, f"Field {field_name} should be None but was {actual_value}"
            else:
                assert actual_value == expected_value, f"Field {field_name} mismatch: expected {expected_value}, got {actual_value}"
    
    def assert_relationship_integrity(self, model_instance, relationship_name: str, 
                                   expected_count: int = None, related_model_class=None):
        """
        Validate relationship mappings and foreign key integrity.
        
        Args:
            model_instance: Model instance with relationships to validate
            relationship_name: Name of the relationship attribute
            expected_count: Expected number of related objects
            related_model_class: Expected class of related objects
        """
        relationship = getattr(model_instance, relationship_name, None)
        assert relationship is not None, f"Relationship {relationship_name} not found"
        
        if expected_count is not None:
            if hasattr(relationship, '__len__'):
                actual_count = len(relationship)
            elif hasattr(relationship, 'count'):
                actual_count = relationship.count()
            else:
                actual_count = 1 if relationship else 0
            assert actual_count == expected_count, f"Relationship {relationship_name} count mismatch: expected {expected_count}, got {actual_count}"
        
        if related_model_class and relationship:
            if hasattr(relationship, '__iter__'):
                for related_obj in relationship:
                    assert isinstance(related_obj, related_model_class), f"Related object type mismatch in {relationship_name}"
            else:
                assert isinstance(relationship, related_model_class), f"Related object type mismatch in {relationship_name}"
    
    @contextmanager
    def measure_performance(self, operation_name: str):
        """
        Context manager for measuring database operation performance.
        
        Args:
            operation_name: Name of the operation being measured
        """
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss
        
        try:
            yield
        finally:
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss
            
            execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
            memory_delta = end_memory - start_memory
            
            self.performance_metrics[operation_name].append({
                'execution_time_ms': execution_time,
                'memory_delta_bytes': memory_delta,
                'timestamp': datetime.utcnow()
            })
    
    def validate_audit_fields(self, model_instance, operation_type: str = None):
        """
        Validate audit field population and user context tracking.
        
        Args:
            model_instance: Model instance with AuditMixin fields
            operation_type: Expected operation type (INSERT, UPDATE, DELETE)
        """
        if hasattr(model_instance, 'created_at'):
            assert model_instance.created_at is not None, "created_at field should be populated"
            assert isinstance(model_instance.created_at, datetime), "created_at should be datetime"
        
        if hasattr(model_instance, 'updated_at'):
            assert model_instance.updated_at is not None, "updated_at field should be populated"
            assert isinstance(model_instance.updated_at, datetime), "updated_at should be datetime"
        
        if operation_type and hasattr(model_instance, 'operation_type'):
            assert model_instance.operation_type == operation_type, f"Operation type mismatch: expected {operation_type}"


class TestUserModel(ModelTestBase):
    """
    Comprehensive User model testing validating authentication fields, encrypted data,
    RBAC relationships, and Auth0 integration per Section 0.1.2 authentication migration requirements.
    
    Tests cover user authentication patterns, profile management, session handling,
    and security features ensuring complete functional parity with Node.js implementation.
    """
    
    def test_user_creation_with_basic_fields(self):
        """Test basic user creation with authentication and profile fields."""
        with self.measure_performance('user_creation_basic'):
            user_data = {
                'auth0_user_id': f"auth0|{uuid.uuid4().hex[:24]}",
                'email': 'test@example.com',
                'username': 'testuser',
                'first_name': 'Test',
                'last_name': 'User',
                'is_active': True,
                'email_verified': True
            }
            
            user = UserFactory(**user_data)
            self.db.add(user)
            self.db.commit()
            
            # Validate basic fields
            self.assert_model_fields(user, user_data)
            
            # Validate audit fields
            self.validate_audit_fields(user, 'INSERT')
            
            # Validate unique constraints
            assert user.id is not None, "User ID should be auto-generated"
            assert user.email == user_data['email'], "Email should be preserved"
            assert user.username == user_data['username'], "Username should be preserved"
    
    def test_user_encrypted_fields_functionality(self):
        """Test encrypted field storage and retrieval using SQLAlchemy-Utils EncryptedType."""
        with self.measure_performance('user_encrypted_fields'):
            user = UserFactory(
                phone_number='+1-555-123-4567',
                date_of_birth=datetime(1990, 5, 15).date()
            )
            self.db.add(user)
            self.db.commit()
            
            # Refresh from database to test encryption/decryption
            self.db.refresh(user)
            
            # Validate encrypted fields are properly decrypted on access
            assert user.phone_number == '+1-555-123-4567', "Phone number should be decrypted correctly"
            assert user.date_of_birth == datetime(1990, 5, 15).date(), "Date of birth should be decrypted correctly"
            
            # Validate that encrypted data is not stored in plain text (implementation dependent)
            # This would require direct database inspection in a full implementation
    
    def test_user_rbac_relationship_integration(self):
        """Test User-Role many-to-many relationship mapping and RBAC integration."""
        with self.measure_performance('user_rbac_relationships'):
            # Create user with multiple roles
            roles = RoleFactory.create_batch(3, is_active=True)
            user = UserFactory()
            
            # Add roles to user
            for role in roles:
                user.roles.append(role)
            
            self.db.add(user)
            self.db.commit()
            
            # Validate relationship integrity
            self.assert_relationship_integrity(user, 'roles', expected_count=3, related_model_class=Role)
            
            # Test bidirectional relationship
            for role in roles:
                assert user in role.users, "Bidirectional relationship should be maintained"
            
            # Test role removal
            user.roles.remove(roles[0])
            self.db.commit()
            
            self.assert_relationship_integrity(user, 'roles', expected_count=2)
    
    def test_user_session_relationship_management(self):
        """Test User-UserSession one-to-many relationship with session lifecycle."""
        with self.measure_performance('user_session_relationships'):
            user = UserFactory()
            sessions = UserSessionFactory.create_batch(3, user=user, is_active=True)
            
            self.db.add(user)
            self.db.commit()
            
            # Validate session relationships
            self.assert_relationship_integrity(user, 'sessions', expected_count=3, related_model_class=UserSession)
            
            # Test session expiration handling
            expired_session = sessions[0]
            expired_session.expires_at = datetime.utcnow() - timedelta(hours=1)
            expired_session.is_active = False
            self.db.commit()
            
            # Validate that expired session is still associated but marked inactive
            active_sessions = [s for s in user.sessions if s.is_active]
            assert len(active_sessions) == 2, "Only active sessions should be counted"
    
    def test_user_unique_constraint_enforcement(self):
        """Test unique constraint enforcement for email and username fields."""
        with self.measure_performance('user_unique_constraints'):
            # Create first user
            user1 = UserFactory(email='unique@test.com', username='uniqueuser')
            self.db.add(user1)
            self.db.commit()
            
            # Attempt to create user with duplicate email
            with pytest.raises(IntegrityError):
                user2 = UserFactory(email='unique@test.com', username='differentuser')
                self.db.add(user2)
                self.db.commit()
            
            self.db.rollback()
            
            # Attempt to create user with duplicate username
            with pytest.raises(IntegrityError):
                user3 = UserFactory(email='different@test.com', username='uniqueuser')
                self.db.add(user3)
                self.db.commit()
    
    def test_user_business_entity_ownership(self):
        """Test User ownership of BusinessEntity objects with cascade relationships."""
        with self.measure_performance('user_business_ownership'):
            user = UserFactory()
            entities = BusinessEntityFactory.create_batch(3, owner=user)
            
            self.db.add(user)
            self.db.commit()
            
            # Validate ownership relationships
            self.assert_relationship_integrity(user, 'owned_entities', expected_count=3, related_model_class=BusinessEntity)
            
            # Test cascade deletion behavior (if configured)
            for entity in entities:
                assert entity.owner_id == user.id, "Entity should be owned by user"
    
    def test_user_authentication_metadata_tracking(self):
        """Test authentication metadata fields and security tracking."""
        with self.measure_performance('user_auth_metadata'):
            login_time = datetime.utcnow()
            user = UserFactory(
                last_login_at=login_time,
                last_login_ip='192.168.1.100',
                failed_login_attempts=2,
                account_locked_until=None
            )
            self.db.add(user)
            self.db.commit()
            
            # Validate authentication metadata
            assert user.last_login_at == login_time, "Last login time should be preserved"
            assert user.last_login_ip == '192.168.1.100', "Last login IP should be tracked"
            assert user.failed_login_attempts == 2, "Failed login attempts should be tracked"
            
            # Test account locking mechanism
            user.account_locked_until = datetime.utcnow() + timedelta(hours=1)
            user.failed_login_attempts = 5
            self.db.commit()
            
            # Validate account lock status
            assert user.account_locked_until > datetime.utcnow(), "Account should be locked"
            assert not user.is_account_accessible, "Account should not be accessible when locked"
    
    def test_user_profile_data_validation(self):
        """Test user profile data validation and optional field handling."""
        with self.measure_performance('user_profile_validation'):
            # Test with complete profile
            complete_user = UserFactory(
                first_name='John',
                last_name='Doe',
                bio='Software developer with 5+ years experience',
                timezone='America/New_York',
                locale='en-US',
                profile_picture_url='https://example.com/avatar.jpg'
            )
            self.db.add(complete_user)
            self.db.commit()
            
            # Validate profile completeness
            assert complete_user.first_name == 'John', "First name should be stored correctly"
            assert complete_user.last_name == 'Doe', "Last name should be stored correctly"
            assert complete_user.bio is not None, "Bio should be optional but stored when provided"
            assert complete_user.timezone == 'America/New_York', "Timezone should be configurable"
            assert complete_user.locale == 'en-US', "Locale should be configurable"
            
            # Test with minimal profile
            minimal_user = UserFactory(
                first_name=None,
                last_name=None,
                bio=None,
                profile_picture_url=None
            )
            self.db.add(minimal_user)
            self.db.commit()
            
            # Validate minimal profile handling
            assert minimal_user.first_name is None, "Optional fields should accept None"
            assert minimal_user.bio is None, "Bio should be optional"


class TestRolePermissionModels(ModelTestBase):
    """
    RBAC system testing validating Role and Permission models, many-to-many relationships,
    and authorization system integration per Section 0.1.2 authorization requirements.
    
    Tests comprehensive role-based access control functionality including role hierarchy,
    permission granularity, and user-role-permission relationship integrity.
    """
    
    def test_role_creation_and_validation(self):
        """Test Role model creation with validation and status management."""
        with self.measure_performance('role_creation'):
            role_data = {
                'name': 'admin',
                'description': 'Administrative role with full system access',
                'is_active': True
            }
            
            role = RoleFactory(**role_data)
            self.db.add(role)
            self.db.commit()
            
            # Validate role fields
            self.assert_model_fields(role, role_data)
            self.validate_audit_fields(role, 'INSERT')
            
            # Test role status management
            role.is_active = False
            self.db.commit()
            
            assert not role.is_active, "Role should be deactivatable"
    
    def test_permission_resource_action_model(self):
        """Test Permission model with resource-action pattern for granular access control."""
        with self.measure_performance('permission_resource_action'):
            permission_data = {
                'resource': 'users',
                'action': 'create',
                'description': 'Permission to create new users',
                'is_active': True
            }
            
            permission = PermissionFactory(**permission_data)
            self.db.add(permission)
            self.db.commit()
            
            # Validate permission fields
            self.assert_model_fields(permission, permission_data)
            
            # Test resource-action uniqueness (if implemented)
            # This would depend on unique constraints in the actual model
    
    def test_role_permission_many_to_many_relationship(self):
        """Test Role-Permission many-to-many relationship with association metadata."""
        with self.measure_performance('role_permission_relationships'):
            role = RoleFactory(name='editor')
            permissions = PermissionFactory.create_batch(5, is_active=True)
            
            # Assign permissions to role
            for permission in permissions:
                role.permissions.append(permission)
            
            self.db.add(role)
            self.db.commit()
            
            # Validate relationship integrity
            self.assert_relationship_integrity(role, 'permissions', expected_count=5, related_model_class=Permission)
            
            # Test bidirectional relationship
            for permission in permissions:
                assert role in permission.roles, "Bidirectional relationship should be maintained"
            
            # Test permission removal
            role.permissions.remove(permissions[0])
            self.db.commit()
            
            self.assert_relationship_integrity(role, 'permissions', expected_count=4)
    
    def test_role_hierarchy_and_inheritance(self):
        """Test role hierarchy patterns and permission inheritance (if implemented)."""
        with self.measure_performance('role_hierarchy'):
            # Create role hierarchy: admin > manager > user
            admin_role = RoleFactory(name='admin')
            manager_role = RoleFactory(name='manager')  
            user_role = RoleFactory(name='user')
            
            # Create permission set
            admin_perms = PermissionFactory.create_batch(10, is_active=True)
            manager_perms = admin_perms[:7]  # Subset of admin permissions
            user_perms = admin_perms[:3]     # Subset of manager permissions
            
            # Assign permissions by hierarchy
            admin_role.permissions.extend(admin_perms)
            manager_role.permissions.extend(manager_perms)
            user_role.permissions.extend(user_perms)
            
            self.db.add_all([admin_role, manager_role, user_role])
            self.db.commit()
            
            # Validate hierarchy permissions
            assert len(admin_role.permissions) == 10, "Admin should have all permissions"
            assert len(manager_role.permissions) == 7, "Manager should have subset of permissions"
            assert len(user_role.permissions) == 3, "User should have minimal permissions"
    
    def test_permission_deactivation_impact(self):
        """Test permission deactivation and its impact on role-permission relationships."""
        with self.measure_performance('permission_deactivation'):
            role = RoleFactory()
            active_permission = PermissionFactory(is_active=True)
            inactive_permission = PermissionFactory(is_active=False)
            
            role.permissions.extend([active_permission, inactive_permission])
            self.db.add(role)
            self.db.commit()
            
            # Validate total permissions
            assert len(role.permissions) == 2, "Role should have both permissions"
            
            # Filter for active permissions (business logic dependent)
            active_permissions = [p for p in role.permissions if p.is_active]
            assert len(active_permissions) == 1, "Only active permissions should be effective"
    
    def test_rbac_user_role_assignment(self):
        """Test complete RBAC integration with User-Role assignments."""
        with self.measure_performance('rbac_user_assignment'):
            # Create RBAC system
            rbac_system = FactoryDataManager.create_rbac_system(
                user_count=3, role_count=3, permission_count=10
            )
            
            users = rbac_system['users']
            roles = rbac_system['roles']
            permissions = rbac_system['permissions']
            
            # Validate complete RBAC integration
            for user in users:
                assert len(user.roles) > 0, "Users should have assigned roles"
                
                # Collect all permissions through roles
                user_permissions = set()
                for role in user.roles:
                    user_permissions.update(role.permissions)
                
                assert len(user_permissions) > 0, "Users should have permissions through roles"


class TestBusinessEntityModels(ModelTestBase):
    """
    Business entity and relationship model testing validating core business object
    functionality, entity relationships, and business logic integration per Section 0.1.2
    business logic preservation requirements.
    
    Tests business entity management, relationship tracking, and workflow orchestration
    patterns ensuring complete functional equivalence with Node.js implementation.
    """
    
    def test_business_entity_creation_and_metadata(self):
        """Test BusinessEntity model with metadata fields and status management."""
        with self.measure_performance('business_entity_creation'):
            entity_data = {
                'name': 'Acme Corporation',
                'description': 'Technology consulting company',
                'entity_type': 'company',
                'status': 'active',
                'external_id': f"EXT-{uuid.uuid4().hex[:12].upper()}",
                'tags': json.dumps(['technology', 'consulting', 'enterprise']),
                'metadata': json.dumps({
                    'industry': 'Technology',
                    'size': 'large',
                    'location': 'New York',
                    'founded': '2010'
                })
            }
            
            owner = UserFactory()
            entity = BusinessEntityFactory(owner=owner, **entity_data)
            
            self.db.add(entity)
            self.db.commit()
            
            # Validate entity fields
            self.assert_model_fields(entity, entity_data)
            self.validate_audit_fields(entity, 'INSERT')
            
            # Validate owner relationship
            assert entity.owner_id == owner.id, "Entity should be owned by user"
            assert entity in owner.owned_entities, "Bidirectional relationship should work"
    
    def test_entity_relationship_modeling(self):
        """Test EntityRelationship model for business entity interconnections."""
        with self.measure_performance('entity_relationships'):
            # Create related entities
            parent_company = BusinessEntityFactory(entity_type='company', name='Parent Corp')
            subsidiary = BusinessEntityFactory(entity_type='company', name='Subsidiary LLC')
            
            # Create relationship
            relationship = EntityRelationshipFactory(
                source_entity=parent_company,
                target_entity=subsidiary,
                relationship_type='parent_child',
                description='Parent-subsidiary corporate relationship',
                is_active=True,
                strength=9
            )
            
            self.db.add(relationship)
            self.db.commit()
            
            # Validate relationship fields
            assert relationship.source_entity_id == parent_company.id, "Source entity should be linked"
            assert relationship.target_entity_id == subsidiary.id, "Target entity should be linked"
            assert relationship.relationship_type == 'parent_child', "Relationship type should be preserved"
            assert relationship.strength == 9, "Relationship strength should be tracked"
            
            # Validate bidirectional navigation
            assert relationship in parent_company.source_relationships, "Source relationships should be accessible"
            assert relationship in subsidiary.target_relationships, "Target relationships should be accessible"
    
    def test_entity_hierarchy_creation(self):
        """Test complex entity hierarchy creation and relationship navigation."""
        with self.measure_performance('entity_hierarchy'):
            # Create business hierarchy using factory manager
            hierarchy_entities = FactoryDataManager.create_business_hierarchy(
                levels=3, entities_per_level=2
            )
            
            # Validate hierarchy structure
            assert len(hierarchy_entities) == 6, "Should create 6 entities across 3 levels"
            
            # Find top-level entities (no incoming parent relationships)
            top_level_entities = []
            for entity in hierarchy_entities:
                has_parent = any(
                    rel.relationship_type == 'parent_child' and rel.target_entity_id == entity.id
                    for rel in EntityRelationship.query.all()
                )
                if not has_parent:
                    top_level_entities.append(entity)
            
            assert len(top_level_entities) == 2, "Should have 2 top-level entities"
    
    def test_entity_relationship_types_and_validation(self):
        """Test various entity relationship types and their validation rules."""
        with self.measure_performance('relationship_types'):
            entity1 = BusinessEntityFactory(entity_type='company')
            entity2 = BusinessEntityFactory(entity_type='department')
            
            # Test different relationship types
            relationship_types = [
                'parent_child', 'owns', 'manages', 'depends_on',
                'collaborates_with', 'reports_to', 'provides_service_to'
            ]
            
            relationships = []
            for rel_type in relationship_types:
                rel = EntityRelationshipFactory(
                    source_entity=entity1,
                    target_entity=entity2,
                    relationship_type=rel_type,
                    is_active=True
                )
                relationships.append(rel)
            
            self.db.add_all(relationships)
            self.db.commit()
            
            # Validate all relationship types are preserved
            for rel in relationships:
                assert rel.relationship_type in relationship_types, f"Relationship type {rel.relationship_type} should be valid"
                assert rel.is_active, "Relationships should be active by default"
    
    def test_entity_metadata_json_operations(self):
        """Test JSON metadata field operations and queries."""
        with self.measure_performance('json_metadata_operations'):
            entity = BusinessEntityFactory(
                metadata=json.dumps({
                    'industry': 'Technology',
                    'employees': 150,
                    'locations': ['New York', 'San Francisco'],
                    'certifications': {
                        'iso27001': True,
                        'soc2': True
                    }
                })
            )
            
            self.db.add(entity)
            self.db.commit()
            
            # Test metadata access and manipulation
            metadata = json.loads(entity.metadata)
            assert metadata['industry'] == 'Technology', "JSON metadata should be preserved"
            assert metadata['employees'] == 150, "Numeric values should be preserved"
            assert len(metadata['locations']) == 2, "Array values should be preserved"
            assert metadata['certifications']['iso27001'], "Nested objects should be preserved"
    
    def test_entity_status_lifecycle_management(self):
        """Test entity status transitions and lifecycle management."""
        with self.measure_performance('entity_lifecycle'):
            entity = BusinessEntityFactory(status='pending')
            self.db.add(entity)
            self.db.commit()
            
            # Test status transitions
            status_transitions = ['pending', 'active', 'inactive', 'archived']
            
            for status in status_transitions:
                entity.status = status
                self.db.commit()
                
                # Refresh and validate
                self.db.refresh(entity)
                assert entity.status == status, f"Entity status should transition to {status}"
                
                # Validate updated_at field changes
                previous_updated = entity.updated_at
                entity.description = f"Updated for status {status}"
                self.db.commit()
                
                assert entity.updated_at > previous_updated, "updated_at should change on modifications"


class TestAuditAndSecurityModels(ModelTestBase):
    """
    Audit logging and security event model testing validating comprehensive audit trails,
    security monitoring, and compliance requirements per Section 0.1.2 audit trail requirements.
    
    Tests audit log capture, security event tracking, and compliance data management
    ensuring complete audit capabilities for regulatory requirements and security analysis.
    """
    
    def test_audit_log_dml_operation_tracking(self):
        """Test AuditLog model for comprehensive DML operation tracking."""
        with self.measure_performance('audit_log_tracking'):
            user = UserFactory()
            
            audit_data = {
                'table_name': 'users',
                'record_id': str(user.id),
                'operation_type': 'INSERT',
                'user': user,
                'user_ip': '192.168.1.100',
                'user_agent': 'Mozilla/5.0 Test Browser',
                'old_values': None,
                'new_values': json.dumps({
                    'email': user.email,
                    'username': user.username,
                    'is_active': True
                }),
                'changed_fields': json.dumps(['email', 'username', 'is_active']),
                'transaction_id': uuid.uuid4().hex,
                'session_id': uuid.uuid4().hex
            }
            
            audit_log = AuditLogFactory(**audit_data)
            self.db.add(audit_log)
            self.db.commit()
            
            # Validate audit log fields
            self.assert_model_fields(audit_log, audit_data)
            
            # Validate JSON fields
            new_values = json.loads(audit_log.new_values)
            changed_fields = json.loads(audit_log.changed_fields)
            
            assert new_values['email'] == user.email, "New values should be tracked"
            assert 'email' in changed_fields, "Changed fields should be tracked"
    
    def test_audit_log_update_operation_tracking(self):
        """Test audit log tracking for UPDATE operations with before/after values."""
        with self.measure_performance('audit_update_tracking'):
            user = UserFactory()
            
            # Simulate update operation audit
            old_values = {
                'email': 'old@example.com',
                'is_active': False
            }
            new_values = {
                'email': user.email,
                'is_active': True
            }
            
            audit_log = AuditLogFactory(
                table_name='users',
                record_id=str(user.id),
                operation_type='UPDATE',
                user=user,
                old_values=json.dumps(old_values),
                new_values=json.dumps(new_values),
                changed_fields=json.dumps(['email', 'is_active'])
            )
            
            self.db.add(audit_log)
            self.db.commit()
            
            # Validate update tracking
            assert audit_log.operation_type == 'UPDATE', "Operation type should be UPDATE"
            
            old_data = json.loads(audit_log.old_values)
            new_data = json.loads(audit_log.new_values)
            
            assert old_data['email'] != new_data['email'], "Old and new values should differ"
            assert old_data['is_active'] != new_data['is_active'], "Status change should be tracked"
    
    def test_security_event_classification_and_tracking(self):
        """Test SecurityEvent model for threat detection and incident response."""
        with self.measure_performance('security_event_tracking'):
            user = UserFactory()
            
            event_data = {
                'event_type': 'authentication_failure',
                'severity': 'medium',
                'description': 'Multiple failed login attempts detected',
                'user': user,
                'ip_address': '192.168.1.100',
                'user_agent': 'Mozilla/5.0 Test Browser',
                'event_data': json.dumps({
                    'request_path': '/api/auth/login',
                    'method': 'POST',
                    'response_code': 401,
                    'attempt_count': 5
                }),
                'risk_score': 75,
                'is_resolved': False,
                'detection_rule': 'RULE_AUTH_001',
                'source_system': 'webapp'
            }
            
            security_event = SecurityEventFactory(**event_data)
            self.db.add(security_event)
            self.db.commit()
            
            # Validate security event fields
            self.assert_model_fields(security_event, event_data)
            
            # Validate event data JSON
            event_details = json.loads(security_event.event_data)
            assert event_details['attempt_count'] == 5, "Event details should be preserved"
            assert event_details['response_code'] == 401, "Response code should be tracked"
    
    def test_security_event_resolution_workflow(self):
        """Test security event resolution and incident management workflow."""
        with self.measure_performance('security_resolution'):
            user = UserFactory()
            resolver = UserFactory()
            
            security_event = SecurityEventFactory(
                event_type='suspicious_activity',
                severity='high',
                user=user,
                is_resolved=False,
                risk_score=90
            )
            
            self.db.add(security_event)
            self.db.commit()
            
            # Simulate resolution process
            resolution_time = datetime.utcnow()
            security_event.is_resolved = True
            security_event.resolved_by = resolver
            security_event.resolved_at = resolution_time
            
            self.db.commit()
            
            # Validate resolution
            assert security_event.is_resolved, "Event should be marked as resolved"
            assert security_event.resolved_by_id == resolver.id, "Resolver should be tracked"
            assert security_event.resolved_at == resolution_time, "Resolution time should be tracked"
    
    def test_audit_trail_comprehensive_data_generation(self):
        """Test comprehensive audit trail generation across multiple entities."""
        with self.measure_performance('comprehensive_audit_trail'):
            # Generate comprehensive audit trail using factory manager
            audit_logs = FactoryDataManager.create_audit_trail(
                entity_count=10, operations_per_entity=5
            )
            
            # Validate audit trail coverage
            assert len(audit_logs) == 50, "Should create 50 audit log entries"
            
            # Validate operation types distribution
            operation_types = [log.operation_type for log in audit_logs]
            assert 'INSERT' in operation_types, "Should include INSERT operations"
            assert 'UPDATE' in operation_types, "Should include UPDATE operations"
            assert 'DELETE' in operation_types, "Should include DELETE operations"
            
            # Validate user attribution
            users_with_operations = set(log.user_id for log in audit_logs if log.user_id)
            assert len(users_with_operations) > 0, "Audit logs should have user attribution"
    
    def test_audit_log_retention_and_archival_simulation(self):
        """Test audit log retention policies and archival procedures simulation."""
        with self.measure_performance('audit_retention'):
            # Create audit logs with different ages
            current_time = datetime.utcnow()
            
            # Recent logs (within retention period)
            recent_logs = []
            for i in range(5):
                log = AuditLogFactory(
                    created_at=current_time - timedelta(days=i*30)  # 0-4 months old
                )
                recent_logs.append(log)
            
            # Old logs (beyond retention period)
            old_logs = []
            for i in range(5):
                log = AuditLogFactory(
                    created_at=current_time - timedelta(days=(i+24)*30)  # 2+ years old
                )
                old_logs.append(log)
            
            self.db.add_all(recent_logs + old_logs)
            self.db.commit()
            
            # Simulate retention policy queries
            retention_cutoff = current_time - timedelta(days=365*2)  # 2 years
            
            logs_for_archival = self.db.query(AuditLog).filter(
                AuditLog.created_at < retention_cutoff
            ).all()
            
            logs_for_retention = self.db.query(AuditLog).filter(
                AuditLog.created_at >= retention_cutoff
            ).all()
            
            assert len(logs_for_archival) == 5, "Old logs should be identified for archival"
            assert len(logs_for_retention) == 5, "Recent logs should be retained"


class TestUserSessionModel(ModelTestBase):
    """
    User session model testing validating Flask session management, security token handling,
    and authentication flow integration per Section 0.1.3 session architecture specifications.
    
    Tests session lifecycle management, security features, and integration with
    Flask-Login authentication patterns ensuring complete session functionality.
    """
    
    def test_user_session_creation_and_lifecycle(self):
        """Test UserSession creation with security tokens and expiration management."""
        with self.measure_performance('session_lifecycle'):
            user = UserFactory()
            
            session_data = {
                'user': user,
                'session_token': uuid.uuid4().hex,
                'csrf_token': uuid.uuid4().hex,
                'ip_address': '192.168.1.100',
                'user_agent': 'Mozilla/5.0 Test Browser',
                'device_fingerprint': uuid.uuid4().hex[:16],
                'is_active': True,
                'expires_at': datetime.utcnow() + timedelta(hours=24),
                'location_data': json.dumps({
                    'country': 'United States',
                    'city': 'New York',
                    'timezone': 'America/New_York'
                })
            }
            
            session = UserSessionFactory(**session_data)
            self.db.add(session)
            self.db.commit()
            
            # Validate session fields
            self.assert_model_fields(session, session_data)
            
            # Validate session-user relationship
            assert session.user_id == user.id, "Session should be linked to user"
            assert session in user.sessions, "Bidirectional relationship should work"
    
    def test_session_token_uniqueness_and_security(self):
        """Test session token uniqueness constraints and security features."""
        with self.measure_performance('session_security'):
            user1 = UserFactory()
            user2 = UserFactory()
            
            # Create sessions with unique tokens
            session1 = UserSessionFactory(user=user1, session_token='unique_token_1')
            session2 = UserSessionFactory(user=user2, session_token='unique_token_2')
            
            self.db.add_all([session1, session2])
            self.db.commit()
            
            # Attempt to create session with duplicate token
            with pytest.raises(IntegrityError):
                duplicate_session = UserSessionFactory(user=user2, session_token='unique_token_1')
                self.db.add(duplicate_session)
                self.db.commit()
    
    def test_session_expiration_and_cleanup(self):
        """Test session expiration handling and cleanup procedures."""
        with self.measure_performance('session_expiration'):
            user = UserFactory()
            current_time = datetime.utcnow()
            
            # Create active session
            active_session = UserSessionFactory(
                user=user,
                is_active=True,
                expires_at=current_time + timedelta(hours=1)
            )
            
            # Create expired session
            expired_session = UserSessionFactory(
                user=user,
                is_active=True,  # Still marked active but expired
                expires_at=current_time - timedelta(hours=1)
            )
            
            self.db.add_all([active_session, expired_session])
            self.db.commit()
            
            # Query for expired sessions
            expired_sessions = self.db.query(UserSession).filter(
                UserSession.expires_at < current_time
            ).all()
            
            active_sessions = self.db.query(UserSession).filter(
                and_(
                    UserSession.expires_at > current_time,
                    UserSession.is_active == True
                )
            ).all()
            
            assert len(expired_sessions) == 1, "Should identify expired sessions"
            assert len(active_sessions) == 1, "Should identify active sessions"
    
    def test_session_activity_tracking(self):
        """Test session activity tracking and last activity updates."""
        with self.measure_performance('session_activity'):
            user = UserFactory()
            session = UserSessionFactory(user=user, is_active=True)
            
            initial_activity = session.last_activity_at
            self.db.add(session)
            self.db.commit()
            
            # Simulate activity update
            new_activity_time = datetime.utcnow()
            session.last_activity_at = new_activity_time
            self.db.commit()
            
            # Validate activity tracking
            assert session.last_activity_at > initial_activity, "Activity time should be updated"
            
            # Test activity-based session validation
            session_timeout = timedelta(minutes=30)
            is_session_valid = (
                session.is_active and 
                session.expires_at > datetime.utcnow() and
                session.last_activity_at > (datetime.utcnow() - session_timeout)
            )
            
            # Should be valid since we just updated activity
            assert is_session_valid, "Session should be valid based on recent activity"
    
    def test_session_location_and_device_tracking(self):
        """Test session location data and device fingerprinting."""
        with self.measure_performance('session_device_tracking'):
            user = UserFactory()
            
            session = UserSessionFactory(
                user=user,
                ip_address='203.0.113.100',  # Example IP
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                device_fingerprint='device_fp_12345',
                location_data=json.dumps({
                    'country': 'Canada',
                    'city': 'Toronto',
                    'timezone': 'America/Toronto',
                    'lat': 43.6532,
                    'lon': -79.3832
                })
            )
            
            self.db.add(session)
            self.db.commit()
            
            # Validate location data
            location_data = json.loads(session.location_data)
            assert location_data['country'] == 'Canada', "Location country should be tracked"
            assert location_data['city'] == 'Toronto', "Location city should be tracked"
            assert 'lat' in location_data, "Latitude should be tracked"
            assert 'lon' in location_data, "Longitude should be tracked"
            
            # Validate device tracking
            assert session.device_fingerprint == 'device_fp_12345', "Device fingerprint should be tracked"
            assert 'Windows NT' in session.user_agent, "User agent should be preserved"
    
    def test_multiple_active_sessions_per_user(self):
        """Test support for multiple active sessions per user."""
        with self.measure_performance('multiple_sessions'):
            user = UserFactory()
            
            # Create multiple active sessions (different devices)
            sessions = []
            devices = ['desktop', 'mobile', 'tablet']
            
            for device in devices:
                session = UserSessionFactory(
                    user=user,
                    is_active=True,
                    device_fingerprint=f"{device}_fingerprint",
                    user_agent=f"TestAgent/{device}"
                )
                sessions.append(session)
            
            self.db.add_all(sessions)
            self.db.commit()
            
            # Validate multiple sessions
            user_sessions = self.db.query(UserSession).filter(
                and_(
                    UserSession.user_id == user.id,
                    UserSession.is_active == True
                )
            ).all()
            
            assert len(user_sessions) == 3, "User should support multiple active sessions"
            
            # Validate session distinction
            fingerprints = [s.device_fingerprint for s in user_sessions]
            assert len(set(fingerprints)) == 3, "Each session should have unique device fingerprint"


class TestModelPerformanceAndIntegration(ModelTestBase):
    """
    Performance validation and integration testing ensuring Flask-SQLAlchemy models
    meet or exceed Node.js baseline performance metrics per Section 4.7.4.1 performance
    benchmarking requirements.
    
    Tests comprehensive integration scenarios, performance characteristics, and
    system scalability ensuring production readiness and SLA compliance.
    """
    
    def test_bulk_operations_performance(self):
        """Test bulk database operations performance against baseline metrics."""
        with self.measure_performance('bulk_operations'):
            start_time = time.time()
            
            # Create large dataset for performance testing
            users = UserFactory.create_batch(100)
            self.db.add_all(users)
            self.db.commit()
            
            bulk_creation_time = time.time() - start_time
            
            # Validate performance (should be under 1 second for 100 users)
            assert bulk_creation_time < 1.0, f"Bulk creation took {bulk_creation_time:.3f}s, should be under 1.0s"
            
            # Test bulk query performance
            start_time = time.time()
            active_users = self.db.query(User).filter(User.is_active == True).all()
            query_time = time.time() - start_time
            
            assert query_time < 0.1, f"Bulk query took {query_time:.3f}s, should be under 0.1s"
    
    def test_complex_relationship_queries_performance(self):
        """Test complex relationship queries with joins and eager loading."""
        with self.measure_performance('complex_queries'):
            # Create complex data structure
            rbac_system = FactoryDataManager.create_rbac_system(
                user_count=20, role_count=5, permission_count=15
            )
            
            start_time = time.time()
            
            # Complex query with multiple joins
            users_with_permissions = self.db.query(User).join(
                User.roles
            ).join(
                Role.permissions
            ).filter(
                Permission.resource == 'users'
            ).distinct().all()
            
            complex_query_time = time.time() - start_time
            
            assert complex_query_time < 0.2, f"Complex query took {complex_query_time:.3f}s, should be under 0.2s"
            assert len(users_with_permissions) > 0, "Should find users with user permissions"
    
    def test_concurrent_session_handling(self):
        """Test concurrent database session handling and connection pooling."""
        with self.measure_performance('concurrent_sessions'):
            import threading
            import queue
            
            results = queue.Queue()
            error_queue = queue.Queue()
            
            def create_user_concurrently(thread_id):
                try:
                    # Create user in separate thread
                    user = UserFactory(username=f'concurrent_user_{thread_id}')
                    self.db.add(user)
                    self.db.commit()
                    results.put(user.id)
                except Exception as e:
                    error_queue.put(e)
            
            # Launch concurrent threads
            threads = []
            for i in range(10):
                thread = threading.Thread(target=create_user_concurrently, args=(i,))
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join()
            
            # Validate results
            created_users = []
            while not results.empty():
                created_users.append(results.get())
            
            errors = []
            while not error_queue.empty():
                errors.append(error_queue.get())
            
            assert len(created_users) == 10, f"Should create 10 users concurrently, got {len(created_users)}"
            assert len(errors) == 0, f"Should have no errors, got {len(errors)}"
    
    def test_memory_usage_optimization(self):
        """Test memory usage patterns and optimization for large datasets."""
        with self.measure_performance('memory_optimization'):
            import psutil
            process = psutil.Process()
            
            # Measure initial memory
            initial_memory = process.memory_info().rss
            
            # Create large dataset
            large_dataset = UserFactory.create_batch(500)
            self.db.add_all(large_dataset)
            self.db.commit()
            
            # Measure memory after creation
            after_creation_memory = process.memory_info().rss
            memory_increase = after_creation_memory - initial_memory
            
            # Memory increase should be reasonable (under 100MB for 500 users)
            max_acceptable_memory = 100 * 1024 * 1024  # 100MB
            assert memory_increase < max_acceptable_memory, f"Memory increase {memory_increase} bytes exceeds {max_acceptable_memory}"
            
            # Test memory cleanup after session clear
            self.db.expunge_all()
            
            # Force garbage collection
            import gc
            gc.collect()
    
    def test_transaction_rollback_integrity(self):
        """Test transaction rollback capabilities and data integrity."""
        with self.measure_performance('transaction_rollback'):
            # Create initial data
            user = UserFactory()
            self.db.add(user)
            self.db.commit()
            
            initial_user_count = self.db.query(User).count()
            
            # Start transaction and make changes
            self.db.begin()
            
            try:
                # Create additional users
                new_users = UserFactory.create_batch(5)
                self.db.add_all(new_users)
                
                # Simulate error condition
                raise Exception("Simulated transaction error")
                
            except Exception:
                # Rollback transaction
                self.db.rollback()
            
            # Validate rollback integrity
            final_user_count = self.db.query(User).count()
            assert final_user_count == initial_user_count, "Transaction rollback should restore original state"
    
    def test_data_migration_simulation(self):
        """Test data migration patterns and validation procedures."""
        with self.measure_performance('migration_simulation'):
            # Simulate MongoDB document structure migration
            mongodb_user_data = {
                'username': 'migrated_user',
                'email': 'migrated@example.com',
                'profile': {
                    'firstName': 'John',
                    'lastName': 'Doe',
                    'preferences': {
                        'theme': 'dark',
                        'notifications': True
                    }
                },
                'roles': ['admin', 'editor'],
                'metadata': {
                    'lastLogin': '2024-01-15T10:30:00Z',
                    'signupSource': 'web'
                }
            }
            
            # Transform to relational structure
            user = UserFactory(
                username=mongodb_user_data['username'],
                email=mongodb_user_data['email'],
                first_name=mongodb_user_data['profile']['firstName'],
                last_name=mongodb_user_data['profile']['lastName']
            )
            
            # Create roles from array
            role_names = mongodb_user_data['roles']
            roles = []
            for role_name in role_names:
                role = RoleFactory(name=role_name)
                roles.append(role)
                user.roles.append(role)
            
            self.db.add(user)
            self.db.commit()
            
            # Validate migration integrity
            assert user.username == mongodb_user_data['username'], "Username should be preserved"
            assert user.email == mongodb_user_data['email'], "Email should be preserved"
            assert user.first_name == mongodb_user_data['profile']['firstName'], "First name should be extracted"
            assert len(user.roles) == len(mongodb_user_data['roles']), "Roles should be converted to relationships"
    
    def test_model_serialization_performance(self):
        """Test model serialization performance for API responses."""
        with self.measure_performance('serialization_performance'):
            # Create complex object graph
            user = UserFactory()
            roles = RoleFactory.create_batch(3)
            permissions = PermissionFactory.create_batch(10)
            
            # Assign relationships
            for role in roles:
                user.roles.append(role)
                for permission in permissions:
                    role.permissions.append(permission)
            
            self.db.add(user)
            self.db.commit()
            
            start_time = time.time()
            
            # Serialize to dictionary (simulating API response)
            user_dict = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'roles': [
                    {
                        'id': role.id,
                        'name': role.name,
                        'permissions': [
                            {
                                'id': perm.id,
                                'resource': perm.resource,
                                'action': perm.action
                            }
                            for perm in role.permissions
                        ]
                    }
                    for role in user.roles
                ]
            }
            
            serialization_time = time.time() - start_time
            
            # Serialization should be fast (under 0.01 seconds)
            assert serialization_time < 0.01, f"Serialization took {serialization_time:.3f}s, should be under 0.01s"
            
            # Validate serialized structure
            assert 'id' in user_dict, "User ID should be included"
            assert len(user_dict['roles']) == 3, "All roles should be serialized"
            assert len(user_dict['roles'][0]['permissions']) == 10, "All permissions should be serialized"


# Test fixtures and utility functions for pytest integration

@pytest.fixture
def performance_reporter():
    """Fixture for collecting and reporting performance metrics."""
    metrics = defaultdict(list)
    
    yield metrics
    
    # Report performance metrics at end of test session
    if metrics:
        print("\n=== Performance Metrics Report ===")
        for operation, measurements in metrics.items():
            if measurements:
                avg_time = sum(m['execution_time_ms'] for m in measurements) / len(measurements)
                max_time = max(m['execution_time_ms'] for m in measurements)
                print(f"{operation}: avg={avg_time:.2f}ms, max={max_time:.2f}ms, samples={len(measurements)}")


@pytest.mark.integration
class TestFullSystemIntegration(ModelTestBase):
    """
    Full system integration tests validating complete Flask-SQLAlchemy model
    ecosystem functionality and cross-model interactions ensuring comprehensive
    system integration and functional parity validation.
    """
    
    def test_complete_user_workflow_integration(self):
        """Test complete user workflow from registration to complex operations."""
        with self.measure_performance('complete_user_workflow'):
            # Step 1: User registration and profile setup
            user = UserFactory(
                is_active=True,
                email_verified=True
            )
            
            # Step 2: Role assignment
            roles = RoleFactory.create_batch(2, is_active=True)
            permissions = PermissionFactory.create_batch(5, is_active=True)
            
            for role in roles:
                user.roles.append(role)
                for permission in permissions:
                    role.permissions.append(permission)
            
            # Step 3: Session creation
            session = UserSessionFactory(user=user, is_active=True)
            
            # Step 4: Business entity creation
            entity = BusinessEntityFactory(owner=user)
            
            # Step 5: Audit log generation
            audit_log = AuditLogFactory(
                table_name='users',
                record_id=str(user.id),
                operation_type='INSERT',
                user=user
            )
            
            self.db.add_all([user, session, entity, audit_log])
            self.db.commit()
            
            # Validate complete workflow
            assert user.is_active, "User should be active"
            assert len(user.roles) == 2, "User should have roles"
            assert len(user.sessions) == 1, "User should have session"
            assert len(user.owned_entities) == 1, "User should own entity"
            
            # Validate cross-model relationships
            total_permissions = set()
            for role in user.roles:
                total_permissions.update(role.permissions)
            assert len(total_permissions) == 5, "User should have access to all permissions"
    
    def test_system_stress_and_scalability(self):
        """Test system performance under load with realistic data volumes."""
        with self.measure_performance('system_stress_test'):
            # Create realistic system load
            start_time = time.time()
            
            # Create 50 users with complete profiles
            users = []
            for i in range(50):
                user = FactoryDataManager.create_user_with_complete_profile(
                    role_count=2, session_count=1
                )
                users.append(user)
            
            # Create business entity hierarchies
            FactoryDataManager.create_business_hierarchy(levels=4, entities_per_level=3)
            
            # Create comprehensive audit trail
            FactoryDataManager.create_audit_trail(entity_count=50, operations_per_entity=3)
            
            total_time = time.time() - start_time
            
            # System should handle realistic load efficiently
            assert total_time < 5.0, f"System stress test took {total_time:.2f}s, should be under 5.0s"
            
            # Validate data integrity after bulk operations
            total_users = self.db.query(User).count()
            total_entities = self.db.query(BusinessEntity).count()
            total_audit_logs = self.db.query(AuditLog).count()
            
            assert total_users >= 50, "All users should be created"
            assert total_entities >= 12, "All entities should be created"  # 4 levels * 3 entities = 12
            assert total_audit_logs >= 150, "All audit logs should be created"  # 50 * 3 = 150


if __name__ == '__main__':
    # Run tests with performance reporting
    pytest.main([
        __file__,
        '-v',
        '--tb=short',
        '--durations=10',  # Show 10 slowest tests
        '-x'  # Stop on first failure
    ])