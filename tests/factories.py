"""
Factory Boy test data generation module providing SQLAlchemy model factories with realistic test data patterns and relationship management for comprehensive test coverage.

This module implements Django-style factory patterns for SQLAlchemy model instances, replacing Node.js test data arrangements with Python Factory Boy patterns per Section 4.7.3.2. It provides comprehensive factory definitions for realistic test data generation with relationship management and data consistency validation across test execution cycles.

Factories included:
- UserFactory: User authentication and profile data with Auth0 integration
- RoleFactory: Role-based access control roles
- PermissionFactory: Granular permission definitions
- BusinessEntityFactory: Core business objects
- EntityRelationshipFactory: Business entity relationships
- UserSessionFactory: Flask session management data
- AuditLogFactory: Comprehensive audit trail records
- SecurityEventFactory: Security monitoring events

Dependencies:
- factory_boy: Django-style factory patterns for SQLAlchemy models
- Faker: Realistic test data generation
- SQLAlchemy: Database model integration
"""

import factory
import factory.fuzzy
from faker import Faker
from datetime import datetime, timedelta
from sqlalchemy.orm import sessionmaker
from typing import Any, Dict, List, Optional
import uuid
import json
import random
import string

# Import SQLAlchemy models (will be available when models are created)
# These imports follow the model structure documented in the technical specification
from models.base import BaseModel, AuditMixin, EncryptedMixin
from models.user import User, UserSession
from models.rbac import Role, Permission
from models.business import BusinessEntity, EntityRelationship
from models.audit import AuditLog, SecurityEvent

# Initialize Faker instance for realistic data generation
fake = Faker()


class SQLAlchemyModelFactory(factory.alchemy.SQLAlchemyModelFactory):
    """
    Base factory class providing common functionality for all SQLAlchemy model factories.
    
    This base class implements the Factory Boy SQLAlchemy integration pattern and provides
    common utilities for test data generation, relationship management, and data consistency
    validation across all model factories.
    
    Features:
    - SQLAlchemy session management for test isolation
    - Common data generation utilities
    - Relationship handling patterns
    - Data consistency validation methods
    """
    
    class Meta:
        # SQLAlchemy session will be injected by test fixtures
        sqlalchemy_session_persistence = "commit"
        abstract = True
    
    @classmethod
    def _setup_next_sequence(cls):
        """Override to ensure proper sequence management for test data consistency."""
        return getattr(cls, '_next_sequence', 0) + 1


class UserFactory(SQLAlchemyModelFactory):
    """
    User model factory providing realistic test data for authentication and profile management.
    
    Generates comprehensive user test data including Auth0 integration fields, encrypted
    sensitive information, and proper relationship management for RBAC integration.
    Features realistic email addresses, usernames, and authentication metadata.
    
    Usage:
        user = UserFactory()
        admin_user = UserFactory(email='admin@test.com', is_active=True)
        user_with_roles = UserFactory(roles__size=2)
    """
    
    class Meta:
        model = User
    
    # Auth0 integration fields per Section 0 authentication migration requirements
    auth0_user_id = factory.LazyFunction(lambda: f"auth0|{uuid.uuid4().hex[:24]}")
    
    # Core user fields with realistic data patterns
    email = factory.LazyAttribute(lambda obj: fake.email())
    username = factory.LazyAttribute(lambda obj: fake.user_name())
    first_name = factory.LazyAttribute(lambda obj: fake.first_name())
    last_name = factory.LazyAttribute(lambda obj: fake.last_name())
    
    # Account status and verification
    is_active = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.1 else c[1])
    email_verified = factory.LazyAttribute(lambda obj: obj.is_active and random.random() > 0.2)
    phone_verified = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.3 else c[1])
    
    # Encrypted sensitive fields using SQLAlchemy-Utils EncryptedType
    phone_number = factory.LazyFunction(lambda: fake.phone_number() if random.random() > 0.3 else None)
    date_of_birth = factory.LazyFunction(lambda: fake.date_of_birth(minimum_age=18, maximum_age=80) if random.random() > 0.4 else None)
    
    # Profile metadata
    profile_picture_url = factory.LazyFunction(lambda: fake.image_url() if random.random() > 0.5 else None)
    bio = factory.LazyFunction(lambda: fake.text(max_nb_chars=200) if random.random() > 0.6 else None)
    timezone = factory.fuzzy.FuzzyChoice([
        'UTC', 'America/New_York', 'America/Los_Angeles', 'Europe/London', 
        'Europe/Paris', 'Asia/Tokyo', 'Australia/Sydney'
    ])
    locale = factory.fuzzy.FuzzyChoice(['en-US', 'en-GB', 'fr-FR', 'es-ES', 'de-DE', 'ja-JP'])
    
    # Authentication metadata
    last_login_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-30d', end_date='now'))
    last_login_ip = factory.LazyFunction(lambda: fake.ipv4())
    failed_login_attempts = factory.fuzzy.FuzzyInteger(0, 3)
    account_locked_until = None  # Default unlocked
    
    # Audit fields (handled by AuditMixin)
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-1y', end_date='now'))
    updated_at = factory.LazyAttribute(lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now'))
    
    @factory.post_generation
    def roles(self, create, extracted, **kwargs):
        """
        Handle role relationships for RBAC integration.
        
        Args:
            create: Whether to save the object
            extracted: Number of roles to create or specific role list
            **kwargs: Additional role parameters
        """
        if not create:
            return
        
        if extracted is not None:
            if isinstance(extracted, int):
                # Create specified number of roles
                roles = RoleFactory.create_batch(extracted, **kwargs)
                self.roles.extend(roles)
            elif isinstance(extracted, list):
                # Use provided roles
                self.roles.extend(extracted)
    
    @factory.post_generation
    def sessions(self, create, extracted, **kwargs):
        """
        Generate user sessions for Flask session management testing.
        
        Args:
            create: Whether to save the object
            extracted: Number of sessions to create
            **kwargs: Additional session parameters
        """
        if not create:
            return
        
        if extracted is not None:
            sessions = UserSessionFactory.create_batch(
                extracted, 
                user=self, 
                **kwargs
            )


class RoleFactory(SQLAlchemyModelFactory):
    """
    Role model factory for RBAC system testing.
    
    Generates realistic role data for testing role-based access control functionality,
    including predefined system roles and custom role patterns.
    
    Usage:
        admin_role = RoleFactory(name='admin')
        roles = RoleFactory.create_batch(3)
    """
    
    class Meta:
        model = Role
    
    name = factory.fuzzy.FuzzyChoice([
        'admin', 'moderator', 'user', 'viewer', 'editor',
        'manager', 'analyst', 'developer', 'support', 'guest'
    ])
    description = factory.LazyAttribute(lambda obj: f"Role for {obj.name} level access with appropriate permissions")
    is_active = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.05 else c[1])
    
    # Audit fields
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-1y', end_date='now'))
    updated_at = factory.LazyAttribute(lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now'))
    
    @factory.post_generation
    def permissions(self, create, extracted, **kwargs):
        """
        Handle permission relationships for comprehensive RBAC testing.
        
        Args:
            create: Whether to save the object
            extracted: Number of permissions to create or specific permission list
            **kwargs: Additional permission parameters
        """
        if not create:
            return
        
        if extracted is not None:
            if isinstance(extracted, int):
                permissions = PermissionFactory.create_batch(extracted, **kwargs)
                self.permissions.extend(permissions)
            elif isinstance(extracted, list):
                self.permissions.extend(extracted)


class PermissionFactory(SQLAlchemyModelFactory):
    """
    Permission model factory for granular access control testing.
    
    Generates realistic permission data following resource-action patterns for
    Flask endpoint protection and business operation authorization.
    
    Usage:
        read_permission = PermissionFactory(resource='users', action='read')
        permissions = PermissionFactory.create_batch(5)
    """
    
    class Meta:
        model = Permission
    
    resource = factory.fuzzy.FuzzyChoice([
        'users', 'roles', 'permissions', 'business_entities', 'audit_logs',
        'security_events', 'sessions', 'reports', 'settings', 'api'
    ])
    action = factory.fuzzy.FuzzyChoice([
        'create', 'read', 'update', 'delete', 'list', 'export', 'import', 'execute'
    ])
    description = factory.LazyAttribute(
        lambda obj: f"Permission to {obj.action} {obj.resource} resources"
    )
    is_active = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.05 else c[1])
    
    # Audit fields
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-1y', end_date='now'))
    updated_at = factory.LazyAttribute(lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now'))


class BusinessEntityFactory(SQLAlchemyModelFactory):
    """
    Business entity factory for core business object testing.
    
    Generates realistic business entity data for testing business logic operations,
    entity management, and relationship tracking throughout the application.
    
    Usage:
        entity = BusinessEntityFactory()
        company = BusinessEntityFactory(entity_type='company')
        entities_with_owner = BusinessEntityFactory.create_batch(3, owner=user)
    """
    
    class Meta:
        model = BusinessEntity
    
    name = factory.LazyAttribute(lambda obj: fake.company())
    description = factory.LazyAttribute(lambda obj: fake.text(max_nb_chars=500))
    entity_type = factory.fuzzy.FuzzyChoice([
        'company', 'department', 'project', 'team', 'product', 
        'service', 'location', 'asset', 'contract', 'vendor'
    ])
    
    # Status management
    status = factory.fuzzy.FuzzyChoice(['active', 'inactive', 'pending', 'archived'])
    
    # Business metadata
    external_id = factory.LazyFunction(lambda: f"EXT-{uuid.uuid4().hex[:12].upper()}")
    tags = factory.LazyFunction(lambda: json.dumps(fake.words(nb=random.randint(1, 5))))
    metadata = factory.LazyFunction(lambda: json.dumps({
        'industry': fake.company_suffix(),
        'size': random.choice(['small', 'medium', 'large', 'enterprise']),
        'location': fake.city(),
        'founded': fake.year()
    }))
    
    # Ownership relationship
    owner = factory.SubFactory(UserFactory)
    
    # Audit fields
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-2y', end_date='now'))
    updated_at = factory.LazyAttribute(lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now'))


class EntityRelationshipFactory(SQLAlchemyModelFactory):
    """
    Entity relationship factory for testing business entity interconnections.
    
    Generates realistic relationship data for testing complex business object
    relationships, hierarchy management, and entity navigation patterns.
    
    Usage:
        rel = EntityRelationshipFactory()
        parent_child = EntityRelationshipFactory(relationship_type='parent_child')
    """
    
    class Meta:
        model = EntityRelationship
    
    source_entity = factory.SubFactory(BusinessEntityFactory)
    target_entity = factory.SubFactory(BusinessEntityFactory)
    
    relationship_type = factory.fuzzy.FuzzyChoice([
        'parent_child', 'owns', 'manages', 'depends_on', 'collaborates_with',
        'reports_to', 'provides_service_to', 'is_part_of', 'contracts_with'
    ])
    
    description = factory.LazyAttribute(
        lambda obj: f"{obj.source_entity.name} {obj.relationship_type.replace('_', ' ')} {obj.target_entity.name}"
    )
    
    is_active = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.1 else c[1])
    
    # Relationship metadata
    strength = factory.fuzzy.FuzzyInteger(1, 10)  # Relationship strength score
    start_date = factory.LazyFunction(lambda: fake.date_between(start_date='-2y', end_date='now'))
    end_date = factory.LazyFunction(lambda: fake.date_between(start_date='now', end_date='+1y') if random.random() > 0.7 else None)
    
    # Audit fields
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-2y', end_date='now'))
    updated_at = factory.LazyAttribute(lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now'))


class UserSessionFactory(SQLAlchemyModelFactory):
    """
    User session factory for Flask session management testing.
    
    Generates realistic session data for testing Flask session handling, security
    token management, and user authentication flows.
    
    Usage:
        session = UserSessionFactory()
        active_session = UserSessionFactory(is_active=True)
    """
    
    class Meta:
        model = UserSession
    
    user = factory.SubFactory(UserFactory)
    session_token = factory.LazyFunction(lambda: uuid.uuid4().hex)
    csrf_token = factory.LazyFunction(lambda: uuid.uuid4().hex)
    
    # Session metadata
    ip_address = factory.LazyFunction(lambda: fake.ipv4())
    user_agent = factory.LazyFunction(lambda: fake.user_agent())
    device_fingerprint = factory.LazyFunction(lambda: uuid.uuid4().hex[:16])
    
    # Session status
    is_active = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.2 else c[1])
    
    # Session timing
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-30d', end_date='now'))
    last_activity_at = factory.LazyAttribute(lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now'))
    expires_at = factory.LazyAttribute(lambda obj: obj.created_at + timedelta(hours=24))
    
    # Location data
    location_data = factory.LazyFunction(lambda: json.dumps({
        'country': fake.country(),
        'city': fake.city(),
        'timezone': fake.timezone()
    }) if random.random() > 0.3 else None)


class AuditLogFactory(SQLAlchemyModelFactory):
    """
    Audit log factory for comprehensive audit trail testing.
    
    Generates realistic audit log data for testing DML operation tracking,
    change data management, and compliance audit trails.
    
    Usage:
        log = AuditLogFactory()
        insert_log = AuditLogFactory(operation_type='INSERT')
        user_logs = AuditLogFactory.create_batch(10, user=user)
    """
    
    class Meta:
        model = AuditLog
    
    # Operation tracking
    table_name = factory.fuzzy.FuzzyChoice([
        'users', 'roles', 'permissions', 'business_entities', 
        'entity_relationships', 'user_sessions'
    ])
    record_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    operation_type = factory.fuzzy.FuzzyChoice(['INSERT', 'UPDATE', 'DELETE'])
    
    # User context
    user = factory.SubFactory(UserFactory)
    user_ip = factory.LazyFunction(lambda: fake.ipv4())
    user_agent = factory.LazyFunction(lambda: fake.user_agent())
    
    # Change data
    old_values = factory.LazyFunction(lambda: json.dumps({
        'name': fake.name(),
        'email': fake.email(),
        'status': random.choice(['active', 'inactive'])
    }) if random.random() > 0.3 else None)
    
    new_values = factory.LazyFunction(lambda: json.dumps({
        'name': fake.name(),
        'email': fake.email(),
        'status': random.choice(['active', 'inactive'])
    }))
    
    changed_fields = factory.LazyFunction(lambda: json.dumps([
        'name', 'email', 'updated_at'
    ]))
    
    # Audit metadata
    transaction_id = factory.LazyFunction(lambda: uuid.uuid4().hex)
    session_id = factory.LazyFunction(lambda: uuid.uuid4().hex)
    
    # Timing
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-1y', end_date='now'))


class SecurityEventFactory(SQLAlchemyModelFactory):
    """
    Security event factory for security monitoring and incident testing.
    
    Generates realistic security event data for testing threat detection,
    incident response, and security monitoring capabilities.
    
    Usage:
        event = SecurityEventFactory()
        failed_login = SecurityEventFactory(event_type='authentication_failure')
        critical_events = SecurityEventFactory.create_batch(5, severity='critical')
    """
    
    class Meta:
        model = SecurityEvent
    
    # Event classification
    event_type = factory.fuzzy.FuzzyChoice([
        'authentication_failure', 'authorization_violation', 'suspicious_activity',
        'account_locked', 'password_changed', 'permission_escalation',
        'data_access_violation', 'session_hijack_attempt', 'brute_force_attack'
    ])
    
    severity = factory.fuzzy.FuzzyChoice(['low', 'medium', 'high', 'critical'])
    
    # Event details
    description = factory.LazyAttribute(
        lambda obj: f"{obj.event_type.replace('_', ' ').title()} detected with {obj.severity} severity"
    )
    
    # Context data
    user = factory.SubFactory(UserFactory)
    ip_address = factory.LazyFunction(lambda: fake.ipv4())
    user_agent = factory.LazyFunction(lambda: fake.user_agent())
    
    # Event metadata
    event_data = factory.LazyFunction(lambda: json.dumps({
        'request_path': fake.uri_path(),
        'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
        'response_code': random.choice([200, 401, 403, 404, 500]),
        'attempt_count': random.randint(1, 10)
    }))
    
    # Risk assessment
    risk_score = factory.fuzzy.FuzzyInteger(1, 100)
    is_resolved = factory.fuzzy.FuzzyChoice([True, False], getter=lambda c: c[0] if random.random() > 0.4 else c[1])
    resolved_by = factory.SubFactory(UserFactory)
    resolved_at = factory.LazyAttribute(
        lambda obj: fake.date_time_between(start_date=obj.created_at, end_date='now') 
        if obj.is_resolved else None
    )
    
    # Detection metadata
    detection_rule = factory.LazyFunction(lambda: f"RULE_{random.randint(1000, 9999)}")
    source_system = factory.fuzzy.FuzzyChoice(['webapp', 'api', 'auth_service', 'database'])
    
    # Timing
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-90d', end_date='now'))


# Factory helper utilities for test data management and relationship handling

class FactoryDataManager:
    """
    Utility class for managing Factory Boy test data generation with relationship consistency.
    
    Provides methods for creating related object hierarchies, managing test data cleanup,
    and ensuring data consistency across test execution cycles per Section 4.7.3.2.
    """
    
    @staticmethod
    def create_user_with_complete_profile(role_count: int = 2, session_count: int = 1) -> User:
        """
        Create a user with complete profile including roles and sessions.
        
        Args:
            role_count: Number of roles to assign
            session_count: Number of active sessions to create
            
        Returns:
            User: Fully configured user instance for comprehensive testing
        """
        user = UserFactory(
            is_active=True,
            email_verified=True,
            roles__size=role_count
        )
        
        # Create user sessions
        UserSessionFactory.create_batch(session_count, user=user, is_active=True)
        
        return user
    
    @staticmethod
    def create_business_hierarchy(levels: int = 3, entities_per_level: int = 2) -> List[BusinessEntity]:
        """
        Create a hierarchical business entity structure for relationship testing.
        
        Args:
            levels: Number of hierarchy levels
            entities_per_level: Number of entities per level
            
        Returns:
            List[BusinessEntity]: Root level entities with complete hierarchy
        """
        entities = []
        previous_level = []
        
        for level in range(levels):
            current_level = BusinessEntityFactory.create_batch(entities_per_level)
            entities.extend(current_level)
            
            # Create parent-child relationships
            if previous_level:
                for parent in previous_level:
                    for child in current_level:
                        EntityRelationshipFactory(
                            source_entity=parent,
                            target_entity=child,
                            relationship_type='parent_child',
                            is_active=True
                        )
            
            previous_level = current_level
        
        return entities
    
    @staticmethod
    def create_rbac_system(user_count: int = 5, role_count: int = 3, permission_count: int = 10) -> Dict[str, List]:
        """
        Create a complete RBAC system with users, roles, and permissions.
        
        Args:
            user_count: Number of users to create
            role_count: Number of roles to create
            permission_count: Number of permissions to create
            
        Returns:
            Dict: Complete RBAC system components
        """
        # Create permissions
        permissions = PermissionFactory.create_batch(permission_count)
        
        # Create roles with permissions
        roles = []
        for i in range(role_count):
            role = RoleFactory()
            # Assign 3-7 random permissions to each role
            role_permissions = random.sample(permissions, random.randint(3, min(7, len(permissions))))
            role.permissions.extend(role_permissions)
            roles.append(role)
        
        # Create users with roles
        users = []
        for i in range(user_count):
            user = UserFactory()
            # Assign 1-3 random roles to each user
            user_roles = random.sample(roles, random.randint(1, min(3, len(roles))))
            user.roles.extend(user_roles)
            users.append(user)
        
        return {
            'users': users,
            'roles': roles,
            'permissions': permissions
        }
    
    @staticmethod
    def create_audit_trail(entity_count: int = 10, operations_per_entity: int = 5) -> List[AuditLog]:
        """
        Create comprehensive audit trail for testing audit log functionality.
        
        Args:
            entity_count: Number of entities to audit
            operations_per_entity: Number of operations per entity
            
        Returns:
            List[AuditLog]: Complete audit trail for testing
        """
        users = UserFactory.create_batch(3)  # Audit actors
        audit_logs = []
        
        for i in range(entity_count):
            record_id = str(uuid.uuid4())
            table_name = random.choice(['users', 'business_entities', 'roles'])
            
            for j in range(operations_per_entity):
                operation = random.choice(['INSERT', 'UPDATE', 'DELETE'])
                user = random.choice(users)
                
                audit_log = AuditLogFactory(
                    table_name=table_name,
                    record_id=record_id,
                    operation_type=operation,
                    user=user
                )
                audit_logs.append(audit_log)
        
        return audit_logs
    
    @staticmethod
    def cleanup_test_data(session):
        """
        Clean up test data for consistent test execution cycles.
        
        Args:
            session: SQLAlchemy session for cleanup operations
        """
        # Clean up in reverse dependency order
        cleanup_models = [
            SecurityEvent, AuditLog, UserSession, EntityRelationship,
            BusinessEntity, Permission, Role, User
        ]
        
        for model in cleanup_models:
            try:
                session.query(model).delete()
                session.commit()
            except Exception:
                session.rollback()
                raise


# Factory registration for easy access and test fixture integration
FACTORIES = {
    'user': UserFactory,
    'role': RoleFactory,
    'permission': PermissionFactory,
    'business_entity': BusinessEntityFactory,
    'entity_relationship': EntityRelationshipFactory,
    'user_session': UserSessionFactory,
    'audit_log': AuditLogFactory,
    'security_event': SecurityEventFactory
}


def get_factory(model_name: str):
    """
    Get factory class by model name for dynamic test data generation.
    
    Args:
        model_name: Name of the model to get factory for
        
    Returns:
        Factory class for the specified model
        
    Raises:
        KeyError: If model factory is not found
    """
    if model_name not in FACTORIES:
        raise KeyError(f"Factory for model '{model_name}' not found. Available: {list(FACTORIES.keys())}")
    
    return FACTORIES[model_name]