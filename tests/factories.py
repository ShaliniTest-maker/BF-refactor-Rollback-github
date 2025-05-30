"""
Factory Boy Test Data Generation Module

This module provides comprehensive SQLAlchemy model factories using Factory Boy for
realistic test data generation with proper relationship management and data consistency
validation. Replaces Node.js test data patterns with Python Factory Boy patterns 
following Django-style factory patterns for SQLAlchemy model instances.

The factory system supports:
- Realistic test data patterns with localization support
- Complex relationship management across all models
- Data consistency validation across test execution cycles
- Performance-optimized factory configurations for test speed
- Extensible factory inheritance for specialized test scenarios

Features:
- Factory Boy 3.3.0+ integration with SQLAlchemy session management
- Comprehensive factories for all entity models (User, Role, Business, Audit)
- Realistic data generation using Faker library integration
- Relationship factories with proper foreign key management
- Sequence-based unique field generation for conflict prevention
- Trait-based factory variations for different test scenarios
- Performance optimizations for large test data set generation

Dependencies:
- factory-boy: Django-style factory patterns for SQLAlchemy
- faker: Realistic fake data generation with localization
- sqlalchemy: Database session management and model integration
- flask-sqlalchemy: Flask-specific SQLAlchemy configuration
"""

import os
import secrets
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union

import factory
from factory import fuzzy
from factory.alchemy import SQLAlchemyModelFactory
from faker import Faker
from faker.providers import internet, person, company, phone_number, address, date_time

# Import models - use dest_file paths since we're in the destination repository
from models.base import db, BaseModel, AuditMixin, EncryptedMixin
from models.user import User, UserSession, UserUtils
from models.rbac import Role, Permission, UserRole, RolePermission
from models.business import BusinessEntity, EntityRelationship
from models.audit import AuditLog, SecurityEvent

# Initialize Faker instance with localization support
fake = Faker(['en_US', 'en_GB', 'es_ES', 'fr_FR', 'de_DE'])

# Add additional providers for comprehensive test data
fake.add_provider(internet)
fake.add_provider(person)
fake.add_provider(company)
fake.add_provider(phone_number)
fake.add_provider(address)
fake.add_provider(date_time)


class FactorySessionManager:
    """
    SQLAlchemy session management for Factory Boy integration.
    
    Provides thread-safe database session handling with proper transaction
    boundaries and rollback capabilities for isolated test execution.
    
    Features:
    - Automatic session cleanup between test runs
    - Transaction isolation for test data integrity
    - Performance optimizations for bulk factory operations
    - Database state validation and consistency checks
    """
    
    @staticmethod
    def get_session():
        """
        Get SQLAlchemy session for factory operations.
        
        Returns:
            SQLAlchemy session instance
        """
        return db.session
    
    @staticmethod
    def commit_session():
        """
        Safely commit current session with error handling.
        
        Returns:
            Boolean indicating commit success
        """
        try:
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            raise e
    
    @staticmethod
    def rollback_session():
        """
        Safely rollback current session.
        
        Returns:
            Boolean indicating rollback success
        """
        try:
            db.session.rollback()
            return True
        except Exception:
            return False
    
    @staticmethod
    def cleanup_session():
        """
        Clean up session state for fresh test execution.
        """
        try:
            db.session.expunge_all()
            db.session.rollback()
        except Exception:
            pass


class BaseModelFactory(SQLAlchemyModelFactory):
    """
    Abstract base factory for all SQLAlchemy model factories.
    
    Provides common configuration, session management, and audit field
    population for consistent factory behavior across all models.
    
    Features:
    - Automatic SQLAlchemy session management
    - Common audit field population with realistic data
    - Extensible trait system for factory variations
    - Performance optimization configuration
    """
    
    class Meta:
        abstract = True
        sqlalchemy_session = None  # Will be set during factory setup
        sqlalchemy_session_persistence = 'commit'
    
    # Common audit fields for all models inheriting from AuditMixin
    created_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-30d', end_date='now'))
    updated_at = factory.LazyAttribute(lambda obj: obj.created_at + timedelta(
        seconds=fake.random_int(min=0, max=86400)  # Up to 24 hours after creation
    ))
    created_by = factory.LazyFunction(lambda: fake.random_element(elements=('system', 'admin', 'test_user', 'migration')))
    updated_by = factory.LazyAttribute(lambda obj: fake.random_element(elements=(obj.created_by, 'admin', 'system')))
    
    @classmethod
    def _setup_session(cls):
        """Set up SQLAlchemy session for factory operations."""
        if cls._meta.sqlalchemy_session is None:
            cls._meta.sqlalchemy_session = FactorySessionManager.get_session()
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """
        Create model instance with proper session management.
        
        Args:
            model_class: SQLAlchemy model class
            *args: Positional arguments for model creation
            **kwargs: Keyword arguments for model creation
            
        Returns:
            Created model instance
        """
        cls._setup_session()
        instance = super()._create(model_class, *args, **kwargs)
        # Flush to assign ID but don't commit yet
        cls._meta.sqlalchemy_session.flush()
        return instance
    
    @classmethod
    def create_batch(cls, size, **kwargs):
        """
        Create multiple instances with optimized batch processing.
        
        Args:
            size: Number of instances to create
            **kwargs: Keyword arguments for all instances
            
        Returns:
            List of created instances
        """
        cls._setup_session()
        instances = super().create_batch(size, **kwargs)
        # Bulk flush for performance
        cls._meta.sqlalchemy_session.flush()
        return instances


class UserFactory(BaseModelFactory):
    """
    Factory for User model instances with comprehensive authentication data.
    
    Generates realistic user profiles with proper authentication setup,
    encrypted sensitive data, and relationship configurations for testing
    user management workflows.
    
    Features:
    - Realistic username and email generation with uniqueness
    - Secure password hashing using Werkzeug
    - Auth0 integration fields with realistic external IDs
    - Encrypted sensitive data using proper encryption configuration
    - Configurable user status and verification states
    - Role assignment through relationship factories
    """
    
    class Meta:
        model = User
        sqlalchemy_session_persistence = 'commit'
    
    # Core identification fields with uniqueness constraints
    username = factory.LazyFunction(lambda: fake.unique.user_name()[:100])
    email = factory.LazyFunction(lambda: fake.unique.email())
    
    # Authentication fields
    password_hash = factory.LazyFunction(lambda: UserUtils.create_user(
        username='temp', email='temp@example.com', password=fake.password(length=12)
    ).password_hash)
    
    # Auth0 integration fields
    auth0_user_id = factory.LazyFunction(lambda: f"auth0|{secrets.token_hex(12)}")
    
    # Encrypted personal information
    first_name = factory.LazyFunction(lambda: fake.first_name())
    last_name = factory.LazyFunction(lambda: fake.last_name())
    
    # User status fields
    is_active = True
    is_verified = factory.LazyFunction(lambda: fake.boolean(chance_of_getting_true=75))
    is_admin = factory.LazyFunction(lambda: fake.boolean(chance_of_getting_true=10))
    
    # Profile and preferences
    timezone = factory.LazyFunction(lambda: fake.random_element(elements=(
        'UTC', 'America/New_York', 'America/Los_Angeles', 'Europe/London',
        'Europe/Paris', 'Asia/Tokyo', 'Australia/Sydney'
    )))
    locale = factory.LazyFunction(lambda: fake.random_element(elements=(
        'en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ko', 'zh'
    )))
    avatar_url = factory.LazyFunction(lambda: fake.image_url(width=200, height=200))
    
    # Authentication tracking
    last_login_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-7d', end_date='now'))
    login_count = factory.LazyFunction(lambda: fake.random_int(min=1, max=500))
    failed_login_count = 0
    locked_until = None
    
    # Terms and privacy acceptance
    terms_accepted_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-365d', end_date='-1d'))
    privacy_accepted_at = factory.LazyAttribute(lambda obj: obj.terms_accepted_at)
    
    # Auth0 metadata (JSON strings)
    auth0_metadata = factory.LazyFunction(lambda: json.dumps({
        'preferences': {
            'newsletter': fake.boolean(),
            'notifications': fake.boolean()
        },
        'profile_completion': fake.random_int(min=25, max=100)
    }))
    
    auth0_app_metadata = factory.LazyFunction(lambda: json.dumps({
        'app_version': fake.random_element(elements=('1.0.0', '1.1.0', '1.2.0')),
        'signup_source': fake.random_element(elements=('web', 'mobile', 'api')),
        'customer_tier': fake.random_element(elements=('free', 'premium', 'enterprise'))
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        admin_user = factory.Trait(
            is_admin=True,
            is_verified=True,
            login_count=factory.LazyFunction(lambda: fake.random_int(min=100, max=1000))
        )
        
        unverified_user = factory.Trait(
            is_verified=False,
            terms_accepted_at=None,
            privacy_accepted_at=None
        )
        
        locked_user = factory.Trait(
            failed_login_count=5,
            locked_until=factory.LazyFunction(lambda: datetime.utcnow() + timedelta(minutes=30))
        )
        
        auth0_user = factory.Trait(
            password_hash=None,  # Auth0 users don't have local passwords
            auth0_user_id=factory.LazyFunction(lambda: f"auth0|{secrets.token_hex(16)}")
        )
        
        new_user = factory.Trait(
            login_count=0,
            last_login_at=None,
            created_at=factory.LazyFunction(lambda: datetime.utcnow() - timedelta(hours=1))
        )


class RoleFactory(BaseModelFactory):
    """
    Factory for Role model instances with comprehensive authorization data.
    
    Generates realistic role definitions with proper naming conventions,
    permission relationships, and hierarchical structures for testing
    role-based access control (RBAC) workflows.
    
    Features:
    - Realistic role naming with organizational conventions
    - Role hierarchy support with parent-child relationships
    - Permission assignment through association factories
    - Configurable role status and activation states
    - Department and organizational unit alignment
    """
    
    class Meta:
        model = Role
        sqlalchemy_session_persistence = 'commit'
    
    # Core role identification
    name = factory.LazyFunction(lambda: fake.random_element(elements=(
        'admin', 'user', 'manager', 'analyst', 'operator', 'viewer',
        'developer', 'tester', 'support', 'hr_manager', 'finance_admin',
        'marketing_user', 'sales_rep', 'content_editor', 'data_analyst'
    )))
    
    display_name = factory.LazyAttribute(lambda obj: obj.name.replace('_', ' ').title())
    
    description = factory.LazyFunction(lambda: fake.text(max_nb_chars=200))
    
    # Role status and hierarchy
    is_active = True
    is_system_role = factory.LazyFunction(lambda: fake.boolean(chance_of_getting_true=20))
    role_level = factory.LazyFunction(lambda: fake.random_int(min=1, max=5))
    
    # Organizational alignment
    department = factory.LazyFunction(lambda: fake.random_element(elements=(
        'IT', 'HR', 'Finance', 'Marketing', 'Sales', 'Operations',
        'Legal', 'Engineering', 'Product', 'Customer Success'
    )))
    
    # Role metadata
    max_users = factory.LazyFunction(lambda: fake.random_element(elements=(
        None, 5, 10, 25, 50, 100, 500  # None means unlimited
    )))
    
    role_metadata = factory.LazyFunction(lambda: json.dumps({
        'created_by_system': fake.boolean(),
        'auto_assign': fake.boolean(chance_of_getting_true=10),
        'requires_approval': fake.boolean(chance_of_getting_true=30)
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        system_role = factory.Trait(
            is_system_role=True,
            name=factory.LazyFunction(lambda: fake.random_element(elements=(
                'system_admin', 'super_user', 'api_user', 'service_account'
            )))
        )
        
        department_role = factory.Trait(
            name=factory.LazyAttribute(lambda obj: f"{obj.department.lower()}_user"),
            display_name=factory.LazyAttribute(lambda obj: f"{obj.department} User")
        )
        
        admin_role = factory.Trait(
            name='admin',
            display_name='Administrator',
            description='Full system administration access',
            role_level=5,
            max_users=5
        )
        
        viewer_role = factory.Trait(
            name='viewer',
            display_name='Viewer',
            description='Read-only access to system resources',
            role_level=1,
            max_users=None
        )


class PermissionFactory(BaseModelFactory):
    """
    Factory for Permission model instances with resource-action patterns.
    
    Generates realistic permission definitions following RESTful patterns
    and Flask blueprint route protection for comprehensive authorization
    testing scenarios.
    
    Features:
    - Resource-action permission patterns (resource.action)
    - Flask blueprint and route alignment
    - RESTful operation coverage (CRUD operations)
    - System and business permission classifications
    - Permission hierarchy and dependency management
    """
    
    class Meta:
        model = Permission
        sqlalchemy_session_persistence = 'commit'
    
    # Resource-action pattern implementation
    resource = factory.LazyFunction(lambda: fake.random_element(elements=(
        'users', 'roles', 'permissions', 'business_entities', 'audit_logs',
        'sessions', 'reports', 'settings', 'notifications', 'files',
        'api', 'admin', 'dashboard', 'profile', 'billing'
    )))
    
    action = factory.LazyFunction(lambda: fake.random_element(elements=(
        'read', 'create', 'update', 'delete', 'list', 'view',
        'manage', 'admin', 'export', 'import', 'approve', 'publish'
    )))
    
    # Computed permission name using resource.action pattern
    name = factory.LazyAttribute(lambda obj: f"{obj.resource}.{obj.action}")
    
    display_name = factory.LazyAttribute(lambda obj: f"{obj.action.title()} {obj.resource.title()}")
    
    description = factory.LazyFunction(lambda: fake.sentence(nb_words=8))
    
    # Permission classification
    is_active = True
    is_system_permission = factory.LazyFunction(lambda: fake.boolean(chance_of_getting_true=25))
    permission_level = factory.LazyFunction(lambda: fake.random_int(min=1, max=5))
    
    # Flask integration fields
    blueprint_name = factory.LazyAttribute(lambda obj: obj.resource)
    endpoint_pattern = factory.LazyAttribute(lambda obj: f"/{obj.resource}")
    http_methods = factory.LazyFunction(lambda: json.dumps(
        fake.random_elements(elements=('GET', 'POST', 'PUT', 'PATCH', 'DELETE'), 
                           length=fake.random_int(min=1, max=3), unique=True)
    ))
    
    # Permission metadata
    permission_metadata = factory.LazyFunction(lambda: json.dumps({
        'requires_mfa': fake.boolean(chance_of_getting_true=20),
        'audit_level': fake.random_element(elements=('low', 'medium', 'high')),
        'business_impact': fake.random_element(elements=('low', 'medium', 'high', 'critical'))
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        crud_permission = factory.Trait(
            action=factory.LazyFunction(lambda: fake.random_element(elements=(
                'create', 'read', 'update', 'delete'
            )))
        )
        
        admin_permission = factory.Trait(
            action='admin',
            permission_level=5,
            is_system_permission=True,
            permission_metadata=factory.LazyFunction(lambda: json.dumps({
                'requires_mfa': True,
                'audit_level': 'high',
                'business_impact': 'critical'
            }))
        )
        
        read_permission = factory.Trait(
            action='read',
            permission_level=1,
            http_methods=factory.LazyFunction(lambda: json.dumps(['GET']))
        )
        
        write_permission = factory.Trait(
            action=factory.LazyFunction(lambda: fake.random_element(elements=(
                'create', 'update', 'delete'
            ))),
            permission_level=3,
            http_methods=factory.LazyFunction(lambda: json.dumps(['POST', 'PUT', 'PATCH', 'DELETE']))
        )


class UserRoleFactory(BaseModelFactory):
    """
    Factory for UserRole association instances with audit trail.
    
    Generates realistic user-role assignments with proper audit tracking,
    assignment context, and status management for testing RBAC workflows
    and permission inheritance scenarios.
    
    Features:
    - Realistic user-role assignment patterns
    - Comprehensive audit trail with assignment context
    - Status management for active/inactive assignments
    - Assignment metadata for approval workflows
    - Bulk assignment support for organizational testing
    """
    
    class Meta:
        model = UserRole
        sqlalchemy_session_persistence = 'commit'
    
    # Foreign key relationships - will be set by SubFactory or manual assignment
    user = factory.SubFactory(UserFactory)
    role = factory.SubFactory(RoleFactory)
    
    # Assignment audit fields
    assigned_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-90d', end_date='now'))
    assigned_by = factory.LazyFunction(lambda: fake.random_element(elements=(
        'system', 'admin', 'hr_manager', 'department_head', 'auto_assignment'
    )))
    
    # Assignment status
    is_active = True
    expires_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='now', end_date='+365d')
                                     if fake.boolean(chance_of_getting_true=30) else None)
    
    # Assignment context
    assignment_reason = factory.LazyFunction(lambda: fake.random_element(elements=(
        'new_hire', 'promotion', 'transfer', 'project_assignment',
        'temporary_access', 'role_change', 'system_migration'
    )))
    
    assignment_metadata = factory.LazyFunction(lambda: json.dumps({
        'approved_by': fake.name(),
        'approval_date': fake.date_time_this_year().isoformat(),
        'assignment_type': fake.random_element(elements=('permanent', 'temporary', 'conditional')),
        'notification_sent': fake.boolean()
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        expired_assignment = factory.Trait(
            is_active=False,
            expires_at=factory.LazyFunction(lambda: fake.date_time_between(start_date='-30d', end_date='-1d'))
        )
        
        temporary_assignment = factory.Trait(
            expires_at=factory.LazyFunction(lambda: fake.date_time_between(start_date='now', end_date='+30d')),
            assignment_reason='temporary_access'
        )
        
        system_assignment = factory.Trait(
            assigned_by='system',
            assignment_reason='system_migration',
            assignment_metadata=factory.LazyFunction(lambda: json.dumps({
                'auto_assigned': True,
                'migration_batch': fake.uuid4(),
                'system_role': True
            }))
        )


class RolePermissionFactory(BaseModelFactory):
    """
    Factory for RolePermission association instances with grant tracking.
    
    Generates realistic role-permission grants with comprehensive audit
    trails, grant context, and permission inheritance patterns for testing
    authorization workflows and access control scenarios.
    
    Features:
    - Realistic role-permission grant patterns
    - Comprehensive grant audit trail with context
    - Permission inheritance and hierarchy testing
    - Grant metadata for approval and compliance workflows
    - Bulk grant support for role template testing
    """
    
    class Meta:
        model = RolePermission
        sqlalchemy_session_persistence = 'commit'
    
    # Foreign key relationships
    role = factory.SubFactory(RoleFactory)
    permission = factory.SubFactory(PermissionFactory)
    
    # Grant audit fields
    granted_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-180d', end_date='now'))
    granted_by = factory.LazyFunction(lambda: fake.random_element(elements=(
        'system', 'security_admin', 'role_admin', 'department_head', 'auto_grant'
    )))
    
    # Grant status
    is_active = True
    
    # Grant context
    grant_reason = factory.LazyFunction(lambda: fake.random_element(elements=(
        'role_creation', 'permission_update', 'security_review',
        'compliance_requirement', 'business_need', 'system_migration'
    )))
    
    grant_metadata = factory.LazyFunction(lambda: json.dumps({
        'approved_by': fake.name(),
        'approval_date': fake.date_time_this_year().isoformat(),
        'compliance_check': fake.boolean(),
        'business_justification': fake.sentence(),
        'review_required': fake.boolean(chance_of_getting_true=25)
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        system_grant = factory.Trait(
            granted_by='system',
            grant_reason='system_migration',
            grant_metadata=factory.LazyFunction(lambda: json.dumps({
                'auto_granted': True,
                'migration_batch': fake.uuid4(),
                'system_permission': True
            }))
        )
        
        compliance_grant = factory.Trait(
            grant_reason='compliance_requirement',
            grant_metadata=factory.LazyFunction(lambda: json.dumps({
                'compliance_framework': fake.random_element(elements=('SOX', 'GDPR', 'HIPAA', 'PCI')),
                'review_required': True,
                'review_frequency': fake.random_element(elements=('quarterly', 'annually'))
            }))
        )


class UserSessionFactory(BaseModelFactory):
    """
    Factory for UserSession instances with realistic session data.
    
    Generates authentic session instances with proper token management,
    security tracking, and session lifecycle data for testing authentication
    and session management workflows.
    
    Features:
    - Secure session token generation with proper entropy
    - Realistic session lifecycle and expiration patterns
    - Comprehensive security tracking (IP, User-Agent, etc.)
    - Session data storage for application state testing
    - Multiple authentication method support
    """
    
    class Meta:
        model = UserSession
        sqlalchemy_session_persistence = 'commit'
    
    # User relationship
    user = factory.SubFactory(UserFactory)
    
    # Session tokens with proper security
    session_token = factory.LazyFunction(lambda: secrets.token_urlsafe(32))
    csrf_token = factory.LazyFunction(lambda: secrets.token_urlsafe(24))
    refresh_token = factory.LazyFunction(lambda: secrets.token_urlsafe(32))
    
    # Session lifecycle
    expires_at = factory.LazyFunction(lambda: datetime.utcnow() + timedelta(
        seconds=fake.random_int(min=3600, max=86400)  # 1-24 hours
    ))
    is_valid = True
    revoked_at = None
    revoked_by = None
    
    # Security tracking
    ip_address = factory.LazyFunction(lambda: fake.ipv4())
    user_agent = factory.LazyFunction(lambda: fake.user_agent())
    last_activity_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-1h', end_date='now'))
    
    # Session metadata
    login_method = factory.LazyFunction(lambda: fake.random_element(elements=(
        'password', 'auth0', 'social', 'api'
    )))
    
    session_data = factory.LazyFunction(lambda: json.dumps({
        'preferences': {
            'theme': fake.random_element(elements=('light', 'dark', 'auto')),
            'language': fake.random_element(elements=('en', 'es', 'fr', 'de')),
            'timezone': fake.timezone()
        },
        'navigation': {
            'last_page': fake.uri_path(),
            'breadcrumbs': [fake.uri_path() for _ in range(fake.random_int(min=1, max=5))]
        },
        'feature_flags': {
            flag: fake.boolean() for flag in ['beta_features', 'advanced_ui', 'analytics']
        }
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        expired_session = factory.Trait(
            expires_at=factory.LazyFunction(lambda: fake.date_time_between(start_date='-7d', end_date='-1h')),
            is_valid=False
        )
        
        revoked_session = factory.Trait(
            is_valid=False,
            revoked_at=factory.LazyFunction(lambda: fake.date_time_between(start_date='-24h', end_date='now')),
            revoked_by=factory.LazyFunction(lambda: fake.random_element(elements=('user', 'admin', 'system')))
        )
        
        auth0_session = factory.Trait(
            login_method='auth0',
            session_data=factory.LazyFunction(lambda: json.dumps({
                'auth0_session_id': fake.uuid4(),
                'auth0_access_token': secrets.token_urlsafe(32),
                'auth0_id_token': secrets.token_urlsafe(48),
                'auth0_user_info': {
                    'sub': f"auth0|{secrets.token_hex(12)}",
                    'nickname': fake.user_name(),
                    'email': fake.email(),
                    'email_verified': fake.boolean()
                }
            }))
        )
        
        long_session = factory.Trait(
            expires_at=factory.LazyFunction(lambda: datetime.utcnow() + timedelta(days=30))
        )


class BusinessEntityFactory(BaseModelFactory):
    """
    Factory for BusinessEntity instances with realistic business data.
    
    Generates authentic business entity instances with proper ownership,
    status management, and business metadata for testing business logic
    workflows and entity relationship scenarios.
    
    Features:
    - Realistic business naming and description patterns
    - Owner assignment with user relationship management
    - Configurable business entity status and lifecycle
    - Industry and category classification support
    - Business metadata for complex workflow testing
    """
    
    class Meta:
        model = BusinessEntity
        sqlalchemy_session_persistence = 'commit'
    
    # Core business entity fields
    name = factory.LazyFunction(lambda: fake.company())
    description = factory.LazyFunction(lambda: fake.catch_phrase())
    
    # Ownership and status
    owner = factory.SubFactory(UserFactory)
    status = factory.LazyFunction(lambda: fake.random_element(elements=(
        'active', 'inactive', 'pending', 'suspended', 'archived'
    )))
    
    # Business classification
    entity_type = factory.LazyFunction(lambda: fake.random_element(elements=(
        'company', 'department', 'project', 'team', 'product',
        'service', 'location', 'asset', 'contract', 'initiative'
    )))
    
    industry = factory.LazyFunction(lambda: fake.random_element(elements=(
        'Technology', 'Healthcare', 'Finance', 'Manufacturing', 'Retail',
        'Education', 'Government', 'Energy', 'Transportation', 'Real Estate'
    )))
    
    category = factory.LazyFunction(lambda: fake.random_element(elements=(
        'primary', 'secondary', 'support', 'internal', 'external',
        'strategic', 'operational', 'tactical', 'critical', 'standard'
    )))
    
    # Business metadata
    priority_level = factory.LazyFunction(lambda: fake.random_int(min=1, max=5))
    risk_level = factory.LazyFunction(lambda: fake.random_element(elements=(
        'low', 'medium', 'high', 'critical'
    )))
    
    # Additional business fields
    external_id = factory.LazyFunction(lambda: fake.uuid4() if fake.boolean(chance_of_getting_true=60) else None)
    tags = factory.LazyFunction(lambda: json.dumps(
        fake.random_elements(elements=(
            'important', 'urgent', 'revenue', 'cost_center', 'innovation',
            'compliance', 'customer_facing', 'internal_only', 'partner'
        ), length=fake.random_int(min=1, max=4), unique=True)
    ))
    
    # Business contact information
    contact_info = factory.LazyFunction(lambda: json.dumps({
        'phone': fake.phone_number(),
        'email': fake.company_email(),
        'address': {
            'street': fake.street_address(),
            'city': fake.city(),
            'state': fake.state_abbr(),
            'zip_code': fake.zipcode(),
            'country': fake.country_code()
        },
        'website': fake.url()
    }))
    
    # Financial information
    budget_allocated = factory.LazyFunction(lambda: fake.random_int(min=10000, max=1000000)
                                          if fake.boolean(chance_of_getting_true=70) else None)
    
    # Operational metadata
    entity_metadata = factory.LazyFunction(lambda: json.dumps({
        'established_date': fake.date_this_decade().isoformat(),
        'employee_count': fake.random_int(min=1, max=500),
        'reporting_frequency': fake.random_element(elements=('daily', 'weekly', 'monthly', 'quarterly')),
        'compliance_required': fake.boolean(chance_of_getting_true=40),
        'public_facing': fake.boolean(chance_of_getting_true=30)
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        high_priority = factory.Trait(
            priority_level=5,
            risk_level='high',
            status='active'
        )
        
        project_entity = factory.Trait(
            entity_type='project',
            status=factory.LazyFunction(lambda: fake.random_element(elements=(
                'active', 'pending', 'planning'
            ))),
            entity_metadata=factory.LazyFunction(lambda: json.dumps({
                'start_date': fake.date_this_year().isoformat(),
                'estimated_completion': fake.date_between(start_date='today', end_date='+1y').isoformat(),
                'project_manager': fake.name(),
                'stakeholders': [fake.name() for _ in range(fake.random_int(min=2, max=6))]
            }))
        )
        
        department_entity = factory.Trait(
            entity_type='department',
            category='internal',
            entity_metadata=factory.LazyFunction(lambda: json.dumps({
                'department_head': fake.name(),
                'employee_count': fake.random_int(min=5, max=50),
                'budget_code': fake.bothify(text='DEPT-###-????'),
                'cost_center': fake.random_int(min=1000, max=9999)
            }))
        )


class EntityRelationshipFactory(BaseModelFactory):
    """
    Factory for EntityRelationship instances with complex relationship patterns.
    
    Generates realistic business entity relationships with proper relationship
    typing, bidirectional mapping, and relationship metadata for testing
    complex business logic and entity graph scenarios.
    
    Features:
    - Comprehensive relationship type support
    - Bidirectional relationship mapping
    - Relationship strength and importance weighting
    - Temporal relationship tracking with lifecycle management
    - Relationship metadata for business context
    """
    
    class Meta:
        model = EntityRelationship
        sqlalchemy_session_persistence = 'commit'
    
    # Relationship entities
    source_entity = factory.SubFactory(BusinessEntityFactory)
    target_entity = factory.SubFactory(BusinessEntityFactory)
    
    # Relationship classification
    relationship_type = factory.LazyFunction(lambda: fake.random_element(elements=(
        'parent_child', 'sibling', 'dependency', 'ownership', 'partnership',
        'vendor_client', 'supplier_customer', 'reports_to', 'collaborates_with',
        'manages', 'supports', 'integrates_with', 'competes_with', 'serves'
    )))
    
    relationship_direction = factory.LazyFunction(lambda: fake.random_element(elements=(
        'bidirectional', 'source_to_target', 'target_to_source'
    )))
    
    # Relationship status and lifecycle
    is_active = True
    status = factory.LazyFunction(lambda: fake.random_element(elements=(
        'active', 'pending', 'suspended', 'terminated', 'under_review'
    )))
    
    # Relationship strength and importance
    strength = factory.LazyFunction(lambda: fake.random_element(elements=(
        'weak', 'moderate', 'strong', 'critical'
    )))
    importance_score = factory.LazyFunction(lambda: fake.random_int(min=1, max=10))
    
    # Temporal tracking
    relationship_start_date = factory.LazyFunction(lambda: fake.date_between(start_date='-2y', end_date='today'))
    relationship_end_date = factory.LazyFunction(lambda: fake.date_between(start_date='today', end_date='+1y')
                                               if fake.boolean(chance_of_getting_true=20) else None)
    
    # Relationship description and context
    description = factory.LazyFunction(lambda: fake.sentence(nb_words=12))
    
    # Relationship metadata
    relationship_metadata = factory.LazyFunction(lambda: json.dumps({
        'contract_id': fake.uuid4() if fake.boolean(chance_of_getting_true=40) else None,
        'sla_required': fake.boolean(chance_of_getting_true=30),
        'financial_impact': fake.random_element(elements=('none', 'low', 'medium', 'high')),
        'review_frequency': fake.random_element(elements=('monthly', 'quarterly', 'annually', 'as_needed')),
        'stakeholders': [fake.name() for _ in range(fake.random_int(min=1, max=4))],
        'compliance_aspects': fake.random_elements(elements=(
            'data_sharing', 'security_clearance', 'regulatory_compliance',
            'audit_requirements', 'privacy_protection'
        ), length=fake.random_int(min=0, max=3), unique=True)
    }))
    
    class Params:
        """Trait parameters for factory variations"""
        hierarchical = factory.Trait(
            relationship_type='parent_child',
            relationship_direction='source_to_target',
            strength='strong'
        )
        
        partnership = factory.Trait(
            relationship_type='partnership',
            relationship_direction='bidirectional',
            strength=factory.LazyFunction(lambda: fake.random_element(elements=('moderate', 'strong'))),
            relationship_metadata=factory.LazyFunction(lambda: json.dumps({
                'partnership_agreement': fake.uuid4(),
                'revenue_sharing': fake.boolean(),
                'joint_projects': fake.random_int(min=1, max=5),
                'communication_protocol': fake.random_element(elements=('formal', 'informal', 'structured'))
            }))
        )
        
        dependency = factory.Trait(
            relationship_type='dependency',
            strength='critical',
            relationship_metadata=factory.LazyFunction(lambda: json.dumps({
                'dependency_type': fake.random_element(elements=('technical', 'business', 'operational')),
                'criticality_level': 'high',
                'fallback_options': fake.boolean(chance_of_getting_true=60)
            }))
        )


class AuditLogFactory(BaseModelFactory):
    """
    Factory for AuditLog instances with comprehensive operation tracking.
    
    Generates realistic audit log entries with proper operation classification,
    change tracking, and security context for testing audit trail workflows
    and compliance reporting scenarios.
    
    Features:
    - Comprehensive DML operation tracking (INSERT, UPDATE, DELETE)
    - JSON change data with before/after state comparison
    - User context integration with Flask-Login session tracking
    - Performance-optimized audit data generation
    - Compliance-ready audit trail patterns
    """
    
    class Meta:
        model = AuditLog
        sqlalchemy_session_persistence = 'commit'
    
    # Core audit fields
    table_name = factory.LazyFunction(lambda: fake.random_element(elements=(
        'users', 'roles', 'permissions', 'business_entities', 'user_sessions',
        'entity_relationships', 'user_roles', 'role_permissions'
    )))
    
    record_id = factory.LazyFunction(lambda: fake.random_int(min=1, max=10000))
    
    operation_type = factory.LazyFunction(lambda: fake.random_element(elements=(
        'INSERT', 'UPDATE', 'DELETE', 'SELECT'
    )))
    
    # User context
    user_id = factory.SubFactory(UserFactory)
    username = factory.LazyAttribute(lambda obj: obj.user_id.username if obj.user_id else 'system')
    
    # Session context
    session_id = factory.LazyFunction(lambda: fake.uuid4())
    ip_address = factory.LazyFunction(lambda: fake.ipv4())
    user_agent = factory.LazyFunction(lambda: fake.user_agent())
    
    # Change data (JSON format)
    old_values = factory.LazyFunction(lambda: json.dumps({
        'name': fake.name(),
        'email': fake.email(),
        'status': fake.random_element(elements=('active', 'inactive')),
        'last_updated': fake.date_time_this_year().isoformat()
    }) if fake.boolean(chance_of_getting_true=70) else None)
    
    new_values = factory.LazyFunction(lambda: json.dumps({
        'name': fake.name(),
        'email': fake.email(),
        'status': fake.random_element(elements=('active', 'inactive')),
        'last_updated': datetime.utcnow().isoformat()
    }))
    
    # Audit metadata
    operation_context = factory.LazyFunction(lambda: json.dumps({
        'endpoint': fake.uri_path(),
        'method': fake.random_element(elements=('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
        'request_id': fake.uuid4(),
        'transaction_id': fake.uuid4(),
        'client_version': fake.random_element(elements=('1.0.0', '1.1.0', '1.2.0'))
    }))
    
    # Timestamp (from AuditMixin)
    timestamp = factory.LazyFunction(lambda: fake.date_time_between(start_date='-30d', end_date='now'))
    
    class Params:
        """Trait parameters for factory variations"""
        insert_operation = factory.Trait(
            operation_type='INSERT',
            old_values=None,
            new_values=factory.LazyFunction(lambda: json.dumps({
                'id': fake.random_int(min=1, max=10000),
                'created_at': datetime.utcnow().isoformat(),
                'status': 'active'
            }))
        )
        
        update_operation = factory.Trait(
            operation_type='UPDATE',
            old_values=factory.LazyFunction(lambda: json.dumps({
                'status': 'pending',
                'updated_at': fake.date_time_this_year().isoformat()
            })),
            new_values=factory.LazyFunction(lambda: json.dumps({
                'status': 'active',
                'updated_at': datetime.utcnow().isoformat()
            }))
        )
        
        delete_operation = factory.Trait(
            operation_type='DELETE',
            new_values=None,
            old_values=factory.LazyFunction(lambda: json.dumps({
                'id': fake.random_int(min=1, max=10000),
                'status': 'active',
                'deleted_at': datetime.utcnow().isoformat()
            }))
        )
        
        security_audit = factory.Trait(
            operation_context=factory.LazyFunction(lambda: json.dumps({
                'security_event': True,
                'event_type': fake.random_element(elements=(
                    'login_attempt', 'permission_change', 'role_assignment'
                )),
                'risk_level': fake.random_element(elements=('low', 'medium', 'high')),
                'automated_response': fake.boolean()
            }))
        )


class SecurityEventFactory(BaseModelFactory):
    """
    Factory for SecurityEvent instances with comprehensive security monitoring.
    
    Generates realistic security event instances with proper classification,
    severity assessment, and response tracking for testing security monitoring
    workflows and incident response scenarios.
    
    Features:
    - Comprehensive security event type classification
    - Severity-based incident categorization
    - Response tracking and resolution workflow support
    - Security context with threat intelligence integration
    - Performance-optimized security data generation
    """
    
    class Meta:
        model = SecurityEvent
        sqlalchemy_session_persistence = 'commit'
    
    # Core security event fields
    event_type = factory.LazyFunction(lambda: fake.random_element(elements=(
        'authentication_failure', 'authorization_violation', 'suspicious_activity',
        'brute_force_attempt', 'account_lockout', 'permission_escalation',
        'data_access_violation', 'session_hijacking', 'malicious_request',
        'anomalous_behavior', 'policy_violation', 'security_scan_detected'
    )))
    
    severity = factory.LazyFunction(lambda: fake.random_element(elements=(
        'low', 'medium', 'high', 'critical'
    )))
    
    status = factory.LazyFunction(lambda: fake.random_element(elements=(
        'open', 'investigating', 'resolved', 'false_positive', 'escalated'
    )))
    
    # Event context
    source_ip = factory.LazyFunction(lambda: fake.ipv4())
    target_resource = factory.LazyFunction(lambda: fake.random_element(elements=(
        '/api/users', '/api/admin', '/api/roles', '/dashboard',
        '/api/business-entities', '/api/reports', '/login', '/api/permissions'
    )))
    
    user_id = factory.SubFactory(UserFactory)
    session_id = factory.LazyFunction(lambda: fake.uuid4())
    
    # Event details
    description = factory.LazyFunction(lambda: fake.sentence(nb_words=15))
    
    # Risk assessment
    risk_score = factory.LazyFunction(lambda: fake.random_int(min=1, max=100))
    threat_indicators = factory.LazyFunction(lambda: json.dumps(
        fake.random_elements(elements=(
            'multiple_failed_logins', 'unusual_access_pattern', 'suspicious_ip',
            'privilege_escalation_attempt', 'data_exfiltration_pattern',
            'malware_signature', 'known_threat_actor', 'anomalous_timing'
        ), length=fake.random_int(min=1, max=4), unique=True)
    ))
    
    # Response tracking
    detected_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='-7d', end_date='now'))
    resolved_at = factory.LazyFunction(lambda: fake.date_time_between(start_date='now', end_date='+1d')
                                     if fake.boolean(chance_of_getting_true=60) else None)
    resolved_by = factory.LazyFunction(lambda: fake.random_element(elements=(
        'security_team', 'system_admin', 'automated_response', 'soc_analyst'
    )) if fake.boolean(chance_of_getting_true=60) else None)
    
    # Event metadata
    event_metadata = factory.LazyFunction(lambda: json.dumps({
        'detection_method': fake.random_element(elements=(
            'automated_rule', 'manual_review', 'user_report', 'system_alert'
        )),
        'affected_systems': fake.random_elements(elements=(
            'web_application', 'database', 'api_gateway', 'authentication_service'
        ), length=fake.random_int(min=1, max=3), unique=True),
        'mitigation_actions': fake.random_elements(elements=(
            'account_locked', 'ip_blocked', 'session_terminated', 'alert_sent',
            'investigation_started', 'escalated_to_admin'
        ), length=fake.random_int(min=1, max=3), unique=True),
        'investigation_notes': fake.text(max_nb_chars=200)
    }))
    
    # Additional context
    related_events = factory.LazyFunction(lambda: json.dumps([
        fake.uuid4() for _ in range(fake.random_int(min=0, max=3))
    ]))
    
    class Params:
        """Trait parameters for factory variations"""
        critical_security_event = factory.Trait(
            severity='critical',
            status=factory.LazyFunction(lambda: fake.random_element(elements=(
                'open', 'investigating', 'escalated'
            ))),
            risk_score=factory.LazyFunction(lambda: fake.random_int(min=80, max=100))
        )
        
        authentication_failure = factory.Trait(
            event_type='authentication_failure',
            target_resource='/login',
            event_metadata=factory.LazyFunction(lambda: json.dumps({
                'failed_attempts': fake.random_int(min=1, max=10),
                'username_attempted': fake.user_name(),
                'detection_method': 'automated_rule',
                'lockout_triggered': fake.boolean(chance_of_getting_true=60)
            }))
        )
        
        privilege_escalation = factory.Trait(
            event_type='permission_escalation',
            severity=factory.LazyFunction(lambda: fake.random_element(elements=('high', 'critical'))),
            event_metadata=factory.LazyFunction(lambda: json.dumps({
                'attempted_privilege': fake.random_element(elements=('admin', 'super_user')),
                'current_privilege': fake.random_element(elements=('user', 'operator')),
                'escalation_method': fake.random_element(elements=('role_manipulation', 'permission_bypass')),
                'investigation_priority': 'high'
            }))
        )
        
        resolved_event = factory.Trait(
            status='resolved',
            resolved_at=factory.LazyFunction(lambda: fake.date_time_between(start_date='-1d', end_date='now')),
            resolved_by='security_team'
        )


# Factory configuration and session management
def configure_factories(app=None):
    """
    Configure Factory Boy with Flask-SQLAlchemy session management.
    
    Args:
        app: Flask application instance (optional)
    """
    # Set up SQLAlchemy session for all factories
    session = FactorySessionManager.get_session()
    
    # Configure all factory classes with the session
    factory_classes = [
        UserFactory, RoleFactory, PermissionFactory, UserRoleFactory,
        RolePermissionFactory, UserSessionFactory, BusinessEntityFactory,
        EntityRelationshipFactory, AuditLogFactory, SecurityEventFactory
    ]
    
    for factory_class in factory_classes:
        factory_class._meta.sqlalchemy_session = session


def reset_factory_sequences():
    """
    Reset all factory sequences for consistent test data generation.
    
    Useful for test isolation and predictable factory behavior across
    different test execution cycles.
    """
    # Reset unique sequences in Faker
    fake.unique.clear()
    
    # Reset Factory Boy sequences if needed
    for factory_class in [
        UserFactory, RoleFactory, PermissionFactory, UserRoleFactory,
        RolePermissionFactory, UserSessionFactory, BusinessEntityFactory,
        EntityRelationshipFactory, AuditLogFactory, SecurityEventFactory
    ]:
        if hasattr(factory_class, '_meta') and hasattr(factory_class._meta, 'sequences'):
            factory_class._meta.sequences.clear()


def cleanup_test_data():
    """
    Clean up test data generated by factories.
    
    Provides comprehensive cleanup of all factory-generated data for
    test isolation and database state management.
    """
    try:
        # Roll back any pending transactions
        FactorySessionManager.rollback_session()
        
        # Clean up session state
        FactorySessionManager.cleanup_session()
        
        # Reset factory sequences
        reset_factory_sequences()
        
        return True
    except Exception as e:
        return False


# Convenience factory methods for common test scenarios
class FactoryPresets:
    """
    Pre-configured factory combinations for common testing scenarios.
    
    Provides convenient methods for creating complex object graphs and
    relationship patterns commonly needed in test scenarios.
    """
    
    @staticmethod
    def create_admin_user_with_roles():
        """
        Create an admin user with comprehensive role assignments.
        
        Returns:
            Tuple of (user, admin_role, permissions)
        """
        # Create admin user
        admin_user = UserFactory(admin_user=True)
        
        # Create admin role with permissions
        admin_role = RoleFactory(admin_role=True)
        
        # Create comprehensive permissions
        permissions = [
            PermissionFactory(admin_permission=True, resource='users'),
            PermissionFactory(admin_permission=True, resource='roles'),
            PermissionFactory(admin_permission=True, resource='permissions'),
            PermissionFactory(admin_permission=True, resource='business_entities'),
            PermissionFactory(admin_permission=True, resource='audit_logs')
        ]
        
        # Assign permissions to role
        for permission in permissions:
            RolePermissionFactory(role=admin_role, permission=permission)
        
        # Assign role to user
        UserRoleFactory(user=admin_user, role=admin_role)
        
        FactorySessionManager.commit_session()
        
        return admin_user, admin_role, permissions
    
    @staticmethod
    def create_business_entity_hierarchy():
        """
        Create a complete business entity hierarchy with relationships.
        
        Returns:
            Dictionary with created entities and relationships
        """
        # Create parent company
        parent_company = BusinessEntityFactory(
            entity_type='company',
            name='Parent Corporation'
        )
        
        # Create departments
        departments = [
            BusinessEntityFactory(entity_type='department', name='Engineering'),
            BusinessEntityFactory(entity_type='department', name='Marketing'),
            BusinessEntityFactory(entity_type='department', name='Sales')
        ]
        
        # Create projects under departments
        projects = []
        for dept in departments:
            project = BusinessEntityFactory(project_entity=True)
            projects.append(project)
            
            # Create relationships
            EntityRelationshipFactory(
                source_entity=dept,
                target_entity=project,
                hierarchical=True
            )
        
        # Create company-department relationships
        dept_relationships = []
        for dept in departments:
            relationship = EntityRelationshipFactory(
                source_entity=parent_company,
                target_entity=dept,
                hierarchical=True
            )
            dept_relationships.append(relationship)
        
        FactorySessionManager.commit_session()
        
        return {
            'parent_company': parent_company,
            'departments': departments,
            'projects': projects,
            'dept_relationships': dept_relationships
        }
    
    @staticmethod
    def create_user_session_with_audit_trail():
        """
        Create a user with active session and comprehensive audit trail.
        
        Returns:
            Dictionary with user, session, and audit records
        """
        # Create user with login history
        user = UserFactory(
            login_count=50,
            last_login_at=fake.date_time_between(start_date='-1h', end_date='now')
        )
        
        # Create active session
        session = UserSessionFactory(user=user)
        
        # Create audit log entries for user creation and session start
        user_creation_audit = AuditLogFactory(
            table_name='users',
            record_id=user.id,
            user_id=user,
            insert_operation=True
        )
        
        session_start_audit = AuditLogFactory(
            table_name='user_sessions',
            record_id=session.id,
            user_id=user,
            insert_operation=True
        )
        
        # Create some security events
        security_events = [
            SecurityEventFactory(user_id=user, resolved_event=True),
            SecurityEventFactory(user_id=user, authentication_failure=True)
        ]
        
        FactorySessionManager.commit_session()
        
        return {
            'user': user,
            'session': session,
            'audit_logs': [user_creation_audit, session_start_audit],
            'security_events': security_events
        }
    
    @staticmethod
    def create_rbac_test_scenario():
        """
        Create a comprehensive RBAC test scenario with multiple users, roles, and permissions.
        
        Returns:
            Dictionary with all created RBAC entities
        """
        # Create permissions for different resources
        permissions = {}
        resources = ['users', 'roles', 'business_entities', 'reports']
        actions = ['read', 'create', 'update', 'delete', 'admin']
        
        for resource in resources:
            permissions[resource] = []
            for action in actions:
                perm = PermissionFactory(resource=resource, action=action)
                permissions[resource].append(perm)
        
        # Create roles with different permission sets
        roles = {
            'admin': RoleFactory(admin_role=True),
            'manager': RoleFactory(name='manager', display_name='Manager'),
            'user': RoleFactory(viewer_role=True),
            'analyst': RoleFactory(name='analyst', display_name='Data Analyst')
        }
        
        # Assign permissions to roles
        role_permissions = {}
        
        # Admin gets all permissions
        role_permissions['admin'] = []
        for resource_perms in permissions.values():
            for perm in resource_perms:
                rp = RolePermissionFactory(role=roles['admin'], permission=perm)
                role_permissions['admin'].append(rp)
        
        # Manager gets read/update permissions
        role_permissions['manager'] = []
        for resource in ['users', 'business_entities']:
            for action in ['read', 'update']:
                perm = next(p for p in permissions[resource] if p.action == action)
                rp = RolePermissionFactory(role=roles['manager'], permission=perm)
                role_permissions['manager'].append(rp)
        
        # User gets read permissions only
        role_permissions['user'] = []
        for resource in resources:
            perm = next(p for p in permissions[resource] if p.action == 'read')
            rp = RolePermissionFactory(role=roles['user'], permission=perm)
            role_permissions['user'].append(rp)
        
        # Create users and assign roles
        users = {
            'admin_user': UserFactory(admin_user=True),
            'manager_user': UserFactory(),
            'regular_user': UserFactory(),
            'analyst_user': UserFactory()
        }
        
        user_roles = {}
        user_roles['admin_user'] = UserRoleFactory(user=users['admin_user'], role=roles['admin'])
        user_roles['manager_user'] = UserRoleFactory(user=users['manager_user'], role=roles['manager'])
        user_roles['regular_user'] = UserRoleFactory(user=users['regular_user'], role=roles['user'])
        user_roles['analyst_user'] = UserRoleFactory(user=users['analyst_user'], role=roles['analyst'])
        
        FactorySessionManager.commit_session()
        
        return {
            'users': users,
            'roles': roles,
            'permissions': permissions,
            'role_permissions': role_permissions,
            'user_roles': user_roles
        }


# Export all factories and utilities
__all__ = [
    # Core factories
    'UserFactory',
    'RoleFactory', 
    'PermissionFactory',
    'UserRoleFactory',
    'RolePermissionFactory',
    'UserSessionFactory',
    'BusinessEntityFactory',
    'EntityRelationshipFactory',
    'AuditLogFactory',
    'SecurityEventFactory',
    
    # Base classes and utilities
    'BaseModelFactory',
    'FactorySessionManager',
    'FactoryPresets',
    
    # Configuration functions
    'configure_factories',
    'reset_factory_sequences',
    'cleanup_test_data'
]