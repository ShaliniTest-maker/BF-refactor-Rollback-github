"""
Role-Based Access Control (RBAC) Models

This module implements comprehensive authorization system models using Flask-SQLAlchemy
declarative classes. Provides complete RBAC infrastructure including many-to-many 
relationships between users, roles, and permissions with proper constraint definitions
and comprehensive audit trail capabilities.

The RBAC system supports:
- Granular permission management with resource-action patterns
- Role hierarchy with active status management
- Comprehensive audit trails for all authorization changes
- Flask blueprint route protection and business operation authorization
- Dynamic permission evaluation and caching integration

Dependencies:
- Flask-SQLAlchemy 3.1.1: ORM functionality and declarative models
- SQLAlchemy event system: Automatic audit field population
- PostgreSQL: Advanced indexing and constraint support
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, 
    Table, Index, UniqueConstraint, CheckConstraint, text
)
from sqlalchemy.orm import relationship, backref, validates
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy import event
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy instance
db = SQLAlchemy()


class AuditMixin:
    """
    Audit mixin providing standardized audit fields for all RBAC models.
    
    Implements automatic timestamp tracking and user attribution for comprehensive
    audit trails required by security and compliance frameworks.
    """
    
    @declared_attr
    def created_at(cls):
        """Timestamp when record was created"""
        return Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    @declared_attr
    def updated_at(cls):
        """Timestamp when record was last updated"""
        return Column(
            DateTime, 
            default=datetime.utcnow, 
            onupdate=datetime.utcnow, 
            nullable=False,
            index=True
        )
    
    @declared_attr
    def created_by(cls):
        """User ID or system identifier who created the record"""
        return Column(String(100), nullable=True)
    
    @declared_attr
    def updated_by(cls):
        """User ID or system identifier who last updated the record"""
        return Column(String(100), nullable=True)


# Association table for many-to-many user-role relationships with audit metadata
user_roles = Table(
    'user_roles',
    db.Model.metadata,
    Column('id', Integer, primary_key=True),
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
    Column('assigned_at', DateTime, default=datetime.utcnow, nullable=False),
    Column('assigned_by', String(100), nullable=True),
    Column('expires_at', DateTime, nullable=True),
    Column('is_active', Boolean, default=True, nullable=False),
    
    # Constraints and indexes for data integrity and performance
    UniqueConstraint('user_id', 'role_id', name='uq_user_role_assignment'),
    Index('idx_user_roles_user_id', 'user_id'),
    Index('idx_user_roles_role_id', 'role_id'),
    Index('idx_user_roles_active', 'is_active'),
    Index('idx_user_roles_assigned_at', 'assigned_at'),
    
    # PostgreSQL partial index for active assignments only
    Index('idx_user_roles_active_assignments', 'user_id', 'role_id', 
          postgresql_where=text('is_active = true'))
)


# Association table for many-to-many role-permission relationships with audit metadata
role_permissions = Table(
    'role_permissions',
    db.Model.metadata,
    Column('id', Integer, primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), nullable=False),
    Column('permission_id', Integer, ForeignKey('permissions.id', ondelete='CASCADE'), nullable=False),
    Column('granted_at', DateTime, default=datetime.utcnow, nullable=False),
    Column('granted_by', String(100), nullable=True),
    Column('expires_at', DateTime, nullable=True),
    Column('is_active', Boolean, default=True, nullable=False),
    
    # Constraints and indexes for data integrity and performance
    UniqueConstraint('role_id', 'permission_id', name='uq_role_permission_grant'),
    Index('idx_role_permissions_role_id', 'role_id'),
    Index('idx_role_permissions_permission_id', 'permission_id'),
    Index('idx_role_permissions_active', 'is_active'),
    Index('idx_role_permissions_granted_at', 'granted_at'),
    
    # PostgreSQL partial index for active grants only
    Index('idx_role_permissions_active_grants', 'role_id', 'permission_id',
          postgresql_where=text('is_active = true'))
)


class Role(db.Model, AuditMixin):
    """
    Role model implementing comprehensive role management for RBAC system.
    
    Supports role hierarchy, active status management, and flexible role assignment
    patterns with full audit trail capabilities. Integrates with Flask blueprint
    route protection and business operation authorization.
    
    Attributes:
        id: Primary key for role identification
        name: Unique role name for identification and lookup
        description: Human-readable role description
        is_active: Status flag for role availability
        is_system: Flag indicating system-defined roles that cannot be deleted
        priority: Role hierarchy priority (higher numbers = higher priority)
        permissions: Many-to-many relationship with Permission model
        
    Database Indexes:
        - Primary key index on id
        - Unique index on name
        - Index on is_active for filtering
        - Index on priority for hierarchy queries
        - Composite index on (is_active, priority) for optimized queries
    """
    
    __tablename__ = 'roles'
    
    # Primary key and core fields
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(500), nullable=True)
    
    # Status and hierarchy management
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_system = Column(Boolean, default=False, nullable=False)
    priority = Column(Integer, default=0, nullable=False, index=True)
    
    # Role metadata
    role_type = Column(String(50), default='custom', nullable=False)
    max_assignments = Column(Integer, nullable=True)  # Optional limit on role assignments
    
    # Relationships with association objects for audit trails
    permissions = relationship(
        'Permission',
        secondary=role_permissions,
        back_populates='roles',
        lazy='dynamic',  # Enable filtering on the relationship
        cascade='all'
    )
    
    # Additional indexes for performance optimization
    __table_args__ = (
        Index('idx_roles_active_priority', 'is_active', 'priority'),
        Index('idx_roles_type', 'role_type'),
        CheckConstraint('priority >= 0', name='ck_role_priority_positive'),
        CheckConstraint("role_type IN ('system', 'custom', 'inherited')", 
                       name='ck_role_type_valid'),
        CheckConstraint('max_assignments IS NULL OR max_assignments > 0', 
                       name='ck_role_max_assignments_positive')
    )
    
    @validates('name')
    def validate_name(self, key, name):
        """Validate role name format and constraints"""
        if not name or len(name.strip()) == 0:
            raise ValueError("Role name cannot be empty")
        if len(name) > 100:
            raise ValueError("Role name cannot exceed 100 characters")
        if not name.replace('_', '').replace('-', '').replace(' ', '').isalnum():
            raise ValueError("Role name can only contain alphanumeric characters, spaces, hyphens, and underscores")
        return name.strip()
    
    @validates('priority')
    def validate_priority(self, key, priority):
        """Validate role priority constraints"""
        if priority is None:
            return 0
        if priority < 0:
            raise ValueError("Role priority must be non-negative")
        if priority > 1000:
            raise ValueError("Role priority cannot exceed 1000")
        return priority
    
    def get_active_permissions(self) -> List['Permission']:
        """
        Get all active permissions assigned to this role.
        
        Returns:
            List of active Permission objects associated with this role
        """
        return self.permissions.filter_by(is_active=True).all()
    
    def has_permission(self, permission_name: str) -> bool:
        """
        Check if role has a specific permission.
        
        Args:
            permission_name: Name of the permission to check
            
        Returns:
            Boolean indicating if role has the permission
        """
        return self.permissions.filter_by(
            name=permission_name, 
            is_active=True
        ).first() is not None
    
    def get_permission_names(self) -> List[str]:
        """
        Get list of permission names for this role.
        
        Returns:
            List of permission names associated with this role
        """
        return [p.name for p in self.get_active_permissions()]
    
    def can_be_assigned_to_user(self, user_id: int) -> bool:
        """
        Check if role can be assigned to a specific user based on constraints.
        
        Args:
            user_id: ID of the user to check assignment eligibility
            
        Returns:
            Boolean indicating if role can be assigned
        """
        if not self.is_active:
            return False
        
        if self.max_assignments is not None:
            # Check current assignment count
            current_assignments = db.session.execute(
                text("""
                    SELECT COUNT(*) FROM user_roles 
                    WHERE role_id = :role_id AND is_active = true
                """),
                {'role_id': self.id}
            ).scalar()
            
            if current_assignments >= self.max_assignments:
                return False
        
        return True
    
    def to_dict(self, include_permissions: bool = False) -> Dict[str, Any]:
        """
        Convert role to dictionary representation.
        
        Args:
            include_permissions: Whether to include permission details
            
        Returns:
            Dictionary representation of the role
        """
        result = {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_active': self.is_active,
            'is_system': self.is_system,
            'priority': self.priority,
            'role_type': self.role_type,
            'max_assignments': self.max_assignments,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }
        
        if include_permissions:
            result['permissions'] = [p.to_dict() for p in self.get_active_permissions()]
        
        return result
    
    def __repr__(self):
        return f"<Role {self.name} (ID: {self.id}, Active: {self.is_active})>"


class Permission(db.Model, AuditMixin):
    """
    Permission model implementing granular access control with resource-action patterns.
    
    Supports Flask blueprint route protection and business operation authorization
    through structured resource and action definitions. Enables dynamic permission
    evaluation and flexible authorization patterns.
    
    Attributes:
        id: Primary key for permission identification
        name: Unique permission name (typically resource.action format)
        resource: Resource type or entity (e.g., 'user', 'business_entity', 'report')
        action: Action type (e.g., 'read', 'write', 'delete', 'admin')
        description: Human-readable permission description
        is_active: Status flag for permission availability
        is_system: Flag indicating system-defined permissions
        roles: Many-to-many relationship with Role model
        
    Database Indexes:
        - Primary key index on id
        - Unique index on name
        - Composite index on (resource, action) for fast lookups
        - Index on is_active for filtering
        - Index on resource for resource-based queries
    """
    
    __tablename__ = 'permissions'
    
    # Primary key and core fields
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(50), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    description = Column(String(500), nullable=True)
    
    # Status and metadata
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_system = Column(Boolean, default=False, nullable=False)
    permission_type = Column(String(50), default='functional', nullable=False)
    
    # Optional scope and context restrictions
    scope = Column(String(100), nullable=True)  # Optional scope restriction
    context_requirements = Column(String(500), nullable=True)  # JSON string for context rules
    
    # Relationships with association objects for audit trails
    roles = relationship(
        'Role',
        secondary=role_permissions,
        back_populates='permissions',
        lazy='dynamic',  # Enable filtering on the relationship
        cascade='all'
    )
    
    # Additional indexes for performance optimization
    __table_args__ = (
        Index('idx_permissions_resource_action', 'resource', 'action'),
        Index('idx_permissions_active_resource', 'is_active', 'resource'),
        Index('idx_permissions_type', 'permission_type'),
        UniqueConstraint('resource', 'action', 'scope', name='uq_permission_resource_action_scope'),
        CheckConstraint("permission_type IN ('functional', 'data', 'system', 'administrative')",
                       name='ck_permission_type_valid'),
        CheckConstraint("action IN ('create', 'read', 'update', 'delete', 'list', 'admin', 'execute', 'manage')",
                       name='ck_permission_action_valid')
    )
    
    @validates('name')
    def validate_name(self, key, name):
        """Validate permission name format and constraints"""
        if not name or len(name.strip()) == 0:
            raise ValueError("Permission name cannot be empty")
        if len(name) > 100:
            raise ValueError("Permission name cannot exceed 100 characters")
        
        # Enforce resource.action naming convention
        if '.' not in name:
            raise ValueError("Permission name must follow 'resource.action' format")
        
        parts = name.split('.')
        if len(parts) != 2:
            raise ValueError("Permission name must have exactly one dot separator")
        
        resource_part, action_part = parts
        if not resource_part or not action_part:
            raise ValueError("Both resource and action parts must be non-empty")
        
        return name.strip().lower()
    
    @validates('resource')
    def validate_resource(self, key, resource):
        """Validate resource name constraints"""
        if not resource or len(resource.strip()) == 0:
            raise ValueError("Resource cannot be empty")
        if len(resource) > 50:
            raise ValueError("Resource name cannot exceed 50 characters")
        if not resource.replace('_', '').isalnum():
            raise ValueError("Resource name can only contain alphanumeric characters and underscores")
        return resource.strip().lower()
    
    @validates('action')
    def validate_action(self, key, action):
        """Validate action name constraints"""
        if not action or len(action.strip()) == 0:
            raise ValueError("Action cannot be empty")
        if len(action) > 50:
            raise ValueError("Action name cannot exceed 50 characters")
        
        valid_actions = {
            'create', 'read', 'update', 'delete', 'list', 
            'admin', 'execute', 'manage'
        }
        action = action.strip().lower()
        if action not in valid_actions:
            raise ValueError(f"Action must be one of: {', '.join(valid_actions)}")
        
        return action
    
    @classmethod
    def create_permission(cls, resource: str, action: str, description: str = None,
                         scope: str = None, permission_type: str = 'functional') -> 'Permission':
        """
        Factory method to create a permission with proper naming convention.
        
        Args:
            resource: Resource name (e.g., 'user', 'business_entity')
            action: Action name (e.g., 'read', 'write', 'delete')
            description: Optional permission description
            scope: Optional permission scope restriction
            permission_type: Type of permission (functional, data, system, administrative)
            
        Returns:
            New Permission instance
        """
        name = f"{resource.lower()}.{action.lower()}"
        
        return cls(
            name=name,
            resource=resource.lower(),
            action=action.lower(),
            description=description or f"Permission to {action} {resource} resources",
            scope=scope,
            permission_type=permission_type
        )
    
    def matches_request(self, resource: str, action: str, context: Dict[str, Any] = None) -> bool:
        """
        Check if permission matches a specific resource and action request.
        
        Args:
            resource: Requested resource
            action: Requested action
            context: Optional context for scope validation
            
        Returns:
            Boolean indicating if permission matches the request
        """
        if not self.is_active:
            return False
        
        # Exact match
        if self.resource == resource.lower() and self.action == action.lower():
            return True
        
        # Wildcard action match (e.g., resource.admin covers all actions on resource)
        if self.resource == resource.lower() and self.action == 'admin':
            return True
        
        # Scope-based validation if context provided
        if self.scope and context:
            return self._validate_scope(context)
        
        return False
    
    def _validate_scope(self, context: Dict[str, Any]) -> bool:
        """
        Validate permission scope against provided context.
        
        Args:
            context: Context information for scope validation
            
        Returns:
            Boolean indicating if context satisfies scope requirements
        """
        if not self.scope:
            return True
        
        # Simple scope validation - can be extended for complex rules
        if self.scope == 'own' and context.get('owner_id') == context.get('user_id'):
            return True
        
        if self.scope == 'department' and context.get('department_id') == context.get('user_department_id'):
            return True
        
        return False
    
    def get_assigned_roles(self) -> List[Role]:
        """
        Get all active roles that have this permission.
        
        Returns:
            List of active Role objects that include this permission
        """
        return self.roles.filter_by(is_active=True).all()
    
    def to_dict(self, include_roles: bool = False) -> Dict[str, Any]:
        """
        Convert permission to dictionary representation.
        
        Args:
            include_roles: Whether to include role details
            
        Returns:
            Dictionary representation of the permission
        """
        result = {
            'id': self.id,
            'name': self.name,
            'resource': self.resource,
            'action': self.action,
            'description': self.description,
            'is_active': self.is_active,
            'is_system': self.is_system,
            'permission_type': self.permission_type,
            'scope': self.scope,
            'context_requirements': self.context_requirements,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by,
            'updated_by': self.updated_by
        }
        
        if include_roles:
            result['roles'] = [r.to_dict() for r in self.get_assigned_roles()]
        
        return result
    
    def __repr__(self):
        return f"<Permission {self.name} (ID: {self.id}, Active: {self.is_active})>"


# SQLAlchemy event listeners for automatic audit field population
@event.listens_for(db.session, 'before_commit')
def populate_audit_fields(session):
    """
    Automatically populate audit fields before database commit.
    
    Captures user context from Flask-Login sessions and populates created_by
    and updated_by fields for comprehensive audit trail tracking.
    """
    try:
        # Import here to avoid circular imports
        from flask import g
        from flask_login import current_user
        
        # Get current user information
        user_id = None
        if hasattr(g, 'current_user_id'):
            user_id = g.current_user_id
        elif hasattr(current_user, 'id') and current_user.is_authenticated:
            user_id = str(current_user.id)
        else:
            user_id = 'system'
        
        # Populate audit fields for new objects
        for obj in session.new:
            if hasattr(obj, 'created_by') and obj.created_by is None:
                obj.created_by = user_id
            if hasattr(obj, 'updated_by') and obj.updated_by is None:
                obj.updated_by = user_id
        
        # Populate audit fields for modified objects
        for obj in session.dirty:
            if hasattr(obj, 'updated_by'):
                obj.updated_by = user_id
    
    except Exception as e:
        # Log the error but don't break the transaction
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to populate audit fields: {e}")


# Utility functions for RBAC operations
class RBACUtils:
    """
    Utility class providing helper methods for RBAC operations.
    
    Includes methods for permission evaluation, role management, and audit
    trail querying to support Flask blueprint integration and business logic.
    """
    
    @staticmethod
    def get_user_permissions(user_id: int, include_inactive: bool = False) -> List[str]:
        """
        Get all permission names for a specific user across all their roles.
        
        Args:
            user_id: ID of the user
            include_inactive: Whether to include inactive roles/permissions
            
        Returns:
            List of unique permission names
        """
        query = db.session.query(Permission.name).distinct()
        query = query.join(role_permissions).join(Role).join(user_roles)
        query = query.filter(user_roles.c.user_id == user_id)
        
        if not include_inactive:
            query = query.filter(
                Role.is_active == True,
                Permission.is_active == True,
                user_roles.c.is_active == True,
                role_permissions.c.is_active == True
            )
        
        return [row[0] for row in query.all()]
    
    @staticmethod
    def user_has_permission(user_id: int, permission_name: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user_id: ID of the user
            permission_name: Name of the permission to check
            
        Returns:
            Boolean indicating if user has the permission
        """
        return permission_name in RBACUtils.get_user_permissions(user_id)
    
    @staticmethod
    def get_role_assignments_audit(role_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit trail for role assignments.
        
        Args:
            role_id: ID of the role
            limit: Maximum number of records to return
            
        Returns:
            List of audit trail records
        """
        query = db.session.execute(
            text("""
                SELECT user_id, assigned_at, assigned_by, is_active
                FROM user_roles 
                WHERE role_id = :role_id 
                ORDER BY assigned_at DESC 
                LIMIT :limit
            """),
            {'role_id': role_id, 'limit': limit}
        )
        
        return [
            {
                'user_id': row[0],
                'assigned_at': row[1].isoformat() if row[1] else None,
                'assigned_by': row[2],
                'is_active': row[3]
            }
            for row in query.fetchall()
        ]
    
    @staticmethod
    def get_permission_grants_audit(permission_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get audit trail for permission grants.
        
        Args:
            permission_id: ID of the permission
            limit: Maximum number of records to return
            
        Returns:
            List of audit trail records
        """
        query = db.session.execute(
            text("""
                SELECT role_id, granted_at, granted_by, is_active
                FROM role_permissions 
                WHERE permission_id = :permission_id 
                ORDER BY granted_at DESC 
                LIMIT :limit
            """),
            {'permission_id': permission_id, 'limit': limit}
        )
        
        return [
            {
                'role_id': row[0],
                'granted_at': row[1].isoformat() if row[1] else None,
                'granted_by': row[2],
                'is_active': row[3]
            }
            for row in query.fetchall()
        ]
    
    @staticmethod
    def create_default_permissions() -> List[Permission]:
        """
        Create default system permissions for common resources and actions.
        
        Returns:
            List of created Permission objects
        """
        default_permissions = [
            # User management permissions
            ('user', 'create', 'Create new user accounts'),
            ('user', 'read', 'View user information'),
            ('user', 'update', 'Modify user information'),
            ('user', 'delete', 'Delete user accounts'),
            ('user', 'list', 'List all users'),
            ('user', 'admin', 'Full user administration'),
            
            # Role management permissions
            ('role', 'create', 'Create new roles'),
            ('role', 'read', 'View role information'),
            ('role', 'update', 'Modify role information'),
            ('role', 'delete', 'Delete roles'),
            ('role', 'list', 'List all roles'),
            ('role', 'admin', 'Full role administration'),
            
            # Permission management permissions
            ('permission', 'create', 'Create new permissions'),
            ('permission', 'read', 'View permission information'),
            ('permission', 'update', 'Modify permission information'),
            ('permission', 'delete', 'Delete permissions'),
            ('permission', 'list', 'List all permissions'),
            ('permission', 'admin', 'Full permission administration'),
            
            # Business entity permissions
            ('business_entity', 'create', 'Create business entities'),
            ('business_entity', 'read', 'View business entities'),
            ('business_entity', 'update', 'Modify business entities'),
            ('business_entity', 'delete', 'Delete business entities'),
            ('business_entity', 'list', 'List business entities'),
            ('business_entity', 'admin', 'Full business entity administration'),
            
            # System administration permissions
            ('system', 'admin', 'System administration access'),
            ('system', 'read', 'View system information'),
            ('audit', 'read', 'View audit logs'),
            ('audit', 'admin', 'Audit log administration'),
        ]
        
        created_permissions = []
        for resource, action, description in default_permissions:
            # Check if permission already exists
            existing = Permission.query.filter_by(
                resource=resource, 
                action=action
            ).first()
            
            if not existing:
                permission = Permission.create_permission(
                    resource=resource,
                    action=action,
                    description=description,
                    permission_type='system'
                )
                permission.is_system = True
                db.session.add(permission)
                created_permissions.append(permission)
        
        if created_permissions:
            db.session.commit()
        
        return created_permissions
    
    @staticmethod
    def create_default_roles() -> List[Role]:
        """
        Create default system roles with appropriate permissions.
        
        Returns:
            List of created Role objects
        """
        # Ensure default permissions exist
        RBACUtils.create_default_permissions()
        
        default_roles = [
            {
                'name': 'administrator',
                'description': 'Full system administrator with all permissions',
                'priority': 1000,
                'permissions': ['*.admin']  # All admin permissions
            },
            {
                'name': 'user_manager',
                'description': 'User account management and administration',
                'priority': 800,
                'permissions': ['user.admin', 'role.read', 'permission.read']
            },
            {
                'name': 'business_admin',
                'description': 'Business entity administration',
                'priority': 700,
                'permissions': ['business_entity.admin', 'user.read']
            },
            {
                'name': 'viewer',
                'description': 'Read-only access to most resources',
                'priority': 100,
                'permissions': ['user.read', 'business_entity.read', 'role.read', 'permission.read']
            },
            {
                'name': 'user',
                'description': 'Basic user access',
                'priority': 50,
                'permissions': ['user.read']
            }
        ]
        
        created_roles = []
        for role_data in default_roles:
            # Check if role already exists
            existing = Role.query.filter_by(name=role_data['name']).first()
            
            if not existing:
                role = Role(
                    name=role_data['name'],
                    description=role_data['description'],
                    priority=role_data['priority'],
                    is_system=True,
                    role_type='system'
                )
                db.session.add(role)
                db.session.flush()  # Get role ID
                
                # Assign permissions
                for perm_pattern in role_data['permissions']:
                    if perm_pattern.endswith('.admin') and perm_pattern.startswith('*'):
                        # All admin permissions
                        permissions = Permission.query.filter(
                            Permission.action == 'admin',
                            Permission.is_active == True
                        ).all()
                    elif perm_pattern.endswith('.admin'):
                        # Specific resource admin permissions
                        resource = perm_pattern.split('.')[0]
                        permissions = Permission.query.filter_by(
                            resource=resource,
                            action='admin',
                            is_active=True
                        ).all()
                    else:
                        # Specific permission
                        permissions = Permission.query.filter_by(
                            name=perm_pattern,
                            is_active=True
                        ).all()
                    
                    for permission in permissions:
                        # Check if permission already assigned
                        existing_grant = db.session.execute(
                            text("""
                                SELECT 1 FROM role_permissions 
                                WHERE role_id = :role_id AND permission_id = :permission_id
                            """),
                            {'role_id': role.id, 'permission_id': permission.id}
                        ).first()
                        
                        if not existing_grant:
                            # Insert into association table
                            db.session.execute(
                                text("""
                                    INSERT INTO role_permissions 
                                    (role_id, permission_id, granted_at, granted_by, is_active)
                                    VALUES (:role_id, :permission_id, :granted_at, :granted_by, :is_active)
                                """),
                                {
                                    'role_id': role.id,
                                    'permission_id': permission.id,
                                    'granted_at': datetime.utcnow(),
                                    'granted_by': 'system',
                                    'is_active': True
                                }
                            )
                
                created_roles.append(role)
        
        if created_roles:
            db.session.commit()
        
        return created_roles


# Export models and utilities for application use
__all__ = [
    'Role',
    'Permission', 
    'user_roles',
    'role_permissions',
    'AuditMixin',
    'RBACUtils',
    'db'
]