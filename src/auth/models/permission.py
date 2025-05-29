"""
Permission Model Implementation for Flask-Principal RBAC System

This module implements the Permission model with comprehensive Flask-Principal Need/Provide pattern
integration, resource-based access control, and dynamic authorization evaluation. The model provides
granular permission management with SQLAlchemy-backed persistence, enabling context-aware authorization
decisions and resource-level security controls throughout the Flask application.

Key Features:
- Flask-Principal Need/Provide pattern implementation with database persistence
- Resource-based permission management for fine-grained access control
- Dynamic permission evaluation for real-time authorization decisions
- Many-to-many role-permission relationships for flexible RBAC implementation
- Context-aware authorization with resource identifier mapping
- Performance optimization with compiled queries and relationship loading
- Comprehensive audit logging integration for security compliance
- Permission hierarchy and inheritance patterns for complex authorization scenarios

Technical Implementation:
- Flask-SQLAlchemy 3.1.1 declarative model with PostgreSQL 15.x backend
- Python 3.13.3 Enum classes for permission type definitions
- Integration with Flask-Principal Need/Provide authorization pattern
- Support for Flask authentication decorators and authorization flows
- Optimized database queries with relationship loading and indexing strategies

Security Architecture Integration:
- Granular permission management per Section 6.4.2.2
- Flask-Principal Need/Provide pattern implementation per Section 6.4.2.1
- Dynamic authorization evaluation per Section 6.4.2.2
- Resource identifier mapping per Section 6.4.2.2
- Many-to-many role-permission relationships per Section 6.4.2.1

Authors: Flask Migration Team
Version: 1.0.0
Created: 2024
License: Proprietary
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Set, Dict, Any, Union, Tuple
import uuid
import re

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Enum as SQLEnum,
    Index, UniqueConstraint, CheckConstraint, event, ForeignKey
)
from sqlalchemy.orm import relationship, validates, joinedload, selectinload
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql import func, and_, or_
from sqlalchemy.dialects.postgresql import UUID, JSONB

# Import base model and database instance
from ...models.base import BaseModel, db


class PermissionType(Enum):
    """
    Permission type enumeration for categorizing different kinds of permissions.
    
    This enum provides standardized permission categorization with guaranteed type safety
    and supports permission organization and management. Each permission type represents
    a different category of system access or functionality.
    
    Permission Categories:
    - SYSTEM: Core system permissions for administrative functions
    - RESOURCE: Resource-specific permissions for data access and manipulation
    - API: API endpoint permissions for service access control
    - UI: User interface permissions for frontend feature access
    - DATA: Data-level permissions for record access and operations
    - WORKFLOW: Business workflow permissions for process control
    - INTEGRATION: External integration permissions for service connections
    - CUSTOM: Custom permissions for application-specific functionality
    
    Integration:
    - Used with SQLAlchemy Enum for database storage and validation
    - Supports Flask-Principal Need creation for authorization patterns
    - Enables permission categorization and filtering capabilities
    - Provides type-safe permission management throughout the application
    """
    
    # Core system permissions
    SYSTEM = "system"
    
    # Resource-specific permissions
    RESOURCE = "resource"
    
    # API access permissions
    API = "api"
    
    # User interface permissions
    UI = "ui"
    
    # Data access permissions
    DATA = "data"
    
    # Workflow control permissions
    WORKFLOW = "workflow"
    
    # Integration permissions
    INTEGRATION = "integration"
    
    # Custom application permissions
    CUSTOM = "custom"
    
    def __str__(self) -> str:
        """String representation of the permission type."""
        return self.value
    
    def __repr__(self) -> str:
        """Developer representation of the permission type."""
        return f"PermissionType.{self.name}"


class PermissionScope(Enum):
    """
    Permission scope enumeration for defining the breadth of permission application.
    
    Scope Categories:
    - GLOBAL: Global permissions that apply system-wide
    - ORGANIZATION: Organization-level permissions for multi-tenant applications
    - RESOURCE: Resource-specific permissions for individual entities
    - USER: User-level permissions for personal data access
    - SESSION: Session-specific permissions for temporary access
    """
    
    GLOBAL = "global"
    ORGANIZATION = "organization"
    RESOURCE = "resource"
    USER = "user"
    SESSION = "session"
    
    def __str__(self) -> str:
        return self.value


class PermissionAction(Enum):
    """
    Standard CRUD actions for resource-based permissions.
    
    Action Types:
    - CREATE: Permission to create new resources
    - READ: Permission to read/view resources
    - UPDATE: Permission to modify existing resources
    - DELETE: Permission to remove resources
    - EXECUTE: Permission to execute operations or workflows
    - MANAGE: Permission to manage resource metadata and settings
    - ADMIN: Administrative permissions for complete resource control
    """
    
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"
    ADMIN = "admin"
    
    def __str__(self) -> str:
        return self.value


class PermissionStatus(Enum):
    """
    Permission status enumeration for permission lifecycle management.
    
    Status values:
    - ACTIVE: Permission is active and can be assigned
    - INACTIVE: Permission is temporarily disabled
    - DEPRECATED: Permission is deprecated but maintained for compatibility
    - ARCHIVED: Permission is archived for historical purposes
    """
    
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    
    def __str__(self) -> str:
        return self.value


class Permission(BaseModel):
    """
    Permission model implementing granular access control with Flask-Principal integration.
    
    This model provides the foundation for fine-grained authorization throughout the Flask
    application, supporting both Flask-Principal Need/Provide patterns and resource-based
    access control. The implementation enables context-aware authorization decisions with
    dynamic permission evaluation and comprehensive audit logging.
    
    Key Features:
    - Flask-Principal Need/Provide pattern with database persistence
    - Resource-based permission management for granular access control
    - Dynamic permission evaluation for real-time authorization decisions
    - Many-to-many role relationships through RolePermission association
    - Context-aware authorization with resource identifier mapping
    - Permission hierarchy and inheritance for complex scenarios
    - Performance optimization with compiled queries and caching
    - Comprehensive audit logging and security monitoring integration
    
    Database Schema:
    - Primary key: Integer auto-increment ID inherited from BaseModel
    - Unique constraints: name, resource_type, resource_id combination
    - Indexes: name, permission_type, scope, status for query optimization
    - Foreign key relationships: Roles (many-to-many), audit trail references
    - JSON metadata storage for flexible permission configuration
    
    Flask-Principal Integration:
    - Need/Provide pattern support for authorization decorators
    - Permission checking methods for real-time authorization
    - Principal identity integration for user context
    - Resource-specific need generation for granular control
    
    Security Features:
    - Resource identifier validation and sanitization
    - Permission name normalization and validation
    - Audit logging for all permission operations
    - Dynamic permission evaluation with context awareness
    - Integration with authentication and authorization systems
    
    Performance Optimization:
    - Compiled query patterns for repeated operations
    - Relationship loading strategies for efficient queries
    - Database indexes for common access patterns
    - Query result caching for static permission configurations
    """
    
    __tablename__ = 'permissions'
    
    # Table arguments for performance and integrity
    __table_args__ = (
        # Unique constraint ensuring no duplicate permissions per resource
        UniqueConstraint('name', 'resource_type', 'resource_id', 
                        name='uq_permissions_name_resource'),
        
        # Performance indexes for common query patterns
        Index('idx_permissions_name', 'name'),
        Index('idx_permissions_type', 'permission_type'),
        Index('idx_permissions_scope', 'scope'),
        Index('idx_permissions_status', 'status'),
        Index('idx_permissions_resource_type', 'resource_type'),
        Index('idx_permissions_active_lookup', 'name', 'is_active', 'status'),
        Index('idx_permissions_resource_lookup', 'resource_type', 'resource_id', 'is_active'),
        Index('idx_permissions_principal_need', 'name', 'resource_type', 'resource_id'),
        
        # Composite indexes for complex queries
        Index('idx_permissions_type_scope_status', 'permission_type', 'scope', 'status'),
        Index('idx_permissions_hierarchy', 'parent_permission_id', 'hierarchy_level'),
        
        # Check constraints for data integrity
        CheckConstraint('hierarchy_level >= 0', name='check_hierarchy_level_positive'),
        CheckConstraint("status IN ('active', 'inactive', 'deprecated', 'archived')", 
                       name='check_valid_status'),
        CheckConstraint("scope IN ('global', 'organization', 'resource', 'user', 'session')",
                       name='check_valid_scope'),
        
        # Database table configuration
        {
            'mysql_engine': 'InnoDB',
            'mysql_charset': 'utf8mb4',
            'postgresql_tablespace': 'permissions_tablespace',
            'comment': 'Permission definitions for Flask-Principal RBAC implementation'
        }
    )
    
    # UUID for external references and API interactions
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False,
                  comment='UUID for external permission references and API operations')
    
    # Core permission identification
    name = Column(String(255), nullable=False,
                  comment='Permission name following standard naming convention')
    
    display_name = Column(String(255), nullable=False,
                         comment='Human-readable permission name for UI display')
    
    description = Column(Text,
                        comment='Detailed description of permission purpose and scope')
    
    # Permission categorization
    permission_type = Column(SQLEnum(PermissionType), nullable=False, 
                           default=PermissionType.RESOURCE,
                           comment='Permission type for categorization and organization')
    
    scope = Column(SQLEnum(PermissionScope), nullable=False, 
                   default=PermissionScope.RESOURCE,
                   comment='Permission scope defining breadth of application')
    
    action = Column(SQLEnum(PermissionAction), nullable=True,
                   comment='Standard CRUD action for resource-based permissions')
    
    # Resource-specific fields for granular control
    resource_type = Column(String(100), nullable=True,
                          comment='Type of resource this permission applies to')
    
    resource_id = Column(String(255), nullable=True,
                        comment='Specific resource identifier for fine-grained control')
    
    resource_pattern = Column(String(500), nullable=True,
                            comment='Regex pattern for matching multiple resources')
    
    # Permission hierarchy and inheritance
    parent_permission_id = Column(Integer, ForeignKey('permissions.id', ondelete='SET NULL'),
                                 comment='Parent permission for hierarchical inheritance')
    
    hierarchy_level = Column(Integer, nullable=False, default=0,
                           comment='Numeric hierarchy level for inheritance ordering')
    
    # Permission lifecycle and status
    status = Column(SQLEnum(PermissionStatus), nullable=False, 
                   default=PermissionStatus.ACTIVE,
                   comment='Permission status for lifecycle management')
    
    is_active = Column(Boolean, nullable=False, default=True,
                      comment='Boolean flag for quick active/inactive filtering')
    
    is_system_permission = Column(Boolean, nullable=False, default=False,
                                comment='Flag indicating system-defined permissions')
    
    # Organization support for multi-tenant implementations
    organization_id = Column(Integer, ForeignKey('organizations.id', ondelete='CASCADE'),
                           comment='Organization association for multi-tenant permission management')
    
    # Permission metadata and configuration
    metadata = Column(JSONB, default=dict,
                     comment='JSON metadata for flexible permission configuration')
    
    conditions = Column(JSONB, default=dict,
                       comment='JSON conditions for dynamic permission evaluation')
    
    # Permission usage statistics
    assignment_count = Column(Integer, nullable=False, default=0,
                            comment='Cached count of active role assignments')
    
    last_used_at = Column(DateTime(timezone=True),
                         comment='Timestamp of most recent permission check')
    
    usage_count = Column(Integer, nullable=False, default=0,
                        comment='Total number of times permission has been checked')
    
    # Audit trail fields
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                       comment='User who created this permission')
    
    updated_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'),
                       comment='User who last updated this permission')
    
    # SQLAlchemy Relationships with Performance Optimization
    
    # Hierarchical permission relationships
    parent_permission = relationship('Permission', remote_side=[id], backref='child_permissions',
                                   lazy='select',
                                   comment='Parent permission for hierarchical inheritance')
    
    # Role assignments through association table
    role_assignments = relationship('RolePermission',
                                  back_populates='permission',
                                  lazy='select',
                                  cascade='all, delete-orphan',
                                  comment='Role assignments for this permission')
    
    # Direct role relationship for simplified queries
    roles = relationship('Role',
                        secondary='role_permissions',
                        secondaryjoin='and_(RolePermission.permission_id == Permission.id, '
                                     'RolePermission.is_active == True)',
                        backref=db.backref('permissions', lazy='select'),
                        lazy='select',
                        comment='Active roles assigned to this permission')
    
    # Audit relationships
    created_by_user = relationship('User', foreign_keys=[created_by],
                                 lazy='select',
                                 comment='User who created this permission')
    
    updated_by_user = relationship('User', foreign_keys=[updated_by],
                                 lazy='select',
                                 comment='User who last updated this permission')
    
    # Organization relationship for multi-tenant support
    organization = relationship('Organization', backref='permissions',
                              lazy='select',
                              comment='Organization owning this permission')
    
    # Hybrid Properties for Performance and Convenience
    
    @hybrid_property
    def full_name(self) -> str:
        """
        Get the full permission name including resource information.
        
        Returns:
            str: Full permission name with resource context
        """
        if self.resource_type and self.resource_id:
            return f"{self.name}:{self.resource_type}:{self.resource_id}"
        elif self.resource_type:
            return f"{self.name}:{self.resource_type}"
        else:
            return self.name
    
    @hybrid_property
    def is_resource_specific(self) -> bool:
        """
        Check if this permission is specific to a resource.
        
        Returns:
            bool: True if permission is resource-specific, False otherwise
        """
        return self.resource_type is not None or self.resource_id is not None
    
    @hybrid_property
    def can_be_assigned(self) -> bool:
        """
        Check if this permission can be assigned to roles.
        
        Returns:
            bool: True if permission can be assigned, False otherwise
        """
        return self.is_active and self.status == PermissionStatus.ACTIVE
    
    @hybrid_property
    def is_inherited(self) -> bool:
        """
        Check if this permission is inherited from a parent permission.
        
        Returns:
            bool: True if permission has a parent, False otherwise
        """
        return self.parent_permission_id is not None
    
    # Validation Methods
    
    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate and normalize permission name.
        
        Args:
            key: Field name being validated
            name: Permission name to validate
            
        Returns:
            str: Validated and normalized permission name
            
        Raises:
            ValueError: If name is invalid
        """
        if not name or not name.strip():
            raise ValueError("Permission name cannot be empty")
        
        # Normalize name - lowercase with underscores
        normalized_name = name.strip().lower().replace(' ', '_').replace('-', '_')
        
        # Validate naming convention
        if not re.match(r'^[a-z][a-z0-9_]*[a-z0-9]$', normalized_name):
            raise ValueError(
                "Permission name must start with a letter, contain only lowercase "
                "letters, numbers, and underscores, and end with a letter or number"
            )
        
        if len(normalized_name) > 255:
            raise ValueError("Permission name cannot exceed 255 characters")
        
        return normalized_name
    
    @validates('display_name')
    def validate_display_name(self, key: str, display_name: str) -> str:
        """
        Validate display name.
        
        Args:
            key: Field name being validated
            display_name: Display name to validate
            
        Returns:
            str: Validated display name
            
        Raises:
            ValueError: If display name is invalid
        """
        if not display_name or not display_name.strip():
            raise ValueError("Permission display name cannot be empty")
        
        normalized_display_name = display_name.strip()
        
        if len(normalized_display_name) > 255:
            raise ValueError("Permission display name cannot exceed 255 characters")
        
        return normalized_display_name
    
    @validates('resource_type')
    def validate_resource_type(self, key: str, resource_type: Optional[str]) -> Optional[str]:
        """
        Validate resource type.
        
        Args:
            key: Field name being validated
            resource_type: Resource type to validate
            
        Returns:
            Optional[str]: Validated resource type
            
        Raises:
            ValueError: If resource type is invalid
        """
        if resource_type is None:
            return None
        
        if not resource_type.strip():
            return None
        
        # Normalize resource type - lowercase
        normalized_type = resource_type.strip().lower()
        
        if not re.match(r'^[a-z][a-z0-9_]*[a-z0-9]$', normalized_type):
            raise ValueError(
                "Resource type must start with a letter and contain only "
                "lowercase letters, numbers, and underscores"
            )
        
        if len(normalized_type) > 100:
            raise ValueError("Resource type cannot exceed 100 characters")
        
        return normalized_type
    
    @validates('resource_id')
    def validate_resource_id(self, key: str, resource_id: Optional[str]) -> Optional[str]:
        """
        Validate resource ID.
        
        Args:
            key: Field name being validated
            resource_id: Resource ID to validate
            
        Returns:
            Optional[str]: Validated resource ID
            
        Raises:
            ValueError: If resource ID is invalid
        """
        if resource_id is None:
            return None
        
        if not resource_id.strip():
            return None
        
        normalized_id = resource_id.strip()
        
        if len(normalized_id) > 255:
            raise ValueError("Resource ID cannot exceed 255 characters")
        
        # Allow various ID formats (UUIDs, integers, alphanumeric)
        if not re.match(r'^[a-zA-Z0-9\-_:.]+$', normalized_id):
            raise ValueError(
                "Resource ID can only contain letters, numbers, hyphens, "
                "underscores, colons, and periods"
            )
        
        return normalized_id
    
    @validates('hierarchy_level')
    def validate_hierarchy_level(self, key: str, hierarchy_level: int) -> int:
        """
        Validate hierarchy level.
        
        Args:
            key: Field name being validated
            hierarchy_level: Hierarchy level to validate
            
        Returns:
            int: Validated hierarchy level
            
        Raises:
            ValueError: If hierarchy level is invalid
        """
        if hierarchy_level is not None and hierarchy_level < 0:
            raise ValueError("Hierarchy level must be non-negative")
        
        return hierarchy_level
    
    # Permission Management Methods
    
    def matches_resource(self, resource_type: Optional[str] = None, 
                        resource_id: Optional[str] = None) -> bool:
        """
        Check if this permission matches the given resource criteria.
        
        Args:
            resource_type: Resource type to match against
            resource_id: Resource ID to match against
            
        Returns:
            bool: True if permission matches the resource criteria
        """
        # Global permissions match everything
        if self.scope == PermissionScope.GLOBAL:
            return True
        
        # Check resource type match
        if self.resource_type is not None:
            if resource_type is None or self.resource_type != resource_type:
                return False
        
        # Check resource ID match
        if self.resource_id is not None:
            if resource_id is None:
                return False
            
            # Exact match
            if self.resource_id == resource_id:
                return True
            
            # Pattern match if resource_pattern is defined
            if self.resource_pattern:
                try:
                    import re
                    return bool(re.match(self.resource_pattern, resource_id))
                except re.error:
                    return False
            
            return False
        
        # If no resource_id specified in permission, it matches any resource of the type
        return True
    
    def check_conditions(self, context: Dict[str, Any]) -> bool:
        """
        Evaluate dynamic permission conditions against context.
        
        Args:
            context: Dictionary containing evaluation context
            
        Returns:
            bool: True if conditions are met, False otherwise
        """
        if not self.conditions:
            return True
        
        try:
            # Simple condition evaluation
            # In production, this could use a more sophisticated rule engine
            for condition_name, condition_value in self.conditions.items():
                context_value = context.get(condition_name)
                
                if isinstance(condition_value, dict):
                    # Handle comparison operators
                    if 'eq' in condition_value:
                        if context_value != condition_value['eq']:
                            return False
                    elif 'in' in condition_value:
                        if context_value not in condition_value['in']:
                            return False
                    elif 'gt' in condition_value:
                        if context_value is None or context_value <= condition_value['gt']:
                            return False
                    elif 'lt' in condition_value:
                        if context_value is None or context_value >= condition_value['lt']:
                            return False
                else:
                    # Direct value comparison
                    if context_value != condition_value:
                        return False
            
            return True
        
        except Exception:
            # If condition evaluation fails, deny permission for security
            return False
    
    def get_inherited_permissions(self) -> Set['Permission']:
        """
        Get all permissions inherited from parent permissions.
        
        Returns:
            Set[Permission]: Set of inherited permissions
        """
        inherited = set()
        
        if self.parent_permission:
            inherited.add(self.parent_permission)
            inherited.update(self.parent_permission.get_inherited_permissions())
        
        return inherited
    
    def can_inherit_from(self, other_permission: 'Permission') -> bool:
        """
        Check if this permission can inherit from another permission.
        
        Args:
            other_permission: Permission to check inheritance compatibility
            
        Returns:
            bool: True if inheritance is allowed, False otherwise
        """
        if not other_permission or other_permission.id == self.id:
            return False
        
        # Check hierarchy levels
        return self.hierarchy_level >= other_permission.hierarchy_level
    
    def assign_to_role(self, role: 'Role', granted_by: Optional['User'] = None) -> bool:
        """
        Assign this permission to a role.
        
        Args:
            role: Role to assign permission to
            granted_by: User who granted the permission
            
        Returns:
            bool: True if permission was assigned, False if already assigned
        """
        # Check if permission is already assigned
        from .role_permission import RolePermission
        
        existing_assignment = db.session.query(RolePermission).filter_by(
            role_id=role.id,
            permission_id=self.id,
            is_active=True
        ).first()
        
        if existing_assignment:
            return False
        
        # Create new assignment
        assignment = RolePermission(
            role_id=role.id,
            permission_id=self.id,
            granted_by_id=granted_by.id if granted_by else None,
            is_active=True,
            granted_at=datetime.now(timezone.utc)
        )
        
        db.session.add(assignment)
        
        # Update permission metadata
        self.assignment_count += 1
        self.updated_at = datetime.now(timezone.utc)
        if granted_by:
            self.updated_by = granted_by.id
        
        return True
    
    def revoke_from_role(self, role: 'Role', revoked_by: Optional['User'] = None) -> bool:
        """
        Revoke this permission from a role.
        
        Args:
            role: Role to revoke permission from
            revoked_by: User who revoked the permission
            
        Returns:
            bool: True if permission was revoked, False if not assigned
        """
        from .role_permission import RolePermission
        
        # Find active assignment
        assignment = db.session.query(RolePermission).filter_by(
            role_id=role.id,
            permission_id=self.id,
            is_active=True
        ).first()
        
        if not assignment:
            return False
        
        # Deactivate assignment
        assignment.is_active = False
        assignment.revoked_at = datetime.now(timezone.utc)
        assignment.revoked_by_id = revoked_by.id if revoked_by else None
        
        # Update permission metadata
        self.assignment_count = max(0, self.assignment_count - 1)
        self.updated_at = datetime.now(timezone.utc)
        if revoked_by:
            self.updated_by = revoked_by.id
        
        return True
    
    def update_usage_stats(self) -> None:
        """
        Update permission usage statistics.
        """
        self.usage_count += 1
        self.last_used_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    # Flask-Principal Integration Methods
    
    def to_principal_need(self) -> str:
        """
        Convert permission to Flask-Principal Need identifier.
        
        Returns:
            str: Principal need identifier for this permission
        """
        if self.resource_type and self.resource_id:
            return f"permission:{self.name}:{self.resource_type}:{self.resource_id}"
        elif self.resource_type:
            return f"permission:{self.name}:{self.resource_type}"
        else:
            return f"permission:{self.name}"
    
    @classmethod
    def from_principal_need(cls, need_str: str) -> Optional['Permission']:
        """
        Find permission from Flask-Principal Need string.
        
        Args:
            need_str: Principal need string to parse
            
        Returns:
            Optional[Permission]: Permission matching the need or None
        """
        if not need_str.startswith('permission:'):
            return None
        
        parts = need_str.split(':', 3)
        
        if len(parts) < 2:
            return None
        
        name = parts[1]
        resource_type = parts[2] if len(parts) > 2 else None
        resource_id = parts[3] if len(parts) > 3 else None
        
        query = cls.query.filter_by(
            name=name,
            is_active=True,
            status=PermissionStatus.ACTIVE
        )
        
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        else:
            query = query.filter(cls.resource_type.is_(None))
        
        if resource_id:
            query = query.filter_by(resource_id=resource_id)
        else:
            query = query.filter(cls.resource_id.is_(None))
        
        return query.first()
    
    def check_permission(self, user: 'User', context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if a user has this permission.
        
        Args:
            user: User to check permission for
            context: Optional context for dynamic evaluation
            
        Returns:
            bool: True if user has permission, False otherwise
        """
        if not self.can_be_assigned:
            return False
        
        # Check dynamic conditions if provided
        if context and not self.check_conditions(context):
            return False
        
        # Check if user has any role with this permission
        user_roles = user.get_active_roles() if hasattr(user, 'get_active_roles') else []
        
        for role in user_roles:
            if self in role.permissions:
                # Update usage statistics
                self.update_usage_stats()
                return True
        
        return False
    
    # Class Methods for Permission Management
    
    @classmethod
    def get_by_name(cls, name: str, resource_type: Optional[str] = None,
                   resource_id: Optional[str] = None) -> Optional['Permission']:
        """
        Get permission by name and optional resource criteria.
        
        Args:
            name: Permission name
            resource_type: Optional resource type
            resource_id: Optional resource ID
            
        Returns:
            Optional[Permission]: Permission instance or None
        """
        query = cls.query.filter_by(
            name=name,
            is_active=True,
            status=PermissionStatus.ACTIVE
        )
        
        if resource_type:
            query = query.filter_by(resource_type=resource_type)
        if resource_id:
            query = query.filter_by(resource_id=resource_id)
        
        return query.first()
    
    @classmethod
    def create_permission(cls, name: str, display_name: str, 
                         permission_type: PermissionType = PermissionType.RESOURCE,
                         scope: PermissionScope = PermissionScope.RESOURCE,
                         description: Optional[str] = None,
                         resource_type: Optional[str] = None,
                         resource_id: Optional[str] = None,
                         action: Optional[PermissionAction] = None,
                         created_by: Optional['User'] = None,
                         **kwargs) -> 'Permission':
        """
        Create a new permission with validation.
        
        Args:
            name: Permission name
            display_name: Human-readable display name
            permission_type: Type of permission
            scope: Permission scope
            description: Optional description
            resource_type: Optional resource type
            resource_id: Optional resource ID
            action: Optional action type
            created_by: User creating the permission
            **kwargs: Additional permission fields
            
        Returns:
            Permission: Created permission instance
        """
        permission = cls(
            name=name,
            display_name=display_name,
            permission_type=permission_type,
            scope=scope,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            created_by=created_by.id if created_by else None,
            **kwargs
        )
        
        db.session.add(permission)
        db.session.commit()
        
        return permission
    
    @classmethod
    def create_default_permissions(cls, organization_id: Optional[int] = None) -> List['Permission']:
        """
        Create default system permissions.
        
        Args:
            organization_id: Optional organization ID
            
        Returns:
            List[Permission]: List of created default permissions
        """
        default_permissions = [
            # System permissions
            {
                'name': 'system_admin',
                'display_name': 'System Administration',
                'description': 'Full system administration access',
                'permission_type': PermissionType.SYSTEM,
                'scope': PermissionScope.GLOBAL,
                'is_system_permission': True
            },
            {
                'name': 'user_management',
                'display_name': 'User Management',
                'description': 'Manage user accounts and profiles',
                'permission_type': PermissionType.SYSTEM,
                'scope': PermissionScope.ORGANIZATION,
                'is_system_permission': True
            },
            
            # Resource permissions
            {
                'name': 'create_resource',
                'display_name': 'Create Resources',
                'description': 'Create new resources',
                'permission_type': PermissionType.RESOURCE,
                'scope': PermissionScope.RESOURCE,
                'action': PermissionAction.CREATE,
                'is_system_permission': True
            },
            {
                'name': 'read_resource',
                'display_name': 'Read Resources',
                'description': 'View and read resources',
                'permission_type': PermissionType.RESOURCE,
                'scope': PermissionScope.RESOURCE,
                'action': PermissionAction.READ,
                'is_system_permission': True
            },
            {
                'name': 'update_resource',
                'display_name': 'Update Resources',
                'description': 'Modify existing resources',
                'permission_type': PermissionType.RESOURCE,
                'scope': PermissionScope.RESOURCE,
                'action': PermissionAction.UPDATE,
                'is_system_permission': True
            },
            {
                'name': 'delete_resource',
                'display_name': 'Delete Resources',
                'description': 'Remove resources',
                'permission_type': PermissionType.RESOURCE,
                'scope': PermissionScope.RESOURCE,
                'action': PermissionAction.DELETE,
                'is_system_permission': True
            },
            
            # API permissions
            {
                'name': 'api_access',
                'display_name': 'API Access',
                'description': 'Access to API endpoints',
                'permission_type': PermissionType.API,
                'scope': PermissionScope.GLOBAL,
                'is_system_permission': True
            },
        ]
        
        created_permissions = []
        
        for perm_data in default_permissions:
            # Check if permission already exists
            existing_permission = cls.get_by_name(perm_data['name'])
            
            if not existing_permission:
                permission = cls(
                    organization_id=organization_id,
                    **perm_data
                )
                
                db.session.add(permission)
                created_permissions.append(permission)
        
        db.session.commit()
        return created_permissions
    
    @classmethod
    def get_user_permissions(cls, user_id: int, resource_type: Optional[str] = None,
                           resource_id: Optional[str] = None) -> List['Permission']:
        """
        Get all permissions for a specific user.
        
        Args:
            user_id: User ID to get permissions for
            resource_type: Optional resource type filter
            resource_id: Optional resource ID filter
            
        Returns:
            List[Permission]: List of permissions for the user
        """
        from .role import Role
        from .user_role_assignment import UserRoleAssignment
        from .role_permission import RolePermission
        
        # Query for user permissions through roles
        query = (
            db.session.query(cls)
            .join(RolePermission, cls.id == RolePermission.permission_id)
            .join(Role, RolePermission.role_id == Role.id)
            .join(UserRoleAssignment, Role.id == UserRoleAssignment.role_id)
            .filter(
                UserRoleAssignment.user_id == user_id,
                UserRoleAssignment.is_active == True,
                Role.is_active == True,
                RolePermission.is_active == True,
                cls.is_active == True,
                cls.status == PermissionStatus.ACTIVE
            )
        )
        
        if resource_type:
            query = query.filter(
                or_(cls.resource_type == resource_type, cls.resource_type.is_(None))
            )
        
        if resource_id:
            query = query.filter(
                or_(cls.resource_id == resource_id, cls.resource_id.is_(None))
            )
        
        return query.distinct().all()
    
    @classmethod
    def get_permissions_by_type(cls, permission_type: PermissionType,
                              organization_id: Optional[int] = None) -> List['Permission']:
        """
        Get all permissions of a specific type.
        
        Args:
            permission_type: Type of permissions to retrieve
            organization_id: Optional organization filter
            
        Returns:
            List[Permission]: List of permissions of the specified type
        """
        query = cls.query.filter_by(
            permission_type=permission_type,
            is_active=True,
            status=PermissionStatus.ACTIVE
        )
        
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        
        return query.order_by(cls.name).all()
    
    @classmethod
    def search_permissions(cls, search_term: str, limit: int = 50) -> List['Permission']:
        """
        Search permissions by name or description.
        
        Args:
            search_term: Term to search for
            limit: Maximum number of results
            
        Returns:
            List[Permission]: List of matching permissions
        """
        search_pattern = f"%{search_term.lower()}%"
        
        return (
            cls.query.filter(
                and_(
                    cls.is_active == True,
                    cls.status == PermissionStatus.ACTIVE,
                    or_(
                        cls.name.ilike(search_pattern),
                        cls.display_name.ilike(search_pattern),
                        cls.description.ilike(search_pattern)
                    )
                )
            )
            .order_by(cls.name)
            .limit(limit)
            .all()
        )
    
    # Audit and Logging Methods
    
    def log_permission_activity(self, activity_type: str, details: Dict[str, Any],
                              user: Optional['User'] = None) -> None:
        """
        Log permission-related activity for audit trail.
        
        Args:
            activity_type: Type of activity
            details: Dictionary of activity details
            user: User who performed the activity
        """
        from .authentication_log import AuthenticationLog
        
        log_entry = AuthenticationLog(
            user_id=user.id if user else None,
            activity_type=f"permission_{activity_type}",
            details={
                'permission_id': self.id,
                'permission_name': self.name,
                'permission_type': self.permission_type.value,
                'resource_type': self.resource_type,
                'resource_id': self.resource_id,
                **details
            },
            ip_address=details.get('ip_address'),
            user_agent=details.get('user_agent'),
            session_id=details.get('session_id')
        )
        
        db.session.add(log_entry)
    
    # String Representation and Debugging
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        if self.resource_type and self.resource_id:
            return f"{self.display_name} ({self.name}:{self.resource_type}:{self.resource_id})"
        elif self.resource_type:
            return f"{self.display_name} ({self.name}:{self.resource_type})"
        else:
            return f"{self.display_name} ({self.name})"
    
    def __repr__(self) -> str:
        """Developer string representation."""
        return (f"<Permission(id={self.id}, name='{self.name}', "
                f"type={self.permission_type.value}, scope={self.scope.value})>")
    
    # Serialization Methods for API Responses
    
    def to_dict(self, include_relationships: bool = False) -> Dict[str, Any]:
        """
        Convert permission to dictionary for API responses.
        
        Args:
            include_relationships: Whether to include relationship data
            
        Returns:
            Dict[str, Any]: Permission data as dictionary
        """
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'name': self.name,
            'display_name': self.display_name,
            'description': self.description,
            'permission_type': self.permission_type.value,
            'scope': self.scope.value,
            'action': self.action.value if self.action else None,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'resource_pattern': self.resource_pattern,
            'hierarchy_level': self.hierarchy_level,
            'status': self.status.value,
            'is_active': self.is_active,
            'is_system_permission': self.is_system_permission,
            'assignment_count': self.assignment_count,
            'usage_count': self.usage_count,
            'metadata': self.metadata,
            'conditions': self.conditions,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'full_name': self.full_name,
            'principal_need': self.to_principal_need()
        }
        
        if include_relationships:
            data.update({
                'roles': [r.to_dict() for r in self.roles],
                'parent_permission': self.parent_permission.to_dict() if self.parent_permission else None,
                'child_permissions': [p.to_dict() for p in self.child_permissions if p.is_active],
                'inherited_permissions': [p.to_dict() for p in self.get_inherited_permissions()]
            })
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Permission':
        """
        Create permission instance from dictionary data.
        
        Args:
            data: Dictionary containing permission data
            
        Returns:
            Permission: New permission instance
        """
        # Extract enum values
        permission_type = PermissionType(data.get('permission_type', PermissionType.RESOURCE.value))
        scope = PermissionScope(data.get('scope', PermissionScope.RESOURCE.value))
        status = PermissionStatus(data.get('status', PermissionStatus.ACTIVE.value))
        action = PermissionAction(data['action']) if data.get('action') else None
        
        return cls(
            name=data.get('name'),
            display_name=data.get('display_name'),
            description=data.get('description'),
            permission_type=permission_type,
            scope=scope,
            action=action,
            resource_type=data.get('resource_type'),
            resource_id=data.get('resource_id'),
            resource_pattern=data.get('resource_pattern'),
            hierarchy_level=data.get('hierarchy_level', 0),
            parent_permission_id=data.get('parent_permission_id'),
            organization_id=data.get('organization_id'),
            status=status,
            is_active=data.get('is_active', True),
            is_system_permission=data.get('is_system_permission', False),
            metadata=data.get('metadata', {}),
            conditions=data.get('conditions', {})
        )


# SQLAlchemy Event Listeners for Audit and Performance

@event.listens_for(Permission, 'before_insert')
def permission_before_insert(mapper, connection, target):
    """
    Event listener for permission creation.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Permission instance being inserted
    """
    # Ensure UUID is set
    if target.uuid is None:
        target.uuid = uuid.uuid4()
    
    # Set default display name if not provided
    if not target.display_name and target.name:
        target.display_name = target.name.replace('_', ' ').title()
    
    # Set audit timestamps
    now = datetime.now(timezone.utc)
    target.created_at = now
    target.updated_at = now


@event.listens_for(Permission, 'before_update')
def permission_before_update(mapper, connection, target):
    """
    Event listener for permission updates.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Permission instance being updated
    """
    # Update timestamp
    target.updated_at = datetime.now(timezone.utc)


@event.listens_for(Permission, 'after_insert')
def permission_after_insert(mapper, connection, target):
    """
    Event listener after permission creation.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Permission instance that was inserted
    """
    # Log permission creation for audit trail
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        f"Permission created: ID={target.id}, name='{target.name}', "
        f"type={target.permission_type.value}, organization={target.organization_id}"
    )


@event.listens_for(Permission, 'after_update')
def permission_after_update(mapper, connection, target):
    """
    Event listener after permission updates.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Permission instance that was updated
    """
    # Log permission updates for audit trail
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        f"Permission updated: ID={target.id}, name='{target.name}', "
        f"type={target.permission_type.value}"
    )


# Performance Optimization: Compiled Queries for Common Operations

def get_active_permissions_query():
    """Compiled query for active permissions."""
    return (
        db.session.query(Permission)
        .filter(Permission.is_active == True, Permission.status == PermissionStatus.ACTIVE)
        .order_by(Permission.name.asc())
    )


def get_user_permissions_query(user_id: int):
    """Compiled query for user permissions."""
    from .role import Role
    from .user_role_assignment import UserRoleAssignment
    from .role_permission import RolePermission
    
    return (
        db.session.query(Permission)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(Role, RolePermission.role_id == Role.id)
        .join(UserRoleAssignment, Role.id == UserRoleAssignment.role_id)
        .filter(
            UserRoleAssignment.user_id == user_id,
            UserRoleAssignment.is_active == True,
            Role.is_active == True,
            RolePermission.is_active == True,
            Permission.is_active == True,
            Permission.status == PermissionStatus.ACTIVE
        )
        .distinct()
        .options(selectinload(Permission.roles))
    )


def get_permissions_by_resource_query(resource_type: str, resource_id: Optional[str] = None):
    """Compiled query for resource-specific permissions."""
    query = (
        db.session.query(Permission)
        .filter(
            Permission.is_active == True,
            Permission.status == PermissionStatus.ACTIVE,
            or_(
                Permission.resource_type == resource_type,
                Permission.resource_type.is_(None)
            )
        )
    )
    
    if resource_id:
        query = query.filter(
            or_(
                Permission.resource_id == resource_id,
                Permission.resource_id.is_(None)
            )
        )
    
    return query.order_by(Permission.hierarchy_level.desc(), Permission.name.asc())


# Export all public components
__all__ = [
    'Permission',
    'PermissionType',
    'PermissionScope', 
    'PermissionAction',
    'PermissionStatus',
    'get_active_permissions_query',
    'get_user_permissions_query',
    'get_permissions_by_resource_query'
]