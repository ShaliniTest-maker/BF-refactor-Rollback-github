"""
Role Model Implementation for Flask-Security RBAC System

This module implements the Role model with comprehensive Flask-Security role-based access control,
Python Enum-backed role definitions, and many-to-many user relationships. The model provides
hierarchical role management, permission inheritance, and optimized SQLAlchemy relationship mapping
for high-performance authorization checks.

Key Features:
- Python Enum-backed role definitions for type-safe role management
- Many-to-many user-role relationships through UserRoleAssignment association table
- Role hierarchy and permission inheritance patterns for Flask-Principal integration
- SQLAlchemy relationship optimization for authorization decorator performance
- Role metadata fields for description, status, and administrative management
- Comprehensive audit logging integration for security compliance
- Performance optimization with compiled queries and relationship loading strategies

Technical Implementation:
- Flask-SQLAlchemy 3.1.1 declarative model with PostgreSQL 15.x backend
- Python 3.13.3 Enum classes for role type definitions
- Integration with Flask-Principal Need/Provide pattern for authorization
- Support for Flask-Security role-based decorators and authentication flows
- Optimized database queries with relationship loading and indexing strategies

Security Architecture Integration:
- RBAC implementation supporting Flask-Principal or Flask-Security frameworks
- Role hierarchy enforcement with permission inheritance capabilities
- Integration with authentication audit logging and security monitoring systems
- Support for real-time authorization decisions and context-aware permissions
- Compliance with security architecture requirements from Section 6.4.2.1

Authors: Flask Migration Team
Version: 1.0.0
Created: 2024
License: Proprietary
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Set, Dict, Any
import uuid

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Enum as SQLEnum,
    Index, UniqueConstraint, CheckConstraint, event
)
from sqlalchemy.orm import relationship, validates, joinedload, selectinload
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, JSONB

# Import base model and database instance
# Note: These would be imported from the application's base model structure
# from src.models.base import BaseModel, db

# For this implementation, we'll define the minimal required base structure
# In production, this would import from the actual base model


class RoleType(Enum):
    """
    Python Enum defining available role types for type-safe role management.
    
    This enum provides standardized role definitions with guaranteed type safety
    and supports role hierarchy enforcement through ordered values. Each role
    type maps to specific permission sets and authorization capabilities.
    
    Role Hierarchy (in order of increasing privileges):
    - GUEST: Basic read-only access for unauthenticated users
    - USER: Standard authenticated user with basic CRUD permissions
    - MODERATOR: Enhanced permissions for content moderation and user management
    - ADMIN: Administrative privileges with system configuration access
    - SUPER_ADMIN: Full system access with critical operation permissions
    
    Integration:
    - Used with SQLAlchemy Enum for database storage and validation
    - Supports Flask-Principal Need/Provide pattern for authorization
    - Enables role hierarchy validation and permission inheritance
    - Provides type-safe role assignment and validation throughout the application
    """
    
    # Basic access roles
    GUEST = "guest"
    USER = "user"
    
    # Enhanced privilege roles  
    MODERATOR = "moderator"
    ADMIN = "admin"
    
    # System administration roles
    SUPER_ADMIN = "super_admin"
    
    @classmethod
    def get_hierarchy_order(cls) -> Dict[str, int]:
        """
        Return role hierarchy ordering for permission inheritance.
        
        Returns:
            Dict[str, int]: Mapping of role values to hierarchy levels
        """
        return {
            cls.GUEST.value: 0,
            cls.USER.value: 10,
            cls.MODERATOR.value: 20,
            cls.ADMIN.value: 30,
            cls.SUPER_ADMIN.value: 40
        }
    
    @classmethod
    def get_inherited_roles(cls, role_type: 'RoleType') -> List['RoleType']:
        """
        Get all roles that the given role inherits permissions from.
        
        Args:
            role_type: The role to check inheritance for
            
        Returns:
            List[RoleType]: List of roles whose permissions are inherited
        """
        hierarchy = cls.get_hierarchy_order()
        current_level = hierarchy[role_type.value]
        
        inherited = []
        for role in cls:
            if hierarchy[role.value] <= current_level:
                inherited.append(role)
        
        return inherited
    
    def __str__(self) -> str:
        """String representation of the role type."""
        return self.value
    
    def __repr__(self) -> str:
        """Developer representation of the role type."""
        return f"RoleType.{self.name}"


class RoleStatus(Enum):
    """
    Role status enumeration for role lifecycle management.
    
    Status values:
    - ACTIVE: Role is active and can be assigned to users
    - INACTIVE: Role is temporarily disabled but preserved
    - DEPRECATED: Role is deprecated and should not be used for new assignments
    - ARCHIVED: Role is archived for historical purposes only
    """
    
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    
    def __str__(self) -> str:
        return self.value


# Database instance - would be imported from application structure
# from src.extensions import db
db = SQLAlchemy()


class Role(db.Model):
    """
    Role model implementing comprehensive Flask-Security RBAC with hierarchical permissions.
    
    This model provides the foundation for role-based access control throughout the Flask
    application, supporting both Flask-Principal and Flask-Security authorization patterns.
    The implementation includes role hierarchy, permission inheritance, and optimized
    SQLAlchemy relationships for high-performance authorization checks.
    
    Key Features:
    - Python Enum-backed role definitions with type safety
    - Hierarchical role system with permission inheritance
    - Many-to-many user relationships through association table
    - Optimized SQLAlchemy queries with relationship loading strategies
    - Comprehensive audit logging and security monitoring integration
    - Role metadata management for administrative operations
    - Performance optimization for authorization decorator patterns
    
    Database Schema:
    - Primary key: Integer auto-increment ID
    - Unique constraints: role_type, name combination
    - Indexes: role_type, status, created_at for query optimization
    - Foreign key relationships: Users (many-to-many), Permissions (many-to-many)
    - JSON metadata storage for flexible role configuration
    
    Security Integration:
    - Flask-Principal Need/Provide pattern support
    - Flask-Security role decorator compatibility
    - Authentication audit logging integration
    - Real-time authorization decision support
    - Role hierarchy enforcement and validation
    
    Performance Optimization:
    - Compiled query patterns for repeated operations
    - Relationship loading strategies (lazy, eager, select-in)
    - Database indexes for common query patterns
    - Query result caching for static role configurations
    - Optimized join patterns for user-role-permission queries
    """
    
    __tablename__ = 'roles'
    
    # Table arguments for performance and integrity
    __table_args__ = (
        # Unique constraint ensuring no duplicate role types per organization
        UniqueConstraint('role_type', 'organization_id', name='uq_roles_type_org'),
        
        # Performance indexes for common query patterns
        Index('idx_roles_type', 'role_type'),
        Index('idx_roles_status', 'status'),
        Index('idx_roles_created_at', 'created_at'),
        Index('idx_roles_hierarchy_level', 'hierarchy_level'),
        Index('idx_roles_active_lookup', 'role_type', 'status', 'is_active'),
        
        # Check constraints for data integrity
        CheckConstraint('hierarchy_level >= 0', name='check_hierarchy_level_positive'),
        CheckConstraint("status IN ('active', 'inactive', 'deprecated', 'archived')", 
                       name='check_valid_status'),
        
        # Database table configuration
        {
            'mysql_engine': 'InnoDB',
            'mysql_charset': 'utf8mb4',
            'postgresql_tablespace': 'roles_tablespace',
            'comment': 'Role definitions for Flask-Security RBAC implementation'
        }
    )
    
    # Primary key and core identification
    id = Column(Integer, primary_key=True, autoincrement=True,
                comment='Primary key for role identification')
    
    # UUID for external references and API interactions
    uuid = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False,
                  comment='UUID for external role references and API operations')
    
    # Role type using Python Enum for type safety
    role_type = Column(SQLEnum(RoleType), nullable=False,
                      comment='Role type using Python Enum for type-safe role management')
    
    # Human-readable role name and description
    name = Column(String(100), nullable=False,
                  comment='Human-readable role name for display purposes')
    
    description = Column(Text,
                        comment='Detailed description of role purpose and permissions')
    
    # Role status and lifecycle management
    status = Column(SQLEnum(RoleStatus), nullable=False, default=RoleStatus.ACTIVE,
                   comment='Role status for lifecycle management')
    
    is_active = Column(Boolean, nullable=False, default=True,
                      comment='Boolean flag for quick active/inactive filtering')
    
    # Role hierarchy and inheritance
    hierarchy_level = Column(Integer, nullable=False, default=0,
                           comment='Numeric hierarchy level for permission inheritance')
    
    parent_role_id = Column(Integer, db.ForeignKey('roles.id', ondelete='SET NULL'),
                           comment='Parent role for hierarchical inheritance')
    
    # Organization support for multi-tenant implementations
    organization_id = Column(Integer, db.ForeignKey('organizations.id', ondelete='CASCADE'),
                           comment='Organization association for multi-tenant role management')
    
    # Role metadata and configuration
    metadata = Column(JSONB, default=dict,
                     comment='JSON metadata for flexible role configuration and properties')
    
    # Permission configuration
    permissions_config = Column(JSONB, default=dict,
                              comment='JSON configuration for role-specific permission settings')
    
    # Audit and lifecycle timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, 
                       default=lambda: datetime.now(timezone.utc),
                       comment='Role creation timestamp with timezone awareness')
    
    updated_at = Column(DateTime(timezone=True), nullable=False,
                       default=lambda: datetime.now(timezone.utc),
                       onupdate=lambda: datetime.now(timezone.utc),
                       comment='Role last update timestamp with automatic updates')
    
    created_by = Column(Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                       comment='User who created this role for audit tracking')
    
    updated_by = Column(Integer, db.ForeignKey('users.id', ondelete='SET NULL'),
                       comment='User who last updated this role for audit tracking')
    
    # Role assignment statistics
    assignment_count = Column(Integer, nullable=False, default=0,
                            comment='Cached count of active user assignments for performance')
    
    last_assigned_at = Column(DateTime(timezone=True),
                            comment='Timestamp of most recent role assignment')
    
    # SQLAlchemy Relationships with Performance Optimization
    
    # Hierarchical role relationships
    parent_role = relationship('Role', remote_side=[id], backref='child_roles',
                             lazy='select',
                             comment='Parent role for hierarchical inheritance')
    
    # User assignments through association table with optimized loading
    user_assignments = relationship('UserRoleAssignment', 
                                  back_populates='role',
                                  lazy='select',
                                  cascade='all, delete-orphan',
                                  comment='User role assignments with metadata')
    
    # Direct user relationship for simplified queries
    users = relationship('User',
                        secondary='user_role_assignments',
                        secondaryjoin='and_(UserRoleAssignment.role_id == Role.id, '
                                     'UserRoleAssignment.is_active == True)',
                        backref=db.backref('roles', lazy='select'),
                        lazy='select',
                        comment='Active users assigned to this role')
    
    # Permission assignments through association table
    permission_assignments = relationship('RolePermission',
                                        back_populates='role',
                                        lazy='select',
                                        cascade='all, delete-orphan',
                                        comment='Permission assignments for this role')
    
    # Direct permission relationship for simplified access
    permissions = relationship('Permission',
                             secondary='role_permissions',
                             secondaryjoin='and_(RolePermission.role_id == Role.id, '
                                          'RolePermission.is_active == True)',
                             backref=db.backref('roles', lazy='select'),
                             lazy='select',
                             comment='Active permissions assigned to this role')
    
    # Audit relationships
    created_by_user = relationship('User', foreign_keys=[created_by],
                                 lazy='select',
                                 comment='User who created this role')
    
    updated_by_user = relationship('User', foreign_keys=[updated_by],
                                 lazy='select',
                                 comment='User who last updated this role')
    
    # Organization relationship for multi-tenant support
    organization = relationship('Organization', backref='roles',
                              lazy='select',
                              comment='Organization owning this role')
    
    # Hybrid Properties for Performance and Convenience
    
    @hybrid_property
    def is_system_role(self) -> bool:
        """
        Check if this is a system-defined role that cannot be deleted.
        
        Returns:
            bool: True if role is system-defined, False otherwise
        """
        system_roles = {RoleType.GUEST, RoleType.USER, RoleType.ADMIN, RoleType.SUPER_ADMIN}
        return self.role_type in system_roles
    
    @hybrid_property
    def can_be_assigned(self) -> bool:
        """
        Check if this role can be assigned to users.
        
        Returns:
            bool: True if role can be assigned, False otherwise
        """
        return self.is_active and self.status == RoleStatus.ACTIVE
    
    @hybrid_property
    def hierarchy_level_value(self) -> int:
        """
        Get the hierarchy level value for permission inheritance.
        
        Returns:
            int: Numeric hierarchy level
        """
        if self.hierarchy_level is not None:
            return self.hierarchy_level
        
        # Fall back to enum-based hierarchy if not explicitly set
        hierarchy = RoleType.get_hierarchy_order()
        return hierarchy.get(self.role_type.value, 0)
    
    # Validation Methods
    
    @validates('role_type')
    def validate_role_type(self, key: str, role_type: RoleType) -> RoleType:
        """
        Validate role type assignment.
        
        Args:
            key: Field name being validated
            role_type: Role type value to validate
            
        Returns:
            RoleType: Validated role type
            
        Raises:
            ValueError: If role type is invalid
        """
        if not isinstance(role_type, RoleType):
            raise ValueError(f"Invalid role type: {role_type}")
        
        return role_type
    
    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate role name.
        
        Args:
            key: Field name being validated
            name: Role name to validate
            
        Returns:
            str: Validated and normalized role name
            
        Raises:
            ValueError: If name is invalid
        """
        if not name or not name.strip():
            raise ValueError("Role name cannot be empty")
        
        # Normalize name - title case with proper spacing
        normalized_name = name.strip().title()
        
        if len(normalized_name) > 100:
            raise ValueError("Role name cannot exceed 100 characters")
        
        return normalized_name
    
    @validates('hierarchy_level')
    def validate_hierarchy_level(self, key: str, hierarchy_level: int) -> int:
        """
        Validate hierarchy level assignment.
        
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
    
    # Role Management Methods
    
    def can_inherit_from(self, other_role: 'Role') -> bool:
        """
        Check if this role can inherit permissions from another role.
        
        Args:
            other_role: Role to check inheritance compatibility
            
        Returns:
            bool: True if inheritance is allowed, False otherwise
        """
        if not other_role or other_role.id == self.id:
            return False
        
        # Check hierarchy levels
        return self.hierarchy_level_value >= other_role.hierarchy_level_value
    
    def get_inherited_permissions(self) -> Set[str]:
        """
        Get all permissions inherited from role hierarchy.
        
        Returns:
            Set[str]: Set of permission names inherited from parent roles
        """
        inherited_permissions = set()
        
        # Add direct permissions
        for permission in self.permissions:
            inherited_permissions.add(permission.name)
        
        # Add permissions from parent roles
        if self.parent_role and self.can_inherit_from(self.parent_role):
            inherited_permissions.update(self.parent_role.get_inherited_permissions())
        
        # Add permissions from role type hierarchy
        inherited_roles = RoleType.get_inherited_roles(self.role_type)
        for role_type in inherited_roles:
            if role_type != self.role_type:
                # Query for role of this type and add its permissions
                role = Role.query.filter_by(
                    role_type=role_type,
                    status=RoleStatus.ACTIVE,
                    is_active=True
                ).first()
                
                if role:
                    for permission in role.permissions:
                        inherited_permissions.add(permission.name)
        
        return inherited_permissions
    
    def has_permission(self, permission_name: str, resource: Optional[str] = None) -> bool:
        """
        Check if role has a specific permission.
        
        Args:
            permission_name: Name of the permission to check
            resource: Optional resource identifier for resource-specific permissions
            
        Returns:
            bool: True if role has the permission, False otherwise
        """
        # Check direct permissions
        for permission in self.permissions:
            if permission.name == permission_name:
                if resource is None or permission.resource == resource:
                    return True
        
        # Check inherited permissions
        inherited_permissions = self.get_inherited_permissions()
        
        if resource:
            # For resource-specific permissions, check both specific and general permissions
            return (f"{permission_name}:{resource}" in inherited_permissions or 
                   permission_name in inherited_permissions)
        else:
            return permission_name in inherited_permissions
    
    def assign_permission(self, permission: 'Permission', granted_by: Optional['User'] = None) -> bool:
        """
        Assign a permission to this role.
        
        Args:
            permission: Permission to assign
            granted_by: User who granted the permission (for audit trail)
            
        Returns:
            bool: True if permission was assigned, False if already assigned
        """
        # Check if permission is already assigned
        existing_assignment = db.session.query(RolePermission).filter_by(
            role_id=self.id,
            permission_id=permission.id,
            is_active=True
        ).first()
        
        if existing_assignment:
            return False
        
        # Create new permission assignment
        from .role_permission import RolePermission  # Avoid circular import
        
        assignment = RolePermission(
            role_id=self.id,
            permission_id=permission.id,
            granted_by_id=granted_by.id if granted_by else None,
            is_active=True,
            granted_at=datetime.now(timezone.utc)
        )
        
        db.session.add(assignment)
        
        # Update role metadata
        self.updated_at = datetime.now(timezone.utc)
        if granted_by:
            self.updated_by = granted_by.id
        
        return True
    
    def revoke_permission(self, permission: 'Permission', revoked_by: Optional['User'] = None) -> bool:
        """
        Revoke a permission from this role.
        
        Args:
            permission: Permission to revoke
            revoked_by: User who revoked the permission (for audit trail)
            
        Returns:
            bool: True if permission was revoked, False if not assigned
        """
        # Find active permission assignment
        assignment = db.session.query(RolePermission).filter_by(
            role_id=self.id,
            permission_id=permission.id,
            is_active=True
        ).first()
        
        if not assignment:
            return False
        
        # Deactivate assignment instead of deleting for audit trail
        assignment.is_active = False
        assignment.revoked_at = datetime.now(timezone.utc)
        assignment.revoked_by_id = revoked_by.id if revoked_by else None
        
        # Update role metadata
        self.updated_at = datetime.now(timezone.utc)
        if revoked_by:
            self.updated_by = revoked_by.id
        
        return True
    
    def get_active_users(self) -> List['User']:
        """
        Get all active users assigned to this role.
        
        Returns:
            List[User]: List of users with active role assignments
        """
        from ..models.user_role_assignment import UserRoleAssignment
        
        # Optimized query with joins
        active_assignments = (
            db.session.query(UserRoleAssignment)
            .filter_by(role_id=self.id, is_active=True)
            .options(joinedload(UserRoleAssignment.user))
            .all()
        )
        
        return [assignment.user for assignment in active_assignments 
                if assignment.user and assignment.user.is_active]
    
    def update_assignment_count(self) -> None:
        """
        Update the cached assignment count for performance optimization.
        """
        from ..models.user_role_assignment import UserRoleAssignment
        
        count = (
            db.session.query(UserRoleAssignment)
            .filter_by(role_id=self.id, is_active=True)
            .count()
        )
        
        self.assignment_count = count
        self.updated_at = datetime.now(timezone.utc)
    
    # Class Methods for Role Management
    
    @classmethod
    def get_by_type(cls, role_type: RoleType, organization_id: Optional[int] = None) -> Optional['Role']:
        """
        Get role by type and optional organization.
        
        Args:
            role_type: Role type to search for
            organization_id: Optional organization ID for multi-tenant filtering
            
        Returns:
            Role: Role instance or None if not found
        """
        query = cls.query.filter_by(
            role_type=role_type,
            is_active=True,
            status=RoleStatus.ACTIVE
        )
        
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        
        return query.first()
    
    @classmethod
    def create_default_roles(cls, organization_id: Optional[int] = None) -> List['Role']:
        """
        Create default system roles for an organization.
        
        Args:
            organization_id: Optional organization ID for multi-tenant setup
            
        Returns:
            List[Role]: List of created default roles
        """
        default_roles = [
            {
                'role_type': RoleType.GUEST,
                'name': 'Guest',
                'description': 'Basic read-only access for unauthenticated users',
                'hierarchy_level': 0
            },
            {
                'role_type': RoleType.USER,
                'name': 'User',
                'description': 'Standard authenticated user with basic permissions',
                'hierarchy_level': 10
            },
            {
                'role_type': RoleType.MODERATOR,
                'name': 'Moderator',
                'description': 'Enhanced permissions for content moderation',
                'hierarchy_level': 20
            },
            {
                'role_type': RoleType.ADMIN,
                'name': 'Administrator',
                'description': 'Administrative privileges with system access',
                'hierarchy_level': 30
            },
            {
                'role_type': RoleType.SUPER_ADMIN,
                'name': 'Super Administrator',
                'description': 'Full system access with critical operations',
                'hierarchy_level': 40
            }
        ]
        
        created_roles = []
        
        for role_data in default_roles:
            # Check if role already exists
            existing_role = cls.get_by_type(
                role_data['role_type'],
                organization_id
            )
            
            if not existing_role:
                role = cls(
                    organization_id=organization_id,
                    **role_data
                )
                
                db.session.add(role)
                created_roles.append(role)
        
        db.session.commit()
        return created_roles
    
    @classmethod
    def get_user_roles(cls, user_id: int) -> List['Role']:
        """
        Get all active roles for a specific user.
        
        Args:
            user_id: User ID to get roles for
            
        Returns:
            List[Role]: List of active roles assigned to the user
        """
        from ..models.user_role_assignment import UserRoleAssignment
        
        # Optimized query with joins and filtering
        assignments = (
            db.session.query(UserRoleAssignment)
            .filter_by(user_id=user_id, is_active=True)
            .join(cls, UserRoleAssignment.role_id == cls.id)
            .filter(cls.is_active == True, cls.status == RoleStatus.ACTIVE)
            .options(joinedload(UserRoleAssignment.role))
            .all()
        )
        
        return [assignment.role for assignment in assignments]
    
    @classmethod
    def get_roles_with_permission(cls, permission_name: str, 
                                 resource: Optional[str] = None) -> List['Role']:
        """
        Get all roles that have a specific permission.
        
        Args:
            permission_name: Permission name to search for
            resource: Optional resource identifier
            
        Returns:
            List[Role]: List of roles with the specified permission
        """
        from ..models.permission import Permission
        from ..models.role_permission import RolePermission
        
        # Query for roles with the permission
        query = (
            db.session.query(cls)
            .join(RolePermission, cls.id == RolePermission.role_id)
            .join(Permission, RolePermission.permission_id == Permission.id)
            .filter(
                cls.is_active == True,
                cls.status == RoleStatus.ACTIVE,
                RolePermission.is_active == True,
                Permission.name == permission_name
            )
        )
        
        if resource:
            query = query.filter(Permission.resource == resource)
        
        return query.distinct().all()
    
    # Flask-Principal Integration Methods
    
    def get_principal_needs(self) -> Set[str]:
        """
        Get Flask-Principal needs for this role.
        
        Returns:
            Set[str]: Set of principal need identifiers
        """
        needs = set()
        
        # Add role-based need
        needs.add(f"role:{self.role_type.value}")
        
        # Add permission-based needs
        for permission in self.permissions:
            if permission.resource:
                needs.add(f"permission:{permission.name}:{permission.resource}")
            else:
                needs.add(f"permission:{permission.name}")
        
        # Add inherited needs from role hierarchy
        inherited_permissions = self.get_inherited_permissions()
        for permission_name in inherited_permissions:
            needs.add(f"permission:{permission_name}")
        
        return needs
    
    # Audit and Logging Methods
    
    def log_role_activity(self, activity_type: str, details: Dict[str, Any],
                         user: Optional['User'] = None) -> None:
        """
        Log role-related activity for audit trail.
        
        Args:
            activity_type: Type of activity (assignment, permission_change, etc.)
            details: Dictionary of activity details
            user: User who performed the activity
        """
        from ..models.authentication_log import AuthenticationLog
        
        log_entry = AuthenticationLog(
            user_id=user.id if user else None,
            activity_type=f"role_{activity_type}",
            details={
                'role_id': self.id,
                'role_type': self.role_type.value,
                'role_name': self.name,
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
        return f"{self.name} ({self.role_type.value})"
    
    def __repr__(self) -> str:
        """Developer string representation."""
        return (f"<Role(id={self.id}, type={self.role_type.value}, "
                f"name='{self.name}', status={self.status.value})>")
    
    # Serialization Methods for API Responses
    
    def to_dict(self, include_relationships: bool = False) -> Dict[str, Any]:
        """
        Convert role to dictionary for API responses.
        
        Args:
            include_relationships: Whether to include relationship data
            
        Returns:
            Dict[str, Any]: Role data as dictionary
        """
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'role_type': self.role_type.value,
            'name': self.name,
            'description': self.description,
            'status': self.status.value,
            'is_active': self.is_active,
            'hierarchy_level': self.hierarchy_level,
            'assignment_count': self.assignment_count,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_assigned_at': self.last_assigned_at.isoformat() if self.last_assigned_at else None
        }
        
        if include_relationships:
            data.update({
                'permissions': [p.to_dict() for p in self.permissions],
                'user_count': len(self.get_active_users()),
                'parent_role': self.parent_role.to_dict() if self.parent_role else None,
                'child_roles': [r.to_dict() for r in self.child_roles if r.is_active]
            })
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Role':
        """
        Create role instance from dictionary data.
        
        Args:
            data: Dictionary containing role data
            
        Returns:
            Role: New role instance
        """
        # Extract enum values
        role_type = RoleType(data['role_type']) if 'role_type' in data else None
        status = RoleStatus(data.get('status', RoleStatus.ACTIVE.value))
        
        return cls(
            role_type=role_type,
            name=data.get('name'),
            description=data.get('description'),
            status=status,
            is_active=data.get('is_active', True),
            hierarchy_level=data.get('hierarchy_level', 0),
            parent_role_id=data.get('parent_role_id'),
            organization_id=data.get('organization_id'),
            metadata=data.get('metadata', {}),
            permissions_config=data.get('permissions_config', {})
        )


# SQLAlchemy Event Listeners for Audit and Performance

@event.listens_for(Role, 'before_insert')
def role_before_insert(mapper, connection, target):
    """
    Event listener for role creation.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Role instance being inserted
    """
    # Set hierarchy level based on role type if not specified
    if target.hierarchy_level is None:
        hierarchy = RoleType.get_hierarchy_order()
        target.hierarchy_level = hierarchy.get(target.role_type.value, 0)
    
    # Ensure UUID is set
    if target.uuid is None:
        target.uuid = uuid.uuid4()
    
    # Set audit timestamps
    now = datetime.now(timezone.utc)
    target.created_at = now
    target.updated_at = now


@event.listens_for(Role, 'before_update')
def role_before_update(mapper, connection, target):
    """
    Event listener for role updates.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Role instance being updated
    """
    # Update timestamp
    target.updated_at = datetime.now(timezone.utc)
    
    # Validate hierarchy level consistency
    if target.hierarchy_level is not None:
        hierarchy = RoleType.get_hierarchy_order()
        expected_level = hierarchy.get(target.role_type.value, 0)
        
        # Log warning if hierarchy level doesn't match role type expectation
        if target.hierarchy_level < expected_level:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                f"Role {target.id} hierarchy level {target.hierarchy_level} "
                f"is lower than expected {expected_level} for type {target.role_type.value}"
            )


@event.listens_for(Role, 'after_insert')
def role_after_insert(mapper, connection, target):
    """
    Event listener after role creation.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Role instance that was inserted
    """
    # Log role creation for audit trail
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        f"Role created: ID={target.id}, type={target.role_type.value}, "
        f"name='{target.name}', organization={target.organization_id}"
    )


@event.listens_for(Role, 'after_update')
def role_after_update(mapper, connection, target):
    """
    Event listener after role updates.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: Role instance that was updated
    """
    # Update assignment count if status changed
    if hasattr(target, '_sa_instance_state'):
        history = target._sa_instance_state.get_history('is_active', True)
        if history.has_changes():
            # Schedule assignment count update
            target.update_assignment_count()


# Performance Optimization: Compiled Queries for Common Operations

# These would be defined as module-level compiled queries for performance
# Example implementations for common role queries

def get_active_roles_query():
    """Compiled query for active roles."""
    return (
        db.session.query(Role)
        .filter(Role.is_active == True, Role.status == RoleStatus.ACTIVE)
        .order_by(Role.hierarchy_level.asc(), Role.name.asc())
    )


def get_user_roles_query(user_id: int):
    """Compiled query for user roles."""
    from .user_role_assignment import UserRoleAssignment
    
    return (
        db.session.query(Role)
        .join(UserRoleAssignment, Role.id == UserRoleAssignment.role_id)
        .filter(
            UserRoleAssignment.user_id == user_id,
            UserRoleAssignment.is_active == True,
            Role.is_active == True,
            Role.status == RoleStatus.ACTIVE
        )
        .options(selectinload(Role.permissions))
        .order_by(Role.hierarchy_level.desc())
    )


def get_roles_with_permission_query(permission_name: str):
    """Compiled query for roles with specific permission."""
    from .permission import Permission
    from .role_permission import RolePermission
    
    return (
        db.session.query(Role)
        .join(RolePermission, Role.id == RolePermission.role_id)
        .join(Permission, RolePermission.permission_id == Permission.id)
        .filter(
            Permission.name == permission_name,
            RolePermission.is_active == True,
            Role.is_active == True,
            Role.status == RoleStatus.ACTIVE
        )
        .distinct()
        .options(selectinload(Role.permissions))
    )


# Export all public components
__all__ = [
    'Role',
    'RoleType', 
    'RoleStatus',
    'get_active_roles_query',
    'get_user_roles_query', 
    'get_roles_with_permission_query'
]