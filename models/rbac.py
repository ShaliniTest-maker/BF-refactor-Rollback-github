"""
Role-Based Access Control (RBAC) models for comprehensive authorization system.

This module implements a complete RBAC infrastructure using Flask-SQLAlchemy 3.1.1
with comprehensive audit trails, many-to-many relationships with association objects,
and support for Flask blueprint route protection. The implementation provides
granular access control through resource-action permission patterns and role hierarchy
management with dynamic permission system administration.

Key Components:
- Role model: Hierarchical role management with active status control
- Permission model: Resource-action based granular access control  
- Association tables: user_roles and role_permissions with audit metadata
- Permission checking utilities: Flask decorator integration support
- Audit trail support: Comprehensive logging of all authorization changes

Security Features:
- Association object audit trails for role and permission assignments
- Resource-action permission model supporting Flask endpoint protection
- Role hierarchy with inheritance and active status management
- Comprehensive authorization change logging and audit trails
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Union, Any
from flask import current_app, g, request
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, 
    UniqueConstraint, Index, Text, event
)
from sqlalchemy.orm import relationship, validates, Session
from sqlalchemy.ext.declarative import declared_attr
from werkzeug.exceptions import Forbidden

# Import base model and database instance
from models.base import BaseModel, db, AuditMixin

# Configure logging for RBAC operations
logger = logging.getLogger(__name__)


class UserRole(db.Model, AuditMixin):
    """
    Association table for User-Role many-to-many relationship with audit metadata.
    
    Provides comprehensive audit trail for role assignments including timestamp
    tracking and user attribution. Supports dynamic role assignment and revocation
    with full accountability and traceability for security compliance.
    
    Features:
    - Audit trail for role assignment changes with user attribution
    - Timestamp tracking for assignment and modification events
    - Soft deletion support for maintaining audit history
    - Index optimization for efficient role lookup queries
    """
    
    __tablename__ = 'user_roles'
    
    # Composite primary key for many-to-many relationship
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), 
                     primary_key=True, nullable=False, index=True)
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), 
                     primary_key=True, nullable=False, index=True)
    
    # Audit metadata for role assignment tracking
    assigned_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    assigned_by = Column(String(255), nullable=True)  # User who assigned the role
    revoked_at = Column(DateTime, nullable=True, index=True)  # Soft deletion timestamp
    revoked_by = Column(String(255), nullable=True)  # User who revoked the role
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Additional metadata for advanced role management
    assignment_reason = Column(Text, nullable=True)  # Reason for role assignment
    temporary_until = Column(DateTime, nullable=True, index=True)  # Temporary role expiration
    
    # Relationships for navigation
    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="user_roles")
    
    # Database constraints and indexes
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='uq_user_role_active'),
        Index('idx_user_roles_active', 'user_id', 'role_id', 'is_active'),
        Index('idx_user_roles_temporal', 'assigned_at', 'revoked_at'),
        Index('idx_user_roles_temporary', 'temporary_until'),
    )
    
    def __repr__(self) -> str:
        """String representation for debugging and logging."""
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id}, active={self.is_active})>"
    
    def revoke_role(self, revoked_by: str = None, reason: str = None) -> bool:
        """
        Revoke role assignment with audit trail.
        
        Args:
            revoked_by: User identifier who is revoking the role
            reason: Reason for role revocation
            
        Returns:
            True if revocation was successful, False otherwise
        """
        try:
            self.is_active = False
            self.revoked_at = datetime.utcnow()
            self.revoked_by = revoked_by or getattr(g, 'current_user_id', 'system')
            if reason:
                self.assignment_reason = f"{self.assignment_reason or ''}\nRevoked: {reason}"
            
            logger.info(f"Role {self.role_id} revoked from user {self.user_id} by {self.revoked_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke role {self.role_id} from user {self.user_id}: {e}")
            return False
    
    def is_expired(self) -> bool:
        """Check if temporary role assignment has expired."""
        if self.temporary_until is None:
            return False
        return datetime.utcnow() > self.temporary_until
    
    @validates('user_id', 'role_id')
    def validate_ids(self, key: str, value: int) -> int:
        """Validate foreign key references."""
        if value is None or value <= 0:
            raise ValueError(f"{key} must be a positive integer")
        return value


class RolePermission(db.Model, AuditMixin):
    """
    Association table for Role-Permission many-to-many relationship with grant tracking.
    
    Provides detailed audit trail for permission grants including comprehensive
    metadata tracking and temporal grant management. Supports permission inheritance
    and dynamic permission assignment with full accountability.
    
    Features:
    - Grant tracking with user attribution and timestamp accuracy
    - Permission inheritance support for role hierarchies
    - Conditional and temporary permission grants
    - Comprehensive audit trail for security compliance
    """
    
    __tablename__ = 'role_permissions'
    
    # Composite primary key for many-to-many relationship
    role_id = Column(Integer, ForeignKey('roles.id', ondelete='CASCADE'), 
                     primary_key=True, nullable=False, index=True)
    permission_id = Column(Integer, ForeignKey('permissions.id', ondelete='CASCADE'), 
                           primary_key=True, nullable=False, index=True)
    
    # Grant audit metadata
    granted_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    granted_by = Column(String(255), nullable=True)  # User who granted the permission
    revoked_at = Column(DateTime, nullable=True, index=True)  # Permission revocation timestamp
    revoked_by = Column(String(255), nullable=True)  # User who revoked the permission
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Advanced permission grant features
    grant_reason = Column(Text, nullable=True)  # Reason for permission grant
    temporary_until = Column(DateTime, nullable=True, index=True)  # Temporary grant expiration
    conditional_grant = Column(Text, nullable=True)  # Conditions for permission usage
    inherited_from = Column(Integer, ForeignKey('roles.id', ondelete='SET NULL'), 
                           nullable=True)  # Role hierarchy inheritance tracking
    
    # Relationships for navigation
    role = relationship("Role", back_populates="role_permissions", foreign_keys=[role_id])
    permission = relationship("Permission", back_populates="role_permissions")
    inherited_from_role = relationship("Role", foreign_keys=[inherited_from])
    
    # Database constraints and indexes
    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='uq_role_permission_active'),
        Index('idx_role_permissions_active', 'role_id', 'permission_id', 'is_active'),
        Index('idx_role_permissions_temporal', 'granted_at', 'revoked_at'),
        Index('idx_role_permissions_inheritance', 'inherited_from'),
        Index('idx_role_permissions_temporary', 'temporary_until'),
    )
    
    def __repr__(self) -> str:
        """String representation for debugging and logging."""
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id}, active={self.is_active})>"
    
    def revoke_permission(self, revoked_by: str = None, reason: str = None) -> bool:
        """
        Revoke permission grant with audit trail.
        
        Args:
            revoked_by: User identifier who is revoking the permission
            reason: Reason for permission revocation
            
        Returns:
            True if revocation was successful, False otherwise
        """
        try:
            self.is_active = False
            self.revoked_at = datetime.utcnow()
            self.revoked_by = revoked_by or getattr(g, 'current_user_id', 'system')
            if reason:
                self.grant_reason = f"{self.grant_reason or ''}\nRevoked: {reason}"
            
            logger.info(f"Permission {self.permission_id} revoked from role {self.role_id} by {self.revoked_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke permission {self.permission_id} from role {self.role_id}: {e}")
            return False
    
    def is_expired(self) -> bool:
        """Check if temporary permission grant has expired."""
        if self.temporary_until is None:
            return False
        return datetime.utcnow() > self.temporary_until
    
    def is_inherited(self) -> bool:
        """Check if permission is inherited from parent role."""
        return self.inherited_from is not None


class Role(BaseModel):
    """
    Role model for hierarchical role-based access control system.
    
    Implements comprehensive role management with hierarchy support, active status
    management, and role inheritance capabilities. Provides foundation for dynamic
    permission system administration and enterprise-grade access control.
    
    Features:
    - Hierarchical role structure with parent-child relationships
    - Active status management for dynamic role administration
    - Role inheritance with permission propagation
    - Comprehensive role metadata and description support
    - Integration with Flask blueprint route protection system
    """
    
    __tablename__ = 'roles'
    
    # Core role attributes
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Role hierarchy support
    parent_role_id = Column(Integer, ForeignKey('roles.id', ondelete='SET NULL'), 
                           nullable=True, index=True)
    hierarchy_level = Column(Integer, default=0, nullable=False, index=True)
    hierarchy_path = Column(String(500), nullable=True, index=True)  # Materialized path for efficiency
    
    # Role metadata
    role_type = Column(String(50), default='custom', nullable=False, index=True)  # system, custom, temporary
    max_assignments = Column(Integer, nullable=True)  # Maximum number of users who can have this role
    requires_approval = Column(Boolean, default=False, nullable=False)  # Require approval for assignment
    
    # System management fields
    is_system_role = Column(Boolean, default=False, nullable=False)  # Prevent deletion of system roles
    display_order = Column(Integer, default=0, nullable=False)  # For UI ordering
    
    # Relationships
    parent_role = relationship("Role", remote_side=[id], back_populates="child_roles")
    child_roles = relationship("Role", back_populates="parent_role", cascade="all, delete-orphan")
    
    # Many-to-many relationships through association tables
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    role_permissions = relationship("RolePermission", back_populates="role", 
                                   foreign_keys=[RolePermission.role_id],
                                   cascade="all, delete-orphan")
    
    # Database constraints and indexes
    __table_args__ = (
        Index('idx_roles_hierarchy', 'parent_role_id', 'hierarchy_level'),
        Index('idx_roles_type_active', 'role_type', 'is_active'),
        Index('idx_roles_name_active', 'name', 'is_active'),
    )
    
    def __repr__(self) -> str:
        """String representation for debugging and logging."""
        return f"<Role(id={self.id}, name='{self.name}', active={self.is_active})>"
    
    @property
    def users(self) -> List['User']:
        """Get all active users assigned to this role."""
        return [ur.user for ur in self.user_roles 
                if ur.is_active and not ur.is_expired()]
    
    @property
    def permissions(self) -> List['Permission']:
        """Get all active permissions for this role."""
        return [rp.permission for rp in self.role_permissions 
                if rp.is_active and not rp.is_expired()]
    
    @property
    def all_permissions(self) -> Set['Permission']:
        """Get all permissions including inherited from parent roles."""
        permissions = set(self.permissions)
        
        # Add inherited permissions from parent roles
        current_role = self.parent_role
        while current_role:
            permissions.update(current_role.permissions)
            current_role = current_role.parent_role
        
        return permissions
    
    def assign_to_user(self, user_id: int, assigned_by: str = None, 
                       reason: str = None, temporary_until: datetime = None) -> Optional[UserRole]:
        """
        Assign role to user with audit trail.
        
        Args:
            user_id: ID of user to assign role to
            assigned_by: User identifier who is assigning the role
            reason: Reason for role assignment
            temporary_until: Optional expiration date for temporary assignment
            
        Returns:
            UserRole instance if successful, None otherwise
        """
        try:
            # Check if assignment already exists and is active
            existing = UserRole.query.filter_by(
                user_id=user_id, role_id=self.id, is_active=True
            ).first()
            
            if existing and not existing.is_expired():
                logger.warning(f"User {user_id} already has active role {self.id}")
                return existing
            
            # Check max assignments limit
            if self.max_assignments:
                active_assignments = UserRole.query.filter_by(
                    role_id=self.id, is_active=True
                ).count()
                
                if active_assignments >= self.max_assignments:
                    logger.error(f"Role {self.id} has reached maximum assignments limit")
                    return None
            
            # Create new role assignment
            user_role = UserRole(
                user_id=user_id,
                role_id=self.id,
                assigned_by=assigned_by or getattr(g, 'current_user_id', 'system'),
                assignment_reason=reason,
                temporary_until=temporary_until
            )
            
            db.session.add(user_role)
            logger.info(f"Role {self.id} assigned to user {user_id} by {user_role.assigned_by}")
            
            return user_role
            
        except Exception as e:
            logger.error(f"Failed to assign role {self.id} to user {user_id}: {e}")
            db.session.rollback()
            return None
    
    def grant_permission(self, permission_id: int, granted_by: str = None,
                        reason: str = None, temporary_until: datetime = None) -> Optional[RolePermission]:
        """
        Grant permission to role with audit trail.
        
        Args:
            permission_id: ID of permission to grant
            granted_by: User identifier who is granting the permission
            reason: Reason for permission grant
            temporary_until: Optional expiration date for temporary grant
            
        Returns:
            RolePermission instance if successful, None otherwise
        """
        try:
            # Check if permission already exists and is active
            existing = RolePermission.query.filter_by(
                role_id=self.id, permission_id=permission_id, is_active=True
            ).first()
            
            if existing and not existing.is_expired():
                logger.warning(f"Role {self.id} already has active permission {permission_id}")
                return existing
            
            # Create new permission grant
            role_permission = RolePermission(
                role_id=self.id,
                permission_id=permission_id,
                granted_by=granted_by or getattr(g, 'current_user_id', 'system'),
                grant_reason=reason,
                temporary_until=temporary_until
            )
            
            db.session.add(role_permission)
            logger.info(f"Permission {permission_id} granted to role {self.id} by {role_permission.granted_by}")
            
            return role_permission
            
        except Exception as e:
            logger.error(f"Failed to grant permission {permission_id} to role {self.id}: {e}")
            db.session.rollback()
            return None
    
    def has_permission(self, resource: str, action: str, check_inheritance: bool = True) -> bool:
        """
        Check if role has specific permission.
        
        Args:
            resource: Resource name to check access for
            action: Action to check permission for
            check_inheritance: Whether to check inherited permissions from parent roles
            
        Returns:
            True if role has permission, False otherwise
        """
        # Check direct permissions
        for permission in self.permissions:
            if permission.matches(resource, action):
                return True
        
        # Check inherited permissions from parent roles
        if check_inheritance and self.parent_role:
            return self.parent_role.has_permission(resource, action, check_inheritance=True)
        
        return False
    
    def get_effective_permissions(self) -> Set[str]:
        """
        Get all effective permissions for this role including inheritance.
        
        Returns:
            Set of permission names in 'resource.action' format
        """
        permissions = set()
        
        # Add direct permissions
        for permission in self.permissions:
            permissions.add(f"{permission.resource}.{permission.action}")
        
        # Add inherited permissions
        current_role = self.parent_role
        while current_role:
            for permission in current_role.permissions:
                permissions.add(f"{permission.resource}.{permission.action}")
            current_role = current_role.parent_role
        
        return permissions
    
    def update_hierarchy_path(self) -> None:
        """Update materialized path for efficient hierarchy queries."""
        if self.parent_role:
            self.hierarchy_path = f"{self.parent_role.hierarchy_path or ''}/{self.parent_role.id}"
            self.hierarchy_level = (self.parent_role.hierarchy_level or 0) + 1
        else:
            self.hierarchy_path = ""
            self.hierarchy_level = 0
    
    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """Validate role name."""
        if not name or len(name.strip()) < 2:
            raise ValueError("Role name must be at least 2 characters long")
        if len(name) > 100:
            raise ValueError("Role name cannot exceed 100 characters")
        return name.strip()
    
    @validates('parent_role_id')
    def validate_parent_role(self, key: str, parent_role_id: Optional[int]) -> Optional[int]:
        """Validate parent role to prevent circular references."""
        if parent_role_id is None:
            return None
        
        if parent_role_id == self.id:
            raise ValueError("Role cannot be its own parent")
        
        # Check for circular reference in hierarchy
        if self.id:  # Only check if role already exists
            parent_role = Role.query.get(parent_role_id)
            if parent_role and parent_role.hierarchy_path:
                if f"/{self.id}/" in f"/{parent_role.hierarchy_path}/":
                    raise ValueError("Circular reference detected in role hierarchy")
        
        return parent_role_id


class Permission(BaseModel):
    """
    Permission model for granular access control with resource-action pattern.
    
    Implements comprehensive permission management supporting Flask blueprint route
    protection and business operation authorization. Provides resource-action based
    granular access control with wildcards and condition support.
    
    Features:
    - Resource-action permission model for granular access control
    - Wildcard support for flexible permission patterns
    - Condition-based permissions for advanced access control
    - Integration with Flask blueprint route protection system
    - Permission validation and normalization capabilities
    """
    
    __tablename__ = 'permissions'
    
    # Core permission attributes
    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(100), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Advanced permission features
    permission_type = Column(String(20), default='standard', nullable=False, index=True)  # standard, wildcard, conditional
    conditions = Column(Text, nullable=True)  # JSON string for conditional permissions
    resource_pattern = Column(String(200), nullable=True)  # For wildcard resources
    priority = Column(Integer, default=0, nullable=False)  # For permission precedence
    
    # System management fields
    is_system_permission = Column(Boolean, default=False, nullable=False)  # Prevent deletion
    permission_category = Column(String(50), nullable=True, index=True)  # For grouping
    requires_context = Column(Boolean, default=False, nullable=False)  # Requires additional context
    
    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission", 
                                   cascade="all, delete-orphan")
    
    # Database constraints and indexes
    __table_args__ = (
        UniqueConstraint('resource', 'action', name='uq_permission_resource_action'),
        Index('idx_permissions_resource_action', 'resource', 'action'),
        Index('idx_permissions_type_active', 'permission_type', 'is_active'),
        Index('idx_permissions_category', 'permission_category'),
    )
    
    def __repr__(self) -> str:
        """String representation for debugging and logging."""
        return f"<Permission(id={self.id}, name='{self.name}', resource='{self.resource}', action='{self.action}')>"
    
    @property
    def roles(self) -> List[Role]:
        """Get all active roles that have this permission."""
        return [rp.role for rp in self.role_permissions 
                if rp.is_active and not rp.is_expired()]
    
    def matches(self, resource: str, action: str, context: Dict[str, Any] = None) -> bool:
        """
        Check if permission matches given resource and action.
        
        Args:
            resource: Resource to check
            action: Action to check  
            context: Additional context for conditional permissions
            
        Returns:
            True if permission matches, False otherwise
        """
        # Direct match
        if self.resource == resource and self.action == action:
            return self._check_conditions(context) if self.requires_context else True
        
        # Wildcard matches
        if self.permission_type == 'wildcard':
            if self._match_wildcard_resource(resource) and self._match_wildcard_action(action):
                return self._check_conditions(context) if self.requires_context else True
        
        return False
    
    def _match_wildcard_resource(self, resource: str) -> bool:
        """Check if resource matches wildcard pattern."""
        if self.resource == '*':
            return True
        
        if self.resource_pattern:
            import re
            pattern = self.resource_pattern.replace('*', '.*')
            return bool(re.match(pattern, resource))
        
        return self.resource == resource
    
    def _match_wildcard_action(self, action: str) -> bool:
        """Check if action matches wildcard pattern."""
        if self.action == '*':
            return True
        
        # Support action wildcards like 'read.*', '*.create'
        if '*' in self.action:
            import re
            pattern = self.action.replace('*', '.*')
            return bool(re.match(pattern, action))
        
        return self.action == action
    
    def _check_conditions(self, context: Dict[str, Any] = None) -> bool:
        """
        Check conditional permissions against provided context.
        
        Args:
            context: Context data for condition evaluation
            
        Returns:
            True if conditions are met, False otherwise
        """
        if not self.conditions or not context:
            return True
        
        try:
            import json
            conditions = json.loads(self.conditions)
            
            # Simple condition checking - can be extended for complex logic
            for key, expected_value in conditions.items():
                if key not in context:
                    return False
                
                context_value = context[key]
                
                # Support different condition types
                if isinstance(expected_value, dict):
                    operator = expected_value.get('op', 'eq')
                    value = expected_value.get('value')
                    
                    if operator == 'eq' and context_value != value:
                        return False
                    elif operator == 'ne' and context_value == value:
                        return False
                    elif operator == 'in' and context_value not in value:
                        return False
                    elif operator == 'not_in' and context_value in value:
                        return False
                elif context_value != expected_value:
                    return False
            
            return True
            
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Error checking permission conditions for {self.name}: {e}")
            return False
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert permission to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            
        Returns:
            Dictionary representation of permission
        """
        result = super().to_dict(include_sensitive=include_sensitive)
        
        # Add computed fields
        result['full_name'] = f"{self.resource}.{self.action}"
        result['role_count'] = len(self.roles)
        
        return result
    
    @validates('resource', 'action')
    def validate_resource_action(self, key: str, value: str) -> str:
        """Validate resource and action values."""
        if not value or len(value.strip()) < 1:
            raise ValueError(f"{key} cannot be empty")
        
        # Normalize to lowercase for consistency
        value = value.strip().lower()
        
        # Validate characters (alphanumeric, underscore, dash, dot, asterisk)
        import re
        if not re.match(r'^[a-z0-9_.\-*]+$', value):
            raise ValueError(f"{key} contains invalid characters")
        
        return value
    
    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """Validate and generate permission name."""
        if name:
            return name.strip()
        
        # Auto-generate name from resource and action if not provided
        if hasattr(self, 'resource') and hasattr(self, 'action') and self.resource and self.action:
            return f"{self.resource}.{self.action}"
        
        return name


# SQLAlchemy event hooks for automatic hierarchy and audit management
@event.listens_for(Role, 'before_insert')
@event.listens_for(Role, 'before_update')
def update_role_hierarchy(mapper, connection, target):
    """Update role hierarchy path before insert/update."""
    if target.parent_role_id:
        # Get parent role hierarchy info
        result = connection.execute(
            "SELECT hierarchy_path, hierarchy_level FROM roles WHERE id = %s",
            (target.parent_role_id,)
        ).fetchone()
        
        if result:
            parent_path, parent_level = result
            target.hierarchy_path = f"{parent_path or ''}/{target.parent_role_id}".lstrip('/')
            target.hierarchy_level = (parent_level or 0) + 1
        else:
            target.hierarchy_path = str(target.parent_role_id)
            target.hierarchy_level = 1
    else:
        target.hierarchy_path = ""
        target.hierarchy_level = 0


@event.listens_for(Permission, 'before_insert')
@event.listens_for(Permission, 'before_update')
def generate_permission_name(mapper, connection, target):
    """Generate permission name if not provided."""
    if not target.name and target.resource and target.action:
        target.name = f"{target.resource}.{target.action}"


# Utility functions for RBAC operations
class RBACManager:
    """
    RBAC management utility class for common authorization operations.
    
    Provides centralized methods for role and permission management,
    user authorization checking, and Flask decorator integration support.
    """
    
    @staticmethod
    def check_user_permission(user_id: int, resource: str, action: str, 
                             context: Dict[str, Any] = None) -> bool:
        """
        Check if user has specific permission through their roles.
        
        Args:
            user_id: ID of user to check
            resource: Resource to check access for
            action: Action to check permission for
            context: Additional context for conditional permissions
            
        Returns:
            True if user has permission, False otherwise
        """
        try:
            # Get all active roles for user
            user_roles = UserRole.query.filter_by(
                user_id=user_id, is_active=True
            ).all()
            
            # Check permissions for each role
            for user_role in user_roles:
                if user_role.is_expired():
                    continue
                
                role = user_role.role
                if role and role.is_active and role.has_permission(resource, action):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking user {user_id} permission for {resource}.{action}: {e}")
            return False
    
    @staticmethod
    def get_user_permissions(user_id: int) -> Set[str]:
        """
        Get all effective permissions for user.
        
        Args:
            user_id: ID of user
            
        Returns:
            Set of permission names in 'resource.action' format
        """
        permissions = set()
        
        try:
            # Get all active roles for user
            user_roles = UserRole.query.filter_by(
                user_id=user_id, is_active=True
            ).all()
            
            # Collect permissions from all roles
            for user_role in user_roles:
                if user_role.is_expired():
                    continue
                
                role = user_role.role
                if role and role.is_active:
                    permissions.update(role.get_effective_permissions())
            
        except Exception as e:
            logger.error(f"Error getting permissions for user {user_id}: {e}")
        
        return permissions
    
    @staticmethod
    def get_user_roles(user_id: int) -> List[Role]:
        """
        Get all active roles for user.
        
        Args:
            user_id: ID of user
            
        Returns:
            List of active Role objects
        """
        try:
            user_roles = UserRole.query.filter_by(
                user_id=user_id, is_active=True
            ).all()
            
            return [ur.role for ur in user_roles 
                   if ur.role and ur.role.is_active and not ur.is_expired()]
                   
        except Exception as e:
            logger.error(f"Error getting roles for user {user_id}: {e}")
            return []
    
    @staticmethod
    def create_permission(resource: str, action: str, description: str = None,
                         permission_type: str = 'standard', **kwargs) -> Optional[Permission]:
        """
        Create new permission with validation.
        
        Args:
            resource: Resource name
            action: Action name
            description: Permission description
            permission_type: Type of permission (standard, wildcard, conditional)
            **kwargs: Additional permission attributes
            
        Returns:
            Permission instance if successful, None otherwise
        """
        try:
            permission = Permission(
                resource=resource,
                action=action,
                description=description,
                permission_type=permission_type,
                **kwargs
            )
            
            db.session.add(permission)
            db.session.flush()  # Get ID without committing
            
            logger.info(f"Created permission: {permission.name}")
            return permission
            
        except Exception as e:
            logger.error(f"Failed to create permission {resource}.{action}: {e}")
            db.session.rollback()
            return None
    
    @staticmethod
    def create_role(name: str, description: str = None, parent_role_id: int = None,
                   **kwargs) -> Optional[Role]:
        """
        Create new role with validation.
        
        Args:
            name: Role name
            description: Role description
            parent_role_id: Parent role ID for hierarchy
            **kwargs: Additional role attributes
            
        Returns:
            Role instance if successful, None otherwise
        """
        try:
            role = Role(
                name=name,
                description=description,
                parent_role_id=parent_role_id,
                **kwargs
            )
            
            db.session.add(role)
            db.session.flush()  # Get ID without committing
            
            logger.info(f"Created role: {role.name}")
            return role
            
        except Exception as e:
            logger.error(f"Failed to create role {name}: {e}")
            db.session.rollback()
            return None


# Flask decorator utilities for route protection
def require_permission(resource: str, action: str):
    """
    Flask decorator to require specific permission for route access.
    
    Args:
        resource: Resource name required
        action: Action required
        
    Returns:
        Decorator function for Flask routes
    """
    from functools import wraps
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get current user from Flask-Login or session
            user_id = getattr(g, 'current_user_id', None)
            
            if not user_id:
                logger.warning(f"Access denied to {resource}.{action}: No authenticated user")
                raise Forbidden("Authentication required")
            
            # Check permission
            if not RBACManager.check_user_permission(user_id, resource, action):
                logger.warning(f"Access denied to {resource}.{action} for user {user_id}")
                raise Forbidden("Insufficient permissions")
            
            # Store permission context for use in the view
            g.current_permission = f"{resource}.{action}"
            g.current_resource = resource
            g.current_action = action
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_role(role_name: str):
    """
    Flask decorator to require specific role for route access.
    
    Args:
        role_name: Role name required
        
    Returns:
        Decorator function for Flask routes
    """
    from functools import wraps
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get current user from Flask-Login or session
            user_id = getattr(g, 'current_user_id', None)
            
            if not user_id:
                logger.warning(f"Access denied to role {role_name}: No authenticated user")
                raise Forbidden("Authentication required")
            
            # Check role membership
            user_roles = RBACManager.get_user_roles(user_id)
            role_names = [role.name for role in user_roles]
            
            if role_name not in role_names:
                logger.warning(f"Access denied to role {role_name} for user {user_id}")
                raise Forbidden("Insufficient role privileges")
            
            # Store role context for use in the view
            g.current_roles = role_names
            g.required_role = role_name
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Export all models and utilities
__all__ = [
    'Role', 'Permission', 'UserRole', 'RolePermission',
    'RBACManager', 'require_permission', 'require_role'
]