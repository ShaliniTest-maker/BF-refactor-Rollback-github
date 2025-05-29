"""
Permission Model Implementation for Flask-Principal RBAC System.

This module implements the Permission model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization and Flask-Principal Need/Provide pattern integration. The model
provides comprehensive granular access control with resource-based permissions and dynamic
authorization evaluation for context-aware security decisions throughout the Flask application.

Key Features:
- Flask-Principal Need/Provide pattern implementation with SQLAlchemy persistence
- Resource-based permissions for fine-grained access control per Section 6.4.2.2
- Dynamic permission evaluation for context-aware authorization decisions
- Many-to-many role-permission relationships for flexible RBAC implementation
- PostgreSQL-optimized field types and constraints per Section 6.2.1
- Permission evaluation methods for real-time authorization in Flask decorators
- Comprehensive audit trail and permission lifecycle management

Technical Specification References:
- Section 6.4.2.1: Role-Based Access Control (RBAC) with Flask-Principal integration
- Section 6.4.2.2: Permission Management with resource-level security
- Section 6.2.2.1: Entity Relationships and Data Models
- Section 6.2.1: Database Technology Transition to PostgreSQL 15.x
- Feature F-007: Authentication and Authorization system implementation
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Union
from enum import Enum
from flask_sqlalchemy import SQLAlchemy
from flask_principal import Need, Permission as PrincipalPermission, identity_loaded
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, UniqueConstraint, CheckConstraint, Enum as SQLEnum
)

from src.models.base import BaseModel, db


class PermissionType(Enum):
    """
    Enumeration of permission types for type-safe permission management.
    
    Provides standardized permission types that align with the authorization
    requirements specified in Section 6.4.2.2 for resource-level security.
    
    Values:
        READ: Read access to resources and data
        WRITE: Write/modify access to resources and data
        DELETE: Delete access to resources and data
        ADMIN: Administrative access with full control
        EXECUTE: Execute/run access for operations and workflows
        MODERATE: Moderation capabilities for content and user management
        VIEW: View access for display-only scenarios
        EDIT: Edit access for modification without deletion
        CREATE: Create access for new resource generation
        APPROVE: Approval access for workflow and content management
        MANAGE: Management access for resource administration
        EXPORT: Export access for data extraction and reporting
    """
    
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    EXECUTE = "execute"
    MODERATE = "moderate"
    VIEW = "view"
    EDIT = "edit"
    CREATE = "create"
    APPROVE = "approve"
    MANAGE = "manage"
    EXPORT = "export"
    
    def __str__(self) -> str:
        """String representation of permission type."""
        return self.value
    
    @classmethod
    def get_hierarchical_permissions(cls, permission_type: 'PermissionType') -> Set['PermissionType']:
        """
        Get all permissions implied by a given permission type.
        
        Implements permission hierarchy where higher-level permissions
        automatically grant lower-level permissions for efficient authorization.
        
        Args:
            permission_type (PermissionType): The permission type to expand
            
        Returns:
            Set[PermissionType]: All permissions implied by the given type
        """
        hierarchy = {
            cls.ADMIN: {cls.ADMIN, cls.MANAGE, cls.DELETE, cls.WRITE, cls.EDIT, 
                       cls.CREATE, cls.APPROVE, cls.MODERATE, cls.EXECUTE, 
                       cls.READ, cls.VIEW, cls.EXPORT},
            cls.MANAGE: {cls.MANAGE, cls.EDIT, cls.CREATE, cls.APPROVE, 
                        cls.MODERATE, cls.READ, cls.VIEW, cls.EXPORT},
            cls.DELETE: {cls.DELETE, cls.WRITE, cls.EDIT, cls.READ, cls.VIEW},
            cls.WRITE: {cls.WRITE, cls.EDIT, cls.CREATE, cls.READ, cls.VIEW},
            cls.EDIT: {cls.EDIT, cls.READ, cls.VIEW},
            cls.CREATE: {cls.CREATE, cls.READ, cls.VIEW},
            cls.APPROVE: {cls.APPROVE, cls.READ, cls.VIEW},
            cls.MODERATE: {cls.MODERATE, cls.READ, cls.VIEW},
            cls.EXECUTE: {cls.EXECUTE, cls.READ, cls.VIEW},
            cls.EXPORT: {cls.EXPORT, cls.READ, cls.VIEW},
            cls.READ: {cls.READ, cls.VIEW},
            cls.VIEW: {cls.VIEW}
        }
        
        return hierarchy.get(permission_type, {permission_type})


class ResourceType(Enum):
    """
    Enumeration of resource types for fine-grained access control.
    
    Defines the types of resources that can have permissions applied,
    enabling resource-specific authorization per Section 6.4.2.2.
    
    Values:
        USER: User account and profile resources
        ROLE: Role management and assignment resources
        PERMISSION: Permission management resources
        SESSION: User session and authentication resources
        BUSINESS_ENTITY: Business entity and data resources
        REPORT: Reporting and analytics resources
        SYSTEM: System-level configuration and management resources
        API: API endpoint and service access resources
        GLOBAL: Global application-wide permissions
    """
    
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    SESSION = "session"
    BUSINESS_ENTITY = "business_entity"
    REPORT = "report"
    SYSTEM = "system"
    API = "api"
    GLOBAL = "global"
    
    def __str__(self) -> str:
        """String representation of resource type."""
        return self.value


class Permission(BaseModel):
    """
    Permission model implementing granular access control with Flask-Principal integration.
    
    This model provides resource-based permissions with dynamic authorization evaluation,
    supporting the Flask-Principal Need/Provide pattern for context-aware security decisions.
    Essential for implementing the RBAC system specified in Section 6.4.2.1.
    
    Attributes:
        id (int): Primary key with auto-incrementing integer per Section 6.2.2.2
        name (str): Human-readable permission name for display and management
        permission_type (PermissionType): Standardized permission type using Python Enum
        resource_type (ResourceType): Type of resource this permission applies to
        resource_id (str): Specific resource identifier for granular control (optional)
        description (str): Detailed description of permission scope and purpose
        is_active (bool): Permission activation status for dynamic enable/disable
        metadata (dict): Additional permission metadata for extensibility
        created_at (datetime): Timestamp of permission creation with UTC timezone
        updated_at (datetime): Timestamp of last permission modification with UTC timezone
        
    Relationships:
        roles (List[Role]): Many-to-many relationship with Role model through association table
    """
    
    __tablename__ = 'permissions'
    
    # Human-readable permission name for display and management
    name = Column(
        String(100),
        nullable=False,
        index=True,
        comment="Human-readable permission name for display and management"
    )
    
    # Permission type using Python Enum for type safety per Section 6.4.2.1
    permission_type = Column(
        SQLEnum(PermissionType),
        nullable=False,
        index=True,
        comment="Standardized permission type using Python Enum for type safety"
    )
    
    # Resource type for granular permission management per Section 6.4.2.2
    resource_type = Column(
        SQLEnum(ResourceType),
        nullable=False,
        index=True,
        comment="Type of resource this permission applies to for granular control"
    )
    
    # Resource identifier for specific resource targeting (optional)
    resource_id = Column(
        String(255),
        nullable=True,
        index=True,
        comment="Specific resource identifier for fine-grained access control"
    )
    
    # Detailed description of permission scope and purpose
    description = Column(
        Text,
        nullable=True,
        comment="Detailed description of permission scope and purpose"
    )
    
    # Permission activation status for dynamic control
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Permission activation status for dynamic enable/disable control"
    )
    
    # Additional metadata for permission extensibility using JSON field
    metadata = Column(
        JSON,
        nullable=True,
        default=dict,
        comment="Additional permission metadata for extensibility and context"
    )
    
    # Database constraints for data integrity per Section 6.2.2.2
    __table_args__ = (
        # Unique constraint ensuring no duplicate permissions for same resource
        UniqueConstraint(
            'permission_type', 'resource_type', 'resource_id',
            name='uq_permission_resource_scope'
        ),
        
        # Unique constraint for permission names within same resource type
        UniqueConstraint(
            'name', 'resource_type',
            name='uq_permission_name_resource'
        ),
        
        # Check constraints for data validation
        CheckConstraint('LENGTH(name) >= 3', name='ck_permission_name_length'),
        CheckConstraint('LENGTH(description) >= 10', name='ck_permission_description_length'),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_permission_type_resource', 'permission_type', 'resource_type'),
        Index('ix_permission_active_type', 'is_active', 'permission_type'),
        Index('ix_permission_resource_id_type', 'resource_id', 'resource_type'),
        Index('ix_permission_name_active', 'name', 'is_active'),
        
        # Table-level comment for documentation
        {'comment': 'Permissions for granular access control with Flask-Principal integration'}
    )
    
    def __init__(self, name: str, permission_type: PermissionType, 
                 resource_type: ResourceType, resource_id: Optional[str] = None,
                 description: Optional[str] = None, **kwargs) -> None:
        """
        Initialize a new Permission instance with validation.
        
        Args:
            name (str): Human-readable permission name
            permission_type (PermissionType): Type of permission being granted
            resource_type (ResourceType): Type of resource permission applies to
            resource_id (Optional[str]): Specific resource identifier for granular control
            description (Optional[str]): Detailed description of permission scope
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If required fields are invalid or missing
        """
        super().__init__(**kwargs)
        
        # Validate and set required fields
        if not name or len(name.strip()) < 3:
            raise ValueError("Permission name must be at least 3 characters long")
        
        if not isinstance(permission_type, PermissionType):
            raise ValueError("Permission type must be a valid PermissionType enum value")
        
        if not isinstance(resource_type, ResourceType):
            raise ValueError("Resource type must be a valid ResourceType enum value")
        
        self.name = name.strip()
        self.permission_type = permission_type
        self.resource_type = resource_type
        self.resource_id = resource_id.strip() if resource_id else None
        self.description = description.strip() if description else None
        
        # Set default values if not provided
        if 'is_active' not in kwargs:
            self.is_active = True
        
        if 'metadata' not in kwargs:
            self.metadata = {}
    
    @validates('name')
    def validate_name(self, key: str, name: str) -> str:
        """
        Validate permission name field.
        
        Args:
            key (str): Field name being validated
            name (str): Permission name value
            
        Returns:
            str: Validated and normalized permission name
            
        Raises:
            ValueError: If name is invalid
        """
        if not name or len(name.strip()) < 3:
            raise ValueError("Permission name must be at least 3 characters long")
        
        return name.strip()
    
    @validates('description')
    def validate_description(self, key: str, description: Optional[str]) -> Optional[str]:
        """
        Validate permission description field.
        
        Args:
            key (str): Field name being validated
            description (Optional[str]): Permission description value
            
        Returns:
            Optional[str]: Validated and normalized description
            
        Raises:
            ValueError: If description is provided but too short
        """
        if description is not None:
            description = description.strip()
            if description and len(description) < 10:
                raise ValueError("Permission description must be at least 10 characters long if provided")
        
        return description
    
    @validates('resource_id')
    def validate_resource_id(self, key: str, resource_id: Optional[str]) -> Optional[str]:
        """
        Validate resource ID field.
        
        Args:
            key (str): Field name being validated
            resource_id (Optional[str]): Resource ID value
            
        Returns:
            Optional[str]: Validated and normalized resource ID
        """
        if resource_id is not None:
            resource_id = resource_id.strip()
            if not resource_id:
                resource_id = None
        
        return resource_id
    
    @hybrid_property
    def is_global(self) -> bool:
        """
        Check if this is a global permission not tied to a specific resource.
        
        Returns:
            bool: True if permission applies globally, False if resource-specific
        """
        return self.resource_id is None or self.resource_type == ResourceType.GLOBAL
    
    @hybrid_property
    def permission_key(self) -> str:
        """
        Generate unique permission key for Flask-Principal Need/Provide pattern.
        
        Creates a standardized permission key that can be used with Flask-Principal
        for authorization decisions and Need/Provide pattern implementation.
        
        Returns:
            str: Unique permission key for Flask-Principal integration
        """
        if self.resource_id:
            return f"{self.permission_type.value}:{self.resource_type.value}:{self.resource_id}"
        else:
            return f"{self.permission_type.value}:{self.resource_type.value}"
    
    def create_principal_need(self) -> Need:
        """
        Create Flask-Principal Need object for authorization evaluation.
        
        Converts the permission into a Flask-Principal Need that can be used
        in permission evaluation and authorization decorators per Section 6.4.2.1.
        
        Returns:
            Need: Flask-Principal Need object for authorization
        """
        if self.resource_id:
            # Resource-specific permission need
            return Need(
                method='permission',
                value=self.permission_key,
                permission_type=self.permission_type.value,
                resource_type=self.resource_type.value,
                resource_id=self.resource_id
            )
        else:
            # Global permission need
            return Need(
                method='permission',
                value=self.permission_key,
                permission_type=self.permission_type.value,
                resource_type=self.resource_type.value
            )
    
    def create_principal_permission(self) -> PrincipalPermission:
        """
        Create Flask-Principal Permission object for decorator usage.
        
        Creates a Flask-Principal Permission that can be used directly in
        authorization decorators and permission checks throughout the application.
        
        Returns:
            PrincipalPermission: Flask-Principal Permission for decorator usage
        """
        return PrincipalPermission(self.create_principal_need())
    
    def implies_permission(self, other_permission: Union['Permission', PermissionType]) -> bool:
        """
        Check if this permission implies another permission through hierarchy.
        
        Evaluates permission hierarchy to determine if this permission automatically
        grants the capabilities of another permission, enabling efficient authorization.
        
        Args:
            other_permission (Union[Permission, PermissionType]): Permission to check against
            
        Returns:
            bool: True if this permission implies the other permission
        """
        if isinstance(other_permission, Permission):
            # Must be same resource type and ID for implication
            if (self.resource_type != other_permission.resource_type or 
                self.resource_id != other_permission.resource_id):
                return False
            
            target_permission_type = other_permission.permission_type
        else:
            target_permission_type = other_permission
        
        # Check hierarchical implications
        implied_permissions = PermissionType.get_hierarchical_permissions(self.permission_type)
        return target_permission_type in implied_permissions
    
    def matches_need(self, need: Need) -> bool:
        """
        Check if this permission matches a Flask-Principal Need.
        
        Evaluates whether this permission satisfies a given Flask-Principal Need,
        supporting dynamic authorization evaluation per Section 6.4.2.2.
        
        Args:
            need (Need): Flask-Principal Need to match against
            
        Returns:
            bool: True if this permission satisfies the Need
        """
        if not self.is_active:
            return False
        
        # Check if this is a permission-type need
        if need.method != 'permission':
            return False
        
        # Parse the need value
        try:
            need_parts = need.value.split(':')
            if len(need_parts) < 2:
                return False
            
            need_permission_type = need_parts[0]
            need_resource_type = need_parts[1]
            need_resource_id = need_parts[2] if len(need_parts) > 2 else None
            
            # Check resource type match
            if self.resource_type.value != need_resource_type:
                return False
            
            # Check resource ID match (None matches global permissions)
            if need_resource_id is not None and self.resource_id != need_resource_id:
                return False
            
            # Check permission type hierarchy
            try:
                need_perm_type = PermissionType(need_permission_type)
                return self.implies_permission(need_perm_type)
            except ValueError:
                return False
            
        except (IndexError, ValueError):
            return False
    
    def can_access_resource(self, resource_type: ResourceType, 
                          resource_id: Optional[str] = None,
                          required_permission: Optional[PermissionType] = None) -> bool:
        """
        Check if this permission grants access to a specific resource.
        
        Provides context-aware authorization evaluation for resource-specific
        access control per Section 6.4.2.2.
        
        Args:
            resource_type (ResourceType): Type of resource being accessed
            resource_id (Optional[str]): Specific resource identifier
            required_permission (Optional[PermissionType]): Required permission level
            
        Returns:
            bool: True if permission grants access to the resource
        """
        if not self.is_active:
            return False
        
        # Check resource type match
        if self.resource_type != resource_type and self.resource_type != ResourceType.GLOBAL:
            return False
        
        # Check resource ID match (global permissions apply to all resources)
        if (self.resource_id is not None and 
            resource_id is not None and 
            self.resource_id != resource_id):
            return False
        
        # Check permission level if specified
        if required_permission is not None:
            return self.implies_permission(required_permission)
        
        return True
    
    def get_effective_permissions(self) -> Set[PermissionType]:
        """
        Get all effective permissions granted by this permission through hierarchy.
        
        Returns the complete set of permissions that this permission grants,
        including hierarchical implications for comprehensive authorization.
        
        Returns:
            Set[PermissionType]: All effective permissions granted
        """
        return PermissionType.get_hierarchical_permissions(self.permission_type)
    
    def to_dict(self, include_metadata: bool = True) -> Dict[str, Any]:
        """
        Convert Permission instance to dictionary representation.
        
        Args:
            include_metadata (bool): Whether to include metadata field
            
        Returns:
            Dict[str, Any]: Dictionary representation of Permission instance
        """
        result = {
            'id': self.id,
            'name': self.name,
            'permission_type': self.permission_type.value,
            'resource_type': self.resource_type.value,
            'resource_id': self.resource_id,
            'description': self.description,
            'is_active': self.is_active,
            'is_global': self.is_global,
            'permission_key': self.permission_key,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_metadata and self.metadata:
            result['metadata'] = self.metadata
        
        return result
    
    @classmethod
    def create_system_permission(cls, permission_type: PermissionType,
                                resource_type: ResourceType,
                                resource_id: Optional[str] = None,
                                description: Optional[str] = None) -> 'Permission':
        """
        Create a system-level permission with standardized naming.
        
        Factory method for creating system permissions with consistent naming
        conventions and proper validation for administrative use.
        
        Args:
            permission_type (PermissionType): Type of permission to create
            resource_type (ResourceType): Type of resource permission applies to
            resource_id (Optional[str]): Specific resource identifier
            description (Optional[str]): Permission description
            
        Returns:
            Permission: Created system permission instance
        """
        # Generate standardized name
        if resource_id:
            name = f"{permission_type.value.title()} {resource_type.value.replace('_', ' ').title()} ({resource_id})"
        else:
            name = f"{permission_type.value.title()} {resource_type.value.replace('_', ' ').title()}"
        
        # Generate description if not provided
        if not description:
            if resource_id:
                description = f"Grants {permission_type.value} access to specific {resource_type.value.replace('_', ' ')} resource: {resource_id}"
            else:
                description = f"Grants {permission_type.value} access to all {resource_type.value.replace('_', ' ')} resources"
        
        return cls(
            name=name,
            permission_type=permission_type,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            metadata={'system_generated': True, 'auto_created': True}
        )
    
    @classmethod
    def find_by_permission_key(cls, permission_key: str) -> Optional['Permission']:
        """
        Find permission by its unique permission key.
        
        Args:
            permission_key (str): Unique permission key to search for
            
        Returns:
            Optional[Permission]: Permission instance if found, None otherwise
        """
        try:
            # Parse permission key
            key_parts = permission_key.split(':')
            if len(key_parts) < 2:
                return None
            
            permission_type = PermissionType(key_parts[0])
            resource_type = ResourceType(key_parts[1])
            resource_id = key_parts[2] if len(key_parts) > 2 else None
            
            # Query for matching permission
            query = cls.query.filter(
                cls.permission_type == permission_type,
                cls.resource_type == resource_type,
                cls.is_active == True
            )
            
            if resource_id:
                query = query.filter(cls.resource_id == resource_id)
            else:
                query = query.filter(cls.resource_id.is_(None))
            
            return query.first()
            
        except (ValueError, IndexError):
            return None
    
    @classmethod
    def find_permissions_for_resource(cls, resource_type: ResourceType,
                                    resource_id: Optional[str] = None,
                                    permission_type: Optional[PermissionType] = None) -> List['Permission']:
        """
        Find all permissions that apply to a specific resource.
        
        Args:
            resource_type (ResourceType): Type of resource to search for
            resource_id (Optional[str]): Specific resource identifier
            permission_type (Optional[PermissionType]): Filter by permission type
            
        Returns:
            List[Permission]: List of applicable permissions
        """
        # Base query for resource type
        query = cls.query.filter(
            cls.is_active == True
        ).filter(
            (cls.resource_type == resource_type) | 
            (cls.resource_type == ResourceType.GLOBAL)
        )
        
        # Filter by resource ID (include global permissions)
        if resource_id:
            query = query.filter(
                (cls.resource_id == resource_id) | 
                (cls.resource_id.is_(None))
            )
        else:
            query = query.filter(cls.resource_id.is_(None))
        
        # Filter by permission type if specified
        if permission_type:
            query = query.filter(cls.permission_type == permission_type)
        
        return query.all()
    
    @classmethod
    def get_hierarchical_permissions_for_type(cls, permission_type: PermissionType) -> List['Permission']:
        """
        Get all permissions that would be granted by a specific permission type.
        
        Args:
            permission_type (PermissionType): Permission type to expand
            
        Returns:
            List[Permission]: All permissions granted by the permission type hierarchy
        """
        implied_types = PermissionType.get_hierarchical_permissions(permission_type)
        
        return cls.query.filter(
            cls.permission_type.in_(implied_types),
            cls.is_active == True
        ).all()
    
    def __repr__(self) -> str:
        """
        String representation of Permission instance for debugging and logging.
        
        Returns:
            str: String representation of Permission instance
        """
        return (
            f"<Permission(id={self.id}, name='{self.name}', "
            f"type={self.permission_type.value}, resource={self.resource_type.value}, "
            f"resource_id='{self.resource_id}', active={self.is_active})>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of Permission instance.
        
        Returns:
            str: User-friendly string representation
        """
        if self.resource_id:
            return f"{self.name} ({self.permission_type.value} on {self.resource_type.value}:{self.resource_id})"
        else:
            return f"{self.name} ({self.permission_type.value} on {self.resource_type.value})"


# Association table for many-to-many relationship between roles and permissions
# This table implements the flexible RBAC requirements per Section 6.4.2.1
role_permissions = db.Table(
    'role_permissions',
    Column(
        'id',
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Auto-incrementing primary key for role-permission associations"
    ),
    Column(
        'role_id',
        Integer,
        ForeignKey('roles.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key reference to Role model"
    ),
    Column(
        'permission_id',
        Integer,
        ForeignKey('permissions.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key reference to Permission model"
    ),
    Column(
        'granted_at',
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="Timestamp when permission was granted to role"
    ),
    Column(
        'granted_by',
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        comment="User who granted this permission (for audit trail)"
    ),
    Column(
        'is_active',
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Association activation status for dynamic control"
    ),
    
    # Constraints for data integrity
    UniqueConstraint('role_id', 'permission_id', name='uq_role_permission'),
    Index('ix_role_permission_active', 'role_id', 'permission_id', 'is_active'),
    Index('ix_role_permission_granted', 'granted_at', 'is_active'),
    
    # Table metadata
    comment='Many-to-many association between roles and permissions for RBAC implementation'
)


# Flask-Principal integration functions for authorization evaluation
def permission_required(permission_type: PermissionType, 
                       resource_type: ResourceType,
                       resource_id: Optional[str] = None):
    """
    Flask decorator for permission-based authorization using Flask-Principal.
    
    Creates a decorator that checks if the current user has the required permission
    for the specified resource, integrating with Flask-Principal for authorization.
    
    Args:
        permission_type (PermissionType): Required permission type
        resource_type (ResourceType): Type of resource being accessed
        resource_id (Optional[str]): Specific resource identifier
        
    Returns:
        Decorator function for Flask route protection
    """
    from functools import wraps
    from flask import abort
    from flask_principal import PermissionDenied
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Find the permission in the database
                permission = Permission.find_permissions_for_resource(
                    resource_type=resource_type,
                    resource_id=resource_id,
                    permission_type=permission_type
                )
                
                if not permission:
                    # Create a temporary permission for evaluation
                    temp_permission = Permission(
                        name=f"Temp {permission_type.value}",
                        permission_type=permission_type,
                        resource_type=resource_type,
                        resource_id=resource_id
                    )
                    principal_permission = temp_permission.create_principal_permission()
                else:
                    principal_permission = permission[0].create_principal_permission()
                
                # Use Flask-Principal for permission evaluation
                principal_permission.test()
                
                return f(*args, **kwargs)
                
            except PermissionDenied:
                abort(403)
        
        return decorated_function
    return decorator


def has_permission(permission_type: PermissionType,
                  resource_type: ResourceType,
                  resource_id: Optional[str] = None) -> bool:
    """
    Check if current user has specific permission without raising exceptions.
    
    Provides a non-decorator method for permission checking in business logic,
    supporting dynamic authorization evaluation per Section 6.4.2.2.
    
    Args:
        permission_type (PermissionType): Required permission type
        resource_type (ResourceType): Type of resource being accessed
        resource_id (Optional[str]): Specific resource identifier
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    try:
        from flask_principal import PermissionDenied
        
        # Find the permission in the database
        permission = Permission.find_permissions_for_resource(
            resource_type=resource_type,
            resource_id=resource_id,
            permission_type=permission_type
        )
        
        if not permission:
            return False
        
        # Use Flask-Principal for permission evaluation
        principal_permission = permission[0].create_principal_permission()
        principal_permission.test()
        
        return True
        
    except (PermissionDenied, Exception):
        return False


# Export all classes and functions for use throughout the application
__all__ = [
    'Permission', 'PermissionType', 'ResourceType', 'role_permissions',
    'permission_required', 'has_permission'
]