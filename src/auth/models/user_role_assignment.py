"""
UserRoleAssignment Association Model for Flask-Security RBAC Implementation

This module implements the UserRoleAssignment association model managing the many-to-many 
relationship between Users and Roles with comprehensive metadata tracking, temporal assignment 
capabilities, and audit trail functionality. The model provides enterprise-grade role-based 
access control (RBAC) foundation with Flask-Security integration, assignment lifecycle 
management, and real-time authorization support.

Key Features:
- Many-to-many User-Role relationship with enhanced metadata tracking
- Temporal assignment management with activation, expiration, and scheduling capabilities
- Comprehensive audit logging for security compliance and regulatory requirements
- Assignment validation and business logic for RBAC integrity enforcement
- Real-time assignment status tracking with automatic expiration handling
- Flask-Security integration for role-based authentication decorators
- Performance optimization with database indexes and query compilation
- Role assignment lifecycle management with creation, modification, and revocation tracking

Technical Implementation:
- Flask-SQLAlchemy 3.1.1 association table pattern with PostgreSQL 15.x backend
- Python 3.13.3 enum-backed status definitions for type-safe assignment management
- Foreign key constraints with cascading behavior for referential integrity
- Composite indexes for optimized authorization query performance
- JSON metadata storage for flexible assignment configuration and tracking
- Event listeners for automatic audit trail generation and status management

Security Architecture Integration:
- Role assignment auditing for Section 6.4.2.5 audit trail requirements
- Temporal assignment fields for Section 6.4.2.1 RBAC lifecycle management
- Database relationship integrity per Section 6.2.2.1 entity relationship design
- Role assignment validation for Section 6.4.2.1 authorization system compliance
- Integration with Flask-Principal Need/Provide pattern for authorization decisions

Performance Optimizations:
- Composite database indexes for user-role lookup performance
- Compiled query patterns for repeated assignment validation operations
- Efficient relationship loading strategies for authorization decorator usage
- Cached assignment counts and status tracking for real-time performance
- Optimized bulk assignment operations for administrative workflows

Authors: Flask Migration Team
Version: 1.0.0
Created: 2024
License: Proprietary
"""

import uuid
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import List, Optional, Dict, Any, Set, Union
from functools import wraps

from flask import current_app, g, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey,
    Index, UniqueConstraint, CheckConstraint, event, func, and_, or_
)
from sqlalchemy.orm import relationship, validates, joinedload, selectinload, Session
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import text

# Import base model and database instance
from ...models.base import BaseModel, db
from ...models.user import User
from .role import Role, RoleType, RoleStatus


class AssignmentStatus(Enum):
    """
    Assignment status enumeration for role assignment lifecycle management.
    
    Status Values:
    - PENDING: Assignment created but not yet activated
    - ACTIVE: Assignment is currently active and grants permissions
    - SUSPENDED: Assignment temporarily suspended but preserved
    - EXPIRED: Assignment has passed its expiration date
    - REVOKED: Assignment has been manually revoked
    - ARCHIVED: Assignment archived for historical purposes
    
    Status Transitions:
    - PENDING → ACTIVE: Manual activation or automatic on activation_date
    - ACTIVE → SUSPENDED: Temporary suspension for security or administrative reasons
    - ACTIVE → EXPIRED: Automatic transition when expiration_date is reached
    - ACTIVE → REVOKED: Manual revocation by authorized personnel
    - SUSPENDED → ACTIVE: Reactivation after suspension period
    - Any Status → ARCHIVED: Administrative archival for record keeping
    """
    
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ARCHIVED = "archived"
    
    @classmethod
    def get_active_statuses(cls) -> Set['AssignmentStatus']:
        """
        Get statuses that indicate an active assignment granting permissions.
        
        Returns:
            Set[AssignmentStatus]: Set of statuses that grant permissions
        """
        return {cls.ACTIVE}
    
    @classmethod
    def get_inactive_statuses(cls) -> Set['AssignmentStatus']:
        """
        Get statuses that indicate an inactive assignment not granting permissions.
        
        Returns:
            Set[AssignmentStatus]: Set of statuses that do not grant permissions
        """
        return {cls.PENDING, cls.SUSPENDED, cls.EXPIRED, cls.REVOKED, cls.ARCHIVED}
    
    @classmethod
    def get_terminal_statuses(cls) -> Set['AssignmentStatus']:
        """
        Get statuses that indicate a finalized assignment that cannot be reactivated.
        
        Returns:
            Set[AssignmentStatus]: Set of terminal statuses
        """
        return {cls.EXPIRED, cls.REVOKED, cls.ARCHIVED}
    
    def is_active(self) -> bool:
        """Check if this status indicates an active assignment."""
        return self in self.get_active_statuses()
    
    def is_terminal(self) -> bool:
        """Check if this status is terminal (cannot be reactivated)."""
        return self in self.get_terminal_statuses()
    
    def __str__(self) -> str:
        return self.value


class AssignmentPriority(Enum):
    """
    Assignment priority enumeration for role precedence management.
    
    Priority Levels:
    - LOW: Low priority assignment (0-25)
    - NORMAL: Standard priority assignment (26-50)
    - HIGH: High priority assignment (51-75)
    - CRITICAL: Critical priority assignment (76-100)
    
    Priority Usage:
    - Used for role conflict resolution when users have multiple conflicting roles
    - Higher priority assignments take precedence in authorization decisions
    - Affects role inheritance and permission aggregation patterns
    """
    
    LOW = 0
    NORMAL = 25
    HIGH = 50
    CRITICAL = 75
    
    def __str__(self) -> str:
        return self.name.lower()


class UserRoleAssignment(BaseModel):
    """
    Association model managing many-to-many relationships between Users and Roles.
    
    This model implements the core RBAC foundation by managing user role assignments with
    comprehensive metadata, temporal capabilities, and audit tracking. It serves as the
    bridge between authentication (User) and authorization (Role) systems, providing
    enterprise-grade access control with Flask-Security integration.
    
    Core Functionality:
    - Many-to-many User-Role relationship management with metadata
    - Temporal assignment capabilities with activation and expiration dates
    - Assignment lifecycle tracking from creation through archival
    - Real-time assignment validation and authorization integration
    - Comprehensive audit logging for security compliance
    - Role conflict resolution through priority and hierarchy management
    - Bulk assignment operations for administrative efficiency
    
    Database Schema:
    - Primary key: Integer auto-increment ID from BaseModel
    - Foreign keys: user_id (Users), role_id (Roles), assigned_by_id (Users)
    - Unique constraint: user_id + role_id + organization_id combination
    - Indexes: Optimized for authorization queries and audit lookups
    - Timestamps: created_at, updated_at from BaseModel + assignment-specific dates
    
    Security Integration:
    - Flask-Security role-based authentication decorator support
    - Flask-Principal Need/Provide pattern integration for authorization
    - Real-time assignment status validation for authentication flows
    - Assignment audit logging for security compliance requirements
    - Role hierarchy enforcement and permission inheritance support
    
    Performance Optimization:
    - Composite indexes for user-role authorization queries
    - Compiled query patterns for repeated assignment validation
    - Efficient bulk assignment operations with batch processing
    - Cached assignment status for real-time authorization decisions
    - Optimized relationship loading for authentication decorator usage
    
    Attributes:
        id (int): Primary key inherited from BaseModel
        uuid (UUID): Universal unique identifier for external references
        user_id (int): Foreign key reference to Users table
        role_id (int): Foreign key reference to Roles table
        organization_id (int): Optional organization ID for multi-tenant support
        status (AssignmentStatus): Current assignment status with lifecycle management
        priority (int): Assignment priority for conflict resolution (0-100)
        is_active (bool): Boolean flag for quick active/inactive filtering
        is_temporary (bool): Flag indicating temporary assignment vs permanent
        activation_date (datetime): Date when assignment becomes active
        expiration_date (datetime): Date when assignment expires (optional)
        suspension_date (datetime): Date when assignment was suspended (if applicable)
        revocation_date (datetime): Date when assignment was revoked (if applicable)
        assigned_by_id (int): Foreign key to User who created the assignment
        assigned_reason (str): Reason for role assignment (audit trail)
        last_validated_at (datetime): Timestamp of last assignment validation
        validation_count (int): Count of authorization validations for analytics
        metadata (dict): JSON storage for flexible assignment configuration
        audit_trail (dict): JSON storage for comprehensive audit logging
        created_at (datetime): Assignment creation timestamp from BaseModel
        updated_at (datetime): Assignment last update timestamp from BaseModel
        
    Relationships:
        user (User): Many-to-one relationship with User model
        role (Role): Many-to-one relationship with Role model
        assigned_by (User): Many-to-one relationship with assigning User
        organization (Organization): Many-to-one relationship with Organization (if multi-tenant)
    """
    
    __tablename__ = 'user_role_assignments'
    
    # Table arguments for performance optimization and integrity constraints
    __table_args__ = (
        # Unique constraint: One active assignment per user-role-organization combination
        UniqueConstraint(
            'user_id', 'role_id', 'organization_id',
            name='uq_user_role_assignment_unique'
        ),
        
        # Performance indexes for authorization queries
        Index('idx_user_role_user_active', 'user_id', 'is_active', 'status'),
        Index('idx_user_role_role_active', 'role_id', 'is_active', 'status'),
        Index('idx_user_role_user_role', 'user_id', 'role_id'),
        Index('idx_user_role_status_active', 'status', 'is_active'),
        Index('idx_user_role_expiration', 'expiration_date', 'is_active'),
        Index('idx_user_role_activation', 'activation_date', 'status'),
        Index('idx_user_role_priority', 'priority', 'is_active'),
        Index('idx_user_role_organization', 'organization_id', 'is_active'),
        Index('idx_user_role_assigned_by', 'assigned_by_id', 'created_at'),
        Index('idx_user_role_temporal', 'activation_date', 'expiration_date', 'is_active'),
        
        # Composite indexes for complex authorization queries
        Index(
            'idx_user_role_auth_lookup', 
            'user_id', 'role_id', 'is_active', 'status', 'activation_date', 'expiration_date'
        ),
        Index(
            'idx_user_role_admin_lookup',
            'assigned_by_id', 'created_at', 'status', 'is_active'
        ),
        
        # Check constraints for data integrity
        CheckConstraint('priority >= 0 AND priority <= 100', name='check_priority_range'),
        CheckConstraint('validation_count >= 0', name='check_validation_count_positive'),
        CheckConstraint(
            'activation_date <= expiration_date OR expiration_date IS NULL',
            name='check_activation_before_expiration'
        ),
        CheckConstraint(
            "status IN ('pending', 'active', 'suspended', 'expired', 'revoked', 'archived')",
            name='check_valid_assignment_status'
        ),
        
        # Database configuration
        {
            'mysql_engine': 'InnoDB',
            'mysql_charset': 'utf8mb4',
            'postgresql_tablespace': 'user_role_assignments_tablespace',
            'comment': 'User role assignments for Flask-Security RBAC implementation'
        }
    )
    
    # UUID for external references and API operations
    uuid = Column(
        UUID(as_uuid=True),
        default=uuid.uuid4,
        unique=True,
        nullable=False,
        comment='UUID for external assignment references and API operations'
    )
    
    # Foreign key relationships with proper constraints per Section 6.2.2.1
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        comment='Foreign key reference to Users table with cascade behavior'
    )
    
    role_id = Column(
        Integer,
        ForeignKey('roles.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        comment='Foreign key reference to Roles table with cascade behavior'
    )
    
    # Multi-tenant organization support
    organization_id = Column(
        Integer,
        ForeignKey('organizations.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=True,
        comment='Optional organization ID for multi-tenant role assignments'
    )
    
    # Assignment status and lifecycle management per Section 6.4.2.1
    status = Column(
        db.Enum(AssignmentStatus),
        nullable=False,
        default=AssignmentStatus.PENDING,
        comment='Assignment status for lifecycle management and authorization'
    )
    
    # Assignment priority for conflict resolution (0-100 scale)
    priority = Column(
        Integer,
        nullable=False,
        default=AssignmentPriority.NORMAL.value,
        comment='Assignment priority for role conflict resolution (0-100)'
    )
    
    # Boolean flags for performance optimization
    is_active = Column(
        Boolean,
        nullable=False,
        default=False,
        comment='Boolean flag for quick active/inactive filtering'
    )
    
    is_temporary = Column(
        Boolean,
        nullable=False,
        default=False,
        comment='Flag indicating temporary assignment versus permanent assignment'
    )
    
    # Temporal assignment fields per Section 6.4.2.1
    activation_date = Column(
        DateTime(timezone=True),
        nullable=True,
        comment='Date when assignment becomes active (null = immediate)'
    )
    
    expiration_date = Column(
        DateTime(timezone=True),
        nullable=True,
        comment='Date when assignment expires (null = permanent)'
    )
    
    # Assignment lifecycle timestamps for audit trails
    suspension_date = Column(
        DateTime(timezone=True),
        nullable=True,
        comment='Date when assignment was suspended for audit tracking'
    )
    
    revocation_date = Column(
        DateTime(timezone=True),
        nullable=True,
        comment='Date when assignment was revoked for audit tracking'
    )
    
    # Assignment attribution and audit tracking
    assigned_by_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL', onupdate='CASCADE'),
        nullable=True,
        comment='Foreign key to User who created the assignment for audit trail'
    )
    
    assigned_reason = Column(
        Text,
        nullable=True,
        comment='Reason for role assignment for audit trail and documentation'
    )
    
    # Assignment validation tracking for analytics and monitoring
    last_validated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment='Timestamp of last assignment validation for performance monitoring'
    )
    
    validation_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment='Count of authorization validations for usage analytics'
    )
    
    # JSON metadata storage for flexible assignment configuration per Section 6.2.4.1
    metadata = Column(
        JSONB,
        nullable=False,
        default=dict,
        comment='JSON metadata for flexible assignment configuration and properties'
    )
    
    # Comprehensive audit trail storage for security compliance per Section 6.4.2.5
    audit_trail = Column(
        JSONB,
        nullable=False,
        default=list,
        comment='JSON audit trail for comprehensive security compliance logging'
    )
    
    # SQLAlchemy Relationships with Performance Optimization
    
    # User relationship for assignment attribution
    user = relationship(
        'User',
        foreign_keys=[user_id],
        backref=db.backref(
            'role_assignments',
            lazy='select',
            cascade='all, delete-orphan',
            order_by='UserRoleAssignment.priority.desc(), UserRoleAssignment.created_at.desc()'
        ),
        lazy='select',
        comment='Many-to-one relationship with User model for assignment attribution'
    )
    
    # Role relationship for permission resolution
    role = relationship(
        'Role',
        foreign_keys=[role_id],
        backref=db.backref(
            'user_assignments',
            lazy='select',
            cascade='all, delete-orphan',
            order_by='UserRoleAssignment.priority.desc(), UserRoleAssignment.created_at.desc()'
        ),
        lazy='select',
        comment='Many-to-one relationship with Role model for permission resolution'
    )
    
    # Assignment creator relationship for audit trails
    assigned_by = relationship(
        'User',
        foreign_keys=[assigned_by_id],
        backref=db.backref(
            'created_assignments',
            lazy='select',
            order_by='UserRoleAssignment.created_at.desc()'
        ),
        lazy='select',
        comment='Many-to-one relationship with assigning User for audit tracking'
    )
    
    # Organization relationship for multi-tenant support
    organization = relationship(
        'Organization',
        backref=db.backref(
            'user_role_assignments',
            lazy='select',
            cascade='all, delete-orphan'
        ),
        lazy='select',
        comment='Many-to-one relationship with Organization for multi-tenant support'
    )
    
    # Hybrid Properties for Business Logic and Performance
    
    @hybrid_property
    def is_currently_active(self) -> bool:
        """
        Check if assignment is currently active considering all temporal constraints.
        
        An assignment is currently active if:
        1. Status is ACTIVE
        2. Current time is after activation_date (if set)
        3. Current time is before expiration_date (if set)
        4. is_active flag is True
        
        Returns:
            bool: True if assignment is currently active and grants permissions
        """
        if not self.is_active or self.status != AssignmentStatus.ACTIVE:
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Check activation date
        if self.activation_date and current_time < self.activation_date:
            return False
        
        # Check expiration date
        if self.expiration_date and current_time >= self.expiration_date:
            return False
        
        return True
    
    @hybrid_property
    def is_expired(self) -> bool:
        """
        Check if assignment has expired based on expiration_date.
        
        Returns:
            bool: True if assignment has passed its expiration date
        """
        if not self.expiration_date:
            return False
        
        return datetime.now(timezone.utc) >= self.expiration_date
    
    @hybrid_property
    def is_pending_activation(self) -> bool:
        """
        Check if assignment is pending activation based on activation_date.
        
        Returns:
            bool: True if assignment is pending activation
        """
        if self.status != AssignmentStatus.PENDING:
            return False
        
        if not self.activation_date:
            return True
        
        return datetime.now(timezone.utc) < self.activation_date
    
    @hybrid_property
    def days_until_expiration(self) -> Optional[int]:
        """
        Calculate days until assignment expiration.
        
        Returns:
            Optional[int]: Number of days until expiration or None if no expiration
        """
        if not self.expiration_date:
            return None
        
        current_time = datetime.now(timezone.utc)
        if current_time >= self.expiration_date:
            return 0
        
        delta = self.expiration_date - current_time
        return delta.days
    
    @hybrid_property
    def assignment_duration(self) -> Optional[timedelta]:
        """
        Calculate total duration of assignment from activation to expiration.
        
        Returns:
            Optional[timedelta]: Assignment duration or None if permanent
        """
        if not self.expiration_date:
            return None
        
        start_date = self.activation_date or self.created_at
        return self.expiration_date - start_date
    
    # Validation Methods
    
    @validates('user_id')
    def validate_user_id(self, key: str, user_id: int) -> int:
        """
        Validate user_id assignment.
        
        Args:
            key: Field name being validated
            user_id: User ID to validate
            
        Returns:
            int: Validated user ID
            
        Raises:
            ValueError: If user ID is invalid
        """
        if user_id is None:
            raise ValueError("User ID is required for role assignment")
        
        if user_id <= 0:
            raise ValueError("User ID must be positive")
        
        # Verify user exists and is active
        user = User.query.filter_by(id=user_id, is_active=True).first()
        if not user:
            raise ValueError(f"Active user with ID {user_id} not found")
        
        return user_id
    
    @validates('role_id')
    def validate_role_id(self, key: str, role_id: int) -> int:
        """
        Validate role_id assignment.
        
        Args:
            key: Field name being validated
            role_id: Role ID to validate
            
        Returns:
            int: Validated role ID
            
        Raises:
            ValueError: If role ID is invalid
        """
        if role_id is None:
            raise ValueError("Role ID is required for role assignment")
        
        if role_id <= 0:
            raise ValueError("Role ID must be positive")
        
        # Verify role exists and can be assigned
        role = Role.query.filter_by(id=role_id).first()
        if not role:
            raise ValueError(f"Role with ID {role_id} not found")
        
        if not role.can_be_assigned:
            raise ValueError(f"Role '{role.name}' cannot be assigned (status: {role.status.value})")
        
        return role_id
    
    @validates('priority')
    def validate_priority(self, key: str, priority: int) -> int:
        """
        Validate assignment priority.
        
        Args:
            key: Field name being validated
            priority: Priority value to validate
            
        Returns:
            int: Validated priority value
            
        Raises:
            ValueError: If priority is invalid
        """
        if priority is None:
            priority = AssignmentPriority.NORMAL.value
        
        if not isinstance(priority, int) or priority < 0 or priority > 100:
            raise ValueError("Priority must be an integer between 0 and 100")
        
        return priority
    
    @validates('activation_date', 'expiration_date')
    def validate_temporal_dates(self, key: str, date_value: Optional[datetime]) -> Optional[datetime]:
        """
        Validate temporal assignment dates.
        
        Args:
            key: Field name being validated
            date_value: Date value to validate
            
        Returns:
            Optional[datetime]: Validated date value
            
        Raises:
            ValueError: If date validation fails
        """
        if date_value is None:
            return None
        
        # Ensure timezone awareness
        if date_value.tzinfo is None:
            date_value = date_value.replace(tzinfo=timezone.utc)
        
        current_time = datetime.now(timezone.utc)
        
        if key == 'activation_date':
            # Activation date should not be more than 1 year in the future
            max_future = current_time + timedelta(days=365)
            if date_value > max_future:
                raise ValueError("Activation date cannot be more than 1 year in the future")
        
        elif key == 'expiration_date':
            # Expiration date should not be in the past (unless updating existing assignment)
            if hasattr(self, 'id') and self.id:
                # Existing assignment - allow past dates for historical records
                pass
            else:
                # New assignment - expiration should be in the future
                if date_value <= current_time:
                    raise ValueError("Expiration date must be in the future")
            
            # Expiration should not be more than 10 years in the future
            max_future = current_time + timedelta(days=3650)
            if date_value > max_future:
                raise ValueError("Expiration date cannot be more than 10 years in the future")
            
            # If activation date is set, expiration should be after activation
            if hasattr(self, 'activation_date') and self.activation_date:
                if date_value <= self.activation_date:
                    raise ValueError("Expiration date must be after activation date")
        
        return date_value
    
    # Assignment Management Methods
    
    def activate_assignment(self, activated_by: Optional[User] = None) -> bool:
        """
        Activate a pending assignment.
        
        Args:
            activated_by: User who activated the assignment (for audit trail)
            
        Returns:
            bool: True if assignment was activated, False otherwise
        """
        if self.status != AssignmentStatus.PENDING:
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Check if activation date allows activation
        if self.activation_date and current_time < self.activation_date:
            return False
        
        # Check if assignment has already expired
        if self.expiration_date and current_time >= self.expiration_date:
            self.status = AssignmentStatus.EXPIRED
            self.is_active = False
            self._add_audit_entry('expired_on_activation', {
                'expired_at': current_time.isoformat(),
                'expiration_date': self.expiration_date.isoformat()
            })
            return False
        
        # Activate the assignment
        self.status = AssignmentStatus.ACTIVE
        self.is_active = True
        self.activation_date = self.activation_date or current_time
        
        # Add audit trail entry
        self._add_audit_entry('activated', {
            'activated_at': current_time.isoformat(),
            'activated_by': activated_by.id if activated_by else None,
            'previous_status': AssignmentStatus.PENDING.value
        })
        
        return True
    
    def suspend_assignment(self, suspended_by: Optional[User] = None, reason: str = None) -> bool:
        """
        Suspend an active assignment.
        
        Args:
            suspended_by: User who suspended the assignment
            reason: Reason for suspension
            
        Returns:
            bool: True if assignment was suspended, False otherwise
        """
        if self.status != AssignmentStatus.ACTIVE:
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Update assignment status
        previous_status = self.status
        self.status = AssignmentStatus.SUSPENDED
        self.is_active = False
        self.suspension_date = current_time
        
        # Add audit trail entry
        self._add_audit_entry('suspended', {
            'suspended_at': current_time.isoformat(),
            'suspended_by': suspended_by.id if suspended_by else None,
            'reason': reason,
            'previous_status': previous_status.value
        })
        
        return True
    
    def reactivate_assignment(self, reactivated_by: Optional[User] = None) -> bool:
        """
        Reactivate a suspended assignment.
        
        Args:
            reactivated_by: User who reactivated the assignment
            
        Returns:
            bool: True if assignment was reactivated, False otherwise
        """
        if self.status != AssignmentStatus.SUSPENDED:
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Check if assignment has expired while suspended
        if self.expiration_date and current_time >= self.expiration_date:
            self.status = AssignmentStatus.EXPIRED
            self.is_active = False
            self._add_audit_entry('expired_during_suspension', {
                'expired_at': current_time.isoformat(),
                'expiration_date': self.expiration_date.isoformat()
            })
            return False
        
        # Reactivate the assignment
        previous_status = self.status
        self.status = AssignmentStatus.ACTIVE
        self.is_active = True
        self.suspension_date = None
        
        # Add audit trail entry
        self._add_audit_entry('reactivated', {
            'reactivated_at': current_time.isoformat(),
            'reactivated_by': reactivated_by.id if reactivated_by else None,
            'previous_status': previous_status.value
        })
        
        return True
    
    def revoke_assignment(self, revoked_by: Optional[User] = None, reason: str = None) -> bool:
        """
        Revoke an assignment permanently.
        
        Args:
            revoked_by: User who revoked the assignment
            reason: Reason for revocation
            
        Returns:
            bool: True if assignment was revoked, False otherwise
        """
        if self.status in AssignmentStatus.get_terminal_statuses():
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Update assignment status
        previous_status = self.status
        self.status = AssignmentStatus.REVOKED
        self.is_active = False
        self.revocation_date = current_time
        
        # Add audit trail entry
        self._add_audit_entry('revoked', {
            'revoked_at': current_time.isoformat(),
            'revoked_by': revoked_by.id if revoked_by else None,
            'reason': reason,
            'previous_status': previous_status.value
        })
        
        return True
    
    def expire_assignment(self) -> bool:
        """
        Mark assignment as expired (typically called by automated processes).
        
        Returns:
            bool: True if assignment was expired, False otherwise
        """
        if self.status in AssignmentStatus.get_terminal_statuses():
            return False
        
        if not self.expiration_date:
            return False
        
        current_time = datetime.now(timezone.utc)
        if current_time < self.expiration_date:
            return False
        
        # Update assignment status
        previous_status = self.status
        self.status = AssignmentStatus.EXPIRED
        self.is_active = False
        
        # Add audit trail entry
        self._add_audit_entry('expired', {
            'expired_at': current_time.isoformat(),
            'expiration_date': self.expiration_date.isoformat(),
            'previous_status': previous_status.value
        })
        
        return True
    
    def extend_expiration(self, new_expiration_date: datetime, 
                         extended_by: Optional[User] = None, reason: str = None) -> bool:
        """
        Extend assignment expiration date.
        
        Args:
            new_expiration_date: New expiration date
            extended_by: User who extended the assignment
            reason: Reason for extension
            
        Returns:
            bool: True if expiration was extended, False otherwise
        """
        if self.status in AssignmentStatus.get_terminal_statuses():
            return False
        
        # Validate new expiration date
        current_time = datetime.now(timezone.utc)
        if new_expiration_date <= current_time:
            raise ValueError("New expiration date must be in the future")
        
        if self.expiration_date and new_expiration_date <= self.expiration_date:
            raise ValueError("New expiration date must be later than current expiration")
        
        # Update expiration date
        old_expiration = self.expiration_date
        self.expiration_date = new_expiration_date
        
        # If assignment was expired, potentially reactivate it
        if self.status == AssignmentStatus.EXPIRED:
            self.status = AssignmentStatus.ACTIVE
            self.is_active = True
        
        # Add audit trail entry
        self._add_audit_entry('expiration_extended', {
            'extended_at': current_time.isoformat(),
            'extended_by': extended_by.id if extended_by else None,
            'reason': reason,
            'old_expiration': old_expiration.isoformat() if old_expiration else None,
            'new_expiration': new_expiration_date.isoformat()
        })
        
        return True
    
    def validate_assignment(self) -> bool:
        """
        Validate assignment and update validation tracking.
        
        Returns:
            bool: True if assignment is valid for authorization, False otherwise
        """
        current_time = datetime.now(timezone.utc)
        
        # Update validation tracking
        self.last_validated_at = current_time
        self.validation_count += 1
        
        # Check if assignment is currently active
        if not self.is_currently_active:
            return False
        
        # Verify user is still active
        if not self.user or not self.user.is_active:
            return False
        
        # Verify role can still be assigned
        if not self.role or not self.role.can_be_assigned:
            return False
        
        return True
    
    def get_effective_permissions(self) -> Set[str]:
        """
        Get effective permissions granted by this assignment.
        
        Returns:
            Set[str]: Set of permission names granted by this role assignment
        """
        if not self.is_currently_active or not self.role:
            return set()
        
        return self.role.get_inherited_permissions()
    
    def has_permission(self, permission_name: str, resource: Optional[str] = None) -> bool:
        """
        Check if this assignment grants a specific permission.
        
        Args:
            permission_name: Permission name to check
            resource: Optional resource identifier
            
        Returns:
            bool: True if assignment grants the permission, False otherwise
        """
        if not self.is_currently_active or not self.role:
            return False
        
        return self.role.has_permission(permission_name, resource)
    
    # Audit Trail Management
    
    def _add_audit_entry(self, action: str, details: Dict[str, Any]) -> None:
        """
        Add entry to audit trail.
        
        Args:
            action: Action type for audit logging
            details: Dictionary of action details
        """
        if not isinstance(self.audit_trail, list):
            self.audit_trail = []
        
        audit_entry = {
            'action': action,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': details,
            'ip_address': getattr(request, 'remote_addr', None) if request else None,
            'user_agent': getattr(request, 'headers', {}).get('User-Agent') if request else None,
            'session_id': getattr(g, 'session_id', None) if g else None
        }
        
        self.audit_trail.append(audit_entry)
        
        # Limit audit trail size (keep last 100 entries)
        if len(self.audit_trail) > 100:
            self.audit_trail = self.audit_trail[-100:]
    
    def get_audit_summary(self) -> Dict[str, Any]:
        """
        Get summary of audit trail activities.
        
        Returns:
            Dict[str, Any]: Summary of audit activities
        """
        if not self.audit_trail:
            return {}
        
        activities = {}
        for entry in self.audit_trail:
            action = entry.get('action', 'unknown')
            activities[action] = activities.get(action, 0) + 1
        
        return {
            'total_entries': len(self.audit_trail),
            'activities': activities,
            'first_entry': self.audit_trail[0]['timestamp'] if self.audit_trail else None,
            'last_entry': self.audit_trail[-1]['timestamp'] if self.audit_trail else None
        }
    
    # Class Methods for Assignment Management
    
    @classmethod
    def create_assignment(
        cls,
        user_id: int,
        role_id: int,
        assigned_by: Optional[User] = None,
        organization_id: Optional[int] = None,
        activation_date: Optional[datetime] = None,
        expiration_date: Optional[datetime] = None,
        priority: int = AssignmentPriority.NORMAL.value,
        assigned_reason: str = None,
        metadata: Dict[str, Any] = None,
        auto_activate: bool = True
    ) -> 'UserRoleAssignment':
        """
        Create a new user role assignment with validation.
        
        Args:
            user_id: ID of user to assign role to
            role_id: ID of role to assign
            assigned_by: User creating the assignment
            organization_id: Optional organization ID for multi-tenant
            activation_date: Optional activation date (None = immediate)
            expiration_date: Optional expiration date (None = permanent)
            priority: Assignment priority (0-100)
            assigned_reason: Reason for assignment
            metadata: Additional metadata
            auto_activate: Whether to auto-activate if activation_date allows
            
        Returns:
            UserRoleAssignment: Created assignment instance
            
        Raises:
            ValueError: If assignment validation fails
        """
        # Check for existing active assignment
        existing = cls.get_active_assignment(user_id, role_id, organization_id)
        if existing:
            raise ValueError(
                f"User {user_id} already has active assignment for role {role_id}"
            )
        
        # Create assignment instance
        assignment = cls(
            user_id=user_id,
            role_id=role_id,
            organization_id=organization_id,
            assigned_by_id=assigned_by.id if assigned_by else None,
            activation_date=activation_date,
            expiration_date=expiration_date,
            priority=priority,
            assigned_reason=assigned_reason,
            metadata=metadata or {},
            status=AssignmentStatus.PENDING,
            is_active=False
        )
        
        # Add to session
        db.session.add(assignment)
        
        # Auto-activate if conditions are met
        if auto_activate:
            current_time = datetime.now(timezone.utc)
            if not activation_date or current_time >= activation_date:
                assignment.activate_assignment(assigned_by)
        
        # Add initial audit entry
        assignment._add_audit_entry('created', {
            'created_by': assigned_by.id if assigned_by else None,
            'reason': assigned_reason,
            'auto_activated': auto_activate and assignment.is_active
        })
        
        return assignment
    
    @classmethod
    def get_active_assignment(
        cls,
        user_id: int,
        role_id: int,
        organization_id: Optional[int] = None
    ) -> Optional['UserRoleAssignment']:
        """
        Get active assignment for user-role combination.
        
        Args:
            user_id: User ID
            role_id: Role ID
            organization_id: Optional organization ID
            
        Returns:
            Optional[UserRoleAssignment]: Active assignment or None
        """
        query = cls.query.filter_by(
            user_id=user_id,
            role_id=role_id,
            is_active=True,
            status=AssignmentStatus.ACTIVE
        )
        
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        
        return query.first()
    
    @classmethod
    def get_user_assignments(
        cls,
        user_id: int,
        active_only: bool = True,
        organization_id: Optional[int] = None
    ) -> List['UserRoleAssignment']:
        """
        Get all assignments for a user.
        
        Args:
            user_id: User ID
            active_only: Whether to return only active assignments
            organization_id: Optional organization filter
            
        Returns:
            List[UserRoleAssignment]: List of user assignments
        """
        query = cls.query.filter_by(user_id=user_id)
        
        if active_only:
            query = query.filter_by(is_active=True, status=AssignmentStatus.ACTIVE)
        
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        
        return query.order_by(
            cls.priority.desc(),
            cls.created_at.desc()
        ).all()
    
    @classmethod
    def get_role_assignments(
        cls,
        role_id: int,
        active_only: bool = True,
        organization_id: Optional[int] = None
    ) -> List['UserRoleAssignment']:
        """
        Get all assignments for a role.
        
        Args:
            role_id: Role ID
            active_only: Whether to return only active assignments
            organization_id: Optional organization filter
            
        Returns:
            List[UserRoleAssignment]: List of role assignments
        """
        query = cls.query.filter_by(role_id=role_id)
        
        if active_only:
            query = query.filter_by(is_active=True, status=AssignmentStatus.ACTIVE)
        
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        
        return query.order_by(
            cls.priority.desc(),
            cls.created_at.desc()
        ).all()
    
    @classmethod
    def get_expiring_assignments(
        cls,
        days_ahead: int = 30,
        organization_id: Optional[int] = None
    ) -> List['UserRoleAssignment']:
        """
        Get assignments expiring within specified days.
        
        Args:
            days_ahead: Number of days to look ahead for expiration
            organization_id: Optional organization filter
            
        Returns:
            List[UserRoleAssignment]: List of expiring assignments
        """
        current_time = datetime.now(timezone.utc)
        expiration_threshold = current_time + timedelta(days=days_ahead)
        
        query = cls.query.filter(
            cls.is_active == True,
            cls.status == AssignmentStatus.ACTIVE,
            cls.expiration_date.isnot(None),
            cls.expiration_date <= expiration_threshold,
            cls.expiration_date > current_time
        )
        
        if organization_id:
            query = query.filter_by(organization_id=organization_id)
        
        return query.order_by(cls.expiration_date.asc()).all()
    
    @classmethod
    def expire_assignments(cls, batch_size: int = 100) -> int:
        """
        Expire assignments that have passed their expiration date.
        
        Args:
            batch_size: Number of assignments to process in each batch
            
        Returns:
            int: Number of assignments expired
        """
        current_time = datetime.now(timezone.utc)
        expired_count = 0
        
        # Process in batches to avoid large transactions
        while True:
            expired_assignments = cls.query.filter(
                cls.is_active == True,
                cls.status.in_([AssignmentStatus.ACTIVE, AssignmentStatus.SUSPENDED]),
                cls.expiration_date.isnot(None),
                cls.expiration_date <= current_time
            ).limit(batch_size).all()
            
            if not expired_assignments:
                break
            
            for assignment in expired_assignments:
                if assignment.expire_assignment():
                    expired_count += 1
            
            # Commit batch
            db.session.commit()
        
        return expired_count
    
    @classmethod
    def cleanup_old_assignments(
        cls,
        days_old: int = 365,
        status_filter: Optional[List[AssignmentStatus]] = None
    ) -> int:
        """
        Archive old assignments for historical record keeping.
        
        Args:
            days_old: Age threshold in days for archival
            status_filter: Optional list of statuses to archive
            
        Returns:
            int: Number of assignments archived
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
        archived_count = 0
        
        # Default to archiving terminal statuses
        if status_filter is None:
            status_filter = [AssignmentStatus.EXPIRED, AssignmentStatus.REVOKED]
        
        old_assignments = cls.query.filter(
            cls.status.in_(status_filter),
            cls.updated_at <= cutoff_date
        ).all()
        
        for assignment in old_assignments:
            if assignment.status != AssignmentStatus.ARCHIVED:
                previous_status = assignment.status
                assignment.status = AssignmentStatus.ARCHIVED
                assignment.is_active = False
                
                assignment._add_audit_entry('archived', {
                    'archived_at': datetime.now(timezone.utc).isoformat(),
                    'previous_status': previous_status.value,
                    'days_old': days_old
                })
                
                archived_count += 1
        
        if archived_count > 0:
            db.session.commit()
        
        return archived_count
    
    @classmethod
    def get_assignment_statistics(
        cls,
        organization_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get assignment statistics for monitoring and analytics.
        
        Args:
            organization_id: Optional organization filter
            
        Returns:
            Dict[str, Any]: Assignment statistics
        """
        base_query = cls.query
        if organization_id:
            base_query = base_query.filter_by(organization_id=organization_id)
        
        # Status distribution
        status_counts = {}
        for status in AssignmentStatus:
            count = base_query.filter_by(status=status).count()
            status_counts[status.value] = count
        
        # Active assignments by role type
        active_by_role = {}
        active_assignments = base_query.filter_by(
            is_active=True,
            status=AssignmentStatus.ACTIVE
        ).join(Role).all()
        
        for assignment in active_assignments:
            role_type = assignment.role.role_type.value
            active_by_role[role_type] = active_by_role.get(role_type, 0) + 1
        
        # Temporal statistics
        current_time = datetime.now(timezone.utc)
        expiring_7_days = base_query.filter(
            cls.is_active == True,
            cls.expiration_date.isnot(None),
            cls.expiration_date <= current_time + timedelta(days=7),
            cls.expiration_date > current_time
        ).count()
        
        expiring_30_days = base_query.filter(
            cls.is_active == True,
            cls.expiration_date.isnot(None),
            cls.expiration_date <= current_time + timedelta(days=30),
            cls.expiration_date > current_time
        ).count()
        
        return {
            'total_assignments': base_query.count(),
            'active_assignments': status_counts.get(AssignmentStatus.ACTIVE.value, 0),
            'status_distribution': status_counts,
            'active_by_role_type': active_by_role,
            'expiring_within_7_days': expiring_7_days,
            'expiring_within_30_days': expiring_30_days,
            'generated_at': current_time.isoformat()
        }
    
    # Flask-Principal Integration Methods
    
    def get_principal_needs(self) -> Set[str]:
        """
        Get Flask-Principal needs for this assignment.
        
        Returns:
            Set[str]: Set of principal need identifiers
        """
        if not self.is_currently_active or not self.role:
            return set()
        
        return self.role.get_principal_needs()
    
    # Serialization Methods for API Responses
    
    def to_dict(self, include_audit: bool = False, include_relationships: bool = False) -> Dict[str, Any]:
        """
        Convert assignment to dictionary for API responses.
        
        Args:
            include_audit: Whether to include audit trail data
            include_relationships: Whether to include relationship data
            
        Returns:
            Dict[str, Any]: Assignment data as dictionary
        """
        data = {
            'id': self.id,
            'uuid': str(self.uuid),
            'user_id': self.user_id,
            'role_id': self.role_id,
            'organization_id': self.organization_id,
            'status': self.status.value,
            'priority': self.priority,
            'is_active': self.is_active,
            'is_temporary': self.is_temporary,
            'is_currently_active': self.is_currently_active,
            'is_expired': self.is_expired,
            'is_pending_activation': self.is_pending_activation,
            'activation_date': self.activation_date.isoformat() if self.activation_date else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'days_until_expiration': self.days_until_expiration,
            'assigned_by_id': self.assigned_by_id,
            'assigned_reason': self.assigned_reason,
            'last_validated_at': self.last_validated_at.isoformat() if self.last_validated_at else None,
            'validation_count': self.validation_count,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_relationships:
            data.update({
                'user': self.user.to_dict() if self.user else None,
                'role': self.role.to_dict() if self.role else None,
                'assigned_by': self.assigned_by.to_dict() if self.assigned_by else None,
                'effective_permissions': list(self.get_effective_permissions())
            })
        
        if include_audit:
            data.update({
                'audit_trail': self.audit_trail,
                'audit_summary': self.get_audit_summary()
            })
        
        return data
    
    # String Representation and Debugging
    
    def __str__(self) -> str:
        """User-friendly string representation."""
        user_name = self.user.username if self.user else f"User#{self.user_id}"
        role_name = self.role.name if self.role else f"Role#{self.role_id}"
        return f"{user_name} → {role_name} ({self.status.value})"
    
    def __repr__(self) -> str:
        """Developer string representation."""
        return (
            f"<UserRoleAssignment(id={self.id}, user_id={self.user_id}, "
            f"role_id={self.role_id}, status={self.status.value}, "
            f"active={self.is_active})>"
        )


# SQLAlchemy Event Listeners for Audit and Performance

@event.listens_for(UserRoleAssignment, 'before_insert')
def assignment_before_insert(mapper, connection, target):
    """
    Event listener for assignment creation.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: UserRoleAssignment instance being inserted
    """
    # Ensure UUID is set
    if target.uuid is None:
        target.uuid = uuid.uuid4()
    
    # Set timestamps
    current_time = datetime.now(timezone.utc)
    if target.created_at is None:
        target.created_at = current_time
    target.updated_at = current_time
    
    # Initialize audit trail if empty
    if not target.audit_trail:
        target.audit_trail = []


@event.listens_for(UserRoleAssignment, 'before_update')
def assignment_before_update(mapper, connection, target):
    """
    Event listener for assignment updates.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: UserRoleAssignment instance being updated
    """
    # Update timestamp
    target.updated_at = datetime.now(timezone.utc)
    
    # Auto-expire if past expiration date
    if (target.expiration_date and 
        target.status == AssignmentStatus.ACTIVE and
        datetime.now(timezone.utc) >= target.expiration_date):
        target.status = AssignmentStatus.EXPIRED
        target.is_active = False


@event.listens_for(UserRoleAssignment, 'after_insert')
def assignment_after_insert(mapper, connection, target):
    """
    Event listener after assignment creation.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: UserRoleAssignment instance that was inserted
    """
    # Log assignment creation for monitoring
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        f"Role assignment created: User {target.user_id} → Role {target.role_id} "
        f"(Status: {target.status.value}, Active: {target.is_active})"
    )


@event.listens_for(UserRoleAssignment, 'after_update')
def assignment_after_update(mapper, connection, target):
    """
    Event listener after assignment updates.
    
    Args:
        mapper: SQLAlchemy mapper
        connection: Database connection
        target: UserRoleAssignment instance that was updated
    """
    # Log significant status changes
    if hasattr(target, '_sa_instance_state'):
        status_history = target._sa_instance_state.get_history('status', True)
        if status_history.has_changes():
            import logging
            logger = logging.getLogger(__name__)
            old_status = status_history.deleted[0] if status_history.deleted else None
            logger.info(
                f"Role assignment status changed: User {target.user_id} → Role {target.role_id} "
                f"({old_status} → {target.status.value})"
            )


# Performance Optimization: Compiled Queries for Common Operations

def get_user_active_assignments_query(user_id: int):
    """Compiled query for user's active assignments."""
    return (
        db.session.query(UserRoleAssignment)
        .filter(
            UserRoleAssignment.user_id == user_id,
            UserRoleAssignment.is_active == True,
            UserRoleAssignment.status == AssignmentStatus.ACTIVE
        )
        .options(joinedload(UserRoleAssignment.role))
        .order_by(UserRoleAssignment.priority.desc())
    )


def get_role_active_assignments_query(role_id: int):
    """Compiled query for role's active assignments."""
    return (
        db.session.query(UserRoleAssignment)
        .filter(
            UserRoleAssignment.role_id == role_id,
            UserRoleAssignment.is_active == True,
            UserRoleAssignment.status == AssignmentStatus.ACTIVE
        )
        .options(joinedload(UserRoleAssignment.user))
        .order_by(UserRoleAssignment.created_at.desc())
    )


def get_expiring_assignments_query(days_ahead: int = 30):
    """Compiled query for expiring assignments."""
    current_time = datetime.now(timezone.utc)
    expiration_threshold = current_time + timedelta(days=days_ahead)
    
    return (
        db.session.query(UserRoleAssignment)
        .filter(
            UserRoleAssignment.is_active == True,
            UserRoleAssignment.status == AssignmentStatus.ACTIVE,
            UserRoleAssignment.expiration_date.isnot(None),
            UserRoleAssignment.expiration_date <= expiration_threshold,
            UserRoleAssignment.expiration_date > current_time
        )
        .options(
            joinedload(UserRoleAssignment.user),
            joinedload(UserRoleAssignment.role)
        )
        .order_by(UserRoleAssignment.expiration_date.asc())
    )


# Authorization Helper Functions

def has_user_role(user_id: int, role_type: RoleType, organization_id: Optional[int] = None) -> bool:
    """
    Check if user has active assignment for specified role type.
    
    Args:
        user_id: User ID to check
        role_type: Role type to check for
        organization_id: Optional organization context
        
    Returns:
        bool: True if user has active assignment for role type
    """
    query = (
        db.session.query(UserRoleAssignment)
        .join(Role, UserRoleAssignment.role_id == Role.id)
        .filter(
            UserRoleAssignment.user_id == user_id,
            UserRoleAssignment.is_active == True,
            UserRoleAssignment.status == AssignmentStatus.ACTIVE,
            Role.role_type == role_type,
            Role.is_active == True,
            Role.status == RoleStatus.ACTIVE
        )
    )
    
    if organization_id:
        query = query.filter(UserRoleAssignment.organization_id == organization_id)
    
    return query.first() is not None


def get_user_permissions(user_id: int, organization_id: Optional[int] = None) -> Set[str]:
    """
    Get all permissions for a user from their active role assignments.
    
    Args:
        user_id: User ID to get permissions for
        organization_id: Optional organization context
        
    Returns:
        Set[str]: Set of permission names granted to the user
    """
    assignments = get_user_active_assignments_query(user_id).all()
    
    if organization_id:
        assignments = [a for a in assignments if a.organization_id == organization_id]
    
    permissions = set()
    for assignment in assignments:
        permissions.update(assignment.get_effective_permissions())
    
    return permissions


def user_has_permission(user_id: int, permission_name: str, 
                       resource: Optional[str] = None,
                       organization_id: Optional[int] = None) -> bool:
    """
    Check if user has specific permission through their role assignments.
    
    Args:
        user_id: User ID to check
        permission_name: Permission name to check for
        resource: Optional resource identifier
        organization_id: Optional organization context
        
    Returns:
        bool: True if user has the permission
    """
    assignments = get_user_active_assignments_query(user_id).all()
    
    if organization_id:
        assignments = [a for a in assignments if a.organization_id == organization_id]
    
    for assignment in assignments:
        if assignment.has_permission(permission_name, resource):
            return True
    
    return False


# Flask-Principal Authorization Decorator
def requires_role(role_type: RoleType, organization_id: Optional[int] = None):
    """
    Decorator to require specific role for Flask route access.
    
    Args:
        role_type: Required role type
        organization_id: Optional organization context
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            from flask import abort
            
            if not current_user or not current_user.is_authenticated:
                abort(401)  # Unauthorized
            
            if not has_user_role(current_user.id, role_type, organization_id):
                abort(403)  # Forbidden
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def requires_permission(permission_name: str, resource: Optional[str] = None,
                       organization_id: Optional[int] = None):
    """
    Decorator to require specific permission for Flask route access.
    
    Args:
        permission_name: Required permission name
        resource: Optional resource identifier
        organization_id: Optional organization context
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_login import current_user
            from flask import abort
            
            if not current_user or not current_user.is_authenticated:
                abort(401)  # Unauthorized
            
            if not user_has_permission(current_user.id, permission_name, resource, organization_id):
                abort(403)  # Forbidden
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# Export all public components
__all__ = [
    'UserRoleAssignment',
    'AssignmentStatus',
    'AssignmentPriority',
    'get_user_active_assignments_query',
    'get_role_active_assignments_query',
    'get_expiring_assignments_query',
    'has_user_role',
    'get_user_permissions',
    'user_has_permission',
    'requires_role',
    'requires_permission'
]