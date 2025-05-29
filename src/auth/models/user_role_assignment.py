"""
UserRoleAssignment Model for Flask-Security RBAC Implementation.

This module implements the UserRoleAssignment association model that manages
the many-to-many relationship between Users and Roles with comprehensive
metadata tracking for role assignment lifecycle management. The model provides
temporal role assignment capabilities, audit trails, and business logic validation
for Flask-Security RBAC compliance.

Key Features:
- Many-to-many User-Role relationship with association table pattern
- Temporal role assignment with activation and expiration capabilities
- Comprehensive audit trail and assignment lifecycle management
- Role assignment validation for authorization system compliance
- Foreign key constraints with proper cascading behavior
- Integration with Flask-Principal Need/Provide pattern for authorization
- Assignment status tracking and business logic validation

Technical Specification References:
- Section 6.4.2.1: Role-Based Access Control (RBAC) implementation
- Section 6.2.2.1: Database relationship integrity with proper foreign key constraints
- Section 6.4.2.5: Audit logging for comprehensive audit trails
- Feature F-007: Authentication mechanism migration to Flask-Security
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey,
    Index, UniqueConstraint, CheckConstraint, Enum as SQLEnum, event
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property

from ...models.base import BaseModel, db


class AssignmentStatus(Enum):
    """
    Enumeration for role assignment status values.
    
    Provides type-safe status management for role assignment lifecycle
    with clear state transitions and business logic validation.
    """
    PENDING = "pending"          # Assignment created but not yet active
    ACTIVE = "active"            # Assignment is currently active and enforced
    EXPIRED = "expired"          # Assignment has passed expiration date
    REVOKED = "revoked"          # Assignment manually revoked by administrator
    SUSPENDED = "suspended"      # Assignment temporarily suspended


class AssignmentSource(Enum):
    """
    Enumeration for role assignment source tracking.
    
    Tracks how role assignments were created for audit and compliance purposes.
    """
    MANUAL = "manual"            # Manually assigned by administrator
    AUTOMATIC = "automatic"      # Automatically assigned by system rules
    INHERITED = "inherited"      # Inherited from group or organizational role
    IMPORTED = "imported"        # Imported during data migration or bulk operation
    API = "api"                 # Assigned via API integration
    SSO = "sso"                 # Assigned via Single Sign-On integration


class UserRoleAssignment(BaseModel):
    """
    Association model implementing many-to-many relationship between Users and Roles.
    
    This model extends the basic many-to-many pattern to include comprehensive
    metadata for role assignment tracking, temporal assignment capabilities,
    and audit trail management. Essential for Flask-Security RBAC implementation
    and authorization system compliance.
    
    Attributes:
        id (int): Primary key for the assignment record
        user_id (int): Foreign key reference to User model
        role_id (int): Foreign key reference to Role model
        status (AssignmentStatus): Current status of the role assignment
        source (AssignmentSource): How the assignment was created
        assigned_by_id (int): User ID of who created the assignment (for audit)
        assigned_at (datetime): When the assignment was created
        activated_at (datetime): When the assignment became active
        expires_at (datetime): When the assignment expires (None for permanent)
        revoked_at (datetime): When the assignment was revoked (if applicable)
        revoked_by_id (int): User ID of who revoked the assignment
        revoked_reason (str): Reason for assignment revocation
        metadata (dict): Additional assignment metadata as JSON
        notes (str): Human-readable notes about the assignment
    
    Relationships:
        user (User): Many-to-one relationship with User model
        role (Role): Many-to-one relationship with Role model
        assigned_by (User): Many-to-one relationship with User who created assignment
        revoked_by (User): Many-to-one relationship with User who revoked assignment
    """
    
    __tablename__ = 'user_role_assignments'
    
    # Foreign key relationships with proper constraints per Section 6.2.2.1
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key reference to User model with CASCADE deletion"
    )
    
    role_id = Column(
        Integer,
        ForeignKey('roles.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key reference to Role model with CASCADE deletion"
    )
    
    # Assignment status and lifecycle management
    status = Column(
        SQLEnum(AssignmentStatus),
        nullable=False,
        default=AssignmentStatus.PENDING,
        index=True,
        comment="Current status of the role assignment for lifecycle management"
    )
    
    source = Column(
        SQLEnum(AssignmentSource),
        nullable=False,
        default=AssignmentSource.MANUAL,
        index=True,
        comment="Source of the role assignment for audit and compliance tracking"
    )
    
    # Audit trail fields per Section 6.4.2.5
    assigned_by_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="User ID of who created the assignment for audit trail"
    )
    
    assigned_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Timestamp when the assignment was created"
    )
    
    # Temporal assignment fields per Section 6.4.2.1
    activated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp when the assignment became active (None for immediate)"
    )
    
    expires_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp when the assignment expires (None for permanent)"
    )
    
    # Revocation tracking for security and audit compliance
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp when the assignment was revoked"
    )
    
    revoked_by_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='SET NULL'),
        nullable=True,
        comment="User ID of who revoked the assignment"
    )
    
    revoked_reason = Column(
        String(500),
        nullable=True,
        comment="Human-readable reason for assignment revocation"
    )
    
    # Additional metadata and notes
    metadata = Column(
        Text,
        nullable=True,
        comment="Additional assignment metadata stored as JSON"
    )
    
    notes = Column(
        Text,
        nullable=True,
        comment="Human-readable notes about the assignment"
    )
    
    # SQLAlchemy relationships with proper loading strategies
    user = relationship(
        'User',
        foreign_keys=[user_id],
        back_populates='role_assignments',
        lazy='select',
        doc="Many-to-one relationship with User model"
    )
    
    role = relationship(
        'Role',
        foreign_keys=[role_id],
        back_populates='user_assignments', 
        lazy='select',
        doc="Many-to-one relationship with Role model"
    )
    
    assigned_by = relationship(
        'User',
        foreign_keys=[assigned_by_id],
        lazy='select',
        doc="Many-to-one relationship with User who created the assignment"
    )
    
    revoked_by = relationship(
        'User',
        foreign_keys=[revoked_by_id],
        lazy='select',
        doc="Many-to-one relationship with User who revoked the assignment"
    )
    
    # Database constraints for data integrity and performance
    __table_args__ = (
        # Unique constraint to prevent duplicate active assignments
        UniqueConstraint(
            'user_id', 'role_id', 'status',
            name='uq_user_role_active_assignment'
        ),
        
        # Check constraints for business rule validation
        CheckConstraint(
            "activated_at IS NULL OR activated_at >= assigned_at",
            name='ck_assignment_activation_after_creation'
        ),
        
        CheckConstraint(
            "expires_at IS NULL OR expires_at > assigned_at",
            name='ck_assignment_expiration_after_creation'
        ),
        
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= assigned_at",
            name='ck_assignment_revocation_after_creation'
        ),
        
        CheckConstraint(
            "(status != 'revoked') OR (revoked_at IS NOT NULL)",
            name='ck_revoked_status_has_timestamp'
        ),
        
        # Composite indexes for query performance optimization
        Index('ix_user_role_assignment_user_status', 'user_id', 'status'),
        Index('ix_user_role_assignment_role_status', 'role_id', 'status'),
        Index('ix_user_role_assignment_expiration', 'expires_at', 'status'),
        Index('ix_user_role_assignment_activation', 'activated_at', 'status'),
        Index('ix_user_role_assignment_audit', 'assigned_by_id', 'assigned_at'),
        Index('ix_user_role_assignment_temporal', 'user_id', 'activated_at', 'expires_at'),
        
        # Table comment for documentation
        {'comment': 'User role assignments with temporal and audit capabilities for RBAC'}
    )
    
    def __init__(self, user_id: int, role_id: int, **kwargs):
        """
        Initialize a new UserRoleAssignment with validation.
        
        Args:
            user_id (int): ID of the user receiving the role assignment
            role_id (int): ID of the role being assigned
            **kwargs: Additional assignment parameters
            
        Raises:
            ValueError: If required parameters are missing or invalid
        """
        # Validate required parameters
        if not user_id or not isinstance(user_id, int):
            raise ValueError("Valid user_id is required for role assignment")
        
        if not role_id or not isinstance(role_id, int):
            raise ValueError("Valid role_id is required for role assignment")
        
        # Set basic assignment fields
        self.user_id = user_id
        self.role_id = role_id
        
        # Initialize with defaults and provided kwargs
        super().__init__(**kwargs)
        
        # Set default assigned_at if not provided
        if not hasattr(self, 'assigned_at') or self.assigned_at is None:
            self.assigned_at = datetime.now(timezone.utc)
        
        # Auto-activate if no specific activation time provided
        if self.status == AssignmentStatus.PENDING and self.activated_at is None:
            self.activated_at = self.assigned_at
            self.status = AssignmentStatus.ACTIVE
    
    @validates('expires_at')
    def validate_expiration(self, key: str, expires_at: Optional[datetime]) -> Optional[datetime]:
        """
        Validate expiration timestamp for business rule compliance.
        
        Args:
            key (str): The attribute name being validated
            expires_at (Optional[datetime]): The expiration timestamp to validate
            
        Returns:
            Optional[datetime]: The validated expiration timestamp
            
        Raises:
            ValueError: If expiration timestamp violates business rules
        """
        if expires_at is not None:
            # Ensure expiration is in the future
            current_time = datetime.now(timezone.utc)
            if expires_at <= current_time:
                raise ValueError("Expiration timestamp must be in the future")
            
            # Ensure expiration is after assignment creation
            if hasattr(self, 'assigned_at') and self.assigned_at and expires_at <= self.assigned_at:
                raise ValueError("Expiration timestamp must be after assignment creation")
        
        return expires_at
    
    @validates('activated_at')
    def validate_activation(self, key: str, activated_at: Optional[datetime]) -> Optional[datetime]:
        """
        Validate activation timestamp for business rule compliance.
        
        Args:
            key (str): The attribute name being validated
            activated_at (Optional[datetime]): The activation timestamp to validate
            
        Returns:
            Optional[datetime]: The validated activation timestamp
            
        Raises:
            ValueError: If activation timestamp violates business rules
        """
        if activated_at is not None:
            # Ensure activation is not before assignment creation
            if hasattr(self, 'assigned_at') and self.assigned_at and activated_at < self.assigned_at:
                raise ValueError("Activation timestamp cannot be before assignment creation")
            
            # Ensure activation is before expiration if both are set
            if hasattr(self, 'expires_at') and self.expires_at and activated_at >= self.expires_at:
                raise ValueError("Activation timestamp must be before expiration")
        
        return activated_at
    
    @hybrid_property
    def is_active(self) -> bool:
        """
        Determine if the role assignment is currently active.
        
        Evaluates the assignment status, activation time, and expiration time
        to determine if the assignment should be enforced for authorization.
        
        Returns:
            bool: True if the assignment is currently active and should be enforced
        """
        current_time = datetime.now(timezone.utc)
        
        # Check basic status requirements
        if self.status not in (AssignmentStatus.ACTIVE, AssignmentStatus.PENDING):
            return False
        
        # Check activation time
        if self.activated_at and self.activated_at > current_time:
            return False
        
        # Check expiration time
        if self.expires_at and self.expires_at <= current_time:
            return False
        
        return True
    
    @hybrid_property
    def is_expired(self) -> bool:
        """
        Determine if the role assignment has expired.
        
        Returns:
            bool: True if the assignment has passed its expiration date
        """
        if not self.expires_at:
            return False
        
        current_time = datetime.now(timezone.utc)
        return self.expires_at <= current_time
    
    @hybrid_property
    def is_pending_activation(self) -> bool:
        """
        Determine if the role assignment is pending activation.
        
        Returns:
            bool: True if the assignment is waiting for its activation time
        """
        if not self.activated_at:
            return False
        
        current_time = datetime.now(timezone.utc)
        return (
            self.status == AssignmentStatus.PENDING and
            self.activated_at > current_time
        )
    
    def activate(self, activated_by_id: Optional[int] = None) -> bool:
        """
        Activate the role assignment if eligible.
        
        Args:
            activated_by_id (Optional[int]): ID of user performing the activation
            
        Returns:
            bool: True if activation was successful, False otherwise
        """
        current_time = datetime.now(timezone.utc)
        
        # Can only activate pending assignments
        if self.status != AssignmentStatus.PENDING:
            return False
        
        # Check if activation time has been reached
        if self.activated_at and self.activated_at > current_time:
            return False
        
        # Check if assignment hasn't expired
        if self.expires_at and self.expires_at <= current_time:
            self.status = AssignmentStatus.EXPIRED
            return False
        
        # Activate the assignment
        self.status = AssignmentStatus.ACTIVE
        if not self.activated_at:
            self.activated_at = current_time
        
        # Update audit trail
        self.updated_at = current_time
        
        return True
    
    def revoke(self, revoked_by_id: int, reason: Optional[str] = None) -> bool:
        """
        Revoke the role assignment.
        
        Args:
            revoked_by_id (int): ID of user performing the revocation
            reason (Optional[str]): Reason for revocation
            
        Returns:
            bool: True if revocation was successful, False otherwise
        """
        # Can only revoke active or pending assignments
        if self.status in (AssignmentStatus.REVOKED, AssignmentStatus.EXPIRED):
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Set revocation details
        self.status = AssignmentStatus.REVOKED
        self.revoked_at = current_time
        self.revoked_by_id = revoked_by_id
        self.revoked_reason = reason
        self.updated_at = current_time
        
        return True
    
    def suspend(self, suspended_by_id: int, reason: Optional[str] = None) -> bool:
        """
        Temporarily suspend the role assignment.
        
        Args:
            suspended_by_id (int): ID of user performing the suspension
            reason (Optional[str]): Reason for suspension
            
        Returns:
            bool: True if suspension was successful, False otherwise
        """
        # Can only suspend active assignments
        if self.status != AssignmentStatus.ACTIVE:
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Set suspension details
        self.status = AssignmentStatus.SUSPENDED
        self.updated_at = current_time
        
        # Add suspension details to notes
        suspension_note = f"Suspended by user {suspended_by_id} at {current_time.isoformat()}"
        if reason:
            suspension_note += f" - Reason: {reason}"
        
        if self.notes:
            self.notes += f"\n{suspension_note}"
        else:
            self.notes = suspension_note
        
        return True
    
    def reactivate(self, reactivated_by_id: int) -> bool:
        """
        Reactivate a suspended role assignment.
        
        Args:
            reactivated_by_id (int): ID of user performing the reactivation
            
        Returns:
            bool: True if reactivation was successful, False otherwise
        """
        # Can only reactivate suspended assignments
        if self.status != AssignmentStatus.SUSPENDED:
            return False
        
        current_time = datetime.now(timezone.utc)
        
        # Check if assignment hasn't expired
        if self.expires_at and self.expires_at <= current_time:
            self.status = AssignmentStatus.EXPIRED
            return False
        
        # Reactivate the assignment
        self.status = AssignmentStatus.ACTIVE
        self.updated_at = current_time
        
        # Add reactivation note
        reactivation_note = f"Reactivated by user {reactivated_by_id} at {current_time.isoformat()}"
        if self.notes:
            self.notes += f"\n{reactivation_note}"
        else:
            self.notes = reactivation_note
        
        return True
    
    def extend_expiration(self, new_expires_at: datetime, extended_by_id: int) -> bool:
        """
        Extend the expiration date of the role assignment.
        
        Args:
            new_expires_at (datetime): New expiration timestamp
            extended_by_id (int): ID of user performing the extension
            
        Returns:
            bool: True if extension was successful, False otherwise
        """
        current_time = datetime.now(timezone.utc)
        
        # Validate new expiration date
        if new_expires_at <= current_time:
            return False
        
        # Can only extend active or suspended assignments
        if self.status not in (AssignmentStatus.ACTIVE, AssignmentStatus.SUSPENDED):
            return False
        
        # Update expiration
        old_expires_at = self.expires_at
        self.expires_at = new_expires_at
        self.updated_at = current_time
        
        # Add extension note
        extension_note = f"Expiration extended by user {extended_by_id} at {current_time.isoformat()}"
        if old_expires_at:
            extension_note += f" from {old_expires_at.isoformat()} to {new_expires_at.isoformat()}"
        else:
            extension_note += f" to {new_expires_at.isoformat()}"
        
        if self.notes:
            self.notes += f"\n{extension_note}"
        else:
            self.notes = extension_note
        
        return True
    
    def to_dict(self, include_relations: bool = False) -> Dict[str, Any]:
        """
        Convert assignment to dictionary representation.
        
        Args:
            include_relations (bool): Whether to include related object data
            
        Returns:
            Dict[str, Any]: Dictionary representation of the assignment
        """
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'role_id': self.role_id,
            'status': self.status.value if self.status else None,
            'source': self.source.value if self.source else None,
            'assigned_by_id': self.assigned_by_id,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'activated_at': self.activated_at.isoformat() if self.activated_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revoked_by_id': self.revoked_by_id,
            'revoked_reason': self.revoked_reason,
            'metadata': self.metadata,
            'notes': self.notes,
            'is_active': self.is_active,
            'is_expired': self.is_expired,
            'is_pending_activation': self.is_pending_activation,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_relations:
            result['user'] = self.user.to_dict() if self.user else None
            result['role'] = self.role.to_dict() if self.role else None
            result['assigned_by'] = self.assigned_by.to_dict() if self.assigned_by else None
            result['revoked_by'] = self.revoked_by.to_dict() if self.revoked_by else None
        
        return result
    
    @classmethod
    def get_active_assignments_for_user(cls, user_id: int) -> List['UserRoleAssignment']:
        """
        Retrieve all active role assignments for a specific user.
        
        Args:
            user_id (int): ID of the user to query
            
        Returns:
            List[UserRoleAssignment]: List of active assignments
        """
        current_time = datetime.now(timezone.utc)
        
        return cls.query.filter(
            cls.user_id == user_id,
            cls.status == AssignmentStatus.ACTIVE,
            (cls.activated_at.is_(None)) | (cls.activated_at <= current_time),
            (cls.expires_at.is_(None)) | (cls.expires_at > current_time)
        ).all()
    
    @classmethod
    def get_users_with_role(cls, role_id: int) -> List['UserRoleAssignment']:
        """
        Retrieve all active assignments for a specific role.
        
        Args:
            role_id (int): ID of the role to query
            
        Returns:
            List[UserRoleAssignment]: List of active assignments for the role
        """
        current_time = datetime.now(timezone.utc)
        
        return cls.query.filter(
            cls.role_id == role_id,
            cls.status == AssignmentStatus.ACTIVE,
            (cls.activated_at.is_(None)) | (cls.activated_at <= current_time),
            (cls.expires_at.is_(None)) | (cls.expires_at > current_time)
        ).all()
    
    @classmethod
    def get_expiring_assignments(cls, days_ahead: int = 30) -> List['UserRoleAssignment']:
        """
        Retrieve assignments that will expire within specified days.
        
        Args:
            days_ahead (int): Number of days to look ahead for expiring assignments
            
        Returns:
            List[UserRoleAssignment]: List of assignments expiring soon
        """
        current_time = datetime.now(timezone.utc)
        expiration_threshold = current_time + timedelta(days=days_ahead)
        
        return cls.query.filter(
            cls.status == AssignmentStatus.ACTIVE,
            cls.expires_at.isnot(None),
            cls.expires_at <= expiration_threshold,
            cls.expires_at > current_time
        ).all()
    
    @classmethod
    def cleanup_expired_assignments(cls) -> int:
        """
        Update status of expired assignments.
        
        Returns:
            int: Number of assignments updated to expired status
        """
        current_time = datetime.now(timezone.utc)
        
        # Update expired assignments
        updated_count = cls.query.filter(
            cls.status.in_([AssignmentStatus.ACTIVE, AssignmentStatus.PENDING]),
            cls.expires_at.isnot(None),
            cls.expires_at <= current_time
        ).update({
            'status': AssignmentStatus.EXPIRED,
            'updated_at': current_time
        }, synchronize_session=False)
        
        # Commit the changes
        db.session.commit()
        
        return updated_count
    
    def __repr__(self) -> str:
        """
        String representation for debugging and logging.
        
        Returns:
            str: String representation of the assignment
        """
        return (
            f"<UserRoleAssignment(id={self.id}, user_id={self.user_id}, "
            f"role_id={self.role_id}, status={self.status.value if self.status else None}, "
            f"is_active={self.is_active})>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation.
        
        Returns:
            str: User-friendly string representation
        """
        return f"User {self.user_id} assigned role {self.role_id} ({self.status.value if self.status else 'unknown'})"


# SQLAlchemy event listeners for automatic assignment lifecycle management
@event.listens_for(UserRoleAssignment, 'before_insert')
def validate_assignment_before_insert(mapper, connection, target):
    """
    Validate assignment before database insertion.
    
    Ensures business rules are enforced before creating new assignments.
    """
    # Ensure assignment has valid user and role IDs
    if not target.user_id or not target.role_id:
        raise ValueError("Both user_id and role_id are required for role assignment")
    
    # Set default activation time if not specified
    if target.status == AssignmentStatus.ACTIVE and not target.activated_at:
        target.activated_at = target.assigned_at or datetime.now(timezone.utc)


@event.listens_for(UserRoleAssignment, 'before_update')
def validate_assignment_before_update(mapper, connection, target):
    """
    Validate assignment before database update.
    
    Ensures business rules are maintained during assignment modifications.
    """
    # Update the updated_at timestamp
    target.updated_at = datetime.now(timezone.utc)
    
    # Ensure revoked assignments have revocation timestamp
    if target.status == AssignmentStatus.REVOKED and not target.revoked_at:
        target.revoked_at = datetime.now(timezone.utc)


# Export the model and enums for use throughout the application
__all__ = ['UserRoleAssignment', 'AssignmentStatus', 'AssignmentSource']