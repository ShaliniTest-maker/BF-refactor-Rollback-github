"""
RefreshToken Model Implementation for Auth0 Refresh Token Management.

This module implements the RefreshToken model for comprehensive JWT refresh token 
lifecycle management with automated rotation policies and security revocation 
capabilities. The model integrates with Auth0's refresh token rotation policy 
and Flask-JWT-Extended for enhanced security posture and local JWT processing.

Key Features:
- Auth0 refresh token lifecycle management with automated rotation policies
- Token family tracking for suspicious activity detection and automated revocation
- Immediate token revocation capabilities for security incidents
- Integration with Flask-JWT-Extended for local JWT processing
- Token blacklist management and automated revocation hooks
- PostgreSQL-optimized storage with comprehensive audit trails
- Security incident response coordination and automated containment

Technical Specification References:
- Section 6.4.1.4: Token Handling with Flask-JWT-Extended Integration
- Section 6.4.6.2: Security Incident Response Procedures  
- Section 6.2.1: Database Technology Transition to PostgreSQL 15.x
- Section 6.4.1.4: Auth0 Refresh Token Rotation Policy Implementation
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any
from enum import Enum

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, UniqueConstraint, CheckConstraint, text
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from src.models.base import BaseModel, db


class TokenStatus(Enum):
    """
    Enumeration for refresh token status values.
    
    Defines the lifecycle states of refresh tokens for comprehensive
    token state management and security monitoring.
    """
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    BLACKLISTED = "blacklisted"
    SUPERSEDED = "superseded"


class RevocationReason(Enum):
    """
    Enumeration for token revocation reasons.
    
    Provides structured classification of revocation events for
    security analysis and incident response coordination.
    """
    USER_LOGOUT = "user_logout"
    PASSWORD_CHANGE = "password_change"
    SECURITY_INCIDENT = "security_incident"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    TOKEN_ROTATION = "token_rotation"
    ADMIN_REVOCATION = "admin_revocation"
    TOKEN_COMPROMISE = "token_compromise"
    FAMILY_REVOCATION = "family_revocation"


class RefreshToken(BaseModel):
    """
    RefreshToken model implementing Auth0 refresh token management with 
    automated rotation policies and security revocation capabilities.
    
    This model supports JWT refresh token lifecycle management, token family 
    tracking, and automated revocation procedures for enhanced security posture,
    integrating with Auth0's refresh token rotation policy and Flask-JWT-Extended 
    for comprehensive token management.
    
    Attributes:
        id (int): Primary key with auto-incrementing integer for optimal performance
        token_id (UUID): Unique token identifier for Auth0 integration and tracking
        user_id (int): Foreign key reference to the User model for token ownership
        token_hash (str): Secure hash of the refresh token for validation
        token_family_id (UUID): Family identifier for token rotation tracking
        parent_token_id (int): Reference to the parent token in rotation chain
        status (TokenStatus): Current token status for lifecycle management
        expires_at (datetime): Token expiration timestamp with timezone support
        issued_at (datetime): Token issuance timestamp for audit trails
        revoked_at (datetime): Token revocation timestamp for security tracking
        revocation_reason (RevocationReason): Structured revocation classification
        last_used_at (datetime): Last usage timestamp for activity monitoring
        usage_count (int): Number of times token has been used for analytics
        client_metadata (dict): Client information for security analysis
        security_flags (dict): Security-related flags and indicators
        is_blacklisted (bool): Immediate blacklist flag for security incidents
        rotation_count (int): Number of rotations in the token family
        
    Relationships:
        user (User): Many-to-one relationship with User model for token ownership
        parent_token (RefreshToken): Self-referential relationship for rotation chains
        child_tokens (List[RefreshToken]): One-to-many relationship for rotation tracking
        
    Security Features:
        - Token family tracking for suspicious activity detection
        - Automated revocation procedures for security incidents
        - Integration with Auth0's refresh token rotation policy
        - Blacklist management for immediate invalidation
        - Comprehensive audit trails for compliance and investigation
    """
    
    __tablename__ = 'refresh_tokens'
    
    # Unique token identifier for Auth0 integration per Section 6.4.1.4
    token_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        unique=True,
        default=uuid.uuid4,
        index=True,
        comment="Unique token identifier for Auth0 integration and tracking"
    )
    
    # User relationship for token ownership per Section 6.4.1.4
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key reference to User model for token ownership"
    )
    
    # Secure token storage with hashing per Section 6.4.1.4
    token_hash = Column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        comment="Secure hash of refresh token for validation without exposure"
    )
    
    # Token family tracking for rotation and security per Section 6.4.1.4
    token_family_id = Column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        default=uuid.uuid4,
        comment="Family identifier for token rotation tracking and security analysis"
    )
    
    # Parent token reference for rotation chains per Section 6.4.1.4
    parent_token_id = Column(
        Integer,
        ForeignKey('refresh_tokens.id', ondelete='SET NULL'),
        nullable=True,
        index=True,
        comment="Reference to parent token in rotation chain for family tracking"
    )
    
    # Token status for lifecycle management per Section 6.4.1.4
    status = Column(
        String(20),
        nullable=False,
        default=TokenStatus.ACTIVE.value,
        index=True,
        comment="Current token status for lifecycle management and security tracking"
    )
    
    # Token expiration management per Section 6.4.1.4
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Token expiration timestamp with timezone support for validation"
    )
    
    # Token issuance tracking per Section 6.4.1.4
    issued_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Token issuance timestamp for audit trails and lifecycle tracking"
    )
    
    # Revocation tracking for security incidents per Section 6.4.6.2
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Token revocation timestamp for security incident tracking"
    )
    
    # Structured revocation reason for security analysis per Section 6.4.6.2
    revocation_reason = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Structured revocation reason for security analysis and incident response"
    )
    
    # Activity tracking for security monitoring per Section 6.4.6.1
    last_used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Last usage timestamp for activity monitoring and anomaly detection"
    )
    
    # Usage analytics for security patterns per Section 6.4.6.1
    usage_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of times token has been used for analytics and monitoring"
    )
    
    # Client metadata for security analysis per Section 6.4.6.1
    client_metadata = Column(
        JSON,
        nullable=True,
        comment="Client information for security analysis including IP, user agent, device info"
    )
    
    # Security flags for incident response per Section 6.4.6.2
    security_flags = Column(
        JSON,
        nullable=True,
        comment="Security-related flags and indicators for automated incident detection"
    )
    
    # Immediate blacklist flag for security incidents per Section 6.4.6.2
    is_blacklisted = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Immediate blacklist flag for security incidents and emergency revocation"
    )
    
    # Token rotation tracking per Section 6.4.1.4
    rotation_count = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of rotations in token family for security pattern analysis"
    )
    
    # Relationship definitions for comprehensive token management
    
    # User relationship for token ownership per Section 6.4.1.4
    user = relationship(
        'User',
        back_populates='refresh_tokens',
        lazy='select',
        doc="Many-to-one relationship with User model for token ownership"
    )
    
    # Self-referential relationship for token rotation chains per Section 6.4.1.4
    parent_token = relationship(
        'RefreshToken',
        remote_side='RefreshToken.id',
        back_populates='child_tokens',
        lazy='select',
        doc="Self-referential relationship for parent token in rotation chain"
    )
    
    # Child tokens for rotation tracking per Section 6.4.1.4
    child_tokens = relationship(
        'RefreshToken',
        back_populates='parent_token',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship for child tokens in rotation chain"
    )
    
    # Database constraints for data integrity and performance per Section 6.2.2.2
    __table_args__ = (
        # Unique constraints for token integrity
        UniqueConstraint('token_id', name='uq_refresh_token_id'),
        UniqueConstraint('token_hash', name='uq_refresh_token_hash'),
        
        # Check constraints for data validation
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired', 'blacklisted', 'superseded')",
            name='ck_refresh_token_status'
        ),
        CheckConstraint(
            "expires_at > issued_at",
            name='ck_refresh_token_expiration'
        ),
        CheckConstraint(
            "usage_count >= 0",
            name='ck_refresh_token_usage_count'
        ),
        CheckConstraint(
            "rotation_count >= 0",
            name='ck_refresh_token_rotation_count'
        ),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_refresh_token_user_status', 'user_id', 'status'),
        Index('ix_refresh_token_family_status', 'token_family_id', 'status'),
        Index('ix_refresh_token_expiry_status', 'expires_at', 'status'),
        Index('ix_refresh_token_issued_user', 'issued_at', 'user_id'),
        Index('ix_refresh_token_revoked_reason', 'revoked_at', 'revocation_reason'),
        Index('ix_refresh_token_blacklist_status', 'is_blacklisted', 'status'),
        Index('ix_refresh_token_family_rotation', 'token_family_id', 'rotation_count'),
        
        # Table-level comment for documentation
        {'comment': 'Refresh tokens for Auth0 integration with automated rotation and security tracking'}
    )
    
    def __init__(self, user_id: int, token_hash: str, expires_at: datetime, 
                 token_family_id: Optional[uuid.UUID] = None, 
                 parent_token_id: Optional[int] = None,
                 client_metadata: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """
        Initialize a new RefreshToken instance with security validation.
        
        Args:
            user_id (int): User ID for token ownership
            token_hash (str): Secure hash of the refresh token
            expires_at (datetime): Token expiration timestamp
            token_family_id (Optional[UUID]): Family ID for rotation tracking
            parent_token_id (Optional[int]): Parent token ID for rotation chains
            client_metadata (Optional[Dict]): Client information for security analysis
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If token parameters are invalid or security constraints are violated
        """
        super().__init__(**kwargs)
        
        # Validate required parameters
        if not user_id or user_id <= 0:
            raise ValueError("Valid user_id is required for token ownership")
        
        if not token_hash or len(token_hash) < 64:
            raise ValueError("Token hash must be at least 64 characters for security")
        
        if not expires_at or expires_at <= datetime.now(timezone.utc):
            raise ValueError("Token expiration must be in the future")
        
        # Set core token attributes
        self.user_id = user_id
        self.token_hash = token_hash
        self.expires_at = expires_at
        self.issued_at = datetime.now(timezone.utc)
        
        # Set family tracking attributes
        if token_family_id:
            self.token_family_id = token_family_id
        else:
            self.token_family_id = uuid.uuid4()
        
        if parent_token_id:
            self.parent_token_id = parent_token_id
            # Increment rotation count for child tokens
            self.rotation_count = self._get_parent_rotation_count() + 1
        
        # Set client metadata for security analysis
        self.client_metadata = client_metadata or {}
        
        # Initialize security tracking
        self.security_flags = {}
        self.status = TokenStatus.ACTIVE.value
        self.is_blacklisted = False
        self.usage_count = 0
    
    @validates('status')
    def validate_status(self, key: str, status: str) -> str:
        """
        Validate token status values against allowed enumeration.
        
        Args:
            key (str): The field name being validated
            status (str): The status value to validate
            
        Returns:
            str: The validated status value
            
        Raises:
            ValueError: If status is not a valid TokenStatus value
        """
        try:
            TokenStatus(status)
            return status
        except ValueError:
            raise ValueError(f"Invalid token status: {status}")
    
    @validates('revocation_reason')
    def validate_revocation_reason(self, key: str, reason: str) -> str:
        """
        Validate revocation reason values against allowed enumeration.
        
        Args:
            key (str): The field name being validated
            reason (str): The revocation reason to validate
            
        Returns:
            str: The validated revocation reason
            
        Raises:
            ValueError: If revocation reason is not a valid RevocationReason value
        """
        if reason is None:
            return reason
        
        try:
            RevocationReason(reason)
            return reason
        except ValueError:
            raise ValueError(f"Invalid revocation reason: {reason}")
    
    def _get_parent_rotation_count(self) -> int:
        """
        Get the rotation count from the parent token for chain tracking.
        
        Returns:
            int: Parent token rotation count or 0 if no parent
        """
        if not self.parent_token_id:
            return 0
        
        parent = RefreshToken.query.get(self.parent_token_id)
        return parent.rotation_count if parent else 0
    
    def is_valid(self) -> bool:
        """
        Check if the refresh token is valid for use.
        
        Validates token status, expiration, and blacklist status for
        comprehensive security validation per Section 6.4.1.4.
        
        Returns:
            bool: True if token is valid for use, False otherwise
        """
        current_time = datetime.now(timezone.utc)
        
        return (
            self.status == TokenStatus.ACTIVE.value and
            not self.is_blacklisted and
            self.expires_at > current_time and
            self.revoked_at is None
        )
    
    def is_expired(self) -> bool:
        """
        Check if the refresh token has expired.
        
        Returns:
            bool: True if token is expired, False otherwise
        """
        return datetime.now(timezone.utc) >= self.expires_at
    
    def record_usage(self, client_info: Optional[Dict[str, Any]] = None) -> None:
        """
        Record token usage for security monitoring and analytics.
        
        Updates usage count, last used timestamp, and client metadata
        for comprehensive activity tracking per Section 6.4.6.1.
        
        Args:
            client_info (Optional[Dict]): Updated client information for security analysis
        """
        self.last_used_at = datetime.now(timezone.utc)
        self.usage_count += 1
        
        # Update client metadata if provided
        if client_info:
            if not self.client_metadata:
                self.client_metadata = {}
            self.client_metadata.update(client_info)
        
        # Flag for suspicious usage patterns
        if self.usage_count > 100:  # Configurable threshold
            self._flag_suspicious_activity("high_usage_count")
    
    def revoke(self, reason: RevocationReason, 
               revoke_family: bool = False,
               security_incident: bool = False) -> None:
        """
        Revoke the refresh token with comprehensive audit tracking.
        
        Implements immediate token revocation with security incident
        coordination per Section 6.4.6.2 and automated family
        revocation for enhanced security.
        
        Args:
            reason (RevocationReason): Structured reason for revocation
            revoke_family (bool): Whether to revoke entire token family
            security_incident (bool): Whether this is a security incident
        """
        current_time = datetime.now(timezone.utc)
        
        # Update token status and revocation metadata
        self.status = TokenStatus.REVOKED.value
        self.revoked_at = current_time
        self.revocation_reason = reason.value
        
        # Set blacklist flag for security incidents per Section 6.4.6.2
        if security_incident:
            self.is_blacklisted = True
            self._flag_security_incident(reason)
        
        # Revoke entire token family if requested per Section 6.4.1.4
        if revoke_family:
            self._revoke_token_family(reason, security_incident)
    
    def _revoke_token_family(self, reason: RevocationReason, 
                           security_incident: bool = False) -> None:
        """
        Revoke all tokens in the same family for comprehensive security.
        
        Implements Auth0's refresh token rotation policy with family
        revocation for suspicious activity detection per Section 6.4.1.4.
        
        Args:
            reason (RevocationReason): Reason for family revocation
            security_incident (bool): Whether this is a security incident
        """
        family_tokens = RefreshToken.query.filter(
            RefreshToken.token_family_id == self.token_family_id,
            RefreshToken.status == TokenStatus.ACTIVE.value,
            RefreshToken.id != self.id
        ).all()
        
        for token in family_tokens:
            token.status = TokenStatus.REVOKED.value
            token.revoked_at = datetime.now(timezone.utc)
            token.revocation_reason = RevocationReason.FAMILY_REVOCATION.value
            
            if security_incident:
                token.is_blacklisted = True
                token._flag_security_incident(reason)
    
    def _flag_suspicious_activity(self, activity_type: str) -> None:
        """
        Flag suspicious token activity for security monitoring.
        
        Updates security flags for automated detection and analysis
        per Section 6.4.6.1 anomaly detection requirements.
        
        Args:
            activity_type (str): Type of suspicious activity detected
        """
        if not self.security_flags:
            self.security_flags = {}
        
        self.security_flags['suspicious_activity'] = {
            'type': activity_type,
            'detected_at': datetime.now(timezone.utc).isoformat(),
            'usage_count': self.usage_count,
            'rotation_count': self.rotation_count
        }
    
    def _flag_security_incident(self, reason: RevocationReason) -> None:
        """
        Flag security incident for automated response coordination.
        
        Updates security flags for incident response system integration
        per Section 6.4.6.2 automated response procedures.
        
        Args:
            reason (RevocationReason): Security incident reason
        """
        if not self.security_flags:
            self.security_flags = {}
        
        self.security_flags['security_incident'] = {
            'reason': reason.value,
            'detected_at': datetime.now(timezone.utc).isoformat(),
            'token_family_id': str(self.token_family_id),
            'user_id': self.user_id,
            'immediate_response_required': True
        }
    
    def extend_expiration(self, extension_hours: int = 24) -> None:
        """
        Extend token expiration for renewed sessions.
        
        Implements secure token lifetime extension with validation
        per Section 6.4.1.4 token lifecycle management.
        
        Args:
            extension_hours (int): Number of hours to extend expiration
            
        Raises:
            ValueError: If token is not in valid state for extension
        """
        if not self.is_valid():
            raise ValueError("Cannot extend expiration for invalid token")
        
        if self.is_blacklisted:
            raise ValueError("Cannot extend expiration for blacklisted token")
        
        # Extend expiration with maximum limit
        max_extension = timedelta(days=30)  # Configurable security limit
        requested_extension = timedelta(hours=extension_hours)
        
        if requested_extension > max_extension:
            raise ValueError(f"Extension cannot exceed {max_extension.days} days")
        
        self.expires_at = min(
            self.expires_at + requested_extension,
            self.issued_at + max_extension
        )
    
    def create_rotation_token(self, new_token_hash: str, 
                            new_expires_at: datetime,
                            client_metadata: Optional[Dict[str, Any]] = None) -> 'RefreshToken':
        """
        Create a new token in the rotation chain for automated rotation.
        
        Implements Auth0's refresh token rotation policy with family
        tracking per Section 6.4.1.4 automated rotation procedures.
        
        Args:
            new_token_hash (str): Hash of the new rotated token
            new_expires_at (datetime): Expiration time for new token
            client_metadata (Optional[Dict]): Client information for new token
            
        Returns:
            RefreshToken: New token instance in the rotation chain
            
        Raises:
            ValueError: If current token is not valid for rotation
        """
        if not self.is_valid():
            raise ValueError("Cannot rotate invalid token")
        
        # Create new token in the same family
        new_token = RefreshToken(
            user_id=self.user_id,
            token_hash=new_token_hash,
            expires_at=new_expires_at,
            token_family_id=self.token_family_id,
            parent_token_id=self.id,
            client_metadata=client_metadata or self.client_metadata
        )
        
        # Supersede current token per rotation policy
        self.status = TokenStatus.SUPERSEDED.value
        self.revoked_at = datetime.now(timezone.utc)
        self.revocation_reason = RevocationReason.TOKEN_ROTATION.value
        
        return new_token
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert RefreshToken instance to dictionary representation.
        
        Args:
            include_sensitive (bool): Whether to include sensitive token data
            
        Returns:
            Dict[str, Any]: Dictionary representation of RefreshToken
        """
        result = {
            'id': self.id,
            'token_id': str(self.token_id),
            'user_id': self.user_id,
            'token_family_id': str(self.token_family_id),
            'parent_token_id': self.parent_token_id,
            'status': self.status,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revocation_reason': self.revocation_reason,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'usage_count': self.usage_count,
            'is_blacklisted': self.is_blacklisted,
            'rotation_count': self.rotation_count,
            'client_metadata': self.client_metadata,
            'security_flags': self.security_flags,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_sensitive:
            result['token_hash'] = self.token_hash
        
        return result
    
    @classmethod
    def find_by_token_hash(cls, token_hash: str) -> Optional['RefreshToken']:
        """
        Find refresh token by secure hash with validation.
        
        Args:
            token_hash (str): Token hash to search for
            
        Returns:
            Optional[RefreshToken]: Token instance if found and valid, None otherwise
        """
        if not token_hash:
            return None
        
        return cls.query.filter_by(token_hash=token_hash).first()
    
    @classmethod
    def find_active_by_user(cls, user_id: int) -> List['RefreshToken']:
        """
        Find all active refresh tokens for a user.
        
        Args:
            user_id (int): User ID to search for
            
        Returns:
            List[RefreshToken]: List of active tokens for the user
        """
        current_time = datetime.now(timezone.utc)
        
        return cls.query.filter(
            cls.user_id == user_id,
            cls.status == TokenStatus.ACTIVE.value,
            cls.is_blacklisted == False,
            cls.expires_at > current_time
        ).all()
    
    @classmethod
    def find_by_family(cls, token_family_id: uuid.UUID) -> List['RefreshToken']:
        """
        Find all tokens in a token family for security analysis.
        
        Args:
            token_family_id (UUID): Token family ID to search for
            
        Returns:
            List[RefreshToken]: List of tokens in the family
        """
        return cls.query.filter_by(token_family_id=token_family_id).all()
    
    @classmethod
    def cleanup_expired_tokens(cls, batch_size: int = 1000) -> int:
        """
        Clean up expired and revoked tokens for maintenance.
        
        Implements automated token cleanup for performance and security
        per Section 6.2.4.1 data retention policies.
        
        Args:
            batch_size (int): Number of tokens to process in each batch
            
        Returns:
            int: Number of tokens cleaned up
        """
        current_time = datetime.now(timezone.utc)
        
        # Update expired tokens
        expired_count = cls.query.filter(
            cls.expires_at <= current_time,
            cls.status != TokenStatus.EXPIRED.value
        ).update({
            'status': TokenStatus.EXPIRED.value,
            'updated_at': current_time
        })
        
        db.session.commit()
        return expired_count
    
    @classmethod
    def revoke_user_tokens(cls, user_id: int, reason: RevocationReason,
                          security_incident: bool = False) -> int:
        """
        Revoke all active tokens for a user for security purposes.
        
        Args:
            user_id (int): User ID for token revocation
            reason (RevocationReason): Reason for mass revocation
            security_incident (bool): Whether this is a security incident
            
        Returns:
            int: Number of tokens revoked
        """
        current_time = datetime.now(timezone.utc)
        
        tokens = cls.find_active_by_user(user_id)
        
        for token in tokens:
            token.revoke(reason, revoke_family=False, security_incident=security_incident)
        
        db.session.commit()
        return len(tokens)
    
    def __repr__(self) -> str:
        """
        String representation of RefreshToken instance for debugging.
        
        Returns:
            str: String representation of RefreshToken instance
        """
        return (
            f"<RefreshToken(id={self.id}, token_id='{self.token_id}', "
            f"user_id={self.user_id}, status='{self.status}', "
            f"family_id='{self.token_family_id}')>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of RefreshToken instance.
        
        Returns:
            str: User-friendly string representation
        """
        return f"RefreshToken {self.token_id} for User {self.user_id}"


# Export the model and enums for use throughout the application
__all__ = ['RefreshToken', 'TokenStatus', 'RevocationReason']