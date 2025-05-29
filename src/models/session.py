"""
UserSession Model Implementation for Flask-Login Session Management.

This module implements the UserSession model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization and ItsDangerous integration for secure session token
management. The model provides comprehensive session persistence and authentication
state management while maintaining compatibility with Flask-Login decorators.

Key Features:
- ItsDangerous secure session token generation and validation
- Foreign key relationship to User model with proper constraint management
- Session expiration and validation patterns for authentication security
- PostgreSQL-optimized field types and indexing strategies
- Unique constraints on session tokens for authentication integrity
- Comprehensive session lifecycle management with cleanup capabilities
- Flask-Login compatibility for authentication decorator functionality

Technical Specification References:
- Section 4.6.1: Authentication Mechanism Migration (Feature F-007)
- Section 6.2.2.1: Entity Relationships and Data Models
- Section 6.4.1.3: Enhanced Session Management Integration
- Section 6.4.3.1: ItsDangerous secure session token validation
"""

import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.orm import relationship
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey,
    Index, UniqueConstraint, CheckConstraint, Text
)
from sqlalchemy.sql import func

# Import base model for inheritance pattern consistency
from .base import BaseModel, db


class UserSession(BaseModel):
    """
    UserSession model for Flask-Login session management and authentication state persistence.
    
    This model maintains user session data with proper foreign key relationships to User models
    and implements session validation, cleanup, and security features required for Flask
    authentication decorators and ItsDangerous token management.
    
    Attributes:
        id (int): Primary key with auto-incrementing integer for optimal join performance
        user_id (int): Foreign key reference to User model for session ownership
        session_token (str): Unique cryptographically secure session identifier
        signed_token (str): ItsDangerous signed token for secure session validation
        expires_at (datetime): Session expiration timestamp with UTC timezone
        is_valid (bool): Session validity status for immediate invalidation
        ip_address (str): Client IP address for session security tracking
        user_agent (str): Client user agent for session fingerprinting
        last_activity (datetime): Timestamp of last session activity for timeout management
        remember_me (bool): Persistent session flag for extended authentication
        session_data (str): JSON-serialized session data storage
        created_at (datetime): Session creation timestamp with UTC timezone
        updated_at (datetime): Session last update timestamp with UTC timezone
        
    Relationships:
        user (User): Many-to-one relationship with User model for session ownership
    """
    
    __tablename__ = 'user_sessions'
    
    # Foreign key relationship to User model per Section 6.2.2.1
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
        comment="Foreign key reference to User model for session ownership"
    )
    
    # Session token fields for secure session management per Section 4.6.1
    session_token = Column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique cryptographically secure session identifier"
    )
    
    signed_token = Column(
        Text,
        nullable=False,
        comment="ItsDangerous signed token for secure session validation"
    )
    
    # Session expiration and validation per Flask-Login requirements
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Session expiration timestamp with UTC timezone"
    )
    
    is_valid = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Session validity status for immediate invalidation"
    )
    
    # Session security tracking fields per Section 6.4.1.3
    ip_address = Column(
        String(45),  # IPv6 address length
        nullable=True,
        index=True,
        comment="Client IP address for session security tracking"
    )
    
    user_agent = Column(
        Text,
        nullable=True,
        comment="Client user agent for session fingerprinting"
    )
    
    # Session activity tracking for timeout management
    last_activity = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
        comment="Timestamp of last session activity for timeout management"
    )
    
    # Persistent session support for remember-me functionality
    remember_me = Column(
        Boolean,
        nullable=False,
        default=False,
        comment="Persistent session flag for extended authentication"
    )
    
    # Session data storage for Flask session compatibility
    session_data = Column(
        Text,
        nullable=True,
        comment="JSON-serialized session data storage"
    )
    
    # Relationship mapping to User model per Section 6.2.2.1
    user = relationship(
        'User',
        back_populates='sessions',
        lazy='select',
        doc="Many-to-one relationship with User model for session ownership"
    )
    
    # Database constraints for data integrity and performance per Section 6.2.2.2
    __table_args__ = (
        # Unique constraint on session token for authentication integrity
        UniqueConstraint('session_token', name='uq_session_token'),
        
        # Check constraints for data validation
        CheckConstraint('LENGTH(session_token) >= 32', name='ck_session_token_length'),
        CheckConstraint('expires_at > created_at', name='ck_session_valid_expiration'),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_session_user_valid', 'user_id', 'is_valid'),
        Index('ix_session_valid_expires', 'is_valid', 'expires_at'),
        Index('ix_session_activity', 'last_activity', 'is_valid'),
        Index('ix_session_ip_user', 'ip_address', 'user_id'),
        Index('ix_session_token_valid', 'session_token', 'is_valid'),
        
        # Table-level comment for documentation
        {'comment': 'User sessions for Flask-Login authentication state persistence'}
    )
    
    def __init__(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        remember_me: bool = False,
        session_lifetime_hours: int = 24,
        **kwargs
    ) -> None:
        """
        Initialize a new UserSession instance with secure token generation.
        
        Args:
            user_id (int): ID of the user who owns this session
            ip_address (Optional[str]): Client IP address for security tracking
            user_agent (Optional[str]): Client user agent for fingerprinting
            remember_me (bool): Whether this is a persistent session
            session_lifetime_hours (int): Session lifetime in hours
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If user_id is invalid or session parameters are invalid
        """
        super().__init__(**kwargs)
        
        # Validate user_id
        if not user_id or not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Valid user_id is required")
        
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent[:1000] if user_agent else None  # Truncate long user agents
        self.remember_me = remember_me
        
        # Generate secure session token per Section 4.6.1
        self._generate_session_token()
        
        # Set session expiration based on remember_me flag and configuration
        lifetime_hours = session_lifetime_hours
        if remember_me:
            # Extended lifetime for persistent sessions (30 days default)
            lifetime_hours = current_app.config.get('REMEMBER_COOKIE_DURATION_HOURS', 720)
        
        self.expires_at = datetime.now(timezone.utc) + timedelta(hours=lifetime_hours)
        self.last_activity = datetime.now(timezone.utc)
        self.is_valid = True
        
        # Generate signed token using ItsDangerous per Section 6.4.3.1
        self._generate_signed_token()
    
    def _generate_session_token(self) -> None:
        """
        Generate cryptographically secure session token.
        
        Uses Python's secrets module for cryptographically secure random token
        generation suitable for session management and security-sensitive applications.
        """
        # Generate 64-character hex token (32 bytes of entropy)
        self.session_token = secrets.token_hex(32)
    
    def _generate_signed_token(self) -> None:
        """
        Generate ItsDangerous signed token for secure session validation.
        
        Creates a cryptographically signed token containing session metadata
        for secure session validation and tamper detection per Section 6.4.3.1.
        """
        if not current_app:
            raise RuntimeError("Application context required for token signing")
        
        # Get the secret key from Flask configuration
        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key:
            raise RuntimeError("SECRET_KEY configuration required for session signing")
        
        # Create URL-safe timed serializer with session-specific salt
        serializer = URLSafeTimedSerializer(
            secret_key,
            salt='user-session-token'
        )
        
        # Prepare session data for signing
        session_payload = {
            'session_token': self.session_token,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat() if self.created_at else datetime.now(timezone.utc).isoformat(),
            'remember_me': self.remember_me,
            'ip_address': self.ip_address
        }
        
        # Generate signed token
        self.signed_token = serializer.dumps(session_payload)
    
    def validate_signed_token(self, max_age_seconds: Optional[int] = None) -> bool:
        """
        Validate the ItsDangerous signed token for session security.
        
        Args:
            max_age_seconds (Optional[int]): Maximum age for token validation
            
        Returns:
            bool: True if token is valid and not tampered with, False otherwise
        """
        if not self.signed_token or not current_app:
            return False
        
        try:
            # Get the secret key from Flask configuration
            secret_key = current_app.config.get('SECRET_KEY')
            if not secret_key:
                return False
            
            # Create serializer with matching salt
            serializer = URLSafeTimedSerializer(
                secret_key,
                salt='user-session-token'
            )
            
            # Validate and load the signed token
            payload = serializer.loads(
                self.signed_token,
                max_age=max_age_seconds
            )
            
            # Validate payload data matches current session
            return (
                payload.get('session_token') == self.session_token and
                payload.get('user_id') == self.user_id
            )
            
        except (BadSignature, SignatureExpired, Exception):
            return False
    
    def is_expired(self) -> bool:
        """
        Check if the session has expired based on expiration timestamp.
        
        Returns:
            bool: True if session is expired, False otherwise
        """
        if not self.expires_at:
            return True
        
        return datetime.now(timezone.utc) >= self.expires_at
    
    def is_active(self) -> bool:
        """
        Check if the session is currently active and valid.
        
        Returns:
            bool: True if session is active (valid and not expired), False otherwise
        """
        return self.is_valid and not self.is_expired()
    
    def update_activity(self) -> None:
        """
        Update the last activity timestamp to current time.
        
        Used to track session usage and implement activity-based timeouts.
        """
        self.last_activity = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def extend_session(self, additional_hours: int = 24) -> None:
        """
        Extend the session expiration time.
        
        Args:
            additional_hours (int): Number of hours to extend the session
        """
        if additional_hours > 0:
            self.expires_at = self.expires_at + timedelta(hours=additional_hours)
            self.updated_at = datetime.now(timezone.utc)
    
    def invalidate(self) -> None:
        """
        Invalidate the session for security purposes.
        
        Marks the session as invalid without deleting it from the database,
        allowing for audit trails and security analysis.
        """
        self.is_valid = False
        self.updated_at = datetime.now(timezone.utc)
    
    def refresh_token(self) -> None:
        """
        Generate new session tokens while maintaining session validity.
        
        Used for security rotation of session tokens while keeping the session active.
        """
        self._generate_session_token()
        self._generate_signed_token()
        self.updated_at = datetime.now(timezone.utc)
    
    def set_session_data(self, data: Dict[Any, Any]) -> None:
        """
        Store session data as JSON for Flask session compatibility.
        
        Args:
            data (Dict[Any, Any]): Session data to store
        """
        import json
        
        try:
            self.session_data = json.dumps(data, default=str)
            self.updated_at = datetime.now(timezone.utc)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Session data must be JSON serializable: {e}")
    
    def get_session_data(self) -> Dict[Any, Any]:
        """
        Retrieve session data from JSON storage.
        
        Returns:
            Dict[Any, Any]: Deserialized session data or empty dict if none
        """
        if not self.session_data:
            return {}
        
        import json
        
        try:
            return json.loads(self.session_data)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def is_inactive_timeout(self, timeout_hours: int = 2) -> bool:
        """
        Check if session has been inactive beyond timeout threshold.
        
        Args:
            timeout_hours (int): Inactivity timeout in hours
            
        Returns:
            bool: True if session has been inactive beyond threshold
        """
        if not self.last_activity:
            return True
        
        timeout_threshold = datetime.now(timezone.utc) - timedelta(hours=timeout_hours)
        return self.last_activity < timeout_threshold
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert UserSession instance to dictionary representation.
        
        Args:
            include_sensitive (bool): Whether to include sensitive fields like tokens
            
        Returns:
            Dict[str, Any]: Dictionary representation of UserSession instance
        """
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'is_valid': self.is_valid,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'remember_me': self.remember_me,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_expired': self.is_expired(),
            'is_active': self.is_active()
        }
        
        if include_sensitive:
            result.update({
                'session_token': self.session_token,
                'signed_token': self.signed_token,
                'user_agent': self.user_agent,
                'session_data': self.get_session_data()
            })
        
        return result
    
    @classmethod
    def find_by_token(cls, session_token: str) -> Optional['UserSession']:
        """
        Find session by session token.
        
        Args:
            session_token (str): Session token to search for
            
        Returns:
            Optional[UserSession]: UserSession instance if found, None otherwise
        """
        if not session_token:
            return None
        
        return cls.query.filter_by(
            session_token=session_token,
            is_valid=True
        ).first()
    
    @classmethod
    def find_active_by_token(cls, session_token: str) -> Optional['UserSession']:
        """
        Find active (valid and not expired) session by token.
        
        Args:
            session_token (str): Session token to search for
            
        Returns:
            Optional[UserSession]: Active UserSession instance if found, None otherwise
        """
        session = cls.find_by_token(session_token)
        
        if session and session.is_active():
            return session
        
        return None
    
    @classmethod
    def find_by_user(cls, user_id: int, active_only: bool = True) -> List['UserSession']:
        """
        Find sessions for a specific user.
        
        Args:
            user_id (int): User ID to search for
            active_only (bool): Whether to return only active sessions
            
        Returns:
            List[UserSession]: List of user sessions
        """
        if not user_id:
            return []
        
        query = cls.query.filter_by(user_id=user_id)
        
        if active_only:
            query = query.filter(
                cls.is_valid == True,
                cls.expires_at > datetime.now(timezone.utc)
            )
        
        return query.order_by(cls.last_activity.desc()).all()
    
    @classmethod
    def cleanup_expired_sessions(cls, batch_size: int = 1000) -> int:
        """
        Clean up expired and invalid sessions from the database.
        
        Args:
            batch_size (int): Number of sessions to process in each batch
            
        Returns:
            int: Number of sessions cleaned up
        """
        current_time = datetime.now(timezone.utc)
        
        # Find expired or invalid sessions
        expired_sessions = cls.query.filter(
            (cls.expires_at <= current_time) | (cls.is_valid == False)
        ).limit(batch_size).all()
        
        if not expired_sessions:
            return 0
        
        # Delete expired sessions
        count = len(expired_sessions)
        for session in expired_sessions:
            db.session.delete(session)
        
        db.session.commit()
        return count
    
    @classmethod
    def invalidate_user_sessions(cls, user_id: int, exclude_session_id: Optional[int] = None) -> int:
        """
        Invalidate all sessions for a user (except optionally one session).
        
        Args:
            user_id (int): User ID whose sessions to invalidate
            exclude_session_id (Optional[int]): Session ID to exclude from invalidation
            
        Returns:
            int: Number of sessions invalidated
        """
        if not user_id:
            return 0
        
        query = cls.query.filter(
            cls.user_id == user_id,
            cls.is_valid == True
        )
        
        if exclude_session_id:
            query = query.filter(cls.id != exclude_session_id)
        
        sessions = query.all()
        
        for session in sessions:
            session.invalidate()
        
        db.session.commit()
        return len(sessions)
    
    def __repr__(self) -> str:
        """
        String representation of UserSession instance for debugging and logging.
        
        Returns:
            str: String representation of UserSession instance
        """
        return (
            f"<UserSession(id={self.id}, user_id={self.user_id}, "
            f"token='{self.session_token[:8]}...', is_valid={self.is_valid}, "
            f"expires_at='{self.expires_at}')>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of UserSession instance.
        
        Returns:
            str: User-friendly string representation
        """
        status = "Active" if self.is_active() else "Inactive"
        return f"Session {self.session_token[:8]}... for User {self.user_id} ({status})"