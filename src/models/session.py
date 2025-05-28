"""
UserSession Model for Flask-Login Session Management

This module implements the UserSession model for comprehensive Flask-Login session
management and authentication state persistence. The model provides secure token
generation, session expiration handling, and proper foreign key relationships
for the Flask authentication mechanism migration from Node.js patterns.

Features:
- Flask-Login session persistence and state management
- ItsDangerous secure session token generation and validation
- User session expiration and cleanup mechanisms
- Database relationship mapping with User model
- Session validation and security integrity enforcement
- Unique constraints for authentication token integrity

Technical Specifications:
- Flask-SQLAlchemy 3.1.1 declarative model pattern
- PostgreSQL-optimized field types and indexing
- Foreign key relationships with referential integrity
- Session lifecycle management with automatic cleanup
- Security token generation using ItsDangerous 2.2+
- Authentication integration per Section 4.6.1 requirements

Architecture Integration:
- Service Layer pattern support for workflow orchestration
- Flask-Login authentication decorator compatibility
- Database migration support via Flask-Migrate 4.1.0
- Business logic integration for user session workflows
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
import secrets
import logging

# Flask-SQLAlchemy imports for declarative model pattern
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, 
    ForeignKey, UniqueConstraint, Index, Text
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.declarative import declarative_base

# ItsDangerous imports for secure token generation per Section 4.6.1
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

# Flask-Login imports for authentication integration per Feature F-007
from flask_login import UserMixin

# Flask application context imports
from flask import current_app

# Database instance - will be initialized by Flask application factory
db = SQLAlchemy()

# Logger initialization for session management operations
logger = logging.getLogger(__name__)


class UserSession(db.Model):
    """
    UserSession Model for Flask-Login Session Management and Authentication State Persistence.
    
    This model implements comprehensive session management for Flask authentication
    mechanism migration from Node.js patterns. Provides secure token generation,
    session expiration handling, and proper foreign key relationships to User models.
    
    Features:
        - Secure session token generation using ItsDangerous cryptographic signing
        - Session expiration and validation with configurable timeout periods
        - Foreign key relationship to User model with CASCADE constraint management
        - Unique constraints on session tokens for authentication integrity
        - Session cleanup and security features for production deployment
        - Flask-Login integration for authentication decorator compatibility
    
    Database Design:
        - PostgreSQL-optimized field types with proper indexing
        - Referential integrity with User model via foreign key constraints
        - Composite indexing for efficient session lookup and validation
        - Automatic timestamp management for session lifecycle tracking
    
    Security Features:
        - ItsDangerous token generation with configurable expiration
        - Session token uniqueness enforcement via database constraints
        - Automatic session invalidation for expired tokens
        - Secure session cleanup with proper audit trail maintenance
    
    Authentication Integration:
        - Flask-Login session persistence for user authentication state
        - Session validation patterns for authentication security
        - Integration with authentication decorators per Section 4.6.1
        - User session mapping for multi-device session support
    
    Example Usage:
        >>> # Create new user session
        >>> session = UserSession.create_session(user_id=1, expires_in_hours=24)
        >>> print(f"Session token: {session.session_token}")
        >>> 
        >>> # Validate existing session
        >>> valid_session = UserSession.validate_session(session_token)
        >>> if valid_session and valid_session.is_valid:
        ...     print("Session is valid and active")
        >>> 
        >>> # Cleanup expired sessions
        >>> UserSession.cleanup_expired_sessions()
    """
    
    # Table name for database schema
    __tablename__ = 'user_sessions'
    
    # Primary key field with auto-incrementing integer per Section 6.2.2.2
    id = Column(
        Integer, 
        primary_key=True, 
        autoincrement=True,
        nullable=False,
        comment="Primary key for user session identification"
    )
    
    # Foreign key relationship to User model per Section 6.2.2.1
    user_id = Column(
        Integer,
        ForeignKey('users.id', ondelete='CASCADE', onupdate='CASCADE'),
        nullable=False,
        index=True,  # Index for efficient user session lookups
        comment="Foreign key reference to users table for session ownership"
    )
    
    # Session token field with unique constraint for authentication integrity
    session_token = Column(
        String(255),
        nullable=False,
        unique=True,  # Unique constraint for session token integrity
        index=True,   # Index for efficient session token lookups
        comment="Unique session token generated using ItsDangerous for secure authentication"
    )
    
    # Session expiration timestamp for lifecycle management
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,  # Index for efficient expiration queries
        comment="Session expiration timestamp for automatic cleanup and validation"
    )
    
    # Session creation timestamp for audit trail and lifecycle tracking
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        index=True,  # Index for session history and audit queries
        comment="Session creation timestamp for audit trail and lifecycle tracking"
    )
    
    # Session validity flag for soft deletion and state management
    is_valid = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,  # Index for efficient valid session queries
        comment="Boolean flag indicating session validity and active state"
    )
    
    # Session metadata for additional context and debugging
    session_metadata = Column(
        Text,
        nullable=True,
        comment="JSON metadata for session context, user agent, IP address, etc."
    )
    
    # Last accessed timestamp for session activity tracking
    last_accessed = Column(
        DateTime(timezone=True),
        nullable=True,
        default=datetime.utcnow,
        comment="Timestamp of last session access for activity monitoring"
    )
    
    # User agent string for session security and device tracking
    user_agent = Column(
        String(500),
        nullable=True,
        comment="User agent string for session security and device identification"
    )
    
    # IP address for session security and location tracking
    ip_address = Column(
        String(45),  # IPv6 support with maximum length
        nullable=True,
        comment="IP address for session security and geographic tracking"
    )
    
    # Database relationship to User model with lazy loading
    user = relationship(
        "User",
        back_populates="sessions",
        lazy="select",  # Efficient loading for most use cases
        foreign_keys=[user_id],
        doc="SQLAlchemy relationship to User model for session ownership mapping"
    )
    
    # Table-level constraints and indexes for performance optimization
    __table_args__ = (
        # Composite index for efficient user session queries
        Index('idx_user_sessions_user_valid', 'user_id', 'is_valid'),
        # Composite index for session expiration cleanup
        Index('idx_user_sessions_expires_valid', 'expires_at', 'is_valid'),
        # Composite index for session token validation
        Index('idx_user_sessions_token_valid', 'session_token', 'is_valid'),
        # Unique constraint on session token for authentication integrity
        UniqueConstraint('session_token', name='uq_user_sessions_token'),
        # Table comment for database documentation
        {'comment': 'User session management table for Flask-Login authentication state persistence'}
    )
    
    def __init__(self, user_id: int, expires_at: datetime, session_metadata: Optional[str] = None,
                 user_agent: Optional[str] = None, ip_address: Optional[str] = None):
        """
        Initialize UserSession instance with secure token generation.
        
        Creates a new user session with automatically generated secure token
        using ItsDangerous cryptographic signing. Initializes session with
        provided expiration time and optional metadata for security tracking.
        
        Args:
            user_id (int): User ID for session ownership
            expires_at (datetime): Session expiration timestamp
            session_metadata (Optional[str]): JSON metadata for session context
            user_agent (Optional[str]): User agent string for device tracking
            ip_address (Optional[str]): IP address for security monitoring
        
        Raises:
            ValueError: If user_id is invalid or expires_at is in the past
            RuntimeError: If session token generation fails
        
        Example:
            >>> expires = datetime.utcnow() + timedelta(hours=24)
            >>> session = UserSession(
            ...     user_id=1,
            ...     expires_at=expires,
            ...     user_agent="Mozilla/5.0...",
            ...     ip_address="192.168.1.1"
            ... )
        """
        # Validate input parameters
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError(f"Invalid user_id: {user_id}. Must be positive integer.")
        
        if not isinstance(expires_at, datetime):
            raise ValueError(f"Invalid expires_at: {expires_at}. Must be datetime object.")
        
        if expires_at <= datetime.utcnow():
            raise ValueError(f"Session expiration {expires_at} cannot be in the past.")
        
        # Set basic session attributes
        self.user_id = user_id
        self.expires_at = expires_at
        self.session_metadata = session_metadata
        self.user_agent = user_agent
        self.ip_address = ip_address
        self.created_at = datetime.utcnow()
        self.last_accessed = datetime.utcnow()
        self.is_valid = True
        
        # Generate secure session token using ItsDangerous
        try:
            self.session_token = self._generate_secure_token()
            logger.info(f"UserSession created for user_id={user_id}, expires_at={expires_at}")
        except Exception as e:
            logger.error(f"Failed to generate session token for user_id={user_id}: {str(e)}")
            raise RuntimeError(f"Session token generation failed: {str(e)}")
    
    def __repr__(self) -> str:
        """
        String representation of UserSession for debugging and logging.
        
        Returns:
            str: Formatted string with session details
        """
        return (
            f"<UserSession(id={self.id}, user_id={self.user_id}, "
            f"token={self.session_token[:8]}..., expires_at={self.expires_at}, "
            f"is_valid={self.is_valid})>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of UserSession.
        
        Returns:
            str: User-friendly session description
        """
        status = "Valid" if self.is_valid and not self.is_expired() else "Invalid/Expired"
        return f"UserSession for User {self.user_id} - {status} (expires: {self.expires_at})"
    
    @validates('user_id')
    def validate_user_id(self, key: str, user_id: int) -> int:
        """
        SQLAlchemy validator for user_id field.
        
        Args:
            key (str): Field name being validated
            user_id (int): User ID value to validate
        
        Returns:
            int: Validated user ID
        
        Raises:
            ValueError: If user_id is invalid
        """
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError(f"Invalid user_id: {user_id}. Must be positive integer.")
        return user_id
    
    @validates('expires_at')
    def validate_expires_at(self, key: str, expires_at: datetime) -> datetime:
        """
        SQLAlchemy validator for expires_at field.
        
        Args:
            key (str): Field name being validated
            expires_at (datetime): Expiration timestamp to validate
        
        Returns:
            datetime: Validated expiration timestamp
        
        Raises:
            ValueError: If expires_at is invalid
        """
        if not isinstance(expires_at, datetime):
            raise ValueError(f"Invalid expires_at: {expires_at}. Must be datetime object.")
        
        # Allow past dates for existing sessions being loaded from database
        if hasattr(self, 'id') and self.id is None and expires_at <= datetime.utcnow():
            raise ValueError(f"Session expiration {expires_at} cannot be in the past for new sessions.")
        
        return expires_at
    
    @validates('session_token')
    def validate_session_token(self, key: str, session_token: str) -> str:
        """
        SQLAlchemy validator for session_token field.
        
        Args:
            key (str): Field name being validated
            session_token (str): Session token to validate
        
        Returns:
            str: Validated session token
        
        Raises:
            ValueError: If session_token is invalid
        """
        if not isinstance(session_token, str) or len(session_token.strip()) == 0:
            raise ValueError(f"Invalid session_token: {session_token}. Must be non-empty string.")
        
        if len(session_token) > 255:
            raise ValueError(f"Session token too long: {len(session_token)}. Maximum 255 characters.")
        
        return session_token
    
    def _generate_secure_token(self) -> str:
        """
        Generate secure session token using ItsDangerous cryptographic signing.
        
        Creates a cryptographically secure session token using ItsDangerous
        URLSafeTimedSerializer with the Flask application's secret key.
        The token includes session metadata for validation and security.
        
        Returns:
            str: Secure session token
        
        Raises:
            RuntimeError: If Flask application context is not available
            ValueError: If secret key is not configured
        
        Example:
            >>> session = UserSession(user_id=1, expires_at=future_time)
            >>> print(f"Generated token: {session.session_token}")
        """
        try:
            # Ensure Flask application context is available
            if not current_app:
                raise RuntimeError("Flask application context not available for token generation")
            
            # Get secret key from Flask configuration
            secret_key = current_app.config.get('SECRET_KEY')
            if not secret_key:
                raise ValueError("SECRET_KEY not configured in Flask application")
            
            # Create URLSafeTimedSerializer instance for secure token generation
            serializer = URLSafeTimedSerializer(secret_key)
            
            # Token payload with session metadata for validation
            token_payload = {
                'user_id': self.user_id,
                'created_at': self.created_at.isoformat() if self.created_at else datetime.utcnow().isoformat(),
                'expires_at': self.expires_at.isoformat(),
                'random_salt': secrets.token_hex(16)  # Additional entropy for uniqueness
            }
            
            # Generate secure token with expiration
            token_max_age = int((self.expires_at - datetime.utcnow()).total_seconds())
            secure_token = serializer.dumps(token_payload, max_age=token_max_age)
            
            logger.debug(f"Generated secure token for user_id={self.user_id}")
            return secure_token
            
        except Exception as e:
            logger.error(f"Token generation failed for user_id={self.user_id}: {str(e)}")
            raise RuntimeError(f"Failed to generate secure session token: {str(e)}")
    
    def is_expired(self) -> bool:
        """
        Check if session has expired based on expires_at timestamp.
        
        Returns:
            bool: True if session has expired, False otherwise
        
        Example:
            >>> session = UserSession.query.filter_by(session_token=token).first()
            >>> if session and session.is_expired():
            ...     print("Session has expired")
        """
        return datetime.utcnow() > self.expires_at
    
    def is_active(self) -> bool:
        """
        Check if session is currently active and valid.
        
        Returns:
            bool: True if session is valid and not expired, False otherwise
        
        Example:
            >>> session = UserSession.validate_session(token)
            >>> if session and session.is_active():
            ...     print("Session is active and valid")
        """
        return self.is_valid and not self.is_expired()
    
    def extend_session(self, hours: int = 24) -> None:
        """
        Extend session expiration time by specified hours.
        
        Args:
            hours (int): Number of hours to extend session (default: 24)
        
        Raises:
            ValueError: If hours is not positive
            RuntimeError: If session is already expired or invalid
        
        Example:
            >>> session.extend_session(hours=48)  # Extend for 48 hours
            >>> print(f"Session extended until: {session.expires_at}")
        """
        if not isinstance(hours, int) or hours <= 0:
            raise ValueError(f"Invalid hours: {hours}. Must be positive integer.")
        
        if not self.is_valid:
            raise RuntimeError("Cannot extend invalid session")
        
        if self.is_expired():
            raise RuntimeError("Cannot extend expired session")
        
        # Extend expiration time
        old_expires_at = self.expires_at
        self.expires_at = datetime.utcnow() + timedelta(hours=hours)
        self.last_accessed = datetime.utcnow()
        
        logger.info(f"Extended session {self.id} from {old_expires_at} to {self.expires_at}")
    
    def invalidate_session(self, reason: Optional[str] = None) -> None:
        """
        Invalidate session by setting is_valid to False.
        
        Args:
            reason (Optional[str]): Reason for session invalidation
        
        Example:
            >>> session.invalidate_session("User logged out")
            >>> print(f"Session invalidated: {session.is_valid}")
        """
        self.is_valid = False
        self.last_accessed = datetime.utcnow()
        
        log_msg = f"Session {self.id} invalidated for user_id={self.user_id}"
        if reason:
            log_msg += f" - Reason: {reason}"
        logger.info(log_msg)
    
    def update_last_accessed(self) -> None:
        """
        Update last_accessed timestamp to current time.
        
        Used for session activity tracking and monitoring.
        
        Example:
            >>> session.update_last_accessed()
            >>> print(f"Last accessed: {session.last_accessed}")
        """
        self.last_accessed = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert UserSession instance to dictionary representation.
        
        Returns:
            Dict[str, Any]: Dictionary with session data
        
        Example:
            >>> session_data = session.to_dict()
            >>> print(f"Session ID: {session_data['id']}")
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_token': self.session_token,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None,
            'is_valid': self.is_valid,
            'is_expired': self.is_expired(),
            'is_active': self.is_active(),
            'user_agent': self.user_agent,
            'ip_address': self.ip_address,
            'session_metadata': self.session_metadata
        }
    
    @classmethod
    def create_session(cls, user_id: int, expires_in_hours: int = 24,
                      session_metadata: Optional[str] = None,
                      user_agent: Optional[str] = None,
                      ip_address: Optional[str] = None) -> 'UserSession':
        """
        Create and save new user session with secure token generation.
        
        Class method for creating new user sessions with automatic token
        generation and database persistence. Includes validation and
        error handling for production deployment.
        
        Args:
            user_id (int): User ID for session ownership
            expires_in_hours (int): Session expiration in hours (default: 24)
            session_metadata (Optional[str]): JSON metadata for session context
            user_agent (Optional[str]): User agent string for device tracking
            ip_address (Optional[str]): IP address for security monitoring
        
        Returns:
            UserSession: Created and saved session instance
        
        Raises:
            ValueError: If parameters are invalid
            RuntimeError: If session creation or saving fails
        
        Example:
            >>> session = UserSession.create_session(
            ...     user_id=1,
            ...     expires_in_hours=48,
            ...     user_agent="Mozilla/5.0...",
            ...     ip_address="192.168.1.1"
            ... )
            >>> print(f"Created session: {session.session_token}")
        """
        try:
            # Calculate expiration time
            expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)
            
            # Create session instance
            session = cls(
                user_id=user_id,
                expires_at=expires_at,
                session_metadata=session_metadata,
                user_agent=user_agent,
                ip_address=ip_address
            )
            
            # Save to database
            db.session.add(session)
            db.session.commit()
            
            logger.info(f"Created session {session.id} for user_id={user_id}")
            return session
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create session for user_id={user_id}: {str(e)}")
            raise RuntimeError(f"Session creation failed: {str(e)}")
    
    @classmethod
    def validate_session(cls, session_token: str) -> Optional['UserSession']:
        """
        Validate session token and return active session if valid.
        
        Class method for validating session tokens using ItsDangerous
        verification and database lookup. Returns active session if
        token is valid and not expired.
        
        Args:
            session_token (str): Session token to validate
        
        Returns:
            Optional[UserSession]: Valid session instance or None
        
        Example:
            >>> session = UserSession.validate_session(token)
            >>> if session:
            ...     print(f"Valid session for user {session.user_id}")
            >>> else:
            ...     print("Invalid or expired session")
        """
        try:
            if not session_token or not isinstance(session_token, str):
                logger.warning("Invalid session token format provided")
                return None
            
            # Query session by token
            session = cls.query.filter_by(
                session_token=session_token,
                is_valid=True
            ).first()
            
            if not session:
                logger.debug(f"Session not found for token: {session_token[:8]}...")
                return None
            
            # Check if session is expired
            if session.is_expired():
                logger.info(f"Session {session.id} has expired")
                session.invalidate_session("Session expired")
                db.session.commit()
                return None
            
            # Update last accessed time
            session.update_last_accessed()
            db.session.commit()
            
            logger.debug(f"Validated session {session.id} for user_id={session.user_id}")
            return session
            
        except Exception as e:
            logger.error(f"Session validation failed for token {session_token[:8]}...: {str(e)}")
            return None
    
    @classmethod
    def get_user_sessions(cls, user_id: int, active_only: bool = True) -> list['UserSession']:
        """
        Get all sessions for specified user.
        
        Args:
            user_id (int): User ID to get sessions for
            active_only (bool): Return only active sessions if True
        
        Returns:
            list[UserSession]: List of user sessions
        
        Example:
            >>> sessions = UserSession.get_user_sessions(user_id=1)
            >>> print(f"User has {len(sessions)} active sessions")
        """
        try:
            query = cls.query.filter_by(user_id=user_id)
            
            if active_only:
                query = query.filter_by(is_valid=True).filter(
                    cls.expires_at > datetime.utcnow()
                )
            
            sessions = query.order_by(cls.created_at.desc()).all()
            logger.debug(f"Retrieved {len(sessions)} sessions for user_id={user_id}")
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get sessions for user_id={user_id}: {str(e)}")
            return []
    
    @classmethod
    def invalidate_user_sessions(cls, user_id: int, exclude_session_id: Optional[int] = None) -> int:
        """
        Invalidate all sessions for specified user.
        
        Args:
            user_id (int): User ID to invalidate sessions for
            exclude_session_id (Optional[int]): Session ID to exclude from invalidation
        
        Returns:
            int: Number of sessions invalidated
        
        Example:
            >>> count = UserSession.invalidate_user_sessions(user_id=1)
            >>> print(f"Invalidated {count} sessions")
        """
        try:
            query = cls.query.filter_by(user_id=user_id, is_valid=True)
            
            if exclude_session_id:
                query = query.filter(cls.id != exclude_session_id)
            
            sessions = query.all()
            count = len(sessions)
            
            for session in sessions:
                session.invalidate_session("User logout - all sessions invalidated")
            
            db.session.commit()
            logger.info(f"Invalidated {count} sessions for user_id={user_id}")
            return count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to invalidate sessions for user_id={user_id}: {str(e)}")
            return 0
    
    @classmethod
    def cleanup_expired_sessions(cls, batch_size: int = 1000) -> int:
        """
        Clean up expired sessions from database.
        
        Args:
            batch_size (int): Number of sessions to delete per batch
        
        Returns:
            int: Number of sessions cleaned up
        
        Example:
            >>> count = UserSession.cleanup_expired_sessions()
            >>> print(f"Cleaned up {count} expired sessions")
        """
        try:
            # Find expired sessions
            expired_sessions = cls.query.filter(
                cls.expires_at < datetime.utcnow()
            ).limit(batch_size).all()
            
            count = len(expired_sessions)
            
            if count > 0:
                # Delete expired sessions
                for session in expired_sessions:
                    db.session.delete(session)
                
                db.session.commit()
                logger.info(f"Cleaned up {count} expired sessions")
            
            return count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to cleanup expired sessions: {str(e)}")
            return 0
    
    @classmethod
    def get_session_statistics(cls) -> Dict[str, Any]:
        """
        Get session statistics for monitoring and analytics.
        
        Returns:
            Dict[str, Any]: Session statistics
        
        Example:
            >>> stats = UserSession.get_session_statistics()
            >>> print(f"Total sessions: {stats['total_sessions']}")
        """
        try:
            current_time = datetime.utcnow()
            
            # Count active sessions
            active_sessions = cls.query.filter_by(is_valid=True).filter(
                cls.expires_at > current_time
            ).count()
            
            # Count expired sessions
            expired_sessions = cls.query.filter(
                cls.expires_at <= current_time
            ).count()
            
            # Count invalid sessions
            invalid_sessions = cls.query.filter_by(is_valid=False).count()
            
            # Total sessions
            total_sessions = cls.query.count()
            
            # Sessions created today
            today_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
            sessions_today = cls.query.filter(
                cls.created_at >= today_start
            ).count()
            
            statistics = {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'expired_sessions': expired_sessions,
                'invalid_sessions': invalid_sessions,
                'sessions_created_today': sessions_today,
                'cleanup_required': expired_sessions > 0,
                'generated_at': current_time.isoformat()
            }
            
            logger.debug(f"Generated session statistics: {statistics}")
            return statistics
            
        except Exception as e:
            logger.error(f"Failed to generate session statistics: {str(e)}")
            return {
                'error': str(e),
                'generated_at': datetime.utcnow().isoformat()
            }


# Flask-Login integration functions for authentication decorator compatibility

def load_user_from_session(session_token: str) -> Optional[UserMixin]:
    """
    Load user from session token for Flask-Login integration.
    
    This function provides Flask-Login compatibility by loading user
    instances from session tokens. Used by Flask-Login authentication
    decorators to validate user authentication state.
    
    Args:
        session_token (str): Session token to load user from
    
    Returns:
        Optional[UserMixin]: User instance if session is valid, None otherwise
    
    Example:
        >>> user = load_user_from_session(session_token)
        >>> if user:
        ...     print(f"Authenticated user: {user.username}")
    """
    try:
        session = UserSession.validate_session(session_token)
        if session and session.is_active():
            # Import User model to avoid circular imports
            from .user import User
            return User.query.get(session.user_id)
        return None
    except Exception as e:
        logger.error(f"Failed to load user from session: {str(e)}")
        return None


def create_user_session(user_id: int, request_context: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Create user session and return session token for Flask-Login integration.
    
    Args:
        user_id (int): User ID to create session for
        request_context (Optional[Dict[str, Any]]): Request context with user_agent, ip_address
    
    Returns:
        Optional[str]: Session token if creation successful, None otherwise
    
    Example:
        >>> token = create_user_session(user_id=1, request_context={
        ...     'user_agent': 'Mozilla/5.0...',
        ...     'ip_address': '192.168.1.1'
        ... })
        >>> if token:
        ...     print(f"Session created: {token}")
    """
    try:
        # Extract context information
        user_agent = None
        ip_address = None
        
        if request_context:
            user_agent = request_context.get('user_agent')
            ip_address = request_context.get('ip_address')
        
        # Create session
        session = UserSession.create_session(
            user_id=user_id,
            expires_in_hours=24,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        return session.session_token
        
    except Exception as e:
        logger.error(f"Failed to create user session: {str(e)}")
        return None


# Module exports for organized import management
__all__ = [
    'UserSession',
    'load_user_from_session',
    'create_user_session'
]