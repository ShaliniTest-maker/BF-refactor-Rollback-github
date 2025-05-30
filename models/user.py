"""
User authentication and profile models implementing Flask-SQLAlchemy declarative classes for user management, Auth0 integration, and session handling.

This module provides comprehensive user management capabilities including:
- User model with Auth0 integration fields for external authentication
- UserSession model for Flask session management and tracking
- Encrypted sensitive field storage using SQLAlchemy-Utils EncryptedType
- RBAC relationship integration with Role and Permission models
- Flask-Login user loader integration for session-based authentication
- Comprehensive audit trails and validation for security compliance

The implementation ensures zero security regression during migration from Node.js
while enhancing security through Flask's authentication framework and encrypted
data storage capabilities.
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import ValidationError
from flask import current_app, g
from flask_login import UserMixin
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, Index, event
from sqlalchemy.orm import relationship, validates
from sqlalchemy_utils import EncryptedType, FernetEngine
from sqlalchemy.exc import IntegrityError

# Import base model and database instance
from models.base import BaseModel, EncryptedMixin, db, AuditMixin
from models.rbac import UserRole, Role

# Configure logging for user model operations
logger = logging.getLogger(__name__)


class User(BaseModel, EncryptedMixin, UserMixin):
    """
    User model implementing Flask-SQLAlchemy declarative class for user management
    with Auth0 integration, encrypted sensitive data, and RBAC relationships.
    
    Features:
    - Auth0 Python SDK 4.9.0 integration fields for external authentication
    - Flask-Login UserMixin for session-based authentication flows
    - Encrypted sensitive field storage using SQLAlchemy-Utils EncryptedType
    - Bidirectional relationships with Role models for RBAC integration
    - Comprehensive validation and business logic for user management
    - Audit trail support through AuditMixin inheritance
    
    Security Implementation:
    - Password hashing using Werkzeug's secure password utilities
    - Email and personal data encryption using FernetEngine
    - Auth0 user synchronization for external identity management
    - Session tracking and security validation
    """
    
    __tablename__ = 'users'
    
    # Core user identification fields
    username = Column(String(100), unique=True, nullable=False, index=True)
    
    # Encrypted sensitive data fields using SQLAlchemy-Utils EncryptedType
    email = Column(
        EncryptedType(String(255), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        unique=True, nullable=False, index=True
    )
    
    # Password storage - encrypted for additional security layer
    password_hash = Column(
        EncryptedType(String(255), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=True  # Nullable for Auth0-only users
    )
    
    # Auth0 integration fields for external authentication provider support
    auth0_user_id = Column(String(100), unique=True, nullable=True, index=True)
    auth0_nickname = Column(String(100), nullable=True)
    auth0_picture_url = Column(String(500), nullable=True)
    auth0_email_verified = Column(Boolean, default=False, nullable=False)
    auth0_last_login = Column(DateTime, nullable=True)
    auth0_login_count = Column(Integer, default=0, nullable=False)
    
    # User profile and status fields
    first_name = Column(
        EncryptedType(String(100), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=True
    )
    last_name = Column(
        EncryptedType(String(100), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=True
    )
    display_name = Column(String(200), nullable=True)
    
    # Account status and security fields
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(255), nullable=True)
    email_verification_sent_at = Column(DateTime, nullable=True)
    password_reset_token = Column(String(255), nullable=True)
    password_reset_sent_at = Column(DateTime, nullable=True)
    
    # Authentication tracking fields
    last_login_at = Column(DateTime, nullable=True, index=True)
    last_login_ip = Column(String(45), nullable=True)  # IPv6 compatible
    login_count = Column(Integer, default=0, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_at = Column(DateTime, nullable=True)
    account_locked_until = Column(DateTime, nullable=True)
    
    # User preferences and metadata
    timezone = Column(String(50), default='UTC', nullable=False)
    language = Column(String(10), default='en', nullable=False)
    date_format = Column(String(20), default='YYYY-MM-DD', nullable=False)
    time_format = Column(String(10), default='24h', nullable=False)
    
    # Privacy and compliance fields
    privacy_policy_accepted_at = Column(DateTime, nullable=True)
    terms_of_service_accepted_at = Column(DateTime, nullable=True)
    marketing_consent = Column(Boolean, default=False, nullable=False)
    data_processing_consent = Column(Boolean, default=True, nullable=False)
    
    # RBAC relationship integration with Role models using back_populates
    user_roles = relationship(
        "UserRole", 
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    # Convenience relationship for direct role access
    roles = relationship(
        "Role",
        secondary="user_roles",
        primaryjoin="and_(User.id == UserRole.user_id, UserRole.is_active == True)",
        secondaryjoin="and_(Role.id == UserRole.role_id, Role.is_active == True)",
        viewonly=True,
        lazy="select"
    )
    
    # User session relationship for Flask session management
    user_sessions = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    # Database constraints and indexes for performance optimization
    __table_args__ = (
        Index('idx_users_email_active', 'is_active'),
        Index('idx_users_auth0_verified', 'auth0_user_id', 'auth0_email_verified'),
        Index('idx_users_login_tracking', 'last_login_at', 'login_count'),
        Index('idx_users_account_status', 'is_active', 'is_verified', 'account_locked_at'),
    )
    
    def __repr__(self) -> str:
        """String representation for debugging and logging."""
        return f"<User(id={self.id}, username='{self.username}', email='[ENCRYPTED]', is_active={self.is_active})>"
    
    # Flask-Login UserMixin implementation
    @property
    def is_authenticated(self) -> bool:
        """Return True if user is authenticated."""
        return True
    
    @property
    def is_anonymous(self) -> bool:
        """Return True if user is anonymous."""
        return False
    
    def get_id(self) -> str:
        """Return user ID as string for Flask-Login."""
        return str(self.id)
    
    # Password management methods
    def set_password(self, password: str) -> None:
        """
        Set password hash using secure hashing.
        
        Args:
            password: Plain text password to hash
        """
        if not password or len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        
        self.password_hash = generate_password_hash(password, method='scrypt')
    
    def check_password(self, password: str) -> bool:
        """
        Check password against stored hash.
        
        Args:
            password: Plain text password to verify
            
        Returns:
            True if password matches, False otherwise
        """
        if not self.password_hash:
            return False
        
        try:
            return check_password_hash(self.password_hash, password)
        except Exception as e:
            logger.error(f"Password check failed for user {self.id}: {e}")
            return False
    
    # Auth0 integration methods
    def sync_with_auth0(self, auth0_profile: Dict[str, Any]) -> None:
        """
        Synchronize user data with Auth0 profile information.
        
        Args:
            auth0_profile: Auth0 user profile data
        """
        try:
            # Update Auth0 specific fields
            self.auth0_user_id = auth0_profile.get('user_id')
            self.auth0_nickname = auth0_profile.get('nickname')
            self.auth0_picture_url = auth0_profile.get('picture')
            self.auth0_email_verified = auth0_profile.get('email_verified', False)
            self.auth0_last_login = datetime.utcnow()
            self.auth0_login_count = auth0_profile.get('logins_count', 0)
            
            # Update email if provided and verified
            if auth0_profile.get('email') and self.auth0_email_verified:
                self.email = auth0_profile['email']
            
            # Update name fields if provided
            if auth0_profile.get('given_name'):
                self.first_name = auth0_profile['given_name']
            if auth0_profile.get('family_name'):
                self.last_name = auth0_profile['family_name']
            if auth0_profile.get('name'):
                self.display_name = auth0_profile['name']
            
            logger.info(f"Synchronized user {self.id} with Auth0 profile")
            
        except Exception as e:
            logger.error(f"Failed to sync user {self.id} with Auth0: {e}")
            raise ValidationError(f"Auth0 synchronization failed: {str(e)}")
    
    def update_login_tracking(self, ip_address: str = None) -> None:
        """
        Update login tracking information.
        
        Args:
            ip_address: Client IP address for login tracking
        """
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.login_count += 1
        self.failed_login_attempts = 0  # Reset on successful login
        
        # Clear account lock on successful login
        if self.account_locked_until and datetime.utcnow() > self.account_locked_until:
            self.account_locked_at = None
            self.account_locked_until = None
    
    def increment_failed_login(self, max_attempts: int = 5, lockout_duration: int = 30) -> None:
        """
        Increment failed login attempts and lock account if necessary.
        
        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_duration: Lockout duration in minutes
        """
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= max_attempts:
            self.account_locked_at = datetime.utcnow()
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=lockout_duration)
            logger.warning(f"Account locked for user {self.id} due to {self.failed_login_attempts} failed attempts")
    
    def is_account_locked(self) -> bool:
        """
        Check if account is currently locked.
        
        Returns:
            True if account is locked, False otherwise
        """
        if not self.account_locked_until:
            return False
        
        if datetime.utcnow() > self.account_locked_until:
            # Auto-unlock expired locks
            self.account_locked_at = None
            self.account_locked_until = None
            self.failed_login_attempts = 0
            return False
        
        return True
    
    # RBAC integration methods
    def has_role(self, role_name: str) -> bool:
        """
        Check if user has specific role.
        
        Args:
            role_name: Name of role to check
            
        Returns:
            True if user has role, False otherwise
        """
        return any(role.name == role_name for role in self.roles if role.is_active)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """
        Check if user has specific permission through their roles.
        
        Args:
            resource: Resource name to check access for
            action: Action to check permission for
            
        Returns:
            True if user has permission, False otherwise
        """
        for role in self.roles:
            if role.is_active and role.has_permission(resource, action):
                return True
        return False
    
    def assign_role(self, role: Union[Role, str], assigned_by: str = None, reason: str = None) -> Optional[UserRole]:
        """
        Assign role to user with audit trail.
        
        Args:
            role: Role object or role name to assign
            assigned_by: User who is assigning the role
            reason: Reason for role assignment
            
        Returns:
            UserRole instance if successful, None otherwise
        """
        try:
            if isinstance(role, str):
                role_obj = Role.query.filter_by(name=role, is_active=True).first()
                if not role_obj:
                    raise ValidationError(f"Role '{role}' not found")
            else:
                role_obj = role
            
            return role_obj.assign_to_user(
                self.id, 
                assigned_by=assigned_by or getattr(g, 'current_user_id', 'system'),
                reason=reason
            )
            
        except Exception as e:
            logger.error(f"Failed to assign role to user {self.id}: {e}")
            return None
    
    def remove_role(self, role_name: str, revoked_by: str = None, reason: str = None) -> bool:
        """
        Remove role from user with audit trail.
        
        Args:
            role_name: Name of role to remove
            revoked_by: User who is revoking the role
            reason: Reason for role removal
            
        Returns:
            True if removal was successful, False otherwise
        """
        try:
            user_role = UserRole.query.filter_by(
                user_id=self.id,
                is_active=True
            ).join(Role).filter(Role.name == role_name).first()
            
            if user_role:
                return user_role.revoke_role(
                    revoked_by=revoked_by or getattr(g, 'current_user_id', 'system'),
                    reason=reason
                )
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to remove role from user {self.id}: {e}")
            return False
    
    def get_permissions(self) -> List[str]:
        """
        Get list of all permissions for user through their roles.
        
        Returns:
            List of permission names in 'resource.action' format
        """
        permissions = set()
        for role in self.roles:
            if role.is_active:
                for permission in role.permissions:
                    if permission.is_active:
                        permissions.add(f"{permission.resource}.{permission.action}")
        return list(permissions)
    
    # Session management methods
    def create_session(self, session_data: Dict[str, Any] = None, expires_hours: int = 24) -> 'UserSession':
        """
        Create new user session for Flask session management.
        
        Args:
            session_data: Additional session metadata
            expires_hours: Session expiration in hours
            
        Returns:
            UserSession instance
        """
        from models.user import UserSession
        
        session = UserSession(
            user_id=self.id,
            expires_at=datetime.utcnow() + timedelta(hours=expires_hours),
            session_data=session_data or {},
            created_by=getattr(g, 'current_user_id', str(self.id))
        )
        
        db.session.add(session)
        return session
    
    def invalidate_sessions(self, except_session_id: int = None) -> int:
        """
        Invalidate all user sessions except optionally specified one.
        
        Args:
            except_session_id: Session ID to preserve (usually current session)
            
        Returns:
            Number of sessions invalidated
        """
        query = UserSession.query.filter_by(user_id=self.id, is_valid=True)
        
        if except_session_id:
            query = query.filter(UserSession.id != except_session_id)
        
        sessions = query.all()
        
        for session in sessions:
            session.invalidate(revoked_by=getattr(g, 'current_user_id', str(self.id)))
        
        return len(sessions)
    
    def get_active_sessions(self) -> List['UserSession']:
        """
        Get all active sessions for user.
        
        Returns:
            List of active UserSession objects
        """
        return UserSession.query.filter_by(
            user_id=self.id,
            is_valid=True
        ).filter(
            UserSession.expires_at > datetime.utcnow()
        ).all()
    
    # Validation methods
    def validate(self) -> bool:
        """
        Comprehensive user validation.
        
        Returns:
            True if validation passes
            
        Raises:
            ValidationError: If validation fails
        """
        # Call parent validation
        super().validate()
        
        # Username validation
        if not self.username or len(self.username.strip()) < 3:
            raise ValidationError("Username must be at least 3 characters long")
        
        if len(self.username) > 100:
            raise ValidationError("Username cannot exceed 100 characters")
        
        # Email validation (basic check)
        if self.email and '@' not in self.email:
            raise ValidationError("Invalid email format")
        
        # Auth0 user ID validation
        if self.auth0_user_id and len(self.auth0_user_id) > 100:
            raise ValidationError("Auth0 user ID cannot exceed 100 characters")
        
        # Password validation for local users
        if not self.auth0_user_id and not self.password_hash:
            raise ValidationError("Password is required for local users")
        
        return True
    
    @validates('username')
    def validate_username(self, key: str, username: str) -> str:
        """Validate username format and uniqueness."""
        if not username:
            raise ValidationError("Username is required")
        
        username = username.strip().lower()
        
        # Check for valid characters
        import re
        if not re.match(r'^[a-z0-9_.-]+$', username):
            raise ValidationError("Username can only contain letters, numbers, underscores, dots, and hyphens")
        
        return username
    
    @validates('email')
    def validate_email(self, key: str, email: str) -> str:
        """Validate email format."""
        if not email:
            raise ValidationError("Email is required")
        
        email = email.strip().lower()
        
        # Basic email validation
        import re
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValidationError("Invalid email format")
        
        return email
    
    @validates('timezone')
    def validate_timezone(self, key: str, timezone: str) -> str:
        """Validate timezone string."""
        if not timezone:
            return 'UTC'
        
        # Basic timezone validation
        try:
            import pytz
            pytz.timezone(timezone)
            return timezone
        except:
            logger.warning(f"Invalid timezone {timezone}, defaulting to UTC")
            return 'UTC'
    
    def to_dict(self, include_sensitive: bool = False, exclude_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Convert user to dictionary representation with sensitive data protection.
        
        Args:
            include_sensitive: Whether to include sensitive/encrypted fields
            exclude_fields: List of field names to exclude from output
            
        Returns:
            Dictionary representation of user
        """
        exclude_fields = exclude_fields or []
        exclude_fields.extend(['password_hash', 'email_verification_token', 'password_reset_token'])
        
        result = super().to_dict(include_sensitive=include_sensitive, exclude_fields=exclude_fields)
        
        # Add computed fields
        result['full_name'] = self.get_full_name()
        result['role_names'] = [role.name for role in self.roles if role.is_active]
        result['permission_count'] = len(self.get_permissions())
        result['active_sessions_count'] = len(self.get_active_sessions())
        result['is_locked'] = self.is_account_locked()
        
        return result
    
    def get_full_name(self) -> str:
        """
        Get user's full name.
        
        Returns:
            Full name or display name or username
        """
        if self.display_name:
            return self.display_name
        
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        
        if self.first_name:
            return self.first_name
        
        return self.username
    
    # Class methods for user management
    @classmethod
    def create_user(cls, username: str, email: str, password: str = None, 
                   auth0_user_id: str = None, **kwargs) -> 'User':
        """
        Create new user with validation.
        
        Args:
            username: Unique username
            email: User email address
            password: Password for local users (optional for Auth0 users)
            auth0_user_id: Auth0 user identifier
            **kwargs: Additional user attributes
            
        Returns:
            Created User instance
            
        Raises:
            ValidationError: If creation fails
        """
        try:
            user = cls(
                username=username,
                email=email,
                auth0_user_id=auth0_user_id,
                **kwargs
            )
            
            if password:
                user.set_password(password)
            
            user.validate()
            db.session.add(user)
            db.session.flush()  # Get user ID
            
            logger.info(f"Created user: {user.username} (ID: {user.id})")
            return user
            
        except IntegrityError as e:
            db.session.rollback()
            if 'username' in str(e):
                raise ValidationError("Username already exists")
            elif 'email' in str(e):
                raise ValidationError("Email already exists")
            else:
                raise ValidationError("User creation failed due to constraint violation")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create user {username}: {e}")
            raise ValidationError(f"User creation failed: {str(e)}")
    
    @classmethod
    def find_by_username(cls, username: str) -> Optional['User']:
        """Find user by username."""
        return cls.query.filter_by(username=username.lower()).first()
    
    @classmethod
    def find_by_email(cls, email: str) -> Optional['User']:
        """Find user by email (requires decryption)."""
        # Note: This is a simplified example. In practice, you might need
        # to implement a more sophisticated search for encrypted fields
        users = cls.query.all()
        for user in users:
            if user.email and user.email.lower() == email.lower():
                return user
        return None
    
    @classmethod
    def find_by_auth0_id(cls, auth0_user_id: str) -> Optional['User']:
        """Find user by Auth0 user ID."""
        return cls.query.filter_by(auth0_user_id=auth0_user_id).first()


class UserSession(BaseModel):
    """
    UserSession model for Flask session management replacing Node.js session patterns
    with secure session token storage and expiration tracking.
    
    Features:
    - Secure session token generation with cryptographic randomness
    - Session expiration tracking with automatic cleanup
    - Session metadata storage for enhanced security monitoring
    - Integration with Flask-Login session management
    - Comprehensive audit trails for session lifecycle events
    - Support for device and location tracking for security analysis
    """
    
    __tablename__ = 'user_sessions'
    
    # Foreign key relationship to User
    user_id = Column(Integer, db.ForeignKey('users.id', ondelete='CASCADE'), 
                     nullable=False, index=True)
    
    # Session identification and security
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    session_id = Column(String(100), nullable=True, index=True)  # Flask session ID
    csrf_token = Column(String(255), nullable=True)
    
    # Session lifecycle management
    expires_at = Column(DateTime, nullable=False, index=True)
    is_valid = Column(Boolean, default=True, nullable=False, index=True)
    invalidated_at = Column(DateTime, nullable=True)
    invalidated_by = Column(String(100), nullable=True)
    invalidation_reason = Column(String(255), nullable=True)
    
    # Security and tracking information
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    device_fingerprint = Column(String(255), nullable=True)
    location_country = Column(String(2), nullable=True)
    location_city = Column(String(100), nullable=True)
    
    # Session activity tracking
    last_activity_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    activity_count = Column(Integer, default=0, nullable=False)
    
    # Session metadata and preferences
    session_data = Column(db.JSON, nullable=True)  # PostgreSQL JSON column
    remember_me = Column(Boolean, default=False, nullable=False)
    is_mobile = Column(Boolean, default=False, nullable=False)
    
    # Relationship back to User model using back_populates
    user = relationship("User", back_populates="user_sessions")
    
    # Database constraints and indexes for performance
    __table_args__ = (
        Index('idx_user_sessions_user_valid', 'user_id', 'is_valid'),
        Index('idx_user_sessions_expiry', 'expires_at', 'is_valid'),
        Index('idx_user_sessions_activity', 'last_activity_at', 'is_valid'),
        Index('idx_user_sessions_token_valid', 'session_token', 'is_valid'),
    )
    
    def __repr__(self) -> str:
        """String representation for debugging and logging."""
        return f"<UserSession(id={self.id}, user_id={self.user_id}, token='[REDACTED]', valid={self.is_valid})>"
    
    @classmethod
    def create_session(cls, user_id: int, ip_address: str = None, user_agent: str = None,
                      expires_hours: int = 24, remember_me: bool = False, 
                      session_data: Dict[str, Any] = None) -> 'UserSession':
        """
        Create new user session with secure token generation.
        
        Args:
            user_id: ID of user to create session for
            ip_address: Client IP address
            user_agent: Client user agent string
            expires_hours: Session expiration in hours
            remember_me: Whether this is a persistent session
            session_data: Additional session metadata
            
        Returns:
            Created UserSession instance
        """
        import secrets
        
        try:
            # Generate secure session token
            session_token = secrets.token_urlsafe(32)
            
            # Set expiration based on remember_me preference
            if remember_me:
                expires_at = datetime.utcnow() + timedelta(days=30)  # 30 days for remember me
            else:
                expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
            
            # Create session instance
            session = cls(
                user_id=user_id,
                session_token=session_token,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                remember_me=remember_me,
                session_data=session_data or {},
                is_mobile=cls._detect_mobile_device(user_agent),
                created_by=str(user_id)
            )
            
            # Extract location information if possible
            session._update_location_info(ip_address)
            
            db.session.add(session)
            db.session.flush()  # Get session ID
            
            logger.info(f"Created session {session.id} for user {user_id}")
            return session
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create session for user {user_id}: {e}")
            raise ValidationError(f"Session creation failed: {str(e)}")
    
    @staticmethod
    def _detect_mobile_device(user_agent: str) -> bool:
        """
        Detect if request is from mobile device.
        
        Args:
            user_agent: User agent string
            
        Returns:
            True if mobile device detected
        """
        if not user_agent:
            return False
        
        mobile_patterns = [
            'Mobile', 'Android', 'iPhone', 'iPad', 'BlackBerry', 
            'Windows Phone', 'Opera Mini', 'IEMobile'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern.lower() in user_agent_lower for pattern in mobile_patterns)
    
    def _update_location_info(self, ip_address: str) -> None:
        """
        Update location information based on IP address.
        
        Args:
            ip_address: Client IP address for geolocation
        """
        # This is a placeholder for geolocation implementation
        # In production, you would integrate with a geolocation service
        # such as MaxMind GeoIP2 or similar
        
        if ip_address and ip_address not in ['127.0.0.1', 'localhost']:
            try:
                # Placeholder for actual geolocation implementation
                # geoip_data = get_geolocation(ip_address)
                # self.location_country = geoip_data.get('country_code')
                # self.location_city = geoip_data.get('city')
                pass
            except Exception as e:
                logger.warning(f"Failed to get location for IP {ip_address}: {e}")
    
    def update_activity(self) -> None:
        """Update session activity tracking."""
        self.last_activity_at = datetime.utcnow()
        self.activity_count += 1
    
    def is_expired(self) -> bool:
        """
        Check if session is expired.
        
        Returns:
            True if session is expired
        """
        return datetime.utcnow() > self.expires_at
    
    def is_active(self) -> bool:
        """
        Check if session is active and valid.
        
        Returns:
            True if session is active
        """
        return self.is_valid and not self.is_expired()
    
    def extend_session(self, hours: int = 24) -> None:
        """
        Extend session expiration time.
        
        Args:
            hours: Number of hours to extend session
        """
        if self.is_valid:
            self.expires_at = datetime.utcnow() + timedelta(hours=hours)
            logger.info(f"Extended session {self.id} by {hours} hours")
    
    def invalidate(self, reason: str = None, revoked_by: str = None) -> None:
        """
        Invalidate session with audit trail.
        
        Args:
            reason: Reason for session invalidation
            revoked_by: User who invalidated the session
        """
        self.is_valid = False
        self.invalidated_at = datetime.utcnow()
        self.invalidation_reason = reason or 'Manual invalidation'
        self.invalidated_by = revoked_by or getattr(g, 'current_user_id', 'system')
        
        logger.info(f"Invalidated session {self.id} for user {self.user_id}: {self.invalidation_reason}")
    
    def update_session_data(self, data: Dict[str, Any]) -> None:
        """
        Update session metadata.
        
        Args:
            data: Dictionary of session data to update
        """
        if self.session_data is None:
            self.session_data = {}
        
        self.session_data.update(data)
        self.update_activity()
    
    def get_session_data(self, key: str = None) -> Union[Any, Dict[str, Any]]:
        """
        Get session data.
        
        Args:
            key: Specific key to retrieve, or None for all data
            
        Returns:
            Session data value or entire data dictionary
        """
        if self.session_data is None:
            return None if key else {}
        
        if key:
            return self.session_data.get(key)
        
        return self.session_data
    
    def to_dict(self, include_sensitive: bool = False, exclude_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Convert session to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive fields
            exclude_fields: List of field names to exclude
            
        Returns:
            Dictionary representation of session
        """
        exclude_fields = exclude_fields or []
        
        if not include_sensitive:
            exclude_fields.extend(['session_token', 'csrf_token'])
        
        result = super().to_dict(include_sensitive=include_sensitive, exclude_fields=exclude_fields)
        
        # Add computed fields
        result['is_expired'] = self.is_expired()
        result['is_active'] = self.is_active()
        result['duration_hours'] = (datetime.utcnow() - self.created_at).total_seconds() / 3600
        result['time_until_expiry'] = (self.expires_at - datetime.utcnow()).total_seconds() if not self.is_expired() else 0
        
        return result
    
    @classmethod
    def find_by_token(cls, session_token: str) -> Optional['UserSession']:
        """
        Find session by token.
        
        Args:
            session_token: Session token to search for
            
        Returns:
            UserSession instance or None if not found
        """
        return cls.query.filter_by(session_token=session_token, is_valid=True).first()
    
    @classmethod
    def cleanup_expired_sessions(cls, batch_size: int = 1000) -> int:
        """
        Clean up expired sessions from database.
        
        Args:
            batch_size: Number of sessions to process in each batch
            
        Returns:
            Number of sessions cleaned up
        """
        try:
            cutoff_time = datetime.utcnow()
            
            # Get expired sessions in batches
            expired_sessions = cls.query.filter(
                cls.expires_at < cutoff_time,
                cls.is_valid == True
            ).limit(batch_size).all()
            
            count = 0
            for session in expired_sessions:
                session.invalidate(reason='Expired', revoked_by='system')
                count += 1
            
            if count > 0:
                db.session.commit()
                logger.info(f"Cleaned up {count} expired sessions")
            
            return count
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    @classmethod
    def get_active_sessions_for_user(cls, user_id: int) -> List['UserSession']:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID to get sessions for
            
        Returns:
            List of active UserSession objects
        """
        return cls.query.filter_by(
            user_id=user_id,
            is_valid=True
        ).filter(
            cls.expires_at > datetime.utcnow()
        ).order_by(cls.last_activity_at.desc()).all()


# Flask-Login user loader function integration
def load_user(user_id: str) -> Optional[User]:
    """
    Flask-Login user loader callback for session-based authentication flows.
    
    Args:
        user_id: User ID as string
        
    Returns:
        User instance or None if not found
    """
    try:
        user = User.query.get(int(user_id))
        if user and user.is_active and not user.is_account_locked():
            return user
        return None
    except (ValueError, TypeError):
        return None


# SQLAlchemy event listeners for automatic session cleanup and user audit
@event.listens_for(User, 'before_update')
def user_before_update_handler(mapper, connection, target):
    """Update user modification timestamp and audit fields."""
    target.updated_at = datetime.utcnow()
    target.updated_by = getattr(g, 'current_user_id', 'system')


@event.listens_for(UserSession, 'before_update')
def session_before_update_handler(mapper, connection, target):
    """Update session modification timestamp."""
    target.updated_at = datetime.utcnow()
    target.updated_by = getattr(g, 'current_user_id', 'system')


# Export main components for easy importing
__all__ = [
    'User',
    'UserSession', 
    'load_user'
]