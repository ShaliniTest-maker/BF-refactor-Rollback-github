"""
User Authentication and Profile Models

This module implements Flask-SQLAlchemy declarative classes for comprehensive user management,
Auth0 integration, and session handling. Provides the foundation for user authentication,
profile management, and session tracking capabilities essential for security and user management.

The user system supports:
- Auth0 Python SDK 4.9.0 integration for external authentication
- Flask-Login user loader integration for session-based authentication flows
- SQLAlchemy-Utils EncryptedType for PII protection and compliance
- RBAC relationship integration with Role and Permission models
- Comprehensive audit trails and session management
- Flask-Migrate 4.1.0 compatible schema definitions

Dependencies:
- Flask-SQLAlchemy 3.1.1: ORM functionality and declarative models
- SQLAlchemy-Utils: EncryptedType for sensitive field protection
- Flask-Login: Session-based authentication integration
- Auth0 Python SDK 4.9.0: External authentication provider integration
- python-dotenv: Secure environment variable management
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey,
    Index, UniqueConstraint, CheckConstraint, event, text
)
from sqlalchemy.orm import relationship, validates, backref
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy_utils import EncryptedType, FernetEngine
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

# Initialize SQLAlchemy instance
db = SQLAlchemy()


class AuditMixin:
    """
    Audit mixin providing standardized audit fields for user-related models.
    
    Implements automatic timestamp tracking and user attribution for comprehensive
    audit trails required by security and compliance frameworks.
    """
    
    @declared_attr
    def created_at(cls):
        """Timestamp when record was created"""
        return Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    @declared_attr
    def updated_at(cls):
        """Timestamp when record was last updated"""
        return Column(
            DateTime, 
            default=datetime.utcnow, 
            onupdate=datetime.utcnow, 
            nullable=False,
            index=True
        )
    
    @declared_attr
    def created_by(cls):
        """User ID or system identifier who created the record"""
        return Column(String(100), nullable=True)
    
    @declared_attr
    def updated_by(cls):
        """User ID or system identifier who last updated the record"""
        return Column(String(100), nullable=True)


class EncryptedMixin:
    """
    Mixin providing encrypted field support using SQLAlchemy-Utils EncryptedType.
    
    Implements field-level encryption for sensitive data using FernetEngine for
    maximum security with PII protection and compliance requirements.
    """
    
    @staticmethod
    def get_encryption_key():
        """
        Get encryption key from environment variables for SQLAlchemy-Utils EncryptedType.
        
        Returns:
            Encryption key from FIELD_ENCRYPTION_KEY environment variable
            
        Raises:
            ValueError: If encryption key is not configured
        """
        key = os.environ.get('FIELD_ENCRYPTION_KEY')
        if not key:
            raise ValueError("FIELD_ENCRYPTION_KEY environment variable is required for encrypted fields")
        
        # Ensure key is bytes for Fernet
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        return key


class User(db.Model, UserMixin, AuditMixin, EncryptedMixin):
    """
    User model implementing comprehensive user management with Auth0 integration.
    
    Supports Auth0 external authentication, encrypted sensitive data storage,
    RBAC integration, and Flask-Login session management. Provides the foundation
    for all user authentication and authorization workflows.
    
    Attributes:
        id: Primary key for user identification
        auth0_user_id: Auth0 external user identifier for SSO integration
        username: Unique username for user identification
        email: Encrypted email address for PII protection
        password_hash: Encrypted password hash for fallback authentication
        first_name: Encrypted first name for PII protection
        last_name: Encrypted last name for PII protection
        is_active: Account status flag
        is_verified: Email verification status
        last_login_at: Timestamp of last successful login
        login_count: Total number of successful logins
        roles: Many-to-many relationship with Role model for RBAC
        
    Database Indexes:
        - Primary key index on id
        - Unique index on username
        - Unique index on auth0_user_id (for Auth0 integration)
        - Index on is_active for filtering
        - Index on last_login_at for activity tracking
        - Composite index on (is_active, is_verified) for user queries
    """
    
    __tablename__ = 'users'
    
    # Primary key and core identification
    id = Column(Integer, primary_key=True)
    auth0_user_id = Column(String(255), unique=True, nullable=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    
    # Encrypted sensitive fields using SQLAlchemy-Utils EncryptedType with FernetEngine
    email = Column(
        EncryptedType(String(255), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=False,
        index=True  # Note: Encrypted fields have limited index utility
    )
    
    password_hash = Column(
        EncryptedType(String(255), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=True  # Nullable for Auth0-only users
    )
    
    first_name = Column(
        EncryptedType(String(100), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=True
    )
    
    last_name = Column(
        EncryptedType(String(100), lambda: EncryptedMixin.get_encryption_key(), FernetEngine),
        nullable=True
    )
    
    # User status and verification
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False, index=True)
    is_admin = Column(Boolean, default=False, nullable=False)
    
    # Authentication tracking
    last_login_at = Column(DateTime, nullable=True, index=True)
    login_count = Column(Integer, default=0, nullable=False)
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    
    # Profile and preferences (non-encrypted)
    timezone = Column(String(50), default='UTC', nullable=False)
    locale = Column(String(10), default='en', nullable=False)
    avatar_url = Column(String(500), nullable=True)
    
    # Auth0 integration metadata
    auth0_metadata = Column(Text, nullable=True)  # JSON string for Auth0 user metadata
    auth0_app_metadata = Column(Text, nullable=True)  # JSON string for Auth0 app metadata
    
    # Terms and privacy
    terms_accepted_at = Column(DateTime, nullable=True)
    privacy_accepted_at = Column(DateTime, nullable=True)
    
    # RBAC relationship integration with Role models using back_populates
    roles = relationship(
        'Role',
        secondary='user_roles',
        back_populates='users',
        lazy='dynamic',  # Enable filtering on the relationship
        cascade='all'
    )
    
    # User sessions relationship
    sessions = relationship(
        'UserSession',
        back_populates='user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    
    # Additional indexes for performance optimization
    __table_args__ = (
        Index('idx_users_active_verified', 'is_active', 'is_verified'),
        Index('idx_users_login_tracking', 'last_login_at', 'login_count'),
        Index('idx_users_auth0_integration', 'auth0_user_id', 'is_active'),
        UniqueConstraint('email', name='uq_users_email'),  # Note: Limited utility with encryption
        CheckConstraint('login_count >= 0', name='ck_user_login_count_positive'),
        CheckConstraint('failed_login_count >= 0', name='ck_user_failed_login_count_positive'),
        CheckConstraint("timezone != ''", name='ck_user_timezone_not_empty'),
        CheckConstraint("locale IN ('en', 'es', 'fr', 'de', 'it', 'pt', 'ja', 'ko', 'zh')", 
                       name='ck_user_locale_valid')
    )
    
    @validates('username')
    def validate_username(self, key, username):
        """Validate username format and constraints"""
        if not username or len(username.strip()) == 0:
            raise ValueError("Username cannot be empty")
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(username) > 100:
            raise ValueError("Username cannot exceed 100 characters")
        if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
            raise ValueError("Username can only contain alphanumeric characters, hyphens, underscores, and periods")
        return username.strip().lower()
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format before encryption"""
        if not email:
            raise ValueError("Email cannot be empty")
        if '@' not in email or '.' not in email.split('@')[1]:
            raise ValueError("Invalid email format")
        if len(email) > 255:
            raise ValueError("Email cannot exceed 255 characters")
        return email.strip().lower()
    
    @validates('auth0_user_id')
    def validate_auth0_user_id(self, key, auth0_user_id):
        """Validate Auth0 user ID format"""
        if auth0_user_id is not None:
            if len(auth0_user_id) > 255:
                raise ValueError("Auth0 user ID cannot exceed 255 characters")
            if not auth0_user_id.strip():
                return None
        return auth0_user_id
    
    def set_password(self, password: str) -> None:
        """
        Set user password with secure hashing.
        
        Args:
            password: Plain text password to hash and store
            
        Raises:
            ValueError: If password doesn't meet security requirements
        """
        if not password:
            raise ValueError("Password cannot be empty")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(password) > 128:
            raise ValueError("Password cannot exceed 128 characters")
        
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password: str) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Plain text password to verify
            
        Returns:
            Boolean indicating if password is correct
        """
        if not self.password_hash or not password:
            return False
        return check_password_hash(self.password_hash, password)
    
    def update_login_tracking(self) -> None:
        """Update login tracking information"""
        self.last_login_at = datetime.utcnow()
        self.login_count += 1
        self.failed_login_count = 0  # Reset failed login count on successful login
        self.locked_until = None  # Clear any account locks
    
    def record_failed_login(self, max_attempts: int = 5, lockout_duration: int = 30) -> bool:
        """
        Record failed login attempt and potentially lock account.
        
        Args:
            max_attempts: Maximum failed attempts before locking
            lockout_duration: Lockout duration in minutes
            
        Returns:
            Boolean indicating if account is now locked
        """
        self.failed_login_count += 1
        
        if self.failed_login_count >= max_attempts:
            self.locked_until = datetime.utcnow() + timedelta(minutes=lockout_duration)
            return True
        
        return False
    
    def is_account_locked(self) -> bool:
        """
        Check if account is currently locked due to failed login attempts.
        
        Returns:
            Boolean indicating if account is locked
        """
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until
    
    def unlock_account(self) -> None:
        """Unlock account and reset failed login count"""
        self.locked_until = None
        self.failed_login_count = 0
    
    def get_active_roles(self) -> List['Role']:
        """
        Get all active roles assigned to this user.
        
        Returns:
            List of active Role objects
        """
        from .rbac import user_roles
        return self.roles.filter_by(is_active=True).all()
    
    def has_role(self, role_name: str) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            role_name: Name of the role to check
            
        Returns:
            Boolean indicating if user has the role
        """
        return self.roles.filter_by(name=role_name, is_active=True).first() is not None
    
    def has_permission(self, permission_name: str) -> bool:
        """
        Check if user has a specific permission through their roles.
        
        Args:
            permission_name: Name of the permission to check
            
        Returns:
            Boolean indicating if user has the permission
        """
        for role in self.get_active_roles():
            if role.has_permission(permission_name):
                return True
        return False
    
    def get_permissions(self) -> List[str]:
        """
        Get all permission names for this user across all their roles.
        
        Returns:
            List of unique permission names
        """
        permissions = set()
        for role in self.get_active_roles():
            permissions.update(role.get_permission_names())
        return list(permissions)
    
    def assign_role(self, role: 'Role', assigned_by: str = None) -> bool:
        """
        Assign a role to this user.
        
        Args:
            role: Role object to assign
            assigned_by: User ID who assigned the role
            
        Returns:
            Boolean indicating if role was successfully assigned
        """
        if not role.is_active:
            return False
        
        if not role.can_be_assigned_to_user(self.id):
            return False
        
        # Check if role is already assigned
        if self.has_role(role.name):
            return True
        
        # Insert into association table with audit information
        db.session.execute(
            text("""
                INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by, is_active)
                VALUES (:user_id, :role_id, :assigned_at, :assigned_by, :is_active)
            """),
            {
                'user_id': self.id,
                'role_id': role.id,
                'assigned_at': datetime.utcnow(),
                'assigned_by': assigned_by or 'system',
                'is_active': True
            }
        )
        
        return True
    
    def revoke_role(self, role: 'Role', revoked_by: str = None) -> bool:
        """
        Revoke a role from this user.
        
        Args:
            role: Role object to revoke
            revoked_by: User ID who revoked the role
            
        Returns:
            Boolean indicating if role was successfully revoked
        """
        # Update association table to mark as inactive
        result = db.session.execute(
            text("""
                UPDATE user_roles 
                SET is_active = false, updated_by = :revoked_by
                WHERE user_id = :user_id AND role_id = :role_id AND is_active = true
            """),
            {
                'user_id': self.id,
                'role_id': role.id,
                'revoked_by': revoked_by or 'system'
            }
        )
        
        return result.rowcount > 0
    
    def sync_with_auth0(self, auth0_user_data: Dict[str, Any]) -> None:
        """
        Synchronize user data with Auth0 user information.
        
        Args:
            auth0_user_data: Auth0 user data dictionary
        """
        # Update Auth0 user ID if provided
        if 'user_id' in auth0_user_data:
            self.auth0_user_id = auth0_user_data['user_id']
        
        # Update email if provided and different
        if 'email' in auth0_user_data and auth0_user_data['email']:
            self.email = auth0_user_data['email']
        
        # Update verification status
        if 'email_verified' in auth0_user_data:
            self.is_verified = auth0_user_data['email_verified']
        
        # Update name information if provided
        if 'given_name' in auth0_user_data:
            self.first_name = auth0_user_data['given_name']
        if 'family_name' in auth0_user_data:
            self.last_name = auth0_user_data['family_name']
        
        # Update avatar URL if provided
        if 'picture' in auth0_user_data:
            self.avatar_url = auth0_user_data['picture']
        
        # Store Auth0 metadata as JSON
        if 'user_metadata' in auth0_user_data:
            self.auth0_metadata = json.dumps(auth0_user_data['user_metadata'])
        if 'app_metadata' in auth0_user_data:
            self.auth0_app_metadata = json.dumps(auth0_user_data['app_metadata'])
        
        # Update login tracking
        if 'last_login' in auth0_user_data:
            try:
                # Parse Auth0 datetime format
                from dateutil.parser import parse
                self.last_login_at = parse(auth0_user_data['last_login'])
            except (ValueError, TypeError):
                pass
        
        if 'logins_count' in auth0_user_data:
            self.login_count = max(self.login_count, auth0_user_data['logins_count'])
    
    def get_auth0_metadata(self) -> Dict[str, Any]:
        """
        Get Auth0 user metadata as dictionary.
        
        Returns:
            Dictionary of Auth0 user metadata
        """
        if not self.auth0_metadata:
            return {}
        try:
            return json.loads(self.auth0_metadata)
        except (ValueError, TypeError):
            return {}
    
    def get_auth0_app_metadata(self) -> Dict[str, Any]:
        """
        Get Auth0 app metadata as dictionary.
        
        Returns:
            Dictionary of Auth0 app metadata
        """
        if not self.auth0_app_metadata:
            return {}
        try:
            return json.loads(self.auth0_app_metadata)
        except (ValueError, TypeError):
            return {}
    
    def get_full_name(self) -> str:
        """
        Get user's full name from encrypted fields.
        
        Returns:
            Full name string or username if names not available
        """
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.username
    
    def to_dict(self, include_sensitive: bool = False, include_roles: bool = False) -> Dict[str, Any]:
        """
        Convert user to dictionary representation.
        
        Args:
            include_sensitive: Whether to include sensitive information
            include_roles: Whether to include role information
            
        Returns:
            Dictionary representation of the user
        """
        result = {
            'id': self.id,
            'username': self.username,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'is_admin': self.is_admin,
            'timezone': self.timezone,
            'locale': self.locale,
            'avatar_url': self.avatar_url,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'login_count': self.login_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        if include_sensitive:
            result.update({
                'email': self.email,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'full_name': self.get_full_name(),
                'auth0_user_id': self.auth0_user_id,
                'auth0_metadata': self.get_auth0_metadata(),
                'auth0_app_metadata': self.get_auth0_app_metadata(),
                'terms_accepted_at': self.terms_accepted_at.isoformat() if self.terms_accepted_at else None,
                'privacy_accepted_at': self.privacy_accepted_at.isoformat() if self.privacy_accepted_at else None
            })
        
        if include_roles:
            result['roles'] = [role.to_dict() for role in self.get_active_roles()]
            result['permissions'] = self.get_permissions()
        
        return result
    
    # Flask-Login required methods
    def get_id(self):
        """Return user ID as string for Flask-Login"""
        return str(self.id)
    
    @property
    def is_authenticated(self):
        """Return True if user is authenticated"""
        return True
    
    @property
    def is_anonymous(self):
        """Return False since this is an authenticated user"""
        return False
    
    def __repr__(self):
        return f"<User {self.username} (ID: {self.id}, Active: {self.is_active})>"


class UserSession(db.Model, AuditMixin):
    """
    User session model for Flask session management with secure token storage.
    
    Replaces Node.js session patterns with Flask-compatible session tracking
    including secure session token storage, expiration tracking, and session
    validation capabilities for comprehensive session management.
    
    Attributes:
        id: Primary key for session identification
        user_id: Foreign key reference to User model
        session_token: Unique secure session token
        csrf_token: CSRF protection token
        expires_at: Session expiration timestamp
        is_valid: Session validity flag
        ip_address: Client IP address for security tracking
        user_agent: Client user agent for security tracking
        last_activity_at: Timestamp of last session activity
        
    Database Indexes:
        - Primary key index on id
        - Unique index on session_token
        - Foreign key index on user_id
        - Index on expires_at for cleanup queries
        - Index on is_valid for filtering
        - Composite index on (user_id, is_valid) for user session queries
    """
    
    __tablename__ = 'user_sessions'
    
    # Primary key and relationships
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    
    # Session tokens and security
    session_token = Column(String(255), unique=True, nullable=False, index=True)
    csrf_token = Column(String(255), nullable=True)
    refresh_token = Column(String(255), nullable=True)
    
    # Session lifecycle
    expires_at = Column(DateTime, nullable=False, index=True)
    is_valid = Column(Boolean, default=True, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(String(100), nullable=True)
    
    # Security tracking
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    last_activity_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Session metadata
    session_data = Column(Text, nullable=True)  # JSON string for session data
    login_method = Column(String(50), default='password', nullable=False)  # password, auth0, etc.
    
    # Relationship with User model
    user = relationship('User', back_populates='sessions')
    
    # Additional indexes for performance optimization
    __table_args__ = (
        Index('idx_user_sessions_user_valid', 'user_id', 'is_valid'),
        Index('idx_user_sessions_cleanup', 'expires_at', 'is_valid'),
        Index('idx_user_sessions_activity', 'last_activity_at', 'is_valid'),
        Index('idx_user_sessions_security', 'ip_address', 'user_agent'),
        CheckConstraint('expires_at > created_at', name='ck_session_expires_after_creation'),
        CheckConstraint("login_method IN ('password', 'auth0', 'social', 'api', 'system')",
                       name='ck_session_login_method_valid')
    )
    
    @classmethod
    def create_session(cls, user: User, expires_in: int = 3600, ip_address: str = None,
                      user_agent: str = None, login_method: str = 'password') -> 'UserSession':
        """
        Create a new user session with secure tokens.
        
        Args:
            user: User object for the session
            expires_in: Session duration in seconds (default: 1 hour)
            ip_address: Client IP address
            user_agent: Client user agent
            login_method: Method used for login
            
        Returns:
            New UserSession instance
        """
        session = cls(
            user_id=user.id,
            session_token=secrets.token_urlsafe(32),
            csrf_token=secrets.token_urlsafe(24),
            refresh_token=secrets.token_urlsafe(32),
            expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
            ip_address=ip_address,
            user_agent=user_agent,
            login_method=login_method,
            last_activity_at=datetime.utcnow()
        )
        
        return session
    
    def is_expired(self) -> bool:
        """
        Check if session is expired.
        
        Returns:
            Boolean indicating if session is expired
        """
        return datetime.utcnow() > self.expires_at
    
    def is_active(self) -> bool:
        """
        Check if session is active (valid and not expired).
        
        Returns:
            Boolean indicating if session is active
        """
        return self.is_valid and not self.is_expired()
    
    def extend_session(self, extend_by: int = 3600) -> None:
        """
        Extend session expiration time.
        
        Args:
            extend_by: Additional seconds to extend the session
        """
        if self.is_active():
            self.expires_at = max(
                self.expires_at,
                datetime.utcnow() + timedelta(seconds=extend_by)
            )
            self.last_activity_at = datetime.utcnow()
    
    def update_activity(self, ip_address: str = None, user_agent: str = None) -> None:
        """
        Update session activity tracking.
        
        Args:
            ip_address: Current client IP address
            user_agent: Current client user agent
        """
        self.last_activity_at = datetime.utcnow()
        
        if ip_address and ip_address != self.ip_address:
            # Log potential session hijacking attempt
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Session IP change detected: {self.ip_address} -> {ip_address} for user {self.user_id}")
        
        if ip_address:
            self.ip_address = ip_address
        if user_agent:
            self.user_agent = user_agent
    
    def revoke_session(self, revoked_by: str = None) -> None:
        """
        Revoke session and mark as invalid.
        
        Args:
            revoked_by: User ID who revoked the session
        """
        self.is_valid = False
        self.revoked_at = datetime.utcnow()
        self.revoked_by = revoked_by or 'system'
    
    def get_session_data(self) -> Dict[str, Any]:
        """
        Get session data as dictionary.
        
        Returns:
            Dictionary of session data
        """
        if not self.session_data:
            return {}
        try:
            return json.loads(self.session_data)
        except (ValueError, TypeError):
            return {}
    
    def set_session_data(self, data: Dict[str, Any]) -> None:
        """
        Set session data from dictionary.
        
        Args:
            data: Dictionary of session data to store
        """
        self.session_data = json.dumps(data) if data else None
    
    def to_dict(self, include_tokens: bool = False) -> Dict[str, Any]:
        """
        Convert session to dictionary representation.
        
        Args:
            include_tokens: Whether to include sensitive token information
            
        Returns:
            Dictionary representation of the session
        """
        result = {
            'id': self.id,
            'user_id': self.user_id,
            'expires_at': self.expires_at.isoformat(),
            'is_valid': self.is_valid,
            'is_expired': self.is_expired(),
            'is_active': self.is_active(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'last_activity_at': self.last_activity_at.isoformat(),
            'login_method': self.login_method,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'revoked_by': self.revoked_by
        }
        
        if include_tokens:
            result.update({
                'session_token': self.session_token,
                'csrf_token': self.csrf_token,
                'refresh_token': self.refresh_token,
                'session_data': self.get_session_data()
            })
        
        return result
    
    @classmethod
    def cleanup_expired_sessions(cls, batch_size: int = 1000) -> int:
        """
        Clean up expired sessions from the database.
        
        Args:
            batch_size: Number of sessions to delete per batch
            
        Returns:
            Number of sessions deleted
        """
        deleted_count = 0
        
        while True:
            # Delete expired sessions in batches
            result = db.session.execute(
                text("""
                    DELETE FROM user_sessions 
                    WHERE expires_at < :now 
                    AND id IN (
                        SELECT id FROM user_sessions 
                        WHERE expires_at < :now 
                        LIMIT :batch_size
                    )
                """),
                {
                    'now': datetime.utcnow(),
                    'batch_size': batch_size
                }
            )
            
            batch_deleted = result.rowcount
            deleted_count += batch_deleted
            
            if batch_deleted == 0:
                break
            
            db.session.commit()
        
        return deleted_count
    
    def __repr__(self):
        return f"<UserSession {self.session_token[:8]}... for User {self.user_id} (Valid: {self.is_valid})>"


# SQLAlchemy event listeners for automatic audit field population
@event.listens_for(db.session, 'before_commit')
def populate_user_audit_fields(session):
    """
    Automatically populate audit fields before database commit.
    
    Captures user context from Flask-Login sessions and populates created_by
    and updated_by fields for comprehensive audit trail tracking.
    """
    try:
        # Import here to avoid circular imports
        from flask import g
        from flask_login import current_user
        
        # Get current user information
        user_id = None
        if hasattr(g, 'current_user_id'):
            user_id = str(g.current_user_id)
        elif hasattr(current_user, 'id') and current_user.is_authenticated:
            user_id = str(current_user.id)
        else:
            user_id = 'system'
        
        # Populate audit fields for new objects
        for obj in session.new:
            if hasattr(obj, 'created_by') and obj.created_by is None:
                obj.created_by = user_id
            if hasattr(obj, 'updated_by') and obj.updated_by is None:
                obj.updated_by = user_id
        
        # Populate audit fields for modified objects
        for obj in session.dirty:
            if hasattr(obj, 'updated_by'):
                obj.updated_by = user_id
    
    except Exception as e:
        # Log the error but don't break the transaction
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to populate user audit fields: {e}")


# Flask-Login user loader function
def load_user(user_id):
    """
    Flask-Login user loader function for session-based authentication.
    
    Args:
        user_id: User ID from session
        
    Returns:
        User object or None if not found
    """
    try:
        return User.query.filter_by(id=int(user_id), is_active=True).first()
    except (ValueError, TypeError):
        return None


# Utility functions for user management
class UserUtils:
    """
    Utility class providing helper methods for user management operations.
    
    Includes methods for user creation, authentication, session management,
    and Auth0 integration to support Flask application user workflows.
    """
    
    @staticmethod
    def create_user(username: str, email: str, password: str = None, 
                   auth0_user_id: str = None, **kwargs) -> User:
        """
        Create a new user with proper validation and setup.
        
        Args:
            username: Unique username
            email: Email address
            password: Password (optional for Auth0 users)
            auth0_user_id: Auth0 user identifier
            **kwargs: Additional user attributes
            
        Returns:
            New User instance
            
        Raises:
            ValueError: If validation fails
        """
        # Validate required fields
        if not username or not email:
            raise ValueError("Username and email are required")
        
        # Check for existing user
        existing_user = User.query.filter(
            (User.username == username.lower()) | (User.email == email.lower())
        ).first()
        
        if existing_user:
            raise ValueError("User with this username or email already exists")
        
        # Create user
        user = User(
            username=username.lower(),
            email=email.lower(),
            auth0_user_id=auth0_user_id,
            **kwargs
        )
        
        # Set password if provided
        if password:
            user.set_password(password)
        
        return user
    
    @staticmethod
    def authenticate_user(username_or_email: str, password: str) -> Optional[User]:
        """
        Authenticate user with username/email and password.
        
        Args:
            username_or_email: Username or email address
            password: Password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        # Find user by username or email
        user = User.query.filter(
            (User.username == username_or_email.lower()) | 
            (User.email == username_or_email.lower())
        ).filter_by(is_active=True).first()
        
        if not user:
            return None
        
        # Check if account is locked
        if user.is_account_locked():
            return None
        
        # Verify password
        if not user.check_password(password):
            user.record_failed_login()
            db.session.commit()
            return None
        
        # Update login tracking
        user.update_login_tracking()
        db.session.commit()
        
        return user
    
    @staticmethod
    def find_or_create_auth0_user(auth0_user_data: Dict[str, Any]) -> User:
        """
        Find existing Auth0 user or create new one from Auth0 data.
        
        Args:
            auth0_user_data: Auth0 user data dictionary
            
        Returns:
            User object (existing or newly created)
        """
        auth0_user_id = auth0_user_data.get('user_id')
        email = auth0_user_data.get('email')
        
        if not auth0_user_id:
            raise ValueError("Auth0 user ID is required")
        
        # Try to find existing user by Auth0 ID
        user = User.query.filter_by(auth0_user_id=auth0_user_id).first()
        
        if user:
            # Update existing user with latest Auth0 data
            user.sync_with_auth0(auth0_user_data)
            return user
        
        # Try to find by email if no Auth0 ID match
        if email:
            user = User.query.filter_by(email=email.lower()).first()
            if user:
                # Link existing user to Auth0
                user.auth0_user_id = auth0_user_id
                user.sync_with_auth0(auth0_user_data)
                return user
        
        # Create new user from Auth0 data
        username = auth0_user_data.get('username') or auth0_user_data.get('nickname')
        if not username and email:
            username = email.split('@')[0]
        
        # Ensure username is unique
        base_username = username.lower()
        counter = 1
        while User.query.filter_by(username=username.lower()).first():
            username = f"{base_username}{counter}"
            counter += 1
        
        user = UserUtils.create_user(
            username=username,
            email=email,
            auth0_user_id=auth0_user_id,
            is_verified=auth0_user_data.get('email_verified', False)
        )
        
        # Sync with Auth0 data
        user.sync_with_auth0(auth0_user_data)
        
        return user
    
    @staticmethod
    def create_session_for_user(user: User, **session_kwargs) -> UserSession:
        """
        Create a new session for authenticated user.
        
        Args:
            user: User object
            **session_kwargs: Additional session parameters
            
        Returns:
            New UserSession instance
        """
        session = UserSession.create_session(user, **session_kwargs)
        db.session.add(session)
        db.session.commit()
        return session
    
    @staticmethod
    def validate_session_token(session_token: str) -> Optional[UserSession]:
        """
        Validate session token and return active session.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            UserSession object if valid, None otherwise
        """
        if not session_token:
            return None
        
        session = UserSession.query.filter_by(
            session_token=session_token,
            is_valid=True
        ).first()
        
        if not session or session.is_expired():
            return None
        
        return session
    
    @staticmethod
    def get_user_by_session_token(session_token: str) -> Optional[User]:
        """
        Get user by session token.
        
        Args:
            session_token: Session token
            
        Returns:
            User object if session is valid, None otherwise
        """
        session = UserUtils.validate_session_token(session_token)
        if session:
            return session.user
        return None


# Export models and utilities for application use
__all__ = [
    'User',
    'UserSession',
    'AuditMixin',
    'EncryptedMixin',
    'UserUtils',
    'load_user',
    'db'
]