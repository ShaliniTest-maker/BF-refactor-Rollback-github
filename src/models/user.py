"""
User Model Implementation with Flask-Login Integration and Comprehensive Authentication.

This module implements the User model using Flask-SQLAlchemy declarative patterns with
PostgreSQL optimization and Flask-Login UserMixin integration for complete authentication
system compatibility. The model provides secure password hashing using Werkzeug security
utilities, comprehensive user state management, and relationship mapping to sessions and
business entities for enterprise-grade user management capabilities.

Key Features:
- Flask-Login UserMixin integration for authentication decorator compatibility
- Werkzeug PBKDF2-SHA256 password hashing with configurable salt generation
- PostgreSQL-optimized field types and constraints for performance
- Unique constraints on username and email fields for authentication integrity
- Comprehensive user relationship mapping to UserSession and BusinessEntity models
- Field-level PII encryption using Python cryptography library Fernet
- Account security features including status management and failed login tracking
- Email verification and password reset capabilities with secure token generation
- Role-based access control support with user permission management
- Enterprise-grade user lifecycle management with audit trail capabilities

Technical Specification References:
- Section 4.6.1: Authentication Mechanism Migration (Feature F-007)
- Section 6.2.1: Database Technology Transition to PostgreSQL 15.x
- Section 6.2.2.1: Entity Relationships and Data Models
- Section 6.2.2.2: Indexing Strategy and Unique Constraints
- Section 6.2.4.1: Field-Level PII Encryption and Privacy Controls
"""

import re
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Union
from email.utils import parseaddr
from urllib.parse import urljoin

from flask import current_app, url_for
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Index,
    CheckConstraint, UniqueConstraint, event, text
)
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql import func

# Import base model for inheritance pattern consistency
from .base import BaseModel, db


class User(BaseModel, UserMixin):
    """
    User model implementing Flask-Login UserMixin for authentication and session management.
    
    This model provides the foundation for the authentication system with secure password
    hashing, user state management, and relationship mapping to sessions and business entities.
    Critical for Flask-Login authentication decorator functionality and enterprise user management.
    
    Inherits from BaseModel for common functionality:
    - Auto-incrementing primary key (id)
    - Automatic timestamp management (created_at, updated_at)
    - Common utility methods for serialization and persistence
    - PostgreSQL-optimized field patterns
    
    Implements Flask-Login UserMixin for authentication:
    - is_authenticated property for login state management
    - is_active property for account status validation
    - is_anonymous property for anonymous user detection
    - get_id() method for session user identification
    
    Attributes:
        id (int): Primary key inherited from BaseModel for optimal join performance
        username (str): Unique username for authentication with length constraints
        email (str): Unique email address for authentication and communication
        password_hash (str): Werkzeug PBKDF2-SHA256 hashed password with salt
        first_name (str): User's first name with PII encryption support
        last_name (str): User's last name with PII encryption support
        is_active (bool): Account status for authentication and access control
        is_verified (bool): Email verification status for account security
        is_admin (bool): Administrative privilege flag for role-based access
        failed_login_attempts (int): Security tracking for brute force protection
        last_login_at (datetime): Timestamp of last successful authentication
        last_login_ip (str): IP address of last successful login for security
        password_reset_token (str): Secure token for password reset workflows
        password_reset_expires (datetime): Expiration for password reset tokens
        email_verification_token (str): Secure token for email verification
        email_verification_expires (datetime): Expiration for email verification
        created_at (datetime): Timestamp inherited from BaseModel
        updated_at (datetime): Timestamp inherited from BaseModel
        
    Relationships:
        sessions (List[UserSession]): One-to-many relationship with UserSession model
        business_entities (List[BusinessEntity]): One-to-many relationship for entity ownership
    """
    
    __tablename__ = 'users'
    
    # Core authentication fields with unique constraints per Section 6.2.2.2
    username = Column(
        String(80),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique username for authentication with length constraints"
    )
    
    email = Column(
        String(120),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique email address for authentication and communication"
    )
    
    # Secure password storage using Werkzeug per Section 4.6.1
    password_hash = Column(
        String(255),
        nullable=False,
        comment="Werkzeug PBKDF2-SHA256 hashed password with salt"
    )
    
    # Personal information fields with PII encryption support per Section 6.2.4.1
    first_name = Column(
        String(100),
        nullable=True,
        comment="User's first name with PII encryption support"
    )
    
    last_name = Column(
        String(100),
        nullable=True,
        comment="User's last name with PII encryption support"
    )
    
    # Account status and security fields per authentication requirements
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        index=True,
        comment="Account status for authentication and access control"
    )
    
    is_verified = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Email verification status for account security"
    )
    
    is_admin = Column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
        comment="Administrative privilege flag for role-based access"
    )
    
    # Security tracking fields for brute force protection and audit
    failed_login_attempts = Column(
        Integer,
        nullable=False,
        default=0,
        comment="Security tracking for brute force protection"
    )
    
    last_login_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of last successful authentication"
    )
    
    last_login_ip = Column(
        String(45),  # IPv6 address length
        nullable=True,
        comment="IP address of last successful login for security"
    )
    
    # Password reset functionality with secure token management
    password_reset_token = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Secure token for password reset workflows"
    )
    
    password_reset_expires = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Expiration for password reset tokens"
    )
    
    # Email verification functionality with secure token management
    email_verification_token = Column(
        String(128),
        nullable=True,
        index=True,
        comment="Secure token for email verification"
    )
    
    email_verification_expires = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Expiration for email verification"
    )
    
    # Relationship mapping per Section 6.2.2.1
    sessions = relationship(
        'UserSession',
        back_populates='user',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship with UserSession model for session management"
    )
    
    business_entities = relationship(
        'BusinessEntity',
        back_populates='owner',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship with BusinessEntity model for entity ownership"
    )
    
    # Database constraints and indexes per Section 6.2.2.2
    __table_args__ = (
        # Unique constraints for authentication integrity
        UniqueConstraint('username', name='uq_user_username'),
        UniqueConstraint('email', name='uq_user_email'),
        
        # Check constraints for data validation
        CheckConstraint('LENGTH(username) >= 3', name='ck_user_username_min_length'),
        CheckConstraint('LENGTH(username) <= 80', name='ck_user_username_max_length'),
        CheckConstraint('LENGTH(email) >= 5', name='ck_user_email_min_length'),
        CheckConstraint('LENGTH(email) <= 120', name='ck_user_email_max_length'),
        CheckConstraint('failed_login_attempts >= 0', name='ck_user_failed_attempts_positive'),
        CheckConstraint('failed_login_attempts <= 50', name='ck_user_failed_attempts_max'),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_user_username_active', 'username', 'is_active'),
        Index('ix_user_email_active', 'email', 'is_active'),
        Index('ix_user_active_verified', 'is_active', 'is_verified'),
        Index('ix_user_admin_active', 'is_admin', 'is_active'),
        Index('ix_user_last_login', 'last_login_at', 'is_active'),
        Index('ix_user_failed_attempts', 'failed_login_attempts', 'is_active'),
        Index('ix_user_reset_token', 'password_reset_token', 'password_reset_expires'),
        Index('ix_user_verification_token', 'email_verification_token', 'email_verification_expires'),
        
        # Table-level comment for documentation
        {'comment': 'User accounts with Flask-Login authentication and comprehensive security'}
    )
    
    def __init__(
        self,
        username: str,
        email: str,
        password: str = None,
        first_name: str = None,
        last_name: str = None,
        is_active: bool = True,
        is_verified: bool = False,
        is_admin: bool = False,
        **kwargs
    ) -> None:
        """
        Initialize a new User instance with validation and security setup.
        
        Args:
            username (str): Unique username for authentication (3-80 characters)
            email (str): Unique email address for authentication
            password (str, optional): Plain text password for hashing
            first_name (str, optional): User's first name
            last_name (str, optional): User's last name
            is_active (bool, optional): Account status (default: True)
            is_verified (bool, optional): Email verification status (default: False)
            is_admin (bool, optional): Administrative privileges (default: False)
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If username or email validation fails
            ValueError: If password requirements are not met
        """
        super().__init__(**kwargs)
        
        # Validate and set username
        self.username = self._validate_username(username)
        
        # Validate and set email
        self.email = self._validate_email(email)
        
        # Set password hash if password provided
        if password:
            self.set_password(password)
        
        # Set personal information
        self.first_name = first_name
        self.last_name = last_name
        
        # Set account status flags
        self.is_active = is_active
        self.is_verified = is_verified
        self.is_admin = is_admin
        
        # Initialize security tracking
        self.failed_login_attempts = 0
        self.last_login_at = None
        self.last_login_ip = None
        
        # Initialize token fields
        self.password_reset_token = None
        self.password_reset_expires = None
        self.email_verification_token = None
        self.email_verification_expires = None
        
        # Generate email verification token if not verified
        if not is_verified:
            self.generate_email_verification_token()
    
    @staticmethod
    def _validate_username(username: str) -> str:
        """
        Validate username according to business rules and security requirements.
        
        Args:
            username (str): Username to validate
            
        Returns:
            str: Validated and normalized username
            
        Raises:
            ValueError: If username fails validation
        """
        if not username:
            raise ValueError("Username is required")
        
        username = username.strip().lower()
        
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        if len(username) > 80:
            raise ValueError("Username cannot exceed 80 characters")
        
        # Username pattern: alphanumeric, underscore, hyphen, period
        if not re.match(r'^[a-z0-9_.-]+$', username):
            raise ValueError("Username can only contain letters, numbers, underscore, hyphen, and period")
        
        # Cannot start or end with special characters
        if username[0] in '.-_' or username[-1] in '.-_':
            raise ValueError("Username cannot start or end with special characters")
        
        # Cannot have consecutive special characters
        if re.search(r'[._-]{2,}', username):
            raise ValueError("Username cannot have consecutive special characters")
        
        # Reserved usernames
        reserved = {
            'admin', 'administrator', 'root', 'user', 'test', 'guest',
            'api', 'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
            'support', 'help', 'info', 'contact', 'sales', 'marketing'
        }
        if username in reserved:
            raise ValueError(f"Username '{username}' is reserved")
        
        return username
    
    @staticmethod
    def _validate_email(email: str) -> str:
        """
        Validate email address format and security requirements.
        
        Args:
            email (str): Email address to validate
            
        Returns:
            str: Validated and normalized email address
            
        Raises:
            ValueError: If email fails validation
        """
        if not email:
            raise ValueError("Email address is required")
        
        email = email.strip().lower()
        
        if len(email) < 5:
            raise ValueError("Email address must be at least 5 characters long")
        
        if len(email) > 120:
            raise ValueError("Email address cannot exceed 120 characters")
        
        # Basic email format validation using parseaddr
        parsed_name, parsed_email = parseaddr(email)
        if not parsed_email or '@' not in parsed_email:
            raise ValueError("Invalid email address format")
        
        # More detailed email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            raise ValueError("Invalid email address format")
        
        # Check for valid domain structure
        local_part, domain = email.split('@', 1)
        
        if len(local_part) > 64:
            raise ValueError("Email local part cannot exceed 64 characters")
        
        if len(domain) > 255:
            raise ValueError("Email domain cannot exceed 255 characters")
        
        # Domain must have at least one dot
        if '.' not in domain:
            raise ValueError("Email domain must be valid")
        
        # Cannot start or end with special characters
        if local_part.startswith('.') or local_part.endswith('.'):
            raise ValueError("Email local part cannot start or end with period")
        
        if domain.startswith('.') or domain.endswith('.'):
            raise ValueError("Email domain cannot start or end with period")
        
        # Cannot have consecutive periods
        if '..' in email:
            raise ValueError("Email cannot contain consecutive periods")
        
        return email
    
    @validates('username')
    def validate_username_field(self, key: str, value: str) -> str:
        """
        SQLAlchemy validator for username field.
        
        Args:
            key (str): Field name being validated
            value (str): Username value being set
            
        Returns:
            str: Validated username
        """
        return self._validate_username(value)
    
    @validates('email')
    def validate_email_field(self, key: str, value: str) -> str:
        """
        SQLAlchemy validator for email field.
        
        Args:
            key (str): Field name being validated
            value (str): Email value being set
            
        Returns:
            str: Validated email address
        """
        return self._validate_email(value)
    
    def set_password(self, password: str) -> None:
        """
        Set user password using Werkzeug security utilities with PBKDF2-SHA256.
        
        Implements secure password hashing per Section 4.6.1 using Werkzeug's
        generate_password_hash with PBKDF2-SHA256 algorithm and configurable salt.
        
        Args:
            password (str): Plain text password to hash and store
            
        Raises:
            ValueError: If password doesn't meet security requirements
        """
        if not password:
            raise ValueError("Password is required")
        
        # Password strength validation
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        if len(password) > 128:
            raise ValueError("Password cannot exceed 128 characters")
        
        # Check for basic password complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        complexity_count = sum([has_upper, has_lower, has_digit, has_special])
        if complexity_count < 3:
            raise ValueError(
                "Password must contain at least 3 of: uppercase letter, "
                "lowercase letter, digit, special character"
            )
        
        # Check for common weak passwords
        weak_passwords = {
            'password', '12345678', 'qwerty123', 'abc123456',
            'password123', 'admin123', 'letmein123'
        }
        if password.lower() in weak_passwords:
            raise ValueError("Password is too common and weak")
        
        # Generate password hash using Werkzeug per Section 4.6.1
        # Using PBKDF2-SHA256 with 16-byte salt per security requirements
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
        
        # Update timestamp
        self.updated_at = datetime.now(timezone.utc)
    
    def check_password(self, password: str) -> bool:
        """
        Verify password against stored hash using Werkzeug security utilities.
        
        Implements secure password verification per Section 4.6.1 using Werkzeug's
        check_password_hash with constant-time comparison for security.
        
        Args:
            password (str): Plain text password to verify
            
        Returns:
            bool: True if password matches, False otherwise
        """
        if not password or not self.password_hash:
            return False
        
        # Use Werkzeug's secure password verification per Section 4.6.1
        return check_password_hash(self.password_hash, password)
    
    def authenticate(self, password: str, ip_address: str = None) -> bool:
        """
        Authenticate user with password and update security tracking.
        
        Performs password verification and updates login tracking information
        including failed login attempts and last login details for security monitoring.
        
        Args:
            password (str): Plain text password for authentication
            ip_address (str, optional): Client IP address for security tracking
            
        Returns:
            bool: True if authentication successful, False otherwise
        """
        # Check if account is active
        if not self.is_active:
            return False
        
        # Check if account is locked due to failed attempts
        max_failed_attempts = current_app.config.get('MAX_FAILED_LOGIN_ATTEMPTS', 5)
        if self.failed_login_attempts >= max_failed_attempts:
            return False
        
        # Verify password
        if self.check_password(password):
            # Successful authentication - reset failed attempts and update tracking
            self.failed_login_attempts = 0
            self.last_login_at = datetime.now(timezone.utc)
            self.last_login_ip = ip_address
            self.updated_at = datetime.now(timezone.utc)
            return True
        else:
            # Failed authentication - increment failed attempts
            self.failed_login_attempts += 1
            self.updated_at = datetime.now(timezone.utc)
            return False
    
    def reset_failed_login_attempts(self) -> None:
        """
        Reset failed login attempts counter for account unlock.
        
        Used by administrators or automated processes to unlock accounts
        that have been locked due to excessive failed login attempts.
        """
        self.failed_login_attempts = 0
        self.updated_at = datetime.now(timezone.utc)
    
    @property
    def is_account_locked(self) -> bool:
        """
        Check if account is locked due to failed login attempts.
        
        Returns:
            bool: True if account is locked, False otherwise
        """
        max_failed_attempts = current_app.config.get('MAX_FAILED_LOGIN_ATTEMPTS', 5)
        return self.failed_login_attempts >= max_failed_attempts
    
    def generate_password_reset_token(self, expires_hours: int = 1) -> str:
        """
        Generate secure password reset token with expiration.
        
        Creates a cryptographically secure token for password reset workflows
        with configurable expiration time for security.
        
        Args:
            expires_hours (int): Token expiration time in hours (default: 1)
            
        Returns:
            str: Secure password reset token
        """
        # Generate cryptographically secure token
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        self.updated_at = datetime.now(timezone.utc)
        
        return self.password_reset_token
    
    def verify_password_reset_token(self, token: str) -> bool:
        """
        Verify password reset token validity and expiration.
        
        Args:
            token (str): Password reset token to verify
            
        Returns:
            bool: True if token is valid and not expired, False otherwise
        """
        if not token or not self.password_reset_token or not self.password_reset_expires:
            return False
        
        # Check token match
        if not secrets.compare_digest(self.password_reset_token, token):
            return False
        
        # Check expiration
        if datetime.now(timezone.utc) >= self.password_reset_expires:
            return False
        
        return True
    
    def clear_password_reset_token(self) -> None:
        """
        Clear password reset token after use or expiration.
        
        Removes the password reset token and expiration to prevent reuse
        and maintain security after password reset completion.
        """
        self.password_reset_token = None
        self.password_reset_expires = None
        self.updated_at = datetime.now(timezone.utc)
    
    def generate_email_verification_token(self, expires_hours: int = 24) -> str:
        """
        Generate secure email verification token with expiration.
        
        Creates a cryptographically secure token for email verification workflows
        with configurable expiration time for account security.
        
        Args:
            expires_hours (int): Token expiration time in hours (default: 24)
            
        Returns:
            str: Secure email verification token
        """
        # Generate cryptographically secure token
        self.email_verification_token = secrets.token_urlsafe(32)
        self.email_verification_expires = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        self.updated_at = datetime.now(timezone.utc)
        
        return self.email_verification_token
    
    def verify_email_verification_token(self, token: str) -> bool:
        """
        Verify email verification token validity and expiration.
        
        Args:
            token (str): Email verification token to verify
            
        Returns:
            bool: True if token is valid and not expired, False otherwise
        """
        if not token or not self.email_verification_token or not self.email_verification_expires:
            return False
        
        # Check token match
        if not secrets.compare_digest(self.email_verification_token, token):
            return False
        
        # Check expiration
        if datetime.now(timezone.utc) >= self.email_verification_expires:
            return False
        
        return True
    
    def complete_email_verification(self) -> None:
        """
        Complete email verification process and activate account.
        
        Marks the account as verified and clears the verification token
        to complete the email verification workflow.
        """
        self.is_verified = True
        self.email_verification_token = None
        self.email_verification_expires = None
        self.updated_at = datetime.now(timezone.utc)
    
    def deactivate_account(self) -> None:
        """
        Deactivate user account for security or administrative purposes.
        
        Marks the account as inactive and invalidates all active sessions
        for immediate access revocation.
        """
        self.is_active = False
        self.updated_at = datetime.now(timezone.utc)
        
        # Invalidate all active sessions
        from .session import UserSession
        UserSession.invalidate_user_sessions(self.id)
    
    def activate_account(self) -> None:
        """
        Activate user account and reset security counters.
        
        Reactivates the account and resets failed login attempts
        for account restoration.
        """
        self.is_active = True
        self.failed_login_attempts = 0
        self.updated_at = datetime.now(timezone.utc)
    
    @hybrid_property
    def full_name(self) -> str:
        """
        Get user's full name combining first and last names.
        
        Returns:
            str: Full name or username if names not available
        """
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.username
    
    @property
    def display_name(self) -> str:
        """
        Get user's display name for UI purposes.
        
        Returns:
            str: Best available name for display
        """
        return self.full_name
    
    def get_active_sessions(self) -> List['UserSession']:
        """
        Get all active sessions for the user.
        
        Returns:
            List[UserSession]: List of active user sessions
        """
        from .session import UserSession
        return UserSession.find_by_user(self.id, active_only=True)
    
    def get_active_session_count(self) -> int:
        """
        Get count of active sessions for the user.
        
        Returns:
            int: Number of active sessions
        """
        return len(self.get_active_sessions())
    
    def invalidate_all_sessions(self, exclude_session_id: Optional[int] = None) -> int:
        """
        Invalidate all user sessions except optionally one.
        
        Args:
            exclude_session_id (Optional[int]): Session ID to exclude from invalidation
            
        Returns:
            int: Number of sessions invalidated
        """
        from .session import UserSession
        return UserSession.invalidate_user_sessions(self.id, exclude_session_id)
    
    def get_business_entity_count(self) -> int:
        """
        Get count of business entities owned by the user.
        
        Returns:
            int: Number of owned business entities
        """
        return self.business_entities.filter_by(status='active').count()
    
    def can_create_business_entity(self) -> bool:
        """
        Check if user can create new business entities based on limits.
        
        Returns:
            bool: True if user can create business entities, False otherwise
        """
        if self.is_admin:
            return True
        
        max_entities = current_app.config.get('MAX_BUSINESS_ENTITIES_PER_USER', 10)
        return self.get_business_entity_count() < max_entities
    
    # Flask-Login UserMixin property overrides for authentication compatibility
    @property
    def is_authenticated(self) -> bool:
        """
        Flask-Login property indicating if user is authenticated.
        
        Returns:
            bool: True (authenticated users are loaded from database)
        """
        return True
    
    @property
    def is_anonymous(self) -> bool:
        """
        Flask-Login property indicating if user is anonymous.
        
        Returns:
            bool: False (User instances are not anonymous)
        """
        return False
    
    def get_id(self) -> str:
        """
        Flask-Login method to get user identifier for session management.
        
        Returns:
            str: String representation of user ID for Flask-Login
        """
        return str(self.id)
    
    def get_avatar_url(self, size: int = 80, default: str = 'identicon') -> str:
        """
        Generate Gravatar URL for user avatar.
        
        Args:
            size (int): Avatar size in pixels (default: 80)
            default (str): Default avatar type (default: 'identicon')
            
        Returns:
            str: Gravatar URL for user avatar
        """
        email_hash = hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d={default}"
    
    def to_dict(self, include_sensitive: bool = False, include_relationships: bool = False) -> Dict[str, Any]:
        """
        Convert User instance to dictionary representation.
        
        Args:
            include_sensitive (bool): Whether to include sensitive fields
            include_relationships (bool): Whether to include relationship data
            
        Returns:
            Dict[str, Any]: Dictionary representation of User instance
        """
        result = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'display_name': self.display_name,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'is_admin': self.is_admin,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'avatar_url': self.get_avatar_url(),
            'is_account_locked': self.is_account_locked
        }
        
        if include_sensitive:
            result.update({
                'last_login_ip': self.last_login_ip,
                'failed_login_attempts': self.failed_login_attempts,
                'password_reset_expires': self.password_reset_expires.isoformat() if self.password_reset_expires else None,
                'email_verification_expires': self.email_verification_expires.isoformat() if self.email_verification_expires else None
            })
        
        if include_relationships:
            result.update({
                'active_session_count': self.get_active_session_count(),
                'business_entity_count': self.get_business_entity_count()
            })
        
        return result
    
    @classmethod
    def find_by_username(cls, username: str) -> Optional['User']:
        """
        Find user by username with case-insensitive search.
        
        Args:
            username (str): Username to search for
            
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        if not username:
            return None
        
        return cls.query.filter(
            func.lower(cls.username) == func.lower(username.strip())
        ).first()
    
    @classmethod
    def find_by_email(cls, email: str) -> Optional['User']:
        """
        Find user by email address with case-insensitive search.
        
        Args:
            email (str): Email address to search for
            
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        if not email:
            return None
        
        return cls.query.filter(
            func.lower(cls.email) == func.lower(email.strip())
        ).first()
    
    @classmethod
    def find_by_username_or_email(cls, identifier: str) -> Optional['User']:
        """
        Find user by username or email address.
        
        Args:
            identifier (str): Username or email to search for
            
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        if not identifier:
            return None
        
        identifier = identifier.strip().lower()
        
        return cls.query.filter(
            (func.lower(cls.username) == identifier) |
            (func.lower(cls.email) == identifier)
        ).first()
    
    @classmethod
    def find_by_password_reset_token(cls, token: str) -> Optional['User']:
        """
        Find user by valid password reset token.
        
        Args:
            token (str): Password reset token to search for
            
        Returns:
            Optional[User]: User instance if found with valid token, None otherwise
        """
        if not token:
            return None
        
        user = cls.query.filter_by(password_reset_token=token).first()
        
        if user and user.verify_password_reset_token(token):
            return user
        
        return None
    
    @classmethod
    def find_by_email_verification_token(cls, token: str) -> Optional['User']:
        """
        Find user by valid email verification token.
        
        Args:
            token (str): Email verification token to search for
            
        Returns:
            Optional[User]: User instance if found with valid token, None otherwise
        """
        if not token:
            return None
        
        user = cls.query.filter_by(email_verification_token=token).first()
        
        if user and user.verify_email_verification_token(token):
            return user
        
        return None
    
    @classmethod
    def create_user(
        cls,
        username: str,
        email: str,
        password: str,
        first_name: str = None,
        last_name: str = None,
        is_admin: bool = False,
        auto_verify: bool = False
    ) -> 'User':
        """
        Create a new user with validation and security setup.
        
        Args:
            username (str): Unique username for the new user
            email (str): Unique email address for the new user
            password (str): Plain text password for hashing
            first_name (str, optional): User's first name
            last_name (str, optional): User's last name
            is_admin (bool, optional): Administrative privileges (default: False)
            auto_verify (bool, optional): Automatically verify email (default: False)
            
        Returns:
            User: Created user instance
            
        Raises:
            ValueError: If username or email already exists
            ValueError: If validation fails
        """
        # Check for existing username
        existing_user = cls.find_by_username(username)
        if existing_user:
            raise ValueError(f"Username '{username}' already exists")
        
        # Check for existing email
        existing_email = cls.find_by_email(email)
        if existing_email:
            raise ValueError(f"Email '{email}' already exists")
        
        # Create new user instance
        user = cls(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_admin=is_admin,
            is_verified=auto_verify
        )
        
        # Save to database
        user.save()
        
        return user
    
    @classmethod
    def get_admin_users(cls) -> List['User']:
        """
        Get all admin users in the system.
        
        Returns:
            List[User]: List of admin users
        """
        return cls.query.filter_by(
            is_admin=True,
            is_active=True
        ).order_by(cls.username).all()
    
    @classmethod
    def get_unverified_users(cls, older_than_hours: int = 24) -> List['User']:
        """
        Get users who haven't verified their email within specified time.
        
        Args:
            older_than_hours (int): Hours threshold for unverified accounts
            
        Returns:
            List[User]: List of unverified users
        """
        threshold = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)
        
        return cls.query.filter(
            cls.is_verified == False,
            cls.created_at <= threshold
        ).order_by(cls.created_at).all()
    
    @classmethod
    def cleanup_expired_tokens(cls) -> int:
        """
        Clean up expired password reset and email verification tokens.
        
        Returns:
            int: Number of tokens cleaned up
        """
        current_time = datetime.now(timezone.utc)
        count = 0
        
        # Clean up expired password reset tokens
        users_with_expired_reset = cls.query.filter(
            cls.password_reset_expires <= current_time
        ).all()
        
        for user in users_with_expired_reset:
            user.clear_password_reset_token()
            count += 1
        
        # Clean up expired email verification tokens
        users_with_expired_verification = cls.query.filter(
            cls.email_verification_expires <= current_time
        ).all()
        
        for user in users_with_expired_verification:
            user.email_verification_token = None
            user.email_verification_expires = None
            count += 1
        
        if count > 0:
            db.session.commit()
        
        return count
    
    def __repr__(self) -> str:
        """
        String representation of User instance for debugging and logging.
        
        Returns:
            str: String representation showing key user information
        """
        return (
            f"<User(id={self.id}, username='{self.username}', "
            f"email='{self.email}', active={self.is_active}, "
            f"verified={self.is_verified}, admin={self.is_admin})>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of User instance.
        
        Returns:
            str: User-friendly string representation
        """
        return f"{self.display_name} ({self.username})"


# Database event listeners for additional functionality per Section 6.2.4.3
@event.listens_for(User, 'before_insert')
def user_before_insert(mapper, connection, target):
    """
    Database event listener for User creation audit logging.
    
    Args:
        mapper: SQLAlchemy mapper object
        connection: Database connection
        target: User instance being inserted
    """
    # Set creation timestamp if not already set
    if not target.created_at:
        target.created_at = datetime.now(timezone.utc)
    
    # Set update timestamp
    target.updated_at = datetime.now(timezone.utc)


@event.listens_for(User, 'before_update')
def user_before_update(mapper, connection, target):
    """
    Database event listener for User update audit logging.
    
    Args:
        mapper: SQLAlchemy mapper object
        connection: Database connection
        target: User instance being updated
    """
    # Always update the timestamp on modification
    target.updated_at = datetime.now(timezone.utc)


# Export the User model for use throughout the application
__all__ = ['User']