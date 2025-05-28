"""
User Model Implementation for Flask-Login Authentication System.

This module implements the User model using Flask-SQLAlchemy declarative patterns
with PostgreSQL optimization and Flask-Login UserMixin integration. The model
provides comprehensive user authentication and session management capabilities
while maintaining functional parity with the original Node.js implementation.

Key Features:
- Flask-Login UserMixin integration for authentication decorators
- Werkzeug security utilities for secure password hashing
- PostgreSQL-optimized field types and constraints
- Unique constraints on username and email fields
- Relationship mapping to UserSession and BusinessEntity models
- Comprehensive timestamp management with automatic population
"""

from datetime import datetime, timezone
from typing import Optional, List
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, 
    Index, UniqueConstraint, CheckConstraint
)

# Flask-SQLAlchemy instance - will be initialized by application factory
db = SQLAlchemy()


class User(db.Model, UserMixin):
    """
    User model implementing Flask-Login UserMixin for authentication and session management.
    
    This model provides the foundation for the authentication system with secure password
    hashing, user state management, and relationship mapping to sessions and business entities.
    Critical for Flask-Login authentication decorator functionality.
    
    Attributes:
        id (int): Primary key with auto-incrementing integer for optimal join performance
        username (str): Unique username for user identification and authentication
        email (str): Unique email address for user identification and communication
        password_hash (str): Securely hashed password using Werkzeug PBKDF2 with SHA-256
        is_active (bool): User account status for authentication and access control
        created_at (datetime): Timestamp of user account creation with UTC timezone
        updated_at (datetime): Timestamp of last user account modification with UTC timezone
        
    Relationships:
        sessions (List[UserSession]): One-to-many relationship with user sessions
        business_entities (List[BusinessEntity]): One-to-many relationship with owned entities
    """
    
    __tablename__ = 'users'
    
    # Primary key configuration for optimal join performance per Section 6.2.2.2
    id = Column(
        Integer, 
        primary_key=True, 
        autoincrement=True,
        comment="Auto-incrementing primary key for optimal PostgreSQL join performance"
    )
    
    # User identification fields with unique constraints per Section 6.2.2.2
    username = Column(
        String(80), 
        unique=True, 
        nullable=False,
        index=True,
        comment="Unique username for user identification and authentication"
    )
    
    email = Column(
        String(120), 
        unique=True, 
        nullable=False,
        index=True,
        comment="Unique email address for user identification and communication"
    )
    
    # Secure password storage using Werkzeug hashing per Section 4.6.1
    password_hash = Column(
        String(255), 
        nullable=False,
        comment="Securely hashed password using Werkzeug PBKDF2 with SHA-256"
    )
    
    # User state management for authentication per Flask-Login requirements
    is_active = Column(
        Boolean, 
        nullable=False, 
        default=True,
        index=True,
        comment="User account status for authentication and access control"
    )
    
    # Timestamp fields for audit and lifecycle management per Section 6.2.1
    created_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc),
        comment="Timestamp of user account creation with UTC timezone"
    )
    
    updated_at = Column(
        DateTime(timezone=True), 
        nullable=False, 
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        comment="Timestamp of last user account modification with UTC timezone"
    )
    
    # Relationship mapping to UserSession model per Section 6.2.2.1
    sessions = relationship(
        'UserSession',
        back_populates='user',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship with user sessions for authentication state management"
    )
    
    # Relationship mapping to BusinessEntity model per Section 6.2.2.1
    business_entities = relationship(
        'BusinessEntity',
        back_populates='owner',
        lazy='dynamic',
        cascade='all, delete-orphan',
        passive_deletes=True,
        doc="One-to-many relationship with owned business entities"
    )
    
    # Database constraints for data integrity per Section 6.2.2.2
    __table_args__ = (
        # Unique constraints for authentication integrity
        UniqueConstraint('username', name='uq_user_username'),
        UniqueConstraint('email', name='uq_user_email'),
        
        # Check constraints for data validation
        CheckConstraint('LENGTH(username) >= 3', name='ck_user_username_length'),
        CheckConstraint('LENGTH(email) >= 5', name='ck_user_email_length'),
        CheckConstraint("email LIKE '%@%.%'", name='ck_user_email_format'),
        
        # Composite indexes for performance optimization per Section 6.2.2.2
        Index('ix_user_active_created', 'is_active', 'created_at'),
        Index('ix_user_email_active', 'email', 'is_active'),
        Index('ix_user_username_active', 'username', 'is_active'),
        
        # Table-level comment for documentation
        {'comment': 'User accounts for authentication and session management'}
    )
    
    def __init__(self, username: str, email: str, password: str, **kwargs) -> None:
        """
        Initialize a new User instance with secure password hashing.
        
        Args:
            username (str): Unique username for the user account
            email (str): Unique email address for the user account
            password (str): Plain text password to be securely hashed
            **kwargs: Additional keyword arguments for model fields
            
        Raises:
            ValueError: If username or email format is invalid
        """
        super().__init__(**kwargs)
        self.username = username.strip().lower() if username else None
        self.email = email.strip().lower() if email else None
        
        # Validate input requirements
        if not self.username or len(self.username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        if not self.email or '@' not in self.email or '.' not in self.email:
            raise ValueError("Valid email address is required")
        
        # Set secure password hash using Werkzeug per Section 4.6.1
        self.set_password(password)
        
        # Set default values if not provided
        if 'is_active' not in kwargs:
            self.is_active = True
    
    def set_password(self, password: str) -> None:
        """
        Set user password using Werkzeug secure hashing with salt generation.
        
        Implements PBKDF2 with SHA-256 and configurable salt length per Section 4.6.1
        for secure password storage meeting enterprise security requirements.
        
        Args:
            password (str): Plain text password to be securely hashed
            
        Raises:
            ValueError: If password does not meet minimum security requirements
        """
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        # Generate secure password hash using Werkzeug per Section 4.6.1
        # Uses PBKDF2 with SHA-256, salt length of 16, and 100,000 iterations
        self.password_hash = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
    
    def check_password(self, password: str) -> bool:
        """
        Validate password against stored hash using constant-time comparison.
        
        Uses Werkzeug check_password_hash for secure password validation with
        constant-time comparison to prevent timing attacks per Section 4.6.1.
        
        Args:
            password (str): Plain text password to validate
            
        Returns:
            bool: True if password matches stored hash, False otherwise
        """
        if not password or not self.password_hash:
            return False
        
        # Use Werkzeug constant-time comparison per Section 4.6.1
        return check_password_hash(self.password_hash, password)
    
    # Flask-Login UserMixin implementation for authentication decorator compatibility
    
    def is_authenticated(self) -> bool:
        """
        Flask-Login required method for authentication status.
        
        Returns:
            bool: True if user is authenticated (always True for User instances)
        """
        return True
    
    def is_anonymous(self) -> bool:
        """
        Flask-Login required method for anonymous user detection.
        
        Returns:
            bool: False for authenticated User instances
        """
        return False
    
    def get_id(self) -> str:
        """
        Flask-Login required method for session management.
        
        Returns:
            str: String representation of user ID for session storage
        """
        return str(self.id)
    
    # Additional utility methods for business logic integration
    
    def get_active_sessions(self) -> List['UserSession']:
        """
        Retrieve all active sessions for the user.
        
        Returns:
            List[UserSession]: List of active user sessions
        """
        from .session import UserSession  # Avoid circular imports
        
        return self.sessions.filter(
            UserSession.is_valid == True,
            UserSession.expires_at > datetime.now(timezone.utc)
        ).all()
    
    def invalidate_all_sessions(self) -> None:
        """
        Invalidate all user sessions for security purposes.
        
        Used for password changes, account security events, or logout-all functionality.
        """
        for session in self.sessions:
            session.is_valid = False
        
        # Commit changes through SQLAlchemy session
        db.session.commit()
    
    def get_owned_entities(self) -> List['BusinessEntity']:
        """
        Retrieve all business entities owned by this user.
        
        Returns:
            List[BusinessEntity]: List of owned business entities
        """
        return self.business_entities.filter_by(status='active').all()
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert User instance to dictionary representation.
        
        Args:
            include_sensitive (bool): Whether to include sensitive fields like password_hash
            
        Returns:
            dict: Dictionary representation of User instance
        """
        result = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_sensitive:
            result['password_hash'] = self.password_hash
        
        return result
    
    @classmethod
    def find_by_username(cls, username: str) -> Optional['User']:
        """
        Find user by username with case-insensitive matching.
        
        Args:
            username (str): Username to search for
            
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        if not username:
            return None
        
        return cls.query.filter(
            cls.username == username.strip().lower(),
            cls.is_active == True
        ).first()
    
    @classmethod
    def find_by_email(cls, email: str) -> Optional['User']:
        """
        Find user by email address with case-insensitive matching.
        
        Args:
            email (str): Email address to search for
            
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        if not email:
            return None
        
        return cls.query.filter(
            cls.email == email.strip().lower(),
            cls.is_active == True
        ).first()
    
    @classmethod
    def find_by_credentials(cls, identifier: str, password: str) -> Optional['User']:
        """
        Find and authenticate user by username/email and password.
        
        Args:
            identifier (str): Username or email address
            password (str): Plain text password for authentication
            
        Returns:
            Optional[User]: Authenticated User instance if credentials are valid, None otherwise
        """
        if not identifier or not password:
            return None
        
        # Try to find user by username or email
        user = cls.find_by_username(identifier) or cls.find_by_email(identifier)
        
        # Validate password if user found
        if user and user.check_password(password):
            return user
        
        return None
    
    def __repr__(self) -> str:
        """
        String representation of User instance for debugging and logging.
        
        Returns:
            str: String representation of User instance
        """
        return (
            f"<User(id={self.id}, username='{self.username}', "
            f"email='{self.email}', is_active={self.is_active})>"
        )
    
    def __str__(self) -> str:
        """
        Human-readable string representation of User instance.
        
        Returns:
            str: User-friendly string representation
        """
        return f"User: {self.username} ({self.email})"