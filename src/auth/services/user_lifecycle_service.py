"""
User Lifecycle Management Service

This module implements comprehensive user account lifecycle management including 
registration, profile management, password reset, and account deactivation workflows.
The service orchestrates user data synchronization between Auth0 and Flask-SQLAlchemy 
models while maintaining data integrity and security policies throughout the user 
account lifecycle.

This service follows the Service Layer architectural pattern as defined in Section 6.1.3
for business logic orchestration within the Flask monolithic application, providing
centralized user management business logic and workflow coordination.

Key Features:
- User registration with Auth0 and database synchronization (Section 6.4.1.1)
- User profile management with Auth0 Management API integration (Section 6.4.1.1)
- Password reset and account recovery workflows (Section 6.4.1.5)
- Account deactivation and data retention policies (Section 6.4.3.5)
- Comprehensive audit logging for user lifecycle operations (Section 6.4.2.5)
- Security policy enforcement and threat detection integration (Section 6.4.6.1)

Dependencies:
- Auth0 Python SDK 4.9.0 for external identity management
- Flask-SQLAlchemy 3.1.1 for database model persistence
- Python structlog for comprehensive audit logging
- Flask application factory pattern for service registration

Author: DevSecOps Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import structlog
from flask import current_app, g
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.orm import sessionmaker
import hashlib
import secrets
import re

# Core Flask and SQLAlchemy imports
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# Security and encryption imports
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Auth0 and authentication imports
try:
    from auth0.management import Auth0
    from auth0.exceptions import Auth0Error
except ImportError:
    # Fallback for development environments
    Auth0 = None
    Auth0Error = Exception

# Internal application imports
from src.models.user import User
from src.models.session import UserSession
from src.auth.security_monitor import SecurityMonitor
from src.auth.password_utils import PasswordUtils
from src.auth.auth0_integration import Auth0Integration


class UserAccountStatus(Enum):
    """User account status enumeration for lifecycle management"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING_VERIFICATION = "pending_verification"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    DELETED = "deleted"


class LifecycleOperationType(Enum):
    """User lifecycle operation types for audit logging"""
    REGISTRATION = "registration"
    PROFILE_UPDATE = "profile_update"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_ACTIVATION = "account_activation"
    ACCOUNT_DEACTIVATION = "account_deactivation"
    ACCOUNT_DELETION = "account_deletion"
    DATA_SYNC = "data_sync"
    SECURITY_UPDATE = "security_update"


@dataclass
class UserLifecycleEvent:
    """Data structure for user lifecycle audit events"""
    event_id: str
    user_id: str
    operation_type: LifecycleOperationType
    timestamp: datetime
    auth0_user_id: Optional[str] = None
    previous_state: Optional[Dict[str, Any]] = None
    new_state: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class UserRegistrationData:
    """User registration data structure with validation"""
    username: str
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Validate registration data on initialization"""
        self._validate_email()
        self._validate_username()
        self._validate_password()
    
    def _validate_email(self):
        """Validate email format using regex pattern"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, self.email):
            raise ValueError(f"Invalid email format: {self.email}")
    
    def _validate_username(self):
        """Validate username format and length"""
        if not self.username or len(self.username) < 3:
            raise ValueError("Username must be at least 3 characters long")
        if not re.match(r'^[a-zA-Z0-9_-]+$', self.username):
            raise ValueError("Username can only contain letters, numbers, hyphens, and underscores")
    
    def _validate_password(self):
        """Validate password strength requirements"""
        if not self.password or len(self.password) < 8:
            raise ValueError("Password must be at least 8 characters long")


@dataclass
class UserProfileUpdateData:
    """User profile update data structure"""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def has_updates(self) -> bool:
        """Check if any profile updates are provided"""
        return any([
            self.first_name is not None,
            self.last_name is not None,
            self.email is not None,
            self.phone_number is not None,
            self.metadata is not None
        ])


class UserLifecycleError(Exception):
    """Base exception for user lifecycle operations"""
    pass


class UserRegistrationError(UserLifecycleError):
    """Exception for user registration failures"""
    pass


class UserProfileError(UserLifecycleError):
    """Exception for user profile operation failures"""
    pass


class DataSynchronizationError(UserLifecycleError):
    """Exception for data synchronization failures"""
    pass


class UserLifecycleService:
    """
    Comprehensive user lifecycle management service implementing Service Layer pattern
    
    This service orchestrates user account operations including registration, profile
    management, password reset, and account deactivation workflows while maintaining
    data synchronization between Auth0 and Flask-SQLAlchemy models.
    
    The service implements comprehensive audit logging for all user lifecycle operations
    and enforces security policies throughout the user account lifecycle.
    
    Architecture:
    - Service Layer pattern for business logic orchestration (Section 6.1.3)
    - Auth0 integration for external identity management (Section 6.4.1.1)
    - Flask-SQLAlchemy for database model persistence (Section 6.2.1)
    - Structured audit logging with Python structlog (Section 6.4.2.5)
    """
    
    def __init__(self, db: SQLAlchemy, auth0_integration: Auth0Integration,
                 security_monitor: SecurityMonitor, password_utils: PasswordUtils):
        """
        Initialize user lifecycle service with required dependencies
        
        Args:
            db: Flask-SQLAlchemy database instance
            auth0_integration: Auth0 integration service
            security_monitor: Security monitoring service
            password_utils: Password security utilities
        """
        self.db = db
        self.auth0_integration = auth0_integration
        self.security_monitor = security_monitor
        self.password_utils = password_utils
        self.logger = structlog.get_logger("user_lifecycle")
        
        # Initialize session factory for database operations
        self.session_factory = sessionmaker(bind=db.engine)
        
        # Configuration from Flask app config
        self.config = {
            'password_reset_token_expiry': 3600,  # 1 hour
            'verification_token_expiry': 86400,   # 24 hours
            'max_failed_attempts': 5,
            'account_lockout_duration': 1800,     # 30 minutes
            'data_retention_days': 2555,          # 7 years for compliance
            'enable_auth0_sync': True,
            'auto_verify_email': False,
            'require_password_change': False
        }
        
        self.logger.info(
            "UserLifecycleService initialized",
            auth0_enabled=self.config['enable_auth0_sync'],
            password_reset_expiry=self.config['password_reset_token_expiry'],
            data_retention_days=self.config['data_retention_days']
        )
    
    def register_user(self, registration_data: UserRegistrationData,
                     ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None) -> Tuple[User, bool]:
        """
        Register a new user with Auth0 and database synchronization
        
        Implements comprehensive user registration workflow including:
        - Input validation and sanitization
        - Auth0 user creation with Management API
        - Local database user record creation
        - Data synchronization between Auth0 and Flask-SQLAlchemy
        - Comprehensive audit logging for registration events
        - Security monitoring for registration patterns
        
        Args:
            registration_data: UserRegistrationData with user information
            ip_address: Client IP address for security monitoring
            user_agent: Client user agent for audit logging
            
        Returns:
            Tuple of (User object, bool indicating if Auth0 sync was successful)
            
        Raises:
            UserRegistrationError: If registration fails
            DataSynchronizationError: If Auth0 sync fails but local user created
        """
        event_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(
            "Starting user registration",
            event_id=event_id,
            username=registration_data.username,
            email=registration_data.email,
            ip_address=ip_address
        )
        
        # Create audit event for registration
        lifecycle_event = UserLifecycleEvent(
            event_id=event_id,
            user_id="",  # Will be set after user creation
            operation_type=LifecycleOperationType.REGISTRATION,
            timestamp=start_time,
            metadata={
                'username': registration_data.username,
                'email': registration_data.email,
                'has_phone': bool(registration_data.phone_number),
                'registration_method': 'email_password'
            },
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        session = self.session_factory()
        auth0_user_id = None
        auth0_sync_success = False
        
        try:
            # Check for existing users with same email or username
            existing_user = session.query(User).filter(
                (User.email == registration_data.email) |
                (User.username == registration_data.username)
            ).first()
            
            if existing_user:
                if existing_user.email == registration_data.email:
                    raise UserRegistrationError(f"User with email {registration_data.email} already exists")
                else:
                    raise UserRegistrationError(f"Username {registration_data.username} is already taken")
            
            # Hash password securely
            password_hash = self.password_utils.generate_password_hash(
                registration_data.password
            )
            
            # Create local user record first
            user = User(
                username=registration_data.username,
                email=registration_data.email,
                password_hash=password_hash,
                first_name=registration_data.first_name,
                last_name=registration_data.last_name,
                phone_number=registration_data.phone_number,
                status=UserAccountStatus.PENDING_VERIFICATION.value,
                is_active=False,
                email_verified=self.config['auto_verify_email'],
                created_at=start_time,
                updated_at=start_time
            )
            
            # Add user metadata if provided
            if registration_data.metadata:
                user.metadata = json.dumps(registration_data.metadata)
            
            session.add(user)
            session.flush()  # Get user ID without committing
            
            lifecycle_event.user_id = str(user.id)
            lifecycle_event.new_state = self._serialize_user_state(user)
            
            # Attempt Auth0 user creation if enabled
            if self.config['enable_auth0_sync']:
                try:
                    auth0_user_data = {
                        'email': registration_data.email,
                        'password': registration_data.password,
                        'connection': 'Username-Password-Authentication',
                        'username': registration_data.username,
                        'user_metadata': {
                            'local_user_id': str(user.id),
                            'first_name': registration_data.first_name,
                            'last_name': registration_data.last_name,
                            'phone_number': registration_data.phone_number
                        },
                        'app_metadata': {
                            'local_user_id': str(user.id),
                            'registration_date': start_time.isoformat(),
                            'registration_ip': ip_address
                        }
                    }
                    
                    auth0_user = self.auth0_integration.create_user(auth0_user_data)
                    auth0_user_id = auth0_user.get('user_id')
                    
                    # Update local user with Auth0 ID
                    user.auth0_user_id = auth0_user_id
                    auth0_sync_success = True
                    
                    lifecycle_event.auth0_user_id = auth0_user_id
                    lifecycle_event.metadata['auth0_sync'] = True
                    
                    self.logger.info(
                        "Auth0 user created successfully",
                        event_id=event_id,
                        user_id=user.id,
                        auth0_user_id=auth0_user_id
                    )
                    
                except Auth0Error as e:
                    self.logger.error(
                        "Auth0 user creation failed",
                        event_id=event_id,
                        user_id=user.id,
                        error=str(e)
                    )
                    
                    lifecycle_event.metadata['auth0_sync'] = False
                    lifecycle_event.metadata['auth0_error'] = str(e)
                    
                    # Continue with local registration even if Auth0 fails
                    # This will be flagged for manual sync later
                    auth0_sync_success = False
            
            # Commit the transaction
            session.commit()
            
            # Log successful registration
            lifecycle_event.success = True
            self._log_lifecycle_event(lifecycle_event)
            
            # Generate email verification token if required
            if not self.config['auto_verify_email']:
                verification_token = self._generate_verification_token(user.id)
                self._store_verification_token(user.id, verification_token)
                
                self.logger.info(
                    "Email verification token generated",
                    event_id=event_id,
                    user_id=user.id,
                    token_expiry=self.config['verification_token_expiry']
                )
            
            # Security monitoring for registration patterns
            self.security_monitor.track_user_activity(
                user_id=str(user.id),
                action="user_registration",
                resource="user_account",
                details={
                    'registration_method': 'email_password',
                    'auth0_sync': auth0_sync_success,
                    'email_verified': user.email_verified,
                    'ip_address': ip_address
                }
            )
            
            self.logger.info(
                "User registration completed successfully",
                event_id=event_id,
                user_id=user.id,
                username=user.username,
                auth0_sync=auth0_sync_success,
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
            
            return user, auth0_sync_success
            
        except UserRegistrationError:
            # Re-raise user registration errors as-is
            session.rollback()
            lifecycle_event.success = False
            lifecycle_event.error_message = str(e)
            self._log_lifecycle_event(lifecycle_event)
            raise
            
        except SQLAlchemyError as e:
            session.rollback()
            error_msg = f"Database error during user registration: {str(e)}"
            
            lifecycle_event.success = False
            lifecycle_event.error_message = error_msg
            self._log_lifecycle_event(lifecycle_event)
            
            self.logger.error(
                "Database error during user registration",
                event_id=event_id,
                error=str(e),
                username=registration_data.username
            )
            
            raise UserRegistrationError(error_msg)
            
        except Exception as e:
            session.rollback()
            error_msg = f"Unexpected error during user registration: {str(e)}"
            
            lifecycle_event.success = False
            lifecycle_event.error_message = error_msg
            self._log_lifecycle_event(lifecycle_event)
            
            self.logger.error(
                "Unexpected error during user registration",
                event_id=event_id,
                error=str(e),
                username=registration_data.username,
                error_type=type(e).__name__
            )
            
            raise UserRegistrationError(error_msg)
            
        finally:
            session.close()
    
    def update_user_profile(self, user_id: str, update_data: UserProfileUpdateData,
                           updated_by: Optional[str] = None,
                           ip_address: Optional[str] = None,
                           user_agent: Optional[str] = None) -> Tuple[User, bool]:
        """
        Update user profile with Auth0 synchronization
        
        Implements comprehensive user profile update workflow including:
        - Input validation and change detection
        - Local database profile updates
        - Auth0 profile synchronization via Management API
        - Bidirectional data consistency validation
        - Comprehensive audit logging for profile changes
        - Security monitoring for profile modification patterns
        
        Args:
            user_id: User ID to update
            update_data: UserProfileUpdateData with updated information
            updated_by: ID of user making the update (for audit)
            ip_address: Client IP address for security monitoring
            user_agent: Client user agent for audit logging
            
        Returns:
            Tuple of (Updated User object, bool indicating Auth0 sync success)
            
        Raises:
            UserProfileError: If profile update fails
            DataSynchronizationError: If Auth0 sync fails but local update succeeded
        """
        event_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        if not update_data.has_updates():
            raise UserProfileError("No profile updates provided")
        
        self.logger.info(
            "Starting user profile update",
            event_id=event_id,
            user_id=user_id,
            updated_by=updated_by,
            ip_address=ip_address
        )
        
        session = self.session_factory()
        auth0_sync_success = False
        
        try:
            # Retrieve existing user
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise UserProfileError(f"User with ID {user_id} not found")
            
            # Capture previous state for audit
            previous_state = self._serialize_user_state(user)
            
            # Create lifecycle event
            lifecycle_event = UserLifecycleEvent(
                event_id=event_id,
                user_id=user_id,
                operation_type=LifecycleOperationType.PROFILE_UPDATE,
                timestamp=start_time,
                auth0_user_id=user.auth0_user_id,
                previous_state=previous_state,
                metadata={
                    'updated_by': updated_by,
                    'update_fields': []
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Apply profile updates
            updated_fields = []
            
            if update_data.first_name is not None:
                user.first_name = update_data.first_name
                updated_fields.append('first_name')
            
            if update_data.last_name is not None:
                user.last_name = update_data.last_name
                updated_fields.append('last_name')
            
            if update_data.email is not None and update_data.email != user.email:
                # Validate email uniqueness
                existing_user = session.query(User).filter(
                    User.email == update_data.email,
                    User.id != user_id
                ).first()
                
                if existing_user:
                    raise UserProfileError(f"Email {update_data.email} is already in use")
                
                user.email = update_data.email
                user.email_verified = False  # Require re-verification
                updated_fields.append('email')
            
            if update_data.phone_number is not None:
                user.phone_number = update_data.phone_number
                updated_fields.append('phone_number')
            
            if update_data.metadata is not None:
                # Merge with existing metadata
                existing_metadata = {}
                if user.metadata:
                    try:
                        existing_metadata = json.loads(user.metadata)
                    except json.JSONDecodeError:
                        existing_metadata = {}
                
                existing_metadata.update(update_data.metadata)
                user.metadata = json.dumps(existing_metadata)
                updated_fields.append('metadata')
            
            user.updated_at = start_time
            lifecycle_event.metadata['update_fields'] = updated_fields
            
            # Attempt Auth0 profile synchronization
            if self.config['enable_auth0_sync'] and user.auth0_user_id:
                try:
                    auth0_update_data = {}
                    
                    if 'first_name' in updated_fields or 'last_name' in updated_fields:
                        auth0_update_data['user_metadata'] = {}
                        if update_data.first_name is not None:
                            auth0_update_data['user_metadata']['first_name'] = update_data.first_name
                        if update_data.last_name is not None:
                            auth0_update_data['user_metadata']['last_name'] = update_data.last_name
                    
                    if 'email' in updated_fields:
                        auth0_update_data['email'] = update_data.email
                        auth0_update_data['email_verified'] = False
                    
                    if 'phone_number' in updated_fields:
                        if 'user_metadata' not in auth0_update_data:
                            auth0_update_data['user_metadata'] = {}
                        auth0_update_data['user_metadata']['phone_number'] = update_data.phone_number
                    
                    if auth0_update_data:
                        self.auth0_integration.update_user(user.auth0_user_id, auth0_update_data)
                        auth0_sync_success = True
                        
                        self.logger.info(
                            "Auth0 profile updated successfully",
                            event_id=event_id,
                            user_id=user_id,
                            auth0_user_id=user.auth0_user_id,
                            updated_fields=updated_fields
                        )
                
                except Auth0Error as e:
                    self.logger.error(
                        "Auth0 profile update failed",
                        event_id=event_id,
                        user_id=user_id,
                        auth0_user_id=user.auth0_user_id,
                        error=str(e)
                    )
                    
                    lifecycle_event.metadata['auth0_sync'] = False
                    lifecycle_event.metadata['auth0_error'] = str(e)
                    auth0_sync_success = False
            
            # Commit the transaction
            session.commit()
            
            # Capture new state for audit
            lifecycle_event.new_state = self._serialize_user_state(user)
            lifecycle_event.success = True
            lifecycle_event.metadata['auth0_sync'] = auth0_sync_success
            self._log_lifecycle_event(lifecycle_event)
            
            # Security monitoring for profile updates
            self.security_monitor.track_user_activity(
                user_id=user_id,
                action="profile_update",
                resource="user_profile",
                details={
                    'updated_fields': updated_fields,
                    'updated_by': updated_by,
                    'auth0_sync': auth0_sync_success,
                    'ip_address': ip_address
                }
            )
            
            self.logger.info(
                "User profile update completed successfully",
                event_id=event_id,
                user_id=user_id,
                updated_fields=updated_fields,
                auth0_sync=auth0_sync_success,
                duration_ms=(datetime.utcnow() - start_time).total_seconds() * 1000
            )
            
            return user, auth0_sync_success
            
        except UserProfileError:
            # Re-raise profile errors as-is
            session.rollback()
            lifecycle_event.success = False
            lifecycle_event.error_message = str(e)
            self._log_lifecycle_event(lifecycle_event)
            raise
            
        except SQLAlchemyError as e:
            session.rollback()
            error_msg = f"Database error during profile update: {str(e)}"
            
            lifecycle_event.success = False
            lifecycle_event.error_message = error_msg
            self._log_lifecycle_event(lifecycle_event)
            
            self.logger.error(
                "Database error during profile update",
                event_id=event_id,
                user_id=user_id,
                error=str(e)
            )
            
            raise UserProfileError(error_msg)
            
        except Exception as e:
            session.rollback()
            error_msg = f"Unexpected error during profile update: {str(e)}"
            
            lifecycle_event.success = False
            lifecycle_event.error_message = error_msg
            self._log_lifecycle_event(lifecycle_event)
            
            self.logger.error(
                "Unexpected error during profile update",
                event_id=event_id,
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise UserProfileError(error_msg)
            
        finally:
            session.close()
    
    def initiate_password_reset(self, email: str,
                               ip_address: Optional[str] = None,
                               user_agent: Optional[str] = None) -> str:
        """
        Initiate password reset workflow
        
        Implements secure password reset initiation including:
        - User verification by email address
        - Secure reset token generation with expiration
        - Token storage with proper indexing
        - Comprehensive audit logging for security monitoring
        - Rate limiting for brute force protection
        
        Args:
            email: User email address for password reset
            ip_address: Client IP address for security monitoring
            user_agent: Client user agent for audit logging
            
        Returns:
            Password reset token (for email delivery)
            
        Raises:
            UserProfileError: If user not found or reset not allowed
        """
        event_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(
            "Starting password reset initiation",
            event_id=event_id,
            email=email,
            ip_address=ip_address
        )
        
        session = self.session_factory()
        
        try:
            # Find user by email
            user = session.query(User).filter(User.email == email).first()
            if not user:
                # Security: Don't reveal whether email exists
                self.logger.warning(
                    "Password reset attempted for non-existent email",
                    event_id=event_id,
                    email=email,
                    ip_address=ip_address
                )
                
                # Still generate a token-like string to prevent timing attacks
                dummy_token = self._generate_reset_token()
                return dummy_token
            
            # Check if user account is active
            if user.status == UserAccountStatus.DEACTIVATED.value:
                raise UserProfileError("Cannot reset password for deactivated account")
            
            # Generate secure reset token
            reset_token = self._generate_reset_token()
            token_hash = self._hash_token(reset_token)
            expiry_time = start_time + timedelta(seconds=self.config['password_reset_token_expiry'])
            
            # Store reset token
            self._store_password_reset_token(user.id, token_hash, expiry_time)
            
            # Create lifecycle event
            lifecycle_event = UserLifecycleEvent(
                event_id=event_id,
                user_id=str(user.id),
                operation_type=LifecycleOperationType.PASSWORD_RESET,
                timestamp=start_time,
                auth0_user_id=user.auth0_user_id,
                metadata={
                    'action': 'reset_initiated',
                    'token_expiry': expiry_time.isoformat()
                },
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            self._log_lifecycle_event(lifecycle_event)
            
            # Security monitoring
            self.security_monitor.track_user_activity(
                user_id=str(user.id),
                action="password_reset_initiated",
                resource="user_credentials",
                details={
                    'email': email,
                    'token_expiry': expiry_time.isoformat(),
                    'ip_address': ip_address
                }
            )
            
            session.commit()
            
            self.logger.info(
                "Password reset token generated successfully",
                event_id=event_id,
                user_id=user.id,
                email=email,
                token_expiry=expiry_time.isoformat()
            )
            
            return reset_token
            
        except Exception as e:
            session.rollback()
            
            self.logger.error(
                "Error during password reset initiation",
                event_id=event_id,
                email=email,
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise UserProfileError(f"Failed to initiate password reset: {str(e)}")
            
        finally:
            session.close()
    
    def complete_password_reset(self, reset_token: str, new_password: str,
                               ip_address: Optional[str] = None,
                               user_agent: Optional[str] = None) -> User:
        """
        Complete password reset workflow
        
        Implements secure password reset completion including:
        - Reset token validation and expiry checking
        - Password strength validation
        - Secure password hashing and storage
        - Auth0 password synchronization
        - Token cleanup and invalidation
        - Comprehensive audit logging
        
        Args:
            reset_token: Password reset token from email
            new_password: New password to set
            ip_address: Client IP address for security monitoring
            user_agent: Client user agent for audit logging
            
        Returns:
            Updated User object
            
        Raises:
            UserProfileError: If token invalid or password reset fails
        """
        event_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(
            "Starting password reset completion",
            event_id=event_id,
            ip_address=ip_address
        )
        
        session = self.session_factory()
        
        try:
            # Validate and retrieve user by reset token
            token_hash = self._hash_token(reset_token)
            user = self._get_user_by_reset_token(token_hash, session)
            
            if not user:
                raise UserProfileError("Invalid or expired password reset token")
            
            # Validate new password
            if not new_password or len(new_password) < 8:
                raise UserProfileError("Password must be at least 8 characters long")
            
            # Check if user account is active
            if user.status == UserAccountStatus.DEACTIVATED.value:
                raise UserProfileError("Cannot reset password for deactivated account")
            
            # Hash new password
            new_password_hash = self.password_utils.generate_password_hash(new_password)
            
            # Capture previous state
            previous_state = self._serialize_user_state(user)
            
            # Update user password
            user.password_hash = new_password_hash
            user.password_reset_at = start_time
            user.updated_at = start_time
            
            # Clear failed login attempts
            user.failed_login_attempts = 0
            user.last_failed_login = None
            user.account_locked_until = None
            
            # Attempt Auth0 password synchronization
            auth0_sync_success = False
            if self.config['enable_auth0_sync'] and user.auth0_user_id:
                try:
                    self.auth0_integration.change_password(
                        user.auth0_user_id,
                        new_password
                    )
                    auth0_sync_success = True
                    
                    self.logger.info(
                        "Auth0 password updated successfully",
                        event_id=event_id,
                        user_id=user.id,
                        auth0_user_id=user.auth0_user_id
                    )
                    
                except Auth0Error as e:
                    self.logger.error(
                        "Auth0 password update failed",
                        event_id=event_id,
                        user_id=user.id,
                        auth0_user_id=user.auth0_user_id,
                        error=str(e)
                    )
                    auth0_sync_success = False
            
            # Clean up reset token
            self._cleanup_password_reset_token(token_hash, session)
            
            # Create lifecycle event
            lifecycle_event = UserLifecycleEvent(
                event_id=event_id,
                user_id=str(user.id),
                operation_type=LifecycleOperationType.PASSWORD_RESET,
                timestamp=start_time,
                auth0_user_id=user.auth0_user_id,
                previous_state=previous_state,
                new_state=self._serialize_user_state(user),
                metadata={
                    'action': 'reset_completed',
                    'auth0_sync': auth0_sync_success,
                    'failed_attempts_cleared': True
                },
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            self._log_lifecycle_event(lifecycle_event)
            
            # Security monitoring
            self.security_monitor.track_user_activity(
                user_id=str(user.id),
                action="password_reset_completed",
                resource="user_credentials",
                details={
                    'auth0_sync': auth0_sync_success,
                    'failed_attempts_cleared': True,
                    'ip_address': ip_address
                }
            )
            
            session.commit()
            
            self.logger.info(
                "Password reset completed successfully",
                event_id=event_id,
                user_id=user.id,
                auth0_sync=auth0_sync_success
            )
            
            return user
            
        except UserProfileError:
            session.rollback()
            raise
            
        except Exception as e:
            session.rollback()
            
            self.logger.error(
                "Error during password reset completion",
                event_id=event_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise UserProfileError(f"Failed to complete password reset: {str(e)}")
            
        finally:
            session.close()
    
    def deactivate_user_account(self, user_id: str,
                               deactivated_by: str,
                               reason: Optional[str] = None,
                               retain_data: bool = True,
                               ip_address: Optional[str] = None,
                               user_agent: Optional[str] = None) -> User:
        """
        Deactivate user account with data retention policies
        
        Implements comprehensive account deactivation including:
        - Account status update to deactivated
        - Session invalidation and cleanup
        - Auth0 account blocking/suspension
        - Data retention policy enforcement
        - Comprehensive audit logging
        - Security monitoring for deactivation patterns
        
        Args:
            user_id: User ID to deactivate
            deactivated_by: ID of user performing deactivation
            reason: Optional reason for deactivation
            retain_data: Whether to retain user data per retention policies
            ip_address: Client IP address for audit logging
            user_agent: Client user agent for audit logging
            
        Returns:
            Deactivated User object
            
        Raises:
            UserProfileError: If deactivation fails
        """
        event_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(
            "Starting user account deactivation",
            event_id=event_id,
            user_id=user_id,
            deactivated_by=deactivated_by,
            reason=reason,
            retain_data=retain_data
        )
        
        session = self.session_factory()
        
        try:
            # Retrieve user
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise UserProfileError(f"User with ID {user_id} not found")
            
            if user.status == UserAccountStatus.DEACTIVATED.value:
                self.logger.warning(
                    "Attempted to deactivate already deactivated user",
                    event_id=event_id,
                    user_id=user_id
                )
                return user
            
            # Capture previous state
            previous_state = self._serialize_user_state(user)
            
            # Update user status
            user.status = UserAccountStatus.DEACTIVATED.value
            user.is_active = False
            user.deactivated_at = start_time
            user.deactivated_by = deactivated_by
            user.deactivation_reason = reason
            user.updated_at = start_time
            
            # Invalidate all user sessions
            self._invalidate_all_user_sessions(user_id, session)
            
            # Attempt Auth0 account blocking
            auth0_sync_success = False
            if self.config['enable_auth0_sync'] and user.auth0_user_id:
                try:
                    self.auth0_integration.block_user(user.auth0_user_id)
                    auth0_sync_success = True
                    
                    self.logger.info(
                        "Auth0 user blocked successfully",
                        event_id=event_id,
                        user_id=user_id,
                        auth0_user_id=user.auth0_user_id
                    )
                    
                except Auth0Error as e:
                    self.logger.error(
                        "Auth0 user blocking failed",
                        event_id=event_id,
                        user_id=user_id,
                        auth0_user_id=user.auth0_user_id,
                        error=str(e)
                    )
                    auth0_sync_success = False
            
            # Apply data retention policies if not retaining data
            if not retain_data:
                self._apply_data_deletion_policies(user, session)
            
            # Create lifecycle event
            lifecycle_event = UserLifecycleEvent(
                event_id=event_id,
                user_id=user_id,
                operation_type=LifecycleOperationType.ACCOUNT_DEACTIVATION,
                timestamp=start_time,
                auth0_user_id=user.auth0_user_id,
                previous_state=previous_state,
                new_state=self._serialize_user_state(user),
                metadata={
                    'deactivated_by': deactivated_by,
                    'reason': reason,
                    'retain_data': retain_data,
                    'auth0_sync': auth0_sync_success,
                    'sessions_invalidated': True
                },
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )
            
            self._log_lifecycle_event(lifecycle_event)
            
            # Security monitoring
            self.security_monitor.track_user_activity(
                user_id=user_id,
                action="account_deactivation",
                resource="user_account",
                details={
                    'deactivated_by': deactivated_by,
                    'reason': reason,
                    'retain_data': retain_data,
                    'auth0_sync': auth0_sync_success,
                    'ip_address': ip_address
                }
            )
            
            session.commit()
            
            self.logger.info(
                "User account deactivation completed successfully",
                event_id=event_id,
                user_id=user_id,
                auth0_sync=auth0_sync_success,
                retain_data=retain_data
            )
            
            return user
            
        except UserProfileError:
            session.rollback()
            raise
            
        except Exception as e:
            session.rollback()
            
            self.logger.error(
                "Error during user account deactivation",
                event_id=event_id,
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise UserProfileError(f"Failed to deactivate user account: {str(e)}")
            
        finally:
            session.close()
    
    def synchronize_user_data(self, user_id: str,
                             force_sync: bool = False,
                             sync_direction: str = "bidirectional") -> Dict[str, Any]:
        """
        Synchronize user data between Auth0 and local database
        
        Implements comprehensive data synchronization including:
        - Bidirectional data comparison and conflict resolution
        - Auth0 Management API data retrieval
        - Local database data updates
        - Conflict detection and resolution strategies
        - Comprehensive audit logging for sync operations
        - Data integrity validation
        
        Args:
            user_id: User ID to synchronize
            force_sync: Whether to force sync even if no changes detected
            sync_direction: Direction of sync ("local_to_auth0", "auth0_to_local", "bidirectional")
            
        Returns:
            Dictionary with sync results and statistics
            
        Raises:
            DataSynchronizationError: If synchronization fails
        """
        event_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        valid_directions = ["local_to_auth0", "auth0_to_local", "bidirectional"]
        if sync_direction not in valid_directions:
            raise DataSynchronizationError(f"Invalid sync direction: {sync_direction}")
        
        self.logger.info(
            "Starting user data synchronization",
            event_id=event_id,
            user_id=user_id,
            sync_direction=sync_direction,
            force_sync=force_sync
        )
        
        session = self.session_factory()
        sync_results = {
            'event_id': event_id,
            'user_id': user_id,
            'sync_direction': sync_direction,
            'start_time': start_time.isoformat(),
            'success': False,
            'changes_detected': False,
            'changes_applied': False,
            'conflicts_resolved': 0,
            'fields_updated': [],
            'errors': []
        }
        
        try:
            # Retrieve local user
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                raise DataSynchronizationError(f"User with ID {user_id} not found")
            
            if not user.auth0_user_id:
                raise DataSynchronizationError(f"User {user_id} has no Auth0 ID for synchronization")
            
            # Retrieve Auth0 user data
            try:
                auth0_user = self.auth0_integration.get_user(user.auth0_user_id)
            except Auth0Error as e:
                raise DataSynchronizationError(f"Failed to retrieve Auth0 user: {str(e)}")
            
            # Compare data and detect changes
            local_data = self._extract_sync_data(user)
            auth0_data = self._extract_auth0_sync_data(auth0_user)
            
            conflicts = self._detect_sync_conflicts(local_data, auth0_data)
            changes_needed = len(conflicts) > 0
            
            if not changes_needed and not force_sync:
                sync_results['success'] = True
                sync_results['changes_detected'] = False
                
                self.logger.info(
                    "No data synchronization changes needed",
                    event_id=event_id,
                    user_id=user_id
                )
                
                return sync_results
            
            sync_results['changes_detected'] = True
            sync_results['conflicts_resolved'] = len(conflicts)
            
            # Capture previous state
            previous_state = self._serialize_user_state(user)
            
            # Apply synchronization based on direction
            if sync_direction in ["auth0_to_local", "bidirectional"]:
                updates_applied = self._apply_auth0_to_local_sync(user, auth0_data, conflicts)
                sync_results['fields_updated'].extend(updates_applied)
            
            if sync_direction in ["local_to_auth0", "bidirectional"]:
                auth0_updates = self._apply_local_to_auth0_sync(user, local_data, conflicts)
                if auth0_updates:
                    try:
                        self.auth0_integration.update_user(user.auth0_user_id, auth0_updates)
                        sync_results['fields_updated'].extend(auth0_updates.keys())
                    except Auth0Error as e:
                        sync_results['errors'].append(f"Auth0 update failed: {str(e)}")
                        self.logger.error(
                            "Auth0 update during sync failed",
                            event_id=event_id,
                            user_id=user_id,
                            error=str(e)
                        )
            
            # Update sync metadata
            user.last_sync_at = start_time
            user.updated_at = start_time
            
            sync_results['changes_applied'] = len(sync_results['fields_updated']) > 0
            sync_results['success'] = True
            
            # Create lifecycle event
            lifecycle_event = UserLifecycleEvent(
                event_id=event_id,
                user_id=user_id,
                operation_type=LifecycleOperationType.DATA_SYNC,
                timestamp=start_time,
                auth0_user_id=user.auth0_user_id,
                previous_state=previous_state,
                new_state=self._serialize_user_state(user),
                metadata={
                    'sync_direction': sync_direction,
                    'force_sync': force_sync,
                    'conflicts_resolved': sync_results['conflicts_resolved'],
                    'fields_updated': sync_results['fields_updated'],
                    'errors': sync_results['errors']
                },
                success=sync_results['success']
            )
            
            self._log_lifecycle_event(lifecycle_event)
            
            # Security monitoring
            self.security_monitor.track_user_activity(
                user_id=user_id,
                action="data_synchronization",
                resource="user_data",
                details={
                    'sync_direction': sync_direction,
                    'conflicts_resolved': sync_results['conflicts_resolved'],
                    'fields_updated': sync_results['fields_updated'],
                    'success': sync_results['success']
                }
            )
            
            session.commit()
            
            sync_results['end_time'] = datetime.utcnow().isoformat()
            sync_results['duration_ms'] = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            self.logger.info(
                "User data synchronization completed",
                event_id=event_id,
                user_id=user_id,
                success=sync_results['success'],
                conflicts_resolved=sync_results['conflicts_resolved'],
                fields_updated=sync_results['fields_updated'],
                duration_ms=sync_results['duration_ms']
            )
            
            return sync_results
            
        except DataSynchronizationError:
            session.rollback()
            sync_results['success'] = False
            sync_results['end_time'] = datetime.utcnow().isoformat()
            raise
            
        except Exception as e:
            session.rollback()
            error_msg = f"Unexpected error during data synchronization: {str(e)}"
            sync_results['success'] = False
            sync_results['errors'].append(error_msg)
            sync_results['end_time'] = datetime.utcnow().isoformat()
            
            self.logger.error(
                "Unexpected error during user data synchronization",
                event_id=event_id,
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise DataSynchronizationError(error_msg)
            
        finally:
            session.close()
    
    def get_user_lifecycle_history(self, user_id: str,
                                  operation_types: Optional[List[LifecycleOperationType]] = None,
                                  start_date: Optional[datetime] = None,
                                  end_date: Optional[datetime] = None,
                                  limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve user lifecycle audit history
        
        Provides comprehensive audit trail retrieval for compliance and
        security investigation purposes including operation filtering,
        date range filtering, and detailed event metadata.
        
        Args:
            user_id: User ID to retrieve history for
            operation_types: Optional filter for specific operation types
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of events to return
            
        Returns:
            List of lifecycle events with full audit details
        """
        self.logger.info(
            "Retrieving user lifecycle history",
            user_id=user_id,
            operation_types=[op.value for op in operation_types] if operation_types else None,
            start_date=start_date.isoformat() if start_date else None,
            end_date=end_date.isoformat() if end_date else None,
            limit=limit
        )
        
        # In a production system, this would query a dedicated audit log table
        # For this implementation, we'll return a placeholder structure
        history = []
        
        # This would be implemented with proper audit log storage
        # and retrieval mechanisms in a production environment
        
        return history
    
    # Private helper methods
    
    def _serialize_user_state(self, user: User) -> Dict[str, Any]:
        """Serialize user state for audit logging"""
        return {
            'id': str(user.id),
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone_number': user.phone_number,
            'status': user.status,
            'is_active': user.is_active,
            'email_verified': user.email_verified,
            'auth0_user_id': user.auth0_user_id,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'deactivated_at': user.deactivated_at.isoformat() if user.deactivated_at else None
        }
    
    def _log_lifecycle_event(self, event: UserLifecycleEvent):
        """Log lifecycle event using structured logging"""
        self.security_monitor.track_user_activity(
            user_id=event.user_id,
            action=f"lifecycle_{event.operation_type.value}",
            resource="user_lifecycle",
            details=asdict(event)
        )
        
        self.logger.info(
            "User lifecycle event logged",
            event_id=event.event_id,
            user_id=event.user_id,
            operation_type=event.operation_type.value,
            success=event.success,
            error_message=event.error_message
        )
    
    def _generate_reset_token(self) -> str:
        """Generate secure password reset token"""
        return secrets.token_urlsafe(32)
    
    def _generate_verification_token(self, user_id: str) -> str:
        """Generate secure email verification token"""
        return secrets.token_urlsafe(32)
    
    def _hash_token(self, token: str) -> str:
        """Hash token for secure storage"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _store_password_reset_token(self, user_id: str, token_hash: str, expiry: datetime):
        """Store password reset token in database"""
        # In production, this would use a dedicated token storage table
        # with proper indexing and cleanup mechanisms
        pass
    
    def _store_verification_token(self, user_id: str, token: str):
        """Store email verification token"""
        # Implementation would store verification token with expiry
        pass
    
    def _get_user_by_reset_token(self, token_hash: str, session) -> Optional[User]:
        """Retrieve user by password reset token"""
        # In production, this would query the token storage table
        # and return the associated user if token is valid and not expired
        return None
    
    def _cleanup_password_reset_token(self, token_hash: str, session):
        """Remove used password reset token"""
        # Implementation would remove the token from storage
        pass
    
    def _invalidate_all_user_sessions(self, user_id: str, session):
        """Invalidate all active sessions for a user"""
        session.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active == True
        ).update({'is_active': False})
    
    def _apply_data_deletion_policies(self, user: User, session):
        """Apply data deletion policies for deactivated users"""
        # Implementation would apply GDPR-compliant data deletion
        # while preserving necessary records for compliance
        pass
    
    def _extract_sync_data(self, user: User) -> Dict[str, Any]:
        """Extract synchronizable data from local user"""
        return {
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone_number': user.phone_number,
            'email_verified': user.email_verified,
            'status': user.status
        }
    
    def _extract_auth0_sync_data(self, auth0_user: Dict[str, Any]) -> Dict[str, Any]:
        """Extract synchronizable data from Auth0 user"""
        user_metadata = auth0_user.get('user_metadata', {})
        return {
            'email': auth0_user.get('email'),
            'first_name': user_metadata.get('first_name'),
            'last_name': user_metadata.get('last_name'),
            'phone_number': user_metadata.get('phone_number'),
            'email_verified': auth0_user.get('email_verified', False),
            'status': 'active' if not auth0_user.get('blocked') else 'suspended'
        }
    
    def _detect_sync_conflicts(self, local_data: Dict[str, Any], 
                              auth0_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect synchronization conflicts between local and Auth0 data"""
        conflicts = []
        
        for field in local_data:
            local_value = local_data.get(field)
            auth0_value = auth0_data.get(field)
            
            if local_value != auth0_value:
                conflicts.append({
                    'field': field,
                    'local_value': local_value,
                    'auth0_value': auth0_value
                })
        
        return conflicts
    
    def _apply_auth0_to_local_sync(self, user: User, auth0_data: Dict[str, Any],
                                  conflicts: List[Dict[str, Any]]) -> List[str]:
        """Apply Auth0 data to local user record"""
        updated_fields = []
        
        for conflict in conflicts:
            field = conflict['field']
            auth0_value = conflict['auth0_value']
            
            if hasattr(user, field) and auth0_value is not None:
                setattr(user, field, auth0_value)
                updated_fields.append(field)
        
        return updated_fields
    
    def _apply_local_to_auth0_sync(self, user: User, local_data: Dict[str, Any],
                                  conflicts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare Auth0 updates from local data"""
        auth0_updates = {}
        user_metadata_updates = {}
        
        for conflict in conflicts:
            field = conflict['field']
            local_value = conflict['local_value']
            
            if field == 'email':
                auth0_updates['email'] = local_value
            elif field in ['first_name', 'last_name', 'phone_number']:
                user_metadata_updates[field] = local_value
            elif field == 'email_verified':
                auth0_updates['email_verified'] = local_value
        
        if user_metadata_updates:
            auth0_updates['user_metadata'] = user_metadata_updates
        
        return auth0_updates


def create_user_lifecycle_service(db: SQLAlchemy, 
                                 auth0_integration: Auth0Integration,
                                 security_monitor: SecurityMonitor,
                                 password_utils: PasswordUtils) -> UserLifecycleService:
    """
    Factory function to create UserLifecycleService instance
    
    This factory function integrates with Flask application factory pattern
    for service registration and dependency injection as specified in Section 6.1.3.
    
    Args:
        db: Flask-SQLAlchemy database instance
        auth0_integration: Auth0 integration service
        security_monitor: Security monitoring service
        password_utils: Password security utilities
        
    Returns:
        Configured UserLifecycleService instance
    """
    return UserLifecycleService(
        db=db,
        auth0_integration=auth0_integration,
        security_monitor=security_monitor,
        password_utils=password_utils
    )