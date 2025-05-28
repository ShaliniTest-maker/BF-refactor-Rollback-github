"""
User Service Implementation

This module implements the Service Layer pattern for comprehensive user management
workflows including registration, authentication, profile management, and user entity
operations. Maintains functional equivalence with original Node.js business rules
while leveraging Flask ecosystem capabilities.

Key Features:
- User registration and authentication business logic preservation (Feature F-005)
- Service Layer pattern implementation for workflow orchestration (Feature F-006)
- Flask-Login integration for session management (Feature F-007)
- User entity relationship mapping for complex business workflows (Section 6.2.2.1)
- Python 3.13.3 business logic implementation with functional equivalence (Section 5.2.3)

Architecture:
- Inherits from BaseService for transaction boundary management
- Integrates with Flask-SQLAlchemy for data persistence
- Utilizes authentication utilities for security operations
- Implements comprehensive error handling and validation
- Supports dependency injection patterns for clean separation

Dependencies:
- Flask-SQLAlchemy models: User, UserSession, BusinessEntity, EntityRelationship
- Authentication utilities: session_manager, password_utils
- Common utilities: validation, error_handling, logging
- Base service class for consistent service patterns
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from flask import current_app, request
from flask_login import login_user, logout_user, current_user
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import joinedload
from werkzeug.security import generate_password_hash, check_password_hash

# Import base service for transaction management and service patterns
from .base import BaseService

# Import database models for user operations
from ..models.user import User
from ..models.session import UserSession
from ..models.business_entity import BusinessEntity
from ..models.entity_relationship import EntityRelationship

# Import authentication utilities for security operations
from ..auth.session_manager import SessionManager
from ..auth.password_utils import PasswordUtils
from ..auth.security_monitor import SecurityMonitor

# Import common utilities for cross-cutting concerns
from ..utils.validation import ValidationUtils
from ..utils.error_handling import (
    UserServiceError, ValidationError, AuthenticationError,
    UserNotFoundError, DuplicateUserError, SessionError
)
from ..utils.logging import StructuredLogger
from ..utils.datetime import DateTimeUtils


class UserStatus(Enum):
    """User account status enumeration for business logic control."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    LOCKED = "locked"


class RegistrationStatus(Enum):
    """User registration workflow status tracking."""
    SUCCESS = "success"
    EMAIL_EXISTS = "email_exists"
    USERNAME_EXISTS = "username_exists"
    VALIDATION_FAILED = "validation_failed"
    SYSTEM_ERROR = "system_error"


@dataclass
class UserRegistrationData:
    """Data transfer object for user registration operations."""
    username: str
    email: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    profile_data: Optional[Dict[str, Any]] = None


@dataclass
class UserAuthenticationData:
    """Data transfer object for user authentication operations."""
    identifier: str  # username or email
    password: str
    remember_me: bool = False
    device_info: Optional[Dict[str, Any]] = None


@dataclass
class UserProfileData:
    """Data transfer object for user profile update operations."""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    profile_data: Optional[Dict[str, Any]] = None
    status: Optional[UserStatus] = None


@dataclass
class UserServiceResult:
    """Standardized service operation result with comprehensive metadata."""
    success: bool
    data: Optional[Any] = None
    message: Optional[str] = None
    error_code: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class UserService(BaseService):
    """
    Comprehensive user management service implementing Service Layer pattern.
    
    This service orchestrates complex user-related business processes through
    systematic workflow management while maintaining functional equivalence
    with original Node.js user business rules. Provides clean abstraction
    for user operations across multiple Flask blueprints.
    
    Key Responsibilities:
    - User lifecycle management (registration, activation, deactivation)
    - Authentication and session management with Flask-Login integration
    - Profile management and user data operations
    - User entity relationship coordination
    - Business rule enforcement and validation
    - Security monitoring and audit trail generation
    """
    
    def __init__(self, 
                 session_manager: Optional[SessionManager] = None,
                 password_utils: Optional[PasswordUtils] = None,
                 security_monitor: Optional[SecurityMonitor] = None):
        """
        Initialize user service with dependency injection support.
        
        Args:
            session_manager: Flask-Login session management utility
            password_utils: Password security and validation utility
            security_monitor: Security event monitoring utility
        """
        super().__init__()
        
        # Initialize service dependencies with proper injection support
        self.session_manager = session_manager or SessionManager()
        self.password_utils = password_utils or PasswordUtils()
        self.security_monitor = security_monitor or SecurityMonitor()
        
        # Initialize validation and utility components
        self.validation_utils = ValidationUtils()
        self.logger = StructuredLogger(__name__)
        self.datetime_utils = DateTimeUtils()
        
        # Business logic configuration from Flask application
        self.config = {
            'password_min_length': current_app.config.get('PASSWORD_MIN_LENGTH', 8),
            'session_timeout_hours': current_app.config.get('SESSION_TIMEOUT_HOURS', 24),
            'max_login_attempts': current_app.config.get('MAX_LOGIN_ATTEMPTS', 5),
            'account_lockout_duration': current_app.config.get('ACCOUNT_LOCKOUT_DURATION', 30),
            'enable_remember_me': current_app.config.get('ENABLE_REMEMBER_ME', True),
            'audit_user_operations': current_app.config.get('AUDIT_USER_OPERATIONS', True)
        }

    # =============================================================================
    # User Registration and Lifecycle Management
    # =============================================================================
    
    def register_user(self, registration_data: UserRegistrationData) -> UserServiceResult:
        """
        Register new user with comprehensive validation and business logic.
        
        Implements complete user registration workflow including:
        - Input validation and sanitization
        - Duplicate user checking (email and username)
        - Password security validation and hashing
        - User account creation with proper status management
        - Initial session creation for authenticated user experience
        - Security event logging and audit trail generation
        
        Args:
            registration_data: User registration information with validation
            
        Returns:
            UserServiceResult: Registration outcome with user data or error details
            
        Raises:
            ValidationError: Invalid input data or business rule violations
            DuplicateUserError: Email or username already exists
            UserServiceError: System-level registration failures
        """
        try:
            self.logger.info("Starting user registration workflow", extra={
                'username': registration_data.username,
                'email': registration_data.email,
                'operation': 'user_registration'
            })
            
            # Phase 1: Comprehensive input validation
            validation_result = self._validate_registration_data(registration_data)
            if not validation_result.success:
                return UserServiceResult(
                    success=False,
                    message=validation_result.message,
                    error_code="VALIDATION_FAILED",
                    metadata={'validation_errors': validation_result.metadata}
                )
            
            # Phase 2: Business rule enforcement - duplicate checking
            duplicate_check = self._check_user_duplicates(
                registration_data.email, 
                registration_data.username
            )
            if not duplicate_check.success:
                return duplicate_check
            
            # Phase 3: Password security processing
            password_hash = self.password_utils.hash_password(
                registration_data.password,
                salt_length=16
            )
            
            # Phase 4: Database transaction for user creation
            with self.get_transaction() as transaction:
                try:
                    # Create user entity with comprehensive field mapping
                    new_user = User(
                        username=registration_data.username.lower().strip(),
                        email=registration_data.email.lower().strip(),
                        password_hash=password_hash,
                        first_name=registration_data.first_name,
                        last_name=registration_data.last_name,
                        status=UserStatus.ACTIVE.value,
                        is_active=True,
                        created_at=self.datetime_utils.utc_now(),
                        updated_at=self.datetime_utils.utc_now(),
                        profile_data=registration_data.profile_data or {}
                    )
                    
                    # Add to session and flush for ID generation
                    self.db.session.add(new_user)
                    self.db.session.flush()
                    
                    # Create initial user session for immediate authentication
                    initial_session = self._create_user_session(
                        new_user,
                        device_info=getattr(registration_data, 'device_info', None)
                    )
                    
                    # Commit transaction for consistency
                    transaction.commit()
                    
                    # Security monitoring and audit logging
                    self.security_monitor.log_user_registration(new_user.id, {
                        'username': new_user.username,
                        'email': new_user.email,
                        'registration_timestamp': new_user.created_at.isoformat(),
                        'initial_session_id': initial_session.id if initial_session else None
                    })
                    
                    self.logger.info("User registration completed successfully", extra={
                        'user_id': new_user.id,
                        'username': new_user.username,
                        'operation': 'user_registration_success'
                    })
                    
                    return UserServiceResult(
                        success=True,
                        data=self._serialize_user_data(new_user),
                        message="User registered successfully",
                        metadata={
                            'user_id': new_user.id,
                            'session_created': initial_session is not None,
                            'registration_timestamp': new_user.created_at.isoformat()
                        }
                    )
                    
                except IntegrityError as e:
                    transaction.rollback()
                    self.logger.error("Database integrity error during registration", 
                                    extra={'error': str(e), 'operation': 'user_registration_error'})
                    
                    # Determine specific constraint violation
                    if 'username' in str(e):
                        return UserServiceResult(
                            success=False,
                            message="Username already exists",
                            error_code="USERNAME_EXISTS"
                        )
                    elif 'email' in str(e):
                        return UserServiceResult(
                            success=False,
                            message="Email already exists",
                            error_code="EMAIL_EXISTS"
                        )
                    else:
                        raise UserServiceError("Database constraint violation during registration")
                        
        except Exception as e:
            self.logger.error("Unexpected error during user registration", 
                            extra={'error': str(e), 'operation': 'user_registration_error'})
            raise UserServiceError(f"Registration failed: {str(e)}")
    
    def activate_user(self, user_id: int, activation_token: Optional[str] = None) -> UserServiceResult:
        """
        Activate user account with optional token validation.
        
        Args:
            user_id: Target user identifier
            activation_token: Optional activation token for verification
            
        Returns:
            UserServiceResult: Activation outcome with updated user data
        """
        try:
            with self.get_transaction() as transaction:
                user = self._get_user_by_id(user_id)
                if not user:
                    return UserServiceResult(
                        success=False,
                        message="User not found",
                        error_code="USER_NOT_FOUND"
                    )
                
                # Validate activation token if provided
                if activation_token:
                    if not self._validate_activation_token(user, activation_token):
                        return UserServiceResult(
                            success=False,
                            message="Invalid activation token",
                            error_code="INVALID_TOKEN"
                        )
                
                # Update user status to active
                user.status = UserStatus.ACTIVE.value
                user.is_active = True
                user.updated_at = self.datetime_utils.utc_now()
                
                transaction.commit()
                
                self.security_monitor.log_user_activation(user.id)
                
                return UserServiceResult(
                    success=True,
                    data=self._serialize_user_data(user),
                    message="User activated successfully"
                )
                
        except Exception as e:
            self.logger.error("Error during user activation", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"User activation failed: {str(e)}")
    
    def deactivate_user(self, user_id: int, reason: Optional[str] = None) -> UserServiceResult:
        """
        Deactivate user account and invalidate all sessions.
        
        Args:
            user_id: Target user identifier
            reason: Optional deactivation reason for audit purposes
            
        Returns:
            UserServiceResult: Deactivation outcome
        """
        try:
            with self.get_transaction() as transaction:
                user = self._get_user_by_id(user_id)
                if not user:
                    return UserServiceResult(
                        success=False,
                        message="User not found",
                        error_code="USER_NOT_FOUND"
                    )
                
                # Update user status to inactive
                user.status = UserStatus.INACTIVE.value
                user.is_active = False
                user.updated_at = self.datetime_utils.utc_now()
                
                # Invalidate all active user sessions
                self._invalidate_all_user_sessions(user_id)
                
                transaction.commit()
                
                self.security_monitor.log_user_deactivation(user.id, reason)
                
                return UserServiceResult(
                    success=True,
                    message="User deactivated successfully",
                    metadata={'reason': reason}
                )
                
        except Exception as e:
            self.logger.error("Error during user deactivation", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"User deactivation failed: {str(e)}")

    # =============================================================================
    # Authentication and Session Management
    # =============================================================================
    
    def authenticate_user(self, auth_data: UserAuthenticationData) -> UserServiceResult:
        """
        Authenticate user with comprehensive security checks and session management.
        
        Implements complete authentication workflow including:
        - User identification by username or email
        - Password validation with security monitoring
        - Account lockout protection and attempt tracking
        - Flask-Login session creation and management
        - Security event logging and audit trail generation
        
        Args:
            auth_data: Authentication credentials and options
            
        Returns:
            UserServiceResult: Authentication outcome with session data
            
        Raises:
            AuthenticationError: Invalid credentials or account issues
            UserServiceError: System-level authentication failures
        """
        try:
            self.logger.info("Starting user authentication workflow", extra={
                'identifier': auth_data.identifier,
                'remember_me': auth_data.remember_me,
                'operation': 'user_authentication'
            })
            
            # Phase 1: User identification and retrieval
            user = self._get_user_by_identifier(auth_data.identifier)
            if not user:
                # Security: Log failed authentication attempt
                self.security_monitor.log_authentication_failure(
                    auth_data.identifier, 
                    "user_not_found"
                )
                return UserServiceResult(
                    success=False,
                    message="Invalid credentials",
                    error_code="AUTHENTICATION_FAILED"
                )
            
            # Phase 2: Account status validation
            account_check = self._validate_account_status(user)
            if not account_check.success:
                return account_check
            
            # Phase 3: Password verification with security monitoring
            if not self.password_utils.verify_password(
                auth_data.password, 
                user.password_hash
            ):
                # Handle failed authentication attempt
                self._handle_failed_authentication(user, auth_data.identifier)
                return UserServiceResult(
                    success=False,
                    message="Invalid credentials",
                    error_code="AUTHENTICATION_FAILED"
                )
            
            # Phase 4: Successful authentication processing
            with self.get_transaction() as transaction:
                # Reset failed login attempts on successful authentication
                user.failed_login_attempts = 0
                user.last_login_at = self.datetime_utils.utc_now()
                user.updated_at = self.datetime_utils.utc_now()
                
                # Create new user session
                user_session = self._create_user_session(
                    user, 
                    device_info=auth_data.device_info
                )
                
                # Flask-Login integration for session management
                login_success = login_user(
                    user, 
                    remember=auth_data.remember_me and self.config['enable_remember_me']
                )
                
                if not login_success:
                    transaction.rollback()
                    raise AuthenticationError("Flask-Login session creation failed")
                
                transaction.commit()
                
                # Security monitoring and audit logging
                self.security_monitor.log_successful_authentication(user.id, {
                    'session_id': user_session.id if user_session else None,
                    'remember_me': auth_data.remember_me,
                    'device_info': auth_data.device_info,
                    'authentication_timestamp': user.last_login_at.isoformat()
                })
                
                self.logger.info("User authentication completed successfully", extra={
                    'user_id': user.id,
                    'username': user.username,
                    'session_id': user_session.id if user_session else None,
                    'operation': 'user_authentication_success'
                })
                
                return UserServiceResult(
                    success=True,
                    data=self._serialize_user_data(user),
                    message="Authentication successful",
                    metadata={
                        'session_id': user_session.id if user_session else None,
                        'remember_me': auth_data.remember_me,
                        'last_login': user.last_login_at.isoformat()
                    }
                )
                
        except Exception as e:
            self.logger.error("Unexpected error during user authentication", 
                            extra={'error': str(e), 'operation': 'user_authentication_error'})
            raise UserServiceError(f"Authentication failed: {str(e)}")
    
    def logout_user(self, user_id: Optional[int] = None) -> UserServiceResult:
        """
        Logout user and invalidate current session.
        
        Args:
            user_id: Optional user ID, defaults to current authenticated user
            
        Returns:
            UserServiceResult: Logout outcome
        """
        try:
            # Determine target user for logout
            target_user_id = user_id or (current_user.id if current_user.is_authenticated else None)
            
            if not target_user_id:
                return UserServiceResult(
                    success=False,
                    message="No user session to logout",
                    error_code="NO_ACTIVE_SESSION"
                )
            
            # Invalidate current user session
            if hasattr(current_user, 'id') and current_user.id == target_user_id:
                self._invalidate_current_session()
            
            # Flask-Login logout
            logout_user()
            
            self.security_monitor.log_user_logout(target_user_id)
            
            return UserServiceResult(
                success=True,
                message="Logout successful"
            )
            
        except Exception as e:
            self.logger.error("Error during user logout", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Logout failed: {str(e)}")

    # =============================================================================
    # Profile Management and User Data Operations
    # =============================================================================
    
    def get_user_profile(self, user_id: int) -> UserServiceResult:
        """
        Retrieve comprehensive user profile with related data.
        
        Args:
            user_id: Target user identifier
            
        Returns:
            UserServiceResult: User profile data with relationships
        """
        try:
            user = self._get_user_by_id_with_relationships(user_id)
            if not user:
                return UserServiceResult(
                    success=False,
                    message="User not found",
                    error_code="USER_NOT_FOUND"
                )
            
            profile_data = self._serialize_user_profile(user)
            
            return UserServiceResult(
                success=True,
                data=profile_data,
                message="Profile retrieved successfully"
            )
            
        except Exception as e:
            self.logger.error("Error retrieving user profile", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Profile retrieval failed: {str(e)}")
    
    def update_user_profile(self, user_id: int, profile_data: UserProfileData) -> UserServiceResult:
        """
        Update user profile with validation and business logic.
        
        Args:
            user_id: Target user identifier
            profile_data: Profile update information
            
        Returns:
            UserServiceResult: Update outcome with refreshed profile data
        """
        try:
            with self.get_transaction() as transaction:
                user = self._get_user_by_id(user_id)
                if not user:
                    return UserServiceResult(
                        success=False,
                        message="User not found",
                        error_code="USER_NOT_FOUND"
                    )
                
                # Validate profile update data
                validation_result = self._validate_profile_update(profile_data, user)
                if not validation_result.success:
                    return validation_result
                
                # Apply profile updates
                if profile_data.first_name is not None:
                    user.first_name = profile_data.first_name.strip()
                
                if profile_data.last_name is not None:
                    user.last_name = profile_data.last_name.strip()
                
                if profile_data.email is not None:
                    # Check for email duplicates
                    if self._email_exists(profile_data.email, exclude_user_id=user_id):
                        return UserServiceResult(
                            success=False,
                            message="Email already exists",
                            error_code="EMAIL_EXISTS"
                        )
                    user.email = profile_data.email.lower().strip()
                
                if profile_data.profile_data is not None:
                    user.profile_data = {**(user.profile_data or {}), **profile_data.profile_data}
                
                if profile_data.status is not None:
                    user.status = profile_data.status.value
                
                user.updated_at = self.datetime_utils.utc_now()
                
                transaction.commit()
                
                self.security_monitor.log_profile_update(user.id, {
                    'updated_fields': [k for k, v in profile_data.__dict__.items() if v is not None],
                    'update_timestamp': user.updated_at.isoformat()
                })
                
                return UserServiceResult(
                    success=True,
                    data=self._serialize_user_data(user),
                    message="Profile updated successfully"
                )
                
        except Exception as e:
            self.logger.error("Error updating user profile", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Profile update failed: {str(e)}")
    
    def change_user_password(self, user_id: int, current_password: str, new_password: str) -> UserServiceResult:
        """
        Change user password with validation and security checks.
        
        Args:
            user_id: Target user identifier
            current_password: Current password for verification
            new_password: New password to set
            
        Returns:
            UserServiceResult: Password change outcome
        """
        try:
            with self.get_transaction() as transaction:
                user = self._get_user_by_id(user_id)
                if not user:
                    return UserServiceResult(
                        success=False,
                        message="User not found",
                        error_code="USER_NOT_FOUND"
                    )
                
                # Verify current password
                if not self.password_utils.verify_password(current_password, user.password_hash):
                    self.security_monitor.log_password_change_failure(user.id, "invalid_current_password")
                    return UserServiceResult(
                        success=False,
                        message="Current password is incorrect",
                        error_code="INVALID_PASSWORD"
                    )
                
                # Validate new password
                password_validation = self.password_utils.validate_password_strength(new_password)
                if not password_validation.is_valid:
                    return UserServiceResult(
                        success=False,
                        message="New password does not meet requirements",
                        error_code="WEAK_PASSWORD",
                        metadata={'requirements': password_validation.requirements}
                    )
                
                # Update password hash
                user.password_hash = self.password_utils.hash_password(new_password)
                user.updated_at = self.datetime_utils.utc_now()
                
                # Invalidate all existing sessions except current
                self._invalidate_other_user_sessions(user_id)
                
                transaction.commit()
                
                self.security_monitor.log_password_change_success(user.id)
                
                return UserServiceResult(
                    success=True,
                    message="Password changed successfully"
                )
                
        except Exception as e:
            self.logger.error("Error changing user password", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Password change failed: {str(e)}")

    # =============================================================================
    # User Entity Relationship Management
    # =============================================================================
    
    def get_user_business_entities(self, user_id: int, include_relationships: bool = True) -> UserServiceResult:
        """
        Retrieve all business entities owned by user with optional relationships.
        
        Args:
            user_id: Target user identifier
            include_relationships: Whether to include entity relationships
            
        Returns:
            UserServiceResult: Business entities data with relationships
        """
        try:
            user = self._get_user_by_id(user_id)
            if not user:
                return UserServiceResult(
                    success=False,
                    message="User not found",
                    error_code="USER_NOT_FOUND"
                )
            
            # Build query with optional relationship loading
            query = self.db.session.query(BusinessEntity).filter_by(owner_id=user_id)
            
            if include_relationships:
                query = query.options(
                    joinedload(BusinessEntity.source_relationships),
                    joinedload(BusinessEntity.target_relationships)
                )
            
            entities = query.all()
            
            # Serialize entities with relationships
            entities_data = [
                self._serialize_business_entity(entity, include_relationships)
                for entity in entities
            ]
            
            return UserServiceResult(
                success=True,
                data=entities_data,
                message="Business entities retrieved successfully",
                metadata={'entity_count': len(entities)}
            )
            
        except Exception as e:
            self.logger.error("Error retrieving user business entities", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Business entities retrieval failed: {str(e)}")
    
    def create_business_entity(self, user_id: int, entity_data: Dict[str, Any]) -> UserServiceResult:
        """
        Create new business entity for user with validation.
        
        Args:
            user_id: Owner user identifier
            entity_data: Business entity information
            
        Returns:
            UserServiceResult: Created entity data
        """
        try:
            with self.get_transaction() as transaction:
                user = self._get_user_by_id(user_id)
                if not user:
                    return UserServiceResult(
                        success=False,
                        message="User not found",
                        error_code="USER_NOT_FOUND"
                    )
                
                # Validate entity data
                validation_result = self._validate_business_entity_data(entity_data)
                if not validation_result.success:
                    return validation_result
                
                # Create business entity
                new_entity = BusinessEntity(
                    name=entity_data['name'].strip(),
                    description=entity_data.get('description', '').strip(),
                    owner_id=user_id,
                    status=entity_data.get('status', 'active'),
                    created_at=self.datetime_utils.utc_now(),
                    updated_at=self.datetime_utils.utc_now()
                )
                
                self.db.session.add(new_entity)
                self.db.session.flush()
                
                transaction.commit()
                
                self.logger.info("Business entity created successfully", extra={
                    'entity_id': new_entity.id,
                    'user_id': user_id,
                    'operation': 'create_business_entity'
                })
                
                return UserServiceResult(
                    success=True,
                    data=self._serialize_business_entity(new_entity),
                    message="Business entity created successfully"
                )
                
        except Exception as e:
            self.logger.error("Error creating business entity", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Business entity creation failed: {str(e)}")

    # =============================================================================
    # Session Management Utilities
    # =============================================================================
    
    def get_user_sessions(self, user_id: int, active_only: bool = True) -> UserServiceResult:
        """
        Retrieve user sessions with filtering options.
        
        Args:
            user_id: Target user identifier
            active_only: Whether to return only active sessions
            
        Returns:
            UserServiceResult: User sessions data
        """
        try:
            query = self.db.session.query(UserSession).filter_by(user_id=user_id)
            
            if active_only:
                query = query.filter_by(is_valid=True).filter(
                    UserSession.expires_at > self.datetime_utils.utc_now()
                )
            
            sessions = query.order_by(UserSession.created_at.desc()).all()
            
            sessions_data = [self._serialize_user_session(session) for session in sessions]
            
            return UserServiceResult(
                success=True,
                data=sessions_data,
                message="User sessions retrieved successfully",
                metadata={'session_count': len(sessions)}
            )
            
        except Exception as e:
            self.logger.error("Error retrieving user sessions", 
                            extra={'error': str(e), 'user_id': user_id})
            raise UserServiceError(f"Sessions retrieval failed: {str(e)}")
    
    def invalidate_user_session(self, user_id: int, session_id: int) -> UserServiceResult:
        """
        Invalidate specific user session.
        
        Args:
            user_id: User identifier for security validation
            session_id: Target session identifier
            
        Returns:
            UserServiceResult: Session invalidation outcome
        """
        try:
            with self.get_transaction() as transaction:
                session = self.db.session.query(UserSession).filter_by(
                    id=session_id,
                    user_id=user_id
                ).first()
                
                if not session:
                    return UserServiceResult(
                        success=False,
                        message="Session not found",
                        error_code="SESSION_NOT_FOUND"
                    )
                
                session.is_valid = False
                session.updated_at = self.datetime_utils.utc_now()
                
                transaction.commit()
                
                self.security_monitor.log_session_invalidation(user_id, session_id)
                
                return UserServiceResult(
                    success=True,
                    message="Session invalidated successfully"
                )
                
        except Exception as e:
            self.logger.error("Error invalidating user session", 
                            extra={'error': str(e), 'user_id': user_id, 'session_id': session_id})
            raise UserServiceError(f"Session invalidation failed: {str(e)}")

    # =============================================================================
    # Private Helper Methods - Validation and Business Logic
    # =============================================================================
    
    def _validate_registration_data(self, data: UserRegistrationData) -> UserServiceResult:
        """Validate user registration data with comprehensive checks."""
        errors = []
        
        # Username validation
        if not data.username or len(data.username.strip()) < 3:
            errors.append("Username must be at least 3 characters long")
        elif not self.validation_utils.is_valid_username(data.username):
            errors.append("Username contains invalid characters")
        
        # Email validation
        if not data.email or not self.validation_utils.is_valid_email(data.email):
            errors.append("Valid email address is required")
        
        # Password validation
        password_validation = self.password_utils.validate_password_strength(data.password)
        if not password_validation.is_valid:
            errors.extend(password_validation.errors)
        
        if errors:
            return UserServiceResult(
                success=False,
                message="Validation failed",
                error_code="VALIDATION_FAILED",
                metadata={'validation_errors': errors}
            )
        
        return UserServiceResult(success=True)
    
    def _check_user_duplicates(self, email: str, username: str) -> UserServiceResult:
        """Check for existing users with same email or username."""
        # Check email duplicates
        if self._email_exists(email):
            return UserServiceResult(
                success=False,
                message="Email already exists",
                error_code="EMAIL_EXISTS"
            )
        
        # Check username duplicates
        if self._username_exists(username):
            return UserServiceResult(
                success=False,
                message="Username already exists",
                error_code="USERNAME_EXISTS"
            )
        
        return UserServiceResult(success=True)
    
    def _validate_account_status(self, user: User) -> UserServiceResult:
        """Validate user account status for authentication."""
        if not user.is_active:
            return UserServiceResult(
                success=False,
                message="Account is inactive",
                error_code="ACCOUNT_INACTIVE"
            )
        
        if user.status == UserStatus.SUSPENDED.value:
            return UserServiceResult(
                success=False,
                message="Account is suspended",
                error_code="ACCOUNT_SUSPENDED"
            )
        
        if user.status == UserStatus.LOCKED.value:
            return UserServiceResult(
                success=False,
                message="Account is locked",
                error_code="ACCOUNT_LOCKED"
            )
        
        return UserServiceResult(success=True)
    
    def _handle_failed_authentication(self, user: User, identifier: str) -> None:
        """Handle failed authentication attempt with security measures."""
        try:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.updated_at = self.datetime_utils.utc_now()
            
            # Check for account lockout threshold
            if user.failed_login_attempts >= self.config['max_login_attempts']:
                user.status = UserStatus.LOCKED.value
                lockout_duration = timedelta(minutes=self.config['account_lockout_duration'])
                user.locked_until = self.datetime_utils.utc_now() + lockout_duration
                
                self.security_monitor.log_account_lockout(user.id, {
                    'failed_attempts': user.failed_login_attempts,
                    'lockout_duration': self.config['account_lockout_duration']
                })
            
            self.db.session.commit()
            
            # Log security event
            self.security_monitor.log_authentication_failure(identifier, "invalid_password", {
                'user_id': user.id,
                'failed_attempts': user.failed_login_attempts,
                'account_locked': user.status == UserStatus.LOCKED.value
            })
            
        except Exception as e:
            self.logger.error("Error handling failed authentication", 
                            extra={'error': str(e), 'user_id': user.id})

    # =============================================================================
    # Private Helper Methods - Database Operations
    # =============================================================================
    
    def _get_user_by_id(self, user_id: int) -> Optional[User]:
        """Retrieve user by ID with basic loading."""
        return self.db.session.query(User).filter_by(id=user_id).first()
    
    def _get_user_by_id_with_relationships(self, user_id: int) -> Optional[User]:
        """Retrieve user by ID with relationship loading."""
        return self.db.session.query(User).options(
            joinedload(User.sessions),
            joinedload(User.business_entities)
        ).filter_by(id=user_id).first()
    
    def _get_user_by_identifier(self, identifier: str) -> Optional[User]:
        """Retrieve user by username or email."""
        return self.db.session.query(User).filter(
            (User.username == identifier.lower()) | 
            (User.email == identifier.lower())
        ).first()
    
    def _email_exists(self, email: str, exclude_user_id: Optional[int] = None) -> bool:
        """Check if email already exists in database."""
        query = self.db.session.query(User).filter_by(email=email.lower())
        if exclude_user_id:
            query = query.filter(User.id != exclude_user_id)
        return query.first() is not None
    
    def _username_exists(self, username: str, exclude_user_id: Optional[int] = None) -> bool:
        """Check if username already exists in database."""
        query = self.db.session.query(User).filter_by(username=username.lower())
        if exclude_user_id:
            query = query.filter(User.id != exclude_user_id)
        return query.first() is not None
    
    def _create_user_session(self, user: User, device_info: Optional[Dict[str, Any]] = None) -> Optional[UserSession]:
        """Create new user session with proper expiration."""
        try:
            session_token = self.session_manager.generate_session_token()
            expires_at = self.datetime_utils.utc_now() + timedelta(
                hours=self.config['session_timeout_hours']
            )
            
            user_session = UserSession(
                user_id=user.id,
                session_token=session_token,
                expires_at=expires_at,
                is_valid=True,
                device_info=device_info or {},
                created_at=self.datetime_utils.utc_now()
            )
            
            self.db.session.add(user_session)
            self.db.session.flush()
            
            return user_session
            
        except Exception as e:
            self.logger.error("Error creating user session", 
                            extra={'error': str(e), 'user_id': user.id})
            return None
    
    def _invalidate_all_user_sessions(self, user_id: int) -> None:
        """Invalidate all sessions for a user."""
        self.db.session.query(UserSession).filter_by(
            user_id=user_id,
            is_valid=True
        ).update({
            'is_valid': False,
            'updated_at': self.datetime_utils.utc_now()
        })
    
    def _invalidate_other_user_sessions(self, user_id: int) -> None:
        """Invalidate all other sessions except current."""
        current_session_token = getattr(request, 'session_token', None)
        
        query = self.db.session.query(UserSession).filter_by(
            user_id=user_id,
            is_valid=True
        )
        
        if current_session_token:
            query = query.filter(UserSession.session_token != current_session_token)
        
        query.update({
            'is_valid': False,
            'updated_at': self.datetime_utils.utc_now()
        })
    
    def _invalidate_current_session(self) -> None:
        """Invalidate current user session."""
        if hasattr(current_user, 'id') and current_user.is_authenticated:
            current_session_token = getattr(request, 'session_token', None)
            if current_session_token:
                self.db.session.query(UserSession).filter_by(
                    user_id=current_user.id,
                    session_token=current_session_token
                ).update({
                    'is_valid': False,
                    'updated_at': self.datetime_utils.utc_now()
                })

    # =============================================================================
    # Private Helper Methods - Data Serialization
    # =============================================================================
    
    def _serialize_user_data(self, user: User) -> Dict[str, Any]:
        """Serialize user data for API responses."""
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'status': user.status,
            'is_active': user.is_active,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None,
            'last_login_at': user.last_login_at.isoformat() if user.last_login_at else None,
            'profile_data': user.profile_data or {}
        }
    
    def _serialize_user_profile(self, user: User) -> Dict[str, Any]:
        """Serialize comprehensive user profile with relationships."""
        profile_data = self._serialize_user_data(user)
        
        # Add relationship counts
        profile_data['business_entities_count'] = len(user.business_entities) if user.business_entities else 0
        profile_data['active_sessions_count'] = len([
            s for s in (user.sessions or []) 
            if s.is_valid and s.expires_at > self.datetime_utils.utc_now()
        ])
        
        return profile_data
    
    def _serialize_user_session(self, session: UserSession) -> Dict[str, Any]:
        """Serialize user session data."""
        return {
            'id': session.id,
            'user_id': session.user_id,
            'created_at': session.created_at.isoformat() if session.created_at else None,
            'expires_at': session.expires_at.isoformat() if session.expires_at else None,
            'is_valid': session.is_valid,
            'device_info': session.device_info or {}
        }
    
    def _serialize_business_entity(self, entity: BusinessEntity, include_relationships: bool = False) -> Dict[str, Any]:
        """Serialize business entity data with optional relationships."""
        entity_data = {
            'id': entity.id,
            'name': entity.name,
            'description': entity.description,
            'owner_id': entity.owner_id,
            'status': entity.status,
            'created_at': entity.created_at.isoformat() if entity.created_at else None,
            'updated_at': entity.updated_at.isoformat() if entity.updated_at else None
        }
        
        if include_relationships:
            entity_data['relationships'] = {
                'source_relationships': [
                    {
                        'id': rel.id,
                        'target_entity_id': rel.target_entity_id,
                        'relationship_type': rel.relationship_type,
                        'is_active': rel.is_active
                    }
                    for rel in (entity.source_relationships or [])
                ],
                'target_relationships': [
                    {
                        'id': rel.id,
                        'source_entity_id': rel.source_entity_id,
                        'relationship_type': rel.relationship_type,
                        'is_active': rel.is_active
                    }
                    for rel in (entity.target_relationships or [])
                ]
            }
        
        return entity_data

    # =============================================================================
    # Private Helper Methods - Additional Validation
    # =============================================================================
    
    def _validate_profile_update(self, profile_data: UserProfileData, user: User) -> UserServiceResult:
        """Validate profile update data."""
        errors = []
        
        # Email validation if provided
        if profile_data.email is not None:
            if not self.validation_utils.is_valid_email(profile_data.email):
                errors.append("Valid email address is required")
        
        # Name validation if provided
        if profile_data.first_name is not None and len(profile_data.first_name.strip()) == 0:
            errors.append("First name cannot be empty")
            
        if profile_data.last_name is not None and len(profile_data.last_name.strip()) == 0:
            errors.append("Last name cannot be empty")
        
        if errors:
            return UserServiceResult(
                success=False,
                message="Validation failed",
                error_code="VALIDATION_FAILED",
                metadata={'validation_errors': errors}
            )
        
        return UserServiceResult(success=True)
    
    def _validate_business_entity_data(self, entity_data: Dict[str, Any]) -> UserServiceResult:
        """Validate business entity creation data."""
        errors = []
        
        # Name validation
        if not entity_data.get('name') or len(entity_data['name'].strip()) < 2:
            errors.append("Entity name must be at least 2 characters long")
        
        # Status validation
        if 'status' in entity_data and entity_data['status'] not in ['active', 'inactive', 'pending']:
            errors.append("Invalid entity status")
        
        if errors:
            return UserServiceResult(
                success=False,
                message="Validation failed",
                error_code="VALIDATION_FAILED",
                metadata={'validation_errors': errors}
            )
        
        return UserServiceResult(success=True)
    
    def _validate_activation_token(self, user: User, token: str) -> bool:
        """Validate user activation token."""
        # Implementation would depend on token generation strategy
        # This is a placeholder for token validation logic
        return self.session_manager.validate_activation_token(user.id, token)


# =============================================================================
# Service Factory Function for Dependency Injection
# =============================================================================

def create_user_service(
    session_manager: Optional[SessionManager] = None,
    password_utils: Optional[PasswordUtils] = None,
    security_monitor: Optional[SecurityMonitor] = None
) -> UserService:
    """
    Factory function for creating UserService instances with dependency injection.
    
    This factory function supports the Flask application factory pattern and
    enables clean dependency injection for testing and modular development.
    
    Args:
        session_manager: Optional session management utility
        password_utils: Optional password security utility  
        security_monitor: Optional security monitoring utility
        
    Returns:
        UserService: Configured user service instance
    """
    return UserService(
        session_manager=session_manager,
        password_utils=password_utils,
        security_monitor=security_monitor
    )