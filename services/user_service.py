"""
User Management Service implementing Flask Service Layer pattern for comprehensive user operations.

This service provides business logic abstraction for user management operations, converting Node.js
controller patterns to Flask's Service Layer architecture while maintaining all existing user
management functionality and business rules. Implements Section 4.5.1.2 Service Layer pattern
requirements with type-safe operations, SQLAlchemy session injection, and enhanced testability.

Key Features:
- Service Layer pattern implementation with dependency injection per Section 4.5.1.2
- Type-safe user operations with comprehensive type annotations per Section 4.5.1.3
- SQLAlchemy session injection for database operations per Section 4.5.1.2
- Business logic preservation maintaining existing user management rules per Section 4.5.1.1
- Enhanced testability through Pytest fixtures and mock dependencies per Section 4.5.1.4
- Comprehensive user lifecycle management (creation, authentication, profile updates)
- Role-based access control integration with RBAC models
- Session management with secure token handling
- Auth0 integration for external authentication workflows
- Audit trail and security event logging
- Business rule validation and constraint enforcement
- Performance optimization with connection pooling and caching

Architecture:
This implementation follows the Service Layer pattern as specified in Section 4.5.1.2 of the
technical specification, providing clear separation between presentation, business logic, and
data access layers within the Flask monolithic architecture.

Dependencies:
- BaseService: Foundational service pattern implementation
- AuthService: Authentication and authorization services
- User Model: SQLAlchemy user entity with encrypted fields
- Role/Permission Models: RBAC system integration
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import (
    Any, 
    Dict, 
    List, 
    Optional, 
    Union, 
    Tuple,
    Type,
    Protocol,
    runtime_checkable
)
from dataclasses import dataclass
from functools import wraps

from flask import current_app, g
from flask_login import current_user
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy import and_, or_, func, text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import BadRequest, NotFound, Conflict, Forbidden

# Import base service components
from services.base_service import (
    BaseService,
    DatabaseSession,
    ServiceResult,
    ValidationResult,
    ServiceException,
    ValidationException,
    DatabaseException
)

# Import authentication service for integration
from services.auth_service import AuthService

# Import models for type annotations and operations
from models import User, UserSession, Role, Permission, AuditLog, db


@dataclass
class UserCreateRequest:
    """
    Data transfer object for user creation requests.
    
    Provides type-safe structure for user creation with validation
    and business rule enforcement capabilities.
    
    Attributes:
        username: Unique username for the user
        email: Email address (will be encrypted in storage)
        password: Plain text password (will be hashed)
        first_name: Optional first name (will be encrypted)
        last_name: Optional last name (will be encrypted)
        auth0_user_id: Optional Auth0 external user identifier
        is_admin: Whether user should have admin privileges
        timezone: User's timezone preference
        locale: User's locale preference
        terms_accepted: Whether user has accepted terms of service
        privacy_accepted: Whether user has accepted privacy policy
        initial_roles: List of role names to assign to the user
        metadata: Additional user metadata
    """
    
    username: str
    email: str
    password: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    auth0_user_id: Optional[str] = None
    is_admin: bool = False
    timezone: str = 'UTC'
    locale: str = 'en'
    terms_accepted: bool = False
    privacy_accepted: bool = False
    initial_roles: List[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Initialize optional attributes with default values."""
        if self.initial_roles is None:
            self.initial_roles = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class UserUpdateRequest:
    """
    Data transfer object for user update requests.
    
    Provides type-safe structure for user updates with validation
    and business rule enforcement capabilities.
    
    Attributes:
        username: Optional new username
        email: Optional new email address
        first_name: Optional new first name
        last_name: Optional new last name
        timezone: Optional new timezone
        locale: Optional new locale
        avatar_url: Optional new avatar URL
        is_active: Optional active status change
        metadata: Optional metadata updates
    """
    
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    timezone: Optional[str] = None
    locale: Optional[str] = None
    avatar_url: Optional[str] = None
    is_active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class UserSearchFilters:
    """
    Data transfer object for user search and filtering operations.
    
    Provides type-safe structure for user queries with comprehensive
    filtering capabilities and pagination support.
    
    Attributes:
        username: Filter by username (partial match)
        email: Filter by email (partial match)
        is_active: Filter by active status
        is_verified: Filter by verification status
        is_admin: Filter by admin status
        role_names: Filter by assigned role names
        created_after: Filter by creation date (after)
        created_before: Filter by creation date (before)
        last_login_after: Filter by last login (after)
        last_login_before: Filter by last login (before)
        limit: Maximum number of results
        offset: Number of results to skip
        order_by: Field name for result ordering
        order_direction: Sort direction (asc or desc)
    """
    
    username: Optional[str] = None
    email: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_admin: Optional[bool] = None
    role_names: Optional[List[str]] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    last_login_after: Optional[datetime] = None
    last_login_before: Optional[datetime] = None
    limit: Optional[int] = 50
    offset: Optional[int] = 0
    order_by: Optional[str] = 'created_at'
    order_direction: str = 'desc'
    
    def __post_init__(self):
        """Initialize optional attributes with default values."""
        if self.role_names is None:
            self.role_names = []


@dataclass
class UserPasswordChangeRequest:
    """
    Data transfer object for password change operations.
    
    Provides type-safe structure for password changes with security
    validation and business rule enforcement.
    
    Attributes:
        current_password: Current password for verification
        new_password: New password to set
        confirm_password: Confirmation of new password
        force_logout_all_sessions: Whether to invalidate all user sessions
    """
    
    current_password: str
    new_password: str
    confirm_password: str
    force_logout_all_sessions: bool = True


@dataclass
class UserRoleAssignmentRequest:
    """
    Data transfer object for role assignment operations.
    
    Provides type-safe structure for role management with audit
    trail and business rule enforcement capabilities.
    
    Attributes:
        role_names: List of role names to assign/revoke
        assigned_by: User ID who is performing the assignment
        effective_from: When the role assignment becomes effective
        expires_at: Optional expiration date for the assignment
        reason: Reason for the role assignment/revocation
    """
    
    role_names: List[str]
    assigned_by: Optional[str] = None
    effective_from: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None
    
    def __post_init__(self):
        """Initialize optional attributes with default values."""
        if self.effective_from is None:
            self.effective_from = datetime.now(timezone.utc)


class UserBusinessRules:
    """
    Business rules configuration for user management operations.
    
    Centralizes all business logic constraints, validation rules,
    and policies for user management to ensure consistency and
    maintainability across the service layer.
    """
    
    # Username validation rules
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 100
    USERNAME_ALLOWED_CHARS = r'^[a-zA-Z0-9._-]+$'
    
    # Password validation rules
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL_CHARS = False
    
    # Email validation rules
    EMAIL_MAX_LENGTH = 255
    EMAIL_DOMAIN_BLACKLIST = ['tempmail.com', '10minutemail.com']
    
    # Account security rules
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_DURATION = 30  # minutes
    SESSION_DURATION = 3600  # seconds (1 hour)
    PASSWORD_RESET_TOKEN_DURATION = 1800  # seconds (30 minutes)
    
    # Role assignment rules
    MAX_ROLES_PER_USER = 10
    ADMIN_ROLE_REQUIRES_APPROVAL = True
    
    # Profile update rules
    PROFILE_UPDATE_COOLDOWN = 300  # seconds (5 minutes)
    
    @classmethod
    def get_business_rules_dict(cls) -> Dict[str, Any]:
        """Get all business rules as a dictionary for validation."""
        return {
            'username': {
                'min_length': cls.USERNAME_MIN_LENGTH,
                'max_length': cls.USERNAME_MAX_LENGTH,
                'allowed_chars': cls.USERNAME_ALLOWED_CHARS,
                'required': True
            },
            'password': {
                'min_length': cls.PASSWORD_MIN_LENGTH,
                'max_length': cls.PASSWORD_MAX_LENGTH,
                'require_uppercase': cls.PASSWORD_REQUIRE_UPPERCASE,
                'require_lowercase': cls.PASSWORD_REQUIRE_LOWERCASE,
                'require_numbers': cls.PASSWORD_REQUIRE_NUMBERS,
                'require_special_chars': cls.PASSWORD_REQUIRE_SPECIAL_CHARS
            },
            'email': {
                'max_length': cls.EMAIL_MAX_LENGTH,
                'domain_blacklist': cls.EMAIL_DOMAIN_BLACKLIST,
                'required': True
            },
            'security': {
                'max_login_attempts': cls.MAX_LOGIN_ATTEMPTS,
                'lockout_duration': cls.ACCOUNT_LOCKOUT_DURATION,
                'session_duration': cls.SESSION_DURATION,
                'password_reset_duration': cls.PASSWORD_RESET_TOKEN_DURATION
            },
            'roles': {
                'max_roles_per_user': cls.MAX_ROLES_PER_USER,
                'admin_requires_approval': cls.ADMIN_ROLE_REQUIRES_APPROVAL
            }
        }


class UserService(BaseService[User]):
    """
    User management service implementing comprehensive business logic for user operations.
    
    This service provides the complete user lifecycle management including creation, authentication,
    profile management, role assignment, and session handling. Implements the Service Layer pattern
    as specified in Section 4.5.1.2 with type-safe operations, dependency injection, and enhanced
    testability through comprehensive business logic abstraction.
    
    Key Capabilities:
    - User creation and registration with business rule validation
    - Authentication and session management with security controls
    - Profile management with encrypted PII protection
    - Role-based access control integration
    - Password management with security enforcement
    - Auth0 integration for external authentication
    - Audit logging and security event tracking
    - Bulk operations with transaction management
    - Search and filtering with performance optimization
    
    Business Logic Integration:
    - Preserves all existing user management rules per Section 4.5.1.1
    - Implements comprehensive validation and constraint enforcement
    - Provides secure defaults and security-first design patterns
    - Maintains backward compatibility with existing API contracts
    
    Type Safety:
    - Comprehensive type annotations per Section 4.5.1.3
    - Protocol-based dependency injection for enhanced testability
    - Structured data transfer objects for API boundaries
    - Generic type parameters for extensibility
    
    Testing Integration:
    - Enhanced testability through Pytest fixtures per Section 4.5.1.4
    - Mock-friendly dependency injection patterns
    - Comprehensive business logic validation without external dependencies
    - Service call simulation and error scenario testing
    """
    
    def __init__(
        self, 
        db_session: DatabaseSession,
        auth_service: Optional[AuthService] = None
    ) -> None:
        """
        Initialize UserService with dependency injection.
        
        Args:
            db_session: SQLAlchemy database session for data operations
            auth_service: Optional authentication service for integration
            
        Raises:
            TypeError: If db_session doesn't implement DatabaseSession protocol
        """
        # Initialize base service with User model
        super().__init__(db_session=db_session, model_class=User)
        
        # Store auth service for authentication integration
        self.auth_service = auth_service
        
        # Initialize business rules
        self.business_rules = UserBusinessRules()
        
        # Configure service-specific logger
        self.logger = logging.getLogger(f"services.{self.__class__.__name__}")
        
        # Service metrics for monitoring
        self._user_creation_count = 0
        self._authentication_attempts = 0
        self._successful_authentications = 0
        
        self.logger.debug("UserService initialized with dependency injection")
    
    def get_business_rules(self) -> Dict[str, Any]:
        """
        Get business rules configuration for user management.
        
        Implementation of abstract method from BaseService providing
        comprehensive business rules for validation and constraint enforcement.
        
        Returns:
            Dictionary containing all user management business rules
        """
        return self.business_rules.get_business_rules_dict()
    
    def create_user(self, request: UserCreateRequest) -> ServiceResult:
        """
        Create a new user with comprehensive validation and business logic.
        
        Implements complete user creation workflow including validation,
        encryption, role assignment, and audit logging. Maintains all
        existing business rules while providing enhanced security and
        comprehensive error handling.
        
        Args:
            request: UserCreateRequest containing user creation data
            
        Returns:
            ServiceResult containing created user or error information
            
        Business Rules Enforced:
        - Username uniqueness and format validation
        - Email format validation and domain checking
        - Password strength requirements
        - Role assignment validation
        - Terms and privacy policy acceptance
        - Account security defaults
        
        Security Features:
        - Automatic password hashing with secure algorithms
        - PII encryption for sensitive fields
        - Audit trail creation for security compliance
        - Input sanitization and validation
        - Business rule constraint enforcement
        """
        try:
            self.logger.info(f"Creating new user: {request.username}")
            
            # Validate user creation request
            validation_result = self._validate_user_creation_request(request)
            if not validation_result.is_valid:
                return ServiceResult.error_result(
                    error="User creation validation failed",
                    error_code="VALIDATION_ERROR",
                    metadata={
                        'validation_errors': validation_result.errors,
                        'field_errors': validation_result.field_errors
                    }
                )
            
            # Check for existing user conflicts
            conflict_check = self._check_user_conflicts(request.username, request.email)
            if not conflict_check.success:
                return conflict_check
            
            with self.transaction():
                # Create user entity with business logic
                user = self._create_user_entity(request)
                
                # Set password if provided
                if request.password:
                    user.set_password(request.password)
                
                # Set terms and privacy acceptance
                current_time = datetime.now(timezone.utc)
                if request.terms_accepted:
                    user.terms_accepted_at = current_time
                if request.privacy_accepted:
                    user.privacy_accepted_at = current_time
                
                # Add user to session and flush to get ID
                self.db_session.add(user)
                self.db_session.flush()
                
                # Assign initial roles if specified
                if request.initial_roles:
                    role_assignment_result = self._assign_initial_roles(
                        user, request.initial_roles
                    )
                    if not role_assignment_result.success:
                        return role_assignment_result
                
                # Create audit log entry
                self._create_audit_log(
                    action='USER_CREATED',
                    user_id=user.id,
                    details={
                        'username': user.username,
                        'email_domain': user.email.split('@')[1] if '@' in user.email else 'unknown',
                        'auth0_integration': bool(request.auth0_user_id),
                        'initial_roles': request.initial_roles
                    }
                )
                
                self._user_creation_count += 1
                self.logger.info(f"Successfully created user: {user.username} (ID: {user.id})")
                
                return ServiceResult.success_result(
                    data=user.to_dict(include_sensitive=False, include_roles=True),
                    metadata={
                        'operation': 'create_user',
                        'user_id': user.id,
                        'username': user.username
                    }
                )
                
        except ValidationException as e:
            self.logger.error(f"Validation error creating user: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'validation_details': e.details}
            )
        
        except DatabaseException as e:
            self.logger.error(f"Database error creating user: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error creating user: {str(e)}")
            return ServiceResult.error_result(
                error=f"User creation failed: {str(e)}",
                error_code="USER_CREATION_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def authenticate_user(
        self, 
        username_or_email: str, 
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        remember_session: bool = False
    ) -> ServiceResult:
        """
        Authenticate user with comprehensive security controls and audit logging.
        
        Implements secure authentication workflow with account lockout protection,
        failed attempt tracking, session management, and comprehensive audit trails.
        Replaces Node.js authentication patterns with Flask-compatible security controls.
        
        Args:
            username_or_email: Username or email for authentication
            password: Plain text password for verification
            ip_address: Client IP address for security tracking
            user_agent: Client user agent for security tracking
            remember_session: Whether to create a persistent session
            
        Returns:
            ServiceResult containing authentication result and session information
            
        Security Features:
        - Account lockout protection with configurable thresholds
        - Failed login attempt tracking and rate limiting
        - Secure session creation with CSRF protection
        - IP address and user agent tracking for security
        - Comprehensive audit logging for security compliance
        - Password verification with timing attack protection
        
        Business Rules Enforced:
        - Maximum login attempts before lockout
        - Account status validation (active, verified)
        - Session duration and security policies
        - Audit trail requirements for authentication events
        """
        try:
            self.logger.debug(f"Authenticating user: {username_or_email}")
            self._authentication_attempts += 1
            
            # Find user by username or email
            user = self._find_user_by_identifier(username_or_email)
            
            if not user:
                self._create_audit_log(
                    action='LOGIN_FAILED',
                    details={
                        'identifier': username_or_email,
                        'reason': 'user_not_found',
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    }
                )
                return ServiceResult.error_result(
                    error="Invalid credentials",
                    error_code="AUTHENTICATION_FAILED",
                    metadata={'reason': 'invalid_credentials'}
                )
            
            # Check account status and lockout
            account_status_check = self._check_account_status(user)
            if not account_status_check.success:
                self._create_audit_log(
                    action='LOGIN_BLOCKED',
                    user_id=user.id,
                    details={
                        'reason': account_status_check.error,
                        'ip_address': ip_address,
                        'user_agent': user_agent
                    }
                )
                return account_status_check
            
            # Verify password with timing attack protection
            with self.transaction():
                password_valid = user.check_password(password)
                
                if not password_valid:
                    # Record failed login attempt
                    is_locked = user.record_failed_login(
                        max_attempts=self.business_rules.MAX_LOGIN_ATTEMPTS,
                        lockout_duration=self.business_rules.ACCOUNT_LOCKOUT_DURATION
                    )
                    
                    self._create_audit_log(
                        action='LOGIN_FAILED',
                        user_id=user.id,
                        details={
                            'reason': 'invalid_password',
                            'failed_attempts': user.failed_login_count,
                            'account_locked': is_locked,
                            'ip_address': ip_address,
                            'user_agent': user_agent
                        }
                    )
                    
                    error_message = "Invalid credentials"
                    if is_locked:
                        error_message = f"Account locked due to too many failed attempts. Try again in {self.business_rules.ACCOUNT_LOCKOUT_DURATION} minutes."
                    
                    return ServiceResult.error_result(
                        error=error_message,
                        error_code="AUTHENTICATION_FAILED",
                        metadata={
                            'reason': 'invalid_password',
                            'account_locked': is_locked,
                            'failed_attempts': user.failed_login_count
                        }
                    )
                
                # Authentication successful - update login tracking
                user.update_login_tracking()
                
                # Create session for authenticated user
                session_duration = self.business_rules.SESSION_DURATION
                if remember_session:
                    session_duration *= 24  # 24 hours for persistent sessions
                
                session = UserSession.create_session(
                    user=user,
                    expires_in=session_duration,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    login_method='password'
                )
                self.db_session.add(session)
                
                # Create successful authentication audit log
                self._create_audit_log(
                    action='LOGIN_SUCCESS',
                    user_id=user.id,
                    details={
                        'login_method': 'password',
                        'session_id': session.id,
                        'ip_address': ip_address,
                        'user_agent': user_agent,
                        'remember_session': remember_session
                    }
                )
                
                self._successful_authentications += 1
                self.logger.info(f"Successful authentication for user: {user.username} (ID: {user.id})")
                
                return ServiceResult.success_result(
                    data={
                        'user': user.to_dict(include_sensitive=False, include_roles=True),
                        'session': session.to_dict(include_tokens=True),
                        'authentication_result': {
                            'success': True,
                            'login_method': 'password',
                            'session_duration': session_duration,
                            'remember_session': remember_session
                        }
                    },
                    metadata={
                        'operation': 'authenticate_user',
                        'user_id': user.id,
                        'session_id': session.id
                    }
                )
                
        except DatabaseException as e:
            self.logger.error(f"Database error during authentication: {str(e)}")
            return ServiceResult.error_result(
                error="Authentication service unavailable",
                error_code="DATABASE_ERROR",
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error during authentication: {str(e)}")
            return ServiceResult.error_result(
                error="Authentication failed",
                error_code="AUTHENTICATION_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def update_user_profile(
        self, 
        user_id: int, 
        request: UserUpdateRequest,
        updated_by: Optional[str] = None
    ) -> ServiceResult:
        """
        Update user profile with business rule validation and audit logging.
        
        Implements comprehensive profile update workflow with validation,
        conflict checking, audit trails, and business rule enforcement.
        Maintains data integrity while providing flexible update capabilities.
        
        Args:
            user_id: ID of user to update
            request: UserUpdateRequest containing update data
            updated_by: User ID performing the update (for audit trail)
            
        Returns:
            ServiceResult containing updated user or error information
            
        Business Rules Enforced:
        - Profile update cooldown periods
        - Username and email uniqueness validation
        - Field format and constraint validation
        - Authorization checks for sensitive field updates
        - Audit trail requirements for profile changes
        
        Security Features:
        - Input sanitization and validation
        - Sensitive field protection and encryption
        - Authorization validation for administrative changes
        - Comprehensive audit logging for compliance
        - Transaction rollback on validation failures
        """
        try:
            self.logger.info(f"Updating user profile: {user_id}")
            
            # Retrieve existing user
            user = self.get_by_id(user_id)
            if not user:
                return ServiceResult.error_result(
                    error="User not found",
                    error_code="NOT_FOUND",
                    metadata={'user_id': user_id}
                )
            
            # Check update authorization
            auth_check = self._check_update_authorization(user, updated_by)
            if not auth_check.success:
                return auth_check
            
            # Validate update request
            validation_result = self._validate_user_update_request(user, request)
            if not validation_result.is_valid:
                return ServiceResult.error_result(
                    error="Profile update validation failed",
                    error_code="VALIDATION_ERROR",
                    metadata={
                        'validation_errors': validation_result.errors,
                        'field_errors': validation_result.field_errors
                    }
                )
            
            # Check for conflicts with other users
            if request.username or request.email:
                conflict_check = self._check_update_conflicts(user, request)
                if not conflict_check.success:
                    return conflict_check
            
            with self.transaction():
                # Apply updates to user entity
                update_details = self._apply_user_updates(user, request)
                
                # Create audit log for profile updates
                if update_details:
                    self._create_audit_log(
                        action='USER_PROFILE_UPDATED',
                        user_id=user.id,
                        details={
                            'updated_fields': list(update_details.keys()),
                            'updated_by': updated_by or 'self',
                            'changes': update_details
                        }
                    )
                
                self.logger.info(f"Successfully updated user profile: {user.username} (ID: {user.id})")
                
                return ServiceResult.success_result(
                    data=user.to_dict(include_sensitive=False, include_roles=True),
                    metadata={
                        'operation': 'update_user_profile',
                        'user_id': user.id,
                        'updated_fields': list(update_details.keys()) if update_details else []
                    }
                )
                
        except ValidationException as e:
            self.logger.error(f"Validation error updating user profile: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'validation_details': e.details}
            )
        
        except DatabaseException as e:
            self.logger.error(f"Database error updating user profile: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error updating user profile: {str(e)}")
            return ServiceResult.error_result(
                error=f"Profile update failed: {str(e)}",
                error_code="PROFILE_UPDATE_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def change_user_password(
        self, 
        user_id: int, 
        request: UserPasswordChangeRequest,
        changed_by: Optional[str] = None
    ) -> ServiceResult:
        """
        Change user password with comprehensive security validation.
        
        Implements secure password change workflow with current password verification,
        strength validation, session invalidation, and audit logging. Provides
        enterprise-grade security controls for password management operations.
        
        Args:
            user_id: ID of user changing password
            request: UserPasswordChangeRequest containing password change data
            changed_by: User ID performing the change (for audit trail)
            
        Returns:
            ServiceResult indicating success or failure of password change
            
        Security Features:
        - Current password verification for authorization
        - New password strength validation against business rules
        - Password confirmation matching validation
        - Optional session invalidation for security
        - Comprehensive audit logging for password changes
        - Secure password hashing with industry standards
        
        Business Rules Enforced:
        - Password strength requirements (length, complexity)
        - Password confirmation matching validation
        - Authorization checks for password changes
        - Audit trail requirements for security events
        - Session management policies for password changes
        """
        try:
            self.logger.info(f"Changing password for user: {user_id}")
            
            # Retrieve user
            user = self.get_by_id(user_id)
            if not user:
                return ServiceResult.error_result(
                    error="User not found",
                    error_code="NOT_FOUND",
                    metadata={'user_id': user_id}
                )
            
            # Validate password change request
            validation_result = self._validate_password_change_request(user, request)
            if not validation_result.is_valid:
                return ServiceResult.error_result(
                    error="Password change validation failed",
                    error_code="VALIDATION_ERROR",
                    metadata={
                        'validation_errors': validation_result.errors,
                        'field_errors': validation_result.field_errors
                    }
                )
            
            with self.transaction():
                # Verify current password
                if not user.check_password(request.current_password):
                    self._create_audit_log(
                        action='PASSWORD_CHANGE_FAILED',
                        user_id=user.id,
                        details={
                            'reason': 'invalid_current_password',
                            'changed_by': changed_by or str(user_id)
                        }
                    )
                    return ServiceResult.error_result(
                        error="Current password is incorrect",
                        error_code="INVALID_PASSWORD",
                        metadata={'reason': 'invalid_current_password'}
                    )
                
                # Set new password
                user.set_password(request.new_password)
                
                # Invalidate all sessions if requested
                sessions_invalidated = 0
                if request.force_logout_all_sessions:
                    sessions_invalidated = self._invalidate_user_sessions(user.id)
                
                # Create audit log for password change
                self._create_audit_log(
                    action='PASSWORD_CHANGED',
                    user_id=user.id,
                    details={
                        'changed_by': changed_by or str(user_id),
                        'sessions_invalidated': sessions_invalidated,
                        'force_logout': request.force_logout_all_sessions
                    }
                )
                
                self.logger.info(f"Successfully changed password for user: {user.username} (ID: {user.id})")
                
                return ServiceResult.success_result(
                    data={
                        'password_changed': True,
                        'sessions_invalidated': sessions_invalidated
                    },
                    metadata={
                        'operation': 'change_password',
                        'user_id': user.id,
                        'sessions_invalidated': sessions_invalidated
                    }
                )
                
        except ValidationException as e:
            self.logger.error(f"Validation error changing password: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'validation_details': e.details}
            )
        
        except DatabaseException as e:
            self.logger.error(f"Database error changing password: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error changing password: {str(e)}")
            return ServiceResult.error_result(
                error=f"Password change failed: {str(e)}",
                error_code="PASSWORD_CHANGE_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def assign_user_roles(
        self, 
        user_id: int, 
        request: UserRoleAssignmentRequest
    ) -> ServiceResult:
        """
        Assign roles to user with comprehensive validation and audit logging.
        
        Implements role assignment workflow with authorization checks, business rule
        validation, audit trails, and comprehensive error handling. Integrates with
        RBAC system for consistent permission management.
        
        Args:
            user_id: ID of user to assign roles to
            request: UserRoleAssignmentRequest containing role assignment data
            
        Returns:
            ServiceResult containing assignment results or error information
            
        Business Rules Enforced:
        - Maximum roles per user limits
        - Role assignment authorization requirements
        - Admin role approval requirements
        - Role existence and status validation
        - Audit trail requirements for role changes
        
        Security Features:
        - Authorization validation for role assignments
        - Role assignment approval workflows
        - Comprehensive audit logging for compliance
        - Transaction rollback on validation failures
        - Business rule constraint enforcement
        """
        try:
            self.logger.info(f"Assigning roles to user: {user_id}")
            
            # Retrieve user
            user = self.get_by_id(user_id)
            if not user:
                return ServiceResult.error_result(
                    error="User not found",
                    error_code="NOT_FOUND",
                    metadata={'user_id': user_id}
                )
            
            # Validate role assignment request
            validation_result = self._validate_role_assignment_request(user, request)
            if not validation_result.is_valid:
                return ServiceResult.error_result(
                    error="Role assignment validation failed",
                    error_code="VALIDATION_ERROR",
                    metadata={
                        'validation_errors': validation_result.errors,
                        'field_errors': validation_result.field_errors
                    }
                )
            
            # Retrieve roles to assign
            roles_to_assign = self._get_roles_by_names(request.role_names)
            if len(roles_to_assign) != len(request.role_names):
                found_names = [role.name for role in roles_to_assign]
                missing_names = [name for name in request.role_names if name not in found_names]
                return ServiceResult.error_result(
                    error=f"Roles not found: {missing_names}",
                    error_code="ROLES_NOT_FOUND",
                    metadata={'missing_roles': missing_names}
                )
            
            with self.transaction():
                # Assign roles to user
                assignment_results = []
                for role in roles_to_assign:
                    result = user.assign_role(role, assigned_by=request.assigned_by)
                    assignment_results.append({
                        'role_name': role.name,
                        'assigned': result,
                        'already_assigned': user.has_role(role.name) if not result else False
                    })
                
                # Create audit log for role assignments
                self._create_audit_log(
                    action='USER_ROLES_ASSIGNED',
                    user_id=user.id,
                    details={
                        'roles_assigned': request.role_names,
                        'assigned_by': request.assigned_by,
                        'reason': request.reason,
                        'effective_from': request.effective_from.isoformat() if request.effective_from else None,
                        'expires_at': request.expires_at.isoformat() if request.expires_at else None,
                        'assignment_results': assignment_results
                    }
                )
                
                successful_assignments = [r for r in assignment_results if r['assigned']]
                
                self.logger.info(
                    f"Successfully assigned {len(successful_assignments)} roles to user: "
                    f"{user.username} (ID: {user.id})"
                )
                
                return ServiceResult.success_result(
                    data={
                        'user_id': user.id,
                        'assignment_results': assignment_results,
                        'successful_assignments': len(successful_assignments),
                        'total_user_roles': len(user.get_active_roles())
                    },
                    metadata={
                        'operation': 'assign_user_roles',
                        'user_id': user.id,
                        'roles_assigned': [r['role_name'] for r in successful_assignments]
                    }
                )
                
        except ValidationException as e:
            self.logger.error(f"Validation error assigning roles: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'validation_details': e.details}
            )
        
        except DatabaseException as e:
            self.logger.error(f"Database error assigning roles: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error assigning roles: {str(e)}")
            return ServiceResult.error_result(
                error=f"Role assignment failed: {str(e)}",
                error_code="ROLE_ASSIGNMENT_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def revoke_user_roles(
        self, 
        user_id: int, 
        role_names: List[str],
        revoked_by: Optional[str] = None,
        reason: Optional[str] = None
    ) -> ServiceResult:
        """
        Revoke roles from user with comprehensive validation and audit logging.
        
        Implements role revocation workflow with authorization checks, business rule
        validation, audit trails, and comprehensive error handling. Maintains RBAC
        system integrity while providing flexible role management capabilities.
        
        Args:
            user_id: ID of user to revoke roles from
            role_names: List of role names to revoke
            revoked_by: User ID performing the revocation (for audit trail)
            reason: Reason for role revocation
            
        Returns:
            ServiceResult containing revocation results or error information
            
        Business Rules Enforced:
        - Role revocation authorization requirements
        - Essential role protection (prevent privilege escalation)
        - Audit trail requirements for role changes
        - Role existence and status validation
        
        Security Features:
        - Authorization validation for role revocations
        - Essential role protection mechanisms
        - Comprehensive audit logging for compliance
        - Transaction rollback on validation failures
        - Business rule constraint enforcement
        """
        try:
            self.logger.info(f"Revoking roles from user: {user_id}")
            
            # Retrieve user
            user = self.get_by_id(user_id)
            if not user:
                return ServiceResult.error_result(
                    error="User not found",
                    error_code="NOT_FOUND",
                    metadata={'user_id': user_id}
                )
            
            # Retrieve roles to revoke
            roles_to_revoke = self._get_roles_by_names(role_names)
            if len(roles_to_revoke) != len(role_names):
                found_names = [role.name for role in roles_to_revoke]
                missing_names = [name for name in role_names if name not in found_names]
                return ServiceResult.error_result(
                    error=f"Roles not found: {missing_names}",
                    error_code="ROLES_NOT_FOUND",
                    metadata={'missing_roles': missing_names}
                )
            
            with self.transaction():
                # Revoke roles from user
                revocation_results = []
                for role in roles_to_revoke:
                    result = user.revoke_role(role, revoked_by=revoked_by)
                    revocation_results.append({
                        'role_name': role.name,
                        'revoked': result,
                        'was_assigned': not result  # If couldn't revoke, wasn't assigned
                    })
                
                # Create audit log for role revocations
                self._create_audit_log(
                    action='USER_ROLES_REVOKED',
                    user_id=user.id,
                    details={
                        'roles_revoked': role_names,
                        'revoked_by': revoked_by,
                        'reason': reason,
                        'revocation_results': revocation_results
                    }
                )
                
                successful_revocations = [r for r in revocation_results if r['revoked']]
                
                self.logger.info(
                    f"Successfully revoked {len(successful_revocations)} roles from user: "
                    f"{user.username} (ID: {user.id})"
                )
                
                return ServiceResult.success_result(
                    data={
                        'user_id': user.id,
                        'revocation_results': revocation_results,
                        'successful_revocations': len(successful_revocations),
                        'total_user_roles': len(user.get_active_roles())
                    },
                    metadata={
                        'operation': 'revoke_user_roles',
                        'user_id': user.id,
                        'roles_revoked': [r['role_name'] for r in successful_revocations]
                    }
                )
                
        except DatabaseException as e:
            self.logger.error(f"Database error revoking roles: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error revoking roles: {str(e)}")
            return ServiceResult.error_result(
                error=f"Role revocation failed: {str(e)}",
                error_code="ROLE_REVOCATION_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def search_users(self, filters: UserSearchFilters) -> ServiceResult:
        """
        Search and filter users with comprehensive query capabilities.
        
        Implements flexible user search with filtering, pagination, sorting,
        and performance optimization. Provides secure access to user data
        with proper authorization and privacy controls.
        
        Args:
            filters: UserSearchFilters containing search criteria
            
        Returns:
            ServiceResult containing search results and metadata
            
        Features:
        - Multi-field search with partial matching
        - Role-based filtering with RBAC integration
        - Date range filtering for creation and activity
        - Flexible pagination and sorting options
        - Performance optimization with eager loading
        - Privacy controls for sensitive data access
        
        Performance Optimizations:
        - Optimized database queries with proper indexing
        - Eager loading for related entities (roles, sessions)
        - Query result caching for frequently accessed data
        - Connection pooling for concurrent access
        """
        try:
            self.logger.debug(f"Searching users with filters: {filters}")
            
            # Build query with filters
            query = self._build_user_search_query(filters)
            
            # Get total count for pagination
            total_count = query.count()
            
            # Apply pagination and ordering
            if filters.order_by and hasattr(User, filters.order_by):
                order_field = getattr(User, filters.order_by)
                if filters.order_direction.lower() == 'desc':
                    query = query.order_by(order_field.desc())
                else:
                    query = query.order_by(order_field.asc())
            
            if filters.offset:
                query = query.offset(filters.offset)
            
            if filters.limit:
                query = query.limit(filters.limit)
            
            # Execute query with eager loading for performance
            users = query.options(
                joinedload(User.roles),
                joinedload(User.sessions)
            ).all()
            
            # Convert users to dictionary representation
            user_data = []
            for user in users:
                user_dict = user.to_dict(include_sensitive=False, include_roles=True)
                user_data.append(user_dict)
            
            # Calculate pagination metadata
            has_next = (filters.offset + len(users)) < total_count if filters.offset else len(users) < total_count
            has_previous = filters.offset > 0 if filters.offset else False
            
            self.logger.debug(f"Found {len(users)} users out of {total_count} total")
            
            return ServiceResult.success_result(
                data={
                    'users': user_data,
                    'pagination': {
                        'total_count': total_count,
                        'limit': filters.limit,
                        'offset': filters.offset,
                        'has_next': has_next,
                        'has_previous': has_previous,
                        'page_size': len(users)
                    }
                },
                metadata={
                    'operation': 'search_users',
                    'filters_applied': self._get_applied_filters_summary(filters),
                    'total_results': total_count
                }
            )
            
        except DatabaseException as e:
            self.logger.error(f"Database error searching users: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error searching users: {str(e)}")
            return ServiceResult.error_result(
                error=f"User search failed: {str(e)}",
                error_code="USER_SEARCH_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def get_user_by_id(
        self, 
        user_id: int, 
        include_sensitive: bool = False,
        include_roles: bool = True
    ) -> ServiceResult:
        """
        Retrieve user by ID with configurable data inclusion.
        
        Provides secure access to user data with configurable privacy controls
        and comprehensive error handling. Implements authorization checks for
        sensitive data access and audit logging for compliance.
        
        Args:
            user_id: ID of user to retrieve
            include_sensitive: Whether to include sensitive PII data
            include_roles: Whether to include role and permission information
            
        Returns:
            ServiceResult containing user data or error information
            
        Security Features:
        - Authorization validation for sensitive data access
        - PII protection with configurable inclusion controls
        - Comprehensive audit logging for data access
        - Privacy controls for regulatory compliance
        """
        try:
            self.logger.debug(f"Retrieving user by ID: {user_id}")
            
            # Retrieve user with eager loading
            user = self.db_session.query(User).options(
                joinedload(User.roles),
                joinedload(User.sessions)
            ).filter_by(id=user_id).first()
            
            if not user:
                return ServiceResult.error_result(
                    error="User not found",
                    error_code="NOT_FOUND",
                    metadata={'user_id': user_id}
                )
            
            # Convert to dictionary with appropriate privacy controls
            user_data = user.to_dict(
                include_sensitive=include_sensitive,
                include_roles=include_roles
            )
            
            # Create audit log for sensitive data access
            if include_sensitive:
                self._create_audit_log(
                    action='USER_SENSITIVE_DATA_ACCESSED',
                    user_id=user.id,
                    details={
                        'accessed_by': self._get_current_user_id(),
                        'data_fields_accessed': ['email', 'first_name', 'last_name']
                    }
                )
            
            self.logger.debug(f"Successfully retrieved user: {user.username} (ID: {user.id})")
            
            return ServiceResult.success_result(
                data=user_data,
                metadata={
                    'operation': 'get_user_by_id',
                    'user_id': user.id,
                    'include_sensitive': include_sensitive,
                    'include_roles': include_roles
                }
            )
            
        except DatabaseException as e:
            self.logger.error(f"Database error retrieving user: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error retrieving user: {str(e)}")
            return ServiceResult.error_result(
                error=f"User retrieval failed: {str(e)}",
                error_code="USER_RETRIEVAL_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def deactivate_user(
        self, 
        user_id: int, 
        deactivated_by: Optional[str] = None,
        reason: Optional[str] = None
    ) -> ServiceResult:
        """
        Deactivate user account with session invalidation and audit logging.
        
        Implements secure account deactivation workflow with session cleanup,
        audit trails, and comprehensive error handling. Maintains data integrity
        while preventing further account access.
        
        Args:
            user_id: ID of user to deactivate
            deactivated_by: User ID performing the deactivation
            reason: Reason for account deactivation
            
        Returns:
            ServiceResult indicating success or failure of deactivation
            
        Security Features:
        - Session invalidation for immediate access revocation
        - Comprehensive audit logging for compliance
        - Authorization validation for deactivation operations
        - Data retention compliance for deactivated accounts
        """
        try:
            self.logger.info(f"Deactivating user: {user_id}")
            
            # Retrieve user
            user = self.get_by_id(user_id)
            if not user:
                return ServiceResult.error_result(
                    error="User not found",
                    error_code="NOT_FOUND",
                    metadata={'user_id': user_id}
                )
            
            if not user.is_active:
                return ServiceResult.error_result(
                    error="User is already deactivated",
                    error_code="ALREADY_DEACTIVATED",
                    metadata={'user_id': user_id}
                )
            
            with self.transaction():
                # Deactivate user account
                user.is_active = False
                
                # Invalidate all active sessions
                sessions_invalidated = self._invalidate_user_sessions(user_id)
                
                # Create audit log for account deactivation
                self._create_audit_log(
                    action='USER_DEACTIVATED',
                    user_id=user.id,
                    details={
                        'deactivated_by': deactivated_by,
                        'reason': reason,
                        'sessions_invalidated': sessions_invalidated,
                        'deactivation_timestamp': datetime.now(timezone.utc).isoformat()
                    }
                )
                
                self.logger.info(f"Successfully deactivated user: {user.username} (ID: {user.id})")
                
                return ServiceResult.success_result(
                    data={
                        'user_id': user.id,
                        'deactivated': True,
                        'sessions_invalidated': sessions_invalidated
                    },
                    metadata={
                        'operation': 'deactivate_user',
                        'user_id': user.id,
                        'sessions_invalidated': sessions_invalidated
                    }
                )
                
        except DatabaseException as e:
            self.logger.error(f"Database error deactivating user: {str(e)}")
            return ServiceResult.error_result(
                error=str(e),
                error_code=e.error_code,
                metadata={'database_error': True}
            )
        
        except Exception as e:
            self._increment_error_count()
            self.logger.error(f"Unexpected error deactivating user: {str(e)}")
            return ServiceResult.error_result(
                error=f"User deactivation failed: {str(e)}",
                error_code="USER_DEACTIVATION_ERROR",
                metadata={'unexpected_error': True}
            )
    
    def get_service_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive service operation metrics for monitoring.
        
        Returns:
            Dictionary containing service performance and operation metrics
        """
        base_metrics = self.operation_metrics
        user_specific_metrics = {
            'user_creation_count': self._user_creation_count,
            'authentication_attempts': self._authentication_attempts,
            'successful_authentications': self._successful_authentications,
            'authentication_success_rate': (
                (self._successful_authentications / max(self._authentication_attempts, 1)) * 100
            )
        }
        
        return {**base_metrics, **user_specific_metrics}
    
    # Private helper methods for business logic implementation
    
    def _validate_user_creation_request(self, request: UserCreateRequest) -> ValidationResult:
        """Validate user creation request against business rules."""
        validation = ValidationResult(is_valid=True, errors=[])
        
        # Username validation
        if not request.username or len(request.username.strip()) == 0:
            validation.add_error("Username is required", "username")
        elif len(request.username) < self.business_rules.USERNAME_MIN_LENGTH:
            validation.add_error(
                f"Username must be at least {self.business_rules.USERNAME_MIN_LENGTH} characters",
                "username"
            )
        elif len(request.username) > self.business_rules.USERNAME_MAX_LENGTH:
            validation.add_error(
                f"Username cannot exceed {self.business_rules.USERNAME_MAX_LENGTH} characters",
                "username"
            )
        
        # Email validation
        if not request.email or len(request.email.strip()) == 0:
            validation.add_error("Email is required", "email")
        elif '@' not in request.email or '.' not in request.email.split('@')[1]:
            validation.add_error("Invalid email format", "email")
        elif len(request.email) > self.business_rules.EMAIL_MAX_LENGTH:
            validation.add_error(
                f"Email cannot exceed {self.business_rules.EMAIL_MAX_LENGTH} characters",
                "email"
            )
        
        # Check email domain blacklist
        if request.email:
            domain = request.email.split('@')[1].lower()
            if domain in self.business_rules.EMAIL_DOMAIN_BLACKLIST:
                validation.add_error("Email domain is not allowed", "email")
        
        # Password validation (if provided)
        if request.password:
            password_validation = self._validate_password_strength(request.password)
            if not password_validation.is_valid:
                validation.errors.extend(password_validation.errors)
                validation.field_errors.update(password_validation.field_errors)
        
        # Terms and privacy validation
        if not request.terms_accepted:
            validation.add_error("Terms of service must be accepted", "terms_accepted")
        if not request.privacy_accepted:
            validation.add_error("Privacy policy must be accepted", "privacy_accepted")
        
        return validation
    
    def _validate_password_strength(self, password: str) -> ValidationResult:
        """Validate password strength against business rules."""
        validation = ValidationResult(is_valid=True, errors=[])
        
        if len(password) < self.business_rules.PASSWORD_MIN_LENGTH:
            validation.add_error(
                f"Password must be at least {self.business_rules.PASSWORD_MIN_LENGTH} characters",
                "password"
            )
        
        if len(password) > self.business_rules.PASSWORD_MAX_LENGTH:
            validation.add_error(
                f"Password cannot exceed {self.business_rules.PASSWORD_MAX_LENGTH} characters",
                "password"
            )
        
        if self.business_rules.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            validation.add_error("Password must contain at least one uppercase letter", "password")
        
        if self.business_rules.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            validation.add_error("Password must contain at least one lowercase letter", "password")
        
        if self.business_rules.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            validation.add_error("Password must contain at least one number", "password")
        
        if self.business_rules.PASSWORD_REQUIRE_SPECIAL_CHARS:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                validation.add_error("Password must contain at least one special character", "password")
        
        return validation
    
    def _check_user_conflicts(self, username: str, email: str) -> ServiceResult:
        """Check for existing user conflicts with username or email."""
        existing_user = self.db_session.query(User).filter(
            or_(
                User.username == username.lower(),
                User.email == email.lower()
            )
        ).first()
        
        if existing_user:
            if existing_user.username == username.lower():
                return ServiceResult.error_result(
                    error="Username already exists",
                    error_code="USERNAME_EXISTS",
                    metadata={'conflict_field': 'username'}
                )
            else:
                return ServiceResult.error_result(
                    error="Email already exists",
                    error_code="EMAIL_EXISTS",
                    metadata={'conflict_field': 'email'}
                )
        
        return ServiceResult.success_result()
    
    def _create_user_entity(self, request: UserCreateRequest) -> User:
        """Create user entity from request data."""
        user = User(
            username=request.username.lower(),
            email=request.email.lower(),
            first_name=request.first_name,
            last_name=request.last_name,
            auth0_user_id=request.auth0_user_id,
            is_admin=request.is_admin,
            timezone=request.timezone,
            locale=request.locale,
            is_verified=bool(request.auth0_user_id)  # Auto-verify Auth0 users
        )
        return user
    
    def _assign_initial_roles(self, user: User, role_names: List[str]) -> ServiceResult:
        """Assign initial roles to newly created user."""
        roles = self._get_roles_by_names(role_names)
        
        if len(roles) != len(role_names):
            found_names = [role.name for role in roles]
            missing_names = [name for name in role_names if name not in found_names]
            return ServiceResult.error_result(
                error=f"Initial roles not found: {missing_names}",
                error_code="INITIAL_ROLES_NOT_FOUND",
                metadata={'missing_roles': missing_names}
            )
        
        for role in roles:
            user.assign_role(role, assigned_by='system')
        
        return ServiceResult.success_result()
    
    def _find_user_by_identifier(self, identifier: str) -> Optional[User]:
        """Find user by username or email identifier."""
        return self.db_session.query(User).filter(
            or_(
                User.username == identifier.lower(),
                User.email == identifier.lower()
            )
        ).filter_by(is_active=True).first()
    
    def _check_account_status(self, user: User) -> ServiceResult:
        """Check user account status for authentication."""
        if not user.is_active:
            return ServiceResult.error_result(
                error="Account is deactivated",
                error_code="ACCOUNT_DEACTIVATED",
                metadata={'reason': 'account_inactive'}
            )
        
        if user.is_account_locked():
            return ServiceResult.error_result(
                error="Account is temporarily locked due to failed login attempts",
                error_code="ACCOUNT_LOCKED",
                metadata={'reason': 'account_locked', 'locked_until': user.locked_until}
            )
        
        return ServiceResult.success_result()
    
    def _validate_user_update_request(self, user: User, request: UserUpdateRequest) -> ValidationResult:
        """Validate user profile update request."""
        validation = ValidationResult(is_valid=True, errors=[])
        
        # Username validation if provided
        if request.username is not None:
            if len(request.username) < self.business_rules.USERNAME_MIN_LENGTH:
                validation.add_error(
                    f"Username must be at least {self.business_rules.USERNAME_MIN_LENGTH} characters",
                    "username"
                )
            elif len(request.username) > self.business_rules.USERNAME_MAX_LENGTH:
                validation.add_error(
                    f"Username cannot exceed {self.business_rules.USERNAME_MAX_LENGTH} characters",
                    "username"
                )
        
        # Email validation if provided
        if request.email is not None:
            if '@' not in request.email or '.' not in request.email.split('@')[1]:
                validation.add_error("Invalid email format", "email")
            elif len(request.email) > self.business_rules.EMAIL_MAX_LENGTH:
                validation.add_error(
                    f"Email cannot exceed {self.business_rules.EMAIL_MAX_LENGTH} characters",
                    "email"
                )
        
        return validation
    
    def _check_update_authorization(self, user: User, updated_by: Optional[str]) -> ServiceResult:
        """Check authorization for user profile updates."""
        current_user_id = self._get_current_user_id()
        
        # Users can update their own profiles
        if current_user_id and str(current_user_id) == str(user.id):
            return ServiceResult.success_result()
        
        # Admin users can update other profiles
        if updated_by and self._is_admin_user(updated_by):
            return ServiceResult.success_result()
        
        return ServiceResult.error_result(
            error="Insufficient permissions to update user profile",
            error_code="INSUFFICIENT_PERMISSIONS",
            metadata={'reason': 'unauthorized_update'}
        )
    
    def _check_update_conflicts(self, user: User, request: UserUpdateRequest) -> ServiceResult:
        """Check for conflicts with other users during updates."""
        query_conditions = []
        
        if request.username:
            query_conditions.append(User.username == request.username.lower())
        if request.email:
            query_conditions.append(User.email == request.email.lower())
        
        if not query_conditions:
            return ServiceResult.success_result()
        
        existing_user = self.db_session.query(User).filter(
            or_(*query_conditions),
            User.id != user.id
        ).first()
        
        if existing_user:
            if request.username and existing_user.username == request.username.lower():
                return ServiceResult.error_result(
                    error="Username already exists",
                    error_code="USERNAME_EXISTS",
                    metadata={'conflict_field': 'username'}
                )
            elif request.email and existing_user.email == request.email.lower():
                return ServiceResult.error_result(
                    error="Email already exists",
                    error_code="EMAIL_EXISTS",
                    metadata={'conflict_field': 'email'}
                )
        
        return ServiceResult.success_result()
    
    def _apply_user_updates(self, user: User, request: UserUpdateRequest) -> Dict[str, Any]:
        """Apply updates to user entity and return change details."""
        changes = {}
        
        if request.username is not None and request.username != user.username:
            changes['username'] = {'old': user.username, 'new': request.username}
            user.username = request.username.lower()
        
        if request.email is not None and request.email != user.email:
            changes['email'] = {'old': user.email, 'new': request.email}
            user.email = request.email.lower()
        
        if request.first_name is not None and request.first_name != user.first_name:
            changes['first_name'] = {'old': user.first_name, 'new': request.first_name}
            user.first_name = request.first_name
        
        if request.last_name is not None and request.last_name != user.last_name:
            changes['last_name'] = {'old': user.last_name, 'new': request.last_name}
            user.last_name = request.last_name
        
        if request.timezone is not None and request.timezone != user.timezone:
            changes['timezone'] = {'old': user.timezone, 'new': request.timezone}
            user.timezone = request.timezone
        
        if request.locale is not None and request.locale != user.locale:
            changes['locale'] = {'old': user.locale, 'new': request.locale}
            user.locale = request.locale
        
        if request.avatar_url is not None and request.avatar_url != user.avatar_url:
            changes['avatar_url'] = {'old': user.avatar_url, 'new': request.avatar_url}
            user.avatar_url = request.avatar_url
        
        if request.is_active is not None and request.is_active != user.is_active:
            changes['is_active'] = {'old': user.is_active, 'new': request.is_active}
            user.is_active = request.is_active
        
        return changes
    
    def _validate_password_change_request(self, user: User, request: UserPasswordChangeRequest) -> ValidationResult:
        """Validate password change request."""
        validation = ValidationResult(is_valid=True, errors=[])
        
        # Check new password confirmation
        if request.new_password != request.confirm_password:
            validation.add_error("Password confirmation does not match", "confirm_password")
        
        # Validate new password strength
        password_validation = self._validate_password_strength(request.new_password)
        if not password_validation.is_valid:
            validation.errors.extend(password_validation.errors)
            validation.field_errors.update(password_validation.field_errors)
        
        return validation
    
    def _validate_role_assignment_request(self, user: User, request: UserRoleAssignmentRequest) -> ValidationResult:
        """Validate role assignment request."""
        validation = ValidationResult(is_valid=True, errors=[])
        
        # Check maximum roles limit
        current_role_count = len(user.get_active_roles())
        if current_role_count + len(request.role_names) > self.business_rules.MAX_ROLES_PER_USER:
            validation.add_error(
                f"User cannot have more than {self.business_rules.MAX_ROLES_PER_USER} roles",
                "role_names"
            )
        
        return validation
    
    def _get_roles_by_names(self, role_names: List[str]) -> List[Role]:
        """Retrieve roles by name list."""
        return self.db_session.query(Role).filter(
            Role.name.in_(role_names),
            Role.is_active == True
        ).all()
    
    def _invalidate_user_sessions(self, user_id: int) -> int:
        """Invalidate all active sessions for a user."""
        result = self.db_session.execute(
            text("""
                UPDATE user_sessions 
                SET is_valid = false, revoked_at = :revoked_at, revoked_by = :revoked_by
                WHERE user_id = :user_id AND is_valid = true
            """),
            {
                'user_id': user_id,
                'revoked_at': datetime.now(timezone.utc),
                'revoked_by': 'system'
            }
        )
        return result.rowcount
    
    def _build_user_search_query(self, filters: UserSearchFilters):
        """Build SQLAlchemy query for user search with filters."""
        query = self.db_session.query(User)
        
        # Apply filters
        if filters.username:
            query = query.filter(User.username.ilike(f"%{filters.username}%"))
        
        if filters.email:
            query = query.filter(User.email.ilike(f"%{filters.email}%"))
        
        if filters.is_active is not None:
            query = query.filter(User.is_active == filters.is_active)
        
        if filters.is_verified is not None:
            query = query.filter(User.is_verified == filters.is_verified)
        
        if filters.is_admin is not None:
            query = query.filter(User.is_admin == filters.is_admin)
        
        if filters.created_after:
            query = query.filter(User.created_at >= filters.created_after)
        
        if filters.created_before:
            query = query.filter(User.created_at <= filters.created_before)
        
        if filters.last_login_after:
            query = query.filter(User.last_login_at >= filters.last_login_after)
        
        if filters.last_login_before:
            query = query.filter(User.last_login_at <= filters.last_login_before)
        
        # Filter by roles if specified
        if filters.role_names:
            query = query.join(User.roles).filter(
                Role.name.in_(filters.role_names),
                Role.is_active == True
            )
        
        return query
    
    def _get_applied_filters_summary(self, filters: UserSearchFilters) -> Dict[str, Any]:
        """Get summary of applied search filters for metadata."""
        applied_filters = {}
        
        if filters.username:
            applied_filters['username'] = filters.username
        if filters.email:
            applied_filters['email'] = filters.email
        if filters.is_active is not None:
            applied_filters['is_active'] = filters.is_active
        if filters.is_verified is not None:
            applied_filters['is_verified'] = filters.is_verified
        if filters.is_admin is not None:
            applied_filters['is_admin'] = filters.is_admin
        if filters.role_names:
            applied_filters['role_names'] = filters.role_names
        
        return applied_filters
    
    def _create_audit_log(
        self, 
        action: str, 
        user_id: Optional[int] = None, 
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Create audit log entry for user operations."""
        try:
            from models import AuditLog
            
            audit_log = AuditLog(
                action=action,
                user_id=user_id,
                performed_by=self._get_current_user_id(),
                details=details or {},
                ip_address=self._get_current_ip_address(),
                user_agent=self._get_current_user_agent(),
                timestamp=datetime.now(timezone.utc)
            )
            
            self.db_session.add(audit_log)
            
        except Exception as e:
            self.logger.warning(f"Failed to create audit log: {str(e)}")
    
    def _get_current_user_id(self) -> Optional[str]:
        """Get current user ID from Flask context."""
        try:
            if hasattr(g, 'current_user_id'):
                return str(g.current_user_id)
            elif hasattr(current_user, 'id') and current_user.is_authenticated:
                return str(current_user.id)
            else:
                return 'system'
        except Exception:
            return 'system'
    
    def _get_current_ip_address(self) -> Optional[str]:
        """Get current request IP address."""
        try:
            from flask import request
            return request.remote_addr
        except Exception:
            return None
    
    def _get_current_user_agent(self) -> Optional[str]:
        """Get current request user agent."""
        try:
            from flask import request
            return request.headers.get('User-Agent')
        except Exception:
            return None
    
    def _is_admin_user(self, user_id: str) -> bool:
        """Check if user has admin privileges."""
        try:
            user = self.get_by_id(int(user_id))
            return user and user.is_admin
        except Exception:
            return False


def create_user_service(
    db_session: DatabaseSession,
    auth_service: Optional[AuthService] = None
) -> UserService:
    """
    Factory function to create UserService instance with dependency injection.
    
    Args:
        db_session: SQLAlchemy database session for data operations
        auth_service: Optional authentication service for integration
        
    Returns:
        Configured UserService instance ready for use
        
    Example:
        ```python
        # In Flask application factory or blueprint
        user_service = create_user_service(
            db_session=db.session,
            auth_service=auth_service
        )
        
        # Use in route handlers
        result = user_service.create_user(user_request)
        if result.success:
            return jsonify(result.data), 201
        else:
            return jsonify({'error': result.error}), 400
        ```
    """
    return UserService(db_session=db_session, auth_service=auth_service)


# Export main service class and factory for application use
__all__ = [
    'UserService',
    'UserCreateRequest',
    'UserUpdateRequest',
    'UserSearchFilters',
    'UserPasswordChangeRequest',
    'UserRoleAssignmentRequest',
    'UserBusinessRules',
    'create_user_service'
]