"""
User Service Layer Implementation for User Management Workflows

This module implements the UserService class following the Service Layer pattern
as specified in Feature F-005 and F-006. The service orchestrates complex user-related
business processes including registration, authentication, profile management, and user
entity operations while maintaining functional equivalence with original Node.js user
business rules.

Key Features:
- User registration and authentication workflow orchestration per Feature F-007
- Flask-Login integration for session management per Section 4.6.1
- User entity relationship management per Section 6.2.2.1
- Comprehensive user profile management with validation
- Service Layer pattern implementation for clean abstraction
- Business logic preservation maintaining Node.js functional equivalence

Architecture Integration:
- Flask-SQLAlchemy integration for database operations per Section 5.2.3
- BaseService inheritance for transaction boundary management
- Flask-Login user loader integration for authentication decorators
- ItsDangerous token management for secure operations
- User session lifecycle coordination with UserSession model
- Comprehensive error handling and validation per Section 4.5.3

Business Logic Coverage:
- User account creation with validation and security controls
- User authentication with credential validation and session management
- User profile updates with business rule enforcement
- User entity ownership and relationship management
- User session management and security operations
- Password management with secure hashing and validation
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

# Flask and Flask extensions
from flask import current_app, g
from flask_login import UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# SQLAlchemy for database operations
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import selectinload, joinedload

# Base service and dependencies
from .base import BaseService, ServiceError, ValidationError, TransactionError, retry_on_failure
from .validation_service import ValidationService

# Models for user management
from ..models.user import User
from ..models.session import UserSession, create_user_session
from ..models.business_entity import BusinessEntity

# Type hints for better code documentation
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ..models.entity_relationship import EntityRelationship

# Logger configuration
logger = logging.getLogger(__name__)


class UserRegistrationError(ServiceError):
    """Exception raised when user registration fails."""
    pass


class UserAuthenticationError(ServiceError):
    """Exception raised when user authentication fails."""
    pass


class UserProfileError(ServiceError):
    """Exception raised when user profile operations fail."""
    pass


class UserSessionError(ServiceError):
    """Exception raised when user session operations fail."""
    pass


class UserService(BaseService):
    """
    User Service implementing business logic for user management workflows.
    
    This service orchestrates complex user-related business processes through the
    Service Layer pattern while maintaining functional equivalence with original
    Node.js user business rules. Provides clean abstraction for user operations
    across multiple Flask blueprints.
    
    Features:
        - User registration workflow with comprehensive validation
        - User authentication with Flask-Login session management
        - User profile management with business rule enforcement
        - User entity relationship coordination and ownership management
        - User session lifecycle management with security controls
        - Password management with secure hashing and validation policies
        - Integration with Flask authentication decorators and Auth0
    
    Service Composition:
        - ValidationService for comprehensive input validation
        - UserSession model for session management
        - BusinessEntity model for entity ownership coordination
        - Flask-Login integration for authentication state management
    
    Example Usage:
        >>> user_service = current_app.injector.get(UserService)
        >>> 
        >>> # User registration
        >>> user_data = {
        ...     'username': 'john_doe',
        ...     'email': 'john@example.com',
        ...     'password': 'SecurePassword123!'
        ... }
        >>> user = user_service.register_user(user_data)
        >>> 
        >>> # User authentication
        >>> authenticated_user = user_service.authenticate_user('john_doe', 'SecurePassword123!')
        >>> if authenticated_user:
        ...     session_token = user_service.create_user_session(authenticated_user.id)
        >>> 
        >>> # User profile update
        >>> profile_updates = {'email': 'john.doe@example.com'}
        >>> updated_user = user_service.update_user_profile(user.id, profile_updates)
    """
    
    def __init__(self, *args, **kwargs):
        """
        Initialize UserService with required dependencies.
        
        Inherits from BaseService for transaction boundary management and
        Flask-SQLAlchemy session handling. Initializes validation service
        composition for business rule enforcement.
        """
        super().__init__(*args, **kwargs)
        
        # Service composition for validation
        self._validation_service = None
        
        # User-specific caching for performance optimization
        self._user_cache_prefix = "user_service"
        
        # Business rule configuration
        self._password_policy = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_digit': True,
            'require_special': True,
            'max_length': 128
        }
        
        # Session configuration
        self._default_session_hours = 24
        self._remember_me_hours = 168  # 7 days
        
        self.logger.info("UserService initialized with comprehensive business logic support")
    
    @property
    def validation_service(self) -> ValidationService:
        """
        Get validation service instance through service composition.
        
        Returns:
            ValidationService: Validation service for business rule enforcement
        """
        if self._validation_service is None:
            self._validation_service = self.compose_service(ValidationService)
        return self._validation_service
    
    def validate_business_rules(self, data: Dict[str, Any]) -> bool:
        """
        Validate user-specific business rules.
        
        Implements abstract method from BaseService for user-specific validation
        including username policies, email format validation, and password security.
        
        Args:
            data: User data to validate
        
        Returns:
            bool: True if validation passes
        
        Raises:
            ValidationError: When business rules are violated
        """
        try:
            # Username validation
            if 'username' in data:
                username = data['username']
                if not self._validate_username(username):
                    raise ValidationError("Username does not meet business requirements")
            
            # Email validation
            if 'email' in data:
                email = data['email']
                if not self._validate_email_format(email):
                    raise ValidationError("Email format does not meet business requirements")
            
            # Password validation
            if 'password' in data:
                password = data['password']
                if not self._validate_password_policy(password):
                    raise ValidationError("Password does not meet security policy requirements")
            
            self.logger.debug("User business rule validation passed")
            return True
            
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error in business rule validation: {e}")
            raise ValidationError(f"Business rule validation failed: {str(e)}")
    
    def _validate_username(self, username: str) -> bool:
        """
        Validate username according to business rules.
        
        Args:
            username: Username to validate
        
        Returns:
            bool: True if username is valid
        """
        if not username or not isinstance(username, str):
            return False
        
        # Username length requirements
        if len(username) < 3 or len(username) > 80:
            return False
        
        # Username character requirements (alphanumeric, underscore, hyphen)
        username_pattern = r'^[a-zA-Z0-9_-]+$'
        if not re.match(username_pattern, username):
            return False
        
        # Username must start with letter or number
        if not username[0].isalnum():
            return False
        
        return True
    
    def _validate_email_format(self, email: str) -> bool:
        """
        Validate email format according to business rules.
        
        Args:
            email: Email address to validate
        
        Returns:
            bool: True if email format is valid
        """
        if not email or not isinstance(email, str):
            return False
        
        # Basic email format validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False
        
        # Email length requirements
        if len(email) < 5 or len(email) > 120:
            return False
        
        return True
    
    def _validate_password_policy(self, password: str) -> bool:
        """
        Validate password according to security policy.
        
        Args:
            password: Password to validate
        
        Returns:
            bool: True if password meets policy requirements
        """
        if not password or not isinstance(password, str):
            return False
        
        policy = self._password_policy
        
        # Length requirements
        if len(password) < policy['min_length'] or len(password) > policy['max_length']:
            return False
        
        # Character requirements
        if policy['require_uppercase'] and not any(c.isupper() for c in password):
            return False
        
        if policy['require_lowercase'] and not any(c.islower() for c in password):
            return False
        
        if policy['require_digit'] and not any(c.isdigit() for c in password):
            return False
        
        if policy['require_special'] and not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            return False
        
        return True
    
    @retry_on_failure(max_retries=3)
    def register_user(self, user_data: Dict[str, Any], 
                     auto_login: bool = False,
                     request_context: Optional[Dict[str, Any]] = None) -> User:
        """
        Register new user with comprehensive validation and security controls.
        
        Implements user registration workflow with business rule validation,
        duplicate checking, secure password hashing, and optional auto-login
        functionality. Maintains functional equivalence with Node.js registration.
        
        Args:
            user_data: User registration data containing username, email, password
            auto_login: Whether to automatically log in user after registration
            request_context: Request context for session creation (user_agent, ip_address)
        
        Returns:
            User: Created user instance
        
        Raises:
            UserRegistrationError: When registration fails due to validation or constraints
            ValidationError: When input validation fails
            TransactionError: When database operations fail
        
        Example:
            >>> user_data = {
            ...     'username': 'john_doe',
            ...     'email': 'john@example.com',
            ...     'password': 'SecurePassword123!'
            ... }
            >>> user = user_service.register_user(user_data, auto_login=True)
            >>> print(f"Registered user: {user.username}")
        """
        try:
            self.log_service_operation("User registration initiated", {'username': user_data.get('username')})
            
            # Validate required fields
            required_fields = ['username', 'email', 'password']
            validated_data = self.validate_input(user_data, required_fields)
            
            # Business rule validation
            self.validate_business_rules(validated_data)
            
            # Check for existing users
            existing_user = self._check_user_existence(
                validated_data['username'], 
                validated_data['email']
            )
            if existing_user:
                raise UserRegistrationError(
                    f"User already exists with username or email"
                )
            
            # Create user within transaction boundary
            with self.transaction_boundary():
                # Create user instance
                user = User(
                    username=validated_data['username'].strip().lower(),
                    email=validated_data['email'].strip().lower(),
                    password=validated_data['password']
                )
                
                # Add additional user fields if provided
                if 'is_active' in validated_data:
                    user.is_active = bool(validated_data['is_active'])
                
                # Save user to database
                self.session.add(user)
                self.session.flush()  # Get user ID without committing
                
                # Auto-login if requested
                session_token = None
                if auto_login:
                    session_token = self._create_user_session_internal(
                        user.id, 
                        request_context
                    )
                    
                    # Flask-Login integration
                    login_user(user)
                
                self.log_service_operation(
                    "User registration completed", 
                    {
                        'user_id': user.id,
                        'username': user.username,
                        'auto_login': auto_login
                    }
                )
                
                # Clear user cache
                self._invalidate_user_cache(user.id)
                
                return user
                
        except ValidationError:
            raise
        except IntegrityError as e:
            self.handle_integrity_error(e, "user registration")
        except Exception as e:
            self.logger.error(f"User registration failed: {e}")
            raise UserRegistrationError(
                "User registration failed due to system error",
                original_error=e
            )
    
    def _check_user_existence(self, username: str, email: str) -> Optional[User]:
        """
        Check if user already exists with given username or email.
        
        Args:
            username: Username to check
            email: Email to check
        
        Returns:
            Optional[User]: Existing user if found, None otherwise
        """
        return User.query.filter(
            (User.username == username.strip().lower()) |
            (User.email == email.strip().lower())
        ).first()
    
    @retry_on_failure(max_retries=3)
    def authenticate_user(self, identifier: str, password: str,
                         remember_me: bool = False,
                         request_context: Optional[Dict[str, Any]] = None) -> Optional[User]:
        """
        Authenticate user with credentials and create session.
        
        Implements user authentication workflow with credential validation,
        Flask-Login integration, and session management. Supports username
        or email identification with secure password verification.
        
        Args:
            identifier: Username or email for authentication
            password: Plain text password for verification
            remember_me: Whether to create extended session for remember-me functionality
            request_context: Request context for session creation
        
        Returns:
            Optional[User]: Authenticated user if credentials are valid, None otherwise
        
        Raises:
            UserAuthenticationError: When authentication fails due to system error
            ValidationError: When input validation fails
        
        Example:
            >>> user = user_service.authenticate_user('john_doe', 'SecurePassword123!')
            >>> if user:
            ...     print(f"Authenticated: {user.username}")
            ... else:
            ...     print("Authentication failed")
        """
        try:
            self.log_service_operation("User authentication initiated", {'identifier': identifier})
            
            # Input validation
            if not identifier or not password:
                self.logger.warning("Authentication failed: missing credentials")
                return None
            
            # Find user by username or email
            user = User.find_by_credentials(identifier.strip(), password)
            
            if not user:
                self.logger.warning(f"Authentication failed for identifier: {identifier}")
                return None
            
            # Check user active status
            if not user.is_active:
                self.logger.warning(f"Authentication failed: user {user.id} is inactive")
                return None
            
            # Create user session
            session_hours = self._remember_me_hours if remember_me else self._default_session_hours
            session_token = self._create_user_session_internal(
                user.id,
                request_context,
                expires_in_hours=session_hours
            )
            
            # Flask-Login integration
            login_user(user, remember=remember_me)
            
            # Update user last accessed time
            user.updated_at = datetime.now(timezone.utc)
            self.session.commit()
            
            self.log_service_operation(
                "User authentication successful", 
                {
                    'user_id': user.id,
                    'username': user.username,
                    'remember_me': remember_me
                }
            )
            
            return user
            
        except Exception as e:
            self.logger.error(f"User authentication error: {e}")
            raise UserAuthenticationError(
                "Authentication failed due to system error",
                original_error=e
            )
    
    def _create_user_session_internal(self, user_id: int,
                                    request_context: Optional[Dict[str, Any]] = None,
                                    expires_in_hours: int = None) -> str:
        """
        Internal method to create user session with context.
        
        Args:
            user_id: User ID for session creation
            request_context: Request context with user_agent, ip_address
            expires_in_hours: Session expiration in hours
        
        Returns:
            str: Session token
        
        Raises:
            UserSessionError: When session creation fails
        """
        try:
            if expires_in_hours is None:
                expires_in_hours = self._default_session_hours
            
            # Extract context information
            user_agent = None
            ip_address = None
            
            if request_context:
                user_agent = request_context.get('user_agent')
                ip_address = request_context.get('ip_address')
            
            # Create session using UserSession model
            session = UserSession.create_session(
                user_id=user_id,
                expires_in_hours=expires_in_hours,
                user_agent=user_agent,
                ip_address=ip_address
            )
            
            return session.session_token
            
        except Exception as e:
            self.logger.error(f"Session creation failed for user {user_id}: {e}")
            raise UserSessionError(
                "Failed to create user session",
                original_error=e
            )
    
    @retry_on_failure(max_retries=2)
    def logout_user(self, user_id: Optional[int] = None,
                   invalidate_all_sessions: bool = False) -> bool:
        """
        Logout user and invalidate sessions.
        
        Implements user logout workflow with session invalidation and
        Flask-Login integration. Supports single session or all session
        invalidation for security purposes.
        
        Args:
            user_id: User ID to logout (uses current user if None)
            invalidate_all_sessions: Whether to invalidate all user sessions
        
        Returns:
            bool: True if logout successful
        
        Raises:
            UserSessionError: When logout operations fail
        
        Example:
            >>> success = user_service.logout_user(user_id=1, invalidate_all_sessions=True)
            >>> if success:
            ...     print("User logged out successfully")
        """
        try:
            # Get user ID from current user if not provided
            if user_id is None:
                if hasattr(current_user, 'id'):
                    user_id = current_user.id
                else:
                    user_id = self.get_current_user_id()
            
            if not user_id:
                self.logger.warning("Logout attempted without valid user ID")
                return False
            
            self.log_service_operation("User logout initiated", {'user_id': user_id})
            
            # Invalidate sessions
            if invalidate_all_sessions:
                invalidated_count = UserSession.invalidate_user_sessions(user_id)
                self.logger.info(f"Invalidated {invalidated_count} sessions for user {user_id}")
            else:
                # Invalidate current session only
                current_session_id = getattr(g, 'current_session_id', None)
                if current_session_id:
                    UserSession.invalidate_user_sessions(
                        user_id, 
                        exclude_session_id=current_session_id
                    )
            
            # Flask-Login logout
            logout_user()
            
            # Clear user cache
            self._invalidate_user_cache(user_id)
            
            self.log_service_operation(
                "User logout completed", 
                {
                    'user_id': user_id,
                    'invalidate_all': invalidate_all_sessions
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"User logout error: {e}")
            raise UserSessionError(
                "Logout failed due to system error",
                original_error=e
            )
    
    @retry_on_failure(max_retries=3)
    def update_user_profile(self, user_id: int, 
                           profile_data: Dict[str, Any],
                           current_password: Optional[str] = None) -> User:
        """
        Update user profile with business rule validation.
        
        Implements user profile update workflow with validation, constraint
        checking, and security controls. Supports email updates, password
        changes, and profile metadata modifications.
        
        Args:
            user_id: User ID to update
            profile_data: Profile data to update
            current_password: Current password for sensitive updates
        
        Returns:
            User: Updated user instance
        
        Raises:
            UserProfileError: When profile update fails
            ValidationError: When validation fails
            TransactionError: When database operations fail
        
        Example:
            >>> profile_updates = {
            ...     'email': 'john.doe@example.com',
            ...     'password': 'NewSecurePassword123!'
            ... }
            >>> updated_user = user_service.update_user_profile(
            ...     user_id=1,
            ...     profile_data=profile_updates,
            ...     current_password='OldPassword123!'
            ... )
        """
        try:
            self.log_service_operation("User profile update initiated", {'user_id': user_id})
            
            # Get user instance
            user = self.get_user_by_id(user_id)
            if not user:
                raise UserProfileError(f"User not found: {user_id}")
            
            # Validate input data
            validated_data = self.validate_input(profile_data)
            
            # Check if sensitive updates require current password
            sensitive_fields = {'email', 'password'}
            if any(field in validated_data for field in sensitive_fields):
                if not current_password or not user.check_password(current_password):
                    raise UserProfileError("Current password required for sensitive updates")
            
            # Business rule validation for updates
            self.validate_business_rules(validated_data)
            
            # Update user within transaction boundary
            with self.transaction_boundary():
                updates_made = []
                
                # Update email if provided
                if 'email' in validated_data:
                    new_email = validated_data['email'].strip().lower()
                    if new_email != user.email:
                        # Check email uniqueness
                        existing_user = User.find_by_email(new_email)
                        if existing_user and existing_user.id != user.id:
                            raise UserProfileError("Email address is already in use")
                        
                        user.email = new_email
                        updates_made.append('email')
                
                # Update password if provided
                if 'password' in validated_data:
                    user.set_password(validated_data['password'])
                    updates_made.append('password')
                    
                    # Invalidate all other sessions for security
                    UserSession.invalidate_user_sessions(
                        user_id, 
                        exclude_session_id=getattr(g, 'current_session_id', None)
                    )
                
                # Update other allowed fields
                allowed_fields = {'is_active'}
                for field in allowed_fields:
                    if field in validated_data:
                        setattr(user, field, validated_data[field])
                        updates_made.append(field)
                
                # Update timestamp
                user.updated_at = datetime.now(timezone.utc)
                
                # Commit changes
                self.session.commit()
                
                self.log_service_operation(
                    "User profile update completed", 
                    {
                        'user_id': user_id,
                        'updates_made': updates_made
                    }
                )
                
                # Clear user cache
                self._invalidate_user_cache(user_id)
                
                return user
                
        except ValidationError:
            raise
        except IntegrityError as e:
            self.handle_integrity_error(e, "user profile update")
        except Exception as e:
            self.logger.error(f"User profile update failed: {e}")
            raise UserProfileError(
                "Profile update failed due to system error",
                original_error=e
            )
    
    def get_user_by_id(self, user_id: int, 
                      include_sessions: bool = False,
                      include_entities: bool = False) -> Optional[User]:
        """
        Get user by ID with optional relationship loading.
        
        Args:
            user_id: User ID to retrieve
            include_sessions: Whether to eagerly load user sessions
            include_entities: Whether to eagerly load user business entities
        
        Returns:
            Optional[User]: User instance if found, None otherwise
        
        Example:
            >>> user = user_service.get_user_by_id(1, include_sessions=True)
            >>> if user:
            ...     print(f"User {user.username} has {len(user.sessions)} sessions")
        """
        try:
            # Check cache first
            cache_key = f"{self._user_cache_prefix}:user:{user_id}"
            cached_user = self.get_cached_result(cache_key)
            if cached_user and not (include_sessions or include_entities):
                return cached_user
            
            # Build query with optional eager loading
            query = User.query.filter_by(id=user_id)
            
            if include_sessions:
                query = query.options(selectinload(User.sessions))
            
            if include_entities:
                query = query.options(selectinload(User.business_entities))
            
            user = query.first()
            
            # Cache result if no relationships loaded
            if user and not (include_sessions or include_entities):
                self.cache_result(cache_key, user, ttl=300)
            
            return user
            
        except Exception as e:
            self.logger.error(f"Failed to get user {user_id}: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username with caching.
        
        Args:
            username: Username to search for
        
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        try:
            # Check cache first
            cache_key = f"{self._user_cache_prefix}:username:{username.lower()}"
            cached_user = self.get_cached_result(cache_key)
            if cached_user:
                return cached_user
            
            user = User.find_by_username(username)
            
            # Cache result
            if user:
                self.cache_result(cache_key, user, ttl=300)
            
            return user
            
        except Exception as e:
            self.logger.error(f"Failed to get user by username {username}: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email with caching.
        
        Args:
            email: Email address to search for
        
        Returns:
            Optional[User]: User instance if found, None otherwise
        """
        try:
            # Check cache first
            cache_key = f"{self._user_cache_prefix}:email:{email.lower()}"
            cached_user = self.get_cached_result(cache_key)
            if cached_user:
                return cached_user
            
            user = User.find_by_email(email)
            
            # Cache result
            if user:
                self.cache_result(cache_key, user, ttl=300)
            
            return user
            
        except Exception as e:
            self.logger.error(f"Failed to get user by email {email}: {e}")
            return None
    
    def get_user_sessions(self, user_id: int, active_only: bool = True) -> List[UserSession]:
        """
        Get user sessions with filtering options.
        
        Args:
            user_id: User ID to get sessions for
            active_only: Whether to return only active sessions
        
        Returns:
            List[UserSession]: List of user sessions
        
        Example:
            >>> sessions = user_service.get_user_sessions(user_id=1)
            >>> print(f"User has {len(sessions)} active sessions")
        """
        try:
            return UserSession.get_user_sessions(user_id, active_only)
        except Exception as e:
            self.logger.error(f"Failed to get sessions for user {user_id}: {e}")
            return []
    
    def get_user_business_entities(self, user_id: int, 
                                  status_filter: Optional[str] = 'active') -> List[BusinessEntity]:
        """
        Get business entities owned by user.
        
        Args:
            user_id: User ID to get entities for
            status_filter: Status filter for entities (None for all)
        
        Returns:
            List[BusinessEntity]: List of owned business entities
        
        Example:
            >>> entities = user_service.get_user_business_entities(user_id=1)
            >>> print(f"User owns {len(entities)} active entities")
        """
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return []
            
            query = user.business_entities
            
            if status_filter:
                query = query.filter_by(status=status_filter)
            
            return query.all()
            
        except Exception as e:
            self.logger.error(f"Failed to get entities for user {user_id}: {e}")
            return []
    
    def create_user_session(self, user_id: int,
                           request_context: Optional[Dict[str, Any]] = None,
                           expires_in_hours: int = None) -> Optional[str]:
        """
        Create user session with context information.
        
        Args:
            user_id: User ID to create session for
            request_context: Request context with user_agent, ip_address
            expires_in_hours: Session expiration in hours
        
        Returns:
            Optional[str]: Session token if successful, None otherwise
        
        Example:
            >>> context = {
            ...     'user_agent': 'Mozilla/5.0...',
            ...     'ip_address': '192.168.1.1'
            ... }
            >>> token = user_service.create_user_session(user_id=1, request_context=context)
        """
        try:
            return self._create_user_session_internal(
                user_id, 
                request_context, 
                expires_in_hours
            )
        except Exception as e:
            self.logger.error(f"Failed to create session for user {user_id}: {e}")
            return None
    
    def validate_user_session(self, session_token: str) -> Optional[User]:
        """
        Validate user session and return associated user.
        
        Args:
            session_token: Session token to validate
        
        Returns:
            Optional[User]: User instance if session is valid, None otherwise
        
        Example:
            >>> user = user_service.validate_user_session(session_token)
            >>> if user:
            ...     print(f"Valid session for user: {user.username}")
        """
        try:
            session = UserSession.validate_session(session_token)
            if session and session.is_active():
                return self.get_user_by_id(session.user_id)
            return None
        except Exception as e:
            self.logger.error(f"Session validation failed: {e}")
            return None
    
    def invalidate_user_sessions(self, user_id: int,
                               exclude_session_id: Optional[int] = None) -> int:
        """
        Invalidate user sessions for security purposes.
        
        Args:
            user_id: User ID to invalidate sessions for
            exclude_session_id: Session ID to exclude from invalidation
        
        Returns:
            int: Number of sessions invalidated
        
        Example:
            >>> count = user_service.invalidate_user_sessions(user_id=1)
            >>> print(f"Invalidated {count} sessions")
        """
        try:
            count = UserSession.invalidate_user_sessions(user_id, exclude_session_id)
            self._invalidate_user_cache(user_id)
            return count
        except Exception as e:
            self.logger.error(f"Failed to invalidate sessions for user {user_id}: {e}")
            return 0
    
    def change_user_password(self, user_id: int, 
                           current_password: str,
                           new_password: str,
                           invalidate_sessions: bool = True) -> bool:
        """
        Change user password with security controls.
        
        Args:
            user_id: User ID for password change
            current_password: Current password for verification
            new_password: New password to set
            invalidate_sessions: Whether to invalidate other sessions
        
        Returns:
            bool: True if password change successful
        
        Raises:
            UserProfileError: When password change fails
            ValidationError: When validation fails
        
        Example:
            >>> success = user_service.change_user_password(
            ...     user_id=1,
            ...     current_password='OldPassword123!',
            ...     new_password='NewSecurePassword123!'
            ... )
        """
        try:
            return self.update_user_profile(
                user_id,
                {'password': new_password},
                current_password=current_password
            ) is not None
        except Exception as e:
            self.logger.error(f"Password change failed for user {user_id}: {e}")
            raise UserProfileError(
                "Password change failed",
                original_error=e
            )
    
    def deactivate_user(self, user_id: int, 
                       reason: Optional[str] = None) -> bool:
        """
        Deactivate user account and invalidate sessions.
        
        Args:
            user_id: User ID to deactivate
            reason: Reason for deactivation
        
        Returns:
            bool: True if deactivation successful
        
        Example:
            >>> success = user_service.deactivate_user(user_id=1, reason="Account suspended")
        """
        try:
            # Update user status
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            with self.transaction_boundary():
                user.is_active = False
                user.updated_at = datetime.now(timezone.utc)
                
                # Invalidate all sessions
                UserSession.invalidate_user_sessions(user_id)
                
                self.log_service_operation(
                    "User deactivated", 
                    {
                        'user_id': user_id,
                        'reason': reason
                    }
                )
                
                # Clear cache
                self._invalidate_user_cache(user_id)
                
                return True
                
        except Exception as e:
            self.logger.error(f"User deactivation failed for user {user_id}: {e}")
            return False
    
    def reactivate_user(self, user_id: int) -> bool:
        """
        Reactivate user account.
        
        Args:
            user_id: User ID to reactivate
        
        Returns:
            bool: True if reactivation successful
        
        Example:
            >>> success = user_service.reactivate_user(user_id=1)
        """
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return False
            
            with self.transaction_boundary():
                user.is_active = True
                user.updated_at = datetime.now(timezone.utc)
                
                self.log_service_operation("User reactivated", {'user_id': user_id})
                
                # Clear cache
                self._invalidate_user_cache(user_id)
                
                return True
                
        except Exception as e:
            self.logger.error(f"User reactivation failed for user {user_id}: {e}")
            return False
    
    def get_user_statistics(self) -> Dict[str, Any]:
        """
        Get user statistics for monitoring and analytics.
        
        Returns:
            Dict[str, Any]: User statistics
        
        Example:
            >>> stats = user_service.get_user_statistics()
            >>> print(f"Total users: {stats['total_users']}")
        """
        try:
            current_time = datetime.now(timezone.utc)
            
            # Count total users
            total_users = User.query.count()
            
            # Count active users
            active_users = User.query.filter_by(is_active=True).count()
            
            # Count users created today
            today_start = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
            users_created_today = User.query.filter(
                User.created_at >= today_start
            ).count()
            
            # Count users created this week
            week_start = current_time - timedelta(days=7)
            users_created_week = User.query.filter(
                User.created_at >= week_start
            ).count()
            
            # Get session statistics
            session_stats = UserSession.get_session_statistics()
            
            statistics = {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': total_users - active_users,
                'users_created_today': users_created_today,
                'users_created_week': users_created_week,
                'session_statistics': session_stats,
                'generated_at': current_time.isoformat()
            }
            
            return statistics
            
        except Exception as e:
            self.logger.error(f"Failed to generate user statistics: {e}")
            return {
                'error': str(e),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
    
    def cleanup_expired_sessions(self, batch_size: int = 1000) -> int:
        """
        Clean up expired user sessions.
        
        Args:
            batch_size: Number of sessions to clean up per batch
        
        Returns:
            int: Number of sessions cleaned up
        
        Example:
            >>> count = user_service.cleanup_expired_sessions()
            >>> print(f"Cleaned up {count} expired sessions")
        """
        try:
            return UserSession.cleanup_expired_sessions(batch_size)
        except Exception as e:
            self.logger.error(f"Session cleanup failed: {e}")
            return 0
    
    def _invalidate_user_cache(self, user_id: int) -> None:
        """
        Invalidate all cached data for a user.
        
        Args:
            user_id: User ID to invalidate cache for
        """
        try:
            # Clear specific user cache keys
            cache_keys = [
                f"{self._user_cache_prefix}:user:{user_id}",
            ]
            
            for key in cache_keys:
                if key in self._session_cache:
                    del self._session_cache[key]
            
            self.logger.debug(f"Invalidated cache for user {user_id}")
            
        except Exception as e:
            self.logger.error(f"Cache invalidation failed for user {user_id}: {e}")
    
    def user_loader_callback(self, user_id: str) -> Optional[UserMixin]:
        """
        Flask-Login user loader callback function.
        
        This method is used by Flask-Login to load user instances from
        user IDs stored in sessions. Integrates with the service layer
        for consistent user management.
        
        Args:
            user_id: String representation of user ID
        
        Returns:
            Optional[UserMixin]: User instance if found, None otherwise
        
        Example:
            >>> # Register with Flask-Login
            >>> @login_manager.user_loader
            >>> def load_user(user_id):
            ...     return user_service.user_loader_callback(user_id)
        """
        try:
            if not user_id or not user_id.isdigit():
                return None
            
            user = self.get_user_by_id(int(user_id))
            return user if user and user.is_active else None
            
        except Exception as e:
            self.logger.error(f"User loader callback failed for user_id {user_id}: {e}")
            return None


# Module exports for organized import management
__all__ = [
    'UserService',
    'UserRegistrationError',
    'UserAuthenticationError', 
    'UserProfileError',
    'UserSessionError'
]