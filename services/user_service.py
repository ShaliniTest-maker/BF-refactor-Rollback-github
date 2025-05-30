"""
User Management Service

This service implements comprehensive user management business logic following the Flask Service Layer
pattern. It provides type-safe user operations with SQLAlchemy integration, dependency injection,
and enhanced testability through Pytest fixtures.

Key Features:
- Service Layer pattern implementation per Section 4.5.1.2
- Type-safe user operations with comprehensive type annotations per Section 4.5.1.3  
- SQLAlchemy session injection for database operations per Section 4.5.1.2
- Business logic preservation maintaining existing user management rules per Section 4.5.1.1
- Enhanced testability through Pytest fixtures and mock dependencies per Section 4.5.1.4
"""

from typing import Optional, List, Dict, Any, Union, Tuple
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from enum import Enum

from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import and_, or_, func, desc, asc
from werkzeug.security import generate_password_hash, check_password_hash

from services.base_service import BaseService
from services.auth_service import AuthService
from models import User, UserSession, Role, Permission


# Configure logging
logger = logging.getLogger(__name__)


class UserStatus(Enum):
    """User account status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    DELETED = "deleted"


@dataclass
class UserSearchCriteria:
    """Type-safe search criteria for user queries"""
    email: Optional[str] = None
    username: Optional[str] = None
    status: Optional[UserStatus] = None
    role_names: Optional[List[str]] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    include_inactive: bool = False
    limit: Optional[int] = None
    offset: Optional[int] = None
    order_by: Optional[str] = None
    order_direction: str = "asc"


@dataclass
class UserCreationData:
    """Type-safe user creation data structure"""
    username: str
    email: str
    password: Optional[str] = None
    auth0_user_id: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role_names: Optional[List[str]] = None
    is_active: bool = True
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class UserUpdateData:
    """Type-safe user update data structure"""
    username: Optional[str] = None
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
    role_names: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    last_login: Optional[datetime] = None


@dataclass
class UserValidationResult:
    """Type-safe validation result structure"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    
    def add_error(self, error: str) -> None:
        """Add validation error"""
        self.errors.append(error)
        self.is_valid = False
    
    def add_warning(self, warning: str) -> None:
        """Add validation warning"""
        self.warnings.append(warning)


@dataclass
class UserOperationResult:
    """Type-safe operation result structure"""
    success: bool
    user: Optional[User] = None
    error_message: Optional[str] = None
    validation_errors: Optional[List[str]] = None
    
    @classmethod
    def success_result(cls, user: User) -> 'UserOperationResult':
        """Create successful operation result"""
        return cls(success=True, user=user)
    
    @classmethod
    def error_result(cls, error_message: str, validation_errors: Optional[List[str]] = None) -> 'UserOperationResult':
        """Create error operation result"""
        return cls(
            success=False, 
            error_message=error_message,
            validation_errors=validation_errors or []
        )


class UserServiceError(Exception):
    """Custom exception for user service operations"""
    pass


class UserNotFoundError(UserServiceError):
    """Exception raised when user is not found"""
    pass


class UserValidationError(UserServiceError):
    """Exception raised when user validation fails"""
    def __init__(self, message: str, validation_errors: List[str]):
        super().__init__(message)
        self.validation_errors = validation_errors


class DuplicateUserError(UserServiceError):
    """Exception raised when attempting to create duplicate user"""
    pass


class UserService(BaseService):
    """
    User Management Service implementing comprehensive user operations.
    
    This service provides type-safe user management capabilities including:
    - User CRUD operations with validation
    - User profile management
    - Role and permission handling
    - Authentication support
    - Session management
    - Business logic orchestration
    
    The service follows Flask Service Layer pattern with dependency injection
    and comprehensive type annotations for enhanced maintainability and testability.
    """
    
    def __init__(self, db_session: Session, auth_service: Optional[AuthService] = None):
        """
        Initialize User Service with dependency injection.
        
        Args:
            db_session: SQLAlchemy database session for transaction management
            auth_service: Optional authentication service for password operations
        """
        super().__init__(db_session)
        self.auth_service = auth_service or AuthService(db_session)
        logger.info("UserService initialized with database session and authentication service")
    
    # User Creation and Management
    
    def create_user(self, user_data: UserCreationData) -> UserOperationResult:
        """
        Create new user with comprehensive validation and business logic.
        
        Args:
            user_data: Type-safe user creation data structure
            
        Returns:
            UserOperationResult with success status and user object or error details
            
        Raises:
            UserValidationError: If validation fails
            DuplicateUserError: If user already exists
            UserServiceError: For other service-level errors
        """
        try:
            logger.info(f"Creating new user with username: {user_data.username}")
            
            # Validate user data
            validation_result = self._validate_user_creation_data(user_data)
            if not validation_result.is_valid:
                logger.warning(f"User creation validation failed: {validation_result.errors}")
                raise UserValidationError("User validation failed", validation_result.errors)
            
            # Check for duplicate users
            self._check_duplicate_user(user_data.username, user_data.email)
            
            # Begin transaction
            with self.db_session.begin():
                # Create user instance
                user = User(
                    username=user_data.username,
                    email=user_data.email,
                    auth0_user_id=user_data.auth0_user_id,
                    first_name=user_data.first_name,
                    last_name=user_data.last_name,
                    is_active=user_data.is_active,
                    metadata=user_data.metadata or {},
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                # Set password if provided
                if user_data.password:
                    user.password_hash = generate_password_hash(user_data.password)
                
                # Add user to session
                self.db_session.add(user)
                self.db_session.flush()  # Get user ID for role assignment
                
                # Assign roles if specified
                if user_data.role_names:
                    self._assign_roles_to_user(user, user_data.role_names)
                
                # Final validation and commit handled by context manager
                logger.info(f"Successfully created user with ID: {user.id}")
                return UserOperationResult.success_result(user)
                
        except UserValidationError:
            raise
        except DuplicateUserError:
            raise
        except IntegrityError as e:
            logger.error(f"Database integrity error creating user: {str(e)}")
            raise DuplicateUserError(f"User with username '{user_data.username}' or email '{user_data.email}' already exists")
        except SQLAlchemyError as e:
            logger.error(f"Database error creating user: {str(e)}")
            raise UserServiceError(f"Database error occurred while creating user: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error creating user: {str(e)}")
            raise UserServiceError(f"Unexpected error occurred while creating user: {str(e)}")
    
    def update_user(self, user_id: int, update_data: UserUpdateData) -> UserOperationResult:
        """
        Update existing user with validation and business logic.
        
        Args:
            user_id: ID of user to update
            update_data: Type-safe user update data structure
            
        Returns:
            UserOperationResult with success status and updated user or error details
        """
        try:
            logger.info(f"Updating user with ID: {user_id}")
            
            # Retrieve user
            user = self.get_user_by_id(user_id, include_roles=True)
            if not user:
                return UserOperationResult.error_result(f"User with ID {user_id} not found")
            
            # Validate update data
            validation_result = self._validate_user_update_data(update_data, user)
            if not validation_result.is_valid:
                logger.warning(f"User update validation failed: {validation_result.errors}")
                return UserOperationResult.error_result(
                    "User validation failed", 
                    validation_result.errors
                )
            
            # Begin transaction
            with self.db_session.begin():
                # Update user fields
                if update_data.username is not None:
                    user.username = update_data.username
                if update_data.email is not None:
                    user.email = update_data.email
                if update_data.first_name is not None:
                    user.first_name = update_data.first_name
                if update_data.last_name is not None:
                    user.last_name = update_data.last_name
                if update_data.is_active is not None:
                    user.is_active = update_data.is_active
                if update_data.last_login is not None:
                    user.last_login = update_data.last_login
                if update_data.metadata is not None:
                    user.metadata = {**(user.metadata or {}), **update_data.metadata}
                
                # Update timestamp
                user.updated_at = datetime.utcnow()
                
                # Update roles if specified
                if update_data.role_names is not None:
                    self._update_user_roles(user, update_data.role_names)
                
                logger.info(f"Successfully updated user with ID: {user_id}")
                return UserOperationResult.success_result(user)
                
        except SQLAlchemyError as e:
            logger.error(f"Database error updating user: {str(e)}")
            return UserOperationResult.error_result(f"Database error occurred while updating user: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error updating user: {str(e)}")
            return UserOperationResult.error_result(f"Unexpected error occurred while updating user: {str(e)}")
    
    def delete_user(self, user_id: int, soft_delete: bool = True) -> UserOperationResult:
        """
        Delete user with soft or hard delete options.
        
        Args:
            user_id: ID of user to delete
            soft_delete: If True, mark as deleted; if False, remove from database
            
        Returns:
            UserOperationResult indicating success or failure
        """
        try:
            logger.info(f"Deleting user with ID: {user_id}, soft_delete: {soft_delete}")
            
            # Retrieve user
            user = self.get_user_by_id(user_id)
            if not user:
                return UserOperationResult.error_result(f"User with ID {user_id} not found")
            
            # Begin transaction
            with self.db_session.begin():
                if soft_delete:
                    # Soft delete - mark as inactive and deleted
                    user.is_active = False
                    user.status = UserStatus.DELETED.value
                    user.deleted_at = datetime.utcnow()
                    user.updated_at = datetime.utcnow()
                    
                    # Invalidate all user sessions
                    self._invalidate_user_sessions(user_id)
                    
                    logger.info(f"Successfully soft deleted user with ID: {user_id}")
                else:
                    # Hard delete - remove from database
                    # First remove all user sessions
                    self.db_session.query(UserSession).filter(
                        UserSession.user_id == user_id
                    ).delete()
                    
                    # Remove user
                    self.db_session.delete(user)
                    
                    logger.info(f"Successfully hard deleted user with ID: {user_id}")
                
                return UserOperationResult.success_result(user)
                
        except SQLAlchemyError as e:
            logger.error(f"Database error deleting user: {str(e)}")
            return UserOperationResult.error_result(f"Database error occurred while deleting user: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error deleting user: {str(e)}")
            return UserOperationResult.error_result(f"Unexpected error occurred while deleting user: {str(e)}")
    
    # User Retrieval Methods
    
    def get_user_by_id(self, user_id: int, include_roles: bool = False, include_sessions: bool = False) -> Optional[User]:
        """
        Retrieve user by ID with optional relationship loading.
        
        Args:
            user_id: User ID to retrieve
            include_roles: Whether to include user roles
            include_sessions: Whether to include user sessions
            
        Returns:
            User object if found, None otherwise
        """
        try:
            query = self.db_session.query(User)
            
            # Configure relationship loading
            if include_roles:
                query = query.options(joinedload(User.roles))
            if include_sessions:
                query = query.options(selectinload(User.sessions))
            
            user = query.filter(User.id == user_id).first()
            
            if user:
                logger.debug(f"Retrieved user with ID: {user_id}")
            else:
                logger.debug(f"User with ID {user_id} not found")
            
            return user
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by ID {user_id}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by ID {user_id}: {str(e)}")
            return None
    
    def get_user_by_username(self, username: str, include_roles: bool = False) -> Optional[User]:
        """
        Retrieve user by username.
        
        Args:
            username: Username to search for
            include_roles: Whether to include user roles
            
        Returns:
            User object if found, None otherwise
        """
        try:
            query = self.db_session.query(User)
            
            if include_roles:
                query = query.options(joinedload(User.roles))
            
            user = query.filter(User.username == username).first()
            
            if user:
                logger.debug(f"Retrieved user with username: {username}")
            else:
                logger.debug(f"User with username '{username}' not found")
            
            return user
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by username '{username}': {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by username '{username}': {str(e)}")
            return None
    
    def get_user_by_email(self, email: str, include_roles: bool = False) -> Optional[User]:
        """
        Retrieve user by email address.
        
        Args:
            email: Email address to search for
            include_roles: Whether to include user roles
            
        Returns:
            User object if found, None otherwise
        """
        try:
            query = self.db_session.query(User)
            
            if include_roles:
                query = query.options(joinedload(User.roles))
            
            user = query.filter(User.email == email).first()
            
            if user:
                logger.debug(f"Retrieved user with email: {email}")
            else:
                logger.debug(f"User with email '{email}' not found")
            
            return user
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by email '{email}': {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by email '{email}': {str(e)}")
            return None
    
    def get_user_by_auth0_id(self, auth0_user_id: str) -> Optional[User]:
        """
        Retrieve user by Auth0 user ID.
        
        Args:
            auth0_user_id: Auth0 user identifier
            
        Returns:
            User object if found, None otherwise
        """
        try:
            user = self.db_session.query(User).filter(
                User.auth0_user_id == auth0_user_id
            ).first()
            
            if user:
                logger.debug(f"Retrieved user with Auth0 ID: {auth0_user_id}")
            else:
                logger.debug(f"User with Auth0 ID '{auth0_user_id}' not found")
            
            return user
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by Auth0 ID '{auth0_user_id}': {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error retrieving user by Auth0 ID '{auth0_user_id}': {str(e)}")
            return None
    
    def search_users(self, criteria: UserSearchCriteria) -> Tuple[List[User], int]:
        """
        Search users based on comprehensive criteria.
        
        Args:
            criteria: Type-safe search criteria structure
            
        Returns:
            Tuple of (users_list, total_count)
        """
        try:
            # Base query
            query = self.db_session.query(User)
            count_query = self.db_session.query(func.count(User.id))
            
            # Apply filters
            filters = []
            
            if criteria.email:
                filters.append(User.email.ilike(f"%{criteria.email}%"))
            
            if criteria.username:
                filters.append(User.username.ilike(f"%{criteria.username}%"))
            
            if criteria.status:
                filters.append(User.status == criteria.status.value)
            
            if not criteria.include_inactive:
                filters.append(User.is_active == True)
            
            if criteria.created_after:
                filters.append(User.created_at >= criteria.created_after)
            
            if criteria.created_before:
                filters.append(User.created_at <= criteria.created_before)
            
            if criteria.role_names:
                query = query.join(User.roles).filter(Role.name.in_(criteria.role_names))
                count_query = count_query.join(User.roles).filter(Role.name.in_(criteria.role_names))
            
            # Apply all filters
            if filters:
                query = query.filter(and_(*filters))
                count_query = count_query.filter(and_(*filters))
            
            # Get total count
            total_count = count_query.scalar()
            
            # Apply ordering
            if criteria.order_by:
                order_column = getattr(User, criteria.order_by, None)
                if order_column:
                    if criteria.order_direction.lower() == "desc":
                        query = query.order_by(desc(order_column))
                    else:
                        query = query.order_by(asc(order_column))
                else:
                    logger.warning(f"Invalid order_by column: {criteria.order_by}")
            else:
                query = query.order_by(User.created_at.desc())
            
            # Apply pagination
            if criteria.offset:
                query = query.offset(criteria.offset)
            
            if criteria.limit:
                query = query.limit(criteria.limit)
            
            users = query.all()
            
            logger.info(f"User search returned {len(users)} users out of {total_count} total")
            return users, total_count
            
        except SQLAlchemyError as e:
            logger.error(f"Database error searching users: {str(e)}")
            return [], 0
        except Exception as e:
            logger.error(f"Unexpected error searching users: {str(e)}")
            return [], 0
    
    # User Authentication Support
    
    def authenticate_user(self, identifier: str, password: str) -> Optional[User]:
        """
        Authenticate user by username/email and password.
        
        Args:
            identifier: Username or email address
            password: Plain text password
            
        Returns:
            User object if authentication successful, None otherwise
        """
        try:
            # Find user by username or email
            user = self.db_session.query(User).filter(
                or_(User.username == identifier, User.email == identifier)
            ).first()
            
            if not user:
                logger.info(f"Authentication failed: user not found for identifier '{identifier}'")
                return None
            
            if not user.is_active:
                logger.info(f"Authentication failed: user '{identifier}' is not active")
                return None
            
            if not user.password_hash:
                logger.info(f"Authentication failed: user '{identifier}' has no password set")
                return None
            
            # Verify password
            if check_password_hash(user.password_hash, password):
                # Update last login
                user.last_login = datetime.utcnow()
                user.updated_at = datetime.utcnow()
                self.db_session.commit()
                
                logger.info(f"Authentication successful for user '{identifier}'")
                return user
            else:
                logger.info(f"Authentication failed: invalid password for user '{identifier}'")
                return None
                
        except SQLAlchemyError as e:
            logger.error(f"Database error during authentication: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during authentication: {str(e)}")
            return None
    
    def change_user_password(self, user_id: int, current_password: str, new_password: str) -> UserOperationResult:
        """
        Change user password with current password verification.
        
        Args:
            user_id: ID of user whose password to change
            current_password: Current password for verification
            new_password: New password to set
            
        Returns:
            UserOperationResult indicating success or failure
        """
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return UserOperationResult.error_result(f"User with ID {user_id} not found")
            
            # Verify current password
            if not user.password_hash or not check_password_hash(user.password_hash, current_password):
                return UserOperationResult.error_result("Current password is incorrect")
            
            # Validate new password
            validation_result = self._validate_password(new_password)
            if not validation_result.is_valid:
                return UserOperationResult.error_result(
                    "Password validation failed",
                    validation_result.errors
                )
            
            # Update password
            with self.db_session.begin():
                user.password_hash = generate_password_hash(new_password)
                user.updated_at = datetime.utcnow()
                
                # Optionally invalidate all existing sessions for security
                self._invalidate_user_sessions(user_id)
            
            logger.info(f"Password changed successfully for user ID: {user_id}")
            return UserOperationResult.success_result(user)
            
        except SQLAlchemyError as e:
            logger.error(f"Database error changing password: {str(e)}")
            return UserOperationResult.error_result(f"Database error occurred while changing password: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error changing password: {str(e)}")
            return UserOperationResult.error_result(f"Unexpected error occurred while changing password: {str(e)}")
    
    def reset_user_password(self, user_id: int, new_password: str) -> UserOperationResult:
        """
        Reset user password (admin operation, no current password verification).
        
        Args:
            user_id: ID of user whose password to reset
            new_password: New password to set
            
        Returns:
            UserOperationResult indicating success or failure
        """
        try:
            user = self.get_user_by_id(user_id)
            if not user:
                return UserOperationResult.error_result(f"User with ID {user_id} not found")
            
            # Validate new password
            validation_result = self._validate_password(new_password)
            if not validation_result.is_valid:
                return UserOperationResult.error_result(
                    "Password validation failed",
                    validation_result.errors
                )
            
            # Reset password
            with self.db_session.begin():
                user.password_hash = generate_password_hash(new_password)
                user.updated_at = datetime.utcnow()
                
                # Invalidate all existing sessions for security
                self._invalidate_user_sessions(user_id)
            
            logger.info(f"Password reset successfully for user ID: {user_id}")
            return UserOperationResult.success_result(user)
            
        except SQLAlchemyError as e:
            logger.error(f"Database error resetting password: {str(e)}")
            return UserOperationResult.error_result(f"Database error occurred while resetting password: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error resetting password: {str(e)}")
            return UserOperationResult.error_result(f"Unexpected error occurred while resetting password: {str(e)}")
    
    # User Session Management
    
    def get_user_sessions(self, user_id: int, include_expired: bool = False) -> List[UserSession]:
        """
        Get all sessions for a user.
        
        Args:
            user_id: User ID to get sessions for
            include_expired: Whether to include expired sessions
            
        Returns:
            List of UserSession objects
        """
        try:
            query = self.db_session.query(UserSession).filter(UserSession.user_id == user_id)
            
            if not include_expired:
                query = query.filter(
                    and_(
                        UserSession.expires_at > datetime.utcnow(),
                        UserSession.is_valid == True
                    )
                )
            
            sessions = query.order_by(UserSession.created_at.desc()).all()
            
            logger.debug(f"Retrieved {len(sessions)} sessions for user ID: {user_id}")
            return sessions
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user sessions: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving user sessions: {str(e)}")
            return []
    
    def invalidate_user_session(self, session_id: int) -> bool:
        """
        Invalidate a specific user session.
        
        Args:
            session_id: Session ID to invalidate
            
        Returns:
            True if session was invalidated, False otherwise
        """
        try:
            with self.db_session.begin():
                session = self.db_session.query(UserSession).filter(
                    UserSession.id == session_id
                ).first()
                
                if session:
                    session.is_valid = False
                    session.updated_at = datetime.utcnow()
                    logger.info(f"Invalidated session ID: {session_id}")
                    return True
                else:
                    logger.warning(f"Session ID {session_id} not found")
                    return False
                    
        except SQLAlchemyError as e:
            logger.error(f"Database error invalidating session: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error invalidating session: {str(e)}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired user sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            with self.db_session.begin():
                expired_sessions = self.db_session.query(UserSession).filter(
                    or_(
                        UserSession.expires_at < datetime.utcnow(),
                        UserSession.is_valid == False
                    )
                )
                
                count = expired_sessions.count()
                expired_sessions.delete()
                
                logger.info(f"Cleaned up {count} expired sessions")
                return count
                
        except SQLAlchemyError as e:
            logger.error(f"Database error cleaning up sessions: {str(e)}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error cleaning up sessions: {str(e)}")
            return 0
    
    # User Role and Permission Management
    
    def get_user_permissions(self, user_id: int) -> List[str]:
        """
        Get all permissions for a user (through their roles).
        
        Args:
            user_id: User ID to get permissions for
            
        Returns:
            List of permission names
        """
        try:
            user = self.db_session.query(User).options(
                joinedload(User.roles).joinedload(Role.permissions)
            ).filter(User.id == user_id).first()
            
            if not user:
                logger.warning(f"User with ID {user_id} not found")
                return []
            
            permissions = set()
            for role in user.roles:
                for permission in role.permissions:
                    permissions.add(permission.name)
            
            permission_list = list(permissions)
            logger.debug(f"Retrieved {len(permission_list)} permissions for user ID: {user_id}")
            return permission_list
            
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user permissions: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving user permissions: {str(e)}")
            return []
    
    def user_has_permission(self, user_id: int, permission_name: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user_id: User ID to check
            permission_name: Permission name to check for
            
        Returns:
            True if user has permission, False otherwise
        """
        try:
            exists = self.db_session.query(
                self.db_session.query(User)
                .join(User.roles)
                .join(Role.permissions)
                .filter(
                    and_(
                        User.id == user_id,
                        Permission.name == permission_name,
                        User.is_active == True
                    )
                ).exists()
            ).scalar()
            
            logger.debug(f"User {user_id} has permission '{permission_name}': {exists}")
            return exists
            
        except SQLAlchemyError as e:
            logger.error(f"Database error checking user permission: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking user permission: {str(e)}")
            return False
    
    def assign_role_to_user(self, user_id: int, role_name: str) -> bool:
        """
        Assign a role to a user.
        
        Args:
            user_id: User ID to assign role to
            role_name: Name of role to assign
            
        Returns:
            True if role was assigned, False otherwise
        """
        try:
            with self.db_session.begin():
                user = self.get_user_by_id(user_id, include_roles=True)
                role = self.db_session.query(Role).filter(Role.name == role_name).first()
                
                if not user:
                    logger.error(f"User with ID {user_id} not found")
                    return False
                
                if not role:
                    logger.error(f"Role '{role_name}' not found")
                    return False
                
                # Check if user already has this role
                if role in user.roles:
                    logger.info(f"User {user_id} already has role '{role_name}'")
                    return True
                
                user.roles.append(role)
                user.updated_at = datetime.utcnow()
                
                logger.info(f"Assigned role '{role_name}' to user {user_id}")
                return True
                
        except SQLAlchemyError as e:
            logger.error(f"Database error assigning role to user: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error assigning role to user: {str(e)}")
            return False
    
    def remove_role_from_user(self, user_id: int, role_name: str) -> bool:
        """
        Remove a role from a user.
        
        Args:
            user_id: User ID to remove role from
            role_name: Name of role to remove
            
        Returns:
            True if role was removed, False otherwise
        """
        try:
            with self.db_session.begin():
                user = self.get_user_by_id(user_id, include_roles=True)
                role = self.db_session.query(Role).filter(Role.name == role_name).first()
                
                if not user:
                    logger.error(f"User with ID {user_id} not found")
                    return False
                
                if not role:
                    logger.error(f"Role '{role_name}' not found")
                    return False
                
                # Check if user has this role
                if role not in user.roles:
                    logger.info(f"User {user_id} does not have role '{role_name}'")
                    return True
                
                user.roles.remove(role)
                user.updated_at = datetime.utcnow()
                
                logger.info(f"Removed role '{role_name}' from user {user_id}")
                return True
                
        except SQLAlchemyError as e:
            logger.error(f"Database error removing role from user: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error removing role from user: {str(e)}")
            return False
    
    # Analytics and Reporting
    
    def get_user_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive user statistics.
        
        Returns:
            Dictionary containing user statistics
        """
        try:
            stats = {
                "total_users": self.db_session.query(func.count(User.id)).scalar(),
                "active_users": self.db_session.query(func.count(User.id)).filter(User.is_active == True).scalar(),
                "inactive_users": self.db_session.query(func.count(User.id)).filter(User.is_active == False).scalar(),
                "users_with_auth0": self.db_session.query(func.count(User.id)).filter(User.auth0_user_id.isnot(None)).scalar(),
                "users_registered_today": self.db_session.query(func.count(User.id)).filter(
                    func.date(User.created_at) == datetime.utcnow().date()
                ).scalar(),
                "users_logged_in_today": self.db_session.query(func.count(User.id)).filter(
                    func.date(User.last_login) == datetime.utcnow().date()
                ).scalar()
            }
            
            logger.info(f"Generated user statistics: {stats}")
            return stats
            
        except SQLAlchemyError as e:
            logger.error(f"Database error generating user stats: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error generating user stats: {str(e)}")
            return {}
    
    # Private Helper Methods
    
    def _validate_user_creation_data(self, user_data: UserCreationData) -> UserValidationResult:
        """
        Validate user creation data.
        
        Args:
            user_data: User creation data to validate
            
        Returns:
            UserValidationResult with validation status and errors
        """
        result = UserValidationResult(is_valid=True, errors=[], warnings=[])
        
        # Validate username
        if not user_data.username or len(user_data.username.strip()) == 0:
            result.add_error("Username is required")
        elif len(user_data.username) < 3:
            result.add_error("Username must be at least 3 characters long")
        elif len(user_data.username) > 50:
            result.add_error("Username cannot exceed 50 characters")
        
        # Validate email
        if not user_data.email or len(user_data.email.strip()) == 0:
            result.add_error("Email is required")
        elif not self._is_valid_email(user_data.email):
            result.add_error("Invalid email format")
        
        # Validate password if provided
        if user_data.password:
            password_validation = self._validate_password(user_data.password)
            if not password_validation.is_valid:
                result.errors.extend(password_validation.errors)
                result.is_valid = False
        
        # Validate role names if provided
        if user_data.role_names:
            for role_name in user_data.role_names:
                if not self._role_exists(role_name):
                    result.add_error(f"Role '{role_name}' does not exist")
        
        return result
    
    def _validate_user_update_data(self, update_data: UserUpdateData, existing_user: User) -> UserValidationResult:
        """
        Validate user update data.
        
        Args:
            update_data: User update data to validate
            existing_user: Existing user object
            
        Returns:
            UserValidationResult with validation status and errors
        """
        result = UserValidationResult(is_valid=True, errors=[], warnings=[])
        
        # Validate username if being updated
        if update_data.username is not None:
            if len(update_data.username.strip()) == 0:
                result.add_error("Username cannot be empty")
            elif len(update_data.username) < 3:
                result.add_error("Username must be at least 3 characters long")
            elif len(update_data.username) > 50:
                result.add_error("Username cannot exceed 50 characters")
            elif update_data.username != existing_user.username:
                # Check if new username is already taken
                existing_user_with_username = self.get_user_by_username(update_data.username)
                if existing_user_with_username and existing_user_with_username.id != existing_user.id:
                    result.add_error(f"Username '{update_data.username}' is already taken")
        
        # Validate email if being updated
        if update_data.email is not None:
            if len(update_data.email.strip()) == 0:
                result.add_error("Email cannot be empty")
            elif not self._is_valid_email(update_data.email):
                result.add_error("Invalid email format")
            elif update_data.email != existing_user.email:
                # Check if new email is already taken
                existing_user_with_email = self.get_user_by_email(update_data.email)
                if existing_user_with_email and existing_user_with_email.id != existing_user.id:
                    result.add_error(f"Email '{update_data.email}' is already taken")
        
        # Validate role names if provided
        if update_data.role_names is not None:
            for role_name in update_data.role_names:
                if not self._role_exists(role_name):
                    result.add_error(f"Role '{role_name}' does not exist")
        
        return result
    
    def _validate_password(self, password: str) -> UserValidationResult:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            UserValidationResult with validation status and errors
        """
        result = UserValidationResult(is_valid=True, errors=[], warnings=[])
        
        if not password:
            result.add_error("Password is required")
            return result
        
        if len(password) < 8:
            result.add_error("Password must be at least 8 characters long")
        
        if len(password) > 128:
            result.add_error("Password cannot exceed 128 characters")
        
        # Check for complexity requirements
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_score < 3:
            result.add_error("Password must contain at least 3 of the following: uppercase letters, lowercase letters, digits, special characters")
        
        return result
    
    def _is_valid_email(self, email: str) -> bool:
        """
        Validate email format.
        
        Args:
            email: Email to validate
            
        Returns:
            True if email format is valid, False otherwise
        """
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def _check_duplicate_user(self, username: str, email: str) -> None:
        """
        Check for duplicate username or email.
        
        Args:
            username: Username to check
            email: Email to check
            
        Raises:
            DuplicateUserError: If username or email already exists
        """
        existing_user = self.db_session.query(User).filter(
            or_(User.username == username, User.email == email)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                raise DuplicateUserError(f"Username '{username}' already exists")
            else:
                raise DuplicateUserError(f"Email '{email}' already exists")
    
    def _role_exists(self, role_name: str) -> bool:
        """
        Check if a role exists.
        
        Args:
            role_name: Role name to check
            
        Returns:
            True if role exists, False otherwise
        """
        try:
            return self.db_session.query(Role).filter(Role.name == role_name).first() is not None
        except SQLAlchemyError:
            return False
    
    def _assign_roles_to_user(self, user: User, role_names: List[str]) -> None:
        """
        Assign multiple roles to a user.
        
        Args:
            user: User object to assign roles to
            role_names: List of role names to assign
        """
        roles = self.db_session.query(Role).filter(Role.name.in_(role_names)).all()
        user.roles.extend(roles)
    
    def _update_user_roles(self, user: User, role_names: List[str]) -> None:
        """
        Update user roles (replace existing roles).
        
        Args:
            user: User object to update roles for
            role_names: List of role names to set
        """
        roles = self.db_session.query(Role).filter(Role.name.in_(role_names)).all()
        user.roles = roles
    
    def _invalidate_user_sessions(self, user_id: int) -> None:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User ID whose sessions to invalidate
        """
        self.db_session.query(UserSession).filter(
            UserSession.user_id == user_id
        ).update({
            "is_valid": False,
            "updated_at": datetime.utcnow()
        })