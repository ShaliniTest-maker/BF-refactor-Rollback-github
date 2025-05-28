"""
Migration utility functions supporting the transition from Node.js authentication patterns to Flask implementations.

This module provides comprehensive data transformation utilities, compatibility helpers, and migration 
validation functions to ensure seamless conversion of authentication data and workflows during the 
technology migration process from Node.js to Python 3.13.3/Flask 3.1.1.

Key Features:
- Node.js to Python data structure transformation per Section 0.2.1
- User credential migration with data integrity validation per Section 4.6.2
- Session management migration from Node.js to Flask patterns per Section 6.4.1.3
- Authentication workflow compatibility verification per Section 4.6.3
- Backward compatibility maintenance during migration per Section 0.2.1
"""

import hashlib
import hmac
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Flask and security imports
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app, g
import bcrypt

# Auth utility dependencies
from .crypto_helpers import (
    generate_secure_token,
    create_signed_token,
    verify_signed_token,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    constant_time_compare
)
from .validation_helpers import (
    validate_email_format,
    validate_username_format,
    sanitize_user_input,
    validate_password_strength
)

# Configure logging for migration operations
logger = logging.getLogger(__name__)


class MigrationStatus(Enum):
    """Migration operation status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    VALIDATED = "validated"


class AuthDataFormat(Enum):
    """Authentication data format enumeration"""
    NODEJS_MONGODB = "nodejs_mongodb"
    NODEJS_BCRYPT = "nodejs_bcrypt"
    NODEJS_SESSION = "nodejs_session"
    FLASK_SQLALCHEMY = "flask_sqlalchemy"
    FLASK_WERKZEUG = "flask_werkzeug"
    FLASK_SESSION = "flask_session"


@dataclass
class MigrationResult:
    """Migration operation result data structure"""
    status: MigrationStatus
    operation: str
    source_format: AuthDataFormat
    target_format: AuthDataFormat
    records_processed: int
    records_successful: int
    records_failed: int
    validation_passed: bool
    error_details: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    execution_time_ms: Optional[float] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class UserCredentialData:
    """User credential data structure for migration"""
    user_id: Union[str, int]
    username: str
    email: str
    password_hash: str
    password_algorithm: str
    salt: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SessionData:
    """Session data structure for migration"""
    session_id: str
    user_id: Union[str, int]
    session_data: Dict[str, Any]
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_valid: bool = True


class AuthenticationMigrationHelper:
    """
    Comprehensive authentication migration helper class providing utilities for transitioning
    from Node.js authentication patterns to Flask implementations.
    
    This class implements the core migration functionality as specified in Section 0.2.1 
    for Node.js to Flask authentication data transformation.
    """
    
    def __init__(self, app=None):
        """
        Initialize authentication migration helper with Flask application context.
        
        Args:
            app: Flask application instance (optional for factory pattern)
        """
        self.app = app
        self.migration_stats = {
            'total_operations': 0,
            'successful_operations': 0,
            'failed_operations': 0,
            'validation_errors': []
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask application factory pattern"""
        self.app = app
        app.auth_migration_helper = self
        
        # Configure migration settings from app config
        self.bcrypt_rounds = app.config.get('MIGRATION_BCRYPT_ROUNDS', 12)
        self.werkzeug_method = app.config.get('MIGRATION_WERKZEUG_METHOD', 'pbkdf2:sha256')
        self.session_timeout = app.config.get('MIGRATION_SESSION_TIMEOUT', 3600)
        
        logger.info("Authentication migration helper initialized", extra={
            'bcrypt_rounds': self.bcrypt_rounds,
            'werkzeug_method': self.werkzeug_method,
            'session_timeout': self.session_timeout
        })
    
    def transform_nodejs_user_data(
        self, 
        nodejs_user_data: Dict[str, Any],
        target_format: AuthDataFormat = AuthDataFormat.FLASK_SQLALCHEMY
    ) -> Tuple[UserCredentialData, MigrationResult]:
        """
        Transform Node.js user data structures to Flask-compatible format.
        
        Implements Section 0.2.1 requirement for Node.js to Python data transformation
        with comprehensive validation and error handling.
        
        Args:
            nodejs_user_data: Raw user data from Node.js application
            target_format: Target authentication data format
            
        Returns:
            Tuple of transformed user data and migration result
        """
        start_time = datetime.now()
        errors = []
        warnings = []
        
        try:
            # Validate required fields in Node.js data
            required_fields = ['_id', 'username', 'email', 'password']
            missing_fields = [field for field in required_fields if field not in nodejs_user_data]
            
            if missing_fields:
                error_msg = f"Missing required fields: {missing_fields}"
                errors.append(error_msg)
                logger.error("User data transformation failed", extra={
                    'missing_fields': missing_fields,
                    'user_data_keys': list(nodejs_user_data.keys())
                })
                
                return None, MigrationResult(
                    status=MigrationStatus.FAILED,
                    operation="transform_nodejs_user_data",
                    source_format=AuthDataFormat.NODEJS_MONGODB,
                    target_format=target_format,
                    records_processed=1,
                    records_successful=0,
                    records_failed=1,
                    validation_passed=False,
                    error_details=errors,
                    execution_time_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
            
            # Extract and validate user ID
            user_id = str(nodejs_user_data['_id'])
            if not user_id:
                errors.append("Invalid user ID")
            
            # Validate and sanitize username
            username = sanitize_user_input(nodejs_user_data['username'])
            if not validate_username_format(username):
                errors.append(f"Invalid username format: {username}")
            
            # Validate and sanitize email
            email = sanitize_user_input(nodejs_user_data['email'].lower())
            if not validate_email_format(email):
                errors.append(f"Invalid email format: {email}")
            
            # Handle password hash migration
            password_hash = nodejs_user_data.get('password', '')
            password_algorithm = self._detect_password_algorithm(password_hash)
            
            if password_algorithm == 'unknown':
                warnings.append(f"Unknown password algorithm detected for user {user_id}")
                logger.warning("Unknown password algorithm", extra={
                    'user_id': user_id,
                    'password_hash_prefix': password_hash[:20] if password_hash else 'empty'
                })
            
            # Extract timestamps with timezone handling
            created_at = self._parse_nodejs_timestamp(
                nodejs_user_data.get('createdAt') or nodejs_user_data.get('created_at')
            )
            updated_at = self._parse_nodejs_timestamp(
                nodejs_user_data.get('updatedAt') or nodejs_user_data.get('updated_at')
            )
            
            # Extract user status
            is_active = nodejs_user_data.get('isActive', True)
            if isinstance(is_active, str):
                is_active = is_active.lower() in ('true', '1', 'yes', 'active')
            
            # Extract metadata
            metadata = {
                'original_id': nodejs_user_data.get('_id'),
                'migration_timestamp': datetime.now(timezone.utc).isoformat(),
                'source_system': 'nodejs',
                'roles': nodejs_user_data.get('roles', []),
                'permissions': nodejs_user_data.get('permissions', []),
                'last_login': self._parse_nodejs_timestamp(nodejs_user_data.get('lastLogin')),
                'login_count': nodejs_user_data.get('loginCount', 0)
            }
            
            # Remove None values from metadata
            metadata = {k: v for k, v in metadata.items() if v is not None}
            
            # Create transformed user credential data
            transformed_data = UserCredentialData(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                password_algorithm=password_algorithm,
                salt=nodejs_user_data.get('salt'),
                created_at=created_at,
                updated_at=updated_at,
                is_active=is_active,
                metadata=metadata
            )
            
            # Validate transformed data
            validation_errors = self._validate_user_credential_data(transformed_data)
            if validation_errors:
                errors.extend(validation_errors)
            
            # Determine success status
            success = len(errors) == 0
            records_successful = 1 if success else 0
            records_failed = 0 if success else 1
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            migration_result = MigrationResult(
                status=MigrationStatus.COMPLETED if success else MigrationStatus.FAILED,
                operation="transform_nodejs_user_data",
                source_format=AuthDataFormat.NODEJS_MONGODB,
                target_format=target_format,
                records_processed=1,
                records_successful=records_successful,
                records_failed=records_failed,
                validation_passed=len(validation_errors) == 0,
                error_details=errors if errors else None,
                warnings=warnings if warnings else None,
                execution_time_ms=execution_time
            )
            
            if success:
                logger.info("User data transformation completed", extra={
                    'user_id': user_id,
                    'username': username,
                    'email': email,
                    'execution_time_ms': execution_time,
                    'warnings_count': len(warnings)
                })
            else:
                logger.error("User data transformation failed", extra={
                    'user_id': user_id,
                    'errors': errors,
                    'execution_time_ms': execution_time
                })
            
            return transformed_data if success else None, migration_result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            error_msg = f"Exception during user data transformation: {str(e)}"
            errors.append(error_msg)
            
            logger.exception("User data transformation exception", extra={
                'nodejs_user_data_keys': list(nodejs_user_data.keys()) if nodejs_user_data else [],
                'execution_time_ms': execution_time
            })
            
            return None, MigrationResult(
                status=MigrationStatus.FAILED,
                operation="transform_nodejs_user_data",
                source_format=AuthDataFormat.NODEJS_MONGODB,
                target_format=target_format,
                records_processed=1,
                records_successful=0,
                records_failed=1,
                validation_passed=False,
                error_details=errors,
                execution_time_ms=execution_time
            )
    
    def migrate_password_hash(
        self, 
        nodejs_password_hash: str,
        password_algorithm: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Tuple[str, MigrationResult]:
        """
        Migrate password hash from Node.js format to Werkzeug format.
        
        Implements Section 4.6.2 requirement for user credential migration with 
        data integrity validation and Section 4.6.2 password hashing conversion.
        
        Args:
            nodejs_password_hash: Original password hash from Node.js
            password_algorithm: Detected or known password algorithm
            user_id: User identifier for logging purposes
            
        Returns:
            Tuple of Flask-compatible password hash and migration result
        """
        start_time = datetime.now()
        errors = []
        warnings = []
        
        try:
            if not nodejs_password_hash:
                errors.append("Empty password hash provided")
                return None, MigrationResult(
                    status=MigrationStatus.FAILED,
                    operation="migrate_password_hash",
                    source_format=AuthDataFormat.NODEJS_BCRYPT,
                    target_format=AuthDataFormat.FLASK_WERKZEUG,
                    records_processed=1,
                    records_successful=0,
                    records_failed=1,
                    validation_passed=False,
                    error_details=errors,
                    execution_time_ms=(datetime.now() - start_time).total_seconds() * 1000
                )
            
            # Detect password algorithm if not provided
            if password_algorithm is None:
                password_algorithm = self._detect_password_algorithm(nodejs_password_hash)
            
            # Handle different password hash formats
            if password_algorithm == 'bcrypt':
                # bcrypt hashes are compatible across Node.js and Python
                # Validate bcrypt format
                if self._validate_bcrypt_hash(nodejs_password_hash):
                    werkzeug_hash = nodejs_password_hash
                    warnings.append("bcrypt hash preserved - direct compatibility")
                else:
                    errors.append("Invalid bcrypt hash format")
                    werkzeug_hash = None
                    
            elif password_algorithm == 'pbkdf2':
                # Convert PBKDF2 from Node.js format to Werkzeug format
                werkzeug_hash = self._convert_pbkdf2_hash(nodejs_password_hash)
                if werkzeug_hash is None:
                    errors.append("Failed to convert PBKDF2 hash")
                    
            elif password_algorithm == 'scrypt':
                # Handle scrypt password hashes
                werkzeug_hash = self._convert_scrypt_hash(nodejs_password_hash)
                if werkzeug_hash is None:
                    errors.append("Failed to convert scrypt hash")
                    warnings.append("scrypt conversion may require password reset")
                    
            elif password_algorithm == 'sha256' or password_algorithm == 'md5':
                # Legacy hash algorithms - require special handling
                warnings.append(f"Legacy {password_algorithm} detected - recommend password reset")
                werkzeug_hash = self._handle_legacy_hash(nodejs_password_hash, password_algorithm)
                if werkzeug_hash is None:
                    errors.append(f"Cannot migrate {password_algorithm} hash safely")
                    
            else:
                # Unknown algorithm - preserve original but flag for review
                werkzeug_hash = nodejs_password_hash
                warnings.append(f"Unknown algorithm '{password_algorithm}' - preserved original hash")
                errors.append("Password hash requires manual review and possible user password reset")
            
            # Validate the resulting hash
            if werkzeug_hash and not self._validate_werkzeug_hash(werkzeug_hash):
                errors.append("Generated Werkzeug hash failed validation")
                werkzeug_hash = None
            
            # Determine success status
            success = len(errors) == 0 and werkzeug_hash is not None
            records_successful = 1 if success else 0
            records_failed = 0 if success else 1
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            migration_result = MigrationResult(
                status=MigrationStatus.COMPLETED if success else MigrationStatus.FAILED,
                operation="migrate_password_hash",
                source_format=AuthDataFormat.NODEJS_BCRYPT,
                target_format=AuthDataFormat.FLASK_WERKZEUG,
                records_processed=1,
                records_successful=records_successful,
                records_failed=records_failed,
                validation_passed=success,
                error_details=errors if errors else None,
                warnings=warnings if warnings else None,
                execution_time_ms=execution_time
            )
            
            if success:
                logger.info("Password hash migration completed", extra={
                    'user_id': user_id,
                    'source_algorithm': password_algorithm,
                    'target_format': 'werkzeug',
                    'execution_time_ms': execution_time,
                    'warnings_count': len(warnings)
                })
            else:
                logger.error("Password hash migration failed", extra={
                    'user_id': user_id,
                    'source_algorithm': password_algorithm,
                    'errors': errors,
                    'execution_time_ms': execution_time
                })
            
            return werkzeug_hash, migration_result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            error_msg = f"Exception during password hash migration: {str(e)}"
            errors.append(error_msg)
            
            logger.exception("Password hash migration exception", extra={
                'user_id': user_id,
                'password_algorithm': password_algorithm,
                'execution_time_ms': execution_time
            })
            
            return None, MigrationResult(
                status=MigrationStatus.FAILED,
                operation="migrate_password_hash",
                source_format=AuthDataFormat.NODEJS_BCRYPT,
                target_format=AuthDataFormat.FLASK_WERKZEUG,
                records_processed=1,
                records_successful=0,
                records_failed=1,
                validation_passed=False,
                error_details=errors,
                execution_time_ms=execution_time
            )
    
    def convert_nodejs_session_data(
        self, 
        nodejs_session_data: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> Tuple[SessionData, MigrationResult]:
        """
        Convert Node.js session data to Flask-compatible session format.
        
        Implements Section 6.4.1.3 requirement for session management migration 
        from Node.js to Flask patterns with ItsDangerous security.
        
        Args:
            nodejs_session_data: Raw session data from Node.js application
            user_id: Associated user identifier
            
        Returns:
            Tuple of converted session data and migration result
        """
        start_time = datetime.now()
        errors = []
        warnings = []
        
        try:
            # Validate required session fields
            if not nodejs_session_data:
                errors.append("Empty session data provided")
                
            # Extract session ID
            session_id = nodejs_session_data.get('sessionId') or nodejs_session_data.get('_id')
            if not session_id:
                session_id = generate_secure_token(32)
                warnings.append("Generated new session ID - original not found")
            else:
                session_id = str(session_id)
            
            # Extract user ID from session if not provided
            if not user_id:
                user_id = nodejs_session_data.get('userId') or nodejs_session_data.get('user')
                if isinstance(user_id, dict):
                    user_id = user_id.get('_id') or user_id.get('id')
                user_id = str(user_id) if user_id else None
            
            if not user_id:
                errors.append("No user ID found in session data")
            
            # Parse timestamps
            created_at = self._parse_nodejs_timestamp(
                nodejs_session_data.get('createdAt') or 
                nodejs_session_data.get('created') or
                datetime.now(timezone.utc)
            )
            
            # Handle session expiration
            expires_at = None
            if 'expiresAt' in nodejs_session_data:
                expires_at = self._parse_nodejs_timestamp(nodejs_session_data['expiresAt'])
            elif 'expires' in nodejs_session_data:
                expires_at = self._parse_nodejs_timestamp(nodejs_session_data['expires'])
            elif 'maxAge' in nodejs_session_data:
                max_age = nodejs_session_data['maxAge']
                if isinstance(max_age, (int, float)):
                    expires_at = created_at + timedelta(seconds=max_age)
            
            # Default expiration if none found
            if not expires_at:
                expires_at = created_at + timedelta(seconds=self.session_timeout)
                warnings.append(f"Using default session timeout: {self.session_timeout}s")
            
            # Extract session data and sanitize
            session_data = {}
            
            # Copy standard session fields
            for field in ['csrf_token', 'flash_messages', 'user_preferences', 'cart', 'temp_data']:
                if field in nodejs_session_data:
                    session_data[field] = nodejs_session_data[field]
            
            # Handle authentication-specific data
            if 'authenticated' in nodejs_session_data:
                session_data['_user_authenticated'] = bool(nodejs_session_data['authenticated'])
            
            if 'permissions' in nodejs_session_data:
                session_data['_user_permissions'] = nodejs_session_data['permissions']
            
            if 'roles' in nodejs_session_data:
                session_data['_user_roles'] = nodejs_session_data['roles']
            
            # Handle Flask-Login specific fields
            session_data['_user_id'] = user_id
            session_data['_fresh'] = True  # Mark as fresh for Flask-Login
            session_data['_permanent'] = True
            
            # Add migration metadata
            session_data['_migration_info'] = {
                'migrated_from': 'nodejs',
                'migration_timestamp': datetime.now(timezone.utc).isoformat(),
                'original_session_id': nodejs_session_data.get('sessionId'),
                'migration_version': '1.0'
            }
            
            # Extract client information
            ip_address = nodejs_session_data.get('ipAddress') or nodejs_session_data.get('ip')
            user_agent = nodejs_session_data.get('userAgent') or nodejs_session_data.get('ua')
            
            # Determine session validity
            is_valid = True
            current_time = datetime.now(timezone.utc)
            
            if expires_at and current_time > expires_at:
                is_valid = False
                warnings.append("Session has expired")
            
            if 'isValid' in nodejs_session_data:
                is_valid = bool(nodejs_session_data['isValid']) and is_valid
            
            # Create converted session data
            converted_session = SessionData(
                session_id=session_id,
                user_id=user_id,
                session_data=session_data,
                created_at=created_at,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                is_valid=is_valid
            )
            
            # Validate converted session data
            validation_errors = self._validate_session_data(converted_session)
            if validation_errors:
                errors.extend(validation_errors)
            
            # Determine success status
            success = len(errors) == 0
            records_successful = 1 if success else 0
            records_failed = 0 if success else 1
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            migration_result = MigrationResult(
                status=MigrationStatus.COMPLETED if success else MigrationStatus.FAILED,
                operation="convert_nodejs_session_data",
                source_format=AuthDataFormat.NODEJS_SESSION,
                target_format=AuthDataFormat.FLASK_SESSION,
                records_processed=1,
                records_successful=records_successful,
                records_failed=records_failed,
                validation_passed=len(validation_errors) == 0,
                error_details=errors if errors else None,
                warnings=warnings if warnings else None,
                execution_time_ms=execution_time
            )
            
            if success:
                logger.info("Session data conversion completed", extra={
                    'session_id': session_id,
                    'user_id': user_id,
                    'expires_at': expires_at.isoformat() if expires_at else None,
                    'is_valid': is_valid,
                    'execution_time_ms': execution_time,
                    'warnings_count': len(warnings)
                })
            else:
                logger.error("Session data conversion failed", extra={
                    'session_id': session_id,
                    'user_id': user_id,
                    'errors': errors,
                    'execution_time_ms': execution_time
                })
            
            return converted_session if success else None, migration_result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            error_msg = f"Exception during session data conversion: {str(e)}"
            errors.append(error_msg)
            
            logger.exception("Session data conversion exception", extra={
                'user_id': user_id,
                'nodejs_session_keys': list(nodejs_session_data.keys()) if nodejs_session_data else [],
                'execution_time_ms': execution_time
            })
            
            return None, MigrationResult(
                status=MigrationStatus.FAILED,
                operation="convert_nodejs_session_data",
                source_format=AuthDataFormat.NODEJS_SESSION,
                target_format=AuthDataFormat.FLASK_SESSION,
                records_processed=1,
                records_successful=0,
                records_failed=1,
                validation_passed=False,
                error_details=errors,
                execution_time_ms=execution_time
            )
    
    def validate_authentication_workflow(
        self, 
        user_data: UserCredentialData,
        test_password: Optional[str] = None
    ) -> MigrationResult:
        """
        Validate authentication workflow compatibility after migration.
        
        Implements Section 4.6.3 requirement for authentication workflow 
        compatibility verification during migration.
        
        Args:
            user_data: Migrated user credential data
            test_password: Optional test password for validation
            
        Returns:
            Migration result with validation details
        """
        start_time = datetime.now()
        errors = []
        warnings = []
        validation_tests = []
        
        try:
            # Test 1: User data structure validation
            validation_errors = self._validate_user_credential_data(user_data)
            test_result = {
                'test_name': 'user_data_structure',
                'passed': len(validation_errors) == 0,
                'details': validation_errors if validation_errors else ['User data structure valid']
            }
            validation_tests.append(test_result)
            
            if validation_errors:
                errors.extend([f"User data structure: {error}" for error in validation_errors])
            
            # Test 2: Password hash compatibility
            if user_data.password_hash:
                password_valid = self._validate_werkzeug_hash(user_data.password_hash)
                test_result = {
                    'test_name': 'password_hash_format',
                    'passed': password_valid,
                    'details': ['Password hash format valid'] if password_valid else ['Invalid password hash format']
                }
                validation_tests.append(test_result)
                
                if not password_valid:
                    errors.append("Password hash format validation failed")
                
                # Test password verification if test password provided
                if test_password and password_valid:
                    try:
                        verify_result = check_password_hash(user_data.password_hash, test_password)
                        test_result = {
                            'test_name': 'password_verification',
                            'passed': verify_result,
                            'details': ['Password verification successful'] if verify_result else ['Password verification failed']
                        }
                        validation_tests.append(test_result)
                        
                        if not verify_result:
                            warnings.append("Test password verification failed - may require password reset")
                            
                    except Exception as e:
                        test_result = {
                            'test_name': 'password_verification',
                            'passed': False,
                            'details': [f'Password verification exception: {str(e)}']
                        }
                        validation_tests.append(test_result)
                        errors.append(f"Password verification exception: {str(e)}")
            
            # Test 3: Email format validation
            email_valid = validate_email_format(user_data.email)
            test_result = {
                'test_name': 'email_format',
                'passed': email_valid,
                'details': ['Email format valid'] if email_valid else ['Invalid email format']
            }
            validation_tests.append(test_result)
            
            if not email_valid:
                errors.append("Email format validation failed")
            
            # Test 4: Username format validation
            username_valid = validate_username_format(user_data.username)
            test_result = {
                'test_name': 'username_format',
                'passed': username_valid,
                'details': ['Username format valid'] if username_valid else ['Invalid username format']
            }
            validation_tests.append(test_result)
            
            if not username_valid:
                errors.append("Username format validation failed")
            
            # Test 5: Timestamp validation
            timestamp_valid = True
            timestamp_details = []
            
            if user_data.created_at:
                if not isinstance(user_data.created_at, datetime):
                    timestamp_valid = False
                    timestamp_details.append("Invalid created_at timestamp format")
                elif user_data.created_at.tzinfo is None:
                    warnings.append("created_at timestamp missing timezone info")
                    timestamp_details.append("created_at missing timezone - should be timezone aware")
            
            if user_data.updated_at:
                if not isinstance(user_data.updated_at, datetime):
                    timestamp_valid = False
                    timestamp_details.append("Invalid updated_at timestamp format")
                elif user_data.updated_at.tzinfo is None:
                    warnings.append("updated_at timestamp missing timezone info")
                    timestamp_details.append("updated_at missing timezone - should be timezone aware")
            
            if not timestamp_details:
                timestamp_details = ['Timestamp validation passed']
                
            test_result = {
                'test_name': 'timestamp_validation',
                'passed': timestamp_valid,
                'details': timestamp_details
            }
            validation_tests.append(test_result)
            
            if not timestamp_valid:
                errors.append("Timestamp validation failed")
            
            # Test 6: Metadata validation
            metadata_valid = True
            metadata_details = []
            
            if user_data.metadata:
                if not isinstance(user_data.metadata, dict):
                    metadata_valid = False
                    metadata_details.append("Metadata must be a dictionary")
                else:
                    # Check for required migration metadata
                    required_metadata = ['original_id', 'migration_timestamp', 'source_system']
                    missing_metadata = [key for key in required_metadata if key not in user_data.metadata]
                    
                    if missing_metadata:
                        warnings.append(f"Missing recommended metadata: {missing_metadata}")
                        metadata_details.append(f"Missing recommended metadata: {missing_metadata}")
                    else:
                        metadata_details.append("Metadata validation passed")
            else:
                warnings.append("No metadata found - recommended for migration tracking")
                metadata_details.append("No metadata - recommended for migration tracking")
            
            test_result = {
                'test_name': 'metadata_validation',
                'passed': metadata_valid,
                'details': metadata_details
            }
            validation_tests.append(test_result)
            
            if not metadata_valid:
                errors.append("Metadata validation failed")
            
            # Calculate validation summary
            tests_passed = sum(1 for test in validation_tests if test['passed'])
            total_tests = len(validation_tests)
            validation_passed = tests_passed == total_tests
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create comprehensive migration result
            migration_result = MigrationResult(
                status=MigrationStatus.VALIDATED if validation_passed else MigrationStatus.FAILED,
                operation="validate_authentication_workflow",
                source_format=AuthDataFormat.NODEJS_MONGODB,
                target_format=AuthDataFormat.FLASK_SQLALCHEMY,
                records_processed=1,
                records_successful=1 if validation_passed else 0,
                records_failed=0 if validation_passed else 1,
                validation_passed=validation_passed,
                error_details=errors if errors else None,
                warnings=warnings if warnings else None,
                execution_time_ms=execution_time
            )
            
            # Add detailed validation results to metadata
            if not hasattr(migration_result, 'metadata'):
                migration_result.metadata = {}
                
            migration_result.metadata = {
                'validation_tests': validation_tests,
                'tests_passed': tests_passed,
                'total_tests': total_tests,
                'validation_score': round((tests_passed / total_tests) * 100, 2) if total_tests > 0 else 0
            }
            
            if validation_passed:
                logger.info("Authentication workflow validation completed", extra={
                    'user_id': user_data.user_id,
                    'username': user_data.username,
                    'tests_passed': tests_passed,
                    'total_tests': total_tests,
                    'execution_time_ms': execution_time,
                    'warnings_count': len(warnings)
                })
            else:
                logger.error("Authentication workflow validation failed", extra={
                    'user_id': user_data.user_id,
                    'username': user_data.username,
                    'tests_passed': tests_passed,
                    'total_tests': total_tests,
                    'errors': errors,
                    'execution_time_ms': execution_time
                })
            
            return migration_result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            error_msg = f"Exception during authentication workflow validation: {str(e)}"
            errors.append(error_msg)
            
            logger.exception("Authentication workflow validation exception", extra={
                'user_id': user_data.user_id if user_data else None,
                'execution_time_ms': execution_time
            })
            
            return MigrationResult(
                status=MigrationStatus.FAILED,
                operation="validate_authentication_workflow",
                source_format=AuthDataFormat.NODEJS_MONGODB,
                target_format=AuthDataFormat.FLASK_SQLALCHEMY,
                records_processed=1,
                records_successful=0,
                records_failed=1,
                validation_passed=False,
                error_details=errors,
                execution_time_ms=execution_time
            )
    
    def verify_backward_compatibility(
        self, 
        original_data: Dict[str, Any],
        migrated_data: Union[UserCredentialData, SessionData],
        compatibility_checks: Optional[List[str]] = None
    ) -> MigrationResult:
        """
        Verify backward compatibility during migration process.
        
        Implements Section 0.2.1 requirement for backward compatibility 
        maintenance during migration.
        
        Args:
            original_data: Original Node.js data structure
            migrated_data: Migrated Flask data structure
            compatibility_checks: Specific checks to perform
            
        Returns:
            Migration result with compatibility verification details
        """
        start_time = datetime.now()
        errors = []
        warnings = []
        compatibility_tests = []
        
        try:
            if compatibility_checks is None:
                compatibility_checks = [
                    'data_integrity',
                    'field_mapping',
                    'format_compatibility',
                    'security_preservation',
                    'functionality_preservation'
                ]
            
            # Test 1: Data Integrity Check
            if 'data_integrity' in compatibility_checks:
                integrity_result = self._check_data_integrity(original_data, migrated_data)
                compatibility_tests.append(integrity_result)
                if not integrity_result['passed']:
                    errors.extend(integrity_result['details'])
            
            # Test 2: Field Mapping Verification
            if 'field_mapping' in compatibility_checks:
                mapping_result = self._check_field_mapping(original_data, migrated_data)
                compatibility_tests.append(mapping_result)
                if not mapping_result['passed']:
                    errors.extend(mapping_result['details'])
                else:
                    warnings.extend(mapping_result.get('warnings', []))
            
            # Test 3: Format Compatibility
            if 'format_compatibility' in compatibility_checks:
                format_result = self._check_format_compatibility(original_data, migrated_data)
                compatibility_tests.append(format_result)
                if not format_result['passed']:
                    errors.extend(format_result['details'])
            
            # Test 4: Security Preservation
            if 'security_preservation' in compatibility_checks:
                security_result = self._check_security_preservation(original_data, migrated_data)
                compatibility_tests.append(security_result)
                if not security_result['passed']:
                    errors.extend(security_result['details'])
                else:
                    warnings.extend(security_result.get('warnings', []))
            
            # Test 5: Functionality Preservation
            if 'functionality_preservation' in compatibility_checks:
                functionality_result = self._check_functionality_preservation(original_data, migrated_data)
                compatibility_tests.append(functionality_result)
                if not functionality_result['passed']:
                    errors.extend(functionality_result['details'])
            
            # Calculate compatibility summary
            tests_passed = sum(1 for test in compatibility_tests if test['passed'])
            total_tests = len(compatibility_tests)
            compatibility_passed = tests_passed == total_tests
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Determine data type for logging
            data_type = "session" if isinstance(migrated_data, SessionData) else "user"
            data_id = getattr(migrated_data, 'session_id' if isinstance(migrated_data, SessionData) else 'user_id', 'unknown')
            
            migration_result = MigrationResult(
                status=MigrationStatus.VALIDATED if compatibility_passed else MigrationStatus.FAILED,
                operation="verify_backward_compatibility",
                source_format=AuthDataFormat.NODEJS_MONGODB,
                target_format=AuthDataFormat.FLASK_SQLALCHEMY,
                records_processed=1,
                records_successful=1 if compatibility_passed else 0,
                records_failed=0 if compatibility_passed else 1,
                validation_passed=compatibility_passed,
                error_details=errors if errors else None,
                warnings=warnings if warnings else None,
                execution_time_ms=execution_time
            )
            
            # Add detailed compatibility results
            if not hasattr(migration_result, 'metadata'):
                migration_result.metadata = {}
                
            migration_result.metadata = {
                'compatibility_tests': compatibility_tests,
                'tests_passed': tests_passed,
                'total_tests': total_tests,
                'compatibility_score': round((tests_passed / total_tests) * 100, 2) if total_tests > 0 else 0,
                'data_type': data_type,
                'data_id': data_id
            }
            
            if compatibility_passed:
                logger.info("Backward compatibility verification completed", extra={
                    'data_type': data_type,
                    'data_id': data_id,
                    'tests_passed': tests_passed,
                    'total_tests': total_tests,
                    'execution_time_ms': execution_time,
                    'warnings_count': len(warnings)
                })
            else:
                logger.error("Backward compatibility verification failed", extra={
                    'data_type': data_type,
                    'data_id': data_id,
                    'tests_passed': tests_passed,
                    'total_tests': total_tests,
                    'errors': errors,
                    'execution_time_ms': execution_time
                })
            
            return migration_result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            error_msg = f"Exception during backward compatibility verification: {str(e)}"
            errors.append(error_msg)
            
            logger.exception("Backward compatibility verification exception", extra={
                'original_data_keys': list(original_data.keys()) if isinstance(original_data, dict) else [],
                'migrated_data_type': type(migrated_data).__name__,
                'execution_time_ms': execution_time
            })
            
            return MigrationResult(
                status=MigrationStatus.FAILED,
                operation="verify_backward_compatibility",
                source_format=AuthDataFormat.NODEJS_MONGODB,
                target_format=AuthDataFormat.FLASK_SQLALCHEMY,
                records_processed=1,
                records_successful=0,
                records_failed=1,
                validation_passed=False,
                error_details=errors,
                execution_time_ms=execution_time
            )
    
    def generate_migration_report(
        self, 
        migration_results: List[MigrationResult],
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive migration report from migration results.
        
        Args:
            migration_results: List of migration operation results
            include_recommendations: Whether to include improvement recommendations
            
        Returns:
            Comprehensive migration report dictionary
        """
        try:
            if not migration_results:
                return {
                    'error': 'No migration results provided',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            
            # Calculate overall statistics
            total_operations = len(migration_results)
            successful_operations = sum(1 for result in migration_results 
                                      if result.status in [MigrationStatus.COMPLETED, MigrationStatus.VALIDATED])
            failed_operations = sum(1 for result in migration_results 
                                  if result.status == MigrationStatus.FAILED)
            
            total_records_processed = sum(result.records_processed for result in migration_results)
            total_records_successful = sum(result.records_successful for result in migration_results)
            total_records_failed = sum(result.records_failed for result in migration_results)
            
            # Calculate average execution time
            execution_times = [result.execution_time_ms for result in migration_results 
                             if result.execution_time_ms is not None]
            avg_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0
            
            # Collect all errors and warnings
            all_errors = []
            all_warnings = []
            
            for result in migration_results:
                if result.error_details:
                    all_errors.extend(result.error_details)
                if result.warnings:
                    all_warnings.extend(result.warnings)
            
            # Group operations by type
            operations_by_type = {}
            for result in migration_results:
                op_type = result.operation
                if op_type not in operations_by_type:
                    operations_by_type[op_type] = {
                        'total': 0,
                        'successful': 0,
                        'failed': 0,
                        'avg_time_ms': 0
                    }
                
                operations_by_type[op_type]['total'] += 1
                if result.status in [MigrationStatus.COMPLETED, MigrationStatus.VALIDATED]:
                    operations_by_type[op_type]['successful'] += 1
                else:
                    operations_by_type[op_type]['failed'] += 1
            
            # Calculate average times per operation type
            for op_type in operations_by_type:
                op_times = [result.execution_time_ms for result in migration_results 
                           if result.operation == op_type and result.execution_time_ms is not None]
                operations_by_type[op_type]['avg_time_ms'] = (
                    sum(op_times) / len(op_times) if op_times else 0
                )
            
            # Build comprehensive report
            report = {
                'report_metadata': {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'total_operations': total_operations,
                    'report_version': '1.0',
                    'migration_helper_version': '1.0'
                },
                'summary': {
                    'success_rate': round((successful_operations / total_operations) * 100, 2) if total_operations > 0 else 0,
                    'total_operations': total_operations,
                    'successful_operations': successful_operations,
                    'failed_operations': failed_operations,
                    'total_records_processed': total_records_processed,
                    'total_records_successful': total_records_successful,
                    'total_records_failed': total_records_failed,
                    'average_execution_time_ms': round(avg_execution_time, 2)
                },
                'operations_breakdown': operations_by_type,
                'error_summary': {
                    'total_errors': len(all_errors),
                    'unique_errors': len(set(all_errors)),
                    'error_details': list(set(all_errors))  # Deduplicated errors
                },
                'warning_summary': {
                    'total_warnings': len(all_warnings),
                    'unique_warnings': len(set(all_warnings)),
                    'warning_details': list(set(all_warnings))  # Deduplicated warnings
                },
                'detailed_results': [asdict(result) for result in migration_results]
            }
            
            # Add recommendations if requested
            if include_recommendations:
                recommendations = self._generate_migration_recommendations(migration_results)
                report['recommendations'] = recommendations
            
            logger.info("Migration report generated", extra={
                'total_operations': total_operations,
                'success_rate': report['summary']['success_rate'],
                'total_errors': len(all_errors),
                'total_warnings': len(all_warnings)
            })
            
            return report
            
        except Exception as e:
            logger.exception("Failed to generate migration report")
            return {
                'error': f'Failed to generate migration report: {str(e)}',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    # Private helper methods
    
    def _detect_password_algorithm(self, password_hash: str) -> str:
        """Detect password hashing algorithm from hash format"""
        if not password_hash:
            return 'unknown'
        
        # bcrypt detection
        if password_hash.startswith('$2a$') or password_hash.startswith('$2b$') or password_hash.startswith('$2y$'):
            return 'bcrypt'
        
        # PBKDF2 detection
        if password_hash.startswith('pbkdf2:') or password_hash.startswith('$pbkdf2'):
            return 'pbkdf2'
        
        # scrypt detection
        if password_hash.startswith('$scrypt$') or 'scrypt' in password_hash:
            return 'scrypt'
        
        # SHA-256 detection
        if len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash.lower()):
            return 'sha256'
        
        # MD5 detection
        if len(password_hash) == 32 and all(c in '0123456789abcdef' for c in password_hash.lower()):
            return 'md5'
        
        return 'unknown'
    
    def _validate_bcrypt_hash(self, bcrypt_hash: str) -> bool:
        """Validate bcrypt hash format"""
        try:
            return bcrypt_hash.startswith(('$2a$', '$2b$', '$2y$')) and len(bcrypt_hash) == 60
        except:
            return False
    
    def _validate_werkzeug_hash(self, werkzeug_hash: str) -> bool:
        """Validate Werkzeug password hash format"""
        try:
            # Check for bcrypt format (direct compatibility)
            if self._validate_bcrypt_hash(werkzeug_hash):
                return True
            
            # Check for Werkzeug PBKDF2 format
            if werkzeug_hash.startswith('pbkdf2:'):
                parts = werkzeug_hash.split('$')
                return len(parts) >= 3
            
            return False
        except:
            return False
    
    def _convert_pbkdf2_hash(self, nodejs_hash: str) -> Optional[str]:
        """Convert Node.js PBKDF2 hash to Werkzeug format"""
        try:
            # This is a simplified conversion - in practice, you might need 
            # more sophisticated parsing based on your Node.js hash format
            if nodejs_hash.startswith('pbkdf2:'):
                return nodejs_hash  # Already in compatible format
            elif nodejs_hash.startswith('$pbkdf2'):
                # Convert from standard PBKDF2 format to Werkzeug format
                parts = nodejs_hash.split('$')
                if len(parts) >= 5:
                    algorithm = parts[1]
                    iterations = parts[2]
                    salt = parts[3]
                    hash_value = parts[4]
                    return f"pbkdf2:{algorithm}:{iterations}${salt}${hash_value}"
            
            return None
        except:
            return None
    
    def _convert_scrypt_hash(self, nodejs_hash: str) -> Optional[str]:
        """Convert Node.js scrypt hash - may require password reset"""
        # scrypt hashes often require password reset due to incompatible formats
        return None
    
    def _handle_legacy_hash(self, nodejs_hash: str, algorithm: str) -> Optional[str]:
        """Handle legacy hash algorithms - usually requires password reset"""
        # For security reasons, legacy hashes should trigger password reset
        return None
    
    def _parse_nodejs_timestamp(self, timestamp: Any) -> Optional[datetime]:
        """Parse Node.js timestamp to Python datetime with timezone awareness"""
        if not timestamp:
            return None
        
        try:
            # Handle different timestamp formats
            if isinstance(timestamp, datetime):
                # Ensure timezone awareness
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                return timestamp
            
            elif isinstance(timestamp, (int, float)):
                # Unix timestamp
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
            
            elif isinstance(timestamp, str):
                # ISO format string
                try:
                    # Try parsing with timezone
                    return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    # Try parsing without timezone and add UTC
                    dt = datetime.fromisoformat(timestamp)
                    return dt.replace(tzinfo=timezone.utc)
            
            return None
            
        except Exception as e:
            logger.warning("Failed to parse timestamp", extra={
                'timestamp': str(timestamp),
                'error': str(e)
            })
            return None
    
    def _validate_user_credential_data(self, user_data: UserCredentialData) -> List[str]:
        """Validate user credential data structure"""
        errors = []
        
        if not user_data.user_id:
            errors.append("Missing user ID")
        
        if not user_data.username:
            errors.append("Missing username")
        elif not validate_username_format(user_data.username):
            errors.append("Invalid username format")
        
        if not user_data.email:
            errors.append("Missing email")
        elif not validate_email_format(user_data.email):
            errors.append("Invalid email format")
        
        if not user_data.password_hash:
            errors.append("Missing password hash")
        
        return errors
    
    def _validate_session_data(self, session_data: SessionData) -> List[str]:
        """Validate session data structure"""
        errors = []
        
        if not session_data.session_id:
            errors.append("Missing session ID")
        
        if not session_data.user_id:
            errors.append("Missing user ID")
        
        if not session_data.session_data or not isinstance(session_data.session_data, dict):
            errors.append("Invalid session data structure")
        
        if not session_data.created_at:
            errors.append("Missing created_at timestamp")
        
        if not session_data.expires_at:
            errors.append("Missing expires_at timestamp")
        
        return errors
    
    def _check_data_integrity(self, original: Dict[str, Any], migrated: Any) -> Dict[str, Any]:
        """Check data integrity between original and migrated data"""
        try:
            integrity_issues = []
            
            if isinstance(migrated, UserCredentialData):
                # Check user data integrity
                if original.get('_id') != str(migrated.user_id):
                    integrity_issues.append("User ID mismatch")
                
                if original.get('username') != migrated.username:
                    integrity_issues.append("Username mismatch")
                
                if original.get('email', '').lower() != migrated.email.lower():
                    integrity_issues.append("Email mismatch")
            
            elif isinstance(migrated, SessionData):
                # Check session data integrity
                original_user_id = original.get('userId') or original.get('user')
                if isinstance(original_user_id, dict):
                    original_user_id = original_user_id.get('_id') or original_user_id.get('id')
                
                if str(original_user_id) != str(migrated.user_id):
                    integrity_issues.append("Session user ID mismatch")
            
            return {
                'test_name': 'data_integrity',
                'passed': len(integrity_issues) == 0,
                'details': integrity_issues if integrity_issues else ['Data integrity verified']
            }
            
        except Exception as e:
            return {
                'test_name': 'data_integrity',
                'passed': False,
                'details': [f'Data integrity check failed: {str(e)}']
            }
    
    def _check_field_mapping(self, original: Dict[str, Any], migrated: Any) -> Dict[str, Any]:
        """Check field mapping completeness"""
        try:
            missing_fields = []
            mapped_fields = []
            warnings = []
            
            if isinstance(migrated, UserCredentialData):
                # Expected field mappings for user data
                field_mappings = {
                    '_id': 'user_id',
                    'username': 'username', 
                    'email': 'email',
                    'password': 'password_hash',
                    'createdAt': 'created_at',
                    'updatedAt': 'updated_at',
                    'isActive': 'is_active'
                }
                
                for orig_field, new_field in field_mappings.items():
                    if orig_field in original:
                        if hasattr(migrated, new_field) and getattr(migrated, new_field) is not None:
                            mapped_fields.append(f"{orig_field} -> {new_field}")
                        else:
                            missing_fields.append(f"Failed to map {orig_field} to {new_field}")
                
                # Check for additional original fields that might be missing
                additional_fields = set(original.keys()) - set(field_mappings.keys())
                if additional_fields:
                    warnings.append(f"Additional original fields not mapped: {list(additional_fields)}")
            
            elif isinstance(migrated, SessionData):
                # Expected field mappings for session data
                field_mappings = {
                    'sessionId': 'session_id',
                    'userId': 'user_id',
                    'createdAt': 'created_at',
                    'expiresAt': 'expires_at',
                    'ipAddress': 'ip_address',
                    'userAgent': 'user_agent'
                }
                
                for orig_field, new_field in field_mappings.items():
                    if orig_field in original:
                        if hasattr(migrated, new_field) and getattr(migrated, new_field) is not None:
                            mapped_fields.append(f"{orig_field} -> {new_field}")
                        else:
                            missing_fields.append(f"Failed to map {orig_field} to {new_field}")
            
            return {
                'test_name': 'field_mapping',
                'passed': len(missing_fields) == 0,
                'details': missing_fields if missing_fields else mapped_fields,
                'warnings': warnings
            }
            
        except Exception as e:
            return {
                'test_name': 'field_mapping',
                'passed': False,
                'details': [f'Field mapping check failed: {str(e)}']
            }
    
    def _check_format_compatibility(self, original: Dict[str, Any], migrated: Any) -> Dict[str, Any]:
        """Check format compatibility"""
        try:
            format_issues = []
            
            if isinstance(migrated, UserCredentialData):
                # Check email format consistency
                if 'email' in original and migrated.email:
                    if original['email'].lower() != migrated.email.lower():
                        format_issues.append("Email format inconsistency")
                
                # Check password hash format
                if migrated.password_hash and not self._validate_werkzeug_hash(migrated.password_hash):
                    format_issues.append("Invalid password hash format for Flask")
            
            elif isinstance(migrated, SessionData):
                # Check session data format
                if not isinstance(migrated.session_data, dict):
                    format_issues.append("Session data must be dictionary format")
                
                # Check timestamp formats
                if migrated.created_at and migrated.created_at.tzinfo is None:
                    format_issues.append("Created timestamp should be timezone-aware")
                
                if migrated.expires_at and migrated.expires_at.tzinfo is None:
                    format_issues.append("Expiration timestamp should be timezone-aware")
            
            return {
                'test_name': 'format_compatibility',
                'passed': len(format_issues) == 0,
                'details': format_issues if format_issues else ['Format compatibility verified']
            }
            
        except Exception as e:
            return {
                'test_name': 'format_compatibility',
                'passed': False,
                'details': [f'Format compatibility check failed: {str(e)}']
            }
    
    def _check_security_preservation(self, original: Dict[str, Any], migrated: Any) -> Dict[str, Any]:
        """Check security preservation during migration"""
        try:
            security_issues = []
            warnings = []
            
            if isinstance(migrated, UserCredentialData):
                # Check password hash security
                if 'password' in original and migrated.password_hash:
                    original_hash = original['password']
                    algorithm = self._detect_password_algorithm(original_hash)
                    
                    if algorithm == 'md5' or algorithm == 'sha256':
                        security_issues.append("Weak password hash algorithm detected - requires password reset")
                    elif algorithm == 'unknown':
                        warnings.append("Unknown password algorithm - security review recommended")
                
                # Check for sensitive data in metadata
                if migrated.metadata:
                    sensitive_keys = ['password', 'token', 'secret', 'key']
                    for key in migrated.metadata:
                        if any(sensitive in key.lower() for sensitive in sensitive_keys):
                            warnings.append(f"Potentially sensitive data in metadata: {key}")
            
            elif isinstance(migrated, SessionData):
                # Check session security
                if migrated.session_data:
                    # Check for sensitive data in session
                    sensitive_keys = ['password', 'token', 'secret', 'key']
                    for key in migrated.session_data:
                        if any(sensitive in key.lower() for sensitive in sensitive_keys):
                            warnings.append(f"Potentially sensitive data in session: {key}")
                
                # Check session expiration
                if migrated.expires_at:
                    current_time = datetime.now(timezone.utc)
                    if migrated.expires_at <= current_time:
                        warnings.append("Session has already expired")
            
            return {
                'test_name': 'security_preservation',
                'passed': len(security_issues) == 0,
                'details': security_issues if security_issues else ['Security preservation verified'],
                'warnings': warnings
            }
            
        except Exception as e:
            return {
                'test_name': 'security_preservation',
                'passed': False,
                'details': [f'Security preservation check failed: {str(e)}']
            }
    
    def _check_functionality_preservation(self, original: Dict[str, Any], migrated: Any) -> Dict[str, Any]:
        """Check functionality preservation during migration"""
        try:
            functionality_issues = []
            
            if isinstance(migrated, UserCredentialData):
                # Check user status preservation
                original_active = original.get('isActive', True)
                if isinstance(original_active, str):
                    original_active = original_active.lower() in ('true', '1', 'yes', 'active')
                
                if bool(original_active) != bool(migrated.is_active):
                    functionality_issues.append("User active status not preserved")
                
                # Check role preservation
                if 'roles' in original:
                    if not migrated.metadata or 'roles' not in migrated.metadata:
                        functionality_issues.append("User roles not preserved in migration")
                    elif set(original['roles']) != set(migrated.metadata['roles']):
                        functionality_issues.append("User roles modified during migration")
            
            elif isinstance(migrated, SessionData):
                # Check session validity preservation
                original_valid = original.get('isValid', True)
                if bool(original_valid) != bool(migrated.is_valid):
                    functionality_issues.append("Session validity status not preserved")
                
                # Check session data preservation
                if 'data' in original and isinstance(original['data'], dict):
                    for key in original['data']:
                        if key not in migrated.session_data:
                            functionality_issues.append(f"Session data key '{key}' not preserved")
            
            return {
                'test_name': 'functionality_preservation',
                'passed': len(functionality_issues) == 0,
                'details': functionality_issues if functionality_issues else ['Functionality preservation verified']
            }
            
        except Exception as e:
            return {
                'test_name': 'functionality_preservation',
                'passed': False,
                'details': [f'Functionality preservation check failed: {str(e)}']
            }
    
    def _generate_migration_recommendations(self, migration_results: List[MigrationResult]) -> Dict[str, Any]:
        """Generate recommendations based on migration results"""
        try:
            recommendations = {
                'priority_actions': [],
                'improvements': [],
                'security_considerations': [],
                'performance_optimizations': []
            }
            
            # Analyze error patterns
            all_errors = []
            for result in migration_results:
                if result.error_details:
                    all_errors.extend(result.error_details)
            
            # Common error patterns and recommendations
            error_patterns = {
                'password': {
                    'keywords': ['password', 'hash', 'bcrypt', 'pbkdf2'],
                    'recommendation': 'Consider implementing password reset flow for users with incompatible password hashes'
                },
                'timestamp': {
                    'keywords': ['timestamp', 'timezone', 'created_at', 'updated_at'],
                    'recommendation': 'Ensure all timestamps are timezone-aware for consistent behavior across deployments'
                },
                'session': {
                    'keywords': ['session', 'expired', 'invalid'],
                    'recommendation': 'Implement session cleanup procedures and user re-authentication flows'
                },
                'validation': {
                    'keywords': ['format', 'invalid', 'validation'],
                    'recommendation': 'Add data validation and sanitization at data entry points'
                }
            }
            
            for pattern_name, pattern_info in error_patterns.items():
                matching_errors = [error for error in all_errors 
                                 if any(keyword in error.lower() for keyword in pattern_info['keywords'])]
                if matching_errors:
                    recommendations['priority_actions'].append({
                        'category': pattern_name,
                        'description': pattern_info['recommendation'],
                        'affected_operations': len(matching_errors)
                    })
            
            # Performance recommendations
            slow_operations = [result for result in migration_results 
                             if result.execution_time_ms and result.execution_time_ms > 1000]
            if slow_operations:
                recommendations['performance_optimizations'].append({
                    'issue': 'Slow migration operations detected',
                    'recommendation': 'Consider batch processing or parallel execution for large data sets',
                    'affected_operations': len(slow_operations)
                })
            
            # Security recommendations
            security_warnings = []
            for result in migration_results:
                if result.warnings:
                    security_warnings.extend([w for w in result.warnings if 'security' in w.lower() or 'password' in w.lower()])
            
            if security_warnings:
                recommendations['security_considerations'].append({
                    'issue': 'Security-related warnings detected',
                    'recommendation': 'Review and address security warnings before production deployment',
                    'warning_count': len(security_warnings)
                })
            
            # General improvements
            failed_validations = [result for result in migration_results if not result.validation_passed]
            if failed_validations:
                recommendations['improvements'].append({
                    'issue': 'Validation failures detected',
                    'recommendation': 'Implement comprehensive data validation before migration processing',
                    'failed_operations': len(failed_validations)
                })
            
            return recommendations
            
        except Exception as e:
            logger.exception("Failed to generate migration recommendations")
            return {
                'error': f'Failed to generate recommendations: {str(e)}'
            }


# Convenience functions for easy access

def transform_user_data(nodejs_user_data: Dict[str, Any], app=None) -> Tuple[UserCredentialData, MigrationResult]:
    """
    Convenience function to transform Node.js user data to Flask format.
    
    Args:
        nodejs_user_data: Raw user data from Node.js application
        app: Flask application instance (optional)
        
    Returns:
        Tuple of transformed user data and migration result
    """
    helper = AuthenticationMigrationHelper(app)
    return helper.transform_nodejs_user_data(nodejs_user_data)


def migrate_password(nodejs_password_hash: str, app=None) -> Tuple[str, MigrationResult]:
    """
    Convenience function to migrate password hash from Node.js to Flask format.
    
    Args:
        nodejs_password_hash: Original password hash from Node.js
        app: Flask application instance (optional)
        
    Returns:
        Tuple of Flask-compatible password hash and migration result
    """
    helper = AuthenticationMigrationHelper(app)
    return helper.migrate_password_hash(nodejs_password_hash)


def convert_session_data(nodejs_session_data: Dict[str, Any], app=None) -> Tuple[SessionData, MigrationResult]:
    """
    Convenience function to convert Node.js session data to Flask format.
    
    Args:
        nodejs_session_data: Raw session data from Node.js application
        app: Flask application instance (optional)
        
    Returns:
        Tuple of converted session data and migration result
    """
    helper = AuthenticationMigrationHelper(app)
    return helper.convert_nodejs_session_data(nodejs_session_data)


def validate_migration(user_data: UserCredentialData, test_password: str = None, app=None) -> MigrationResult:
    """
    Convenience function to validate authentication workflow after migration.
    
    Args:
        user_data: Migrated user credential data
        test_password: Optional test password for validation
        app: Flask application instance (optional)
        
    Returns:
        Migration result with validation details
    """
    helper = AuthenticationMigrationHelper(app)
    return helper.validate_authentication_workflow(user_data, test_password)


def verify_compatibility(original_data: Dict[str, Any], migrated_data: Any, app=None) -> MigrationResult:
    """
    Convenience function to verify backward compatibility during migration.
    
    Args:
        original_data: Original Node.js data structure
        migrated_data: Migrated Flask data structure
        app: Flask application instance (optional)
        
    Returns:
        Migration result with compatibility verification details
    """
    helper = AuthenticationMigrationHelper(app)
    return helper.verify_backward_compatibility(original_data, migrated_data)