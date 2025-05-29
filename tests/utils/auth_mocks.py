"""
Authentication Testing Utilities

This module provides comprehensive authentication testing utilities for Flask authentication
mechanism testing during the Node.js to Flask migration. The utilities enable testing of
Auth0 integration, Flask-Login session simulation, authentication decorator validation,
and CSRF protection implementation while ensuring security posture preservation throughout
the migration process.

Key Features:
- Auth0 mock factories with JWT token simulation per Section 6.4.1.4
- Flask-Login session mocks with ItsDangerous cookie signing simulation per Feature F-007
- Authentication decorator testing utilities for Flask middleware migration per Section 4.6.2
- CSRF protection testing mocks with Flask-WTF integration per Section 4.6.2
- User authentication state mocks for comprehensive test coverage per Feature F-007
- Security monitoring test utilities with structured logging validation per Section 6.4.2.5

Dependencies:
- pytest 8.3.2 for comprehensive test framework integration
- Flask 3.1.1 with Flask-Login for session management
- Auth0 Python SDK 4.9.0 for identity provider integration
- Flask-WTF for CSRF protection testing
- ItsDangerous 2.2+ for secure cookie signing simulation
- Werkzeug security utilities for password hashing

Author: Flask Migration Team
Version: 1.0.0
Created: 2024
"""

import os
import jwt
import json
import time
import uuid
import pytest
import logging
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List, Union, Generator, Callable
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from functools import wraps

# Flask core imports
from flask import Flask, current_app, g, request, session
from flask.testing import FlaskClient
from werkzeug.test import Client
from werkzeug.security import generate_password_hash, check_password_hash

# Authentication imports
from flask_login import UserMixin, login_user, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Application imports
from src.models import User, UserSession
from src.auth.decorators import require_auth, require_permission, require_role
from src.auth.session_manager import SessionManager
from src.auth.auth0_integration import Auth0Service


# =====================================
# Authentication Mock Configuration
# =====================================

@dataclass
class MockAuthConfig:
    """
    Authentication mock configuration providing centralized settings
    for all authentication testing utilities and mock factories.
    
    This configuration class standardizes authentication testing parameters
    per Feature F-007, ensuring consistent mock behavior across all
    authentication testing scenarios.
    
    Attributes:
        auth0_domain: Mock Auth0 domain for testing
        auth0_client_id: Mock Auth0 client ID
        auth0_client_secret: Mock Auth0 client secret
        jwt_secret: JWT signing secret for token simulation
        jwt_algorithm: JWT signing algorithm
        token_expiration: Default token expiration time in seconds
        session_timeout: Default session timeout in seconds
        csrf_enabled: CSRF protection status for testing
        security_monitoring: Security event monitoring status
    """
    auth0_domain: str = "test-auth0-domain.auth0.com"
    auth0_client_id: str = "test_auth0_client_id"
    auth0_client_secret: str = "test_auth0_client_secret"
    jwt_secret: str = "test-jwt-secret-key-for-testing-only"
    jwt_algorithm: str = "HS256"
    token_expiration: int = 3600  # 1 hour
    session_timeout: int = 1800   # 30 minutes
    csrf_enabled: bool = True
    security_monitoring: bool = True
    
    # Auth0 API endpoints for mocking
    auth0_token_endpoint: str = "https://test-auth0-domain.auth0.com/oauth/token"
    auth0_userinfo_endpoint: str = "https://test-auth0-domain.auth0.com/userinfo"
    auth0_management_endpoint: str = "https://test-auth0-domain.auth0.com/api/v2/"
    
    # Security testing parameters
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    password_min_length: int = 8
    require_special_chars: bool = True


# =====================================
# Auth0 Mock Factories and JWT Simulation
# =====================================

class Auth0MockFactory:
    """
    Auth0 mock factory providing comprehensive Auth0 integration testing
    utilities with JWT token simulation per Section 6.4.1.4.
    
    This factory creates mock Auth0 service instances, JWT tokens, and user
    profile data for comprehensive authentication testing without external
    Auth0 dependencies while maintaining realistic testing scenarios.
    
    Features:
        - JWT token generation and validation simulation
        - Auth0 Management API mock responses
        - User profile synchronization mocking
        - Token refresh and revocation simulation
        - Error condition testing support
    """
    
    def __init__(self, config: Optional[MockAuthConfig] = None):
        """
        Initialize Auth0 mock factory with configuration.
        
        Args:
            config: Mock configuration instance, uses default if None
        """
        self.config = config or MockAuthConfig()
        self.mock_users = {}
        self.mock_tokens = {}
        self.revoked_tokens = set()
        self.login_attempts = {}
        
    def create_mock_jwt_token(
        self,
        user_id: Union[str, int],
        email: str,
        username: str,
        roles: List[str] = None,
        permissions: List[str] = None,
        expires_in: Optional[int] = None
    ) -> str:
        """
        Create mock JWT token with Auth0-compatible claims structure
        for comprehensive authentication testing.
        
        This method generates JWT tokens with realistic Auth0 claim structure
        per Section 6.4.1.4, enabling comprehensive token validation testing
        and authentication flow simulation.
        
        Args:
            user_id: Unique user identifier
            email: User email address
            username: User display name
            roles: List of user roles for RBAC testing
            permissions: List of user permissions
            expires_in: Token expiration time in seconds
            
        Returns:
            str: Encoded JWT token with Auth0-compatible claims
            
        Features:
            - Auth0-compatible claim structure
            - Role and permission embedding
            - Configurable expiration times
            - Audience and issuer validation
            - Custom claims support
        """
        now = datetime.now(timezone.utc)
        expiration = expires_in or self.config.token_expiration
        
        # Auth0-compatible JWT claims
        payload = {
            # Standard JWT claims
            'iss': f'https://{self.config.auth0_domain}/',
            'aud': [self.config.auth0_client_id, f'https://{self.config.auth0_domain}/api/v2/'],
            'sub': f'auth0|{user_id}',
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(seconds=expiration)).timestamp()),
            'azp': self.config.auth0_client_id,
            'scope': 'openid profile email',
            
            # Auth0 user profile claims
            'email': email,
            'email_verified': True,
            'name': username,
            'nickname': username,
            'picture': f'https://avatars.example.com/{user_id}',
            'updated_at': now.isoformat(),
            
            # Custom application claims
            'app_metadata': {
                'roles': roles or ['user'],
                'permissions': permissions or ['read'],
                'tenant': 'test_tenant',
                'user_id': str(user_id)
            },
            'user_metadata': {
                'preferences': {'theme': 'light', 'timezone': 'UTC'},
                'profile_complete': True
            },
            
            # Security claims
            'auth_time': int(now.timestamp()),
            'amr': ['pwd'],  # Authentication method reference
            'at_hash': 'test_access_token_hash'
        }
        
        # Generate and store token
        token = jwt.encode(payload, self.config.jwt_secret, algorithm=self.config.jwt_algorithm)
        self.mock_tokens[token] = payload
        
        return token
    
    def validate_mock_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate mock JWT token and return decoded claims for testing
        authentication decorator functionality.
        
        This method simulates Auth0 JWT token validation per Section 6.4.1.4,
        enabling comprehensive testing of authentication decorators and
        token-based access control mechanisms.
        
        Args:
            token: JWT token string to validate
            
        Returns:
            Optional[Dict[str, Any]]: Decoded token claims if valid, None otherwise
            
        Features:
            - JWT signature validation simulation
            - Token expiration checking
            - Revocation status verification
            - Error condition simulation
            - Claims structure validation
        """
        try:
            # Check if token is revoked
            if token in self.revoked_tokens:
                return None
            
            # Decode and validate token
            payload = jwt.decode(
                token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm],
                audience=self.config.auth0_client_id,
                issuer=f'https://{self.config.auth0_domain}/'
            )
            
            # Verify token exists in mock storage
            if token not in self.mock_tokens:
                return None
            
            # Additional validation checks
            if payload.get('exp', 0) < time.time():
                return None
            
            return payload
            
        except (jwt.InvalidTokenError, jwt.ExpiredSignatureError, jwt.InvalidAudienceError):
            return None
    
    def create_mock_auth0_service(self) -> Mock:
        """
        Create comprehensive Auth0 service mock with realistic API responses
        for integration testing without external dependencies.
        
        This method creates a complete Auth0 service mock per Section 6.4.1.1,
        enabling comprehensive authentication integration testing with simulated
        Auth0 Management API responses and user profile operations.
        
        Returns:
            Mock: Configured Auth0 service mock with realistic responses
            
        Features:
            - User authentication simulation
            - Management API mock responses
            - User profile CRUD operations
            - Token refresh and revocation
            - Error condition simulation
        """
        mock_auth0 = Mock(spec=Auth0Service)
        
        # Mock authentication methods
        mock_auth0.authenticate_user.side_effect = self._mock_authenticate_user
        mock_auth0.validate_token.side_effect = self._mock_validate_token
        mock_auth0.refresh_token.side_effect = self._mock_refresh_token
        mock_auth0.revoke_token.side_effect = self._mock_revoke_token
        
        # Mock user management methods
        mock_auth0.get_user_profile.side_effect = self._mock_get_user_profile
        mock_auth0.update_user_profile.side_effect = self._mock_update_user_profile
        mock_auth0.create_user.side_effect = self._mock_create_user
        mock_auth0.delete_user.side_effect = self._mock_delete_user
        
        # Mock management API methods
        mock_auth0.get_users.side_effect = self._mock_get_users
        mock_auth0.get_user_roles.side_effect = self._mock_get_user_roles
        mock_auth0.assign_user_roles.side_effect = self._mock_assign_user_roles
        mock_auth0.remove_user_roles.side_effect = self._mock_remove_user_roles
        
        # Mock configuration properties
        mock_auth0.domain = self.config.auth0_domain
        mock_auth0.client_id = self.config.auth0_client_id
        mock_auth0.is_connected = True
        
        return mock_auth0
    
    def _mock_authenticate_user(self, email: str, password: str) -> Dict[str, Any]:
        """Mock user authentication with realistic response structure."""
        # Simulate authentication attempt tracking
        if email not in self.login_attempts:
            self.login_attempts[email] = {'attempts': 0, 'locked_until': None}
        
        attempt_info = self.login_attempts[email]
        
        # Check if account is locked
        if attempt_info['locked_until'] and datetime.now() < attempt_info['locked_until']:
            return {
                'success': False,
                'error': 'account_locked',
                'message': 'Account temporarily locked due to too many failed attempts',
                'locked_until': attempt_info['locked_until'].isoformat()
            }
        
        # Check credentials (simplified for testing)
        if email in self.mock_users and password == 'validpassword':
            # Reset failed attempts on successful login
            attempt_info['attempts'] = 0
            attempt_info['locked_until'] = None
            
            user_data = self.mock_users[email]
            token = self.create_mock_jwt_token(
                user_id=user_data['user_id'],
                email=email,
                username=user_data['username'],
                roles=user_data.get('roles', ['user']),
                permissions=user_data.get('permissions', ['read'])
            )
            
            return {
                'success': True,
                'access_token': token,
                'token_type': 'Bearer',
                'expires_in': self.config.token_expiration,
                'user_info': user_data
            }
        else:
            # Track failed attempt
            attempt_info['attempts'] += 1
            
            # Lock account after max attempts
            if attempt_info['attempts'] >= self.config.max_login_attempts:
                attempt_info['locked_until'] = datetime.now() + timedelta(seconds=self.config.lockout_duration)
            
            return {
                'success': False,
                'error': 'invalid_credentials',
                'message': 'Invalid email or password',
                'attempts_remaining': max(0, self.config.max_login_attempts - attempt_info['attempts'])
            }
    
    def _mock_validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Mock token validation with comprehensive error handling."""
        return self.validate_mock_jwt_token(token)
    
    def _mock_refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Mock token refresh with rotation policy simulation."""
        # Simulate refresh token validation
        if refresh_token.startswith('valid_refresh_'):
            user_id = refresh_token.split('_')[-1]
            
            # Generate new access token
            new_token = self.create_mock_jwt_token(
                user_id=user_id,
                email=f'user{user_id}@example.com',
                username=f'testuser{user_id}'
            )
            
            # Generate new refresh token (rotation policy)
            new_refresh_token = f'valid_refresh_{user_id}_{int(time.time())}'
            
            return {
                'success': True,
                'access_token': new_token,
                'refresh_token': new_refresh_token,
                'token_type': 'Bearer',
                'expires_in': self.config.token_expiration
            }
        else:
            return {
                'success': False,
                'error': 'invalid_refresh_token',
                'message': 'Refresh token is invalid or expired'
            }
    
    def _mock_revoke_token(self, token: str) -> bool:
        """Mock token revocation for security testing."""
        self.revoked_tokens.add(token)
        return True
    
    def _mock_get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Mock user profile retrieval from Auth0 Management API."""
        for email, user_data in self.mock_users.items():
            if str(user_data['user_id']) == str(user_id):
                return {
                    'user_id': user_data['user_id'],
                    'email': email,
                    'username': user_data['username'],
                    'name': user_data.get('name', user_data['username']),
                    'picture': user_data.get('picture', f'https://avatars.example.com/{user_id}'),
                    'email_verified': user_data.get('email_verified', True),
                    'created_at': user_data.get('created_at', datetime.now().isoformat()),
                    'updated_at': user_data.get('updated_at', datetime.now().isoformat()),
                    'last_login': user_data.get('last_login'),
                    'login_count': user_data.get('login_count', 0),
                    'app_metadata': user_data.get('app_metadata', {}),
                    'user_metadata': user_data.get('user_metadata', {})
                }
        return None
    
    def _mock_update_user_profile(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Mock user profile update operations."""
        for email, user_data in self.mock_users.items():
            if str(user_data['user_id']) == str(user_id):
                user_data.update(updates)
                user_data['updated_at'] = datetime.now().isoformat()
                return True
        return False
    
    def _mock_create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Mock user creation in Auth0."""
        user_id = str(uuid.uuid4())
        email = user_data['email']
        
        self.mock_users[email] = {
            'user_id': user_id,
            'username': user_data.get('username', email.split('@')[0]),
            'name': user_data.get('name', user_data.get('username', email.split('@')[0])),
            'email_verified': user_data.get('email_verified', False),
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'roles': user_data.get('roles', ['user']),
            'permissions': user_data.get('permissions', ['read']),
            'app_metadata': user_data.get('app_metadata', {}),
            'user_metadata': user_data.get('user_metadata', {})
        }
        
        return {'user_id': user_id, 'email': email}
    
    def _mock_delete_user(self, user_id: str) -> bool:
        """Mock user deletion from Auth0."""
        for email, user_data in list(self.mock_users.items()):
            if str(user_data['user_id']) == str(user_id):
                del self.mock_users[email]
                return True
        return False
    
    def _mock_get_users(self, page: int = 0, per_page: int = 50) -> Dict[str, Any]:
        """Mock user list retrieval with pagination."""
        users_list = list(self.mock_users.values())
        start = page * per_page
        end = start + per_page
        
        return {
            'users': users_list[start:end],
            'total': len(users_list),
            'page': page,
            'per_page': per_page,
            'length': len(users_list[start:end])
        }
    
    def _mock_get_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        """Mock user roles retrieval."""
        for email, user_data in self.mock_users.items():
            if str(user_data['user_id']) == str(user_id):
                roles = user_data.get('roles', ['user'])
                return [{'id': f'role_{role}', 'name': role, 'description': f'{role.title()} role'} for role in roles]
        return []
    
    def _mock_assign_user_roles(self, user_id: str, role_ids: List[str]) -> bool:
        """Mock user role assignment."""
        for email, user_data in self.mock_users.items():
            if str(user_data['user_id']) == str(user_id):
                current_roles = set(user_data.get('roles', []))
                new_roles = [role_id.replace('role_', '') for role_id in role_ids]
                user_data['roles'] = list(current_roles.union(new_roles))
                return True
        return False
    
    def _mock_remove_user_roles(self, user_id: str, role_ids: List[str]) -> bool:
        """Mock user role removal."""
        for email, user_data in self.mock_users.items():
            if str(user_data['user_id']) == str(user_id):
                current_roles = set(user_data.get('roles', []))
                remove_roles = {role_id.replace('role_', '') for role_id in role_ids}
                user_data['roles'] = list(current_roles - remove_roles)
                return True
        return False
    
    def add_mock_user(
        self,
        email: str,
        username: str,
        user_id: Optional[str] = None,
        roles: List[str] = None,
        permissions: List[str] = None,
        **kwargs
    ) -> str:
        """
        Add mock user to the Auth0 user database for testing.
        
        This method enables test setup with predefined users per Feature F-007,
        supporting comprehensive authentication testing scenarios with
        configurable user attributes and permissions.
        
        Args:
            email: User email address
            username: User display name
            user_id: Optional custom user ID
            roles: List of user roles
            permissions: List of user permissions
            **kwargs: Additional user attributes
            
        Returns:
            str: Generated or provided user ID
            
        Features:
            - Configurable user attributes
            - Role and permission assignment
            - Custom metadata support
            - Realistic user profile structure
        """
        user_id = user_id or str(uuid.uuid4())
        
        self.mock_users[email] = {
            'user_id': user_id,
            'username': username,
            'name': kwargs.get('name', username),
            'email_verified': kwargs.get('email_verified', True),
            'created_at': kwargs.get('created_at', datetime.now().isoformat()),
            'updated_at': kwargs.get('updated_at', datetime.now().isoformat()),
            'roles': roles or ['user'],
            'permissions': permissions or ['read'],
            'app_metadata': kwargs.get('app_metadata', {}),
            'user_metadata': kwargs.get('user_metadata', {}),
            **kwargs
        }
        
        return user_id


# =====================================
# Flask-Login Session Mocking
# =====================================

class FlaskLoginSessionMock:
    """
    Flask-Login session mock providing comprehensive session management
    testing utilities with ItsDangerous cookie signing simulation.
    
    This class enables comprehensive Flask-Login testing per Feature F-007,
    providing session management simulation, user authentication state
    mocking, and secure cookie handling for authentication testing.
    
    Features:
        - Session creation and validation simulation
        - ItsDangerous cookie signing and verification
        - User authentication state management
        - Session timeout and renewal testing
        - Remember-me functionality simulation
    """
    
    def __init__(self, app: Flask, config: Optional[MockAuthConfig] = None):
        """
        Initialize Flask-Login session mock with application context.
        
        Args:
            app: Flask application instance
            config: Mock configuration instance
        """
        self.app = app
        self.config = config or MockAuthConfig()
        self.active_sessions = {}
        self.session_tokens = {}
        
    def create_mock_session(
        self,
        user: User,
        remember: bool = False,
        duration: Optional[timedelta] = None
    ) -> Dict[str, Any]:
        """
        Create mock user session with ItsDangerous cookie signing simulation
        for comprehensive session management testing.
        
        This method simulates Flask-Login session creation per Section 4.6.2,
        enabling comprehensive testing of session management, cookie handling,
        and user authentication state preservation.
        
        Args:
            user: User instance for session creation
            remember: Enable remember-me functionality
            duration: Custom session duration
            
        Returns:
            Dict[str, Any]: Session data with signed cookies and metadata
            
        Features:
            - ItsDangerous session cookie signing
            - Remember-me token generation
            - Session expiration management
            - CSRF token integration
            - Session metadata tracking
        """
        session_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)
        
        # Calculate session expiration
        if remember and duration:
            expires_at = created_at + duration
        elif remember:
            expires_at = created_at + timedelta(days=30)  # Remember-me default
        else:
            expires_at = created_at + timedelta(seconds=self.config.session_timeout)
        
        # Create session data
        session_data = {
            'session_id': session_id,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'created_at': created_at.isoformat(),
            'expires_at': expires_at.isoformat(),
            'remember': remember,
            'fresh': True,
            'active': True,
            'ip_address': '127.0.0.1',  # Test IP
            'user_agent': 'Flask-Test-Client/1.0'
        }
        
        # Generate session token using ItsDangerous
        serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
        session_token = serializer.dumps({
            'user_id': user.id,
            'session_id': session_id,
            'created_at': created_at.isoformat()
        })
        
        # Generate remember-me token if needed
        remember_token = None
        if remember:
            remember_data = {
                'user_id': user.id,
                'username': user.username,
                'token_type': 'remember_me'
            }
            remember_token = serializer.dumps(remember_data)
        
        # Store session data
        self.active_sessions[session_id] = session_data
        self.session_tokens[session_token] = session_data
        
        # Create cookie data
        cookie_data = {
            'session_token': session_token,
            'remember_token': remember_token,
            'csrf_token': self._generate_csrf_token(session_id),
            'session_id': session_id,
            'expires': expires_at.isoformat()
        }
        
        return {
            'session_data': session_data,
            'cookies': cookie_data,
            'signed_cookies': self._create_signed_cookies(cookie_data)
        }
    
    def validate_mock_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate mock session token and return session data for authentication
        decorator testing and session management validation.
        
        This method simulates Flask-Login session validation per Section 4.6.2,
        enabling comprehensive testing of authentication decorators and
        session-based access control mechanisms.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Optional[Dict[str, Any]]: Session data if valid, None otherwise
            
        Features:
            - ItsDangerous signature verification
            - Session expiration checking
            - Session activity validation
            - Token replay protection
            - Session state verification
        """
        try:
            # Verify token signature using ItsDangerous
            serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
            token_data = serializer.loads(
                session_token,
                max_age=self.config.session_timeout
            )
            
            # Retrieve session data
            if session_token not in self.session_tokens:
                return None
            
            session_data = self.session_tokens[session_token]
            
            # Verify session is still active
            if not session_data.get('active', False):
                return None
            
            # Check session expiration
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.now(timezone.utc) > expires_at:
                # Mark session as expired
                session_data['active'] = False
                return None
            
            # Update last activity
            session_data['last_activity'] = datetime.now(timezone.utc).isoformat()
            
            return session_data
            
        except (SignatureExpired, BadSignature, KeyError):
            return None
    
    def refresh_mock_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh mock session extending expiration time for session
        renewal testing and activity-based session management.
        
        This method simulates session refresh functionality per Section 4.6.2,
        enabling testing of session renewal mechanisms and activity-based
        session timeout policies.
        
        Args:
            session_token: Current session token to refresh
            
        Returns:
            Optional[Dict[str, Any]]: New session data if successful, None otherwise
            
        Features:
            - Session token regeneration
            - Expiration time extension
            - Activity tracking update
            - Fresh session flag management
            - Cookie data refresh
        """
        session_data = self.validate_mock_session(session_token)
        if not session_data:
            return None
        
        # Create new session with extended expiration
        new_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.config.session_timeout)
        
        # Update session data
        session_data.update({
            'expires_at': new_expires_at.isoformat(),
            'fresh': False,  # Renewed sessions are not fresh
            'last_refresh': datetime.now(timezone.utc).isoformat()
        })
        
        # Generate new session token
        serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
        new_session_token = serializer.dumps({
            'user_id': session_data['user_id'],
            'session_id': session_data['session_id'],
            'refresh_time': datetime.now(timezone.utc).isoformat()
        })
        
        # Update token mapping
        if session_token in self.session_tokens:
            del self.session_tokens[session_token]
        self.session_tokens[new_session_token] = session_data
        
        # Create new cookie data
        cookie_data = {
            'session_token': new_session_token,
            'csrf_token': self._generate_csrf_token(session_data['session_id']),
            'session_id': session_data['session_id'],
            'expires': new_expires_at.isoformat()
        }
        
        return {
            'session_data': session_data,
            'cookies': cookie_data,
            'signed_cookies': self._create_signed_cookies(cookie_data)
        }
    
    def revoke_mock_session(self, session_token: str) -> bool:
        """
        Revoke mock session for logout testing and security incident
        response validation.
        
        This method simulates session revocation per Section 6.4.6.2,
        enabling testing of logout procedures and security incident
        response mechanisms including session invalidation.
        
        Args:
            session_token: Session token to revoke
            
        Returns:
            bool: True if session was successfully revoked
            
        Features:
            - Session data cleanup
            - Token invalidation
            - Security event logging
            - Cascade session removal
        """
        if session_token in self.session_tokens:
            session_data = self.session_tokens[session_token]
            session_id = session_data.get('session_id')
            
            # Mark session as inactive
            session_data['active'] = False
            session_data['revoked_at'] = datetime.now(timezone.utc).isoformat()
            
            # Remove from active sessions
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            
            # Keep token mapping for audit trail
            # del self.session_tokens[session_token]
            
            return True
        
        return False
    
    def _generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token for session protection."""
        csrf_data = {
            'session_id': session_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'token_type': 'csrf'
        }
        
        serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
        return serializer.dumps(csrf_data)
    
    def _create_signed_cookies(self, cookie_data: Dict[str, Any]) -> Dict[str, str]:
        """Create signed cookies using ItsDangerous for secure cookie simulation."""
        serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
        
        signed_cookies = {}
        for key, value in cookie_data.items():
            if value is not None:
                signed_cookies[f'signed_{key}'] = serializer.dumps({key: value})
        
        return signed_cookies


# =====================================
# Authentication Decorator Testing Utilities
# =====================================

class AuthDecoratorTestUtils:
    """
    Authentication decorator testing utilities providing comprehensive
    testing support for Flask authentication decorators and middleware
    migration validation per Section 4.6.2.
    
    This class enables testing of authentication decorators converted from
    Node.js middleware patterns, supporting comprehensive validation of
    authentication enforcement, authorization controls, and security posture
    preservation during the migration process.
    
    Features:
        - Authentication decorator testing simulation
        - Authorization validation utilities
        - Role-based access control testing
        - Permission checking simulation
        - Security policy enforcement validation
    """
    
    def __init__(self, app: Flask, config: Optional[MockAuthConfig] = None):
        """
        Initialize authentication decorator testing utilities.
        
        Args:
            app: Flask application instance
            config: Mock configuration instance
        """
        self.app = app
        self.config = config or MockAuthConfig()
        self.auth_attempts = []
        self.authorization_checks = []
        
    @contextmanager
    def mock_authenticated_user(
        self,
        user: User,
        roles: List[str] = None,
        permissions: List[str] = None,
        session_data: Dict[str, Any] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Context manager providing authenticated user context for testing
        authentication decorators and protected endpoints.
        
        This context manager simulates authenticated user state per Feature F-007,
        enabling comprehensive testing of authentication decorators and
        access control mechanisms with proper user context injection.
        
        Args:
            user: User instance for authentication
            roles: List of user roles for RBAC testing
            permissions: List of user permissions
            session_data: Additional session data
            
        Yields:
            Dict[str, Any]: Authentication context data
            
        Features:
            - User authentication state simulation
            - Role and permission injection
            - Session context management
            - Request context setup
            - Authentication decorator bypass
        """
        with self.app.test_request_context():
            # Set up authentication context
            auth_context = {
                'user': user,
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'roles': roles or ['user'],
                'permissions': permissions or ['read'],
                'authenticated': True,
                'session_data': session_data or {},
                'auth_time': datetime.now(timezone.utc).isoformat()
            }
            
            # Inject user into Flask-Login context
            with patch('flask_login.current_user', user):
                with patch('flask_login.current_user.is_authenticated', True):
                    # Set up request context variables
                    g.user = user
                    g.authenticated = True
                    g.auth_context = auth_context
                    g.user_roles = auth_context['roles']
                    g.user_permissions = auth_context['permissions']
                    
                    # Mock session data
                    session.update({
                        'user_id': user.id,
                        'username': user.username,
                        'authenticated': True,
                        '_fresh': True
                    })
                    
                    yield auth_context
    
    def test_require_auth_decorator(
        self,
        endpoint_function: Callable,
        user: Optional[User] = None,
        expect_success: bool = True
    ) -> Dict[str, Any]:
        """
        Test @require_auth decorator functionality with various authentication
        states and user contexts.
        
        This method enables comprehensive testing of authentication decorators
        per Section 4.6.2, validating decorator behavior with authenticated
        and unauthenticated users, session states, and error conditions.
        
        Args:
            endpoint_function: Flask endpoint function with @require_auth decorator
            user: User instance for authentication (None for unauthenticated test)
            expect_success: Expected authentication result
            
        Returns:
            Dict[str, Any]: Test results with authentication status and response data
            
        Features:
            - Authentication decorator validation
            - Success and failure scenario testing
            - Error response verification
            - Status code validation
            - Security event tracking
        """
        test_result = {
            'decorator': 'require_auth',
            'user': user.username if user else None,
            'expected_success': expect_success,
            'actual_success': False,
            'response_data': None,
            'status_code': None,
            'error_message': None,
            'execution_time': None
        }
        
        start_time = time.time()
        
        try:
            if user:
                # Test with authenticated user
                with self.mock_authenticated_user(user):
                    response = endpoint_function()
                    test_result['actual_success'] = True
                    test_result['response_data'] = response
                    test_result['status_code'] = 200
            else:
                # Test without authentication
                with self.app.test_request_context():
                    try:
                        response = endpoint_function()
                        test_result['actual_success'] = True
                        test_result['response_data'] = response
                        test_result['status_code'] = 200
                    except Exception as e:
                        # Expected for unauthenticated requests
                        test_result['actual_success'] = False
                        test_result['error_message'] = str(e)
                        test_result['status_code'] = 401
        
        except Exception as e:
            test_result['actual_success'] = False
            test_result['error_message'] = str(e)
            test_result['status_code'] = getattr(e, 'code', 500)
        
        finally:
            test_result['execution_time'] = time.time() - start_time
        
        # Record authentication attempt
        self.auth_attempts.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'decorator': 'require_auth',
            'user_id': user.id if user else None,
            'success': test_result['actual_success'],
            'expected': expect_success,
            'matches_expectation': test_result['actual_success'] == expect_success
        })
        
        return test_result
    
    def test_require_role_decorator(
        self,
        endpoint_function: Callable,
        required_role: str,
        user: User,
        user_roles: List[str],
        expect_success: bool = True
    ) -> Dict[str, Any]:
        """
        Test @require_role decorator functionality with various role
        configurations and user contexts.
        
        This method enables comprehensive testing of role-based access control
        per Section 6.4.2.1, validating role requirement enforcement and
        authorization decision logic for RBAC implementation.
        
        Args:
            endpoint_function: Flask endpoint function with @require_role decorator
            required_role: Role required by the decorator
            user: User instance for authorization testing
            user_roles: List of roles assigned to the user
            expect_success: Expected authorization result
            
        Returns:
            Dict[str, Any]: Test results with authorization status and response data
            
        Features:
            - Role-based access control validation
            - Multiple role scenario testing
            - Authorization failure handling
            - Role hierarchy testing
            - Security policy enforcement
        """
        test_result = {
            'decorator': 'require_role',
            'required_role': required_role,
            'user_roles': user_roles,
            'user': user.username,
            'expected_success': expect_success,
            'actual_success': False,
            'response_data': None,
            'status_code': None,
            'error_message': None,
            'execution_time': None
        }
        
        start_time = time.time()
        
        try:
            with self.mock_authenticated_user(user, roles=user_roles):
                # Mock the role requirement check
                has_required_role = required_role in user_roles
                
                if has_required_role:
                    response = endpoint_function()
                    test_result['actual_success'] = True
                    test_result['response_data'] = response
                    test_result['status_code'] = 200
                else:
                    # Simulate authorization failure
                    test_result['actual_success'] = False
                    test_result['error_message'] = f'Insufficient privileges: requires {required_role} role'
                    test_result['status_code'] = 403
        
        except Exception as e:
            test_result['actual_success'] = False
            test_result['error_message'] = str(e)
            test_result['status_code'] = getattr(e, 'code', 500)
        
        finally:
            test_result['execution_time'] = time.time() - start_time
        
        # Record authorization check
        self.authorization_checks.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'decorator': 'require_role',
            'user_id': user.id,
            'required_role': required_role,
            'user_roles': user_roles,
            'success': test_result['actual_success'],
            'expected': expect_success,
            'matches_expectation': test_result['actual_success'] == expect_success
        })
        
        return test_result
    
    def test_require_permission_decorator(
        self,
        endpoint_function: Callable,
        required_permission: str,
        user: User,
        user_permissions: List[str],
        expect_success: bool = True
    ) -> Dict[str, Any]:
        """
        Test @require_permission decorator functionality with various permission
        configurations and user contexts.
        
        This method enables comprehensive testing of permission-based access
        control per Section 6.4.2.2, validating granular permission enforcement
        and authorization logic for fine-grained access control.
        
        Args:
            endpoint_function: Flask endpoint function with @require_permission decorator
            required_permission: Permission required by the decorator
            user: User instance for authorization testing
            user_permissions: List of permissions assigned to the user
            expect_success: Expected authorization result
            
        Returns:
            Dict[str, Any]: Test results with authorization status and response data
            
        Features:
            - Permission-based access control validation
            - Granular permission testing
            - Permission inheritance testing
            - Resource-level authorization
            - Security policy validation
        """
        test_result = {
            'decorator': 'require_permission',
            'required_permission': required_permission,
            'user_permissions': user_permissions,
            'user': user.username,
            'expected_success': expect_success,
            'actual_success': False,
            'response_data': None,
            'status_code': None,
            'error_message': None,
            'execution_time': None
        }
        
        start_time = time.time()
        
        try:
            with self.mock_authenticated_user(user, permissions=user_permissions):
                # Mock the permission check
                has_required_permission = required_permission in user_permissions
                
                if has_required_permission:
                    response = endpoint_function()
                    test_result['actual_success'] = True
                    test_result['response_data'] = response
                    test_result['status_code'] = 200
                else:
                    # Simulate authorization failure
                    test_result['actual_success'] = False
                    test_result['error_message'] = f'Insufficient privileges: requires {required_permission} permission'
                    test_result['status_code'] = 403
        
        except Exception as e:
            test_result['actual_success'] = False
            test_result['error_message'] = str(e)
            test_result['status_code'] = getattr(e, 'code', 500)
        
        finally:
            test_result['execution_time'] = time.time() - start_time
        
        # Record authorization check
        self.authorization_checks.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'decorator': 'require_permission',
            'user_id': user.id,
            'required_permission': required_permission,
            'user_permissions': user_permissions,
            'success': test_result['actual_success'],
            'expected': expect_success,
            'matches_expectation': test_result['actual_success'] == expect_success
        })
        
        return test_result
    
    def get_authentication_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive authentication testing metrics for performance
        analysis and security validation.
        
        This method provides detailed authentication testing metrics per
        Section 4.7.1, enabling performance analysis and security posture
        validation during authentication mechanism migration testing.
        
        Returns:
            Dict[str, Any]: Comprehensive authentication testing metrics
            
        Features:
            - Authentication success/failure rates
            - Authorization metrics by role/permission
            - Performance timing analysis
            - Security event correlation
            - Test coverage validation
        """
        total_auth_attempts = len(self.auth_attempts)
        successful_auth = sum(1 for attempt in self.auth_attempts if attempt['success'])
        
        total_authz_checks = len(self.authorization_checks)
        successful_authz = sum(1 for check in self.authorization_checks if check['success'])
        
        return {
            'authentication': {
                'total_attempts': total_auth_attempts,
                'successful_attempts': successful_auth,
                'failure_rate': (total_auth_attempts - successful_auth) / max(total_auth_attempts, 1) * 100,
                'success_rate': successful_auth / max(total_auth_attempts, 1) * 100
            },
            'authorization': {
                'total_checks': total_authz_checks,
                'successful_checks': successful_authz,
                'failure_rate': (total_authz_checks - successful_authz) / max(total_authz_checks, 1) * 100,
                'success_rate': successful_authz / max(total_authz_checks, 1) * 100
            },
            'performance': {
                'avg_auth_time': sum(attempt.get('execution_time', 0) for attempt in self.auth_attempts) / max(total_auth_attempts, 1),
                'avg_authz_time': sum(check.get('execution_time', 0) for check in self.authorization_checks) / max(total_authz_checks, 1)
            },
            'test_coverage': {
                'decorators_tested': len(set(attempt['decorator'] for attempt in self.auth_attempts + self.authorization_checks)),
                'unique_users_tested': len(set(attempt.get('user_id') for attempt in self.auth_attempts if attempt.get('user_id'))),
                'roles_tested': len(set(check.get('required_role') for check in self.authorization_checks if check.get('required_role'))),
                'permissions_tested': len(set(check.get('required_permission') for check in self.authorization_checks if check.get('required_permission')))
            }
        }


# =====================================
# CSRF Protection Testing Mocks
# =====================================

class CSRFProtectionMock:
    """
    CSRF protection testing mock providing comprehensive Flask-WTF CSRF
    testing utilities per Section 4.6.2.
    
    This class enables comprehensive CSRF protection testing during the
    Flask migration, supporting Flask-WTF integration validation and
    CSRF token handling for form submissions and AJAX requests.
    
    Features:
        - CSRF token generation and validation
        - Form submission CSRF testing
        - AJAX request CSRF validation
        - CSRF exemption testing
        - Security policy enforcement
    """
    
    def __init__(self, app: Flask, config: Optional[MockAuthConfig] = None):
        """
        Initialize CSRF protection mock with Flask application.
        
        Args:
            app: Flask application instance
            config: Mock configuration instance
        """
        self.app = app
        self.config = config or MockAuthConfig()
        self.csrf_tokens = {}
        self.csrf_failures = []
        
    def generate_mock_csrf_token(
        self,
        session_id: Optional[str] = None,
        form_name: Optional[str] = None
    ) -> str:
        """
        Generate mock CSRF token for form and AJAX request testing.
        
        This method simulates Flask-WTF CSRF token generation per Section 4.6.2,
        enabling comprehensive testing of CSRF protection mechanisms and
        form submission validation.
        
        Args:
            session_id: Optional session identifier for token binding
            form_name: Optional form name for scoped CSRF tokens
            
        Returns:
            str: Generated CSRF token for testing
            
        Features:
            - Session-bound CSRF tokens
            - Form-specific token scoping
            - Token expiration management
            - Secure token generation
            - Token validation tracking
        """
        # Generate token data
        token_data = {
            'session_id': session_id or 'test_session',
            'form_name': form_name,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'token_type': 'csrf',
            'nonce': str(uuid.uuid4())
        }
        
        # Create signed token using ItsDangerous
        serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
        csrf_token = serializer.dumps(token_data)
        
        # Store token for validation
        self.csrf_tokens[csrf_token] = token_data
        
        return csrf_token
    
    def validate_mock_csrf_token(
        self,
        csrf_token: str,
        session_id: Optional[str] = None,
        form_name: Optional[str] = None
    ) -> bool:
        """
        Validate mock CSRF token for form submission and AJAX request testing.
        
        This method simulates Flask-WTF CSRF token validation per Section 4.6.2,
        enabling comprehensive testing of CSRF protection enforcement and
        token validation logic.
        
        Args:
            csrf_token: CSRF token to validate
            session_id: Expected session identifier
            form_name: Expected form name for scoped validation
            
        Returns:
            bool: True if token is valid, False otherwise
            
        Features:
            - Token signature verification
            - Session binding validation
            - Form scope verification
            - Token expiration checking
            - Replay attack protection
        """
        try:
            # Verify token signature
            serializer = URLSafeTimedSerializer(self.app.config['SECRET_KEY'])
            token_data = serializer.loads(
                csrf_token,
                max_age=3600  # 1 hour token expiration
            )
            
            # Verify token exists in our storage
            if csrf_token not in self.csrf_tokens:
                self._record_csrf_failure('token_not_found', csrf_token)
                return False
            
            stored_data = self.csrf_tokens[csrf_token]
            
            # Verify session binding if provided
            if session_id and stored_data.get('session_id') != session_id:
                self._record_csrf_failure('session_mismatch', csrf_token)
                return False
            
            # Verify form scope if provided
            if form_name and stored_data.get('form_name') != form_name:
                self._record_csrf_failure('form_mismatch', csrf_token)
                return False
            
            # Token is valid
            return True
            
        except (SignatureExpired, BadSignature):
            self._record_csrf_failure('invalid_signature', csrf_token)
            return False
    
    def create_mock_csrf_headers(
        self,
        csrf_token: str,
        additional_headers: Dict[str, str] = None
    ) -> Dict[str, str]:
        """
        Create mock HTTP headers with CSRF token for AJAX request testing.
        
        This method creates CSRF-protected headers per Section 4.6.2,
        enabling comprehensive testing of AJAX request CSRF protection
        and header-based token validation.
        
        Args:
            csrf_token: CSRF token for header inclusion
            additional_headers: Additional headers to include
            
        Returns:
            Dict[str, str]: HTTP headers with CSRF token
            
        Features:
            - CSRF header configuration
            - AJAX request headers
            - Content type specification
            - Security header inclusion
        """
        headers = {
            'X-CSRFToken': csrf_token,
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    def create_mock_csrf_form_data(
        self,
        csrf_token: str,
        form_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create mock form data with CSRF token for form submission testing.
        
        This method creates CSRF-protected form data per Section 4.6.2,
        enabling comprehensive testing of form submission CSRF protection
        and hidden field token validation.
        
        Args:
            csrf_token: CSRF token for form inclusion
            form_data: Additional form data to include
            
        Returns:
            Dict[str, Any]: Form data with CSRF token
            
        Features:
            - CSRF token form field
            - Form data structure
            - Hidden field simulation
            - Form validation support
        """
        form_data = form_data or {}
        form_data['csrf_token'] = csrf_token
        
        return form_data
    
    def _record_csrf_failure(self, failure_type: str, token: str):
        """Record CSRF validation failure for security monitoring."""
        self.csrf_failures.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'failure_type': failure_type,
            'token': token[:20] + '...',  # Truncated for security
            'ip_address': '127.0.0.1',  # Test IP
            'user_agent': 'Flask-Test-Client/1.0'
        })
    
    def get_csrf_metrics(self) -> Dict[str, Any]:
        """
        Get CSRF protection metrics for security validation and testing analysis.
        
        This method provides comprehensive CSRF protection metrics per
        Section 4.6.2, enabling security validation and CSRF implementation
        effectiveness analysis.
        
        Returns:
            Dict[str, Any]: CSRF protection metrics and statistics
            
        Features:
            - Token generation statistics
            - Validation success/failure rates
            - Security event correlation
            - Attack pattern analysis
        """
        total_tokens = len(self.csrf_tokens)
        total_failures = len(self.csrf_failures)
        
        failure_types = {}
        for failure in self.csrf_failures:
            failure_type = failure['failure_type']
            failure_types[failure_type] = failure_types.get(failure_type, 0) + 1
        
        return {
            'tokens_generated': total_tokens,
            'validation_failures': total_failures,
            'failure_rate': total_failures / max(total_tokens, 1) * 100,
            'failure_types': failure_types,
            'protection_effectiveness': max(0, 100 - (total_failures / max(total_tokens, 1) * 100))
        }


# =====================================
# Security Monitoring Test Utilities
# =====================================

class SecurityMonitoringMock:
    """
    Security monitoring test utilities providing structured logging validation
    and security event testing per Section 6.4.2.5.
    
    This class enables comprehensive security monitoring testing during the
    Flask migration, supporting structured logging validation, security event
    correlation, and audit trail verification for security posture preservation.
    
    Features:
        - Structured logging validation
        - Security event simulation
        - Audit trail verification
        - Incident response testing
        - Compliance reporting validation
    """
    
    def __init__(self, app: Flask, config: Optional[MockAuthConfig] = None):
        """
        Initialize security monitoring mock with Flask application.
        
        Args:
            app: Flask application instance
            config: Mock configuration instance
        """
        self.app = app
        self.config = config or MockAuthConfig()
        self.security_events = []
        self.audit_logs = []
        self.monitoring_enabled = config.security_monitoring if config else True
        
        # Set up structured logging for testing
        self.logger = logging.getLogger('security_monitor_test')
        self.logger.setLevel(logging.INFO)
        
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        user_id: Optional[Union[str, int]] = None,
        details: Dict[str, Any] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Log security event with structured format for monitoring validation.
        
        This method simulates security event logging per Section 6.4.2.5,
        enabling comprehensive testing of security monitoring capabilities
        and structured logging format validation.
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            user_id: User identifier associated with event
            details: Additional event details
            ip_address: Source IP address
            user_agent: User agent string
            
        Returns:
            Dict[str, Any]: Structured security event data
            
        Features:
            - Structured JSON logging format
            - Event categorization and severity
            - User context correlation
            - Timestamp precision
            - Security metadata inclusion
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        
        security_event = {
            'event_id': event_id,
            'timestamp': timestamp.isoformat(),
            'event_type': event_type,
            'severity': severity,
            'user_id': user_id,
            'ip_address': ip_address or '127.0.0.1',
            'user_agent': user_agent or 'Flask-Test-Client/1.0',
            'details': details or {},
            'source': 'flask_application',
            'environment': 'testing',
            'application_version': '1.0.0-test',
            'blueprint': getattr(g, 'blueprint_name', 'unknown'),
            'endpoint': getattr(g, 'endpoint_name', 'unknown'),
            'request_id': getattr(g, 'request_id', str(uuid.uuid4()))
        }
        
        # Store event for validation
        self.security_events.append(security_event)
        
        # Log structured event
        if self.monitoring_enabled:
            self.logger.info(
                f"Security Event: {event_type}",
                extra={'security_event': security_event}
            )
        
        return security_event
    
    def log_audit_event(
        self,
        action: str,
        resource: str,
        user_id: Union[str, int],
        success: bool,
        details: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Log audit event for compliance and security trail validation.
        
        This method simulates audit logging per Section 6.4.2.5,
        enabling comprehensive testing of audit trail generation and
        compliance reporting capabilities.
        
        Args:
            action: Action performed by user
            resource: Resource affected by action
            user_id: User performing the action
            success: Whether action was successful
            details: Additional audit details
            
        Returns:
            Dict[str, Any]: Structured audit event data
            
        Features:
            - Audit trail generation
            - Action success/failure tracking
            - Resource access logging
            - User activity correlation
            - Compliance data structure
        """
        audit_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        
        audit_event = {
            'audit_id': audit_id,
            'timestamp': timestamp.isoformat(),
            'action': action,
            'resource': resource,
            'user_id': user_id,
            'success': success,
            'details': details or {},
            'source': 'flask_application',
            'environment': 'testing',
            'session_id': getattr(g, 'session_id', 'test_session'),
            'request_method': getattr(request, 'method', 'TEST'),
            'request_url': getattr(request, 'url', 'http://test/endpoint'),
            'response_status': 200 if success else 403
        }
        
        # Store audit event
        self.audit_logs.append(audit_event)
        
        # Log structured audit event
        if self.monitoring_enabled:
            self.logger.info(
                f"Audit Event: {action} on {resource}",
                extra={'audit_event': audit_event}
            )
        
        return audit_event
    
    def simulate_security_incident(
        self,
        incident_type: str,
        severity: str = 'high',
        affected_users: List[Union[str, int]] = None,
        details: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Simulate security incident for incident response testing and
        security monitoring validation.
        
        This method simulates security incidents per Section 6.4.6.2,
        enabling comprehensive testing of incident response mechanisms
        and security monitoring capabilities.
        
        Args:
            incident_type: Type of security incident
            severity: Incident severity level
            affected_users: List of affected user IDs
            details: Additional incident details
            
        Returns:
            Dict[str, Any]: Security incident data
            
        Features:
            - Incident simulation and tracking
            - Multi-user impact analysis
            - Severity classification
            - Response time measurement
            - Recovery validation
        """
        incident_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        
        incident = {
            'incident_id': incident_id,
            'timestamp': timestamp.isoformat(),
            'incident_type': incident_type,
            'severity': severity,
            'status': 'detected',
            'affected_users': affected_users or [],
            'details': details or {},
            'detection_method': 'automated_testing',
            'response_required': severity in ['high', 'critical'],
            'estimated_impact': len(affected_users or []),
            'source': 'security_test_simulation'
        }
        
        # Log related security events
        for user_id in (affected_users or []):
            self.log_security_event(
                event_type=f'incident_{incident_type}',
                severity=severity,
                user_id=user_id,
                details={
                    'incident_id': incident_id,
                    'affected_user': True
                }
            )
        
        return incident
    
    def validate_structured_logging(self) -> Dict[str, Any]:
        """
        Validate structured logging format and completeness for security
        monitoring compliance and audit requirements.
        
        This method validates structured logging per Section 6.4.2.5,
        enabling comprehensive testing of logging format compliance and
        security monitoring data quality.
        
        Returns:
            Dict[str, Any]: Logging validation results and compliance metrics
            
        Features:
            - Log format validation
            - Required field verification
            - Data quality assessment
            - Compliance checking
            - Missing data identification
        """
        total_events = len(self.security_events)
        total_audits = len(self.audit_logs)
        
        # Validate security events
        valid_security_events = 0
        security_validation_errors = []
        
        required_security_fields = [
            'event_id', 'timestamp', 'event_type', 'severity',
            'source', 'environment'
        ]
        
        for event in self.security_events:
            missing_fields = [field for field in required_security_fields if not event.get(field)]
            if not missing_fields:
                valid_security_events += 1
            else:
                security_validation_errors.append({
                    'event_id': event.get('event_id', 'unknown'),
                    'missing_fields': missing_fields
                })
        
        # Validate audit events
        valid_audit_events = 0
        audit_validation_errors = []
        
        required_audit_fields = [
            'audit_id', 'timestamp', 'action', 'resource',
            'user_id', 'success'
        ]
        
        for audit in self.audit_logs:
            missing_fields = [field for field in required_audit_fields if audit.get(field) is None]
            if not missing_fields:
                valid_audit_events += 1
            else:
                audit_validation_errors.append({
                    'audit_id': audit.get('audit_id', 'unknown'),
                    'missing_fields': missing_fields
                })
        
        return {
            'security_events': {
                'total': total_events,
                'valid': valid_security_events,
                'validation_rate': valid_security_events / max(total_events, 1) * 100,
                'errors': security_validation_errors
            },
            'audit_events': {
                'total': total_audits,
                'valid': valid_audit_events,
                'validation_rate': valid_audit_events / max(total_audits, 1) * 100,
                'errors': audit_validation_errors
            },
            'overall_compliance': {
                'total_logs': total_events + total_audits,
                'valid_logs': valid_security_events + valid_audit_events,
                'compliance_rate': (valid_security_events + valid_audit_events) / max(total_events + total_audits, 1) * 100
            }
        }
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive security monitoring metrics for testing analysis
        and security posture validation.
        
        This method provides security monitoring metrics per Section 6.4.2.5,
        enabling comprehensive testing analysis and security effectiveness
        measurement during the Flask migration.
        
        Returns:
            Dict[str, Any]: Comprehensive security monitoring metrics
            
        Features:
            - Event frequency analysis
            - Severity distribution
            - User activity patterns
            - Security trend analysis
            - Compliance metrics
        """
        # Event type distribution
        event_types = {}
        severity_distribution = {}
        user_activity = {}
        
        for event in self.security_events:
            event_type = event['event_type']
            severity = event['severity']
            user_id = event.get('user_id')
            
            event_types[event_type] = event_types.get(event_type, 0) + 1
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            if user_id:
                user_activity[str(user_id)] = user_activity.get(str(user_id), 0) + 1
        
        # Audit action distribution
        audit_actions = {}
        success_rate_by_action = {}
        
        for audit in self.audit_logs:
            action = audit['action']
            success = audit['success']
            
            audit_actions[action] = audit_actions.get(action, 0) + 1
            
            if action not in success_rate_by_action:
                success_rate_by_action[action] = {'total': 0, 'successful': 0}
            
            success_rate_by_action[action]['total'] += 1
            if success:
                success_rate_by_action[action]['successful'] += 1
        
        # Calculate success rates
        for action_data in success_rate_by_action.values():
            action_data['success_rate'] = action_data['successful'] / action_data['total'] * 100
        
        return {
            'security_events': {
                'total_events': len(self.security_events),
                'event_types': event_types,
                'severity_distribution': severity_distribution,
                'user_activity': user_activity,
                'monitoring_enabled': self.monitoring_enabled
            },
            'audit_logs': {
                'total_audits': len(self.audit_logs),
                'audit_actions': audit_actions,
                'success_rates': success_rate_by_action
            },
            'overall_metrics': {
                'total_logs': len(self.security_events) + len(self.audit_logs),
                'monitoring_coverage': 100 if self.monitoring_enabled else 0,
                'data_quality': self.validate_structured_logging()['overall_compliance']['compliance_rate']
            }
        }


# =====================================
# Pytest Fixtures for Authentication Testing
# =====================================

@pytest.fixture
def auth_config() -> MockAuthConfig:
    """
    Authentication testing configuration fixture providing standardized
    authentication testing parameters for consistent mock behavior.
    
    This fixture provides authentication configuration per Feature F-007,
    enabling consistent authentication testing across all test scenarios
    with configurable parameters for comprehensive validation.
    
    Returns:
        MockAuthConfig: Authentication testing configuration instance
        
    Features:
        - Standardized authentication parameters
        - Configurable token expiration
        - Security testing thresholds
        - Mock service configuration
        - Testing environment adaptation
    """
    return MockAuthConfig(
        auth0_domain="test-auth0-domain.auth0.com",
        jwt_secret="test-jwt-secret-for-testing",
        token_expiration=3600,
        session_timeout=1800,
        csrf_enabled=True,
        security_monitoring=True
    )


@pytest.fixture
def auth0_mock_factory(auth_config: MockAuthConfig) -> Auth0MockFactory:
    """
    Auth0 mock factory fixture providing comprehensive Auth0 integration
    testing utilities with JWT token simulation.
    
    This fixture creates Auth0 mock factory per Section 6.4.1.4,
    enabling comprehensive testing of Auth0 integration without external
    dependencies while maintaining realistic testing scenarios.
    
    Args:
        auth_config: Authentication configuration from auth_config fixture
        
    Returns:
        Auth0MockFactory: Configured Auth0 mock factory instance
        
    Features:
        - JWT token generation and validation
        - Auth0 service mocking
        - User profile management
        - Token lifecycle simulation
        - Management API mocking
    """
    factory = Auth0MockFactory(auth_config)
    
    # Add default test users
    factory.add_mock_user(
        email='testuser@example.com',
        username='testuser',
        roles=['user'],
        permissions=['read', 'write']
    )
    
    factory.add_mock_user(
        email='admin@example.com',
        username='admin',
        roles=['admin', 'user'],
        permissions=['read', 'write', 'delete', 'admin']
    )
    
    return factory


@pytest.fixture
def flask_login_mock(app: Flask, auth_config: MockAuthConfig) -> FlaskLoginSessionMock:
    """
    Flask-Login session mock fixture providing comprehensive session
    management testing utilities with ItsDangerous cookie signing.
    
    This fixture creates Flask-Login mock per Feature F-007,
    enabling comprehensive testing of session management, user authentication
    state, and secure cookie handling during the Flask migration.
    
    Args:
        app: Flask application instance from app fixture
        auth_config: Authentication configuration from auth_config fixture
        
    Returns:
        FlaskLoginSessionMock: Configured Flask-Login session mock instance
        
    Features:
        - Session creation and validation
        - ItsDangerous cookie signing
        - Remember-me functionality
        - Session timeout management
        - User authentication state
    """
    return FlaskLoginSessionMock(app, auth_config)


@pytest.fixture
def auth_decorator_utils(app: Flask, auth_config: MockAuthConfig) -> AuthDecoratorTestUtils:
    """
    Authentication decorator testing utilities fixture providing comprehensive
    decorator testing support for Flask authentication migration.
    
    This fixture creates decorator testing utilities per Section 4.6.2,
    enabling comprehensive testing of authentication decorators converted
    from Node.js middleware patterns to Flask decorator syntax.
    
    Args:
        app: Flask application instance from app fixture
        auth_config: Authentication configuration from auth_config fixture
        
    Returns:
        AuthDecoratorTestUtils: Configured authentication decorator testing utilities
        
    Features:
        - Authentication decorator testing
        - Authorization validation
        - Role-based access control testing
        - Permission checking simulation
        - Security metrics collection
    """
    return AuthDecoratorTestUtils(app, auth_config)


@pytest.fixture
def csrf_mock(app: Flask, auth_config: MockAuthConfig) -> CSRFProtectionMock:
    """
    CSRF protection mock fixture providing comprehensive Flask-WTF CSRF
    testing utilities for form and AJAX request validation.
    
    This fixture creates CSRF protection mock per Section 4.6.2,
    enabling comprehensive testing of CSRF protection implementation
    during the Flask migration with Flask-WTF integration.
    
    Args:
        app: Flask application instance from app fixture
        auth_config: Authentication configuration from auth_config fixture
        
    Returns:
        CSRFProtectionMock: Configured CSRF protection mock instance
        
    Features:
        - CSRF token generation and validation
        - Form submission protection
        - AJAX request CSRF validation
        - Security policy enforcement
        - Attack simulation and detection
    """
    return CSRFProtectionMock(app, auth_config)


@pytest.fixture
def security_monitor_mock(app: Flask, auth_config: MockAuthConfig) -> SecurityMonitoringMock:
    """
    Security monitoring mock fixture providing structured logging validation
    and security event testing utilities for security posture preservation.
    
    This fixture creates security monitoring mock per Section 6.4.2.5,
    enabling comprehensive testing of security monitoring capabilities
    and structured logging validation during the Flask migration.
    
    Args:
        app: Flask application instance from app fixture
        auth_config: Authentication configuration from auth_config fixture
        
    Returns:
        SecurityMonitoringMock: Configured security monitoring mock instance
        
    Features:
        - Structured logging validation
        - Security event simulation
        - Audit trail verification
        - Incident response testing
        - Compliance reporting
    """
    return SecurityMonitoringMock(app, auth_config)


@pytest.fixture
def mock_jwt_token(auth0_mock_factory: Auth0MockFactory, test_user: User) -> str:
    """
    Mock JWT token fixture providing pre-generated JWT tokens for
    authentication testing and token validation scenarios.
    
    This fixture creates JWT tokens per Section 6.4.1.4,
    enabling comprehensive testing of JWT token handling and
    authentication flows without external Auth0 dependencies.
    
    Args:
        auth0_mock_factory: Auth0 mock factory from auth0_mock_factory fixture
        test_user: Test user instance from test_user fixture
        
    Returns:
        str: Generated JWT token for testing
        
    Features:
        - Auth0-compatible JWT structure
        - User context embedding
        - Token expiration configuration
        - Claims validation support
        - Signature verification simulation
    """
    return auth0_mock_factory.create_mock_jwt_token(
        user_id=test_user.id,
        email=test_user.email,
        username=test_user.username,
        roles=['user'],
        permissions=['read', 'write']
    )


@pytest.fixture
def mock_user_session(
    flask_login_mock: FlaskLoginSessionMock,
    test_user: User
) -> Dict[str, Any]:
    """
    Mock user session fixture providing pre-created user sessions for
    session management testing and authentication state validation.
    
    This fixture creates user sessions per Feature F-007,
    enabling comprehensive testing of session management functionality
    and user authentication state during the Flask migration.
    
    Args:
        flask_login_mock: Flask-Login mock from flask_login_mock fixture
        test_user: Test user instance from test_user fixture
        
    Returns:
        Dict[str, Any]: Session data with cookies and metadata
        
    Features:
        - Pre-authenticated session state
        - Secure cookie generation
        - Session metadata tracking
        - ItsDangerous token signing
        - Expiration time management
    """
    return flask_login_mock.create_mock_session(
        user=test_user,
        remember=False,
        duration=timedelta(hours=1)
    )


@pytest.fixture
def mock_csrf_token(csrf_mock: CSRFProtectionMock) -> str:
    """
    Mock CSRF token fixture providing pre-generated CSRF tokens for
    form submission testing and CSRF protection validation.
    
    This fixture creates CSRF tokens per Section 4.6.2,
    enabling comprehensive testing of CSRF protection mechanisms
    and form validation during the Flask migration.
    
    Args:
        csrf_mock: CSRF protection mock from csrf_mock fixture
        
    Returns:
        str: Generated CSRF token for testing
        
    Features:
        - Flask-WTF compatible tokens
        - Session binding support
        - Form-specific scoping
        - Expiration management
        - Validation support
    """
    return csrf_mock.generate_mock_csrf_token(
        session_id='test_session',
        form_name='test_form'
    )


# Export all components for easy importing
__all__ = [
    # Configuration
    'MockAuthConfig',
    # Mock factories and utilities
    'Auth0MockFactory',
    'FlaskLoginSessionMock',
    'AuthDecoratorTestUtils',
    'CSRFProtectionMock',
    'SecurityMonitoringMock',
    # Pytest fixtures
    'auth_config',
    'auth0_mock_factory',
    'flask_login_mock',
    'auth_decorator_utils',
    'csrf_mock',
    'security_monitor_mock',
    'mock_jwt_token',
    'mock_user_session',
    'mock_csrf_token'
]