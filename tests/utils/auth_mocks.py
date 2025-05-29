"""
Authentication Testing Utilities

This module provides comprehensive authentication testing utilities for the Flask migration project,
enabling thorough testing of Auth0 integration, Flask-Login session management, and authentication
decorator functionality. The utilities support the Node.js to Flask migration by providing mock
factories and testing patterns that ensure security posture preservation and authentication flow
validation.

Key Components:
- Auth0 mock factories with JWT token simulation per Section 6.4.1.4
- Flask-Login session mocks with ItsDangerous cookie signing per Feature F-007
- Authentication decorator testing utilities per Section 4.6.2
- CSRF protection testing mocks with Flask-WTF integration per Section 4.6.2
- User authentication state mocks for comprehensive test coverage per Feature F-007
- Security monitoring test utilities with structured logging validation per Section 6.4.2.5

Dependencies:
- src/auth/decorators.py: Authentication decorator patterns
- src/auth/auth0_integration.py: Auth0 Python SDK integration
- src/auth/session_manager.py: Flask-Login session management
- tests/utils/flask_fixtures.py: Core Flask testing infrastructure

Usage:
    import pytest
    from tests.utils.auth_mocks import (
        Auth0MockFactory,
        FlaskLoginMockFactory,
        CSRFMockFactory,
        UserAuthStateMocks,
        SecurityMonitoringMocks
    )
    
    def test_authentication_flow(auth_mock_factory):
        mock_user = auth_mock_factory.create_authenticated_user()
        assert mock_user.is_authenticated
"""

import pytest
import json
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from dataclasses import dataclass, asdict
from flask import Flask, request, session, g
from flask_login import UserMixin, AnonymousUserMixin
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.test import Client
from werkzeug.security import generate_password_hash
import jwt
import secrets
import structlog
from collections import defaultdict, deque

# Production-ready imports for mocking authentication components
try:
    from src.auth.decorators import require_auth, require_permission, require_role
    from src.auth.auth0_integration import Auth0Integration
    from src.auth.session_manager import SessionManager
    from src.auth.csrf_protection import CSRFProtection
    from src.auth.token_handler import TokenHandler
    from src.auth.security_monitor import SecurityMonitor
    from src.models.user import User
except ImportError:
    # Graceful fallback for development environments
    require_auth = None
    require_permission = None
    require_role = None
    Auth0Integration = None
    SessionManager = None
    CSRFProtection = None
    TokenHandler = None
    SecurityMonitor = None
    User = None


@dataclass
class MockJWTToken:
    """Mock JWT token structure for Auth0 testing."""
    access_token: str
    refresh_token: Optional[str]
    id_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: str = "openid profile email"
    issued_at: float = None
    expires_at: float = None
    
    def __post_init__(self):
        if self.issued_at is None:
            self.issued_at = time.time()
        if self.expires_at is None:
            self.expires_at = self.issued_at + self.expires_in


@dataclass
class MockAuth0User:
    """Mock Auth0 user profile for testing."""
    user_id: str
    email: str
    username: str
    name: str
    picture: Optional[str] = None
    email_verified: bool = True
    roles: List[str] = None
    permissions: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.roles is None:
            self.roles = ["user"]
        if self.permissions is None:
            self.permissions = ["read"]
        if self.metadata is None:
            self.metadata = {}


@dataclass
class MockUserSession:
    """Mock user session data for Flask-Login testing."""
    user_id: str
    session_id: str
    is_authenticated: bool = True
    is_active: bool = True
    is_anonymous: bool = False
    login_time: datetime = None
    last_activity: datetime = None
    remember_me: bool = False
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def __post_init__(self):
        if self.login_time is None:
            self.login_time = datetime.utcnow()
        if self.last_activity is None:
            self.last_activity = datetime.utcnow()


class MockFlaskLoginUser(UserMixin):
    """Mock Flask-Login user class for testing authentication decorators."""
    
    def __init__(self, 
                 user_id: str,
                 email: str,
                 username: str,
                 roles: List[str] = None,
                 permissions: List[str] = None,
                 is_authenticated: bool = True,
                 is_active: bool = True):
        self.id = user_id
        self.email = email
        self.username = username
        self.roles = roles or ["user"]
        self.permissions = permissions or ["read"]
        self._is_authenticated = is_authenticated
        self._is_active = is_active
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    @property
    def is_authenticated(self):
        return self._is_authenticated
    
    @property
    def is_active(self):
        return self._is_active
    
    @property
    def is_anonymous(self):
        return False
    
    def get_id(self):
        return str(self.id)
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in self.permissions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "roles": self.roles,
            "permissions": self.permissions,
            "is_authenticated": self.is_authenticated,
            "is_active": self.is_active
        }


class Auth0MockFactory:
    """
    Comprehensive Auth0 mock factory providing JWT token simulation and Auth0 integration testing.
    
    This factory creates realistic Auth0 authentication scenarios for testing the migration
    from Node.js middleware to Flask authentication decorators per Section 6.4.1.4.
    """
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.issuer = "https://test-tenant.auth0.com/"
        self.audience = "flask-test-app"
        self.algorithm = "HS256"
        self._mock_users = {}
        self._issued_tokens = {}
        self._revoked_tokens = set()
    
    def create_mock_user(self, 
                        user_id: str = None,
                        email: str = None,
                        username: str = None,
                        roles: List[str] = None,
                        permissions: List[str] = None) -> MockAuth0User:
        """Create a mock Auth0 user with realistic profile data."""
        user_id = user_id or f"auth0|{uuid.uuid4().hex[:24]}"
        email = email or f"test.user.{uuid.uuid4().hex[:8]}@example.com"
        username = username or f"testuser_{uuid.uuid4().hex[:8]}"
        
        user = MockAuth0User(
            user_id=user_id,
            email=email,
            username=username,
            name=f"Test User {username}",
            picture=f"https://example.com/avatar/{user_id}.jpg",
            roles=roles or ["user"],
            permissions=permissions or ["read"],
            metadata={
                "app_metadata": {"plan": "free", "roles": roles or ["user"]},
                "user_metadata": {"preferences": {"theme": "light"}}
            }
        )
        
        self._mock_users[user_id] = user
        return user
    
    def generate_jwt_token(self, 
                          user: MockAuth0User,
                          token_type: str = "access",
                          expires_in: int = 3600,
                          custom_claims: Dict[str, Any] = None) -> str:
        """Generate a realistic JWT token for testing."""
        now = time.time()
        exp = now + expires_in
        
        # Standard JWT claims
        claims = {
            "iss": self.issuer,
            "sub": user.user_id,
            "aud": self.audience,
            "iat": int(now),
            "exp": int(exp),
            "azp": "test_client_id",
            "scope": "openid profile email"
        }
        
        # Token type specific claims
        if token_type == "access":
            claims.update({
                "permissions": user.permissions,
                "roles": user.roles,
                "email": user.email,
                "email_verified": user.email_verified
            })
        elif token_type == "id":
            claims.update({
                "name": user.name,
                "picture": user.picture,
                "email": user.email,
                "email_verified": user.email_verified,
                "username": user.username
            })
        
        # Add custom claims
        if custom_claims:
            claims.update(custom_claims)
        
        token = jwt.encode(claims, self.secret_key, algorithm=self.algorithm)
        self._issued_tokens[token] = {
            "user_id": user.user_id,
            "type": token_type,
            "issued_at": now,
            "expires_at": exp
        }
        
        return token
    
    def create_token_set(self, 
                        user: MockAuth0User,
                        include_refresh: bool = True) -> MockJWTToken:
        """Create a complete token set for authentication testing."""
        access_token = self.generate_jwt_token(user, "access")
        id_token = self.generate_jwt_token(user, "id")
        refresh_token = None
        
        if include_refresh:
            refresh_token = self.generate_jwt_token(
                user, "refresh", expires_in=86400 * 30  # 30 days
            )
        
        return MockJWTToken(
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=id_token
        )
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate a JWT token and return claims."""
        if token in self._revoked_tokens:
            raise jwt.InvalidTokenError("Token has been revoked")
        
        try:
            claims = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )
            return claims
        except jwt.ExpiredSignatureError:
            raise jwt.ExpiredSignatureError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise jwt.InvalidTokenError(f"Invalid token: {str(e)}")
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a JWT token for testing token revocation flows."""
        self._revoked_tokens.add(token)
        return True
    
    def create_auth0_mock(self) -> Mock:
        """Create a comprehensive Auth0 integration mock."""
        auth0_mock = Mock(spec=Auth0Integration)
        
        # Configure authentication methods
        auth0_mock.authenticate_user.side_effect = self._mock_authenticate_user
        auth0_mock.validate_token.side_effect = self.validate_token
        auth0_mock.refresh_token.side_effect = self._mock_refresh_token
        auth0_mock.revoke_token.side_effect = self.revoke_token
        auth0_mock.get_user_info.side_effect = self._mock_get_user_info
        
        return auth0_mock
    
    def _mock_authenticate_user(self, email: str, password: str) -> Optional[MockJWTToken]:
        """Mock user authentication."""
        # Find user by email
        user = None
        for mock_user in self._mock_users.values():
            if mock_user.email == email:
                user = mock_user
                break
        
        if user:
            return self.create_token_set(user)
        return None
    
    def _mock_refresh_token(self, refresh_token: str) -> MockJWTToken:
        """Mock token refresh."""
        claims = self.validate_token(refresh_token)
        user_id = claims["sub"]
        
        if user_id in self._mock_users:
            user = self._mock_users[user_id]
            return self.create_token_set(user)
        
        raise jwt.InvalidTokenError("Invalid refresh token")
    
    def _mock_get_user_info(self, access_token: str) -> MockAuth0User:
        """Mock user info retrieval."""
        claims = self.validate_token(access_token)
        user_id = claims["sub"]
        
        if user_id in self._mock_users:
            return self._mock_users[user_id]
        
        raise jwt.InvalidTokenError("User not found")


class FlaskLoginMockFactory:
    """
    Flask-Login session mock factory providing comprehensive session simulation with ItsDangerous
    cookie signing per Feature F-007. Enables testing of Flask-Login session management patterns
    during the Node.js to Flask migration.
    """
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.serializer = URLSafeTimedSerializer(self.secret_key)
        self._active_sessions = {}
        self._session_cookies = {}
    
    def create_mock_user(self, 
                        user_id: str = None,
                        email: str = None,
                        username: str = None,
                        roles: List[str] = None,
                        permissions: List[str] = None,
                        is_authenticated: bool = True) -> MockFlaskLoginUser:
        """Create a mock Flask-Login user for testing."""
        user_id = user_id or str(uuid.uuid4())
        email = email or f"test.user.{uuid.uuid4().hex[:8]}@example.com"
        username = username or f"testuser_{uuid.uuid4().hex[:8]}"
        
        return MockFlaskLoginUser(
            user_id=user_id,
            email=email,
            username=username,
            roles=roles,
            permissions=permissions,
            is_authenticated=is_authenticated
        )
    
    def create_session_data(self,
                           user: MockFlaskLoginUser,
                           remember_me: bool = False,
                           ip_address: str = None,
                           user_agent: str = None) -> MockUserSession:
        """Create mock session data for Flask-Login testing."""
        session_id = str(uuid.uuid4())
        
        session_data = MockUserSession(
            user_id=user.get_id(),
            session_id=session_id,
            is_authenticated=user.is_authenticated,
            is_active=user.is_active,
            remember_me=remember_me,
            ip_address=ip_address or "127.0.0.1",
            user_agent=user_agent or "pytest-test-client/1.0"
        )
        
        self._active_sessions[session_id] = session_data
        return session_data
    
    def sign_session_cookie(self, 
                           session_data: MockUserSession,
                           max_age: int = 3600) -> str:
        """Sign session data using ItsDangerous for secure cookie simulation."""
        cookie_data = {
            "user_id": session_data.user_id,
            "session_id": session_data.session_id,
            "login_time": session_data.login_time.isoformat(),
            "remember_me": session_data.remember_me
        }
        
        signed_cookie = self.serializer.dumps(cookie_data, max_age=max_age)
        self._session_cookies[session_data.session_id] = signed_cookie
        return signed_cookie
    
    def validate_session_cookie(self, 
                               signed_cookie: str,
                               max_age: int = 3600) -> Dict[str, Any]:
        """Validate a signed session cookie using ItsDangerous."""
        try:
            cookie_data = self.serializer.loads(signed_cookie, max_age=max_age)
            return cookie_data
        except SignatureExpired:
            raise SignatureExpired("Session cookie has expired")
        except BadSignature:
            raise BadSignature("Invalid session cookie signature")
    
    def create_login_manager_mock(self) -> Mock:
        """Create a comprehensive Flask-Login LoginManager mock."""
        login_manager_mock = Mock()
        
        # Configure user loader
        login_manager_mock.user_loader = Mock()
        login_manager_mock.request_loader = Mock()
        login_manager_mock.header_loader = Mock()
        
        # Configure session protection
        login_manager_mock.session_protection = "strong"
        login_manager_mock.login_view = "auth.login"
        login_manager_mock.login_message = "Please log in to access this page."
        login_manager_mock.needs_refresh_message = "Please reauthenticate to access this page."
        
        return login_manager_mock
    
    def mock_current_user(self, user: MockFlaskLoginUser = None) -> Mock:
        """Create a mock current_user for Flask-Login testing."""
        if user is None:
            # Return anonymous user
            anonymous_mock = Mock(spec=AnonymousUserMixin)
            anonymous_mock.is_authenticated = False
            anonymous_mock.is_active = False
            anonymous_mock.is_anonymous = True
            anonymous_mock.get_id.return_value = None
            return anonymous_mock
        
        # Return authenticated user mock
        user_mock = Mock(spec=MockFlaskLoginUser)
        user_mock.id = user.id
        user_mock.email = user.email
        user_mock.username = user.username
        user_mock.roles = user.roles
        user_mock.permissions = user.permissions
        user_mock.is_authenticated = user.is_authenticated
        user_mock.is_active = user.is_active
        user_mock.is_anonymous = False
        user_mock.get_id.return_value = user.get_id()
        user_mock.has_role.side_effect = user.has_role
        user_mock.has_permission.side_effect = user.has_permission
        
        return user_mock


class CSRFMockFactory:
    """
    CSRF protection testing utilities providing Flask-WTF integration mocks per Section 4.6.2.
    Enables comprehensive testing of CSRF protection during the Node.js to Flask migration.
    """
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.serializer = URLSafeTimedSerializer(self.secret_key)
        self._generated_tokens = set()
    
    def generate_csrf_token(self, 
                           session_id: str = None,
                           max_age: int = 3600) -> str:
        """Generate a CSRF token for testing."""
        session_id = session_id or str(uuid.uuid4())
        timestamp = int(time.time())
        
        token_data = {
            "session_id": session_id,
            "timestamp": timestamp,
            "nonce": secrets.token_hex(16)
        }
        
        csrf_token = self.serializer.dumps(token_data, max_age=max_age)
        self._generated_tokens.add(csrf_token)
        return csrf_token
    
    def validate_csrf_token(self, 
                           csrf_token: str,
                           session_id: str = None,
                           max_age: int = 3600) -> bool:
        """Validate a CSRF token."""
        try:
            token_data = self.serializer.loads(csrf_token, max_age=max_age)
            
            # Validate session ID if provided
            if session_id and token_data.get("session_id") != session_id:
                return False
            
            return csrf_token in self._generated_tokens
        except (SignatureExpired, BadSignature):
            return False
    
    def create_csrf_protection_mock(self) -> Mock:
        """Create a Flask-WTF CSRFProtect mock."""
        csrf_mock = Mock(spec=CSRFProtection)
        
        # Configure CSRF methods
        csrf_mock.generate_csrf.side_effect = self.generate_csrf_token
        csrf_mock.validate_csrf.side_effect = self.validate_csrf_token
        csrf_mock.exempt_views = set()
        
        return csrf_mock
    
    def create_form_with_csrf(self, 
                             csrf_token: str = None,
                             form_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create form data with CSRF token for testing."""
        csrf_token = csrf_token or self.generate_csrf_token()
        form_data = form_data or {}
        
        form_data["csrf_token"] = csrf_token
        return form_data


class UserAuthStateMocks:
    """
    User authentication state mocks providing comprehensive test coverage for various
    authentication scenarios per Feature F-007. Enables testing of different user
    states and permission combinations during Flask migration.
    """
    
    def __init__(self):
        self.auth0_factory = Auth0MockFactory()
        self.flask_login_factory = FlaskLoginMockFactory()
        self._user_scenarios = {}
    
    def create_authenticated_user(self, 
                                 roles: List[str] = None,
                                 permissions: List[str] = None,
                                 **kwargs) -> MockFlaskLoginUser:
        """Create an authenticated user for testing."""
        return self.flask_login_factory.create_mock_user(
            roles=roles or ["user"],
            permissions=permissions or ["read"],
            is_authenticated=True,
            **kwargs
        )
    
    def create_anonymous_user(self) -> Mock:
        """Create an anonymous user for testing."""
        return self.flask_login_factory.mock_current_user(None)
    
    def create_admin_user(self, **kwargs) -> MockFlaskLoginUser:
        """Create an admin user with elevated permissions."""
        return self.flask_login_factory.create_mock_user(
            roles=["admin", "user"],
            permissions=["read", "write", "delete", "admin"],
            is_authenticated=True,
            **kwargs
        )
    
    def create_inactive_user(self, **kwargs) -> MockFlaskLoginUser:
        """Create an inactive user for testing access denial."""
        user = self.flask_login_factory.create_mock_user(
            is_authenticated=False,
            **kwargs
        )
        user._is_active = False
        return user
    
    def create_user_scenario(self, 
                           scenario_name: str,
                           user_config: Dict[str, Any]) -> MockFlaskLoginUser:
        """Create and cache a user scenario for reuse."""
        user = self.flask_login_factory.create_mock_user(**user_config)
        self._user_scenarios[scenario_name] = user
        return user
    
    def get_user_scenario(self, scenario_name: str) -> Optional[MockFlaskLoginUser]:
        """Get a cached user scenario."""
        return self._user_scenarios.get(scenario_name)
    
    def create_permission_matrix(self) -> Dict[str, MockFlaskLoginUser]:
        """Create a matrix of users with different permission combinations."""
        return {
            "guest": self.create_anonymous_user(),
            "user": self.create_authenticated_user(
                roles=["user"],
                permissions=["read"]
            ),
            "moderator": self.create_authenticated_user(
                roles=["moderator", "user"],
                permissions=["read", "write", "moderate"]
            ),
            "admin": self.create_admin_user(),
            "inactive": self.create_inactive_user()
        }


class SecurityMonitoringMocks:
    """
    Security monitoring test utilities with structured logging validation per Section 6.4.2.5.
    Provides comprehensive testing capabilities for security event logging, anomaly detection,
    and incident response during the Flask migration.
    """
    
    def __init__(self):
        self.logger = structlog.get_logger("test_security_monitor")
        self._logged_events = []
        self._security_metrics = defaultdict(int)
        self._anomaly_detections = []
        self._incident_responses = []
    
    def create_security_monitor_mock(self) -> Mock:
        """Create a comprehensive security monitoring mock."""
        security_mock = Mock(spec=SecurityMonitor)
        
        # Configure monitoring methods
        security_mock.log_authentication_attempt.side_effect = self._mock_log_auth_attempt
        security_mock.log_authorization_event.side_effect = self._mock_log_authz_event
        security_mock.detect_anomaly.side_effect = self._mock_detect_anomaly
        security_mock.trigger_incident_response.side_effect = self._mock_trigger_incident
        security_mock.get_security_metrics.side_effect = self._mock_get_metrics
        
        return security_mock
    
    def _mock_log_auth_attempt(self, 
                              user_id: str,
                              success: bool,
                              method: str = "password",
                              ip_address: str = None,
                              user_agent: str = None):
        """Mock authentication attempt logging."""
        event = {
            "event_type": "authentication_attempt",
            "user_id": user_id,
            "success": success,
            "method": method,
            "ip_address": ip_address or "127.0.0.1",
            "user_agent": user_agent or "test-client",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self._logged_events.append(event)
        self._security_metrics["auth_attempts"] += 1
        
        if success:
            self._security_metrics["auth_successes"] += 1
        else:
            self._security_metrics["auth_failures"] += 1
            
        self.logger.info("Authentication attempt logged", **event)
    
    def _mock_log_authz_event(self,
                             user_id: str,
                             resource: str,
                             action: str,
                             granted: bool,
                             reason: str = None):
        """Mock authorization event logging."""
        event = {
            "event_type": "authorization_event",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "granted": granted,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self._logged_events.append(event)
        self._security_metrics["authz_events"] += 1
        
        if granted:
            self._security_metrics["authz_granted"] += 1
        else:
            self._security_metrics["authz_denied"] += 1
            
        self.logger.info("Authorization event logged", **event)
    
    def _mock_detect_anomaly(self,
                            anomaly_type: str,
                            severity: str,
                            details: Dict[str, Any]):
        """Mock anomaly detection."""
        anomaly = {
            "anomaly_type": anomaly_type,
            "severity": severity,
            "details": details,
            "detection_time": datetime.utcnow().isoformat(),
            "id": str(uuid.uuid4())
        }
        
        self._anomaly_detections.append(anomaly)
        self._security_metrics["anomalies_detected"] += 1
        
        self.logger.warning("Security anomaly detected", **anomaly)
        return anomaly["id"]
    
    def _mock_trigger_incident(self,
                              incident_type: str,
                              severity: str,
                              user_id: str = None,
                              details: Dict[str, Any] = None):
        """Mock incident response trigger."""
        incident = {
            "incident_type": incident_type,
            "severity": severity,
            "user_id": user_id,
            "details": details or {},
            "triggered_time": datetime.utcnow().isoformat(),
            "id": str(uuid.uuid4()),
            "status": "triggered"
        }
        
        self._incident_responses.append(incident)
        self._security_metrics["incidents_triggered"] += 1
        
        self.logger.error("Security incident triggered", **incident)
        return incident["id"]
    
    def _mock_get_metrics(self) -> Dict[str, int]:
        """Mock security metrics retrieval."""
        return dict(self._security_metrics)
    
    def get_logged_events(self, event_type: str = None) -> List[Dict[str, Any]]:
        """Get logged security events for testing validation."""
        if event_type:
            return [event for event in self._logged_events 
                   if event.get("event_type") == event_type]
        return self._logged_events.copy()
    
    def get_anomaly_detections(self) -> List[Dict[str, Any]]:
        """Get detected anomalies for testing validation."""
        return self._anomaly_detections.copy()
    
    def get_incident_responses(self) -> List[Dict[str, Any]]:
        """Get triggered incidents for testing validation."""
        return self._incident_responses.copy()
    
    def clear_test_data(self):
        """Clear all test data for fresh test scenarios."""
        self._logged_events.clear()
        self._security_metrics.clear()
        self._anomaly_detections.clear()
        self._incident_responses.clear()


# Pytest fixtures for convenient testing
@pytest.fixture
def auth0_mock_factory():
    """Provide Auth0 mock factory for testing."""
    return Auth0MockFactory()


@pytest.fixture
def flask_login_mock_factory():
    """Provide Flask-Login mock factory for testing."""
    return FlaskLoginMockFactory()


@pytest.fixture
def csrf_mock_factory():
    """Provide CSRF protection mock factory for testing."""
    return CSRFMockFactory()


@pytest.fixture
def user_auth_state_mocks():
    """Provide user authentication state mocks for testing."""
    return UserAuthStateMocks()


@pytest.fixture
def security_monitoring_mocks():
    """Provide security monitoring mocks for testing."""
    return SecurityMonitoringMocks()


@pytest.fixture
def authenticated_user(flask_login_mock_factory):
    """Provide an authenticated user for testing."""
    return flask_login_mock_factory.create_mock_user(
        roles=["user"],
        permissions=["read"],
        is_authenticated=True
    )


@pytest.fixture
def admin_user(flask_login_mock_factory):
    """Provide an admin user for testing."""
    return flask_login_mock_factory.create_mock_user(
        roles=["admin", "user"],
        permissions=["read", "write", "delete", "admin"],
        is_authenticated=True
    )


@pytest.fixture
def anonymous_user(flask_login_mock_factory):
    """Provide an anonymous user for testing."""
    return flask_login_mock_factory.mock_current_user(None)


@pytest.fixture
def auth_token_set(auth0_mock_factory):
    """Provide a complete Auth0 token set for testing."""
    user = auth0_mock_factory.create_mock_user()
    return auth0_mock_factory.create_token_set(user)


@pytest.fixture
def csrf_token(csrf_mock_factory):
    """Provide a CSRF token for testing."""
    return csrf_mock_factory.generate_csrf_token()


# Utility functions for authentication testing
def mock_authentication_decorators():
    """
    Mock authentication decorators for testing without actual authentication.
    
    This utility allows testing of route logic without requiring actual
    authentication infrastructure during unit testing.
    """
    def mock_require_auth(f):
        """Mock authentication requirement decorator."""
        def wrapper(*args, **kwargs):
            # Mock authentication check
            if not hasattr(g, 'current_user') or not g.current_user.is_authenticated:
                return {"error": "Authentication required"}, 401
            return f(*args, **kwargs)
        return wrapper
    
    def mock_require_permission(permission):
        """Mock permission requirement decorator."""
        def decorator(f):
            def wrapper(*args, **kwargs):
                # Mock permission check
                if not hasattr(g, 'current_user') or not g.current_user.has_permission(permission):
                    return {"error": f"Permission '{permission}' required"}, 403
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    def mock_require_role(role):
        """Mock role requirement decorator."""
        def decorator(f):
            def wrapper(*args, **kwargs):
                # Mock role check
                if not hasattr(g, 'current_user') or not g.current_user.has_role(role):
                    return {"error": f"Role '{role}' required"}, 403
                return f(*args, **kwargs)
            return wrapper
        return decorator
    
    return {
        "require_auth": mock_require_auth,
        "require_permission": mock_require_permission,
        "require_role": mock_require_role
    }


def create_test_request_context(app: Flask, 
                               user: MockFlaskLoginUser = None,
                               csrf_token: str = None,
                               headers: Dict[str, str] = None):
    """
    Create a test request context with authentication and CSRF setup.
    
    This utility function provides a convenient way to set up request contexts
    for testing authentication flows and decorators.
    """
    with app.test_request_context(headers=headers or {}):
        # Set up user context
        if user:
            g.current_user = user
            session['user_id'] = user.get_id()
            session['_user_id'] = user.get_id()
        else:
            g.current_user = Mock(is_authenticated=False, is_anonymous=True)
        
        # Set up CSRF token
        if csrf_token:
            session['csrf_token'] = csrf_token
        
        yield


class AuthenticationTestingPatterns:
    """
    Collection of common authentication testing patterns for Flask migration.
    
    This class provides standardized testing patterns that ensure comprehensive
    coverage of authentication scenarios during the Node.js to Flask migration.
    """
    
    @staticmethod
    def test_decorator_authentication_required(route_function, 
                                             test_client: Client,
                                             authenticated_user: MockFlaskLoginUser):
        """Test that a route requires authentication."""
        # Test unauthenticated access
        response = test_client.get('/protected-route')
        assert response.status_code == 401
        
        # Test authenticated access
        with test_client.session_transaction() as sess:
            sess['user_id'] = authenticated_user.get_id()
        
        response = test_client.get('/protected-route')
        assert response.status_code in [200, 302]  # Success or redirect
    
    @staticmethod
    def test_permission_based_access(route_function,
                                   test_client: Client,
                                   user_with_permission: MockFlaskLoginUser,
                                   user_without_permission: MockFlaskLoginUser,
                                   required_permission: str):
        """Test permission-based access control."""
        # Test user without permission
        with test_client.session_transaction() as sess:
            sess['user_id'] = user_without_permission.get_id()
        
        response = test_client.get('/protected-route')
        assert response.status_code == 403
        
        # Test user with permission
        with test_client.session_transaction() as sess:
            sess['user_id'] = user_with_permission.get_id()
        
        response = test_client.get('/protected-route')
        assert response.status_code in [200, 302]
    
    @staticmethod
    def test_csrf_protection(route_function,
                           test_client: Client,
                           csrf_token: str,
                           form_data: Dict[str, Any]):
        """Test CSRF protection on form submissions."""
        # Test POST without CSRF token
        response = test_client.post('/protected-form', data=form_data)
        assert response.status_code == 400  # CSRF validation failure
        
        # Test POST with valid CSRF token
        form_data['csrf_token'] = csrf_token
        response = test_client.post('/protected-form', data=form_data)
        assert response.status_code in [200, 302]  # Success or redirect
    
    @staticmethod
    def test_session_management(test_client: Client,
                              user: MockFlaskLoginUser,
                              session_timeout: int = 3600):
        """Test session creation, validation, and expiration."""
        # Test session creation
        with test_client.session_transaction() as sess:
            sess['user_id'] = user.get_id()
            sess['login_time'] = datetime.utcnow().isoformat()
        
        # Test session validation
        response = test_client.get('/user-profile')
        assert response.status_code == 200
        
        # Test session expiration (simulate)
        with test_client.session_transaction() as sess:
            sess['login_time'] = (datetime.utcnow() - timedelta(seconds=session_timeout + 1)).isoformat()
        
        response = test_client.get('/user-profile')
        assert response.status_code == 401  # Session expired


# Export all public classes and functions for easy importing
__all__ = [
    'Auth0MockFactory',
    'FlaskLoginMockFactory', 
    'CSRFMockFactory',
    'UserAuthStateMocks',
    'SecurityMonitoringMocks',
    'MockJWTToken',
    'MockAuth0User',
    'MockUserSession',
    'MockFlaskLoginUser',
    'mock_authentication_decorators',
    'create_test_request_context',
    'AuthenticationTestingPatterns'
]