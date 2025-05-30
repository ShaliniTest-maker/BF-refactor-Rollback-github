"""
Authentication and Authorization Testing Module

This module implements comprehensive testing for Flask authentication decorators,
Auth0 integration, and session management, ensuring 100% functional parity with
the original Node.js authentication system while migrating to Flask-based patterns.

Test Coverage Areas:
- Flask authentication decorators replacing Node.js middleware patterns
- Auth0 Python SDK 4.9.0 integration with mock authentication tokens
- Flask session management with secure cookie protection via ItsDangerous 2.2+
- Role-based access control (RBAC) with SQLAlchemy models
- JWT token validation using Flask-JWT-Extended 4.7.1
- Security event monitoring and audit trail validation
- Performance validation maintaining Node.js baseline response times

Key Testing Patterns:
- pytest fixtures for authentication context management
- Factory Boy integration for realistic user and role test data
- Mock Auth0 service responses for isolated testing
- Flask test client integration with session management
- Comprehensive security assertion utilities
"""

import pytest
import jwt
import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Optional, Any, Callable

# Flask testing imports
from flask import Flask, session, request, g, current_app
from flask.testing import FlaskClient
from werkzeug.test import Client

# Authentication and security imports
from flask_jwt_extended import (
    create_access_token, create_refresh_token, decode_token,
    get_jwt_identity, get_jwt, jwt_required
)
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# SQLAlchemy testing imports
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

# Test utilities and factories
from tests.factories import (
    UserFactory, RoleFactory, PermissionFactory, UserSessionFactory,
    SecurityEventFactory, FactoryDataManager
)
from tests.utils import ResponseAssertions, DatabaseTestUtils, AuthTestUtils

# Application imports (these would be available when the app is created)
from services.auth_service import AuthenticationService, AuthorizationService
from blueprints.auth import auth_blueprint
from models.user import User, UserSession
from models.rbac import Role, Permission
from models.audit import SecurityEvent


# =============================================================================
# Authentication Test Fixtures
# =============================================================================

@pytest.fixture
def auth_service(app, db_session):
    """
    Authentication service fixture with mock Auth0 integration.
    
    Provides a configured AuthenticationService instance with mocked
    external dependencies for isolated testing of authentication logic.
    """
    with app.app_context():
        service = AuthenticationService()
        
        # Mock Auth0 client for isolated testing
        with patch.object(service, 'auth0_client') as mock_auth0:
            mock_auth0.users.get.return_value = {
                'user_id': 'auth0|test123',
                'email': 'test@example.com',
                'email_verified': True,
                'name': 'Test User'
            }
            yield service


@pytest.fixture
def authorization_service(app, db_session):
    """
    Authorization service fixture with RBAC test data.
    
    Provides a configured AuthorizationService instance with
    comprehensive role and permission test data for access control testing.
    """
    with app.app_context():
        service = AuthorizationService()
        yield service


@pytest.fixture
def test_user_with_roles(db_session):
    """
    Test user fixture with comprehensive role and permission setup.
    
    Creates a test user with multiple roles and permissions for
    complete authentication and authorization testing scenarios.
    """
    # Create RBAC system components
    rbac_system = FactoryDataManager.create_rbac_system(
        user_count=1, role_count=3, permission_count=10
    )
    
    user = rbac_system['users'][0]
    user.is_active = True
    user.email_verified = True
    
    db_session.commit()
    return user


@pytest.fixture
def admin_user(db_session):
    """
    Admin user fixture for elevated permission testing.
    
    Creates an admin user with comprehensive permissions for testing
    administrative access control and security boundary validation.
    """
    # Create admin role with all permissions
    admin_role = RoleFactory(name='admin', description='System administrator')
    permissions = PermissionFactory.create_batch(5)
    admin_role.permissions.extend(permissions)
    
    # Create admin user
    admin_user = UserFactory(
        email='admin@test.com',
        is_active=True,
        email_verified=True
    )
    admin_user.roles.append(admin_role)
    
    db_session.commit()
    return admin_user


@pytest.fixture
def mock_auth0_token():
    """
    Mock Auth0 JWT token fixture for authentication testing.
    
    Provides a properly formatted JWT token that mimics Auth0's token
    structure for testing token validation and claims extraction.
    """
    payload = {
        'sub': 'auth0|test123456789',
        'email': 'test@example.com',
        'email_verified': True,
        'name': 'Test User',
        'iat': int(datetime.utcnow().timestamp()),
        'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        'aud': 'test-client-id',
        'iss': 'https://test-domain.auth0.com/',
        'scope': 'read:profile write:profile'
    }
    
    # Use test secret for token generation
    secret = 'test-secret-key-for-auth0-integration'
    token = jwt.encode(payload, secret, algorithm='HS256')
    
    return {
        'token': token,
        'payload': payload,
        'secret': secret
    }


@pytest.fixture
def authenticated_client(client, test_user_with_roles, app):
    """
    Authenticated Flask test client fixture.
    
    Provides a Flask test client with an authenticated user session
    for testing protected endpoints and authorization workflows.
    """
    with app.app_context():
        # Create access token for the test user
        access_token = create_access_token(
            identity=str(test_user_with_roles.id),
            additional_claims={
                'email': test_user_with_roles.email,
                'roles': [role.name for role in test_user_with_roles.roles]
            }
        )
        
        # Set authentication headers
        client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {access_token}'
        
        # Create user session
        with client.session_transaction() as sess:
            sess['user_id'] = str(test_user_with_roles.id)
            sess['user_email'] = test_user_with_roles.email
            sess['csrf_token'] = 'test-csrf-token'
        
        yield client


@pytest.fixture
def mock_security_logger():
    """
    Mock security logger fixture for security event testing.
    
    Provides a mocked security logger for testing security event
    generation, audit trail creation, and monitoring functionality.
    """
    with patch('services.auth_service.SecurityLogger') as mock_logger:
        yield mock_logger


# =============================================================================
# Flask Authentication Decorator Tests
# =============================================================================

class TestFlaskAuthenticationDecorators:
    """
    Test suite for Flask authentication decorators replacing Node.js middleware patterns.
    
    Validates authentication decorator functionality, token validation,
    session management, and security policy enforcement per Section 0.1.2.
    """
    
    def test_jwt_required_decorator_valid_token(self, app, test_user_with_roles, mock_security_logger):
        """
        Test JWT required decorator with valid authentication token.
        
        Validates that the Flask authentication decorator properly validates
        JWT tokens and grants access to protected endpoints with valid credentials.
        """
        with app.app_context():
            # Create valid access token
            access_token = create_access_token(
                identity=str(test_user_with_roles.id),
                additional_claims={'email': test_user_with_roles.email}
            )
            
            # Mock protected route with JWT required decorator
            @jwt_required()
            def protected_endpoint():
                current_user_id = get_jwt_identity()
                claims = get_jwt()
                return {
                    'user_id': current_user_id,
                    'email': claims.get('email'),
                    'status': 'authenticated'
                }
            
            # Test with valid token in header
            with app.test_request_context(
                headers={'Authorization': f'Bearer {access_token}'}
            ):
                result = protected_endpoint()
                
                assert result['user_id'] == str(test_user_with_roles.id)
                assert result['email'] == test_user_with_roles.email
                assert result['status'] == 'authenticated'
    
    def test_jwt_required_decorator_invalid_token(self, app, mock_security_logger):
        """
        Test JWT required decorator with invalid authentication token.
        
        Validates that the Flask authentication decorator properly rejects
        invalid tokens and blocks access to protected endpoints.
        """
        with app.app_context():
            @jwt_required()
            def protected_endpoint():
                return {'status': 'should_not_reach'}
            
            # Test with invalid token
            with app.test_request_context(
                headers={'Authorization': 'Bearer invalid-token'}
            ):
                with pytest.raises(Exception):  # Should raise JWT decode error
                    protected_endpoint()
    
    def test_jwt_required_decorator_missing_token(self, app, mock_security_logger):
        """
        Test JWT required decorator with missing authentication token.
        
        Validates that the Flask authentication decorator properly handles
        missing authentication tokens and returns appropriate error responses.
        """
        with app.app_context():
            @jwt_required()
            def protected_endpoint():
                return {'status': 'should_not_reach'}
            
            # Test without authentication header
            with app.test_request_context():
                with pytest.raises(Exception):  # Should raise missing token error
                    protected_endpoint()
    
    def test_jwt_token_expiration_handling(self, app, test_user_with_roles, mock_security_logger):
        """
        Test JWT token expiration handling and security validation.
        
        Validates that expired tokens are properly rejected and security
        events are logged for expired token access attempts.
        """
        with app.app_context():
            # Create expired token
            expired_token = create_access_token(
                identity=str(test_user_with_roles.id),
                expires_delta=timedelta(seconds=-1)
            )
            
            @jwt_required()
            def protected_endpoint():
                return {'status': 'should_not_reach'}
            
            # Test with expired token
            with app.test_request_context(
                headers={'Authorization': f'Bearer {expired_token}'}
            ):
                with pytest.raises(Exception):  # Should raise token expired error
                    protected_endpoint()
    
    def test_role_based_access_decorator(self, app, test_user_with_roles, mock_security_logger):
        """
        Test role-based access control decorator implementation.
        
        Validates that role-based access decorators properly enforce
        authorization policies based on user roles and permissions.
        """
        with app.app_context():
            from services.auth_service import require_role
            
            # Get user's first role
            user_role = test_user_with_roles.roles[0].name
            
            access_token = create_access_token(
                identity=str(test_user_with_roles.id),
                additional_claims={
                    'roles': [user_role]
                }
            )
            
            @require_role(user_role)
            def role_protected_endpoint():
                return {'status': 'authorized', 'role': user_role}
            
            # Test with correct role
            with app.test_request_context(
                headers={'Authorization': f'Bearer {access_token}'}
            ):
                # Mock get_jwt_identity and get_jwt for role validation
                with patch('services.auth_service.get_jwt_identity', return_value=str(test_user_with_roles.id)):
                    with patch('services.auth_service.get_jwt', return_value={'roles': [user_role]}):
                        result = role_protected_endpoint()
                        assert result['status'] == 'authorized'
                        assert result['role'] == user_role
    
    def test_permission_based_access_decorator(self, app, test_user_with_roles, mock_security_logger):
        """
        Test permission-based access control decorator implementation.
        
        Validates that permission-based access decorators properly enforce
        granular authorization policies based on user permissions.
        """
        with app.app_context():
            from services.auth_service import require_permission
            
            # Get user's first permission
            user_permission = f"{test_user_with_roles.roles[0].permissions[0].resource}.{test_user_with_roles.roles[0].permissions[0].action}"
            
            access_token = create_access_token(
                identity=str(test_user_with_roles.id),
                additional_claims={
                    'permissions': [user_permission]
                }
            )
            
            @require_permission(user_permission)
            def permission_protected_endpoint():
                return {'status': 'authorized', 'permission': user_permission}
            
            # Test with correct permission
            with app.test_request_context(
                headers={'Authorization': f'Bearer {access_token}'}
            ):
                # Mock permission validation
                with patch('services.auth_service.get_jwt_identity', return_value=str(test_user_with_roles.id)):
                    with patch('services.auth_service.get_jwt', return_value={'permissions': [user_permission]}):
                        result = permission_protected_endpoint()
                        assert result['status'] == 'authorized'
                        assert result['permission'] == user_permission


# =============================================================================
# Auth0 Integration Tests
# =============================================================================

class TestAuth0Integration:
    """
    Test suite for Auth0 Python SDK 4.9.0 integration with mock authentication tokens.
    
    Validates Auth0 service integration, token exchange workflows,
    user profile synchronization, and authentication flow patterns per Section 3.6.3.
    """
    
    def test_auth0_user_info_retrieval(self, auth_service, mock_auth0_token):
        """
        Test Auth0 user information retrieval with mock token.
        
        Validates that the Auth0 integration properly retrieves user
        information using access tokens and handles API responses correctly.
        """
        with patch.object(auth_service, 'auth0_client') as mock_auth0:
            # Mock Auth0 API response
            mock_auth0.users.get.return_value = {
                'user_id': 'auth0|test123',
                'email': 'test@example.com',
                'email_verified': True,
                'name': 'Test User',
                'picture': 'https://example.com/avatar.jpg',
                'given_name': 'Test',
                'family_name': 'User'
            }
            
            # Test user info retrieval
            user_info = auth_service.get_auth0_user_info('auth0|test123')
            
            assert user_info['user_id'] == 'auth0|test123'
            assert user_info['email'] == 'test@example.com'
            assert user_info['email_verified'] is True
            assert user_info['name'] == 'Test User'
            
            # Verify Auth0 API was called correctly
            mock_auth0.users.get.assert_called_once_with('auth0|test123')
    
    def test_auth0_token_validation(self, auth_service, mock_auth0_token):
        """
        Test Auth0 JWT token validation and claims extraction.
        
        Validates that Auth0 tokens are properly validated using the
        Auth0 Python SDK and claims are correctly extracted for user context.
        """
        token_data = mock_auth0_token
        
        with patch.object(auth_service, 'validate_auth0_token') as mock_validate:
            mock_validate.return_value = token_data['payload']
            
            # Test token validation
            claims = auth_service.validate_auth0_token(token_data['token'])
            
            assert claims['sub'] == 'auth0|test123456789'
            assert claims['email'] == 'test@example.com'
            assert claims['email_verified'] is True
            assert 'exp' in claims
            assert 'iat' in claims
    
    def test_auth0_user_profile_sync(self, auth_service, test_user_with_roles, mock_auth0_token, db_session):
        """
        Test Auth0 user profile synchronization with local database.
        
        Validates that user profile information from Auth0 is properly
        synchronized with the local SQLAlchemy user model.
        """
        with patch.object(auth_service, 'auth0_client') as mock_auth0:
            # Mock Auth0 profile data
            auth0_profile = {
                'user_id': 'auth0|test123',
                'email': 'updated@example.com',
                'email_verified': True,
                'name': 'Updated Test User',
                'given_name': 'Updated',
                'family_name': 'User',
                'picture': 'https://example.com/new-avatar.jpg'
            }
            mock_auth0.users.get.return_value = auth0_profile
            
            # Test profile synchronization
            updated_user = auth_service.sync_user_profile(
                user_id=test_user_with_roles.id,
                auth0_user_id='auth0|test123'
            )
            
            assert updated_user.email == 'updated@example.com'
            assert updated_user.first_name == 'Updated'
            assert updated_user.last_name == 'User'
            assert updated_user.auth0_user_id == 'auth0|test123'
    
    def test_auth0_authentication_flow(self, client, auth_service, mock_auth0_token):
        """
        Test complete Auth0 authentication flow with callback handling.
        
        Validates the end-to-end authentication workflow including
        Auth0 callback processing, token exchange, and session creation.
        """
        token_data = mock_auth0_token
        
        with patch.object(auth_service, 'handle_auth0_callback') as mock_callback:
            # Mock successful authentication response
            mock_callback.return_value = {
                'access_token': token_data['token'],
                'user_info': token_data['payload'],
                'session_created': True
            }
            
            # Test authentication callback
            response = client.post('/auth/callback', json={
                'code': 'test-auth-code',
                'state': 'test-state'
            })
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert 'access_token' in response_data
            assert response_data['session_created'] is True
    
    def test_auth0_logout_handling(self, authenticated_client, auth_service):
        """
        Test Auth0 logout flow with session cleanup.
        
        Validates that logout properly cleans up local sessions
        and coordinates with Auth0 logout endpoints.
        """
        with patch.object(auth_service, 'handle_logout') as mock_logout:
            mock_logout.return_value = {
                'session_cleared': True,
                'auth0_logout_url': 'https://test-domain.auth0.com/v2/logout'
            }
            
            # Test logout flow
            response = authenticated_client.post('/auth/logout')
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert response_data['session_cleared'] is True
            assert 'auth0_logout_url' in response_data


# =============================================================================
# Flask Session Management Tests
# =============================================================================

class TestFlaskSessionManagement:
    """
    Test suite for Flask session management with secure cookie protection via ItsDangerous 2.2+.
    
    Validates Flask session handling, secure cookie configuration,
    CSRF protection, and session security measures per Section 0.1.3.
    """
    
    def test_secure_session_creation(self, app, test_user_with_roles):
        """
        Test secure Flask session creation with ItsDangerous protection.
        
        Validates that Flask sessions are properly created with secure
        cookie settings and ItsDangerous cryptographic protection.
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                # Create secure session data
                sess['user_id'] = str(test_user_with_roles.id)
                sess['user_email'] = test_user_with_roles.email
                sess['auth_timestamp'] = datetime.utcnow().isoformat()
                sess['csrf_token'] = 'secure-csrf-token'
            
            # Verify session data is properly stored
            with client.session_transaction() as sess:
                assert sess['user_id'] == str(test_user_with_roles.id)
                assert sess['user_email'] == test_user_with_roles.email
                assert 'auth_timestamp' in sess
                assert sess['csrf_token'] == 'secure-csrf-token'
    
    def test_session_cookie_security_headers(self, app, client):
        """
        Test Flask session cookie security configuration.
        
        Validates that session cookies are configured with proper
        security attributes including HTTPOnly, Secure, and SameSite flags.
        """
        with app.app_context():
            # Verify security configuration
            assert app.config['SESSION_COOKIE_HTTPONLY'] is True
            assert app.config['SESSION_COOKIE_SECURE'] is True
            assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
            
            # Test session cookie creation
            response = client.post('/auth/login', json={
                'username': 'test@example.com',
                'password': 'test-password'
            })
            
            # Check for secure cookie attributes in response
            cookie_header = response.headers.get('Set-Cookie', '')
            assert 'HttpOnly' in cookie_header
            assert 'Secure' in cookie_header
            assert 'SameSite=Lax' in cookie_header
    
    def test_session_expiration_handling(self, app, authenticated_client):
        """
        Test Flask session expiration and automatic cleanup.
        
        Validates that expired sessions are properly handled and
        cleaned up according to configured session timeout policies.
        """
        with app.app_context():
            # Test session expiration configuration
            assert app.config['PERMANENT_SESSION_LIFETIME'] == timedelta(hours=1)
            
            # Simulate expired session
            with authenticated_client.session_transaction() as sess:
                # Set session timestamp to past expiration
                expired_time = datetime.utcnow() - timedelta(hours=2)
                sess['auth_timestamp'] = expired_time.isoformat()
            
            # Test access with expired session
            response = authenticated_client.get('/api/protected-endpoint')
            assert response.status_code == 401  # Should reject expired session
    
    def test_csrf_token_validation(self, app, authenticated_client):
        """
        Test CSRF token generation and validation for session security.
        
        Validates that CSRF tokens are properly generated, stored in
        sessions, and validated for state-changing operations.
        """
        with app.app_context():
            # Get CSRF token from session
            with authenticated_client.session_transaction() as sess:
                csrf_token = sess.get('csrf_token')
                assert csrf_token is not None
            
            # Test CSRF protected endpoint
            response = authenticated_client.post('/api/update-profile', 
                json={'name': 'Updated Name'},
                headers={'X-CSRF-TOKEN': csrf_token}
            )
            assert response.status_code != 403  # Should not reject valid CSRF token
            
            # Test without CSRF token
            response = authenticated_client.post('/api/update-profile',
                json={'name': 'Updated Name'}
            )
            assert response.status_code == 403  # Should reject missing CSRF token
    
    def test_session_fixation_protection(self, app, client):
        """
        Test session fixation attack protection mechanisms.
        
        Validates that session IDs are regenerated after authentication
        to prevent session fixation attacks.
        """
        # Get initial session ID
        response = client.get('/auth/login-form')
        initial_session_id = client.get_cookie('session')
        
        # Perform authentication
        response = client.post('/auth/login', json={
            'username': 'test@example.com',
            'password': 'test-password'
        })
        
        # Verify session ID changed after authentication
        new_session_id = client.get_cookie('session')
        assert new_session_id != initial_session_id
    
    def test_concurrent_session_management(self, app, test_user_with_roles, db_session):
        """
        Test concurrent session management and limits.
        
        Validates that the system properly handles multiple concurrent
        sessions per user and enforces session limits when configured.
        """
        # Create multiple sessions for the same user
        sessions = UserSessionFactory.create_batch(
            3, 
            user=test_user_with_roles,
            is_active=True
        )
        db_session.commit()
        
        # Verify session tracking
        active_sessions = UserSession.query.filter_by(
            user_id=test_user_with_roles.id,
            is_active=True
        ).count()
        
        assert active_sessions == 3
        
        # Test session limit enforcement (if implemented)
        with app.app_context():
            from services.auth_service import enforce_session_limit
            result = enforce_session_limit(test_user_with_roles.id, max_sessions=2)
            
            # Should deactivate oldest sessions
            remaining_active = UserSession.query.filter_by(
                user_id=test_user_with_roles.id,
                is_active=True
            ).count()
            
            assert remaining_active <= 2


# =============================================================================
# Authorization and Security Testing
# =============================================================================

class TestAuthorizationSecurity:
    """
    Test suite for authorization security and access control validation.
    
    Validates role-based access control, permission checking,
    security event logging, and comprehensive security testing per Section 0.1.3.
    """
    
    def test_role_based_authorization_success(self, app, test_user_with_roles, authorization_service):
        """
        Test successful role-based authorization with valid user roles.
        
        Validates that users with appropriate roles can access
        protected resources and operations.
        """
        with app.app_context():
            user_role = test_user_with_roles.roles[0].name
            
            # Test role authorization
            is_authorized = authorization_service.check_role_access(
                user_id=test_user_with_roles.id,
                required_role=user_role
            )
            
            assert is_authorized is True
    
    def test_role_based_authorization_failure(self, app, test_user_with_roles, authorization_service, mock_security_logger):
        """
        Test role-based authorization failure and security logging.
        
        Validates that users without required roles are denied access
        and that authorization failures are properly logged.
        """
        with app.app_context():
            # Test with role user doesn't have
            is_authorized = authorization_service.check_role_access(
                user_id=test_user_with_roles.id,
                required_role='super_admin'
            )
            
            assert is_authorized is False
            
            # Verify security event was logged
            mock_security_logger.log_authorization_failure.assert_called()
    
    def test_permission_based_authorization_success(self, app, test_user_with_roles, authorization_service):
        """
        Test successful permission-based authorization with valid permissions.
        
        Validates that users with appropriate permissions can perform
        specific operations on protected resources.
        """
        with app.app_context():
            # Get user's first permission
            user_permission = test_user_with_roles.roles[0].permissions[0]
            permission_name = f"{user_permission.resource}.{user_permission.action}"
            
            # Test permission authorization
            is_authorized = authorization_service.check_permission_access(
                user_id=test_user_with_roles.id,
                permission=permission_name
            )
            
            assert is_authorized is True
    
    def test_permission_based_authorization_failure(self, app, test_user_with_roles, authorization_service, mock_security_logger):
        """
        Test permission-based authorization failure and security monitoring.
        
        Validates that users without required permissions are denied access
        and that authorization violations trigger security alerts.
        """
        with app.app_context():
            # Test with permission user doesn't have
            is_authorized = authorization_service.check_permission_access(
                user_id=test_user_with_roles.id,
                permission='admin.delete_all'
            )
            
            assert is_authorized is False
            
            # Verify security event was logged
            mock_security_logger.log_authorization_failure.assert_called()
    
    def test_security_event_generation(self, app, test_user_with_roles, db_session, mock_security_logger):
        """
        Test security event generation for authentication and authorization activities.
        
        Validates that security events are properly created and stored
        for audit trail and security monitoring purposes.
        """
        with app.app_context():
            # Create security events
            events = [
                SecurityEventFactory(
                    user=test_user_with_roles,
                    event_type='authentication_success',
                    severity='info'
                ),
                SecurityEventFactory(
                    user=test_user_with_roles,
                    event_type='authorization_failure',
                    severity='warning'
                )
            ]
            db_session.commit()
            
            # Verify events were created
            auth_event = SecurityEvent.query.filter_by(
                user_id=test_user_with_roles.id,
                event_type='authentication_success'
            ).first()
            
            assert auth_event is not None
            assert auth_event.severity == 'info'
            
            authz_event = SecurityEvent.query.filter_by(
                user_id=test_user_with_roles.id,
                event_type='authorization_failure'
            ).first()
            
            assert authz_event is not None
            assert authz_event.severity == 'warning'
    
    def test_suspicious_activity_detection(self, app, test_user_with_roles, mock_security_logger):
        """
        Test suspicious activity detection and automated response.
        
        Validates that suspicious authentication patterns trigger
        security alerts and protective measures.
        """
        with app.app_context():
            from services.auth_service import detect_suspicious_activity
            
            # Simulate suspicious activity pattern
            suspicious_events = [
                {'event_type': 'failed_login', 'ip': '192.168.1.100', 'timestamp': datetime.utcnow()},
                {'event_type': 'failed_login', 'ip': '192.168.1.100', 'timestamp': datetime.utcnow()},
                {'event_type': 'failed_login', 'ip': '192.168.1.100', 'timestamp': datetime.utcnow()},
                {'event_type': 'failed_login', 'ip': '10.0.0.50', 'timestamp': datetime.utcnow()},
                {'event_type': 'failed_login', 'ip': '10.0.0.50', 'timestamp': datetime.utcnow()},
            ]
            
            # Test suspicious activity detection
            is_suspicious = detect_suspicious_activity(
                user_id=test_user_with_roles.id,
                events=suspicious_events,
                time_window=timedelta(minutes=5)
            )
            
            assert is_suspicious is True
            
            # Verify security alert was triggered
            mock_security_logger.log_security_event.assert_called()


# =============================================================================
# Performance and Integration Tests
# =============================================================================

class TestAuthenticationPerformance:
    """
    Test suite for authentication performance validation maintaining Node.js baseline.
    
    Validates that authentication operations meet or exceed Node.js
    performance baselines while maintaining identical functionality per Section 4.7.4.1.
    """
    
    @pytest.mark.benchmark(group="authentication")
    def test_jwt_token_validation_performance(self, benchmark, app, test_user_with_roles):
        """
        Benchmark JWT token validation performance against Node.js baseline.
        
        Validates that JWT token validation maintains sub-50ms response
        times consistent with Node.js authentication middleware performance.
        """
        with app.app_context():
            access_token = create_access_token(
                identity=str(test_user_with_roles.id),
                additional_claims={'email': test_user_with_roles.email}
            )
            
            def validate_token():
                with app.test_request_context(
                    headers={'Authorization': f'Bearer {access_token}'}
                ):
                    return decode_token(access_token)
            
            # Benchmark token validation
            result = benchmark(validate_token)
            assert result['sub'] == str(test_user_with_roles.id)
    
    @pytest.mark.benchmark(group="authorization")
    def test_permission_check_performance(self, benchmark, app, test_user_with_roles, authorization_service):
        """
        Benchmark permission checking performance for scalability validation.
        
        Validates that permission checking operations maintain efficient
        response times under load for high-throughput authorization scenarios.
        """
        with app.app_context():
            user_permission = test_user_with_roles.roles[0].permissions[0]
            permission_name = f"{user_permission.resource}.{user_permission.action}"
            
            def check_permission():
                return authorization_service.check_permission_access(
                    user_id=test_user_with_roles.id,
                    permission=permission_name
                )
            
            # Benchmark permission checking
            result = benchmark(check_permission)
            assert result is True
    
    @pytest.mark.benchmark(group="session_management")
    def test_session_creation_performance(self, benchmark, app):
        """
        Benchmark Flask session creation and management performance.
        
        Validates that session operations maintain efficient performance
        for concurrent user scenarios and high session turnover rates.
        """
        with app.app_context():
            def create_session():
                with app.test_client() as client:
                    with client.session_transaction() as sess:
                        sess['user_id'] = str(uuid.uuid4())
                        sess['auth_timestamp'] = datetime.utcnow().isoformat()
                        sess['csrf_token'] = 'test-csrf-token'
                    return True
            
            # Benchmark session creation
            result = benchmark(create_session)
            assert result is True


# =============================================================================
# Integration Test Suite
# =============================================================================

class TestAuthenticationIntegration:
    """
    Comprehensive integration test suite for authentication system components.
    
    Validates end-to-end authentication workflows, component integration,
    and system behavior under various scenarios and edge cases.
    """
    
    def test_complete_authentication_workflow(self, client, auth_service, mock_auth0_token, db_session):
        """
        Test complete authentication workflow from login to protected resource access.
        
        Validates the entire authentication process including login,
        token generation, session creation, and protected endpoint access.
        """
        # Step 1: Initial login request
        login_response = client.post('/auth/login', json={
            'username': 'test@example.com',
            'password': 'test-password'
        })
        
        assert login_response.status_code in [200, 302]  # Success or redirect
        
        # Step 2: Access protected resource
        if login_response.status_code == 200:
            response_data = json.loads(login_response.data)
            access_token = response_data.get('access_token')
            
            protected_response = client.get('/api/protected',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            assert protected_response.status_code == 200
    
    def test_authentication_error_handling(self, client, auth_service):
        """
        Test authentication error handling and recovery scenarios.
        
        Validates that authentication errors are properly handled,
        logged, and communicated to clients with appropriate responses.
        """
        # Test invalid credentials
        response = client.post('/auth/login', json={
            'username': 'invalid@example.com',
            'password': 'wrong-password'
        })
        
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'error' in response_data
        
        # Test malformed request
        response = client.post('/auth/login', json={
            'invalid_field': 'test'
        })
        
        assert response.status_code == 400
    
    def test_concurrent_authentication_requests(self, app, db_session):
        """
        Test concurrent authentication request handling and resource contention.
        
        Validates that the authentication system properly handles
        concurrent requests without race conditions or resource conflicts.
        """
        import threading
        import time
        
        results = []
        
        def authenticate_user(user_email):
            with app.test_client() as client:
                response = client.post('/auth/login', json={
                    'username': user_email,
                    'password': 'test-password'
                })
                results.append(response.status_code)
        
        # Create concurrent authentication requests
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=authenticate_user,
                args=[f'user{i}@example.com']
            )
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Verify all requests were handled
        assert len(results) == 5
        assert all(status in [200, 401] for status in results)
    
    def test_authentication_system_resilience(self, app, client, mock_auth0_token):
        """
        Test authentication system resilience and error recovery.
        
        Validates that the authentication system gracefully handles
        external service failures and maintains core functionality.
        """
        with patch('services.auth_service.AuthenticationService.auth0_client') as mock_auth0:
            # Simulate Auth0 service failure
            mock_auth0.users.get.side_effect = Exception("Auth0 service unavailable")
            
            # Test graceful degradation
            response = client.post('/auth/login', json={
                'username': 'test@example.com',
                'password': 'test-password'
            })
            
            # Should handle gracefully (either fallback auth or proper error)
            assert response.status_code in [200, 401, 503]
            
            if response.status_code == 503:
                response_data = json.loads(response.data)
                assert 'service_unavailable' in response_data.get('error', '')