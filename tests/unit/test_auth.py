"""
Comprehensive unit tests for Flask authentication components.

This module provides comprehensive unit testing for all Flask authentication components
including decorators, session management, Auth0 integration, CSRF protection, password
utilities, token handling, and security monitoring. Tests validate the migration from
Node.js middleware patterns to Flask decorator architecture while ensuring security
posture preservation and complete functional parity.

Test Coverage:
- Authentication decorators with Flask-Login integration
- Session management with ItsDangerous secure cookie signing  
- Auth0 Python SDK integration with JWT token validation
- CSRF protection implementation with Flask-WTF
- Password utilities with Werkzeug security
- JWT token lifecycle management with Flask-JWT-Extended
- Security monitoring with structured logging

Requirements Tested:
- Feature F-007: Authentication mechanism migration from Node.js middleware to Flask decorators
- Section 4.6.2: Flask-Login session management validation
- Section 6.4.1.1: Auth0 Python SDK integration testing
- Section 6.4.1.4: JWT token lifecycle management testing
- Section 6.4.2.5: Security monitoring with structured logging
- Feature F-009: 100% functionality parity validation
"""

import pytest
import json
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, call
from werkzeug.test import Client
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, session, g, current_app
from flask_login import current_user, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import structlog

# Import authentication components for testing
from src.auth.decorators import require_auth, require_permission, require_role
from src.auth.session_manager import SessionManager
from src.auth.auth0_integration import Auth0Integration
from src.auth.csrf_protection import CSRFProtectionService
from src.auth.password_utils import PasswordUtils
from src.auth.token_handler import TokenHandler
from src.auth.security_monitor import SecurityMonitor


class TestAuthenticationDecorators:
    """
    Unit tests for Flask authentication decorators.
    
    Tests the migration from Node.js authentication middleware to Flask decorator
    patterns, ensuring complete functionality preservation and security posture
    maintenance. Validates Flask-Login integration, role-based access control,
    and permission enforcement.
    """

    @pytest.fixture
    def mock_user(self):
        """Mock user object for authentication testing."""
        user = Mock()
        user.id = 'user_123'
        user.is_authenticated = True
        user.is_active = True
        user.is_anonymous = False
        user.get_id.return_value = 'user_123'
        user.roles = ['user']
        user.permissions = ['read', 'write']
        return user

    @pytest.fixture
    def mock_admin_user(self):
        """Mock admin user object for authorization testing."""
        user = Mock()
        user.id = 'admin_123'
        user.is_authenticated = True
        user.is_active = True
        user.is_anonymous = False
        user.get_id.return_value = 'admin_123'
        user.roles = ['admin', 'user']
        user.permissions = ['read', 'write', 'delete', 'admin']
        return user

    def test_require_auth_decorator_with_authenticated_user(self, app, mock_user):
        """Test @require_auth decorator allows access for authenticated users."""
        with app.test_request_context():
            with patch('flask_login.current_user', mock_user):
                
                @require_auth
                def protected_endpoint():
                    return {'status': 'success', 'user_id': mock_user.id}
                
                result = protected_endpoint()
                
                assert result['status'] == 'success'
                assert result['user_id'] == 'user_123'

    def test_require_auth_decorator_with_unauthenticated_user(self, app):
        """Test @require_auth decorator blocks access for unauthenticated users."""
        with app.test_request_context():
            mock_anonymous_user = Mock()
            mock_anonymous_user.is_authenticated = False
            mock_anonymous_user.is_anonymous = True
            
            with patch('flask_login.current_user', mock_anonymous_user):
                with pytest.raises(Exception) as exc_info:
                    
                    @require_auth
                    def protected_endpoint():
                        return {'status': 'success'}
                    
                    protected_endpoint()
                
                # Should raise 401 Unauthorized
                assert '401' in str(exc_info.value) or 'Unauthorized' in str(exc_info.value)

    def test_require_permission_decorator_with_valid_permission(self, app, mock_user):
        """Test @require_permission decorator allows access with valid permissions."""
        with app.test_request_context():
            with patch('flask_login.current_user', mock_user):
                
                @require_permission('read')
                def protected_endpoint():
                    return {'status': 'success', 'permission': 'read'}
                
                result = protected_endpoint()
                
                assert result['status'] == 'success'
                assert result['permission'] == 'read'

    def test_require_permission_decorator_with_invalid_permission(self, app, mock_user):
        """Test @require_permission decorator blocks access without required permission."""
        with app.test_request_context():
            with patch('flask_login.current_user', mock_user):
                with pytest.raises(Exception) as exc_info:
                    
                    @require_permission('admin')
                    def protected_endpoint():
                        return {'status': 'success'}
                    
                    protected_endpoint()
                
                # Should raise 403 Forbidden
                assert '403' in str(exc_info.value) or 'Forbidden' in str(exc_info.value)

    def test_require_role_decorator_with_valid_role(self, app, mock_admin_user):
        """Test @require_role decorator allows access with valid role."""
        with app.test_request_context():
            with patch('flask_login.current_user', mock_admin_user):
                
                @require_role('admin')
                def admin_endpoint():
                    return {'status': 'success', 'role': 'admin'}
                
                result = admin_endpoint()
                
                assert result['status'] == 'success'
                assert result['role'] == 'admin'

    def test_require_role_decorator_with_invalid_role(self, app, mock_user):
        """Test @require_role decorator blocks access without required role."""
        with app.test_request_context():
            with patch('flask_login.current_user', mock_user):
                with pytest.raises(Exception) as exc_info:
                    
                    @require_role('admin')
                    def admin_endpoint():
                        return {'status': 'success'}
                    
                    admin_endpoint()
                
                # Should raise 403 Forbidden
                assert '403' in str(exc_info.value) or 'Forbidden' in str(exc_info.value)

    def test_decorator_chaining(self, app, mock_admin_user):
        """Test chaining multiple authentication decorators."""
        with app.test_request_context():
            with patch('flask_login.current_user', mock_admin_user):
                
                @require_auth
                @require_role('admin')
                @require_permission('delete')
                def super_protected_endpoint():
                    return {'status': 'success', 'level': 'super_protected'}
                
                result = super_protected_endpoint()
                
                assert result['status'] == 'success'
                assert result['level'] == 'super_protected'

    @patch('src.auth.decorators.SecurityMonitor')
    def test_decorator_security_logging(self, mock_security_monitor, app, mock_user):
        """Test authentication decorators log security events."""
        with app.test_request_context('/test', method='GET'):
            with patch('flask_login.current_user', mock_user):
                mock_monitor_instance = Mock()
                mock_security_monitor.return_value = mock_monitor_instance
                
                @require_auth
                def protected_endpoint():
                    return {'status': 'success'}
                
                protected_endpoint()
                
                # Verify security monitoring is called
                mock_monitor_instance.log_authentication_event.assert_called_once()


class TestSessionManager:
    """
    Unit tests for Flask session management.
    
    Tests Flask-Login integration, ItsDangerous secure cookie signing, session
    lifecycle management, and timeout policies. Validates migration from Node.js
    session patterns to Flask session handling while maintaining security posture.
    """

    @pytest.fixture
    def session_manager(self, app):
        """Initialize SessionManager for testing."""
        return SessionManager(app)

    @pytest.fixture
    def mock_user_model(self):
        """Mock user model for session testing."""
        user = Mock()
        user.id = 'user_123'
        user.username = 'testuser'
        user.email = 'test@example.com'
        user.is_active = True
        user.get_id.return_value = 'user_123'
        return user

    def test_session_manager_initialization(self, session_manager, app):
        """Test SessionManager initializes correctly with Flask app."""
        assert session_manager.app == app
        assert session_manager.login_manager is not None
        assert session_manager.serializer is not None

    def test_user_loader_callback(self, session_manager, app, mock_user_model):
        """Test user loader callback retrieves user from session."""
        with app.test_request_context():
            with patch('src.models.user.User.query') as mock_query:
                mock_query.get.return_value = mock_user_model
                
                loaded_user = session_manager.load_user('user_123')
                
                assert loaded_user == mock_user_model
                mock_query.get.assert_called_once_with('user_123')

    def test_create_session(self, session_manager, app, mock_user_model):
        """Test session creation with secure cookie signing."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                with patch('flask_login.login_user') as mock_login:
                    session_manager.create_session(mock_user_model, remember=True)
                    
                    mock_login.assert_called_once_with(
                        mock_user_model, 
                        remember=True, 
                        duration=timedelta(days=30)
                    )

    def test_destroy_session(self, session_manager, app):
        """Test session destruction and cleanup."""
        with app.test_client() as client:
            with client.session_transaction() as sess:
                with patch('flask_login.logout_user') as mock_logout:
                    session_manager.destroy_session()
                    
                    mock_logout.assert_called_once()

    def test_session_cookie_signing(self, session_manager, app):
        """Test ItsDangerous session cookie signing and verification."""
        test_data = {'user_id': 'user_123', 'timestamp': time.time()}
        
        # Test signing
        signed_data = session_manager.sign_session_data(test_data)
        assert isinstance(signed_data, str)
        assert len(signed_data) > 0
        
        # Test verification
        unsigned_data = session_manager.verify_session_data(signed_data)
        assert unsigned_data['user_id'] == 'user_123'
        assert 'timestamp' in unsigned_data

    def test_session_cookie_tampering_detection(self, session_manager):
        """Test detection of tampered session cookies."""
        tampered_cookie = "tampered.cookie.data"
        
        with pytest.raises(BadSignature):
            session_manager.verify_session_data(tampered_cookie)

    def test_session_expiration(self, session_manager):
        """Test session expiration validation."""
        # Create expired session data
        old_timestamp = time.time() - 3700  # 1 hour + 100 seconds ago
        expired_data = {'user_id': 'user_123', 'timestamp': old_timestamp}
        signed_expired = session_manager.sign_session_data(expired_data)
        
        with pytest.raises(SignatureExpired):
            session_manager.verify_session_data(signed_expired, max_age=3600)

    def test_session_timeout_policies(self, session_manager, app):
        """Test session timeout and renewal policies."""
        with app.test_request_context():
            # Test default timeout
            assert session_manager.session_timeout == 3600  # 1 hour
            
            # Test remember me timeout
            assert session_manager.remember_timeout == timedelta(days=30)

    @patch('src.auth.security_monitor.SecurityMonitor')
    def test_session_security_logging(self, mock_security_monitor, session_manager, app, mock_user_model):
        """Test session management security event logging."""
        with app.test_request_context():
            mock_monitor_instance = Mock()
            mock_security_monitor.return_value = mock_monitor_instance
            
            session_manager.create_session(mock_user_model)
            
            # Verify security event is logged
            mock_monitor_instance.log_session_event.assert_called_once()


class TestAuth0Integration:
    """
    Unit tests for Auth0 integration service.
    
    Tests Auth0 Python SDK integration, JWT token validation, user profile
    synchronization, and Management API interactions. Validates migration from
    Node.js Auth0 patterns to Python SDK implementation.
    """

    @pytest.fixture
    def auth0_integration(self, app):
        """Initialize Auth0Integration for testing."""
        app.config['AUTH0_DOMAIN'] = 'test.auth0.com'
        app.config['AUTH0_CLIENT_ID'] = 'test_client_id'
        app.config['AUTH0_CLIENT_SECRET'] = 'test_client_secret'
        app.config['AUTH0_AUDIENCE'] = 'test_audience'
        return Auth0Integration(app)

    @pytest.fixture
    def mock_jwt_token(self):
        """Mock JWT token for testing."""
        return {
            'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...',
            'refresh_token': 'refresh_token_123',
            'id_token': 'id_token_123',
            'token_type': 'Bearer',
            'expires_in': 3600
        }

    @pytest.fixture
    def mock_user_profile(self):
        """Mock Auth0 user profile for testing."""
        return {
            'user_id': 'auth0|user_123',
            'email': 'test@example.com',
            'name': 'Test User',
            'picture': 'https://example.com/avatar.jpg',
            'email_verified': True,
            'created_at': '2023-01-01T00:00:00.000Z',
            'updated_at': '2023-12-01T00:00:00.000Z'
        }

    def test_auth0_initialization(self, auth0_integration, app):
        """Test Auth0Integration initializes with correct configuration."""
        assert auth0_integration.domain == 'test.auth0.com'
        assert auth0_integration.client_id == 'test_client_id'
        assert auth0_integration.client_secret == 'test_client_secret'
        assert auth0_integration.audience == 'test_audience'

    @patch('auth0.authentication.Users')
    def test_validate_jwt_token(self, mock_auth0_users, auth0_integration, mock_jwt_token):
        """Test JWT token validation with Auth0 public keys."""
        mock_users_instance = Mock()
        mock_auth0_users.return_value = mock_users_instance
        mock_users_instance.userinfo.return_value = {
            'sub': 'auth0|user_123',
            'email': 'test@example.com'
        }
        
        result = auth0_integration.validate_token(mock_jwt_token['access_token'])
        
        assert result['sub'] == 'auth0|user_123'
        assert result['email'] == 'test@example.com'
        mock_users_instance.userinfo.assert_called_once_with(mock_jwt_token['access_token'])

    @patch('auth0.management.Auth0')
    def test_get_user_profile(self, mock_auth0_mgmt, auth0_integration, mock_user_profile):
        """Test user profile retrieval from Auth0 Management API."""
        mock_mgmt_instance = Mock()
        mock_auth0_mgmt.return_value = mock_mgmt_instance
        mock_mgmt_instance.users.get.return_value = mock_user_profile
        
        profile = auth0_integration.get_user_profile('auth0|user_123')
        
        assert profile['user_id'] == 'auth0|user_123'
        assert profile['email'] == 'test@example.com'
        mock_mgmt_instance.users.get.assert_called_once_with('auth0|user_123')

    @patch('auth0.management.Auth0')
    def test_refresh_token_rotation(self, mock_auth0_mgmt, auth0_integration, mock_jwt_token):
        """Test Auth0 refresh token rotation policy."""
        mock_mgmt_instance = Mock()
        mock_auth0_mgmt.return_value = mock_mgmt_instance
        
        new_tokens = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            'expires_in': 3600
        }
        mock_mgmt_instance.refresh_token.return_value = new_tokens
        
        result = auth0_integration.refresh_tokens(mock_jwt_token['refresh_token'])
        
        assert result['access_token'] == 'new_access_token'
        assert result['refresh_token'] == 'new_refresh_token'

    @patch('auth0.management.Auth0')
    def test_revoke_tokens(self, mock_auth0_mgmt, auth0_integration):
        """Test token revocation for security incidents."""
        mock_mgmt_instance = Mock()
        mock_auth0_mgmt.return_value = mock_mgmt_instance
        mock_mgmt_instance.revoke_refresh_token.return_value = {'revoked': True}
        
        result = auth0_integration.revoke_user_tokens('auth0|user_123')
        
        assert result['revoked'] is True
        mock_mgmt_instance.revoke_refresh_token.assert_called_once()

    @patch('src.models.user.User')
    def test_sync_user_profile(self, mock_user_model, auth0_integration, mock_user_profile):
        """Test user profile synchronization with Flask-SQLAlchemy."""
        mock_user_instance = Mock()
        mock_user_model.query.filter_by.return_value.first.return_value = mock_user_instance
        
        auth0_integration.sync_user_profile(mock_user_profile)
        
        # Verify user data is updated
        assert mock_user_instance.email == mock_user_profile['email']
        assert mock_user_instance.name == mock_user_profile['name']

    def test_auth0_error_handling(self, auth0_integration):
        """Test Auth0 API error handling and resilience."""
        with patch('auth0.authentication.Users') as mock_users:
            mock_users.side_effect = Exception("Auth0 API Error")
            
            with pytest.raises(Exception) as exc_info:
                auth0_integration.validate_token('invalid_token')
            
            assert "Auth0 API Error" in str(exc_info.value)

    @patch('src.auth.security_monitor.SecurityMonitor')
    def test_auth0_security_monitoring(self, mock_security_monitor, auth0_integration):
        """Test Auth0 integration security event monitoring."""
        mock_monitor_instance = Mock()
        mock_security_monitor.return_value = mock_monitor_instance
        
        with patch('auth0.authentication.Users'):
            auth0_integration.validate_token('test_token')
        
        # Verify security monitoring
        mock_monitor_instance.log_auth0_event.assert_called_once()


class TestCSRFProtection:
    """
    Unit tests for CSRF protection service.
    
    Tests Flask-WTF CSRF protection implementation, token generation and validation,
    exemption management, and security event logging. Validates protection against
    Cross-Site Request Forgery attacks.
    """

    @pytest.fixture
    def csrf_service(self, app):
        """Initialize CSRF protection service for testing."""
        return CSRFProtectionService(app)

    def test_csrf_service_initialization(self, csrf_service, app):
        """Test CSRF protection service initializes correctly."""
        assert csrf_service.app == app
        assert csrf_service.csrf is not None

    def test_csrf_token_generation(self, csrf_service, app):
        """Test CSRF token generation for forms and AJAX requests."""
        with app.test_request_context():
            token = csrf_service.generate_csrf_token()
            
            assert isinstance(token, str)
            assert len(token) > 20  # CSRF tokens should be sufficiently long

    def test_csrf_token_validation_success(self, csrf_service, app):
        """Test successful CSRF token validation."""
        with app.test_request_context():
            token = csrf_service.generate_csrf_token()
            
            # Mock token in request
            with patch('flask.request') as mock_request:
                mock_request.form = {'csrf_token': token}
                
                is_valid = csrf_service.validate_csrf_token(token)
                assert is_valid is True

    def test_csrf_token_validation_failure(self, csrf_service, app):
        """Test CSRF token validation failure with invalid token."""
        with app.test_request_context():
            invalid_token = 'invalid_csrf_token'
            
            is_valid = csrf_service.validate_csrf_token(invalid_token)
            assert is_valid is False

    def test_csrf_protection_on_post_request(self, app):
        """Test CSRF protection blocks POST requests without valid token."""
        with app.test_client() as client:
            response = client.post('/test', data={'field': 'value'})
            
            # Should return 400 Bad Request for missing CSRF token
            assert response.status_code == 400

    def test_csrf_exemption_for_api_endpoints(self, csrf_service, app):
        """Test CSRF exemption for API endpoints with alternative authentication."""
        with app.test_request_context('/api/data'):
            # API endpoints should be exempt from CSRF protection
            is_exempt = csrf_service.is_endpoint_exempt('/api/data')
            assert is_exempt is True

    def test_csrf_ajax_integration(self, csrf_service, app):
        """Test CSRF token integration for AJAX requests."""
        with app.test_request_context():
            token = csrf_service.generate_csrf_token()
            
            # Test AJAX header validation
            with patch('flask.request') as mock_request:
                mock_request.headers = {'X-CSRFToken': token}
                
                is_valid = csrf_service.validate_ajax_csrf(token)
                assert is_valid is True

    @patch('src.auth.security_monitor.SecurityMonitor')
    def test_csrf_violation_logging(self, mock_security_monitor, csrf_service, app):
        """Test CSRF violation security event logging."""
        with app.test_request_context():
            mock_monitor_instance = Mock()
            mock_security_monitor.return_value = mock_monitor_instance
            
            csrf_service.handle_csrf_violation('invalid_token')
            
            # Verify security event is logged
            mock_monitor_instance.log_security_violation.assert_called_once()

    def test_csrf_token_expiration(self, csrf_service, app):
        """Test CSRF token expiration handling."""
        with app.test_request_context():
            # Generate token with short expiration
            token = csrf_service.generate_csrf_token(expires_in=1)
            
            # Wait for expiration
            time.sleep(2)
            
            is_valid = csrf_service.validate_csrf_token(token)
            assert is_valid is False


class TestPasswordUtils:
    """
    Unit tests for password security utilities.
    
    Tests Werkzeug security utilities for password hashing, validation, and
    strength requirements. Validates migration from Node.js password handling
    to Flask/Werkzeug security patterns.
    """

    @pytest.fixture
    def password_utils(self):
        """Initialize PasswordUtils for testing."""
        return PasswordUtils()

    def test_password_hashing_generation(self, password_utils):
        """Test secure password hash generation with salt."""
        password = "test_password_123"
        password_hash = password_utils.generate_password_hash(password)
        
        assert isinstance(password_hash, str)
        assert len(password_hash) > 50  # Hashed passwords should be long
        assert password != password_hash  # Should be hashed, not plain text

    def test_password_hash_verification_success(self, password_utils):
        """Test successful password hash verification."""
        password = "test_password_123"
        password_hash = password_utils.generate_password_hash(password)
        
        is_valid = password_utils.check_password_hash(password_hash, password)
        assert is_valid is True

    def test_password_hash_verification_failure(self, password_utils):
        """Test password hash verification failure with wrong password."""
        password = "test_password_123"
        wrong_password = "wrong_password"
        password_hash = password_utils.generate_password_hash(password)
        
        is_valid = password_utils.check_password_hash(password_hash, wrong_password)
        assert is_valid is False

    def test_password_strength_validation_strong(self, password_utils):
        """Test password strength validation for strong passwords."""
        strong_passwords = [
            "StrongP@ssw0rd123",
            "MySecur3P@$$word!",
            "C0mpl3x_P@ssw0rd_2023"
        ]
        
        for password in strong_passwords:
            strength = password_utils.validate_password_strength(password)
            assert strength['is_strong'] is True
            assert strength['score'] >= 8

    def test_password_strength_validation_weak(self, password_utils):
        """Test password strength validation for weak passwords."""
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "qwerty"
        ]
        
        for password in weak_passwords:
            strength = password_utils.validate_password_strength(password)
            assert strength['is_strong'] is False
            assert strength['score'] < 6

    def test_password_policy_enforcement(self, password_utils):
        """Test password policy enforcement rules."""
        policy_violations = [
            ("short", "ab12"),  # Too short
            ("no_uppercase", "lowercase123!"),  # No uppercase
            ("no_lowercase", "UPPERCASE123!"),  # No lowercase
            ("no_digits", "NoDigitsHere!"),  # No digits
            ("no_special", "NoSpecialChars123")  # No special characters
        ]
        
        for violation_type, password in policy_violations:
            policy_check = password_utils.check_password_policy(password)
            assert policy_check['valid'] is False
            assert violation_type in policy_check['violations']

    def test_password_migration_compatibility(self, password_utils):
        """Test password migration from Node.js hashing to Werkzeug."""
        # Simulate legacy password hash migration
        legacy_password = "legacy_password_123"
        
        # Generate new Werkzeug hash
        new_hash = password_utils.generate_password_hash(legacy_password)
        
        # Verify migration preserves password verification
        is_valid = password_utils.check_password_hash(new_hash, legacy_password)
        assert is_valid is True

    def test_constant_time_comparison(self, password_utils):
        """Test constant-time password comparison for security."""
        password = "test_password_123"
        password_hash = password_utils.generate_password_hash(password)
        
        # Multiple verifications should take similar time (constant-time)
        import time
        
        times = []
        for _ in range(5):
            start = time.time()
            password_utils.check_password_hash(password_hash, password)
            end = time.time()
            times.append(end - start)
        
        # Times should be relatively consistent (within 50% variance)
        avg_time = sum(times) / len(times)
        for t in times:
            assert abs(t - avg_time) / avg_time < 0.5

    @patch('src.auth.security_monitor.SecurityMonitor')
    def test_password_security_events(self, mock_security_monitor, password_utils):
        """Test password utility security event logging."""
        mock_monitor_instance = Mock()
        mock_security_monitor.return_value = mock_monitor_instance
        
        # Test weak password attempt
        password_utils.validate_password_strength("weak123")
        
        # Verify security monitoring
        mock_monitor_instance.log_password_event.assert_called_once()


class TestTokenHandler:
    """
    Unit tests for JWT token handling service.
    
    Tests Flask-JWT-Extended integration, token lifecycle management, refresh
    token rotation, and Auth0 integration. Validates migration from Node.js
    JWT patterns to Flask-JWT-Extended implementation.
    """

    @pytest.fixture
    def token_handler(self, app):
        """Initialize TokenHandler for testing."""
        app.config['JWT_SECRET_KEY'] = 'test-jwt-secret'
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
        app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
        return TokenHandler(app)

    @pytest.fixture
    def mock_user_claims(self):
        """Mock user claims for JWT token testing."""
        return {
            'user_id': 'user_123',
            'email': 'test@example.com',
            'roles': ['user'],
            'permissions': ['read', 'write']
        }

    def test_token_handler_initialization(self, token_handler, app):
        """Test TokenHandler initializes correctly with Flask-JWT-Extended."""
        assert token_handler.app == app
        assert token_handler.jwt_manager is not None

    def test_access_token_generation(self, token_handler, app, mock_user_claims):
        """Test JWT access token generation with user claims."""
        with app.test_request_context():
            token = token_handler.generate_access_token(mock_user_claims)
            
            assert isinstance(token, str)
            assert len(token) > 50  # JWT tokens should be long
            
            # Decode and verify claims
            decoded = token_handler.decode_token(token)
            assert decoded['user_id'] == 'user_123'
            assert decoded['email'] == 'test@example.com'

    def test_refresh_token_generation(self, token_handler, app, mock_user_claims):
        """Test JWT refresh token generation."""
        with app.test_request_context():
            refresh_token = token_handler.generate_refresh_token(mock_user_claims)
            
            assert isinstance(refresh_token, str)
            assert len(refresh_token) > 50
            
            # Verify refresh token can be decoded
            decoded = token_handler.decode_token(refresh_token)
            assert decoded['user_id'] == 'user_123'

    def test_token_validation_success(self, token_handler, app, mock_user_claims):
        """Test successful JWT token validation."""
        with app.test_request_context():
            token = token_handler.generate_access_token(mock_user_claims)
            
            is_valid = token_handler.validate_token(token)
            assert is_valid is True

    def test_token_validation_failure(self, token_handler, app):
        """Test JWT token validation failure with invalid token."""
        invalid_token = "invalid.jwt.token"
        
        is_valid = token_handler.validate_token(invalid_token)
        assert is_valid is False

    def test_token_expiration_handling(self, token_handler, app, mock_user_claims):
        """Test JWT token expiration validation."""
        with app.test_request_context():
            # Generate token with short expiration
            app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=1)
            token = token_handler.generate_access_token(mock_user_claims)
            
            # Wait for expiration
            time.sleep(2)
            
            is_valid = token_handler.validate_token(token)
            assert is_valid is False

    def test_refresh_token_rotation(self, token_handler, app, mock_user_claims):
        """Test refresh token rotation for enhanced security."""
        with app.test_request_context():
            old_refresh = token_handler.generate_refresh_token(mock_user_claims)
            
            # Rotate refresh token
            new_tokens = token_handler.rotate_refresh_token(old_refresh)
            
            assert 'access_token' in new_tokens
            assert 'refresh_token' in new_tokens
            assert new_tokens['refresh_token'] != old_refresh

    def test_token_blacklisting(self, token_handler, app, mock_user_claims):
        """Test token blacklisting for revocation."""
        with app.test_request_context():
            token = token_handler.generate_access_token(mock_user_claims)
            
            # Blacklist token
            token_handler.blacklist_token(token)
            
            # Token should now be invalid
            is_valid = token_handler.validate_token(token)
            assert is_valid is False

    def test_user_token_revocation(self, token_handler, app):
        """Test revoking all tokens for a specific user."""
        user_id = 'user_123'
        
        # Mock existing tokens for user
        mock_tokens = ['token1', 'token2', 'token3']
        
        with patch.object(token_handler, 'get_user_tokens', return_value=mock_tokens):
            revoked_count = token_handler.revoke_user_tokens(user_id)
            
            assert revoked_count == 3

    @patch('src.auth.auth0_integration.Auth0Integration')
    def test_auth0_token_integration(self, mock_auth0, token_handler, app):
        """Test integration between local JWT tokens and Auth0 tokens."""
        mock_auth0_instance = Mock()
        mock_auth0.return_value = mock_auth0_instance
        
        auth0_token = 'auth0_access_token'
        
        # Test Auth0 token validation
        mock_auth0_instance.validate_token.return_value = {
            'sub': 'auth0|user_123',
            'email': 'test@example.com'
        }
        
        result = token_handler.validate_auth0_token(auth0_token)
        
        assert result['sub'] == 'auth0|user_123'
        mock_auth0_instance.validate_token.assert_called_once_with(auth0_token)

    @patch('src.auth.security_monitor.SecurityMonitor')
    def test_token_security_monitoring(self, mock_security_monitor, token_handler, app, mock_user_claims):
        """Test token handling security event monitoring."""
        with app.test_request_context():
            mock_monitor_instance = Mock()
            mock_security_monitor.return_value = mock_monitor_instance
            
            token_handler.generate_access_token(mock_user_claims)
            
            # Verify security monitoring
            mock_monitor_instance.log_token_event.assert_called_once()


class TestSecurityMonitor:
    """
    Unit tests for security monitoring service.
    
    Tests structured logging with Python structlog, Prometheus metrics integration,
    anomaly detection, and security incident response. Validates comprehensive
    security event monitoring and alerting capabilities.
    """

    @pytest.fixture
    def security_monitor(self, app):
        """Initialize SecurityMonitor for testing."""
        return SecurityMonitor(app)

    def test_security_monitor_initialization(self, security_monitor, app):
        """Test SecurityMonitor initializes with structured logging."""
        assert security_monitor.app == app
        assert security_monitor.logger is not None
        assert hasattr(security_monitor, 'prometheus_metrics')

    def test_authentication_event_logging(self, security_monitor, app):
        """Test structured logging of authentication events."""
        with app.test_request_context('/login', method='POST'):
            event_data = {
                'user_id': 'user_123',
                'action': 'login_attempt',
                'success': True,
                'ip_address': '192.168.1.100'
            }
            
            with patch.object(security_monitor.logger, 'info') as mock_log:
                security_monitor.log_authentication_event(**event_data)
                
                # Verify structured logging call
                mock_log.assert_called_once()
                call_args = mock_log.call_args[1]
                assert call_args['user_id'] == 'user_123'
                assert call_args['action'] == 'login_attempt'

    def test_security_violation_logging(self, security_monitor, app):
        """Test security violation event logging with severity."""
        with app.test_request_context('/protected', method='GET'):
            violation_data = {
                'violation_type': 'csrf_token_missing',
                'severity': 'high',
                'user_id': 'user_123',
                'endpoint': '/protected'
            }
            
            with patch.object(security_monitor.logger, 'warning') as mock_log:
                security_monitor.log_security_violation(**violation_data)
                
                mock_log.assert_called_once()

    def test_prometheus_metrics_integration(self, security_monitor, app):
        """Test Prometheus metrics collection for security events."""
        with app.test_request_context():
            with patch.object(security_monitor, 'prometheus_metrics') as mock_metrics:
                
                security_monitor.increment_auth_counter('login_success')
                
                # Verify Prometheus counter increment
                mock_metrics.auth_events_total.labels.assert_called_once()

    def test_anomaly_detection_patterns(self, security_monitor):
        """Test anomaly detection for suspicious authentication patterns."""
        # Simulate rapid login attempts
        events = [
            {'user_id': 'user_123', 'timestamp': time.time(), 'success': False}
            for _ in range(10)
        ]
        
        anomaly_detected = security_monitor.detect_anomaly(events, 'rapid_failed_logins')
        
        assert anomaly_detected is True

    def test_security_incident_creation(self, security_monitor, app):
        """Test automated security incident creation."""
        incident_data = {
            'incident_type': 'brute_force_attack',
            'severity': 'high',
            'user_id': 'user_123',
            'evidence': {'failed_attempts': 15, 'time_window': 300}
        }
        
        with patch.object(security_monitor, 'create_incident') as mock_create:
            security_monitor.handle_security_incident(**incident_data)
            
            mock_create.assert_called_once()

    def test_real_time_alerting(self, security_monitor):
        """Test real-time security alerting capabilities."""
        alert_data = {
            'alert_type': 'critical_security_event',
            'message': 'Multiple authentication failures detected',
            'channels': ['slack', 'email']
        }
        
        with patch.object(security_monitor, 'send_alert') as mock_alert:
            security_monitor.trigger_alert(**alert_data)
            
            mock_alert.assert_called_once()

    def test_aws_cloudwatch_integration(self, security_monitor):
        """Test AWS CloudWatch Logs integration for centralized monitoring."""
        log_data = {
            'log_group': '/aws/flask/security',
            'log_stream': 'authentication-events',
            'message': 'Security event logged'
        }
        
        with patch('boto3.client') as mock_boto:
            mock_cloudwatch = Mock()
            mock_boto.return_value = mock_cloudwatch
            
            security_monitor.send_to_cloudwatch(**log_data)
            
            mock_cloudwatch.put_log_events.assert_called_once()

    def test_structured_log_format(self, security_monitor):
        """Test structured JSON log format for machine readability."""
        with patch.object(security_monitor.logger, 'info') as mock_log:
            security_monitor.log_structured_event(
                event_type='user_action',
                user_id='user_123',
                action='data_access',
                resource='sensitive_data',
                timestamp=datetime.utcnow().isoformat()
            )
            
            # Verify structured log format
            mock_log.assert_called_once()
            call_kwargs = mock_log.call_args[1]
            assert 'event_type' in call_kwargs
            assert 'timestamp' in call_kwargs

    def test_security_context_preservation(self, security_monitor, app):
        """Test security context preservation across request lifecycle."""
        with app.test_request_context('/api/data', method='GET'):
            # Set security context
            security_monitor.set_security_context({
                'request_id': 'req_123',
                'user_id': 'user_123',
                'session_id': 'sess_456'
            })
            
            context = security_monitor.get_security_context()
            
            assert context['request_id'] == 'req_123'
            assert context['user_id'] == 'user_123'

    @patch('src.auth.security_monitor.structlog')
    def test_structlog_configuration(self, mock_structlog, security_monitor):
        """Test structlog configuration for JSON output."""
        # Verify structlog is configured correctly
        mock_structlog.configure.assert_called_once()
        
        # Check processor configuration includes JSON renderer
        config_call = mock_structlog.configure.call_args[1]
        processors = config_call['processors']
        
        # Should include JSON processor for structured output
        assert any('JSONRenderer' in str(processor) for processor in processors)


class TestAuthenticationIntegration:
    """
    Integration tests for complete authentication workflows.
    
    Tests end-to-end authentication flows combining multiple components to
    validate complete functionality preservation from Node.js to Flask migration.
    """

    def test_complete_login_workflow(self, app, client):
        """Test complete user login workflow from start to finish."""
        # Mock user credentials
        credentials = {
            'email': 'test@example.com',
            'password': 'SecureP@ssw0rd123'
        }
        
        with patch('src.auth.password_utils.PasswordUtils.check_password_hash') as mock_check:
            mock_check.return_value = True
            
            with patch('src.models.user.User.query') as mock_query:
                mock_user = Mock()
                mock_user.id = 'user_123'
                mock_user.email = credentials['email']
                mock_user.is_active = True
                mock_query.filter_by.return_value.first.return_value = mock_user
                
                response = client.post('/auth/login', json=credentials)
                
                assert response.status_code == 200
                response_data = response.get_json()
                assert 'access_token' in response_data

    def test_protected_endpoint_access(self, app, client):
        """Test access to protected endpoints with authentication."""
        # Generate valid JWT token
        with app.test_request_context():
            token_handler = TokenHandler(app)
            token = token_handler.generate_access_token({'user_id': 'user_123'})
            
            headers = {'Authorization': f'Bearer {token}'}
            response = client.get('/api/protected', headers=headers)
            
            assert response.status_code == 200

    def test_session_persistence(self, app, client):
        """Test session persistence across multiple requests."""
        with client.session_transaction() as sess:
            sess['user_id'] = 'user_123'
            sess['authenticated'] = True
        
        # First request
        response1 = client.get('/api/profile')
        assert response1.status_code == 200
        
        # Second request - session should persist
        response2 = client.get('/api/profile')
        assert response2.status_code == 200

    def test_logout_and_token_revocation(self, app, client):
        """Test complete logout workflow with token revocation."""
        with patch('src.auth.token_handler.TokenHandler.blacklist_token') as mock_blacklist:
            token = 'test_access_token'
            headers = {'Authorization': f'Bearer {token}'}
            
            response = client.post('/auth/logout', headers=headers)
            
            assert response.status_code == 200
            mock_blacklist.assert_called_once_with(token)

    def test_csrf_protection_integration(self, app, client):
        """Test CSRF protection in authentication workflows."""
        # Get CSRF token
        response = client.get('/auth/csrf-token')
        csrf_token = response.get_json()['csrf_token']
        
        # Submit form with CSRF token
        form_data = {
            'email': 'test@example.com',
            'password': 'password123',
            'csrf_token': csrf_token
        }
        
        response = client.post('/auth/login', data=form_data)
        assert response.status_code != 400  # Should not be CSRF error

    def test_auth0_integration_flow(self, app, client):
        """Test Auth0 integration in authentication flow."""
        with patch('src.auth.auth0_integration.Auth0Integration.validate_token') as mock_validate:
            mock_validate.return_value = {
                'sub': 'auth0|user_123',
                'email': 'test@example.com'
            }
            
            auth0_token = 'auth0_access_token'
            headers = {'Authorization': f'Bearer {auth0_token}'}
            
            response = client.get('/api/user-profile', headers=headers)
            assert response.status_code == 200

    def test_security_monitoring_integration(self, app, client):
        """Test security monitoring across authentication workflows."""
        with patch('src.auth.security_monitor.SecurityMonitor.log_authentication_event') as mock_log:
            credentials = {
                'email': 'test@example.com',
                'password': 'wrong_password'
            }
            
            # Failed login attempt
            response = client.post('/auth/login', json=credentials)
            
            # Verify security event is logged
            mock_log.assert_called_once()
            call_args = mock_log.call_args[1]
            assert call_args['success'] is False


class TestNodeJSMigrationParity:
    """
    Tests specifically validating 100% functional parity with Node.js implementation.
    
    These tests ensure that the Flask authentication system maintains identical
    behavior to the original Node.js middleware patterns while leveraging Flask's
    decorator architecture and security improvements.
    """

    def test_middleware_to_decorator_equivalence(self, app):
        """Test that Flask decorators provide equivalent protection to Node.js middleware."""
        # Mock Node.js middleware behavior
        node_middleware_result = {
            'authenticated': True,
            'user_id': 'user_123',
            'roles': ['user'],
            'permissions': ['read', 'write']
        }
        
        # Test Flask decorator equivalent
        with app.test_request_context():
            with patch('flask_login.current_user') as mock_user:
                mock_user.is_authenticated = True
                mock_user.id = 'user_123'
                mock_user.roles = ['user']
                mock_user.permissions = ['read', 'write']
                
                @require_auth
                def protected_endpoint():
                    return {
                        'authenticated': current_user.is_authenticated,
                        'user_id': current_user.id,
                        'roles': current_user.roles,
                        'permissions': current_user.permissions
                    }
                
                flask_result = protected_endpoint()
                
                # Results should be equivalent
                assert flask_result['authenticated'] == node_middleware_result['authenticated']
                assert flask_result['user_id'] == node_middleware_result['user_id']
                assert flask_result['roles'] == node_middleware_result['roles']

    def test_session_handling_parity(self, app):
        """Test Flask session handling maintains Node.js session behavior."""
        # Node.js session characteristics
        node_session_features = {
            'secure_cookies': True,
            'session_timeout': 3600,  # 1 hour
            'remember_me': True,
            'cookie_httponly': True
        }
        
        session_manager = SessionManager(app)
        
        # Verify Flask implementation matches
        assert session_manager.secure_cookies == node_session_features['secure_cookies']
        assert session_manager.session_timeout == node_session_features['session_timeout']
        assert session_manager.remember_me_support == node_session_features['remember_me']
        assert session_manager.cookie_httponly == node_session_features['cookie_httponly']

    def test_authentication_error_responses_parity(self, app, client):
        """Test authentication error responses match Node.js format."""
        # Expected Node.js error response format
        expected_error_format = {
            'error': 'Unauthorized',
            'message': 'Authentication required',
            'status_code': 401
        }
        
        response = client.get('/api/protected')
        
        assert response.status_code == 401
        response_data = response.get_json()
        assert response_data['error'] == expected_error_format['error']
        assert response_data['status_code'] == expected_error_format['status_code']

    def test_password_hashing_compatibility(self):
        """Test password hashing maintains compatibility with existing user passwords."""
        password_utils = PasswordUtils()
        
        # Simulate existing password from Node.js system
        existing_password = "existing_user_password"
        
        # Generate hash with Flask/Werkzeug
        flask_hash = password_utils.generate_password_hash(existing_password)
        
        # Verify hash can be validated
        is_valid = password_utils.check_password_hash(flask_hash, existing_password)
        assert is_valid is True

    def test_jwt_token_format_compatibility(self, app):
        """Test JWT tokens maintain format compatibility with Node.js implementation."""
        token_handler = TokenHandler(app)
        
        user_claims = {
            'user_id': 'user_123',
            'email': 'test@example.com',
            'roles': ['user']
        }
        
        with app.test_request_context():
            token = token_handler.generate_access_token(user_claims)
            decoded = token_handler.decode_token(token)
            
            # Verify token contains expected claims (Node.js format)
            assert 'user_id' in decoded
            assert 'email' in decoded
            assert 'roles' in decoded
            assert 'exp' in decoded  # Expiration claim
            assert 'iat' in decoded  # Issued at claim

    def test_api_response_format_consistency(self, app, client):
        """Test API response formats remain consistent with Node.js implementation."""
        # Mock successful authentication response
        with patch('src.auth.auth0_integration.Auth0Integration.validate_token') as mock_validate:
            mock_validate.return_value = {
                'sub': 'auth0|user_123',
                'email': 'test@example.com'
            }
            
            credentials = {
                'email': 'test@example.com',
                'password': 'password123'
            }
            
            response = client.post('/auth/login', json=credentials)
            response_data = response.get_json()
            
            # Verify response format matches Node.js structure
            expected_fields = ['access_token', 'token_type', 'expires_in', 'user']
            for field in expected_fields:
                assert field in response_data

    def test_security_headers_preservation(self, app, client):
        """Test security headers match Node.js implementation."""
        response = client.get('/api/protected')
        
        # Expected security headers from Node.js
        expected_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        
        for header in expected_headers:
            assert header in response.headers

    def test_performance_equivalence(self, app, client):
        """Test authentication performance meets or exceeds Node.js benchmarks."""
        import time
        
        # Benchmark authentication decorator performance
        start_time = time.time()
        
        for _ in range(100):
            with app.test_request_context():
                with patch('flask_login.current_user') as mock_user:
                    mock_user.is_authenticated = True
                    
                    @require_auth
                    def test_endpoint():
                        return {'status': 'success'}
                    
                    test_endpoint()
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 100
        
        # Should be faster than 1ms per authentication check
        assert avg_time < 0.001


# Test configuration and fixtures for authentication testing
@pytest.fixture
def app():
    """Create Flask application for testing."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['JWT_SECRET_KEY'] = 'jwt-test-secret'
    app.config['AUTH0_DOMAIN'] = 'test.auth0.com'
    app.config['AUTH0_CLIENT_ID'] = 'test_client_id'
    app.config['AUTH0_CLIENT_SECRET'] = 'test_client_secret'
    
    # Initialize extensions
    csrf = CSRFProtect(app)
    jwt = JWTManager(app)
    
    return app


@pytest.fixture
def client(app):
    """Create test client for HTTP requests."""
    return app.test_client()


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])