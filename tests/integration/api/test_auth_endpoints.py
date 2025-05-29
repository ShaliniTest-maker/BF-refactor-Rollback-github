"""
Authentication endpoint integration test suite validating Flask authentication decorators,
session management, and user access control functionality.

This comprehensive test suite ensures complete authentication mechanism migration from 
Node.js middleware patterns to Flask authentication decorators while maintaining existing 
user access patterns and security levels. Validates ItsDangerous session management, 
Flask-Login integration, and secure cookie protection.

Tests implemented per Section 4.7.1 with pytest-flask 1.3.0 fixtures and performance
validation against Node.js baseline per Feature F-009.
"""

import pytest
import json
import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

# Flask and extension imports
from flask import Flask, request, session, g
from flask_login import login_user, logout_user, current_user
from flask_wtf.csrf import generate_csrf, validate_csrf

# Application imports  
from src import create_app
from src.auth.decorators import require_auth, require_permission, require_role
from src.auth.session_manager import SessionManager
from src.auth.auth0_integration import Auth0Integration
from src.auth.token_handler import TokenHandler
from src.auth.csrf_protection import CSRFProtection
from src.auth.password_utils import PasswordUtils
from src.auth.security_monitor import SecurityMonitor
from src.models.user import User
from src.blueprints.auth import auth_bp
from src.blueprints.api import api_bp


class TestAuthenticationEndpoints:
    """
    Comprehensive authentication endpoint integration test suite.
    
    Tests all authentication mechanisms converted from Node.js middleware patterns
    to Flask authentication decorators, ensuring 100% functionality parity
    per Feature F-009 requirements.
    """

    @pytest.fixture(autouse=True)
    def setup_method(self, app, db, client):
        """
        Setup method for each test with comprehensive authentication environment.
        
        Initializes Flask-Login, ItsDangerous session management, and Auth0 mocking
        per Section 4.7.1 requirements for authentication testing.
        """
        self.app = app
        self.db = db
        self.client = client
        
        # Initialize authentication components per Section 6.4.1
        self.session_manager = SessionManager(app)
        self.token_handler = TokenHandler(app)
        self.csrf_protection = CSRFProtection(app) 
        self.password_utils = PasswordUtils()
        self.security_monitor = SecurityMonitor(app)
        
        # Create test user for authentication scenarios
        self.test_user = User(
            username='test_user',
            email='test@example.com',
            password_hash=generate_password_hash('secure_password123'),
            is_active=True,
            created_at=datetime.utcnow()
        )
        db.session.add(self.test_user)
        db.session.commit()
        
        # Mock Auth0 integration for testing per Section 6.4.1.1
        self.auth0_mock = Mock(spec=Auth0Integration)
        self.auth0_mock.validate_token.return_value = {
            'sub': 'auth0|test_user_id',
            'email': 'test@example.com',
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        # Performance baseline tracking per Feature F-009
        self.performance_metrics = {
            'auth_response_times': [],
            'session_operations': [],
            'token_validations': []
        }

    def test_flask_login_session_initialization(self, app, client):
        """
        Test Flask-Login session initialization and user loading.
        
        Validates comprehensive session management with ItsDangerous secure cookie
        signing per Section 6.4.1.3 and Flask-Login integration per Feature F-007.
        """
        with app.test_request_context():
            # Test user loader functionality
            loaded_user = app.login_manager.user_loader(str(self.test_user.id))
            assert loaded_user is not None
            assert loaded_user.id == self.test_user.id
            assert loaded_user.email == self.test_user.email
            
            # Test session manager initialization
            assert hasattr(app, 'session_manager')
            assert app.session_manager.login_manager is not None
            
            # Verify ItsDangerous configuration per Section 3.2.3
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            test_data = {'user_id': self.test_user.id, 'test': 'secure_session'}
            signed_data = serializer.dumps(test_data)
            unsigned_data = serializer.loads(signed_data)
            assert unsigned_data == test_data

    def test_authentication_decorator_integration(self, app, client):
        """
        Test Flask authentication decorators replacing Node.js middleware patterns.
        
        Validates @require_auth, @require_permission, and @require_role decorators
        per Section 4.6.1 authentication mechanism migration requirements.
        """
        with app.test_request_context():
            # Test require_auth decorator without authentication
            @require_auth
            def protected_endpoint():
                return {'message': 'Protected content'}
            
            # Should raise 401 without authentication
            with pytest.raises(Exception) as exc_info:
                protected_endpoint()
            
            # Test with authenticated user
            with client.session_transaction() as sess:
                sess['_user_id'] = str(self.test_user.id)
                sess['_fresh'] = True
            
            # Mock current_user for decorator testing
            with patch('src.auth.decorators.current_user', self.test_user):
                result = protected_endpoint()
                assert result['message'] == 'Protected content'

    def test_itsdangerous_session_security(self, app, client):
        """
        Test ItsDangerous secure session cookie signing and protection.
        
        Validates session tamper protection and secure cookie implementation
        per Section 6.4.1.3 security requirements.
        """
        with app.test_request_context():
            serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            
            # Test secure session data signing
            session_data = {
                'user_id': self.test_user.id,
                'login_time': datetime.utcnow().isoformat(),
                'csrf_token': 'test_csrf_token'
            }
            
            # Sign session data
            signed_session = serializer.dumps(session_data)
            assert signed_session is not None
            assert isinstance(signed_session, str)
            
            # Verify tamper detection
            tampered_session = signed_session[:-5] + 'XXXXX'
            with pytest.raises(Exception):
                serializer.loads(tampered_session)
            
            # Test session expiration
            expired_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            with pytest.raises(Exception):
                expired_serializer.loads(signed_session, max_age=0)

    def test_csrf_protection_integration(self, app, client):
        """
        Test Flask-WTF CSRF protection implementation.
        
        Validates CSRF token generation, validation, and protection against
        cross-site request forgery attacks per Section 4.6.2 requirements.
        """
        with app.test_request_context():
            # Test CSRF token generation
            csrf_token = generate_csrf()
            assert csrf_token is not None
            assert len(csrf_token) > 20  # Sufficient entropy
            
            # Test CSRF validation with valid token
            assert validate_csrf(csrf_token) is True
            
            # Test CSRF validation with invalid token
            assert validate_csrf('invalid_csrf_token') is False
            
        # Test CSRF protection on POST requests
        response = client.post('/auth/login', data={
            'email': 'test@example.com',
            'password': 'secure_password123'
        })
        # Should fail without CSRF token
        assert response.status_code == 400
        
        # Test with valid CSRF token
        with client.session_transaction() as sess:
            csrf_token = generate_csrf()
            sess['csrf_token'] = csrf_token
            
        response = client.post('/auth/login', data={
            'email': 'test@example.com', 
            'password': 'secure_password123',
            'csrf_token': csrf_token
        })
        # Should succeed with valid CSRF token
        assert response.status_code in [200, 302]

    @patch('src.auth.auth0_integration.Auth0Integration.validate_token')
    def test_auth0_jwt_token_validation(self, mock_validate, app, client):
        """
        Test Auth0 JWT token validation and integration.
        
        Validates Auth0 Python SDK integration, token validation, and user
        profile synchronization per Section 6.4.1.1 requirements.
        """
        # Mock successful token validation
        mock_validate.return_value = {
            'sub': 'auth0|test_user_123',
            'email': 'test@example.com',
            'email_verified': True,
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            'aud': 'test_audience',
            'iss': 'https://test-domain.auth0.com/'
        }
        
        # Test JWT token validation
        test_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test.signature'
        
        response = client.get('/api/protected', headers={
            'Authorization': f'Bearer {test_token}'
        })
        
        # Verify token validation was called
        mock_validate.assert_called_once_with(test_token)
        
        # Test token refresh workflow
        with patch('src.auth.token_handler.TokenHandler.refresh_token') as mock_refresh:
            mock_refresh.return_value = {
                'access_token': 'new_access_token',
                'refresh_token': 'new_refresh_token',
                'expires_in': 3600
            }
            
            response = client.post('/auth/refresh', json={
                'refresh_token': 'valid_refresh_token'
            })
            
            assert response.status_code == 200
            response_data = json.loads(response.data)
            assert 'access_token' in response_data

    def test_password_security_utilities(self, app):
        """
        Test Werkzeug password security utilities implementation.
        
        Validates secure password hashing, salt generation, and constant-time
        comparison per Section 4.6.2 password security requirements.
        """
        with app.test_request_context():
            password = 'test_secure_password123!'
            
            # Test password hashing with salt
            password_hash = self.password_utils.hash_password(password)
            assert password_hash is not None
            assert password_hash != password  # Should be hashed
            assert len(password_hash) > 50  # Sufficient hash length
            
            # Test password verification
            assert self.password_utils.verify_password(password, password_hash) is True
            assert self.password_utils.verify_password('wrong_password', password_hash) is False
            
            # Test password strength validation
            weak_passwords = ['123', 'password', 'abc']
            for weak_password in weak_passwords:
                assert self.password_utils.validate_password_strength(weak_password) is False
            
            strong_passwords = ['SecureP@ssw0rd123!', 'MyStr0ng!P@ssword']
            for strong_password in strong_passwords:
                assert self.password_utils.validate_password_strength(strong_password) is True

    def test_session_lifecycle_management(self, app, client):
        """
        Test comprehensive session lifecycle management.
        
        Validates session creation, validation, renewal, and cleanup procedures
        per Section 6.4.1.3 session management requirements.
        """
        # Test session creation during login
        login_data = {
            'email': self.test_user.email,
            'password': 'secure_password123'
        }
        
        # Mock successful authentication
        with patch('src.auth.password_utils.PasswordUtils.verify_password', return_value=True):
            response = client.post('/auth/login', 
                                 data=login_data,
                                 follow_redirects=True)
            
            # Verify session creation
            with client.session_transaction() as sess:
                assert '_user_id' in sess
                assert sess['_user_id'] == str(self.test_user.id)
                assert '_fresh' in sess
        
        # Test session validation
        response = client.get('/api/profile')
        assert response.status_code == 200
        
        # Test session renewal
        with client.session_transaction() as sess:
            original_timestamp = sess.get('_session_timestamp')
        
        time.sleep(1)  # Ensure timestamp difference
        
        response = client.get('/api/profile')
        assert response.status_code == 200
        
        with client.session_transaction() as sess:
            new_timestamp = sess.get('_session_timestamp') 
            # Session should be renewed
            assert new_timestamp != original_timestamp
        
        # Test session cleanup during logout
        response = client.post('/auth/logout')
        assert response.status_code in [200, 302]
        
        with client.session_transaction() as sess:
            assert '_user_id' not in sess
            assert '_fresh' not in sess

    def test_authentication_before_request_handlers(self, app, client):
        """
        Test Flask before_request handlers replacing Express.js auth middleware.
        
        Validates before_request authentication logic and request context setup
        per Section 4.3.2 middleware replacement requirements.
        """
        with app.test_request_context('/api/protected'):
            # Test before_request execution
            with patch('src.blueprints.auth.auth_bp.before_request') as mock_before:
                mock_before.return_value = None  # Allow request to proceed
                
                # Simulate authenticated request
                with client.session_transaction() as sess:
                    sess['_user_id'] = str(self.test_user.id)
                
                response = client.get('/api/protected')
                
                # Verify before_request was called
                mock_before.assert_called()
        
        # Test authentication state setup in request context
        with app.test_request_context():
            g.user = self.test_user
            g.authenticated = True
            
            # Verify request context variables
            assert hasattr(g, 'user')
            assert hasattr(g, 'authenticated')
            assert g.user.id == self.test_user.id
            assert g.authenticated is True

    def test_security_monitoring_integration(self, app, client):
        """
        Test security monitoring and audit logging integration.
        
        Validates authentication event logging, anomaly detection, and security
        monitoring per Section 6.4.6.1 security monitoring requirements.
        """
        with app.test_request_context():
            # Test authentication success logging
            self.security_monitor.log_authentication_event(
                user_id=self.test_user.id,
                event_type='login_success',
                ip_address='127.0.0.1',
                user_agent='test_agent'
            )
            
            # Test authentication failure logging
            self.security_monitor.log_authentication_event(
                user_id=None,
                event_type='login_failure',
                ip_address='127.0.0.1',
                user_agent='test_agent',
                details={'reason': 'invalid_credentials'}
            )
            
            # Test suspicious activity detection
            for i in range(6):  # Trigger rate limiting
                self.security_monitor.log_authentication_event(
                    user_id=None,
                    event_type='login_failure',
                    ip_address='192.168.1.100',
                    user_agent='automated_bot'
                )
            
            # Verify anomaly detection
            anomalies = self.security_monitor.detect_anomalies('192.168.1.100')
            assert len(anomalies) > 0
            assert anomalies[0]['type'] == 'suspicious_login_pattern'

    @pytest.mark.performance
    def test_authentication_performance_baseline(self, app, client):
        """
        Test authentication endpoint performance against Node.js baseline.
        
        Validates response times and concurrent user handling per Section 4.7.1
        performance testing requirements and Feature F-009 parity validation.
        """
        # Performance test configuration
        num_concurrent_users = 50
        num_requests_per_user = 10
        baseline_response_time = 200  # milliseconds (Node.js baseline)
        
        def authenticate_user():
            """Simulate user authentication for performance testing."""
            start_time = time.time()
            
            # Test login performance
            response = client.post('/auth/login', data={
                'email': self.test_user.email,
                'password': 'secure_password123'
            })
            
            login_time = (time.time() - start_time) * 1000
            self.performance_metrics['auth_response_times'].append(login_time)
            
            # Test protected endpoint access
            start_time = time.time()
            response = client.get('/api/profile')
            access_time = (time.time() - start_time) * 1000
            
            return login_time, access_time
        
        # Execute concurrent authentication tests
        threads = []
        for _ in range(num_concurrent_users):
            thread = threading.Thread(target=authenticate_user)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Analyze performance metrics
        avg_response_time = sum(self.performance_metrics['auth_response_times']) / len(self.performance_metrics['auth_response_times'])
        max_response_time = max(self.performance_metrics['auth_response_times'])
        
        # Validate performance against baseline
        assert avg_response_time <= baseline_response_time * 1.2  # 20% tolerance
        assert max_response_time <= baseline_response_time * 2.0  # Maximum tolerance
        
        # Log performance results
        print(f"Authentication Performance Results:")
        print(f"Average Response Time: {avg_response_time:.2f}ms")
        print(f"Maximum Response Time: {max_response_time:.2f}ms")
        print(f"Baseline Compliance: {'PASS' if avg_response_time <= baseline_response_time else 'FAIL'}")

    def test_authorization_role_based_access_control(self, app, client):
        """
        Test role-based access control (RBAC) implementation.
        
        Validates user role and permission management, ensuring existing
        authorization patterns are preserved per Feature F-007 requirements.
        """
        with app.test_request_context():
            # Create admin user for role testing
            admin_user = User(
                username='admin_user',
                email='admin@example.com',
                password_hash=generate_password_hash('admin_password123'),
                role='admin',
                is_active=True
            )
            self.db.session.add(admin_user)
            self.db.session.commit()
            
            # Test role-based decorator
            @require_role('admin')
            def admin_only_endpoint():
                return {'message': 'Admin access granted'}
            
            # Test with regular user (should fail)
            with patch('src.auth.decorators.current_user', self.test_user):
                with pytest.raises(Exception):
                    admin_only_endpoint()
            
            # Test with admin user (should succeed)
            with patch('src.auth.decorators.current_user', admin_user):
                result = admin_only_endpoint()
                assert result['message'] == 'Admin access granted'
            
            # Test permission-based access control
            @require_permission('write_posts')
            def permission_protected_endpoint():
                return {'message': 'Permission granted'}
            
            # Mock user permissions
            with patch('src.auth.decorators.current_user') as mock_user:
                mock_user.has_permission.return_value = True
                result = permission_protected_endpoint()
                assert result['message'] == 'Permission granted'

    def test_authentication_error_handling(self, app, client):
        """
        Test comprehensive authentication error handling and responses.
        
        Validates error scenarios, status codes, and security logging per
        Section 4.6.3 error handling requirements.
        """
        # Test invalid credentials
        response = client.post('/auth/login', data={
            'email': 'nonexistent@example.com',
            'password': 'wrong_password'
        })
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'error' in response_data
        assert response_data['error'] == 'Invalid credentials'
        
        # Test missing authentication
        response = client.get('/api/protected')
        assert response.status_code == 401
        
        # Test expired session
        with client.session_transaction() as sess:
            sess['_user_id'] = str(self.test_user.id)
            sess['_session_timestamp'] = (datetime.utcnow() - timedelta(hours=25)).isoformat()
        
        response = client.get('/api/profile')
        assert response.status_code == 401
        
        # Test CSRF token mismatch
        response = client.post('/auth/change-password', data={
            'current_password': 'secure_password123',
            'new_password': 'new_secure_password456',
            'csrf_token': 'invalid_csrf_token'
        })
        assert response.status_code == 400

    def test_token_refresh_and_revocation(self, app, client):
        """
        Test JWT token refresh and revocation mechanisms.
        
        Validates token lifecycle management, refresh token rotation, and
        revocation procedures per Section 6.4.1.4 token handling requirements.
        """
        with app.test_request_context():
            # Test token generation
            access_token = self.token_handler.generate_access_token(self.test_user.id)
            refresh_token = self.token_handler.generate_refresh_token(self.test_user.id)
            
            assert access_token is not None
            assert refresh_token is not None
            
            # Test token validation
            token_data = self.token_handler.validate_access_token(access_token)
            assert token_data['user_id'] == self.test_user.id
            
            # Test token refresh
            new_tokens = self.token_handler.refresh_access_token(refresh_token)
            assert 'access_token' in new_tokens
            assert 'refresh_token' in new_tokens
            assert new_tokens['access_token'] != access_token
            
            # Test token revocation
            self.token_handler.revoke_token(access_token)
            
            # Revoked token should be invalid
            with pytest.raises(Exception):
                self.token_handler.validate_access_token(access_token)

    def test_concurrent_session_management(self, app, client):
        """
        Test concurrent session management and scalability.
        
        Validates session handling under concurrent load and multi-device
        session support per Section 6.4.1.3 session management requirements.
        """
        num_concurrent_sessions = 20
        session_results = []
        
        def create_concurrent_session():
            """Create concurrent user session for scalability testing."""
            try:
                # Create session
                with client.session_transaction() as sess:
                    sess['_user_id'] = str(self.test_user.id)
                    sess['_fresh'] = True
                    sess['_session_id'] = f"session_{threading.current_thread().ident}"
                
                # Test session access
                response = client.get('/api/profile')
                session_results.append({
                    'status_code': response.status_code,
                    'thread_id': threading.current_thread().ident,
                    'success': response.status_code == 200
                })
                
            except Exception as e:
                session_results.append({
                    'status_code': 500,
                    'thread_id': threading.current_thread().ident,
                    'success': False,
                    'error': str(e)
                })
        
        # Execute concurrent session tests
        threads = []
        for _ in range(num_concurrent_sessions):
            thread = threading.Thread(target=create_concurrent_session)
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Validate results
        successful_sessions = [r for r in session_results if r['success']]
        assert len(successful_sessions) == num_concurrent_sessions
        
        # Verify no session conflicts
        unique_threads = set(r['thread_id'] for r in session_results)
        assert len(unique_threads) == num_concurrent_sessions

    def test_security_posture_maintenance(self, app, client):
        """
        Test security posture maintenance during migration.
        
        Validates that Flask implementation maintains or improves security
        compared to Node.js baseline per Feature F-007 requirements.
        """
        security_tests = [
            # Test secure cookie attributes
            {
                'name': 'secure_cookies',
                'test': lambda: self._test_secure_cookie_attributes(),
                'requirement': 'HTTPOnly and Secure cookie flags'
            },
            # Test session fixation protection
            {
                'name': 'session_fixation',
                'test': lambda: self._test_session_fixation_protection(),
                'requirement': 'Session ID regeneration on login'
            },
            # Test password hash security
            {
                'name': 'password_security',
                'test': lambda: self._test_password_hash_security(),
                'requirement': 'Secure password hashing with salt'
            },
            # Test timing attack protection
            {
                'name': 'timing_attacks',
                'test': lambda: self._test_timing_attack_protection(),
                'requirement': 'Constant-time password comparison'
            }
        ]
        
        security_results = {}
        
        for test in security_tests:
            try:
                result = test['test']()
                security_results[test['name']] = {
                    'passed': result,
                    'requirement': test['requirement']
                }
            except Exception as e:
                security_results[test['name']] = {
                    'passed': False,
                    'requirement': test['requirement'],
                    'error': str(e)
                }
        
        # Validate all security tests passed
        failed_tests = [name for name, result in security_results.items() 
                       if not result['passed']]
        
        assert len(failed_tests) == 0, f"Security tests failed: {failed_tests}"

    def _test_secure_cookie_attributes(self):
        """Test secure cookie configuration."""
        with self.app.test_request_context():
            # Verify secure cookie settings
            assert self.app.config.get('SESSION_COOKIE_SECURE') is True
            assert self.app.config.get('SESSION_COOKIE_HTTPONLY') is True
            assert self.app.config.get('SESSION_COOKIE_SAMESITE') == 'Lax'
        return True

    def _test_session_fixation_protection(self):
        """Test session fixation protection."""
        with self.client.session_transaction() as sess:
            original_session_id = sess.get('_session_id', 'default')
        
        # Simulate login
        response = self.client.post('/auth/login', data={
            'email': self.test_user.email,
            'password': 'secure_password123'
        })
        
        with self.client.session_transaction() as sess:
            new_session_id = sess.get('_session_id', 'default')
        
        # Session ID should change after login
        return new_session_id != original_session_id

    def _test_password_hash_security(self):
        """Test password hash security implementation."""
        password = 'test_password_123'
        hash1 = self.password_utils.hash_password(password)
        hash2 = self.password_utils.hash_password(password)
        
        # Hashes should be different (due to salt)
        return hash1 != hash2 and len(hash1) > 50

    def _test_timing_attack_protection(self):
        """Test timing attack protection in password verification."""
        correct_password = 'secure_password123'
        wrong_password = 'wrong_password'
        password_hash = self.password_utils.hash_password(correct_password)
        
        # Time password verification operations
        start_time = time.time()
        self.password_utils.verify_password(correct_password, password_hash)
        correct_time = time.time() - start_time
        
        start_time = time.time()
        self.password_utils.verify_password(wrong_password, password_hash)
        wrong_time = time.time() - start_time
        
        # Time difference should be minimal (constant-time comparison)
        time_difference = abs(correct_time - wrong_time)
        return time_difference < 0.001  # Less than 1ms difference

    def teardown_method(self):
        """
        Cleanup after each test method.
        
        Ensures proper cleanup of authentication state and performance metrics
        collection for test isolation.
        """
        # Clear performance metrics
        self.performance_metrics.clear()
        
        # Reset security monitor state
        if hasattr(self, 'security_monitor'):
            self.security_monitor.reset_state()
        
        # Clear session state
        with self.client.session_transaction() as sess:
            sess.clear()


class TestAuthenticationIntegration:
    """
    Integration tests for authentication component interactions.
    
    Tests the integration between Flask authentication decorators, session
    management, and external services per Feature F-007 requirements.
    """

    def test_end_to_end_authentication_flow(self, app, client, db):
        """
        Test complete end-to-end authentication flow.
        
        Validates the entire authentication process from login to logout,
        ensuring seamless integration of all authentication components.
        """
        # Step 1: User registration
        registration_data = {
            'username': 'integration_user',
            'email': 'integration@example.com',
            'password': 'integration_password123'
        }
        
        response = client.post('/auth/register', data=registration_data)
        assert response.status_code in [200, 201, 302]
        
        # Step 2: User login
        login_data = {
            'email': 'integration@example.com',
            'password': 'integration_password123'
        }
        
        response = client.post('/auth/login', data=login_data)
        assert response.status_code in [200, 302]
        
        # Step 3: Access protected resource
        response = client.get('/api/profile')
        assert response.status_code == 200
        
        # Step 4: Token refresh (if applicable)
        response = client.post('/auth/refresh')
        assert response.status_code == 200
        
        # Step 5: User logout
        response = client.post('/auth/logout')
        assert response.status_code in [200, 302]
        
        # Step 6: Verify access is denied after logout
        response = client.get('/api/profile')
        assert response.status_code == 401

    def test_flask_login_auth0_integration(self, app, client):
        """
        Test integration between Flask-Login and Auth0 authentication.
        
        Validates seamless integration between local Flask session management
        and external Auth0 identity provider per Section 6.4.1.1 requirements.
        """
        # Mock Auth0 authentication response
        with patch('src.auth.auth0_integration.Auth0Integration.authenticate') as mock_auth:
            mock_auth.return_value = {
                'access_token': 'auth0_access_token',
                'id_token': 'auth0_id_token',
                'user_info': {
                    'sub': 'auth0|user_123',
                    'email': 'auth0user@example.com',
                    'email_verified': True
                }
            }
            
            # Test Auth0 login callback
            response = client.get('/auth/callback?code=auth0_code&state=test_state')
            assert response.status_code in [200, 302]
            
            # Verify Flask-Login session is established
            with client.session_transaction() as sess:
                assert '_user_id' in sess
            
            # Test authenticated access
            response = client.get('/api/profile')
            assert response.status_code == 200

    @pytest.mark.benchmark
    def test_authentication_performance_benchmark(self, app, client, benchmark):
        """
        Benchmark authentication performance using pytest-benchmark.
        
        Measures authentication response times for performance regression
        testing per Section 4.7.1 performance validation requirements.
        """
        def authentication_benchmark():
            """Benchmark function for authentication operations."""
            # Benchmark login operation
            response = client.post('/auth/login', data={
                'email': 'test@example.com',
                'password': 'secure_password123'
            })
            
            # Benchmark protected endpoint access
            response = client.get('/api/profile')
            
            return response.status_code
        
        # Execute benchmark
        result = benchmark(authentication_benchmark)
        assert result == 200
        
        # Validate benchmark results against Node.js baseline
        # (This would be configured in CI/CD pipeline)
        assert benchmark.stats['mean'] < 0.2  # 200ms baseline


if __name__ == '__main__':
    # Run tests with comprehensive coverage reporting
    pytest.main([
        __file__,
        '-v',
        '--cov=src.auth',
        '--cov=src.blueprints.auth',
        '--cov-report=html',
        '--cov-report=term-missing',
        '--benchmark-only',
        '--benchmark-sort=mean'
    ])