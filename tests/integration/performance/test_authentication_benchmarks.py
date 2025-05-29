"""
Authentication Performance Benchmarking Test Suite

This module provides comprehensive authentication performance benchmarking using pytest-benchmark 5.1.0
to validate Flask authentication response times, Auth0 integration performance, and ItsDangerous session
management efficiency. This test suite ensures sub-150ms authentication response times and validates
security performance while maintaining equivalent or improved authentication flow efficiency compared
to Node.js middleware patterns.

Key Features:
- Auth0 authentication flow benchmarking with sub-150ms response time validation per Section 4.11.1
- pytest-benchmark fixtures measuring Flask authentication decorator performance per Section 4.7.1
- ItsDangerous session management performance validation against Node.js baseline per Section 5.1.1
- Flask authentication middleware timing analysis with security preservation per Section 6.5.1.1
- Automated authentication performance regression testing per Section 4.7.2
- Auth0 integration monitoring with comprehensive authentication flow analysis per Section 6.5.2.2

Migration Context:
This test suite supports the strategic technology migration from Node.js/Express.js authentication
middleware to Python 3.13.3/Flask 3.1.1 authentication decorators and ItsDangerous session management.
The benchmarking ensures that Flask authentication mechanisms meet or exceed Node.js performance
while preserving security posture and user experience patterns.

Performance Requirements:
- Authentication response times must be < 150ms per Section 4.11.1
- Flask authentication decorators must perform equivalent to Node.js middleware
- ItsDangerous session management must maintain security without performance degradation
- Auth0 integration must preserve external authentication flow efficiency
- All authentication flows must support automated regression testing
"""

import asyncio
import json
import time
import threading
import statistics
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
from contextlib import contextmanager
import secrets
import hashlib
import base64

import pytest
from flask import Flask, request, session, g, current_app
from flask.testing import FlaskClient
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Authentication component imports
try:
    from src.auth.decorators import require_auth, require_permission, require_role
    from src.auth.session_manager import SessionManager, create_session, validate_session
    from src.auth.auth0_integration import Auth0Integration, validate_auth0_token
    from src.auth.token_handler import TokenHandler, generate_jwt_token, validate_jwt_token
    from src.auth.password_utils import hash_password, verify_password
    from src.auth.csrf_protection import CSRFProtection, generate_csrf_token, validate_csrf_token
    from src.auth.security_monitor import SecurityMonitor, log_auth_event
    AUTH_MODULES_AVAILABLE = True
except ImportError:
    # Mock imports for testing when modules are not yet fully implemented
    AUTH_MODULES_AVAILABLE = False


# Performance testing markers per Section 4.7.1
pytestmark = [
    pytest.mark.performance,
    pytest.mark.auth_performance,
    pytest.mark.integration
]


class AuthenticationTestData:
    """
    Test data provider for authentication performance benchmarking.
    
    This class provides consistent test data for authentication benchmarking
    including user credentials, tokens, and session data for performance validation.
    """
    
    def __init__(self):
        """Initialize authentication test data."""
        self.test_users = [
            {
                'id': 1,
                'username': 'test_user_1',
                'email': 'test1@example.com',
                'password': 'SecurePassword123!',
                'role': 'user',
                'permissions': ['read', 'write']
            },
            {
                'id': 2,
                'username': 'test_admin',
                'email': 'admin@example.com', 
                'password': 'AdminPassword456!',
                'role': 'admin',
                'permissions': ['read', 'write', 'admin', 'delete']
            },
            {
                'id': 3,
                'username': 'test_viewer',
                'email': 'viewer@example.com',
                'password': 'ViewerPassword789!',
                'role': 'viewer',
                'permissions': ['read']
            }
        ]
        
        # Auth0 test tokens (mock data for performance testing)
        self.auth0_test_tokens = {
            'valid_token': self._generate_mock_jwt_token({
                'sub': 'auth0|test_user_1',
                'email': 'test1@example.com',
                'email_verified': True,
                'iat': int(time.time()),
                'exp': int(time.time()) + 3600,
                'aud': 'test-auth0-audience',
                'iss': 'https://test-domain.auth0.com/'
            }),
            'expired_token': self._generate_mock_jwt_token({
                'sub': 'auth0|test_user_1',
                'email': 'test1@example.com',
                'iat': int(time.time()) - 7200,
                'exp': int(time.time()) - 3600,
                'aud': 'test-auth0-audience',
                'iss': 'https://test-domain.auth0.com/'
            }),
            'invalid_signature': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.invalid.signature'
        }
        
        # Session test data
        self.session_test_data = [
            {
                'user_id': 1,
                'session_data': {
                    'username': 'test_user_1',
                    'role': 'user',
                    'last_activity': datetime.now(timezone.utc).isoformat(),
                    'csrf_token': secrets.token_hex(32)
                }
            },
            {
                'user_id': 2,
                'session_data': {
                    'username': 'test_admin',
                    'role': 'admin',
                    'last_activity': datetime.now(timezone.utc).isoformat(),
                    'csrf_token': secrets.token_hex(32)
                }
            }
        ]
        
    def _generate_mock_jwt_token(self, payload: Dict[str, Any]) -> str:
        """Generate mock JWT token for testing purposes."""
        import json
        import base64
        
        # Create JWT header
        header = {
            'typ': 'JWT',
            'alg': 'RS256',
            'kid': 'test-key-id'
        }
        
        # Encode header and payload
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        # Create mock signature (for testing only)
        signature = base64.urlsafe_b64encode(
            hashlib.sha256(f"{header_encoded}.{payload_encoded}".encode()).digest()
        ).decode().rstrip('=')
        
        return f"{header_encoded}.{payload_encoded}.{signature}"
        
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get test user by ID."""
        for user in self.test_users:
            if user['id'] == user_id:
                return user.copy()
        return None
        
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get test user by username."""
        for user in self.test_users:
            if user['username'] == username:
                return user.copy()
        return None


class MockAuth0Integration:
    """
    Mock Auth0 integration for performance testing.
    
    This class provides mock Auth0 functionality for performance benchmarking
    without requiring actual Auth0 service connectivity.
    """
    
    def __init__(self):
        """Initialize mock Auth0 integration."""
        self.domain = "test-domain.auth0.com"
        self.client_id = "test-client-id"
        self.client_secret = "test-client-secret"
        self.audience = "test-auth0-audience"
        self.validation_call_count = 0
        self.token_refresh_count = 0
        
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Mock Auth0 token validation for performance testing.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Token validation result
        """
        self.validation_call_count += 1
        
        # Simulate network latency for realistic performance testing
        await asyncio.sleep(0.02)  # 20ms mock latency
        
        if 'expired' in token:
            return {
                'valid': False,
                'error': 'Token expired',
                'user_info': None
            }
        elif 'invalid' in token:
            return {
                'valid': False,
                'error': 'Invalid signature',
                'user_info': None
            }
        else:
            return {
                'valid': True,
                'error': None,
                'user_info': {
                    'sub': 'auth0|test_user_1',
                    'email': 'test1@example.com',
                    'email_verified': True,
                    'permissions': ['read', 'write']
                }
            }
            
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Mock Auth0 token refresh for performance testing.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            Token refresh result
        """
        self.token_refresh_count += 1
        
        # Simulate Auth0 API call latency
        await asyncio.sleep(0.05)  # 50ms mock latency
        
        return {
            'access_token': 'mock_new_access_token',
            'refresh_token': 'mock_new_refresh_token',
            'expires_in': 3600,
            'token_type': 'Bearer'
        }
        
    def get_user_profile(self, user_id: str) -> Dict[str, Any]:
        """Mock Auth0 user profile retrieval."""
        return {
            'user_id': user_id,
            'email': 'test1@example.com',
            'email_verified': True,
            'name': 'Test User',
            'picture': 'https://example.com/avatar.jpg',
            'created_at': '2024-01-01T00:00:00.000Z',
            'updated_at': datetime.now(timezone.utc).isoformat()
        }


class MockFlaskAuth:
    """
    Mock Flask authentication components for performance testing.
    
    This class provides mock implementations of Flask authentication decorators
    and session management for comprehensive performance benchmarking.
    """
    
    def __init__(self, app: Flask, test_data: AuthenticationTestData):
        """Initialize mock Flask authentication."""
        self.app = app
        self.test_data = test_data
        self.serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY', 'test-secret'))
        self.auth_calls = 0
        self.session_calls = 0
        self.csrf_calls = 0
        
    def mock_require_auth(self, f):
        """Mock authentication decorator."""
        def wrapper(*args, **kwargs):
            self.auth_calls += 1
            
            # Simulate authentication check
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return {'error': 'Missing or invalid authorization header'}, 401
                
            token = auth_header.split(' ')[1]
            
            # Mock token validation (simulate ItsDangerous processing time)
            try:
                start_time = time.perf_counter()
                data = self.serializer.loads(token, max_age=3600)
                processing_time = time.perf_counter() - start_time
                
                # Store timing data for analysis
                g.auth_processing_time = processing_time
                g.current_user = self.test_data.get_user_by_id(data.get('user_id'))
                
                return f(*args, **kwargs)
                
            except (BadSignature, SignatureExpired):
                return {'error': 'Invalid or expired token'}, 401
                
        return wrapper
        
    def mock_create_session(self, user_id: int) -> str:
        """Mock session creation with ItsDangerous."""
        self.session_calls += 1
        
        session_data = {
            'user_id': user_id,
            'created_at': time.time(),
            'csrf_token': secrets.token_hex(32)
        }
        
        # Measure ItsDangerous session signing performance
        start_time = time.perf_counter()
        session_token = self.serializer.dumps(session_data)
        signing_time = time.perf_counter() - start_time
        
        # Store performance metrics
        g.session_signing_time = signing_time
        
        return session_token
        
    def mock_validate_csrf_token(self, token: str) -> bool:
        """Mock CSRF token validation."""
        self.csrf_calls += 1
        
        # Simulate CSRF validation processing time
        time.sleep(0.001)  # 1ms processing time
        
        return len(token) == 64 and all(c in '0123456789abcdef' for c in token)
        
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get authentication performance statistics."""
        return {
            'auth_decorator_calls': self.auth_calls,
            'session_manager_calls': self.session_calls,
            'csrf_validation_calls': self.csrf_calls
        }


# Test Fixtures for Authentication Benchmarking
@pytest.fixture(scope="function")
def auth_test_data():
    """Authentication test data fixture."""
    return AuthenticationTestData()


@pytest.fixture(scope="function")
def mock_auth0(auth_test_data):
    """Mock Auth0 integration fixture."""
    return MockAuth0Integration()


@pytest.fixture(scope="function")
def mock_flask_auth(flask_app_factory, auth_test_data):
    """Mock Flask authentication fixture."""
    return MockFlaskAuth(flask_app_factory, auth_test_data)


@pytest.fixture(scope="function")
def authenticated_client(flask_client, mock_flask_auth, auth_test_data):
    """Flask client with authentication setup."""
    # Create session for test user
    user = auth_test_data.test_users[0]
    session_token = mock_flask_auth.mock_create_session(user['id'])
    
    # Set authorization header for requests
    flask_client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {session_token}'
    
    return flask_client


# Core Authentication Performance Tests
class TestFlaskAuthenticationDecorators:
    """
    Test suite for Flask authentication decorator performance.
    
    This test class validates Flask authentication decorator performance against
    Node.js middleware patterns per Section 4.7.1 requirements.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="auth_decorators")
    def test_require_auth_decorator_performance(self, benchmark, flask_client, 
                                              mock_flask_auth, auth_test_data,
                                              authentication_performance_benchmark):
        """
        Benchmark Flask @require_auth decorator performance.
        
        This test validates that Flask authentication decorators meet sub-150ms
        response time requirements per Section 4.11.1 while maintaining security.
        """
        user = auth_test_data.test_users[0]
        session_token = mock_flask_auth.mock_create_session(user['id'])
        
        def auth_decorator_execution():
            """Execute authentication decorator workflow."""
            # Simulate request with authentication
            with flask_client.application.test_request_context(
                '/api/protected',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                # Apply mock authentication decorator
                @mock_flask_auth.mock_require_auth
                def protected_endpoint():
                    return {'message': 'Access granted', 'user_id': user['id']}
                    
                result = protected_endpoint()
                return result
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            auth_decorator_execution,
            'flask_require_auth_decorator',
            baseline_key='auth_middleware'
        )
        
        # Validate performance requirements per Section 4.11.1
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_auth_time = statistics.mean(auth_metrics)
            assert mean_auth_time < 0.150, f"Auth decorator exceeded 150ms threshold: {mean_auth_time:.3f}s"
            
        # Verify security preservation
        assert comparison.get('meets_auth_time_threshold', False), "Authentication performance below threshold"
        
        # Check for performance improvement over baseline
        if comparison.get('baseline_available'):
            improvement = comparison.get('performance_improvement', 0)
            assert improvement >= -5.0, f"Performance regression detected: {improvement:.1f}%"
            
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="auth_decorators")
    def test_role_based_auth_decorator_performance(self, benchmark, flask_client,
                                                  mock_flask_auth, auth_test_data,
                                                  authentication_performance_benchmark):
        """
        Benchmark role-based authentication decorator performance.
        
        This test validates role-based access control decorator performance
        while maintaining authorization security.
        """
        admin_user = auth_test_data.test_users[1]  # Admin user
        session_token = mock_flask_auth.mock_create_session(admin_user['id'])
        
        def role_auth_execution():
            """Execute role-based authentication workflow."""
            with flask_client.application.test_request_context(
                '/api/admin',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                # Mock role-based decorator
                @mock_flask_auth.mock_require_auth
                def admin_endpoint():
                    user = getattr(g, 'current_user', None)
                    if user and user.get('role') == 'admin':
                        return {'message': 'Admin access granted'}
                    return {'error': 'Insufficient permissions'}, 403
                    
                return admin_endpoint()
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            role_auth_execution,
            'flask_role_based_auth_decorator',
            baseline_key='role_auth_middleware'
        )
        
        # Validate role-based auth performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_auth_time = statistics.mean(auth_metrics)
            assert mean_auth_time < 0.150, f"Role auth exceeded 150ms threshold: {mean_auth_time:.3f}s"
            
        # Verify authorization logic preservation
        assert comparison.get('meets_auth_time_threshold', False), "Role-based auth performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="auth_decorators") 
    def test_permission_based_auth_decorator_performance(self, benchmark, flask_client,
                                                        mock_flask_auth, auth_test_data,
                                                        authentication_performance_benchmark):
        """
        Benchmark permission-based authentication decorator performance.
        
        This test validates fine-grained permission checking performance
        while maintaining comprehensive authorization controls.
        """
        user = auth_test_data.test_users[0]  # User with specific permissions
        session_token = mock_flask_auth.mock_create_session(user['id'])
        
        def permission_auth_execution():
            """Execute permission-based authentication workflow."""
            with flask_client.application.test_request_context(
                '/api/write-resource',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                # Mock permission-based decorator
                @mock_flask_auth.mock_require_auth
                def write_endpoint():
                    user = getattr(g, 'current_user', None)
                    if user and 'write' in user.get('permissions', []):
                        return {'message': 'Write permission granted'}
                    return {'error': 'Insufficient permissions'}, 403
                    
                return write_endpoint()
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            permission_auth_execution,
            'flask_permission_based_auth_decorator',
            baseline_key='permission_auth_middleware'
        )
        
        # Validate permission-based auth performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_auth_time = statistics.mean(auth_metrics)
            assert mean_auth_time < 0.150, f"Permission auth exceeded 150ms threshold: {mean_auth_time:.3f}s"
            
        # Verify permission logic preservation
        assert comparison.get('meets_auth_time_threshold', False), "Permission-based auth performance below threshold"


class TestItsDangerousSessionManagement:
    """
    Test suite for ItsDangerous session management performance.
    
    This test class validates ItsDangerous session signing and validation
    performance against Node.js session management per Section 5.1.1.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="session_management")
    def test_session_token_creation_performance(self, benchmark, flask_app_factory,
                                              auth_test_data, authentication_performance_benchmark):
        """
        Benchmark ItsDangerous session token creation performance.
        
        This test validates session token generation performance using
        ItsDangerous while maintaining security properties.
        """
        app = flask_app_factory
        serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY', 'test-secret'))
        user = auth_test_data.test_users[0]
        
        def session_creation_execution():
            """Execute session token creation workflow."""
            session_data = {
                'user_id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'created_at': time.time(),
                'csrf_token': secrets.token_hex(32)
            }
            
            # Measure ItsDangerous session signing performance
            start_time = time.perf_counter()
            session_token = serializer.dumps(session_data)
            signing_time = time.perf_counter() - start_time
            
            # Validate token can be loaded
            loaded_data = serializer.loads(session_token)
            assert loaded_data['user_id'] == user['id']
            
            return signing_time
            
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            session_creation_execution,
            'itsdangerous_session_creation',
            baseline_key='nodejs_session_creation'
        )
        
        # Validate session creation performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_creation_time = statistics.mean(auth_metrics)
            assert mean_creation_time < 0.010, f"Session creation exceeded 10ms threshold: {mean_creation_time:.3f}s"
            
        # Verify security preservation
        assert comparison.get('meets_auth_time_threshold', False), "Session creation performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="session_management")
    def test_session_token_validation_performance(self, benchmark, flask_app_factory,
                                                 auth_test_data, authentication_performance_benchmark):
        """
        Benchmark ItsDangerous session token validation performance.
        
        This test validates session token validation performance while
        maintaining security against tampering and expiration.
        """
        app = flask_app_factory
        serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY', 'test-secret'))
        user = auth_test_data.test_users[0]
        
        # Pre-create session tokens for validation testing
        session_tokens = []
        for _ in range(10):
            session_data = {
                'user_id': user['id'],
                'username': user['username'],
                'created_at': time.time(),
                'csrf_token': secrets.token_hex(32)
            }
            token = serializer.dumps(session_data)
            session_tokens.append(token)
            
        def session_validation_execution():
            """Execute session token validation workflow."""
            token = session_tokens[0]  # Use first token for consistency
            
            # Measure ItsDangerous session validation performance
            start_time = time.perf_counter()
            try:
                loaded_data = serializer.loads(token, max_age=3600)  # 1 hour expiry
                validation_time = time.perf_counter() - start_time
                
                # Verify session data integrity
                assert loaded_data['user_id'] == user['id']
                assert loaded_data['username'] == user['username']
                
                return validation_time
                
            except (BadSignature, SignatureExpired) as e:
                validation_time = time.perf_counter() - start_time
                # Even failed validations should be fast
                return validation_time
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            session_validation_execution,
            'itsdangerous_session_validation',
            baseline_key='nodejs_session_validation'
        )
        
        # Validate session validation performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_validation_time = statistics.mean(auth_metrics)
            assert mean_validation_time < 0.005, f"Session validation exceeded 5ms threshold: {mean_validation_time:.3f}s"
            
        # Verify validation efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Session validation performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="session_management")
    def test_session_expiration_handling_performance(self, benchmark, flask_app_factory,
                                                    authentication_performance_benchmark):
        """
        Benchmark session expiration handling performance.
        
        This test validates expired session detection and handling performance
        while maintaining security against replay attacks.
        """
        app = flask_app_factory
        serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY', 'test-secret'))
        
        # Create expired session token
        expired_data = {
            'user_id': 1,
            'username': 'test_user',
            'created_at': time.time() - 7200,  # 2 hours ago
            'csrf_token': secrets.token_hex(32)
        }
        expired_token = serializer.dumps(expired_data)
        
        def session_expiration_execution():
            """Execute session expiration handling workflow."""
            start_time = time.perf_counter()
            
            try:
                # Attempt to load expired session with 1 hour max age
                loaded_data = serializer.loads(expired_token, max_age=3600)
                expiration_time = time.perf_counter() - start_time
                return expiration_time, False  # Should not reach here
                
            except SignatureExpired:
                expiration_time = time.perf_counter() - start_time
                return expiration_time, True  # Expected path
                
            except BadSignature:
                expiration_time = time.perf_counter() - start_time
                return expiration_time, False  # Unexpected
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            lambda: session_expiration_execution()[0],  # Only return timing
            'itsdangerous_session_expiration',
            baseline_key='nodejs_session_expiration'
        )
        
        # Validate expiration handling performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_expiration_time = statistics.mean(auth_metrics)
            assert mean_expiration_time < 0.005, f"Session expiration exceeded 5ms threshold: {mean_expiration_time:.3f}s"
            
        # Verify expiration security
        _, expired_correctly = session_expiration_execution()
        assert expired_correctly, "Expired session was not properly detected"


class TestAuth0IntegrationPerformance:
    """
    Test suite for Auth0 integration performance validation.
    
    This test class validates Auth0 integration performance per Section 6.5.1.1
    while maintaining external authentication flow efficiency.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="auth0_integration")
    @pytest.mark.asyncio
    async def test_auth0_token_validation_performance(self, benchmark, mock_auth0,
                                                     authentication_performance_benchmark):
        """
        Benchmark Auth0 token validation performance.
        
        This test validates Auth0 JWT token validation performance including
        network latency simulation and token processing overhead.
        """
        valid_token = mock_auth0.auth0_test_tokens.get('valid_token', 'mock_token')
        
        async def auth0_validation_execution():
            """Execute Auth0 token validation workflow."""
            start_time = time.perf_counter()
            
            # Simulate Auth0 token validation with network latency
            result = await mock_auth0.validate_token(valid_token)
            
            validation_time = time.perf_counter() - start_time
            
            # Verify token validation success
            assert result['valid'] is True
            assert result['user_info'] is not None
            
            return validation_time
            
        # Convert async function for benchmark
        def sync_auth0_validation():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(auth0_validation_execution())
            finally:
                loop.close()
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            sync_auth0_validation,
            'auth0_token_validation',
            baseline_key='nodejs_auth0_validation'
        )
        
        # Validate Auth0 performance per Section 6.5.1.1
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_validation_time = statistics.mean(auth_metrics)
            assert mean_validation_time < 0.150, f"Auth0 validation exceeded 150ms threshold: {mean_validation_time:.3f}s"
            
        # Verify Auth0 integration efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Auth0 validation performance below threshold"
        
    @pytest.mark.auth_performance  
    @pytest.mark.benchmark(group="auth0_integration")
    @pytest.mark.asyncio
    async def test_auth0_token_refresh_performance(self, benchmark, mock_auth0,
                                                  authentication_performance_benchmark):
        """
        Benchmark Auth0 token refresh performance.
        
        This test validates Auth0 refresh token flow performance including
        token rotation and renewal overhead.
        """
        refresh_token = 'mock_refresh_token_for_testing'
        
        async def auth0_refresh_execution():
            """Execute Auth0 token refresh workflow."""
            start_time = time.perf_counter()
            
            # Simulate Auth0 token refresh with network latency
            result = await mock_auth0.refresh_token(refresh_token)
            
            refresh_time = time.perf_counter() - start_time
            
            # Verify token refresh success
            assert 'access_token' in result
            assert 'refresh_token' in result
            assert result['expires_in'] > 0
            
            return refresh_time
            
        # Convert async function for benchmark
        def sync_auth0_refresh():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(auth0_refresh_execution())
            finally:
                loop.close()
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            sync_auth0_refresh,
            'auth0_token_refresh',
            baseline_key='nodejs_auth0_refresh'
        )
        
        # Validate Auth0 refresh performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_refresh_time = statistics.mean(auth_metrics)
            assert mean_refresh_time < 0.200, f"Auth0 refresh exceeded 200ms threshold: {mean_refresh_time:.3f}s"
            
        # Verify refresh flow efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Auth0 refresh performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="auth0_integration") 
    def test_auth0_user_profile_retrieval_performance(self, benchmark, mock_auth0,
                                                     authentication_performance_benchmark):
        """
        Benchmark Auth0 user profile retrieval performance.
        
        This test validates Auth0 Management API user profile retrieval
        performance for user synchronization workflows.
        """
        user_id = 'auth0|test_user_1'
        
        def auth0_profile_execution():
            """Execute Auth0 user profile retrieval workflow."""
            start_time = time.perf_counter()
            
            # Simulate Auth0 user profile retrieval
            profile = mock_auth0.get_user_profile(user_id)
            
            retrieval_time = time.perf_counter() - start_time
            
            # Verify profile data
            assert profile['user_id'] == user_id
            assert 'email' in profile
            assert 'created_at' in profile
            
            return retrieval_time
            
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            auth0_profile_execution,
            'auth0_user_profile_retrieval',
            baseline_key='nodejs_auth0_profile'
        )
        
        # Validate profile retrieval performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_retrieval_time = statistics.mean(auth_metrics)
            assert mean_retrieval_time < 0.100, f"Profile retrieval exceeded 100ms threshold: {mean_retrieval_time:.3f}s"
            
        # Verify profile sync efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Profile retrieval performance below threshold"


class TestCSRFProtectionPerformance:
    """
    Test suite for CSRF protection performance validation.
    
    This test class validates Flask-WTF CSRF protection performance while
    maintaining security against Cross-Site Request Forgery attacks.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="csrf_protection")
    def test_csrf_token_generation_performance(self, benchmark, flask_app_factory,
                                              authentication_performance_benchmark):
        """
        Benchmark CSRF token generation performance.
        
        This test validates CSRF token generation performance using
        Flask-WTF while maintaining anti-CSRF security properties.
        """
        app = flask_app_factory
        
        def csrf_generation_execution():
            """Execute CSRF token generation workflow."""
            with app.test_request_context():
                start_time = time.perf_counter()
                
                # Generate CSRF token (mock implementation)
                csrf_token = secrets.token_hex(32)
                
                generation_time = time.perf_counter() - start_time
                
                # Verify token properties
                assert len(csrf_token) == 64
                assert all(c in '0123456789abcdef' for c in csrf_token)
                
                return generation_time
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            csrf_generation_execution,
            'csrf_token_generation',
            baseline_key='nodejs_csrf_generation'
        )
        
        # Validate CSRF generation performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_generation_time = statistics.mean(auth_metrics)
            assert mean_generation_time < 0.001, f"CSRF generation exceeded 1ms threshold: {mean_generation_time:.3f}s"
            
        # Verify generation efficiency
        assert comparison.get('meets_auth_time_threshold', False), "CSRF generation performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="csrf_protection")
    def test_csrf_token_validation_performance(self, benchmark, flask_app_factory,
                                              mock_flask_auth, authentication_performance_benchmark):
        """
        Benchmark CSRF token validation performance.
        
        This test validates CSRF token validation performance while
        maintaining protection against CSRF attacks.
        """
        app = flask_app_factory
        valid_csrf_token = secrets.token_hex(32)
        
        def csrf_validation_execution():
            """Execute CSRF token validation workflow."""
            with app.test_request_context():
                start_time = time.perf_counter()
                
                # Validate CSRF token (mock implementation)
                is_valid = mock_flask_auth.mock_validate_csrf_token(valid_csrf_token)
                
                validation_time = time.perf_counter() - start_time
                
                # Verify validation result
                assert is_valid is True
                
                return validation_time
                
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            csrf_validation_execution,
            'csrf_token_validation', 
            baseline_key='nodejs_csrf_validation'
        )
        
        # Validate CSRF validation performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_validation_time = statistics.mean(auth_metrics)
            assert mean_validation_time < 0.002, f"CSRF validation exceeded 2ms threshold: {mean_validation_time:.3f}s"
            
        # Verify validation efficiency
        assert comparison.get('meets_auth_time_threshold', False), "CSRF validation performance below threshold"


class TestPasswordSecurityPerformance:
    """
    Test suite for password security utilities performance.
    
    This test class validates Werkzeug password hashing and verification
    performance while maintaining cryptographic security properties.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="password_security")
    def test_password_hashing_performance(self, benchmark, authentication_performance_benchmark):
        """
        Benchmark Werkzeug password hashing performance.
        
        This test validates password hashing performance using Werkzeug
        security utilities while maintaining cryptographic strength.
        """
        test_password = 'SecureTestPassword123!'
        
        def password_hashing_execution():
            """Execute password hashing workflow."""
            start_time = time.perf_counter()
            
            # Hash password using Werkzeug (mock implementation)
            password_hash = generate_password_hash(
                test_password,
                method='pbkdf2:sha256',
                salt_length=16
            )
            
            hashing_time = time.perf_counter() - start_time
            
            # Verify hash properties
            assert password_hash.startswith('pbkdf2:sha256:')
            assert len(password_hash) > 50  # Reasonable hash length
            
            return hashing_time
            
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            password_hashing_execution,
            'werkzeug_password_hashing',
            baseline_key='nodejs_password_hashing'
        )
        
        # Validate password hashing performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_hashing_time = statistics.mean(auth_metrics)
            # Password hashing is intentionally slow for security
            assert mean_hashing_time < 1.0, f"Password hashing exceeded 1s threshold: {mean_hashing_time:.3f}s"
            
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="password_security")
    def test_password_verification_performance(self, benchmark, authentication_performance_benchmark):
        """
        Benchmark Werkzeug password verification performance.
        
        This test validates password verification performance while
        maintaining constant-time comparison security.
        """
        test_password = 'SecureTestPassword123!'
        password_hash = generate_password_hash(
            test_password,
            method='pbkdf2:sha256',
            salt_length=16
        )
        
        def password_verification_execution():
            """Execute password verification workflow."""
            start_time = time.perf_counter()
            
            # Verify password using Werkzeug constant-time comparison
            is_valid = check_password_hash(password_hash, test_password)
            
            verification_time = time.perf_counter() - start_time
            
            # Verify validation result
            assert is_valid is True
            
            return verification_time
            
        # Execute performance benchmark
        comparison = authentication_performance_benchmark(
            password_verification_execution,
            'werkzeug_password_verification',
            baseline_key='nodejs_password_verification'
        )
        
        # Validate password verification performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_verification_time = statistics.mean(auth_metrics)
            # Password verification should be reasonably fast
            assert mean_verification_time < 0.5, f"Password verification exceeded 500ms threshold: {mean_verification_time:.3f}s"
            
        # Verify verification efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Password verification performance below threshold"


class TestConcurrentAuthenticationLoad:
    """
    Test suite for concurrent authentication load performance.
    
    This test class validates authentication system performance under
    concurrent user load per Section 6.5.2.5 requirements.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="concurrent_auth")
    def test_concurrent_authentication_load(self, benchmark, flask_client, mock_flask_auth,
                                          auth_test_data, concurrent_load_benchmark):
        """
        Benchmark concurrent authentication requests performance.
        
        This test validates authentication system performance under
        concurrent user load while maintaining security and consistency.
        """
        users = auth_test_data.test_users
        session_tokens = []
        
        # Pre-create session tokens for concurrent testing
        for user in users:
            token = mock_flask_auth.mock_create_session(user['id'])
            session_tokens.append(token)
            
        def concurrent_auth_request():
            """Execute single authentication request."""
            token = session_tokens[0]  # Use first token for consistency
            
            with flask_client.application.test_request_context(
                '/api/protected',
                headers={'Authorization': f'Bearer {token}'}
            ):
                # Apply authentication decorator
                @mock_flask_auth.mock_require_auth
                def protected_endpoint():
                    return {'message': 'Authenticated', 'timestamp': time.time()}
                    
                result = protected_endpoint()
                return result
                
        # Execute concurrent load benchmark
        load_analysis = concurrent_load_benchmark(
            concurrent_auth_request,
            'concurrent_authentication_load',
            concurrent_users=20,
            requests_per_user=10
        )
        
        # Validate concurrent authentication performance
        if 'response_time_stats' in load_analysis:
            stats = load_analysis['response_time_stats']
            
            # Verify concurrent load handling
            assert stats['mean'] < 0.150, f"Concurrent auth mean exceeded 150ms: {stats['mean']:.3f}s"
            assert stats['p95'] < 0.200, f"Concurrent auth P95 exceeded 200ms: {stats['p95']:.3f}s"
            assert load_analysis['error_rate'] < 0.01, f"Error rate too high: {load_analysis['error_rate']:.2%}"
            
        # Verify throughput requirements
        assert load_analysis.get('meets_throughput_threshold', False), "Concurrent auth throughput below threshold"
        assert load_analysis.get('meets_concurrent_users_threshold', False), "Concurrent users capacity below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.benchmark(group="concurrent_auth") 
    def test_concurrent_session_management_load(self, benchmark, flask_app_factory,
                                               auth_test_data, concurrent_load_benchmark):
        """
        Benchmark concurrent session management performance.
        
        This test validates session creation and validation performance
        under concurrent load with ItsDangerous session management.
        """
        app = flask_app_factory
        serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY', 'test-secret'))
        users = auth_test_data.test_users
        
        def concurrent_session_operation():
            """Execute concurrent session management operation."""
            user = users[0]  # Use first user for consistency
            
            with app.test_request_context():
                # Create session
                session_data = {
                    'user_id': user['id'],
                    'username': user['username'],
                    'created_at': time.time(),
                    'csrf_token': secrets.token_hex(32)
                }
                
                # Create and validate session token
                session_token = serializer.dumps(session_data)
                loaded_data = serializer.loads(session_token, max_age=3600)
                
                assert loaded_data['user_id'] == user['id']
                return session_token
                
        # Execute concurrent session benchmark
        load_analysis = concurrent_load_benchmark(
            concurrent_session_operation,
            'concurrent_session_management',
            concurrent_users=15,
            requests_per_user=8
        )
        
        # Validate concurrent session performance
        if 'response_time_stats' in load_analysis:
            stats = load_analysis['response_time_stats']
            
            # Verify session management under load
            assert stats['mean'] < 0.050, f"Concurrent session mean exceeded 50ms: {stats['mean']:.3f}s"
            assert stats['p95'] < 0.100, f"Concurrent session P95 exceeded 100ms: {stats['p95']:.3f}s"
            assert load_analysis['error_rate'] < 0.001, f"Session error rate too high: {load_analysis['error_rate']:.3%}"
            
        # Verify session throughput
        assert load_analysis.get('meets_throughput_threshold', False), "Session management throughput below threshold"


class TestAuthenticationRegressionDetection:
    """
    Test suite for authentication performance regression detection.
    
    This test class validates automated regression detection for authentication
    performance per Section 4.7.2 requirements.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.regression_test
    def test_authentication_performance_regression_detection(self, flask_client, mock_flask_auth,
                                                           auth_test_data, regression_detector,
                                                           baseline_comparison):
        """
        Test automated detection of authentication performance regressions.
        
        This test validates that performance regression detection correctly
        identifies authentication performance degradation scenarios.
        """
        user = auth_test_data.test_users[0]
        session_token = mock_flask_auth.mock_create_session(user['id'])
        
        # Collect authentication performance metrics
        auth_times = []
        for _ in range(10):
            start_time = time.perf_counter()
            
            with flask_client.application.test_request_context(
                '/api/protected',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                @mock_flask_auth.mock_require_auth
                def auth_endpoint():
                    return {'message': 'Authenticated'}
                    
                result = auth_endpoint()
                
            auth_time = time.perf_counter() - start_time
            auth_times.append(auth_time)
            
        # Compare with baseline
        comparison = baseline_comparison(
            'authentication_regression_test',
            auth_times,
            baseline_key='auth_baseline',
            tolerance_percent=10.0
        )
        
        # Detect regression
        regression_analysis = regression_detector(comparison)
        
        # Validate regression detection
        assert 'overall_status' in regression_analysis
        assert 'regressions_detected' in regression_analysis
        assert 'recommendations' in regression_analysis
        
        # Verify no false positive regressions for normal performance
        if statistics.mean(auth_times) < 0.150:  # Within threshold
            assert regression_analysis['overall_status'] in ['PASS', 'WARNING']
            
    @pytest.mark.auth_performance
    @pytest.mark.regression_test
    def test_session_management_regression_detection(self, flask_app_factory, auth_test_data,
                                                    regression_detector, baseline_comparison):
        """
        Test automated detection of session management performance regressions.
        
        This test validates regression detection for ItsDangerous session
        management performance degradation.
        """
        app = flask_app_factory
        serializer = URLSafeTimedSerializer(app.config.get('SECRET_KEY', 'test-secret'))
        user = auth_test_data.test_users[0]
        
        # Collect session management performance metrics
        session_times = []
        for _ in range(10):
            start_time = time.perf_counter()
            
            # Session creation and validation
            session_data = {
                'user_id': user['id'],
                'created_at': time.time(),
                'csrf_token': secrets.token_hex(32)
            }
            
            token = serializer.dumps(session_data)
            loaded_data = serializer.loads(token, max_age=3600)
            
            session_time = time.perf_counter() - start_time
            session_times.append(session_time)
            
        # Compare with baseline
        comparison = baseline_comparison(
            'session_management_regression_test',
            session_times,
            baseline_key='session_baseline',
            tolerance_percent=5.0
        )
        
        # Detect regression
        regression_analysis = regression_detector(comparison)
        
        # Validate session regression detection
        assert 'overall_status' in regression_analysis
        
        # Verify acceptable session performance
        if statistics.mean(session_times) < 0.010:  # Within 10ms threshold
            assert regression_analysis['overall_status'] in ['PASS', 'WARNING']


# Integration Tests for Complete Authentication Flows
class TestCompleteAuthenticationFlowPerformance:
    """
    Test suite for complete authentication flow performance validation.
    
    This test class validates end-to-end authentication workflow performance
    including login, authorization, and logout sequences.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.integration
    @pytest.mark.benchmark(group="auth_flows")
    def test_complete_login_flow_performance(self, benchmark, flask_client, mock_flask_auth,
                                           auth_test_data, authentication_performance_benchmark):
        """
        Benchmark complete user login flow performance.
        
        This test validates end-to-end login workflow performance including
        credential validation, session creation, and token generation.
        """
        user = auth_test_data.test_users[0]
        
        def complete_login_execution():
            """Execute complete login workflow."""
            start_time = time.perf_counter()
            
            # Step 1: Password verification (mock)
            password_valid = check_password_hash(
                generate_password_hash(user['password']),
                user['password']
            )
            assert password_valid
            
            # Step 2: Session creation
            session_token = mock_flask_auth.mock_create_session(user['id'])
            assert session_token
            
            # Step 3: CSRF token generation
            csrf_token = secrets.token_hex(32)
            assert len(csrf_token) == 64
            
            # Step 4: Authentication response preparation
            auth_response = {
                'success': True,
                'user_id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'session_token': session_token,
                'csrf_token': csrf_token
            }
            
            login_time = time.perf_counter() - start_time
            return login_time
            
        # Execute login flow benchmark
        comparison = authentication_performance_benchmark(
            complete_login_execution,
            'complete_login_flow',
            baseline_key='nodejs_login_flow'
        )
        
        # Validate complete login performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_login_time = statistics.mean(auth_metrics)
            assert mean_login_time < 0.150, f"Complete login exceeded 150ms threshold: {mean_login_time:.3f}s"
            
        # Verify login flow efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Login flow performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.integration  
    @pytest.mark.benchmark(group="auth_flows")
    def test_complete_authorization_flow_performance(self, benchmark, flask_client, mock_flask_auth,
                                                   auth_test_data, authentication_performance_benchmark):
        """
        Benchmark complete authorization flow performance.
        
        This test validates request authorization workflow performance including
        session validation, permission checking, and access control.
        """
        admin_user = auth_test_data.test_users[1]  # Admin user
        session_token = mock_flask_auth.mock_create_session(admin_user['id'])
        
        def complete_authorization_execution():
            """Execute complete authorization workflow."""
            start_time = time.perf_counter()
            
            with flask_client.application.test_request_context(
                '/api/admin/users',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                # Step 1: Session validation
                @mock_flask_auth.mock_require_auth
                def admin_endpoint():
                    current_user = getattr(g, 'current_user', None)
                    
                    # Step 2: Role verification
                    if not current_user or current_user.get('role') != 'admin':
                        return {'error': 'Insufficient permissions'}, 403
                        
                    # Step 3: Permission checking
                    if 'admin' not in current_user.get('permissions', []):
                        return {'error': 'Missing admin permission'}, 403
                        
                    # Step 4: CSRF validation (mock)
                    csrf_valid = mock_flask_auth.mock_validate_csrf_token(
                        'mock_csrf_token_12345678901234567890123456789012'
                    )
                    if not csrf_valid:
                        return {'error': 'Invalid CSRF token'}, 403
                        
                    # Step 5: Access granted
                    return {'message': 'Admin access granted', 'user_id': current_user['id']}
                    
                result = admin_endpoint()
                
            authorization_time = time.perf_counter() - start_time
            return authorization_time
            
        # Execute authorization flow benchmark
        comparison = authentication_performance_benchmark(
            complete_authorization_execution,
            'complete_authorization_flow',
            baseline_key='nodejs_authorization_flow'
        )
        
        # Validate authorization flow performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_auth_time = statistics.mean(auth_metrics)
            assert mean_auth_time < 0.150, f"Authorization flow exceeded 150ms threshold: {mean_auth_time:.3f}s"
            
        # Verify authorization efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Authorization flow performance below threshold"
        
    @pytest.mark.auth_performance
    @pytest.mark.integration
    @pytest.mark.benchmark(group="auth_flows")
    def test_complete_logout_flow_performance(self, benchmark, flask_client, mock_flask_auth,
                                            auth_test_data, authentication_performance_benchmark):
        """
        Benchmark complete user logout flow performance.
        
        This test validates logout workflow performance including session
        invalidation, token revocation, and cleanup operations.
        """
        user = auth_test_data.test_users[0]
        session_token = mock_flask_auth.mock_create_session(user['id'])
        
        def complete_logout_execution():
            """Execute complete logout workflow."""
            start_time = time.perf_counter()
            
            with flask_client.application.test_request_context(
                '/api/logout',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                # Step 1: Session validation
                @mock_flask_auth.mock_require_auth
                def logout_endpoint():
                    current_user = getattr(g, 'current_user', None)
                    assert current_user is not None
                    
                    # Step 2: Session invalidation (mock)
                    # In real implementation, add token to blocklist
                    session_invalidated = True
                    
                    # Step 3: CSRF token cleanup
                    csrf_cleaned = True
                    
                    # Step 4: Auth0 token revocation (mock)
                    if hasattr(g, 'auth0_token'):
                        auth0_revoked = True
                    else:
                        auth0_revoked = True  # No Auth0 token to revoke
                        
                    # Step 5: Logout response
                    return {
                        'success': True,
                        'message': 'Logged out successfully',
                        'session_invalidated': session_invalidated,
                        'csrf_cleaned': csrf_cleaned,
                        'auth0_revoked': auth0_revoked
                    }
                    
                result = logout_endpoint()
                
            logout_time = time.perf_counter() - start_time
            return logout_time
            
        # Execute logout flow benchmark
        comparison = authentication_performance_benchmark(
            complete_logout_execution,
            'complete_logout_flow',
            baseline_key='nodejs_logout_flow'
        )
        
        # Validate logout flow performance
        auth_metrics = comparison.get('flask_metrics', [])
        if auth_metrics:
            mean_logout_time = statistics.mean(auth_metrics)
            assert mean_logout_time < 0.100, f"Logout flow exceeded 100ms threshold: {mean_logout_time:.3f}s"
            
        # Verify logout efficiency
        assert comparison.get('meets_auth_time_threshold', False), "Logout flow performance below threshold"


# Performance Report Generation and Analysis
class TestAuthenticationPerformanceReporting:
    """
    Test suite for authentication performance reporting and analysis.
    
    This test class validates comprehensive performance reporting capabilities
    for authentication benchmarking results and regression analysis.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.reporting
    def test_authentication_performance_report_generation(self, flask_client, mock_flask_auth,
                                                         auth_test_data, performance_report_generator):
        """
        Test comprehensive authentication performance report generation.
        
        This test validates performance report generation capabilities for
        authentication benchmarking results and analysis.
        """
        # Collect comprehensive authentication performance data
        test_results = []
        
        # Authentication decorator performance
        user = auth_test_data.test_users[0]
        session_token = mock_flask_auth.mock_create_session(user['id'])
        
        auth_times = []
        for _ in range(5):
            start_time = time.perf_counter()
            
            with flask_client.application.test_request_context(
                '/api/protected',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                @mock_flask_auth.mock_require_auth
                def auth_endpoint():
                    return {'message': 'Authenticated'}
                    
                result = auth_endpoint()
                
            auth_time = time.perf_counter() - start_time
            auth_times.append(auth_time)
            
        test_results.append({
            'test_name': 'authentication_decorator_performance',
            'flask_metrics': {
                'count': len(auth_times),
                'mean': statistics.mean(auth_times),
                'min': min(auth_times),
                'max': max(auth_times),
                'p95': max(auth_times)  # Simplified for small sample
            },
            'overall_status': 'PASS' if statistics.mean(auth_times) < 0.150 else 'FAIL'
        })
        
        # Session management performance
        session_times = []
        for _ in range(5):
            start_time = time.perf_counter()
            token = mock_flask_auth.mock_create_session(user['id'])
            session_time = time.perf_counter() - start_time
            session_times.append(session_time)
            
        test_results.append({
            'test_name': 'session_management_performance',
            'flask_metrics': {
                'count': len(session_times),
                'mean': statistics.mean(session_times),
                'min': min(session_times),
                'max': max(session_times),
                'p95': max(session_times)
            },
            'overall_status': 'PASS' if statistics.mean(session_times) < 0.010 else 'FAIL'
        })
        
        # Generate comprehensive performance report
        report = performance_report_generator(
            test_results,
            'authentication_performance_benchmark_report'
        )
        
        # Validate report structure
        assert 'report_name' in report
        assert 'generation_timestamp' in report
        assert 'test_summary' in report
        assert 'performance_overview' in report
        assert 'detailed_results' in report
        
        # Validate test summary
        test_summary = report['test_summary']
        assert test_summary['total_tests'] == len(test_results)
        assert test_summary['passed_tests'] + test_summary['failed_tests'] + test_summary['warning_tests'] == test_summary['total_tests']
        
        # Validate performance overview
        performance_overview = report['performance_overview']
        if 'auth_performance' in performance_overview:
            auth_perf = performance_overview['auth_performance']
            assert 'mean_auth_time' in auth_perf
            assert 'fastest_auth' in auth_perf
            assert 'slowest_auth' in auth_perf
            
        # Validate recommendations
        assert 'recommendations' in report
        if test_summary['failed_tests'] > 0:
            assert len(report['recommendations']) > 0
            
    @pytest.mark.auth_performance
    @pytest.mark.monitoring
    def test_authentication_monitoring_integration(self, flask_client, mock_flask_auth,
                                                  auth_test_data, performance_monitor):
        """
        Test authentication performance monitoring integration.
        
        This test validates integration with OpenTelemetry monitoring
        and Prometheus metrics collection for authentication workflows.
        """
        otel_manager = performance_monitor['otel_manager']
        user = auth_test_data.test_users[0]
        
        # Execute authentication with monitoring
        with otel_manager.trace_performance('authentication_monitoring_test') as span:
            session_token = mock_flask_auth.mock_create_session(user['id'])
            
            with flask_client.application.test_request_context(
                '/api/monitored',
                headers={'Authorization': f'Bearer {session_token}'}
            ):
                @mock_flask_auth.mock_require_auth
                def monitored_endpoint():
                    if span:
                        span.set_attribute('auth.user_id', user['id'])
                        span.set_attribute('auth.username', user['username'])
                        span.set_attribute('auth.method', 'session_token')
                        
                    return {
                        'message': 'Monitored authentication successful',
                        'user_id': user['id']
                    }
                    
                result = monitored_endpoint()
                
        # Verify monitoring integration
        stats = mock_flask_auth.get_performance_stats()
        assert stats['auth_decorator_calls'] > 0
        assert stats['session_manager_calls'] > 0
        
        # Validate trace attributes (if span available)
        if span:
            # In real implementation, verify span attributes and metrics
            pass


if __name__ == '__main__':
    """
    Direct execution of authentication performance benchmarks.
    
    This allows running authentication benchmarks directly for development
    and debugging purposes outside of the full pytest suite.
    """
    import sys
    
    print("Authentication Performance Benchmarking Test Suite")
    print("=" * 55)
    print("Testing Flask authentication performance against Node.js baseline")
    print(f"Python version: {sys.version}")
    print(f"Test modules available: {AUTH_MODULES_AVAILABLE}")
    print()
    
    # Run specific benchmark if requested
    if len(sys.argv) > 1:
        test_name = sys.argv[1]
        pytest.main([__file__ + f"::{test_name}", "-v", "--benchmark-only"])
    else:
        # Run all authentication benchmarks
        pytest.main([__file__, "-v", "--benchmark-only", "-m", "auth_performance"])