"""
pytest configuration file providing Flask application test fixtures, database setup/teardown,
authentication mocks, and shared testing utilities for the Flask 3.1.1 migration project.

This module establishes the testing foundation for pytest-flask integration with comprehensive
fixture management for Flask app factory testing, database isolation, and authentication
simulation as specified in Section 4.7.1 of the technical specification.

Key Features:
- pytest-flask 1.3.0 plugin configuration for Flask-specific testing capabilities
- Flask application factory integration for test client initialization  
- Test database configuration with Flask-SQLAlchemy testing patterns
- Authentication testing support with Auth0 and Flask-Login mocking
- Test environment isolation with proper request context management

Dependencies:
- pytest-flask 1.3.0: Flask application testing fixtures and utilities
- Flask 3.1.1: Application factory pattern and request context management
- Flask-SQLAlchemy 3.1.1: Database ORM and testing patterns
- Flask-Login: User session management and authentication simulation
"""

import os
import tempfile
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import json
import uuid
from typing import Dict, Any, Generator, Optional

# Flask and extension imports
from flask import Flask, g, session, request, current_app
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, logout_user, current_user

# Import application components
try:
    from app import create_app
    from config import TestingConfig
    from src.models import db, User  # Assuming User model exists
    from src.auth.models import AuthSession
except ImportError:
    # Handle case where modules don't exist yet during development
    create_app = None
    TestingConfig = None
    db = None
    User = None
    AuthSession = None


class TestingConfiguration:
    """
    Enhanced testing configuration class providing comprehensive test environment setup
    with Flask-SQLAlchemy testing patterns and security considerations.
    
    This configuration ensures complete isolation between test runs and provides
    consistent database and authentication state for all test scenarios.
    """
    
    # Flask core configuration
    TESTING = True
    SECRET_KEY = 'test-secret-key-for-pytest-only'
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing
    
    # Database configuration for testing isolation
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'  # In-memory database for speed
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'echo': False  # Set to True for SQL debugging during tests
    }
    
    # Authentication testing configuration
    AUTH0_DOMAIN = 'test-domain.auth0.com'
    AUTH0_CLIENT_ID = 'test-client-id'
    AUTH0_CLIENT_SECRET = 'test-client-secret'
    AUTH0_AUDIENCE = 'test-audience'
    
    # Session management for testing
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # Security testing configuration
    BCRYPT_LOG_ROUNDS = 4  # Faster password hashing for tests
    JWT_SECRET_KEY = 'test-jwt-secret'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    
    # External service mocking configuration
    EXTERNAL_API_BASE_URL = 'http://localhost:8080/mock'
    DISABLE_EXTERNAL_CALLS = True
    
    # Logging configuration for tests
    LOG_LEVEL = 'WARNING'  # Reduce log noise during testing
    

class MockUser(UserMixin):
    """
    Mock user class for authentication testing scenarios, implementing Flask-Login
    UserMixin interface for compatibility with Flask authentication decorators.
    
    This class provides comprehensive user simulation for testing authentication
    flows, authorization scenarios, and session management functionality.
    """
    
    def __init__(self, id: str = None, username: str = None, email: str = None, 
                 roles: list = None, is_active: bool = True, **kwargs):
        self.id = id or str(uuid.uuid4())
        self.username = username or f'testuser_{self.id[:8]}'
        self.email = email or f'{self.username}@test.example.com'
        self.roles = roles or ['user']
        self._is_active = is_active
        self.created_at = datetime.utcnow()
        self.last_login = datetime.utcnow()
        
        # Additional user attributes for comprehensive testing
        self.first_name = kwargs.get('first_name', 'Test')
        self.last_name = kwargs.get('last_name', 'User')
        self.is_verified = kwargs.get('is_verified', True)
        self.profile_data = kwargs.get('profile_data', {})
        
    def is_active(self):
        """Check if user account is active"""
        return self._is_active
        
    def is_authenticated(self):
        """Check if user is authenticated"""
        return True
        
    def is_anonymous(self):
        """Check if user is anonymous"""
        return False
        
    def get_id(self):
        """Get user identifier for Flask-Login"""
        return str(self.id)
        
    def has_role(self, role: str) -> bool:
        """Check if user has specific role"""
        return role in self.roles
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'roles': self.roles,
            'is_active': self._is_active,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat()
        }


class MockAuth0Client:
    """
    Comprehensive Auth0 client mock for testing authentication workflows without
    external API dependencies. Provides realistic Auth0 API response simulation
    for user management, token validation, and authentication flow testing.
    
    This mock ensures consistent authentication testing while maintaining
    compatibility with the actual Auth0 Python SDK interface.
    """
    
    def __init__(self):
        self.users = {}
        self.tokens = {}
        self.management_tokens = {}
        
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Mock user authentication returning realistic Auth0 token response
        """
        user_id = f'auth0|{uuid.uuid4()}'
        access_token = f'test_access_token_{uuid.uuid4()}'
        refresh_token = f'test_refresh_token_{uuid.uuid4()}'
        
        # Store token for validation
        self.tokens[access_token] = {
            'user_id': user_id,
            'username': username,
            'expires_at': datetime.utcnow() + timedelta(hours=1),
            'scopes': ['read:profile', 'update:profile']
        }
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'id_token': f'test_id_token_{uuid.uuid4()}',
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': 'read:profile update:profile',
            'user_info': {
                'sub': user_id,
                'username': username,
                'email': f'{username}@test.example.com',
                'email_verified': True,
                'name': f'Test {username.capitalize()}',
                'picture': f'https://test.auth0.com/avatar/{user_id}',
                'updated_at': datetime.utcnow().isoformat()
            }
        }
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Mock token validation with realistic Auth0 response format
        """
        token_data = self.tokens.get(token)
        if not token_data:
            raise ValueError('Invalid token')
            
        if token_data['expires_at'] < datetime.utcnow():
            raise ValueError('Token expired')
            
        return {
            'sub': token_data['user_id'],
            'username': token_data['username'],
            'exp': int(token_data['expires_at'].timestamp()),
            'iat': int((datetime.utcnow() - timedelta(minutes=30)).timestamp()),
            'aud': 'test-audience',
            'iss': 'https://test-domain.auth0.com/',
            'scope': ' '.join(token_data['scopes'])
        }
    
    def get_user_info(self, token: str) -> Dict[str, Any]:
        """
        Mock user info retrieval from Auth0 userinfo endpoint
        """
        token_data = self.validate_token(token)
        return {
            'sub': token_data['sub'],
            'username': token_data['username'], 
            'email': f"{token_data['username']}@test.example.com",
            'email_verified': True,
            'name': f"Test {token_data['username'].capitalize()}",
            'picture': f"https://test.auth0.com/avatar/{token_data['sub']}",
            'updated_at': datetime.utcnow().isoformat(),
            'user_metadata': {},
            'app_metadata': {'roles': ['user']}
        }
    
    def revoke_token(self, token: str) -> bool:
        """
        Mock token revocation for logout testing
        """
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False


# ================================
# Core pytest-flask Configuration
# ================================

@pytest.fixture(scope='session')
def app() -> Generator[Flask, None, None]:
    """
    Flask application factory fixture providing isolated Flask app instance
    for testing with comprehensive configuration and extension initialization.
    
    This fixture implements the Flask application factory pattern as specified
    in Section 5.1.1, providing environment-specific configuration loading
    and blueprint registration orchestration for testing scenarios.
    
    Yields:
        Flask: Configured Flask application instance with testing extensions
    """
    if create_app is None:
        # Create minimal Flask app if imports failed
        app = Flask(__name__)
        app.config.from_object(TestingConfiguration)
    else:
        # Use actual application factory with testing configuration
        app = create_app('testing')
        
    # Ensure testing configuration is applied
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-key-for-pytest-only',
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False
    })
    
    # Create application context for testing
    with app.app_context():
        # Initialize database tables if SQLAlchemy is available
        if db is not None:
            db.create_all()
            
        yield app
        
        # Cleanup after tests
        if db is not None:
            db.session.remove()
            db.drop_all()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """
    Flask test client fixture providing HTTP request simulation capabilities
    for API endpoint testing and integration testing scenarios.
    
    This fixture enables comprehensive testing of Flask blueprints, route
    handlers, and authentication workflows as specified in Section 4.7.1.
    
    Args:
        app: Flask application instance from app fixture
        
    Returns:
        FlaskClient: Configured test client for HTTP request simulation
    """
    return app.test_client()


@pytest.fixture
def runner(app: Flask):
    """
    Flask CLI runner fixture for testing Flask Click commands and
    application management commands during testing scenarios.
    
    Args:
        app: Flask application instance from app fixture
        
    Returns:
        FlaskCliRunner: CLI runner for command testing
    """
    return app.test_cli_runner()


# ================================
# Database Testing Fixtures
# ================================

@pytest.fixture
def db_session(app: Flask):
    """
    Database session fixture providing isolated database transactions
    with automatic rollback for test isolation and data consistency.
    
    This fixture implements Flask-SQLAlchemy testing patterns as specified
    in Section 6.2, ensuring complete database isolation between tests
    and preventing test data contamination.
    
    Args:
        app: Flask application instance from app fixture
        
    Yields:
        SQLAlchemy session: Database session with automatic rollback
    """
    if db is None:
        yield None
        return
        
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create a nested transaction for test isolation
        connection = db.engine.connect()
        transaction = connection.begin()
        
        # Configure session to use the transaction
        session_options = dict(bind=connection, binds={})
        session = db.create_scoped_session(options=session_options)
        
        # Replace the default session
        db.session = session
        
        try:
            yield session
        finally:
            # Rollback transaction and cleanup
            session.remove()
            transaction.rollback()
            connection.close()


@pytest.fixture
def sample_users(db_session):
    """
    Sample user data fixture providing realistic test users for authentication
    and authorization testing scenarios with various roles and permissions.
    
    Args:
        db_session: Database session from db_session fixture
        
    Returns:
        Dict[str, MockUser]: Dictionary of sample users by role
    """
    users = {
        'admin': MockUser(
            username='admin_user',
            email='admin@test.example.com',
            roles=['admin', 'user'],
            first_name='Admin',
            last_name='User'
        ),
        'user': MockUser(
            username='regular_user', 
            email='user@test.example.com',
            roles=['user'],
            first_name='Regular',
            last_name='User'
        ),
        'inactive': MockUser(
            username='inactive_user',
            email='inactive@test.example.com',
            roles=['user'],
            is_active=False,
            first_name='Inactive',
            last_name='User'
        ),
        'moderator': MockUser(
            username='moderator_user',
            email='moderator@test.example.com',
            roles=['moderator', 'user'],
            first_name='Moderator',
            last_name='User'
        )
    }
    
    # If User model is available, create actual database records
    if User is not None and db_session is not None:
        for role, mock_user in users.items():
            user = User(
                id=mock_user.id,
                username=mock_user.username,
                email=mock_user.email,
                is_active=mock_user._is_active,
                created_at=mock_user.created_at
            )
            db_session.add(user)
        
        db_session.commit()
    
    return users


# ================================
# Authentication Testing Fixtures
# ================================

@pytest.fixture
def mock_auth0_client():
    """
    Auth0 client mock fixture providing comprehensive authentication service
    simulation for testing Auth0 integration without external dependencies.
    
    This fixture enables testing of authentication flows, token validation,
    and user management operations as specified in Section 6.4.1.
    
    Returns:
        MockAuth0Client: Configured Auth0 client mock
    """
    return MockAuth0Client()


@pytest.fixture
def authenticated_user(app: Flask, sample_users: Dict[str, MockUser]):
    """
    Authenticated user fixture providing pre-authenticated user session
    for testing protected endpoints and authorization scenarios.
    
    This fixture simulates Flask-Login user authentication and session
    management for comprehensive authentication testing.
    
    Args:
        app: Flask application instance
        sample_users: Sample user data from sample_users fixture
        
    Returns:
        MockUser: Authenticated user instance
    """
    user = sample_users['user']
    
    with app.test_request_context():
        # Simulate Flask-Login user authentication
        with patch('flask_login.current_user', user):
            # Set up session data
            session['user_id'] = user.id
            session['username'] = user.username
            session['authenticated'] = True
            session['auth_time'] = datetime.utcnow().isoformat()
            
            yield user


@pytest.fixture
def admin_user(app: Flask, sample_users: Dict[str, MockUser]):
    """
    Admin user fixture providing pre-authenticated admin session for
    testing administrative endpoints and elevated privilege scenarios.
    
    Args:
        app: Flask application instance
        sample_users: Sample user data from sample_users fixture
        
    Returns:
        MockUser: Authenticated admin user instance
    """
    admin = sample_users['admin']
    
    with app.test_request_context():
        with patch('flask_login.current_user', admin):
            session['user_id'] = admin.id
            session['username'] = admin.username
            session['authenticated'] = True
            session['auth_time'] = datetime.utcnow().isoformat()
            session['roles'] = admin.roles
            
            yield admin


@pytest.fixture
def auth_headers(authenticated_user: MockUser, mock_auth0_client: MockAuth0Client):
    """
    Authentication headers fixture providing realistic HTTP headers
    for API endpoint testing with proper token format and validation.
    
    Args:
        authenticated_user: Authenticated user from authenticated_user fixture
        mock_auth0_client: Auth0 client mock from mock_auth0_client fixture
        
    Returns:
        Dict[str, str]: HTTP headers with authentication token
    """
    # Generate mock authentication token
    auth_response = mock_auth0_client.authenticate(
        authenticated_user.username, 
        'test_password'
    )
    
    return {
        'Authorization': f"Bearer {auth_response['access_token']}",
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


# ================================
# Request Context and Mocking Fixtures
# ================================

@pytest.fixture
def request_context(app: Flask):
    """
    Flask request context fixture providing proper request context management
    for testing Flask components that require request context availability.
    
    This fixture ensures proper Flask request context initialization and
    cleanup for testing blueprints, decorators, and context-dependent code.
    
    Args:
        app: Flask application instance
        
    Yields:
        Flask request context
    """
    with app.test_request_context() as ctx:
        # Initialize request context variables
        g.request_id = str(uuid.uuid4())
        g.request_start_time = datetime.utcnow()
        
        yield ctx


@pytest.fixture
def mock_external_services():
    """
    External services mock fixture providing comprehensive mocking of
    external API dependencies and third-party service integrations.
    
    This fixture ensures test isolation by preventing external API calls
    during testing while providing realistic response simulation.
    
    Returns:
        Dict[str, Mock]: Dictionary of mocked external services
    """
    mocks = {}
    
    # Mock Auth0 Management API
    auth0_mock = Mock()
    auth0_mock.users.get.return_value = {
        'user_id': 'test_user_id',
        'email': 'test@example.com',
        'username': 'testuser',
        'email_verified': True
    }
    mocks['auth0_management'] = auth0_mock
    
    # Mock external API endpoints
    api_mock = Mock()
    api_mock.get.return_value = Mock(
        status_code=200,
        json=lambda: {'status': 'success', 'data': {}}
    )
    mocks['external_api'] = api_mock
    
    # Mock email service
    email_mock = Mock()
    email_mock.send.return_value = True
    mocks['email_service'] = email_mock
    
    return mocks


@pytest.fixture
def mock_database_operations(db_session):
    """
    Database operations mock fixture for testing database-dependent code
    without requiring actual database transactions or complex setup.
    
    Args:
        db_session: Database session from db_session fixture
        
    Returns:
        Mock: Database operations mock with realistic behavior
    """
    db_mock = Mock()
    
    # Mock common database operations
    db_mock.query.return_value.filter.return_value.first.return_value = None
    db_mock.query.return_value.filter.return_value.all.return_value = []
    db_mock.add.return_value = None
    db_mock.commit.return_value = None
    db_mock.rollback.return_value = None
    
    return db_mock


# ================================
# Performance and Monitoring Fixtures
# ================================

@pytest.fixture
def performance_monitor():
    """
    Performance monitoring fixture for testing application performance
    and ensuring SLA compliance during testing scenarios.
    
    This fixture provides performance metric collection and validation
    capabilities for comprehensive testing as specified in Section 4.7.1.
    
    Returns:
        Dict[str, Any]: Performance monitoring utilities
    """
    import time
    
    monitor = {
        'start_time': None,
        'end_time': None,
        'duration': None,
        'metrics': {}
    }
    
    def start_monitoring():
        monitor['start_time'] = time.time()
        
    def stop_monitoring():
        monitor['end_time'] = time.time()
        monitor['duration'] = monitor['end_time'] - monitor['start_time']
        
    def get_duration():
        return monitor.get('duration', 0)
        
    def assert_performance_threshold(max_duration: float):
        """Assert that operation completed within performance threshold"""
        actual_duration = get_duration()
        assert actual_duration <= max_duration, \
            f"Performance threshold exceeded: {actual_duration}s > {max_duration}s"
    
    monitor['start'] = start_monitoring
    monitor['stop'] = stop_monitoring
    monitor['get_duration'] = get_duration
    monitor['assert_threshold'] = assert_performance_threshold
    
    return monitor


# ================================
# Utility Fixtures and Helpers
# ================================

@pytest.fixture
def json_response_validator():
    """
    JSON response validation fixture providing comprehensive API response
    validation utilities for testing REST API endpoints and data schemas.
    
    Returns:
        Callable: JSON response validation function
    """
    def validate_response(response, expected_status: int = 200, 
                         required_fields: list = None, 
                         schema: dict = None):
        """
        Validate Flask response format and content
        
        Args:
            response: Flask test client response
            expected_status: Expected HTTP status code
            required_fields: List of required JSON fields
            schema: JSON schema for validation
        """
        assert response.status_code == expected_status, \
            f"Expected status {expected_status}, got {response.status_code}"
            
        if response.content_type and 'application/json' in response.content_type:
            json_data = response.get_json()
            assert json_data is not None, "Response should contain valid JSON"
            
            if required_fields:
                for field in required_fields:
                    assert field in json_data, f"Required field '{field}' missing from response"
                    
            if schema:
                # Basic schema validation (extend with jsonschema for complex schemas)
                for key, expected_type in schema.items():
                    if key in json_data:
                        assert isinstance(json_data[key], expected_type), \
                            f"Field '{key}' should be of type {expected_type.__name__}"
        
        return response.get_json() if response.content_type and 'application/json' in response.content_type else None
    
    return validate_response


@pytest.fixture
def test_data_factory():
    """
    Test data factory fixture providing utilities for generating
    realistic test data for various testing scenarios and edge cases.
    
    Returns:
        Dict[str, Callable]: Test data generation functions
    """
    def create_user_data(**overrides):
        """Create realistic user data for testing"""
        defaults = {
            'username': f'testuser_{uuid.uuid4().hex[:8]}',
            'email': f'test_{uuid.uuid4().hex[:8]}@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'is_active': True,
            'created_at': datetime.utcnow().isoformat()
        }
        defaults.update(overrides)
        return defaults
    
    def create_api_request_data(**overrides):
        """Create realistic API request data for testing"""
        defaults = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': str(uuid.uuid4()),
            'source': 'test_client'
        }
        defaults.update(overrides)
        return defaults
    
    def create_error_response_data(error_type: str = 'ValidationError', **overrides):
        """Create realistic error response data for testing"""
        defaults = {
            'error': error_type,
            'message': 'Test error message',
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': str(uuid.uuid4())
        }
        defaults.update(overrides)
        return defaults
    
    return {
        'user': create_user_data,
        'api_request': create_api_request_data,
        'error_response': create_error_response_data
    }


# ================================
# Environment and Configuration Fixtures
# ================================

@pytest.fixture(autouse=True)
def setup_test_environment(monkeypatch):
    """
    Test environment setup fixture that automatically configures the
    testing environment with proper isolation and security settings.
    
    This fixture runs automatically for all tests to ensure consistent
    environment configuration and prevent test interference.
    
    Args:
        monkeypatch: pytest monkeypatch fixture for environment modification
    """
    # Set testing environment variables
    test_env_vars = {
        'FLASK_ENV': 'testing',
        'TESTING': 'True',
        'SECRET_KEY': 'test-secret-key-for-pytest-only',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'WTF_CSRF_ENABLED': 'False',
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'test-client-id',
        'AUTH0_CLIENT_SECRET': 'test-client-secret',
        'DISABLE_EXTERNAL_CALLS': 'True'
    }
    
    for key, value in test_env_vars.items():
        monkeypatch.setenv(key, value)
    
    # Mock external service calls to prevent network calls during testing
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post, \
         patch('requests.put') as mock_put, \
         patch('requests.delete') as mock_delete:
        
        # Configure default mock responses
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'status': 'success', 'data': {}}
        
        mock_get.return_value = mock_response
        mock_post.return_value = mock_response
        mock_put.return_value = mock_response  
        mock_delete.return_value = mock_response
        
        yield


@pytest.fixture
def temp_directory():
    """
    Temporary directory fixture for testing file operations and
    temporary file storage during testing scenarios.
    
    Yields:
        str: Path to temporary directory
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


# ================================
# Pytest Configuration and Hooks
# ================================

def pytest_configure(config):
    """
    pytest configuration hook for setting up testing environment
    and registering custom markers for test categorization.
    """
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests (deselect with '-m \"not unit\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (deselect with '-m \"not integration\"')"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests (deselect with '-m \"not performance\"')"
    )
    config.addinivalue_line(
        "markers", "auth: marks tests as authentication tests (deselect with '-m \"not auth\"')"
    )
    config.addinivalue_line(
        "markers", "database: marks tests as database tests (deselect with '-m \"not database\"')"
    )
    config.addinivalue_line(
        "markers", "api: marks tests as API tests (deselect with '-m \"not api\"')"
    )


def pytest_sessionstart(session):
    """
    pytest session start hook for global test session initialization
    and environment validation.
    """
    print("\n" + "="*80)
    print("FLASK APPLICATION TESTING SESSION STARTED")
    print("="*80)
    print(f"Testing Flask 3.1.1 migration with Python {os.sys.version}")
    print(f"pytest-flask plugin: Enabled")
    print(f"Database: SQLite in-memory for testing isolation")
    print(f"Authentication: Auth0 mocking enabled")
    print("="*80)


def pytest_sessionfinish(session, exitstatus):
    """
    pytest session finish hook for cleanup and final reporting.
    """
    print("\n" + "="*80)
    print("FLASK APPLICATION TESTING SESSION COMPLETED")
    print(f"Exit status: {exitstatus}")
    print("="*80)


# ================================
# Parametrized Test Data
# ================================

# Common test data for parametrized tests
TEST_USER_SCENARIOS = [
    ('valid_user', {'username': 'testuser', 'email': 'test@example.com'}),
    ('admin_user', {'username': 'admin', 'email': 'admin@example.com', 'roles': ['admin']}),
    ('inactive_user', {'username': 'inactive', 'email': 'inactive@example.com', 'is_active': False}),
]

API_ENDPOINT_SCENARIOS = [
    ('GET', '/api/users', 200),
    ('POST', '/api/users', 201),
    ('PUT', '/api/users/1', 200),
    ('DELETE', '/api/users/1', 204),
]

AUTHENTICATION_SCENARIOS = [
    ('valid_credentials', {'username': 'test', 'password': 'password'}, True),
    ('invalid_password', {'username': 'test', 'password': 'wrong'}, False),
    ('invalid_username', {'username': 'invalid', 'password': 'password'}, False),
    ('empty_credentials', {'username': '', 'password': ''}, False),
]

# Export test scenarios for use in other test modules
__all__ = [
    'TEST_USER_SCENARIOS',
    'API_ENDPOINT_SCENARIOS', 
    'AUTHENTICATION_SCENARIOS',
    'TestingConfiguration',
    'MockUser',
    'MockAuth0Client'
]