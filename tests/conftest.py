"""
Pytest Configuration and Fixtures for Flask Application Testing

This module provides comprehensive pytest configuration for Flask 3.1.1 application testing,
implementing pytest 8.3.3 with Flask testing utilities per Section 3.6.3 of the technical
specification. Provides Flask application fixtures, database session management, authentication
testing, and Factory Boy integration for realistic test data generation.

Key Features:
- Flask application factory fixtures with TestingConfig for isolated test execution
- SQLAlchemy test database sessions with automatic rollback capabilities ensuring test isolation
- Comprehensive pytest fixtures for authentication testing with Auth0 mock integration
- Factory Boy integration with SQLAlchemy model fixtures for realistic test data generation
- pytest-flask plugin integration with Flask test client initialization and application context management
- Performance benchmarking fixtures with pytest-benchmark for SLA validation
- Database testing setup with dedicated test database configuration per Section 4.7.3.1

Testing Architecture:
The conftest.py file implements a three-tier testing architecture:
- Application Layer: Flask app factory fixtures with environment-specific test configuration
- Service Layer: Authentication, session management, and business logic testing fixtures
- Data Layer: Database session management, model factories, and data validation fixtures

Author: Flask Migration System
Version: 1.0.0
Compatibility: Pytest 8.3.3, Flask 3.1.1, Flask-SQLAlchemy 3.1.1, Factory Boy 3.3.1
"""

import os
import sys
import pytest
import tempfile
import shutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Generator, Union
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Core Flask and testing imports
from flask import Flask, current_app
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy

# Application imports
from app import create_app, FlaskApplicationError
from config import TestingConfig, get_config
from models.user import User, UserSession, UserUtils, db

# Testing framework imports
import factory
from factory.alchemy import SQLAlchemyModelFactory
from factory import fuzzy
import factory.fuzzy


# =============================================================================
# PYTEST CONFIGURATION AND MARKERS
# =============================================================================

def pytest_configure(config):
    """
    Configure pytest with custom markers and test environment settings.
    
    Implements pytest configuration per Section 4.7.3.1 with custom markers
    for test categorization including unit, integration, and end-to-end
    test classifications.
    """
    # Register custom markers for test categorization
    config.addinivalue_line(
        "markers", 
        "unit: Unit tests for individual components and functions"
    )
    config.addinivalue_line(
        "markers", 
        "integration: Integration tests for API endpoints and services"
    )
    config.addinivalue_line(
        "markers", 
        "e2e: End-to-end tests for complete user workflows"
    )
    config.addinivalue_line(
        "markers", 
        "performance: Performance and benchmark tests"
    )
    config.addinivalue_line(
        "markers", 
        "auth: Authentication and authorization tests"
    )
    config.addinivalue_line(
        "markers", 
        "database: Database operation and migration tests"
    )
    config.addinivalue_line(
        "markers", 
        "slow: Slow tests that should be run sparingly"
    )
    config.addinivalue_line(
        "markers", 
        "external: Tests requiring external services (marked for skipping in CI)"
    )


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to apply automatic markers based on test location.
    
    Automatically categorizes tests based on file location and naming patterns
    to ensure proper test organization and execution control.
    """
    for item in items:
        # Add markers based on file location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)
        
        # Add markers based on test function name patterns
        if "test_auth" in item.name or "auth" in str(item.fspath):
            item.add_marker(pytest.mark.auth)
        elif "test_db" in item.name or "database" in str(item.fspath):
            item.add_marker(pytest.mark.database)
        elif "test_performance" in item.name or "benchmark" in item.name:
            item.add_marker(pytest.mark.performance)
        
        # Mark slow tests
        if "slow" in item.name or any(keyword in item.name for keyword in ["stress", "load", "large"]):
            item.add_marker(pytest.mark.slow)


# =============================================================================
# FLASK APPLICATION FIXTURES
# =============================================================================

@pytest.fixture(scope='session')
def test_config():
    """
    Provide testing configuration with database URL override for test isolation.
    
    Creates a dedicated test database configuration ensuring complete isolation
    from development and production databases per Section 4.7.3.1 database
    testing setup requirements.
    
    Returns:
        TestingConfig: Flask testing configuration class
    """
    # Create temporary test database
    test_db_path = tempfile.mktemp(suffix='.db')
    test_database_url = f'sqlite:///{test_db_path}'
    
    # Override database URL for testing
    original_test_database_url = os.environ.get('TEST_DATABASE_URL')
    os.environ['TEST_DATABASE_URL'] = test_database_url
    
    # Create custom testing configuration
    class CustomTestingConfig(TestingConfig):
        SQLALCHEMY_DATABASE_URI = test_database_url
        WTF_CSRF_ENABLED = False
        LOGIN_DISABLED = True
        TESTING = True
        DEBUG = False
        
        # Test-specific settings
        SECRET_KEY = 'test-secret-key-for-testing-only'
        FIELD_ENCRYPTION_KEY = b'test-encryption-key-32-bytes-long!'
        
        # Disable external services in tests
        AUTH0_DOMAIN = None
        AUTH0_CLIENT_ID = None
        AUTH0_CLIENT_SECRET = None
        
        # Fast test database settings
        SQLALCHEMY_POOL_SIZE = 1
        SQLALCHEMY_MAX_OVERFLOW = 0
        SQLALCHEMY_POOL_TIMEOUT = 5
        
        # Test logging configuration
        LOG_LEVEL = 'WARNING'
    
    yield CustomTestingConfig
    
    # Cleanup: restore original environment and remove test database
    if original_test_database_url:
        os.environ['TEST_DATABASE_URL'] = original_test_database_url
    elif 'TEST_DATABASE_URL' in os.environ:
        del os.environ['TEST_DATABASE_URL']
    
    # Remove test database file if it exists
    try:
        if os.path.exists(test_db_path):
            os.unlink(test_db_path)
    except OSError:
        pass


@pytest.fixture(scope='session')
def app(test_config):
    """
    Create Flask application instance with testing configuration.
    
    Implements Flask application factory fixtures with TestingConfig for
    isolated test execution per Section 0.2.1 testing requirements.
    This fixture provides the core Flask application instance used
    throughout the test suite.
    
    Args:
        test_config: Testing configuration fixture
        
    Returns:
        Flask: Configured Flask application instance for testing
        
    Yields:
        Flask application with testing configuration
    """
    try:
        # Create Flask application using factory pattern with testing config
        app = create_app(config_name='testing')
        
        # Override configuration with test-specific settings
        app.config.from_object(test_config)
        
        # Ensure we're in testing mode
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['LOGIN_DISABLED'] = True
        
        # Create application context for testing
        with app.app_context():
            # Initialize database tables for testing
            db.create_all()
            
            # Validate database setup
            try:
                # Test database connectivity
                db.session.execute('SELECT 1')
                db.session.commit()
                print(f"Test database initialized successfully: {app.config['SQLALCHEMY_DATABASE_URI']}")
            except Exception as e:
                print(f"Database initialization failed: {e}")
                raise
            
            yield app
            
            # Cleanup: Drop all tables after test session
            db.drop_all()
            db.session.remove()
    
    except FlaskApplicationError as e:
        pytest.fail(f"Flask application creation failed: {e.message}")
    except Exception as e:
        pytest.fail(f"Unexpected error creating Flask application: {e}")


@pytest.fixture
def client(app):
    """
    Provide Flask test client for HTTP request testing.
    
    Configures pytest-flask plugin integration with Flask test client
    initialization and application context management per Section 4.7.3.1.
    
    Args:
        app: Flask application fixture
        
    Returns:
        FlaskClient: Flask test client for making HTTP requests
    """
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def runner(app):
    """
    Provide Flask CLI test runner for command testing.
    
    Args:
        app: Flask application fixture
        
    Returns:
        FlaskCliRunner: Flask CLI test runner
    """
    return app.test_cli_runner()


# =============================================================================
# DATABASE FIXTURES
# =============================================================================

@pytest.fixture
def database(app):
    """
    Provide database session with automatic rollback for test isolation.
    
    Establishes SQLAlchemy test database sessions with automatic rollback
    capabilities ensuring test isolation per Section 4.7.3.1 database
    testing setup. Each test gets a fresh database state with automatic
    cleanup after test completion.
    
    Args:
        app: Flask application fixture
        
    Yields:
        SQLAlchemy database session with rollback capabilities
    """
    with app.app_context():
        # Create a new transaction for the test
        connection = db.engine.connect()
        transaction = connection.begin()
        
        # Configure session to use the transaction
        db.session.configure(bind=connection)
        
        try:
            yield db
        finally:
            # Rollback transaction to ensure test isolation
            transaction.rollback()
            connection.close()
            
            # Reset session state
            db.session.remove()


@pytest.fixture
def db_session(database):
    """
    Provide direct access to database session for test operations.
    
    Args:
        database: Database fixture with rollback capabilities
        
    Returns:
        Database session for direct database operations
    """
    return database.session


@pytest.fixture(autouse=True)
def cleanup_database(database):
    """
    Automatically clean up database state after each test.
    
    This fixture runs automatically after every test to ensure clean
    database state and prevent test contamination.
    
    Args:
        database: Database fixture
    """
    yield
    
    # Explicit cleanup of all data after test
    try:
        database.session.query(UserSession).delete()
        database.session.query(User).delete()
        database.session.commit()
    except Exception as e:
        database.session.rollback()
        print(f"Database cleanup warning: {e}")


# =============================================================================
# FACTORY BOY INTEGRATION FOR TEST DATA GENERATION
# =============================================================================

class UserFactory(SQLAlchemyModelFactory):
    """
    Factory Boy factory for User model with realistic test data generation.
    
    Implements Factory Boy integration with SQLAlchemy model fixtures
    for realistic test data generation per Section 4.7.3.2. Provides
    comprehensive user creation with proper field validation and
    relationship management.
    """
    
    class Meta:
        model = User
        sqlalchemy_session_persistence = 'commit'
    
    # Core user identification
    username = factory.Sequence(lambda n: f"testuser{n}")
    email = factory.LazyAttribute(lambda obj: f"{obj.username}@example.com")
    
    # Encrypted personal information
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    
    # User status and verification
    is_active = True
    is_verified = True
    is_admin = False
    
    # Authentication tracking
    login_count = fuzzy.FuzzyInteger(0, 100)
    failed_login_count = 0
    locked_until = None
    
    # Profile and preferences
    timezone = fuzzy.FuzzyChoice(['UTC', 'America/New_York', 'Europe/London', 'Asia/Tokyo'])
    locale = fuzzy.FuzzyChoice(['en', 'es', 'fr', 'de'])
    avatar_url = factory.Faker('image_url')
    
    # Audit fields
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)
    created_by = 'test_system'
    updated_by = 'test_system'
    
    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        """Set password after user creation"""
        if not create:
            return
        
        password = extracted or 'test_password_123'
        self.set_password(password)
    
    @factory.post_generation
    def auth0_user_id(self, create, extracted, **kwargs):
        """Set Auth0 user ID if provided"""
        if not create:
            return
        
        if extracted:
            self.auth0_user_id = extracted


class UserSessionFactory(SQLAlchemyModelFactory):
    """
    Factory Boy factory for UserSession model with realistic session data.
    
    Provides comprehensive user session creation for authentication testing
    with proper token generation and expiration handling.
    """
    
    class Meta:
        model = UserSession
        sqlalchemy_session_persistence = 'commit'
    
    # Core session identification
    user = factory.SubFactory(UserFactory)
    session_token = factory.LazyFunction(lambda: os.urandom(32).hex())
    csrf_token = factory.LazyFunction(lambda: os.urandom(24).hex())
    refresh_token = factory.LazyFunction(lambda: os.urandom(32).hex())
    
    # Session lifecycle
    expires_at = factory.LazyFunction(lambda: datetime.utcnow() + timedelta(hours=1))
    is_valid = True
    
    # Security tracking
    ip_address = factory.Faker('ipv4')
    user_agent = factory.Faker('user_agent')
    last_activity_at = factory.LazyFunction(datetime.utcnow)
    
    # Session metadata
    login_method = 'password'
    
    # Audit fields
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)


@pytest.fixture
def user_factory():
    """
    Provide UserFactory for test data generation.
    
    Returns:
        UserFactory class for creating test users
    """
    return UserFactory


@pytest.fixture
def session_factory():
    """
    Provide UserSessionFactory for session test data generation.
    
    Returns:
        UserSessionFactory class for creating test sessions
    """
    return UserSessionFactory


@pytest.fixture
def create_user(database, user_factory):
    """
    Provide function to create test users with proper database session.
    
    Args:
        database: Database fixture
        user_factory: UserFactory fixture
        
    Returns:
        Function to create test users with database persistence
    """
    def _create_user(**kwargs):
        """Create user with database persistence"""
        user = user_factory(**kwargs)
        database.session.add(user)
        database.session.commit()
        return user
    
    return _create_user


@pytest.fixture
def create_session(database, session_factory):
    """
    Provide function to create test sessions with proper database session.
    
    Args:
        database: Database fixture
        session_factory: UserSessionFactory fixture
        
    Returns:
        Function to create test sessions with database persistence
    """
    def _create_session(**kwargs):
        """Create session with database persistence"""
        session = session_factory(**kwargs)
        database.session.add(session)
        database.session.commit()
        return session
    
    return _create_session


# =============================================================================
# AUTHENTICATION FIXTURES
# =============================================================================

@pytest.fixture
def mock_auth0():
    """
    Provide Auth0 mock integration for authentication testing.
    
    Creates comprehensive pytest fixtures for authentication testing with
    Auth0 mock integration per Section 3.6.3 authentication fixtures.
    Provides mock authentication tokens, user session management, and
    authorization testing capabilities.
    
    Returns:
        Mock Auth0 client and authentication functions
    """
    with patch('auth0.management.Auth0') as mock_auth0_client, \
         patch('auth0.authentication.Users') as mock_auth0_users:
        
        # Configure Auth0 Management API mock
        mock_management = MagicMock()
        mock_auth0_client.return_value = mock_management
        
        # Configure Auth0 Users API mock
        mock_users_api = MagicMock()
        mock_auth0_users.return_value = mock_users_api
        
        # Mock user data generator
        def generate_auth0_user_data(user_id='auth0|test123', email='test@example.com', **kwargs):
            """Generate realistic Auth0 user data for testing"""
            return {
                'user_id': user_id,
                'email': email,
                'email_verified': kwargs.get('email_verified', True),
                'username': kwargs.get('username', email.split('@')[0]),
                'given_name': kwargs.get('given_name', 'Test'),
                'family_name': kwargs.get('family_name', 'User'),
                'nickname': kwargs.get('nickname', email.split('@')[0]),
                'picture': kwargs.get('picture', 'https://example.com/avatar.png'),
                'created_at': kwargs.get('created_at', datetime.utcnow().isoformat()),
                'updated_at': kwargs.get('updated_at', datetime.utcnow().isoformat()),
                'last_login': kwargs.get('last_login', datetime.utcnow().isoformat()),
                'logins_count': kwargs.get('logins_count', 1),
                'user_metadata': kwargs.get('user_metadata', {}),
                'app_metadata': kwargs.get('app_metadata', {})
            }
        
        # Configure mock responses
        mock_management.users.get.return_value = generate_auth0_user_data()
        mock_management.users.list.return_value = {
            'users': [generate_auth0_user_data()],
            'total': 1,
            'start': 0,
            'limit': 50
        }
        
        # Mock authentication methods
        mock_users_api.userinfo.return_value = generate_auth0_user_data()
        
        yield {
            'client': mock_auth0_client,
            'management': mock_management,
            'users_api': mock_users_api,
            'generate_user_data': generate_auth0_user_data
        }


@pytest.fixture
def mock_jwt_token():
    """
    Provide mock JWT token generation for authentication testing.
    
    Returns:
        Function to generate mock JWT tokens with customizable claims
    """
    def _generate_token(user_id='test_user_123', email='test@example.com', **claims):
        """Generate mock JWT token with user claims"""
        import base64
        import json
        
        # Mock JWT header
        header = {
            'typ': 'JWT',
            'alg': 'RS256',
            'kid': 'test_key_id'
        }
        
        # Mock JWT payload
        payload = {
            'iss': 'https://test-tenant.auth0.com/',
            'sub': user_id,
            'aud': 'test_audience',
            'iat': int(datetime.utcnow().timestamp()),
            'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            'azp': 'test_client_id',
            'scope': 'openid profile email',
            'email': email,
            'email_verified': True,
            **claims
        }
        
        # Create mock JWT (not cryptographically valid, for testing only)
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature = 'mock_signature_for_testing'
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    return _generate_token


@pytest.fixture
def authenticated_user(create_user, create_session):
    """
    Provide authenticated user with valid session for testing.
    
    Creates a complete authenticated user with valid session token
    for testing authenticated endpoints and user session management.
    
    Returns:
        Dictionary containing user, session, and authentication tokens
    """
    # Create test user
    user = create_user(
        username='authenticated_user',
        email='auth@example.com',
        is_verified=True,
        is_active=True
    )
    
    # Create valid session
    session = create_session(
        user=user,
        expires_at=datetime.utcnow() + timedelta(hours=2),
        is_valid=True,
        login_method='password'
    )
    
    return {
        'user': user,
        'session': session,
        'session_token': session.session_token,
        'csrf_token': session.csrf_token,
        'user_id': user.id,
        'username': user.username,
        'email': user.email
    }


@pytest.fixture
def admin_user(create_user, create_session):
    """
    Provide authenticated admin user for authorization testing.
    
    Returns:
        Dictionary containing admin user, session, and tokens
    """
    # Create admin user
    admin = create_user(
        username='admin_user',
        email='admin@example.com',
        is_admin=True,
        is_verified=True,
        is_active=True
    )
    
    # Create admin session
    session = create_session(
        user=admin,
        expires_at=datetime.utcnow() + timedelta(hours=2),
        is_valid=True,
        login_method='password'
    )
    
    return {
        'user': admin,
        'session': session,
        'session_token': session.session_token,
        'csrf_token': session.csrf_token,
        'user_id': admin.id,
        'username': admin.username,
        'email': admin.email
    }


@pytest.fixture
def auth_headers(authenticated_user):
    """
    Provide authentication headers for API testing.
    
    Args:
        authenticated_user: Authenticated user fixture
        
    Returns:
        Dictionary of HTTP headers for authenticated requests
    """
    return {
        'Authorization': f"Bearer {authenticated_user['session_token']}",
        'X-CSRF-Token': authenticated_user['csrf_token'],
        'Content-Type': 'application/json'
    }


@pytest.fixture
def mock_request_context(app):
    """
    Provide Flask request context for testing request-dependent functions.
    
    Args:
        app: Flask application fixture
        
    Yields:
        Flask test request context
    """
    with app.test_request_context():
        yield


# =============================================================================
# PERFORMANCE TESTING FIXTURES
# =============================================================================

@pytest.fixture
def benchmark_config():
    """
    Provide pytest-benchmark configuration for performance testing.
    
    Implements pytest-benchmark for automated performance regression
    detection per Section 4.7.4.1 performance benchmarking framework.
    
    Returns:
        Dictionary of benchmark configuration settings
    """
    return {
        'min_rounds': 5,
        'max_time': 1.0,
        'min_time': 0.000005,
        'timer': 'time.perf_counter',
        'disable_gc': True,
        'warmup': True,
        'warmup_iterations': 100000
    }


@pytest.fixture
def performance_data():
    """
    Provide performance baseline data for SLA compliance validation.
    
    Returns:
        Dictionary of performance SLA thresholds and baseline metrics
    """
    return {
        'api_response_time_sla': 0.2,  # 200ms SLA for API responses
        'database_query_sla': 0.05,   # 50ms SLA for database queries
        'authentication_sla': 0.1,    # 100ms SLA for authentication
        'baseline_metrics': {
            'user_creation': 0.05,
            'user_authentication': 0.08,
            'session_creation': 0.03,
            'database_query': 0.02
        }
    }


# =============================================================================
# UTILITY FIXTURES
# =============================================================================

@pytest.fixture
def temp_directory():
    """
    Provide temporary directory for file-based testing.
    
    Yields:
        Path to temporary directory that is automatically cleaned up
    """
    temp_dir = tempfile.mkdtemp()
    try:
        yield Path(temp_dir)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_environment_variables():
    """
    Provide mock environment variables for testing configuration.
    
    Yields:
        Function to set temporary environment variables
    """
    original_env = os.environ.copy()
    
    def set_env(**kwargs):
        """Set environment variables for testing"""
        for key, value in kwargs.items():
            os.environ[key] = str(value)
    
    try:
        yield set_env
    finally:
        # Restore original environment
        os.environ.clear()
        os.environ.update(original_env)


@pytest.fixture
def sample_user_data():
    """
    Provide sample user data for various test scenarios.
    
    Returns:
        Dictionary containing various user data scenarios
    """
    return {
        'valid_user': {
            'username': 'validuser',
            'email': 'valid@example.com',
            'password': 'SecurePassword123!',
            'first_name': 'Valid',
            'last_name': 'User'
        },
        'invalid_user': {
            'username': '',  # Invalid empty username
            'email': 'invalid-email',  # Invalid email format
            'password': '123'  # Too short password
        },
        'auth0_user': {
            'auth0_user_id': 'auth0|test123456789',
            'username': 'auth0user',
            'email': 'auth0@example.com',
            'email_verified': True,
            'given_name': 'Auth0',
            'family_name': 'User'
        },
        'admin_user': {
            'username': 'adminuser',
            'email': 'admin@example.com',
            'password': 'AdminPassword123!',
            'is_admin': True,
            'first_name': 'Admin',
            'last_name': 'User'
        }
    }


@pytest.fixture(scope='session', autouse=True)
def setup_test_environment():
    """
    Set up test environment and validate configuration.
    
    This fixture runs once per test session to set up the testing environment
    and validate that all required dependencies and configurations are available.
    """
    print("\n" + "="*80)
    print("FLASK APPLICATION TESTING ENVIRONMENT SETUP")
    print("="*80)
    
    # Validate pytest version
    import pytest
    pytest_version = pytest.__version__
    print(f"✓ Pytest version: {pytest_version}")
    
    # Validate Flask version
    import flask
    flask_version = flask.__version__
    print(f"✓ Flask version: {flask_version}")
    
    # Validate SQLAlchemy version
    import sqlalchemy
    sqlalchemy_version = sqlalchemy.__version__
    print(f"✓ SQLAlchemy version: {sqlalchemy_version}")
    
    # Validate Factory Boy version
    factory_version = factory.__version__
    print(f"✓ Factory Boy version: {factory_version}")
    
    # Set test environment variables
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['FLASK_CONFIG'] = 'testing'
    os.environ['FIELD_ENCRYPTION_KEY'] = b'test-encryption-key-32-bytes-long!'.decode('utf-8')
    
    print("✓ Test environment variables configured")
    print("✓ Database isolation configured")
    print("✓ Authentication mocking configured")
    print("✓ Factory Boy integration configured")
    
    print("="*80)
    print("TEST ENVIRONMENT SETUP COMPLETE")
    print("="*80 + "\n")
    
    yield
    
    # Cleanup after all tests
    print("\n" + "="*80)
    print("CLEANING UP TEST ENVIRONMENT")
    print("="*80)
    
    # Clean up any remaining test files or data
    test_files = Path.cwd().glob("test_*.db")
    for test_file in test_files:
        try:
            test_file.unlink()
            print(f"✓ Cleaned up test database: {test_file}")
        except OSError:
            pass
    
    print("✓ Test environment cleanup complete")
    print("="*80 + "\n")


# =============================================================================
# EXPORT FIXTURES FOR EXTERNAL USE
# =============================================================================

__all__ = [
    # Flask application fixtures
    'app',
    'client',
    'runner',
    'test_config',
    
    # Database fixtures
    'database',
    'db_session',
    'cleanup_database',
    
    # Factory Boy fixtures
    'user_factory',
    'session_factory',
    'create_user',
    'create_session',
    
    # Authentication fixtures
    'mock_auth0',
    'mock_jwt_token',
    'authenticated_user',
    'admin_user',
    'auth_headers',
    'mock_request_context',
    
    # Performance testing fixtures
    'benchmark_config',
    'performance_data',
    
    # Utility fixtures
    'temp_directory',
    'mock_environment_variables',
    'sample_user_data',
    'setup_test_environment'
]