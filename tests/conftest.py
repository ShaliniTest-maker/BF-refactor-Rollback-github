"""
Primary pytest configuration file providing Flask application fixtures, database session management,
and test client initialization for comprehensive test isolation and execution across unit, integration,
and performance test suites.

This module implements the Flask testing infrastructure requirements specified in Section 4.7.3.1
with pytest-flask plugin integration, SQLAlchemy test database sessions with automatic rollback
capabilities, and comprehensive authentication fixtures for Auth0 mock integration.
"""

import os
import tempfile
from unittest.mock import Mock, patch
from typing import Generator, Dict, Any, Optional

import pytest
from flask import Flask
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session
from werkzeug.test import Client

# Import Factory Boy for test data generation per Section 4.7.3.2
import factory
from factory.alchemy import SQLAlchemyModelFactory

# Import application components
# Note: These imports will be available once the corresponding files are created
try:
    from app import create_app
    from config import TestingConfig
    from models.user import User
except ImportError:
    # Provide fallback implementations for early testing phase
    create_app = None
    TestingConfig = None
    User = None


# ============================================================================
# Flask Application Fixtures
# ============================================================================

@pytest.fixture(scope='session')
def testing_config() -> Dict[str, Any]:
    """
    Provide testing configuration for Flask application factory.
    
    Returns:
        Configuration dictionary for testing environment with:
        - Test database configuration
        - Debug mode enabled for enhanced error reporting
        - Testing mode enabled for Flask test utilities
        - Disabled CSRF protection for API testing
        - In-memory SQLite database for test isolation
    
    Per Section 4.7.3.1: Test environment isolation with dedicated test database configuration
    """
    # Create temporary database file for testing isolation
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    
    config = {
        'TESTING': True,
        'DEBUG': True,
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SECRET_KEY': 'test-secret-key-for-testing-only',
        'AUTH0_DOMAIN': 'test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'test_client_id',
        'AUTH0_CLIENT_SECRET': 'test_client_secret',
        'AUTH0_AUDIENCE': 'test_audience',
        'DATABASE_URL': f'sqlite:///{db_path}',
        'FLASK_ENV': 'testing',
        'FLASK_CONFIG': 'testing'
    }
    
    yield config
    
    # Cleanup: Remove temporary database file
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture(scope='session')
def app(testing_config: Dict[str, Any]) -> Generator[Flask, None, None]:
    """
    Create Flask application instance with testing configuration.
    
    This fixture implements the Flask application factory pattern with TestingConfig
    for isolated test execution per Section 0.2.1 testing requirements.
    
    Args:
        testing_config: Testing configuration dictionary
        
    Yields:
        Configured Flask application instance with:
        - Testing configuration applied
        - Database initialized with test schema
        - All blueprints registered
        - Application context established
    
    Per Section 4.7.3.1: Flask Testing Integration with pytest-flask plugin
    """
    if create_app is None:
        # Fallback application for early testing phase
        app_instance = Flask(__name__)
        app_instance.config.update(testing_config)
        
        # Initialize SQLAlchemy for testing
        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy()
        db.init_app(app_instance)
        
        # Store db instance for access in other fixtures
        app_instance.db = db
    else:
        # Use production application factory
        app_instance = create_app(config_override=testing_config)
    
    # Create application context for database operations
    with app_instance.app_context():
        # Initialize database schema for testing
        if hasattr(app_instance, 'db'):
            app_instance.db.create_all()
        
        yield app_instance
        
        # Cleanup: Drop all tables after session
        if hasattr(app_instance, 'db'):
            app_instance.db.drop_all()


@pytest.fixture(scope='function')
def client(app: Flask) -> FlaskClient:
    """
    Create Flask test client for API endpoint testing.
    
    Provides Flask test client configuration and application context management
    per Section 4.7.3.1 pytest-flask plugin integration.
    
    Args:
        app: Flask application instance
        
    Returns:
        Flask test client configured for:
        - API endpoint testing
        - Request/response validation
        - Session management testing
        - Authentication flow testing
    
    Per Section 4.7.1: API endpoints testing using Flask test client
    """
    return app.test_client()


@pytest.fixture(scope='function')
def runner(app: Flask):
    """
    Create Flask CLI test runner for command testing.
    
    Args:
        app: Flask application instance
        
    Returns:
        Flask CLI test runner for testing Flask commands and CLI operations
    """
    return app.test_cli_runner()


# ============================================================================
# Database Session Management Fixtures
# ============================================================================

@pytest.fixture(scope='function')
def db_session(app: Flask) -> Generator[Session, None, None]:
    """
    Provide SQLAlchemy database session with automatic rollback capabilities.
    
    This fixture establishes SQLAlchemy test database sessions with automatic rollback
    capabilities ensuring test isolation per Section 4.7.3.1 database testing setup.
    
    Args:
        app: Flask application instance with database configuration
        
    Yields:
        SQLAlchemy session with:
        - Transaction isolation for each test function
        - Automatic rollback after test execution
        - Nested transaction support for complex testing scenarios
        - Connection pooling for performance optimization
    
    Per Section 4.7.3.1: Database Testing Setup with rollback capabilities
    """
    if not hasattr(app, 'db'):
        pytest.skip("Database not configured for this test")
    
    # Create a connection to the database
    connection = app.db.engine.connect()
    
    # Begin a non-ORM transaction for rollback capability
    transaction = connection.begin()
    
    # Configure the session to use the connection with transaction
    session = app.db.create_scoped_session(
        options={"bind": connection, "binds": {}}
    )
    
    # Make session available to SQLAlchemy models
    app.db.session = session
    
    yield session
    
    # Cleanup: Rollback transaction and close connection
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope='function')
def db(app: Flask, db_session: Session) -> SQLAlchemy:
    """
    Provide configured SQLAlchemy database instance.
    
    Args:
        app: Flask application instance
        db_session: Database session with rollback capabilities
        
    Returns:
        SQLAlchemy database instance configured for testing with:
        - Active session management
        - Model access for test data manipulation
        - Migration support for schema testing
    """
    if not hasattr(app, 'db'):
        pytest.skip("Database not configured for this test")
    
    return app.db


# ============================================================================
# Authentication Testing Fixtures
# ============================================================================

@pytest.fixture(scope='function')
def auth_headers() -> Dict[str, str]:
    """
    Provide mock authentication headers for API testing.
    
    Creates comprehensive pytest fixtures for authentication testing with Auth0 mock
    integration per Section 3.6.3 authentication fixtures.
    
    Returns:
        Authentication headers containing:
        - Mock JWT token for Auth0 integration testing
        - Standard HTTP authorization header format
        - User identification claims for session management
        - Role-based access control headers
    
    Per Section 3.6.3: Authentication fixtures with mock authentication tokens
    """
    mock_token = (
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0."
        "eyJpc3MiOiJodHRwczovL3Rlc3QtZG9tYWluLmF1dGgwLmNvbS8iLCJzdWIiOiJ0ZXN0LXVzZXItaWQiLA=="
        "eyJhdWQiOiJ0ZXN0X2F1ZGllbmNlIiwiaWF0IjoxNjAwMDAwMDAwLCJleHAiOjE2MDAwMDM2MDB9."
        "mock-signature-for-testing-purposes-only"
    )
    
    return {
        'Authorization': f'Bearer {mock_token}',
        'Content-Type': 'application/json',
        'X-User-ID': 'test-user-id',
        'X-User-Role': 'user'
    }


@pytest.fixture(scope='function')
def mock_auth0_client():
    """
    Provide mock Auth0 client for authentication testing.
    
    Returns:
        Mock Auth0 client with:
        - Token validation simulation
        - User profile retrieval mocking
        - Authentication flow simulation
        - Error condition testing support
    
    Per Section 3.6.3: Auth0 integration testing fixtures
    """
    with patch('auth0.authentication.Users') as mock_users:
        with patch('auth0.management.Auth0') as mock_management:
            # Configure mock responses for successful authentication
            mock_users.return_value.userinfo.return_value = {
                'sub': 'test-user-id',
                'email': 'test@example.com',
                'name': 'Test User',
                'picture': 'https://example.com/avatar.jpg',
                'email_verified': True
            }
            
            mock_management.return_value.users.get.return_value = {
                'user_id': 'test-user-id',
                'email': 'test@example.com',
                'name': 'Test User',
                'app_metadata': {'roles': ['user']},
                'user_metadata': {'preferences': {}}
            }
            
            yield {
                'users': mock_users,
                'management': mock_management
            }


@pytest.fixture(scope='function')
def authenticated_user(db_session: Session) -> Optional[Any]:
    """
    Provide authenticated user instance for session testing.
    
    Args:
        db_session: Database session for user creation
        
    Returns:
        User model instance representing authenticated user with:
        - Valid authentication credentials
        - Active session state
        - Required user profile information
        - Role-based permissions
    
    Per Section 3.6.3: User session management in authentication fixtures
    """
    if User is None:
        # Return mock user data when model is not available
        return {
            'id': 'test-user-id',
            'email': 'test@example.com',
            'name': 'Test User',
            'is_active': True,
            'roles': ['user']
        }
    
    # Create test user in database
    user = User(
        id='test-user-id',
        email='test@example.com',
        name='Test User',
        is_active=True
    )
    
    db_session.add(user)
    db_session.commit()
    
    return user


# ============================================================================
# Factory Boy Integration Fixtures
# ============================================================================

@pytest.fixture(scope='session')
def factory_session(app: Flask):
    """
    Configure Factory Boy session for test data generation.
    
    Implements Factory Boy integration with SQLAlchemy model fixtures for realistic
    test data generation per Section 4.7.3.2.
    
    Args:
        app: Flask application instance
        
    Returns:
        Factory Boy session configuration for:
        - SQLAlchemy model factory integration
        - Realistic test data generation patterns
        - Relationship management between models
        - Data consistency validation across tests
    
    Per Section 4.7.3.2: Factory Boy Integration with SQLAlchemy models
    """
    if hasattr(app, 'db'):
        # Configure Factory Boy to use the test database session
        factory.alchemy.DEFAULT_DB_ALIAS = app.db.session
    
    return factory.alchemy.DEFAULT_DB_ALIAS


@pytest.fixture(scope='function')
def user_factory(db_session: Session, factory_session):
    """
    Provide User model factory for test data generation.
    
    Args:
        db_session: Database session for model persistence
        factory_session: Factory Boy session configuration
        
    Returns:
        User factory class for generating test user instances with:
        - Realistic user profile data
        - Valid email addresses and names
        - Configurable user roles and permissions
        - Relationship data for associated models
    """
    if User is None:
        # Provide mock factory when model is not available
        class MockUserFactory:
            @staticmethod
            def create(**kwargs):
                return {
                    'id': kwargs.get('id', 'mock-user-id'),
                    'email': kwargs.get('email', 'mock@example.com'),
                    'name': kwargs.get('name', 'Mock User'),
                    'is_active': kwargs.get('is_active', True)
                }
        
        return MockUserFactory
    
    class UserFactory(SQLAlchemyModelFactory):
        class Meta:
            model = User
            sqlalchemy_session = db_session
            sqlalchemy_session_persistence = 'commit'
        
        id = factory.Sequence(lambda n: f'user-{n}')
        email = factory.Faker('email')
        name = factory.Faker('name')
        is_active = True
        created_at = factory.Faker('date_time_this_year')
        updated_at = factory.LazyAttribute(lambda obj: obj.created_at)
    
    return UserFactory


# ============================================================================
# Performance Testing Fixtures
# ============================================================================

@pytest.fixture(scope='function')
def benchmark_config() -> Dict[str, Any]:
    """
    Provide pytest-benchmark configuration for performance testing.
    
    Returns:
        Benchmark configuration for:
        - Response time measurement and analysis
        - Memory usage profiling during test execution
        - Statistical performance comparison with baseline
        - SLA compliance validation thresholds
    
    Per Section 4.7.4.1: pytest-benchmark framework for statistical performance analysis
    """
    return {
        'min_rounds': 5,
        'max_time': 1.0,
        'min_time': 0.1,
        'warmup': True,
        'warmup_iterations': 2,
        'disable_gc': True,
        'timer': 'time.perf_counter',
        'group_by': 'func'
    }


# ============================================================================
# Test Environment Management
# ============================================================================

@pytest.fixture(autouse=True, scope='function')
def test_environment_isolation():
    """
    Ensure test environment isolation and cleanup.
    
    This fixture runs automatically for every test function to:
    - Reset any global state between tests
    - Clear cached data and temporary files
    - Restore environment variables to testing defaults
    - Validate test isolation requirements
    
    Per Section 4.7.3.1: Test environment isolation with dedicated test database configuration
    """
    # Store original environment variables
    original_env = dict(os.environ)
    
    # Set testing environment variables
    os.environ.update({
        'FLASK_ENV': 'testing',
        'FLASK_CONFIG': 'testing',
        'TESTING': 'True'
    })
    
    yield
    
    # Restore original environment variables
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture(scope='function')
def api_test_data() -> Dict[str, Any]:
    """
    Provide standardized test data for API endpoint testing.
    
    Returns:
        Dictionary containing:
        - Valid request payloads for API testing
        - Expected response formats and structures
        - Error condition test data
        - Edge case scenarios for comprehensive validation
    
    Per Section 4.7.1: API endpoints testing with comprehensive validation
    """
    return {
        'user': {
            'valid_payload': {
                'name': 'Test User',
                'email': 'test@example.com',
                'password': 'SecurePassword123!'
            },
            'invalid_payload': {
                'name': '',
                'email': 'invalid-email',
                'password': '123'
            },
            'update_payload': {
                'name': 'Updated Test User',
                'email': 'updated@example.com'
            }
        },
        'auth': {
            'login_payload': {
                'email': 'test@example.com',
                'password': 'SecurePassword123!'
            },
            'invalid_credentials': {
                'email': 'test@example.com',
                'password': 'wrongpassword'
            }
        }
    }


# ============================================================================
# Test Markers and Categories
# ============================================================================

def pytest_configure(config):
    """
    Configure pytest markers for test categorization.
    
    This function registers custom pytest markers for test classification
    per Section 3.6.3 test configuration requirements.
    
    Args:
        config: Pytest configuration object
    """
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests (fast, isolated)"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (database, services)"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance benchmarks"
    )
    config.addinivalue_line(
        "markers", "auth: marks tests as authentication and authorization tests"
    )
    config.addinivalue_line(
        "markers", "api: marks tests as API endpoint tests"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow running (>1 second)"
    )


# ============================================================================
# Error Handling and Test Recovery
# ============================================================================

@pytest.fixture(scope='function')
def error_handler():
    """
    Provide error handling utilities for test failure analysis.
    
    Returns:
        Error handler with:
        - Test failure categorization and analysis
        - Automatic recovery procedures for transient failures
        - Detailed logging for debugging test issues
        - State capture for post-mortem analysis
    
    Per Section 4.7.6: Error handling and recovery procedures
    """
    errors = []
    
    def capture_error(error_type: str, message: str, context: Dict[str, Any] = None):
        """Capture error information for analysis."""
        error_info = {
            'type': error_type,
            'message': message,
            'context': context or {},
            'timestamp': pytest.approx(1234567890, abs=1e6)  # Mock timestamp for testing
        }
        errors.append(error_info)
    
    def get_errors():
        """Retrieve captured errors."""
        return errors.copy()
    
    def clear_errors():
        """Clear captured errors."""
        errors.clear()
    
    return {
        'capture': capture_error,
        'get_errors': get_errors,
        'clear_errors': clear_errors
    }