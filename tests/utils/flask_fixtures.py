"""
Core Flask Testing Fixtures

This module provides comprehensive Flask testing fixtures for pytest-flask 1.3.0 integration,
enabling consistent Flask application testing across all test modules with proper setup and
teardown procedures. The fixtures support Flask application factory pattern testing, request
context management, database testing with Flask-SQLAlchemy, and blueprint testing infrastructure.

Key Features:
- Flask application factory pattern testing support per Feature F-008
- pytest-flask 1.3.0 plugin integration for Flask-specific testing capabilities per Section 4.7.1
- Test environment configuration with Flask app.config management per Feature F-010
- Blueprint testing infrastructure for API endpoint validation per Feature F-001
- Database testing fixtures with Flask-SQLAlchemy integration per Feature F-003
- Flask development server fixtures for integration testing per Section 3.6.1

Dependencies:
- Flask 3.1.1 with application factory pattern
- pytest-flask 1.3.0 for Flask-specific testing capabilities
- Flask-SQLAlchemy 3.1.1 for database ORM functionality
- Flask-Migrate 4.1.0 for database versioning
- pytest-benchmark 5.1.0 for performance testing integration

Author: Flask Migration Team
Version: 1.0.0
Created: 2024
"""

import os
import pytest
import tempfile
from unittest.mock import Mock, patch
from contextlib import contextmanager
from typing import Generator, Any, Dict, Optional, List
from datetime import datetime, timedelta

# Flask core imports
from flask import Flask, current_app, g
from flask.testing import FlaskClient
from flask.ctx import RequestContext, AppContext

# Database and migration imports
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

# Authentication imports for testing
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer

# Application imports
from src.models import db, User, UserSession, BusinessEntity, EntityRelationship
from src.blueprints import register_blueprints
from config import TestingConfig


# =====================================
# Flask Application Factory Fixtures
# =====================================

@pytest.fixture(scope='session')
def app_config() -> Dict[str, Any]:
    """
    Flask application test configuration fixture providing environment-specific
    settings for test isolation and Flask app.config management.
    
    This fixture establishes test environment configuration per Feature F-010,
    ensuring proper isolation between test runs and production environments.
    
    Returns:
        Dict[str, Any]: Test configuration dictionary for Flask app.config
        
    Features:
        - In-memory SQLite database for fast test execution
        - Disabled CSRF protection for testing convenience
        - Testing mode activation for Flask debugging
        - Secret key generation for session management
        - Database query tracking disabled for performance
    """
    # Create temporary database file for test isolation
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(db_fd)
    
    config = {
        'TESTING': True,
        'DEBUG': True,
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key-for-testing-only',
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'poolclass': StaticPool,
            'pool_pre_ping': True,
            'connect_args': {
                'check_same_thread': False,
            },
        },
        # Performance testing configuration
        'BENCHMARK_ONLY': False,
        'BENCHMARK_SORT': 'mean',
        'BENCHMARK_COLUMNS': ['min', 'max', 'mean', 'stddev', 'rounds', 'iterations'],
        # Authentication testing configuration
        'AUTH_TOKEN_EXPIRATION': 3600,  # 1 hour for testing
        'SESSION_TIMEOUT': 1800,  # 30 minutes for testing
        # Blueprint testing configuration
        'BLUEPRINT_TESTING_MODE': True,
        'API_TESTING_HEADERS': {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        },
    }
    
    yield config
    
    # Cleanup: Remove temporary database file
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture(scope='session')
def app(app_config: Dict[str, Any]) -> Generator[Flask, None, None]:
    """
    Flask application factory fixture with pytest-flask 1.3.0 integration,
    providing structured Flask application initialization for testing.
    
    This fixture implements the Flask application factory pattern per Section 5.1.1,
    enabling comprehensive testing of the Flask 3.1.1 application with proper
    configuration management and blueprint registration.
    
    Args:
        app_config: Test configuration dictionary from app_config fixture
        
    Yields:
        Flask: Configured Flask application instance for testing
        
    Features:
        - Flask application factory pattern integration
        - Blueprint registration orchestration
        - Database initialization with Flask-SQLAlchemy
        - Migration context setup with Flask-Migrate
        - Test environment isolation
    """
    # Import the application factory
    from app import create_app
    
    # Create Flask application with test configuration
    flask_app = create_app(config=app_config)
    
    # Establish application context for testing
    with flask_app.app_context():
        # Initialize database tables for testing
        db.create_all()
        
        # Yield the configured application
        yield flask_app
        
        # Cleanup: Drop all database tables
        db.drop_all()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """
    Flask test client fixture providing HTTP request simulation capabilities
    for API endpoint testing and blueprint validation.
    
    This fixture enables comprehensive API endpoint testing per Feature F-001,
    supporting Flask blueprint testing infrastructure with proper request
    context management and response validation.
    
    Args:
        app: Flask application instance from app fixture
        
    Returns:
        FlaskClient: Flask test client for HTTP request simulation
        
    Features:
        - HTTP method testing (GET, POST, PUT, DELETE)
        - JSON request/response handling
        - Session management and cookie support
        - Blueprint route testing
        - Authentication testing support
    """
    return app.test_client()


@pytest.fixture
def runner(app: Flask):
    """
    Flask CLI runner fixture for testing Click command-line interfaces
    and Flask-Migrate database operations.
    
    This fixture supports Flask development server fixtures per Section 3.6.1,
    enabling testing of CLI commands and database migration operations.
    
    Args:
        app: Flask application instance from app fixture
        
    Returns:
        FlaskCliRunner: Flask CLI test runner for command testing
        
    Features:
        - Flask CLI command testing
        - Database migration command testing
        - Environment variable injection
        - Command output validation
    """
    return app.test_cli_runner()


# =====================================
# Database Testing Fixtures
# =====================================

@pytest.fixture
def db_session(app: Flask) -> Generator[SQLAlchemy, None, None]:
    """
    Database session fixture with Flask-SQLAlchemy integration and transaction
    rollback capabilities for test isolation.
    
    This fixture implements Flask-SQLAlchemy test database fixtures per Feature F-003,
    providing comprehensive database testing with automatic transaction rollback
    to ensure test isolation and data consistency.
    
    Args:
        app: Flask application instance from app fixture
        
    Yields:
        SQLAlchemy: Database session with transaction isolation
        
    Features:
        - Transaction-based test isolation
        - Automatic rollback after each test
        - Flask-SQLAlchemy session management
        - Database constraint validation
        - Relationship integrity testing
    """
    with app.app_context():
        # Begin a transaction
        connection = db.engine.connect()
        transaction = connection.begin()
        
        # Configure session to use the transaction
        db.session = db.create_scoped_session(
            options={'bind': connection, 'binds': {}}
        )
        
        # Create all tables within the transaction
        db.create_all()
        
        yield db
        
        # Rollback transaction to clean up test data
        transaction.rollback()
        connection.close()
        db.session.remove()


@pytest.fixture
def clean_db(db_session: SQLAlchemy) -> SQLAlchemy:
    """
    Clean database fixture ensuring empty database state for each test.
    
    This fixture provides a clean database state by truncating all tables
    while preserving schema structure, enabling reliable test execution
    with predictable data states.
    
    Args:
        db_session: Database session from db_session fixture
        
    Returns:
        SQLAlchemy: Clean database session with empty tables
        
    Features:
        - Table truncation for clean state
        - Schema preservation
        - Foreign key constraint handling
        - Identity column reset
    """
    # Truncate all tables while preserving schema
    for table in reversed(db.metadata.sorted_tables):
        db_session.session.execute(table.delete())
    
    db_session.session.commit()
    return db_session


# =====================================
# Request Context Management Fixtures
# =====================================

@pytest.fixture
def app_context(app: Flask) -> Generator[AppContext, None, None]:
    """
    Flask application context fixture for testing components that require
    current_app access outside of request contexts.
    
    This fixture enables proper Flask request context management per Section 4.7.1,
    supporting session and authentication testing with proper context isolation.
    
    Args:
        app: Flask application instance from app fixture
        
    Yields:
        AppContext: Flask application context for testing
        
    Features:
        - Application context management
        - current_app access enablement
        - Configuration access for testing
        - Extension context support
    """
    with app.app_context() as ctx:
        yield ctx


@pytest.fixture
def request_context(app: Flask) -> Generator[RequestContext, None, None]:
    """
    Flask request context fixture enabling proper session and authentication
    testing with request-bound context management.
    
    This fixture supports Flask request context fixtures per Section 4.7.1,
    enabling comprehensive testing of request-dependent functionality including
    session management, authentication decorators, and request data processing.
    
    Args:
        app: Flask application instance from app fixture
        
    Yields:
        RequestContext: Flask request context for testing
        
    Features:
        - Request context simulation
        - Session data access
        - Authentication context support
        - Request data injection
        - Context variable management
    """
    with app.test_request_context() as ctx:
        yield ctx


@pytest.fixture
def authenticated_request_context(app: Flask, test_user: User) -> Generator[RequestContext, None, None]:
    """
    Authenticated request context fixture providing pre-authenticated user
    context for testing protected endpoints and user-specific functionality.
    
    This fixture enables comprehensive authentication testing per Feature F-007,
    supporting Flask-Login integration and ItsDangerous session management
    with proper user authentication state simulation.
    
    Args:
        app: Flask application instance from app fixture
        test_user: Authenticated user instance from test_user fixture
        
    Yields:
        RequestContext: Authenticated Flask request context for testing
        
    Features:
        - Pre-authenticated user context
        - Session management simulation
        - Authentication decorator testing
        - User-specific data access
        - Permission validation testing
    """
    with app.test_request_context() as ctx:
        # Simulate authenticated user session
        from flask_login import login_user
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user_id'] = test_user.id
                sess['_fresh'] = True
        
        # Set up Flask-Login user context
        g.user = test_user
        g.authenticated = True
        
        yield ctx


# =====================================
# Blueprint Testing Fixtures
# =====================================

@pytest.fixture
def blueprint_client(app: Flask) -> FlaskClient:
    """
    Blueprint-specific test client fixture with pre-configured headers
    and request settings optimized for API endpoint validation.
    
    This fixture provides Flask blueprint testing infrastructure per Feature F-001,
    enabling modular route validation with proper request formatting and
    response validation for comprehensive API testing.
    
    Args:
        app: Flask application instance from app fixture
        
    Returns:
        FlaskClient: Configured test client for blueprint testing
        
    Features:
        - API-optimized request headers
        - JSON content type handling
        - Blueprint route isolation
        - Response format validation
        - Error handling testing
    """
    client = app.test_client()
    
    # Configure default headers for API testing
    client.environ_base.update({
        'CONTENT_TYPE': 'application/json',
        'ACCEPT': 'application/json',
    })
    
    return client


@pytest.fixture
def api_headers() -> Dict[str, str]:
    """
    Standard API headers fixture for consistent request formatting
    across all API endpoint tests.
    
    This fixture provides standardized HTTP headers for API testing,
    ensuring consistent request formatting and content type handling
    for comprehensive blueprint validation.
    
    Returns:
        Dict[str, str]: Standard API headers for testing
        
    Features:
        - JSON content type specification
        - Accept header configuration
        - CORS header support
        - Authentication header templates
    """
    return {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Flask-Test-Client/1.0',
    }


@pytest.fixture
def auth_headers(test_user: User, api_headers: Dict[str, str]) -> Dict[str, str]:
    """
    Authenticated API headers fixture providing pre-configured authentication
    headers for testing protected endpoints.
    
    This fixture enables authentication testing with proper header management
    per Feature F-007, supporting ItsDangerous token generation and session
    management for comprehensive security testing.
    
    Args:
        test_user: Authenticated user instance from test_user fixture
        api_headers: Base API headers from api_headers fixture
        
    Returns:
        Dict[str, str]: Authenticated API headers for testing
        
    Features:
        - Authentication token generation
        - Session header management
        - CSRF token handling
        - User context headers
    """
    headers = api_headers.copy()
    
    # Generate authentication token using ItsDangerous
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    auth_token = serializer.dumps({'user_id': test_user.id})
    
    headers.update({
        'Authorization': f'Bearer {auth_token}',
        'X-User-ID': str(test_user.id),
        'X-Session-ID': f'test-session-{test_user.id}',
    })
    
    return headers


# =====================================
# Test Data Factory Fixtures
# =====================================

@pytest.fixture
def test_user(db_session: SQLAlchemy) -> User:
    """
    Test user factory fixture providing standardized user instances
    for authentication and user-related testing.
    
    This fixture creates consistent test user data for comprehensive
    authentication testing per Feature F-007, supporting Flask-Login
    integration and user session management validation.
    
    Args:
        db_session: Database session from db_session fixture
        
    Returns:
        User: Test user instance with standard attributes
        
    Features:
        - Standardized user attributes
        - Secure password hashing
        - Email validation patterns
        - User state management
        - Relationship data setup
    """
    user = User(
        username='testuser',
        email='test@example.com',
        password_hash=generate_password_hash('testpassword123'),
        is_active=True,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db_session.session.add(user)
    db_session.session.commit()
    db_session.session.refresh(user)
    
    return user


@pytest.fixture
def test_user_session(db_session: SQLAlchemy, test_user: User) -> UserSession:
    """
    Test user session factory fixture providing session instances
    for session management and authentication testing.
    
    This fixture creates user session data for comprehensive session
    testing per Feature F-007, supporting ItsDangerous token validation
    and Flask-Login session management.
    
    Args:
        db_session: Database session from db_session fixture
        test_user: User instance from test_user fixture
        
    Returns:
        UserSession: Test session instance with proper relationships
        
    Features:
        - Session token generation
        - Expiration time management
        - User relationship validation
        - Session state tracking
    """
    # Generate secure session token
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    session_token = serializer.dumps({'user_id': test_user.id, 'timestamp': datetime.utcnow().isoformat()})
    
    session = UserSession(
        user_id=test_user.id,
        session_token=session_token,
        expires_at=datetime.utcnow() + timedelta(hours=1),
        created_at=datetime.utcnow(),
        is_valid=True
    )
    
    db_session.session.add(session)
    db_session.session.commit()
    db_session.session.refresh(session)
    
    return session


@pytest.fixture
def test_business_entity(db_session: SQLAlchemy, test_user: User) -> BusinessEntity:
    """
    Test business entity factory fixture providing business domain objects
    for service layer and business logic testing.
    
    This fixture creates business entity data for comprehensive business
    logic testing per Feature F-005, supporting Service Layer pattern
    validation and entity relationship testing.
    
    Args:
        db_session: Database session from db_session fixture
        test_user: User instance from test_user fixture
        
    Returns:
        BusinessEntity: Test business entity with proper relationships
        
    Features:
        - Business entity attributes
        - User ownership relationships
        - Status management
        - Metadata handling
    """
    entity = BusinessEntity(
        name='Test Business Entity',
        description='A test business entity for comprehensive testing',
        owner_id=test_user.id,
        status='active',
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db_session.session.add(entity)
    db_session.session.commit()
    db_session.session.refresh(entity)
    
    return entity


@pytest.fixture
def test_entity_relationship(
    db_session: SQLAlchemy,
    test_business_entity: BusinessEntity
) -> EntityRelationship:
    """
    Test entity relationship factory fixture providing relationship instances
    for complex business logic and workflow testing.
    
    This fixture creates entity relationship data for comprehensive
    relationship testing per database design Section 6.2.2.1, supporting
    complex business workflow validation and referential integrity testing.
    
    Args:
        db_session: Database session from db_session fixture
        test_business_entity: Business entity instance from test_business_entity fixture
        
    Returns:
        EntityRelationship: Test relationship instance with proper associations
        
    Features:
        - Dual entity relationships
        - Relationship type categorization
        - Temporal state management
        - Business rule validation
    """
    # Create a second business entity for relationship testing
    target_entity = BusinessEntity(
        name='Target Business Entity',
        description='Target entity for relationship testing',
        owner_id=test_business_entity.owner_id,
        status='active',
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    db_session.session.add(target_entity)
    db_session.session.commit()
    db_session.session.refresh(target_entity)
    
    # Create relationship between entities
    relationship = EntityRelationship(
        source_entity_id=test_business_entity.id,
        target_entity_id=target_entity.id,
        relationship_type='test_relationship',
        created_at=datetime.utcnow(),
        is_active=True
    )
    
    db_session.session.add(relationship)
    db_session.session.commit()
    db_session.session.refresh(relationship)
    
    return relationship


# =====================================
# Performance Testing Fixtures
# =====================================

@pytest.fixture
def benchmark_config() -> Dict[str, Any]:
    """
    Performance testing configuration fixture for pytest-benchmark 5.1.0
    integration with Flask application performance validation.
    
    This fixture provides benchmark configuration for performance testing
    per Section 4.7.1, enabling comprehensive performance comparison against
    Node.js baseline metrics with automated threshold validation.
    
    Returns:
        Dict[str, Any]: Benchmark configuration for performance testing
        
    Features:
        - Response time measurement configuration
        - Memory usage profiling settings
        - Concurrent load testing parameters
        - Baseline comparison thresholds
        - Performance regression detection
    """
    return {
        'sort': 'mean',
        'columns': ['min', 'max', 'mean', 'stddev', 'rounds', 'iterations'],
        'disable_gc': True,
        'warmup': True,
        'warmup_iterations': 10,
        'min_rounds': 5,
        'max_time': 5.0,
        'threshold': {
            'api_response_time': 0.5,  # 500ms maximum response time
            'database_query_time': 0.2,  # 200ms maximum query time
            'memory_usage_mb': 100,  # 100MB maximum memory usage
        },
        'baseline_comparison': True,
        'regression_detection': True,
    }


@pytest.fixture
def performance_client(app: Flask, benchmark_config: Dict[str, Any]) -> FlaskClient:
    """
    Performance testing client fixture with optimized configuration
    for benchmark testing and response time measurement.
    
    This fixture provides performance-optimized test client for comprehensive
    benchmarking per Section 4.7.1, supporting pytest-benchmark integration
    with Flask application performance validation.
    
    Args:
        app: Flask application instance from app fixture
        benchmark_config: Benchmark configuration from benchmark_config fixture
        
    Returns:
        FlaskClient: Performance-optimized test client for benchmarking
        
    Features:
        - Performance monitoring integration
        - Response time measurement
        - Memory usage tracking
        - Concurrent request simulation
        - Baseline comparison support
    """
    client = app.test_client()
    
    # Configure client for performance testing
    client.benchmark_config = benchmark_config
    client.performance_mode = True
    
    return client


# =====================================
# Mock and Utility Fixtures
# =====================================

@pytest.fixture
def mock_external_service():
    """
    External service mock fixture providing simulated external API responses
    for integration testing without external dependencies.
    
    This fixture enables comprehensive integration testing by mocking external
    service dependencies, ensuring test reliability and isolation while
    validating integration patterns and error handling.
    
    Returns:
        Mock: Configured mock object for external service simulation
        
    Features:
        - API response simulation
        - Error condition testing
        - Timeout simulation
        - Rate limiting testing
        - Authentication mock support
    """
    mock_service = Mock()
    mock_service.get_data.return_value = {'status': 'success', 'data': {'test': 'value'}}
    mock_service.post_data.return_value = {'status': 'created', 'id': 123}
    mock_service.auth_validate.return_value = True
    mock_service.timeout_error = False
    mock_service.rate_limited = False
    
    return mock_service


@pytest.fixture
def temp_directory():
    """
    Temporary directory fixture for file-based testing operations
    with automatic cleanup after test completion.
    
    This fixture provides isolated file system testing environment
    for comprehensive file operation testing, configuration management,
    and log file validation with proper cleanup procedures.
    
    Yields:
        str: Path to temporary directory for testing
        
    Features:
        - Isolated file system environment
        - Automatic cleanup after tests
        - Permission management
        - File operation testing support
    """
    import tempfile
    import shutil
    
    temp_dir = tempfile.mkdtemp()
    
    yield temp_dir
    
    # Cleanup: Remove temporary directory
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def enable_db_query_tracking(app: Flask):
    """
    Database query tracking fixture for performance monitoring and
    optimization during testing phases.
    
    This auto-use fixture enables comprehensive database query tracking
    for performance analysis and optimization validation, supporting
    SQLAlchemy query optimization per Section 6.2.5.1.
    
    Args:
        app: Flask application instance from app fixture
        
    Features:
        - Query execution time tracking
        - Query count monitoring
        - N+1 query detection
        - Performance threshold validation
        - Optimization recommendation generation
    """
    if app.config.get('TESTING') and app.config.get('TRACK_QUERIES', False):
        from sqlalchemy import event
        
        queries = []
        
        @event.listens_for(Engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = datetime.utcnow()
        
        @event.listens_for(Engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            end_time = datetime.utcnow()
            start_time = getattr(context, '_query_start_time', end_time)
            execution_time = (end_time - start_time).total_seconds()
            
            queries.append({
                'statement': statement,
                'parameters': parameters,
                'execution_time': execution_time,
                'timestamp': end_time
            })
        
        # Store queries in Flask g context for test access
        with app.app_context():
            g.db_queries = queries


# =====================================
# Cleanup and Teardown Fixtures
# =====================================

@pytest.fixture(autouse=True)
def cleanup_after_test():
    """
    Automatic cleanup fixture ensuring proper resource cleanup
    after each test execution for reliable test isolation.
    
    This auto-use fixture provides comprehensive cleanup procedures
    for maintaining test isolation and preventing resource leaks
    during extensive test suite execution.
    
    Features:
        - Memory cleanup and garbage collection
        - Database connection cleanup
        - File system cleanup
        - Mock object reset
        - Context variable cleanup
    """
    yield
    
    # Cleanup operations after each test
    import gc
    
    # Clear Flask application context
    try:
        from flask import g, session
        g._get_current_object().__dict__.clear()
        session.clear()
    except RuntimeError:
        # No application context available
        pass
    
    # Force garbage collection
    gc.collect()


# =====================================
# Flask Development Server Fixtures
# =====================================

@pytest.fixture(scope='session')
def live_server(app: Flask):
    """
    Flask development server fixture for integration testing with
    live HTTP server simulation per Section 3.6.1.
    
    This session-scoped fixture provides a live Flask development server
    for comprehensive integration testing, enabling real HTTP request
    simulation and end-to-end testing capabilities.
    
    Args:
        app: Flask application instance from app fixture
        
    Yields:
        str: Live server URL for HTTP request testing
        
    Features:
        - Live HTTP server simulation
        - Real request/response testing
        - Integration testing support
        - Performance testing capabilities
        - End-to-end workflow validation
    """
    import threading
    import socket
    from werkzeug.serving import make_server
    
    # Find available port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    port = sock.getsockname()[1]
    sock.close()
    
    # Create and start server
    server = make_server('localhost', port, app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    yield f'http://localhost:{port}'
    
    # Cleanup: Shutdown server
    server.shutdown()
    server_thread.join(timeout=1)


# =====================================
# Configuration and Environment Fixtures
# =====================================

@pytest.fixture
def test_environment_variables(monkeypatch):
    """
    Test environment variables fixture for testing environment-specific
    configuration and deployment scenarios.
    
    This fixture provides controlled environment variable injection
    for comprehensive configuration testing, supporting Flask app.config
    environment-specific settings validation per Feature F-010.
    
    Args:
        monkeypatch: pytest monkeypatch fixture for environment variable injection
        
    Features:
        - Environment variable injection
        - Configuration testing support
        - Deployment scenario simulation
        - Secret management testing
        - Environment isolation validation
    """
    test_env_vars = {
        'FLASK_ENV': 'testing',
        'SECRET_KEY': 'test-secret-key-for-testing',
        'DATABASE_URL': 'sqlite:///:memory:',
        'REDIS_URL': 'redis://localhost:6379/1',
        'LOG_LEVEL': 'DEBUG',
        'TESTING': 'True',
    }
    
    for key, value in test_env_vars.items():
        monkeypatch.setenv(key, value)
    
    return test_env_vars


# Export all fixtures for easy importing
__all__ = [
    # Application fixtures
    'app_config', 'app', 'client', 'runner',
    # Database fixtures
    'db_session', 'clean_db',
    # Context fixtures
    'app_context', 'request_context', 'authenticated_request_context',
    # Blueprint fixtures
    'blueprint_client', 'api_headers', 'auth_headers',
    # Test data fixtures
    'test_user', 'test_user_session', 'test_business_entity', 'test_entity_relationship',
    # Performance fixtures
    'benchmark_config', 'performance_client',
    # Utility fixtures
    'mock_external_service', 'temp_directory',
    # Server fixtures
    'live_server',
    # Environment fixtures
    'test_environment_variables',
]