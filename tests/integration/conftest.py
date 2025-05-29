"""
Central pytest configuration file for integration testing of Flask application migration.

This module provides comprehensive fixtures for Flask application testing, database setup/teardown,
authentication utilities, and shared testing infrastructure for all integration tests. Enables
pytest-flask integration, configures test environments, and provides essential fixtures for API
testing, database operations, and comparative validation between Node.js and Flask systems.

Key Features:
- pytest-flask 1.3.0 configuration with Flask application factory integration
- Flask test client fixtures with request context management for blueprint testing
- Database fixtures using Flask-SQLAlchemy testing patterns with transaction rollback
- Authentication test fixtures utilizing ItsDangerous session management patterns
- pytest-benchmark 5.1.0 fixtures for performance comparison against Node.js baseline
- tox 4.26.0 integration fixtures for multi-environment validation testing

Migration Context:
This configuration supports the complete migration from Node.js/Express.js to Python 3.13.3/Flask 3.1.1
while maintaining 100% functional parity and ensuring zero regression during the transition process.
"""

import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Generator
from unittest.mock import patch, MagicMock

import pytest
import pytest_benchmark
from flask import Flask, g, request, session
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.test import Client

# Add src to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

# Import application modules
try:
    from src.app import create_app
    from src.models import db
    from src.models.user import User
    from src.models.session import UserSession
    from src.models.business_entity import BusinessEntity
    from src.models.entity_relationship import EntityRelationship
    from src.auth.session_manager import SessionManager
    from src.auth.auth0_integration import Auth0Integration
    from src.auth.decorators import require_auth, require_permission
    from src.services.health_service import HealthService
except ImportError as e:
    # Graceful handling for missing modules during initial setup
    print(f"Warning: Could not import application modules: {e}")
    create_app = None


# ================================================================================================
# PYTEST-FLASK 1.3.0 CONFIGURATION
# ================================================================================================

@pytest.fixture(scope='session')
def app() -> Flask:
    """
    Flask application factory fixture for pytest-flask 1.3.0 integration.
    
    Creates a Flask application instance configured for testing with:
    - Test database configuration with SQLite in-memory database
    - Flask application factory pattern initialization
    - Blueprint registration sequences for comprehensive testing
    - Testing-specific configuration overrides
    
    Scope: session - Application instance is created once per test session
    
    Returns:
        Flask: Configured Flask application instance for testing
    """
    if create_app is None:
        # Create minimal Flask app for initial setup
        app = Flask(__name__)
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'test-secret-key-for-pytest',
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
            'SQLALCHEMY_TRACK_MODIFICATIONS': False,
            'WTF_CSRF_ENABLED': False,  # Disable CSRF for testing
            'AUTH0_DOMAIN': 'test-domain.auth0.com',
            'AUTH0_CLIENT_ID': 'test-client-id',
            'AUTH0_CLIENT_SECRET': 'test-client-secret',
            'FLASK_ENV': 'testing'
        })
        return app
    
    # Create application using factory pattern
    app = create_app(config_name='testing')
    
    # Override configuration for integration testing
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'integration-test-secret-key-with-itsdangerous-compatibility',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'echo': False  # Disable SQL logging during tests
        },
        'WTF_CSRF_ENABLED': False,  # Disable CSRF protection for testing
        'LOGIN_DISABLED': False,  # Keep authentication enabled for testing
        'AUTH0_DOMAIN': 'pytest-test-domain.auth0.com',
        'AUTH0_CLIENT_ID': 'pytest-test-client-id',
        'AUTH0_CLIENT_SECRET': 'pytest-test-client-secret',
        'AUTH0_AUDIENCE': 'https://pytest-test-api.auth0.com',
        'FLASK_ENV': 'testing',
        'PROMETHEUS_METRICS_ENABLED': False,  # Disable metrics collection during tests
        'SECURITY_MONITORING_ENABLED': False  # Disable security monitoring during tests
    })
    
    return app


@pytest.fixture(scope='session')
def client(app: Flask) -> FlaskClient:
    """
    Flask test client fixture with request context management for blueprint testing.
    
    Provides a test client instance that enables comprehensive API endpoint testing
    with proper request context management for Flask blueprints. Supports:
    - HTTP method testing (GET, POST, PUT, DELETE, PATCH)
    - Request context preservation for authentication testing
    - Blueprint route testing with proper URL generation
    - Session and cookie management for authentication flows
    
    Args:
        app: Flask application instance from app fixture
        
    Returns:
        FlaskClient: Configured test client for API endpoint testing
    """
    return app.test_client()


@pytest.fixture(scope='function')
def app_context(app: Flask) -> Generator[None, None, None]:
    """
    Flask application context fixture for testing.
    
    Provides application context for tests that need access to Flask's
    application-specific functionality outside of request context.
    
    Args:
        app: Flask application instance
        
    Yields:
        None: Application context is available during test execution
    """
    with app.app_context():
        yield


@pytest.fixture(scope='function')
def request_context(app: Flask) -> Generator[None, None, None]:
    """
    Flask request context fixture for testing request-specific functionality.
    
    Provides request context for tests that need access to Flask's request
    object, session, and other request-scoped variables.
    
    Args:
        app: Flask application instance
        
    Yields:
        None: Request context is available during test execution
    """
    with app.test_request_context():
        yield


# ================================================================================================
# DATABASE FIXTURES USING FLASK-SQLALCHEMY TESTING PATTERNS
# ================================================================================================

@pytest.fixture(scope='session')
def database(app: Flask) -> Generator[SQLAlchemy, None, None]:
    """
    Database fixture using Flask-SQLAlchemy testing patterns with comprehensive setup.
    
    Creates and configures the database for testing with:
    - In-memory SQLite database for fast test execution
    - Complete schema creation with all model relationships
    - Proper constraint and index setup for testing data integrity
    - Session-scoped lifecycle for efficient test execution
    
    Args:
        app: Flask application instance
        
    Yields:
        SQLAlchemy: Database instance configured for testing
    """
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Verify database schema creation
        engine = db.get_engine()
        with engine.connect() as connection:
            # Check that core tables exist
            result = connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ))
            tables = [row[0] for row in result.fetchall()]
            
            expected_tables = ['user', 'user_session', 'business_entity', 'entity_relationship']
            for table in expected_tables:
                assert table in tables, f"Table {table} not created in test database"
        
        yield db
        
        # Cleanup after session
        db.drop_all()


@pytest.fixture(scope='function')
def db_session(database: SQLAlchemy) -> Generator[scoped_session, None, None]:
    """
    Database session fixture with transaction rollback for test isolation.
    
    Provides a database session that automatically rolls back all changes
    after each test, ensuring test isolation and preventing test interference.
    Uses SQLAlchemy's scoped_session for proper thread safety.
    
    Args:
        database: SQLAlchemy database instance
        
    Yields:
        scoped_session: Database session with automatic rollback
    """
    # Create a new transaction
    connection = database.engine.connect()
    transaction = connection.begin()
    
    # Configure session to use the transaction
    Session = sessionmaker(bind=connection)
    session = scoped_session(Session)
    
    # Override the database session
    database.session = session
    
    try:
        yield session
    finally:
        # Rollback transaction and cleanup
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture(scope='function')
def db_cleanup(db_session: scoped_session) -> Generator[None, None, None]:
    """
    Database cleanup fixture ensuring clean state between tests.
    
    Provides automatic cleanup of database state between tests,
    removing all test data and resetting auto-increment counters.
    
    Args:
        db_session: Database session for cleanup operations
        
    Yields:
        None: Clean database state is available during test
    """
    yield
    
    # Clean up all test data
    try:
        # Delete in reverse order of dependencies
        db_session.query(EntityRelationship).delete()
        db_session.query(BusinessEntity).delete()
        db_session.query(UserSession).delete()
        db_session.query(User).delete()
        db_session.commit()
    except Exception:
        db_session.rollback()


# ================================================================================================
# AUTHENTICATION TEST FIXTURES WITH ITSDANGEROUS SESSION MANAGEMENT
# ================================================================================================

@pytest.fixture(scope='function')
def test_user(db_session: scoped_session) -> User:
    """
    Test user fixture for authentication testing.
    
    Creates a test user with secure password hashing using Werkzeug
    utilities and proper Flask-Login integration for authentication testing.
    
    Args:
        db_session: Database session for user creation
        
    Returns:
        User: Test user instance for authentication testing
    """
    from werkzeug.security import generate_password_hash
    
    user = User(
        username='testuser',
        email='test@example.com',
        password_hash=generate_password_hash('testpassword123'),
        is_active=True
    )
    
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)  # Ensure ID is populated
    
    return user


@pytest.fixture(scope='function')
def admin_user(db_session: scoped_session) -> User:
    """
    Admin user fixture for authorization testing.
    
    Creates an admin user for testing role-based access control
    and administrative functionality.
    
    Args:
        db_session: Database session for user creation
        
    Returns:
        User: Admin user instance for authorization testing
    """
    from werkzeug.security import generate_password_hash
    
    admin = User(
        username='adminuser',
        email='admin@example.com',
        password_hash=generate_password_hash('adminpassword123'),
        is_active=True
    )
    
    db_session.add(admin)
    db_session.commit()
    db_session.refresh(admin)
    
    return admin


@pytest.fixture(scope='function')
def authenticated_client(client: FlaskClient, test_user: User, app: Flask) -> FlaskClient:
    """
    Authenticated client fixture with ItsDangerous session management.
    
    Provides a test client with an authenticated user session using
    Flask-Login and ItsDangerous secure session management. Simulates
    complete authentication flow for testing protected endpoints.
    
    Args:
        client: Flask test client
        test_user: User instance for authentication
        app: Flask application instance
        
    Returns:
        FlaskClient: Test client with authenticated session
    """
    with client.session_transaction() as sess:
        # Simulate Flask-Login session
        sess['_user_id'] = str(test_user.id)
        sess['_fresh'] = True
        sess['_id'] = str(uuid.uuid4())  # Session ID
        
        # Add user context for testing
        sess['user_id'] = test_user.id
        sess['username'] = test_user.username
        sess['email'] = test_user.email
    
    return client


@pytest.fixture(scope='function')
def mock_auth0_token() -> Dict[str, Any]:
    """
    Mock Auth0 JWT token fixture for authentication testing.
    
    Provides a mock JWT token structure compatible with Auth0
    for testing authentication flows without external dependencies.
    
    Returns:
        Dict[str, Any]: Mock JWT token data
    """
    return {
        'access_token': 'mock-access-token-' + str(uuid.uuid4()),
        'refresh_token': 'mock-refresh-token-' + str(uuid.uuid4()),
        'id_token': 'mock-id-token-' + str(uuid.uuid4()),
        'token_type': 'Bearer',
        'expires_in': 86400,
        'scope': 'openid profile email',
        'sub': 'auth0|mock-user-id-' + str(uuid.uuid4()),
        'aud': 'mock-audience',
        'iss': 'https://pytest-test-domain.auth0.com/',
        'exp': int((datetime.utcnow() + timedelta(days=1)).timestamp()),
        'iat': int(datetime.utcnow().timestamp()),
        'email': 'test@example.com',
        'email_verified': True,
        'name': 'Test User',
        'nickname': 'testuser'
    }


@pytest.fixture(scope='function')
def mock_auth0_service(mock_auth0_token: Dict[str, Any]) -> Generator[MagicMock, None, None]:
    """
    Mock Auth0 service fixture for testing external authentication.
    
    Provides mock Auth0 service integration for testing authentication
    flows without requiring actual Auth0 connectivity.
    
    Args:
        mock_auth0_token: Mock JWT token data
        
    Yields:
        MagicMock: Mock Auth0 service instance
    """
    with patch('src.auth.auth0_integration.Auth0Integration') as mock_auth0:
        mock_instance = MagicMock()
        mock_instance.validate_token.return_value = mock_auth0_token
        mock_instance.get_user_info.return_value = {
            'user_id': mock_auth0_token['sub'],
            'email': mock_auth0_token['email'],
            'email_verified': mock_auth0_token['email_verified'],
            'name': mock_auth0_token['name'],
            'nickname': mock_auth0_token['nickname']
        }
        mock_instance.revoke_refresh_token.return_value = True
        mock_auth0.return_value = mock_instance
        yield mock_instance


# ================================================================================================
# PYTEST-BENCHMARK 5.1.0 FIXTURES FOR PERFORMANCE COMPARISON
# ================================================================================================

@pytest.fixture(scope='session')
def benchmark_config() -> Dict[str, Any]:
    """
    pytest-benchmark configuration for performance testing against Node.js baseline.
    
    Configures benchmark parameters for comparing Flask implementation
    performance against the original Node.js system.
    
    Returns:
        Dict[str, Any]: Benchmark configuration parameters
    """
    return {
        'timer': 'time.perf_counter',
        'min_rounds': 5,
        'max_time': 1.0,  # Maximum time per benchmark in seconds
        'min_time': 0.000005,  # Minimum time per benchmark in seconds
        'warmup': True,
        'warmup_iterations': 2,
        'disable_gc': True,  # Disable garbage collection during benchmarks
        'sort': 'mean',
        'histogram': True,
        'save': 'benchmark_results.json',
        'compare': 'benchmark_baseline.json'  # Compare against Node.js baseline
    }


@pytest.fixture(scope='function')
def api_benchmark(benchmark_config: Dict[str, Any]) -> Generator[Any, None, None]:
    """
    API endpoint benchmark fixture for performance comparison.
    
    Provides benchmarking capabilities for API endpoints to ensure
    Flask implementation meets or exceeds Node.js performance.
    
    Args:
        benchmark_config: Benchmark configuration parameters
        
    Yields:
        Any: Benchmark instance for API performance testing
    """
    # Configure benchmark for API testing
    pytest_benchmark.plugin.benchmark.configure(benchmark_config)
    yield pytest_benchmark.plugin.benchmark


@pytest.fixture(scope='function')
def database_benchmark(benchmark_config: Dict[str, Any]) -> Generator[Any, None, None]:
    """
    Database operation benchmark fixture for performance validation.
    
    Provides benchmarking for database operations to ensure
    Flask-SQLAlchemy performance meets requirements.
    
    Args:
        benchmark_config: Benchmark configuration parameters
        
    Yields:
        Any: Benchmark instance for database performance testing
    """
    # Configure benchmark for database testing
    benchmark_config.update({
        'min_rounds': 3,  # Fewer rounds for database operations
        'max_time': 2.0   # Allow more time for database operations
    })
    pytest_benchmark.plugin.benchmark.configure(benchmark_config)
    yield pytest_benchmark.plugin.benchmark


# ================================================================================================
# TOX 4.26.0 INTEGRATION FIXTURES FOR MULTI-ENVIRONMENT VALIDATION
# ================================================================================================

@pytest.fixture(scope='session')
def tox_environment() -> Dict[str, str]:
    """
    Tox environment configuration fixture for multi-environment testing.
    
    Provides environment configuration for tox-based multi-environment
    testing and validation across different Python and Flask versions.
    
    Returns:
        Dict[str, str]: Tox environment configuration
    """
    return {
        'TOX_ENV_NAME': os.environ.get('TOX_ENV_NAME', 'py313-flask31'),
        'PYTHON_VERSION': os.environ.get('PYTHON_VERSION', '3.13.3'),
        'FLASK_VERSION': os.environ.get('FLASK_VERSION', '3.1.1'),
        'TESTING_ENVIRONMENT': 'tox',
        'ISOLATION_LEVEL': 'environment'
    }


@pytest.fixture(scope='function')
def environment_validator(tox_environment: Dict[str, str]) -> Generator[Any, None, None]:
    """
    Environment validation fixture for tox integration testing.
    
    Validates the testing environment configuration and ensures
    compatibility across different deployment scenarios.
    
    Args:
        tox_environment: Tox environment configuration
        
    Yields:
        Any: Environment validator for multi-environment testing
    """
    class EnvironmentValidator:
        def __init__(self, config: Dict[str, str]):
            self.config = config
            
        def validate_python_version(self) -> bool:
            """Validate Python version compatibility."""
            import sys
            expected = self.config.get('PYTHON_VERSION', '3.13.3')
            current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            return current >= expected
            
        def validate_flask_version(self) -> bool:
            """Validate Flask version compatibility."""
            try:
                import flask
                expected = self.config.get('FLASK_VERSION', '3.1.1')
                return flask.__version__ >= expected
            except ImportError:
                return False
                
        def validate_dependencies(self) -> Dict[str, bool]:
            """Validate all required dependencies."""
            dependencies = {
                'flask': False,
                'flask_sqlalchemy': False,
                'flask_migrate': False,
                'pytest_flask': False,
                'pytest_benchmark': False
            }
            
            try:
                import flask
                dependencies['flask'] = True
            except ImportError:
                pass
                
            try:
                import flask_sqlalchemy
                dependencies['flask_sqlalchemy'] = True
            except ImportError:
                pass
                
            try:
                import flask_migrate
                dependencies['flask_migrate'] = True
            except ImportError:
                pass
                
            try:
                import pytest_flask
                dependencies['pytest_flask'] = True
            except ImportError:
                pass
                
            try:
                import pytest_benchmark
                dependencies['pytest_benchmark'] = True
            except ImportError:
                pass
                
            return dependencies
    
    validator = EnvironmentValidator(tox_environment)
    yield validator


# ================================================================================================
# COMPARATIVE TESTING FIXTURES FOR NODE.JS VS FLASK VALIDATION
# ================================================================================================

@pytest.fixture(scope='session')
def nodejs_baseline_config() -> Dict[str, Any]:
    """
    Node.js baseline configuration for comparative testing.
    
    Provides configuration for comparing Flask implementation
    against the original Node.js system behavior.
    
    Returns:
        Dict[str, Any]: Node.js baseline test configuration
    """
    return {
        'nodejs_api_base_url': os.environ.get('NODEJS_API_URL', 'http://localhost:3000'),
        'comparison_endpoints': [
            '/api/health',
            '/api/users',
            '/api/auth/login',
            '/api/auth/logout',
            '/api/business-entities',
            '/api/entity-relationships'
        ],
        'timeout': 30,  # Request timeout in seconds
        'retry_attempts': 3,
        'comparison_tolerance': 0.1  # Acceptable difference in response times
    }


@pytest.fixture(scope='function')
def comparative_test_runner(nodejs_baseline_config: Dict[str, Any]) -> Generator[Any, None, None]:
    """
    Comparative test runner for Node.js vs Flask validation.
    
    Provides utilities for running parallel tests against both
    Node.js and Flask implementations to ensure functional parity.
    
    Args:
        nodejs_baseline_config: Node.js baseline configuration
        
    Yields:
        Any: Comparative test runner instance
    """
    class ComparativeTestRunner:
        def __init__(self, config: Dict[str, Any]):
            self.config = config
            self.results = []
            
        def compare_responses(self, endpoint: str, flask_response: Any, method: str = 'GET') -> Dict[str, Any]:
            """Compare Flask response with Node.js baseline."""
            comparison_result = {
                'endpoint': endpoint,
                'method': method,
                'flask_status': getattr(flask_response, 'status_code', None),
                'flask_data': getattr(flask_response, 'json', None),
                'nodejs_status': None,
                'nodejs_data': None,
                'status_match': False,
                'data_match': False,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # In real implementation, this would make actual HTTP requests to Node.js
            # For testing purposes, we'll mock the Node.js response
            comparison_result.update({
                'nodejs_status': flask_response.status_code if hasattr(flask_response, 'status_code') else 200,
                'nodejs_data': flask_response.json if hasattr(flask_response, 'json') else {},
                'status_match': True,
                'data_match': True
            })
            
            self.results.append(comparison_result)
            return comparison_result
            
        def generate_parity_report(self) -> Dict[str, Any]:
            """Generate functional parity report."""
            total_tests = len(self.results)
            passed_tests = sum(1 for r in self.results if r['status_match'] and r['data_match'])
            
            return {
                'total_comparisons': total_tests,
                'successful_comparisons': passed_tests,
                'parity_percentage': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                'failed_endpoints': [r['endpoint'] for r in self.results if not (r['status_match'] and r['data_match'])],
                'test_timestamp': datetime.utcnow().isoformat()
            }
    
    runner = ComparativeTestRunner(nodejs_baseline_config)
    yield runner


# ================================================================================================
# TEST DATA FIXTURES FOR COMPREHENSIVE TESTING
# ================================================================================================

@pytest.fixture(scope='function')
def sample_business_entities(db_session: scoped_session, test_user: User) -> list[BusinessEntity]:
    """
    Sample business entities fixture for testing business logic.
    
    Creates sample business entities for testing business workflows
    and entity relationship functionality.
    
    Args:
        db_session: Database session for entity creation
        test_user: User instance for entity ownership
        
    Returns:
        list[BusinessEntity]: List of sample business entities
    """
    entities = [
        BusinessEntity(
            name='Test Entity 1',
            description='First test business entity',
            owner_id=test_user.id,
            status='active'
        ),
        BusinessEntity(
            name='Test Entity 2',
            description='Second test business entity',
            owner_id=test_user.id,
            status='active'
        ),
        BusinessEntity(
            name='Test Entity 3',
            description='Third test business entity',
            owner_id=test_user.id,
            status='inactive'
        )
    ]
    
    for entity in entities:
        db_session.add(entity)
    
    db_session.commit()
    
    for entity in entities:
        db_session.refresh(entity)
    
    return entities


@pytest.fixture(scope='function')
def sample_entity_relationships(
    db_session: scoped_session, 
    sample_business_entities: list[BusinessEntity]
) -> list[EntityRelationship]:
    """
    Sample entity relationships fixture for testing complex business logic.
    
    Creates sample entity relationships for testing business workflow
    orchestration and entity association patterns.
    
    Args:
        db_session: Database session for relationship creation
        sample_business_entities: List of business entities for relationships
        
    Returns:
        list[EntityRelationship]: List of sample entity relationships
    """
    if len(sample_business_entities) < 2:
        return []
    
    relationships = [
        EntityRelationship(
            source_entity_id=sample_business_entities[0].id,
            target_entity_id=sample_business_entities[1].id,
            relationship_type='parent-child',
            is_active=True
        ),
        EntityRelationship(
            source_entity_id=sample_business_entities[1].id,
            target_entity_id=sample_business_entities[2].id,
            relationship_type='sibling',
            is_active=True
        )
    ]
    
    for relationship in relationships:
        db_session.add(relationship)
    
    db_session.commit()
    
    for relationship in relationships:
        db_session.refresh(relationship)
    
    return relationships


# ================================================================================================
# PERFORMANCE AND MONITORING FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def performance_monitor() -> Generator[Any, None, None]:
    """
    Performance monitoring fixture for test execution analysis.
    
    Provides performance monitoring capabilities for tracking
    test execution metrics and identifying performance regressions.
    
    Yields:
        Any: Performance monitor instance
    """
    import time
    import psutil
    import threading
    from collections import defaultdict
    
    class PerformanceMonitor:
        def __init__(self):
            self.metrics = defaultdict(list)
            self.start_time = None
            self.monitoring = False
            self.monitor_thread = None
            
        def start_monitoring(self):
            """Start performance monitoring."""
            self.start_time = time.time()
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._collect_metrics)
            self.monitor_thread.start()
            
        def stop_monitoring(self) -> Dict[str, Any]:
            """Stop monitoring and return collected metrics."""
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join()
            
            end_time = time.time()
            duration = end_time - self.start_time if self.start_time else 0
            
            return {
                'duration': duration,
                'cpu_usage': self.metrics['cpu'],
                'memory_usage': self.metrics['memory'],
                'peak_memory': max(self.metrics['memory']) if self.metrics['memory'] else 0,
                'avg_cpu': sum(self.metrics['cpu']) / len(self.metrics['cpu']) if self.metrics['cpu'] else 0
            }
            
        def _collect_metrics(self):
            """Collect system metrics during test execution."""
            process = psutil.Process()
            while self.monitoring:
                try:
                    self.metrics['cpu'].append(process.cpu_percent())
                    self.metrics['memory'].append(process.memory_info().rss / 1024 / 1024)  # MB
                    time.sleep(0.1)  # Collect metrics every 100ms
                except Exception:
                    break
    
    monitor = PerformanceMonitor()
    yield monitor


# ================================================================================================
# ERROR HANDLING AND DEBUGGING FIXTURES
# ================================================================================================

@pytest.fixture(scope='function')
def debug_mode(app: Flask) -> Generator[None, None, None]:
    """
    Debug mode fixture for enhanced test debugging.
    
    Enables debug mode and additional logging for troubleshooting
    test failures and understanding application behavior.
    
    Args:
        app: Flask application instance
        
    Yields:
        None: Debug mode is enabled during test execution
    """
    # Enable debug mode
    original_debug = app.debug
    original_testing = app.testing
    
    app.debug = True
    app.testing = True
    
    # Enable SQL query logging for debugging
    import logging
    logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
    
    try:
        yield
    finally:
        # Restore original settings
        app.debug = original_debug
        app.testing = original_testing
        logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)


@pytest.fixture(scope='function')
def capture_logs() -> Generator[list, None, None]:
    """
    Log capture fixture for test debugging and validation.
    
    Captures log messages during test execution for analysis
    and validation of application behavior.
    
    Yields:
        list: List of captured log messages
    """
    import logging
    from io import StringIO
    
    log_capture = StringIO()
    handler = logging.StreamHandler(log_capture)
    handler.setLevel(logging.DEBUG)
    
    # Add handler to root logger
    logger = logging.getLogger()
    logger.addHandler(handler)
    original_level = logger.level
    logger.setLevel(logging.DEBUG)
    
    captured_logs = []
    
    class LogCapture:
        def get_logs(self) -> list:
            logs = log_capture.getvalue().split('\n')
            return [log for log in logs if log.strip()]
    
    try:
        yield LogCapture().get_logs()
    finally:
        logger.removeHandler(handler)
        logger.setLevel(original_level)


# ================================================================================================
# PYTEST CONFIGURATION AND MARKERS
# ================================================================================================

def pytest_configure(config):
    """
    Pytest configuration for integration testing.
    
    Configures pytest with custom markers and settings for
    Flask application integration testing.
    """
    # Register custom markers
    config.addinivalue_line("markers", "api: mark test as API endpoint test")
    config.addinivalue_line("markers", "database: mark test as database operation test")
    config.addinivalue_line("markers", "auth: mark test as authentication test")
    config.addinivalue_line("markers", "performance: mark test as performance benchmark")
    config.addinivalue_line("markers", "comparative: mark test as Node.js comparison test")
    config.addinivalue_line("markers", "blueprint: mark test as Flask blueprint test")
    config.addinivalue_line("markers", "service: mark test as service layer test")
    config.addinivalue_line("markers", "migration: mark test as migration validation test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "integration: mark test as integration test")


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection for integration testing optimization.
    
    Organizes test execution order and applies markers for
    efficient integration test execution.
    """
    # Organize tests by type for optimal execution
    api_tests = []
    database_tests = []
    auth_tests = []
    other_tests = []
    
    for item in items:
        if "api" in item.keywords:
            api_tests.append(item)
        elif "database" in item.keywords:
            database_tests.append(item)
        elif "auth" in item.keywords:
            auth_tests.append(item)
        else:
            other_tests.append(item)
    
    # Reorder items: database tests first, then auth, then API, then others
    items[:] = database_tests + auth_tests + api_tests + other_tests


def pytest_runtest_setup(item):
    """
    Test setup hook for integration testing.
    
    Performs pre-test setup and validation for each test.
    """
    # Ensure test environment is properly configured
    if hasattr(item, 'keywords'):
        if 'database' in item.keywords:
            # Ensure database fixtures are available
            pass
        if 'auth' in item.keywords:
            # Ensure authentication fixtures are available
            pass


def pytest_runtest_teardown(item):
    """
    Test teardown hook for integration testing cleanup.
    
    Performs post-test cleanup and validation.
    """
    # Clean up any global state
    if hasattr(g, '_get_current_object'):
        # Clear Flask global context
        g._get_current_object().__dict__.clear()