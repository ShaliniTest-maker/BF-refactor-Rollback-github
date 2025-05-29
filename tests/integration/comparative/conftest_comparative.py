"""
Specialized pytest configuration file providing comparative testing fixtures, dual-system setup utilities,
and shared testing infrastructure specifically for side-by-side validation between Node.js and Flask systems.

This module enables simultaneous Node.js and Flask testing environments, configures baseline capture mechanisms,
and provides essential fixtures for comparative validation workflows per Section 4.7.1 and 4.7.2 requirements.

Key Capabilities:
- pytest-flask 1.3.0 comparative testing fixtures with dual-system support
- Node.js baseline system connection and Flask test environment initialization
- Comparative database fixtures with transaction isolation for both systems
- Authentication test fixtures for cross-system session and security compatibility
- pytest-benchmark 5.1.0 comparative fixtures for performance baseline comparison
- Tox 4.26.0 integration fixtures for multi-environment comparative testing orchestration

Dependencies:
- Flask 3.1.1 application factory pattern for test client initialization
- Flask-SQLAlchemy 3.1.1 for database testing with PostgreSQL 15.x
- pytest-flask 1.3.0 for Flask-specific testing capabilities
- pytest-benchmark 5.1.0 for performance comparison and baseline validation
- Auth0 Python SDK 4.9.0 for authentication system testing
- Flask-Login for session management testing
- Prometheus client for metrics collection during testing

References:
- Section 4.7.1: pytest-flask Plugin Configuration
- Section 4.7.2: Comparative Testing Process
- Section 6.4.1: Authentication Framework
- Section 6.2.1: Database Technology Transition
- Feature F-009: Functionality Parity Validation Process
"""

import os
import sys
import time
import json
import uuid
import subprocess
import threading
import logging
from typing import Dict, Any, Optional, List, Tuple, Generator
from contextlib import contextmanager
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

import pytest
import requests
import psutil
from flask import Flask, g, current_app
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
import redis
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge
import structlog

# Flask application and extension imports
from src import create_app
from src.models import db, User, UserSession, BusinessEntity, EntityRelationship
from src.auth import AuthenticationService, SessionManager, Auth0Integration
from src.services import WorkflowOrchestrationService

# Testing framework imports
try:
    import pytest_flask
    import pytest_benchmark
    import pytest_xdist
except ImportError as e:
    raise ImportError(f"Required testing dependencies not available: {e}")

# Configure structured logging for test environment
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.WriteLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("comparative_testing")


# =============================================================================
# Configuration and Constants
# =============================================================================

class ComparativeTestConfig:
    """Configuration class for comparative testing environments and thresholds."""
    
    # Node.js baseline system configuration
    NODEJS_BASE_URL = os.getenv('NODEJS_BASE_URL', 'http://localhost:3000')
    NODEJS_TIMEOUT = int(os.getenv('NODEJS_TIMEOUT', '30'))
    NODEJS_HEALTH_ENDPOINT = '/health'
    
    # Flask test system configuration
    FLASK_ENV = 'testing'
    FLASK_SECRET_KEY = 'test-secret-key-for-comparative-testing'
    FLASK_WTF_CSRF_ENABLED = False  # Disabled for testing
    
    # Test database configuration
    TEST_DATABASE_URL = os.getenv(
        'TEST_DATABASE_URL',
        'postgresql+psycopg2://test_user:test_pass@localhost:5432/test_db'
    )
    
    # Performance baseline thresholds per Section 4.7.1
    PERFORMANCE_THRESHOLDS = {
        'simple_query_95th_percentile': 0.5,  # 500ms
        'complex_query_95th_percentile': 2.0,  # 2000ms
        'api_response_95th_percentile': 1.0,   # 1000ms
        'memory_usage_threshold': 0.85,        # 85% max
        'error_rate_threshold': 0.05,          # 5% max
    }
    
    # Authentication testing configuration
    AUTH0_TEST_DOMAIN = os.getenv('AUTH0_TEST_DOMAIN', 'test-domain.auth0.com')
    AUTH0_TEST_CLIENT_ID = os.getenv('AUTH0_TEST_CLIENT_ID', 'test-client-id')
    AUTH0_TEST_CLIENT_SECRET = os.getenv('AUTH0_TEST_CLIENT_SECRET', 'test-secret')
    
    # Redis configuration for session testing
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/1')
    
    # Prometheus metrics configuration
    PROMETHEUS_REGISTRY = CollectorRegistry()
    
    # Tox environment configuration
    TOX_ENVIRONMENTS = ['py313-flask31', 'py313-comparative', 'py313-benchmark']


# =============================================================================
# Pytest Configuration Hooks
# =============================================================================

def pytest_configure(config):
    """Configure pytest with comparative testing markers and options."""
    config.addinivalue_line(
        "markers", 
        "comparative: mark test as comparative between Node.js and Flask systems"
    )
    config.addinivalue_line(
        "markers",
        "baseline: mark test as Node.js baseline capture"
    )
    config.addinivalue_line(
        "markers",
        "performance: mark test as performance comparison"
    )
    config.addinivalue_line(
        "markers",
        "authentication: mark test as authentication system comparison"
    )
    config.addinivalue_line(
        "markers",
        "database: mark test as database operation comparison"
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running (> 5 seconds)"
    )
    
    # Configure comparative testing session data
    config._comparative_session_data = {
        'start_time': datetime.utcnow(),
        'test_results': [],
        'baseline_data': {},
        'metrics_registry': ComparativeTestConfig.PROMETHEUS_REGISTRY
    }


def pytest_sessionstart(session):
    """Initialize comparative testing session with baseline capture."""
    logger.info("Starting comparative testing session", 
                config=ComparativeTestConfig.__dict__)
    
    # Initialize Prometheus metrics for comparative testing
    session.config._comparative_metrics = {
        'test_duration': Histogram(
            'comparative_test_duration_seconds',
            'Duration of comparative tests',
            ['test_type', 'system'],
            registry=ComparativeTestConfig.PROMETHEUS_REGISTRY
        ),
        'test_results': Counter(
            'comparative_test_results_total',
            'Results of comparative tests',
            ['test_type', 'result', 'system'],
            registry=ComparativeTestConfig.PROMETHEUS_REGISTRY
        ),
        'performance_delta': Histogram(
            'comparative_performance_delta_seconds',
            'Performance difference between systems',
            ['endpoint', 'metric_type'],
            registry=ComparativeTestConfig.PROMETHEUS_REGISTRY
        )
    }


def pytest_sessionfinish(session, exitstatus):
    """Finalize comparative testing session with report generation."""
    session_data = session.config._comparative_session_data
    end_time = datetime.utcnow()
    duration = (end_time - session_data['start_time']).total_seconds()
    
    logger.info("Comparative testing session completed",
                duration_seconds=duration,
                exit_status=exitstatus,
                total_tests=len(session_data['test_results']))


# =============================================================================
# Flask Application Fixtures
# =============================================================================

@pytest.fixture(scope='session')
def comparative_flask_app():
    """
    Create Flask application instance configured for comparative testing.
    
    Provides Flask 3.1.1 application factory pattern with test-specific configuration
    including database isolation, authentication mocking, and monitoring integration.
    
    References:
    - Section 4.7.1: Flask application factory integration for test client initialization
    - Section 5.1.1: Flask application factory pattern
    """
    # Configure test environment variables
    test_config = {
        'TESTING': True,
        'ENV': 'testing',
        'SECRET_KEY': ComparativeTestConfig.FLASK_SECRET_KEY,
        'WTF_CSRF_ENABLED': ComparativeTestConfig.FLASK_WTF_CSRF_ENABLED,
        'SQLALCHEMY_DATABASE_URI': ComparativeTestConfig.TEST_DATABASE_URL,
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'echo': False
        },
        'AUTH0_DOMAIN': ComparativeTestConfig.AUTH0_TEST_DOMAIN,
        'AUTH0_CLIENT_ID': ComparativeTestConfig.AUTH0_TEST_CLIENT_ID,
        'AUTH0_CLIENT_SECRET': ComparativeTestConfig.AUTH0_TEST_CLIENT_SECRET,
        'REDIS_URL': ComparativeTestConfig.REDIS_URL,
        'PROMETHEUS_METRICS_ENABLED': True
    }
    
    logger.info("Creating Flask application for comparative testing",
                config_keys=list(test_config.keys()))
    
    # Create Flask application with test configuration
    app = create_app(config_override=test_config)
    
    with app.app_context():
        # Initialize database tables for testing
        db.create_all()
        
        # Initialize authentication services
        app.auth_service = AuthenticationService(app)
        app.session_manager = SessionManager(app)
        app.auth0_integration = Auth0Integration(app)
        
        logger.info("Flask application created for comparative testing",
                    tables_created=len(db.metadata.tables))
    
    yield app
    
    # Cleanup
    with app.app_context():
        db.drop_all()
        db.session.remove()


@pytest.fixture(scope='function')
def comparative_client(comparative_flask_app):
    """
    Create Flask test client for comparative testing with request context management.
    
    Provides pytest-flask 1.3.0 integration with comprehensive request context setup
    and automatic cleanup for consistent test environment isolation.
    
    References:
    - Section 4.7.1: pytest-flask Plugin Configuration
    - Section 4.7.1: Request context management for session and authentication testing
    """
    with comparative_flask_app.test_client() as client:
        with comparative_flask_app.app_context():
            # Initialize request context for testing
            g.request_id = str(uuid.uuid4())
            g.test_mode = True
            g.comparative_testing = True
            
            logger.info("Flask test client created",
                        request_id=g.request_id,
                        client_type='comparative')
            
            yield client


@pytest.fixture(scope='function')
def comparative_flask_context(comparative_flask_app):
    """
    Provide Flask application context for comparative testing operations.
    
    Enables direct access to Flask application context for service layer testing,
    database operations, and authentication system validation.
    """
    with comparative_flask_app.app_context():
        g.request_id = str(uuid.uuid4())
        g.test_mode = True
        g.comparative_testing = True
        
        yield comparative_flask_app


# =============================================================================
# Node.js Baseline System Fixtures
# =============================================================================

class NodeJSBaselineClient:
    """
    Client for interacting with Node.js baseline system during comparative testing.
    
    Provides comprehensive API interaction capabilities including request/response capture,
    performance metrics collection, and baseline data storage for comparative validation.
    """
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Flask-Comparative-Testing/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self._connection_validated = False
        
    def validate_connection(self) -> bool:
        """Validate connection to Node.js baseline system."""
        try:
            response = self.session.get(
                f"{self.base_url}{ComparativeTestConfig.NODEJS_HEALTH_ENDPOINT}",
                timeout=self.timeout
            )
            self._connection_validated = response.status_code == 200
            
            logger.info("Node.js baseline connection validation",
                        status_code=response.status_code,
                        success=self._connection_validated)
            
            return self._connection_validated
        except Exception as e:
            logger.error("Failed to connect to Node.js baseline system",
                         error=str(e), base_url=self.base_url)
            return False
    
    def make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make request to Node.js baseline system with comprehensive response capture.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint path
            **kwargs: Additional request parameters
            
        Returns:
            Dict containing response data, timing, and metadata
        """
        if not self._connection_validated:
            raise RuntimeError("Node.js baseline connection not validated")
        
        url = f"{self.base_url}{endpoint}"
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            end_time = time.time()
            
            # Capture comprehensive response data
            baseline_data = {
                'request': {
                    'method': method.upper(),
                    'url': url,
                    'headers': dict(kwargs.get('headers', {})),
                    'data': kwargs.get('json') or kwargs.get('data'),
                    'params': kwargs.get('params'),
                    'timestamp': datetime.utcnow().isoformat()
                },
                'response': {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_type': response.headers.get('content-type'),
                    'data': None,
                    'size_bytes': len(response.content)
                },
                'performance': {
                    'duration_seconds': end_time - start_time,
                    'start_time': start_time,
                    'end_time': end_time
                },
                'metadata': {
                    'baseline_system': 'nodejs',
                    'endpoint': endpoint,
                    'success': response.status_code < 400
                }
            }
            
            # Parse response data based on content type
            try:
                if 'application/json' in response.headers.get('content-type', ''):
                    baseline_data['response']['data'] = response.json()
                else:
                    baseline_data['response']['data'] = response.text
            except Exception as parse_error:
                baseline_data['response']['data'] = response.text
                baseline_data['metadata']['parse_error'] = str(parse_error)
            
            logger.info("Node.js baseline request completed",
                        method=method, endpoint=endpoint,
                        status_code=response.status_code,
                        duration=baseline_data['performance']['duration_seconds'])
            
            return baseline_data
            
        except Exception as e:
            end_time = time.time()
            logger.error("Node.js baseline request failed",
                         method=method, endpoint=endpoint, error=str(e))
            
            return {
                'request': {
                    'method': method.upper(),
                    'url': url,
                    'timestamp': datetime.utcnow().isoformat()
                },
                'response': None,
                'performance': {
                    'duration_seconds': end_time - start_time,
                    'start_time': start_time,
                    'end_time': end_time
                },
                'metadata': {
                    'baseline_system': 'nodejs',
                    'endpoint': endpoint,
                    'success': False,
                    'error': str(e)
                }
            }


@pytest.fixture(scope='session')
def nodejs_baseline_client():
    """
    Create Node.js baseline system client for comparative testing.
    
    Provides connection validation and request/response capture capabilities
    for establishing ground truth data during comparative validation.
    
    References:
    - Section 4.7.2: Node.js baseline connection establishment
    - Section 4.7.2: Baseline comparison against Node.js system performance metrics
    """
    client = NodeJSBaselineClient(
        base_url=ComparativeTestConfig.NODEJS_BASE_URL,
        timeout=ComparativeTestConfig.NODEJS_TIMEOUT
    )
    
    # Validate connection to Node.js system
    if not client.validate_connection():
        pytest.skip("Node.js baseline system not available for comparative testing")
    
    logger.info("Node.js baseline client initialized",
                base_url=client.base_url)
    
    yield client


@pytest.fixture(scope='function')
def baseline_capture_session(nodejs_baseline_client):
    """
    Create baseline capture session for individual test functions.
    
    Provides isolated baseline data capture with automatic cleanup
    and session-specific data management.
    """
    session_id = str(uuid.uuid4())
    session_data = {
        'session_id': session_id,
        'start_time': datetime.utcnow(),
        'captured_baselines': {},
        'client': nodejs_baseline_client
    }
    
    logger.info("Baseline capture session started", session_id=session_id)
    
    yield session_data
    
    session_data['end_time'] = datetime.utcnow()
    logger.info("Baseline capture session completed",
                session_id=session_id,
                baselines_captured=len(session_data['captured_baselines']))


# =============================================================================
# Database Testing Fixtures
# =============================================================================

@pytest.fixture(scope='function')
def comparative_db_session(comparative_flask_app):
    """
    Create isolated database session for comparative testing with transaction isolation.
    
    Provides Flask-SQLAlchemy 3.1.1 session management with automatic rollback
    for test isolation and consistent database state across comparative tests.
    
    References:
    - Section 6.2.1: PostgreSQL 15.x with Flask-SQLAlchemy 3.1.1 integration
    - Section 4.7.2: Database fixtures with transaction isolation for both systems
    """
    with comparative_flask_app.app_context():
        # Create nested transaction for test isolation
        connection = db.engine.connect()
        transaction = connection.begin()
        
        # Create scoped session for test
        session_factory = sessionmaker(bind=connection)
        test_session = scoped_session(session_factory)
        
        # Replace default session with test session
        original_session = db.session
        db.session = test_session
        
        logger.info("Comparative database session created",
                    isolation_level='READ_COMMITTED',
                    transaction_id=id(transaction))
        
        try:
            yield test_session
        finally:
            # Rollback transaction and restore original session
            test_session.remove()
            transaction.rollback()
            connection.close()
            db.session = original_session
            
            logger.info("Comparative database session cleaned up",
                        transaction_id=id(transaction))


@pytest.fixture(scope='function')
def comparative_test_data(comparative_db_session):
    """
    Create standardized test data for comparative testing across both systems.
    
    Provides consistent test data sets that can be used for validation
    between Node.js and Flask implementations with proper relationship mapping.
    
    References:
    - Section 6.2.2.1: Entity Relationships and Data Models
    - Feature F-003: Database Model Conversion
    """
    test_data = {}
    
    # Create test users
    test_users = [
        User(
            username='comparative_user_1',
            email='user1@comparative.test',
            password_hash='test_hash_1',
            is_active=True
        ),
        User(
            username='comparative_user_2',
            email='user2@comparative.test',
            password_hash='test_hash_2',
            is_active=True
        )
    ]
    
    for user in test_users:
        comparative_db_session.add(user)
    comparative_db_session.flush()  # Get IDs without committing
    
    test_data['users'] = test_users
    
    # Create test business entities
    test_entities = [
        BusinessEntity(
            name='Test Entity 1',
            description='Comparative testing entity 1',
            owner_id=test_users[0].id,
            status='active'
        ),
        BusinessEntity(
            name='Test Entity 2',
            description='Comparative testing entity 2',
            owner_id=test_users[1].id,
            status='active'
        )
    ]
    
    for entity in test_entities:
        comparative_db_session.add(entity)
    comparative_db_session.flush()
    
    test_data['entities'] = test_entities
    
    # Create test entity relationships
    test_relationship = EntityRelationship(
        source_entity_id=test_entities[0].id,
        target_entity_id=test_entities[1].id,
        relationship_type='comparative_test',
        is_active=True
    )
    
    comparative_db_session.add(test_relationship)
    comparative_db_session.flush()
    
    test_data['relationships'] = [test_relationship]
    
    # Create test sessions
    test_sessions = [
        UserSession(
            user_id=test_users[0].id,
            session_token='test_token_1',
            expires_at=datetime.utcnow() + timedelta(hours=24),
            is_valid=True
        ),
        UserSession(
            user_id=test_users[1].id,
            session_token='test_token_2',
            expires_at=datetime.utcnow() + timedelta(hours=24),
            is_valid=True
        )
    ]
    
    for session in test_sessions:
        comparative_db_session.add(session)
    comparative_db_session.flush()
    
    test_data['sessions'] = test_sessions
    
    logger.info("Comparative test data created",
                users=len(test_data['users']),
                entities=len(test_data['entities']),
                relationships=len(test_data['relationships']),
                sessions=len(test_data['sessions']))
    
    yield test_data
    
    # Cleanup handled by database session fixture rollback


@pytest.fixture(scope='function') 
def database_performance_monitor(comparative_db_session):
    """
    Monitor database performance during comparative testing.
    
    Provides SQLAlchemy query monitoring and PostgreSQL performance metrics
    collection for database operation comparison between systems.
    
    References:
    - Section 6.2.1: PostgreSQL query performance tracking
    - Section 4.7.1: Database query performance benchmarking with SQLAlchemy optimization
    """
    performance_data = {
        'queries': [],
        'start_time': time.time(),
        'monitoring_active': True
    }
    
    # SQL query event listener for performance tracking
    def query_listener(conn, cursor, statement, parameters, context, executemany):
        if performance_data['monitoring_active']:
            query_start = time.time()
            context._query_start_time = query_start
    
    def query_end_listener(conn, cursor, statement, parameters, context, executemany):
        if performance_data['monitoring_active'] and hasattr(context, '_query_start_time'):
            duration = time.time() - context._query_start_time
            performance_data['queries'].append({
                'statement': statement,
                'parameters': parameters,
                'duration_seconds': duration,
                'timestamp': datetime.utcnow().isoformat(),
                'executemany': executemany
            })
    
    # Register event listeners
    from sqlalchemy import event
    event.listen(db.engine, 'before_cursor_execute', query_listener)
    event.listen(db.engine, 'after_cursor_execute', query_end_listener)
    
    logger.info("Database performance monitoring started")
    
    try:
        yield performance_data
    finally:
        performance_data['monitoring_active'] = False
        performance_data['end_time'] = time.time()
        
        # Remove event listeners
        event.remove(db.engine, 'before_cursor_execute', query_listener)
        event.remove(db.engine, 'after_cursor_execute', query_end_listener)
        
        total_queries = len(performance_data['queries'])
        avg_duration = sum(q['duration_seconds'] for q in performance_data['queries']) / max(total_queries, 1)
        
        logger.info("Database performance monitoring completed",
                    total_queries=total_queries,
                    average_duration=avg_duration,
                    monitoring_duration=performance_data['end_time'] - performance_data['start_time'])


# =============================================================================
# Authentication Testing Fixtures
# =============================================================================

@pytest.fixture(scope='function')
def mock_auth0_service(comparative_flask_app):
    """
    Create mock Auth0 service for comparative authentication testing.
    
    Provides Auth0 Python SDK 4.9.0 integration testing with mocked responses
    for consistent authentication testing across both systems.
    
    References:
    - Section 6.4.1.1: Auth0 integration with Flask application factory
    - Section 4.7.2: Authentication test fixtures for cross-system session management validation
    """
    mock_auth0_data = {
        'users': {},
        'tokens': {},
        'management_api_calls': [],
        'token_validation_calls': []
    }
    
    class MockAuth0Management:
        def __init__(self):
            self.users = mock_auth0_data['users']
            
        def get_user(self, user_id):
            if user_id in self.users:
                return self.users[user_id]
            raise Exception(f"User {user_id} not found")
        
        def create_user(self, user_data):
            user_id = f"auth0|{uuid.uuid4()}"
            self.users[user_id] = {
                'user_id': user_id,
                'email': user_data.get('email'),
                'username': user_data.get('username'),
                'created_at': datetime.utcnow().isoformat(),
                **user_data
            }
            mock_auth0_data['management_api_calls'].append({
                'action': 'create_user',
                'data': user_data,
                'timestamp': datetime.utcnow().isoformat()
            })
            return self.users[user_id]
        
        def update_user(self, user_id, user_data):
            if user_id in self.users:
                self.users[user_id].update(user_data)
                mock_auth0_data['management_api_calls'].append({
                    'action': 'update_user',
                    'user_id': user_id,
                    'data': user_data,
                    'timestamp': datetime.utcnow().isoformat()
                })
                return self.users[user_id]
            raise Exception(f"User {user_id} not found")
    
    class MockAuth0Client:
        def __init__(self):
            self.management = MockAuth0Management()
            
        def validate_token(self, token):
            mock_auth0_data['token_validation_calls'].append({
                'token': token[:20] + '...',  # Truncated for security
                'timestamp': datetime.utcnow().isoformat()
            })
            
            if token in mock_auth0_data['tokens']:
                return mock_auth0_data['tokens'][token]
            return None
        
        def generate_token(self, user_id, expires_in=3600):
            token = f"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.{uuid.uuid4()}.{uuid.uuid4()}"
            token_data = {
                'access_token': token,
                'user_id': user_id,
                'expires_at': (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat(),
                'scope': 'read:profile write:profile',
                'token_type': 'Bearer'
            }
            mock_auth0_data['tokens'][token] = token_data
            return token_data
    
    mock_client = MockAuth0Client()
    
    # Patch Auth0 integration in Flask app
    with patch.object(comparative_flask_app.auth0_integration, 'client', mock_client):
        logger.info("Mock Auth0 service initialized for comparative testing")
        yield {
            'client': mock_client,
            'data': mock_auth0_data,
            'management': mock_client.management
        }


@pytest.fixture(scope='function')
def comparative_authentication_context(comparative_flask_app, mock_auth0_service, comparative_test_data):
    """
    Create comparative authentication context for cross-system validation.
    
    Provides authentication state setup that can be used for testing
    both Node.js and Flask authentication systems with identical user contexts.
    
    References:
    - Section 6.4.1.3: Flask session management with ItsDangerous
    - Section 4.6.2: Flask-Login session management implementation
    """
    auth_context = {
        'test_users': [],
        'active_sessions': {},
        'auth_tokens': {},
        'session_manager': comparative_flask_app.session_manager
    }
    
    # Create authenticated users for testing
    for i, user in enumerate(comparative_test_data['users']):
        # Create Auth0 user
        auth0_user = mock_auth0_service['management'].create_user({
            'email': user.email,
            'username': user.username,
            'user_metadata': {
                'flask_user_id': user.id,
                'test_user': True
            }
        })
        
        # Generate Auth0 token
        token_data = mock_auth0_service['client'].generate_token(auth0_user['user_id'])
        
        # Create Flask session
        session_data = {
            'user_id': user.id,
            'auth0_user_id': auth0_user['user_id'],
            'email': user.email,
            'username': user.username,
            'authenticated': True,
            'session_start': datetime.utcnow().isoformat()
        }
        
        auth_context['test_users'].append({
            'flask_user': user,
            'auth0_user': auth0_user,
            'token_data': token_data,
            'session_data': session_data
        })
        
        auth_context['active_sessions'][user.id] = session_data
        auth_context['auth_tokens'][token_data['access_token']] = token_data
    
    logger.info("Comparative authentication context created",
                users_count=len(auth_context['test_users']),
                sessions_count=len(auth_context['active_sessions']))
    
    yield auth_context


@pytest.fixture(scope='function')
def flask_login_user(comparative_client, comparative_authentication_context):
    """
    Create logged-in Flask user for authentication testing.
    
    Provides Flask-Login authenticated user context for testing
    authentication decorators and session management.
    """
    if not comparative_authentication_context['test_users']:
        pytest.skip("No test users available for Flask login")
    
    test_user = comparative_authentication_context['test_users'][0]
    
    with comparative_client.session_transaction() as sess:
        sess['_user_id'] = str(test_user['flask_user'].id)
        sess['_fresh'] = True
        sess['_id'] = str(uuid.uuid4())
        sess.permanent = True
    
    logger.info("Flask user logged in for testing",
                user_id=test_user['flask_user'].id,
                username=test_user['flask_user'].username)
    
    yield test_user['flask_user']


# =============================================================================
# Performance Testing Fixtures
# =============================================================================

@pytest.fixture(scope='function')
def pytest_benchmark_config(request):
    """
    Configure pytest-benchmark 5.1.0 for comparative performance testing.
    
    Provides standardized benchmarking configuration with baseline comparison
    and threshold validation for performance regression detection.
    
    References:
    - Section 4.7.1: pytest-benchmark 5.1.0 fixture integration for API response time measurement
    - Section 4.7.1: Performance metrics validation against Node.js baseline
    """
    benchmark_config = {
        'min_rounds': 3,
        'max_time': 30.0,
        'min_time': 0.1,
        'timer': time.perf_counter,
        'disable_gc': True,
        'warmup': True,
        'warmup_iterations': 2,
        'sort': 'mean',
        'histogram': True,
        'thresholds': ComparativeTestConfig.PERFORMANCE_THRESHOLDS
    }
    
    # Configure benchmark plugin if available
    if hasattr(request.config, 'option') and hasattr(request.config.option, 'benchmark_only'):
        request.config.option.benchmark_min_rounds = benchmark_config['min_rounds']
        request.config.option.benchmark_max_time = benchmark_config['max_time']
        request.config.option.benchmark_disable_gc = benchmark_config['disable_gc']
        request.config.option.benchmark_warmup = benchmark_config['warmup']
        request.config.option.benchmark_sort = benchmark_config['sort']
    
    logger.info("pytest-benchmark configuration initialized",
                config=benchmark_config)
    
    yield benchmark_config


@pytest.fixture(scope='function')
def performance_comparison_context(pytest_benchmark_config, nodejs_baseline_client):
    """
    Create performance comparison context for baseline validation.
    
    Provides performance testing utilities with automatic baseline capture
    and comparison reporting for comprehensive performance validation.
    """
    context = {
        'baseline_metrics': {},
        'flask_metrics': {},
        'comparisons': [],
        'thresholds': pytest_benchmark_config['thresholds'],
        'start_time': time.time()
    }
    
    def capture_baseline_performance(endpoint: str, method: str = 'GET', **kwargs):
        """Capture Node.js baseline performance for comparison."""
        baseline_data = nodejs_baseline_client.make_request(method, endpoint, **kwargs)
        
        if baseline_data['metadata']['success']:
            context['baseline_metrics'][f"{method}:{endpoint}"] = {
                'duration_seconds': baseline_data['performance']['duration_seconds'],
                'status_code': baseline_data['response']['status_code'],
                'response_size': baseline_data['response']['size_bytes'],
                'timestamp': baseline_data['request']['timestamp']
            }
            
            logger.info("Baseline performance captured",
                        endpoint=endpoint, method=method,
                        duration=baseline_data['performance']['duration_seconds'])
        
        return baseline_data
    
    def capture_flask_performance(endpoint: str, duration: float, status_code: int, response_size: int):
        """Capture Flask performance metrics for comparison."""
        context['flask_metrics'][f"GET:{endpoint}"] = {
            'duration_seconds': duration,
            'status_code': status_code,
            'response_size': response_size,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        logger.info("Flask performance captured",
                    endpoint=endpoint, duration=duration)
    
    def compare_performance(endpoint: str, method: str = 'GET'):
        """Compare Flask and Node.js performance for specific endpoint."""
        key = f"{method}:{endpoint}"
        
        if key in context['baseline_metrics'] and key in context['flask_metrics']:
            baseline = context['baseline_metrics'][key]
            flask = context['flask_metrics'][key]
            
            comparison = {
                'endpoint': endpoint,
                'method': method,
                'baseline_duration': baseline['duration_seconds'],
                'flask_duration': flask['duration_seconds'],
                'performance_delta': flask['duration_seconds'] - baseline['duration_seconds'],
                'performance_ratio': flask['duration_seconds'] / baseline['duration_seconds'],
                'meets_threshold': flask['duration_seconds'] <= context['thresholds']['api_response_95th_percentile'],
                'timestamp': datetime.utcnow().isoformat()
            }
            
            context['comparisons'].append(comparison)
            
            logger.info("Performance comparison completed",
                        endpoint=endpoint,
                        baseline_duration=baseline['duration_seconds'],
                        flask_duration=flask['duration_seconds'],
                        delta=comparison['performance_delta'],
                        meets_threshold=comparison['meets_threshold'])
            
            return comparison
        else:
            logger.warning("Cannot compare performance - missing metrics",
                           endpoint=endpoint, method=method,
                           has_baseline=key in context['baseline_metrics'],
                           has_flask=key in context['flask_metrics'])
            return None
    
    context['capture_baseline'] = capture_baseline_performance
    context['capture_flask'] = capture_flask_performance
    context['compare'] = compare_performance
    
    yield context
    
    context['end_time'] = time.time()
    total_comparisons = len(context['comparisons'])
    passing_comparisons = sum(1 for c in context['comparisons'] if c['meets_threshold'])
    
    logger.info("Performance comparison context completed",
                total_comparisons=total_comparisons,
                passing_comparisons=passing_comparisons,
                success_rate=passing_comparisons / max(total_comparisons, 1))


# =============================================================================
# Monitoring and Metrics Fixtures
# =============================================================================

@pytest.fixture(scope='function')
def prometheus_metrics_collector():
    """
    Create Prometheus metrics collector for comparative testing monitoring.
    
    Provides real-time metrics collection during comparative tests
    with custom registry isolation for test-specific metrics.
    
    References:
    - Section 6.4.6.1: Prometheus Python client embedded within Flask applications
    - Section 6.4.6.1: Real-time observability and alerting metrics
    """
    # Create isolated registry for test metrics
    test_registry = CollectorRegistry()
    
    # Define comparative testing metrics
    metrics = {
        'api_requests': Counter(
            'comparative_api_requests_total',
            'Total API requests during comparative testing',
            ['system', 'endpoint', 'method', 'status_code'],
            registry=test_registry
        ),
        'response_time': Histogram(
            'comparative_response_time_seconds',
            'API response time during comparative testing',
            ['system', 'endpoint', 'method'],
            registry=test_registry,
            buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        ),
        'database_queries': Counter(
            'comparative_database_queries_total',
            'Database queries during comparative testing',
            ['system', 'query_type', 'table'],
            registry=test_registry
        ),
        'authentication_events': Counter(
            'comparative_auth_events_total',
            'Authentication events during comparative testing',
            ['system', 'event_type', 'result'],
            registry=test_registry
        ),
        'memory_usage': Gauge(
            'comparative_memory_usage_bytes',
            'Memory usage during comparative testing',
            ['system', 'component'],
            registry=test_registry
        )
    }
    
    def record_api_request(system: str, endpoint: str, method: str, status_code: int, duration: float):
        """Record API request metrics."""
        metrics['api_requests'].labels(
            system=system,
            endpoint=endpoint,
            method=method,
            status_code=str(status_code)
        ).inc()
        
        metrics['response_time'].labels(
            system=system,
            endpoint=endpoint,
            method=method
        ).observe(duration)
    
    def record_database_query(system: str, query_type: str, table: str):
        """Record database query metrics."""
        metrics['database_queries'].labels(
            system=system,
            query_type=query_type,
            table=table
        ).inc()
    
    def record_auth_event(system: str, event_type: str, result: str):
        """Record authentication event metrics."""
        metrics['authentication_events'].labels(
            system=system,
            event_type=event_type,
            result=result
        ).inc()
    
    def record_memory_usage(system: str, component: str, bytes_used: int):
        """Record memory usage metrics."""
        metrics['memory_usage'].labels(
            system=system,
            component=component
        ).set(bytes_used)
    
    collector = {
        'registry': test_registry,
        'metrics': metrics,
        'record_api_request': record_api_request,
        'record_database_query': record_database_query,
        'record_auth_event': record_auth_event,
        'record_memory_usage': record_memory_usage
    }
    
    logger.info("Prometheus metrics collector initialized",
                metrics_count=len(metrics))
    
    yield collector


@pytest.fixture(scope='function')
def system_resource_monitor():
    """
    Monitor system resources during comparative testing.
    
    Provides system resource monitoring for memory usage, CPU utilization,
    and process metrics during comparative test execution.
    
    References:
    - Section 4.7.1: Memory usage profiling for Flask application resource consumption
    - Section 6.4.6.1: Enhanced anomaly detection with Python runtime monitoring
    """
    monitor_data = {
        'start_time': time.time(),
        'samples': [],
        'monitoring_active': True,
        'sample_interval': 1.0  # seconds
    }
    
    def collect_sample():
        """Collect system resource sample."""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            
            sample = {
                'timestamp': time.time(),
                'cpu_percent': process.cpu_percent(),
                'memory_rss_mb': memory_info.rss / 1024 / 1024,
                'memory_vms_mb': memory_info.vms / 1024 / 1024,
                'memory_percent': process.memory_percent(),
                'num_threads': process.num_threads(),
                'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0,
                'connections': len(process.connections()),
                'io_read_bytes': process.io_counters().read_bytes if hasattr(process, 'io_counters') else 0,
                'io_write_bytes': process.io_counters().write_bytes if hasattr(process, 'io_counters') else 0
            }
            
            if monitor_data['monitoring_active']:
                monitor_data['samples'].append(sample)
            
            return sample
        except Exception as e:
            logger.error("Failed to collect resource sample", error=str(e))
            return None
    
    def start_monitoring():
        """Start background resource monitoring."""
        def monitor_loop():
            while monitor_data['monitoring_active']:
                collect_sample()
                time.sleep(monitor_data['sample_interval'])
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        monitor_data['monitor_thread'] = monitor_thread
    
    def get_statistics():
        """Get resource usage statistics."""
        if not monitor_data['samples']:
            return {}
        
        samples = monitor_data['samples']
        stats = {
            'duration_seconds': monitor_data['samples'][-1]['timestamp'] - monitor_data['samples'][0]['timestamp'],
            'sample_count': len(samples),
            'cpu_percent': {
                'min': min(s['cpu_percent'] for s in samples),
                'max': max(s['cpu_percent'] for s in samples),
                'avg': sum(s['cpu_percent'] for s in samples) / len(samples)
            },
            'memory_rss_mb': {
                'min': min(s['memory_rss_mb'] for s in samples),
                'max': max(s['memory_rss_mb'] for s in samples),
                'avg': sum(s['memory_rss_mb'] for s in samples) / len(samples)
            },
            'memory_percent': {
                'min': min(s['memory_percent'] for s in samples),
                'max': max(s['memory_percent'] for s in samples),
                'avg': sum(s['memory_percent'] for s in samples) / len(samples)
            }
        }
        
        return stats
    
    monitor_data['collect_sample'] = collect_sample
    monitor_data['start_monitoring'] = start_monitoring
    monitor_data['get_statistics'] = get_statistics
    
    # Start monitoring
    start_monitoring()
    
    logger.info("System resource monitoring started")
    
    yield monitor_data
    
    # Stop monitoring
    monitor_data['monitoring_active'] = False
    monitor_data['end_time'] = time.time()
    
    statistics = get_statistics()
    logger.info("System resource monitoring completed",
                duration=monitor_data['end_time'] - monitor_data['start_time'],
                samples=len(monitor_data['samples']),
                stats=statistics)


# =============================================================================
# Tox Integration Fixtures
# =============================================================================

@pytest.fixture(scope='session')
def tox_environment_manager():
    """
    Create tox 4.26.0 environment manager for multi-environment comparative testing.
    
    Provides tox environment coordination and multi-environment test execution
    management for comprehensive comparative validation across Python configurations.
    
    References:
    - Section 4.7.2: tox 4.26.0 for multi-environment comparative testing execution
    - Section 4.7.2: Parallel environment provisioning for comparative validation
    """
    tox_config = {
        'environments': ComparativeTestConfig.TOX_ENVIRONMENTS,
        'current_env': os.getenv('TOX_ENV_NAME', 'py313-comparative'),
        'isolation_enabled': True,
        'parallel_execution': True,
        'environment_data': {}
    }
    
    def get_environment_info():
        """Get current tox environment information."""
        env_info = {
            'tox_env_name': tox_config['current_env'],
            'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            'python_executable': sys.executable,
            'working_directory': os.getcwd(),
            'environment_variables': {
                k: v for k, v in os.environ.items() 
                if k.startswith(('TOX_', 'PYTEST_', 'FLASK_', 'SQLALCHEMY_'))
            }
        }
        return env_info
    
    def validate_environment():
        """Validate tox environment configuration."""
        env_info = get_environment_info()
        
        # Validate Python version
        required_version = (3, 13, 3)
        current_version = sys.version_info[:3]
        
        if current_version < required_version:
            logger.warning("Python version below recommended",
                           current=current_version,
                           required=required_version)
        
        # Validate Flask dependencies
        try:
            import flask
            import flask_sqlalchemy
            import pytest_flask
            import pytest_benchmark
            
            logger.info("Tox environment validation successful",
                        flask_version=flask.__version__,
                        python_version=env_info['python_version'],
                        tox_env=env_info['tox_env_name'])
            
            return True
        except ImportError as e:
            logger.error("Tox environment validation failed",
                         missing_dependency=str(e))
            return False
    
    def execute_in_environment(command: str, env_name: str = None):
        """Execute command in specific tox environment."""
        target_env = env_name or tox_config['current_env']
        
        try:
            result = subprocess.run(
                ['tox', '-e', target_env, '--', command],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            execution_result = {
                'command': command,
                'environment': target_env,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': result.returncode == 0
            }
            
            logger.info("Tox command executed",
                        command=command,
                        environment=target_env,
                        success=execution_result['success'])
            
            return execution_result
        
        except subprocess.TimeoutExpired:
            logger.error("Tox command timeout",
                         command=command,
                         environment=target_env)
            return {
                'command': command,
                'environment': target_env,
                'returncode': -1,
                'error': 'timeout',
                'success': False
            }
        except Exception as e:
            logger.error("Tox command failed",
                         command=command,
                         environment=target_env,
                         error=str(e))
            return {
                'command': command,
                'environment': target_env,
                'returncode': -1,
                'error': str(e),
                'success': False
            }
    
    # Validate current environment
    if not validate_environment():
        pytest.skip("Tox environment validation failed")
    
    tox_manager = {
        'config': tox_config,
        'get_environment_info': get_environment_info,
        'validate_environment': validate_environment,
        'execute_in_environment': execute_in_environment,
        'environment_info': get_environment_info()
    }
    
    logger.info("Tox environment manager initialized",
                current_env=tox_config['current_env'],
                environments=tox_config['environments'])
    
    yield tox_manager


# =============================================================================
# Utility Fixtures and Helpers
# =============================================================================

@pytest.fixture(scope='function')
def comparative_test_logger():
    """
    Create structured logger for comparative testing with correlation IDs.
    
    Provides comprehensive logging for comparative test execution
    with correlation tracking and structured output.
    """
    test_id = str(uuid.uuid4())
    test_logger = structlog.get_logger("comparative_test").bind(
        test_id=test_id,
        test_type="comparative",
        timestamp=datetime.utcnow().isoformat()
    )
    
    test_logger.info("Comparative test started", test_id=test_id)
    
    yield test_logger
    
    test_logger.info("Comparative test completed", test_id=test_id)


@pytest.fixture(scope='function')
def discrepancy_detector():
    """
    Create discrepancy detection utility for comparative validation.
    
    Provides utilities for detecting and analyzing differences
    between Node.js and Flask system responses.
    """
    discrepancies = []
    
    def detect_response_discrepancy(nodejs_response: Dict, flask_response: Dict, endpoint: str):
        """Detect discrepancies between system responses."""
        issues = []
        
        # Status code comparison
        if nodejs_response.get('status_code') != flask_response.get('status_code'):
            issues.append({
                'type': 'status_code_mismatch',
                'nodejs_value': nodejs_response.get('status_code'),
                'flask_value': flask_response.get('status_code'),
                'severity': 'high'
            })
        
        # Response data comparison
        nodejs_data = nodejs_response.get('data')
        flask_data = flask_response.get('data')
        
        if nodejs_data != flask_data:
            issues.append({
                'type': 'response_data_mismatch',
                'nodejs_sample': str(nodejs_data)[:100],
                'flask_sample': str(flask_data)[:100],
                'severity': 'critical'
            })
        
        # Performance comparison
        nodejs_duration = nodejs_response.get('duration_seconds', 0)
        flask_duration = flask_response.get('duration_seconds', 0)
        performance_delta = abs(flask_duration - nodejs_duration)
        
        if performance_delta > ComparativeTestConfig.PERFORMANCE_THRESHOLDS['api_response_95th_percentile']:
            issues.append({
                'type': 'performance_degradation',
                'nodejs_duration': nodejs_duration,
                'flask_duration': flask_duration,
                'delta_seconds': performance_delta,
                'severity': 'medium'
            })
        
        if issues:
            discrepancy = {
                'endpoint': endpoint,
                'timestamp': datetime.utcnow().isoformat(),
                'issues': issues,
                'nodejs_response': nodejs_response,
                'flask_response': flask_response
            }
            discrepancies.append(discrepancy)
            
            logger.warning("Response discrepancy detected",
                           endpoint=endpoint,
                           issue_count=len(issues),
                           severity_levels=[i['severity'] for i in issues])
        
        return issues
    
    def get_discrepancy_summary():
        """Get summary of all detected discrepancies."""
        if not discrepancies:
            return {'total': 0, 'by_severity': {}, 'by_type': {}}
        
        by_severity = {}
        by_type = {}
        
        for discrepancy in discrepancies:
            for issue in discrepancy['issues']:
                severity = issue['severity']
                issue_type = issue['type']
                
                by_severity[severity] = by_severity.get(severity, 0) + 1
                by_type[issue_type] = by_type.get(issue_type, 0) + 1
        
        return {
            'total': len(discrepancies),
            'by_severity': by_severity,
            'by_type': by_type,
            'discrepancies': discrepancies
        }
    
    detector = {
        'detect_response_discrepancy': detect_response_discrepancy,
        'get_discrepancy_summary': get_discrepancy_summary,
        'discrepancies': discrepancies
    }
    
    yield detector
    
    summary = get_discrepancy_summary()
    if summary['total'] > 0:
        logger.warning("Comparative testing completed with discrepancies",
                       total_discrepancies=summary['total'],
                       by_severity=summary['by_severity'])
    else:
        logger.info("Comparative testing completed with no discrepancies")


@pytest.fixture(scope='function')
def test_timeout_manager():
    """
    Manage test timeouts for comparative testing operations.
    
    Provides timeout management for long-running comparative tests
    with automatic cleanup and timeout detection.
    """
    timeouts = {
        'api_request': 30.0,
        'database_operation': 60.0,
        'authentication_flow': 45.0,
        'performance_benchmark': 120.0,
        'baseline_capture': 90.0
    }
    
    active_timeouts = {}
    
    @contextmanager
    def timeout_context(operation_type: str, custom_timeout: float = None):
        """Context manager for operation timeouts."""
        timeout_value = custom_timeout or timeouts.get(operation_type, 30.0)
        start_time = time.time()
        timeout_id = str(uuid.uuid4())
        
        active_timeouts[timeout_id] = {
            'operation': operation_type,
            'start_time': start_time,
            'timeout_seconds': timeout_value
        }
        
        try:
            yield timeout_value
        finally:
            end_time = time.time()
            duration = end_time - start_time
            
            if timeout_id in active_timeouts:
                active_timeouts[timeout_id]['end_time'] = end_time
                active_timeouts[timeout_id]['duration'] = duration
                active_timeouts[timeout_id]['timed_out'] = duration > timeout_value
                
                if duration > timeout_value:
                    logger.warning("Operation timeout exceeded",
                                   operation=operation_type,
                                   duration=duration,
                                   timeout=timeout_value)
                
                del active_timeouts[timeout_id]
    
    def get_timeout_statistics():
        """Get timeout statistics for completed operations."""
        completed_timeouts = [t for t in active_timeouts.values() if 'duration' in t]
        
        if not completed_timeouts:
            return {}
        
        return {
            'total_operations': len(completed_timeouts),
            'timed_out_operations': sum(1 for t in completed_timeouts if t.get('timed_out', False)),
            'average_duration': sum(t['duration'] for t in completed_timeouts) / len(completed_timeouts),
            'max_duration': max(t['duration'] for t in completed_timeouts),
            'min_duration': min(t['duration'] for t in completed_timeouts)
        }
    
    manager = {
        'timeout_context': timeout_context,
        'timeouts': timeouts,
        'active_timeouts': active_timeouts,
        'get_timeout_statistics': get_timeout_statistics
    }
    
    yield manager


# =============================================================================
# Cleanup and Teardown
# =============================================================================

@pytest.fixture(scope='function', autouse=True)
def comparative_test_cleanup():
    """
    Automatic cleanup fixture for comparative testing resources.
    
    Ensures proper cleanup of test resources, connections, and temporary data
    after each comparative test function completes.
    """
    cleanup_tasks = []
    
    def register_cleanup(cleanup_func, description: str = ""):
        """Register cleanup function to be executed after test."""
        cleanup_tasks.append({
            'function': cleanup_func,
            'description': description
        })
    
    yield register_cleanup
    
    # Execute cleanup tasks
    for task in cleanup_tasks:
        try:
            task['function']()
            logger.debug("Cleanup task completed",
                         description=task['description'])
        except Exception as e:
            logger.error("Cleanup task failed",
                         description=task['description'],
                         error=str(e))