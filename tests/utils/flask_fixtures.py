"""
Core Flask Testing Fixtures and Utilities

This module provides comprehensive Flask-specific testing fixtures implementing
pytest-flask 1.3.0 integration for Flask application factory test client
initialization, request context management, and Flask-specific testing patterns.
Establishes foundational testing infrastructure enabling consistent Flask
application testing across all test modules with proper setup and teardown
procedures as specified in Section 4.7.1.

The fixtures complement the base testing infrastructure in conftest.py with
specialized Flask testing patterns including:
- Flask application factory pattern testing support per Feature F-008
- Blueprint testing infrastructure for modular route validation per Feature F-001
- Flask-SQLAlchemy test database fixtures with transaction rollback per Feature F-003
- Request context management for session and authentication testing per Section 4.7.1
- Flask development server fixtures for integration testing per Section 3.6.1

Key Dependencies:
- pytest-flask 1.3.0: Flask application testing fixtures and utilities
- Flask 3.1.1: Application factory pattern and request context management
- Flask-SQLAlchemy 3.1.1: Database ORM and testing patterns with PostgreSQL 14
- Flask-Login: User session management and authentication simulation

Author: Blitzy Development Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import os
import pytest
import tempfile
import threading
import time
import subprocess
import socket
from contextlib import contextmanager
from typing import Dict, Any, Generator, Optional, List, Tuple, Callable
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import uuid
import json
import multiprocessing

# Flask core imports for application factory pattern testing
from flask import Flask, Blueprint, g, session, request, current_app, jsonify
from flask.testing import FlaskClient
from flask.ctx import RequestContext, AppContext
from werkzeug.test import Client, EnvironBuilder
from werkzeug.wrappers import Response

# Flask extension imports for comprehensive testing support
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, logout_user, current_user, LoginManager

# Import application components with fallback handling
try:
    from app import create_app, create_wsgi_app
    from config import Config, DevelopmentConfig, TestingConfig, ProductionConfig, StagingConfig
    from src.models.base import db
    from src.models.user import User
    from src.models.session import UserSession
    from src.auth.session_manager import FlaskSessionManager
    from src.auth.auth0_integration import Auth0Integration
    from src.auth.decorators import AuthenticationDecorators
    from src.services.user_service import UserService
    from src.services.validation_service import ValidationService
except ImportError:
    # Handle development scenario where modules may not exist yet
    create_app = None
    create_wsgi_app = None
    Config = None
    DevelopmentConfig = None
    TestingConfig = None
    ProductionConfig = None
    StagingConfig = None
    db = None
    User = None
    UserSession = None
    FlaskSessionManager = None
    Auth0Integration = None
    AuthenticationDecorators = None
    UserService = None
    ValidationService = None


class FlaskTestingConfig:
    """
    Enhanced Flask testing configuration providing comprehensive test environment
    isolation and Flask app.config management per Feature F-010.
    
    This configuration class extends base testing configuration with Flask-specific
    testing patterns including request context management, blueprint testing support,
    and Flask-SQLAlchemy integration optimizations for testing scenarios.
    """
    
    # Flask core testing configuration
    TESTING = True
    DEBUG = False
    SECRET_KEY = 'flask-test-secret-key-for-pytest-only'
    WTF_CSRF_ENABLED = False  # Disable CSRF for testing simplicity
    SERVER_NAME = 'localhost:5000'  # Required for some Flask testing patterns
    
    # Database configuration for Flask-SQLAlchemy testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'echo': False,  # Enable for SQL query debugging
        'pool_timeout': 10,
        'pool_size': 5,
        'max_overflow': 0  # Disable overflow for testing predictability
    }
    
    # Session management configuration for testing
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_COOKIE_SECURE = False  # Allow testing over HTTP
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Authentication testing configuration
    AUTH0_DOMAIN = 'test-domain.auth0.com'
    AUTH0_CLIENT_ID = 'test-client-id'
    AUTH0_CLIENT_SECRET = 'test-client-secret'
    AUTH0_AUDIENCE = 'test-audience'
    JWT_SECRET_KEY = 'test-jwt-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    
    # Flask-Login testing configuration
    LOGIN_DISABLED = False  # Enable login for authentication testing
    REMEMBER_COOKIE_DURATION = timedelta(hours=1)
    
    # Blueprint testing configuration
    BLUEPRINT_PREFIX_OVERRIDE = '/test'  # Optional prefix for blueprint testing
    
    # Performance testing configuration
    MAX_REQUEST_DURATION = 1.0  # Maximum allowed request duration in seconds
    PERFORMANCE_MONITORING_ENABLED = True
    
    # External service mocking configuration
    EXTERNAL_SERVICES_MOCK = True
    DISABLE_EXTERNAL_CALLS = True
    
    # Logging configuration for testing
    LOG_LEVEL = 'WARNING'
    TESTING_LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class FlaskBlueprintTestSuite:
    """
    Flask blueprint testing utilities providing comprehensive blueprint validation
    and modular route testing infrastructure per Feature F-001.
    
    This class implements blueprint-specific testing patterns enabling isolated
    testing of Flask blueprint functionality, route registration validation,
    and blueprint-specific configuration testing.
    """
    
    def __init__(self, app: Flask):
        self.app = app
        self.registered_blueprints = []
        self.blueprint_test_data = {}
        
    def register_test_blueprint(self, blueprint: Blueprint, url_prefix: str = None) -> None:
        """
        Register a test blueprint with the Flask application for testing.
        
        Args:
            blueprint: Flask Blueprint instance to register
            url_prefix: Optional URL prefix for blueprint routes
        """
        self.app.register_blueprint(blueprint, url_prefix=url_prefix)
        self.registered_blueprints.append({
            'blueprint': blueprint,
            'name': blueprint.name,
            'url_prefix': url_prefix,
            'registered_at': datetime.utcnow()
        })
        
    def create_test_blueprint(self, name: str, routes: List[Tuple[str, str, Callable]] = None) -> Blueprint:
        """
        Create a test blueprint with specified routes for testing scenarios.
        
        Args:
            name: Blueprint name
            routes: List of (route, method, handler) tuples
            
        Returns:
            Blueprint: Configured test blueprint
        """
        blueprint = Blueprint(name, __name__, url_prefix=f'/test/{name}')
        
        if routes:
            for route, method, handler in routes:
                blueprint.route(route, methods=[method])(handler)
        else:
            # Add default test routes
            @blueprint.route('/')
            def index():
                return jsonify({'blueprint': name, 'status': 'active'})
                
            @blueprint.route('/health')
            def health():
                return jsonify({'blueprint': name, 'health': 'ok'})
                
            @blueprint.route('/info')
            def info():
                return jsonify({
                    'blueprint': name,
                    'routes': len(blueprint.deferred_functions),
                    'url_prefix': blueprint.url_prefix
                })
        
        self.blueprint_test_data[name] = {
            'created_at': datetime.utcnow(),
            'routes_count': len(blueprint.deferred_functions)
        }
        
        return blueprint
        
    def validate_blueprint_registration(self, blueprint_name: str) -> Dict[str, Any]:
        """
        Validate that a blueprint is properly registered with the Flask application.
        
        Args:
            blueprint_name: Name of the blueprint to validate
            
        Returns:
            Dict containing validation results
        """
        blueprint_found = False
        blueprint_info = None
        
        for bp_name, bp_instance in self.app.blueprints.items():
            if bp_name == blueprint_name:
                blueprint_found = True
                blueprint_info = {
                    'name': bp_name,
                    'url_prefix': bp_instance.url_prefix,
                    'has_static_folder': bp_instance.has_static_folder,
                    'template_folder': bp_instance.template_folder,
                    'deferred_functions_count': len(bp_instance.deferred_functions)
                }
                break
        
        return {
            'registered': blueprint_found,
            'blueprint_info': blueprint_info,
            'total_blueprints': len(self.app.blueprints),
            'validation_timestamp': datetime.utcnow().isoformat()
        }
        
    def get_blueprint_routes(self, blueprint_name: str) -> List[Dict[str, Any]]:
        """
        Extract all routes registered by a specific blueprint.
        
        Args:
            blueprint_name: Name of the blueprint
            
        Returns:
            List of route information dictionaries
        """
        routes = []
        
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint and rule.endpoint.startswith(f'{blueprint_name}.'):
                routes.append({
                    'endpoint': rule.endpoint,
                    'rule': str(rule),
                    'methods': list(rule.methods),
                    'subdomain': rule.subdomain,
                    'strict_slashes': rule.strict_slashes
                })
        
        return routes


class FlaskDatabaseTestManager:
    """
    Flask-SQLAlchemy database testing manager providing comprehensive database
    fixture management with transaction rollback and data isolation per Feature F-003.
    
    This manager implements Flask-SQLAlchemy testing patterns ensuring complete
    database isolation between tests, transaction rollback mechanisms, and
    realistic test data generation for database testing scenarios.
    """
    
    def __init__(self, app: Flask, db_instance: SQLAlchemy):
        self.app = app
        self.db = db_instance
        self.test_transactions = []
        self.test_data_snapshots = {}
        
    @contextmanager
    def isolated_transaction(self):
        """
        Provide isolated database transaction context for testing with automatic rollback.
        
        This context manager ensures complete database isolation between tests
        by creating a savepoint before test execution and rolling back to it
        after test completion, preventing test data contamination.
        
        Yields:
            SQLAlchemy session with transaction isolation
        """
        with self.app.app_context():
            # Create a savepoint for transaction isolation
            connection = self.db.engine.connect()
            transaction = connection.begin()
            
            # Configure session to use the transaction
            session_options = dict(bind=connection, binds={})
            session = self.db.create_scoped_session(options=session_options)
            
            # Replace the default session
            original_session = self.db.session
            self.db.session = session
            
            try:
                yield session
            except Exception:
                # Rollback on exception
                transaction.rollback()
                raise
            finally:
                # Always rollback and cleanup
                session.remove()
                transaction.rollback()
                connection.close()
                
                # Restore original session
                self.db.session = original_session
                
    def create_test_tables(self) -> None:
        """
        Create all database tables for testing environment with proper schema setup.
        """
        with self.app.app_context():
            self.db.create_all()
            
    def drop_test_tables(self) -> None:
        """
        Drop all database tables for testing cleanup.
        """
        with self.app.app_context():
            self.db.drop_all()
            
    def populate_test_data(self, test_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Any]]:
        """
        Populate database with test data for testing scenarios.
        
        Args:
            test_data: Dictionary mapping table names to test record lists
            
        Returns:
            Dictionary mapping table names to created model instances
        """
        created_objects = {}
        
        with self.isolated_transaction() as session:
            for table_name, records in test_data.items():
                created_objects[table_name] = []
                
                # Dynamically get model class based on table name
                model_class = self._get_model_class(table_name)
                if not model_class:
                    continue
                    
                for record_data in records:
                    instance = model_class(**record_data)
                    session.add(instance)
                    created_objects[table_name].append(instance)
                
                session.commit()
        
        return created_objects
        
    def _get_model_class(self, table_name: str):
        """
        Get model class by table name for dynamic test data creation.
        
        Args:
            table_name: Database table name
            
        Returns:
            SQLAlchemy model class or None
        """
        # Map table names to model classes
        model_mapping = {
            'users': User,
            'user_sessions': UserSession,
            # Add more model mappings as needed
        }
        
        return model_mapping.get(table_name)
        
    def assert_database_state(self, expected_counts: Dict[str, int]) -> None:
        """
        Assert database state matches expected record counts for validation.
        
        Args:
            expected_counts: Dictionary mapping table names to expected record counts
        """
        with self.app.app_context():
            for table_name, expected_count in expected_counts.items():
                model_class = self._get_model_class(table_name)
                if model_class:
                    actual_count = model_class.query.count()
                    assert actual_count == expected_count, \
                        f"Table '{table_name}' has {actual_count} records, expected {expected_count}"


class FlaskDevServerManager:
    """
    Flask development server manager for integration testing scenarios per Section 3.6.1.
    
    This manager provides Flask development server fixtures enabling comprehensive
    integration testing with real HTTP requests, server lifecycle management,
    and multi-threaded testing support for realistic testing scenarios.
    """
    
    def __init__(self, app: Flask, host: str = 'localhost', port: int = None):
        self.app = app
        self.host = host
        self.port = port or self._find_free_port()
        self.server_process = None
        self.server_thread = None
        self.is_running = False
        
    def _find_free_port(self) -> int:
        """Find a free port for the test server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
        
    def start_server(self, timeout: int = 10) -> bool:
        """
        Start Flask development server in a separate thread for integration testing.
        
        Args:
            timeout: Maximum time to wait for server startup
            
        Returns:
            bool: True if server started successfully
        """
        if self.is_running:
            return True
            
        def run_server():
            """Run Flask development server in thread"""
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        
        # Start server in separate thread
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        # Wait for server to start
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                import requests
                response = requests.get(f'http://{self.host}:{self.port}/health', timeout=1)
                if response.status_code == 200:
                    self.is_running = True
                    return True
            except:
                time.sleep(0.1)
                
        return False
        
    def stop_server(self) -> None:
        """Stop the Flask development server."""
        if self.server_thread and self.server_thread.is_alive():
            # Note: In a real implementation, you might need a more sophisticated
            # mechanism to stop the server gracefully
            self.is_running = False
            
    def get_server_url(self) -> str:
        """Get the complete server URL for testing."""
        return f'http://{self.host}:{self.port}'
        
    def health_check(self) -> bool:
        """Perform health check on the running server."""
        if not self.is_running:
            return False
            
        try:
            import requests
            response = requests.get(f'{self.get_server_url()}/health', timeout=2)
            return response.status_code == 200
        except:
            return False


# ================================
# Core Flask Testing Fixtures
# ================================

@pytest.fixture(scope='function')
def flask_app_factory():
    """
    Flask application factory testing fixture providing Flask application factory
    pattern testing support per Feature F-008.
    
    This fixture enables testing of the Flask application factory pattern with
    different configuration scenarios, environment-specific settings, and
    comprehensive application initialization validation.
    
    Returns:
        Callable: Application factory function for testing
    """
    def create_test_app(config_name: str = 'testing', **config_overrides) -> Flask:
        """
        Create Flask application instance for testing with specified configuration.
        
        Args:
            config_name: Configuration environment name
            **config_overrides: Additional configuration overrides
            
        Returns:
            Flask: Configured Flask application instance
        """
        if create_app is not None:
            app = create_app(config_name)
        else:
            # Fallback Flask application creation
            app = Flask(__name__)
            app.config.from_object(FlaskTestingConfig)
            
        # Apply configuration overrides
        app.config.update(config_overrides)
        
        # Ensure testing configuration
        app.config.update({
            'TESTING': True,
            'SECRET_KEY': 'flask-test-secret-key-for-pytest-only',
            'WTF_CSRF_ENABLED': False,
            'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:'
        })
        
        return app
        
    return create_test_app


@pytest.fixture
def flask_app_with_context(flask_app_factory):
    """
    Flask application with application context for context-dependent testing.
    
    This fixture provides a Flask application with an active application context,
    enabling testing of Flask components that require application context such as
    database operations, configuration access, and extension usage.
    
    Args:
        flask_app_factory: Application factory from flask_app_factory fixture
        
    Yields:
        Flask: Application instance with active application context
    """
    app = flask_app_factory()
    
    with app.app_context():
        # Initialize database tables if SQLAlchemy is available
        if db is not None:
            db.init_app(app)
            db.create_all()
            
        yield app
        
        # Cleanup
        if db is not None:
            db.session.remove()
            db.drop_all()


@pytest.fixture
def flask_request_context(flask_app_with_context):
    """
    Flask request context fixture enabling proper session and authentication testing
    per Section 4.7.1.
    
    This fixture provides comprehensive request context management for testing
    Flask components that require request context including session handling,
    authentication decorators, and request-specific data processing.
    
    Args:
        flask_app_with_context: Flask app with context from flask_app_with_context fixture
        
    Yields:
        RequestContext: Active Flask request context
    """
    with flask_app_with_context.test_request_context() as ctx:
        # Initialize request context variables
        g.request_id = str(uuid.uuid4())
        g.start_time = datetime.utcnow()
        g.user_id = None
        g.authenticated = False
        
        # Initialize session data
        session.permanent = False
        session['csrf_token'] = str(uuid.uuid4())
        session['session_id'] = str(uuid.uuid4())
        
        yield ctx


@pytest.fixture
def flask_authenticated_context(flask_request_context, sample_users):
    """
    Flask authenticated request context with user session for authentication testing.
    
    This fixture extends flask_request_context with authenticated user session,
    enabling testing of protected endpoints, authorization decorators, and
    user-specific functionality with realistic authentication state.
    
    Args:
        flask_request_context: Request context from flask_request_context fixture
        sample_users: Sample users from conftest.py sample_users fixture
        
    Yields:
        RequestContext: Request context with authenticated user session
    """
    user = sample_users['user'] if sample_users else Mock()
    
    # Set up authenticated session
    session['user_id'] = getattr(user, 'id', 'test_user_id')
    session['username'] = getattr(user, 'username', 'testuser')
    session['authenticated'] = True
    session['auth_time'] = datetime.utcnow().isoformat()
    session['roles'] = getattr(user, 'roles', ['user'])
    
    # Set up request context globals
    g.user_id = session['user_id']
    g.authenticated = True
    g.current_user = user
    
    # Mock Flask-Login current_user
    with patch('flask_login.current_user', user):
        yield flask_request_context


@pytest.fixture
def flask_blueprint_tester(flask_app_with_context):
    """
    Flask blueprint testing infrastructure for modular route validation per Feature F-001.
    
    This fixture provides comprehensive blueprint testing utilities enabling
    isolated testing of Flask blueprint functionality, route registration
    validation, and blueprint-specific configuration testing.
    
    Args:
        flask_app_with_context: Flask app with context
        
    Returns:
        FlaskBlueprintTestSuite: Blueprint testing utilities
    """
    return FlaskBlueprintTestSuite(flask_app_with_context)


@pytest.fixture
def flask_db_manager(flask_app_with_context):
    """
    Flask-SQLAlchemy test database fixture with transaction rollback per Feature F-003.
    
    This fixture provides comprehensive database testing infrastructure with
    transaction isolation, automatic rollback, and test data management
    capabilities for Flask-SQLAlchemy integration testing.
    
    Args:
        flask_app_with_context: Flask app with context
        
    Returns:
        FlaskDatabaseTestManager: Database testing utilities
    """
    if db is None:
        # Return mock manager if SQLAlchemy not available
        return Mock()
        
    return FlaskDatabaseTestManager(flask_app_with_context, db)


@pytest.fixture
def flask_dev_server(flask_app_factory):
    """
    Flask development server fixture for integration testing per Section 3.6.1.
    
    This fixture provides Flask development server lifecycle management for
    comprehensive integration testing with real HTTP requests and server
    interaction validation in realistic testing scenarios.
    
    Args:
        flask_app_factory: Application factory from flask_app_factory fixture
        
    Yields:
        FlaskDevServerManager: Development server manager
    """
    app = flask_app_factory()
    server_manager = FlaskDevServerManager(app)
    
    # Start server for testing
    if server_manager.start_server():
        yield server_manager
    else:
        pytest.fail("Failed to start Flask development server for testing")
    
    # Cleanup
    server_manager.stop_server()


# ================================
# Flask Configuration Testing Fixtures
# ================================

@pytest.fixture
def flask_config_environments():
    """
    Flask application configuration fixtures for test environment isolation per Feature F-010.
    
    This fixture provides comprehensive configuration testing utilities for
    validating Flask app.config management across different environments
    and configuration scenarios with proper isolation and validation.
    
    Returns:
        Dict[str, type]: Configuration classes by environment name
    """
    config_classes = {
        'testing': FlaskTestingConfig,
        'development': DevelopmentConfig if DevelopmentConfig else FlaskTestingConfig,
        'staging': StagingConfig if StagingConfig else FlaskTestingConfig,
        'production': ProductionConfig if ProductionConfig else FlaskTestingConfig
    }
    
    return config_classes


@pytest.fixture
def flask_config_validator(flask_app_factory):
    """
    Flask configuration validation utilities for testing configuration integrity.
    
    Args:
        flask_app_factory: Application factory fixture
        
    Returns:
        Callable: Configuration validation function
    """
    def validate_config(config_name: str, required_keys: List[str] = None) -> Dict[str, Any]:
        """
        Validate Flask application configuration for testing scenarios.
        
        Args:
            config_name: Configuration environment name
            required_keys: List of required configuration keys
            
        Returns:
            Dict containing validation results
        """
        app = flask_app_factory(config_name)
        
        validation_results = {
            'config_name': config_name,
            'testing_mode': app.config.get('TESTING', False),
            'secret_key_configured': bool(app.config.get('SECRET_KEY')),
            'database_configured': bool(app.config.get('SQLALCHEMY_DATABASE_URI')),
            'missing_keys': [],
            'configuration_valid': True
        }
        
        # Check required keys
        if required_keys:
            for key in required_keys:
                if not app.config.get(key):
                    validation_results['missing_keys'].append(key)
                    validation_results['configuration_valid'] = False
        
        return validation_results
        
    return validate_config


# ================================
# Flask Session and Authentication Testing Fixtures
# ================================

@pytest.fixture
def flask_session_manager(flask_app_with_context):
    """
    Flask session management testing utilities for session lifecycle testing.
    
    This fixture provides comprehensive session testing infrastructure for
    validating Flask session management, authentication state, and session
    security measures during testing scenarios.
    
    Args:
        flask_app_with_context: Flask app with context
        
    Returns:
        Dict[str, Callable]: Session management testing utilities
    """
    def create_session(user_data: Dict[str, Any] = None) -> str:
        """Create a test session with optional user data."""
        session_id = str(uuid.uuid4())
        
        # Set up session data
        session['session_id'] = session_id
        session['created_at'] = datetime.utcnow().isoformat()
        session['last_accessed'] = datetime.utcnow().isoformat()
        
        if user_data:
            session.update(user_data)
            
        return session_id
        
    def validate_session(expected_keys: List[str] = None) -> Dict[str, Any]:
        """Validate current session state."""
        validation = {
            'session_exists': bool(session),
            'session_id': session.get('session_id'),
            'has_csrf_token': 'csrf_token' in session,
            'is_authenticated': session.get('authenticated', False),
            'missing_keys': []
        }
        
        if expected_keys:
            for key in expected_keys:
                if key not in session:
                    validation['missing_keys'].append(key)
                    
        return validation
        
    def clear_session():
        """Clear session data for testing."""
        session.clear()
        
    return {
        'create': create_session,
        'validate': validate_session,
        'clear': clear_session
    }


@pytest.fixture
def flask_auth_decorators_tester(flask_authenticated_context):
    """
    Flask authentication decorators testing utilities for decorator validation.
    
    This fixture provides comprehensive testing infrastructure for Flask
    authentication decorators, authorization controls, and security enforcement
    mechanisms in realistic testing scenarios.
    
    Args:
        flask_authenticated_context: Authenticated context fixture
        
    Returns:
        Dict[str, Callable]: Authentication decorator testing utilities
    """
    def create_protected_endpoint(auth_required: bool = True, roles: List[str] = None):
        """
        Create a test endpoint with authentication decorators for testing.
        
        Args:
            auth_required: Whether authentication is required
            roles: Required roles for authorization
            
        Returns:
            Callable: Decorated test endpoint function
        """
        def test_endpoint():
            return jsonify({
                'message': 'Access granted',
                'user_id': g.get('user_id'),
                'authenticated': g.get('authenticated', False),
                'timestamp': datetime.utcnow().isoformat()
            })
            
        if auth_required:
            # Apply authentication decorator (mock implementation)
            def auth_decorator(f):
                def wrapper(*args, **kwargs):
                    if not g.get('authenticated'):
                        return jsonify({'error': 'Authentication required'}), 401
                    return f(*args, **kwargs)
                return wrapper
            test_endpoint = auth_decorator(test_endpoint)
            
        if roles:
            # Apply role-based authorization decorator (mock implementation)
            def role_decorator(f):
                def wrapper(*args, **kwargs):
                    user_roles = session.get('roles', [])
                    if not any(role in user_roles for role in roles):
                        return jsonify({'error': 'Insufficient permissions'}), 403
                    return f(*args, **kwargs)
                return wrapper
            test_endpoint = role_decorator(test_endpoint)
            
        return test_endpoint
        
    def test_auth_flow(endpoint_func: Callable, expected_status: int = 200) -> Dict[str, Any]:
        """
        Test authentication flow with provided endpoint.
        
        Args:
            endpoint_func: Endpoint function to test
            expected_status: Expected HTTP status code
            
        Returns:
            Dict containing test results
        """
        try:
            response = endpoint_func()
            
            if hasattr(response, 'status_code'):
                status_code = response.status_code
                response_data = response.get_json() if hasattr(response, 'get_json') else None
            else:
                # Handle direct return values
                status_code = 200
                response_data = response
                
            return {
                'status_code': status_code,
                'response_data': response_data,
                'test_passed': status_code == expected_status,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'status_code': 500,
                'error': str(e),
                'test_passed': False,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    return {
        'create_protected_endpoint': create_protected_endpoint,
        'test_auth_flow': test_auth_flow
    }


# ================================
# Flask Performance Testing Fixtures
# ================================

@pytest.fixture
def flask_performance_monitor():
    """
    Flask performance monitoring utilities for testing performance requirements.
    
    This fixture provides comprehensive performance testing infrastructure for
    validating Flask application performance against baseline requirements and
    ensuring SLA compliance during testing scenarios.
    
    Returns:
        Dict[str, Callable]: Performance monitoring utilities
    """
    performance_data = {}
    
    def start_monitoring(operation_name: str):
        """Start performance monitoring for an operation."""
        performance_data[operation_name] = {
            'start_time': time.time(),
            'end_time': None,
            'duration': None,
            'status': 'running'
        }
        
    def stop_monitoring(operation_name: str):
        """Stop performance monitoring and calculate duration."""
        if operation_name in performance_data:
            end_time = time.time()
            performance_data[operation_name].update({
                'end_time': end_time,
                'duration': end_time - performance_data[operation_name]['start_time'],
                'status': 'completed'
            })
            
    def assert_performance_threshold(operation_name: str, max_duration: float):
        """Assert that operation completed within performance threshold."""
        if operation_name in performance_data:
            actual_duration = performance_data[operation_name].get('duration', float('inf'))
            assert actual_duration <= max_duration, \
                f"Performance threshold exceeded for {operation_name}: {actual_duration:.3f}s > {max_duration}s"
                
    def get_performance_report() -> Dict[str, Any]:
        """Get comprehensive performance report for all monitored operations."""
        return {
            'operations': performance_data.copy(),
            'total_operations': len(performance_data),
            'average_duration': sum(
                data.get('duration', 0) for data in performance_data.values()
            ) / len(performance_data) if performance_data else 0,
            'report_timestamp': datetime.utcnow().isoformat()
        }
    
    return {
        'start': start_monitoring,
        'stop': stop_monitoring,
        'assert_threshold': assert_performance_threshold,
        'get_report': get_performance_report
    }


# ================================
# Flask Testing Utility Functions
# ================================

def create_test_response(data: Any = None, status_code: int = 200, 
                        headers: Dict[str, str] = None) -> Response:
    """
    Create a test Response object for Flask testing scenarios.
    
    Args:
        data: Response data (will be JSON serialized if dict)
        status_code: HTTP status code
        headers: Optional response headers
        
    Returns:
        Response: Flask Response object for testing
    """
    if isinstance(data, dict):
        response_data = json.dumps(data)
        content_type = 'application/json'
    else:
        response_data = str(data) if data is not None else ''
        content_type = 'text/plain'
        
    response_headers = {'Content-Type': content_type}
    if headers:
        response_headers.update(headers)
        
    return Response(
        response=response_data,
        status=status_code,
        headers=response_headers
    )


def assert_flask_response_format(response, expected_status: int = 200,
                                expected_content_type: str = 'application/json',
                                required_fields: List[str] = None) -> Dict[str, Any]:
    """
    Assert Flask response format meets testing requirements.
    
    Args:
        response: Flask test client response
        expected_status: Expected HTTP status code
        expected_content_type: Expected content type
        required_fields: List of required JSON fields
        
    Returns:
        Dict containing response validation results
    """
    validation_results = {
        'status_code_valid': response.status_code == expected_status,
        'content_type_valid': expected_content_type in (response.content_type or ''),
        'json_valid': False,
        'required_fields_present': True,
        'missing_fields': []
    }
    
    # Validate JSON response if expected
    if 'application/json' in expected_content_type:
        try:
            json_data = response.get_json()
            validation_results['json_valid'] = json_data is not None
            
            if required_fields and json_data:
                for field in required_fields:
                    if field not in json_data:
                        validation_results['missing_fields'].append(field)
                        validation_results['required_fields_present'] = False
                        
        except Exception:
            validation_results['json_valid'] = False
    
    # Assert all validations pass
    assert validation_results['status_code_valid'], \
        f"Expected status {expected_status}, got {response.status_code}"
    assert validation_results['content_type_valid'], \
        f"Expected content type {expected_content_type}, got {response.content_type}"
    
    if 'application/json' in expected_content_type:
        assert validation_results['json_valid'], "Response should contain valid JSON"
        assert validation_results['required_fields_present'], \
            f"Missing required fields: {validation_results['missing_fields']}"
    
    return validation_results


# ================================
# Flask Testing Markers and Configuration
# ================================

# Pytest markers for Flask-specific test categorization
FLASK_TEST_MARKERS = {
    'flask_unit': 'Unit tests for Flask components',
    'flask_integration': 'Integration tests for Flask application',
    'flask_blueprint': 'Tests for Flask blueprint functionality',
    'flask_auth': 'Tests for Flask authentication mechanisms',
    'flask_database': 'Tests for Flask-SQLAlchemy integration',
    'flask_performance': 'Performance tests for Flask application',
    'flask_config': 'Tests for Flask configuration management'
}

# Flask testing configuration constants
FLASK_TESTING_CONSTANTS = {
    'MAX_REQUEST_DURATION': 1.0,
    'MAX_DATABASE_QUERY_TIME': 0.5,
    'MAX_AUTHENTICATION_TIME': 0.2,
    'DEFAULT_TEST_TIMEOUT': 30,
    'PERFORMANCE_THRESHOLD_MARGIN': 0.1
}

# Export all fixtures and utilities for use in other test modules
__all__ = [
    # Configuration classes
    'FlaskTestingConfig',
    'FlaskBlueprintTestSuite',
    'FlaskDatabaseTestManager',
    'FlaskDevServerManager',
    
    # Core fixtures
    'flask_app_factory',
    'flask_app_with_context',
    'flask_request_context',
    'flask_authenticated_context',
    'flask_blueprint_tester',
    'flask_db_manager',
    'flask_dev_server',
    
    # Configuration fixtures
    'flask_config_environments',
    'flask_config_validator',
    
    # Session and authentication fixtures
    'flask_session_manager',
    'flask_auth_decorators_tester',
    
    # Performance fixtures
    'flask_performance_monitor',
    
    # Utility functions
    'create_test_response',
    'assert_flask_response_format',
    
    # Constants
    'FLASK_TEST_MARKERS',
    'FLASK_TESTING_CONSTANTS'
]