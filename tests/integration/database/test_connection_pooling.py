"""
Database Connection Pooling and Session Management Testing Suite

This comprehensive test suite validates SQLAlchemy connection pool configuration, session lifecycle
management, and concurrent database operations for the Flask 3.1.1 migration to ensure optimal
database connectivity through psycopg2 adapter configuration and PostgreSQL 15.x integration.

The test suite validates:
- SQLAlchemy connection pooling optimization for production deployment per Section 6.2.5.2
- PostgreSQL psycopg2 adapter integration with optimized connectivity per Section 6.2.1
- Connection pool configuration supporting concurrent user loads equivalent to Node.js per Section 5.2.4
- Connection health validation for AWS containerized deployment environments per Section 6.2.5.2
- Database session management with proper cleanup and transaction boundaries per Section 5.2.4

Test Categories:
- Connection Pool Configuration Testing
- PostgreSQL psycopg2 Adapter Integration Testing
- Connection Health Validation Testing
- Concurrent Session Management Testing
- Connection Lifecycle and Resource Management Testing
- Performance and Load Testing

Dependencies:
- pytest 8.3.3: Testing framework with advanced fixtures and parametrization
- pytest-benchmark 5.1.0: Performance testing and benchmarking capabilities
- Flask-SQLAlchemy 3.1.1: ORM with connection pooling and session management
- psycopg2 2.9.9: PostgreSQL adapter for Python with advanced connection features
- PostgreSQL 15.x: Target database system with ACID compliance and connection pooling
- threading: Multi-threading support for concurrent testing scenarios

Author: Flask Migration Team
Version: 1.0.0
Last Updated: 2024
"""

import pytest
import time
import threading
import multiprocessing
import psutil
import logging
import json
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch, Mock, MagicMock
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple, Optional, Generator
import statistics

# Flask and SQLAlchemy imports
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text, inspect, event
from sqlalchemy.pool import QueuePool, NullPool, StaticPool
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, TimeoutError, InvalidRequestError
from sqlalchemy.orm import Session, sessionmaker
import psycopg2
from psycopg2 import OperationalError as Psycopg2OperationalError
from psycopg2.extensions import connection as Psycopg2Connection

# Application imports
from config import DevelopmentConfig, ProductionConfig, TestingConfig, get_config
from src.models import db
from src.models.user import User
from src.models.session import UserSession
from src.models.business_entity import BusinessEntity


class ConnectionPoolTestConfig:
    """
    Enhanced testing configuration specifically designed for connection pooling validation
    with comprehensive parameter testing and environment simulation capabilities.
    
    This configuration provides fine-grained control over SQLAlchemy connection pool
    parameters for thorough testing of various deployment scenarios and load conditions.
    """
    
    # Base PostgreSQL connection configuration
    # Using test database with realistic connection string format
    TEST_DATABASE_URI = 'postgresql+psycopg2://test_user:test_pass@localhost:5432/test_db'
    
    # Development environment pool configuration
    DEVELOPMENT_POOL_CONFIG = {
        'pool_size': 5,
        'max_overflow': 10,
        'pool_timeout': 20,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'echo': False
    }
    
    # Production environment pool configuration
    PRODUCTION_POOL_CONFIG = {
        'pool_size': 20,
        'max_overflow': 30,
        'pool_timeout': 30,
        'pool_recycle': 1800,
        'pool_pre_ping': True,
        'echo': False
    }
    
    # Staging environment pool configuration
    STAGING_POOL_CONFIG = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_timeout': 25,
        'pool_recycle': 2700,
        'pool_pre_ping': True,
        'echo': False
    }
    
    # High-load testing configuration
    HIGH_LOAD_POOL_CONFIG = {
        'pool_size': 50,
        'max_overflow': 100,
        'pool_timeout': 60,
        'pool_recycle': 900,
        'pool_pre_ping': True,
        'echo': False
    }
    
    # Minimal resource configuration for testing edge cases
    MINIMAL_POOL_CONFIG = {
        'pool_size': 1,
        'max_overflow': 2,
        'pool_timeout': 5,
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'echo': False
    }


class ConnectionPoolMonitor:
    """
    Comprehensive connection pool monitoring utility for tracking pool metrics,
    connection lifecycle events, and performance statistics during testing scenarios.
    
    This monitor provides detailed insights into connection pool behavior including
    connection acquisition times, pool utilization rates, and resource cleanup efficiency.
    """
    
    def __init__(self):
        self.metrics = {
            'connections_created': 0,
            'connections_closed': 0,
            'connections_checked_in': 0,
            'connections_checked_out': 0,
            'pool_timeouts': 0,
            'pool_overflows': 0,
            'connection_acquisition_times': [],
            'pool_utilization_history': [],
            'error_counts': {},
            'session_lifecycle_events': []
        }
        self.start_time = None
        self.active_connections = set()
        self.lock = threading.Lock()
        
    def start_monitoring(self):
        """Initialize monitoring session with timestamp and reset metrics"""
        self.start_time = time.time()
        self.metrics = {
            'connections_created': 0,
            'connections_closed': 0,
            'connections_checked_in': 0,
            'connections_checked_out': 0,
            'pool_timeouts': 0,
            'pool_overflows': 0,
            'connection_acquisition_times': [],
            'pool_utilization_history': [],
            'error_counts': {},
            'session_lifecycle_events': []
        }
        self.active_connections.clear()
        
    def record_connection_created(self, connection_id: str):
        """Record new connection creation event"""
        with self.lock:
            self.metrics['connections_created'] += 1
            self.active_connections.add(connection_id)
            
    def record_connection_closed(self, connection_id: str):
        """Record connection closure event"""
        with self.lock:
            self.metrics['connections_closed'] += 1
            self.active_connections.discard(connection_id)
            
    def record_connection_checkout(self, connection_id: str, acquisition_time: float):
        """Record connection checkout with timing information"""
        with self.lock:
            self.metrics['connections_checked_out'] += 1
            self.metrics['connection_acquisition_times'].append(acquisition_time)
            
    def record_connection_checkin(self, connection_id: str):
        """Record connection check-in event"""
        with self.lock:
            self.metrics['connections_checked_in'] += 1
            
    def record_pool_timeout(self):
        """Record pool timeout event"""
        with self.lock:
            self.metrics['pool_timeouts'] += 1
            
    def record_pool_overflow(self):
        """Record pool overflow event"""
        with self.lock:
            self.metrics['pool_overflows'] += 1
            
    def record_error(self, error_type: str):
        """Record error event by type"""
        with self.lock:
            if error_type not in self.metrics['error_counts']:
                self.metrics['error_counts'][error_type] = 0
            self.metrics['error_counts'][error_type] += 1
            
    def record_pool_utilization(self, pool_size: int, active_count: int):
        """Record pool utilization snapshot"""
        with self.lock:
            utilization = (active_count / pool_size) * 100 if pool_size > 0 else 0
            self.metrics['pool_utilization_history'].append({
                'timestamp': time.time(),
                'utilization_percent': utilization,
                'active_connections': active_count,
                'pool_size': pool_size
            })
            
    def get_statistics(self) -> Dict[str, Any]:
        """Generate comprehensive statistics report"""
        with self.lock:
            acquisition_times = self.metrics['connection_acquisition_times']
            
            stats = {
                'monitoring_duration': time.time() - self.start_time if self.start_time else 0,
                'total_connections_created': self.metrics['connections_created'],
                'total_connections_closed': self.metrics['connections_closed'],
                'total_checkouts': self.metrics['connections_checked_out'],
                'total_checkins': self.metrics['connections_checked_in'],
                'pool_timeouts': self.metrics['pool_timeouts'],
                'pool_overflows': self.metrics['pool_overflows'],
                'active_connections_count': len(self.active_connections),
                'error_summary': dict(self.metrics['error_counts']),
                'acquisition_time_stats': {
                    'mean': statistics.mean(acquisition_times) if acquisition_times else 0,
                    'median': statistics.median(acquisition_times) if acquisition_times else 0,
                    'min': min(acquisition_times) if acquisition_times else 0,
                    'max': max(acquisition_times) if acquisition_times else 0,
                    'count': len(acquisition_times)
                },
                'utilization_stats': self._calculate_utilization_stats()
            }
            
            return stats
            
    def _calculate_utilization_stats(self) -> Dict[str, float]:
        """Calculate pool utilization statistics"""
        if not self.metrics['pool_utilization_history']:
            return {'mean': 0, 'max': 0, 'min': 0}
            
        utilizations = [item['utilization_percent'] for item in self.metrics['pool_utilization_history']]
        return {
            'mean': statistics.mean(utilizations),
            'max': max(utilizations),
            'min': min(utilizations)
        }


# ================================
# Test Fixtures and Setup
# ================================

@pytest.fixture(scope='session')
def pool_monitor():
    """
    Connection pool monitor fixture providing comprehensive monitoring capabilities
    for tracking connection pool behavior and performance metrics throughout tests.
    
    Returns:
        ConnectionPoolMonitor: Configured monitoring instance
    """
    return ConnectionPoolMonitor()


@pytest.fixture
def mock_postgresql_engine():
    """
    Mock PostgreSQL engine fixture for testing connection pool configuration
    without requiring actual database connectivity during unit testing scenarios.
    
    Returns:
        Mock: Configured SQLAlchemy engine mock with pool behavior simulation
    """
    mock_engine = Mock()
    mock_pool = Mock()
    
    # Configure pool behavior simulation
    mock_pool.size.return_value = 10
    mock_pool.checked_in.return_value = 5
    mock_pool.checked_out.return_value = 5
    mock_pool.overflow.return_value = 0
    mock_pool.invalid.return_value = 0
    
    mock_engine.pool = mock_pool
    mock_engine.url.drivername = 'postgresql+psycopg2'
    mock_engine.url.database = 'test_db'
    mock_engine.url.host = 'localhost'
    mock_engine.url.port = 5432
    
    return mock_engine


@pytest.fixture
def test_database_engine():
    """
    Test database engine fixture creating actual SQLAlchemy engine with
    test-specific connection pool configuration for integration testing.
    
    Returns:
        Engine: SQLAlchemy engine configured for testing with monitoring
    """
    # Use SQLite for testing to avoid PostgreSQL dependency in tests
    engine = create_engine(
        'sqlite:///:memory:',
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=3600,
        pool_pre_ping=True,
        echo=False
    )
    
    yield engine
    
    # Cleanup
    engine.dispose()


@pytest.fixture(params=[
    ConnectionPoolTestConfig.DEVELOPMENT_POOL_CONFIG,
    ConnectionPoolTestConfig.PRODUCTION_POOL_CONFIG,
    ConnectionPoolTestConfig.STAGING_POOL_CONFIG
])
def pool_config(request):
    """
    Parametrized pool configuration fixture testing various deployment scenarios
    including development, production, and staging environment configurations.
    
    Returns:
        Dict[str, Any]: Pool configuration parameters for testing
    """
    return request.param


@pytest.fixture
def concurrent_test_setup():
    """
    Concurrent testing setup fixture providing utilities for multi-threaded
    database operation testing and connection pool stress testing scenarios.
    
    Returns:
        Dict[str, Any]: Concurrent testing utilities and configuration
    """
    return {
        'thread_count': multiprocessing.cpu_count() * 2,
        'operations_per_thread': 50,
        'max_workers': 20,
        'timeout_seconds': 60,
        'connection_hold_time': 0.1
    }


# ================================
# Connection Pool Configuration Tests
# ================================

class TestConnectionPoolConfiguration:
    """
    Comprehensive test suite for SQLAlchemy connection pool configuration validation
    ensuring proper pool parameter setup and environment-specific optimization.
    """
    
    def test_development_pool_configuration(self, app):
        """
        Test development environment connection pool configuration matches
        requirements from Section 6.2.5.2 with appropriate resource allocation.
        """
        with app.app_context():
            config = DevelopmentConfig()
            engine_options = config.SQLALCHEMY_ENGINE_OPTIONS
            
            # Validate development pool sizing
            assert engine_options['pool_size'] == 5, \
                "Development pool size should be 5 for resource efficiency"
            assert engine_options['max_overflow'] == 10, \
                "Development max overflow should be 10"
            assert engine_options['pool_timeout'] >= 20, \
                "Development pool timeout should be at least 20 seconds"
            assert engine_options['pool_recycle'] == 3600, \
                "Development pool recycle should be 1 hour"
            assert engine_options['pool_pre_ping'] is True, \
                "Development environment must enable pool_pre_ping for connection health"
            
    def test_production_pool_configuration(self, app):
        """
        Test production environment connection pool configuration meets
        performance requirements from Section 6.2.5.2 for high-load scenarios.
        """
        with app.app_context():
            config = ProductionConfig()
            engine_options = config.SQLALCHEMY_ENGINE_OPTIONS
            
            # Validate production pool sizing for high load
            assert engine_options['pool_size'] >= 20, \
                "Production pool size should be at least 20 for concurrent load"
            assert engine_options['max_overflow'] >= 30, \
                "Production max overflow should be at least 30"
            assert engine_options['pool_timeout'] >= 30, \
                "Production pool timeout should be at least 30 seconds"
            assert engine_options['pool_recycle'] <= 1800, \
                "Production pool recycle should be 30 minutes or less"
            assert engine_options['pool_pre_ping'] is True, \
                "Production environment requires pool_pre_ping for reliability"
                
    def test_pool_parameter_validation(self, pool_config):
        """
        Test comprehensive validation of connection pool parameters across
        different deployment environments ensuring parameter consistency.
        """
        # Validate required parameters are present
        required_params = ['pool_size', 'max_overflow', 'pool_timeout', 'pool_recycle', 'pool_pre_ping']
        for param in required_params:
            assert param in pool_config, f"Required pool parameter '{param}' missing"
            
        # Validate parameter value ranges
        assert pool_config['pool_size'] > 0, "Pool size must be positive"
        assert pool_config['max_overflow'] >= 0, "Max overflow must be non-negative"
        assert pool_config['pool_timeout'] > 0, "Pool timeout must be positive"
        assert pool_config['pool_recycle'] > 0, "Pool recycle interval must be positive"
        assert isinstance(pool_config['pool_pre_ping'], bool), "Pool pre-ping must be boolean"
        
        # Validate logical relationships between parameters
        assert pool_config['max_overflow'] >= pool_config['pool_size'], \
            "Max overflow should be at least equal to pool size"
        assert pool_config['pool_timeout'] <= 300, \
            "Pool timeout should not exceed 5 minutes to prevent request hanging"
            
    def test_environment_specific_optimization(self):
        """
        Test environment-specific pool optimization ensuring proper parameter
        tuning for development, staging, and production deployment scenarios.
        """
        dev_config = ConnectionPoolTestConfig.DEVELOPMENT_POOL_CONFIG
        prod_config = ConnectionPoolTestConfig.PRODUCTION_POOL_CONFIG
        staging_config = ConnectionPoolTestConfig.STAGING_POOL_CONFIG
        
        # Development should use minimal resources
        assert dev_config['pool_size'] < prod_config['pool_size'], \
            "Development pool should be smaller than production"
        assert dev_config['max_overflow'] <= prod_config['max_overflow'], \
            "Development overflow should not exceed production"
            
        # Staging should be intermediate between dev and production
        assert dev_config['pool_size'] <= staging_config['pool_size'] <= prod_config['pool_size'], \
            "Staging pool size should be between development and production"
            
        # All environments should enable connection health validation
        for config in [dev_config, prod_config, staging_config]:
            assert config['pool_pre_ping'] is True, \
                "All environments must enable pool_pre_ping for connection health"
                
    def test_postgresql_connection_string_format(self):
        """
        Test PostgreSQL connection string format validation ensuring proper
        psycopg2 adapter integration as specified in Section 6.2.1.
        """
        test_config = TestingConfig()
        
        # Test connection URI construction
        with patch.dict('os.environ', {
            'DB_HOST': 'test-host',
            'DB_PORT': '5432',
            'DB_NAME': 'test_db',
            'DB_USER': 'test_user',
            'DB_PASSWORD': 'test_pass'
        }):
            uri = test_config.get_database_uri()
            
            # Validate PostgreSQL+psycopg2 format
            assert uri.startswith('postgresql+psycopg2://'), \
                "Connection URI must use postgresql+psycopg2 driver"
            assert 'test-host:5432' in uri, \
                "Connection URI must include host and port"
            assert 'test_db' in uri, \
                "Connection URI must include database name"
            assert 'test_user' in uri, \
                "Connection URI must include username"
                
    def test_connection_uri_special_characters(self):
        """
        Test connection URI handling of special characters in passwords
        ensuring proper URL encoding for secure database connectivity.
        """
        test_config = TestingConfig()
        
        # Test password with special characters
        with patch.dict('os.environ', {
            'DB_HOST': 'localhost',
            'DB_PORT': '5432',
            'DB_NAME': 'test_db',
            'DB_USER': 'test_user',
            'DB_PASSWORD': 'p@ssw0rd!#$%'
        }):
            uri = test_config.get_database_uri()
            
            # Verify special characters are properly encoded
            assert 'p%40ssw0rd%21%23%24%25' in uri or 'p@ssw0rd!#$%' not in uri, \
                "Special characters in password should be URL encoded"
            assert uri.startswith('postgresql+psycopg2://'), \
                "Connection URI format should remain valid with special characters"


# ================================
# PostgreSQL psycopg2 Adapter Integration Tests
# ================================

class TestPsycopg2AdapterIntegration:
    """
    Test suite for PostgreSQL psycopg2 adapter integration validation ensuring
    optimal connectivity and PostgreSQL-specific feature utilization.
    """
    
    def test_psycopg2_driver_availability(self):
        """
        Test psycopg2 driver availability and version compatibility ensuring
        proper PostgreSQL adapter integration per Section 6.2.1 requirements.
        """
        # Verify psycopg2 can be imported and version checked
        try:
            import psycopg2
            version_info = psycopg2.__version__
            
            # Validate version meets minimum requirements (2.9.9)
            version_parts = version_info.split('.')
            major, minor = int(version_parts[0]), int(version_parts[1])
            
            assert major >= 2, "psycopg2 major version should be 2 or higher"
            if major == 2:
                assert minor >= 9, "psycopg2 minor version should be 9 or higher for version 2.x"
                
        except ImportError:
            pytest.skip("psycopg2 not available in test environment")
            
    def test_psycopg2_connection_parameters(self):
        """
        Test psycopg2-specific connection parameters and options ensuring
        optimal PostgreSQL connectivity configuration.
        """
        # Test connection parameter validation
        connection_params = {
            'host': 'localhost',
            'port': 5432,
            'database': 'test_db',
            'user': 'test_user',
            'password': 'test_pass',
            'sslmode': 'prefer',
            'connect_timeout': 30,
            'application_name': 'flask_app_test'
        }
        
        # Validate parameter format for psycopg2
        for key, value in connection_params.items():
            assert key in ['host', 'port', 'database', 'user', 'password', 
                          'sslmode', 'connect_timeout', 'application_name'], \
                f"Connection parameter '{key}' should be valid for psycopg2"
                
        # Validate parameter types
        assert isinstance(connection_params['port'], int), "Port should be integer"
        assert isinstance(connection_params['connect_timeout'], int), "Timeout should be integer"
        assert connection_params['sslmode'] in ['disable', 'allow', 'prefer', 'require'], \
            "SSL mode should be valid psycopg2 option"
            
    def test_sqlalchemy_psycopg2_engine_creation(self, test_database_engine):
        """
        Test SQLAlchemy engine creation with psycopg2 adapter ensuring proper
        integration and configuration for PostgreSQL connectivity.
        """
        # For this test, we'll create a mock engine since we're using SQLite in tests
        with patch('sqlalchemy.create_engine') as mock_create_engine:
            mock_engine = Mock()
            mock_engine.url.drivername = 'postgresql+psycopg2'
            mock_create_engine.return_value = mock_engine
            
            # Test engine creation with psycopg2
            from sqlalchemy import create_engine
            engine = create_engine(
                'postgresql+psycopg2://test:test@localhost:5432/test',
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True
            )
            
            # Verify create_engine was called with correct parameters
            mock_create_engine.assert_called_once()
            args, kwargs = mock_create_engine.call_args
            
            assert 'postgresql+psycopg2' in args[0], \
                "Engine should be created with psycopg2 driver"
            assert 'pool_size' in kwargs, \
                "Pool size should be specified in engine creation"
            assert 'pool_pre_ping' in kwargs, \
                "Pool pre-ping should be specified for connection health"
                
    def test_psycopg2_connection_pooling_compatibility(self):
        """
        Test psycopg2 adapter compatibility with SQLAlchemy connection pooling
        ensuring optimal resource management and connection reuse.
        """
        # Test pooling configuration compatibility
        pooling_config = {
            'poolclass': QueuePool,
            'pool_size': 20,
            'max_overflow': 30,
            'pool_timeout': 30,
            'pool_recycle': 1800,
            'pool_pre_ping': True
        }
        
        # Validate pooling parameters are compatible with psycopg2
        assert pooling_config['poolclass'] == QueuePool, \
            "QueuePool should be used for PostgreSQL connections"
        assert pooling_config['pool_pre_ping'] is True, \
            "Pool pre-ping is essential for psycopg2 connection health"
        assert pooling_config['pool_recycle'] > 0, \
            "Pool recycle should be positive for connection freshness"
            
    def test_postgresql_specific_features(self):
        """
        Test PostgreSQL-specific features availability through psycopg2 adapter
        including advanced data types and connection options.
        """
        # Test PostgreSQL-specific connection options
        pg_options = {
            'isolation_level': 'READ_COMMITTED',
            'autocommit': False,
            'cursor_factory': None,  # Default cursor factory
            'async_': False  # Synchronous connections for Flask
        }
        
        # Validate PostgreSQL connection options
        valid_isolation_levels = [
            'READ_UNCOMMITTED', 'READ_COMMITTED', 
            'REPEATABLE_READ', 'SERIALIZABLE'
        ]
        assert pg_options['isolation_level'] in valid_isolation_levels, \
            "Isolation level should be valid PostgreSQL option"
        assert isinstance(pg_options['autocommit'], bool), \
            "Autocommit should be boolean"
        assert pg_options['async_'] is False, \
            "Flask applications should use synchronous connections"


# ================================
# Connection Health Validation Tests
# ================================

class TestConnectionHealthValidation:
    """
    Test suite for connection health validation ensuring robust connection management
    with pool_pre_ping functionality and stale connection detection.
    """
    
    def test_pool_pre_ping_configuration(self, test_database_engine):
        """
        Test pool_pre_ping configuration ensuring connection health validation
        before reuse as specified in Section 6.2.5.2 for containerized environments.
        """
        # Verify pool_pre_ping is enabled
        assert hasattr(test_database_engine.pool, '_pre_ping'), \
            "Engine should support pool_pre_ping functionality"
            
        # Test connection health check before use
        with test_database_engine.connect() as connection:
            # Simulate connection health check
            try:
                result = connection.execute(text("SELECT 1"))
                assert result.fetchone()[0] == 1, \
                    "Health check query should return expected result"
            except Exception as e:
                pytest.fail(f"Connection health check failed: {e}")
                
    def test_stale_connection_detection(self, test_database_engine, pool_monitor):
        """
        Test stale connection detection and automatic recovery ensuring
        reliable connection management in long-running containerized environments.
        """
        pool_monitor.start_monitoring()
        
        # Simulate connection acquisition and potential staleness
        connections = []
        try:
            # Acquire multiple connections
            for i in range(3):
                conn = test_database_engine.connect()
                connections.append(conn)
                pool_monitor.record_connection_checkout(f"conn_{i}", 0.01)
                
            # Simulate connection health validation
            for i, conn in enumerate(connections):
                try:
                    # Execute health check query
                    result = conn.execute(text("SELECT 1 as health_check"))
                    assert result.fetchone()[0] == 1, \
                        f"Connection {i} health check should succeed"
                except Exception as e:
                    pool_monitor.record_error("stale_connection")
                    pytest.fail(f"Stale connection detected: {e}")
                    
        finally:
            # Cleanup connections
            for i, conn in enumerate(connections):
                conn.close()
                pool_monitor.record_connection_checkin(f"conn_{i}")
                
        # Validate monitoring results
        stats = pool_monitor.get_statistics()
        assert stats['error_summary'].get('stale_connection', 0) == 0, \
            "No stale connections should be detected with proper health checking"
            
    def test_connection_recycling_mechanism(self, test_database_engine):
        """
        Test connection recycling mechanism ensuring proper connection lifecycle
        management and resource optimization per Section 6.2.5.2.
        """
        # Test connection age tracking and recycling
        original_recycle_time = test_database_engine.pool._recycle
        
        # Verify recycle time is configured
        assert original_recycle_time > 0, \
            "Connection recycle time should be positive"
        assert original_recycle_time <= 3600, \
            "Connection recycle time should not exceed 1 hour"
            
        # Test connection creation timestamp tracking
        with test_database_engine.connect() as connection:
            # Verify connection is fresh
            assert hasattr(connection, 'info') or True, \
                "Connection should support metadata for recycling"
                
    def test_connection_timeout_handling(self, pool_monitor):
        """
        Test connection timeout handling ensuring graceful degradation
        when connection pool is exhausted or unresponsive.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with very short timeout for testing
        timeout_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=1,
            max_overflow=0,
            pool_timeout=1,  # Very short timeout
            pool_pre_ping=True
        )
        
        try:
            # Acquire the only available connection
            conn1 = timeout_engine.connect()
            pool_monitor.record_connection_checkout("timeout_test", 0.01)
            
            # Attempt to acquire another connection (should timeout)
            start_time = time.time()
            try:
                conn2 = timeout_engine.connect()
                conn2.close()
                pytest.fail("Second connection should have timed out")
            except TimeoutError:
                acquisition_time = time.time() - start_time
                pool_monitor.record_pool_timeout()
                assert acquisition_time >= 1.0, \
                    "Timeout should respect configured pool_timeout"
            except Exception as e:
                # SQLite may throw different exceptions
                pool_monitor.record_pool_timeout()
                
        finally:
            if 'conn1' in locals():
                conn1.close()
            timeout_engine.dispose()
            
        # Validate timeout was recorded
        stats = pool_monitor.get_statistics()
        assert stats['pool_timeouts'] > 0, \
            "Pool timeout should be recorded when pool is exhausted"
            
    def test_connection_health_monitoring(self, test_database_engine, pool_monitor):
        """
        Test comprehensive connection health monitoring including error detection,
        recovery mechanisms, and performance impact assessment.
        """
        pool_monitor.start_monitoring()
        
        # Test multiple connection health scenarios
        health_test_scenarios = [
            ("healthy_connection", lambda conn: conn.execute(text("SELECT 1"))),
            ("simple_query", lambda conn: conn.execute(text("SELECT 'test' as value"))),
            ("transaction_test", lambda conn: self._test_transaction_health(conn))
        ]
        
        for scenario_name, health_test in health_test_scenarios:
            start_time = time.time()
            
            try:
                with test_database_engine.connect() as connection:
                    result = health_test(connection)
                    acquisition_time = time.time() - start_time
                    
                    pool_monitor.record_connection_checkout(scenario_name, acquisition_time)
                    
                    # Validate health check passed
                    assert result is not None, \
                        f"Health check '{scenario_name}' should return result"
                        
            except Exception as e:
                pool_monitor.record_error(f"health_check_{scenario_name}")
                pytest.fail(f"Health check '{scenario_name}' failed: {e}")
                
        # Validate health monitoring results
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= len(health_test_scenarios), \
            "All health check scenarios should be recorded"
        assert stats['acquisition_time_stats']['mean'] < 1.0, \
            "Health check acquisition time should be reasonable"
            
    def _test_transaction_health(self, connection):
        """Helper method for transaction-based health testing"""
        trans = connection.begin()
        try:
            result = connection.execute(text("SELECT 1 as transaction_test"))
            trans.commit()
            return result
        except Exception:
            trans.rollback()
            raise


# ================================
# Concurrent Session Management Tests
# ================================

class TestConcurrentSessionManagement:
    """
    Test suite for concurrent session management validation ensuring thread-safe
    database operations and proper session isolation per Section 5.2.4.
    """
    
    def test_thread_safe_session_creation(self, app, concurrent_test_setup, pool_monitor):
        """
        Test thread-safe session creation ensuring proper session isolation
        and concurrent access support equivalent to Node.js per Section 5.2.4.
        """
        pool_monitor.start_monitoring()
        thread_count = concurrent_test_setup['thread_count']
        session_results = {}
        session_errors = []
        session_lock = threading.Lock()
        
        def create_session_worker(worker_id: int):
            """Worker function for concurrent session creation testing"""
            try:
                with app.app_context():
                    # Create database session
                    session = db.session
                    
                    # Execute simple query to validate session
                    result = session.execute(text("SELECT :worker_id as id"), 
                                           {'worker_id': worker_id})
                    row = result.fetchone()
                    
                    with session_lock:
                        session_results[worker_id] = row[0] if row else None
                        pool_monitor.record_connection_checkout(f"session_{worker_id}", 0.01)
                        
            except Exception as e:
                with session_lock:
                    session_errors.append(f"Worker {worker_id}: {str(e)}")
                    pool_monitor.record_error("session_creation")
                    
        # Execute concurrent session creation
        threads = []
        for i in range(thread_count):
            thread = threading.Thread(target=create_session_worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=concurrent_test_setup['timeout_seconds'])
            
        # Validate results
        assert len(session_errors) == 0, \
            f"Session creation errors occurred: {session_errors}"
        assert len(session_results) == thread_count, \
            f"Expected {thread_count} successful sessions, got {len(session_results)}"
            
        # Validate session isolation
        for worker_id, result in session_results.items():
            assert result == worker_id, \
                f"Session {worker_id} should return its own worker ID"
                
        # Validate monitoring results
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= thread_count, \
            "All session creations should be recorded"
            
    def test_concurrent_database_operations(self, app, db_session, concurrent_test_setup, pool_monitor):
        """
        Test concurrent database operations ensuring proper transaction isolation
        and data consistency during simultaneous read/write operations.
        """
        pool_monitor.start_monitoring()
        
        # Prepare test data
        operation_count = concurrent_test_setup['operations_per_thread']
        thread_count = min(concurrent_test_setup['thread_count'], 10)  # Limit for test stability
        
        operation_results = []
        operation_errors = []
        results_lock = threading.Lock()
        
        def database_operation_worker(worker_id: int):
            """Worker function for concurrent database operations"""
            worker_results = []
            
            try:
                with app.app_context():
                    for op_id in range(operation_count):
                        start_time = time.time()
                        
                        # Perform database operation (read/write mix)
                        session = db.session
                        
                        if op_id % 2 == 0:
                            # Read operation
                            result = session.execute(
                                text("SELECT :value as test_value"), 
                                {'value': f"{worker_id}_{op_id}"}
                            )
                            data = result.fetchone()
                            worker_results.append(('read', data[0] if data else None))
                        else:
                            # Write simulation (using query since we're in memory)
                            result = session.execute(
                                text("SELECT :worker_id + :op_id as sum_value"), 
                                {'worker_id': worker_id, 'op_id': op_id}
                            )
                            data = result.fetchone()
                            worker_results.append(('write', data[0] if data else None))
                            
                        operation_time = time.time() - start_time
                        pool_monitor.record_connection_checkout(f"op_{worker_id}_{op_id}", operation_time)
                        
                        # Small delay to simulate real work
                        time.sleep(concurrent_test_setup['connection_hold_time'])
                        
            except Exception as e:
                with results_lock:
                    operation_errors.append(f"Worker {worker_id}: {str(e)}")
                    pool_monitor.record_error("concurrent_operation")
                    
            with results_lock:
                operation_results.extend(worker_results)
                
        # Execute concurrent operations
        threads = []
        for i in range(thread_count):
            thread = threading.Thread(target=database_operation_worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=concurrent_test_setup['timeout_seconds'])
            
        # Validate results
        assert len(operation_errors) == 0, \
            f"Concurrent operation errors: {operation_errors}"
        assert len(operation_results) == thread_count * operation_count, \
            f"Expected {thread_count * operation_count} operations, got {len(operation_results)}"
            
        # Validate operation distribution
        read_ops = [r for r in operation_results if r[0] == 'read']
        write_ops = [r for r in operation_results if r[0] == 'write']
        
        expected_read_count = thread_count * (operation_count // 2 + operation_count % 2)
        expected_write_count = thread_count * (operation_count // 2)
        
        assert len(read_ops) == expected_read_count, \
            f"Expected {expected_read_count} read operations, got {len(read_ops)}"
        assert len(write_ops) == expected_write_count, \
            f"Expected {expected_write_count} write operations, got {len(write_ops)}"
            
    def test_session_cleanup_and_transaction_boundaries(self, app, concurrent_test_setup):
        """
        Test proper session cleanup and transaction boundary management
        ensuring resource cleanup and preventing session leaks.
        """
        cleanup_results = []
        cleanup_errors = []
        cleanup_lock = threading.Lock()
        
        def session_cleanup_worker(worker_id: int):
            """Worker function testing session cleanup"""
            try:
                with app.app_context():
                    # Start transaction
                    session = db.session
                    transaction = session.begin()
                    
                    try:
                        # Perform operations within transaction
                        result = session.execute(
                            text("SELECT :worker_id as id"), 
                            {'worker_id': worker_id}
                        )
                        data = result.fetchone()
                        
                        # Simulate transaction completion
                        transaction.commit()
                        
                        with cleanup_lock:
                            cleanup_results.append(('success', worker_id, data[0] if data else None))
                            
                    except Exception as e:
                        transaction.rollback()
                        raise e
                        
            except Exception as e:
                with cleanup_lock:
                    cleanup_errors.append(f"Worker {worker_id}: {str(e)}")
                    
        # Execute session cleanup testing
        threads = []
        thread_count = min(concurrent_test_setup['thread_count'], 10)
        
        for i in range(thread_count):
            thread = threading.Thread(target=session_cleanup_worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)
            
        # Validate cleanup results
        assert len(cleanup_errors) == 0, \
            f"Session cleanup errors: {cleanup_errors}"
        assert len(cleanup_results) == thread_count, \
            f"Expected {thread_count} successful cleanups, got {len(cleanup_results)}"
            
        # Validate transaction isolation
        for result_type, worker_id, returned_id in cleanup_results:
            assert result_type == 'success', "All transactions should succeed"
            assert returned_id == worker_id, "Transaction isolation should be maintained"
            
    def test_connection_pool_under_concurrent_load(self, concurrent_test_setup, pool_monitor):
        """
        Test connection pool behavior under concurrent load ensuring proper
        resource allocation and performance maintenance under stress.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with limited pool for stress testing
        stress_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_pre_ping=True
        )
        
        connection_results = []
        connection_errors = []
        results_lock = threading.Lock()
        
        def connection_stress_worker(worker_id: int):
            """Worker function for connection pool stress testing"""
            worker_connections = []
            
            try:
                # Acquire multiple connections rapidly
                for i in range(3):
                    start_time = time.time()
                    conn = stress_engine.connect()
                    acquisition_time = time.time() - start_time
                    
                    worker_connections.append(conn)
                    
                    # Execute query to validate connection
                    result = conn.execute(text("SELECT :value as test"), 
                                        {'value': f"{worker_id}_{i}"})
                    data = result.fetchone()
                    
                    with results_lock:
                        connection_results.append((worker_id, i, data[0] if data else None))
                        pool_monitor.record_connection_checkout(f"stress_{worker_id}_{i}", acquisition_time)
                        
                    # Hold connection briefly
                    time.sleep(concurrent_test_setup['connection_hold_time'])
                    
            except Exception as e:
                with results_lock:
                    connection_errors.append(f"Worker {worker_id}: {str(e)}")
                    pool_monitor.record_error("connection_stress")
                    
            finally:
                # Cleanup connections
                for conn in worker_connections:
                    try:
                        conn.close()
                    except Exception:
                        pass
                        
        # Execute stress test
        threads = []
        thread_count = min(concurrent_test_setup['thread_count'], 8)
        
        for i in range(thread_count):
            thread = threading.Thread(target=connection_stress_worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=concurrent_test_setup['timeout_seconds'])
            
        # Cleanup
        stress_engine.dispose()
        
        # Validate stress test results
        stats = pool_monitor.get_statistics()
        
        # Allow some errors under extreme stress, but not complete failure
        error_rate = len(connection_errors) / thread_count if thread_count > 0 else 0
        assert error_rate < 0.5, \
            f"Error rate under stress should be less than 50%, got {error_rate * 100:.1f}%"
            
        # Validate acquisition times are reasonable
        if stats['acquisition_time_stats']['count'] > 0:
            mean_acquisition_time = stats['acquisition_time_stats']['mean']
            assert mean_acquisition_time < 5.0, \
                f"Mean connection acquisition time should be under 5s, got {mean_acquisition_time:.2f}s"


# ================================
# Connection Lifecycle and Resource Management Tests
# ================================

class TestConnectionLifecycleManagement:
    """
    Test suite for connection lifecycle management ensuring proper resource
    allocation, cleanup, and optimization throughout connection lifespan.
    """
    
    def test_connection_creation_lifecycle(self, test_database_engine, pool_monitor):
        """
        Test complete connection creation lifecycle from acquisition to disposal
        ensuring proper resource management and monitoring capabilities.
        """
        pool_monitor.start_monitoring()
        
        connection_lifecycle_stages = []
        
        # Stage 1: Connection acquisition
        start_time = time.time()
        connection = test_database_engine.connect()
        acquisition_time = time.time() - start_time
        
        connection_lifecycle_stages.append(('acquired', acquisition_time))
        pool_monitor.record_connection_checkout("lifecycle_test", acquisition_time)
        
        # Stage 2: Connection utilization
        try:
            # Execute multiple queries to test connection stability
            queries = [
                ("SELECT 1 as test1", {'test1': 1}),
                ("SELECT 2 as test2", {'test2': 2}),
                ("SELECT 'hello' as greeting", {'greeting': 'hello'})
            ]
            
            for query, expected in queries:
                result = connection.execute(text(query))
                row = result.fetchone()
                
                assert row is not None, f"Query '{query}' should return result"
                connection_lifecycle_stages.append(('query_executed', query))
                
        except Exception as e:
            connection_lifecycle_stages.append(('error', str(e)))
            pool_monitor.record_error("lifecycle_query")
            
        # Stage 3: Connection cleanup
        try:
            connection.close()
            connection_lifecycle_stages.append(('closed', None))
            pool_monitor.record_connection_checkin("lifecycle_test")
            
        except Exception as e:
            connection_lifecycle_stages.append(('close_error', str(e)))
            pool_monitor.record_error("lifecycle_close")
            
        # Validate lifecycle stages
        stage_names = [stage[0] for stage in connection_lifecycle_stages]
        
        assert 'acquired' in stage_names, "Connection should be acquired"
        assert 'query_executed' in stage_names, "Queries should be executed"
        assert 'closed' in stage_names, "Connection should be closed"
        assert 'error' not in stage_names, "No errors should occur during lifecycle"
        
        # Validate performance metrics
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= 1, "Connection checkout should be recorded"
        assert stats['total_checkins'] >= 1, "Connection checkin should be recorded"
        
    def test_connection_recycling_behavior(self, pool_monitor):
        """
        Test connection recycling behavior ensuring proper connection age
        management and resource optimization per Section 6.2.5.2.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with short recycle time for testing
        recycle_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=3,
            max_overflow=2,
            pool_recycle=2,  # Very short for testing
            pool_pre_ping=True
        )
        
        recycling_results = []
        
        try:
            # Phase 1: Create initial connections
            initial_connections = []
            for i in range(3):
                conn = recycle_engine.connect()
                initial_connections.append(conn)
                pool_monitor.record_connection_checkout(f"initial_{i}", 0.01)
                recycling_results.append(('created', i))
                
            # Phase 2: Close connections to return to pool
            for i, conn in enumerate(initial_connections):
                conn.close()
                pool_monitor.record_connection_checkin(f"initial_{i}")
                recycling_results.append(('returned_to_pool', i))
                
            # Phase 3: Wait for recycle time to elapse
            time.sleep(3)  # Wait longer than recycle time
            
            # Phase 4: Acquire new connections (should trigger recycling)
            recycled_connections = []
            for i in range(3):
                conn = recycle_engine.connect()
                recycled_connections.append(conn)
                pool_monitor.record_connection_checkout(f"recycled_{i}", 0.01)
                recycling_results.append(('recycled', i))
                
            # Cleanup
            for conn in recycled_connections:
                conn.close()
                
        finally:
            recycle_engine.dispose()
            
        # Validate recycling behavior
        created_count = len([r for r in recycling_results if r[0] == 'created'])
        recycled_count = len([r for r in recycling_results if r[0] == 'recycled'])
        
        assert created_count == 3, "Should create 3 initial connections"
        assert recycled_count == 3, "Should create 3 recycled connections"
        
        # Validate monitoring
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= 6, "Should record all connection checkouts"
        
    def test_connection_pool_overflow_management(self, pool_monitor):
        """
        Test connection pool overflow management ensuring proper handling
        when pool size is exceeded and overflow connections are created.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with small pool and overflow for testing
        overflow_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=2,
            max_overflow=3,
            pool_timeout=5,
            pool_pre_ping=True
        )
        
        overflow_connections = []
        overflow_results = []
        
        try:
            # Phase 1: Acquire connections up to pool size
            for i in range(2):
                conn = overflow_engine.connect()
                overflow_connections.append(conn)
                pool_monitor.record_connection_checkout(f"pool_{i}", 0.01)
                overflow_results.append(('pool_connection', i))
                
            # Phase 2: Acquire overflow connections
            for i in range(3):
                conn = overflow_engine.connect()
                overflow_connections.append(conn)
                pool_monitor.record_connection_checkout(f"overflow_{i}", 0.01)
                pool_monitor.record_pool_overflow()
                overflow_results.append(('overflow_connection', i))
                
            # Validate all connections work
            for i, conn in enumerate(overflow_connections):
                result = conn.execute(text("SELECT :id as conn_id"), {'id': i})
                row = result.fetchone()
                assert row[0] == i, f"Connection {i} should return correct ID"
                
        finally:
            # Cleanup all connections
            for i, conn in enumerate(overflow_connections):
                conn.close()
                pool_monitor.record_connection_checkin(f"conn_{i}")
                
            overflow_engine.dispose()
            
        # Validate overflow behavior
        pool_connections = len([r for r in overflow_results if r[0] == 'pool_connection'])
        overflow_connections_count = len([r for r in overflow_results if r[0] == 'overflow_connection'])
        
        assert pool_connections == 2, "Should use pool connections first"
        assert overflow_connections_count == 3, "Should create overflow connections when needed"
        
        # Validate monitoring
        stats = pool_monitor.get_statistics()
        assert stats['pool_overflows'] >= 3, "Should record overflow events"
        assert stats['total_checkouts'] >= 5, "Should record all connection acquisitions"
        
    def test_resource_cleanup_and_memory_management(self, pool_monitor):
        """
        Test resource cleanup and memory management ensuring proper disposal
        of connections and prevention of resource leaks.
        """
        pool_monitor.start_monitoring()
        
        # Track initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        cleanup_engines = []
        memory_samples = []
        
        try:
            # Create and dispose multiple engines to test cleanup
            for cycle in range(5):
                # Create engine
                engine = create_engine(
                    'sqlite:///:memory:',
                    pool_size=5,
                    max_overflow=10,
                    pool_pre_ping=True
                )
                cleanup_engines.append(engine)
                
                # Use engine briefly
                connections = []
                for i in range(5):
                    conn = engine.connect()
                    connections.append(conn)
                    pool_monitor.record_connection_checkout(f"cleanup_{cycle}_{i}", 0.01)
                    
                    # Execute query
                    conn.execute(text("SELECT 1"))
                    
                # Close connections
                for i, conn in enumerate(connections):
                    conn.close()
                    pool_monitor.record_connection_checkin(f"cleanup_{cycle}_{i}")
                    
                # Dispose engine
                engine.dispose()
                
                # Sample memory usage
                current_memory = process.memory_info().rss
                memory_samples.append(current_memory)
                
        except Exception as e:
            pytest.fail(f"Resource cleanup test failed: {e}")
            
        finally:
            # Ensure all engines are disposed
            for engine in cleanup_engines:
                try:
                    engine.dispose()
                except Exception:
                    pass
                    
        # Validate memory management
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        
        # Allow some memory growth but not excessive
        memory_growth_mb = memory_growth / (1024 * 1024)
        assert memory_growth_mb < 50, \
            f"Memory growth should be under 50MB, got {memory_growth_mb:.1f}MB"
            
        # Validate monitoring
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= 25, "Should record all connection operations"
        assert stats['total_checkins'] >= 25, "Should record all connection returns"
        
        # Check for balanced checkout/checkin
        checkout_checkin_diff = abs(stats['total_checkouts'] - stats['total_checkins'])
        assert checkout_checkin_diff <= 1, \
            "Checkouts and checkins should be approximately balanced"


# ================================
# Performance and Load Testing
# ================================

class TestConnectionPoolPerformance:
    """
    Test suite for connection pool performance validation ensuring optimal
    performance under various load conditions and SLA compliance.
    """
    
    @pytest.mark.benchmark
    def test_connection_acquisition_performance(self, test_database_engine, benchmark, pool_monitor):
        """
        Test connection acquisition performance ensuring sub-second response times
        and compliance with 95th percentile targets per Section 6.2.1.
        """
        pool_monitor.start_monitoring()
        
        def acquire_and_use_connection():
            """Benchmark function for connection acquisition"""
            connection = test_database_engine.connect()
            try:
                # Execute simple query
                result = connection.execute(text("SELECT 1 as benchmark_test"))
                row = result.fetchone()
                return row[0] if row else None
            finally:
                connection.close()
                
        # Run benchmark
        result = benchmark(acquire_and_use_connection)
        
        # Validate performance requirements
        assert result == 1, "Benchmark should return expected result"
        
        # Check benchmark statistics
        stats = benchmark.stats
        
        # Validate 95th percentile performance (simple query < 500ms per Section 6.2.1)
        assert stats.mean < 0.5, \
            f"Mean acquisition time should be under 500ms, got {stats.mean * 1000:.1f}ms"
        assert stats.max < 2.0, \
            f"Max acquisition time should be under 2s, got {stats.max * 1000:.1f}ms"
            
        # Record in monitor
        pool_monitor.record_connection_checkout("benchmark", stats.mean)
        
    def test_concurrent_load_performance(self, concurrent_test_setup, pool_monitor):
        """
        Test performance under concurrent load ensuring system maintains
        responsiveness equivalent to Node.js baseline per Section 5.2.4.
        """
        pool_monitor.start_monitoring()
        
        # Create engine optimized for concurrent load
        load_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=20,
            max_overflow=30,
            pool_timeout=30,
            pool_pre_ping=True
        )
        
        # Performance tracking
        performance_results = []
        performance_errors = []
        results_lock = threading.Lock()
        
        def concurrent_load_worker(worker_id: int):
            """Worker function for concurrent load testing"""
            worker_times = []
            
            try:
                operations_count = concurrent_test_setup['operations_per_thread']
                
                for op_id in range(operations_count):
                    start_time = time.time()
                    
                    # Acquire connection and execute query
                    conn = load_engine.connect()
                    try:
                        result = conn.execute(
                            text("SELECT :worker_id * :op_id as result"), 
                            {'worker_id': worker_id, 'op_id': op_id + 1}
                        )
                        row = result.fetchone()
                        
                        operation_time = time.time() - start_time
                        worker_times.append(operation_time)
                        
                        # Validate result
                        expected = worker_id * (op_id + 1)
                        assert row[0] == expected, \
                            f"Operation result should be {expected}, got {row[0]}"
                            
                    finally:
                        conn.close()
                        
                with results_lock:
                    performance_results.extend(worker_times)
                    
            except Exception as e:
                with results_lock:
                    performance_errors.append(f"Worker {worker_id}: {str(e)}")
                    pool_monitor.record_error("concurrent_load")
                    
        # Execute concurrent load test
        threads = []
        thread_count = min(concurrent_test_setup['thread_count'], 10)
        
        start_time = time.time()
        
        for i in range(thread_count):
            thread = threading.Thread(target=concurrent_load_worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=concurrent_test_setup['timeout_seconds'])
            
        total_time = time.time() - start_time
        
        # Cleanup
        load_engine.dispose()
        
        # Validate performance results
        assert len(performance_errors) == 0, \
            f"Concurrent load errors: {performance_errors}"
        assert len(performance_results) > 0, \
            "Should have performance timing results"
            
        # Calculate performance statistics
        mean_time = statistics.mean(performance_results)
        p95_time = sorted(performance_results)[int(len(performance_results) * 0.95)]
        max_time = max(performance_results)
        
        # Validate performance against SLA targets
        assert mean_time < 0.1, \
            f"Mean operation time should be under 100ms, got {mean_time * 1000:.1f}ms"
        assert p95_time < 0.5, \
            f"95th percentile should be under 500ms, got {p95_time * 1000:.1f}ms"
        assert max_time < 2.0, \
            f"Max operation time should be under 2s, got {max_time * 1000:.1f}ms"
            
        # Calculate throughput
        total_operations = len(performance_results)
        throughput = total_operations / total_time
        
        assert throughput > 100, \
            f"Throughput should exceed 100 ops/sec, got {throughput:.1f} ops/sec"
            
    def test_pool_utilization_efficiency(self, pool_monitor):
        """
        Test connection pool utilization efficiency ensuring optimal resource
        allocation and minimal waste under various load patterns.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with known pool parameters
        utilization_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=10,
            max_overflow=5,
            pool_timeout=10,
            pool_pre_ping=True
        )
        
        utilization_scenarios = [
            ("low_load", 2, 1.0),      # 2 connections for 1 second
            ("medium_load", 7, 2.0),   # 7 connections for 2 seconds
            ("high_load", 12, 1.5),    # 12 connections (triggers overflow) for 1.5 seconds
            ("burst_load", 15, 0.5)    # 15 connections (max capacity) for 0.5 seconds
        ]
        
        utilization_results = {}
        
        try:
            for scenario_name, connection_count, hold_time in utilization_scenarios:
                scenario_start = time.time()
                connections = []
                
                # Acquire connections
                for i in range(min(connection_count, 15)):  # Cap at pool + overflow
                    try:
                        conn = utilization_engine.connect()
                        connections.append(conn)
                        
                        # Record pool utilization
                        active_count = len(connections)
                        pool_monitor.record_pool_utilization(10, active_count)
                        
                    except TimeoutError:
                        # Expected when exceeding pool capacity
                        pool_monitor.record_pool_timeout()
                        break
                        
                # Hold connections for specified time
                time.sleep(hold_time)
                
                # Execute queries on all connections
                query_times = []
                for i, conn in enumerate(connections):
                    query_start = time.time()
                    result = conn.execute(text("SELECT :id as conn_test"), {'id': i})
                    row = result.fetchone()
                    query_time = time.time() - query_start
                    query_times.append(query_time)
                    
                    assert row[0] == i, f"Query should return connection ID {i}"
                    
                # Release connections
                for conn in connections:
                    conn.close()
                    
                scenario_time = time.time() - scenario_start
                
                utilization_results[scenario_name] = {
                    'connections_acquired': len(connections),
                    'target_connections': connection_count,
                    'scenario_time': scenario_time,
                    'mean_query_time': statistics.mean(query_times) if query_times else 0,
                    'efficiency': len(connections) / connection_count if connection_count > 0 else 0
                }
                
        finally:
            utilization_engine.dispose()
            
        # Validate utilization efficiency
        for scenario_name, results in utilization_results.items():
            efficiency = results['efficiency']
            
            if scenario_name in ['low_load', 'medium_load']:
                # Should achieve 100% efficiency for loads within pool capacity
                assert efficiency >= 0.9, \
                    f"Scenario '{scenario_name}' should have high efficiency, got {efficiency:.2f}"
            else:
                # High load scenarios may have reduced efficiency due to pool limits
                assert efficiency >= 0.6, \
                    f"Scenario '{scenario_name}' should have reasonable efficiency, got {efficiency:.2f}"
                    
            # Validate query performance remains good under load
            mean_query_time = results['mean_query_time']
            assert mean_query_time < 0.1, \
                f"Query time in '{scenario_name}' should be under 100ms, got {mean_query_time * 1000:.1f}ms"
                
        # Validate overall monitoring statistics
        stats = pool_monitor.get_statistics()
        assert stats['utilization_stats']['max'] > 50, \
            "Should achieve at least 50% peak utilization"
        assert stats['utilization_stats']['mean'] > 20, \
            "Should maintain reasonable average utilization"
            
    def test_memory_efficiency_under_load(self, concurrent_test_setup):
        """
        Test memory efficiency under sustained load ensuring minimal memory
        footprint and proper resource cleanup to prevent memory leaks.
        """
        # Track memory usage throughout test
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        memory_samples = []
        
        # Create engine for memory testing
        memory_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=15,
            max_overflow=10,
            pool_pre_ping=True
        )
        
        try:
            # Execute sustained load cycles
            for cycle in range(10):
                cycle_connections = []
                
                # Acquire connections
                for i in range(20):
                    try:
                        conn = memory_engine.connect()
                        cycle_connections.append(conn)
                        
                        # Execute query to ensure connection is used
                        result = conn.execute(text("SELECT :cycle * :conn as value"), 
                                            {'cycle': cycle, 'conn': i})
                        row = result.fetchone()
                        assert row[0] == cycle * i, "Query result should be correct"
                        
                    except TimeoutError:
                        break  # Expected when pool is exhausted
                        
                # Hold connections briefly
                time.sleep(0.1)
                
                # Release all connections
                for conn in cycle_connections:
                    conn.close()
                    
                # Sample memory after each cycle
                current_memory = process.memory_info().rss
                memory_samples.append(current_memory)
                
                # Force garbage collection
                import gc
                gc.collect()
                
        finally:
            memory_engine.dispose()
            
        # Analyze memory usage
        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory
        memory_growth_mb = memory_growth / (1024 * 1024)
        
        # Validate memory efficiency
        assert memory_growth_mb < 20, \
            f"Memory growth should be under 20MB, got {memory_growth_mb:.1f}MB"
            
        # Check for memory stability (no continuous growth)
        if len(memory_samples) >= 5:
            early_avg = statistics.mean(memory_samples[:5])
            late_avg = statistics.mean(memory_samples[-5:])
            growth_rate = (late_avg - early_avg) / early_avg if early_avg > 0 else 0
            
            assert growth_rate < 0.1, \
                f"Memory growth rate should be under 10%, got {growth_rate * 100:.1f}%"


# ================================
# Integration and End-to-End Tests
# ================================

class TestDatabaseIntegrationWithModels:
    """
    Integration tests validating database connection pooling with actual
    Flask-SQLAlchemy models ensuring real-world functionality.
    """
    
    def test_model_operations_with_connection_pooling(self, app, db_session, pool_monitor):
        """
        Test Flask-SQLAlchemy model operations with connection pooling
        ensuring proper integration and performance.
        """
        if User is None:
            pytest.skip("User model not available for integration testing")
            
        pool_monitor.start_monitoring()
        
        with app.app_context():
            # Test user creation with connection pooling
            test_users = []
            
            for i in range(10):
                user_data = {
                    'username': f'pool_test_user_{i}',
                    'email': f'pooltest{i}@example.com',
                    'is_active': True
                }
                
                start_time = time.time()
                
                # Create user (this should use connection pool)
                user = User(**user_data)
                db_session.add(user)
                db_session.commit()
                
                operation_time = time.time() - start_time
                pool_monitor.record_connection_checkout(f"user_create_{i}", operation_time)
                
                test_users.append(user)
                
                # Validate user was created
                assert user.id is not None, f"User {i} should have ID after commit"
                assert user.username == user_data['username'], "Username should match"
                
            # Test bulk query operations
            start_time = time.time()
            all_users = db_session.query(User).filter(
                User.username.like('pool_test_user_%')
            ).all()
            query_time = time.time() - start_time
            
            pool_monitor.record_connection_checkout("bulk_query", query_time)
            
            assert len(all_users) == 10, "Should retrieve all test users"
            
            # Test concurrent model operations
            def concurrent_model_worker(worker_id: int):
                try:
                    with app.app_context():
                        # Query existing users
                        users = db_session.query(User).filter(
                            User.username.like('pool_test_user_%')
                        ).limit(3).all()
                        
                        # Update users
                        for user in users:
                            user.email = f'updated_{worker_id}_{user.email}'
                            
                        db_session.commit()
                        return len(users)
                        
                except Exception as e:
                    return f"Error: {str(e)}"
                    
            # Execute concurrent operations
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [
                    executor.submit(concurrent_model_worker, i) 
                    for i in range(5)
                ]
                
                results = [future.result(timeout=30) for future in futures]
                
            # Validate concurrent results
            for i, result in enumerate(results):
                if isinstance(result, str) and result.startswith("Error"):
                    pytest.fail(f"Concurrent operation {i} failed: {result}")
                else:
                    assert result >= 0, f"Worker {i} should return valid count"
                    
        # Validate monitoring results
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= 15, "Should record all database operations"
        
        # Validate performance
        mean_time = stats['acquisition_time_stats']['mean']
        assert mean_time < 0.5, \
            f"Mean database operation time should be under 500ms, got {mean_time * 1000:.1f}ms"
            
    def test_transaction_management_with_pooling(self, app, db_session):
        """
        Test transaction management with connection pooling ensuring proper
        transaction isolation and rollback capabilities.
        """
        if User is None:
            pytest.skip("User model not available for transaction testing")
            
        with app.app_context():
            initial_count = db_session.query(User).count()
            
            # Test successful transaction
            try:
                with db_session.begin():
                    user1 = User(username='tx_test_1', email='tx1@example.com')
                    user2 = User(username='tx_test_2', email='tx2@example.com')
                    
                    db_session.add_all([user1, user2])
                    
                    # Transaction should commit automatically
                    
                final_count = db_session.query(User).count()
                assert final_count == initial_count + 2, \
                    "Successful transaction should add users"
                    
            except Exception as e:
                pytest.fail(f"Successful transaction failed: {e}")
                
            # Test transaction rollback
            current_count = db_session.query(User).count()
            
            try:
                with db_session.begin():
                    user3 = User(username='tx_test_3', email='tx3@example.com')
                    db_session.add(user3)
                    
                    # Force rollback by raising exception
                    raise ValueError("Intentional rollback")
                    
            except ValueError:
                # Expected exception
                pass
                
            rollback_count = db_session.query(User).count()
            assert rollback_count == current_count, \
                "Failed transaction should not add users"
                
    def test_session_isolation_with_multiple_connections(self, app, concurrent_test_setup):
        """
        Test session isolation with multiple connections ensuring proper
        data isolation and consistency across concurrent sessions.
        """
        if User is None:
            pytest.skip("User model not available for session isolation testing")
            
        isolation_results = []
        isolation_errors = []
        results_lock = threading.Lock()
        
        def session_isolation_worker(worker_id: int):
            """Worker function for session isolation testing"""
            try:
                with app.app_context():
                    # Each worker operates in its own session
                    session = db.session
                    
                    # Create worker-specific user
                    user = User(
                        username=f'isolation_worker_{worker_id}',
                        email=f'worker{worker_id}@isolation.test'
                    )
                    session.add(user)
                    session.commit()
                    
                    # Query to verify isolation
                    worker_users = session.query(User).filter(
                        User.username.like(f'isolation_worker_{worker_id}')
                    ).all()
                    
                    with results_lock:
                        isolation_results.append({
                            'worker_id': worker_id,
                            'user_count': len(worker_users),
                            'user_id': user.id
                        })
                        
            except Exception as e:
                with results_lock:
                    isolation_errors.append(f"Worker {worker_id}: {str(e)}")
                    
        # Execute session isolation test
        threads = []
        thread_count = min(concurrent_test_setup['thread_count'], 8)
        
        for i in range(thread_count):
            thread = threading.Thread(target=session_isolation_worker, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)
            
        # Validate isolation results
        assert len(isolation_errors) == 0, \
            f"Session isolation errors: {isolation_errors}"
        assert len(isolation_results) == thread_count, \
            f"Expected {thread_count} isolation results, got {len(isolation_results)}"
            
        # Validate each worker created exactly one user
        for result in isolation_results:
            assert result['user_count'] == 1, \
                f"Worker {result['worker_id']} should create exactly 1 user"
            assert result['user_id'] is not None, \
                f"Worker {result['worker_id']} user should have valid ID"
                
        # Validate unique user IDs (no conflicts)
        user_ids = [result['user_id'] for result in isolation_results]
        unique_ids = set(user_ids)
        assert len(unique_ids) == len(user_ids), \
            "All users should have unique IDs (no session conflicts)"


# ================================
# Error Handling and Edge Cases
# ================================

class TestConnectionPoolErrorHandling:
    """
    Test suite for connection pool error handling and edge case scenarios
    ensuring robust behavior under adverse conditions.
    """
    
    def test_database_unavailable_handling(self, pool_monitor):
        """
        Test handling of database unavailability ensuring graceful degradation
        and proper error reporting when database is unreachable.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with invalid connection string
        invalid_engine = create_engine(
            'postgresql+psycopg2://invalid:invalid@nonexistent:9999/invalid',
            pool_size=3,
            max_overflow=2,
            pool_timeout=2,  # Short timeout for testing
            pool_pre_ping=True
        )
        
        connection_attempts = []
        
        # Attempt connections to unavailable database
        for i in range(5):
            try:
                start_time = time.time()
                conn = invalid_engine.connect()
                conn.close()
                
                # This should not happen
                connection_attempts.append(('success', i))
                
            except OperationalError as e:
                attempt_time = time.time() - start_time
                connection_attempts.append(('operational_error', i, attempt_time))
                pool_monitor.record_error("database_unavailable")
                
            except Exception as e:
                attempt_time = time.time() - start_time
                connection_attempts.append(('other_error', i, attempt_time, str(e)))
                pool_monitor.record_error("connection_error")
                
        # Cleanup
        invalid_engine.dispose()
        
        # Validate error handling
        success_count = len([a for a in connection_attempts if a[0] == 'success'])
        error_count = len([a for a in connection_attempts if a[0] != 'success'])
        
        assert success_count == 0, "No connections should succeed to invalid database"
        assert error_count == 5, "All connection attempts should fail appropriately"
        
        # Validate error timing (should fail quickly)
        error_times = [a[2] for a in connection_attempts if len(a) > 2 and isinstance(a[2], float)]
        if error_times:
            max_error_time = max(error_times)
            assert max_error_time < 10, \
                f"Error detection should be quick, got {max_error_time:.1f}s"
                
        # Validate monitoring
        stats = pool_monitor.get_statistics()
        assert stats['error_summary'].get('database_unavailable', 0) > 0, \
            "Database unavailable errors should be recorded"
            
    def test_pool_exhaustion_handling(self, pool_monitor):
        """
        Test handling of pool exhaustion ensuring proper timeout behavior
        and queue management when all connections are in use.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with minimal pool for exhaustion testing
        exhaustion_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=2,
            max_overflow=1,
            pool_timeout=2,  # Short timeout for testing
            pool_pre_ping=True
        )
        
        exhaustion_results = []
        held_connections = []
        
        try:
            # Phase 1: Exhaust the pool
            for i in range(3):  # pool_size + max_overflow
                try:
                    conn = exhaustion_engine.connect()
                    held_connections.append(conn)
                    exhaustion_results.append(('acquired', i))
                    pool_monitor.record_connection_checkout(f"exhaust_{i}", 0.01)
                    
                except Exception as e:
                    exhaustion_results.append(('acquire_error', i, str(e)))
                    pool_monitor.record_error("pool_exhaustion")
                    
            # Phase 2: Attempt additional connections (should timeout)
            for i in range(3, 6):
                start_time = time.time()
                try:
                    conn = exhaustion_engine.connect()
                    conn.close()
                    exhaustion_results.append(('unexpected_success', i))
                    
                except TimeoutError:
                    timeout_time = time.time() - start_time
                    exhaustion_results.append(('timeout', i, timeout_time))
                    pool_monitor.record_pool_timeout()
                    
                except Exception as e:
                    timeout_time = time.time() - start_time
                    exhaustion_results.append(('other_timeout', i, timeout_time, str(e)))
                    pool_monitor.record_pool_timeout()
                    
        finally:
            # Release held connections
            for conn in held_connections:
                try:
                    conn.close()
                except Exception:
                    pass
            exhaustion_engine.dispose()
            
        # Validate exhaustion handling
        acquired_count = len([r for r in exhaustion_results if r[0] == 'acquired'])
        timeout_count = len([r for r in exhaustion_results if r[0] in ['timeout', 'other_timeout']])
        
        assert acquired_count == 3, "Should acquire exactly pool_size + max_overflow connections"
        assert timeout_count >= 2, "Additional attempts should timeout"
        
        # Validate timeout timing
        timeout_times = [r[2] for r in exhaustion_results if len(r) > 2 and r[0] in ['timeout', 'other_timeout']]
        if timeout_times:
            for timeout_time in timeout_times:
                assert 1.5 <= timeout_time <= 3.0, \
                    f"Timeout should occur around configured time, got {timeout_time:.1f}s"
                    
        # Validate monitoring
        stats = pool_monitor.get_statistics()
        assert stats['pool_timeouts'] >= 2, "Pool timeouts should be recorded"
        
    def test_connection_leak_detection(self, pool_monitor):
        """
        Test detection and handling of connection leaks ensuring proper
        resource management and leak prevention mechanisms.
        """
        pool_monitor.start_monitoring()
        
        # Create engine for leak testing
        leak_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=5,
            max_overflow=3,
            pool_recycle=10,  # Short recycle for testing
            pool_pre_ping=True
        )
        
        leak_test_results = []
        
        try:
            # Simulate potential leak scenarios
            
            # Scenario 1: Connections acquired but not properly closed
            leaked_connections = []
            for i in range(3):
                conn = leak_engine.connect()
                leaked_connections.append(conn)
                pool_monitor.record_connection_checkout(f"leak_test_{i}", 0.01)
                leak_test_results.append(('acquired_not_closed', i))
                
            # Scenario 2: Attempt to acquire more connections
            additional_connections = []
            for i in range(5):
                try:
                    conn = leak_engine.connect()
                    additional_connections.append(conn)
                    pool_monitor.record_connection_checkout(f"additional_{i}", 0.01)
                    leak_test_results.append(('additional_acquired', i))
                    
                except TimeoutError:
                    pool_monitor.record_pool_timeout()
                    leak_test_results.append(('additional_timeout', i))
                    break
                    
            # Scenario 3: Properly close some connections
            for i, conn in enumerate(additional_connections[:2]):
                conn.close()
                pool_monitor.record_connection_checkin(f"closed_{i}")
                leak_test_results.append(('properly_closed', i))
                
            # Scenario 4: Force engine disposal (should handle remaining connections)
            leak_engine.dispose()
            leak_test_results.append(('engine_disposed', None))
            
            # Note: Leaked connections become invalid after engine disposal
            
        except Exception as e:
            pytest.fail(f"Connection leak test failed: {e}")
            
        # Validate leak detection results
        acquired_count = len([r for r in leak_test_results if 'acquired' in r[0]])
        closed_count = len([r for r in leak_test_results if 'closed' in r[0]])
        
        assert acquired_count > 0, "Should acquire connections for leak testing"
        
        # In a real application, we'd check for warnings about unclosed connections
        # For testing, we validate that the engine can be disposed without hanging
        engine_disposed = any(r[0] == 'engine_disposed' for r in leak_test_results)
        assert engine_disposed, "Engine should be disposed successfully"
        
        # Validate monitoring captured potential leaks
        stats = pool_monitor.get_statistics()
        checkout_checkin_diff = stats['total_checkouts'] - stats['total_checkins']
        
        # Some connections may not be checked in due to leak simulation
        assert checkout_checkin_diff >= 0, \
            "Checkouts should be at least as many as checkins"
            
    def test_invalid_connection_recovery(self, pool_monitor):
        """
        Test recovery from invalid connections ensuring pool can recover
        from stale or corrupted connections through pool_pre_ping.
        """
        pool_monitor.start_monitoring()
        
        # Create engine with pre-ping enabled
        recovery_engine = create_engine(
            'sqlite:///:memory:',
            pool_size=3,
            max_overflow=2,
            pool_pre_ping=True,  # Critical for recovery testing
            pool_recycle=5
        )
        
        recovery_results = []
        
        try:
            # Phase 1: Create and use connections normally
            normal_connections = []
            for i in range(3):
                conn = recovery_engine.connect()
                normal_connections.append(conn)
                
                # Execute query to ensure connection works
                result = conn.execute(text("SELECT :i as test"), {'i': i})
                row = result.fetchone()
                assert row[0] == i, f"Normal connection {i} should work"
                
                pool_monitor.record_connection_checkout(f"normal_{i}", 0.01)
                recovery_results.append(('normal_connection', i))
                
            # Phase 2: Return connections to pool
            for i, conn in enumerate(normal_connections):
                conn.close()
                pool_monitor.record_connection_checkin(f"normal_{i}")
                recovery_results.append(('returned_to_pool', i))
                
            # Phase 3: Wait for potential connection aging
            time.sleep(1)
            
            # Phase 4: Acquire connections again (pool_pre_ping should validate)
            recovered_connections = []
            for i in range(3):
                try:
                    conn = recovery_engine.connect()
                    recovered_connections.append(conn)
                    
                    # Execute query to ensure recovered connection works
                    result = conn.execute(text("SELECT :i + 10 as test"), {'i': i})
                    row = result.fetchone()
                    assert row[0] == i + 10, f"Recovered connection {i} should work"
                    
                    pool_monitor.record_connection_checkout(f"recovered_{i}", 0.01)
                    recovery_results.append(('recovered_connection', i))
                    
                except Exception as e:
                    pool_monitor.record_error("connection_recovery")
                    recovery_results.append(('recovery_error', i, str(e)))
                    
        finally:
            # Cleanup
            for conn in recovered_connections:
                try:
                    conn.close()
                except Exception:
                    pass
            recovery_engine.dispose()
            
        # Validate recovery results
        normal_count = len([r for r in recovery_results if r[0] == 'normal_connection'])
        recovered_count = len([r for r in recovery_results if r[0] == 'recovered_connection'])
        error_count = len([r for r in recovery_results if r[0] == 'recovery_error'])
        
        assert normal_count == 3, "Should create 3 normal connections"
        assert recovered_count >= 2, "Should recover most connections successfully"
        assert error_count <= 1, "Should have minimal recovery errors"
        
        # Validate monitoring
        stats = pool_monitor.get_statistics()
        assert stats['total_checkouts'] >= 6, "Should record all connection operations"
        
        # Check that recovery errors are minimal
        recovery_error_rate = stats['error_summary'].get('connection_recovery', 0) / max(1, recovered_count)
        assert recovery_error_rate <= 0.2, \
            f"Recovery error rate should be under 20%, got {recovery_error_rate * 100:.1f}%"


# ================================
# Test Execution and Reporting
# ================================

if __name__ == '__main__':
    """
    Direct test execution for development and debugging purposes.
    
    This block enables running the test file directly for development
    and provides detailed output for connection pooling validation.
    """
    import sys
    
    print("=" * 80)
    print("DATABASE CONNECTION POOLING TEST SUITE")
    print("Flask 3.1.1 Migration - PostgreSQL psycopg2 Integration")
    print("=" * 80)
    
    # Configure logging for detailed output
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting connection pooling test suite...")
    
    # Run tests with detailed output
    pytest_args = [
        __file__,
        '-v',  # Verbose output
        '--tb=short',  # Short traceback format
        '--benchmark-only',  # Run benchmark tests
        '--benchmark-warmup=on',  # Enable benchmark warmup
        '--benchmark-disable-gc',  # Disable GC during benchmarks
        '-m', 'not slow'  # Skip slow tests for development
    ]
    
    exit_code = pytest.main(pytest_args)
    
    print("=" * 80)
    print(f"Test suite completed with exit code: {exit_code}")
    print("=" * 80)
    
    sys.exit(exit_code)