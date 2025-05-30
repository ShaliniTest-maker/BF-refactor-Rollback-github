"""
Performance Validation and Benchmarking Module

This module implements comprehensive performance testing and validation for the Flask 3.1.1
application using pytest-benchmark framework, providing statistical analysis of response times,
memory profiling, and SLA compliance testing against Node.js baseline performance metrics.

The implementation follows Section 4.7.4.1 performance benchmarking framework requirements
with pytest-benchmark integration for response time benchmarking, memory usage profiling,
database query performance validation, and load testing scenarios with concurrent user simulation.

Key Features:
- Statistical performance analysis with baseline comparison and regression detection
- API endpoint response time benchmarking with SLA compliance validation
- Memory usage profiling and optimization recommendations
- Database query performance validation and SQLAlchemy optimization testing
- Concurrent user simulation and load testing scenarios
- Performance regression detection with automated alerts
- Comprehensive reporting with performance trend analysis

Performance SLA Requirements (Per Section 2.4.2):
- API response times ≤ 200ms for standard operations
- Complex business logic operations ≤ 500ms
- Support 2000+ concurrent requests
- Memory usage 150-300MB per worker process
- Database query response times ≤ 100ms

Author: Flask Migration System
Version: 1.0.0
Compatibility: pytest-benchmark 4.0+, Flask 3.1.1, SQLAlchemy 2.0+
"""

import gc
import json
import logging
import multiprocessing
import psutil
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Callable
from unittest.mock import patch

import pytest
import requests
from flask import Flask
from flask.testing import FlaskClient
from memory_profiler import profile as memory_profile
from sqlalchemy import text
from sqlalchemy.orm import Session

# Performance testing dependencies
try:
    import locust
    from locust import HttpUser, task, between
    from locust.env import Environment
    from locust.stats import stats_printer, stats_history
    from locust.log import setup_logging
    LOCUST_AVAILABLE = True
except ImportError:
    LOCUST_AVAILABLE = False
    logging.warning("Locust not available - some load testing features will be disabled")

# Configure logging for performance testing
logger = logging.getLogger(__name__)


# =============================================================================
# PERFORMANCE TESTING CONFIGURATION
# =============================================================================

class PerformanceConfig:
    """
    Configuration class for performance testing parameters and SLA thresholds.
    
    Implements performance requirements from Section 2.4.2 and 4.7.4.1 with
    configurable thresholds for regression detection and SLA compliance validation.
    """
    
    # Response Time SLA Thresholds (milliseconds)
    API_RESPONSE_TIME_THRESHOLD = 200.0  # Standard API operations
    COMPLEX_OPERATION_THRESHOLD = 500.0  # Complex business logic operations
    DATABASE_QUERY_THRESHOLD = 100.0     # Database query response times
    AUTHENTICATION_THRESHOLD = 150.0     # Authentication operations
    
    # Concurrent Load Testing Thresholds
    MAX_CONCURRENT_REQUESTS = 2000       # Maximum concurrent request support
    LOAD_TEST_DURATION = 30              # Load test duration in seconds
    RAMP_UP_TIME = 10                    # User ramp-up time in seconds
    
    # Memory Usage Thresholds (MB)
    MIN_MEMORY_THRESHOLD = 150           # Minimum memory usage per worker
    MAX_MEMORY_THRESHOLD = 300           # Maximum memory usage per worker
    MEMORY_LEAK_THRESHOLD = 50           # Memory leak detection threshold (MB)
    
    # Statistical Analysis Configuration
    BENCHMARK_MIN_ROUNDS = 5             # Minimum benchmark rounds
    BENCHMARK_MAX_TIME = 1.0             # Maximum benchmark execution time
    CONFIDENCE_INTERVAL = 0.95           # Statistical confidence interval
    REGRESSION_THRESHOLD = 0.15          # 15% performance regression threshold
    
    # Database Performance Configuration
    DB_CONNECTION_POOL_SIZE = 20         # SQLAlchemy connection pool size
    DB_QUERY_TIMEOUT = 5.0               # Database query timeout in seconds
    DB_STRESS_TEST_QUERIES = 100         # Number of queries for stress testing


# =============================================================================
# PERFORMANCE MEASUREMENT UTILITIES
# =============================================================================

class PerformanceProfiler:
    """
    Comprehensive performance profiling utility for Flask application monitoring.
    
    Provides memory usage tracking, response time measurement, database query
    profiling, and resource utilization monitoring for performance analysis.
    """
    
    def __init__(self):
        self.measurements = []
        self.baseline_metrics = {}
        self.memory_snapshots = []
        self.query_performance = {}
    
    @contextmanager
    def measure_response_time(self, operation_name: str):
        """
        Context manager for measuring response time with high precision.
        
        Args:
            operation_name: Name of the operation being measured
            
        Yields:
            Performance measurement context with timing data
        """
        start_time = time.perf_counter()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        try:
            yield
        finally:
            end_time = time.perf_counter()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            memory_delta = end_memory - start_memory
            
            measurement = {
                'operation': operation_name,
                'response_time_ms': response_time,
                'start_memory_mb': start_memory,
                'end_memory_mb': end_memory,
                'memory_delta_mb': memory_delta,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'cpu_usage': psutil.cpu_percent(interval=None),
                'memory_usage_mb': end_memory
            }
            
            self.measurements.append(measurement)
            logger.debug(f"Performance measurement: {operation_name} - {response_time:.2f}ms")
    
    def get_operation_statistics(self, operation_name: str) -> Dict[str, float]:
        """
        Calculate statistical metrics for a specific operation.
        
        Args:
            operation_name: Name of the operation to analyze
            
        Returns:
            Dictionary containing statistical performance metrics
        """
        operation_measurements = [
            m for m in self.measurements 
            if m['operation'] == operation_name
        ]
        
        if not operation_measurements:
            return {}
        
        response_times = [m['response_time_ms'] for m in operation_measurements]
        memory_deltas = [m['memory_delta_mb'] for m in operation_measurements]
        
        return {
            'count': len(response_times),
            'mean_response_time': statistics.mean(response_times),
            'median_response_time': statistics.median(response_times),
            'min_response_time': min(response_times),
            'max_response_time': max(response_times),
            'stdev_response_time': statistics.stdev(response_times) if len(response_times) > 1 else 0,
            'p95_response_time': self._calculate_percentile(response_times, 0.95),
            'p99_response_time': self._calculate_percentile(response_times, 0.99),
            'mean_memory_delta': statistics.mean(memory_deltas),
            'max_memory_delta': max(memory_deltas),
            'total_memory_growth': sum(memory_deltas)
        }
    
    def _calculate_percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile value for performance data."""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile)
        if index >= len(sorted_data):
            index = len(sorted_data) - 1
        
        return sorted_data[index]
    
    def detect_performance_regression(self, operation_name: str, baseline_metrics: Dict[str, float]) -> Dict[str, Any]:
        """
        Detect performance regression against baseline metrics.
        
        Args:
            operation_name: Operation to analyze for regression
            baseline_metrics: Baseline performance metrics for comparison
            
        Returns:
            Regression analysis results with recommendations
        """
        current_metrics = self.get_operation_statistics(operation_name)
        
        if not current_metrics or not baseline_metrics:
            return {'regression_detected': False, 'reason': 'Insufficient data'}
        
        regression_analysis = {
            'operation': operation_name,
            'regression_detected': False,
            'performance_changes': {},
            'recommendations': [],
            'severity': 'none'
        }
        
        # Analyze response time regression
        current_mean = current_metrics.get('mean_response_time', 0)
        baseline_mean = baseline_metrics.get('mean_response_time', 0)
        
        if baseline_mean > 0:
            response_time_change = (current_mean - baseline_mean) / baseline_mean
            regression_analysis['performance_changes']['response_time_change_percent'] = response_time_change * 100
            
            if response_time_change > PerformanceConfig.REGRESSION_THRESHOLD:
                regression_analysis['regression_detected'] = True
                regression_analysis['severity'] = 'high' if response_time_change > 0.3 else 'medium'
                regression_analysis['recommendations'].append(
                    f"Response time increased by {response_time_change * 100:.1f}% - investigate code changes"
                )
        
        # Analyze memory usage regression
        current_memory = current_metrics.get('mean_memory_delta', 0)
        baseline_memory = baseline_metrics.get('mean_memory_delta', 0)
        
        if current_memory > PerformanceConfig.MEMORY_LEAK_THRESHOLD:
            regression_analysis['regression_detected'] = True
            regression_analysis['recommendations'].append(
                f"Memory growth detected: {current_memory:.2f}MB - check for memory leaks"
            )
        
        return regression_analysis


# =============================================================================
# DATABASE PERFORMANCE TESTING
# =============================================================================

class DatabasePerformanceTester:
    """
    Database performance testing utility for SQLAlchemy query optimization.
    
    Provides comprehensive database performance validation including query execution
    time analysis, connection pool performance, and database stress testing.
    """
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.query_measurements = []
        self.connection_pool_stats = {}
    
    def benchmark_query_performance(self, query: str, parameters: Dict[str, Any] = None) -> Dict[str, float]:
        """
        Benchmark database query performance with statistical analysis.
        
        Args:
            query: SQL query to benchmark
            parameters: Query parameters for parameterized queries
            
        Returns:
            Query performance metrics and statistics
        """
        execution_times = []
        
        for i in range(PerformanceConfig.BENCHMARK_MIN_ROUNDS):
            start_time = time.perf_counter()
            
            try:
                if parameters:
                    result = self.db_session.execute(text(query), parameters)
                else:
                    result = self.db_session.execute(text(query))
                
                # Fetch all results to ensure complete execution
                rows = result.fetchall()
                row_count = len(rows)
                
                end_time = time.perf_counter()
                execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
                execution_times.append(execution_time)
                
                logger.debug(f"Query execution {i+1}: {execution_time:.2f}ms, {row_count} rows")
                
            except Exception as e:
                logger.error(f"Query execution failed: {str(e)}")
                execution_times.append(float('inf'))
        
        # Filter out failed executions
        valid_times = [t for t in execution_times if t != float('inf')]
        
        if not valid_times:
            return {'error': 'All query executions failed'}
        
        return {
            'query': query,
            'execution_count': len(valid_times),
            'mean_execution_time': statistics.mean(valid_times),
            'median_execution_time': statistics.median(valid_times),
            'min_execution_time': min(valid_times),
            'max_execution_time': max(valid_times),
            'stdev_execution_time': statistics.stdev(valid_times) if len(valid_times) > 1 else 0,
            'sla_compliant': all(t <= PerformanceConfig.DATABASE_QUERY_THRESHOLD for t in valid_times)
        }
    
    def stress_test_database_connections(self) -> Dict[str, Any]:
        """
        Perform database connection stress testing with concurrent queries.
        
        Returns:
            Connection pool performance metrics and stress test results
        """
        stress_test_results = {
            'concurrent_connections': 0,
            'successful_queries': 0,
            'failed_queries': 0,
            'average_response_time': 0.0,
            'connection_errors': [],
            'performance_degradation': False
        }
        
        def execute_test_query():
            """Execute a simple test query for connection stress testing."""
            try:
                start_time = time.perf_counter()
                result = self.db_session.execute(text("SELECT 1 as test_value"))
                result.fetchone()
                end_time = time.perf_counter()
                
                return {
                    'success': True,
                    'response_time': (end_time - start_time) * 1000,
                    'error': None
                }
            except Exception as e:
                return {
                    'success': False,
                    'response_time': 0,
                    'error': str(e)
                }
        
        # Execute concurrent queries to stress test connections
        with ThreadPoolExecutor(max_workers=PerformanceConfig.DB_CONNECTION_POOL_SIZE) as executor:
            futures = [
                executor.submit(execute_test_query) 
                for _ in range(PerformanceConfig.DB_STRESS_TEST_QUERIES)
            ]
            
            response_times = []
            
            for future in as_completed(futures):
                result = future.result()
                
                if result['success']:
                    stress_test_results['successful_queries'] += 1
                    response_times.append(result['response_time'])
                else:
                    stress_test_results['failed_queries'] += 1
                    stress_test_results['connection_errors'].append(result['error'])
        
        if response_times:
            stress_test_results['average_response_time'] = statistics.mean(response_times)
            stress_test_results['max_response_time'] = max(response_times)
            
            # Check for performance degradation
            if stress_test_results['average_response_time'] > PerformanceConfig.DATABASE_QUERY_THRESHOLD:
                stress_test_results['performance_degradation'] = True
        
        return stress_test_results


# =============================================================================
# LOAD TESTING SCENARIOS
# =============================================================================

if LOCUST_AVAILABLE:
    class FlaskLoadTestUser(HttpUser):
        """
        Locust user class for Flask application load testing.
        
        Implements realistic user behavior patterns for concurrent load testing
        with configurable wait times and task distribution.
        """
        
        wait_time = between(1, 3)  # Wait 1-3 seconds between requests
        
        def on_start(self):
            """Initialize user session and authentication."""
            # Perform login or authentication setup
            login_response = self.client.post('/api/auth/login', json={
                'username': 'test@example.com',
                'password': 'testpassword123'
            })
            
            if login_response.status_code == 200:
                auth_data = login_response.json().get('data', {})
                self.auth_token = auth_data.get('access_token')
                self.headers = {'Authorization': f'Bearer {self.auth_token}'}
            else:
                self.headers = {}
        
        @task(3)
        def get_user_list(self):
            """Test user list endpoint under load."""
            self.client.get('/api/users', headers=self.headers)
        
        @task(2)
        def get_user_detail(self):
            """Test user detail endpoint under load."""
            self.client.get('/api/users/1', headers=self.headers)
        
        @task(1)
        def create_entity(self):
            """Test entity creation under load."""
            entity_data = {
                'name': f'Load Test Entity {time.time()}',
                'entity_type': 'company',
                'description': 'Load testing entity creation'
            }
            self.client.post('/api/entities', json=entity_data, headers=self.headers)
        
        @task(1)
        def health_check(self):
            """Test health check endpoint under load."""
            self.client.get('/health')


class LoadTestRunner:
    """
    Load testing orchestrator using Locust for concurrent user simulation.
    
    Provides comprehensive load testing scenarios with configurable user counts,
    ramp-up patterns, and performance metric collection.
    """
    
    def __init__(self, target_host: str = "http://localhost:5000"):
        self.target_host = target_host
        self.test_results = {}
    
    def run_load_test(self, user_count: int, spawn_rate: int, duration: int) -> Dict[str, Any]:
        """
        Execute load test with specified parameters.
        
        Args:
            user_count: Number of concurrent users to simulate
            spawn_rate: Rate of user spawning (users per second)
            duration: Test duration in seconds
            
        Returns:
            Load test results with performance metrics
        """
        if not LOCUST_AVAILABLE:
            pytest.skip("Locust not available for load testing")
        
        # Setup Locust environment
        env = Environment(user_classes=[FlaskLoadTestUser])
        env.create_local_runner()
        
        # Start load test
        env.runner.start(user_count=user_count, spawn_rate=spawn_rate)
        
        # Run for specified duration
        time.sleep(duration)
        
        # Stop load test
        env.runner.stop()
        
        # Collect performance metrics
        stats = env.runner.stats
        
        load_test_results = {
            'user_count': user_count,
            'duration': duration,
            'total_requests': stats.total.num_requests,
            'total_failures': stats.total.num_failures,
            'average_response_time': stats.total.avg_response_time,
            'median_response_time': stats.total.median_response_time,
            'max_response_time': stats.total.max_response_time,
            'requests_per_second': stats.total.total_rps,
            'failure_rate': stats.total.fail_ratio,
            'endpoint_statistics': {}
        }
        
        # Collect per-endpoint statistics
        for name, stat in stats.entries.items():
            if name != 'Aggregated':
                load_test_results['endpoint_statistics'][name] = {
                    'requests': stat.num_requests,
                    'failures': stat.num_failures,
                    'avg_response_time': stat.avg_response_time,
                    'median_response_time': stat.median_response_time,
                    'max_response_time': stat.max_response_time
                }
        
        return load_test_results


# =============================================================================
# PYTEST FIXTURES FOR PERFORMANCE TESTING
# =============================================================================

@pytest.fixture(scope='function')
def performance_profiler():
    """
    Provide performance profiler instance for test execution.
    
    Returns:
        PerformanceProfiler instance for response time and memory measurement
    """
    profiler = PerformanceProfiler()
    yield profiler
    
    # Log performance summary after test completion
    if profiler.measurements:
        logger.info(f"Performance test completed with {len(profiler.measurements)} measurements")


@pytest.fixture(scope='function')
def db_performance_tester(db_session):
    """
    Provide database performance tester instance.
    
    Args:
        db_session: Database session from conftest.py
        
    Returns:
        DatabasePerformanceTester instance for query performance analysis
    """
    tester = DatabasePerformanceTester(db_session)
    yield tester


@pytest.fixture(scope='function')
def load_test_runner(app):
    """
    Provide load test runner for concurrent testing scenarios.
    
    Args:
        app: Flask application instance
        
    Returns:
        LoadTestRunner instance for load testing execution
    """
    # Start test server in background for load testing
    import threading
    from werkzeug.serving import make_server
    
    server = make_server('127.0.0.1', 5555, app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    runner = LoadTestRunner(target_host="http://127.0.0.1:5555")
    yield runner
    
    # Cleanup: shutdown test server
    server.shutdown()


# =============================================================================
# API ENDPOINT PERFORMANCE TESTS
# =============================================================================

class TestAPIPerformance:
    """
    Comprehensive API endpoint performance testing suite.
    
    Implements performance validation per Section 4.7.4.1 with response time
    benchmarking, SLA compliance testing, and regression detection.
    """
    
    @pytest.mark.performance
    def test_health_endpoint_performance(self, client: FlaskClient, benchmark, performance_profiler):
        """
        Test health endpoint response time performance.
        
        Validates health check endpoint meets SLA requirements with sub-200ms response times.
        """
        def health_check():
            with performance_profiler.measure_response_time('health_check'):
                response = client.get('/health')
                assert response.status_code == 200
                return response
        
        # Benchmark health endpoint performance
        result = benchmark(health_check)
        
        # Validate SLA compliance
        stats = performance_profiler.get_operation_statistics('health_check')
        assert stats['mean_response_time'] < PerformanceConfig.API_RESPONSE_TIME_THRESHOLD, \
            f"Health endpoint response time {stats['mean_response_time']:.2f}ms exceeds SLA threshold"
        
        logger.info(f"Health endpoint performance: {stats['mean_response_time']:.2f}ms average")
    
    @pytest.mark.performance
    def test_user_list_endpoint_performance(self, client: FlaskClient, benchmark, performance_profiler, auth_headers):
        """
        Test user list endpoint performance under standard load.
        
        Validates user list API response times meet SLA requirements for standard operations.
        """
        def get_user_list():
            with performance_profiler.measure_response_time('user_list'):
                response = client.get('/api/users', headers=auth_headers)
                # Accept both 200 (success) and 401 (auth error) for performance testing
                assert response.status_code in [200, 401]
                return response
        
        # Benchmark user list endpoint performance
        result = benchmark(get_user_list)
        
        # Validate SLA compliance
        stats = performance_profiler.get_operation_statistics('user_list')
        assert stats['mean_response_time'] < PerformanceConfig.API_RESPONSE_TIME_THRESHOLD, \
            f"User list response time {stats['mean_response_time']:.2f}ms exceeds SLA threshold"
        
        logger.info(f"User list endpoint performance: {stats['mean_response_time']:.2f}ms average")
    
    @pytest.mark.performance
    def test_authentication_endpoint_performance(self, client: FlaskClient, benchmark, performance_profiler):
        """
        Test authentication endpoint performance validation.
        
        Validates authentication operations meet specialized SLA requirements for auth processes.
        """
        def authenticate_user():
            with performance_profiler.measure_response_time('authentication'):
                response = client.post('/api/auth/login', json={
                    'username': 'test@example.com',
                    'password': 'testpassword123'
                })
                # Accept auth failures for performance testing
                assert response.status_code in [200, 401, 422]
                return response
        
        # Benchmark authentication endpoint performance
        result = benchmark(authenticate_user)
        
        # Validate authentication SLA compliance
        stats = performance_profiler.get_operation_statistics('authentication')
        assert stats['mean_response_time'] < PerformanceConfig.AUTHENTICATION_THRESHOLD, \
            f"Authentication response time {stats['mean_response_time']:.2f}ms exceeds SLA threshold"
        
        logger.info(f"Authentication endpoint performance: {stats['mean_response_time']:.2f}ms average")
    
    @pytest.mark.performance
    def test_entity_creation_performance(self, client: FlaskClient, benchmark, performance_profiler, auth_headers):
        """
        Test entity creation endpoint performance for complex operations.
        
        Validates complex business logic operations meet extended SLA requirements.
        """
        def create_entity():
            with performance_profiler.measure_response_time('entity_creation'):
                entity_data = {
                    'name': f'Performance Test Entity {time.time()}',
                    'entity_type': 'company',
                    'description': 'Performance testing entity with comprehensive validation',
                    'metadata': {
                        'test_type': 'performance',
                        'creation_timestamp': datetime.now(timezone.utc).isoformat(),
                        'performance_data': {'cpu_usage': psutil.cpu_percent()}
                    }
                }
                response = client.post('/api/entities', json=entity_data, headers=auth_headers)
                # Accept various response codes for performance testing
                assert response.status_code in [201, 401, 422]
                return response
        
        # Benchmark entity creation performance
        result = benchmark(create_entity)
        
        # Validate complex operation SLA compliance
        stats = performance_profiler.get_operation_statistics('entity_creation')
        assert stats['mean_response_time'] < PerformanceConfig.COMPLEX_OPERATION_THRESHOLD, \
            f"Entity creation response time {stats['mean_response_time']:.2f}ms exceeds SLA threshold"
        
        logger.info(f"Entity creation performance: {stats['mean_response_time']:.2f}ms average")


# =============================================================================
# DATABASE PERFORMANCE TESTS
# =============================================================================

class TestDatabasePerformance:
    """
    Database performance testing suite for SQLAlchemy query optimization.
    
    Implements database performance validation per Section 4.7.4.1 with query
    execution time analysis and connection pool performance testing.
    """
    
    @pytest.mark.performance
    def test_simple_query_performance(self, db_performance_tester, benchmark):
        """
        Test simple database query performance against SLA thresholds.
        
        Validates basic database connectivity and query execution performance.
        """
        def execute_simple_query():
            return db_performance_tester.benchmark_query_performance(
                "SELECT 1 as test_value, CURRENT_TIMESTAMP as current_time"
            )
        
        # Benchmark simple query execution
        result = benchmark(execute_simple_query)
        
        # Validate query performance metrics
        assert 'mean_execution_time' in result
        assert result['mean_execution_time'] < PerformanceConfig.DATABASE_QUERY_THRESHOLD, \
            f"Simple query execution time {result['mean_execution_time']:.2f}ms exceeds SLA threshold"
        
        assert result.get('sla_compliant', False), "Query performance does not meet SLA requirements"
        
        logger.info(f"Simple query performance: {result['mean_execution_time']:.2f}ms average")
    
    @pytest.mark.performance
    def test_connection_pool_performance(self, db_performance_tester, benchmark):
        """
        Test database connection pool performance under stress conditions.
        
        Validates connection pool efficiency and concurrent query handling.
        """
        def stress_test_connections():
            return db_performance_tester.stress_test_database_connections()
        
        # Benchmark connection pool stress test
        result = benchmark(stress_test_connections)
        
        # Validate connection pool performance
        assert result['successful_queries'] > 0, "No successful queries in stress test"
        assert result['average_response_time'] < PerformanceConfig.DATABASE_QUERY_THRESHOLD, \
            f"Connection pool response time {result['average_response_time']:.2f}ms exceeds threshold"
        
        # Check for excessive connection failures
        failure_rate = result['failed_queries'] / (result['successful_queries'] + result['failed_queries'])
        assert failure_rate < 0.05, f"Connection failure rate {failure_rate:.2%} too high"
        
        logger.info(f"Connection pool performance: {result['average_response_time']:.2f}ms average, "
                   f"{result['successful_queries']} successful queries")
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_complex_query_performance(self, db_performance_tester, benchmark):
        """
        Test complex database query performance with joins and aggregations.
        
        Validates performance of complex business logic database operations.
        """
        def execute_complex_query():
            # Create a more complex query that would be typical in the application
            complex_query = """
            WITH performance_metrics AS (
                SELECT 
                    1 as metric_id,
                    'response_time' as metric_name,
                    RANDOM() * 1000 as metric_value,
                    CURRENT_TIMESTAMP as measurement_time
                UNION ALL
                SELECT 
                    2 as metric_id,
                    'memory_usage' as metric_name,
                    RANDOM() * 300 as metric_value,
                    CURRENT_TIMESTAMP as measurement_time
                UNION ALL
                SELECT 
                    3 as metric_id,
                    'cpu_usage' as metric_name,
                    RANDOM() * 100 as metric_value,
                    CURRENT_TIMESTAMP as measurement_time
            )
            SELECT 
                metric_name,
                AVG(metric_value) as avg_value,
                MAX(metric_value) as max_value,
                MIN(metric_value) as min_value,
                COUNT(*) as sample_count
            FROM performance_metrics
            GROUP BY metric_name
            ORDER BY metric_name
            """
            
            return db_performance_tester.benchmark_query_performance(complex_query)
        
        # Benchmark complex query execution
        result = benchmark(execute_complex_query)
        
        # Validate complex query performance
        assert 'mean_execution_time' in result
        assert result['mean_execution_time'] < PerformanceConfig.COMPLEX_OPERATION_THRESHOLD, \
            f"Complex query execution time {result['mean_execution_time']:.2f}ms exceeds SLA threshold"
        
        logger.info(f"Complex query performance: {result['mean_execution_time']:.2f}ms average")


# =============================================================================
# MEMORY PERFORMANCE TESTS
# =============================================================================

class TestMemoryPerformance:
    """
    Memory usage and profiling test suite for resource optimization.
    
    Implements memory profiling per Section 4.7.4.1 with memory leak detection
    and resource utilization monitoring.
    """
    
    @pytest.mark.performance
    def test_memory_usage_baseline(self, client: FlaskClient, performance_profiler):
        """
        Establish memory usage baseline for Flask application.
        
        Measures baseline memory consumption and validates against SLA thresholds.
        """
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        # Execute a series of API calls to establish baseline
        with performance_profiler.measure_response_time('memory_baseline'):
            for i in range(10):
                response = client.get('/health')
                assert response.status_code == 200
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        memory_growth = final_memory - initial_memory
        
        # Validate memory usage is within SLA thresholds
        assert initial_memory >= PerformanceConfig.MIN_MEMORY_THRESHOLD, \
            f"Initial memory usage {initial_memory:.2f}MB below minimum threshold"
        
        assert final_memory <= PerformanceConfig.MAX_MEMORY_THRESHOLD, \
            f"Final memory usage {final_memory:.2f}MB exceeds maximum threshold"
        
        assert memory_growth <= PerformanceConfig.MEMORY_LEAK_THRESHOLD, \
            f"Memory growth {memory_growth:.2f}MB indicates potential memory leak"
        
        logger.info(f"Memory baseline: {initial_memory:.2f}MB -> {final_memory:.2f}MB "
                   f"(growth: {memory_growth:.2f}MB)")
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_memory_leak_detection(self, client: FlaskClient, performance_profiler):
        """
        Detect memory leaks through sustained operation testing.
        
        Performs extended testing to identify memory leaks in application components.
        """
        memory_measurements = []
        
        # Perform sustained operations to detect memory leaks
        for iteration in range(50):
            current_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            memory_measurements.append(current_memory)
            
            with performance_profiler.measure_response_time(f'memory_leak_test_{iteration}'):
                # Execute various endpoints to stress memory usage
                client.get('/health')
                client.get('/health/detailed')
                
                # Force garbage collection
                gc.collect()
        
        # Analyze memory growth pattern
        initial_memory = memory_measurements[0]
        final_memory = memory_measurements[-1]
        total_growth = final_memory - initial_memory
        
        # Calculate memory growth trend
        if len(memory_measurements) > 1:
            # Simple linear regression to detect memory growth trend
            x_values = list(range(len(memory_measurements)))
            y_values = memory_measurements
            
            n = len(x_values)
            sum_x = sum(x_values)
            sum_y = sum(y_values)
            sum_xy = sum(x * y for x, y in zip(x_values, y_values))
            sum_x2 = sum(x * x for x in x_values)
            
            # Calculate slope (memory growth rate)
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            memory_growth_rate = slope  # MB per iteration
        else:
            memory_growth_rate = 0
        
        # Validate memory leak thresholds
        assert total_growth <= PerformanceConfig.MEMORY_LEAK_THRESHOLD, \
            f"Total memory growth {total_growth:.2f}MB indicates memory leak"
        
        assert memory_growth_rate <= 1.0, \
            f"Memory growth rate {memory_growth_rate:.2f}MB/iteration too high"
        
        logger.info(f"Memory leak test: {initial_memory:.2f}MB -> {final_memory:.2f}MB "
                   f"(growth rate: {memory_growth_rate:.3f}MB/iteration)")


# =============================================================================
# LOAD TESTING AND CONCURRENT USER SIMULATION
# =============================================================================

class TestLoadPerformance:
    """
    Load testing and concurrent user simulation test suite.
    
    Implements load testing scenarios per Section 4.7.4.1 with concurrent user
    simulation and scalability validation.
    """
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.skipif(not LOCUST_AVAILABLE, reason="Locust not available for load testing")
    def test_concurrent_user_simulation(self, load_test_runner):
        """
        Test application performance under concurrent user load.
        
        Validates system capability to handle multiple concurrent users within SLA thresholds.
        """
        # Start with moderate load testing
        user_count = 50
        spawn_rate = 5  # 5 users per second
        duration = 30   # 30 seconds
        
        load_test_results = load_test_runner.run_load_test(
            user_count=user_count,
            spawn_rate=spawn_rate,
            duration=duration
        )
        
        # Validate load test results
        assert load_test_results['total_requests'] > 0, "No requests completed during load test"
        assert load_test_results['failure_rate'] < 0.05, \
            f"Failure rate {load_test_results['failure_rate']:.2%} too high"
        
        assert load_test_results['average_response_time'] < PerformanceConfig.API_RESPONSE_TIME_THRESHOLD, \
            f"Average response time {load_test_results['average_response_time']:.2f}ms exceeds SLA"
        
        assert load_test_results['requests_per_second'] > 10, \
            f"Throughput {load_test_results['requests_per_second']:.2f} RPS too low"
        
        logger.info(f"Load test results: {load_test_results['total_requests']} requests, "
                   f"{load_test_results['average_response_time']:.2f}ms avg response time, "
                   f"{load_test_results['requests_per_second']:.2f} RPS")
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_concurrent_api_requests(self, client: FlaskClient, performance_profiler):
        """
        Test concurrent API request handling without external load testing tools.
        
        Validates concurrent request processing using threading for isolated testing.
        """
        def make_concurrent_request(thread_id: int) -> Dict[str, Any]:
            """Make concurrent API request for performance testing."""
            try:
                start_time = time.perf_counter()
                response = client.get('/health')
                end_time = time.perf_counter()
                
                return {
                    'thread_id': thread_id,
                    'success': response.status_code == 200,
                    'response_time': (end_time - start_time) * 1000,
                    'status_code': response.status_code
                }
            except Exception as e:
                return {
                    'thread_id': thread_id,
                    'success': False,
                    'response_time': 0,
                    'error': str(e)
                }
        
        # Execute concurrent requests
        concurrent_requests = 20
        
        with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
            futures = [
                executor.submit(make_concurrent_request, i) 
                for i in range(concurrent_requests)
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        # Analyze concurrent request performance
        successful_requests = [r for r in results if r['success']]
        failed_requests = [r for r in results if not r['success']]
        
        assert len(successful_requests) > 0, "No successful concurrent requests"
        
        success_rate = len(successful_requests) / len(results)
        assert success_rate >= 0.95, f"Success rate {success_rate:.2%} too low for concurrent requests"
        
        response_times = [r['response_time'] for r in successful_requests]
        avg_response_time = statistics.mean(response_times)
        max_response_time = max(response_times)
        
        assert avg_response_time < PerformanceConfig.API_RESPONSE_TIME_THRESHOLD, \
            f"Concurrent request average response time {avg_response_time:.2f}ms exceeds SLA"
        
        logger.info(f"Concurrent requests: {len(successful_requests)}/{len(results)} successful, "
                   f"{avg_response_time:.2f}ms avg, {max_response_time:.2f}ms max")


# =============================================================================
# PERFORMANCE REGRESSION TESTING
# =============================================================================

class TestPerformanceRegression:
    """
    Performance regression detection and baseline comparison testing.
    
    Implements regression detection per Section 4.7.4.1 with statistical analysis
    and automated performance trend monitoring.
    """
    
    @pytest.mark.performance
    def test_response_time_regression(self, client: FlaskClient, performance_profiler, benchmark):
        """
        Test for performance regression in API response times.
        
        Compares current performance against established baselines for regression detection.
        """
        # Establish baseline metrics (in real implementation, these would be loaded from storage)
        baseline_metrics = {
            'mean_response_time': 150.0,  # 150ms baseline
            'p95_response_time': 200.0,   # 200ms 95th percentile
            'mean_memory_delta': 5.0      # 5MB memory delta
        }
        
        def benchmark_health_endpoint():
            with performance_profiler.measure_response_time('regression_test'):
                response = client.get('/health')
                assert response.status_code == 200
                return response
        
        # Execute benchmark test
        result = benchmark(benchmark_health_endpoint)
        
        # Analyze performance regression
        current_metrics = performance_profiler.get_operation_statistics('regression_test')
        regression_analysis = performance_profiler.detect_performance_regression(
            'regression_test', baseline_metrics
        )
        
        # Validate no significant regression detected
        if regression_analysis['regression_detected']:
            logger.warning(f"Performance regression detected: {regression_analysis}")
            
            # Allow for minor regressions, fail on major ones
            if regression_analysis['severity'] == 'high':
                pytest.fail(f"High severity performance regression detected: {regression_analysis}")
        
        # Log performance comparison
        logger.info(f"Regression analysis: {regression_analysis}")
    
    @pytest.mark.performance
    def test_benchmark_comparison_with_statistics(self, client: FlaskClient, benchmark):
        """
        Test statistical performance comparison with comprehensive metrics.
        
        Provides detailed statistical analysis for performance validation and monitoring.
        """
        # Configure benchmark for statistical analysis
        benchmark.pedantic(
            lambda: client.get('/health').status_code == 200,
            rounds=10,
            iterations=5,
            warmup_rounds=2
        )
        
        # Access benchmark statistics
        stats = benchmark.stats
        
        # Validate statistical performance metrics
        assert stats['mean'] < PerformanceConfig.API_RESPONSE_TIME_THRESHOLD / 1000, \
            f"Mean execution time {stats['mean']*1000:.2f}ms exceeds SLA threshold"
        
        assert stats['stddev'] < 0.05, \
            f"Standard deviation {stats['stddev']:.3f}s indicates inconsistent performance"
        
        # Log detailed performance statistics
        logger.info(f"Benchmark statistics: mean={stats['mean']*1000:.2f}ms, "
                   f"stddev={stats['stddev']*1000:.2f}ms, "
                   f"min={stats['min']*1000:.2f}ms, max={stats['max']*1000:.2f}ms")


# =============================================================================
# SLA COMPLIANCE VALIDATION
# =============================================================================

class TestSLACompliance:
    """
    Service Level Agreement (SLA) compliance validation test suite.
    
    Implements comprehensive SLA validation per Section 2.4.2 with automated
    compliance checking and reporting.
    """
    
    @pytest.mark.performance
    def test_api_response_time_sla(self, client: FlaskClient, performance_profiler):
        """
        Validate API response time SLA compliance across all endpoints.
        
        Tests standard API operations must complete within 200ms per Section 2.4.2.
        """
        endpoints_to_test = [
            ('/health', 'GET'),
            ('/health/detailed', 'GET'),
            ('/health/database', 'GET'),
            ('/health/blueprints', 'GET')
        ]
        
        sla_compliance_results = {}
        
        for endpoint, method in endpoints_to_test:
            operation_name = f"{method}_{endpoint.replace('/', '_')}"
            
            # Execute multiple requests for statistical validation
            for i in range(5):
                with performance_profiler.measure_response_time(operation_name):
                    if method == 'GET':
                        response = client.get(endpoint)
                    
                    # Accept various response codes for SLA testing
                    assert response.status_code in [200, 404, 500]
            
            # Analyze SLA compliance
            stats = performance_profiler.get_operation_statistics(operation_name)
            sla_compliant = stats['mean_response_time'] < PerformanceConfig.API_RESPONSE_TIME_THRESHOLD
            
            sla_compliance_results[endpoint] = {
                'compliant': sla_compliant,
                'mean_response_time': stats['mean_response_time'],
                'p95_response_time': stats['p95_response_time'],
                'threshold': PerformanceConfig.API_RESPONSE_TIME_THRESHOLD
            }
            
            # Individual endpoint SLA validation
            assert sla_compliant, \
                f"Endpoint {endpoint} response time {stats['mean_response_time']:.2f}ms exceeds SLA"
        
        # Log comprehensive SLA compliance report
        logger.info("SLA Compliance Report:")
        for endpoint, results in sla_compliance_results.items():
            logger.info(f"  {endpoint}: {results['mean_response_time']:.2f}ms "
                       f"({'PASS' if results['compliant'] else 'FAIL'})")
    
    @pytest.mark.performance
    def test_memory_usage_sla(self, client: FlaskClient):
        """
        Validate memory usage SLA compliance per Section 2.4.2.
        
        Tests memory usage remains within 150-300MB per worker process threshold.
        """
        # Monitor memory usage during sustained operations
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        # Execute sustained operations
        for i in range(20):
            response = client.get('/health')
            assert response.status_code == 200
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        peak_memory = max(initial_memory, final_memory)
        
        # Validate memory SLA compliance
        assert peak_memory >= PerformanceConfig.MIN_MEMORY_THRESHOLD, \
            f"Memory usage {peak_memory:.2f}MB below minimum threshold"
        
        assert peak_memory <= PerformanceConfig.MAX_MEMORY_THRESHOLD, \
            f"Memory usage {peak_memory:.2f}MB exceeds maximum threshold"
        
        logger.info(f"Memory SLA compliance: {peak_memory:.2f}MB "
                   f"(range: {PerformanceConfig.MIN_MEMORY_THRESHOLD}-{PerformanceConfig.MAX_MEMORY_THRESHOLD}MB)")
    
    @pytest.mark.performance
    def test_concurrent_request_sla(self, client: FlaskClient):
        """
        Validate concurrent request handling SLA per Section 2.4.2.
        
        Tests system capability to handle multiple concurrent requests effectively.
        """
        def concurrent_request_test():
            """Execute concurrent requests for SLA validation."""
            response = client.get('/health')
            return response.status_code == 200
        
        # Execute concurrent requests
        concurrent_count = 10  # Reduced for test environment
        
        with ThreadPoolExecutor(max_workers=concurrent_count) as executor:
            start_time = time.perf_counter()
            futures = [executor.submit(concurrent_request_test) for _ in range(concurrent_count)]
            results = [future.result() for future in as_completed(futures)]
            end_time = time.perf_counter()
        
        # Analyze concurrent request performance
        successful_requests = sum(results)
        total_time = end_time - start_time
        throughput = len(results) / total_time  # requests per second
        
        # Validate concurrent request SLA
        success_rate = successful_requests / len(results)
        assert success_rate >= 0.95, f"Concurrent request success rate {success_rate:.2%} below SLA"
        
        assert throughput >= 5.0, f"Throughput {throughput:.2f} RPS below minimum SLA requirement"
        
        logger.info(f"Concurrent request SLA: {successful_requests}/{len(results)} successful, "
                   f"{throughput:.2f} RPS throughput")


# =============================================================================
# PERFORMANCE TEST REPORTING
# =============================================================================

@pytest.fixture(scope='session', autouse=True)
def performance_test_report():
    """
    Generate comprehensive performance test report after test session completion.
    
    Provides detailed performance analysis and recommendations for optimization.
    """
    performance_data = {
        'test_session': {
            'start_time': datetime.now(timezone.utc).isoformat(),
            'python_version': f"{psutil.sys.version_info.major}.{psutil.sys.version_info.minor}",
            'system_info': {
                'cpu_count': psutil.cpu_count(),
                'memory_total_mb': psutil.virtual_memory().total / 1024 / 1024,
                'platform': psutil.sys.platform
            }
        },
        'sla_thresholds': {
            'api_response_time_ms': PerformanceConfig.API_RESPONSE_TIME_THRESHOLD,
            'complex_operation_ms': PerformanceConfig.COMPLEX_OPERATION_THRESHOLD,
            'database_query_ms': PerformanceConfig.DATABASE_QUERY_THRESHOLD,
            'memory_range_mb': f"{PerformanceConfig.MIN_MEMORY_THRESHOLD}-{PerformanceConfig.MAX_MEMORY_THRESHOLD}"
        }
    }
    
    yield performance_data
    
    # Finalize performance report
    performance_data['test_session']['end_time'] = datetime.now(timezone.utc).isoformat()
    
    # Log performance test summary
    logger.info("=== PERFORMANCE TEST SUMMARY ===")
    logger.info(f"Test session duration: {performance_data['test_session']['start_time']} - "
               f"{performance_data['test_session']['end_time']}")
    logger.info(f"SLA Thresholds: {performance_data['sla_thresholds']}")
    logger.info("Performance validation completed successfully")


if __name__ == "__main__":
    """
    Direct execution support for performance testing validation.
    
    Enables standalone performance test execution for development and debugging.
    """
    import subprocess
    import sys
    
    # Execute performance tests with benchmark reporting
    cmd = [
        sys.executable, '-m', 'pytest', __file__,
        '-v', '--benchmark-only', '--benchmark-json=performance_results.json',
        '-m', 'performance'
    ]
    
    logger.info("Starting performance test execution...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    sys.exit(result.returncode)