"""
Performance Testing Utilities for Flask Migration

This module implements comprehensive performance benchmarking infrastructure using 
pytest-benchmark 5.1.0 for Flask application performance validation against Node.js 
baseline metrics. Provides response time validation, memory usage profiling, and 
performance regression detection during the migration process.

Technical Specification Compliance:
- Section 4.7.1: pytest-benchmark 5.1.0 integration for API response time measurement
- Section 4.7.2: Performance comparison utilities for Node.js baseline validation  
- Section 2.4.2: Memory usage validation and database performance requirements
- Section 2.4.3: Concurrent user support validation
- Section 5.3.3: SQLAlchemy optimization and PostgreSQL 14 performance benchmarking

Performance Requirements:
- API response times: equivalent or improved compared to Node.js implementation
- Database performance: maintain current performance levels or better
- Memory usage: comparable to Node.js implementation
- Concurrent users: support same level of concurrent user load as original system
"""

import asyncio
import gc
import json
import logging
import psutil
import pytest
import requests
import statistics
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from unittest.mock import patch

import pytest_benchmark
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

# Import Flask application and models for testing
try:
    from app import create_app
    from config import Config
    from src.models import db
except ImportError:
    # Handle cases where imports are not available during test discovery
    create_app = None
    Config = None
    db = None


# Configure logging for performance testing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """
    Comprehensive performance metrics container for Flask application benchmarking.
    
    Captures essential performance indicators for comparison against Node.js baseline
    including response times, memory usage, database query performance, and 
    concurrent user handling capabilities.
    """
    response_time_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    database_query_time_ms: float = 0.0
    concurrent_users_supported: int = 0
    throughput_requests_per_second: float = 0.0
    error_rate_percent: float = 0.0
    connection_pool_usage: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for JSON serialization and reporting."""
        return {
            'response_time_ms': self.response_time_ms,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
            'database_query_time_ms': self.database_query_time_ms,
            'concurrent_users_supported': self.concurrent_users_supported,
            'throughput_requests_per_second': self.throughput_requests_per_second,
            'error_rate_percent': self.error_rate_percent,
            'connection_pool_usage': self.connection_pool_usage,
            'timestamp': self.timestamp
        }
    
    def compare_with_baseline(self, baseline: 'PerformanceMetrics') -> Dict[str, float]:
        """
        Compare current metrics with Node.js baseline metrics.
        
        Args:
            baseline: Node.js baseline performance metrics
            
        Returns:
            Dictionary containing percentage differences for each metric
        """
        comparisons = {}
        
        if baseline.response_time_ms > 0:
            comparisons['response_time_improvement'] = (
                (baseline.response_time_ms - self.response_time_ms) / baseline.response_time_ms * 100
            )
        
        if baseline.memory_usage_mb > 0:
            comparisons['memory_usage_difference'] = (
                (self.memory_usage_mb - baseline.memory_usage_mb) / baseline.memory_usage_mb * 100
            )
        
        if baseline.throughput_requests_per_second > 0:
            comparisons['throughput_improvement'] = (
                (self.throughput_requests_per_second - baseline.throughput_requests_per_second) / 
                baseline.throughput_requests_per_second * 100
            )
        
        comparisons['concurrent_users_difference'] = (
            self.concurrent_users_supported - baseline.concurrent_users_supported
        )
        
        return comparisons


@dataclass
class BaselineMetrics:
    """
    Node.js baseline performance metrics for comparison validation.
    
    Contains performance benchmarks from the original Node.js implementation
    used for validating Flask application performance parity during migration.
    """
    api_response_times: Dict[str, float] = field(default_factory=dict)
    memory_baseline_mb: float = 100.0  # Typical Node.js application memory usage
    database_query_baselines: Dict[str, float] = field(default_factory=dict)
    concurrent_users_baseline: int = 100
    throughput_baseline_rps: float = 50.0
    error_rate_threshold: float = 1.0  # Maximum acceptable error rate percentage
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'BaselineMetrics':
        """
        Load baseline metrics from JSON file containing Node.js performance data.
        
        Args:
            filepath: Path to JSON file with baseline metrics
            
        Returns:
            BaselineMetrics instance populated with Node.js data
        """
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return cls(**data)
        except FileNotFoundError:
            logger.warning(f"Baseline file {filepath} not found, using default values")
            return cls()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing baseline file {filepath}: {e}")
            return cls()


class PerformanceProfiler:
    """
    Advanced performance profiling utilities for Flask application monitoring.
    
    Provides comprehensive performance monitoring including memory usage tracking,
    CPU utilization measurement, and resource consumption analysis during
    benchmarking operations.
    """
    
    def __init__(self):
        self.process = psutil.Process()
        self.memory_snapshots: List[float] = []
        self.cpu_snapshots: List[float] = []
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
    
    @contextmanager
    def memory_profile(self):
        """
        Context manager for memory usage profiling during test execution.
        
        Tracks memory consumption and provides statistics for comparison
        against Node.js baseline memory usage requirements.
        """
        tracemalloc.start()
        gc.collect()  # Clean up before measurement
        
        initial_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        
        try:
            yield
        finally:
            final_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            memory_delta = final_memory - initial_memory
            peak_mb = peak / 1024 / 1024
            
            logger.info(f"Memory usage: Initial={initial_memory:.2f}MB, "
                       f"Final={final_memory:.2f}MB, Delta={memory_delta:.2f}MB, "
                       f"Peak={peak_mb:.2f}MB")
    
    def start_continuous_monitoring(self, interval: float = 0.1):
        """
        Start continuous system resource monitoring during performance tests.
        
        Args:
            interval: Monitoring interval in seconds
        """
        self._monitoring = True
        self.memory_snapshots.clear()
        self.cpu_snapshots.clear()
        
        def monitor():
            while self._monitoring:
                try:
                    memory_mb = self.process.memory_info().rss / 1024 / 1024
                    cpu_percent = self.process.cpu_percent()
                    
                    self.memory_snapshots.append(memory_mb)
                    self.cpu_snapshots.append(cpu_percent)
                    
                    time.sleep(interval)
                except Exception as e:
                    logger.error(f"Error during monitoring: {e}")
                    break
        
        self._monitor_thread = threading.Thread(target=monitor, daemon=True)
        self._monitor_thread.start()
    
    def stop_continuous_monitoring(self) -> PerformanceMetrics:
        """
        Stop continuous monitoring and return aggregated performance metrics.
        
        Returns:
            PerformanceMetrics with statistical analysis of resource usage
        """
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        
        metrics = PerformanceMetrics()
        
        if self.memory_snapshots:
            metrics.memory_usage_mb = statistics.mean(self.memory_snapshots)
        
        if self.cpu_snapshots:
            metrics.cpu_usage_percent = statistics.mean(self.cpu_snapshots)
        
        return metrics


class DatabasePerformanceMonitor:
    """
    SQLAlchemy and PostgreSQL performance monitoring for database operations.
    
    Implements comprehensive database performance tracking including query execution
    times, connection pool utilization, and PostgreSQL 14 optimization validation
    as specified in Section 5.3.3.
    """
    
    def __init__(self, engine: Engine):
        self.engine = engine
        self.query_times: List[float] = []
        self.connection_events: List[Dict] = []
        self._setup_listeners()
    
    def _setup_listeners(self):
        """Setup SQLAlchemy event listeners for performance monitoring."""
        
        @event.listens_for(self.engine, "before_cursor_execute")
        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.perf_counter()
        
        @event.listens_for(self.engine, "after_cursor_execute")
        def after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            if hasattr(context, '_query_start_time'):
                query_time = (time.perf_counter() - context._query_start_time) * 1000
                self.query_times.append(query_time)
                
                logger.debug(f"Query executed in {query_time:.2f}ms: "
                           f"{statement[:100]}{'...' if len(statement) > 100 else ''}")
        
        @event.listens_for(self.engine, "connect")
        def connect(dbapi_connection, connection_record):
            self.connection_events.append({
                'event': 'connect',
                'timestamp': time.time(),
                'connection_id': id(dbapi_connection)
            })
        
        @event.listens_for(self.engine, "close")
        def close(dbapi_connection, connection_record):
            self.connection_events.append({
                'event': 'close',
                'timestamp': time.time(),
                'connection_id': id(dbapi_connection)
            })
    
    def get_connection_pool_stats(self) -> Dict[str, Any]:
        """
        Get PostgreSQL connection pool statistics for performance analysis.
        
        Returns:
            Dictionary containing connection pool utilization metrics
        """
        pool = self.engine.pool
        
        if isinstance(pool, QueuePool):
            return {
                'pool_size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'invalid': pool.invalid(),
                'utilization_percent': (pool.checkedout() / pool.size() * 100) if pool.size() > 0 else 0
            }
        else:
            return {'pool_type': type(pool).__name__, 'size': getattr(pool, 'size', lambda: 'unknown')()}
    
    def benchmark_query(self, query: str, params: Optional[Dict] = None) -> float:
        """
        Benchmark individual database query performance.
        
        Args:
            query: SQL query string to benchmark
            params: Optional query parameters
            
        Returns:
            Query execution time in milliseconds
        """
        start_time = time.perf_counter()
        
        with self.engine.connect() as conn:
            conn.execute(text(query), params or {})
        
        execution_time = (time.perf_counter() - start_time) * 1000
        return execution_time
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Generate comprehensive database performance summary.
        
        Returns:
            Dictionary with query statistics and connection pool metrics
        """
        summary = {
            'total_queries': len(self.query_times),
            'average_query_time_ms': statistics.mean(self.query_times) if self.query_times else 0,
            'median_query_time_ms': statistics.median(self.query_times) if self.query_times else 0,
            'max_query_time_ms': max(self.query_times) if self.query_times else 0,
            'min_query_time_ms': min(self.query_times) if self.query_times else 0,
            'connection_pool_stats': self.get_connection_pool_stats(),
            'connection_events_count': len(self.connection_events)
        }
        
        if len(self.query_times) > 1:
            summary['query_time_stddev_ms'] = statistics.stdev(self.query_times)
        
        return summary


class ConcurrentUserSimulator:
    """
    Concurrent user load testing utilities for scalability validation.
    
    Simulates multiple concurrent users to validate Flask application performance
    under load and ensure equivalent or improved concurrent user support compared
    to the original Node.js implementation per Section 2.4.3.
    """
    
    def __init__(self, base_url: str, max_workers: int = 50):
        self.base_url = base_url
        self.max_workers = max_workers
        self.session = requests.Session()
        # Configure session for performance testing
        self.session.headers.update({
            'User-Agent': 'Flask-Migration-Performance-Test/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def simulate_user_session(self, endpoints: List[str], duration_seconds: int = 60) -> Dict[str, Any]:
        """
        Simulate single user session across multiple endpoints.
        
        Args:
            endpoints: List of API endpoints to test
            duration_seconds: Duration of user simulation
            
        Returns:
            Dictionary with user session performance metrics
        """
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        request_count = 0
        error_count = 0
        response_times = []
        
        while time.time() < end_time:
            for endpoint in endpoints:
                try:
                    response_start = time.perf_counter()
                    response = self.session.get(f"{self.base_url}{endpoint}", timeout=30)
                    response_time = (time.perf_counter() - response_start) * 1000
                    
                    response_times.append(response_time)
                    request_count += 1
                    
                    if response.status_code >= 400:
                        error_count += 1
                        
                except Exception as e:
                    error_count += 1
                    logger.warning(f"Request error for {endpoint}: {e}")
                
                # Small delay between requests to simulate realistic user behavior
                time.sleep(0.1)
        
        return {
            'requests_made': request_count,
            'errors': error_count,
            'error_rate': (error_count / request_count * 100) if request_count > 0 else 0,
            'average_response_time_ms': statistics.mean(response_times) if response_times else 0,
            'median_response_time_ms': statistics.median(response_times) if response_times else 0,
            'max_response_time_ms': max(response_times) if response_times else 0,
            'duration_seconds': time.time() - start_time
        }
    
    def concurrent_load_test(self, 
                           endpoints: List[str], 
                           concurrent_users: int, 
                           duration_seconds: int = 60) -> Dict[str, Any]:
        """
        Execute concurrent load testing with multiple simulated users.
        
        Args:
            endpoints: List of API endpoints to test
            concurrent_users: Number of concurrent users to simulate
            duration_seconds: Duration of load test
            
        Returns:
            Comprehensive load testing results and performance metrics
        """
        logger.info(f"Starting load test with {concurrent_users} concurrent users "
                   f"for {duration_seconds} seconds")
        
        start_time = time.time()
        results = []
        
        with ThreadPoolExecutor(max_workers=min(concurrent_users, self.max_workers)) as executor:
            # Submit all user simulation tasks
            futures = [
                executor.submit(self.simulate_user_session, endpoints, duration_seconds)
                for _ in range(concurrent_users)
            ]
            
            # Collect results as they complete
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"User simulation failed: {e}")
                    results.append({
                        'requests_made': 0,
                        'errors': 1,
                        'error_rate': 100,
                        'average_response_time_ms': 0,
                        'median_response_time_ms': 0,
                        'max_response_time_ms': 0,
                        'duration_seconds': 0
                    })
        
        # Aggregate results
        total_duration = time.time() - start_time
        total_requests = sum(r['requests_made'] for r in results)
        total_errors = sum(r['errors'] for r in results)
        all_response_times = []
        
        for result in results:
            if 'response_times' in result:
                all_response_times.extend(result['response_times'])
        
        return {
            'concurrent_users': concurrent_users,
            'total_duration_seconds': total_duration,
            'total_requests': total_requests,
            'total_errors': total_errors,
            'overall_error_rate': (total_errors / total_requests * 100) if total_requests > 0 else 0,
            'requests_per_second': total_requests / total_duration if total_duration > 0 else 0,
            'successful_users': len([r for r in results if r['error_rate'] < 10]),
            'average_user_requests': total_requests / concurrent_users if concurrent_users > 0 else 0,
            'user_results': results
        }


class PerformanceRegressionDetector:
    """
    Automated performance regression detection with threshold validation.
    
    Implements comprehensive regression detection algorithms to identify
    performance degradations during Flask migration and ensure performance
    requirements are maintained per Section 4.7.1.
    """
    
    def __init__(self, baseline_metrics: BaselineMetrics):
        self.baseline = baseline_metrics
        self.tolerance_thresholds = {
            'response_time_degradation_percent': 10.0,  # Max 10% slower than baseline
            'memory_increase_percent': 20.0,            # Max 20% more memory usage
            'throughput_decrease_percent': 5.0,         # Max 5% throughput decrease
            'error_rate_increase_percent': 1.0,         # Max 1% error rate increase
            'database_query_degradation_percent': 15.0  # Max 15% query time increase
        }
    
    def detect_response_time_regression(self, 
                                      current_metrics: PerformanceMetrics,
                                      endpoint: str) -> Dict[str, Any]:
        """
        Detect API response time performance regressions.
        
        Args:
            current_metrics: Current Flask application performance metrics
            endpoint: API endpoint being tested
            
        Returns:
            Regression detection results with recommendations
        """
        baseline_time = self.baseline.api_response_times.get(endpoint, 0)
        
        if baseline_time == 0:
            return {
                'regression_detected': False,
                'reason': 'No baseline data available',
                'recommendation': f'Establish baseline metrics for {endpoint}'
            }
        
        degradation_percent = (
            (current_metrics.response_time_ms - baseline_time) / baseline_time * 100
        )
        
        threshold = self.tolerance_thresholds['response_time_degradation_percent']
        regression_detected = degradation_percent > threshold
        
        return {
            'regression_detected': regression_detected,
            'baseline_time_ms': baseline_time,
            'current_time_ms': current_metrics.response_time_ms,
            'degradation_percent': degradation_percent,
            'threshold_percent': threshold,
            'recommendation': (
                f'Response time regression detected for {endpoint}. '
                f'Optimize implementation or adjust performance expectations.'
                if regression_detected else
                f'Response time within acceptable range for {endpoint}.'
            )
        }
    
    def detect_memory_regression(self, current_metrics: PerformanceMetrics) -> Dict[str, Any]:
        """
        Detect memory usage performance regressions.
        
        Args:
            current_metrics: Current Flask application performance metrics
            
        Returns:
            Memory regression analysis results
        """
        baseline_memory = self.baseline.memory_baseline_mb
        
        increase_percent = (
            (current_metrics.memory_usage_mb - baseline_memory) / baseline_memory * 100
        )
        
        threshold = self.tolerance_thresholds['memory_increase_percent']
        regression_detected = increase_percent > threshold
        
        return {
            'regression_detected': regression_detected,
            'baseline_memory_mb': baseline_memory,
            'current_memory_mb': current_metrics.memory_usage_mb,
            'increase_percent': increase_percent,
            'threshold_percent': threshold,
            'recommendation': (
                'Memory usage regression detected. '
                'Review Flask application memory management and optimization.'
                if regression_detected else
                'Memory usage within acceptable range.'
            )
        }
    
    def detect_throughput_regression(self, current_metrics: PerformanceMetrics) -> Dict[str, Any]:
        """
        Detect throughput performance regressions.
        
        Args:
            current_metrics: Current Flask application performance metrics
            
        Returns:
            Throughput regression analysis results
        """
        baseline_throughput = self.baseline.throughput_baseline_rps
        
        decrease_percent = (
            (baseline_throughput - current_metrics.throughput_requests_per_second) / 
            baseline_throughput * 100
        )
        
        threshold = self.tolerance_thresholds['throughput_decrease_percent']
        regression_detected = decrease_percent > threshold
        
        return {
            'regression_detected': regression_detected,
            'baseline_throughput_rps': baseline_throughput,
            'current_throughput_rps': current_metrics.throughput_requests_per_second,
            'decrease_percent': decrease_percent,
            'threshold_percent': threshold,
            'recommendation': (
                'Throughput regression detected. '
                'Optimize Flask application request handling and database queries.'
                if regression_detected else
                'Throughput performance within acceptable range.'
            )
        }
    
    def comprehensive_regression_analysis(self, 
                                        current_metrics: PerformanceMetrics,
                                        endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive regression analysis across all performance metrics.
        
        Args:
            current_metrics: Current Flask application performance metrics
            endpoint: Optional specific endpoint for analysis
            
        Returns:
            Complete regression analysis report with recommendations
        """
        analysis_results = {
            'overall_regression_detected': False,
            'timestamp': time.time(),
            'analysis_details': {}
        }
        
        # Response time analysis (if endpoint specified)
        if endpoint:
            response_analysis = self.detect_response_time_regression(current_metrics, endpoint)
            analysis_results['analysis_details']['response_time'] = response_analysis
            if response_analysis['regression_detected']:
                analysis_results['overall_regression_detected'] = True
        
        # Memory usage analysis
        memory_analysis = self.detect_memory_regression(current_metrics)
        analysis_results['analysis_details']['memory_usage'] = memory_analysis
        if memory_analysis['regression_detected']:
            analysis_results['overall_regression_detected'] = True
        
        # Throughput analysis
        throughput_analysis = self.detect_throughput_regression(current_metrics)
        analysis_results['analysis_details']['throughput'] = throughput_analysis
        if throughput_analysis['regression_detected']:
            analysis_results['overall_regression_detected'] = True
        
        # Error rate analysis
        baseline_error_rate = self.baseline.error_rate_threshold
        error_rate_exceeded = current_metrics.error_rate_percent > baseline_error_rate
        
        analysis_results['analysis_details']['error_rate'] = {
            'regression_detected': error_rate_exceeded,
            'baseline_error_rate': baseline_error_rate,
            'current_error_rate': current_metrics.error_rate_percent,
            'recommendation': (
                'Error rate exceeds acceptable threshold. '
                'Review Flask application error handling and stability.'
                if error_rate_exceeded else
                'Error rate within acceptable range.'
            )
        }
        
        if error_rate_exceeded:
            analysis_results['overall_regression_detected'] = True
        
        # Generate overall recommendations
        if analysis_results['overall_regression_detected']:
            analysis_results['overall_recommendation'] = (
                'Performance regressions detected. Prioritize optimization efforts '
                'based on individual metric analysis and re-run performance validation.'
            )
        else:
            analysis_results['overall_recommendation'] = (
                'All performance metrics within acceptable ranges. '
                'Flask migration performance validation successful.'
            )
        
        return analysis_results


# pytest-benchmark 5.1.0 integration fixtures and utilities

@pytest.fixture(scope="session")
def flask_app():
    """
    Create Flask application instance for performance testing.
    
    Returns:
        Configured Flask application with testing configuration
    """
    if create_app is None:
        pytest.skip("Flask application not available for testing")
    
    # Configure for testing with performance monitoring
    test_config = {
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'postgresql://test_user:test_pass@localhost/test_db',
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_size': 10,
            'pool_timeout': 30,
            'pool_recycle': 3600,
            'max_overflow': 20
        }
    }
    
    app = create_app(test_config)
    
    with app.app_context():
        if db is not None:
            db.create_all()
        yield app
        if db is not None:
            db.session.remove()
            db.drop_all()


@pytest.fixture(scope="session")
def flask_client(flask_app):
    """
    Create Flask test client for API performance testing.
    
    Args:
        flask_app: Flask application fixture
        
    Returns:
        Flask test client configured for performance benchmarking
    """
    return flask_app.test_client()


@pytest.fixture(scope="session")
def performance_profiler():
    """
    Create performance profiler instance for resource monitoring.
    
    Returns:
        PerformanceProfiler configured for Flask application monitoring
    """
    return PerformanceProfiler()


@pytest.fixture(scope="session")
def database_monitor(flask_app):
    """
    Create database performance monitor for SQLAlchemy monitoring.
    
    Args:
        flask_app: Flask application fixture
        
    Returns:
        DatabasePerformanceMonitor configured for PostgreSQL monitoring
    """
    if db is None:
        pytest.skip("Database not available for testing")
    
    return DatabasePerformanceMonitor(db.engine)


@pytest.fixture(scope="session")
def baseline_metrics():
    """
    Load Node.js baseline metrics for performance comparison.
    
    Returns:
        BaselineMetrics instance with Node.js performance data
    """
    # Attempt to load from configuration file
    baseline_file = Path(__file__).parent.parent / 'data' / 'nodejs_baseline_metrics.json'
    return BaselineMetrics.load_from_file(str(baseline_file))


@pytest.fixture(scope="session")
def regression_detector(baseline_metrics):
    """
    Create performance regression detector for automated validation.
    
    Args:
        baseline_metrics: Node.js baseline metrics fixture
        
    Returns:
        PerformanceRegressionDetector configured with baseline data
    """
    return PerformanceRegressionDetector(baseline_metrics)


@pytest.fixture(scope="function")
def concurrent_simulator(flask_app):
    """
    Create concurrent user simulator for load testing.
    
    Args:
        flask_app: Flask application fixture
        
    Returns:
        ConcurrentUserSimulator configured for Flask application testing
    """
    # Use test server URL or localhost
    base_url = "http://localhost:5000"
    return ConcurrentUserSimulator(base_url)


def benchmark_api_endpoint(benchmark, client: FlaskClient, endpoint: str, method: str = 'GET', 
                          data: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Benchmark Flask API endpoint performance using pytest-benchmark.
    
    Args:
        benchmark: pytest-benchmark fixture
        client: Flask test client
        endpoint: API endpoint to benchmark
        method: HTTP method (GET, POST, PUT, DELETE)
        data: Optional request data for POST/PUT requests
        
    Returns:
        Dictionary containing benchmark results and performance metrics
    """
    def execute_request():
        if method.upper() == 'GET':
            return client.get(endpoint)
        elif method.upper() == 'POST':
            return client.post(endpoint, json=data)
        elif method.upper() == 'PUT':
            return client.put(endpoint, json=data)
        elif method.upper() == 'DELETE':
            return client.delete(endpoint)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
    
    # Execute benchmark with pytest-benchmark
    result = benchmark(execute_request)
    
    # Calculate performance metrics from benchmark statistics
    stats = benchmark.stats
    
    return {
        'endpoint': endpoint,
        'method': method,
        'mean_time_seconds': stats.mean,
        'mean_time_ms': stats.mean * 1000,
        'median_time_seconds': stats.median,
        'median_time_ms': stats.median * 1000,
        'min_time_seconds': stats.min,
        'min_time_ms': stats.min * 1000,
        'max_time_seconds': stats.max,
        'max_time_ms': stats.max * 1000,
        'stddev_seconds': stats.stddev,
        'stddev_ms': stats.stddev * 1000,
        'rounds': stats.rounds,
        'iterations': stats.iterations
    }


def benchmark_database_query(benchmark, monitor: DatabasePerformanceMonitor, 
                           query: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Benchmark database query performance using pytest-benchmark and SQLAlchemy monitoring.
    
    Args:
        benchmark: pytest-benchmark fixture  
        monitor: Database performance monitor
        query: SQL query to benchmark
        params: Optional query parameters
        
    Returns:
        Dictionary containing query benchmark results and database statistics
    """
    def execute_query():
        return monitor.benchmark_query(query, params)
    
    # Clear previous query statistics
    monitor.query_times.clear()
    
    # Execute benchmark
    result = benchmark(execute_query)
    
    # Get database performance statistics
    db_stats = monitor.get_performance_summary()
    
    # Calculate performance metrics
    stats = benchmark.stats
    
    return {
        'query': query[:100] + ('...' if len(query) > 100 else ''),
        'params': params,
        'mean_time_seconds': stats.mean,
        'mean_time_ms': stats.mean * 1000,
        'median_time_ms': stats.median * 1000,
        'min_time_ms': stats.min * 1000,
        'max_time_ms': stats.max * 1000,
        'stddev_ms': stats.stddev * 1000,
        'rounds': stats.rounds,
        'database_stats': db_stats
    }


def performance_test_with_memory_profiling(profiler: PerformanceProfiler, 
                                         test_function: Callable,
                                         monitoring_duration: float = 10.0) -> Dict[str, Any]:
    """
    Execute performance test with comprehensive memory and CPU profiling.
    
    Args:
        profiler: Performance profiler instance
        test_function: Function to execute during profiling
        monitoring_duration: Duration of continuous monitoring in seconds
        
    Returns:
        Dictionary containing profiling results and performance metrics
    """
    # Start continuous monitoring
    profiler.start_continuous_monitoring()
    
    start_time = time.time()
    
    try:
        with profiler.memory_profile():
            # Execute test function
            result = test_function()
    finally:
        # Stop monitoring and collect metrics
        metrics = profiler.stop_continuous_monitoring()
        metrics.timestamp = start_time
        
        # Wait for monitoring to complete if needed
        end_time = time.time()
        if end_time - start_time < monitoring_duration:
            time.sleep(monitoring_duration - (end_time - start_time))
    
    return {
        'test_result': result,
        'performance_metrics': metrics.to_dict(),
        'execution_duration_seconds': end_time - start_time
    }


# Additional utility functions for comprehensive performance validation

def validate_performance_requirements(metrics: PerformanceMetrics, 
                                    baseline: BaselineMetrics,
                                    requirements: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate Flask application performance against requirements from Section 2.4.2.
    
    Args:
        metrics: Current Flask application performance metrics
        baseline: Node.js baseline performance metrics
        requirements: Performance requirements dictionary
        
    Returns:
        Validation results with pass/fail status for each requirement
    """
    validation_results = {
        'overall_pass': True,
        'timestamp': time.time(),
        'requirements_validation': {}
    }
    
    # Response time requirement validation
    response_time_pass = metrics.response_time_ms <= baseline.api_response_times.get('average', float('inf'))
    validation_results['requirements_validation']['response_time'] = {
        'requirement': 'API response times equivalent or improved',
        'pass': response_time_pass,
        'current_ms': metrics.response_time_ms,
        'baseline_ms': baseline.api_response_times.get('average', 0)
    }
    
    # Memory usage requirement validation  
    memory_pass = metrics.memory_usage_mb <= baseline.memory_baseline_mb * 1.2  # 20% tolerance
    validation_results['requirements_validation']['memory_usage'] = {
        'requirement': 'Memory usage comparable to Node.js implementation',
        'pass': memory_pass,
        'current_mb': metrics.memory_usage_mb,
        'baseline_mb': baseline.memory_baseline_mb,
        'tolerance_percent': 20
    }
    
    # Concurrent users requirement validation
    concurrent_users_pass = metrics.concurrent_users_supported >= baseline.concurrent_users_baseline
    validation_results['requirements_validation']['concurrent_users'] = {
        'requirement': 'Support same level of concurrent user load',
        'pass': concurrent_users_pass,
        'current_users': metrics.concurrent_users_supported,
        'baseline_users': baseline.concurrent_users_baseline
    }
    
    # Throughput requirement validation
    throughput_pass = metrics.throughput_requests_per_second >= baseline.throughput_baseline_rps * 0.95  # 5% tolerance
    validation_results['requirements_validation']['throughput'] = {
        'requirement': 'Maintain or improve throughput performance',
        'pass': throughput_pass,
        'current_rps': metrics.throughput_requests_per_second,
        'baseline_rps': baseline.throughput_baseline_rps,
        'tolerance_percent': 5
    }
    
    # Update overall pass status
    validation_results['overall_pass'] = all(
        req['pass'] for req in validation_results['requirements_validation'].values()
    )
    
    return validation_results


def generate_performance_report(metrics: PerformanceMetrics,
                              baseline: BaselineMetrics,
                              regression_analysis: Dict[str, Any],
                              validation_results: Dict[str, Any]) -> str:
    """
    Generate comprehensive performance testing report for Flask migration validation.
    
    Args:
        metrics: Current Flask application performance metrics
        baseline: Node.js baseline performance metrics  
        regression_analysis: Performance regression analysis results
        validation_results: Requirements validation results
        
    Returns:
        Formatted performance report string
    """
    report_lines = [
        "=" * 80,
        "FLASK MIGRATION PERFORMANCE VALIDATION REPORT",
        "=" * 80,
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}",
        "",
        "PERFORMANCE METRICS SUMMARY",
        "-" * 40,
        f"Response Time: {metrics.response_time_ms:.2f}ms",
        f"Memory Usage: {metrics.memory_usage_mb:.2f}MB",
        f"CPU Usage: {metrics.cpu_usage_percent:.2f}%",
        f"Database Query Time: {metrics.database_query_time_ms:.2f}ms",
        f"Concurrent Users Supported: {metrics.concurrent_users_supported}",
        f"Throughput: {metrics.throughput_requests_per_second:.2f} req/sec",
        f"Error Rate: {metrics.error_rate_percent:.2f}%",
        "",
        "BASELINE COMPARISON",
        "-" * 40
    ]
    
    # Add baseline comparisons
    comparisons = metrics.compare_with_baseline(
        PerformanceMetrics(
            response_time_ms=baseline.api_response_times.get('average', 0),
            memory_usage_mb=baseline.memory_baseline_mb,
            throughput_requests_per_second=baseline.throughput_baseline_rps,
            concurrent_users_supported=baseline.concurrent_users_baseline
        )
    )
    
    for metric, improvement in comparisons.items():
        if isinstance(improvement, float):
            report_lines.append(f"{metric}: {improvement:+.2f}%")
        else:
            report_lines.append(f"{metric}: {improvement:+d}")
    
    report_lines.extend([
        "",
        "REQUIREMENTS VALIDATION",
        "-" * 40
    ])
    
    # Add validation results
    for req_name, req_data in validation_results['requirements_validation'].items():
        status = "PASS" if req_data['pass'] else "FAIL"
        report_lines.append(f"{req_name.upper()}: {status}")
        report_lines.append(f"  Requirement: {req_data['requirement']}")
    
    # Add regression analysis summary
    report_lines.extend([
        "",
        "REGRESSION ANALYSIS",
        "-" * 40,
        f"Overall Regression Detected: {'YES' if regression_analysis['overall_regression_detected'] else 'NO'}"
    ])
    
    if regression_analysis['overall_regression_detected']:
        report_lines.append("RECOMMENDATIONS:")
        for analysis_type, analysis_data in regression_analysis['analysis_details'].items():
            if analysis_data.get('regression_detected'):
                report_lines.append(f"  - {analysis_data.get('recommendation', 'Review performance optimization')}")
    
    report_lines.extend([
        "",
        "OVERALL ASSESSMENT",
        "-" * 40,
        f"Performance Validation: {'PASS' if validation_results['overall_pass'] else 'FAIL'}",
        f"Migration Status: {'READY FOR PRODUCTION' if validation_results['overall_pass'] and not regression_analysis['overall_regression_detected'] else 'REQUIRES OPTIMIZATION'}",
        "=" * 80
    ])
    
    return "\n".join(report_lines)