"""
pytest performance testing configuration file providing comprehensive performance testing 
fixtures, pytest-benchmark 5.1.0 configuration, baseline data management, and testing 
infrastructure for primary performance validation.

This configuration establishes the foundational testing environment for pytest-benchmark
integration with Flask 3.1.1 application performance testing, Node.js baseline comparison,
and automated performance regression detection across all performance testing scenarios
as specified in Section 4.7.1 and Section 4.11 of the technical specification.

Key Features:
- pytest-benchmark 5.1.0 configuration for statistical performance measurement
- Flask application factory pattern performance testing with monitoring integration
- Performance threshold validation for sub-200ms API, sub-100ms database, sub-150ms auth
- Baseline comparison framework with Node.js metrics storage and validation
- Automated performance regression detection with statistical analysis
- Multi-environment testing orchestration with tox 4.26.0 integration
- Memory profiling and resource utilization monitoring
- Concurrent load testing infrastructure and thread pool analysis

Dependencies:
- pytest-benchmark 5.1.0: Statistical performance measurement and benchmarking
- Flask 3.1.1: Application factory pattern and request context performance
- memory_profiler: Memory usage analysis and profiling capabilities
- tox 4.26.0: Multi-environment testing orchestration
- threading: Concurrent testing infrastructure for load scenarios
"""

import os
import json
import time
import threading
import statistics
import tracemalloc
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Generator, Tuple
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import sqlite3
import pickle
import hashlib

import pytest
from pytest_benchmark import BenchmarkFixture
from unittest.mock import Mock, patch, MagicMock
import requests
from memory_profiler import profile, memory_usage
import psutil
import threading

# Flask and extension imports
from flask import Flask, g, request, current_app
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy
from werkzeug.test import Client

# Import application components and parent conftest
try:
    from app import create_app
    from config import TestingConfig, PerformanceConfig
    from src.models import db, User
    from src.auth.models import AuthSession
    from tests.conftest import (
        TestingConfiguration, MockUser, MockAuth0Client,
        sample_users, authenticated_user, auth_headers
    )
except ImportError:
    # Handle case where modules don't exist yet during development
    create_app = None
    TestingConfig = None
    PerformanceConfig = None
    db = None
    User = None
    AuthSession = None
    TestingConfiguration = None
    MockUser = None
    MockAuth0Client = None


class PerformanceTestingConfiguration(TestingConfiguration):
    """
    Enhanced performance testing configuration extending base testing configuration
    with performance-specific settings, monitoring capabilities, and threshold validation.
    
    This configuration ensures optimal performance testing environment setup with
    comprehensive monitoring, profiling, and baseline comparison capabilities as
    specified in Section 4.11.3 for Flask performance benchmarks and SLA alignment.
    """
    
    # Performance testing specific configuration
    PERFORMANCE_TESTING = True
    BENCHMARK_TIMEOUT = 300  # 5 minute timeout for benchmarks
    BENCHMARK_MIN_ROUNDS = 10  # Minimum benchmark rounds for statistical validity
    BENCHMARK_MAX_TIME = 60  # Maximum time per benchmark in seconds
    
    # Performance SLA thresholds as per Section 4.11.1
    API_RESPONSE_TIME_THRESHOLD = 0.200  # 200ms for Flask API responses
    DATABASE_QUERY_THRESHOLD = 0.100     # 100ms for SQLAlchemy queries
    AUTHENTICATION_THRESHOLD = 0.150     # 150ms for authentication flows
    MEMORY_USAGE_THRESHOLD_MB = 512       # 512MB memory usage threshold
    CONCURRENT_USER_THRESHOLD = 100       # Concurrent user capacity
    
    # Database configuration optimized for performance testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///performance_test.db'
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 20,
        'max_overflow': 30,
        'pool_pre_ping': True,
        'pool_recycle': 3600,
        'echo': False  # Disable SQL logging for performance
    }
    
    # Performance monitoring configuration
    ENABLE_MEMORY_PROFILING = True
    ENABLE_CPU_PROFILING = True
    ENABLE_THREAD_MONITORING = True
    PERFORMANCE_METRICS_STORAGE = 'performance_metrics.db'
    
    # Baseline comparison configuration
    BASELINE_DATA_PATH = 'baseline_performance_data.json'
    NODEJS_BASELINE_PATH = 'nodejs_baseline_metrics.json'
    PERFORMANCE_REGRESSION_THRESHOLD = 0.10  # 10% performance regression threshold
    ENABLE_BASELINE_COMPARISON = True
    
    # Concurrent testing configuration
    DEFAULT_THREAD_POOL_SIZE = 50
    MAX_CONCURRENT_REQUESTS = 200
    LOAD_TEST_DURATION = 60  # Load test duration in seconds
    RAMP_UP_TIME = 10        # Ramp up time for load tests
    
    # Statistical analysis configuration
    CONFIDENCE_INTERVAL = 0.95
    OUTLIER_DETECTION_ENABLED = True
    STATISTICAL_SIGNIFICANCE_THRESHOLD = 0.05


class PerformanceMetricsCollector:
    """
    Comprehensive performance metrics collection and analysis class providing
    statistical analysis, baseline comparison, and performance regression detection
    capabilities for Flask application performance validation.
    
    This collector implements comprehensive performance monitoring as specified
    in Section 6.5.1.1 for observability and performance validation requirements.
    """
    
    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path or 'performance_metrics.db'
        self.metrics_buffer = defaultdict(list)
        self.baseline_data = {}
        self.session_metrics = {}
        self._init_storage()
        self._load_baseline_data()
    
    def _init_storage(self):
        """Initialize SQLite storage for performance metrics persistence"""
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()
        
        # Create performance metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_name TEXT NOT NULL,
                metric_type TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                test_session TEXT,
                environment TEXT,
                metadata TEXT
            )
        ''')
        
        # Create baseline comparison table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_comparisons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_name TEXT NOT NULL,
                flask_value REAL NOT NULL,
                nodejs_value REAL,
                performance_ratio REAL,
                passed BOOLEAN,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_baseline_data(self):
        """Load Node.js baseline performance data for comparison"""
        baseline_path = Path('tests/performance/nodejs_baseline_metrics.json')
        if baseline_path.exists():
            with open(baseline_path, 'r') as f:
                self.baseline_data = json.load(f)
    
    def record_metric(self, test_name: str, metric_type: str, value: float, 
                     unit: str, metadata: Dict[str, Any] = None):
        """
        Record performance metric with comprehensive metadata and storage
        
        Args:
            test_name: Name of the test generating the metric
            metric_type: Type of metric (response_time, memory_usage, etc.)
            value: Measured value
            unit: Unit of measurement (ms, MB, etc.)
            metadata: Additional metric metadata
        """
        metric_data = {
            'test_name': test_name,
            'metric_type': metric_type,
            'value': value,
            'unit': unit,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': json.dumps(metadata or {})
        }
        
        # Store in buffer for session analysis
        self.metrics_buffer[f"{test_name}:{metric_type}"].append(value)
        
        # Persist to database
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO performance_metrics 
            (test_name, metric_type, value, unit, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (test_name, metric_type, value, unit, 
              metric_data['timestamp'], metric_data['metadata']))
        conn.commit()
        conn.close()
    
    def compare_with_baseline(self, test_name: str, metric_type: str, 
                            flask_value: float) -> Dict[str, Any]:
        """
        Compare Flask performance with Node.js baseline metrics
        
        Args:
            test_name: Name of the test
            metric_type: Type of metric being compared
            flask_value: Flask implementation measured value
            
        Returns:
            Dict containing comparison results and analysis
        """
        baseline_key = f"{test_name}:{metric_type}"
        nodejs_value = self.baseline_data.get(baseline_key)
        
        if nodejs_value is None:
            return {
                'comparison_available': False,
                'message': f'No baseline data available for {baseline_key}'
            }
        
        # Calculate performance ratio (Flask/Node.js)
        performance_ratio = flask_value / nodejs_value if nodejs_value > 0 else float('inf')
        
        # Determine if performance is acceptable (within 10% regression threshold)
        threshold = PerformanceTestingConfiguration.PERFORMANCE_REGRESSION_THRESHOLD
        passed = performance_ratio <= (1.0 + threshold)
        
        comparison_result = {
            'comparison_available': True,
            'flask_value': flask_value,
            'nodejs_value': nodejs_value,
            'performance_ratio': performance_ratio,
            'improvement_percentage': ((nodejs_value - flask_value) / nodejs_value) * 100,
            'passed': passed,
            'threshold_used': threshold,
            'analysis': self._generate_performance_analysis(performance_ratio, passed)
        }
        
        # Store comparison results
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO baseline_comparisons 
            (test_name, flask_value, nodejs_value, performance_ratio, passed)
            VALUES (?, ?, ?, ?, ?)
        ''', (f"{test_name}:{metric_type}", flask_value, nodejs_value, 
              performance_ratio, passed))
        conn.commit()
        conn.close()
        
        return comparison_result
    
    def _generate_performance_analysis(self, ratio: float, passed: bool) -> str:
        """Generate human-readable performance analysis"""
        if ratio < 0.9:
            return f"Excellent performance - {((1-ratio)*100):.1f}% faster than Node.js"
        elif ratio < 1.0:
            return f"Good performance - {((1-ratio)*100):.1f}% faster than Node.js"
        elif ratio < 1.1:
            return f"Acceptable performance - {((ratio-1)*100):.1f}% slower than Node.js"
        else:
            return f"Performance regression - {((ratio-1)*100):.1f}% slower than Node.js"
    
    def get_session_statistics(self, test_name: str, metric_type: str) -> Dict[str, float]:
        """Calculate statistical analysis for session metrics"""
        key = f"{test_name}:{metric_type}"
        values = self.metrics_buffer.get(key, [])
        
        if not values:
            return {}
        
        return {
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0.0,
            'min': min(values),
            'max': max(values),
            'count': len(values),
            'p95': self._percentile(values, 0.95),
            'p99': self._percentile(values, 0.99)
        }
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile value from list of measurements"""
        sorted_values = sorted(values)
        index = int(percentile * len(sorted_values))
        return sorted_values[min(index, len(sorted_values) - 1)]


class ConcurrentLoadTester:
    """
    Concurrent load testing utility providing comprehensive load testing capabilities
    with thread pool management, request distribution, and performance monitoring
    for validating Flask application performance under concurrent user scenarios.
    
    This utility implements concurrent testing as specified in Section 4.7.1 for
    comprehensive load testing and system capacity validation.
    """
    
    def __init__(self, app: Flask, thread_pool_size: int = 50):
        self.app = app
        self.thread_pool_size = thread_pool_size
        self.results = []
        self.errors = []
        self.start_time = None
        self.end_time = None
        
    def execute_concurrent_requests(self, request_func: Callable, 
                                  num_requests: int = 100,
                                  ramp_up_time: float = 0) -> Dict[str, Any]:
        """
        Execute concurrent requests with configurable load patterns
        
        Args:
            request_func: Function that makes a single request
            num_requests: Total number of requests to execute
            ramp_up_time: Time to ramp up to full load (seconds)
            
        Returns:
            Dict containing load test results and performance metrics
        """
        self.results = []
        self.errors = []
        self.start_time = time.time()
        
        # Calculate request scheduling for ramp-up
        if ramp_up_time > 0:
            request_intervals = [
                (i * ramp_up_time) / num_requests for i in range(num_requests)
            ]
        else:
            request_intervals = [0] * num_requests
        
        with ThreadPoolExecutor(max_workers=self.thread_pool_size) as executor:
            # Submit all requests with timing
            futures = []
            for i, delay in enumerate(request_intervals):
                future = executor.submit(self._timed_request, request_func, delay, i)
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    self.results.append(result)
                except Exception as e:
                    self.errors.append({
                        'error': str(e),
                        'traceback': traceback.format_exc(),
                        'timestamp': time.time()
                    })
        
        self.end_time = time.time()
        return self._analyze_load_test_results()
    
    def _timed_request(self, request_func: Callable, delay: float, 
                      request_id: int) -> Dict[str, Any]:
        """Execute single timed request with delay"""
        if delay > 0:
            time.sleep(delay)
        
        start_time = time.time()
        try:
            response = request_func()
            end_time = time.time()
            
            return {
                'request_id': request_id,
                'start_time': start_time,
                'end_time': end_time,
                'duration': end_time - start_time,
                'status_code': getattr(response, 'status_code', 200),
                'success': True,
                'response_size': len(getattr(response, 'data', b''))
            }
        except Exception as e:
            end_time = time.time()
            return {
                'request_id': request_id,
                'start_time': start_time,
                'end_time': end_time,
                'duration': end_time - start_time,
                'success': False,
                'error': str(e)
            }
    
    def _analyze_load_test_results(self) -> Dict[str, Any]:
        """Analyze load test results and generate performance metrics"""
        successful_requests = [r for r in self.results if r.get('success', False)]
        failed_requests = [r for r in self.results if not r.get('success', True)]
        
        if not successful_requests:
            return {
                'total_requests': len(self.results),
                'successful_requests': 0,
                'failed_requests': len(failed_requests),
                'success_rate': 0.0,
                'error': 'All requests failed'
            }
        
        durations = [r['duration'] for r in successful_requests]
        total_duration = self.end_time - self.start_time
        
        return {
            'total_requests': len(self.results),
            'successful_requests': len(successful_requests),
            'failed_requests': len(failed_requests),
            'success_rate': len(successful_requests) / len(self.results),
            'total_duration': total_duration,
            'requests_per_second': len(successful_requests) / total_duration,
            'average_response_time': statistics.mean(durations),
            'median_response_time': statistics.median(durations),
            'min_response_time': min(durations),
            'max_response_time': max(durations),
            'p95_response_time': self._percentile(durations, 0.95),
            'p99_response_time': self._percentile(durations, 0.99),
            'std_dev_response_time': statistics.stdev(durations) if len(durations) > 1 else 0.0,
            'errors': self.errors
        }
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile from duration measurements"""
        sorted_values = sorted(values)
        index = int(percentile * len(sorted_values))
        return sorted_values[min(index, len(sorted_values) - 1)]


class MemoryProfiler:
    """
    Memory profiling utility providing comprehensive memory usage analysis,
    garbage collection monitoring, and memory leak detection for Flask
    application performance validation and optimization.
    
    This profiler implements Python memory monitoring as specified in
    Section 6.5.2.2 for comprehensive memory usage analysis and optimization.
    """
    
    def __init__(self):
        self.snapshots = []
        self.gc_stats = []
        self.peak_memory = 0
        self.baseline_memory = 0
        
    def start_profiling(self):
        """Start memory profiling with tracemalloc integration"""
        tracemalloc.start()
        self.baseline_memory = self._get_current_memory_usage()
        
    def stop_profiling(self) -> Dict[str, Any]:
        """Stop memory profiling and return comprehensive analysis"""
        if not tracemalloc.is_tracing():
            return {'error': 'Memory profiling was not started'}
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        return {
            'current_memory_mb': current / 1024 / 1024,
            'peak_memory_mb': peak / 1024 / 1024,
            'baseline_memory_mb': self.baseline_memory,
            'memory_growth_mb': (current / 1024 / 1024) - self.baseline_memory,
            'gc_collections': self._get_gc_stats(),
            'memory_efficiency': self._calculate_memory_efficiency(current, peak)
        }
    
    def profile_function(self, func: Callable, *args, **kwargs) -> Tuple[Any, Dict[str, Any]]:
        """
        Profile memory usage of a specific function execution
        
        Args:
            func: Function to profile
            *args: Function positional arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Tuple of (function_result, memory_profile)
        """
        self.start_profiling()
        start_memory = self._get_current_memory_usage()
        
        try:
            result = func(*args, **kwargs)
        finally:
            end_memory = self._get_current_memory_usage()
            profile_data = self.stop_profiling()
            profile_data['function_memory_delta'] = end_memory - start_memory
            
        return result, profile_data
    
    def _get_current_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def _get_gc_stats(self) -> Dict[str, int]:
        """Get garbage collection statistics"""
        import gc
        return {
            f'generation_{i}': gc.get_count()[i] 
            for i in range(len(gc.get_count()))
        }
    
    def _calculate_memory_efficiency(self, current: int, peak: int) -> float:
        """Calculate memory efficiency score (0.0 to 1.0)"""
        if peak == 0:
            return 1.0
        return min(1.0, current / peak)


# ================================
# Core Performance Testing Fixtures
# ================================

@pytest.fixture(scope='session')
def performance_app() -> Generator[Flask, None, None]:
    """
    Performance testing Flask application factory fixture providing optimized
    Flask app instance with performance monitoring integration and comprehensive
    configuration for performance testing scenarios.
    
    This fixture implements the Flask application factory pattern as specified
    in Section 5.1.1 with performance monitoring integration and optimization
    for accurate performance measurement and baseline comparison validation.
    
    Yields:
        Flask: Configured Flask application instance optimized for performance testing
    """
    if create_app is None:
        # Create minimal Flask app for performance testing if imports failed
        app = Flask(__name__)
        app.config.from_object(PerformanceTestingConfiguration)
    else:
        # Use actual application factory with performance configuration
        app = create_app('performance')
    
    # Apply performance testing configuration
    app.config.update({
        'TESTING': True,
        'PERFORMANCE_TESTING': True,
        'SECRET_KEY': 'performance-test-secret-key',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///performance_test.db',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'pool_size': 20,
            'max_overflow': 30,
            'pool_pre_ping': True,
            'pool_recycle': 3600,
            'echo': False
        }
    })
    
    # Initialize performance monitoring
    with app.app_context():
        # Configure database for performance testing
        if db is not None:
            db.create_all()
            
        # Set up performance monitoring hooks
        @app.before_request
        def before_request():
            g.start_time = time.time()
            g.request_id = os.urandom(16).hex()
            
        @app.after_request
        def after_request(response):
            if hasattr(g, 'start_time'):
                duration = time.time() - g.start_time
                response.headers['X-Response-Time'] = f"{duration:.3f}s"
                response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
            return response
        
        yield app
        
        # Cleanup after performance testing
        if db is not None:
            db.session.remove()
            db.drop_all()


@pytest.fixture
def performance_client(performance_app: Flask) -> FlaskClient:
    """
    Performance testing client fixture providing optimized Flask test client
    with performance monitoring capabilities and request tracking for
    comprehensive API endpoint performance validation.
    
    Args:
        performance_app: Performance-optimized Flask application instance
        
    Returns:
        FlaskClient: Test client with performance monitoring integration
    """
    return performance_app.test_client()


@pytest.fixture
def performance_metrics_collector() -> PerformanceMetricsCollector:
    """
    Performance metrics collection fixture providing comprehensive metrics
    storage, analysis, and baseline comparison capabilities for performance
    testing validation and regression detection.
    
    Returns:
        PerformanceMetricsCollector: Configured metrics collector with storage
    """
    collector = PerformanceMetricsCollector()
    yield collector
    
    # Cleanup storage after testing if needed
    # Note: Keeping metrics for analysis - remove if not needed
    pass


@pytest.fixture
def benchmark_fixture(benchmark: BenchmarkFixture, 
                     performance_metrics_collector: PerformanceMetricsCollector) -> BenchmarkFixture:
    """
    Enhanced pytest-benchmark fixture with performance metrics collection
    integration, baseline comparison, and comprehensive statistical analysis
    for Flask application performance validation.
    
    This fixture configures pytest-benchmark 5.1.0 with comprehensive settings
    as specified in Section 4.7.1 for statistical performance measurement
    and validation against performance SLA requirements.
    
    Args:
        benchmark: pytest-benchmark fixture
        performance_metrics_collector: Metrics collector for storage and analysis
        
    Returns:
        BenchmarkFixture: Enhanced benchmark fixture with metrics integration
    """
    # Configure benchmark settings for comprehensive testing
    benchmark.pedantic(
        rounds=PerformanceTestingConfiguration.BENCHMARK_MIN_ROUNDS,
        iterations=1,
        warmup_rounds=2
    )
    
    # Store original benchmark function
    original_benchmark = benchmark.__call__
    
    def enhanced_benchmark(func, *args, **kwargs):
        """Enhanced benchmark with metrics collection and analysis"""
        test_name = func.__name__ if hasattr(func, '__name__') else 'unknown_test'
        
        # Execute benchmark with metrics collection
        result = original_benchmark(func, *args, **kwargs)
        
        # Extract performance metrics
        if hasattr(result, 'stats') and result.stats:
            mean_time = result.stats.mean
            
            # Record metrics
            performance_metrics_collector.record_metric(
                test_name=test_name,
                metric_type='response_time',
                value=mean_time,
                unit='seconds',
                metadata={
                    'rounds': result.stats.rounds,
                    'iterations': result.stats.iterations,
                    'min': result.stats.min,
                    'max': result.stats.max,
                    'stddev': result.stats.stddev
                }
            )
            
            # Compare with baseline if available
            comparison = performance_metrics_collector.compare_with_baseline(
                test_name, 'response_time', mean_time
            )
            
            if comparison.get('comparison_available'):
                print(f"\nBaseline Comparison for {test_name}:")
                print(f"  Flask: {mean_time:.3f}s")
                print(f"  Node.js: {comparison['nodejs_value']:.3f}s")
                print(f"  Ratio: {comparison['performance_ratio']:.2f}")
                print(f"  Status: {'PASS' if comparison['passed'] else 'FAIL'}")
                print(f"  Analysis: {comparison['analysis']}")
        
        return result
    
    # Replace benchmark function
    benchmark.__call__ = enhanced_benchmark
    return benchmark


# ================================
# Specialized Performance Testing Fixtures
# ================================

@pytest.fixture
def api_performance_tester(performance_client: FlaskClient,
                          performance_metrics_collector: PerformanceMetricsCollector):
    """
    API performance testing fixture providing comprehensive Flask API endpoint
    performance validation with sub-200ms response time validation and
    statistical analysis capabilities.
    
    This fixture implements API performance testing as specified in Section 4.11.1
    for sub-200ms Flask API response time SLA compliance and comprehensive
    endpoint performance validation.
    
    Args:
        performance_client: Performance-optimized Flask test client
        performance_metrics_collector: Metrics collector for analysis
        
    Returns:
        Dict[str, Callable]: API performance testing utilities
    """
    def test_endpoint_performance(endpoint: str, method: str = 'GET', 
                                 data: Dict = None, headers: Dict = None,
                                 expected_threshold: float = None) -> Dict[str, Any]:
        """
        Test API endpoint performance with comprehensive validation
        
        Args:
            endpoint: API endpoint URL
            method: HTTP method
            data: Request data
            headers: Request headers
            expected_threshold: Expected response time threshold
            
        Returns:
            Dict containing performance test results
        """
        threshold = expected_threshold or PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD
        
        # Execute multiple requests for statistical analysis
        durations = []
        responses = []
        
        for _ in range(10):  # 10 requests for statistical validity
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = performance_client.get(endpoint, headers=headers)
            elif method.upper() == 'POST':
                response = performance_client.post(endpoint, json=data, headers=headers)
            elif method.upper() == 'PUT':
                response = performance_client.put(endpoint, json=data, headers=headers)
            elif method.upper() == 'DELETE':
                response = performance_client.delete(endpoint, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            duration = time.time() - start_time
            durations.append(duration)
            responses.append(response)
        
        # Calculate statistics
        avg_duration = statistics.mean(durations)
        median_duration = statistics.median(durations)
        max_duration = max(durations)
        min_duration = min(durations)
        
        # Record metrics
        test_name = f"api_{method.lower()}_{endpoint.replace('/', '_')}"
        performance_metrics_collector.record_metric(
            test_name=test_name,
            metric_type='response_time',
            value=avg_duration,
            unit='seconds',
            metadata={
                'endpoint': endpoint,
                'method': method,
                'median': median_duration,
                'min': min_duration,
                'max': max_duration,
                'threshold': threshold
            }
        )
        
        # Validate threshold compliance
        threshold_passed = avg_duration <= threshold
        
        return {
            'endpoint': endpoint,
            'method': method,
            'average_duration': avg_duration,
            'median_duration': median_duration,
            'min_duration': min_duration,
            'max_duration': max_duration,
            'threshold': threshold,
            'threshold_passed': threshold_passed,
            'status_codes': [r.status_code for r in responses],
            'all_responses_successful': all(200 <= r.status_code < 300 for r in responses)
        }
    
    def validate_api_sla_compliance(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate API SLA compliance across multiple endpoints"""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['threshold_passed'])
        
        return {
            'total_endpoints_tested': total_tests,
            'endpoints_passed': passed_tests,
            'sla_compliance_rate': passed_tests / total_tests if total_tests > 0 else 0.0,
            'overall_sla_passed': passed_tests == total_tests,
            'failed_endpoints': [
                r['endpoint'] for r in results if not r['threshold_passed']
            ]
        }
    
    return {
        'test_endpoint': test_endpoint_performance,
        'validate_sla': validate_api_sla_compliance
    }


@pytest.fixture
def database_performance_tester(performance_app: Flask,
                               performance_metrics_collector: PerformanceMetricsCollector):
    """
    Database performance testing fixture providing SQLAlchemy query performance
    validation with sub-100ms response time validation and connection pool
    efficiency analysis for comprehensive database performance testing.
    
    This fixture implements database performance testing as specified in
    Section 4.11.1 for sub-100ms SQLAlchemy query response validation and
    comprehensive database operation performance analysis.
    
    Args:
        performance_app: Performance-optimized Flask application
        performance_metrics_collector: Metrics collector for analysis
        
    Returns:
        Dict[str, Callable]: Database performance testing utilities
    """
    def test_query_performance(query_func: Callable, query_name: str,
                             expected_threshold: float = None) -> Dict[str, Any]:
        """
        Test database query performance with comprehensive validation
        
        Args:
            query_func: Function that executes the database query
            query_name: Name of the query for metrics tracking
            expected_threshold: Expected query response time threshold
            
        Returns:
            Dict containing query performance test results
        """
        threshold = expected_threshold or PerformanceTestingConfiguration.DATABASE_QUERY_THRESHOLD
        
        with performance_app.app_context():
            # Execute multiple queries for statistical analysis
            durations = []
            results = []
            
            for _ in range(20):  # 20 queries for statistical validity
                start_time = time.time()
                try:
                    result = query_func()
                    duration = time.time() - start_time
                    durations.append(duration)
                    results.append(result)
                except Exception as e:
                    duration = time.time() - start_time
                    durations.append(duration)
                    results.append({'error': str(e)})
            
            # Calculate statistics
            avg_duration = statistics.mean(durations)
            median_duration = statistics.median(durations)
            
            # Record metrics
            performance_metrics_collector.record_metric(
                test_name=f"database_{query_name}",
                metric_type='query_time',
                value=avg_duration,
                unit='seconds',
                metadata={
                    'query_name': query_name,
                    'median': median_duration,
                    'min': min(durations),
                    'max': max(durations),
                    'threshold': threshold
                }
            )
            
            return {
                'query_name': query_name,
                'average_duration': avg_duration,
                'median_duration': median_duration,
                'threshold': threshold,
                'threshold_passed': avg_duration <= threshold,
                'total_queries': len(durations),
                'successful_queries': len([r for r in results if 'error' not in r])
            }
    
    def test_connection_pool_performance() -> Dict[str, Any]:
        """Test database connection pool performance and efficiency"""
        with performance_app.app_context():
            # Test concurrent database connections
            if db is None:
                return {'error': 'Database not available for testing'}
            
            start_time = time.time()
            
            def execute_simple_query():
                return db.session.execute('SELECT 1').scalar()
            
            # Test connection pool under load
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [
                    executor.submit(execute_simple_query) 
                    for _ in range(100)
                ]
                
                results = []
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.append({'success': True, 'result': result})
                    except Exception as e:
                        results.append({'success': False, 'error': str(e)})
            
            total_duration = time.time() - start_time
            successful_connections = len([r for r in results if r.get('success')])
            
            return {
                'total_connections': len(results),
                'successful_connections': successful_connections,
                'connection_success_rate': successful_connections / len(results),
                'total_duration': total_duration,
                'connections_per_second': len(results) / total_duration,
                'pool_efficiency': successful_connections / len(results)
            }
    
    return {
        'test_query': test_query_performance,
        'test_connection_pool': test_connection_pool_performance
    }


@pytest.fixture
def authentication_performance_tester(performance_client: FlaskClient,
                                     performance_metrics_collector: PerformanceMetricsCollector,
                                     auth_headers: Dict[str, str]):
    """
    Authentication performance testing fixture providing comprehensive Flask
    authentication response time validation with sub-150ms performance targets
    and ItsDangerous session management efficiency analysis.
    
    This fixture implements authentication performance testing as specified in
    Section 4.11.1 for sub-150ms Flask authentication response validation and
    comprehensive security performance analysis.
    
    Args:
        performance_client: Performance-optimized Flask test client
        performance_metrics_collector: Metrics collector for analysis
        auth_headers: Authentication headers for testing
        
    Returns:
        Dict[str, Callable]: Authentication performance testing utilities
    """
    def test_authentication_flow_performance(auth_endpoint: str = '/auth/login',
                                           credentials: Dict = None) -> Dict[str, Any]:
        """
        Test authentication flow performance with comprehensive validation
        
        Args:
            auth_endpoint: Authentication endpoint URL
            credentials: User credentials for authentication
            
        Returns:
            Dict containing authentication performance results
        """
        threshold = PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD
        default_credentials = credentials or {
            'username': 'test_user',
            'password': 'test_password'
        }
        
        # Execute multiple authentication attempts for statistical analysis
        durations = []
        responses = []
        
        for _ in range(15):  # 15 attempts for statistical validity
            start_time = time.time()
            
            response = performance_client.post(
                auth_endpoint, 
                json=default_credentials,
                headers={'Content-Type': 'application/json'}
            )
            
            duration = time.time() - start_time
            durations.append(duration)
            responses.append(response)
        
        # Calculate statistics
        avg_duration = statistics.mean(durations)
        median_duration = statistics.median(durations)
        
        # Record metrics
        performance_metrics_collector.record_metric(
            test_name='authentication_flow',
            metric_type='auth_response_time',
            value=avg_duration,
            unit='seconds',
            metadata={
                'endpoint': auth_endpoint,
                'median': median_duration,
                'min': min(durations),
                'max': max(durations),
                'threshold': threshold
            }
        )
        
        return {
            'auth_endpoint': auth_endpoint,
            'average_duration': avg_duration,
            'median_duration': median_duration,
            'threshold': threshold,
            'threshold_passed': avg_duration <= threshold,
            'successful_authentications': len([r for r in responses if 200 <= r.status_code < 300])
        }
    
    def test_session_management_performance() -> Dict[str, Any]:
        """Test session management and validation performance"""
        threshold = PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD
        
        # Test session validation performance
        durations = []
        
        for _ in range(20):  # 20 session validations
            start_time = time.time()
            
            # Test protected endpoint with authentication
            response = performance_client.get(
                '/api/protected',  # Assuming protected endpoint exists
                headers=auth_headers
            )
            
            duration = time.time() - start_time
            durations.append(duration)
        
        avg_duration = statistics.mean(durations)
        
        # Record metrics
        performance_metrics_collector.record_metric(
            test_name='session_validation',
            metric_type='session_response_time',
            value=avg_duration,
            unit='seconds',
            metadata={
                'median': statistics.median(durations),
                'threshold': threshold
            }
        )
        
        return {
            'average_duration': avg_duration,
            'threshold': threshold,
            'threshold_passed': avg_duration <= threshold,
            'total_validations': len(durations)
        }
    
    return {
        'test_auth_flow': test_authentication_flow_performance,
        'test_session_mgmt': test_session_management_performance
    }


@pytest.fixture
def concurrent_load_tester(performance_app: Flask) -> ConcurrentLoadTester:
    """
    Concurrent load testing fixture providing comprehensive concurrent user
    simulation, thread pool management, and system capacity validation for
    Flask application performance under load scenarios.
    
    This fixture implements concurrent testing as specified in Section 4.7.1
    for comprehensive load testing and concurrent user capacity validation.
    
    Args:
        performance_app: Performance-optimized Flask application
        
    Returns:
        ConcurrentLoadTester: Configured concurrent load testing utility
    """
    return ConcurrentLoadTester(
        app=performance_app,
        thread_pool_size=PerformanceTestingConfiguration.DEFAULT_THREAD_POOL_SIZE
    )


@pytest.fixture
def memory_profiler() -> MemoryProfiler:
    """
    Memory profiling fixture providing comprehensive memory usage analysis,
    garbage collection monitoring, and memory leak detection for Flask
    application memory performance validation.
    
    This fixture implements memory profiling as specified in Section 6.5.1.1
    for comprehensive memory usage analysis and optimization validation.
    
    Returns:
        MemoryProfiler: Configured memory profiling utility
    """
    return MemoryProfiler()


# ================================
# Baseline Comparison and Validation Fixtures
# ================================

@pytest.fixture
def baseline_comparison_validator(performance_metrics_collector: PerformanceMetricsCollector):
    """
    Baseline comparison validation fixture providing comprehensive Node.js
    baseline comparison, migration validation, and performance regression
    detection for ensuring migration success criteria.
    
    This fixture implements baseline comparison as specified in Section 4.7.2
    for migration validation with 100% functional equivalence and performance
    validation requirements.
    
    Args:
        performance_metrics_collector: Metrics collector with baseline data
        
    Returns:
        Dict[str, Callable]: Baseline comparison and validation utilities
    """
    def validate_performance_regression(test_results: List[Dict[str, Any]],
                                      regression_threshold: float = None) -> Dict[str, Any]:
        """
        Validate performance regression against Node.js baseline
        
        Args:
            test_results: List of test results to validate
            regression_threshold: Maximum allowed performance regression
            
        Returns:
            Dict containing regression validation results
        """
        threshold = regression_threshold or PerformanceTestingConfiguration.PERFORMANCE_REGRESSION_THRESHOLD
        
        validation_results = []
        overall_passed = True
        
        for result in test_results:
            test_name = result.get('test_name', 'unknown')
            metric_type = result.get('metric_type', 'response_time')
            flask_value = result.get('value', 0)
            
            comparison = performance_metrics_collector.compare_with_baseline(
                test_name, metric_type, flask_value
            )
            
            if comparison.get('comparison_available'):
                passed = comparison['passed']
                overall_passed &= passed
                
                validation_results.append({
                    'test_name': test_name,
                    'metric_type': metric_type,
                    'flask_value': flask_value,
                    'nodejs_value': comparison['nodejs_value'],
                    'performance_ratio': comparison['performance_ratio'],
                    'improvement_percentage': comparison['improvement_percentage'],
                    'passed': passed,
                    'analysis': comparison['analysis']
                })
        
        return {
            'total_tests': len(validation_results),
            'passed_tests': len([r for r in validation_results if r['passed']]),
            'overall_regression_check_passed': overall_passed,
            'regression_threshold': threshold,
            'detailed_results': validation_results,
            'summary': {
                'average_performance_ratio': statistics.mean([
                    r['performance_ratio'] for r in validation_results
                ]) if validation_results else 0,
                'tests_with_improvement': len([
                    r for r in validation_results if r['performance_ratio'] < 1.0
                ]),
                'tests_with_regression': len([
                    r for r in validation_results if r['performance_ratio'] > (1.0 + threshold)
                ])
            }
        }
    
    def generate_migration_report(validation_results: Dict[str, Any]) -> str:
        """Generate comprehensive migration validation report"""
        report = []
        report.append("=" * 80)
        report.append("FLASK MIGRATION PERFORMANCE VALIDATION REPORT")
        report.append("=" * 80)
        report.append(f"Total Tests: {validation_results['total_tests']}")
        report.append(f"Passed Tests: {validation_results['passed_tests']}")
        report.append(f"Overall Status: {'PASS' if validation_results['overall_regression_check_passed'] else 'FAIL'}")
        report.append(f"Regression Threshold: {validation_results['regression_threshold'] * 100:.1f}%")
        report.append("")
        
        summary = validation_results['summary']
        report.append("SUMMARY STATISTICS:")
        report.append(f"  Average Performance Ratio: {summary['average_performance_ratio']:.3f}")
        report.append(f"  Tests with Performance Improvement: {summary['tests_with_improvement']}")
        report.append(f"  Tests with Performance Regression: {summary['tests_with_regression']}")
        report.append("")
        
        if validation_results['detailed_results']:
            report.append("DETAILED RESULTS:")
            for result in validation_results['detailed_results']:
                status = "PASS" if result['passed'] else "FAIL"
                report.append(f"  [{status}] {result['test_name']}")
                report.append(f"    Flask: {result['flask_value']:.3f}s")
                report.append(f"    Node.js: {result['nodejs_value']:.3f}s") 
                report.append(f"    Ratio: {result['performance_ratio']:.3f}")
                report.append(f"    Analysis: {result['analysis']}")
                report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    return {
        'validate_regression': validate_performance_regression,
        'generate_report': generate_migration_report
    }


# ================================
# Performance Testing Utilities and Helpers
# ================================

@pytest.fixture
def performance_threshold_validator():
    """
    Performance threshold validation fixture providing SLA compliance
    validation utilities for API, database, and authentication performance
    thresholds as specified in Section 4.11.1.
    
    Returns:
        Dict[str, Callable]: Threshold validation utilities
    """
    def validate_api_threshold(duration: float, endpoint: str = None) -> Dict[str, Any]:
        """Validate API response time against SLA threshold"""
        threshold = PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD
        passed = duration <= threshold
        
        return {
            'metric_type': 'api_response_time',
            'duration': duration,
            'threshold': threshold,
            'passed': passed,
            'endpoint': endpoint,
            'margin': threshold - duration if passed else duration - threshold,
            'percentage_of_threshold': (duration / threshold) * 100
        }
    
    def validate_database_threshold(duration: float, query_name: str = None) -> Dict[str, Any]:
        """Validate database query time against SLA threshold"""
        threshold = PerformanceTestingConfiguration.DATABASE_QUERY_THRESHOLD
        passed = duration <= threshold
        
        return {
            'metric_type': 'database_query_time',
            'duration': duration,
            'threshold': threshold,
            'passed': passed,
            'query_name': query_name,
            'margin': threshold - duration if passed else duration - threshold,
            'percentage_of_threshold': (duration / threshold) * 100
        }
    
    def validate_authentication_threshold(duration: float, auth_type: str = None) -> Dict[str, Any]:
        """Validate authentication response time against SLA threshold"""
        threshold = PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD
        passed = duration <= threshold
        
        return {
            'metric_type': 'authentication_response_time',
            'duration': duration,
            'threshold': threshold,
            'passed': passed,
            'auth_type': auth_type,
            'margin': threshold - duration if passed else duration - threshold,
            'percentage_of_threshold': (duration / threshold) * 100
        }
    
    def validate_memory_threshold(memory_mb: float, test_name: str = None) -> Dict[str, Any]:
        """Validate memory usage against threshold"""
        threshold = PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB
        passed = memory_mb <= threshold
        
        return {
            'metric_type': 'memory_usage',
            'memory_mb': memory_mb,
            'threshold': threshold,
            'passed': passed,
            'test_name': test_name,
            'margin': threshold - memory_mb if passed else memory_mb - threshold,
            'percentage_of_threshold': (memory_mb / threshold) * 100
        }
    
    return {
        'validate_api': validate_api_threshold,
        'validate_database': validate_database_threshold,
        'validate_auth': validate_authentication_threshold,
        'validate_memory': validate_memory_threshold
    }


@pytest.fixture
def performance_data_generator():
    """
    Performance test data generation fixture providing utilities for
    creating realistic test data scenarios for performance testing
    and load testing validation.
    
    Returns:
        Dict[str, Callable]: Performance test data generation utilities
    """
    def generate_api_test_data(num_records: int = 100) -> List[Dict[str, Any]]:
        """Generate realistic API test data for performance testing"""
        import uuid
        import random
        from datetime import datetime, timedelta
        
        data = []
        for i in range(num_records):
            record = {
                'id': str(uuid.uuid4()),
                'name': f'Test Record {i}',
                'email': f'test{i}@example.com',
                'created_at': (datetime.utcnow() - timedelta(days=random.randint(0, 365))).isoformat(),
                'status': random.choice(['active', 'inactive', 'pending']),
                'metadata': {
                    'category': random.choice(['A', 'B', 'C']),
                    'priority': random.randint(1, 5),
                    'tags': [f'tag{j}' for j in range(random.randint(1, 5))]
                }
            }
            data.append(record)
        
        return data
    
    def generate_concurrent_user_data(num_users: int = 50) -> List[Dict[str, Any]]:
        """Generate concurrent user simulation data"""
        users = []
        for i in range(num_users):
            user = {
                'user_id': f'user_{i}',
                'username': f'testuser{i}',
                'email': f'user{i}@test.example.com',
                'session_duration': random.randint(60, 3600),  # 1 minute to 1 hour
                'requests_per_session': random.randint(5, 50),
                'think_time': random.uniform(1.0, 5.0)  # Think time between requests
            }
            users.append(user)
        
        return users
    
    def generate_database_test_queries() -> List[Dict[str, Any]]:
        """Generate database test queries for performance validation"""
        queries = [
            {
                'name': 'simple_select',
                'query': 'SELECT COUNT(*) FROM users',
                'expected_threshold': 0.050  # 50ms
            },
            {
                'name': 'join_query',
                'query': 'SELECT u.*, p.* FROM users u LEFT JOIN profiles p ON u.id = p.user_id',
                'expected_threshold': 0.100  # 100ms
            },
            {
                'name': 'complex_aggregation',
                'query': 'SELECT status, COUNT(*), AVG(created_at) FROM users GROUP BY status',
                'expected_threshold': 0.150  # 150ms
            }
        ]
        
        return queries
    
    return {
        'generate_api_data': generate_api_test_data,
        'generate_user_data': generate_concurrent_user_data,
        'generate_db_queries': generate_database_test_queries
    }


# ================================
# Performance Testing Session Management
# ================================

@pytest.fixture(scope='session', autouse=True)
def performance_testing_session():
    """
    Performance testing session management fixture providing session-wide
    setup, monitoring, and cleanup for comprehensive performance testing
    validation across all performance testing scenarios.
    
    This fixture runs automatically for all performance tests to ensure
    consistent testing environment and comprehensive session monitoring.
    """
    print("\n" + "=" * 80)
    print("PERFORMANCE TESTING SESSION STARTED")
    print("=" * 80)
    print(f"pytest-benchmark 5.1.0: Enabled")
    print(f"Flask 3.1.1 Performance Testing: Active")
    print(f"Python 3.13.3 Environment: Optimized")
    print(f"Performance SLA Thresholds:")
    print(f"  API Response Time: {PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD * 1000:.0f}ms")
    print(f"  Database Query Time: {PerformanceTestingConfiguration.DATABASE_QUERY_THRESHOLD * 1000:.0f}ms")
    print(f"  Authentication Time: {PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD * 1000:.0f}ms")
    print(f"  Memory Usage: {PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB:.0f}MB")
    print("=" * 80)
    
    # Initialize session-wide performance monitoring
    session_start_time = time.time()
    initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
    
    yield
    
    # Session cleanup and final reporting
    session_end_time = time.time()
    final_memory = psutil.Process().memory_info().rss / 1024 / 1024
    session_duration = session_end_time - session_start_time
    memory_delta = final_memory - initial_memory
    
    print("\n" + "=" * 80)
    print("PERFORMANCE TESTING SESSION COMPLETED")
    print("=" * 80)
    print(f"Session Duration: {session_duration:.2f} seconds")
    print(f"Initial Memory: {initial_memory:.2f} MB")
    print(f"Final Memory: {final_memory:.2f} MB")
    print(f"Memory Delta: {memory_delta:+.2f} MB")
    print("=" * 80)


# ================================
# Pytest Configuration for Performance Testing
# ================================

def pytest_configure(config):
    """
    pytest configuration hook for performance testing setup and
    custom marker registration for performance test categorization.
    """
    # Add performance testing markers
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )
    config.addinivalue_line(
        "markers", "benchmark: marks tests as benchmark tests requiring pytest-benchmark"
    )
    config.addinivalue_line(
        "markers", "load_test: marks tests as concurrent load tests"
    )
    config.addinivalue_line(
        "markers", "memory_test: marks tests as memory profiling tests"
    )
    config.addinivalue_line(
        "markers", "baseline_comparison: marks tests requiring Node.js baseline comparison"
    )
    config.addinivalue_line(
        "markers", "sla_validation: marks tests validating SLA compliance"
    )


def pytest_collection_modifyitems(config, items):
    """
    pytest collection hook for modifying performance test items and
    adding automatic markers based on test location and naming patterns.
    """
    for item in items:
        # Auto-mark performance tests
        if 'performance' in item.nodeid:
            item.add_marker(pytest.mark.performance)
        
        # Auto-mark benchmark tests
        if 'benchmark' in item.name or 'benchmark' in item.nodeid:
            item.add_marker(pytest.mark.benchmark)
        
        # Auto-mark load tests
        if 'load' in item.name or 'concurrent' in item.name:
            item.add_marker(pytest.mark.load_test)
        
        # Auto-mark memory tests
        if 'memory' in item.name:
            item.add_marker(pytest.mark.memory_test)


# ================================
# Export Performance Testing Utilities
# ================================

__all__ = [
    'PerformanceTestingConfiguration',
    'PerformanceMetricsCollector',
    'ConcurrentLoadTester',
    'MemoryProfiler',
    'performance_app',
    'performance_client',
    'performance_metrics_collector',
    'benchmark_fixture',
    'api_performance_tester',
    'database_performance_tester',
    'authentication_performance_tester',
    'concurrent_load_tester',
    'memory_profiler',
    'baseline_comparison_validator',
    'performance_threshold_validator',
    'performance_data_generator'
]