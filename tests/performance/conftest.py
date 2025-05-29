"""
pytest Performance Testing Configuration

This module provides comprehensive performance testing fixtures and configuration
for pytest-benchmark 5.1.0 integration with Flask 3.1.1 application performance
validation, Node.js baseline comparison, and automated performance regression
detection as specified in Section 4.7.1 of the technical specification.

Key Features:
- pytest-benchmark 5.1.0 configuration for statistical performance measurement
- Flask application factory pattern performance testing fixtures
- Node.js baseline comparison framework for migration validation
- Automated performance regression detection with SLA compliance
- Multi-environment testing orchestration with tox 4.26.0 integration
- Comprehensive performance monitoring for API, database, and authentication

Performance SLA Targets (Section 4.11.1):
- API Response Time: < 200ms
- Database Query Response: < 100ms
- Authentication Response: < 150ms
- Memory Footprint: Equivalent or improved vs Node.js baseline

Dependencies:
- pytest-benchmark 5.1.0: Statistical performance measurement and comparison
- Flask 3.1.1: Application factory pattern and request context management
- Python 3.13.3: Runtime performance optimization and monitoring
- psutil: System resource monitoring and memory profiling
- memory_profiler: Python memory allocation tracking
- threading: Concurrent load testing simulation

Author: DevSecOps Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
pytest-benchmark: 5.1.0
"""

import os
import sys
import json
import time
import uuid
import tempfile
import threading
import statistics
import tracemalloc
from typing import Dict, List, Any, Optional, Callable, Generator, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from unittest.mock import Mock, patch, MagicMock

# Performance testing imports
import pytest
import psutil
import memory_profiler
from pytest_benchmark import BenchmarkFixture
from pytest_benchmark.plugin import BenchmarkSession

# Flask and testing imports
from flask import Flask, request, g, current_app
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy

# Import application components for performance testing
try:
    from app import create_app, create_wsgi_app
    from config import TestingConfig
    from tests.conftest import TestingConfiguration, MockUser, MockAuth0Client
    from src.models import db, User
    from src.services.user_service import UserService
    from src.services.business_entity_service import BusinessEntityService
except ImportError:
    # Handle case where modules don't exist yet during development
    create_app = None
    create_wsgi_app = None
    TestingConfig = None
    TestingConfiguration = None
    MockUser = None
    MockAuth0Client = None
    db = None
    User = None
    UserService = None
    BusinessEntityService = None


class PerformanceTestingConfiguration(TestingConfiguration):
    """
    Enhanced performance testing configuration extending base testing configuration
    with performance-specific settings and optimizations for comprehensive
    benchmark testing and baseline comparison validation.
    
    This configuration ensures optimal performance testing environment with
    minimal overhead while providing accurate performance measurements.
    """
    
    # Performance testing specific configuration
    TESTING = True
    PERFORMANCE_TESTING = True
    SECRET_KEY = 'performance-test-secret-key'
    WTF_CSRF_ENABLED = False
    
    # Database configuration optimized for performance testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,  # Reduced for testing
        'max_overflow': 5,
        'pool_timeout': 30,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'echo': False  # Disable SQL logging for performance
    }
    
    # Flask configuration for performance testing
    JSON_SORT_KEYS = False  # Disable JSON key sorting for performance
    PREFERRED_URL_SCHEME = 'http'
    APPLICATION_ROOT = '/'
    
    # Performance monitoring configuration
    PERFORMANCE_MONITORING_ENABLED = True
    MEMORY_PROFILING_ENABLED = True
    CONCURRENT_LOAD_TESTING_ENABLED = True
    
    # Baseline comparison configuration
    NODE_JS_BASELINE_DATA_PATH = os.getenv(
        'NODE_JS_BASELINE_DATA_PATH',
        'tests/performance/baselines/nodejs_metrics.json'
    )
    PERFORMANCE_BASELINE_STORAGE = os.getenv(
        'PERFORMANCE_BASELINE_STORAGE',
        'tests/performance/baselines/'
    )
    
    # SLA thresholds (Section 4.11.1)
    API_RESPONSE_TIME_THRESHOLD_MS = 200
    DATABASE_QUERY_THRESHOLD_MS = 100
    AUTHENTICATION_THRESHOLD_MS = 150
    MEMORY_FOOTPRINT_THRESHOLD_MB = 256
    CONCURRENT_USERS_THRESHOLD = 100
    
    # pytest-benchmark configuration
    BENCHMARK_MIN_ROUNDS = 5
    BENCHMARK_MIN_TIME = 0.1
    BENCHMARK_MAX_TIME = 30.0
    BENCHMARK_TIMER = 'time.perf_counter'
    BENCHMARK_DISABLE_GC = False  # Keep GC enabled for realistic testing
    BENCHMARK_WARMUP = True
    BENCHMARK_WARMUP_ITERATIONS = 2


class PerformanceMetricsCollector:
    """
    Comprehensive performance metrics collection and analysis system providing
    statistical measurement, baseline comparison, and SLA validation for
    Flask application performance testing scenarios.
    
    This collector implements pytest-benchmark integration with advanced
    statistical analysis and Node.js baseline comparison capabilities.
    """
    
    def __init__(self, baseline_path: str = None):
        self.baseline_path = baseline_path or PerformanceTestingConfiguration.NODE_JS_BASELINE_DATA_PATH
        self.current_metrics = {}
        self.baseline_metrics = {}
        self.performance_violations = []
        self.memory_snapshots = []
        self.load_test_results = []
        
        # Initialize baseline data if available
        self._load_baseline_metrics()
        
        # Initialize memory tracking
        tracemalloc.start()
        
        # Performance tracking state
        self.start_time = None
        self.end_time = None
        self.request_count = 0
        self.error_count = 0
        
    def _load_baseline_metrics(self) -> None:
        """Load Node.js baseline performance metrics for comparison"""
        try:
            if Path(self.baseline_path).exists():
                with open(self.baseline_path, 'r') as f:
                    self.baseline_metrics = json.load(f)
            else:
                # Create default baseline metrics for comparison
                self.baseline_metrics = {
                    'api_response_times': {
                        'mean': 150.0,  # 150ms average
                        'median': 140.0,
                        'p95': 180.0,
                        'p99': 200.0,
                        'min': 50.0,
                        'max': 250.0
                    },
                    'database_query_times': {
                        'mean': 75.0,  # 75ms average
                        'median': 70.0,
                        'p95': 90.0,
                        'p99': 100.0,
                        'min': 10.0,
                        'max': 120.0
                    },
                    'authentication_times': {
                        'mean': 120.0,  # 120ms average
                        'median': 115.0,
                        'p95': 140.0,
                        'p99': 150.0,
                        'min': 80.0,
                        'max': 180.0
                    },
                    'memory_usage': {
                        'rss_mb': 180.0,  # 180MB resident set size
                        'heap_mb': 120.0,  # 120MB heap usage
                        'peak_mb': 220.0   # 220MB peak usage
                    },
                    'concurrent_users': {
                        'max_supported': 100,
                        'avg_response_time': 160.0,
                        'throughput_rps': 250.0
                    }
                }
                
                # Save default baseline for future use
                self._save_baseline_metrics()
                
        except Exception as e:
            print(f"Warning: Could not load baseline metrics: {e}")
            self.baseline_metrics = {}
    
    def _save_baseline_metrics(self) -> None:
        """Save baseline metrics to storage"""
        try:
            baseline_dir = Path(self.baseline_path).parent
            baseline_dir.mkdir(parents=True, exist_ok=True)
            
            with open(self.baseline_path, 'w') as f:
                json.dump(self.baseline_metrics, f, indent=2)
                
        except Exception as e:
            print(f"Warning: Could not save baseline metrics: {e}")
    
    def start_measurement(self) -> None:
        """Start performance measurement session"""
        self.start_time = time.perf_counter()
        self.request_count = 0
        self.error_count = 0
        
        # Take initial memory snapshot
        if tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            self.memory_snapshots.append({
                'timestamp': time.time(),
                'type': 'start',
                'current_mb': current / 1024 / 1024,
                'peak_mb': peak / 1024 / 1024
            })
    
    def end_measurement(self) -> Dict[str, Any]:
        """End performance measurement and return results"""
        self.end_time = time.perf_counter()
        duration = self.end_time - self.start_time if self.start_time else 0
        
        # Take final memory snapshot
        if tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            self.memory_snapshots.append({
                'timestamp': time.time(),
                'type': 'end',
                'current_mb': current / 1024 / 1024,
                'peak_mb': peak / 1024 / 1024
            })
        
        # Calculate performance metrics
        results = {
            'duration_seconds': duration,
            'request_count': self.request_count,
            'error_count': self.error_count,
            'requests_per_second': self.request_count / duration if duration > 0 else 0,
            'error_rate': self.error_count / self.request_count if self.request_count > 0 else 0,
            'memory_snapshots': self.memory_snapshots[-2:] if len(self.memory_snapshots) >= 2 else self.memory_snapshots,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return results
    
    def record_api_request(self, duration_ms: float, status_code: int = 200) -> None:
        """Record API request performance"""
        self.request_count += 1
        if status_code >= 400:
            self.error_count += 1
        
        # Store in current metrics
        if 'api_requests' not in self.current_metrics:
            self.current_metrics['api_requests'] = []
        
        self.current_metrics['api_requests'].append({
            'duration_ms': duration_ms,
            'status_code': status_code,
            'timestamp': time.time()
        })
    
    def record_database_query(self, duration_ms: float, query_type: str = 'SELECT') -> None:
        """Record database query performance"""
        if 'database_queries' not in self.current_metrics:
            self.current_metrics['database_queries'] = []
        
        self.current_metrics['database_queries'].append({
            'duration_ms': duration_ms,
            'query_type': query_type,
            'timestamp': time.time()
        })
    
    def record_authentication_request(self, duration_ms: float, success: bool = True) -> None:
        """Record authentication request performance"""
        if 'authentication_requests' not in self.current_metrics:
            self.current_metrics['authentication_requests'] = []
        
        self.current_metrics['authentication_requests'].append({
            'duration_ms': duration_ms,
            'success': success,
            'timestamp': time.time()
        })
    
    def validate_sla_compliance(self) -> Dict[str, bool]:
        """Validate performance against SLA thresholds"""
        compliance_results = {}
        
        # Validate API response times
        if 'api_requests' in self.current_metrics:
            api_durations = [req['duration_ms'] for req in self.current_metrics['api_requests']]
            if api_durations:
                avg_api_time = statistics.mean(api_durations)
                p95_api_time = statistics.quantiles(api_durations, n=20)[18] if len(api_durations) > 1 else api_durations[0]
                
                compliance_results['api_response_time'] = (
                    avg_api_time <= PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD_MS and
                    p95_api_time <= PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD_MS
                )
        
        # Validate database query times
        if 'database_queries' in self.current_metrics:
            db_durations = [query['duration_ms'] for query in self.current_metrics['database_queries']]
            if db_durations:
                avg_db_time = statistics.mean(db_durations)
                compliance_results['database_query_time'] = (
                    avg_db_time <= PerformanceTestingConfiguration.DATABASE_QUERY_THRESHOLD_MS
                )
        
        # Validate authentication times
        if 'authentication_requests' in self.current_metrics:
            auth_durations = [req['duration_ms'] for req in self.current_metrics['authentication_requests']]
            if auth_durations:
                avg_auth_time = statistics.mean(auth_durations)
                compliance_results['authentication_time'] = (
                    avg_auth_time <= PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD_MS
                )
        
        return compliance_results
    
    def compare_with_baseline(self) -> Dict[str, Any]:
        """Compare current performance with Node.js baseline"""
        comparison_results = {}
        
        # Compare API response times
        if 'api_requests' in self.current_metrics and 'api_response_times' in self.baseline_metrics:
            api_durations = [req['duration_ms'] for req in self.current_metrics['api_requests']]
            if api_durations:
                current_mean = statistics.mean(api_durations)
                baseline_mean = self.baseline_metrics['api_response_times']['mean']
                
                comparison_results['api_response_time'] = {
                    'current_mean': current_mean,
                    'baseline_mean': baseline_mean,
                    'improvement_percent': ((baseline_mean - current_mean) / baseline_mean) * 100,
                    'meets_baseline': current_mean <= baseline_mean
                }
        
        # Compare database query times
        if 'database_queries' in self.current_metrics and 'database_query_times' in self.baseline_metrics:
            db_durations = [query['duration_ms'] for query in self.current_metrics['database_queries']]
            if db_durations:
                current_mean = statistics.mean(db_durations)
                baseline_mean = self.baseline_metrics['database_query_times']['mean']
                
                comparison_results['database_query_time'] = {
                    'current_mean': current_mean,
                    'baseline_mean': baseline_mean,
                    'improvement_percent': ((baseline_mean - current_mean) / baseline_mean) * 100,
                    'meets_baseline': current_mean <= baseline_mean
                }
        
        return comparison_results
    
    def generate_performance_report(self) -> str:
        """Generate comprehensive performance test report"""
        report_lines = [
            "="*80,
            "FLASK PERFORMANCE TEST REPORT",
            f"Generated: {datetime.utcnow().isoformat()}",
            f"Python Version: {sys.version}",
            "="*80,
        ]
        
        # SLA Compliance Section
        sla_compliance = self.validate_sla_compliance()
        report_lines.extend([
            "",
            "SLA COMPLIANCE VALIDATION:",
            "-" * 40
        ])
        
        for metric, compliant in sla_compliance.items():
            status = "✓ PASS" if compliant else "✗ FAIL"
            report_lines.append(f"{metric}: {status}")
        
        # Baseline Comparison Section
        baseline_comparison = self.compare_with_baseline()
        if baseline_comparison:
            report_lines.extend([
                "",
                "BASELINE COMPARISON (vs Node.js):",
                "-" * 40
            ])
            
            for metric, comparison in baseline_comparison.items():
                improvement = comparison.get('improvement_percent', 0)
                sign = "+" if improvement > 0 else ""
                report_lines.append(
                    f"{metric}: {comparison['current_mean']:.2f}ms "
                    f"(baseline: {comparison['baseline_mean']:.2f}ms, "
                    f"{sign}{improvement:.1f}%)"
                )
        
        # Memory Usage Section
        if self.memory_snapshots:
            report_lines.extend([
                "",
                "MEMORY USAGE:",
                "-" * 40
            ])
            
            for snapshot in self.memory_snapshots[-2:]:
                report_lines.append(
                    f"{snapshot['type']}: {snapshot['current_mb']:.2f}MB current, "
                    f"{snapshot['peak_mb']:.2f}MB peak"
                )
        
        report_lines.extend([
            "",
            "="*80
        ])
        
        return "\n".join(report_lines)


class ConcurrentLoadTester:
    """
    Concurrent load testing framework for validating Flask application
    performance under multi-user scenarios and concurrent request processing
    with comprehensive throughput analysis and resource monitoring.
    """
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.results = []
        self.metrics_collector = PerformanceMetricsCollector()
        
    def execute_concurrent_requests(
        self,
        test_function: Callable,
        num_requests: int = 50,
        max_workers: int = None
    ) -> Dict[str, Any]:
        """
        Execute concurrent requests for load testing
        
        Args:
            test_function: Function to execute concurrently
            num_requests: Total number of requests to execute
            max_workers: Maximum concurrent workers
            
        Returns:
            Dictionary containing load test results and metrics
        """
        max_workers = max_workers or self.max_workers
        results = []
        errors = []
        
        start_time = time.perf_counter()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all requests
            futures = [
                executor.submit(self._execute_with_timing, test_function, i)
                for i in range(num_requests)
            ]
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    errors.append(str(e))
        
        end_time = time.perf_counter()
        total_duration = end_time - start_time
        
        # Calculate performance metrics
        successful_results = [r for r in results if r['success']]
        response_times = [r['duration'] for r in successful_results]
        
        load_test_metrics = {
            'total_requests': num_requests,
            'successful_requests': len(successful_results),
            'failed_requests': len(errors),
            'success_rate': len(successful_results) / num_requests,
            'total_duration': total_duration,
            'requests_per_second': num_requests / total_duration,
            'concurrent_workers': max_workers,
            'response_times': {
                'mean': statistics.mean(response_times) if response_times else 0,
                'median': statistics.median(response_times) if response_times else 0,
                'min': min(response_times) if response_times else 0,
                'max': max(response_times) if response_times else 0,
                'p95': statistics.quantiles(response_times, n=20)[18] if len(response_times) > 1 else 0,
                'p99': statistics.quantiles(response_times, n=100)[98] if len(response_times) > 1 else 0
            },
            'errors': errors[:10],  # Keep first 10 errors for analysis
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return load_test_metrics
    
    def _execute_with_timing(self, test_function: Callable, request_id: int) -> Dict[str, Any]:
        """Execute test function with performance timing"""
        start_time = time.perf_counter()
        success = False
        error_message = None
        
        try:
            result = test_function()
            success = True
        except Exception as e:
            error_message = str(e)
        
        end_time = time.perf_counter()
        duration = (end_time - start_time) * 1000  # Convert to milliseconds
        
        return {
            'request_id': request_id,
            'duration': duration,
            'success': success,
            'error': error_message,
            'timestamp': time.time()
        }
    
    def validate_concurrent_performance(
        self,
        load_test_results: Dict[str, Any],
        max_avg_response_time: float = 300.0,
        min_success_rate: float = 0.95,
        min_throughput: float = 50.0
    ) -> Dict[str, bool]:
        """
        Validate concurrent load test performance against thresholds
        
        Args:
            load_test_results: Results from execute_concurrent_requests
            max_avg_response_time: Maximum acceptable average response time (ms)
            min_success_rate: Minimum acceptable success rate (0.0-1.0)
            min_throughput: Minimum acceptable throughput (requests/second)
            
        Returns:
            Dictionary containing validation results
        """
        validation_results = {}
        
        # Validate average response time
        avg_response_time = load_test_results['response_times']['mean']
        validation_results['avg_response_time'] = avg_response_time <= max_avg_response_time
        
        # Validate success rate
        success_rate = load_test_results['success_rate']
        validation_results['success_rate'] = success_rate >= min_success_rate
        
        # Validate throughput
        throughput = load_test_results['requests_per_second']
        validation_results['throughput'] = throughput >= min_throughput
        
        # Overall validation
        validation_results['overall_pass'] = all(validation_results.values())
        
        return validation_results


# ================================
# pytest-benchmark Configuration
# ================================

def pytest_configure(config):
    """
    Configure pytest-benchmark for performance testing
    
    Implements comprehensive pytest-benchmark 5.1.0 configuration with
    statistical measurement, baseline comparison, and automated regression
    detection as specified in Section 4.7.1.
    """
    # Configure benchmark plugin
    config.addinivalue_line(
        "markers", "benchmark: mark test as a benchmark test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "load_test: mark test as a load test"
    )
    config.addinivalue_line(
        "markers", "memory_test: mark test as a memory profiling test"
    )
    config.addinivalue_line(
        "markers", "baseline_comparison: mark test for baseline comparison"
    )
    
    # Set benchmark configuration from environment or defaults
    config.option.benchmark_min_rounds = int(
        os.getenv('BENCHMARK_MIN_ROUNDS', PerformanceTestingConfiguration.BENCHMARK_MIN_ROUNDS)
    )
    config.option.benchmark_min_time = float(
        os.getenv('BENCHMARK_MIN_TIME', PerformanceTestingConfiguration.BENCHMARK_MIN_TIME)
    )
    config.option.benchmark_max_time = float(
        os.getenv('BENCHMARK_MAX_TIME', PerformanceTestingConfiguration.BENCHMARK_MAX_TIME)
    )
    config.option.benchmark_warmup = PerformanceTestingConfiguration.BENCHMARK_WARMUP
    config.option.benchmark_warmup_iterations = PerformanceTestingConfiguration.BENCHMARK_WARMUP_ITERATIONS
    config.option.benchmark_timer = PerformanceTestingConfiguration.BENCHMARK_TIMER
    config.option.benchmark_disable_gc = PerformanceTestingConfiguration.BENCHMARK_DISABLE_GC


def pytest_benchmark_update_machine_info(config, machine_info):
    """
    Update benchmark machine info with additional performance context
    
    Args:
        config: pytest configuration
        machine_info: Machine information dictionary
    """
    # Add Python and Flask version information
    machine_info['python_version'] = sys.version
    machine_info['flask_version'] = '3.1.1'
    machine_info['pytest_benchmark_version'] = '5.1.0'
    
    # Add system performance information
    machine_info['cpu_count'] = psutil.cpu_count()
    machine_info['memory_total_gb'] = psutil.virtual_memory().total / (1024**3)
    
    # Add environment information
    machine_info['testing_environment'] = os.getenv('FLASK_ENV', 'testing')
    machine_info['performance_testing'] = True


# ================================
# Core Performance Testing Fixtures
# ================================

@pytest.fixture(scope='session')
def performance_app() -> Generator[Flask, None, None]:
    """
    Flask application fixture optimized for performance testing
    
    Creates a Flask application instance with performance testing configuration
    and minimal overhead for accurate benchmark measurements per Section 5.1.1.
    
    Yields:
        Flask application instance configured for performance testing
    """
    if create_app is None:
        # Create minimal Flask app if imports failed
        app = Flask(__name__)
        app.config.from_object(PerformanceTestingConfiguration)
    else:
        # Use actual application factory with performance testing configuration
        app = create_app('testing')
        
        # Override with performance testing configuration
        app.config.from_object(PerformanceTestingConfiguration)
    
    # Ensure performance testing configuration is applied
    app.config.update({
        'TESTING': True,
        'PERFORMANCE_TESTING': True,
        'SECRET_KEY': 'performance-test-secret-key',
        'WTF_CSRF_ENABLED': False,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'JSON_SORT_KEYS': False  # Disable for performance
    })
    
    # Create application context for performance testing
    with app.app_context():
        # Initialize database tables if SQLAlchemy is available
        if db is not None:
            db.create_all()
            
        yield app
        
        # Cleanup after performance tests
        if db is not None:
            db.session.remove()
            db.drop_all()


@pytest.fixture
def performance_client(performance_app: Flask) -> FlaskClient:
    """
    Flask test client fixture optimized for performance testing
    
    Provides HTTP request simulation capabilities with minimal overhead
    for accurate API performance measurement and load testing scenarios.
    
    Args:
        performance_app: Flask application from performance_app fixture
        
    Returns:
        FlaskClient: Optimized test client for performance testing
    """
    return performance_app.test_client()


@pytest.fixture
def benchmark_config() -> Dict[str, Any]:
    """
    pytest-benchmark configuration fixture
    
    Provides standardized benchmark configuration for consistent
    performance measurement across all test scenarios.
    
    Returns:
        Dictionary containing benchmark configuration parameters
    """
    return {
        'min_rounds': PerformanceTestingConfiguration.BENCHMARK_MIN_ROUNDS,
        'min_time': PerformanceTestingConfiguration.BENCHMARK_MIN_TIME,
        'max_time': PerformanceTestingConfiguration.BENCHMARK_MAX_TIME,
        'timer': PerformanceTestingConfiguration.BENCHMARK_TIMER,
        'disable_gc': PerformanceTestingConfiguration.BENCHMARK_DISABLE_GC,
        'warmup': PerformanceTestingConfiguration.BENCHMARK_WARMUP,
        'warmup_iterations': PerformanceTestingConfiguration.BENCHMARK_WARMUP_ITERATIONS
    }


@pytest.fixture
def performance_metrics() -> PerformanceMetricsCollector:
    """
    Performance metrics collection fixture
    
    Provides comprehensive performance measurement and analysis capabilities
    with baseline comparison and SLA validation as specified in Section 4.7.2.
    
    Returns:
        PerformanceMetricsCollector: Configured metrics collector
    """
    return PerformanceMetricsCollector()


@pytest.fixture
def load_tester() -> ConcurrentLoadTester:
    """
    Concurrent load testing fixture
    
    Provides concurrent user simulation and load testing capabilities
    for validating Flask application performance under concurrent scenarios.
    
    Returns:
        ConcurrentLoadTester: Configured load testing framework
    """
    return ConcurrentLoadTester()


# ================================
# Database Performance Testing Fixtures
# ================================

@pytest.fixture
def db_performance_session(performance_app: Flask):
    """
    Database session fixture optimized for performance testing
    
    Provides isolated database session with performance monitoring
    for comprehensive database query performance validation per Section 6.2.
    
    Args:
        performance_app: Flask application from performance_app fixture
        
    Yields:
        SQLAlchemy session: Database session with performance monitoring
    """
    if db is None:
        yield None
        return
        
    with performance_app.app_context():
        # Create database tables for performance testing
        db.create_all()
        
        # Configure session with performance monitoring
        connection = db.engine.connect()
        transaction = connection.begin()
        
        # Create scoped session for isolated testing
        session_options = dict(bind=connection, binds={})
        session = db.create_scoped_session(options=session_options)
        
        # Replace default session
        db.session = session
        
        try:
            yield session
        finally:
            # Cleanup after performance testing
            session.remove()
            transaction.rollback()
            connection.close()


@pytest.fixture
def sample_performance_data(db_performance_session):
    """
    Sample data fixture for database performance testing
    
    Provides realistic test data sets for comprehensive database
    performance validation and query optimization testing.
    
    Args:
        db_performance_session: Database session from db_performance_session fixture
        
    Returns:
        Dictionary containing sample data for performance testing
    """
    sample_data = {
        'users': [],
        'business_entities': [],
        'relationships': []
    }
    
    if User is not None and db_performance_session is not None:
        # Create sample users for performance testing
        for i in range(100):  # Create 100 users for realistic testing
            user = User(
                id=str(uuid.uuid4()),
                username=f'perftest_user_{i}',
                email=f'perftest_{i}@performance.test',
                is_active=True,
                created_at=datetime.utcnow()
            )
            sample_data['users'].append(user)
            db_performance_session.add(user)
        
        db_performance_session.commit()
    
    return sample_data


# ================================
# Authentication Performance Testing Fixtures
# ================================

@pytest.fixture
def auth_performance_client(performance_app: Flask):
    """
    Authentication performance testing client fixture
    
    Provides pre-configured authentication testing client with
    performance monitoring for authentication flow validation.
    
    Args:
        performance_app: Flask application from performance_app fixture
        
    Returns:
        Tuple containing FlaskClient and MockAuth0Client for testing
    """
    client = performance_app.test_client()
    
    # Initialize mock Auth0 client for authentication testing
    if MockAuth0Client is not None:
        mock_auth0 = MockAuth0Client()
    else:
        mock_auth0 = Mock()
        mock_auth0.authenticate.return_value = {
            'access_token': 'test_token',
            'user_info': {'sub': 'test_user'}
        }
    
    return client, mock_auth0


@pytest.fixture
def auth_performance_headers(auth_performance_client):
    """
    Authentication headers fixture for performance testing
    
    Provides pre-generated authentication headers for consistent
    API authentication performance testing scenarios.
    
    Args:
        auth_performance_client: Authentication client from auth_performance_client fixture
        
    Returns:
        Dictionary containing authentication headers
    """
    client, mock_auth0 = auth_performance_client
    
    # Generate authentication token
    auth_response = mock_auth0.authenticate('perftest_user', 'test_password')
    
    return {
        'Authorization': f"Bearer {auth_response['access_token']}",
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }


# ================================
# Memory Profiling Fixtures
# ================================

@pytest.fixture
def memory_profiler():
    """
    Memory profiling fixture for Python memory usage analysis
    
    Provides comprehensive memory monitoring and profiling capabilities
    for validating Flask application memory footprint optimization.
    
    Returns:
        Memory profiling utilities and monitoring functions
    """
    
    class MemoryProfiler:
        def __init__(self):
            self.snapshots = []
            self.process = psutil.Process()
            
        def start_profiling(self):
            """Start memory profiling session"""
            if not tracemalloc.is_tracing():
                tracemalloc.start()
            
            # Take initial snapshot
            self.take_snapshot('start')
            
        def take_snapshot(self, label: str = None):
            """Take memory usage snapshot"""
            snapshot = {
                'label': label or f'snapshot_{len(self.snapshots)}',
                'timestamp': time.time(),
                'rss_mb': self.process.memory_info().rss / 1024 / 1024,
                'vms_mb': self.process.memory_info().vms / 1024 / 1024,
                'memory_percent': self.process.memory_percent()
            }
            
            if tracemalloc.is_tracing():
                current, peak = tracemalloc.get_traced_memory()
                snapshot.update({
                    'tracemalloc_current_mb': current / 1024 / 1024,
                    'tracemalloc_peak_mb': peak / 1024 / 1024
                })
            
            self.snapshots.append(snapshot)
            return snapshot
            
        def stop_profiling(self):
            """Stop memory profiling and return results"""
            self.take_snapshot('end')
            
            if tracemalloc.is_tracing():
                tracemalloc.stop()
            
            return self.get_analysis()
            
        def get_analysis(self):
            """Analyze memory usage patterns"""
            if len(self.snapshots) < 2:
                return {'error': 'Insufficient snapshots for analysis'}
            
            start_snapshot = self.snapshots[0]
            end_snapshot = self.snapshots[-1]
            
            analysis = {
                'start_rss_mb': start_snapshot['rss_mb'],
                'end_rss_mb': end_snapshot['rss_mb'],
                'rss_delta_mb': end_snapshot['rss_mb'] - start_snapshot['rss_mb'],
                'peak_rss_mb': max(s['rss_mb'] for s in self.snapshots),
                'avg_memory_percent': statistics.mean(s['memory_percent'] for s in self.snapshots),
                'snapshots': self.snapshots
            }
            
            # Add tracemalloc analysis if available
            if 'tracemalloc_current_mb' in start_snapshot:
                analysis.update({
                    'tracemalloc_delta_mb': (
                        end_snapshot['tracemalloc_current_mb'] - start_snapshot['tracemalloc_current_mb']
                    ),
                    'tracemalloc_peak_mb': max(
                        s.get('tracemalloc_peak_mb', 0) for s in self.snapshots
                    )
                })
            
            return analysis
    
    return MemoryProfiler()


# ================================
# Baseline Comparison Fixtures
# ================================

@pytest.fixture
def baseline_comparison():
    """
    Node.js baseline comparison fixture
    
    Provides comprehensive baseline comparison framework for validating
    Flask performance against Node.js baseline metrics per Section 4.7.2.
    
    Returns:
        Baseline comparison utilities and validation functions
    """
    
    class BaselineComparison:
        def __init__(self):
            self.metrics_collector = PerformanceMetricsCollector()
            
        def compare_api_performance(
            self,
            flask_response_times: List[float],
            metric_name: str = 'api_response_times'
        ) -> Dict[str, Any]:
            """
            Compare Flask API performance with Node.js baseline
            
            Args:
                flask_response_times: List of Flask response times in milliseconds
                metric_name: Baseline metric name for comparison
                
            Returns:
                Dictionary containing comparison results
            """
            if not flask_response_times:
                return {'error': 'No Flask response times provided'}
            
            baseline_metrics = self.metrics_collector.baseline_metrics.get(metric_name, {})
            if not baseline_metrics:
                return {'error': f'No baseline metrics found for {metric_name}'}
            
            # Calculate Flask statistics
            flask_stats = {
                'mean': statistics.mean(flask_response_times),
                'median': statistics.median(flask_response_times),
                'min': min(flask_response_times),
                'max': max(flask_response_times),
                'p95': statistics.quantiles(flask_response_times, n=20)[18] if len(flask_response_times) > 1 else flask_response_times[0],
                'p99': statistics.quantiles(flask_response_times, n=100)[98] if len(flask_response_times) > 1 else flask_response_times[0]
            }
            
            # Calculate improvements
            comparison = {}
            for stat_name, flask_value in flask_stats.items():
                baseline_value = baseline_metrics.get(stat_name, 0)
                if baseline_value > 0:
                    improvement_percent = ((baseline_value - flask_value) / baseline_value) * 100
                    comparison[stat_name] = {
                        'flask': flask_value,
                        'baseline': baseline_value,
                        'improvement_percent': improvement_percent,
                        'better': flask_value <= baseline_value
                    }
            
            # Overall assessment
            comparison['overall_assessment'] = {
                'better_metrics': sum(1 for comp in comparison.values() if isinstance(comp, dict) and comp.get('better', False)),
                'total_metrics': len([comp for comp in comparison.values() if isinstance(comp, dict)]),
                'overall_better': flask_stats['mean'] <= baseline_metrics.get('mean', float('inf'))
            }
            
            return comparison
            
        def validate_migration_success(
            self,
            api_times: List[float] = None,
            db_times: List[float] = None,
            auth_times: List[float] = None
        ) -> Dict[str, Any]:
            """
            Validate migration success against baseline performance
            
            Args:
                api_times: API response times in milliseconds
                db_times: Database query times in milliseconds
                auth_times: Authentication times in milliseconds
                
            Returns:
                Dictionary containing migration validation results
            """
            validation_results = {
                'migration_successful': True,
                'performance_regressions': [],
                'performance_improvements': [],
                'validation_timestamp': datetime.utcnow().isoformat()
            }
            
            # Validate API performance
            if api_times:
                api_comparison = self.compare_api_performance(api_times, 'api_response_times')
                if 'overall_assessment' in api_comparison:
                    if not api_comparison['overall_assessment']['overall_better']:
                        validation_results['migration_successful'] = False
                        validation_results['performance_regressions'].append('API response times')
                    else:
                        validation_results['performance_improvements'].append('API response times')
            
            # Validate database performance
            if db_times:
                db_comparison = self.compare_api_performance(db_times, 'database_query_times')
                if 'overall_assessment' in db_comparison:
                    if not db_comparison['overall_assessment']['overall_better']:
                        validation_results['migration_successful'] = False
                        validation_results['performance_regressions'].append('Database query times')
                    else:
                        validation_results['performance_improvements'].append('Database query times')
            
            # Validate authentication performance
            if auth_times:
                auth_comparison = self.compare_api_performance(auth_times, 'authentication_times')
                if 'overall_assessment' in auth_comparison:
                    if not auth_comparison['overall_assessment']['overall_better']:
                        validation_results['migration_successful'] = False
                        validation_results['performance_regressions'].append('Authentication times')
                    else:
                        validation_results['performance_improvements'].append('Authentication times')
            
            return validation_results
    
    return BaselineComparison()


# ================================
# Utility Fixtures and Helpers
# ================================

@pytest.fixture
def performance_test_data():
    """
    Performance test data generation fixture
    
    Provides utilities for generating realistic test data for
    comprehensive performance testing scenarios.
    
    Returns:
        Dictionary containing test data generation functions
    """
    
    def generate_api_test_data(count: int = 100) -> List[Dict[str, Any]]:
        """Generate realistic API test data"""
        return [
            {
                'id': str(uuid.uuid4()),
                'name': f'Test Entity {i}',
                'description': f'Performance test entity number {i}',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'test_index': i,
                    'performance_test': True,
                    'batch_id': str(uuid.uuid4())
                }
            }
            for i in range(count)
        ]
    
    def generate_user_test_data(count: int = 50) -> List[Dict[str, Any]]:
        """Generate realistic user test data"""
        return [
            {
                'id': str(uuid.uuid4()),
                'username': f'perftest_user_{i}',
                'email': f'perftest_{i}@performance.test',
                'first_name': f'Test{i}',
                'last_name': 'User',
                'is_active': True,
                'created_at': datetime.utcnow().isoformat()
            }
            for i in range(count)
        ]
    
    def generate_query_test_data() -> Dict[str, List[str]]:
        """Generate database query test scenarios"""
        return {
            'select_queries': [
                'SELECT * FROM users WHERE is_active = true',
                'SELECT id, username FROM users ORDER BY created_at DESC LIMIT 10',
                'SELECT COUNT(*) FROM users WHERE created_at > ?'
            ],
            'insert_queries': [
                'INSERT INTO users (id, username, email) VALUES (?, ?, ?)',
                'INSERT INTO business_entities (id, name, type) VALUES (?, ?, ?)'
            ],
            'update_queries': [
                'UPDATE users SET last_login = ? WHERE id = ?',
                'UPDATE business_entities SET updated_at = ? WHERE id = ?'
            ]
        }
    
    return {
        'api_data': generate_api_test_data,
        'user_data': generate_user_test_data,
        'query_data': generate_query_test_data
    }


@pytest.fixture
def sla_validator():
    """
    SLA validation fixture for performance threshold checking
    
    Provides comprehensive SLA validation utilities for ensuring
    performance compliance with specified thresholds per Section 4.11.1.
    
    Returns:
        SLA validation utilities and threshold checking functions
    """
    
    class SLAValidator:
        def __init__(self):
            self.thresholds = {
                'api_response_time_ms': PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD_MS,
                'database_query_time_ms': PerformanceTestingConfiguration.DATABASE_QUERY_THRESHOLD_MS,
                'authentication_time_ms': PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD_MS,
                'memory_footprint_mb': PerformanceTestingConfiguration.MEMORY_FOOTPRINT_THRESHOLD_MB,
                'concurrent_users': PerformanceTestingConfiguration.CONCURRENT_USERS_THRESHOLD
            }
        
        def validate_response_time(self, response_times: List[float], threshold_ms: float = None) -> Dict[str, Any]:
            """Validate response time against SLA threshold"""
            threshold_ms = threshold_ms or self.thresholds['api_response_time_ms']
            
            if not response_times:
                return {'error': 'No response times provided'}
            
            mean_time = statistics.mean(response_times)
            p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) > 1 else response_times[0]
            p99_time = statistics.quantiles(response_times, n=100)[98] if len(response_times) > 1 else response_times[0]
            
            return {
                'mean_compliant': mean_time <= threshold_ms,
                'p95_compliant': p95_time <= threshold_ms,
                'p99_compliant': p99_time <= threshold_ms,
                'overall_compliant': mean_time <= threshold_ms and p95_time <= threshold_ms,
                'metrics': {
                    'mean': mean_time,
                    'p95': p95_time,
                    'p99': p99_time,
                    'threshold': threshold_ms
                },
                'violations': [
                    time for time in response_times if time > threshold_ms
                ]
            }
        
        def validate_concurrent_performance(self, load_test_results: Dict[str, Any]) -> Dict[str, Any]:
            """Validate concurrent load test performance"""
            validation_results = {
                'success_rate_compliant': load_test_results['success_rate'] >= 0.95,
                'response_time_compliant': load_test_results['response_times']['mean'] <= self.thresholds['api_response_time_ms'],
                'throughput_adequate': load_test_results['requests_per_second'] >= 50.0,
                'concurrent_users_supported': load_test_results.get('concurrent_workers', 0) >= 10
            }
            
            validation_results['overall_compliant'] = all(validation_results.values())
            
            return validation_results
        
        def generate_sla_report(self, test_results: Dict[str, Any]) -> str:
            """Generate comprehensive SLA compliance report"""
            report_lines = [
                "="*60,
                "SLA COMPLIANCE REPORT",
                f"Generated: {datetime.utcnow().isoformat()}",
                "="*60,
                ""
            ]
            
            # Process each SLA metric
            for metric, results in test_results.items():
                if isinstance(results, dict) and 'overall_compliant' in results:
                    status = "✓ COMPLIANT" if results['overall_compliant'] else "✗ VIOLATION"
                    report_lines.append(f"{metric.upper()}: {status}")
                    
                    if 'metrics' in results:
                        for key, value in results['metrics'].items():
                            if isinstance(value, float):
                                report_lines.append(f"  {key}: {value:.2f}")
                            else:
                                report_lines.append(f"  {key}: {value}")
                    
                    report_lines.append("")
            
            report_lines.extend([
                "="*60,
                ""
            ])
            
            return "\n".join(report_lines)
    
    return SLAValidator()


# ================================
# Performance Test Session Hooks
# ================================

def pytest_sessionstart(session):
    """
    pytest session start hook for performance testing initialization
    """
    print("\n" + "="*80)
    print("FLASK PERFORMANCE TESTING SESSION STARTED")
    print("="*80)
    print(f"Python Version: {sys.version}")
    print(f"Flask Version: 3.1.1")
    print(f"pytest-benchmark Version: 5.1.0")
    print(f"Performance Testing Configuration: Enabled")
    print(f"Baseline Comparison: Enabled")
    print(f"SLA Validation: Enabled")
    print("="*80)
    print("Performance SLA Thresholds:")
    print(f"  API Response Time: < {PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD_MS}ms")
    print(f"  Database Query Time: < {PerformanceTestingConfiguration.DATABASE_QUERY_THRESHOLD_MS}ms")
    print(f"  Authentication Time: < {PerformanceTestingConfiguration.AUTHENTICATION_THRESHOLD_MS}ms")
    print(f"  Memory Footprint: < {PerformanceTestingConfiguration.MEMORY_FOOTPRINT_THRESHOLD_MB}MB")
    print("="*80)


def pytest_sessionfinish(session, exitstatus):
    """
    pytest session finish hook for performance testing cleanup and reporting
    """
    print("\n" + "="*80)
    print("FLASK PERFORMANCE TESTING SESSION COMPLETED")
    print("="*80)
    print(f"Exit Status: {exitstatus}")
    print(f"Session Duration: {getattr(session, 'duration', 'Unknown')}")
    
    if exitstatus == 0:
        print("✓ All performance tests passed")
    else:
        print("✗ Some performance tests failed - check output for details")
    
    print("="*80)


# ================================
# Export Configuration and Utilities
# ================================

# Export key classes and configurations for use in performance tests
__all__ = [
    'PerformanceTestingConfiguration',
    'PerformanceMetricsCollector', 
    'ConcurrentLoadTester',
    'performance_app',
    'performance_client',
    'benchmark_config',
    'performance_metrics',
    'load_tester',
    'baseline_comparison',
    'memory_profiler',
    'sla_validator',
    'performance_test_data'
]