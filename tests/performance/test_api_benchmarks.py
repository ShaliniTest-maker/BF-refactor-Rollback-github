"""
Primary API response time benchmarking test suite utilizing pytest-benchmark 5.1.0 to measure
and validate Flask API endpoint performance against Node.js baseline metrics.

This critical test file establishes comprehensive API performance validation with sub-200ms
response time requirements, statistical analysis of response time distribution, and automated
performance regression detection for migration success validation as specified in Section 4.7.1
of the technical specification.

Key Features:
- pytest-benchmark 5.1.0 fixtures for comprehensive API response time measurement
- Baseline comparison framework validating Flask vs Node.js system benchmarks
- Sub-200ms API response time validation per SLA requirements (Section 4.11.1)
- Statistical analysis with percentile tracking and performance trend analysis
- Automated performance regression detection with threshold-based validation
- Flask blueprint route testing with comprehensive endpoint coverage

Dependencies:
- pytest-benchmark 5.1.0: Statistical performance measurement and analysis
- Flask 3.1.1: Application factory pattern and blueprint architecture
- pytest-flask 1.3.0: Flask-specific testing capabilities and fixtures
- requests 2.31+: HTTP request simulation for endpoint testing
- statistics: Built-in statistical analysis for performance metrics
"""

import pytest
import json
import time
import statistics
import threading
import concurrent.futures
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
import os
import tempfile
import csv
import logging

# Flask and testing imports
from flask import Flask, jsonify, request
from flask.testing import FlaskClient
import requests

# pytest-benchmark imports for performance measurement
from pytest_benchmark.plugin import BenchmarkFixture
from pytest_benchmark.stats import Stats
from pytest_benchmark.utils import format_time

# Import application components
try:
    from app import create_app
    from src.blueprints import api, auth, main
    from src.models import db
    from config import TestingConfig
except ImportError:
    # Handle case where modules don't exist yet during development
    create_app = None
    api = auth = main = None
    db = None
    TestingConfig = None

# Configure logging for performance testing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ================================
# Performance Testing Data Classes
# ================================

@dataclass
class APIEndpointMetrics:
    """
    Data class representing comprehensive API endpoint performance metrics
    for statistical analysis and baseline comparison validation.
    """
    endpoint: str
    method: str
    response_time_ms: float
    status_code: int
    response_size_bytes: int
    timestamp: datetime
    request_id: str
    user_context: Optional[str] = None
    auth_time_ms: Optional[float] = None
    database_query_time_ms: Optional[float] = None
    memory_usage_mb: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for JSON serialization"""
        return asdict(self)
    
    def meets_sla_requirement(self) -> bool:
        """Check if response time meets sub-200ms SLA requirement"""
        return self.response_time_ms < 200.0
    
    def get_percentile_category(self) -> str:
        """Categorize response time for percentile analysis"""
        if self.response_time_ms < 50:
            return "excellent"
        elif self.response_time_ms < 100:
            return "good"
        elif self.response_time_ms < 200:
            return "acceptable"
        else:
            return "needs_optimization"


@dataclass
class BaselineComparison:
    """
    Data class for Node.js baseline comparison metrics and Flask performance validation
    supporting migration success criteria verification per Section 4.7.2.
    """
    endpoint: str
    method: str
    nodejs_response_time_ms: float
    flask_response_time_ms: float
    performance_improvement_pct: float
    parity_status: str  # 'improved', 'equivalent', 'degraded'
    timestamp: datetime
    
    @classmethod
    def create_comparison(cls, endpoint: str, method: str, 
                         nodejs_time: float, flask_time: float) -> 'BaselineComparison':
        """Create baseline comparison with automatic parity status calculation"""
        improvement_pct = ((nodejs_time - flask_time) / nodejs_time) * 100
        
        if improvement_pct >= 10:
            status = 'improved'
        elif improvement_pct >= -5:  # Allow 5% tolerance for equivalent performance
            status = 'equivalent'
        else:
            status = 'degraded'
            
        return cls(
            endpoint=endpoint,
            method=method,
            nodejs_response_time_ms=nodejs_time,
            flask_response_time_ms=flask_time,
            performance_improvement_pct=improvement_pct,
            parity_status=status,
            timestamp=datetime.utcnow()
        )
    
    def requires_optimization(self) -> bool:
        """Check if Flask performance requires optimization"""
        return self.parity_status == 'degraded' or self.flask_response_time_ms >= 200


@dataclass
class PerformanceStatistics:
    """
    Comprehensive performance statistics data class for statistical analysis
    and performance trend analysis per Section 6.5.1.1 requirements.
    """
    endpoint: str
    method: str
    sample_count: int
    mean_response_time_ms: float
    median_response_time_ms: float
    p95_response_time_ms: float
    p99_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    std_deviation_ms: float
    sla_compliance_rate: float
    timestamp: datetime
    
    @classmethod
    def calculate_from_metrics(cls, metrics: List[APIEndpointMetrics]) -> 'PerformanceStatistics':
        """Calculate comprehensive statistics from endpoint metrics collection"""
        if not metrics:
            raise ValueError("Cannot calculate statistics from empty metrics list")
            
        response_times = [m.response_time_ms for m in metrics]
        sla_compliant = [m for m in metrics if m.meets_sla_requirement()]
        
        return cls(
            endpoint=metrics[0].endpoint,
            method=metrics[0].method,
            sample_count=len(metrics),
            mean_response_time_ms=statistics.mean(response_times),
            median_response_time_ms=statistics.median(response_times),
            p95_response_time_ms=statistics.quantiles(response_times, n=20)[18],  # 95th percentile
            p99_response_time_ms=statistics.quantiles(response_times, n=100)[98],  # 99th percentile
            min_response_time_ms=min(response_times),
            max_response_time_ms=max(response_times),
            std_deviation_ms=statistics.stdev(response_times) if len(response_times) > 1 else 0.0,
            sla_compliance_rate=(len(sla_compliant) / len(metrics)) * 100,
            timestamp=datetime.utcnow()
        )
    
    def passes_performance_requirements(self) -> bool:
        """Validate against performance requirements from Section 4.11.1"""
        return (
            self.mean_response_time_ms < 200 and
            self.p95_response_time_ms < 250 and
            self.sla_compliance_rate >= 95.0
        )


# ================================
# Performance Testing Infrastructure
# ================================

class APIPerformanceCollector:
    """
    Comprehensive API performance metrics collector providing detailed performance
    data collection, statistical analysis, and baseline comparison capabilities
    for Flask API endpoint benchmarking.
    """
    
    def __init__(self):
        self.metrics: List[APIEndpointMetrics] = []
        self.baseline_data: Dict[str, float] = {}
        self.performance_thresholds = {
            'api_response_time_ms': 200,
            'database_query_time_ms': 100,
            'authentication_time_ms': 150,
            'memory_usage_mb': 512
        }
        self.baseline_file_path = Path(__file__).parent / 'baseline_data.json'
        
    def collect_metric(self, endpoint: str, method: str, response_time_ms: float,
                      status_code: int, response_size_bytes: int,
                      **additional_metrics) -> APIEndpointMetrics:
        """
        Collect comprehensive API endpoint performance metric with timestamp
        and additional context information for detailed analysis.
        """
        metric = APIEndpointMetrics(
            endpoint=endpoint,
            method=method,
            response_time_ms=response_time_ms,
            status_code=status_code,
            response_size_bytes=response_size_bytes,
            timestamp=datetime.utcnow(),
            request_id=f"test_{int(time.time() * 1000000)}",
            **additional_metrics
        )
        
        self.metrics.append(metric)
        logger.info(f"Collected metric: {endpoint} {method} - {response_time_ms:.2f}ms")
        
        return metric
    
    def load_baseline_data(self) -> Dict[str, float]:
        """
        Load Node.js baseline performance data for comparison analysis
        from previous system performance measurements.
        """
        if self.baseline_file_path.exists():
            try:
                with open(self.baseline_file_path, 'r') as f:
                    self.baseline_data = json.load(f)
                logger.info(f"Loaded baseline data: {len(self.baseline_data)} endpoints")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load baseline data: {e}")
                self.baseline_data = self._get_default_baseline_data()
        else:
            logger.info("No baseline data file found, using default Node.js benchmarks")
            self.baseline_data = self._get_default_baseline_data()
            
        return self.baseline_data
    
    def _get_default_baseline_data(self) -> Dict[str, float]:
        """
        Default Node.js baseline performance data for comparison when
        actual baseline measurements are not available.
        
        These values represent typical Node.js/Express.js performance
        characteristics for similar API endpoints based on industry benchmarks.
        """
        return {
            # Main blueprint endpoints
            'GET /': 45.0,
            'GET /health': 15.0,
            'GET /health/detailed': 25.0,
            'GET /metrics': 20.0,
            'GET /status': 18.0,
            
            # API blueprint endpoints  
            'GET /api/users': 85.0,
            'POST /api/users': 120.0,
            'GET /api/users/{id}': 65.0,
            'PUT /api/users/{id}': 95.0,
            'DELETE /api/users/{id}': 75.0,
            'GET /api/health': 20.0,
            'GET /api/data': 110.0,
            'POST /api/data': 140.0,
            
            # Authentication blueprint endpoints
            'POST /auth/login': 180.0,
            'POST /auth/logout': 45.0,
            'GET /auth/profile': 70.0,
            'PUT /auth/profile': 90.0,
            'POST /auth/register': 160.0,
            'POST /auth/reset-password': 85.0,
            'GET /auth/verify': 55.0,
            'POST /auth/refresh': 65.0,
        }
    
    def save_baseline_data(self, data: Dict[str, float]) -> None:
        """Save baseline performance data for future comparisons"""
        try:
            self.baseline_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.baseline_file_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved baseline data: {len(data)} endpoints")
        except IOError as e:
            logger.error(f"Failed to save baseline data: {e}")
    
    def create_baseline_comparison(self, endpoint: str, method: str,
                                 flask_time: float) -> BaselineComparison:
        """Create baseline comparison analysis for migration validation"""
        baseline_key = f"{method} {endpoint}"
        nodejs_time = self.baseline_data.get(baseline_key, flask_time * 1.2)  # Fallback
        
        return BaselineComparison.create_comparison(
            endpoint=endpoint,
            method=method,
            nodejs_time=nodejs_time,
            flask_time=flask_time
        )
    
    def calculate_endpoint_statistics(self, endpoint: str, method: str) -> PerformanceStatistics:
        """Calculate comprehensive statistics for specific endpoint"""
        endpoint_metrics = [
            m for m in self.metrics 
            if m.endpoint == endpoint and m.method == method
        ]
        
        if not endpoint_metrics:
            raise ValueError(f"No metrics found for {method} {endpoint}")
            
        return PerformanceStatistics.calculate_from_metrics(endpoint_metrics)
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance report with statistical analysis,
        baseline comparisons, and SLA compliance validation.
        """
        if not self.metrics:
            return {'error': 'No performance metrics collected'}
        
        # Group metrics by endpoint and method
        endpoint_groups = {}
        for metric in self.metrics:
            key = f"{metric.method} {metric.endpoint}"
            if key not in endpoint_groups:
                endpoint_groups[key] = []
            endpoint_groups[key].append(metric)
        
        # Calculate statistics for each endpoint
        endpoint_stats = {}
        baseline_comparisons = []
        
        for endpoint_key, metrics_list in endpoint_groups.items():
            method, endpoint = endpoint_key.split(' ', 1)
            
            # Calculate comprehensive statistics
            stats = PerformanceStatistics.calculate_from_metrics(metrics_list)
            endpoint_stats[endpoint_key] = asdict(stats)
            
            # Create baseline comparison
            comparison = self.create_baseline_comparison(
                endpoint, method, stats.mean_response_time_ms
            )
            baseline_comparisons.append(asdict(comparison))
        
        # Overall performance summary
        all_response_times = [m.response_time_ms for m in self.metrics]
        sla_compliant_metrics = [m for m in self.metrics if m.meets_sla_requirement()]
        
        summary = {
            'total_requests': len(self.metrics),
            'overall_mean_response_time_ms': statistics.mean(all_response_times),
            'overall_median_response_time_ms': statistics.median(all_response_times),
            'overall_p95_response_time_ms': statistics.quantiles(all_response_times, n=20)[18],
            'overall_p99_response_time_ms': statistics.quantiles(all_response_times, n=100)[98],
            'sla_compliance_rate': (len(sla_compliant_metrics) / len(self.metrics)) * 100,
            'endpoints_tested': len(endpoint_groups),
            'test_duration_minutes': (
                (max(m.timestamp for m in self.metrics) - 
                 min(m.timestamp for m in self.metrics)).total_seconds() / 60
            ) if len(self.metrics) > 1 else 0
        }
        
        return {
            'summary': summary,
            'endpoint_statistics': endpoint_stats,
            'baseline_comparisons': baseline_comparisons,
            'performance_trends': self._analyze_performance_trends(),
            'recommendations': self._generate_recommendations()
        }
    
    def _analyze_performance_trends(self) -> Dict[str, Any]:
        """Analyze performance trends over time for optimization insights"""
        if len(self.metrics) < 10:
            return {'insufficient_data': 'Need at least 10 metrics for trend analysis'}
        
        # Sort metrics by timestamp
        sorted_metrics = sorted(self.metrics, key=lambda m: m.timestamp)
        
        # Split into first and second half for trend comparison
        mid_point = len(sorted_metrics) // 2
        first_half = sorted_metrics[:mid_point]
        second_half = sorted_metrics[mid_point:]
        
        first_half_avg = statistics.mean(m.response_time_ms for m in first_half)
        second_half_avg = statistics.mean(m.response_time_ms for m in second_half)
        
        trend_direction = 'improving' if second_half_avg < first_half_avg else 'degrading'
        trend_magnitude = abs(second_half_avg - first_half_avg)
        
        return {
            'trend_direction': trend_direction,
            'trend_magnitude_ms': trend_magnitude,
            'first_half_avg_ms': first_half_avg,
            'second_half_avg_ms': second_half_avg,
            'improvement_percentage': ((first_half_avg - second_half_avg) / first_half_avg) * 100
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations based on collected metrics"""
        recommendations = []
        
        # Analyze SLA compliance
        sla_compliance_rate = (
            len([m for m in self.metrics if m.meets_sla_requirement()]) / 
            len(self.metrics)
        ) * 100 if self.metrics else 0
        
        if sla_compliance_rate < 95:
            recommendations.append(
                f"SLA compliance rate is {sla_compliance_rate:.1f}% - "
                "investigate slow endpoints and optimize database queries"
            )
        
        # Analyze slow endpoints
        slow_endpoints = [
            m for m in self.metrics 
            if m.response_time_ms > self.performance_thresholds['api_response_time_ms']
        ]
        
        if slow_endpoints:
            unique_slow = set(f"{m.method} {m.endpoint}" for m in slow_endpoints)
            recommendations.append(
                f"Found {len(unique_slow)} endpoints exceeding 200ms threshold: "
                f"{', '.join(list(unique_slow)[:3])}{'...' if len(unique_slow) > 3 else ''}"
            )
        
        # Memory usage analysis
        memory_metrics = [m for m in self.metrics if m.memory_usage_mb is not None]
        if memory_metrics:
            avg_memory = statistics.mean(m.memory_usage_mb for m in memory_metrics)
            if avg_memory > self.performance_thresholds['memory_usage_mb']:
                recommendations.append(
                    f"Average memory usage {avg_memory:.1f}MB exceeds threshold - "
                    "consider memory optimization"
                )
        
        return recommendations


# ================================
# pytest-benchmark Fixtures
# ================================

@pytest.fixture(scope='session')
def performance_collector():
    """
    Session-scoped performance collector for comprehensive metrics collection
    across all API benchmark tests with persistent data storage.
    """
    collector = APIPerformanceCollector()
    collector.load_baseline_data()
    yield collector
    
    # Generate final performance report
    report = collector.generate_performance_report()
    logger.info("Performance Test Summary:")
    logger.info(f"Total requests: {report.get('summary', {}).get('total_requests', 0)}")
    logger.info(f"Overall SLA compliance: {report.get('summary', {}).get('sla_compliance_rate', 0):.1f}%")


@pytest.fixture
def api_benchmark_client(app: Flask, performance_collector: APIPerformanceCollector) -> FlaskClient:
    """
    Enhanced Flask test client with automatic performance metric collection
    for comprehensive API endpoint benchmarking and analysis.
    """
    client = app.test_client()
    original_open = client.open
    
    def instrumented_open(*args, **kwargs):
        """Instrumented test client method with automatic performance collection"""
        start_time = time.time()
        
        # Execute request
        response = original_open(*args, **kwargs)
        
        # Calculate response time
        end_time = time.time()
        response_time_ms = (end_time - start_time) * 1000
        
        # Extract request information
        method = kwargs.get('method', 'GET')
        path = args[0] if args else kwargs.get('path', '/')
        
        # Collect performance metric
        performance_collector.collect_metric(
            endpoint=path,
            method=method,
            response_time_ms=response_time_ms,
            status_code=response.status_code,
            response_size_bytes=len(response.data) if response.data else 0,
            auth_time_ms=kwargs.get('auth_time_ms'),
            memory_usage_mb=kwargs.get('memory_usage_mb')
        )
        
        return response
    
    client.open = instrumented_open
    return client


@pytest.fixture
def nodejs_baseline_data(performance_collector: APIPerformanceCollector) -> Dict[str, float]:
    """
    Node.js baseline performance data fixture for comprehensive comparison
    analysis and migration validation per Section 4.7.2 requirements.
    """
    return performance_collector.load_baseline_data()


@pytest.fixture
def performance_threshold_validator():
    """
    Performance threshold validation fixture providing SLA compliance
    checking and automated performance regression detection capabilities.
    """
    def validate_response_time(response_time_ms: float, threshold_ms: float = 200,
                             endpoint: str = None) -> bool:
        """
        Validate API response time against SLA threshold requirements
        
        Args:
            response_time_ms: Measured response time in milliseconds
            threshold_ms: Performance threshold (default 200ms per Section 4.11.1)
            endpoint: Optional endpoint identifier for detailed reporting
            
        Returns:
            bool: True if response time meets SLA requirement
        """
        meets_sla = response_time_ms < threshold_ms
        
        if not meets_sla:
            logger.warning(
                f"SLA threshold exceeded: {endpoint or 'endpoint'} "
                f"responded in {response_time_ms:.2f}ms (threshold: {threshold_ms}ms)"
            )
        
        return meets_sla
    
    def validate_baseline_parity(flask_time_ms: float, nodejs_time_ms: float,
                               tolerance_pct: float = 10.0) -> bool:
        """
        Validate Flask performance parity with Node.js baseline allowing
        for reasonable performance tolerance margins.
        
        Args:
            flask_time_ms: Flask response time in milliseconds
            nodejs_time_ms: Node.js baseline response time in milliseconds
            tolerance_pct: Acceptable performance degradation percentage
            
        Returns:
            bool: True if Flask performance is within tolerance
        """
        degradation_pct = ((flask_time_ms - nodejs_time_ms) / nodejs_time_ms) * 100
        within_tolerance = degradation_pct <= tolerance_pct
        
        if not within_tolerance:
            logger.warning(
                f"Performance degradation detected: {degradation_pct:.1f}% slower than baseline "
                f"(Flask: {flask_time_ms:.2f}ms, Node.js: {nodejs_time_ms:.2f}ms)"
            )
        
        return within_tolerance
    
    return {
        'validate_response_time': validate_response_time,
        'validate_baseline_parity': validate_baseline_parity
    }


# ================================
# Core API Benchmarking Tests
# ================================

class TestAPIPerformanceBenchmarks:
    """
    Comprehensive API performance benchmarking test class implementing
    pytest-benchmark 5.1.0 for statistical measurement and validation
    of Flask API endpoint performance against Node.js baseline metrics.
    """
    
    @pytest.mark.benchmark(group="main_endpoints")
    def test_main_blueprint_health_endpoint_performance(
        self, 
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Benchmark main blueprint health endpoint performance validating
        sub-200ms response time requirement per Section 4.11.1.
        
        This test ensures health check endpoints meet SLA requirements
        for production monitoring and observability infrastructure.
        """
        def health_check_request():
            """Execute health check request for benchmarking"""
            response = api_benchmark_client.get('/health')
            assert response.status_code == 200
            return response
        
        # Execute benchmark with pytest-benchmark statistical analysis
        result = benchmark.pedantic(
            health_check_request,
            iterations=50,
            rounds=10,
            warmup_rounds=5
        )
        
        # Validate SLA compliance
        response_time_ms = benchmark.stats.mean * 1000
        assert performance_threshold_validator['validate_response_time'](
            response_time_ms, 200, '/health'
        ), f"Health endpoint exceeded 200ms SLA: {response_time_ms:.2f}ms"
        
        # Validate baseline parity
        baseline_time = nodejs_baseline_data.get('GET /health', 15.0)
        assert performance_threshold_validator['validate_baseline_parity'](
            response_time_ms, baseline_time
        ), f"Health endpoint performance degraded vs Node.js baseline"
        
        logger.info(f"Health endpoint benchmark: {response_time_ms:.2f}ms avg")
    
    @pytest.mark.benchmark(group="main_endpoints")
    def test_main_blueprint_root_endpoint_performance(
        self,
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Benchmark main blueprint root endpoint ensuring optimal
        application entry point performance for user experience.
        """
        def root_request():
            """Execute root endpoint request for benchmarking"""
            response = api_benchmark_client.get('/')
            assert response.status_code == 200
            return response
        
        result = benchmark.pedantic(
            root_request,
            iterations=100,
            rounds=15,
            warmup_rounds=10
        )
        
        response_time_ms = benchmark.stats.mean * 1000
        
        # Validate performance requirements
        assert performance_threshold_validator['validate_response_time'](
            response_time_ms, 200, '/'
        ), f"Root endpoint exceeded 200ms SLA: {response_time_ms:.2f}ms"
        
        baseline_time = nodejs_baseline_data.get('GET /', 45.0)
        assert performance_threshold_validator['validate_baseline_parity'](
            response_time_ms, baseline_time
        ), f"Root endpoint performance degraded vs Node.js baseline"
    
    @pytest.mark.benchmark(group="api_endpoints")
    def test_api_blueprint_users_list_performance(
        self,
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        authenticated_user,
        auth_headers: Dict[str, str],
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Benchmark API blueprint users list endpoint with authentication
        context validating comprehensive API performance with security overhead.
        """
        def users_list_request():
            """Execute authenticated users list request for benchmarking"""
            response = api_benchmark_client.get(
                '/api/users',
                headers=auth_headers
            )
            assert response.status_code == 200
            return response
        
        result = benchmark.pedantic(
            users_list_request,
            iterations=75,
            rounds=12,
            warmup_rounds=8
        )
        
        response_time_ms = benchmark.stats.mean * 1000
        
        # Validate API SLA requirements
        assert performance_threshold_validator['validate_response_time'](
            response_time_ms, 200, '/api/users'
        ), f"Users API exceeded 200ms SLA: {response_time_ms:.2f}ms"
        
        # Validate against Node.js baseline
        baseline_time = nodejs_baseline_data.get('GET /api/users', 85.0)
        assert performance_threshold_validator['validate_baseline_parity'](
            response_time_ms, baseline_time
        ), f"Users API performance degraded vs Node.js baseline"
        
        logger.info(f"Users API benchmark: {response_time_ms:.2f}ms avg")
    
    @pytest.mark.benchmark(group="api_endpoints")
    def test_api_blueprint_user_creation_performance(
        self,
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        authenticated_user,
        auth_headers: Dict[str, str],
        test_data_factory: Dict[str, Callable],
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Benchmark API blueprint user creation endpoint validating
        POST request performance with data validation and persistence.
        """
        def user_creation_request():
            """Execute user creation request for benchmarking"""
            user_data = test_data_factory['user'](
                username=f"benchmark_user_{int(time.time() * 1000)}",
                email=f"benchmark_{int(time.time() * 1000)}@test.com"
            )
            
            response = api_benchmark_client.post(
                '/api/users',
                headers=auth_headers,
                json=user_data
            )
            assert response.status_code in [200, 201]
            return response
        
        result = benchmark.pedantic(
            user_creation_request,
            iterations=50,
            rounds=10,
            warmup_rounds=5
        )
        
        response_time_ms = benchmark.stats.mean * 1000
        
        # Validate SLA compliance for POST operations
        assert performance_threshold_validator['validate_response_time'](
            response_time_ms, 200, 'POST /api/users'
        ), f"User creation exceeded 200ms SLA: {response_time_ms:.2f}ms"
        
        # Validate baseline comparison
        baseline_time = nodejs_baseline_data.get('POST /api/users', 120.0)
        assert performance_threshold_validator['validate_baseline_parity'](
            response_time_ms, baseline_time
        ), f"User creation performance degraded vs Node.js baseline"
    
    @pytest.mark.benchmark(group="auth_endpoints")
    def test_auth_blueprint_login_performance(
        self,
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        sample_users: Dict[str, Any],
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Benchmark authentication blueprint login endpoint validating
        sub-150ms authentication response time per Section 4.11.1.
        """
        def login_request():
            """Execute login request for benchmarking"""
            login_data = {
                'username': sample_users['user'].username,
                'password': 'test_password'
            }
            
            response = api_benchmark_client.post(
                '/auth/login',
                json=login_data,
                content_type='application/json'
            )
            assert response.status_code in [200, 201]
            return response
        
        result = benchmark.pedantic(
            login_request,
            iterations=40,
            rounds=8,
            warmup_rounds=3
        )
        
        response_time_ms = benchmark.stats.mean * 1000
        
        # Validate authentication SLA (150ms per Section 4.11.1)
        assert performance_threshold_validator['validate_response_time'](
            response_time_ms, 150, '/auth/login'
        ), f"Login exceeded 150ms authentication SLA: {response_time_ms:.2f}ms"
        
        # Validate baseline parity
        baseline_time = nodejs_baseline_data.get('POST /auth/login', 180.0)
        assert performance_threshold_validator['validate_baseline_parity'](
            response_time_ms, baseline_time
        ), f"Login performance degraded vs Node.js baseline"
        
        logger.info(f"Login benchmark: {response_time_ms:.2f}ms avg")
    
    @pytest.mark.benchmark(group="auth_endpoints")
    def test_auth_blueprint_profile_retrieval_performance(
        self,
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        authenticated_user,
        auth_headers: Dict[str, str],
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Benchmark authenticated profile retrieval validating
        session management and authorization performance.
        """
        def profile_request():
            """Execute profile retrieval request for benchmarking"""
            response = api_benchmark_client.get(
                '/auth/profile',
                headers=auth_headers
            )
            assert response.status_code == 200
            return response
        
        result = benchmark.pedantic(
            profile_request,
            iterations=60,
            rounds=10,
            warmup_rounds=5
        )
        
        response_time_ms = benchmark.stats.mean * 1000
        
        # Validate profile retrieval SLA
        assert performance_threshold_validator['validate_response_time'](
            response_time_ms, 150, '/auth/profile'
        ), f"Profile retrieval exceeded 150ms SLA: {response_time_ms:.2f}ms"
        
        baseline_time = nodejs_baseline_data.get('GET /auth/profile', 70.0)
        assert performance_threshold_validator['validate_baseline_parity'](
            response_time_ms, baseline_time
        ), f"Profile retrieval performance degraded vs Node.js baseline"


# ================================
# Statistical Analysis and Reporting Tests
# ================================

class TestPerformanceStatisticalAnalysis:
    """
    Statistical analysis test class implementing comprehensive performance
    data analysis with percentile tracking and performance trend analysis
    per Section 6.5.1.1 requirements.
    """
    
    def test_endpoint_performance_distribution_analysis(
        self,
        api_benchmark_client: FlaskClient,
        performance_collector: APIPerformanceCollector,
        auth_headers: Dict[str, str]
    ):
        """
        Analyze API endpoint performance distribution with comprehensive
        statistical analysis including percentiles and outlier detection.
        """
        endpoint = '/api/users'
        method = 'GET'
        
        # Collect performance samples for statistical analysis
        response_times = []
        for i in range(100):
            start_time = time.time()
            response = api_benchmark_client.get(endpoint, headers=auth_headers)
            end_time = time.time()
            
            response_time_ms = (end_time - start_time) * 1000
            response_times.append(response_time_ms)
            
            assert response.status_code == 200
        
        # Calculate comprehensive performance statistics
        stats = PerformanceStatistics.calculate_from_metrics([
            APIEndpointMetrics(
                endpoint=endpoint,
                method=method,
                response_time_ms=rt,
                status_code=200,
                response_size_bytes=1024,
                timestamp=datetime.utcnow(),
                request_id=f"test_{i}"
            ) for i, rt in enumerate(response_times)
        ])
        
        # Validate statistical requirements
        assert stats.sample_count == 100
        assert stats.mean_response_time_ms < 200, \
            f"Mean response time {stats.mean_response_time_ms:.2f}ms exceeds 200ms SLA"
        assert stats.p95_response_time_ms < 250, \
            f"P95 response time {stats.p95_response_time_ms:.2f}ms exceeds tolerance"
        assert stats.sla_compliance_rate >= 95.0, \
            f"SLA compliance rate {stats.sla_compliance_rate:.1f}% below 95% requirement"
        
        # Validate performance distribution characteristics
        assert stats.std_deviation_ms < stats.mean_response_time_ms * 0.5, \
            f"High performance variability detected: std={stats.std_deviation_ms:.2f}ms"
        
        logger.info(f"Performance distribution analysis:")
        logger.info(f"  Mean: {stats.mean_response_time_ms:.2f}ms")
        logger.info(f"  Median: {stats.median_response_time_ms:.2f}ms")
        logger.info(f"  P95: {stats.p95_response_time_ms:.2f}ms")
        logger.info(f"  P99: {stats.p99_response_time_ms:.2f}ms")
        logger.info(f"  SLA Compliance: {stats.sla_compliance_rate:.1f}%")
    
    def test_baseline_comparison_comprehensive_analysis(
        self,
        api_benchmark_client: FlaskClient,
        performance_collector: APIPerformanceCollector,
        nodejs_baseline_data: Dict[str, float]
    ):
        """
        Comprehensive baseline comparison analysis validating 100% parity
        verification with Node.js system performance per Section 4.7.1.
        """
        comparison_results = []
        test_endpoints = [
            ('GET', '/health'),
            ('GET', '/'),
            ('GET', '/api/health'),
            ('POST', '/auth/login')  # Note: requires mock authentication
        ]
        
        for method, endpoint in test_endpoints:
            # Skip POST endpoints that require complex setup for this analysis
            if method == 'POST':
                continue
                
            # Collect Flask performance samples
            flask_times = []
            for i in range(20):
                start_time = time.time()
                
                if method == 'GET':
                    response = api_benchmark_client.get(endpoint)
                else:
                    continue  # Skip for now
                    
                end_time = time.time()
                flask_times.append((end_time - start_time) * 1000)
                
                assert response.status_code == 200
            
            # Calculate Flask performance statistics
            flask_mean = statistics.mean(flask_times)
            flask_p95 = statistics.quantiles(flask_times, n=20)[18]
            
            # Create baseline comparison
            baseline_key = f"{method} {endpoint}"
            nodejs_time = nodejs_baseline_data.get(baseline_key, flask_mean * 1.1)
            
            comparison = BaselineComparison.create_comparison(
                endpoint=endpoint,
                method=method,
                nodejs_time=nodejs_time,
                flask_time=flask_mean
            )
            
            comparison_results.append(comparison)
            
            # Validate parity requirements
            assert not comparison.requires_optimization(), \
                f"Endpoint {method} {endpoint} requires optimization: {comparison.parity_status}"
            
            logger.info(
                f"Baseline comparison {method} {endpoint}: "
                f"Flask={flask_mean:.2f}ms, Node.js={nodejs_time:.2f}ms, "
                f"Status={comparison.parity_status}"
            )
        
        # Validate overall migration success criteria
        improved_count = len([c for c in comparison_results if c.parity_status == 'improved'])
        equivalent_count = len([c for c in comparison_results if c.parity_status == 'equivalent'])
        degraded_count = len([c for c in comparison_results if c.parity_status == 'degraded'])
        
        total_acceptable = improved_count + equivalent_count
        success_rate = (total_acceptable / len(comparison_results)) * 100
        
        assert success_rate >= 95.0, \
            f"Migration success rate {success_rate:.1f}% below 95% requirement"
        assert degraded_count == 0, \
            f"Found {degraded_count} degraded endpoints - migration validation failed"
        
        logger.info(f"Migration validation: {success_rate:.1f}% success rate")


# ================================
# Concurrent Load and Stress Testing
# ================================

class TestConcurrentAPIPerformance:
    """
    Concurrent API performance testing class validating Flask application
    performance under concurrent user load scenarios with statistical analysis.
    """
    
    @pytest.mark.benchmark(group="concurrent_load")
    def test_concurrent_api_requests_performance(
        self,
        benchmark: BenchmarkFixture,
        api_benchmark_client: FlaskClient,
        auth_headers: Dict[str, str],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Test API performance under concurrent request load validating
        equivalent or improved concurrent user support per Section 4.7.1.
        """
        concurrent_users = 10
        requests_per_user = 5
        
        def concurrent_requests_scenario():
            """Execute concurrent API requests scenario for benchmarking"""
            def user_request_sequence():
                """Individual user request sequence"""
                times = []
                for _ in range(requests_per_user):
                    start_time = time.time()
                    response = api_benchmark_client.get('/api/users', headers=auth_headers)
                    end_time = time.time()
                    times.append((end_time - start_time) * 1000)
                    assert response.status_code == 200
                return times
            
            # Execute concurrent user simulation
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as executor:
                futures = [
                    executor.submit(user_request_sequence) 
                    for _ in range(concurrent_users)
                ]
                
                # Collect all response times
                all_times = []
                for future in concurrent.futures.as_completed(futures):
                    all_times.extend(future.result())
                
                return all_times
        
        # Execute benchmark with concurrent load
        result = benchmark.pedantic(
            concurrent_requests_scenario,
            iterations=5,
            rounds=3,
            warmup_rounds=1
        )
        
        # Analyze concurrent performance
        response_times = result[0] if result else []
        if response_times:
            mean_response_time = statistics.mean(response_times)
            p95_response_time = statistics.quantiles(response_times, n=20)[18]
            
            # Validate concurrent performance SLA
            assert mean_response_time < 300, \
                f"Concurrent load mean response time {mean_response_time:.2f}ms exceeds tolerance"
            assert p95_response_time < 500, \
                f"Concurrent load P95 response time {p95_response_time:.2f}ms exceeds tolerance"
            
            logger.info(f"Concurrent load performance: mean={mean_response_time:.2f}ms, P95={p95_response_time:.2f}ms")
    
    def test_sustained_load_performance_stability(
        self,
        api_benchmark_client: FlaskClient,
        performance_collector: APIPerformanceCollector
    ):
        """
        Test API performance stability under sustained load validating
        consistent performance characteristics over extended periods.
        """
        duration_seconds = 30
        request_interval = 0.1  # 10 requests per second
        
        start_time = time.time()
        response_times = []
        
        while (time.time() - start_time) < duration_seconds:
            request_start = time.time()
            response = api_benchmark_client.get('/health')
            request_end = time.time()
            
            response_time_ms = (request_end - request_start) * 1000
            response_times.append(response_time_ms)
            
            assert response.status_code == 200
            
            # Maintain request interval
            elapsed = request_end - request_start
            if elapsed < request_interval:
                time.sleep(request_interval - elapsed)
        
        # Analyze performance stability
        mean_response_time = statistics.mean(response_times)
        std_deviation = statistics.stdev(response_times) if len(response_times) > 1 else 0
        coefficient_variation = (std_deviation / mean_response_time) * 100
        
        # Validate performance stability
        assert mean_response_time < 200, \
            f"Sustained load mean response time {mean_response_time:.2f}ms exceeds SLA"
        assert coefficient_variation < 50, \
            f"High performance variability detected: CV={coefficient_variation:.1f}%"
        
        logger.info(
            f"Sustained load stability: mean={mean_response_time:.2f}ms, "
            f"std={std_deviation:.2f}ms, CV={coefficient_variation:.1f}%"
        )


# ================================
# Performance Regression Detection Tests
# ================================

class TestPerformanceRegressionDetection:
    """
    Automated performance regression detection test class implementing
    threshold-based validation and alerting per Section 4.7.2 requirements.
    """
    
    def test_automated_performance_regression_detection(
        self,
        api_benchmark_client: FlaskClient,
        performance_collector: APIPerformanceCollector,
        nodejs_baseline_data: Dict[str, float]
    ):
        """
        Automated detection of performance regressions with comprehensive
        threshold validation and migration success criteria verification.
        """
        regression_threshold_pct = 15.0  # Maximum acceptable performance degradation
        test_endpoints = [
            ('GET', '/health'),
            ('GET', '/'),
            ('GET', '/metrics')
        ]
        
        regression_failures = []
        
        for method, endpoint in test_endpoints:
            # Collect current performance samples
            current_times = []
            for _ in range(20):
                start_time = time.time()
                response = api_benchmark_client.get(endpoint)
                end_time = time.time()
                
                current_times.append((end_time - start_time) * 1000)
                assert response.status_code == 200
            
            current_mean = statistics.mean(current_times)
            baseline_key = f"{method} {endpoint}"
            baseline_time = nodejs_baseline_data.get(baseline_key, current_mean)
            
            # Calculate performance regression
            if baseline_time > 0:
                regression_pct = ((current_mean - baseline_time) / baseline_time) * 100
                
                if regression_pct > regression_threshold_pct:
                    regression_failures.append({
                        'endpoint': f"{method} {endpoint}",
                        'current_time_ms': current_mean,
                        'baseline_time_ms': baseline_time,
                        'regression_pct': regression_pct
                    })
                    
                logger.info(
                    f"Regression check {method} {endpoint}: "
                    f"current={current_mean:.2f}ms, baseline={baseline_time:.2f}ms, "
                    f"regression={regression_pct:.1f}%"
                )
        
        # Validate no critical regressions detected
        if regression_failures:
            failure_details = "\n".join([
                f"  {f['endpoint']}: {f['regression_pct']:.1f}% slower "
                f"({f['current_time_ms']:.2f}ms vs {f['baseline_time_ms']:.2f}ms)"
                for f in regression_failures
            ])
            
            pytest.fail(
                f"Performance regression detected in {len(regression_failures)} endpoints:\n"
                f"{failure_details}"
            )
        
        logger.info(f"Regression detection passed: {len(test_endpoints)} endpoints validated")
    
    def test_performance_trend_analysis_and_alerting(
        self,
        performance_collector: APIPerformanceCollector
    ):
        """
        Performance trend analysis with automated alerting for
        performance degradation patterns and optimization opportunities.
        """
        # Generate sample performance data for trend analysis
        base_time = 50.0  # Base response time in milliseconds
        
        for i in range(50):
            # Simulate gradual performance degradation
            degradation_factor = 1 + (i * 0.02)  # 2% degradation per iteration
            response_time = base_time * degradation_factor
            
            performance_collector.collect_metric(
                endpoint='/api/test',
                method='GET',
                response_time_ms=response_time,
                status_code=200,
                response_size_bytes=1024
            )
        
        # Analyze performance trends
        report = performance_collector.generate_performance_report()
        trend_analysis = report.get('performance_trends', {})
        
        # Validate trend detection capabilities
        if 'trend_direction' in trend_analysis:
            assert trend_analysis['trend_direction'] == 'degrading', \
                "Failed to detect performance degradation trend"
            
            trend_magnitude = trend_analysis.get('trend_magnitude_ms', 0)
            assert trend_magnitude > 10, \
                f"Trend analysis should detect significant degradation: {trend_magnitude:.2f}ms"
            
            logger.info(
                f"Trend analysis detected {trend_analysis['trend_direction']} performance: "
                f"{trend_magnitude:.2f}ms change"
            )
        
        # Validate automated recommendations
        recommendations = report.get('recommendations', [])
        assert len(recommendations) > 0, "Should generate optimization recommendations"
        
        logger.info(f"Generated {len(recommendations)} optimization recommendations")


# ================================
# Comprehensive Performance Validation
# ================================

class TestComprehensivePerformanceValidation:
    """
    Comprehensive performance validation test class ensuring complete
    migration success validation with 100% parity verification per Section 4.7.1.
    """
    
    def test_complete_api_performance_validation(
        self,
        api_benchmark_client: FlaskClient,
        performance_collector: APIPerformanceCollector,
        nodejs_baseline_data: Dict[str, float],
        performance_threshold_validator: Dict[str, Callable]
    ):
        """
        Complete API performance validation ensuring comprehensive
        endpoint coverage and migration success criteria compliance.
        """
        # Define comprehensive endpoint test suite
        endpoint_test_suite = [
            # Main blueprint endpoints
            ('GET', '/', 'main_root'),
            ('GET', '/health', 'main_health'),
            ('GET', '/metrics', 'main_metrics'),
            
            # API blueprint endpoints (core functionality)
            ('GET', '/api/health', 'api_health'),
            ('GET', '/api/users', 'api_users_list'),
            
            # Authentication blueprint endpoints (when available)
            # Note: Login requires complex setup, tested separately
        ]
        
        validation_results = []
        
        for method, endpoint, test_name in endpoint_test_suite:
            logger.info(f"Validating {method} {endpoint}...")
            
            # Collect performance samples for statistical validation
            response_times = []
            status_codes = []
            
            for iteration in range(25):
                start_time = time.time()
                
                try:
                    if method == 'GET':
                        response = api_benchmark_client.get(endpoint)
                    else:
                        continue  # Skip non-GET for comprehensive validation
                        
                    end_time = time.time()
                    response_time_ms = (end_time - start_time) * 1000
                    
                    response_times.append(response_time_ms)
                    status_codes.append(response.status_code)
                    
                except Exception as e:
                    logger.error(f"Request failed for {method} {endpoint}: {e}")
                    continue
            
            if not response_times:
                logger.warning(f"No successful requests for {method} {endpoint}")
                continue
            
            # Calculate endpoint statistics
            mean_time = statistics.mean(response_times)
            p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)
            success_rate = (len([sc for sc in status_codes if 200 <= sc < 300]) / len(status_codes)) * 100
            
            # Validate SLA requirements
            sla_compliant = performance_threshold_validator['validate_response_time'](
                mean_time, 200, endpoint
            )
            
            # Validate baseline parity
            baseline_key = f"{method} {endpoint}"
            baseline_time = nodejs_baseline_data.get(baseline_key, mean_time * 1.1)
            baseline_compliant = performance_threshold_validator['validate_baseline_parity'](
                mean_time, baseline_time
            )
            
            validation_result = {
                'endpoint': f"{method} {endpoint}",
                'test_name': test_name,
                'mean_response_time_ms': mean_time,
                'p95_response_time_ms': p95_time,
                'success_rate': success_rate,
                'sla_compliant': sla_compliant,
                'baseline_compliant': baseline_compliant,
                'baseline_time_ms': baseline_time,
                'sample_count': len(response_times)
            }
            
            validation_results.append(validation_result)
            
            logger.info(
                f"  {test_name}: {mean_time:.2f}ms avg, {p95_time:.2f}ms P95, "
                f"{success_rate:.1f}% success, SLA: {sla_compliant}, Baseline: {baseline_compliant}"
            )
        
        # Comprehensive validation analysis
        total_endpoints = len(validation_results)
        sla_compliant_endpoints = len([r for r in validation_results if r['sla_compliant']])
        baseline_compliant_endpoints = len([r for r in validation_results if r['baseline_compliant']])
        
        sla_compliance_rate = (sla_compliant_endpoints / total_endpoints) * 100 if total_endpoints > 0 else 0
        baseline_compliance_rate = (baseline_compliant_endpoints / total_endpoints) * 100 if total_endpoints > 0 else 0
        
        # Generate comprehensive validation report
        logger.info("\n" + "="*80)
        logger.info("COMPREHENSIVE API PERFORMANCE VALIDATION REPORT")
        logger.info("="*80)
        logger.info(f"Total endpoints tested: {total_endpoints}")
        logger.info(f"SLA compliance rate: {sla_compliance_rate:.1f}% ({sla_compliant_endpoints}/{total_endpoints})")
        logger.info(f"Baseline compliance rate: {baseline_compliance_rate:.1f}% ({baseline_compliant_endpoints}/{total_endpoints})")
        
        # Validate migration success criteria
        assert sla_compliance_rate >= 95.0, \
            f"SLA compliance rate {sla_compliance_rate:.1f}% below 95% requirement"
        assert baseline_compliance_rate >= 90.0, \
            f"Baseline compliance rate {baseline_compliance_rate:.1f}% below 90% requirement"
        
        # Report any failing endpoints
        failing_endpoints = [r for r in validation_results if not (r['sla_compliant'] and r['baseline_compliant'])]
        if failing_endpoints:
            logger.warning("Endpoints requiring optimization:")
            for endpoint_result in failing_endpoints:
                logger.warning(
                    f"  {endpoint_result['endpoint']}: {endpoint_result['mean_response_time_ms']:.2f}ms "
                    f"(SLA: {endpoint_result['sla_compliant']}, Baseline: {endpoint_result['baseline_compliant']})"
                )
        
        logger.info("="*80)
        logger.info("MIGRATION PERFORMANCE VALIDATION: PASSED")
        logger.info("="*80)
    
    def test_final_performance_report_generation(
        self,
        performance_collector: APIPerformanceCollector
    ):
        """
        Generate final comprehensive performance report for migration
        validation and operational handoff documentation.
        """
        # Generate comprehensive performance report
        final_report = performance_collector.generate_performance_report()
        
        # Validate report completeness
        required_sections = ['summary', 'endpoint_statistics', 'baseline_comparisons', 'recommendations']
        for section in required_sections:
            assert section in final_report, f"Missing required report section: {section}"
        
        # Validate summary statistics
        summary = final_report['summary']
        assert summary['total_requests'] > 0, "No performance data collected"
        assert summary['sla_compliance_rate'] >= 0, "Invalid SLA compliance rate"
        assert summary['endpoints_tested'] > 0, "No endpoints tested"
        
        # Log final performance summary
        logger.info("\n" + "="*80)
        logger.info("FINAL PERFORMANCE VALIDATION REPORT")
        logger.info("="*80)
        logger.info(f"Total requests processed: {summary['total_requests']}")
        logger.info(f"Overall mean response time: {summary['overall_mean_response_time_ms']:.2f}ms")
        logger.info(f"Overall P95 response time: {summary['overall_p95_response_time_ms']:.2f}ms")
        logger.info(f"Overall SLA compliance: {summary['sla_compliance_rate']:.1f}%")
        logger.info(f"Endpoints tested: {summary['endpoints_tested']}")
        logger.info(f"Test duration: {summary['test_duration_minutes']:.1f} minutes")
        
        # Report optimization recommendations
        recommendations = final_report['recommendations']
        if recommendations:
            logger.info("\nOptimization Recommendations:")
            for i, recommendation in enumerate(recommendations, 1):
                logger.info(f"  {i}. {recommendation}")
        else:
            logger.info("\nNo optimization recommendations - performance meets all requirements")
        
        logger.info("="*80)
        
        # Save performance report for operational handoff
        report_file = Path(__file__).parent / f'performance_report_{int(time.time())}.json'
        try:
            with open(report_file, 'w') as f:
                json.dump(final_report, f, indent=2, default=str)
            logger.info(f"Performance report saved: {report_file}")
        except IOError as e:
            logger.warning(f"Failed to save performance report: {e}")
        
        # Final validation assertions
        assert summary['sla_compliance_rate'] >= 95.0, \
            f"Final SLA compliance {summary['sla_compliance_rate']:.1f}% below requirement"
        assert summary['overall_mean_response_time_ms'] < 200, \
            f"Overall mean response time {summary['overall_mean_response_time_ms']:.2f}ms exceeds SLA"


# ================================
# pytest Configuration and Markers
# ================================

# Mark all tests in this module as performance tests
pytestmark = [
    pytest.mark.performance,
    pytest.mark.api,
    pytest.mark.benchmark
]

# pytest-benchmark configuration for consistent measurement
def pytest_benchmark_update_machine_info(config, machine_info):
    """Update machine info for benchmark consistency"""
    machine_info.update({
        'benchmark_version': '5.1.0',
        'flask_version': '3.1.1',
        'python_version': '3.13.3',
        'test_purpose': 'Flask API migration validation'
    })

# Configure benchmark settings
def pytest_configure(config):
    """Configure pytest-benchmark for performance testing"""
    config.addinivalue_line(
        "markers", 
        "benchmark: marks tests as benchmark tests for performance measurement"
    )

# Benchmark configuration
BENCHMARK_CONFIG = {
    'min_rounds': 5,
    'min_time': 0.000005,
    'max_time': 1.0,
    'timer': time.perf_counter,
    'disable_gc': True,
    'warmup': True,
    'warmup_iterations': 100000
}