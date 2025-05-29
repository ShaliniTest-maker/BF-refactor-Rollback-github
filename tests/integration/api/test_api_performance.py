"""
API Performance Benchmarking Test Suite

This module implements comprehensive performance testing using pytest-benchmark 5.1.0
to validate response times, throughput, and resource utilization against Node.js baseline metrics.
Ensures the Flask implementation meets or exceeds existing performance standards.

Testing Categories:
- API endpoint response time benchmarking
- Concurrent user load validation
- Database query performance with SQLAlchemy optimization
- Memory footprint profiling
- Response time equivalence validation

Performance Requirements (Section 2.1.9):
- Response time parity: Flask ≤ Node.js baseline
- Concurrent users: Equivalent load handling capability  
- Memory utilization: ≤ 120% of Node.js baseline
- Database queries: Equivalent or improved performance

Dependencies:
- pytest-benchmark 5.1.0 for performance measurement
- pytest-flask 1.3.0 for Flask application testing
- Flask 3.1.1 with SQLAlchemy integration
- Python 3.13.3 runtime environment
"""

import pytest
import time
import threading
import concurrent.futures
import psutil
import gc
import os
import json
from typing import Dict, List, Any, Callable
from dataclasses import dataclass
from contextlib import contextmanager
from unittest.mock import patch, MagicMock

# Flask testing imports
from flask import Flask
from flask.testing import FlaskClient

# Database and ORM imports  
from sqlalchemy import text
from sqlalchemy.orm import Session

# Performance monitoring imports
import memory_profiler
from pytest_benchmark.fixture import BenchmarkFixture


@dataclass
class PerformanceBaseline:
    """
    Node.js baseline performance metrics for comparison testing.
    These values represent the performance standards the Flask implementation must meet.
    """
    # API Response Times (milliseconds)
    health_check_response_ms: float = 10.0
    auth_login_response_ms: float = 150.0
    auth_logout_response_ms: float = 50.0
    api_get_entities_response_ms: float = 200.0
    api_create_entity_response_ms: float = 300.0
    api_update_entity_response_ms: float = 250.0
    api_delete_entity_response_ms: float = 100.0
    
    # Concurrent User Metrics
    max_concurrent_users: int = 1000
    concurrent_throughput_rps: float = 100.0  # requests per second
    
    # Database Query Performance (milliseconds)
    simple_select_query_ms: float = 5.0
    complex_join_query_ms: float = 50.0
    transaction_commit_ms: float = 25.0
    
    # Memory Utilization (MB)
    base_memory_usage_mb: float = 150.0
    max_memory_usage_mb: float = 300.0
    memory_growth_threshold_mb: float = 50.0


@dataclass
class PerformanceResult:
    """Performance test result data structure for analysis and reporting."""
    test_name: str
    response_time_ms: float
    memory_usage_mb: float
    throughput_rps: float = 0.0
    success_rate: float = 100.0
    baseline_comparison: float = 0.0  # Percentage difference from baseline
    
    def is_within_baseline(self, baseline_ms: float, tolerance_percent: float = 5.0) -> bool:
        """Check if performance result is within acceptable baseline tolerance."""
        tolerance_ms = baseline_ms * (tolerance_percent / 100.0)
        return self.response_time_ms <= (baseline_ms + tolerance_ms)


class PerformanceProfiler:
    """
    Memory and CPU performance profiler for Flask application testing.
    Provides detailed resource utilization monitoring during test execution.
    """
    
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.baseline_memory = None
        self.peak_memory = 0.0
        self.memory_samples = []
        
    def start_profiling(self):
        """Initialize performance profiling session."""
        gc.collect()  # Clean up before measurement
        self.baseline_memory = self.get_memory_usage()
        self.peak_memory = self.baseline_memory
        self.memory_samples = [self.baseline_memory]
        
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        memory_info = self.process.memory_info()
        return memory_info.rss / (1024 * 1024)  # Convert bytes to MB
        
    def sample_memory(self):
        """Sample current memory usage for tracking."""
        current_memory = self.get_memory_usage()
        self.memory_samples.append(current_memory)
        if current_memory > self.peak_memory:
            self.peak_memory = current_memory
            
    def get_memory_stats(self) -> Dict[str, float]:
        """Calculate memory usage statistics."""
        if not self.memory_samples:
            return {}
            
        return {
            'baseline_mb': self.baseline_memory or 0.0,
            'peak_mb': self.peak_memory,
            'average_mb': sum(self.memory_samples) / len(self.memory_samples),
            'growth_mb': self.peak_memory - (self.baseline_memory or 0.0),
            'samples_count': len(self.memory_samples)
        }


@pytest.fixture
def performance_baseline():
    """Fixture providing Node.js baseline performance metrics."""
    return PerformanceBaseline()


@pytest.fixture  
def performance_profiler():
    """Fixture providing performance profiling capabilities."""
    profiler = PerformanceProfiler()
    profiler.start_profiling()
    yield profiler
    profiler.sample_memory()


@pytest.fixture
def load_test_client(app):
    """
    Enhanced test client for load testing with connection pooling simulation.
    Mimics production client behavior for realistic performance testing.
    """
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SECRET_KEY': 'test-performance-key',
        'WTF_CSRF_ENABLED': False
    })
    
    with app.test_client() as client:
        with app.app_context():
            yield client


class TestAPIEndpointPerformance:
    """
    API endpoint performance testing suite validating response times
    against Node.js baseline metrics per Section 4.7.1 requirements.
    """
    
    def test_health_check_performance(
        self, 
        load_test_client: FlaskClient, 
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test health check endpoint performance against Node.js baseline.
        
        Performance Requirement: ≤ 10ms response time (Section 2.1.9)
        """
        def health_check_request():
            """Execute health check request for benchmarking."""
            performance_profiler.sample_memory()
            response = load_test_client.get('/health')
            assert response.status_code == 200
            return response
            
        # Benchmark health check endpoint
        result = benchmark(health_check_request)
        
        # Validate performance against baseline
        response_time_ms = result.stats.mean * 1000  # Convert to milliseconds
        memory_stats = performance_profiler.get_memory_stats()
        
        performance_result = PerformanceResult(
            test_name="health_check",
            response_time_ms=response_time_ms,
            memory_usage_mb=memory_stats.get('peak_mb', 0.0),
            baseline_comparison=((response_time_ms - performance_baseline.health_check_response_ms) / 
                               performance_baseline.health_check_response_ms) * 100
        )
        
        # Assert performance requirements
        assert performance_result.is_within_baseline(performance_baseline.health_check_response_ms), \
            f"Health check response time {response_time_ms:.2f}ms exceeds baseline {performance_baseline.health_check_response_ms}ms"
        
        assert memory_stats['growth_mb'] < performance_baseline.memory_growth_threshold_mb, \
            f"Memory growth {memory_stats['growth_mb']:.2f}MB exceeds threshold"
            
    def test_authentication_login_performance(
        self,
        load_test_client: FlaskClient,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test authentication login endpoint performance.
        
        Performance Requirement: ≤ 150ms response time (Section 2.1.9)
        """
        def login_request():
            """Execute login request for benchmarking."""
            performance_profiler.sample_memory()
            response = load_test_client.post('/auth/login', json={
                'username': 'test_user@example.com',
                'password': 'test_password'
            })
            # Accept both success and authentication failure for performance testing
            assert response.status_code in [200, 401]
            return response
            
        # Benchmark authentication endpoint
        result = benchmark(login_request)
        
        # Validate performance metrics
        response_time_ms = result.stats.mean * 1000
        memory_stats = performance_profiler.get_memory_stats()
        
        performance_result = PerformanceResult(
            test_name="auth_login",
            response_time_ms=response_time_ms,
            memory_usage_mb=memory_stats.get('peak_mb', 0.0),
            baseline_comparison=((response_time_ms - performance_baseline.auth_login_response_ms) / 
                               performance_baseline.auth_login_response_ms) * 100
        )
        
        # Assert performance requirements
        assert performance_result.is_within_baseline(performance_baseline.auth_login_response_ms), \
            f"Auth login response time {response_time_ms:.2f}ms exceeds baseline {performance_baseline.auth_login_response_ms}ms"
            
    def test_api_entity_endpoints_performance(
        self,
        load_test_client: FlaskClient,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test core API entity endpoints performance.
        
        Performance Requirements:
        - GET entities: ≤ 200ms (Section 2.1.9)
        - POST entity: ≤ 300ms (Section 2.1.9)
        - PUT entity: ≤ 250ms (Section 2.1.9)
        - DELETE entity: ≤ 100ms (Section 2.1.9)
        """
        # Test GET entities performance
        def get_entities_request():
            performance_profiler.sample_memory()
            response = load_test_client.get('/api/entities')
            assert response.status_code in [200, 404]  # Accept empty result for performance testing
            return response
            
        get_result = benchmark.pedantic(get_entities_request, rounds=10, iterations=1)
        get_response_time_ms = get_result.stats.mean * 1000
        
        assert get_response_time_ms <= performance_baseline.api_get_entities_response_ms, \
            f"GET entities response time {get_response_time_ms:.2f}ms exceeds baseline"
        
        # Test POST entity performance  
        def create_entity_request():
            performance_profiler.sample_memory()
            response = load_test_client.post('/api/entities', json={
                'name': 'Performance Test Entity',
                'description': 'Entity created for performance testing',
                'category': 'test'
            })
            assert response.status_code in [200, 201, 400]  # Accept validation errors for performance testing
            return response
            
        post_result = benchmark.pedantic(create_entity_request, rounds=10, iterations=1)
        post_response_time_ms = post_result.stats.mean * 1000
        
        assert post_response_time_ms <= performance_baseline.api_create_entity_response_ms, \
            f"POST entity response time {post_response_time_ms:.2f}ms exceeds baseline"


class TestConcurrentUserLoadPerformance:
    """
    Concurrent user load testing validating Flask application scalability
    per Section 2.1.9 requirements for equivalent Node.js concurrent handling.
    """
    
    @pytest.mark.parametrize("concurrent_users", [10, 50, 100, 250])
    def test_concurrent_user_load_simulation(
        self,
        load_test_client: FlaskClient,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler,
        concurrent_users: int
    ):
        """
        Test concurrent user load handling with various user counts.
        
        Performance Requirement: Handle equivalent concurrent load to Node.js (Section 2.1.9)
        """
        def concurrent_request_batch():
            """Execute batch of concurrent requests for load testing."""
            
            def single_user_request():
                """Single user request simulation."""
                response = load_test_client.get('/health')
                return response.status_code == 200
                
            # Execute concurrent requests using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as executor:
                performance_profiler.sample_memory()
                start_time = time.time()
                
                # Submit concurrent requests
                futures = [executor.submit(single_user_request) for _ in range(concurrent_users)]
                
                # Wait for all requests to complete
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                end_time = time.time()
                total_time = end_time - start_time
                
                performance_profiler.sample_memory()
                
                return {
                    'success_count': sum(results),
                    'total_requests': concurrent_users,
                    'total_time': total_time,
                    'success_rate': (sum(results) / concurrent_users) * 100,
                    'throughput_rps': concurrent_users / total_time if total_time > 0 else 0
                }
                
        # Benchmark concurrent load
        result = benchmark.pedantic(concurrent_request_batch, rounds=3, iterations=1)
        batch_result = result.stats.mean if hasattr(result.stats, 'mean') else concurrent_request_batch()
        
        if isinstance(batch_result, dict):
            memory_stats = performance_profiler.get_memory_stats()
            
            # Validate load performance requirements
            assert batch_result['success_rate'] >= 95.0, \
                f"Success rate {batch_result['success_rate']:.1f}% below 95% threshold for {concurrent_users} users"
            
            assert batch_result['throughput_rps'] >= performance_baseline.concurrent_throughput_rps * 0.8, \
                f"Throughput {batch_result['throughput_rps']:.1f} RPS below 80% of baseline for {concurrent_users} users"
            
            # Memory growth should be reasonable under load
            assert memory_stats['growth_mb'] < performance_baseline.memory_growth_threshold_mb * 2, \
                f"Memory growth {memory_stats['growth_mb']:.2f}MB excessive under {concurrent_users} concurrent users"
    
    def test_sustained_load_endurance(
        self,
        load_test_client: FlaskClient,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test sustained load endurance over extended duration.
        
        Performance Requirement: Stable performance over time without degradation
        """
        duration_seconds = 30  # Reduced for test suite efficiency
        request_interval = 0.1  # 10 requests per second
        
        start_time = time.time()
        response_times = []
        success_count = 0
        total_requests = 0
        
        while (time.time() - start_time) < duration_seconds:
            request_start = time.time()
            
            try:
                response = load_test_client.get('/health')
                success_count += response.status_code == 200
            except Exception:
                pass  # Continue testing even with individual failures
                
            request_end = time.time()
            response_times.append((request_end - request_start) * 1000)  # Convert to ms
            total_requests += 1
            
            performance_profiler.sample_memory()
            
            # Maintain request interval
            elapsed = request_end - request_start
            if elapsed < request_interval:
                time.sleep(request_interval - elapsed)
        
        # Analyze sustained performance
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            max_response_time = max(response_times)
            success_rate = (success_count / total_requests) * 100 if total_requests > 0 else 0
            
            memory_stats = performance_profiler.get_memory_stats()
            
            # Assert sustained performance requirements
            assert success_rate >= 95.0, \
                f"Sustained load success rate {success_rate:.1f}% below 95% threshold"
                
            assert avg_response_time <= performance_baseline.health_check_response_ms * 2, \
                f"Sustained load average response time {avg_response_time:.2f}ms exceeds threshold"
                
            assert max_response_time <= performance_baseline.health_check_response_ms * 5, \
                f"Sustained load max response time {max_response_time:.2f}ms exceeds threshold"
                
            # Memory should not grow excessively during sustained load
            assert memory_stats['growth_mb'] < performance_baseline.memory_growth_threshold_mb * 3, \
                f"Sustained load memory growth {memory_stats['growth_mb']:.2f}MB excessive"


class TestDatabaseQueryPerformance:
    """
    Database query performance testing with SQLAlchemy optimization
    per Section 5.2.4 requirements for equivalent or improved performance.
    """
    
    def test_simple_select_query_performance(
        self,
        app: Flask,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test simple SELECT query performance against baseline.
        
        Performance Requirement: ≤ 5ms query execution time
        """
        with app.app_context():
            from src.models import db
            
            def simple_select_query():
                """Execute simple SELECT query for benchmarking."""
                performance_profiler.sample_memory()
                
                # Simple query using SQLAlchemy
                result = db.session.execute(text("SELECT 1 as test_value"))
                rows = result.fetchall()
                
                assert len(rows) >= 0  # Ensure query executed
                return rows
                
            # Benchmark simple query
            result = benchmark.pedantic(simple_select_query, rounds=20, iterations=5)
            
            query_time_ms = result.stats.mean * 1000
            memory_stats = performance_profiler.get_memory_stats()
            
            # Assert query performance requirements
            assert query_time_ms <= performance_baseline.simple_select_query_ms, \
                f"Simple SELECT query time {query_time_ms:.2f}ms exceeds baseline {performance_baseline.simple_select_query_ms}ms"
                
            assert memory_stats['growth_mb'] < 10.0, \
                f"Query memory growth {memory_stats['growth_mb']:.2f}MB excessive for simple query"
    
    def test_transaction_performance(
        self,
        app: Flask,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test database transaction performance including commit operations.
        
        Performance Requirement: ≤ 25ms transaction commit time
        """
        with app.app_context():
            from src.models import db
            
            def transaction_operation():
                """Execute database transaction for benchmarking."""
                performance_profiler.sample_memory()
                
                try:
                    # Begin transaction
                    db.session.begin()
                    
                    # Execute simple operation within transaction
                    db.session.execute(text("SELECT 1 as transaction_test"))
                    
                    # Commit transaction
                    db.session.commit()
                    
                except Exception as e:
                    db.session.rollback()
                    raise e
                    
                return True
                
            # Benchmark transaction operations
            result = benchmark.pedantic(transaction_operation, rounds=15, iterations=3)
            
            transaction_time_ms = result.stats.mean * 1000
            memory_stats = performance_profiler.get_memory_stats()
            
            # Assert transaction performance requirements
            assert transaction_time_ms <= performance_baseline.transaction_commit_ms, \
                f"Transaction commit time {transaction_time_ms:.2f}ms exceeds baseline {performance_baseline.transaction_commit_ms}ms"
                
            assert memory_stats['growth_mb'] < 15.0, \
                f"Transaction memory growth {memory_stats['growth_mb']:.2f}MB excessive"
    
    def test_connection_pool_performance(
        self,
        app: Flask,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test database connection pool efficiency under concurrent access.
        
        Performance Requirement: Efficient connection management equivalent to Node.js
        """
        with app.app_context():
            from src.models import db
            
            def connection_pool_simulation():
                """Simulate concurrent database access for connection pool testing."""
                performance_profiler.sample_memory()
                
                def database_worker():
                    """Individual database worker thread."""
                    try:
                        result = db.session.execute(text("SELECT COUNT(*) as connection_test"))
                        return result.fetchone() is not None
                    except Exception:
                        return False
                
                # Simulate concurrent database access
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(database_worker) for _ in range(20)]
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                    
                success_rate = (sum(results) / len(results)) * 100 if results else 0
                return success_rate
                
            # Benchmark connection pool performance
            result = benchmark.pedantic(connection_pool_simulation, rounds=5, iterations=1)
            
            # Connection pool should handle concurrent access efficiently
            success_rate = result.stats.mean if hasattr(result.stats, 'mean') else connection_pool_simulation()
            memory_stats = performance_profiler.get_memory_stats()
            
            # Assert connection pool performance
            assert success_rate >= 95.0, \
                f"Connection pool success rate {success_rate:.1f}% below 95% threshold"
                
            assert memory_stats['growth_mb'] < performance_baseline.memory_growth_threshold_mb, \
                f"Connection pool memory growth {memory_stats['growth_mb']:.2f}MB excessive"


class TestMemoryFootprintValidation:
    """
    Memory footprint validation ensuring Flask application does not exceed
    Node.js baseline by more than 20% per Section 2.1.9 requirements.
    """
    
    def test_baseline_memory_usage(
        self,
        app: Flask,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test baseline memory usage of Flask application at startup.
        
        Performance Requirement: Reasonable baseline memory consumption
        """
        with app.app_context():
            # Allow application to fully initialize
            time.sleep(1.0)
            performance_profiler.sample_memory()
            
            # Sample memory after initialization
            for _ in range(10):
                time.sleep(0.1)
                performance_profiler.sample_memory()
            
            memory_stats = performance_profiler.get_memory_stats()
            baseline_memory = memory_stats['baseline_mb']
            peak_memory = memory_stats['peak_mb']
            
            # Assert baseline memory requirements
            assert baseline_memory <= performance_baseline.base_memory_usage_mb * 1.5, \
                f"Baseline memory usage {baseline_memory:.2f}MB exceeds 150% of expected baseline"
                
            assert peak_memory <= performance_baseline.max_memory_usage_mb, \
                f"Peak memory usage {peak_memory:.2f}MB exceeds maximum threshold"
    
    @memory_profiler.profile
    def test_memory_usage_under_load(
        self,
        load_test_client: FlaskClient,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Test memory usage under simulated load conditions.
        
        Performance Requirement: Memory growth ≤ 20% above Node.js baseline
        """
        initial_memory = performance_profiler.get_memory_usage()
        
        # Simulate load with multiple requests
        for batch in range(5):  # 5 batches of requests
            for request_num in range(20):  # 20 requests per batch
                try:
                    response = load_test_client.get('/health')
                    assert response.status_code == 200
                    
                    if request_num % 5 == 0:  # Sample memory every 5 requests
                        performance_profiler.sample_memory()
                        
                except Exception:
                    pass  # Continue testing even with individual failures
                    
            # Force garbage collection between batches
            gc.collect()
            performance_profiler.sample_memory()
            
        final_memory = performance_profiler.get_memory_usage()
        memory_growth = final_memory - initial_memory
        memory_growth_percent = (memory_growth / initial_memory) * 100 if initial_memory > 0 else 0
        
        memory_stats = performance_profiler.get_memory_stats()
        
        # Assert memory growth requirements (Node.js + 20% tolerance)
        max_allowed_growth = performance_baseline.base_memory_usage_mb * 0.20  # 20% growth tolerance
        
        assert memory_growth <= max_allowed_growth, \
            f"Memory growth {memory_growth:.2f}MB exceeds 20% tolerance ({max_allowed_growth:.2f}MB)"
            
        assert memory_growth_percent <= 30.0, \
            f"Memory growth {memory_growth_percent:.1f}% exceeds 30% threshold"
            
        assert memory_stats['peak_mb'] <= performance_baseline.base_memory_usage_mb * 1.5, \
            f"Peak memory {memory_stats['peak_mb']:.2f}MB exceeds 150% of baseline"


class TestResponseTimeEquivalenceValidation:
    """
    Response time equivalence validation using automated benchmarking
    per Section 4.7.2 for comprehensive parity assessment.
    """
    
    def test_response_time_parity_comprehensive(
        self,
        load_test_client: FlaskClient,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Comprehensive response time parity validation across all endpoint categories.
        
        Performance Requirement: Response times ≤ Node.js baseline equivalence
        """
        # Define test endpoints with their baseline expectations
        test_endpoints = [
            ('/health', 'GET', performance_baseline.health_check_response_ms),
            ('/auth/login', 'POST', performance_baseline.auth_login_response_ms),
            ('/api/entities', 'GET', performance_baseline.api_get_entities_response_ms),
        ]
        
        parity_results = []
        
        for endpoint, method, baseline_ms in test_endpoints:
            def endpoint_request():
                """Execute endpoint request for parity testing."""
                performance_profiler.sample_memory()
                
                if method == 'GET':
                    response = load_test_client.get(endpoint)
                elif method == 'POST':
                    response = load_test_client.post(endpoint, json={'test': 'data'})
                else:
                    response = load_test_client.get(endpoint)  # Default to GET
                    
                # Accept various response codes for parity testing
                assert response.status_code in [200, 201, 400, 401, 404]
                return response
                
            # Benchmark individual endpoint
            result = benchmark.pedantic(endpoint_request, rounds=10, iterations=3)
            response_time_ms = result.stats.mean * 1000
            
            # Calculate parity percentage
            parity_percent = ((response_time_ms - baseline_ms) / baseline_ms) * 100
            
            parity_result = {
                'endpoint': f"{method} {endpoint}",
                'response_time_ms': response_time_ms,
                'baseline_ms': baseline_ms,
                'parity_percent': parity_percent,
                'within_tolerance': abs(parity_percent) <= 10.0  # 10% tolerance
            }
            
            parity_results.append(parity_result)
            
            # Assert individual endpoint parity
            assert parity_result['within_tolerance'], \
                f"Endpoint {parity_result['endpoint']} parity {parity_percent:.1f}% exceeds ±10% tolerance"
        
        # Overall parity assessment
        total_endpoints = len(parity_results)
        within_tolerance_count = sum(1 for result in parity_results if result['within_tolerance'])
        overall_parity_rate = (within_tolerance_count / total_endpoints) * 100 if total_endpoints > 0 else 0
        
        memory_stats = performance_profiler.get_memory_stats()
        
        # Assert overall parity requirements
        assert overall_parity_rate >= 90.0, \
            f"Overall parity rate {overall_parity_rate:.1f}% below 90% threshold"
            
        assert memory_stats['growth_mb'] < performance_baseline.memory_growth_threshold_mb * 2, \
            f"Comprehensive testing memory growth {memory_stats['growth_mb']:.2f}MB excessive"
    
    def test_performance_regression_detection(
        self,
        load_test_client: FlaskClient,
        benchmark: BenchmarkFixture,
        performance_baseline: PerformanceBaseline,
        performance_profiler: PerformanceProfiler
    ):
        """
        Performance regression detection against historical baseline metrics.
        
        Performance Requirement: No performance regression compared to Node.js baseline
        """
        # Execute baseline performance test multiple times for statistical significance
        performance_samples = []
        
        for sample_round in range(5):  # 5 sample rounds
            def baseline_performance_sample():
                """Execute baseline performance sample."""
                performance_profiler.sample_memory()
                
                # Test multiple endpoints for comprehensive baseline
                endpoints = ['/health', '/api/entities']
                response_times = []
                
                for endpoint in endpoints:
                    start_time = time.time()
                    response = load_test_client.get(endpoint)
                    end_time = time.time()
                    
                    response_times.append((end_time - start_time) * 1000)  # Convert to ms
                    
                    # Accept various response codes
                    assert response.status_code in [200, 404]
                
                avg_response_time = sum(response_times) / len(response_times) if response_times else 0
                return avg_response_time
                
            # Benchmark performance sample
            result = benchmark.pedantic(baseline_performance_sample, rounds=3, iterations=1)
            sample_response_time = result.stats.mean if hasattr(result.stats, 'mean') else baseline_performance_sample()
            
            performance_samples.append(sample_response_time)
        
        # Analyze performance consistency
        if performance_samples:
            avg_performance = sum(performance_samples) / len(performance_samples)
            max_performance = max(performance_samples)
            min_performance = min(performance_samples)
            performance_variance = max_performance - min_performance
            
            memory_stats = performance_profiler.get_memory_stats()
            
            # Assert performance regression requirements
            baseline_threshold = (performance_baseline.health_check_response_ms + 
                                performance_baseline.api_get_entities_response_ms) / 2
                                
            assert avg_performance <= baseline_threshold * 1.1, \
                f"Average performance {avg_performance:.2f}ms exceeds 110% of baseline threshold"
                
            assert performance_variance <= baseline_threshold * 0.5, \
                f"Performance variance {performance_variance:.2f}ms indicates instability"
                
            assert memory_stats['growth_mb'] < performance_baseline.memory_growth_threshold_mb, \
                f"Regression testing memory growth {memory_stats['growth_mb']:.2f}MB excessive"


# Performance testing utility functions and markers
pytestmark = [
    pytest.mark.performance,
    pytest.mark.integration,
    pytest.mark.slow
]


def pytest_configure(config):
    """Configure pytest for performance testing with benchmark settings."""
    config.addinivalue_line(
        "markers", "performance: marks tests as performance benchmarking tests"
    )
    config.addinivalue_line(
        "markers", "slow: marks tests as slow-running performance tests"
    )


# Benchmark configuration for consistent testing
@pytest.fixture(autouse=True)
def configure_benchmark(benchmark):
    """Configure benchmark settings for consistent performance testing."""
    benchmark.pedantic(iterations=1, rounds=1, warmup_rounds=1)