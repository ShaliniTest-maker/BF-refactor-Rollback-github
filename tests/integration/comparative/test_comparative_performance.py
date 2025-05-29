"""
Performance benchmarking test suite implementing pytest-benchmark 5.1.0 for comprehensive 
response time and resource usage comparison between Node.js and Flask implementations.

This module validates equivalent or improved performance metrics, monitors concurrent user 
load handling, and ensures memory footprint optimization during migration. It implements 
automated performance regression detection with threshold-based alerting per Section 4.7.1
of the technical specification.

Key Features:
- API response time measurement against Node.js baseline
- Memory usage profiling for Flask application resource consumption
- Database query performance benchmarking with SQLAlchemy optimization
- Concurrent user load testing for equivalent performance validation
- Automated performance regression detection with configurable thresholds

Dependencies:
- pytest-benchmark 5.1.0: Performance measurement and baseline comparison
- pytest-flask 1.3.0: Flask application testing fixtures and context management
- Flask 3.1.1: Target application framework under test
- Flask-SQLAlchemy 3.1.1: Database ORM performance testing
- psutil: System resource monitoring and memory profiling
"""

import asyncio
import gc
import json
import multiprocessing
import os
import psutil
import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from unittest.mock import patch

import requests
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import text
from sqlalchemy.orm import Session

# Flask application and testing imports
from src.app import create_app
from src.models.user import User
from src.models.business_entity import BusinessEntity
from src.services.user_service import UserService
from src.services.business_entity_service import BusinessEntityService
from src.services.validation_service import ValidationService

# Testing infrastructure imports
from tests.integration.conftest import app_factory, test_client, test_db
from tests.integration.comparative.conftest_comparative import (
    nodejs_baseline_client,
    comparative_test_environment,
    baseline_capture_manager,
    performance_threshold_config
)


@dataclass
class PerformanceMetrics:
    """
    Performance metrics data structure for comprehensive measurement tracking.
    
    Captures response times, resource usage, and system performance indicators
    for both Flask and Node.js implementations during comparative testing.
    """
    response_time: float  # Response time in milliseconds
    memory_usage: float   # Memory usage in MB
    cpu_usage: float     # CPU usage percentage
    database_queries: int # Number of database queries executed
    query_time: float    # Total database query execution time
    concurrent_users: int # Number of concurrent users during test
    throughput: float    # Requests per second
    error_rate: float    # Error rate percentage
    timestamp: datetime  # Test execution timestamp
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for JSON serialization."""
        return {
            'response_time': self.response_time,
            'memory_usage': self.memory_usage,
            'cpu_usage': self.cpu_usage,
            'database_queries': self.database_queries,
            'query_time': self.query_time,
            'concurrent_users': self.concurrent_users,
            'throughput': self.throughput,
            'error_rate': self.error_rate,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class PerformanceThresholds:
    """
    Performance threshold configuration for automated regression detection.
    
    Defines acceptable performance boundaries and alert triggers for various
    performance metrics during Flask vs Node.js comparison testing.
    """
    max_response_time_ms: float = 500.0      # Maximum acceptable response time
    max_memory_usage_mb: float = 512.0       # Maximum memory usage threshold
    max_cpu_usage_percent: float = 80.0      # Maximum CPU usage threshold
    min_throughput_rps: float = 100.0        # Minimum requests per second
    max_error_rate_percent: float = 1.0      # Maximum error rate threshold
    response_time_degradation_percent: float = 10.0  # Max degradation vs baseline
    memory_usage_increase_percent: float = 15.0      # Max memory increase vs baseline
    
    def validate_metrics(self, metrics: PerformanceMetrics, baseline: Optional[PerformanceMetrics] = None) -> List[str]:
        """
        Validate performance metrics against thresholds and baseline.
        
        Args:
            metrics: Current performance metrics to validate
            baseline: Optional baseline metrics for comparison
            
        Returns:
            List of threshold violations as human-readable strings
        """
        violations = []
        
        # Absolute threshold validations
        if metrics.response_time > self.max_response_time_ms:
            violations.append(f"Response time {metrics.response_time:.2f}ms exceeds threshold {self.max_response_time_ms}ms")
            
        if metrics.memory_usage > self.max_memory_usage_mb:
            violations.append(f"Memory usage {metrics.memory_usage:.2f}MB exceeds threshold {self.max_memory_usage_mb}MB")
            
        if metrics.cpu_usage > self.max_cpu_usage_percent:
            violations.append(f"CPU usage {metrics.cpu_usage:.2f}% exceeds threshold {self.max_cpu_usage_percent}%")
            
        if metrics.throughput < self.min_throughput_rps:
            violations.append(f"Throughput {metrics.throughput:.2f} RPS below threshold {self.min_throughput_rps} RPS")
            
        if metrics.error_rate > self.max_error_rate_percent:
            violations.append(f"Error rate {metrics.error_rate:.2f}% exceeds threshold {self.max_error_rate_percent}%")
        
        # Baseline comparison validations
        if baseline:
            response_degradation = ((metrics.response_time - baseline.response_time) / baseline.response_time) * 100
            if response_degradation > self.response_time_degradation_percent:
                violations.append(f"Response time degradation {response_degradation:.2f}% exceeds threshold {self.response_time_degradation_percent}%")
                
            memory_increase = ((metrics.memory_usage - baseline.memory_usage) / baseline.memory_usage) * 100
            if memory_increase > self.memory_usage_increase_percent:
                violations.append(f"Memory usage increase {memory_increase:.2f}% exceeds threshold {self.memory_usage_increase_percent}%")
        
        return violations


class PerformanceProfiler:
    """
    Advanced performance profiling utility for comprehensive resource monitoring.
    
    Provides detailed system resource tracking, memory profiling, and performance
    measurement capabilities for Flask application testing against Node.js baseline.
    """
    
    def __init__(self):
        """Initialize performance profiler with system monitoring capabilities."""
        self.process = psutil.Process()
        self.start_time: Optional[datetime] = None
        self.baseline_memory: Optional[float] = None
        self.query_count = 0
        self.query_time = 0.0
        
    @contextmanager
    def measure_performance(self, concurrent_users: int = 1):
        """
        Context manager for comprehensive performance measurement.
        
        Args:
            concurrent_users: Number of concurrent users to simulate
            
        Yields:
            Function to capture performance metrics at measurement completion
        """
        # Force garbage collection for clean measurement baseline
        gc.collect()
        
        # Capture baseline metrics
        self.start_time = datetime.now()
        self.baseline_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        start_cpu_times = self.process.cpu_times()
        self.query_count = 0
        self.query_time = 0.0
        
        try:
            yield self._capture_metrics
        finally:
            # Force garbage collection after measurement
            gc.collect()
    
    def _capture_metrics(self, response_time: float, error_count: int = 0, 
                        total_requests: int = 1) -> PerformanceMetrics:
        """
        Capture comprehensive performance metrics at measurement completion.
        
        Args:
            response_time: Total response time in milliseconds
            error_count: Number of errors encountered during testing
            total_requests: Total number of requests executed
            
        Returns:
            Complete performance metrics data structure
        """
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # Memory usage calculation
        current_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        memory_usage = current_memory - self.baseline_memory if self.baseline_memory else current_memory
        
        # CPU usage calculation
        cpu_usage = self.process.cpu_percent(interval=0.1)
        
        # Throughput calculation
        throughput = total_requests / duration if duration > 0 else 0
        
        # Error rate calculation
        error_rate = (error_count / total_requests * 100) if total_requests > 0 else 0
        
        return PerformanceMetrics(
            response_time=response_time,
            memory_usage=memory_usage,
            cpu_usage=cpu_usage,
            database_queries=self.query_count,
            query_time=self.query_time,
            concurrent_users=1,  # Updated by caller for concurrent tests
            throughput=throughput,
            error_rate=error_rate,
            timestamp=end_time
        )
    
    def track_database_query(self, query_time: float):
        """
        Track database query execution for performance measurement.
        
        Args:
            query_time: Database query execution time in milliseconds
        """
        self.query_count += 1
        self.query_time += query_time


class ConcurrentLoadTester:
    """
    Concurrent load testing utility for validating equivalent user capacity handling.
    
    Implements sophisticated concurrent user simulation with configurable load patterns,
    response time distribution analysis, and system stability monitoring under stress.
    """
    
    def __init__(self, max_workers: int = None):
        """
        Initialize concurrent load tester with configurable worker pool.
        
        Args:
            max_workers: Maximum number of concurrent workers (defaults to CPU count * 2)
        """
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) * 2)
        self.results: List[Dict[str, Any]] = []
        
    def execute_load_test(self, test_function: Callable, concurrent_users: int, 
                         duration_seconds: int = 30, ramp_up_seconds: int = 5) -> Dict[str, Any]:
        """
        Execute comprehensive concurrent load test with configurable parameters.
        
        Args:
            test_function: Function to execute for each concurrent user
            concurrent_users: Number of concurrent users to simulate
            duration_seconds: Duration of sustained load testing
            ramp_up_seconds: Time to gradually increase load to target users
            
        Returns:
            Comprehensive load test results with performance metrics
        """
        start_time = time.time()
        results = []
        errors = []
        
        # Calculate ramp-up schedule
        ramp_interval = ramp_up_seconds / concurrent_users if concurrent_users > 0 else 0
        
        with ThreadPoolExecutor(max_workers=min(self.max_workers, concurrent_users)) as executor:
            # Submit all concurrent user tasks with ramp-up delay
            futures = []
            for user_id in range(concurrent_users):
                # Delay submission to implement gradual ramp-up
                time.sleep(ramp_interval)
                future = executor.submit(self._execute_user_session, test_function, user_id, duration_seconds)
                futures.append(future)
            
            # Collect results from all concurrent users
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    errors.append(str(e))
        
        # Calculate aggregate performance metrics
        total_time = time.time() - start_time
        total_requests = sum(r['requests'] for r in results)
        total_errors = len(errors) + sum(r['errors'] for r in results)
        
        response_times = []
        for result in results:
            response_times.extend(result['response_times'])
        
        return {
            'concurrent_users': concurrent_users,
            'duration': total_time,
            'total_requests': total_requests,
            'total_errors': total_errors,
            'error_rate': (total_errors / total_requests * 100) if total_requests > 0 else 0,
            'throughput': total_requests / total_time if total_time > 0 else 0,
            'avg_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'percentiles': self._calculate_percentiles(response_times),
            'results': results,
            'errors': errors
        }
    
    def _execute_user_session(self, test_function: Callable, user_id: int, 
                             duration_seconds: int) -> Dict[str, Any]:
        """
        Execute individual user session for concurrent load testing.
        
        Args:
            test_function: Function to execute repeatedly for user session
            user_id: Unique identifier for the user session
            duration_seconds: Duration of the user session
            
        Returns:
            User session performance metrics and results
        """
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        requests = 0
        errors = 0
        response_times = []
        
        while time.time() < end_time:
            try:
                request_start = time.time()
                test_function(user_id)
                request_end = time.time()
                
                response_time = (request_end - request_start) * 1000  # Convert to milliseconds
                response_times.append(response_time)
                requests += 1
                
            except Exception as e:
                errors += 1
            
            # Brief pause to simulate realistic user behavior
            time.sleep(0.01)
        
        return {
            'user_id': user_id,
            'requests': requests,
            'errors': errors,
            'response_times': response_times,
            'session_duration': time.time() - start_time
        }
    
    def _calculate_percentiles(self, values: List[float]) -> Dict[str, float]:
        """
        Calculate response time percentiles for performance analysis.
        
        Args:
            values: List of response time values in milliseconds
            
        Returns:
            Dictionary containing 50th, 90th, 95th, and 99th percentiles
        """
        if not values:
            return {'p50': 0, 'p90': 0, 'p95': 0, 'p99': 0}
        
        sorted_values = sorted(values)
        count = len(sorted_values)
        
        return {
            'p50': sorted_values[int(count * 0.5)],
            'p90': sorted_values[int(count * 0.9)],
            'p95': sorted_values[int(count * 0.95)],
            'p99': sorted_values[int(count * 0.99)]
        }


# Performance testing fixtures and utilities
@pytest.fixture
def performance_profiler():
    """Provide performance profiler instance for comprehensive metrics collection."""
    return PerformanceProfiler()


@pytest.fixture
def performance_thresholds():
    """Provide performance threshold configuration for regression detection."""
    return PerformanceThresholds()


@pytest.fixture
def load_tester():
    """Provide concurrent load tester for user capacity validation."""
    return ConcurrentLoadTester()


@pytest.fixture
def database_performance_monitor(test_db):
    """
    Database performance monitoring fixture with query tracking.
    
    Provides SQLAlchemy query performance monitoring and optimization
    validation capabilities for database operation benchmarking.
    """
    query_times = []
    original_execute = test_db.session.execute
    
    def tracked_execute(statement, parameters=None, execution_options=None, bind_arguments=None, _parent_execute_state=None, _add_event=None):
        start_time = time.time()
        try:
            result = original_execute(statement, parameters, execution_options, bind_arguments, _parent_execute_state, _add_event)
            return result
        finally:
            query_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            query_times.append(query_time)
    
    # Patch the execute method for monitoring
    test_db.session.execute = tracked_execute
    
    yield {
        'get_query_times': lambda: query_times.copy(),
        'get_total_query_time': lambda: sum(query_times),
        'get_query_count': lambda: len(query_times),
        'get_average_query_time': lambda: sum(query_times) / len(query_times) if query_times else 0
    }
    
    # Restore original execute method
    test_db.session.execute = original_execute


class TestAPIPerformanceBenchmarking:
    """
    API endpoint performance benchmarking test suite.
    
    Validates response time equivalence and improvement compared to Node.js baseline
    implementation using pytest-benchmark 5.1.0 for accurate measurement and comparison.
    """
    
    def test_api_user_creation_performance(self, benchmark, test_client, performance_profiler, 
                                         nodejs_baseline_client, performance_thresholds):
        """
        Benchmark user creation API endpoint performance against Node.js baseline.
        
        Validates that Flask implementation maintains equivalent or improved response
        times for user registration operations with comprehensive validation.
        """
        # Test data for user creation
        user_data = {
            'email': 'performance.test@example.com',
            'password': 'SecurePassword123!',
            'first_name': 'Performance',
            'last_name': 'Test',
            'profile': {
                'bio': 'Performance testing user account',
                'preferences': {'notifications': True}
            }
        }
        
        # Capture Node.js baseline performance
        baseline_start = time.time()
        baseline_response = nodejs_baseline_client.post('/api/users', json=user_data)
        baseline_time = (time.time() - baseline_start) * 1000  # Convert to milliseconds
        
        assert baseline_response.status_code == 201, "Node.js baseline user creation failed"
        
        # Benchmark Flask implementation
        def flask_user_creation():
            """Flask user creation operation for benchmarking."""
            with performance_profiler.measure_performance() as capture_metrics:
                response = test_client.post('/api/users', json=user_data)
                assert response.status_code == 201
                assert 'id' in response.get_json()
                return capture_metrics(response_time=0)  # Will be updated by benchmark
        
        # Execute benchmark measurement
        result = benchmark(flask_user_creation)
        
        # Calculate performance metrics
        flask_response_time = result * 1000  # Convert to milliseconds
        performance_improvement = ((baseline_time - flask_response_time) / baseline_time) * 100
        
        # Validate performance requirements
        assert flask_response_time <= performance_thresholds.max_response_time_ms, \
            f"Flask response time {flask_response_time:.2f}ms exceeds threshold"
        
        # Validate against baseline (allow up to 10% degradation)
        assert flask_response_time <= baseline_time * 1.1, \
            f"Flask response time {flask_response_time:.2f}ms significantly slower than Node.js {baseline_time:.2f}ms"
        
        # Log performance comparison
        print(f"\nUser Creation Performance Comparison:")
        print(f"Node.js Baseline: {baseline_time:.2f}ms")
        print(f"Flask Implementation: {flask_response_time:.2f}ms")
        print(f"Performance Change: {performance_improvement:.2f}%")
    
    def test_api_business_entity_query_performance(self, benchmark, test_client, 
                                                  database_performance_monitor, 
                                                  nodejs_baseline_client, test_db):
        """
        Benchmark business entity query operations with database performance analysis.
        
        Validates SQLAlchemy query optimization effectiveness and database operation
        performance compared to Node.js MongoDB implementation baseline.
        """
        # Create test business entities for querying
        with test_db.session.begin():
            for i in range(10):
                entity = BusinessEntity(
                    name=f'Performance Test Entity {i}',
                    description=f'Entity for performance testing {i}',
                    status='active',
                    metadata={'test_data': True, 'index': i}
                )
                test_db.session.add(entity)
        
        # Capture Node.js baseline query performance
        baseline_start = time.time()
        baseline_response = nodejs_baseline_client.get('/api/business-entities?status=active&limit=10')
        baseline_time = (time.time() - baseline_start) * 1000
        
        assert baseline_response.status_code == 200, "Node.js baseline query failed"
        baseline_entities = baseline_response.get_json()
        
        # Benchmark Flask SQLAlchemy query implementation
        def flask_entity_query():
            """Flask business entity query operation for benchmarking."""
            start_query_count = database_performance_monitor['get_query_count']()
            
            response = test_client.get('/api/business-entities?status=active&limit=10')
            assert response.status_code == 200
            
            entities = response.get_json()
            assert len(entities.get('data', [])) == len(baseline_entities.get('data', []))
            
            # Validate database query efficiency
            queries_executed = database_performance_monitor['get_query_count']() - start_query_count
            assert queries_executed <= 3, f"Too many database queries executed: {queries_executed}"
            
            return response
        
        # Execute benchmark measurement
        result = benchmark(flask_entity_query)
        flask_response_time = result * 1000
        
        # Analyze database performance
        avg_query_time = database_performance_monitor['get_average_query_time']()
        total_query_time = database_performance_monitor['get_total_query_time']()
        
        # Performance validation
        assert flask_response_time <= baseline_time * 1.15, \
            f"Flask query {flask_response_time:.2f}ms significantly slower than baseline {baseline_time:.2f}ms"
        
        assert avg_query_time <= 50.0, \
            f"Average query time {avg_query_time:.2f}ms exceeds 50ms threshold"
        
        print(f"\nBusiness Entity Query Performance:")
        print(f"Node.js Baseline: {baseline_time:.2f}ms")
        print(f"Flask Implementation: {flask_response_time:.2f}ms")
        print(f"Average Query Time: {avg_query_time:.2f}ms")
        print(f"Total Query Time: {total_query_time:.2f}ms")
    
    def test_api_authentication_performance(self, benchmark, test_client, 
                                           nodejs_baseline_client, performance_thresholds):
        """
        Benchmark authentication flow performance including login and token validation.
        
        Validates Flask-Login and ItsDangerous session management performance
        against Node.js authentication middleware baseline.
        """
        # Test credentials for authentication
        auth_data = {
            'email': 'auth.test@example.com',
            'password': 'AuthTestPassword123!'
        }
        
        # Create test user for authentication
        test_client.post('/api/users', json={
            **auth_data,
            'first_name': 'Auth',
            'last_name': 'Test'
        })
        
        # Capture Node.js baseline authentication performance
        baseline_start = time.time()
        baseline_response = nodejs_baseline_client.post('/api/auth/login', json=auth_data)
        baseline_time = (time.time() - baseline_start) * 1000
        
        assert baseline_response.status_code == 200, "Node.js baseline authentication failed"
        
        # Benchmark Flask authentication implementation
        def flask_authentication():
            """Flask authentication operation for benchmarking."""
            # Login performance measurement
            login_start = time.time()
            response = test_client.post('/api/auth/login', json=auth_data)
            login_time = (time.time() - login_start) * 1000
            
            assert response.status_code == 200
            assert 'token' in response.get_json() or 'session' in response.headers
            
            # Token validation performance (if applicable)
            if 'token' in response.get_json():
                token = response.get_json()['token']
                validation_start = time.time()
                profile_response = test_client.get(
                    '/api/auth/profile',
                    headers={'Authorization': f'Bearer {token}'}
                )
                validation_time = (time.time() - validation_start) * 1000
                
                assert profile_response.status_code == 200
                return login_time + validation_time
            
            return login_time
        
        # Execute benchmark measurement
        result = benchmark(flask_authentication)
        flask_auth_time = result * 1000
        
        # Performance validation
        assert flask_auth_time <= performance_thresholds.max_response_time_ms, \
            f"Flask authentication time {flask_auth_time:.2f}ms exceeds threshold"
        
        assert flask_auth_time <= baseline_time * 1.2, \
            f"Flask authentication {flask_auth_time:.2f}ms significantly slower than baseline {baseline_time:.2f}ms"
        
        print(f"\nAuthentication Performance Comparison:")
        print(f"Node.js Baseline: {baseline_time:.2f}ms")
        print(f"Flask Implementation: {flask_auth_time:.2f}ms")


class TestMemoryUsageProfiling:
    """
    Memory usage profiling test suite for Flask application resource consumption.
    
    Ensures Flask implementation meets or exceeds resource efficiency compared
    to Node.js baseline with comprehensive memory footprint analysis.
    """
    
    def test_memory_usage_during_api_operations(self, test_client, performance_profiler, 
                                              performance_thresholds):
        """
        Profile memory usage during typical API operations and workflow execution.
        
        Validates Flask application memory efficiency during sustained operation
        with multiple concurrent API requests and business logic execution.
        """
        # Force initial garbage collection for clean baseline
        gc.collect()
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        with performance_profiler.measure_performance() as capture_metrics:
            # Simulate sustained API operations
            for i in range(50):
                # User creation operations
                user_response = test_client.post('/api/users', json={
                    'email': f'memory.test.{i}@example.com',
                    'password': 'MemoryTestPassword123!',
                    'first_name': f'Memory{i}',
                    'last_name': 'Test'
                })
                assert user_response.status_code == 201
                
                # Business entity operations
                entity_response = test_client.post('/api/business-entities', json={
                    'name': f'Memory Test Entity {i}',
                    'description': f'Entity for memory testing {i}',
                    'status': 'active'
                })
                assert entity_response.status_code == 201
                
                # Query operations
                query_response = test_client.get('/api/business-entities?limit=10')
                assert query_response.status_code == 200
            
            # Capture final memory metrics
            final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory
            metrics = capture_metrics(response_time=0, total_requests=150)
        
        # Memory usage validation
        assert memory_increase <= performance_thresholds.max_memory_usage_mb, \
            f"Memory increase {memory_increase:.2f}MB exceeds threshold {performance_thresholds.max_memory_usage_mb}MB"
        
        # Validate reasonable memory usage per operation
        memory_per_operation = memory_increase / 150 if memory_increase > 0 else 0
        assert memory_per_operation <= 2.0, \
            f"Memory per operation {memory_per_operation:.2f}MB exceeds 2MB threshold"
        
        print(f"\nMemory Usage Profiling Results:")
        print(f"Initial Memory: {initial_memory:.2f}MB")
        print(f"Final Memory: {final_memory:.2f}MB")
        print(f"Memory Increase: {memory_increase:.2f}MB")
        print(f"Memory per Operation: {memory_per_operation:.2f}MB")
    
    def test_memory_leak_detection(self, test_client, performance_profiler):
        """
        Detect potential memory leaks during sustained operation cycles.
        
        Executes multiple operation cycles with garbage collection to identify
        memory retention issues and validate proper resource cleanup.
        """
        memory_measurements = []
        
        # Execute multiple operation cycles with memory measurement
        for cycle in range(5):
            gc.collect()  # Force garbage collection between cycles
            cycle_start_memory = psutil.Process().memory_info().rss / 1024 / 1024
            
            # Execute sustained operations
            for operation in range(20):
                response = test_client.get('/api/business-entities?limit=5')
                assert response.status_code == 200
            
            gc.collect()  # Force garbage collection after operations
            cycle_end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_measurements.append(cycle_end_memory - cycle_start_memory)
        
        # Analyze memory trend for leak detection
        avg_memory_increase = sum(memory_measurements) / len(memory_measurements)
        max_memory_increase = max(memory_measurements)
        
        # Memory leak validation (should not consistently increase)
        assert avg_memory_increase <= 5.0, \
            f"Average memory increase per cycle {avg_memory_increase:.2f}MB indicates potential leak"
        
        assert max_memory_increase <= 10.0, \
            f"Maximum memory increase {max_memory_increase:.2f}MB exceeds leak threshold"
        
        print(f"\nMemory Leak Detection Results:")
        print(f"Memory increases per cycle: {memory_measurements}")
        print(f"Average increase: {avg_memory_increase:.2f}MB")
        print(f"Maximum increase: {max_memory_increase:.2f}MB")


class TestDatabasePerformanceBenchmarking:
    """
    Database query performance benchmarking with SQLAlchemy optimization validation.
    
    Validates SQLAlchemy query optimization effectiveness and database connection
    pooling efficiency compared to Node.js MongoDB baseline implementation.
    """
    
    def test_database_query_optimization(self, benchmark, test_db, database_performance_monitor):
        """
        Benchmark database query performance with optimization analysis.
        
        Validates SQLAlchemy query efficiency, connection pooling, and optimization
        effectiveness for various query patterns and data access operations.
        """
        # Create test data for query optimization testing
        with test_db.session.begin():
            users = []
            entities = []
            
            for i in range(100):
                user = User(
                    email=f'query.test.{i}@example.com',
                    first_name=f'Query{i}',
                    last_name='Test',
                    is_active=i % 2 == 0
                )
                users.append(user)
                test_db.session.add(user)
                
                entity = BusinessEntity(
                    name=f'Query Test Entity {i}',
                    description=f'Entity for query testing {i}',
                    status='active' if i % 3 == 0 else 'inactive',
                    owner_id=None  # Will be set after user creation
                )
                entities.append(entity)
                test_db.session.add(entity)
            
            test_db.session.flush()  # Ensure IDs are available
            
            # Set entity ownership relationships
            for i, entity in enumerate(entities):
                entity.owner_id = users[i % len(users)].id
        
        # Benchmark complex query operations
        def complex_query_operations():
            """Execute complex database queries for performance measurement."""
            query_start_count = database_performance_monitor['get_query_count']()
            
            # Query 1: Active users with entity count
            active_users = test_db.session.query(User).filter(User.is_active == True).all()
            assert len(active_users) == 50
            
            # Query 2: Business entities with owner information
            entities_with_owners = test_db.session.query(BusinessEntity).join(User).filter(
                BusinessEntity.status == 'active'
            ).all()
            assert len(entities_with_owners) > 0
            
            # Query 3: Aggregate query for entity statistics
            entity_stats = test_db.session.query(
                BusinessEntity.status,
                test_db.func.count(BusinessEntity.id)
            ).group_by(BusinessEntity.status).all()
            assert len(entity_stats) >= 2
            
            # Validate query efficiency
            queries_executed = database_performance_monitor['get_query_count']() - query_start_count
            assert queries_executed <= 5, f"Too many queries executed: {queries_executed}"
            
            return len(active_users) + len(entities_with_owners) + len(entity_stats)
        
        # Execute benchmark measurement
        result = benchmark(complex_query_operations)
        
        # Analyze query performance
        avg_query_time = database_performance_monitor['get_average_query_time']()
        total_query_time = database_performance_monitor['get_total_query_time']()
        query_count = database_performance_monitor['get_query_count']()
        
        # Performance validation
        assert avg_query_time <= 25.0, \
            f"Average query time {avg_query_time:.2f}ms exceeds 25ms threshold"
        
        assert total_query_time <= 100.0, \
            f"Total query time {total_query_time:.2f}ms exceeds 100ms threshold"
        
        print(f"\nDatabase Query Performance Results:")
        print(f"Total Queries: {query_count}")
        print(f"Average Query Time: {avg_query_time:.2f}ms")
        print(f"Total Query Time: {total_query_time:.2f}ms")
        print(f"Query Results: {result}")
    
    def test_database_connection_pooling_performance(self, test_db, performance_profiler):
        """
        Test database connection pooling efficiency under concurrent access.
        
        Validates SQLAlchemy connection pool management and concurrent database
        operation handling for optimal resource utilization.
        """
        def database_operation(thread_id: int):
            """Execute database operation for connection pooling test."""
            try:
                # Simulate typical database operations
                with test_db.session.begin():
                    # Query operation
                    users = test_db.session.query(User).filter(User.is_active == True).limit(5).all()
                    
                    # Insert operation
                    test_entity = BusinessEntity(
                        name=f'Pool Test Entity {thread_id}',
                        description=f'Connection pool testing entity {thread_id}',
                        status='active'
                    )
                    test_db.session.add(test_entity)
                    test_db.session.flush()
                    
                    # Update operation
                    if users:
                        users[0].last_login = datetime.now()
                
                return True
            except Exception as e:
                print(f"Database operation failed for thread {thread_id}: {e}")
                return False
        
        # Execute concurrent database operations
        with performance_profiler.measure_performance() as capture_metrics:
            concurrent_operations = 20
            success_count = 0
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(database_operation, i) 
                    for i in range(concurrent_operations)
                ]
                
                for future in as_completed(futures):
                    if future.result():
                        success_count += 1
            
            metrics = capture_metrics(
                response_time=0, 
                total_requests=concurrent_operations
            )
        
        # Connection pooling validation
        success_rate = (success_count / concurrent_operations) * 100
        assert success_rate >= 95.0, \
            f"Connection pool success rate {success_rate:.1f}% below 95% threshold"
        
        assert metrics.cpu_usage <= 70.0, \
            f"CPU usage {metrics.cpu_usage:.1f}% exceeds 70% threshold during pooling test"
        
        print(f"\nConnection Pooling Performance Results:")
        print(f"Concurrent Operations: {concurrent_operations}")
        print(f"Successful Operations: {success_count}")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"CPU Usage: {metrics.cpu_usage:.1f}%")


class TestConcurrentLoadPerformance:
    """
    Concurrent user load testing for equivalent performance validation.
    
    Verifies equivalent user capacity handling and system stability under
    various load conditions compared to Node.js baseline implementation.
    """
    
    def test_concurrent_user_api_access(self, test_client, load_tester, 
                                       performance_thresholds, nodejs_baseline_client):
        """
        Test concurrent user API access with comprehensive performance analysis.
        
        Validates Flask application ability to handle multiple concurrent users
        with equivalent or improved performance compared to Node.js baseline.
        """
        # Define test operation for concurrent execution
        def user_api_operation(user_id: int):
            """API operation to execute for each concurrent user."""
            try:
                # User profile query
                profile_response = test_client.get(f'/api/users/{user_id % 10 + 1}')
                if profile_response.status_code != 200:
                    raise Exception(f"Profile query failed: {profile_response.status_code}")
                
                # Business entity query
                entity_response = test_client.get('/api/business-entities?limit=5')
                if entity_response.status_code != 200:
                    raise Exception(f"Entity query failed: {entity_response.status_code}")
                
                return True
            except Exception as e:
                raise Exception(f"User operation failed: {e}")
        
        # Execute concurrent load test with varying user counts
        load_test_results = []
        user_counts = [10, 25, 50, 100]
        
        for concurrent_users in user_counts:
            print(f"\nTesting {concurrent_users} concurrent users...")
            
            # Execute load test
            results = load_tester.execute_load_test(
                test_function=user_api_operation,
                concurrent_users=concurrent_users,
                duration_seconds=30,
                ramp_up_seconds=5
            )
            
            # Validate performance requirements
            assert results['error_rate'] <= performance_thresholds.max_error_rate_percent, \
                f"Error rate {results['error_rate']:.2f}% exceeds threshold for {concurrent_users} users"
            
            assert results['throughput'] >= performance_thresholds.min_throughput_rps, \
                f"Throughput {results['throughput']:.2f} RPS below threshold for {concurrent_users} users"
            
            assert results['avg_response_time'] <= performance_thresholds.max_response_time_ms, \
                f"Average response time {results['avg_response_time']:.2f}ms exceeds threshold for {concurrent_users} users"
            
            load_test_results.append({
                'concurrent_users': concurrent_users,
                'results': results
            })
            
            print(f"Results for {concurrent_users} users:")
            print(f"  Throughput: {results['throughput']:.2f} RPS")
            print(f"  Avg Response Time: {results['avg_response_time']:.2f}ms")
            print(f"  Error Rate: {results['error_rate']:.2f}%")
            print(f"  95th Percentile: {results['percentiles']['p95']:.2f}ms")
        
        # Analyze scalability trends
        throughput_trend = [r['results']['throughput'] for r in load_test_results]
        response_time_trend = [r['results']['avg_response_time'] for r in load_test_results]
        
        # Validate reasonable scalability (throughput should increase with users up to a point)
        initial_throughput = throughput_trend[0]
        max_throughput = max(throughput_trend)
        assert max_throughput >= initial_throughput * 2, \
            "System does not scale effectively with increased concurrent users"
        
        print(f"\nConcurrent Load Test Summary:")
        print(f"User Counts: {user_counts}")
        print(f"Throughput Trend: {[f'{t:.1f}' for t in throughput_trend]}")
        print(f"Response Time Trend: {[f'{t:.1f}' for t in response_time_trend]}")
        print(f"Scalability Factor: {max_throughput / initial_throughput:.2f}x")
    
    def test_sustained_load_stability(self, test_client, performance_profiler, 
                                     performance_thresholds):
        """
        Test system stability under sustained concurrent load conditions.
        
        Validates Flask application stability, resource management, and performance
        consistency during extended operation under concurrent user load.
        """
        # Define sustained operation for stability testing
        def sustained_api_operations():
            """Execute sustained API operations for stability testing."""
            operations_completed = 0
            start_time = time.time()
            
            while time.time() - start_time < 60:  # 60-second sustained test
                try:
                    # Rotate through different API operations
                    operation_type = operations_completed % 4
                    
                    if operation_type == 0:
                        response = test_client.get('/api/business-entities?limit=10')
                    elif operation_type == 1:
                        response = test_client.get('/api/users?limit=10')
                    elif operation_type == 2:
                        response = test_client.post('/api/business-entities', json={
                            'name': f'Stability Test Entity {operations_completed}',
                            'description': 'Entity for stability testing',
                            'status': 'active'
                        })
                    else:
                        response = test_client.get('/api/auth/status')
                    
                    if response.status_code not in [200, 201]:
                        raise Exception(f"Operation failed with status {response.status_code}")
                    
                    operations_completed += 1
                    
                    # Brief pause to simulate realistic load
                    time.sleep(0.01)
                    
                except Exception as e:
                    print(f"Sustained operation failed: {e}")
                    break
            
            return operations_completed
        
        # Execute sustained load test with performance monitoring
        with performance_profiler.measure_performance() as capture_metrics:
            # Run multiple concurrent sustained operations
            with ThreadPoolExecutor(max_workers=25) as executor:
                futures = [
                    executor.submit(sustained_api_operations) 
                    for _ in range(25)
                ]
                
                total_operations = sum(future.result() for future in as_completed(futures))
            
            metrics = capture_metrics(
                response_time=0,
                total_requests=total_operations
            )
        
        # Stability validation
        assert metrics.memory_usage <= performance_thresholds.max_memory_usage_mb, \
            f"Memory usage {metrics.memory_usage:.2f}MB exceeds threshold during sustained load"
        
        assert metrics.cpu_usage <= performance_thresholds.max_cpu_usage_percent, \
            f"CPU usage {metrics.cpu_usage:.1f}% exceeds threshold during sustained load"
        
        assert metrics.throughput >= performance_thresholds.min_throughput_rps, \
            f"Throughput {metrics.throughput:.2f} RPS below threshold during sustained load"
        
        # Validate reasonable operation completion rate
        expected_min_operations = 25 * 60 * 5  # 25 threads * 60 seconds * 5 ops/sec minimum
        assert total_operations >= expected_min_operations, \
            f"Completed operations {total_operations} below expected minimum {expected_min_operations}"
        
        print(f"\nSustained Load Stability Results:")
        print(f"Total Operations Completed: {total_operations}")
        print(f"Throughput: {metrics.throughput:.2f} RPS")
        print(f"Memory Usage: {metrics.memory_usage:.2f}MB")
        print(f"CPU Usage: {metrics.cpu_usage:.1f}%")


class TestPerformanceRegressionDetection:
    """
    Automated performance regression detection with threshold-based alerting.
    
    Implements comprehensive regression analysis comparing current Flask performance
    against established baselines with configurable alert thresholds.
    """
    
    def test_performance_regression_detection(self, test_client, performance_profiler, 
                                            performance_thresholds, nodejs_baseline_client):
        """
        Comprehensive performance regression detection against multiple baselines.
        
        Validates Flask performance against Node.js baseline and historical Flask
        performance data with automated alerting for threshold violations.
        """
        # Load historical performance baselines (simulated for this test)
        historical_baselines = {
            'api_response_time': 150.0,  # milliseconds
            'memory_usage': 100.0,       # MB
            'throughput': 200.0,         # RPS
            'database_query_time': 20.0  # milliseconds
        }
        
        # Capture current Flask performance metrics
        current_metrics = []
        
        # Execute performance test suite
        for test_iteration in range(5):
            with performance_profiler.measure_performance() as capture_metrics:
                # API performance test
                start_time = time.time()
                for _ in range(20):
                    response = test_client.get('/api/business-entities?limit=5')
                    assert response.status_code == 200
                api_time = (time.time() - start_time) * 1000 / 20  # Average per request
                
                metrics = capture_metrics(
                    response_time=api_time,
                    total_requests=20
                )
                current_metrics.append(metrics)
        
        # Calculate average current performance
        avg_response_time = sum(m.response_time for m in current_metrics) / len(current_metrics)
        avg_memory_usage = sum(m.memory_usage for m in current_metrics) / len(current_metrics)
        avg_throughput = sum(m.throughput for m in current_metrics) / len(current_metrics)
        
        # Regression analysis against historical baselines
        response_regression = ((avg_response_time - historical_baselines['api_response_time']) / 
                             historical_baselines['api_response_time']) * 100
        memory_regression = ((avg_memory_usage - historical_baselines['memory_usage']) / 
                           historical_baselines['memory_usage']) * 100
        throughput_regression = ((historical_baselines['throughput'] - avg_throughput) / 
                               historical_baselines['throughput']) * 100
        
        # Regression threshold validation
        regression_threshold = 15.0  # 15% regression threshold
        
        regressions_detected = []
        
        if response_regression > regression_threshold:
            regressions_detected.append(f"Response time regression: {response_regression:.2f}%")
        
        if memory_regression > regression_threshold:
            regressions_detected.append(f"Memory usage regression: {memory_regression:.2f}%")
        
        if throughput_regression > regression_threshold:
            regressions_detected.append(f"Throughput regression: {throughput_regression:.2f}%")
        
        # Validate no significant regressions
        assert len(regressions_detected) == 0, \
            f"Performance regressions detected: {'; '.join(regressions_detected)}"
        
        # Validate against absolute thresholds
        threshold_violations = performance_thresholds.validate_metrics(
            PerformanceMetrics(
                response_time=avg_response_time,
                memory_usage=avg_memory_usage,
                cpu_usage=sum(m.cpu_usage for m in current_metrics) / len(current_metrics),
                database_queries=sum(m.database_queries for m in current_metrics),
                query_time=sum(m.query_time for m in current_metrics) / len(current_metrics),
                concurrent_users=1,
                throughput=avg_throughput,
                error_rate=sum(m.error_rate for m in current_metrics) / len(current_metrics),
                timestamp=datetime.now()
            )
        )
        
        assert len(threshold_violations) == 0, \
            f"Performance threshold violations: {'; '.join(threshold_violations)}"
        
        print(f"\nPerformance Regression Analysis:")
        print(f"Current vs Historical Performance:")
        print(f"  Response Time: {avg_response_time:.2f}ms (baseline: {historical_baselines['api_response_time']}ms)")
        print(f"  Memory Usage: {avg_memory_usage:.2f}MB (baseline: {historical_baselines['memory_usage']}MB)")
        print(f"  Throughput: {avg_throughput:.2f} RPS (baseline: {historical_baselines['throughput']} RPS)")
        print(f"Regression Analysis:")
        print(f"  Response Time Change: {response_regression:.2f}%")
        print(f"  Memory Usage Change: {memory_regression:.2f}%")
        print(f"  Throughput Change: {throughput_regression:.2f}%")
        
        if not regressions_detected and not threshold_violations:
            print("✓ No performance regressions detected")
    
    def test_automated_performance_alerting(self, test_client, performance_thresholds):
        """
        Test automated performance alerting system for threshold violations.
        
        Validates automated detection and alerting capabilities for performance
        threshold violations with configurable alert severity levels.
        """
        # Simulate performance test with intentionally poor performance
        def simulate_performance_degradation():
            """Simulate degraded performance for alerting test."""
            # Intentionally slow operation to trigger alerts
            time.sleep(0.6)  # 600ms delay to exceed thresholds
            response = test_client.get('/api/business-entities?limit=1')
            return response
        
        # Execute performance test with degradation
        alerts_triggered = []
        
        start_time = time.time()
        response = simulate_performance_degradation()
        end_time = time.time()
        
        response_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        # Simulate metrics with threshold violations
        degraded_metrics = PerformanceMetrics(
            response_time=response_time,
            memory_usage=600.0,  # Exceeds threshold
            cpu_usage=90.0,      # Exceeds threshold
            database_queries=1,
            query_time=50.0,
            concurrent_users=1,
            throughput=1.0,      # Below threshold
            error_rate=5.0,      # Exceeds threshold
            timestamp=datetime.now()
        )
        
        # Test alerting system
        violations = performance_thresholds.validate_metrics(degraded_metrics)
        
        # Validate alerts are properly triggered
        assert len(violations) > 0, "Expected threshold violations for alerting test"
        
        # Categorize alerts by severity
        critical_alerts = [v for v in violations if 'exceeds threshold' in v and ('memory' in v.lower() or 'cpu' in v.lower())]
        warning_alerts = [v for v in violations if 'below threshold' in v or 'error rate' in v.lower()]
        
        assert len(critical_alerts) >= 2, f"Expected at least 2 critical alerts, got {len(critical_alerts)}"
        assert len(warning_alerts) >= 1, f"Expected at least 1 warning alert, got {len(warning_alerts)}"
        
        print(f"\nAutomated Alerting Test Results:")
        print(f"Total Violations Detected: {len(violations)}")
        print(f"Critical Alerts: {len(critical_alerts)}")
        for alert in critical_alerts:
            print(f"  CRITICAL: {alert}")
        print(f"Warning Alerts: {len(warning_alerts)}")
        for alert in warning_alerts:
            print(f"  WARNING: {alert}")
        
        # Test alert resolution (simulate improved performance)
        improved_metrics = PerformanceMetrics(
            response_time=100.0,  # Within threshold
            memory_usage=200.0,   # Within threshold
            cpu_usage=40.0,       # Within threshold
            database_queries=1,
            query_time=15.0,
            concurrent_users=1,
            throughput=150.0,     # Above threshold
            error_rate=0.5,       # Within threshold
            timestamp=datetime.now()
        )
        
        resolved_violations = performance_thresholds.validate_metrics(improved_metrics)
        assert len(resolved_violations) == 0, f"Expected no violations after improvement, got {len(resolved_violations)}"
        
        print(f"\nAlert Resolution Test:")
        print("✓ All performance alerts resolved after optimization")


# Test execution configuration and reporting
if __name__ == "__main__":
    """
    Direct execution configuration for performance testing suite.
    
    Enables standalone execution of performance tests with comprehensive
    reporting and baseline comparison capabilities.
    """
    pytest.main([
        __file__,
        "--benchmark-only",
        "--benchmark-sort=mean",
        "--benchmark-min-rounds=5",
        "--benchmark-warmup=on",
        "--benchmark-disable-gc",
        "--benchmark-histogram",
        "-v",
        "--tb=short"
    ])